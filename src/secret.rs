//! The single shared secret + config resolution layer used by every command.
//!
//! Two distinct precedence chains live here, so no command re-implements either:
//!
//! ## High-secrets (`--seed`, `--secret-key`)
//!
//! These decode to private key material and must come from exactly ONE source.
//! If more than one of file / stdin / raw argv / env supplies the same secret
//! the resolver refuses with a CLI input error naming the conflicting sources,
//! rather than silently picking one — a stale `--seed-file` quietly overriding
//! an explicit `--seed` is a foot-gun that signs with the wrong key. With a
//! single source the resolution order is:
//!
//! 1. `--<name>-file <path>`  — read the file, trim trailing whitespace.
//! 2. `--<name>-stdin` (or the literal value `-`) — read all of stdin, trim the
//!    trailing newline. Only one stdin reader may run per process.
//! 3. the raw `--<name> <value>` argv flag — the documented-INSECURE path
//!    (shell history / `ps` / CI logs); using it emits a one-line stderr warning.
//! 4. the env var (`CARDANOWALL_SEED` / `CARDANOWALL_RECIPIENT_KEY`).
//! 5. an interactive hidden prompt — ONLY when the secret is required AND stdin
//!    is a TTY. The prompt text goes to stderr; the typed bytes never echo.
//! 6. otherwise: a CLI input error (exit `4`).
//!
//! On every path an identity seed accepts both representations — 64-digit raw
//! hex or the checksummed `L309-SEED-1…` form; a recipient secret key is not a
//! seed and stays hex-only.
//!
//! A high-secret is NEVER a required argv flag — automation supplies it through
//! a file, stdin, or the environment; humans get the hidden prompt. The resolved
//! secret string is zeroized after the bytes are produced.
//!
//! ## Non-secret gateway config (`--base-url`, `--api-key`)
//!
//! The order is `explicit flag > env > active gateway profile > built-in default
//! (data gateways only) > error`. The profile lookup is resolved by the caller
//! (it already holds the parsed config); this module only sequences the chain.

use std::io::{IsTerminal, Read};

use cardanowall::seed_encoding::parse_identity_seed;
use zeroize::{Zeroize, Zeroizing};

use crate::util::{hex_to_bytes, CliError};

/// The exact byte length of the X25519 recipient secret key.
const X25519_SECRET_KEY_LENGTH: usize = 32;

/// Which high-secret is being resolved — drives the env var, the flag names in
/// error messages, and the interactive prompt text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The 32-byte master identity seed.
    Seed,
    /// The X25519 recipient secret key (recipient-sealed decryption).
    RecipientKey,
    /// A passphrase (passphrase-sealed encrypt/decrypt). Unlike the byte
    /// secrets it is used as a UTF-8 string — the crypto layer's pinned
    /// normalization profile turns it into the Argon2id password — so it is
    /// resolved via [`resolve_secret_passphrase`], never decoded to bytes.
    Passphrase,
}

impl SecretKind {
    /// The canonical env var that supplies this secret on every command.
    #[must_use]
    pub fn env_var(self) -> &'static str {
        match self {
            SecretKind::Seed => "CARDANOWALL_SEED",
            SecretKind::RecipientKey => "CARDANOWALL_RECIPIENT_KEY",
            SecretKind::Passphrase => "CARDANOWALL_PASSPHRASE",
        }
    }

    /// The base flag name (without the leading dashes), e.g. `seed`.
    #[must_use]
    pub fn flag(self) -> &'static str {
        match self {
            SecretKind::Seed => "seed",
            SecretKind::RecipientKey => "secret-key",
            SecretKind::Passphrase => "passphrase",
        }
    }

    /// The interactive hidden-prompt line written to stderr.
    fn prompt(self) -> &'static str {
        match self {
            SecretKind::Seed => "Enter identity seed (hex or L309-SEED-1...): ",
            SecretKind::RecipientKey => "Enter X25519 recipient secret key (hex): ",
            SecretKind::Passphrase => "Enter passphrase: ",
        }
    }
}

/// The argv inputs for one high-secret, as collected by clap. The four sources
/// (file / stdin / raw argv / env) are mutually exclusive: supplying more than
/// one is a hard CLI input error, so a stale flag can never silently shadow an
/// explicit one.
///
/// `value` carries raw secret material (the seed / secret-key passed on argv),
/// so `Debug` is hand-written to redact it: no `{:?}`, log, or panic-backtrace
/// path can ever surface the value.
#[derive(Clone, Default)]
pub struct SecretArgs {
    /// `--<name> <hex>` — the raw, documented-insecure argv value.
    pub value: Option<String>,
    /// `--<name>-file <path>`.
    pub file: Option<String>,
    /// `--<name>-stdin` — read the secret from stdin.
    pub stdin: bool,
}

impl std::fmt::Debug for SecretArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretArgs")
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .field("file", &self.file)
            .field("stdin", &self.stdin)
            .finish()
    }
}

impl SecretArgs {
    /// Whether the user supplied any source on argv (file/stdin/value).
    #[must_use]
    pub fn any_present(&self) -> bool {
        self.file.is_some() || self.stdin || self.value.as_deref().is_some_and(|v| !v.is_empty())
    }
}

/// A terminal probe + reader surface, injected so tests never touch a real TTY.
///
/// Production wiring uses [`SystemSecretEnv`]; tests supply a fake that reports a
/// non-terminal stdin and canned stdin/file/env reads.
pub trait SecretEnv {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;
    /// Read the whole of stdin to a `String`.
    fn read_stdin(&self) -> Result<String, CliError>;
    /// Read a file to a `String`.
    fn read_file(&self, path: &str) -> Result<String, CliError>;
    /// Whether stdin is a TTY (gates the interactive prompt).
    fn stdin_is_terminal(&self) -> bool;
    /// Prompt on stderr and read a line WITHOUT echo (the hidden prompt).
    fn prompt_hidden(&self, prompt: &str) -> Result<String, CliError>;
    /// Emit a diagnostic line (the argv-insecurity warning) to stderr. Routed
    /// through the env so tests can capture it instead of scraping the process's
    /// real stderr; production writes the line verbatim.
    fn warn(&self, message: &str);
}

/// The production secret environment: real env, real stdin, real `rpassword`.
pub struct SystemSecretEnv;

impl SecretEnv for SystemSecretEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }

    fn read_stdin(&self) -> Result<String, CliError> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::network(format!("cannot read stdin: {e}")))?;
        Ok(buf)
    }

    fn read_file(&self, path: &str) -> Result<String, CliError> {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::input(format!("cannot read secret file {path}: {e}")))
    }

    fn stdin_is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn prompt_hidden(&self, prompt: &str) -> Result<String, CliError> {
        // rpassword writes the prompt to the controlling terminal and reads the
        // line with echo disabled, so the secret never lands in scrollback.
        rpassword::prompt_password(prompt)
            .map_err(|e| CliError::input(format!("cannot read hidden prompt: {e}")))
    }

    fn warn(&self, message: &str) {
        eprintln!("{message}");
    }
}

/// Trim a secret read from a file or stdin: drop a single trailing newline (and
/// any other surrounding whitespace) so a `printf '%s\n' hex > seed` round-trips.
fn trim_secret(raw: &str) -> String {
    raw.trim().to_string()
}

/// The stderr warning text for a secret passed as a raw argv flag. The value
/// itself is never included — only the advice to use a safer source — because
/// argv is captured by shell history, `ps`, and CI job logs. Built as a pure
/// function so the no-secret-leak invariant is directly unit-testable.
pub(crate) fn argv_secret_warning(kind: SecretKind) -> String {
    format!(
        "cardanowall: warning: passing --{flag} on the command line is insecure \
         (visible in shell history, `ps`, and CI logs); prefer --{flag}-file, \
         --{flag}-stdin, or the {env} environment variable",
        flag = kind.flag(),
        env = kind.env_var(),
    )
}

/// Emit the argv-secret warning through the injected env's diagnostic sink.
/// Public to the crate so command-level secret collectors that do not route
/// through [`resolve_secret_string`] (e.g. `verify`'s repeatable `--secret-key`)
/// share the exact same warning text and the same testable sink.
pub(crate) fn warn_secret_on_argv(kind: SecretKind, env: &dyn SecretEnv) {
    env.warn(&argv_secret_warning(kind));
}

/// The argv/env sources that may supply one high-secret, as boolean presence
/// flags. Used to enforce the single-source rule from both the single-value
/// resolver and the plural collectors (e.g. `verify`'s repeatable key list).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SecretSources {
    /// `--<name>-file` is present and non-empty.
    pub file: bool,
    /// `--<name>-stdin` (or the `-` value sentinel) is present.
    pub stdin: bool,
    /// A raw `--<name>` argv value is present (the `-` sentinel does not count).
    pub argv: bool,
    /// The env var is set and non-empty.
    pub env: bool,
}

impl SecretSources {
    /// The named sources that are present, in the documented precedence order.
    fn present(self, kind: SecretKind) -> Vec<String> {
        let mut names = Vec::new();
        if self.file {
            names.push(format!("--{}-file", kind.flag()));
        }
        if self.stdin {
            names.push(format!("--{}-stdin", kind.flag()));
        }
        if self.argv {
            names.push(format!("--{}", kind.flag()));
        }
        if self.env {
            names.push(kind.env_var().to_string());
        }
        names
    }
}

/// Enforce that a high-secret comes from exactly one source. Resolving silently
/// by precedence lets a stale `--seed-file` (or a leftover env var) override an
/// explicit `--seed` the user thought they were using, signing with the wrong
/// key without ever flagging the mismatch. When more than one source is present
/// this returns a CLI input error naming them (never their values).
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when two or more sources are present.
pub(crate) fn enforce_single_secret_source(
    kind: SecretKind,
    sources: SecretSources,
    cmd: &str,
) -> Result<(), CliError> {
    let names = sources.present(kind);
    if names.len() > 1 {
        return Err(CliError::input(format!(
            "{cmd}: --{flag} given by more than one source ({sources}); supply it from exactly one",
            flag = kind.flag(),
            sources = names.join(", "),
        )));
    }
    Ok(())
}

/// Resolve a high-secret to its raw 32 bytes.
///
/// A seed accepts both representations — 64-digit raw hex (0x prefix and
/// whitespace tolerated) or the checksummed `L309-SEED-1…` bech32 form in
/// either single case; a recipient key is hex-only. `required` decides whether
/// a missing secret triggers the interactive prompt (TTY only) or a hard
/// error. `cmd` and `kind` shape the error/prompt text.
///
/// The intermediate secret string is zeroized before returning, and the
/// returned buffer is [`Zeroizing`] so the bytes are wiped when the caller
/// drops them — a resolved secret never outlives its last use in heap.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a malformed value, a wrong byte length, a
/// missing required secret on a non-TTY, or a file/stdin read failure.
pub fn resolve_secret_bytes(
    kind: SecretKind,
    args: &SecretArgs,
    required: bool,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    let mut secret = match resolve_secret_string(kind, args, required, cmd, env)? {
        Some(secret) => secret,
        None => return Ok(None),
    };
    let result = decode_and_check(kind, &secret, cmd);
    secret.zeroize();
    result.map(Some)
}

/// Resolve a passphrase through the same single-source precedence chain as the
/// byte secrets, returning it as a self-wiping [`Zeroizing<String>`].
///
/// A passphrase is NOT decoded to bytes or length-checked here: the crypto
/// layer's pinned `cardano-poe-pw-norm-v1` normalization (which collapses and
/// trims surrounding whitespace, bounds the length, and rejects an empty
/// result) is the sole authority on its shape, and it runs identically at seal
/// and open across every SDK. `required` and `cmd` shape the prompt / error
/// text exactly as for the byte secrets.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on a source conflict, a missing required
/// passphrase on a non-TTY, or a file/stdin read failure.
pub fn resolve_secret_passphrase(
    args: &SecretArgs,
    required: bool,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<Option<Zeroizing<String>>, CliError> {
    Ok(
        resolve_secret_string(SecretKind::Passphrase, args, required, cmd, env)?
            .map(Zeroizing::new),
    )
}

/// The string half of the resolution chain (source precedence only, no decode).
fn resolve_secret_string(
    kind: SecretKind,
    args: &SecretArgs,
    required: bool,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<Option<String>, CliError> {
    let stdin_sentinel = args.value.as_deref() == Some("-");
    let raw_argv_present = args.value.as_deref().is_some_and(|v| !v.is_empty()) && !stdin_sentinel;

    // A high-secret must come from exactly one place; a stale source must never
    // silently shadow an explicit one.
    enforce_single_secret_source(
        kind,
        SecretSources {
            file: args.file.as_deref().is_some_and(|p| !p.is_empty()),
            stdin: args.stdin || stdin_sentinel,
            argv: raw_argv_present,
            env: env.var(kind.env_var()).is_some(),
        },
        cmd,
    )?;

    // 1. file.
    if let Some(path) = args.file.as_deref().filter(|p| !p.is_empty()) {
        return Ok(Some(trim_secret(&env.read_file(path)?)));
    }
    // 2. stdin (explicit flag or the literal value `-`).
    if args.stdin || stdin_sentinel {
        return Ok(Some(trim_secret(&env.read_stdin()?)));
    }
    // 3. raw argv value (the documented-insecure path): warn before using it,
    //    because it lands in shell history, `ps`, and CI logs.
    if let Some(value) = args.value.as_deref().filter(|v| !v.is_empty()) {
        warn_secret_on_argv(kind, env);
        return Ok(Some(value.trim().to_string()));
    }
    // 4. env var.
    if let Some(value) = env.var(kind.env_var()) {
        return Ok(Some(value.trim().to_string()));
    }
    // 5. interactive hidden prompt — only when required AND stdin is a TTY.
    if required && env.stdin_is_terminal() {
        let entered = env.prompt_hidden(kind.prompt())?;
        let trimmed = trim_secret(&entered);
        if trimmed.is_empty() {
            return Err(CliError::input(format!(
                "{cmd}: no {} provided",
                kind.flag()
            )));
        }
        return Ok(Some(trimmed));
    }
    // 6. nothing.
    if required {
        Err(CliError::input(format!(
            "{cmd}: --{flag} is required — pass --{flag}-file <path>, --{flag}-stdin, \
             set {env}, or run interactively for a hidden prompt",
            flag = kind.flag(),
            env = kind.env_var(),
        )))
    } else {
        Ok(None)
    }
}

/// Decode one resolved secret string to its raw bytes. Seeds route through the
/// SDK identity-seed parser, so both accepted representations (raw hex and the
/// checksummed `L309-SEED-1…` form) work on every input path; recipient secret
/// keys are not seeds and stay hex-only.
///
/// Every intermediate copy of the key material is zeroized on every exit path
/// (including the wrong-length error), and the returned buffer wipes itself
/// on drop.
fn decode_and_check(
    kind: SecretKind,
    value: &str,
    cmd: &str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match kind {
        SecretKind::Seed => parse_identity_seed(value)
            .map(|mut seed| {
                let bytes = Zeroizing::new(seed.to_vec());
                seed.zeroize();
                bytes
            })
            // The seed parser is an external boundary whose error Display can
            // carry value-bearing detail. Never forward `{e}`: report only the
            // input length and the parser's stable, value-free error code.
            .map_err(|e| {
                CliError::input(format!(
                    "{cmd}: --{} invalid seed: {}-char value rejected ({})",
                    kind.flag(),
                    value.chars().count(),
                    e.code(),
                ))
            }),
        SecretKind::RecipientKey => {
            let bytes = hex_to_bytes(value)
                .map(Zeroizing::new)
                .map_err(|e| CliError::input(format!("{cmd}: --{} {e}", kind.flag())))?;
            if bytes.len() != X25519_SECRET_KEY_LENGTH {
                return Err(CliError::input(format!(
                    "{cmd}: --{} must decode to exactly {X25519_SECRET_KEY_LENGTH} bytes (got {})",
                    kind.flag(),
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        // A passphrase is a UTF-8 string used as-is (the crypto layer normalizes
        // it); it never routes through the byte-decode path.
        SecretKind::Passphrase => {
            unreachable!("a passphrase is resolved via resolve_secret_passphrase, not decoded")
        }
    }
}

// ===========================================================================
// Non-secret gateway config resolution (base-url, api-key)
// ===========================================================================

/// Resolve one non-secret config value through `flag > env > profile > error`.
///
/// `default` (data gateways only) is appended by the caller for slots that have a
/// built-in fallback; the API key and base URL have none, so `None` flows through.
#[must_use]
pub fn resolve_config_value(
    flag: Option<&str>,
    env: Option<&str>,
    profile: Option<&str>,
) -> Option<String> {
    for candidate in [flag, env, profile] {
        if let Some(value) = candidate.map(str::trim).filter(|v| !v.is_empty()) {
            return Some(value.to_string());
        }
    }
    None
}

/// The resolved service-gateway endpoint: the base URL plus the opaque bearer.
///
/// `api_key` is a bearer token, so `Debug` is hand-written to redact it: no
/// `{:?}`, log, or panic-backtrace path can ever surface the key.
#[derive(Clone, Default)]
pub struct ServiceGateway {
    /// The required base URL — the full base including the API version segment
    /// (e.g. `https://gateway.example.com/api/v1`). The SDK appends only the
    /// resource path to it.
    pub base_url: String,
    /// The opaque bearer API key, when supplied anywhere.
    pub api_key: Option<String>,
}

impl std::fmt::Debug for ServiceGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceGateway")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Resolve the service-gateway base URL + API key for a network command, applying
/// `explicit flag > env > active gateway profile` to each, and reading both env
/// vars through the injected [`SecretEnv`].
///
/// The base URL is the full base including the API version segment (e.g.
/// `https://gateway.example.com/api/v1`); the SDK appends only the resource path.
/// The base URL is required; the API key is optional (a key-less public gateway).
/// `profile` is the active [`GatewayProfile`](crate::config::GatewayProfile)
/// selected by the caller (the `--gateway-profile` flag or the config default).
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when no base URL resolves from any source.
pub fn resolve_service_gateway(
    base_url_flag: Option<&str>,
    api_key_flag: Option<&str>,
    profile: Option<&crate::config::GatewayProfile>,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<ServiceGateway, CliError> {
    let profile_base = profile.map(|p| p.base_url.as_str());
    let profile_key = profile.and_then(|p| p.api_key.as_deref());

    let base_url = resolve_config_value(
        base_url_flag,
        env.var("CARDANOWALL_BASE_URL").as_deref(),
        profile_base,
    )
    .ok_or_else(|| {
        CliError::input(format!(
            "{cmd}: a gateway base URL is required — pass --base-url, set CARDANOWALL_BASE_URL, \
             or configure a gateway profile (cardanowall gateway add …). Use the full base \
             including the version segment, e.g. https://gateway.example.com/api/v1"
        ))
    })?;

    let api_key = resolve_config_value(
        api_key_flag,
        env.var("CARDANOWALL_API_KEY").as_deref(),
        profile_key,
    );

    Ok(ServiceGateway { base_url, api_key })
}

/// Test doubles for the secret environment, shared by this module's tests and the
/// command modules' tests so each command can exercise the file/stdin/env/error
/// paths without a real TTY.
#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A fake env where stdin is NOT a terminal (so the prompt branch is skipped)
    /// unless a test opts into `terminal = true`.
    pub struct FakeSecretEnv {
        /// Environment variables visible to the fake.
        pub vars: HashMap<String, String>,
        /// Canned file contents keyed by path.
        pub files: HashMap<String, String>,
        /// Canned stdin contents.
        pub stdin: Option<String>,
        /// Whether stdin reports as a TTY (gates the prompt branch).
        pub terminal: bool,
        /// The string the hidden prompt returns when invoked.
        pub prompt_response: Option<String>,
        /// Records whether the prompt branch was hit.
        pub prompted: RefCell<bool>,
        /// Captures every diagnostic line passed to `warn`, so tests can assert
        /// the argv-insecurity warning fires (and only on the argv branch).
        pub warnings: RefCell<Vec<String>>,
    }

    impl Default for FakeSecretEnv {
        fn default() -> Self {
            Self {
                vars: HashMap::new(),
                files: HashMap::new(),
                stdin: None,
                terminal: false,
                prompt_response: None,
                prompted: RefCell::new(false),
                warnings: RefCell::new(Vec::new()),
            }
        }
    }

    impl SecretEnv for FakeSecretEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned().filter(|v| !v.is_empty())
        }
        fn read_stdin(&self) -> Result<String, CliError> {
            self.stdin
                .clone()
                .ok_or_else(|| CliError::network("no stdin in fake".to_string()))
        }
        fn read_file(&self, path: &str) -> Result<String, CliError> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| CliError::input(format!("no fake file {path}")))
        }
        fn stdin_is_terminal(&self) -> bool {
            self.terminal
        }
        fn prompt_hidden(&self, _prompt: &str) -> Result<String, CliError> {
            *self.prompted.borrow_mut() = true;
            self.prompt_response
                .clone()
                .ok_or_else(|| CliError::input("no prompt response in fake".to_string()))
        }
        fn warn(&self, message: &str) {
            self.warnings.borrow_mut().push(message.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeSecretEnv as FakeEnv;
    use super::*;
    use std::collections::HashMap;

    fn seed_hex() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn file_only_resolves() {
        let env = FakeEnv {
            files: HashMap::from([("/s".to_string(), format!("{}\n", seed_hex()))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            file: Some("/s".to_string()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(*bytes, hex_to_bytes(&seed_hex()).unwrap());
    }

    #[test]
    fn stdin_only_resolves_and_trims_newline() {
        let env = FakeEnv {
            stdin: Some(format!("{}\n", seed_hex())),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            stdin: true,
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(*bytes, hex_to_bytes(&seed_hex()).unwrap());
    }

    #[test]
    fn dash_value_means_stdin() {
        let env = FakeEnv {
            stdin: Some(seed_hex()),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some("-".to_string()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn argv_value_resolves_and_emits_the_insecurity_warning() {
        // The sole-source argv path resolves AND emits the insecurity warning to
        // the captured sink. The captured line must carry the advice but never
        // the secret value itself.
        let env = FakeEnv::default();
        let args = SecretArgs {
            value: Some(seed_hex()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(*bytes, hex_to_bytes(&seed_hex()).unwrap());

        let warnings = env.warnings.borrow();
        assert_eq!(warnings.len(), 1, "exactly one warning on the argv branch");
        let warning = &warnings[0];
        assert!(warning.contains("insecure"));
        assert!(warning.contains("--seed"));
        assert!(warning.contains("--seed-file"));
        assert!(warning.contains("CARDANOWALL_SEED"));
        assert!(!warning.contains(&seed_hex()));
    }

    #[test]
    fn argv_warning_names_the_safe_alternatives_per_kind() {
        let seed = argv_secret_warning(SecretKind::Seed);
        assert!(seed.contains("--seed"));
        assert!(seed.contains("--seed-file"));
        assert!(seed.contains("--seed-stdin"));
        assert!(seed.contains("CARDANOWALL_SEED"));
        assert!(seed.contains("insecure"));

        let key = argv_secret_warning(SecretKind::RecipientKey);
        assert!(key.contains("--secret-key"));
        assert!(key.contains("--secret-key-file"));
        assert!(key.contains("--secret-key-stdin"));
        assert!(key.contains("CARDANOWALL_RECIPIENT_KEY"));
    }

    #[test]
    fn argv_warning_never_carries_secret_material() {
        // The warning is built without the value, so even a real-looking secret
        // cannot reach it (the function never receives the value at all).
        let warning = argv_secret_warning(SecretKind::Seed);
        assert!(!warning.contains(&seed_hex()));
        assert!(!warning.contains(&"ef".repeat(32)));
    }

    /// Only the raw argv branch warns; file / stdin / env / prompt are silent.
    /// There is no value exposed on argv on those paths, so the warning must stay
    /// scoped to the branch that actually leaks the secret on the command line.
    #[test]
    fn non_argv_sources_never_warn() {
        // File source.
        let file_env = FakeEnv {
            files: HashMap::from([("/s".to_string(), format!("{}\n", seed_hex()))]),
            ..FakeEnv::default()
        };
        let file_args = SecretArgs {
            file: Some("/s".to_string()),
            ..SecretArgs::default()
        };
        resolve_secret_bytes(SecretKind::Seed, &file_args, true, "identity", &file_env).unwrap();
        assert!(file_env.warnings.borrow().is_empty(), "file path is silent");

        // Stdin source.
        let stdin_env = FakeEnv {
            stdin: Some(format!("{}\n", seed_hex())),
            ..FakeEnv::default()
        };
        let stdin_args = SecretArgs {
            stdin: true,
            ..SecretArgs::default()
        };
        resolve_secret_bytes(SecretKind::Seed, &stdin_args, true, "identity", &stdin_env).unwrap();
        assert!(
            stdin_env.warnings.borrow().is_empty(),
            "stdin path is silent"
        );

        // Env source.
        let env_env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), seed_hex())]),
            ..FakeEnv::default()
        };
        resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env_env,
        )
        .unwrap();
        assert!(env_env.warnings.borrow().is_empty(), "env path is silent");

        // Interactive prompt source (TTY).
        let prompt_env = FakeEnv {
            terminal: true,
            prompt_response: Some(format!("{}\n", seed_hex())),
            ..FakeEnv::default()
        };
        resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &prompt_env,
        )
        .unwrap();
        assert!(
            prompt_env.warnings.borrow().is_empty(),
            "prompt path is silent"
        );
    }

    #[test]
    fn multiple_sources_are_a_conflict_error() {
        // file + stdin + argv + env all present: the resolver must refuse rather
        // than silently let one shadow the others (a stale source signing with
        // the wrong key).
        let env = FakeEnv {
            files: HashMap::from([("/s".to_string(), format!("{}\n", seed_hex()))]),
            stdin: Some("cd".repeat(32)),
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some("12".repeat(32)),
            file: Some("/s".to_string()),
            stdin: true,
        };
        let err =
            resolve_secret_string(SecretKind::Seed, &args, true, "identity", &env).unwrap_err();
        assert_eq!(err.code, 4);
        // The message names the conflicting sources, never the secret values.
        assert!(err.message.contains("--seed-file"));
        assert!(err.message.contains("--seed-stdin"));
        assert!(err.message.contains("--seed"));
        assert!(err.message.contains("CARDANOWALL_SEED"));
        assert!(!err.message.contains(&seed_hex()));
        assert!(!err.message.contains(&"12".repeat(32)));
        assert!(!err.message.contains(&"cd".repeat(32)));
        assert!(!err.message.contains(&"ef".repeat(32)));
    }

    #[test]
    fn argv_plus_env_is_a_conflict_error() {
        // Two sources is enough to trip the conflict guard, even when one is the
        // env var the argv flag used to silently beat.
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some(seed_hex()),
            ..SecretArgs::default()
        };
        let err =
            resolve_secret_string(SecretKind::Seed, &args, true, "identity", &env).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--seed"));
        assert!(err.message.contains("CARDANOWALL_SEED"));
    }

    #[test]
    fn dash_stdin_plus_env_is_a_conflict_error() {
        // The `-` stdin sentinel counts as the stdin source, so combining it with
        // an env var is still a conflict.
        let env = FakeEnv {
            stdin: Some(seed_hex()),
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some("-".to_string()),
            ..SecretArgs::default()
        };
        let err =
            resolve_secret_string(SecretKind::Seed, &args, true, "identity", &env).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--seed-stdin"));
        assert!(err.message.contains("CARDANOWALL_SEED"));
    }

    #[test]
    fn secret_args_debug_redacts_the_argv_value() {
        // A `{:?}` of SecretArgs (e.g. through a log line or a panic backtrace)
        // must never surface the raw secret value; the file path and stdin flag
        // are not secret and stay visible for debugging.
        let args = SecretArgs {
            value: Some(seed_hex()),
            file: Some("/path/to/seed".to_string()),
            stdin: false,
        };
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&seed_hex()));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("/path/to/seed"));
    }

    #[test]
    fn enforce_single_secret_source_counts_sources() {
        // One source is fine.
        assert!(enforce_single_secret_source(
            SecretKind::Seed,
            SecretSources {
                file: true,
                ..SecretSources::default()
            },
            "identity",
        )
        .is_ok());
        // None is fine here (absence is handled downstream by `required`).
        assert!(enforce_single_secret_source(
            SecretKind::Seed,
            SecretSources::default(),
            "identity",
        )
        .is_ok());
        // Two or more is a hard error naming the sources.
        let err = enforce_single_secret_source(
            SecretKind::RecipientKey,
            SecretSources {
                argv: true,
                file: true,
                ..SecretSources::default()
            },
            "verify",
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--secret-key"));
        assert!(err.message.contains("--secret-key-file"));
        assert!(err.message.contains("more than one source"));
    }

    #[test]
    fn env_used_when_no_flag() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), seed_hex())]),
            ..FakeEnv::default()
        };
        let bytes = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn missing_required_non_tty_is_input_error_no_prompt() {
        let env = FakeEnv::default(); // terminal = false
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!*env.prompted.borrow(), "must not prompt on a non-TTY");
    }

    #[test]
    fn missing_optional_is_none() {
        let env = FakeEnv::default();
        let out = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            false,
            "submit",
            &env,
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn prompt_used_only_on_tty_when_required() {
        let env = FakeEnv {
            terminal: true,
            prompt_response: Some(format!("{}\n", seed_hex())),
            ..FakeEnv::default()
        };
        let bytes = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(*env.prompted.borrow());
    }

    #[test]
    fn rejects_wrong_length() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "abcd".to_string())]),
            ..FakeEnv::default()
        };
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    /// The checksummed display form of the all-zero seed, as the SDK encodes it.
    fn zero_seed_encoded() -> String {
        cardanowall::seed_encoding::encode_identity_seed(&[0u8; 32]).unwrap()
    }

    #[test]
    fn seed_accepts_bech32_uppercase_from_env() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), zero_seed_encoded())]),
            ..FakeEnv::default()
        };
        let bytes = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(*bytes, vec![0u8; 32]);
    }

    #[test]
    fn seed_accepts_bech32_lowercase_from_file() {
        let env = FakeEnv {
            files: HashMap::from([(
                "/s".to_string(),
                format!("{}\n", zero_seed_encoded().to_ascii_lowercase()),
            )]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            file: Some("/s".to_string()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(*bytes, vec![0u8; 32]);
    }

    #[test]
    fn seed_rejects_corrupted_bech32_as_input_error() {
        // Flip the final checksum character of the valid lowercase form.
        let mut corrupted = zero_seed_encoded().to_ascii_lowercase();
        let last = corrupted.pop().expect("encoded seed is non-empty");
        corrupted.push(if last == 'q' { 'p' } else { 'q' });
        // Keep the planted value so we can prove the boundary never echoes it.
        let planted = corrupted.clone();
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), corrupted)]),
            ..FakeEnv::default()
        };
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        // The corrupted seed value must NOT appear in the error string — the
        // boundary reports only length + the parser's value-free error code.
        assert!(
            !err.message.contains(&planted),
            "error must not echo the corrupted seed value"
        );
        // Neither may a long verbatim run of it leak (guard against partial echo).
        assert!(!err.message.contains(&planted[..planted.len() - 4]));
    }

    #[test]
    fn seed_malformed_hex_does_not_echo_value() {
        // A 64-char seed-shaped hex with a stray non-hex digit must reject via the
        // boundary without echoing the value — only length + error code.
        let mut planted = "ab".repeat(31);
        planted.push_str("az"); // 64 chars, invalid byte
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), planted.clone())]),
            ..FakeEnv::default()
        };
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&planted));
        assert!(!err.message.contains(&"ab".repeat(31)));
        // It DOES report the length so the user can still self-diagnose.
        assert!(err.message.contains("64-char"));
    }

    #[test]
    fn passphrase_resolves_as_a_string_from_every_source() {
        // File source (trailing newline trimmed).
        let file_env = FakeEnv {
            files: HashMap::from([("/p".to_string(), "correct horse\n".to_string())]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            file: Some("/p".to_string()),
            ..SecretArgs::default()
        };
        let pw = resolve_secret_passphrase(&args, true, "seal", &file_env)
            .unwrap()
            .unwrap();
        assert_eq!(&*pw, "correct horse");

        // Env source.
        let env_env = FakeEnv {
            vars: HashMap::from([(
                "CARDANOWALL_PASSPHRASE".to_string(),
                "battery staple".to_string(),
            )]),
            ..FakeEnv::default()
        };
        let pw = resolve_secret_passphrase(&SecretArgs::default(), true, "seal", &env_env)
            .unwrap()
            .unwrap();
        assert_eq!(&*pw, "battery staple");

        // An optional passphrase absent everywhere is None (the recipient path).
        assert!(resolve_secret_passphrase(
            &SecretArgs::default(),
            false,
            "seal",
            &FakeEnv::default()
        )
        .unwrap()
        .is_none());

        // Two sources conflict, like every other secret.
        let conflict_env = FakeEnv {
            files: HashMap::from([("/p".to_string(), "a\n".to_string())]),
            vars: HashMap::from([("CARDANOWALL_PASSPHRASE".to_string(), "b".to_string())]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            file: Some("/p".to_string()),
            ..SecretArgs::default()
        };
        assert_eq!(
            resolve_secret_passphrase(&args, true, "seal", &conflict_env)
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn recipient_key_stays_hex_only() {
        // The bech32 seed form is NOT a recipient secret key; it must be refused.
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_RECIPIENT_KEY".to_string(), zero_seed_encoded())]),
            ..FakeEnv::default()
        };
        let err = resolve_secret_bytes(
            SecretKind::RecipientKey,
            &SecretArgs::default(),
            true,
            "inbox",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn config_value_precedence() {
        assert_eq!(
            resolve_config_value(Some("flag"), Some("env"), Some("prof")),
            Some("flag".to_string())
        );
        assert_eq!(
            resolve_config_value(None, Some("env"), Some("prof")),
            Some("env".to_string())
        );
        assert_eq!(
            resolve_config_value(None, None, Some("prof")),
            Some("prof".to_string())
        );
        assert_eq!(resolve_config_value(None, None, None), None);
        // Empty strings are skipped.
        assert_eq!(
            resolve_config_value(Some("  "), None, Some("prof")),
            Some("prof".to_string())
        );
    }
}
