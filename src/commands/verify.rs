//! `cardanowall verify <tx-hash>` — the standalone Label 309 verifier.
//!
//! A thin shell over the SDK's `verify_tx`: it owns option parsing, gateway
//! resolution, output formatting, and the verdict → exit-code mapping. The
//! verdict's exit code is passed through verbatim, so the public exit-code
//! contract (`0` valid / `1` integrity / `2` network / `3` pending / `4` CLI
//! input) is whatever the verifier decided, plus `4` for CLI-input failures.
//!
//! The verifier is service-independent: given only the transaction hash, public
//! gateways, and optional recipient keys, it fetches the label-309 metadata,
//! validates the record, and runs the profile-gated signature / decryption /
//! Merkle checks — trusting no publisher and no issuer server.

use cardanowall::verifier::{
    verify_report_to_dict, verify_tx, Decryption, Profile, VerifyTxInput,
    CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
};
use clap::Args;

use crate::config::{
    read_config_file, resolve_gateways, GatewayFlags, ResolvedGateways, SystemConfigEnv,
    SystemGatewayEnv,
};
use crate::output::render_human_report;
use crate::secret::{
    enforce_single_secret_source, warn_secret_on_argv, SecretEnv, SecretKind, SecretSources,
    SystemSecretEnv,
};
use crate::util::{hex_to_bytes, CliError};

/// Arguments for `cardanowall verify`.
///
/// `secret_key` carries raw recipient secret keys passed on argv and `blockfrost`
/// is a Blockfrost project id (an API credential), so `Debug` is hand-written to
/// redact both: no `{:?}`, log, or panic-backtrace path can ever surface them.
#[derive(Args)]
pub struct VerifyArgs {
    /// 64-hex Cardano transaction hash.
    pub tx_hash: String,
    /// core | signed | sealed | recipient-sealed (default: signed).
    #[arg(long)]
    pub profile: Option<String>,
    /// Cardano data-source gateway URL (repeatable; Koios-compatible; or env
    /// CARDANOWALL_CARDANO_GATEWAY). The legacy `--gateway` spelling remains as a
    /// hidden alias.
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub cardano_gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback; or env
    /// CARDANOWALL_BLOCKFROST_PROJECT_ID).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// Arweave gateway URL (repeatable; or env CARDANOWALL_ARWEAVE_GATEWAY).
    #[arg(long = "arweave-gateway")]
    pub arweave_gateway: Vec<String>,
    /// IPFS gateway URL (repeatable; or env CARDANOWALL_IPFS_GATEWAY).
    #[arg(long = "ipfs-gateway")]
    pub ipfs_gateway: Vec<String>,
    /// Confirmation depth threshold (non-negative integer; or env
    /// CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD).
    #[arg(long)]
    pub threshold: Option<String>,
    /// extra entries for the egress deny list (repeatable; or env
    /// CARDANOWALL_DENY_HOST), appended to the built-in defaults. Applies only
    /// to URLs derived from untrusted on-chain records — the record URIs and the
    /// explorer / Arweave / IPFS resolver hops taken to fetch them.
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// the --deny-host entries REPLACE the built-in deny list instead of
    /// appending (or env CARDANOWALL_DENY_HOSTS_REPLACE / config
    /// deny_hosts_replace). With no entries listed, NOTHING is refused — you
    /// take over SSRF protection entirely. Meant for private-network
    /// resolvers (e.g. an internal Arweave mirror, or arlocal on loopback).
    #[arg(long = "deny-hosts-replace")]
    pub deny_hosts_replace: bool,
    /// Recipient secret key for sealed PoE, as bare hex (repeatable; tried
    /// against every sealed item). INSECURE on argv; prefer --secret-key-file /
    /// --secret-key-stdin / CARDANOWALL_RECIPIENT_KEY (comma/space-separated for
    /// several).
    #[arg(long = "secret-key")]
    pub secret_key: Vec<String>,
    /// read recipient secret key(s) from a file (one hex key per line).
    #[arg(long = "secret-key-file")]
    pub secret_key_file: Option<String>,
    /// read recipient secret key(s) from stdin (one per line).
    #[arg(long = "secret-key-stdin")]
    pub secret_key_stdin: bool,
    /// Suppress content fetches (item URIs, sealed ciphertext, Merkle
    /// leaves-lists); the transaction is still resolved from the Cardano
    /// gateway chain.
    #[arg(long = "no-fetch")]
    pub no_fetch: bool,
    /// Emit machine-readable VerifyReport JSON on stdout.
    #[arg(long)]
    pub json: bool,
    /// Pretty-print JSON output (only with --json).
    #[arg(long)]
    pub pretty: bool,
}

impl std::fmt::Debug for VerifyArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyArgs")
            .field("tx_hash", &self.tx_hash)
            .field("profile", &self.profile)
            .field("cardano_gateway", &self.cardano_gateway)
            // The Blockfrost project id authenticates requests to Blockfrost, so
            // it is a credential and must never surface in a debug dump.
            .field(
                "blockfrost",
                &self.blockfrost.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway", &self.arweave_gateway)
            .field("ipfs_gateway", &self.ipfs_gateway)
            .field("threshold", &self.threshold)
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            // The recipient secret keys are secret material: report only how many
            // were supplied, never the bytes.
            .field(
                "secret_key",
                &format_args!("[{} redacted]", self.secret_key.len()),
            )
            .field("secret_key_file", &self.secret_key_file)
            .field("secret_key_stdin", &self.secret_key_stdin)
            .field("no_fetch", &self.no_fetch)
            .field("json", &self.json)
            .field("pretty", &self.pretty)
            .finish()
    }
}

const PROFILES: [(&str, Profile); 4] = [
    ("core", Profile::Core),
    ("signed", Profile::Signed),
    ("sealed", Profile::Sealed),
    ("recipient-sealed", Profile::RecipientSealed),
];

fn parse_threshold(raw: Option<&str>) -> Result<Option<u32>, CliError> {
    let Some(raw) = raw else { return Ok(None) };
    // Parse as `u32` so negatives and values beyond `u32::MAX` are rejected
    // outright rather than wrapped; the round-trip comparison additionally
    // rejects a leading `+`, leading zeros, and embedded whitespace.
    match raw.parse::<u32>() {
        Ok(n) if n.to_string() == raw => Ok(Some(n)),
        _ => Err(CliError::input(format!(
            "verify: --threshold must be a non-negative integer; got \"{raw}\""
        ))),
    }
}

/// Gather the recipient-secret-key specs from a single source. Unlike the other
/// commands, `verify` accepts a *list* of keys per source — a repeated
/// `--secret-key` flag, one-per-line in a file/stdin, or a comma/space list in
/// `CARDANOWALL_RECIPIENT_KEY` — and tries every key against every sealed item.
///
/// The single-source rule still applies: providing the key list from more than
/// one source (e.g. a file plus the env var, or argv plus a file) is a hard CLI
/// input error, identical to every other secret-bearing command, so a stale
/// source can never silently shadow an explicit one. With a single source the
/// order is argv → file → stdin → env.
fn collect_secret_key_specs(
    args: &VerifyArgs,
    env: &dyn SecretEnv,
) -> Result<Vec<String>, CliError> {
    let kind = SecretKind::RecipientKey;
    enforce_single_secret_source(
        kind,
        SecretSources {
            file: args
                .secret_key_file
                .as_deref()
                .is_some_and(|p| !p.is_empty()),
            stdin: args.secret_key_stdin,
            argv: !args.secret_key.is_empty(),
            env: env.var(kind.env_var()).is_some(),
        },
        "verify",
    )?;

    // 1. explicit repeatable flags — the documented-insecure argv path; warn
    //    that the keys are exposed in shell history / `ps` / CI logs.
    if !args.secret_key.is_empty() {
        warn_secret_on_argv(kind, env);
        return Ok(args.secret_key.clone());
    }
    // 2. file (one spec per line).
    if let Some(path) = args.secret_key_file.as_deref().filter(|p| !p.is_empty()) {
        let raw = env.read_file(path)?;
        return Ok(split_secret_lines(&raw));
    }
    // 3. stdin.
    if args.secret_key_stdin {
        let raw = env.read_stdin()?;
        return Ok(split_secret_lines(&raw));
    }
    // 4. env var (comma / whitespace separated).
    if let Some(value) = env.var(kind.env_var()) {
        return Ok(split_secret_list(&value));
    }
    Ok(Vec::new())
}

/// Split file/stdin content into specs: one per non-empty, non-comment line.
fn split_secret_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Split an env value into specs on commas and/or whitespace.
fn split_secret_list(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse one `--secret-key` spec: the bare key hex. The keyring is global to
/// the run — every key is tried against every sealed item — so a spec carries
/// no item index.
fn parse_secret_key(raw: &str) -> Result<Vec<u8>, CliError> {
    if raw.contains(':') {
        // Report only the length: the value is a recipient secret key, so it must
        // never be echoed back into the terminal, shell history, or CI logs.
        return Err(CliError::input(format!(
            "verify: --secret-key expects bare hex (no scheme prefix); got a {}-char value \
             containing ':' (keys are tried against every sealed item, so there is no per-item index)",
            raw.chars().count()
        )));
    }
    hex_to_bytes(raw).map_err(|e| CliError::input(format!("verify: --secret-key {e}")))
}

/// Default profile discriminator when the user does not pass `--profile`:
/// at least one recipient secret key → `recipient-sealed`; otherwise `signed`.
fn choose_profile(args: &VerifyArgs, have_secret_keys: bool) -> Result<Profile, CliError> {
    if let Some(name) = &args.profile {
        return PROFILES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, p)| *p)
            .ok_or_else(|| {
                CliError::input(format!(
                    "verify: --profile must be one of {{core, signed, sealed, recipient-sealed}}; got \"{name}\""
                ))
            });
    }
    if have_secret_keys {
        return Ok(Profile::RecipientSealed);
    }
    Ok(Profile::Signed)
}

/// Run the `verify` command.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for CLI-input failures; otherwise returns an
/// error carrying the verifier's own exit code (`1` / `2` / `3`) with an empty
/// message so the report — already emitted — is the user-facing output.
pub fn run(args: VerifyArgs) -> Result<(), CliError> {
    if args.tx_hash.len() != 64 || !args.tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "verify: <tx-hash> must be 64 hex chars; got \"{}\"",
            args.tx_hash
        )));
    }
    let threshold = parse_threshold(args.threshold.as_deref())?;
    let secret_key_specs = collect_secret_key_specs(&args, &SystemSecretEnv)?;
    let mut secret_keys: Vec<Vec<u8>> = Vec::new();
    for raw in &secret_key_specs {
        secret_keys.push(parse_secret_key(raw)?);
    }
    let profile = choose_profile(&args, !secret_keys.is_empty())?;

    let config = read_config_file(&SystemConfigEnv)?;
    let flags = GatewayFlags {
        gateway: args.cardano_gateway.clone(),
        blockfrost: args.blockfrost.clone(),
        arweave_gateway: args.arweave_gateway.clone(),
        ipfs_gateway: args.ipfs_gateway.clone(),
        threshold,
        deny_host: args.deny_host.clone(),
        deny_hosts_replace: args.deny_hosts_replace,
    };
    let resolved = resolve_gateways(&flags, &SystemGatewayEnv, config.as_ref())?;
    let input = build_verify_input(&args, profile, &resolved, secret_keys);

    let report = verify_tx(&input);

    if args.json {
        let dict = verify_report_to_dict(&report);
        let rendered = if args.pretty {
            serde_json::to_string_pretty(&dict)
        } else {
            serde_json::to_string(&dict)
        }
        .expect("VerifyReport dict serialises");
        println!("{rendered}");
    } else {
        render_human_report(&report);
    }

    exit_code_for_report(&report)
}

/// Map the parsed CLI options onto the SDK verifier's input shape.
fn build_verify_input(
    args: &VerifyArgs,
    profile: Profile,
    resolved: &ResolvedGateways,
    secret_keys: Vec<Vec<u8>>,
) -> VerifyTxInput<'static> {
    // SSRF posture: the resolver already folded the built-in deny list into
    // the effective set — user entries only ever extend it, unless replace
    // mode was chosen explicitly (where an empty set means the user took over
    // egress policy entirely).
    let mut input = VerifyTxInput::new(args.tx_hash.to_lowercase());
    input.profile = profile;
    input.cardano_gateway_chain = Some(resolved.cardano_gateway_chain.clone());
    input.arweave_gateway_chain = Some(resolved.arweave_gateway_chain.clone());
    input.ipfs_gateway_chain = resolved.ipfs_gateway_chain.clone();
    input.blockfrost_project_id = resolved.blockfrost_project_id.clone();
    input.confirmation_depth_threshold = Some(
        resolved
            .confirmation_depth_threshold
            .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT),
    );
    input.deny_hosts = Some(resolved.deny_hosts.clone());
    if !secret_keys.is_empty() {
        input.decryption = Some(
            secret_keys
                .into_iter()
                .map(|recipient_secret_key| Decryption::Recipient {
                    recipient_secret_key,
                })
                .collect(),
        );
    }
    // `--no-fetch` flips the verifier's master content-fetch switch: item-URI,
    // ciphertext, and Merkle leaves-list downloads are suppressed and those
    // claims report as not checked. The transaction itself is still resolved
    // from the Cardano gateway chain — the switch governs content, not the
    // metadata lookup — so the resolved gateway chains stay as configured. (An
    // emptied chain would not mean "offline" anyway: the verifier substitutes
    // its built-in defaults for an absent or empty Arweave chain.)
    if args.no_fetch {
        input.fetch_content = false;
    }
    input
}

/// Map a verifier report onto the CLI exit-code contract.
///
/// The verdict's paired exit code (`0` valid / `1` failed / `2` unverifiable /
/// `3` pending) is passed through verbatim; a non-zero code becomes a silent
/// [`CliError`] (the already-emitted report is the user-facing output, so no
/// extra stderr line is added).
pub fn exit_code_for_report(report: &cardanowall::verifier::VerifyReport) -> Result<(), CliError> {
    let code = i32::from(report.verdict.exit_code());
    if code == 0 {
        Ok(())
    } else {
        Err(CliError {
            code,
            message: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args(tx_hash: &str) -> VerifyArgs {
        VerifyArgs {
            tx_hash: tx_hash.to_string(),
            profile: None,
            cardano_gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            threshold: None,
            deny_host: vec![],
            deny_hosts_replace: false,
            secret_key: vec![],
            secret_key_file: None,
            secret_key_stdin: false,
            no_fetch: false,
            json: true,
            pretty: false,
        }
    }

    #[test]
    fn rejects_non_hex_tx_hash() {
        assert_eq!(run(base_args("not-a-hex-string")).unwrap_err().code, 4);
    }

    #[test]
    fn rejects_bad_threshold() {
        assert_eq!(parse_threshold(Some("banana")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("-1")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("15")).unwrap(), Some(15));
        assert_eq!(parse_threshold(None).unwrap(), None);
        // The full u32 range is accepted; anything beyond it is rejected, not
        // wrapped (4294967297 must never become 1).
        assert_eq!(parse_threshold(Some("4294967295")).unwrap(), Some(u32::MAX));
        assert_eq!(parse_threshold(Some("4294967296")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("4294967297")).unwrap_err().code, 4);
        // Non-canonical spellings fail the round-trip comparison.
        assert_eq!(parse_threshold(Some("+15")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("015")).unwrap_err().code, 4);
    }

    #[test]
    fn no_fetch_suppresses_content_fetch_and_leaves_gateway_chains_intact() {
        let resolved = ResolvedGateways {
            cardano_gateway_chain: vec!["https://cardano.example".to_string()],
            arweave_gateway_chain: vec!["https://arweave.example".to_string()],
            ipfs_gateway_chain: Some(vec!["https://ipfs.example".to_string()]),
            ..ResolvedGateways::default()
        };
        let mut args = base_args(&"0".repeat(64));

        args.no_fetch = true;
        let input = build_verify_input(&args, Profile::Signed, &resolved, vec![]);
        assert!(!input.fetch_content);
        // The chains must stay as resolved: the tx lookup still runs, and an
        // emptied Arweave chain would fall back to the verifier's built-in
        // defaults instead of meaning "no fetch".
        assert_eq!(
            input.cardano_gateway_chain,
            Some(vec!["https://cardano.example".to_string()])
        );
        assert_eq!(
            input.arweave_gateway_chain,
            Some(vec!["https://arweave.example".to_string()])
        );
        assert_eq!(
            input.ipfs_gateway_chain,
            Some(vec!["https://ipfs.example".to_string()])
        );

        args.no_fetch = false;
        assert!(build_verify_input(&args, Profile::Signed, &resolved, vec![]).fetch_content);
    }

    #[test]
    fn secret_key_parses_bare_hex_and_rejects_indexed_specs() {
        let key = parse_secret_key(&"cd".repeat(32)).unwrap();
        assert_eq!(key.len(), 32);
        // The keyring is global to the run; a per-item index prefix is not a
        // valid spec and must fail as CLI input (exit 4) with a clear message
        // that reports only the length, never the key bytes.
        let indexed = format!("3:{}", "ab".repeat(32));
        let err = parse_secret_key(&indexed).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("bare hex"));
        assert!(!err.message.contains(&"ab".repeat(32)));
        assert!(!err.message.contains(&indexed));
        assert_eq!(parse_secret_key("not-hex").unwrap_err().code, 4);
    }

    #[test]
    fn secret_key_hex_error_does_not_leak_the_key() {
        // A 64-char secret-shaped value with one stray byte must reject without
        // echoing the value (the shared hex decoder enforces this).
        let mut bad = "ab".repeat(31);
        bad.push_str("ax");
        let err = parse_secret_key(&bad).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&bad));
        assert!(!err.message.contains(&"ab".repeat(31)));
    }

    #[test]
    fn unknown_profile_is_input_error() {
        let mut args = base_args(&"0".repeat(64));
        args.profile = Some("nope".to_string());
        assert_eq!(choose_profile(&args, false).unwrap_err().code, 4);
    }

    #[test]
    fn secret_key_specs_from_a_single_flag_source_resolve_and_warn() {
        use crate::secret::test_support::FakeSecretEnv;
        let mut args = base_args(&"0".repeat(64));
        args.secret_key = vec!["ab".repeat(32)];
        let env = FakeSecretEnv::default();
        let specs = collect_secret_key_specs(&args, &env).unwrap();
        assert_eq!(specs, vec!["ab".repeat(32)]);
        // The argv path warns through the captured sink, never echoing the key.
        let warnings = env.warnings.borrow();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("insecure"));
        assert!(warnings[0].contains("--secret-key"));
        assert!(!warnings[0].contains(&"ab".repeat(32)));
        // And drives the auto profile to recipient-sealed.
        assert_eq!(
            choose_profile(&args, !specs.is_empty()).unwrap(),
            Profile::RecipientSealed
        );
    }

    #[test]
    fn secret_key_specs_from_more_than_one_source_are_a_conflict_error() {
        use crate::secret::test_support::FakeSecretEnv;
        // argv flag AND env var: verify shares the same single-source rule as the
        // rest of the CLI, so this must hard-error rather than silently first-win.
        let mut args = base_args(&"0".repeat(64));
        args.secret_key = vec!["ab".repeat(32)];
        let env = FakeSecretEnv {
            vars: std::collections::HashMap::from([(
                "CARDANOWALL_RECIPIENT_KEY".to_string(),
                "cd".repeat(32),
            )]),
            ..FakeSecretEnv::default()
        };
        let err = collect_secret_key_specs(&args, &env).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("more than one source"));
        assert!(err.message.contains("--secret-key"));
        assert!(err.message.contains("CARDANOWALL_RECIPIENT_KEY"));
        // The conflicting key bytes never appear in the message.
        assert!(!err.message.contains(&"ab".repeat(32)));
        assert!(!err.message.contains(&"cd".repeat(32)));

        // file AND argv is also a conflict (the case the old priority hid).
        let mut file_args = base_args(&"0".repeat(64));
        file_args.secret_key = vec!["ab".repeat(32)];
        file_args.secret_key_file = Some("/keys".to_string());
        let file_env = FakeSecretEnv {
            files: std::collections::HashMap::from([(
                "/keys".to_string(),
                format!("{}\n", "cd".repeat(32)),
            )]),
            ..FakeSecretEnv::default()
        };
        let err = collect_secret_key_specs(&file_args, &file_env).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--secret-key-file"));
        assert!(err.message.contains("--secret-key"));
    }

    #[test]
    fn secret_key_specs_from_env_when_no_flag() {
        use crate::secret::test_support::FakeSecretEnv;
        let args = base_args(&"0".repeat(64));
        let env = FakeSecretEnv {
            vars: std::collections::HashMap::from([(
                "CARDANOWALL_RECIPIENT_KEY".to_string(),
                format!("{}, {}", "ab".repeat(32), "cd".repeat(32)),
            )]),
            ..FakeSecretEnv::default()
        };
        let specs = collect_secret_key_specs(&args, &env).unwrap();
        assert_eq!(specs.len(), 2);
        // The env source is silent — no argv warning.
        assert!(env.warnings.borrow().is_empty());
    }

    #[test]
    fn verify_args_debug_redacts_secret_keys_and_blockfrost() {
        // A `{:?}` of VerifyArgs must never surface the recipient key bytes or
        // the Blockfrost project id (an API credential); non-secret fields stay
        // visible for debugging.
        let mut args = base_args(&"0".repeat(64));
        args.secret_key = vec!["ab".repeat(32), "cd".repeat(32)];
        args.blockfrost = Some("mainnetSECRETprojectid".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains(&"cd".repeat(32)));
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(rendered.contains("redacted"));
        // The tx hash is not secret and stays visible.
        assert!(rendered.contains(&"0".repeat(64)));
    }
}
