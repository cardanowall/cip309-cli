//! Reads `~/.cardanowall/config.toml` (or the path overridden by
//! `CARDANOWALL_CONFIG_PATH`).
//!
//! A missing default file is NOT an error — it returns `None`. An explicit
//! `CARDANOWALL_CONFIG_PATH` that does not resolve, or a TOML parse error, is a
//! CLI input error (exit `4`) so the user sees a clear failure. Unknown top-level
//! keys emit a stderr warning but do not fail the read.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::util::CliError;

/// One or many strings — config values that accept either a scalar or a list.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringOrList {
    /// A single value.
    One(String),
    /// A list of values.
    Many(Vec<String>),
}

impl StringOrList {
    /// Flatten to a `Vec`, dropping empties — the resolver consumes a uniform list.
    #[must_use]
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrList::One(s) => {
                if s.is_empty() {
                    Vec::new()
                } else {
                    vec![s.clone()]
                }
            }
            StringOrList::Many(v) => v.iter().filter(|s| !s.is_empty()).cloned().collect(),
        }
    }
}

/// One named service-gateway profile: a base URL plus an optional opaque API key.
///
/// This is NOT a login — the gateway API is key-only — so the profile just pairs
/// an endpoint with the bearer the user forwards to it. Persisted under
/// `[gateways.<name>]` in `config.toml`.
///
/// `api_key` is a bearer token, so `Debug` is hand-written to redact it (serde
/// still round-trips the real key to/from disk, which is the intended store);
/// no `{:?}`, log, or assert-failure path can surface the key.
#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayProfile {
    /// The service-gateway base URL — the full base including the API version
    /// segment (e.g. `https://gateway.example.com/api/v1`). The SDK appends only
    /// the resource path to it.
    pub base_url: String,
    /// The opaque bearer API key forwarded to this gateway, when set.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub api_key: Option<String>,
}

impl std::fmt::Debug for GatewayProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayProfile")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// The parsed `config.toml` shape. Every field is optional; the gateway resolver
/// applies precedence and defaults.
///
/// `blockfrost_project_id` is a Blockfrost API credential and `gateways` carries
/// bearer tokens; `Debug` is hand-written to redact the project id (each profile
/// redacts its own key) so no `{:?}`, log, or assert-failure path surfaces a
/// credential. Serde still round-trips the real values to/from disk, the
/// intended store.
#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CardanoWallConfig {
    /// Cardano gateway URL(s) (Koios-compatible).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cardano_gateway: Option<StringOrList>,
    /// Blockfrost project id (enables the Blockfrost fallback).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub blockfrost_project_id: Option<String>,
    /// Arweave gateway URL(s).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arweave_gateway: Option<StringOrList>,
    /// IPFS gateway URL(s).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ipfs_gateway: Option<StringOrList>,
    /// Confirmation-depth threshold.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confirmation_depth_threshold: Option<i64>,
    /// Extra deny-host patterns (appended to the built-in egress deny list).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deny_host: Option<Vec<String>>,
    /// Make the `deny_host` entries REPLACE the built-in egress deny list
    /// instead of appending to it (replacing with none disables the list).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deny_hosts_replace: Option<bool>,
    /// The active service-gateway profile name (`gateway use <name>`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default_gateway: Option<String>,
    /// The named service-gateway profiles (`[gateways.<name>]`). A `BTreeMap` so
    /// the on-disk order is stable (deterministic round-trips).
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub gateways: BTreeMap<String, GatewayProfile>,
}

impl std::fmt::Debug for CardanoWallConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardanoWallConfig")
            .field("cardano_gateway", &self.cardano_gateway)
            .field(
                "blockfrost_project_id",
                &self.blockfrost_project_id.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway", &self.arweave_gateway)
            .field("ipfs_gateway", &self.ipfs_gateway)
            .field(
                "confirmation_depth_threshold",
                &self.confirmation_depth_threshold,
            )
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            .field("default_gateway", &self.default_gateway)
            // Each profile redacts its own api_key via GatewayProfile::Debug.
            .field("gateways", &self.gateways)
            .finish()
    }
}

impl CardanoWallConfig {
    /// The active gateway profile: the one named by `default_gateway`, if it
    /// resolves to a defined profile.
    #[must_use]
    pub fn active_gateway(&self) -> Option<&GatewayProfile> {
        self.default_gateway
            .as_deref()
            .and_then(|name| self.gateways.get(name))
    }

    /// Select the gateway profile a network command should use: the one named by
    /// `--gateway-profile <name>` when given, else the config `default_gateway`.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] (exit `4`) when an explicit `--gateway-profile` names
    /// a profile that is not defined.
    pub fn select_gateway<'a>(
        &'a self,
        requested: Option<&str>,
        cmd: &str,
    ) -> Result<Option<&'a GatewayProfile>, CliError> {
        match requested.map(str::trim).filter(|s| !s.is_empty()) {
            Some(name) => self.gateways.get(name).map(Some).ok_or_else(|| {
                CliError::input(format!(
                    "{cmd}: no gateway profile named \"{name}\" (add one with 'cardanowall gateway add')"
                ))
            }),
            None => Ok(self.active_gateway()),
        }
    }
}

/// The environment + filesystem surface the reader needs, injected for tests.
pub trait ConfigEnv {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;
    /// The user's home directory, when known.
    fn home_dir(&self) -> Option<PathBuf>;
    /// Read a file to a UTF-8 string; `Err(None)` means "not found".
    fn read_to_string(&self, path: &std::path::Path) -> Result<String, Option<std::io::Error>>;
    /// Write a diagnostic line to stderr.
    fn warn(&self, message: &str);
}

/// The production environment: real env vars, real home dir, real filesystem,
/// real stderr.
pub struct SystemConfigEnv;

impl ConfigEnv for SystemConfigEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        // HOME on Unix, USERPROFILE on Windows — the same locations `dirs` checks,
        // without pulling the crate.
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    }

    fn read_to_string(&self, path: &std::path::Path) -> Result<String, Option<std::io::Error>> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(None),
            Err(e) => Err(Some(e)),
        }
    }

    fn warn(&self, message: &str) {
        eprintln!("{message}");
    }
}

/// Read the config file, applying the `CARDANOWALL_CONFIG_PATH` override.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when an explicit config path is set but
/// missing, when the file cannot be read for another reason, or when the TOML
/// fails to parse / carries a malformed value.
pub fn read_config_file(env: &dyn ConfigEnv) -> Result<Option<CardanoWallConfig>, CliError> {
    let explicit = env.var("CARDANOWALL_CONFIG_PATH").filter(|p| !p.is_empty());
    let path = match &explicit {
        Some(p) => PathBuf::from(p),
        None => match env.home_dir() {
            Some(home) => home.join(".cardanowall").join("config.toml"),
            None => return Ok(None),
        },
    };

    let raw = match env.read_to_string(&path) {
        Ok(raw) => raw,
        Err(None) => {
            if explicit.is_some() {
                return Err(CliError::input(format!(
                    "config: CARDANOWALL_CONFIG_PATH points at a file that does not exist: {}",
                    path.display()
                )));
            }
            return Ok(None);
        }
        Err(Some(e)) => {
            return Err(CliError::input(format!(
                "config: cannot read {}: {e}",
                path.display()
            )));
        }
    };

    parse_config_str(&raw, &path, env).map(Some)
}

/// Parse a config TOML string: warn on unknown keys, then strict-parse the known
/// keys. Shared by the read path and the gateway-edit path so both treat unknown
/// keys and malformed values identically.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the TOML fails to parse or a value is the
/// wrong type.
pub fn parse_config_str(
    raw: &str,
    path: &std::path::Path,
    env: &dyn ConfigEnv,
) -> Result<CardanoWallConfig, CliError> {
    // First parse permissively to surface unknown keys as warnings, then parse
    // strictly to enforce field types. A permissive `toml::Table` parse never
    // rejects unknown keys.
    if let Ok(table) = raw.parse::<toml::Table>() {
        for key in table.keys() {
            if !KNOWN_KEYS.contains(&key.as_str()) {
                env.warn(&format!(
                    "warning: unknown key \"{key}\" in {} (ignored)",
                    path.display()
                ));
            }
        }
    }

    // Strict parse: reject malformed values, but tolerate unknown keys by
    // stripping them first (we already warned). We re-table the permissive parse
    // restricted to known keys.
    let filtered = filter_known_keys(raw);
    toml::from_str(&filtered).map_err(|e| {
        // The config carries credentials (api_key, blockfrost_project_id). The
        // toml error's Display — and its message() — echo the offending value and
        // the surrounding source line verbatim, so neither may reach the user.
        // Report only the location, derived from the error's structured span
        // against the (filtered) source, never any value-bearing text.
        CliError::input(format!(
            "config: TOML parse failed at {} ({})",
            path.display(),
            sanitized_toml_location(&e, &filtered),
        ))
    })
}

/// Describe a toml deserialize error by LOCATION ONLY — never its message or
/// Display, both of which echo the offending value and source line verbatim
/// (a credential leak for a config carrying api_key / blockfrost_project_id).
///
/// The location is computed from the error's structured byte span against the
/// source, counting newlines and characters in the prefix before the span start;
/// the offending bytes themselves are never read.
fn sanitized_toml_location(error: &toml::de::Error, source: &str) -> String {
    match error.span() {
        Some(span) => {
            let start = span.start.min(source.len());
            let prefix = &source[..start];
            let line = prefix.matches('\n').count() + 1;
            let col = prefix
                .rsplit('\n')
                .next()
                .map_or(1, |last_line| last_line.chars().count() + 1);
            format!("line {line}, column {col}")
        }
        None => "location unavailable".to_string(),
    }
}

const KNOWN_KEYS: [&str; 9] = [
    "cardano_gateway",
    "blockfrost_project_id",
    "arweave_gateway",
    "ipfs_gateway",
    "confirmation_depth_threshold",
    "deny_host",
    "deny_hosts_replace",
    "default_gateway",
    "gateways",
];

/// The resolved on-disk config path: `CARDANOWALL_CONFIG_PATH` when set, else
/// `<HOME>/.cardanowall/config.toml`.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when no home directory is discoverable and no
/// explicit override is set (so a writer has nowhere to create the file).
pub fn config_path(env: &dyn ConfigEnv) -> Result<PathBuf, CliError> {
    if let Some(explicit) = env.var("CARDANOWALL_CONFIG_PATH").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    match env.home_dir() {
        Some(home) => Ok(home.join(".cardanowall").join("config.toml")),
        None => Err(CliError::input(
            "config: no home directory found and CARDANOWALL_CONFIG_PATH is unset; \
             set CARDANOWALL_CONFIG_PATH to choose where config.toml lives",
        )),
    }
}

/// Re-serialise the parsed TOML keeping only known keys, so the strict
/// `deny_unknown_fields` parse never trips on a key we already warned about.
fn filter_known_keys(raw: &str) -> String {
    let Ok(table) = raw.parse::<toml::Table>() else {
        // Let the strict parse surface the real error.
        return raw.to_string();
    };
    let mut kept = toml::Table::new();
    for (k, v) in table {
        if KNOWN_KEYS.contains(&k.as_str()) {
            kept.insert(k, v);
        }
    }
    // Render via `Table`'s Display, which emits canonical TOML and is
    // infallible. `toml::to_string(&Value::Table(..))` goes through the value
    // serializer, which can return an error on re-serialisation; falling back
    // to `raw` there would smuggle the unknown keys we just stripped past the
    // strict parse.
    kept.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeEnv {
        vars: HashMap<String, String>,
        files: HashMap<PathBuf, String>,
        warnings: RefCell<Vec<String>>,
    }

    impl ConfigEnv for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
        fn home_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/nonexistent-home"))
        }
        fn read_to_string(&self, path: &std::path::Path) -> Result<String, Option<std::io::Error>> {
            self.files.get(path).cloned().ok_or(None)
        }
        fn warn(&self, message: &str) {
            self.warnings.borrow_mut().push(message.to_string());
        }
    }

    fn env_with(files: &[(&str, &str)], vars: &[(&str, &str)]) -> FakeEnv {
        FakeEnv {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            files: files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), c.to_string()))
                .collect(),
            warnings: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn missing_default_file_returns_none() {
        let env = env_with(&[], &[]);
        assert_eq!(read_config_file(&env).unwrap(), None);
    }

    #[test]
    fn explicit_missing_path_is_input_error() {
        let env = env_with(&[], &[("CARDANOWALL_CONFIG_PATH", "/nope/config.toml")]);
        let err = read_config_file(&env).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn parses_valid_toml() {
        let env = env_with(
            &[(
                "/c.toml",
                "cardano_gateway = \"https://api.koios.rest/api/v1\"\narweave_gateway = [\"https://a.example\", \"https://b.example\"]\nconfirmation_depth_threshold = 7\n",
            )],
            &[("CARDANOWALL_CONFIG_PATH", "/c.toml")],
        );
        let cfg = read_config_file(&env).unwrap().unwrap();
        assert_eq!(
            cfg.cardano_gateway.unwrap().to_vec(),
            vec!["https://api.koios.rest/api/v1"]
        );
        assert_eq!(
            cfg.arweave_gateway.unwrap().to_vec(),
            vec!["https://a.example", "https://b.example"]
        );
        assert_eq!(cfg.confirmation_depth_threshold, Some(7));
    }

    #[test]
    fn malformed_toml_is_input_error() {
        let env = env_with(
            &[("/bad.toml", "this is = = = not valid toml")],
            &[("CARDANOWALL_CONFIG_PATH", "/bad.toml")],
        );
        assert_eq!(read_config_file(&env).unwrap_err().code, 4);
    }

    #[test]
    fn malformed_toml_error_never_echoes_planted_credentials() {
        // A type error: confirmation_depth_threshold is an integer field, so a
        // string value triggers the strict-parse deserialize error whose raw
        // Display would echo the offending value verbatim. Plant a recognizable
        // secret-shaped value and a credential line, then prove neither reaches
        // the sanitized error (location-only).
        const PLANTED_THRESHOLD: &str = "SECRETthresholdVALUE";
        const PLANTED_BLOCKFROST: &str = "mainnetSECRETprojectid";
        let raw = format!(
            "blockfrost_project_id = \"{PLANTED_BLOCKFROST}\"\n\
             confirmation_depth_threshold = \"{PLANTED_THRESHOLD}\"\n"
        );
        let env = env_with(
            &[("/leak.toml", raw.as_str())],
            &[("CARDANOWALL_CONFIG_PATH", "/leak.toml")],
        );
        let err = read_config_file(&env).unwrap_err();
        assert_eq!(err.code, 4);
        // Neither planted credential may appear in the error message.
        assert!(
            !err.message.contains(PLANTED_THRESHOLD),
            "error leaked the planted threshold value: {}",
            err.message
        );
        assert!(
            !err.message.contains(PLANTED_BLOCKFROST),
            "error leaked the planted blockfrost credential: {}",
            err.message
        );
        // It still reports a usable location so the user can self-diagnose.
        assert!(err.message.contains("line"));
        assert!(err.message.contains("column"));
    }

    #[test]
    fn syntax_error_on_credential_line_never_echoes_it() {
        // A pure syntax error (unterminated string) whose source-line snippet the
        // toml Display would print verbatim — including the credential on that
        // line. The sanitized boundary reports location only.
        const PLANTED_KEY: &str = "superSECRETbearerTOKEN";
        let raw = format!(
            "[gateways.prod]\n\
             base_url = \"https://gw.example/api/v1\"\n\
             api_key = \"{PLANTED_KEY}\n"
        );
        let env = env_with(
            &[("/syntax.toml", raw.as_str())],
            &[("CARDANOWALL_CONFIG_PATH", "/syntax.toml")],
        );
        let err = read_config_file(&env).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(
            !err.message.contains(PLANTED_KEY),
            "error leaked the planted api_key: {}",
            err.message
        );
        assert!(err.message.contains("line"));
    }

    #[test]
    fn unknown_key_warns_but_parses() {
        let env = env_with(
            &[(
                "/u.toml",
                "cardano_gateway = \"https://api.koios.rest\"\nunknown_key = \"ignored\"\n",
            )],
            &[("CARDANOWALL_CONFIG_PATH", "/u.toml")],
        );
        let cfg = read_config_file(&env).unwrap().unwrap();
        assert!(cfg.cardano_gateway.is_some());
        assert!(env
            .warnings
            .borrow()
            .iter()
            .any(|w| w.contains("unknown_key")));
    }

    #[test]
    fn gateway_profile_debug_redacts_api_key() {
        let profile = GatewayProfile {
            base_url: "https://gw.example/api/v1".to_string(),
            api_key: Some("super-secret-bearer".to_string()),
        };
        let rendered = format!("{profile:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }

    #[test]
    fn config_debug_redacts_blockfrost_and_profile_keys() {
        let mut config = CardanoWallConfig {
            blockfrost_project_id: Some("mainnetSECRETprojectid".to_string()),
            ..CardanoWallConfig::default()
        };
        config.gateways.insert(
            "prod".to_string(),
            GatewayProfile {
                base_url: "https://gw.example/api/v1".to_string(),
                api_key: Some("super-secret-bearer".to_string()),
            },
        );
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        // Non-secret fields stay visible.
        assert!(rendered.contains("https://gw.example/api/v1"));
        assert!(rendered.contains("prod"));
    }
}
