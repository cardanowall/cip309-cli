//! Resolve the gateway slots (cardano, arweave, ipfs, blockfrost) plus the two
//! scalar slots (threshold, deny-hosts) using the precedence:
//!
//! ```text
//! flag (repeatable / comma-list)  →
//! env  (comma-separated)          →
//! config-file (string or array)   →
//! built-in default chain
//! ```
//!
//! First non-empty source wins; lower-precedence sources are NOT merged in. URL
//! shape is validated here (https-only, except loopback).
//!
//! Deny-hosts is the one slot with a second axis: the user's entries (picked
//! by the same first-non-empty precedence) are APPENDED to the built-in SSRF
//! deny list by default, so naming an extra host can never silently drop the
//! loopback/metadata protection. The explicit replace toggle
//! (`--deny-hosts-replace` / `CARDANOWALL_DENY_HOSTS_REPLACE` /
//! `deny_hosts_replace`) makes the user's entries the WHOLE list — the expert
//! escape hatch for a private-network resolver the defaults would block —
//! and replacing with no entries at all disables the deny list entirely.

use cardanowall::verifier::content::ARWEAVE_GATEWAY_DEFAULTS;
use cardanowall::verifier::fetch::DENY_HOSTS_DEFAULT;
use cardanowall::verifier::KOIOS_MAINNET_URL;

use crate::config::read_config_file::CardanoWallConfig;
use crate::util::CliError;

/// The resolved gateway chains and scalars the verifier / inbox paths consume.
///
/// `blockfrost_project_id` is a Blockfrost API credential, so `Debug` is
/// hand-written to redact it: no `{:?}`, log, or assert-failure path can surface
/// the project id.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResolvedGateways {
    /// Cardano (Koios-compatible) gateway chain.
    pub cardano_gateway_chain: Vec<String>,
    /// Blockfrost project id, when configured.
    pub blockfrost_project_id: Option<String>,
    /// Arweave gateway chain.
    pub arweave_gateway_chain: Vec<String>,
    /// IPFS gateway chain, when configured (no baked-in default).
    pub ipfs_gateway_chain: Option<Vec<String>>,
    /// Confirmation-depth threshold, when set anywhere.
    pub confirmation_depth_threshold: Option<u32>,
    /// The effective egress deny list for fetches whose URLs derive from
    /// untrusted on-chain records: the built-in defaults plus the user's
    /// entries, or the user's entries alone under replace mode. May be empty
    /// (replace mode with no entries — the deny list is disabled).
    pub deny_hosts: Vec<String>,
}

impl std::fmt::Debug for ResolvedGateways {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedGateways")
            .field("cardano_gateway_chain", &self.cardano_gateway_chain)
            .field(
                "blockfrost_project_id",
                &self.blockfrost_project_id.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway_chain", &self.arweave_gateway_chain)
            .field("ipfs_gateway_chain", &self.ipfs_gateway_chain)
            .field(
                "confirmation_depth_threshold",
                &self.confirmation_depth_threshold,
            )
            .field("deny_hosts", &self.deny_hosts)
            .finish()
    }
}

/// Flag inputs, already collected by clap (empty vec = flag not given).
///
/// `blockfrost` is a Blockfrost API credential, so `Debug` is hand-written to
/// redact it: no `{:?}`, log, or panic path can surface the project id.
#[derive(Clone, Default)]
pub struct GatewayFlags {
    /// `--cardano-gateway` (repeatable).
    pub gateway: Vec<String>,
    /// `--blockfrost`.
    pub blockfrost: Option<String>,
    /// `--arweave-gateway` (repeatable).
    pub arweave_gateway: Vec<String>,
    /// `--ipfs-gateway` (repeatable).
    pub ipfs_gateway: Vec<String>,
    /// `--threshold` (already parsed to a non-negative integer).
    pub threshold: Option<u32>,
    /// `--deny-host` (repeatable).
    pub deny_host: Vec<String>,
    /// `--deny-hosts-replace`.
    pub deny_hosts_replace: bool,
}

impl std::fmt::Debug for GatewayFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayFlags")
            .field("gateway", &self.gateway)
            .field(
                "blockfrost",
                &self.blockfrost.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway", &self.arweave_gateway)
            .field("ipfs_gateway", &self.ipfs_gateway)
            .field("threshold", &self.threshold)
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            .finish()
    }
}

/// The environment lookups the resolver needs, injected for tests.
pub trait GatewayEnv {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;
}

/// The production env: real process environment.
pub struct SystemGatewayEnv;

impl GatewayEnv for SystemGatewayEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

fn default_cardano_chain() -> Vec<String> {
    vec![KOIOS_MAINNET_URL.to_string()]
}

fn default_arweave_chain() -> Vec<String> {
    // Single source of truth: the SDK's `ar://` gateway rotation, so the CLI
    // resolves the same gateways the SDK verifier walk does.
    ARWEAVE_GATEWAY_DEFAULTS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Split a comma-separated env value into a trimmed, non-empty list.
fn split_env_list(value: Option<&str>) -> Option<Vec<String>> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let list: Vec<String> = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

fn pick_chain(
    flag: &[String],
    env: Option<&str>,
    cfg: Option<Vec<String>>,
    fallback: Vec<String>,
) -> Vec<String> {
    if !flag.is_empty() {
        return flag.to_vec();
    }
    if let Some(list) = split_env_list(env) {
        return list;
    }
    if let Some(list) = cfg {
        if !list.is_empty() {
            return list;
        }
    }
    fallback
}

fn pick_scalar_string(flag: Option<&str>, env: Option<&str>, cfg: Option<&str>) -> Option<String> {
    if let Some(f) = flag {
        if !f.is_empty() {
            return Some(f.to_string());
        }
    }
    if let Some(e) = env {
        let t = e.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(c) = cfg {
        if !c.is_empty() {
            return Some(c.to_string());
        }
    }
    None
}

fn pick_threshold(
    flag: Option<u32>,
    env: Option<&str>,
    cfg: Option<i64>,
) -> Result<Option<u32>, CliError> {
    if let Some(f) = flag {
        return Ok(Some(f));
    }
    if let Some(e) = env {
        let t = e.trim();
        if !t.is_empty() {
            // Parse as `u32` so negatives and values beyond `u32::MAX` are
            // rejected outright rather than wrapped.
            let n: u32 = t.parse().map_err(|_| {
                CliError::input(format!(
                    "verify: CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD must be a non-negative integer; got \"{e}\""
                ))
            })?;
            return Ok(Some(n));
        }
    }
    if let Some(c) = cfg {
        // TOML integers are i64; the checked conversion rejects negatives and
        // values beyond `u32::MAX` rather than wrapping them.
        let n = u32::try_from(c).map_err(|_| {
            CliError::input(format!(
                "verify: config-file confirmation_depth_threshold must be a non-negative integer; got {c}"
            ))
        })?;
        return Ok(Some(n));
    }
    Ok(None)
}

/// Resolve the deny-hosts replace toggle: flag presence wins, then the env
/// variable, then the config key; the default is append mode.
fn pick_deny_hosts_replace(
    flag: bool,
    env: Option<&str>,
    cfg: Option<bool>,
) -> Result<bool, CliError> {
    if flag {
        return Ok(true);
    }
    if let Some(e) = env {
        let t = e.trim();
        if !t.is_empty() {
            return match t.to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                _ => Err(CliError::input(format!(
                    "verify: CARDANOWALL_DENY_HOSTS_REPLACE must be true/false/1/0; got \"{e}\""
                ))),
            };
        }
    }
    Ok(cfg.unwrap_or(false))
}

/// Compute the effective deny list. The user's entries come from the first
/// non-empty source (flag → env → config, like every other slot); append mode
/// unions them with the built-in defaults, replace mode makes them the whole
/// list. The union is deduplicated on the exact entry string, defaults first,
/// so the effective order is stable.
fn pick_deny_hosts(
    flag: &[String],
    env: Option<&str>,
    cfg: Option<&[String]>,
    replace: bool,
) -> Vec<String> {
    let user: Vec<String> = if !flag.is_empty() {
        flag.to_vec()
    } else if let Some(list) = split_env_list(env) {
        list
    } else {
        cfg.map(<[String]>::to_vec).unwrap_or_default()
    };

    let mut effective: Vec<String> = if replace {
        Vec::new()
    } else {
        DENY_HOSTS_DEFAULT
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    };
    for entry in user {
        if !effective.contains(&entry) {
            effective.push(entry);
        }
    }
    effective
}

/// Validate a single gateway URL: https only, except http on loopback.
fn validate_url(url: &str, slot: &str) -> Result<(), CliError> {
    // Minimal scheme + host check without a URL crate: parse `scheme://host…`.
    let lowered = url.trim();
    let (scheme, rest) = match lowered.split_once("://") {
        Some(parts) => parts,
        None => {
            return Err(CliError::input(format!(
                "verify: {slot} URL is not a valid URL; got \"{url}\""
            )))
        }
    };
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("");
    // Strip a port for the loopback comparison.
    let host_only = if host.starts_with('[') {
        // bracketed IPv6 literal
        host.split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h).to_string()
    };
    match scheme {
        "https" => Ok(()),
        "http" => {
            let is_loopback = matches!(
                host_only.as_str(),
                "localhost" | "127.0.0.1" | "::1" | "[::1]"
            );
            if is_loopback {
                Ok(())
            } else {
                Err(CliError::input(format!(
                    "verify: {slot} URL must use https (http is only permitted for localhost); got \"{url}\""
                )))
            }
        }
        _ => Err(CliError::input(format!(
            "verify: {slot} URL must be https (or http on localhost); got \"{url}\""
        ))),
    }
}

fn validate_chain(chain: &[String], slot: &str) -> Result<(), CliError> {
    for url in chain {
        validate_url(url, slot)?;
    }
    Ok(())
}

/// Resolve all gateway slots, applying precedence and validating URL shape.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on an invalid URL or a malformed threshold.
pub fn resolve_gateways(
    flags: &GatewayFlags,
    env: &dyn GatewayEnv,
    config: Option<&CardanoWallConfig>,
) -> Result<ResolvedGateways, CliError> {
    let cardano_gateway_chain = pick_chain(
        &flags.gateway,
        env.var("CARDANOWALL_CARDANO_GATEWAY").as_deref(),
        config.and_then(|c| c.cardano_gateway.as_ref().map(|v| v.to_vec())),
        default_cardano_chain(),
    );
    validate_chain(&cardano_gateway_chain, "--cardano-gateway")?;

    let arweave_gateway_chain = pick_chain(
        &flags.arweave_gateway,
        env.var("CARDANOWALL_ARWEAVE_GATEWAY").as_deref(),
        config.and_then(|c| c.arweave_gateway.as_ref().map(|v| v.to_vec())),
        default_arweave_chain(),
    );
    validate_chain(&arweave_gateway_chain, "--arweave-gateway")?;

    let ipfs_gateway_chain = {
        let from_flag = &flags.ipfs_gateway;
        let from_env = split_env_list(env.var("CARDANOWALL_IPFS_GATEWAY").as_deref());
        let from_cfg = config.and_then(|c| c.ipfs_gateway.as_ref().map(|v| v.to_vec()));
        let chain = if !from_flag.is_empty() {
            Some(from_flag.clone())
        } else if let Some(list) = from_env {
            Some(list)
        } else {
            from_cfg.filter(|l| !l.is_empty())
        };
        if let Some(ref c) = chain {
            validate_chain(c, "--ipfs-gateway")?;
        }
        chain
    };

    let blockfrost_project_id = pick_scalar_string(
        flags.blockfrost.as_deref(),
        env.var("CARDANOWALL_BLOCKFROST_PROJECT_ID").as_deref(),
        config.and_then(|c| c.blockfrost_project_id.as_deref()),
    );

    let confirmation_depth_threshold = pick_threshold(
        flags.threshold,
        env.var("CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD")
            .as_deref(),
        config.and_then(|c| c.confirmation_depth_threshold),
    )?;

    let deny_hosts_replace = pick_deny_hosts_replace(
        flags.deny_hosts_replace,
        env.var("CARDANOWALL_DENY_HOSTS_REPLACE").as_deref(),
        config.and_then(|c| c.deny_hosts_replace),
    )?;
    let deny_hosts = pick_deny_hosts(
        &flags.deny_host,
        env.var("CARDANOWALL_DENY_HOST").as_deref(),
        config.and_then(|c| c.deny_host.as_deref()),
        deny_hosts_replace,
    );

    Ok(ResolvedGateways {
        cardano_gateway_chain,
        blockfrost_project_id,
        arweave_gateway_chain,
        ipfs_gateway_chain,
        confirmation_depth_threshold,
        deny_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::read_config_file::StringOrList;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<String, String>);
    impl GatewayEnv for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }
    fn env(pairs: &[(&str, &str)]) -> FakeEnv {
        FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn falls_back_to_koios_default() {
        let out = resolve_gateways(&GatewayFlags::default(), &env(&[]), None).unwrap();
        assert_eq!(out.cardano_gateway_chain, vec![KOIOS_MAINNET_URL]);
    }

    #[test]
    fn flag_overrides_env_and_config() {
        let flags = GatewayFlags {
            gateway: vec!["https://flag-1.example".to_string()],
            ..GatewayFlags::default()
        };
        let cfg = CardanoWallConfig {
            cardano_gateway: Some(StringOrList::One("https://config.example".to_string())),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(
            &flags,
            &env(&[("CARDANOWALL_CARDANO_GATEWAY", "https://env.example")]),
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(out.cardano_gateway_chain, vec!["https://flag-1.example"]);
    }

    #[test]
    fn env_comma_splits_into_chain() {
        let out = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[(
                "CARDANOWALL_CARDANO_GATEWAY",
                "https://a.example,https://b.example",
            )]),
            None,
        )
        .unwrap();
        assert_eq!(
            out.cardano_gateway_chain,
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn rejects_non_https_non_loopback() {
        let flags = GatewayFlags {
            gateway: vec!["http://evil.example".to_string()],
            ..GatewayFlags::default()
        };
        assert_eq!(
            resolve_gateways(&flags, &env(&[]), None).unwrap_err().code,
            4
        );
    }

    #[test]
    fn allows_http_loopback() {
        let flags = GatewayFlags {
            gateway: vec!["http://localhost:8080/api".to_string()],
            ..GatewayFlags::default()
        };
        assert!(resolve_gateways(&flags, &env(&[]), None).is_ok());
    }

    #[test]
    fn threshold_env_accepts_u32_max_and_rejects_beyond() {
        let max = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[("CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD", "4294967295")]),
            None,
        )
        .unwrap();
        assert_eq!(max.confirmation_depth_threshold, Some(u32::MAX));
        // Beyond u32::MAX must fail loudly (4294967297 must never become 1).
        for bad in ["4294967296", "4294967297", "-1", "banana"] {
            let err = resolve_gateways(
                &GatewayFlags::default(),
                &env(&[("CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD", bad)]),
                None,
            )
            .unwrap_err();
            assert_eq!(err.code, 4, "env threshold {bad:?} must be an input error");
        }
    }

    #[test]
    fn threshold_config_accepts_u32_max_and_rejects_beyond() {
        let cfg = |threshold: i64| CardanoWallConfig {
            confirmation_depth_threshold: Some(threshold),
            ..CardanoWallConfig::default()
        };
        let max = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[]),
            Some(&cfg(i64::from(u32::MAX))),
        )
        .unwrap();
        assert_eq!(max.confirmation_depth_threshold, Some(u32::MAX));
        for bad in [-1i64, 4_294_967_296, 4_294_967_297] {
            let err =
                resolve_gateways(&GatewayFlags::default(), &env(&[]), Some(&cfg(bad))).unwrap_err();
            assert_eq!(err.code, 4, "config threshold {bad} must be an input error");
        }
    }

    #[test]
    fn rejects_unparseable_url() {
        let flags = GatewayFlags {
            gateway: vec!["not-a-url".to_string()],
            ..GatewayFlags::default()
        };
        assert_eq!(
            resolve_gateways(&flags, &env(&[]), None).unwrap_err().code,
            4
        );
    }

    fn defaults() -> Vec<String> {
        DENY_HOSTS_DEFAULT
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    #[test]
    fn deny_hosts_default_to_the_built_in_list() {
        let out = resolve_gateways(&GatewayFlags::default(), &env(&[]), None).unwrap();
        assert_eq!(out.deny_hosts, defaults());
    }

    #[test]
    fn deny_hosts_append_to_the_defaults_from_every_source() {
        // Flag entries extend the built-in list; the defaults are never dropped.
        let flags = GatewayFlags {
            deny_host: vec!["metadata.internal".to_string()],
            ..GatewayFlags::default()
        };
        let out = resolve_gateways(&flags, &env(&[]), None).unwrap();
        let mut expected = defaults();
        expected.push("metadata.internal".to_string());
        assert_eq!(out.deny_hosts, expected);

        // Env: comma-split, appended.
        let out = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[("CARDANOWALL_DENY_HOST", "a.example, b.example")]),
            None,
        )
        .unwrap();
        let mut expected = defaults();
        expected.extend(["a.example".to_string(), "b.example".to_string()]);
        assert_eq!(out.deny_hosts, expected);

        // Config: appended.
        let cfg = CardanoWallConfig {
            deny_host: Some(vec!["c.example".to_string()]),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(&GatewayFlags::default(), &env(&[]), Some(&cfg)).unwrap();
        let mut expected = defaults();
        expected.push("c.example".to_string());
        assert_eq!(out.deny_hosts, expected);
    }

    #[test]
    fn deny_hosts_union_is_deduplicated() {
        // Re-naming a default, or repeating an entry, yields exactly one slot.
        let flags = GatewayFlags {
            deny_host: vec![
                "localhost".to_string(),
                "x.example".to_string(),
                "x.example".to_string(),
            ],
            ..GatewayFlags::default()
        };
        let out = resolve_gateways(&flags, &env(&[]), None).unwrap();
        let mut expected = defaults();
        expected.push("x.example".to_string());
        assert_eq!(out.deny_hosts, expected);
    }

    #[test]
    fn deny_hosts_user_entries_follow_first_source_wins_precedence() {
        // The flag supplies the user entries; env and config entries are NOT
        // merged in (same precedence rule as every other slot) — only the
        // built-in defaults join the union.
        let flags = GatewayFlags {
            deny_host: vec!["flag.example".to_string()],
            ..GatewayFlags::default()
        };
        let cfg = CardanoWallConfig {
            deny_host: Some(vec!["config.example".to_string()]),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(
            &flags,
            &env(&[("CARDANOWALL_DENY_HOST", "env.example")]),
            Some(&cfg),
        )
        .unwrap();
        let mut expected = defaults();
        expected.push("flag.example".to_string());
        assert_eq!(out.deny_hosts, expected);
    }

    #[test]
    fn deny_hosts_replace_makes_the_user_entries_the_whole_list() {
        let flags = GatewayFlags {
            deny_host: vec!["only.example".to_string()],
            deny_hosts_replace: true,
            ..GatewayFlags::default()
        };
        let out = resolve_gateways(&flags, &env(&[]), None).unwrap();
        assert_eq!(out.deny_hosts, vec!["only.example".to_string()]);
    }

    #[test]
    fn deny_hosts_replace_with_no_entries_disables_the_list() {
        let flags = GatewayFlags {
            deny_hosts_replace: true,
            ..GatewayFlags::default()
        };
        let out = resolve_gateways(&flags, &env(&[]), None).unwrap();
        assert!(out.deny_hosts.is_empty());
    }

    #[test]
    fn deny_hosts_replace_toggle_resolves_from_env_and_config() {
        // Env toggle + config entries: the config list replaces the defaults.
        let cfg = CardanoWallConfig {
            deny_host: Some(vec!["mirror.internal".to_string()]),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[("CARDANOWALL_DENY_HOSTS_REPLACE", "true")]),
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(out.deny_hosts, vec!["mirror.internal".to_string()]);

        // Config toggle alone.
        let cfg = CardanoWallConfig {
            deny_host: Some(vec!["mirror.internal".to_string()]),
            deny_hosts_replace: Some(true),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(&GatewayFlags::default(), &env(&[]), Some(&cfg)).unwrap();
        assert_eq!(out.deny_hosts, vec!["mirror.internal".to_string()]);

        // An explicit env "false" overrides a config "true".
        let out = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[("CARDANOWALL_DENY_HOSTS_REPLACE", "false")]),
            Some(&cfg),
        )
        .unwrap();
        let mut expected = defaults();
        expected.push("mirror.internal".to_string());
        assert_eq!(out.deny_hosts, expected);
    }

    #[test]
    fn deny_hosts_replace_env_rejects_non_boolean_values() {
        for bad in ["banana", "yes", "2"] {
            let err = resolve_gateways(
                &GatewayFlags::default(),
                &env(&[("CARDANOWALL_DENY_HOSTS_REPLACE", bad)]),
                None,
            )
            .unwrap_err();
            assert_eq!(err.code, 4, "env toggle {bad:?} must be an input error");
        }
    }

    #[test]
    fn gateway_flags_debug_redacts_blockfrost() {
        let flags = GatewayFlags {
            gateway: vec!["https://koios.example".to_string()],
            blockfrost: Some("mainnetSECRETprojectid".to_string()),
            ..GatewayFlags::default()
        };
        let rendered = format!("{flags:?}");
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(rendered.contains("[redacted]"));
        // Gateway URLs are not credentials and stay visible.
        assert!(rendered.contains("https://koios.example"));
    }

    #[test]
    fn resolved_gateways_debug_redacts_blockfrost() {
        let resolved = resolve_gateways(
            &GatewayFlags {
                gateway: vec!["https://koios.example".to_string()],
                blockfrost: Some("mainnetSECRETprojectid".to_string()),
                ..GatewayFlags::default()
            },
            &env(&[]),
            None,
        )
        .unwrap();
        let rendered = format!("{resolved:?}");
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://koios.example"));
    }
}
