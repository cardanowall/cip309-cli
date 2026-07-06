//! `cardanowall gateway` — manage named service-gateway profiles.
//!
//! A profile pairs a service-gateway `base_url` with an optional opaque `api_key`
//! and is stored under `[gateways.<name>]` in `config.toml` (created `0600`). This
//! is NOT a login: the gateway API is key-only, so a profile is just a saved
//! endpoint-plus-key the network commands resolve when no `--base-url` / env is
//! given.
//!
//! Verbs:
//!
//! - `add <name> --base-url <url> [--api-key-stdin]` — when `--api-key-stdin` is
//!   omitted and stdin is a TTY, the key is read from a hidden prompt.
//! - `use <name>`    — set `default_gateway = "<name>"`.
//! - `list`          — name + base_url + masked key + which is default.
//! - `show <name>`   — one profile (`--json` aware; key masked unless `--reveal`).
//! - `remove <name>` — drop a profile (and clear `default_gateway` if it pointed
//!   at it).
//!
//! Exit codes: `0` ok / `4` CLI input error (unknown profile, missing base URL,
//! malformed config).

use clap::{Args, Subcommand};

use crate::config::{
    load_config_for_edit, system_config_path, write_config, GatewayProfile, SystemConfigEnv,
};
use crate::secret::{SecretEnv, SystemSecretEnv};
use crate::util::CliError;

/// Arguments for `cardanowall gateway`.
#[derive(Debug, Args)]
pub struct GatewayArgs {
    /// The gateway-profile verb to run.
    #[command(subcommand)]
    pub verb: GatewayVerb,
}

/// The gateway-profile verbs.
#[derive(Debug, Subcommand)]
pub enum GatewayVerb {
    /// Save a named gateway profile (base URL + optional API key).
    Add(GatewayAddArgs),
    /// Set the active gateway profile by name.
    Use(GatewayUseArgs),
    /// List saved gateway profiles (API keys masked).
    List(GatewayListArgs),
    /// Show one gateway profile (API key masked unless --reveal).
    Show(GatewayShowArgs),
    /// Remove a saved gateway profile.
    Remove(GatewayRemoveArgs),
}

impl GatewayArgs {
    /// Whether the active verb was invoked with `--json`.
    #[must_use]
    pub fn json_mode(&self) -> bool {
        match &self.verb {
            GatewayVerb::Add(a) => a.json,
            GatewayVerb::Use(a) => a.json,
            GatewayVerb::List(a) => a.json,
            GatewayVerb::Show(a) => a.json,
            GatewayVerb::Remove(a) => a.json,
        }
    }
}

/// Run the `gateway` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: GatewayArgs) -> Result<(), CliError> {
    run_with_env(args, &SystemConfigEnv, &SystemSecretEnv)
}

/// Test-friendly entry point: the config + secret env are injected so the suite
/// drives `add`/`list`/`use`/`remove` against a temp config and a fake prompt.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run_with_env(
    args: GatewayArgs,
    config_env: &dyn crate::config::ConfigEnv,
    secret_env: &dyn SecretEnv,
) -> Result<(), CliError> {
    match args.verb {
        GatewayVerb::Add(a) => run_add(a, config_env, secret_env),
        GatewayVerb::Use(a) => run_use(a, config_env),
        GatewayVerb::List(a) => run_list(a, config_env),
        GatewayVerb::Show(a) => run_show(a, config_env),
        GatewayVerb::Remove(a) => run_remove(a, config_env),
    }
}

// ===========================================================================
// gateway add
// ===========================================================================

/// Arguments for `cardanowall gateway add`.
#[derive(Debug, Args)]
pub struct GatewayAddArgs {
    /// the profile name (e.g. `prod`).
    pub name: String,
    /// the service-gateway base URL (required) — the full base including the API
    /// version segment, e.g. `https://cardanowall.com/api/v1`.
    #[arg(long = "base-url")]
    pub base_url: String,
    /// read the opaque API key from stdin (otherwise prompt when a TTY).
    #[arg(long = "api-key-stdin")]
    pub api_key_stdin: bool,
    /// emit a machine-readable JSON acknowledgement.
    #[arg(long)]
    pub json: bool,
}

fn run_add(
    args: GatewayAddArgs,
    config_env: &dyn crate::config::ConfigEnv,
    secret_env: &dyn SecretEnv,
) -> Result<(), CliError> {
    validate_name(&args.name)?;
    let base_url = args.base_url.trim().to_string();
    if base_url.is_empty() {
        return Err(CliError::input("gateway add: --base-url must not be empty"));
    }

    // The API key is moderately-secret: read it from stdin when asked, else from a
    // hidden prompt on a TTY, else leave it unset (a key-less public gateway).
    let api_key = if args.api_key_stdin {
        let raw = secret_env.read_stdin()?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else if secret_env.stdin_is_terminal() {
        let entered = secret_env.prompt_hidden(&format!(
            "Enter API key for gateway '{}' (blank = none): ",
            args.name
        ))?;
        let trimmed = entered.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    };

    let mut config = load_config_for_edit(config_env)?;
    config.gateways.insert(
        args.name.clone(),
        GatewayProfile {
            base_url: base_url.clone(),
            api_key,
        },
    );
    // First profile added becomes the default so the user need not also `use` it.
    if config.default_gateway.is_none() {
        config.default_gateway = Some(args.name.clone());
    }
    write_config(config_env, &config)?;

    let has_key = config
        .gateways
        .get(&args.name)
        .and_then(|p| p.api_key.as_ref())
        .is_some();
    if args.json {
        let value = serde_json::json!({
            "status": "ok",
            "name": args.name,
            "base_url": base_url,
            "has_api_key": has_key,
            "is_default": config.default_gateway.as_deref() == Some(args.name.as_str()),
        });
        println!("{value}");
    } else {
        println!("ok: saved gateway profile '{}' -> {base_url}", args.name);
        if config.default_gateway.as_deref() == Some(args.name.as_str()) {
            println!("  (set as the default gateway)");
        }
    }
    Ok(())
}

// ===========================================================================
// gateway use
// ===========================================================================

/// Arguments for `cardanowall gateway use`.
#[derive(Debug, Args)]
pub struct GatewayUseArgs {
    /// the profile name to make active.
    pub name: String,
    /// emit a machine-readable JSON acknowledgement.
    #[arg(long)]
    pub json: bool,
}

fn run_use(
    args: GatewayUseArgs,
    config_env: &dyn crate::config::ConfigEnv,
) -> Result<(), CliError> {
    let mut config = load_config_for_edit(config_env)?;
    if !config.gateways.contains_key(&args.name) {
        return Err(unknown_profile(&args.name, &config));
    }
    config.default_gateway = Some(args.name.clone());
    write_config(config_env, &config)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "status": "ok", "default_gateway": args.name })
        );
    } else {
        println!("ok: default gateway is now '{}'", args.name);
    }
    Ok(())
}

// ===========================================================================
// gateway list
// ===========================================================================

/// Arguments for `cardanowall gateway list`.
#[derive(Debug, Args)]
pub struct GatewayListArgs {
    /// emit a machine-readable JSON array.
    #[arg(long)]
    pub json: bool,
}

fn run_list(
    args: GatewayListArgs,
    config_env: &dyn crate::config::ConfigEnv,
) -> Result<(), CliError> {
    let config = load_config_for_edit(config_env)?;
    let default = config.default_gateway.as_deref();

    if args.json {
        let profiles: Vec<serde_json::Value> = config
            .gateways
            .iter()
            .map(|(name, p)| {
                serde_json::json!({
                    "name": name,
                    "base_url": p.base_url,
                    "api_key": mask_key(p.api_key.as_deref()),
                    "has_api_key": p.api_key.is_some(),
                    "is_default": default == Some(name.as_str()),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "gateways": profiles }));
        return Ok(());
    }

    if config.gateways.is_empty() {
        println!(
            "no gateway profiles. Add one with 'cardanowall gateway add <name> --base-url <url>'."
        );
        return Ok(());
    }
    for (name, p) in &config.gateways {
        let marker = if default == Some(name.as_str()) {
            "* "
        } else {
            "  "
        };
        println!(
            "{marker}{name}\t{}\t{}",
            p.base_url,
            mask_key(p.api_key.as_deref())
        );
    }
    Ok(())
}

// ===========================================================================
// gateway show
// ===========================================================================

/// Arguments for `cardanowall gateway show`.
#[derive(Debug, Args)]
pub struct GatewayShowArgs {
    /// the profile name to show.
    pub name: String,
    /// reveal the full API key instead of masking it.
    #[arg(long)]
    pub reveal: bool,
    /// emit a machine-readable JSON object.
    #[arg(long)]
    pub json: bool,
}

fn run_show(
    args: GatewayShowArgs,
    config_env: &dyn crate::config::ConfigEnv,
) -> Result<(), CliError> {
    let config = load_config_for_edit(config_env)?;
    let Some(profile) = config.gateways.get(&args.name) else {
        return Err(unknown_profile(&args.name, &config));
    };
    let is_default = config.default_gateway.as_deref() == Some(args.name.as_str());
    // --reveal prints the full API key to stdout (an explicit owner opt-in, key
    // already plaintext in the config file). Emit a one-line stderr caution when a
    // key is actually revealed so capturing it in a CI log is a conscious act;
    // stdout shape is unchanged, in both text and --json paths.
    if args.reveal && profile.api_key.is_some() {
        eprintln!("warning: full API key printed to stdout");
    }
    let key_display = if args.reveal {
        profile.api_key.clone().unwrap_or_default()
    } else {
        mask_key(profile.api_key.as_deref())
    };

    if args.json {
        let value = serde_json::json!({
            "name": args.name,
            "base_url": profile.base_url,
            "api_key": if args.reveal { serde_json::Value::from(profile.api_key.clone()) } else { serde_json::Value::from(key_display.clone()) },
            "has_api_key": profile.api_key.is_some(),
            "is_default": is_default,
        });
        println!("{value}");
    } else {
        println!("name:      {}", args.name);
        println!("base_url:  {}", profile.base_url);
        println!("api_key:   {key_display}");
        println!("default:   {}", if is_default { "yes" } else { "no" });
    }
    Ok(())
}

// ===========================================================================
// gateway remove
// ===========================================================================

/// Arguments for `cardanowall gateway remove`.
#[derive(Debug, Args)]
pub struct GatewayRemoveArgs {
    /// the profile name to remove.
    pub name: String,
    /// emit a machine-readable JSON acknowledgement.
    #[arg(long)]
    pub json: bool,
}

fn run_remove(
    args: GatewayRemoveArgs,
    config_env: &dyn crate::config::ConfigEnv,
) -> Result<(), CliError> {
    let mut config = load_config_for_edit(config_env)?;
    if config.gateways.remove(&args.name).is_none() {
        return Err(unknown_profile(&args.name, &config));
    }
    // Clearing the default that pointed at the removed profile keeps the config
    // internally consistent (no dangling default_gateway).
    if config.default_gateway.as_deref() == Some(args.name.as_str()) {
        config.default_gateway = None;
    }
    write_config(config_env, &config)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "status": "ok", "removed": args.name })
        );
    } else {
        println!("ok: removed gateway profile '{}'", args.name);
    }
    Ok(())
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Mask an API key for display: keep nothing, show a fixed sigil. A non-empty key
/// renders as `********` (length-hiding); an absent key renders as `<none>`.
fn mask_key(key: Option<&str>) -> String {
    match key {
        Some(k) if !k.is_empty() => "********".to_string(),
        _ => "<none>".to_string(),
    }
}

/// Profile names key a TOML table and a directory-free identifier; keep them to a
/// conservative `[A-Za-z0-9._-]+` so they never need quoting on disk.
fn validate_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(CliError::input(format!(
            "gateway: profile name must be non-empty and match [A-Za-z0-9._-]; got \"{name}\""
        )));
    }
    Ok(())
}

fn unknown_profile(name: &str, config: &crate::config::CardanoWallConfig) -> CliError {
    let known: Vec<&str> = config.gateways.keys().map(String::as_str).collect();
    let hint = if known.is_empty() {
        "no gateway profiles are defined".to_string()
    } else {
        format!("known profiles: {}", known.join(", "))
    };
    let path = system_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "config.toml".to_string());
    CliError::input(format!(
        "gateway: no profile named \"{name}\" in {path} ({hint})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_key() {
        assert_eq!(mask_key(Some("supersecret")), "********");
        assert_eq!(mask_key(Some("")), "<none>");
        assert_eq!(mask_key(None), "<none>");
    }

    #[test]
    fn validates_name() {
        assert!(validate_name("prod").is_ok());
        assert!(validate_name("prod.eu-1_test").is_ok());
        assert_eq!(validate_name("bad name").unwrap_err().code, 4);
        assert_eq!(validate_name("").unwrap_err().code, 4);
        assert_eq!(validate_name("a/b").unwrap_err().code, 4);
    }
}
