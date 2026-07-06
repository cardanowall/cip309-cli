//! `cardanowall verify <tx-hash>` / `verify --record <path>` — the standalone
//! Label 309 verifier.
//!
//! A thin shell over the SDK's `verify_tx` and `verify_record_bytes`: it owns
//! option parsing, gateway resolution, output formatting, and the verdict →
//! exit-code mapping. The verdict's exit code is passed through verbatim, so the
//! public exit-code contract (`0` valid / `1` failed / `2` unverifiable / `3`
//! pending / `4` CLI input) is whatever the verifier decided, plus `4` for
//! CLI-input failures.
//!
//! The verifier is service-independent. In the default mode it takes a
//! transaction hash, public gateways, and optional recipient keys or a
//! passphrase, then fetches the label-309 metadata, validates the record, and
//! runs the profile-gated signature / decryption / Merkle checks — trusting no
//! publisher and no issuer server. In local mode (`--record`) it runs the same
//! pipeline from the structural-validator step onward over caller-supplied
//! record-body bytes, for a producer pre-submission check, an archival
//! re-validation, or a conformance-vector check with no chain lookup at all.

use std::collections::BTreeMap;

use cardanowall::verifier::{
    verify_record_bytes, verify_report_to_dict, verify_tx, BlockInfo, CardanoNetwork, Decryption,
    Profile, VerifyReport, VerifyTxInput, CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
};
use clap::Args;

use crate::commands::certificate::NetworkArg;
use crate::config::{
    read_config_file, resolve_gateways, GatewayFlags, ResolvedGateways, SystemConfigEnv,
    SystemGatewayEnv,
};
use crate::output::render_human_report;
use crate::secret::{
    enforce_single_secret_source, resolve_secret_passphrase, warn_secret_on_argv, SecretArgs,
    SecretEnv, SecretKind, SecretSources, SystemSecretEnv,
};
use crate::util::{hex_to_bytes, is_all_hex, CliError};

/// Arguments for `cardanowall verify`.
///
/// `secret_key` carries raw recipient secret keys passed on argv and `blockfrost`
/// is a Blockfrost project id (an API credential), so `Debug` is hand-written to
/// redact both: no `{:?}`, log, or panic-backtrace path can ever surface them.
#[derive(Args)]
pub struct VerifyArgs {
    /// 64-hex Cardano transaction hash to resolve and verify on chain. Supply
    /// exactly one of this or --record.
    pub tx_hash: Option<String>,
    /// Local mode: verify a Label 309 record body read from this path instead of
    /// resolving a transaction — raw canonical CBOR, or its hex-text encoding.
    /// Runs the structural, signature, and content checks over the supplied bytes
    /// (a producer pre-submission check, an archival re-validation, or a
    /// conformance-vector check). Mutually exclusive with the <tx-hash> argument.
    #[arg(long = "record")]
    pub record: Option<String>,
    /// Local mode only: caller-asserted block time in POSIX seconds. Reported as
    /// the record's `block_time`; omitted from the report when not supplied.
    #[arg(long = "block-time")]
    pub block_time: Option<u64>,
    /// Local mode only: caller-asserted block slot of the including block.
    #[arg(long = "slot")]
    pub slot: Option<u64>,
    /// Local mode only: caller-asserted confirmation depth (>= 1). When supplied,
    /// the confirmation-depth gate runs against --threshold (a depth below it
    /// yields `pending`, skipping the later checks); when omitted the gate is
    /// disabled and no depth is claimed, so the structural / signature / content
    /// checks always run.
    #[arg(long = "confirmations")]
    pub confirmations: Option<u32>,
    /// Cardano network of the anchoring transaction: sets the report's network
    /// identifier and the wallet-path signature address binding (default: mainnet).
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    pub network: NetworkArg,
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
    /// Passphrase for a passphrase-sealed PoE (tried against every sealed item,
    /// alongside any --secret-key). INSECURE on argv; prefer --passphrase-file /
    /// --passphrase-stdin / CARDANOWALL_PASSPHRASE.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// read the passphrase from a file (trailing whitespace trimmed).
    #[arg(long = "passphrase-file")]
    pub passphrase_file: Option<String>,
    /// read the passphrase from stdin.
    #[arg(long = "passphrase-stdin")]
    pub passphrase_stdin: bool,
    /// Per-URI fetch ceiling in bytes, enforced incrementally while streaming; a
    /// fetch that reaches it is aborted and reported as
    /// CONTENT_FETCH_LIMIT_EXCEEDED (a statement about verifier policy, never
    /// about the record). Omit for the transport default.
    #[arg(long = "max-fetch-bytes")]
    pub max_fetch_bytes: Option<u64>,
    /// Out-of-band ciphertext for a sealed item, as `<item-index>=<path>`
    /// (repeatable). Supplies the ciphertext locally for a recipient who holds
    /// it, instead of fetching the item's URIs.
    #[arg(long = "ciphertext")]
    pub ciphertext: Vec<String>,
    /// Out-of-band Merkle leaves-list for a commitment, as `<merkle-index>=<path>`
    /// (repeatable). Supplies the leaves-list locally instead of fetching the
    /// commitment's URIs.
    #[arg(long = "merkle-leaves")]
    pub merkle_leaves: Vec<String>,
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
            .field("record", &self.record)
            .field("block_time", &self.block_time)
            .field("slot", &self.slot)
            .field("confirmations", &self.confirmations)
            .field("network", &self.network)
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
            // The passphrase is secret material: report only its presence.
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[redacted]"),
            )
            .field("passphrase_file", &self.passphrase_file)
            .field("passphrase_stdin", &self.passphrase_stdin)
            .field("max_fetch_bytes", &self.max_fetch_bytes)
            .field("ciphertext", &self.ciphertext)
            .field("merkle_leaves", &self.merkle_leaves)
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

/// The mode-independent verifier inputs both `verify` modes share, resolved
/// once from the parsed options.
struct VerifyInputParts {
    profile: Profile,
    network: CardanoNetwork,
    keyring: Option<Vec<Decryption>>,
    ciphertext_bytes: Option<BTreeMap<usize, Vec<u8>>>,
    merkle_leaves: Option<BTreeMap<usize, Vec<u8>>>,
    max_fetch_bytes: Option<u64>,
    fetch_content: bool,
}

/// Run the `verify` command.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for CLI-input failures; otherwise returns an
/// error carrying the verifier's own exit code (`1` / `2` / `3`) with an empty
/// message so the report — already emitted — is the user-facing output.
pub fn run(args: VerifyArgs) -> Result<(), CliError> {
    // Exactly one input source: an on-chain transaction to resolve, or local
    // record bytes to verify directly.
    match (args.tx_hash.is_some(), args.record.is_some()) {
        (true, true) => {
            return Err(CliError::input(
                "verify: pass either a <tx-hash> or --record <path>, not both",
            ))
        }
        (false, false) => {
            return Err(CliError::input(
                "verify: supply a <tx-hash> to resolve on chain, or --record <path> to verify \
                 local record bytes",
            ))
        }
        _ => {}
    }

    // Only one secret may be read from stdin per process.
    if args.secret_key_stdin && args.passphrase_stdin {
        return Err(CliError::input(
            "verify: --secret-key-stdin and --passphrase-stdin cannot both read stdin; supply one \
             from a file or the environment",
        ));
    }
    let threshold = parse_threshold(args.threshold.as_deref())?;
    let secret_key_specs = collect_secret_key_specs(&args, &SystemSecretEnv)?;
    let mut secret_keys: Vec<Vec<u8>> = Vec::new();
    for raw in &secret_key_specs {
        secret_keys.push(parse_secret_key(raw)?);
    }
    // A passphrase joins the same decryption keyring as the recipient keys: the
    // verifier tries every applicable credential against every sealed item.
    let passphrase = resolve_secret_passphrase(
        &SecretArgs {
            value: args.passphrase.clone(),
            file: args.passphrase_file.clone(),
            stdin: args.passphrase_stdin,
        },
        false,
        "verify",
        &SystemSecretEnv,
    )?;
    let profile = choose_profile(&args, !secret_keys.is_empty() || passphrase.is_some())?;

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

    let parts = VerifyInputParts {
        profile,
        network: cardano_network(args.network),
        keyring: build_keyring(secret_keys, passphrase.map(|p| p.to_string())),
        ciphertext_bytes: parse_indexed_bytes(&args.ciphertext, "--ciphertext")?,
        merkle_leaves: parse_indexed_bytes(&args.merkle_leaves, "--merkle-leaves")?,
        max_fetch_bytes: args.max_fetch_bytes,
        fetch_content: !args.no_fetch,
    };

    let report = if let Some(tx_hash) = args.tx_hash.as_deref() {
        run_online(tx_hash, &args, &resolved, &parts)?
    } else {
        run_local(&args, &resolved, &parts)?
    };

    emit_report(&report, args.json, args.pretty);
    exit_code_for_report(&report)
}

/// Resolve the transaction on chain and run the full public/recipient pipeline.
fn run_online(
    tx_hash: &str,
    args: &VerifyArgs,
    resolved: &ResolvedGateways,
    parts: &VerifyInputParts,
) -> Result<VerifyReport, CliError> {
    if tx_hash.len() != 64 || !tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "verify: <tx-hash> must be 64 hex chars; got \"{tx_hash}\""
        )));
    }
    // The local-mode chain-fact flags have no meaning against a resolved
    // transaction: the explorer supplies inclusion, depth, and time.
    reject_local_only_flags(args)?;
    let threshold = resolved
        .confirmation_depth_threshold
        .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT);
    let input = build_verify_input(tx_hash.to_lowercase(), resolved, parts, threshold);
    Ok(verify_tx(&input))
}

/// Verify caller-supplied record-body bytes with no chain lookup, running the
/// pipeline from the structural-validator step onward.
///
/// Chain facts are caller-asserted (the record has no transaction to resolve):
/// when `--confirmations` is supplied the confirmation-depth gate runs against
/// the effective threshold (a below-threshold depth yields `pending`, faithfully
/// skipping the later steps); when it is omitted the gate is disabled so the
/// structural / signature / content checks — the reason local mode exists — run
/// to completion, and the report claims no confirmation depth. A chain fact the
/// caller did not assert is reported as unknown rather than as the placeholder
/// the pipeline required, so the transcript never surfaces a fabricated depth or
/// a 1970 block time.
fn run_local(
    args: &VerifyArgs,
    resolved: &ResolvedGateways,
    parts: &VerifyInputParts,
) -> Result<VerifyReport, CliError> {
    let path = args
        .record
        .as_deref()
        .expect("run_local is only reached when --record is set");
    if args.confirmations == Some(0) {
        return Err(CliError::input(
            "verify: --confirmations must be >= 1 (a transaction in the tip block has depth 1)",
        ));
    }
    let record_bytes = load_record_bytes(path)?;

    let (confirmation_depth, threshold) = match args.confirmations {
        Some(depth) => (
            depth,
            resolved
                .confirmation_depth_threshold
                .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT),
        ),
        // No asserted depth: pass the tip-inclusive minimum and disable the gate
        // (threshold 0) so `depth < threshold` is never true.
        None => (1, 0),
    };
    let block_info = BlockInfo {
        confirmation_depth,
        block_time: args.block_time.unwrap_or(0),
        block_slot: args.slot,
    };
    let input = build_verify_input(String::new(), resolved, parts, threshold);
    let mut report = verify_record_bytes(&record_bytes, block_info, &input)
        .map_err(|e| CliError::input(format!("verify: {e}")))?;

    if args.confirmations.is_none() {
        report.confirmation_depth = None;
    }
    if args.block_time.is_none() {
        report.block_time = None;
    }
    Ok(report)
}

/// Reject the local-mode-only chain-fact flags when a transaction hash was
/// supplied (their values would silently be ignored otherwise).
fn reject_local_only_flags(args: &VerifyArgs) -> Result<(), CliError> {
    let flag = if args.block_time.is_some() {
        Some("--block-time")
    } else if args.slot.is_some() {
        Some("--slot")
    } else if args.confirmations.is_some() {
        Some("--confirmations")
    } else {
        None
    };
    if let Some(flag) = flag {
        return Err(CliError::input(format!(
            "verify: {flag} applies only to --record local mode; an on-chain transaction resolves \
             its own chain facts"
        )));
    }
    Ok(())
}

/// Emit the report on stdout: canonical JSON under `--json`, else the human
/// transcript.
fn emit_report(report: &VerifyReport, json: bool, pretty: bool) {
    if json {
        let dict = verify_report_to_dict(report);
        let rendered = if pretty {
            serde_json::to_string_pretty(&dict)
        } else {
            serde_json::to_string(&dict)
        }
        .expect("VerifyReport dict serialises");
        println!("{rendered}");
    } else {
        render_human_report(report);
    }
}

/// Build the run's decryption keyring: recipient secret keys (the slots path)
/// plus an optional passphrase (the passphrase path). The verifier dispatches
/// each item on its on-wire key path and tries only the applicable credentials,
/// so mixing the two in one keyring is safe. Empty in → `None`.
fn build_keyring(secret_keys: Vec<Vec<u8>>, passphrase: Option<String>) -> Option<Vec<Decryption>> {
    let mut keyring: Vec<Decryption> = secret_keys
        .into_iter()
        .map(|recipient_secret_key| Decryption::Recipient {
            recipient_secret_key,
        })
        .collect();
    if let Some(passphrase) = passphrase {
        keyring.push(Decryption::Passphrase { passphrase });
    }
    if keyring.is_empty() {
        None
    } else {
        Some(keyring)
    }
}

/// Parse repeatable `<index>=<path>` specs into the index → bytes map the SDK
/// verifier consumes for out-of-band ciphertext / Merkle leaves-list delivery.
/// The bytes are read verbatim (they are binary blobs, not hex text). An empty
/// spec list yields `None` so the field stays absent on the input.
fn parse_indexed_bytes(
    specs: &[String],
    flag: &str,
) -> Result<Option<BTreeMap<usize, Vec<u8>>>, CliError> {
    if specs.is_empty() {
        return Ok(None);
    }
    let mut map: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for spec in specs {
        let (index_str, path) = spec.split_once('=').ok_or_else(|| {
            CliError::input(format!(
                "verify: {flag} expects <index>=<path>; got \"{spec}\""
            ))
        })?;
        let index_str = index_str.trim();
        // Round-trip the parse so a leading `+`, leading zeros, or whitespace is
        // rejected rather than silently normalised.
        let index: usize = index_str
            .parse()
            .ok()
            .filter(|n: &usize| n.to_string() == index_str)
            .ok_or_else(|| {
                CliError::input(format!(
                    "verify: {flag} index must be a non-negative integer; got \"{index_str}\""
                ))
            })?;
        if map.contains_key(&index) {
            return Err(CliError::input(format!(
                "verify: {flag} index {index} was given more than once"
            )));
        }
        let bytes = std::fs::read(path).map_err(|e| {
            CliError::network(format!("verify: cannot read {flag} file {path}: {e}"))
        })?;
        map.insert(index, bytes);
    }
    Ok(Some(map))
}

/// Read the `--record` file as the reassembled canonical record body: either raw
/// canonical-CBOR bytes, or a hex-text encoding of them (the form other commands
/// print). A canonical record body begins with a CBOR map header byte, which is
/// not an ASCII hex digit, so the hex reading never misfires on real CBOR.
fn load_record_bytes(path: &str) -> Result<Vec<u8>, CliError> {
    let raw = std::fs::read(path)
        .map_err(|e| CliError::network(format!("verify: cannot read --record {path}: {e}")))?;
    if let Ok(text) = std::str::from_utf8(&raw) {
        let trimmed = text.trim();
        if is_all_hex(trimmed) {
            return hex_to_bytes(trimmed)
                .map_err(|e| CliError::input(format!("verify: --record {path}: {e}")));
        }
    }
    Ok(raw)
}

/// Map the CLI network selector onto the verifier's network type.
fn cardano_network(network: NetworkArg) -> CardanoNetwork {
    match network {
        NetworkArg::Mainnet => CardanoNetwork::Mainnet,
        NetworkArg::Preprod => CardanoNetwork::Preprod,
    }
}

/// Map the parsed CLI options onto the SDK verifier's input shape.
///
/// `tx_hash` is empty in local mode (there is no transaction); the cardano
/// gateway chain is still populated but goes unused on that path. The SSRF
/// posture is already folded in by the resolver: user deny-host entries only
/// ever extend the built-in set, unless replace mode was chosen explicitly.
fn build_verify_input(
    tx_hash: String,
    resolved: &ResolvedGateways,
    parts: &VerifyInputParts,
    threshold: u32,
) -> VerifyTxInput<'static> {
    let mut input = VerifyTxInput::new(tx_hash);
    input.profile = parts.profile;
    input.cardano_network = parts.network;
    input.cardano_gateway_chain = Some(resolved.cardano_gateway_chain.clone());
    input.arweave_gateway_chain = Some(resolved.arweave_gateway_chain.clone());
    input.ipfs_gateway_chain = resolved.ipfs_gateway_chain.clone();
    input.blockfrost_project_id = resolved.blockfrost_project_id.clone();
    input.confirmation_depth_threshold = Some(threshold);
    input.deny_hosts = Some(resolved.deny_hosts.clone());
    input.decryption = parts.keyring.clone();
    input.ciphertext_bytes = parts.ciphertext_bytes.clone();
    input.merkle_leaves = parts.merkle_leaves.clone();
    input.max_fetch_bytes = parts.max_fetch_bytes;
    // `--no-fetch` flips the master content-fetch switch: item-URI, ciphertext,
    // and Merkle leaves-list downloads are suppressed and those claims report as
    // not checked. It governs content, not the transaction lookup, so the
    // resolved gateway chains stay as configured (an emptied Arweave chain would
    // fall back to the verifier's built-in defaults, not mean "offline").
    input.fetch_content = parts.fetch_content;
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
            tx_hash: Some(tx_hash.to_string()),
            record: None,
            block_time: None,
            slot: None,
            confirmations: None,
            network: NetworkArg::Mainnet,
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
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: false,
            max_fetch_bytes: None,
            ciphertext: vec![],
            merkle_leaves: vec![],
            no_fetch: false,
            json: true,
            pretty: false,
        }
    }

    /// A default [`VerifyInputParts`] for the input-shape tests.
    fn base_parts() -> VerifyInputParts {
        VerifyInputParts {
            profile: Profile::Signed,
            network: CardanoNetwork::Mainnet,
            keyring: None,
            ciphertext_bytes: None,
            merkle_leaves: None,
            max_fetch_bytes: None,
            fetch_content: true,
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
        let mut parts = base_parts();

        parts.fetch_content = false;
        let input = build_verify_input("aa".repeat(32), &resolved, &parts, 15);
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

        parts.fetch_content = true;
        assert!(build_verify_input("aa".repeat(32), &resolved, &parts, 15).fetch_content);
    }

    #[test]
    fn build_keyring_merges_recipient_keys_and_passphrase() {
        // A recipient key plus a passphrase both land in the keyring: one
        // Recipient credential and one Passphrase credential.
        let keyring = build_keyring(vec![vec![0xcd; 32]], Some("open sesame".to_string()))
            .expect("keyring is populated");
        assert_eq!(keyring.len(), 2);
        assert!(keyring
            .iter()
            .any(|d| matches!(d, Decryption::Recipient { .. })));
        assert!(keyring.iter().any(
            |d| matches!(d, Decryption::Passphrase { passphrase } if passphrase == "open sesame")
        ));

        // A passphrase alone still populates the keyring.
        assert_eq!(
            build_keyring(vec![], Some("just a passphrase".to_string()))
                .expect("keyring")
                .len(),
            1
        );

        // No credentials at all leaves the keyring unset, and the built input
        // carries no decryption keyring.
        assert!(build_keyring(vec![], None).is_none());
        let resolved = ResolvedGateways::default();
        assert!(
            build_verify_input("aa".repeat(32), &resolved, &base_parts(), 15)
                .decryption
                .is_none()
        );
    }

    #[test]
    fn passphrase_selects_the_recipient_sealed_profile_by_default() {
        // With no explicit --profile, a passphrase (like a recipient key) picks
        // the decrypting profile.
        let mut args = base_args(&"0".repeat(64));
        assert_eq!(choose_profile(&args, false).unwrap(), Profile::Signed);
        assert_eq!(
            choose_profile(&args, true).unwrap(),
            Profile::RecipientSealed
        );
        // An explicit --profile still wins.
        args.profile = Some("sealed".to_string());
        assert_eq!(choose_profile(&args, true).unwrap(), Profile::Sealed);
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

    // -- input-source selection + the new flag surface ------------------------

    use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
    use cardanowall::verifier::Verdict;
    use std::io::Write as _;

    fn hash_only_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0x11; 32])],
                uris: None,
                enc: None,
            }]),
            merkle: None,
            supersedes: None,
            sigs: None,
            crit: None,
            extensions: Vec::new(),
        }
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(bytes).expect("write temp");
        f.flush().expect("flush temp");
        f
    }

    fn record_args(file: &tempfile::NamedTempFile) -> VerifyArgs {
        let mut args = base_args("");
        args.tx_hash = None;
        args.record = Some(file.path().to_string_lossy().into_owned());
        args
    }

    #[test]
    fn both_tx_and_record_is_input_error() {
        let mut args = base_args(&"0".repeat(64));
        args.record = Some("/some/record.cbor".to_string());
        assert_eq!(run(args).unwrap_err().code, 4);
    }

    #[test]
    fn neither_tx_nor_record_is_input_error() {
        let mut args = base_args("");
        args.tx_hash = None;
        assert_eq!(run(args).unwrap_err().code, 4);
    }

    #[test]
    fn chain_fact_flags_are_rejected_with_a_tx_hash() {
        // The local-mode chain-fact flags have no meaning against a resolved
        // transaction, so each is a hard input error rather than silently ignored.
        let cases: [fn(&mut VerifyArgs); 3] = [
            |a| a.block_time = Some(1),
            |a| a.slot = Some(1),
            |a| a.confirmations = Some(1),
        ];
        for set in cases {
            let mut args = base_args(&"0".repeat(64));
            set(&mut args);
            assert_eq!(run(args).unwrap_err().code, 4);
        }
    }

    #[test]
    fn local_mode_verifies_a_known_good_record_and_claims_no_chain_facts() {
        let bytes = encode_poe_record(&hash_only_record()).expect("encode");
        let file = write_temp(&bytes);
        let args = record_args(&file);
        let mut parts = base_parts();
        // Hash-only record, offline: content is reported not-checked, no error.
        parts.fetch_content = false;
        let report = run_local(&args, &ResolvedGateways::default(), &parts).expect("verify");
        assert_eq!(report.verdict, Verdict::Valid);
        // No chain facts were asserted, so none are claimed (never a fabricated
        // depth or a 1970 block time).
        assert_eq!(report.confirmation_depth, None);
        assert_eq!(report.block_time, None);
        assert!(report.tx_hash.is_empty());
    }

    #[test]
    fn local_mode_reports_the_selected_network() {
        let bytes = encode_poe_record(&hash_only_record()).expect("encode");
        let file = write_temp(&bytes);
        let args = record_args(&file);
        let mut parts = base_parts();
        parts.network = CardanoNetwork::Preprod;
        parts.fetch_content = false;
        let report = run_local(&args, &ResolvedGateways::default(), &parts).expect("verify");
        assert_eq!(report.network, "cardano:preprod");
    }

    #[test]
    fn local_mode_asserted_low_confirmations_yield_pending() {
        let bytes = encode_poe_record(&hash_only_record()).expect("encode");
        let file = write_temp(&bytes);
        let mut args = record_args(&file);
        args.confirmations = Some(3); // below the default threshold of 15
        let mut parts = base_parts();
        parts.fetch_content = false;
        let report = run_local(&args, &ResolvedGateways::default(), &parts).expect("verify");
        assert_eq!(report.verdict, Verdict::Pending);
        // The caller-asserted depth is reported because it was asserted.
        assert_eq!(report.confirmation_depth, Some(3));
    }

    #[test]
    fn local_mode_zero_confirmations_is_input_error() {
        let bytes = encode_poe_record(&hash_only_record()).expect("encode");
        let file = write_temp(&bytes);
        let mut args = record_args(&file);
        args.confirmations = Some(0);
        let err = run_local(&args, &ResolvedGateways::default(), &base_parts()).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn build_input_carries_network_max_fetch_and_out_of_band_bytes() {
        let resolved = ResolvedGateways::default();
        let mut parts = base_parts();
        parts.network = CardanoNetwork::Preprod;
        parts.max_fetch_bytes = Some(4096);
        parts.ciphertext_bytes = Some(BTreeMap::from([(0usize, vec![0xaa, 0xbb])]));
        parts.merkle_leaves = Some(BTreeMap::from([(2usize, vec![0xcc])]));
        let input = build_verify_input("aa".repeat(32), &resolved, &parts, 15);
        assert_eq!(input.cardano_network, CardanoNetwork::Preprod);
        assert_eq!(input.max_fetch_bytes, Some(4096));
        assert_eq!(
            input.ciphertext_bytes,
            Some(BTreeMap::from([(0usize, vec![0xaa, 0xbb])]))
        );
        assert_eq!(
            input.merkle_leaves,
            Some(BTreeMap::from([(2usize, vec![0xcc])]))
        );

        // The unset defaults: mainnet, transport-default fetch ceiling, no bytes.
        let default_input = build_verify_input("aa".repeat(32), &resolved, &base_parts(), 15);
        assert_eq!(default_input.cardano_network, CardanoNetwork::Mainnet);
        assert_eq!(default_input.max_fetch_bytes, None);
        assert!(default_input.ciphertext_bytes.is_none());
        assert!(default_input.merkle_leaves.is_none());
    }

    #[test]
    fn cardano_network_maps_the_cli_selector() {
        assert_eq!(
            cardano_network(NetworkArg::Mainnet),
            CardanoNetwork::Mainnet
        );
        assert_eq!(
            cardano_network(NetworkArg::Preprod),
            CardanoNetwork::Preprod
        );
    }

    #[test]
    fn parse_indexed_bytes_reads_files_and_rejects_bad_specs() {
        let f0 = write_temp(&[0x01, 0x02, 0x03]);
        let f1 = write_temp(&[0xff]);
        let p0 = f0.path().to_string_lossy().into_owned();
        let p1 = f1.path().to_string_lossy().into_owned();

        let map = parse_indexed_bytes(&[format!("0={p0}"), format!("3={p1}")], "--ciphertext")
            .unwrap()
            .expect("some");
        assert_eq!(map.get(&0), Some(&vec![0x01, 0x02, 0x03]));
        assert_eq!(map.get(&3), Some(&vec![0xff]));

        // Empty list → None (the field stays absent on the input).
        assert!(parse_indexed_bytes(&[], "--ciphertext").unwrap().is_none());
        // Missing '=', a non-integer index, and a duplicate index all fail input.
        assert_eq!(
            parse_indexed_bytes(&["0".to_string()], "--ciphertext")
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(
            parse_indexed_bytes(&[format!("x={p0}")], "--ciphertext")
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(
            parse_indexed_bytes(&[format!("0={p0}"), format!("0={p1}")], "--ciphertext")
                .unwrap_err()
                .code,
            4
        );
        // An unreadable file is a network-class (2) error, not an input error.
        assert_eq!(
            parse_indexed_bytes(&["0=/no/such/file/xyzzy".to_string()], "--ciphertext")
                .unwrap_err()
                .code,
            2
        );
    }

    #[test]
    fn load_record_bytes_accepts_raw_cbor_and_hex_text() {
        let bytes = encode_poe_record(&hash_only_record()).expect("encode");
        let raw = write_temp(&bytes);
        assert_eq!(
            load_record_bytes(&raw.path().to_string_lossy()).unwrap(),
            bytes
        );
        // The hex-text form (surrounding whitespace tolerated) decodes identically.
        let hex_text = format!("  {}\n", cardanowall::hex::encode(&bytes));
        let hex_file = write_temp(hex_text.as_bytes());
        assert_eq!(
            load_record_bytes(&hex_file.path().to_string_lossy()).unwrap(),
            bytes
        );
    }
}
