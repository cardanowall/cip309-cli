//! `cardanowall inbox` — sealed-PoE inbox over a raw recipient key. Raw-seed-first;
//! no account envelope.
//!
//! Three verbs:
//!
//! - `sync`    — page sealed records from a Label 309 gateway
//!   (the `/records?sealed=true` resource), trial-decrypt each item with the recipient
//!   key bundle, and persist confirmed matches to the local bookmark. The scan
//!   works from on-chain record bytes and the seed-derived key alone: match and
//!   CEK recovery fetch ZERO ciphertext. Records below the confirmation-depth
//!   threshold are reported as pending and re-evaluated on the next sync.
//! - `list`    — print the locally-persisted bookmark (optionally tip-refreshed
//!   via `--gateway`). A refresh failure never suppresses the list — the local
//!   bookmark is still valid data — but it is reflected in the exit code after
//!   rendering: a deny-host hit is integrity-class (`1`), any other failure is
//!   network-class (`2`).
//! - `decrypt` — the only verb that fetches ciphertext: acquire the sealed
//!   record's off-chain blob, open it with the recipient key bundle, and
//!   recompute the plaintext content hashes.
//!
//! Identity is raw-seed-first: `--seed <hex>` (full key set, locates the bookmark
//! and reads hybrid records) or `--secret-key <hex>` (X25519-only, classical
//! records, cannot locate the bookmark). Gateway reads require `--base-url`
//! (+ `--api-key` when the gateway needs auth).
//!
//! Exit codes: `0` ok / `1` integrity (bad record, hash mismatch, wrong key) /
//! `2` network / `4` CLI input error.

use std::collections::{BTreeMap, HashMap};

use cardanowall::client::{ClientError, Label309Client, Label309ClientConfig, RecordsListInput};
use cardanowall::hash::sha256;
use cardanowall::poe_standard::{
    validate_poe_record, EncScheme1, EncryptionEnvelope, ErrorCode, ItemEntry, PassphraseBlock,
    PathSegment, PoeRecord, ValidateResult, ValidatorOptions, ValidatorRole,
};
use cardanowall::sealed_poe::{
    ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap, passphrase_sealed_poe_open,
    PassphraseOpenArgs, PassphraseOpenResult, RecipientKeyBundle, SealedEnvelope, TrialDecryptKeys,
    TrialDecryptResult, UnwrapFailureReason, UnwrapKeys, UnwrapResult,
};
use cardanowall::verifier::content::{
    provider_mismatch_path, walk_blob_sources, BlobWalkEnd, SourceDecision,
};
use cardanowall::verifier::fetch::ReqwestTransport;
use cardanowall::verifier::{
    extract_label_309_metadata, resolve_cardano_tx, verify_record_signatures, CardanoNetwork,
    ContentFetchPolicy, GatewayFetcher, SigFailureReason, SignatureCheck, SignerType,
    VerifierIssue, CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::config::{
    load_config_for_edit, read_config_file, resolve_gateways, GatewayFlags, ResolvedGateways,
    SystemConfigEnv, SystemGatewayEnv,
};
use crate::inbox::identity::ResolvedIdentity;
use crate::inbox::{envelope_from_item, recompute_item_hashes, RecomputeResult};
use crate::output::render_inbox_list_human;
use crate::secret::{resolve_secret_passphrase, SecretArgs, SystemSecretEnv};
use crate::state::{
    bookmark_path, ed25519_prefix, ed25519_pubkey_hex, load_or_init, save, SealedMatchEntry,
};
use crate::util::{base64::decode_standard, bytes_to_hex, hex_to_bytes, CliError};

/// Arguments for `cardanowall inbox`.
#[derive(Debug, Args)]
pub struct InboxArgs {
    /// The inbox verb to run.
    #[command(subcommand)]
    pub verb: InboxVerb,
}

/// The three inbox verbs.
///
/// The decrypt variant carries the most flags (it is the only networked,
/// content-fetching verb), so it is the largest; the size gap is inherent to a
/// clap arg enum that is parsed exactly once and never held in a hot path.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum InboxVerb {
    /// Pull sealed records from a gateway and trial-decrypt them locally.
    Sync(InboxSyncArgs),
    /// Print sealed-PoE matches from the local bookmark.
    List(InboxListArgs),
    /// Decrypt sealed-PoE items at the given tx-hash using your X25519 key.
    Decrypt(InboxDecryptArgs),
}

impl InboxArgs {
    /// Whether the active verb was invoked with `--json`.
    #[must_use]
    pub fn json_mode(&self) -> bool {
        match &self.verb {
            InboxVerb::Sync(a) => a.json,
            InboxVerb::List(a) => a.json,
            InboxVerb::Decrypt(a) => a.json,
        }
    }
}

/// Run the `inbox` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: InboxArgs) -> Result<(), CliError> {
    match args.verb {
        InboxVerb::Sync(a) => run_sync(a),
        InboxVerb::List(a) => run_list(a),
        InboxVerb::Decrypt(a) => run_decrypt(a),
    }
}

// ===========================================================================
// Shared identity + gateway plumbing
// ===========================================================================

/// Resolve the identity and require the seed-derived Ed25519 key so the
/// bookmark-locating commands have a per-identity path.
fn resolve_identity_with_ed25519(
    source: &crate::inbox::IdentitySource,
    cmd: &str,
) -> Result<(ResolvedIdentity, Vec<u8>), CliError> {
    let identity = source.resolve(cmd, &SystemSecretEnv)?;
    let Some(ed25519) = identity.ed25519_public_key.clone() else {
        return Err(CliError::input(format!(
            "{cmd}: --secret-key alone is insufficient to locate the bookmark file \
             (no Ed25519 derivation path; the bookmark path is keyed by the Ed25519 public key). \
             Use --seed instead."
        )));
    };
    Ok((identity, ed25519))
}

/// Resolve the service gateway (base URL + API key) for an inbox network verb via
/// `flag > env > active gateway profile`.
fn resolve_service_gateway_for(
    base_url: Option<&str>,
    api_key: Option<&str>,
    gateway_profile: Option<&str>,
    cmd: &str,
) -> Result<crate::secret::ServiceGateway, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    let profile = config.select_gateway(gateway_profile, cmd)?;
    crate::secret::resolve_service_gateway(base_url, api_key, profile, cmd, &SystemSecretEnv)
}

fn resolve_gateways_for(flags: GatewayFlags, cmd: &str) -> Result<ResolvedGateways, CliError> {
    let config = read_config_file(&SystemConfigEnv).map_err(|e| relabel(e, cmd))?;
    resolve_gateways(&flags, &SystemGatewayEnv, config.as_ref()).map_err(|e| relabel(e, cmd))
}

/// Relabel a `verify:`-prefixed gateway error to the active inbox command.
fn relabel(err: CliError, cmd: &str) -> CliError {
    CliError {
        code: err.code,
        message: err.message.replacen("verify:", &format!("{cmd}:"), 1),
    }
}

// ===========================================================================
// inbox sync
// ===========================================================================

/// Arguments for `cardanowall inbox sync`.
/// `api_key` is a bearer token and the flattened `identity` carries secret
/// material; `Debug` is hand-written to redact the key (the identity redacts
/// itself) so no `{:?}`, log, or panic path can surface either.
#[derive(Args)]
pub struct InboxSyncArgs {
    /// target Label 309 gateway base URL (or env CARDANOWALL_BASE_URL, or a profile).
    /// Full base incl. the version segment, e.g. `https://cardanowall.com/api/v1`.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or a profile).
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// confirmation-depth threshold (non-negative integer; default 15).
    #[arg(long)]
    pub threshold: Option<u32>,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// emit machine-readable summary JSON on stdout.
    #[arg(long)]
    pub json: bool,
    /// pretty-print --json output.
    #[arg(long)]
    pub pretty: bool,
}

impl std::fmt::Debug for InboxSyncArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxSyncArgs")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("gateway_profile", &self.gateway_profile)
            .field("threshold", &self.threshold)
            .field("identity", &self.identity)
            .field("json", &self.json)
            .field("pretty", &self.pretty)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct SyncSummary {
    scanned: usize,
    matched: usize,
    pending: usize,
    dropped: usize,
    last_cursor: u64,
}

const SYNC_PAGE_LIMIT: u64 = 100;
const MAX_SYNC_PAGES: usize = 10_000;

fn build_client(
    base_url: String,
    api_key: Option<&str>,
    cmd: &str,
) -> Result<Label309Client, CliError> {
    Label309Client::new(Label309ClientConfig {
        api_key: api_key.map(str::to_string).filter(|s| !s.is_empty()),
        base_url: Some(base_url),
    })
    .map_err(|e| CliError::input(format!("{cmd}: {e}")))
}

fn run_sync(args: InboxSyncArgs) -> Result<(), CliError> {
    let (identity, ed25519) = resolve_identity_with_ed25519(&args.identity, "inbox sync")?;
    let threshold = args
        .threshold
        .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT);

    let gateway = resolve_service_gateway_for(
        args.base_url.as_deref(),
        args.api_key.as_deref(),
        args.gateway_profile.as_deref(),
        "inbox sync",
    )?;
    let client = build_client(gateway.base_url, gateway.api_key.as_deref(), "inbox sync")?;
    let records = client.records();

    let prefix = ed25519_prefix(&ed25519)?;
    let ed25519_hex = ed25519_pubkey_hex(&ed25519)?;
    let path = bookmark_path(&prefix)?;
    let mut bookmark = load_or_init(&path, &ed25519_hex)?;

    let bundle = identity.recipient_key_bundle();
    let now = current_iso8601();

    let mut existing: std::collections::HashSet<(String, usize, usize)> = bookmark
        .matched
        .iter()
        .map(|m| (m.tx_hash.clone(), m.item_idx, m.slot_idx))
        .collect();

    let mut scanned = 0usize;
    let mut new_matches = 0usize;
    let mut pending = 0usize;
    let mut dropped = 0usize;
    let mut tip_block_height = bookmark.last_processed_block_height;

    let mut cursor: Option<String> = None;
    let mut pages = 0usize;
    loop {
        let page = records
            .list(Some(&RecordsListInput {
                cursor: cursor.clone(),
                limit: Some(SYNC_PAGE_LIMIT),
                sealed: Some(true),
            }))
            .map_err(|e| map_inbox_client_error(e, "inbox sync"))?;
        // The gateway may not report the chain tip; when it does, advance the
        // durable progress marker. When it doesn't, the SDK's per-page
        // derivation fills it from the rows, and an absent value (an empty
        // page) leaves the marker unchanged.
        if let Some(tip) = page.tip_block_height {
            tip_block_height = tip_block_height.max(tip);
        }

        for record in &page.data {
            scanned += 1;
            let metadata = match decode_standard(&record.metadata_cbor_base64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    dropped += 1;
                    continue;
                }
            };
            // The scan keeps the public validator reading: a record sealed
            // under identifiers this implementation does not support is a valid
            // third-party record the bundle simply cannot open, not a drop.
            let validated = match validate_poe_record(&metadata, &ValidatorOptions::default()) {
                ValidateResult::Ok { record, .. } => *record,
                ValidateResult::Fail { .. } => {
                    dropped += 1;
                    continue;
                }
            };
            let confirmed = record.num_confirmations >= u64::from(threshold);
            let items = validated.items.unwrap_or_default();
            // A poisoned record must never abort the whole sync; drop just this row.
            let mut row_dropped = false;
            for (i, item) in items.iter().enumerate() {
                let Some(envelope) = envelope_from_item(item) else {
                    continue;
                };
                // Per-slot acceptance folds KEM validity, the wrap-open, and the
                // slots_mac check into one accept/reject decision; the item's
                // content-hash map is bound into the slots transcript. Match and
                // CEK recovery happen from on-chain bytes alone — no ciphertext
                // is fetched during the scan.
                let hashes = item_hashes_map(item);
                match ecies_sealed_poe_trial_decrypt(
                    &envelope,
                    &hashes,
                    TrialDecryptKeys::Bundle(&bundle),
                    None,
                ) {
                    Ok(TrialDecryptResult::Match { slot_idx, .. }) => {
                        if confirmed {
                            let key = (record.tx_hash.clone(), i, slot_idx);
                            if existing.insert(key) {
                                bookmark.matched.push(SealedMatchEntry {
                                    tx_hash: record.tx_hash.clone(),
                                    item_idx: i,
                                    slot_idx,
                                    first_seen: now.clone(),
                                    block_height: record.block_height,
                                    num_confirmations_at_first_seen: Some(record.num_confirmations),
                                });
                                new_matches += 1;
                            }
                        } else {
                            pending += 1;
                        }
                    }
                    Ok(TrialDecryptResult::NoMatch) => {}
                    Err(_) => {
                        row_dropped = true;
                        break;
                    }
                }
            }
            if row_dropped {
                dropped += 1;
            }
        }

        pages += 1;
        if !page.has_more || page.next_cursor.is_none() || pages >= MAX_SYNC_PAGES {
            cursor = page.next_cursor;
            break;
        }
        cursor = page.next_cursor;
    }

    bookmark.last_processed_block_height = tip_block_height;
    // The indexer cursor is an opaque string; we persist the block-height tip as
    // the durable progress marker and reset the numeric cursor to the tip.
    bookmark.last_processed_cursor = tip_block_height;
    save(&path, &bookmark)?;

    let summary = SyncSummary {
        scanned,
        matched: new_matches,
        pending,
        dropped,
        last_cursor: bookmark.last_processed_cursor,
    };
    if args.json {
        let value = serde_json::json!({
            "schema_version": 1,
            "scanned": summary.scanned,
            "matched": summary.matched,
            "pending": summary.pending,
            "dropped": summary.dropped,
            "last_cursor": summary.last_cursor,
            "last_block_height": bookmark.last_processed_block_height,
        });
        let rendered = if args.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
        .expect("sync summary serialises");
        println!("{rendered}");
    } else {
        println!(
            "synced: {} records scanned, {} matched, {} pending (below threshold), {} dropped. last_cursor={}",
            summary.scanned, summary.matched, summary.pending, summary.dropped, summary.last_cursor
        );
    }
    let _ = cursor;
    Ok(())
}

// ===========================================================================
// inbox list
// ===========================================================================

/// Arguments for `cardanowall inbox list`.
/// `blockfrost` is a Blockfrost project id (an API credential) and the flattened
/// `identity` carries secret material; `Debug` is hand-written to redact the
/// project id (the identity redacts itself) so no `{:?}`, log, or panic path can
/// surface either.
#[derive(Args)]
pub struct InboxListArgs {
    /// Cardano gateway URL (optional; refreshes num_confirmations).
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// extra entries for the egress deny list (repeatable), appended to the
    /// built-in defaults. Applies to URLs taken from on-chain records.
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// the --deny-host entries REPLACE the built-in deny list instead of
    /// appending. With no entries listed, NOTHING is refused — you take over
    /// SSRF protection entirely.
    #[arg(long = "deny-hosts-replace")]
    pub deny_hosts_replace: bool,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
}

impl std::fmt::Debug for InboxListArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxListArgs")
            .field("gateway", &self.gateway)
            .field(
                "blockfrost",
                &self.blockfrost.as_ref().map(|_| "[redacted]"),
            )
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            .field("identity", &self.identity)
            .field("json", &self.json)
            .field("pretty", &self.pretty)
            .finish()
    }
}

fn run_list(args: InboxListArgs) -> Result<(), CliError> {
    let (_identity, ed25519) = resolve_identity_with_ed25519(&args.identity, "inbox list")?;
    let prefix = ed25519_prefix(&ed25519)?;
    let ed25519_hex = ed25519_pubkey_hex(&ed25519)?;
    let path = bookmark_path(&prefix)?;

    if !path.exists() {
        eprintln!(
            "inbox: no bookmark file at {} — run 'cardanowall inbox sync' first",
            path.display()
        );
        if args.json {
            let value = serde_json::json!({
                "schema_version": 1,
                "identity_pubkey_ed25519_hex": ed25519_hex,
                "bookmark_path": path.display().to_string(),
                "last_processed_cursor": 0,
                "last_processed_block_height": 0,
                "matched": [],
                "pending": [],
            });
            print_json(&value, args.pretty);
        }
        return Ok(());
    }

    let bookmark = load_or_init(&path, &ed25519_hex)?;

    // Optional tip refresh: only when --gateway is supplied. A refresh failure
    // must not suppress the list, but it must not vanish into an exit-0 either:
    // track the worst failure class and surface it as the exit code after
    // rendering. A deny-host hit (service-independence violation) is
    // integrity-class (1) and dominates plain network failures (2).
    let mut tip_refreshed: Option<HashMap<String, u32>> = None;
    let mut refresh_exit = 0i32;
    if !args.gateway.is_empty() {
        let flags = GatewayFlags {
            gateway: args.gateway.clone(),
            blockfrost: args.blockfrost.clone(),
            deny_host: args.deny_host.clone(),
            deny_hosts_replace: args.deny_hosts_replace,
            ..GatewayFlags::default()
        };
        let resolved = resolve_gateways_for(flags, "inbox list")?;
        // The transport carries the deny list so its redirect-policy closure
        // re-applies the same list the fetcher's initial-URL guard uses.
        let transport = ReqwestTransport::with_deny_hosts(resolved.deny_hosts.clone());
        let mut fetcher = GatewayFetcher::new(&transport, Some(&resolved.deny_hosts));
        let mut refreshed = HashMap::new();
        let unique: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            bookmark
                .matched
                .iter()
                .map(|m| m.tx_hash.clone())
                .filter(|h| seen.insert(h.clone()))
                .collect()
        };
        for tx_hash in unique {
            match resolve_cardano_tx(
                &tx_hash,
                Some(&resolved.cardano_gateway_chain),
                resolved.blockfrost_project_id.as_deref(),
                &mut fetcher,
            ) {
                Ok(r) => {
                    refreshed.insert(tx_hash, r.confirmation_depth);
                }
                Err(e) => {
                    eprintln!("inbox list: tip refresh failed for {tx_hash}: {e}");
                    if e.code == ErrorCode::ServiceIndependenceViolation {
                        refresh_exit = 1;
                    } else if refresh_exit != 1 {
                        refresh_exit = 2;
                    }
                }
            }
        }
        tip_refreshed = Some(refreshed);
    }

    if args.json {
        let mut matched: Vec<serde_json::Value> = bookmark
            .matched
            .iter()
            .map(|m| {
                let refreshed = tip_refreshed.as_ref().and_then(|t| t.get(&m.tx_hash));
                let num_confirmations = refreshed
                    .copied()
                    .map(serde_json::Value::from)
                    .or_else(|| {
                        m.num_confirmations_at_first_seen
                            .map(serde_json::Value::from)
                    })
                    .unwrap_or(serde_json::Value::Null);
                serde_json::json!({
                    "tx_hash": m.tx_hash,
                    "item_idx": m.item_idx,
                    "slot_idx": m.slot_idx,
                    "first_seen": m.first_seen,
                    "num_confirmations": num_confirmations,
                    "num_confirmations_stale": refreshed.is_none(),
                })
            })
            .collect();
        matched.sort_by(|a, b| b["first_seen"].as_str().cmp(&a["first_seen"].as_str()));
        let value = serde_json::json!({
            "schema_version": 1,
            "identity_pubkey_ed25519_hex": bookmark.identity_pubkey_ed25519_hex,
            "bookmark_path": path.display().to_string(),
            "last_processed_cursor": bookmark.last_processed_cursor,
            "last_processed_block_height": bookmark.last_processed_block_height,
            "matched": matched,
            "pending": [],
        });
        print_json(&value, args.pretty);
    } else {
        render_inbox_list_human(&bookmark, tip_refreshed.as_ref());
    }
    // The list has rendered; a refresh failure now becomes the exit code. The
    // error is silent — the per-tx diagnostics are already on stderr.
    if refresh_exit == 0 {
        Ok(())
    } else {
        Err(CliError {
            code: refresh_exit,
            message: String::new(),
        })
    }
}

// ===========================================================================
// inbox decrypt
// ===========================================================================

/// Arguments for `cardanowall inbox decrypt`.
///
/// `api_key` is a bearer token, `blockfrost` is an API credential, and the
/// flattened `identity` carries secret material; `Debug` is hand-written to
/// redact the key and the project id (the identity redacts itself) so no
/// `{:?}`, log, or panic path can surface any of them.
#[derive(Args)]
pub struct InboxDecryptArgs {
    /// 64-hex Cardano transaction hash.
    pub tx_hash: String,
    /// restrict decryption to a single item index.
    #[arg(long)]
    pub item: Option<usize>,
    /// write plaintext to this path (or prefix for multi-item).
    #[arg(long)]
    pub out: Option<String>,
    /// target Label 309 gateway base URL (or env CARDANOWALL_BASE_URL, or a profile).
    /// Full base incl. the version segment, e.g. `https://cardanowall.com/api/v1`.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or a profile).
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// Cardano data-source gateway URL (repeatable; fetches the record from chain).
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// Arweave gateway URL (repeatable).
    #[arg(long = "arweave-gateway")]
    pub arweave_gateway: Vec<String>,
    /// IPFS gateway URL (repeatable).
    #[arg(long = "ipfs-gateway")]
    pub ipfs_gateway: Vec<String>,
    /// extra entries for the egress deny list (repeatable), appended to the
    /// built-in defaults. Applies to URLs taken from on-chain records.
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// the --deny-host entries REPLACE the built-in deny list instead of
    /// appending. With no entries listed, NOTHING is refused — you take over
    /// SSRF protection entirely.
    #[arg(long = "deny-hosts-replace")]
    pub deny_hosts_replace: bool,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// Passphrase for a passphrase-sealed item (an alternative to the recipient
    /// identity). INSECURE on argv; prefer --passphrase-file / --passphrase-stdin
    /// / CARDANOWALL_PASSPHRASE.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// read the passphrase from a file (trailing whitespace trimmed).
    #[arg(long = "passphrase-file")]
    pub passphrase_file: Option<String>,
    /// read the passphrase from stdin.
    #[arg(long = "passphrase-stdin")]
    pub passphrase_stdin: bool,
    /// emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
}

impl std::fmt::Debug for InboxDecryptArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxDecryptArgs")
            .field("tx_hash", &self.tx_hash)
            .field("item", &self.item)
            .field("out", &self.out)
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("gateway_profile", &self.gateway_profile)
            .field("gateway", &self.gateway)
            // Blockfrost project id is an API credential.
            .field(
                "blockfrost",
                &self.blockfrost.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway", &self.arweave_gateway)
            .field("ipfs_gateway", &self.ipfs_gateway)
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            .field("identity", &self.identity)
            // The passphrase is secret material: report only its presence.
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[redacted]"),
            )
            .field("passphrase_file", &self.passphrase_file)
            .field("passphrase_stdin", &self.passphrase_stdin)
            .field("json", &self.json)
            .field("pretty", &self.pretty)
            .finish()
    }
}

/// Per-item status in the `--json` results array.
///
/// A machine consumer distinguishes the three end states on `status` alone: an
/// item it can act on (`decrypted`), one addressed to a different recipient or
/// credential (`skipped`, never an error), and a genuine failure (`failed`). The
/// `reason` field carries the specific wire code within `skipped` / `failed`.
const STATUS_DECRYPTED: &str = "decrypted";
const STATUS_SKIPPED: &str = "skipped";
const STATUS_FAILED: &str = "failed";

#[derive(Debug, Serialize)]
struct DecryptItemResult {
    tx_hash: String,
    item_idx: usize,
    /// One of [`STATUS_DECRYPTED`], [`STATUS_SKIPPED`], [`STATUS_FAILED`].
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext_hash_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    bytes_written_to: Option<String>,
    byte_count: Option<usize>,
}

fn run_decrypt(args: InboxDecryptArgs) -> Result<(), CliError> {
    if args.tx_hash.len() != 64 || !args.tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "inbox decrypt: <tx-hash> must be 64 hex chars; got \"{}\"",
            args.tx_hash
        )));
    }
    let tx_hash = args.tx_hash.to_lowercase();

    // In --json mode the machine-readable results object is written to stdout, so
    // recovered plaintext must NOT also land there (it would corrupt the JSON and
    // spill confidential bytes into logs expecting metadata). Require --out: every
    // opened item goes to a file and stdout carries only JSON. Rejected here,
    // before any identity resolution, network call, or decrypt work.
    if args.json && args.out.is_none() {
        return Err(CliError::input(
            "inbox decrypt: --json requires --out so recovered plaintext is written to a file and \
             never shares stdout with the JSON results; pass --out <path> (a filename, or a prefix \
             for a multi-item record)",
        ));
    }

    // Only one secret may be read from stdin per process.
    if args.passphrase_stdin && (args.identity.seed_stdin || args.identity.secret_key_stdin) {
        return Err(CliError::input(
            "inbox decrypt: --passphrase-stdin conflicts with an identity read from stdin; supply \
             one from a file or the environment",
        ));
    }

    // A recipient identity (seed / secret-key) opens the slots key path; a
    // passphrase opens the passphrase key path. Either alone suffices, so the
    // identity is resolved only when supplied — a passphrase-only decrypt needs
    // no recipient key. The identity here may be a raw --secret-key (X25519
    // only): decrypt does not need the bookmark, so the Ed25519 path is not
    // required.
    let identity = if args.identity.any_present(&SystemSecretEnv) {
        Some(args.identity.resolve("inbox decrypt", &SystemSecretEnv)?)
    } else {
        None
    };
    let bundle = identity
        .as_ref()
        .map(ResolvedIdentity::recipient_key_bundle);
    let passphrases: Vec<String> = resolve_secret_passphrase(
        &SecretArgs {
            value: args.passphrase.clone(),
            file: args.passphrase_file.clone(),
            stdin: args.passphrase_stdin,
        },
        false,
        "inbox decrypt",
        &SystemSecretEnv,
    )?
    .map(|p| p.to_string())
    .into_iter()
    .collect();
    if bundle.is_none() && passphrases.is_empty() {
        return Err(CliError::input(
            "inbox decrypt: supply a recipient identity (--seed / --secret-key) or a passphrase \
             (--passphrase) to open the record",
        ));
    }

    // Fetch the record's label-309 metadata. Prefer the chain (gateway) path so a
    // third-party record (not submitted via this gateway) is still reachable; fall
    // back to the agnostic records API when --base-url is supplied without a
    // Cardano --gateway.
    let flags = GatewayFlags {
        gateway: args.gateway.clone(),
        blockfrost: args.blockfrost.clone(),
        arweave_gateway: args.arweave_gateway.clone(),
        ipfs_gateway: args.ipfs_gateway.clone(),
        deny_host: args.deny_host.clone(),
        deny_hosts_replace: args.deny_hosts_replace,
        ..GatewayFlags::default()
    };
    let resolved = resolve_gateways_for(flags, "inbox decrypt")?;
    // The transport carries the deny list so its redirect-policy closure
    // re-applies the same list the fetcher's initial-URL guard uses.
    let transport = ReqwestTransport::with_deny_hosts(resolved.deny_hosts.clone());
    let mut fetcher = GatewayFetcher::new(&transport, Some(&resolved.deny_hosts));

    let metadata = fetch_metadata(&tx_hash, &args, &resolved, &mut fetcher)?;
    // The recipient reading: an envelope this implementation cannot fully
    // validate is a hard reject here — the user asked to decrypt this exact
    // record, so degrading it to opaque metadata would be silent data loss.
    let recipient_options = ValidatorOptions {
        role: ValidatorRole::RecipientOrStrict,
        ..ValidatorOptions::default()
    };
    let validated = match validate_poe_record(&metadata, &recipient_options) {
        ValidateResult::Ok { record, .. } => *record,
        ValidateResult::Fail { issues } => {
            let code = issues.first().map_or("UNKNOWN", |i| i.code.code());
            return Err(CliError::integrity(format!(
                "inbox decrypt: record fails validator: {code}"
            )));
        }
    };
    // Borrow the items (rather than move them out of `validated`) so the whole
    // record stays in hand for the post-decrypt authorship check below.
    let items: &[ItemEntry] = validated.items.as_deref().unwrap_or(&[]);

    // No `--item` means "every item addressed to me". A Label 309 record may
    // seal each of its items to a DIFFERENT recipient (or under a passphrase),
    // so an item not sealed to my key/passphrase is expected, not an error — it
    // is silently skipped, exactly as `inbox sync` skips a record it cannot
    // open. An explicit `--item N` targets one item and stays strict: any failure
    // to open it, a wrong recipient key included, is terminal.
    let all_items = args.item.is_none();
    let target_indices: Vec<usize> = match args.item {
        Some(i) => vec![i],
        None => (0..items.len()).collect(),
    };

    let policy = ContentFetchPolicy {
        arweave_gateways: &resolved.arweave_gateway_chain,
        ipfs_gateways: resolved.ipfs_gateway_chain.as_deref().unwrap_or(&[]),
        max_fetch_bytes: None,
    };

    let DecryptRun { results, exit_code } = decrypt_items(
        &tx_hash,
        items,
        &target_indices,
        all_items,
        bundle.as_ref(),
        &passphrases,
        args.out.as_deref(),
        &policy,
        &mut fetcher,
    )?;

    // All-items mode that opened nothing yet hit no genuine failure: say so
    // plainly and exit 0, mirroring how `inbox sync` silently skips records that
    // are addressed to someone else.
    if all_items
        && exit_code == 0
        && !results.is_empty()
        && !results.iter().any(|r| r.status == STATUS_DECRYPTED)
    {
        eprintln!(
            "inbox decrypt: 0 of {} item(s) at {tx_hash} are sealed to your key or passphrase",
            results.len()
        );
    }

    // Authorship signal: after opening at least one item, tell the recipient who
    // — if anyone — signed the on-chain commitment (the spec's sender-identity
    // verdict split). A signature outcome NEVER changes the decrypt exit code:
    // decryption and authorship are separate verdicts, so a bad signature is
    // surfaced loudly here, not folded into the exit status.
    let authorship = results
        .iter()
        .any(|r| r.status == STATUS_DECRYPTED)
        .then(|| record_authorship(&validated));

    if args.json {
        let value = serde_json::json!({
            "tx_hash": tx_hash,
            "items": results,
            "record_signatures": serde_json::to_value(&authorship)
                .expect("authorship serialises"),
        });
        print_json(&value, args.pretty);
    } else if let Some(summary) = &authorship {
        render_authorship_human(summary);
    }

    if exit_code == 0 {
        Ok(())
    } else {
        Err(CliError {
            code: exit_code,
            message: String::new(),
        })
    }
}

// ===========================================================================
// Record authorship (sender-identity verdict split)
// ===========================================================================

/// A record's authorship verdict for a recipient who has just opened it.
///
/// `signature_count` of `0` is the explicit "record is unsigned" marker (a valid,
/// anonymous sealed PoE — see the spec's sender-identity split). Otherwise each
/// entry carries the signer's pubkey, its short fingerprint, and a verdict.
#[derive(Debug, Serialize)]
struct AuthorshipSummary {
    /// The number of record-level COSE_Sign1 signatures.
    signature_count: usize,
    /// Per-signature verdicts, positionally aligned with `record.sigs`.
    signatures: Vec<AuthorshipSignature>,
}

/// One record-level signature outcome, surfaced to the recipient.
#[derive(Debug, Serialize)]
struct AuthorshipSignature {
    /// The `sigs[]` index.
    index: usize,
    /// One of [`AUTHORSHIP_VALID`], [`AUTHORSHIP_INVALID`],
    /// [`AUTHORSHIP_UNSUPPORTED`], [`AUTHORSHIP_UNRESOLVED`],
    /// [`AUTHORSHIP_ADDRESS_UNVERIFIED`].
    verdict: &'static str,
    /// The resolved signer pubkey (lowercase hex), when resolution succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_pub: Option<String>,
    /// The signer pubkey's short display fingerprint, when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    /// The signer-key resolution path (`in-signature-kid` / `wallet-inline-key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_type: Option<&'static str>,
    /// The wire failure code, for a network-independent failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// A signature that verified end-to-end (kid path), or a wallet signature whose
/// address binding was confirmed.
const AUTHORSHIP_VALID: &str = "valid";
/// The COSE_Sign1 decoded and resolved a key, but the Ed25519 signature (or its
/// decode) failed — the record is not authentically bound to that key.
const AUTHORSHIP_INVALID: &str = "invalid";
/// The signature uses an algorithm this build does not support; per the spec the
/// content claim is unaffected.
const AUTHORSHIP_UNSUPPORTED: &str = "unsupported";
/// No signer key could be resolved for the entry.
const AUTHORSHIP_UNRESOLVED: &str = "unresolved";
/// A wallet-path (path-2) signature whose Ed25519 verify succeeded, but whose
/// wallet-address binding the full public verifier confirms against the CARRYING
/// TRANSACTION's network — context this inbox flow does not resolve.
const AUTHORSHIP_ADDRESS_UNVERIFIED: &str = "address-unverified";

/// Compute the record's authorship summary from its record-level signatures.
///
/// Path-1 (`in-signature-kid`) entries verify fully offline, so their verdict is
/// network-independent and definitive. Path-2 (`wallet-inline-key`) entries carry
/// a wallet-address binding that the full public verifier confirms against the
/// CONTAINING TRANSACTION's network — context this inbox flow does not resolve —
/// so a cryptographically valid wallet signature is surfaced as
/// [`AUTHORSHIP_ADDRESS_UNVERIFIED`], never silently dropped and never falsely
/// bound. The passed network only flips a valid wallet entry between the SDK's
/// `valid` and `WalletAddressMismatch`, both of which collapse to that verdict
/// here, so its value is inert for this summary.
fn record_authorship(record: &PoeRecord) -> AuthorshipSummary {
    let checks = verify_record_signatures(record, CardanoNetwork::Mainnet);
    let signatures = checks.iter().map(authorship_signature).collect();
    AuthorshipSummary {
        signature_count: checks.len(),
        signatures,
    }
}

/// Whether a wallet-path signature's Ed25519 verify succeeded (so only its
/// address binding is in doubt). The SDK runs the crypto verify BEFORE the
/// address check, so both `None` (bound) and `WalletAddressMismatch` (crypto
/// valid, address did not bind under the assumed network) imply a good signature.
fn wallet_signature_crypto_valid(check: &SignatureCheck) -> bool {
    matches!(check.signer_type, Some(SignerType::WalletInlineKey))
        && matches!(
            check.reason,
            None | Some(SigFailureReason::WalletAddressMismatch)
        )
}

/// Map one SDK signature check to the recipient-facing authorship verdict.
fn authorship_verdict(check: &SignatureCheck) -> &'static str {
    if wallet_signature_crypto_valid(check) {
        return AUTHORSHIP_ADDRESS_UNVERIFIED;
    }
    match check.reason {
        None => AUTHORSHIP_VALID,
        Some(SigFailureReason::SignatureUnsupported) => AUTHORSHIP_UNSUPPORTED,
        Some(SigFailureReason::SignerKeyUnresolved) => AUTHORSHIP_UNRESOLVED,
        Some(_) => AUTHORSHIP_INVALID,
    }
}

/// Build the recipient-facing entry for one signature check.
fn authorship_signature(check: &SignatureCheck) -> AuthorshipSignature {
    let verdict = authorship_verdict(check);
    let fingerprint = check
        .signer_pub
        .as_deref()
        .and_then(|hex| hex_to_bytes(hex).ok())
        .map(|bytes| signer_fingerprint(&bytes));
    // Suppress the wire reason for an address-unverified entry: no mismatch was
    // actually determined (the inbox lacks the tx network), so surfacing
    // WALLET_ADDRESS_MISMATCH would misstate the outcome.
    let reason = if verdict == AUTHORSHIP_ADDRESS_UNVERIFIED {
        None
    } else {
        check.reason.map(|r| r.as_str().to_string())
    };
    AuthorshipSignature {
        index: check.index,
        verdict,
        signer_pub: check.signer_pub.clone(),
        fingerprint,
        signer_type: check.signer_type.map(SignerType::as_str),
        reason,
    }
}

/// The 8-byte `sha2-256(pubkey)` fingerprint, grouped `xxxx-xxxx-xxxx-xxxx` — the
/// same short display tag the `identity` command shows for an Ed25519 key.
fn signer_fingerprint(pubkey: &[u8]) -> String {
    let digest = sha256(pubkey);
    let hex = bytes_to_hex(&digest[..8]); // 16 hex chars
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

/// Render the authorship summary to stderr (human mode). It goes to stderr, not
/// stdout, because in non-JSON mode stdout may carry the recovered plaintext.
fn render_authorship_human(summary: &AuthorshipSummary) {
    if summary.signature_count == 0 {
        eprintln!("authorship: record is unsigned");
        return;
    }
    eprintln!(
        "authorship: {} record signature(s)",
        summary.signature_count
    );
    for sig in &summary.signatures {
        let signer = sig.signer_type.unwrap_or("unknown");
        let fingerprint = sig.fingerprint.as_deref().unwrap_or("—");
        let mut line = format!(
            "  [{}] {} — {} (fingerprint {})",
            sig.index, sig.verdict, signer, fingerprint
        );
        if sig.verdict == AUTHORSHIP_ADDRESS_UNVERIFIED {
            line.push_str("; run `cardanowall verify <tx>` for the wallet-address binding");
        } else if let Some(reason) = &sig.reason {
            line.push_str(&format!("; {reason}"));
        }
        eprintln!("{line}");
    }
}

/// The aggregate result of decrypting a record's targeted items: the per-item
/// results (in target order) and the process exit code.
struct DecryptRun {
    results: Vec<DecryptItemResult>,
    exit_code: i32,
}

/// The per-item disposition [`decrypt_items`] acts on after dispatch.
enum ItemOutcome {
    /// The item opened; the recovered plaintext is ready for the hash-check and
    /// write.
    Opened(Vec<u8>),
    /// Benign: the item is addressed to a different recipient or credential type,
    /// or (a passphrase item) no supplied passphrase opened it. Recorded as
    /// skipped and never escalates the exit code. `reason` is the machine-readable
    /// status detail; `note` is the one-line human explanation for stderr.
    Skipped { reason: &'static str, note: String },
    /// A genuine terminal failure on an item we ARE addressed to (or an explicit
    /// `--item` target): the wire code, its exit class (`1` integrity / `2`
    /// network), and an optional richer message that replaces the bare code on
    /// stderr.
    Failed {
        code: &'static str,
        exit: i32,
        message: Option<String>,
    },
}

impl From<ItemOpenOutcome> for ItemOutcome {
    fn from(outcome: ItemOpenOutcome) -> Self {
        match outcome {
            ItemOpenOutcome::Opened(plaintext) => ItemOutcome::Opened(plaintext),
            ItemOpenOutcome::Failed { code, exit } => ItemOutcome::Failed {
                code,
                exit,
                message: None,
            },
        }
    }
}

/// Fold a per-item exit class into the running process exit code: integrity
/// (`1`) dominates network (`2`), which dominates success (`0`).
fn escalate(exit_code: &mut i32, class: i32) {
    if class == 1 {
        *exit_code = 1;
    } else if class == 2 && *exit_code != 1 {
        *exit_code = 2;
    }
}

/// Decrypt the targeted items, write each opened plaintext, and fold the per-item
/// outcomes into the exit code.
///
/// Dispatch is on the item's on-wire key path: recipient slots open with the
/// identity bundle, a passphrase block with the passphrase. In all-items mode an
/// item addressed to a different recipient/credential is a benign skip that never
/// escalates; an explicit `--item` target and any genuine open failure (tampering,
/// deny-host, unavailability, hash mismatch) do escalate.
#[allow(clippy::too_many_arguments)]
fn decrypt_items(
    tx_hash: &str,
    items: &[ItemEntry],
    target_indices: &[usize],
    all_items: bool,
    bundle: Option<&RecipientKeyBundle>,
    passphrases: &[String],
    out: Option<&str>,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<DecryptRun, CliError> {
    let multi = target_indices.len() > 1;
    let mut results: Vec<DecryptItemResult> = Vec::new();
    let mut exit_code = 0i32;

    for &idx in target_indices {
        let Some(item) = items.get(idx) else {
            eprintln!("inbox decrypt: {tx_hash}:{idx}: item index out of range");
            results.push(fail_result(tx_hash, idx, "ITEM_INDEX_OUT_OF_RANGE"));
            escalate(&mut exit_code, 1);
            continue;
        };
        let mut issues: Vec<VerifierIssue> = Vec::new();
        let outcome = match item.enc.as_ref() {
            Some(EncryptionEnvelope::Scheme1(enc)) if enc.slots.is_some() => {
                open_recipient_slots_item(
                    idx,
                    item,
                    bundle,
                    all_items,
                    policy,
                    fetcher,
                    &mut issues,
                )
            }
            Some(EncryptionEnvelope::Scheme1(enc)) if enc.passphrase.is_some() => {
                let block = enc
                    .passphrase
                    .as_ref()
                    .expect("passphrase path implies a block");
                open_passphrase_sealed_item(
                    idx,
                    item,
                    enc,
                    block,
                    passphrases,
                    all_items,
                    policy,
                    fetcher,
                    &mut issues,
                )
            }
            _ => {
                // No sealed envelope at all — e.g. a plaintext PoE item sharing
                // the record. Nothing to decrypt: benign in all-items mode, an
                // explicit mistake when the item was targeted with --item.
                if all_items {
                    ItemOutcome::Skipped {
                        reason: "NO_SEALED_ENVELOPE",
                        note: format!("item {idx}: not sealed — nothing to decrypt, skipped"),
                    }
                } else {
                    ItemOutcome::Failed {
                        code: "NO_SEALED_ENVELOPE",
                        exit: 1,
                        message: Some("item has no sealed envelope".to_string()),
                    }
                }
            }
        };

        // Per-attempt diagnostics belong to an item we actually tried to open. A
        // benign skip either never fetched (recipient gate / wrong shape /
        // plaintext) or fetched a passphrase blob whose provider diagnostics would
        // be misleading noise on an item that simply is not ours — its single note
        // says enough.
        if !matches!(outcome, ItemOutcome::Skipped { .. }) {
            for issue in &issues {
                eprintln!(
                    "inbox decrypt: {tx_hash}:{idx}: {} {}",
                    issue.code.code(),
                    issue.message
                );
            }
        }

        let plaintext = match outcome {
            ItemOutcome::Opened(plaintext) => plaintext,
            ItemOutcome::Skipped { reason, note } => {
                eprintln!("inbox decrypt: {tx_hash}: {note}");
                results.push(skipped_result(tx_hash, idx, reason));
                continue;
            }
            ItemOutcome::Failed {
                code,
                exit,
                message,
            } => {
                let line = message.as_deref().unwrap_or(code);
                eprintln!("inbox decrypt: {tx_hash}:{idx}: {line}");
                results.push(fail_result(tx_hash, idx, code));
                escalate(&mut exit_code, exit);
                continue;
            }
        };

        match recompute_item_hashes(item, &plaintext) {
            RecomputeResult::Ok => {}
            RecomputeResult::Mismatch { alg } | RecomputeResult::UnsupportedAlg { alg } => {
                eprintln!("inbox decrypt: {tx_hash}:{idx}: URI_INTEGRITY_MISMATCH (alg {alg})");
                let mut r = fail_result(tx_hash, idx, "URI_INTEGRITY_MISMATCH");
                r.plaintext_hash_ok = Some(false);
                results.push(r);
                escalate(&mut exit_code, 1);
                continue;
            }
        }

        // With more than one target item, `--out` is a filename PREFIX: each
        // opened item lands at `<out>.item-<N>.bin`, so the index stays visible
        // even when only a subset of a multi-recipient record decrypts.
        let target_path = out.map(|o| {
            if multi {
                format!("{o}.item-{idx}.bin")
            } else {
                o.to_string()
            }
        });
        let written_to = if let Some(path) = target_path {
            write_new_file(&path, &plaintext)?;
            path
        } else {
            if multi {
                eprintln!(
                    "inbox decrypt: {tx_hash} item={idx} ({} bytes)",
                    plaintext.len()
                );
            }
            use std::io::Write;
            std::io::stdout().write_all(&plaintext).map_err(|e| {
                CliError::network(format!("inbox decrypt: stdout write failed: {e}"))
            })?;
            "stdout".to_string()
        };

        results.push(DecryptItemResult {
            tx_hash: tx_hash.to_string(),
            item_idx: idx,
            status: STATUS_DECRYPTED,
            plaintext_hash_ok: Some(true),
            reason: None,
            bytes_written_to: Some(written_to),
            byte_count: Some(plaintext.len()),
        });
    }

    Ok(DecryptRun { results, exit_code })
}

/// Decide the outcome for a recipient-slots item.
///
/// In all-items mode addressability is settled from the ON-CHAIN slots BEFORE any
/// network fetch: the slots-only [`ecies_sealed_poe_trial_decrypt`] (the same
/// primitive `inbox sync` uses) recovers the CEK — or rejects — from the record
/// bytes and the recipient key alone, so an item sealed to someone else is
/// skipped without ever downloading a ciphertext this key cannot open. A match,
/// or an explicit `--item` target, proceeds to fetch-and-open, where any failure
/// stays terminal.
fn open_recipient_slots_item(
    idx: usize,
    item: &ItemEntry,
    bundle: Option<&RecipientKeyBundle>,
    all_items: bool,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ItemOutcome {
    let Some(bundle) = bundle else {
        // Recipient-sealed, but no recipient identity was supplied: this item
        // needs the other credential type. Benign in all-items mode, strict when
        // the user targeted it with --item.
        return if all_items {
            ItemOutcome::Skipped {
                reason: "WRONG_DECRYPTION_INPUT_SHAPE",
                note: format!(
                    "item {idx}: recipient-sealed — skipped (supply --seed / --secret-key to open it)"
                ),
            }
        } else {
            ItemOutcome::Failed {
                code: "WRONG_DECRYPTION_INPUT_SHAPE",
                exit: 1,
                message: Some(
                    "item is recipient-sealed; pass a recipient identity (--seed / --secret-key) \
                     to open it"
                        .to_string(),
                ),
            }
        };
    };
    let Some(envelope) = envelope_from_item(item) else {
        // The item advertises recipient slots the validator accepted, yet no
        // sealed envelope could be projected — a genuine inconsistency, never a
        // "not for me". Terminal in either mode.
        return ItemOutcome::Failed {
            code: "NO_SEALED_ENVELOPE",
            exit: 1,
            message: Some("item has no decryptable sealed envelope".to_string()),
        };
    };
    if all_items {
        let hashes = item_hashes_map(item);
        if let Ok(TrialDecryptResult::NoMatch) = ecies_sealed_poe_trial_decrypt(
            &envelope,
            &hashes,
            TrialDecryptKeys::Bundle(bundle),
            None,
        ) {
            return ItemOutcome::Skipped {
                reason: "NOT_ADDRESSED",
                note: format!("item {idx}: not sealed to your key — skipped"),
            };
        }
    }
    open_sealed_item(idx, item, &envelope, bundle, policy, fetcher, issues).into()
}

/// Decide the outcome for a passphrase-sealed item.
///
/// A passphrase item has no slots-only gate: the only way to test a passphrase is
/// to fetch the blob and attempt the open. A non-open is by design
/// indistinguishable between a wrong / other-recipient passphrase and tampering,
/// so in all-items mode it is treated as a benign, best-effort skip — the one
/// exception being a deny-host hit, which is a service-independence violation
/// independent of the decryption outcome and still dominates. In `--item` mode
/// every non-open stays terminal.
#[allow(clippy::too_many_arguments)]
fn open_passphrase_sealed_item(
    idx: usize,
    item: &ItemEntry,
    enc: &EncScheme1,
    block: &PassphraseBlock,
    passphrases: &[String],
    all_items: bool,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ItemOutcome {
    if passphrases.is_empty() {
        return if all_items {
            ItemOutcome::Skipped {
                reason: "WRONG_DECRYPTION_INPUT_SHAPE",
                note: format!(
                    "item {idx}: passphrase-sealed — skipped (supply --passphrase / \
                     --passphrase-file / --passphrase-stdin to open it)"
                ),
            }
        } else {
            ItemOutcome::Failed {
                code: "WRONG_DECRYPTION_INPUT_SHAPE",
                exit: 1,
                message: Some(
                    "item is passphrase-sealed; pass --passphrase (or --passphrase-file / \
                     --passphrase-stdin) to open it"
                        .to_string(),
                ),
            }
        };
    }
    let opened = open_passphrase_item(idx, item, enc, block, passphrases, policy, fetcher, issues);
    if !all_items {
        // --item N: the user targeted this exact item, so any non-open is terminal.
        return opened.into();
    }
    match opened {
        ItemOpenOutcome::Opened(plaintext) => ItemOutcome::Opened(plaintext),
        // A deny-host hit is an egress/service-independence violation regardless
        // of whether the passphrase matched — it dominates the best-effort skip.
        ItemOpenOutcome::Failed { code, exit }
            if code == ErrorCode::ServiceIndependenceViolation.code() =>
        {
            ItemOutcome::Failed {
                code,
                exit,
                message: None,
            }
        }
        ItemOpenOutcome::Failed { .. } => ItemOutcome::Skipped {
            reason: "PASSPHRASE_NO_MATCH",
            note: format!(
                "item {idx}: not opened by the supplied passphrase — a different passphrase or \
                 tampering"
            ),
        },
    }
}

/// The terminal outcome of one sealed item's open attempt.
enum ItemOpenOutcome {
    /// The envelope opened end-to-end; the recovered plaintext is in hand.
    Opened(Vec<u8>),
    /// A terminal failure: the wire error code plus its exit class
    /// (`1` integrity / `2` network).
    Failed { code: &'static str, exit: i32 },
}

/// Acquire the item's ciphertext and open the sealed envelope with the
/// recipient key bundle, recording per-attempt diagnostics in `issues` (the
/// caller owns their presentation).
///
/// Blob sources are walked in record order (each URI against its scheme's
/// gateway chain) and every acquired blob is attempted independently:
///
/// - `WRONG_RECIPIENT_KEY` / `TAMPERED_HEADER` bind to ON-CHAIN data (the slot
///   set and its MAC), so they are terminal no matter which blob was tried.
/// - A failed content open is blob-dependent: bytes bound to their content
///   address (or supplied out-of-band) condemn the record
///   (`TAMPERED_CIPHERTEXT`); unattributable bytes indict only the serving
///   provider (`URI_PROVIDER_INTEGRITY_MISMATCH`) and the walk continues to
///   the next source.
/// - A deny-host hit anywhere in the walk dominates every walk outcome,
///   including a successful open through a later source: an acquisition path
///   that touches a deny-listed host is a service-independence violation
///   (integrity-class), exactly as in the full verifier, where the
///   error-severity issue forces a failed verdict regardless of content
///   success.
/// - Source exhaustion is an availability outcome (`CIPHERTEXT_UNAVAILABLE`,
///   or `CONTENT_FETCH_LIMIT_EXCEEDED` after a ceiling abort), never a verdict
///   on the record.
fn open_sealed_item(
    idx: usize,
    item: &ItemEntry,
    envelope: &SealedEnvelope,
    bundle: &RecipientKeyBundle,
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ItemOpenOutcome {
    let hashes = item_hashes_map(item);
    let item_path = vec![
        PathSegment::Key("items".to_string()),
        PathSegment::Index(idx),
    ];
    let walk = walk_blob_sources(
        None,
        item.uris.as_deref().unwrap_or(&[]),
        true,
        &item_path,
        policy,
        fetcher,
        issues,
        |blob, issues| {
            match ecies_sealed_poe_unwrap(
                envelope,
                blob.bytes,
                &hashes,
                UnwrapKeys::Bundle(bundle),
                None,
            ) {
                Ok(UnwrapResult::Matched { plaintext }) => {
                    SourceDecision::Accept(ItemOpenOutcome::Opened(plaintext))
                }
                Ok(UnwrapResult::NotMatched { reason }) => match reason {
                    UnwrapFailureReason::WrongRecipientKey => {
                        SourceDecision::Accept(ItemOpenOutcome::Failed {
                            code: ErrorCode::WrongRecipientKey.code(),
                            exit: 1,
                        })
                    }
                    UnwrapFailureReason::TamperedHeader => {
                        SourceDecision::Accept(ItemOpenOutcome::Failed {
                            code: ErrorCode::TamperedHeader.code(),
                            exit: 1,
                        })
                    }
                    UnwrapFailureReason::TamperedCiphertext => {
                        if blob.attributable() {
                            SourceDecision::Accept(ItemOpenOutcome::Failed {
                                code: ErrorCode::TamperedCiphertext.code(),
                                exit: 1,
                            })
                        } else {
                            // Unattributable bytes indict the serving provider,
                            // not the record: record the indictment so the
                            // failure stays diagnosable even when a later
                            // source ends the walk differently.
                            issues.push(VerifierIssue::new(
                                ErrorCode::UriProviderIntegrityMismatch,
                                provider_mismatch_path(&item_path, blob),
                                format!(
                                    "ciphertext bytes fetched from {:?} fail the decryption layer and could not be attributed to the URI's content address; the serving provider is indicted, not the record",
                                    blob.uri.unwrap_or("unknown source")
                                ),
                            ));
                            SourceDecision::NextSource
                        }
                    }
                },
                // Unreachable on a strictly validated record (the recipient
                // reading hard-rejects an envelope it cannot fully validate);
                // defensively classed as a header failure.
                Err(_) => SourceDecision::Accept(ItemOpenOutcome::Failed {
                    code: ErrorCode::TamperedHeader.code(),
                    exit: 1,
                }),
            }
        },
    );
    // A deny-host hit dominates the walk result: an item whose acquisition
    // path touches a deny-listed host is a service-independence violation
    // (integrity-class) even when another source served the blob — the walk
    // records the error-severity issue and keeps going, so the dominance rule
    // must apply to every end state, not just exhaustion.
    if issues
        .iter()
        .any(|i| i.code == ErrorCode::ServiceIndependenceViolation)
    {
        return ItemOpenOutcome::Failed {
            code: ErrorCode::ServiceIndependenceViolation.code(),
            exit: 1,
        };
    }
    match walk {
        BlobWalkEnd::Done(outcome) => outcome,
        BlobWalkEnd::Exhausted { limit_exceeded } => {
            let code = if limit_exceeded {
                ErrorCode::ContentFetchLimitExceeded
            } else {
                ErrorCode::CiphertextUnavailable
            };
            ItemOpenOutcome::Failed {
                code: code.code(),
                exit: 2,
            }
        }
    }
}

/// Acquire the item's ciphertext and open its passphrase-sealed envelope with
/// the supplied passphrase(s), recording per-attempt diagnostics in `issues`.
///
/// The blob-source walk mirrors [`open_sealed_item`]: attributable bytes that
/// no passphrase opens condemn the record (`TAMPERED_CIPHERTEXT`), while
/// unattributable bytes indict only the serving provider and the walk continues.
/// A caller-input fault (an unsupported envelope identifier, a below-floor
/// Argon2id parameter set, or a passphrase the normalization profile rejects) is
/// terminal for the item regardless of the blob. A wrong passphrase, a tampered
/// header, and a spliced envelope are one indistinguishable rejection by design.
#[allow(clippy::too_many_arguments)]
fn open_passphrase_item(
    idx: usize,
    item: &ItemEntry,
    enc: &EncScheme1,
    block: &PassphraseBlock,
    passphrases: &[String],
    policy: &ContentFetchPolicy<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    issues: &mut Vec<VerifierIssue>,
) -> ItemOpenOutcome {
    let hashes = item_hashes_map(item);
    let param = |name: &str| {
        block
            .params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
    };
    let (Some(m), Some(t), Some(p)) = (param("m"), param("t"), param("p")) else {
        return ItemOpenOutcome::Failed {
            code: ErrorCode::KdfDerivationFailed.code(),
            exit: 1,
        };
    };
    let item_path = vec![
        PathSegment::Key("items".to_string()),
        PathSegment::Index(idx),
    ];
    let walk = walk_blob_sources(
        None,
        item.uris.as_deref().unwrap_or(&[]),
        true,
        &item_path,
        policy,
        fetcher,
        issues,
        |blob, issues| {
            for passphrase in passphrases {
                match passphrase_sealed_poe_open(PassphraseOpenArgs {
                    blob: blob.bytes,
                    passphrase,
                    aead: &enc.aead,
                    alg: &block.alg,
                    salt: &block.salt,
                    m,
                    t,
                    p,
                    nonce: &enc.nonce,
                    hashes: &hashes,
                }) {
                    Ok(PassphraseOpenResult::Opened { plaintext }) => {
                        return SourceDecision::Accept(ItemOpenOutcome::Opened(plaintext));
                    }
                    // A wrong passphrase, a tampered header, or a spliced envelope
                    // are one indistinguishable rejection; try the next passphrase.
                    Ok(PassphraseOpenResult::Rejected) => {}
                    // A malformed envelope or an unusable passphrase is terminal
                    // for the item no matter which blob was tried.
                    Err(_) => {
                        return SourceDecision::Accept(ItemOpenOutcome::Failed {
                            code: ErrorCode::KdfDerivationFailed.code(),
                            exit: 1,
                        });
                    }
                }
            }
            // Every passphrase rejected this blob: the failure is blob-dependent.
            if blob.attributable() {
                SourceDecision::Accept(ItemOpenOutcome::Failed {
                    code: ErrorCode::TamperedCiphertext.code(),
                    exit: 1,
                })
            } else {
                issues.push(VerifierIssue::new(
                    ErrorCode::UriProviderIntegrityMismatch,
                    provider_mismatch_path(&item_path, blob),
                    format!(
                        "ciphertext bytes fetched from {:?} fail the passphrase decryption layer and could not be attributed to the URI's content address; the serving provider is indicted, not the record",
                        blob.uri.unwrap_or("unknown source")
                    ),
                ));
                SourceDecision::NextSource
            }
        },
    );
    if issues
        .iter()
        .any(|i| i.code == ErrorCode::ServiceIndependenceViolation)
    {
        return ItemOpenOutcome::Failed {
            code: ErrorCode::ServiceIndependenceViolation.code(),
            exit: 1,
        };
    }
    match walk {
        BlobWalkEnd::Done(outcome) => outcome,
        BlobWalkEnd::Exhausted { limit_exceeded } => {
            let code = if limit_exceeded {
                ErrorCode::ContentFetchLimitExceeded
            } else {
                ErrorCode::CiphertextUnavailable
            };
            ItemOpenOutcome::Failed {
                code: code.code(),
                exit: 2,
            }
        }
    }
}

/// Resolve a service gateway (base URL + API key) when one is configured anywhere
/// (`flag > env > profile`), returning `None` when no base URL is set — `inbox
/// decrypt` then falls back to the Cardano chain path.
fn optional_service_gateway(
    base_url: Option<&str>,
    api_key: Option<&str>,
    gateway_profile: Option<&str>,
    cmd: &str,
) -> Result<Option<crate::secret::ServiceGateway>, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    let profile = config.select_gateway(gateway_profile, cmd)?;
    let env = crate::secret::SystemSecretEnv;
    let profile_base = profile.map(|p| p.base_url.as_str());
    let profile_key = profile.and_then(|p| p.api_key.as_deref());

    let Some(base) = crate::secret::resolve_config_value(
        base_url,
        crate::secret::SecretEnv::var(&env, "CARDANOWALL_BASE_URL").as_deref(),
        profile_base,
    ) else {
        return Ok(None);
    };
    let key = crate::secret::resolve_config_value(
        api_key,
        crate::secret::SecretEnv::var(&env, "CARDANOWALL_API_KEY").as_deref(),
        profile_key,
    );
    Ok(Some(crate::secret::ServiceGateway {
        base_url: base,
        api_key: key,
    }))
}

/// Fetch the record's label-309 metadata bytes: the agnostic records API when a
/// service gateway (base URL via flag / env / profile) is configured, otherwise
/// the Cardano gateway chain.
fn fetch_metadata(
    tx_hash: &str,
    args: &InboxDecryptArgs,
    resolved: &ResolvedGateways,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<Vec<u8>, CliError> {
    if let Some(service) = optional_service_gateway(
        args.base_url.as_deref(),
        args.api_key.as_deref(),
        args.gateway_profile.as_deref(),
        "inbox decrypt",
    )? {
        let client = build_client(
            service.base_url,
            service.api_key.as_deref(),
            "inbox decrypt",
        )?;
        let record = client
            .records()
            .get(tx_hash)
            .map_err(|e| map_inbox_client_error(e, "inbox decrypt"))?;
        return decode_standard(&record.metadata_cbor_base64).map_err(|e| {
            CliError::network(format!("inbox decrypt: metadata base64 decode failed: {e}"))
        });
    }
    // Chain path: resolve the tx and extract label-309.
    let resolved_tx = resolve_cardano_tx(
        tx_hash,
        Some(&resolved.cardano_gateway_chain),
        resolved.blockfrost_project_id.as_deref(),
        fetcher,
    )
    .map_err(|e| {
        // A deny-host hit on the resolve path is a service-independence
        // violation — integrity-class. Every other terminal resolve failure
        // (not found, provider unavailable, provider served wrong bytes) is a
        // provider/network outcome, never a verdict on the record.
        if e.code == ErrorCode::ServiceIndependenceViolation {
            CliError::integrity(format!("inbox decrypt: {e}"))
        } else {
            CliError::network(format!("inbox decrypt: {e}"))
        }
    })?;
    // The resolve step verified the tx-hash binding, so these bytes ARE the
    // transaction: both "no label-309 entry" and "undecodable CBOR" are
    // properties of the tx itself (integrity-class), not of the provider.
    match extract_label_309_metadata(&resolved_tx.tx_cbor) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(CliError::integrity(format!(
            "inbox decrypt: tx {tx_hash} has no label-309 metadata"
        ))),
        Err(e) => Err(CliError::integrity(format!(
            "inbox decrypt: failed to decode tx CBOR: {e}"
        ))),
    }
}

fn write_new_file(path: &str, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => f.write_all(bytes).map_err(|e| {
            CliError::network(format!("inbox decrypt: cannot write {path}: {e}"))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(CliError::input(format!(
            "inbox decrypt: refusing to overwrite existing file {path}; remove it or choose a different --out"
        ))),
        Err(e) => Err(CliError::network(format!(
            "inbox decrypt: cannot create {path}: {e}"
        ))),
    }
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// The item's content-hash map in the shape the sealed-PoE transcript consumes.
fn item_hashes_map(item: &ItemEntry) -> BTreeMap<String, Vec<u8>> {
    item.hashes.iter().cloned().collect()
}

fn fail_result(tx_hash: &str, idx: usize, reason: &str) -> DecryptItemResult {
    DecryptItemResult {
        tx_hash: tx_hash.to_string(),
        item_idx: idx,
        status: STATUS_FAILED,
        plaintext_hash_ok: None,
        reason: Some(reason.to_string()),
        bytes_written_to: None,
        byte_count: None,
    }
}

/// A per-item result for an item that was benignly skipped — addressed to a
/// different recipient/credential, not an error.
fn skipped_result(tx_hash: &str, idx: usize, reason: &str) -> DecryptItemResult {
    DecryptItemResult {
        tx_hash: tx_hash.to_string(),
        item_idx: idx,
        status: STATUS_SKIPPED,
        plaintext_hash_ok: None,
        reason: Some(reason.to_string()),
        bytes_written_to: None,
        byte_count: None,
    }
}

fn map_inbox_client_error(err: ClientError, cmd: &str) -> CliError {
    match err {
        ClientError::Http(http) => {
            // A record-not-found is integrity-class; other gateway errors keep
            // their HTTP framing as integrity (server-attributable) vs network.
            CliError::integrity(format!(
                "{cmd}: HTTP {} {}: {}",
                http.http_status(),
                http.code(),
                http.problem().detail
            ))
        }
        other => CliError::network(format!("{cmd}: {other}")),
    }
}

fn print_json(value: &serde_json::Value, pretty: bool) {
    let rendered = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .expect("inbox JSON serialises");
    println!("{rendered}");
}

/// The current UTC time as an RFC 3339 / ISO-8601 string (second precision).
fn current_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (now / 86_400) as i64;
    let secs_of_day = now % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since the Unix epoch → `(year, month, day)` (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_source(seed: Option<&str>, secret_key: Option<&str>) -> crate::inbox::IdentitySource {
        crate::inbox::IdentitySource {
            seed: seed.map(str::to_string),
            seed_file: None,
            seed_stdin: false,
            secret_key: secret_key.map(str::to_string),
            secret_key_file: None,
            secret_key_stdin: false,
        }
    }

    #[test]
    fn decrypt_rejects_bad_tx_hash() {
        let args = InboxDecryptArgs {
            tx_hash: "short".to_string(),
            item: None,
            out: None,
            base_url: None,
            api_key: None,
            gateway_profile: None,
            gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            deny_host: vec![],
            deny_hosts_replace: false,
            identity: seed_source(Some(&"00".repeat(32)), None),
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: false,
            json: false,
            pretty: false,
        };
        assert_eq!(run_decrypt(args).unwrap_err().code, 4);
    }

    #[test]
    fn decrypt_json_without_out_is_input_error_before_any_network() {
        // --json writes the results object to stdout; raw plaintext must never
        // share that stream. The guard fires as a CLI input error (exit 4) before
        // any identity resolution or network call — no --gateway / --base-url is
        // configured here and a bogus (unreachable) key would still error first,
        // so a non-4 exit would mean the guard let network work begin.
        let args = InboxDecryptArgs {
            tx_hash: "aa".repeat(32),
            item: None,
            out: None,
            base_url: None,
            api_key: None,
            gateway_profile: None,
            gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            deny_host: vec![],
            deny_hosts_replace: false,
            identity: seed_source(Some(&"00".repeat(32)), None),
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: false,
            json: true,
            pretty: false,
        };
        let err = run_decrypt(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--out"), "{}", err.message);
    }

    #[test]
    fn decrypt_rejects_passphrase_stdin_conflicting_with_identity_stdin() {
        // Only one secret may be read from stdin per process — the guard fires
        // before any network call, so this is hermetic.
        let mut identity = seed_source(None, None);
        identity.seed_stdin = true;
        let args = InboxDecryptArgs {
            tx_hash: "aa".repeat(32),
            item: None,
            out: None,
            base_url: None,
            api_key: None,
            gateway_profile: None,
            gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            deny_host: vec![],
            deny_hosts_replace: false,
            identity,
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: true,
            json: false,
            pretty: false,
        };
        let err = run_decrypt(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("stdin"), "{}", err.message);
    }

    #[test]
    fn list_secret_key_alone_is_input_error() {
        let args = InboxListArgs {
            gateway: vec![],
            blockfrost: None,
            deny_host: vec![],
            deny_hosts_replace: false,
            identity: seed_source(None, Some(&"ab".repeat(32))),
            json: false,
            pretty: false,
        };
        assert_eq!(run_list(args).unwrap_err().code, 4);
    }

    #[test]
    fn sync_args_debug_redacts_api_key_and_identity() {
        let args = InboxSyncArgs {
            base_url: Some("https://gw.example/api/v1".to_string()),
            api_key: Some("super-secret-bearer".to_string()),
            gateway_profile: None,
            threshold: None,
            identity: seed_source(Some(&"ab".repeat(32)), None),
            json: false,
            pretty: false,
        };
        let rendered = format!("{args:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }

    #[test]
    fn list_args_debug_redacts_blockfrost_and_identity() {
        let args = InboxListArgs {
            gateway: vec!["https://koios.example".to_string()],
            blockfrost: Some("mainnetSECRETprojectid".to_string()),
            deny_host: vec![],
            deny_hosts_replace: false,
            identity: seed_source(Some(&"ab".repeat(32)), None),
            json: false,
            pretty: false,
        };
        let rendered = format!("{args:?}");
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://koios.example"));
    }

    #[test]
    fn decrypt_args_debug_redacts_api_key_blockfrost_and_identity() {
        let args = InboxDecryptArgs {
            tx_hash: "00".repeat(32),
            item: None,
            out: None,
            base_url: Some("https://gw.example/api/v1".to_string()),
            api_key: Some("super-secret-bearer".to_string()),
            gateway_profile: None,
            gateway: vec![],
            blockfrost: Some("mainnetSECRETprojectid".to_string()),
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            deny_host: vec![],
            deny_hosts_replace: false,
            identity: seed_source(None, Some(&"cd".repeat(32))),
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: false,
            json: false,
            pretty: false,
        };
        let rendered = format!("{args:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(!rendered.contains("mainnetSECRETprojectid"));
        assert!(!rendered.contains(&"cd".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }

    #[test]
    fn civil_date_epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    // -----------------------------------------------------------------------
    // open_sealed_item: blob-walk end states
    // -----------------------------------------------------------------------

    use cardanowall::poe_standard::{EncScheme1, EncryptionEnvelope, Slot};
    use cardanowall::sealed_poe::{
        ecies_sealed_poe_wrap_secure, mlkem768x25519_public_key_from_seed, SealedKem, SealedSlots,
        WrapArgs,
    };
    use cardanowall::seed_derive::derive_x25519_keypair;
    use cardanowall::verifier::fetch::{
        FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
    };

    /// Serves exactly the mapped URLs; every other fetch fails as a transport
    /// error.
    struct MapTransport(HashMap<String, Vec<u8>>);

    impl FetchTransport for MapTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            match self.0.get(url) {
                Some(bytes) => Ok(FetchOutboundResult {
                    status: 200,
                    bytes: bytes.clone(),
                    duration_ms: 1,
                }),
                None => Err(OutboundError::Transport {
                    url: url.to_string(),
                    message: "no mapped response".to_string(),
                }),
            }
        }
    }

    /// A syntactically conformant 43-character Arweave txid (the URI parser
    /// refuses anything else, and a refused URI never reaches a gateway).
    fn ar_txid() -> String {
        "a".repeat(43)
    }

    /// A transport that panics on any fetch: proves a not-addressed item is
    /// skipped from the on-chain slots alone, without ever downloading a
    /// ciphertext it cannot open.
    struct PanicTransport;

    impl FetchTransport for PanicTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            panic!("unexpected fetch to {url}: a not-addressed item must be skipped without a download");
        }
    }

    /// Seal `plaintext` to the seed's classical X25519 key, returning the
    /// on-chain item (a single `ar://` URI) plus the off-chain ciphertext.
    fn sealed_item(recipient_seed: &[u8; 32], plaintext: &[u8]) -> (ItemEntry, Vec<u8>) {
        sealed_item_at(recipient_seed, plaintext, &ar_txid())
    }

    /// As [`sealed_item`], but pins the `ar://` txid so a multi-item record can
    /// map each item to a distinct gateway URL.
    fn sealed_item_at(
        recipient_seed: &[u8; 32],
        plaintext: &[u8],
        txid: &str,
    ) -> (ItemEntry, Vec<u8>) {
        let recipient = derive_x25519_keypair(recipient_seed).unwrap();
        let hashes: BTreeMap<String, Vec<u8>> = [(
            "sha2-256".to_string(),
            cardanowall::hash::sha256(plaintext).to_vec(),
        )]
        .into();
        let sealed = ecies_sealed_poe_wrap_secure(WrapArgs {
            plaintext,
            recipient_public_keys: &[recipient.public_key.to_vec()],
            hashes: &hashes,
            kem: Some(SealedKem::X25519),
            ..WrapArgs::default()
        })
        .unwrap();
        let env = sealed.envelope;
        let slots = match &env.slots {
            SealedSlots::X25519(slots) => slots
                .iter()
                .map(|s| Slot {
                    epk: Some(s.epk.clone()),
                    kem_ct: None,
                    wrap: Some(s.wrap.clone()),
                })
                .collect(),
            SealedSlots::Mlkem768X25519(_) => unreachable!("classical seal"),
        };
        let enc = EncryptionEnvelope::Scheme1(EncScheme1 {
            scheme: u64::try_from(env.scheme).unwrap(),
            aead: env.aead.clone(),
            nonce: env.nonce.clone(),
            kem: Some(env.kem.clone()),
            slots: Some(slots),
            slots_mac: Some(env.slots_mac.clone()),
            passphrase: None,
        });
        let item = ItemEntry {
            hashes: hashes.into_iter().collect(),
            uris: Some(vec![format!("ar://{txid}")]),
            enc: Some(enc),
        };
        (item, sealed.ciphertext)
    }

    /// A passphrase-sealed item pointing at `txid`, plus a well-formed 48-byte
    /// ciphertext blob (32-byte commitment header + one empty STREAM tag) that no
    /// passphrase opens — enough to drive the passphrase open path without a real
    /// Argon2id seal on the write side.
    fn passphrase_item(txid: &str) -> (ItemEntry, Vec<u8>) {
        let enc = EncScheme1 {
            scheme: 1,
            aead: "chacha20-poly1305-stream64k".to_string(),
            nonce: vec![0x07u8; 24],
            kem: None,
            slots: None,
            slots_mac: None,
            passphrase: Some(PassphraseBlock {
                alg: "argon2id".to_string(),
                salt: vec![0x09u8; 16],
                params: vec![
                    ("m".to_string(), 65_536),
                    ("t".to_string(), 3),
                    ("p".to_string(), 1),
                ],
            }),
        };
        let item = ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0u8; 32])],
            uris: Some(vec![format!("ar://{txid}")]),
            enc: Some(EncryptionEnvelope::Scheme1(enc)),
        };
        (item, vec![0u8; 48])
    }

    fn bundle_for_seed(seed: &[u8; 32]) -> RecipientKeyBundle {
        crate::inbox::identity::resolve_identity(
            Some(&cardanowall::hex::encode(seed)),
            None,
            "inbox decrypt",
        )
        .unwrap()
        .recipient_key_bundle()
    }

    /// The bundle a raw `--secret-key` resolves to: KEM-agnostic, both roles set
    /// to the identical 32 bytes.
    fn bundle_for_raw_key(key: &[u8; 32]) -> RecipientKeyBundle {
        crate::inbox::identity::resolve_identity(
            None,
            Some(&cardanowall::hex::encode(key)),
            "inbox decrypt",
        )
        .unwrap()
        .recipient_key_bundle()
    }

    /// Seal `plaintext` to the raw key used as an X-Wing (`mlkem768x25519`)
    /// decapsulation seed, returning the on-chain hybrid item plus the off-chain
    /// ciphertext. The recipient X-Wing public key is derived from the same raw
    /// bytes a raw `--secret-key` supplies.
    fn xwing_sealed_item_at(
        recipient_raw_key: &[u8; 32],
        plaintext: &[u8],
        txid: &str,
    ) -> (ItemEntry, Vec<u8>) {
        let recipient_pub = mlkem768x25519_public_key_from_seed(recipient_raw_key).unwrap();
        let hashes: BTreeMap<String, Vec<u8>> = [(
            "sha2-256".to_string(),
            cardanowall::hash::sha256(plaintext).to_vec(),
        )]
        .into();
        let sealed = ecies_sealed_poe_wrap_secure(WrapArgs {
            plaintext,
            recipient_public_keys: &[recipient_pub.to_vec()],
            hashes: &hashes,
            kem: Some(SealedKem::Mlkem768X25519),
            ..WrapArgs::default()
        })
        .unwrap();
        let env = sealed.envelope;
        let slots = match &env.slots {
            SealedSlots::Mlkem768X25519(slots) => slots
                .iter()
                .map(|s| Slot {
                    epk: None,
                    kem_ct: Some(s.kem_ct.clone()),
                    wrap: Some(s.wrap.clone()),
                })
                .collect(),
            SealedSlots::X25519(_) => unreachable!("hybrid seal"),
        };
        let enc = EncryptionEnvelope::Scheme1(EncScheme1 {
            scheme: u64::try_from(env.scheme).unwrap(),
            aead: env.aead.clone(),
            nonce: env.nonce.clone(),
            kem: Some(env.kem.clone()),
            slots: Some(slots),
            slots_mac: Some(env.slots_mac.clone()),
            passphrase: None,
        });
        let item = ItemEntry {
            hashes: hashes.into_iter().collect(),
            uris: Some(vec![format!("ar://{txid}")]),
            enc: Some(enc),
        };
        (item, sealed.ciphertext)
    }

    #[test]
    fn decrypt_items_raw_secret_key_opens_xwing_item() {
        // A raw --secret-key is KEM-agnostic: the same 32 bytes are the X-Wing
        // decapsulation seed, so it opens an mlkem768x25519-sealed item exactly as
        // `verify --secret-key` does. Before the fix the bundle carried an empty
        // mlkem list and this cleanly (and wrongly) reported not-addressed.
        let raw_key = [0x44u8; 32];
        let txid = "b".repeat(43);
        let (item, ciphertext) = xwing_sealed_item_at(&raw_key, b"hybrid payload", &txid);
        let items = vec![item];
        let bundle = bundle_for_raw_key(&raw_key);

        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{txid}"),
            ciphertext,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));

        let tmp = tempfile::tempdir().unwrap();
        let out_path = tmp.path().join("recv.bin");
        let out = out_path.to_str().unwrap();
        let tx = "aa".repeat(32);

        let run = decrypt_items(
            &tx,
            &items,
            &[0usize],
            true,
            Some(&bundle),
            &[],
            Some(out),
            &policy,
            &mut fetcher,
        )
        .unwrap();

        assert_eq!(run.exit_code, 0);
        assert_eq!(run.results.len(), 1);
        assert_eq!(run.results[0].status, STATUS_DECRYPTED);
        assert_eq!(std::fs::read(out).unwrap(), b"hybrid payload");
    }

    #[test]
    fn open_sealed_item_deny_host_hit_dominates_a_successful_open() {
        let seed = [0x21u8; 32];
        let (item, ciphertext) = sealed_item(&seed, b"sealed payload");
        let envelope = envelope_from_item(&item).unwrap();
        let bundle = bundle_for_seed(&seed);

        // First gateway is deny-listed; the second serves the genuine bytes,
        // so the walk itself ends in a successful open.
        let gateways = vec![
            "https://operator.example".to_string(),
            "https://good.example".to_string(),
        ];
        let policy = ContentFetchPolicy {
            arweave_gateways: &gateways,
            ipfs_gateways: &[],
            max_fetch_bytes: None,
        };
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{}", ar_txid()),
            ciphertext,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome = open_sealed_item(
            0,
            &item,
            &envelope,
            &bundle,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        // The service-independence violation dominates the successful open:
        // integrity-class failure, never exit 0.
        match outcome {
            ItemOpenOutcome::Failed { code, exit } => {
                assert_eq!(code, ErrorCode::ServiceIndependenceViolation.code());
                assert_eq!(exit, 1);
            }
            ItemOpenOutcome::Opened(_) => {
                panic!("a deny-host hit must dominate a successful open")
            }
        }
        assert!(issues
            .iter()
            .any(|i| i.code == ErrorCode::ServiceIndependenceViolation));
    }

    #[test]
    fn open_sealed_item_indicts_provider_for_unattributable_tampered_blob() {
        let seed = [0x22u8; 32];
        let (item, ciphertext) = sealed_item(&seed, b"sealed payload");
        let envelope = envelope_from_item(&item).unwrap();
        let bundle = bundle_for_seed(&seed);

        // The only source serves tampered bytes; an ar:// blob carries no
        // verifiable content-address binding, so the bytes are unattributable
        // and must indict the provider, not the record.
        let mut tampered = ciphertext;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let gateways = vec!["https://good.example".to_string()];
        let policy = ContentFetchPolicy {
            arweave_gateways: &gateways,
            ipfs_gateways: &[],
            max_fetch_bytes: None,
        };
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{}", ar_txid()),
            tampered,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome = open_sealed_item(
            0,
            &item,
            &envelope,
            &bundle,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        // The provider indictment is recorded as a diagnostic...
        assert!(issues
            .iter()
            .any(|i| i.code == ErrorCode::UriProviderIntegrityMismatch));
        // ...and the walk ends in availability: the record is not condemned.
        match outcome {
            ItemOpenOutcome::Failed { code, exit } => {
                assert_eq!(code, ErrorCode::CiphertextUnavailable.code());
                assert_eq!(exit, 2);
            }
            ItemOpenOutcome::Opened(_) => panic!("tampered ciphertext must not open"),
        }
    }

    // -----------------------------------------------------------------------
    // Multi-recipient all-items semantics: benign-skip vs. escalate
    // -----------------------------------------------------------------------

    fn arweave_policy(gateways: &[String]) -> ContentFetchPolicy<'_> {
        ContentFetchPolicy {
            arweave_gateways: gateways,
            ipfs_gateways: &[],
            max_fetch_bytes: None,
        }
    }

    #[test]
    fn open_recipient_slots_item_skips_not_addressed_without_fetch() {
        // A record item sealed to someone else, opened with a stranger's bundle
        // in all-items mode: the on-chain slots settle non-addressability, so the
        // panic transport is never reached — no ciphertext is downloaded.
        let (item, _ct) = sealed_item_at(&[0x70u8; 32], b"secret", &"b".repeat(43));
        let bundle = bundle_for_seed(&[0x71u8; 32]);
        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = PanicTransport;
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome = open_recipient_slots_item(
            0,
            &item,
            Some(&bundle),
            true,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        assert!(matches!(
            outcome,
            ItemOutcome::Skipped {
                reason: "NOT_ADDRESSED",
                ..
            }
        ));
        assert!(issues.is_empty());
    }

    #[test]
    fn open_recipient_slots_item_no_identity_all_items_skips() {
        // Recipient-sealed item, but no identity supplied: in all-items mode this
        // item simply needs the other credential type — benign skip.
        let (item, _ct) = sealed_item_at(&[0x80u8; 32], b"secret", &"b".repeat(43));
        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = PanicTransport;
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome =
            open_recipient_slots_item(0, &item, None, true, &policy, &mut fetcher, &mut issues);

        assert!(matches!(
            outcome,
            ItemOutcome::Skipped {
                reason: "WRONG_DECRYPTION_INPUT_SHAPE",
                ..
            }
        ));
    }

    #[test]
    fn open_recipient_slots_item_no_identity_target_mode_fails() {
        // The same item under an explicit --item target: strict, exit 1.
        let (item, _ct) = sealed_item_at(&[0x80u8; 32], b"secret", &"b".repeat(43));
        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = PanicTransport;
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome =
            open_recipient_slots_item(0, &item, None, false, &policy, &mut fetcher, &mut issues);

        match outcome {
            ItemOutcome::Failed { code, exit, .. } => {
                assert_eq!(code, "WRONG_DECRYPTION_INPUT_SHAPE");
                assert_eq!(exit, 1);
            }
            _ => panic!("--item on a recipient item without a key must fail, not skip"),
        }
    }

    #[test]
    fn open_recipient_slots_item_target_mode_wrong_key_fails() {
        // --item N targeting an item sealed to someone else: a wrong recipient
        // key is terminal (exit 1), never a benign skip. The gate is not applied
        // in --item mode, so the blob IS fetched and the unwrap rejects the key.
        let (item, ct) = sealed_item_at(&[0x60u8; 32], b"secret", &"b".repeat(43));
        let bundle = bundle_for_seed(&[0x61u8; 32]);
        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{}", "b".repeat(43)),
            ct,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();

        let outcome = open_recipient_slots_item(
            0,
            &item,
            Some(&bundle),
            false,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        match outcome {
            ItemOutcome::Failed { code, exit, .. } => {
                assert_eq!(code, ErrorCode::WrongRecipientKey.code());
                assert_eq!(exit, 1);
            }
            _ => panic!("--item wrong recipient key must fail, not skip"),
        }
    }

    #[test]
    fn decrypt_items_multi_recipient_decrypts_mine_skips_others() {
        // A 3-item record: items 0 and 2 sealed to me, item 1 to someone else.
        // All-items decrypt writes my two and skips the third — exit 0.
        let me = [0x30u8; 32];
        let other = [0x31u8; 32];
        let (item0, ct0) = sealed_item_at(&me, b"item zero", &"b".repeat(43));
        let (item1, _ct1) = sealed_item_at(&other, b"item one", &"c".repeat(43));
        let (item2, ct2) = sealed_item_at(&me, b"item two", &"d".repeat(43));
        let items = vec![item0, item1, item2];
        let bundle = bundle_for_seed(&me);

        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        // Only my two items' ciphertexts are served; item 1 is gated out before
        // any fetch, so its (absent) URL is never requested.
        let transport = MapTransport(HashMap::from([
            (format!("https://good.example/{}", "b".repeat(43)), ct0),
            (format!("https://good.example/{}", "d".repeat(43)), ct2),
        ]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));

        let tmp = tempfile::tempdir().unwrap();
        let out_path = tmp.path().join("recv");
        let out = out_path.to_str().unwrap();
        let tx = "aa".repeat(32);

        let run = decrypt_items(
            &tx,
            &items,
            &[0usize, 1, 2],
            true,
            Some(&bundle),
            &[],
            Some(out),
            &policy,
            &mut fetcher,
        )
        .unwrap();

        assert_eq!(run.exit_code, 0);
        assert_eq!(run.results.len(), 3);
        assert_eq!(run.results[0].status, STATUS_DECRYPTED);
        assert_eq!(run.results[1].status, STATUS_SKIPPED);
        assert_eq!(run.results[1].reason.as_deref(), Some("NOT_ADDRESSED"));
        assert_eq!(run.results[2].status, STATUS_DECRYPTED);

        assert_eq!(
            std::fs::read(format!("{out}.item-0.bin")).unwrap(),
            b"item zero"
        );
        assert_eq!(
            std::fs::read(format!("{out}.item-2.bin")).unwrap(),
            b"item two"
        );
        assert!(!std::path::Path::new(&format!("{out}.item-1.bin")).exists());
    }

    #[test]
    fn decrypt_items_zero_addressed_all_skipped_exit_zero() {
        // No item is sealed to me: every item is skipped and the exit is 0 (the
        // clear "0 of N" message is emitted by run_decrypt from this state).
        let me = [0x40u8; 32];
        let other = [0x41u8; 32];
        let (item0, _) = sealed_item_at(&other, b"a", &"b".repeat(43));
        let (item1, _) = sealed_item_at(&other, b"b", &"c".repeat(43));
        let items = vec![item0, item1];
        let bundle = bundle_for_seed(&me);

        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        // Nothing mapped and a panic transport: no item is addressed, so no fetch
        // is attempted.
        let transport = PanicTransport;
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let tx = "aa".repeat(32);

        let run = decrypt_items(
            &tx,
            &items,
            &[0usize, 1],
            true,
            Some(&bundle),
            &[],
            None,
            &policy,
            &mut fetcher,
        )
        .unwrap();

        assert_eq!(run.exit_code, 0);
        assert_eq!(run.results.len(), 2);
        assert!(run.results.iter().all(|r| r.status == STATUS_SKIPPED));
    }

    #[test]
    fn decrypt_items_addressed_deny_host_escalates_exit_one() {
        // An item addressed to me whose only source is a deny-listed host: the
        // gate lets it through, then the acquisition touches a deny host — a
        // service-independence violation that escalates to exit 1.
        let me = [0x50u8; 32];
        let (item, ct) = sealed_item_at(&me, b"payload", &"b".repeat(43));
        let items = vec![item];
        let bundle = bundle_for_seed(&me);

        let gateways = vec!["https://operator.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = MapTransport(HashMap::from([(
            format!("https://operator.example/{}", "b".repeat(43)),
            ct,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let tx = "aa".repeat(32);

        let run = decrypt_items(
            &tx,
            &items,
            &[0usize],
            true,
            Some(&bundle),
            &[],
            None,
            &policy,
            &mut fetcher,
        )
        .unwrap();

        assert_eq!(run.exit_code, 1);
        assert_eq!(run.results[0].status, STATUS_FAILED);
    }

    #[test]
    fn passphrase_item_all_items_wrong_passphrase_skips_not_escalates() {
        // A passphrase item has no slots-only gate: it must be fetched and tried.
        // A non-open is indistinguishable between a wrong/other passphrase and
        // tampering, so in all-items mode it is a benign, best-effort skip.
        let txid = "e".repeat(43);
        let (item, blob) = passphrase_item(&txid);
        let EncryptionEnvelope::Scheme1(enc) = item.enc.as_ref().unwrap() else {
            unreachable!("passphrase_item builds a Scheme1 envelope");
        };
        let block = enc.passphrase.as_ref().unwrap();

        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{txid}"),
            blob,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();
        let passphrases = vec!["definitely-wrong".to_string()];

        let outcome = open_passphrase_sealed_item(
            0,
            &item,
            enc,
            block,
            &passphrases,
            true,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        assert!(matches!(
            outcome,
            ItemOutcome::Skipped {
                reason: "PASSPHRASE_NO_MATCH",
                ..
            }
        ));
    }

    #[test]
    fn passphrase_item_target_mode_wrong_passphrase_fails() {
        // The same item under an explicit --item target: strict, non-zero exit.
        let txid = "e".repeat(43);
        let (item, blob) = passphrase_item(&txid);
        let EncryptionEnvelope::Scheme1(enc) = item.enc.as_ref().unwrap() else {
            unreachable!("passphrase_item builds a Scheme1 envelope");
        };
        let block = enc.passphrase.as_ref().unwrap();

        let gateways = vec!["https://good.example".to_string()];
        let policy = arweave_policy(&gateways);
        let transport = MapTransport(HashMap::from([(
            format!("https://good.example/{txid}"),
            blob,
        )]));
        let deny = vec!["operator.example".to_string()];
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny));
        let mut issues: Vec<VerifierIssue> = Vec::new();
        let passphrases = vec!["definitely-wrong".to_string()];

        let outcome = open_passphrase_sealed_item(
            0,
            &item,
            enc,
            block,
            &passphrases,
            false,
            &policy,
            &mut fetcher,
            &mut issues,
        );

        match outcome {
            ItemOutcome::Failed { exit, .. } => assert_ne!(exit, 0),
            _ => panic!("--item wrong passphrase must fail, not skip"),
        }
    }

    // -----------------------------------------------------------------------
    // Record authorship (sender-identity verdict split)
    // -----------------------------------------------------------------------

    /// A minimal hash-only record carrying `digest` as its single item's
    /// `sha2-256` claim.
    fn hash_only_record(digest: [u8; 32]) -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), digest.to_vec())],
                uris: None,
                enc: None,
            }]),
            ..PoeRecord::default()
        }
    }

    #[test]
    fn record_authorship_surfaces_kid_signer() {
        use cardanowall::client::{assemble_cose_sign1, prepare_sig_structure, Signer};
        use cardanowall::seed_derive::signer_from_seed;

        let seed = [7u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let pubkey = signer.signer_pubkey();
        let record = hash_only_record([0x11u8; 32]);
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let signature = signer.sign(&prepared.sig_structure_bytes).unwrap();
        let assembled = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();
        let mut signed = record;
        signed.sigs = Some(vec![assembled.sig_entry]);

        let authorship = record_authorship(&signed);
        assert_eq!(authorship.signature_count, 1);
        let sig = &authorship.signatures[0];
        assert_eq!(sig.verdict, AUTHORSHIP_VALID);
        assert_eq!(sig.signer_type, Some("in-signature-kid"));
        assert_eq!(
            sig.signer_pub.as_deref(),
            Some(cardanowall::hex::encode(&pubkey).as_str())
        );
        // The fingerprint is the same xxxx-xxxx-xxxx-xxxx display tag the identity
        // command shows.
        let fp = sig.fingerprint.as_deref().unwrap();
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches('-').count(), 3);

        // The JSON surface carries the signer info (snake_case, matching the rest
        // of the inbox decrypt object).
        let json = serde_json::to_value(&authorship).unwrap();
        assert_eq!(json["signature_count"], 1);
        assert_eq!(json["signatures"][0]["verdict"], "valid");
        assert_eq!(json["signatures"][0]["signer_type"], "in-signature-kid");
        assert!(json["signatures"][0]["signer_pub"].is_string());
        assert!(json["signatures"][0]["fingerprint"].is_string());
    }

    #[test]
    fn record_authorship_marks_unsigned_record() {
        // A record with no signatures is the explicit "unsigned" marker: count 0,
        // an empty list — never an omitted or failed authorship signal.
        let record = hash_only_record([0x22u8; 32]);
        let authorship = record_authorship(&record);
        assert_eq!(authorship.signature_count, 0);
        assert!(authorship.signatures.is_empty());
        let json = serde_json::to_value(&authorship).unwrap();
        assert_eq!(json["signature_count"], 0);
        assert!(json["signatures"].as_array().unwrap().is_empty());
    }
}
