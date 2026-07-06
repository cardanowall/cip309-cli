//! `cardanowall submit` — anchor a Label 309 PoE from the command line.
//!
//! Wraps the record-building and publish plumbing as one subcommand with four
//! mutually exclusive modes:
//!
//! - `--hash <spec>`           anchor precomputed digests (repeatable: one
//!   `items[i]` per `--hash`). A spec is a comma-separated list of one or more
//!   `alg:digest` pairs — co-hashing one item under several algorithms
//!   (`--hash sha2-256:<hex>,blake2b-256:<hex>`); a bare `<hex>` takes the lone
//!   `--hash-alg` (default `sha2-256`)
//! - `--file <path>`           hash the file contents and anchor the digest(s)
//!   (`--hash-alg` is repeatable, co-hashing the file under each); add
//!   `--store` to also upload the plaintext and bind its `ar://` URI
//! - `--uri <ar://|ipfs://>`   attach content-discovery mirrors to every
//!   `--hash` / `--file` item, independent of `--store` (repeatable)
//! - `--merkle <leaves-file>`  anchor a Merkle commitment. The file is either
//!   the canonical leaves-list artifact `merkle build` emits
//!   (`cardano-poe-merkle-leaves-v1` CBOR, raw bytes or hex text — its
//!   advisory `leaf_alg` travels into the uploaded list) or a plain text
//!   file with one 64-hex leaf per line; the root + leaves-list (Arweave)
//!   are anchored
//! - `--record <file|->`       publish a pre-built canonical-CBOR record
//!   byte-for-byte (hex text or raw bytes; validated locally first). This
//!   closes the air-gap loop: `sign prepare` → external signer →
//!   `sign assemble` → `submit --record`.
//!
//! Storage uploads (the `--merkle` leaves-list) are size-gated: a blob at or under
//! the resumable threshold rides the single-shot upload; a larger blob uploads in
//! resumable chunks, so an interrupted transfer over a flaky link resumes from the
//! server's missing set instead of restarting. `--chunk-bytes` tunes the chunk
//! size; the server's per-chunk ceiling clamps it down when tighter.
//!
//! Pricing protocol: the gateway requires the published record's canonical
//! length to be at or under the quoted `record_bytes`. For `--hash` / `--file`
//! the record is built (and signed) FIRST, so the quote prices its exact
//! encoded length; for `--merkle` the `ar://` leaves-list URI exists only
//! after the upload, so the quote is priced from the exact-width upper-bound
//! estimate, while the leaves-list's own byte count is exact. The returned
//! `quote_id` is consumed atomically with the record insert.
//!
//! Signer architecture: the SDK never holds identity keys. The optional `--seed`
//! is the 32-byte master identity seed; the record-signing Ed25519 key is derived
//! from it (the same key `identity --seed` prints). Omit it to publish unsigned.
//!
//! Gateway-agnostic: `--base-url` (or `CARDANOWALL_BASE_URL`) and `--api-key` (or
//! `CARDANOWALL_API_KEY`) are required; the key is an opaque bearer forwarded
//! verbatim, never inspected.
//!
//! `--wait submitted|confirmed` (opt-in) follows the record's SSE lifecycle
//! stream after the publish; `--timeout` bounds it. On expiry the summary is
//! still printed and the process exits `3` (pending) — the publish continues
//! server-side. Re-running submit with identical inputs is safe: the gateway
//! deduplicates byte-identical records with no second debit. The optional
//! `--idempotency-key` is forwarded verbatim under the gateway's strict
//! contract (reusing a key requires a byte-identical request body).
//!
//! Exit codes: `0` ok / `1` server rejection or terminal publish failure / `2`
//! network or partial-upload failure / `3` --wait timeout / `4` CLI input error.

use std::io::Read;

use cardanowall::client::{
    Label309Client, Label309ClientConfig, MerkleLeaf, PublishInput, PublishMerkleInput, QuoteInput,
    ResumableSource, ResumableUploadInput, Signer,
};
use cardanowall::estimate::{ItemShape, RecordShape};
use cardanowall::merkle::{decode_leaves_list, DecodedLeavesList, MerkleLeavesListError};
use cardanowall::poe_standard::{
    validate_poe_record, ItemEntry, PoeRecord, ValidateResult, ValidatorOptions,
};
use cardanowall::seed_derive::SeedSigner;
use clap::Args;
use serde::Serialize;

use crate::commands::publish_common::{
    arweave_uri_placeholder, cohash_content, content_upload_idempotency_key,
    encode_record_with_signer, enforce_max_usd, map_client_error, map_publish_error,
    map_upload_error, parse_cohash_spec, parse_supersedes, refresh_quote_if_stale,
    resolve_content_hash_algs, resolve_optional_signer, resolve_required_gateway,
    validate_content_uris, wait_for_poe_target, ContentHashAlg, GatewayArgs, WaitOutcome,
    WaitTargetArg, STORED_CONTENT_UPLOAD_ROLE,
};
use crate::secret::{SecretArgs, SecretEnv, ServiceGateway, SystemSecretEnv};
use crate::util::{
    bytes_to_hex, format_usd_micros, hex_to_bytes, is_all_hex, parse_usd_to_micros, CliError,
};

/// The storage backend `--store` uploads plaintext content to.
const STORAGE_TARGET_ARWEAVE: &str = "arweave";

/// Arguments for `cardanowall submit`.
/// `seed` (the raw argv identity seed) and `api_key` (the bearer token) are
/// secret material, so `Debug` is hand-written to redact both: no `{:?}`, log,
/// or panic-backtrace path can ever surface them.
#[derive(Args)]
pub struct SubmitArgs {
    /// precomputed digest spec (repeatable: each --hash publishes one items[]).
    /// A spec is a comma-separated list of `alg:digest` pairs co-hashing one
    /// item (e.g. `sha2-256:<hex>,blake2b-256:<hex>`); a bare `<hex>` takes the
    /// lone --hash-alg (default sha2-256).
    #[arg(long, value_name = "SPEC", num_args = 1..)]
    pub hash: Vec<String>,
    /// path to a file whose contents will be hashed and anchored.
    #[arg(long)]
    pub file: Option<String>,
    /// content-discovery URI to attach to every item: an already-pinned
    /// `ar://` / `ipfs://` mirror (repeatable). Independent of --store, which
    /// uploads the plaintext and binds its own `ar://`.
    #[arg(long = "uri", value_name = "AR-OR-IPFS-URI")]
    pub uri: Vec<String>,
    /// with --file: also upload the PLAINTEXT content to storage and bind the
    /// returned ar:// URI into the record (a public attachment).
    #[arg(long)]
    pub store: bool,
    /// leaves to commit under one Merkle root: the canonical leaves-list
    /// artifact from `merkle build` (CBOR, raw bytes or hex text; carries the
    /// advisory leaf_alg), or a plain text file with one 64-hex sha2-256 leaf
    /// per line.
    #[arg(long)]
    pub merkle: Option<String>,
    /// pre-built canonical-CBOR record to publish byte-for-byte (a file path,
    /// or '-' for stdin; hex text or raw bytes). Validated locally before any
    /// network call; never re-encoded or re-signed.
    #[arg(long, value_name = "FILE|-")]
    pub record: Option<String>,
    /// content-hash algorithm (repeatable: co-hash a --file item under each,
    /// e.g. --hash-alg sha2-256 --hash-alg blake2b-256; also the default alg
    /// for a bare --hash digest). --merkle accepts sha2-256 only. Default
    /// sha2-256.
    #[arg(long = "hash-alg", value_name = "ALG")]
    pub hash_alg: Vec<String>,
    /// mark this record as superseding an earlier one: the 64-hex Cardano
    /// transaction hash of the record being replaced (--hash / --file / --merkle
    /// modes; a --record carries its own supersedes inside its bytes).
    #[arg(long = "supersedes", value_name = "TX64")]
    pub supersedes: Option<String>,
    /// refuse to publish when the quoted price exceeds this USD amount
    /// (e.g. '1.50'). The refusal exits 1 before any upload or publish.
    #[arg(long = "max-usd", value_name = "USD")]
    pub max_usd: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or the active gateway
    /// profile). Required.
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// 32-byte master identity seed: 64-digit hex or the checksummed
    /// L309-SEED-1... form. Omit to publish unsigned. INSECURE on argv (shell
    /// history / ps / CI logs); prefer --seed-file / --seed-stdin /
    /// CARDANOWALL_SEED.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin (also `--seed -`).
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
    /// target Label 309 gateway base URL (or env CARDANOWALL_BASE_URL, or the active
    /// gateway profile). Required. Full base incl. the version segment, e.g.
    /// `https://cardanowall.com/api/v1`.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// chunk size in bytes for a resumable storage upload (--merkle leaves-list).
    /// A blob over the resumable threshold uploads in chunks so an interrupted
    /// transfer over a flaky link resumes instead of restarting; one at or under
    /// it rides the single-shot path. The server's per-chunk ceiling clamps this
    /// down when it is tighter. Omit for the default.
    #[arg(long = "chunk-bytes")]
    pub chunk_bytes: Option<u64>,
    /// optional Idempotency-Key forwarded verbatim. The gateway's contract is
    /// strict: reusing a key requires a byte-identical request body (which
    /// includes the quote_id), otherwise the publish is rejected (409).
    /// Re-running submit with identical inputs is already safe without a key —
    /// byte-identical records deduplicate server-side with no second debit.
    #[arg(long = "idempotency-key", value_name = "KEY")]
    pub idempotency_key: Option<String>,
    /// after publishing, follow the record's lifecycle stream until it reaches
    /// this state (omit to return immediately after gateway acceptance).
    #[arg(long = "wait", value_enum)]
    pub wait: Option<WaitTargetArg>,
    /// --wait deadline in seconds. On expiry the summary is still printed and
    /// the process exits 3 (pending) — the publish continues on the gateway.
    #[arg(long = "timeout", default_value_t = 600, value_name = "SECONDS")]
    pub timeout: u64,
    /// emit a machine-readable JSON summary on stdout.
    #[arg(long)]
    pub json: bool,
}

impl std::fmt::Debug for SubmitArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmitArgs")
            .field("hash", &self.hash)
            .field("file", &self.file)
            .field("uri", &self.uri)
            .field("store", &self.store)
            .field("merkle", &self.merkle)
            .field("record", &self.record)
            .field("hash_alg", &self.hash_alg)
            .field("supersedes", &self.supersedes)
            .field("max_usd", &self.max_usd)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .field("base_url", &self.base_url)
            .field("gateway_profile", &self.gateway_profile)
            .field("chunk_bytes", &self.chunk_bytes)
            .field("idempotency_key", &self.idempotency_key)
            .field("wait", &self.wait)
            .field("timeout", &self.timeout)
            .field("json", &self.json)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct SubmitOutcome {
    mode: &'static str,
    id: String,
    tx_hash: Option<String>,
    status: String,
    /// The exact canonical-CBOR record bytes that were published, hex-encoded
    /// — archive them; a verifier compares them against the on-chain
    /// metadata byte for byte.
    record_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    items_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ar_uri: Option<String>,
    /// Whether the gateway replayed an already-anchored byte-identical record
    /// (no new debit). `None` on the --merkle path, where the SDK helper does
    /// not report the dedup disposition.
    #[serde(skip_serializing_if = "Option::is_none")]
    replayed: Option<bool>,
    balance_after_usd_micros: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Hash,
    File,
    Merkle,
    Record,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Hash => "hash",
            Mode::File => "file",
            Mode::Merkle => "merkle",
            Mode::Record => "record",
        }
    }
}

impl SubmitArgs {
    fn seed_secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }
}

/// Resolve the required service gateway (base URL + API key) through
/// `flag > env > active gateway profile`.
fn resolve_gateway(args: &SubmitArgs, env: &dyn SecretEnv) -> Result<ServiceGateway, CliError> {
    resolve_required_gateway(
        GatewayArgs {
            base_url: args.base_url.as_deref(),
            api_key: args.api_key.as_deref(),
            gateway_profile: args.gateway_profile.as_deref(),
        },
        "submit",
        env,
    )
}

/// Build the optional seed signer via the shared secret layer.
fn resolve_signer(args: &SubmitArgs, env: &dyn SecretEnv) -> Result<Option<SeedSigner>, CliError> {
    resolve_optional_signer(&args.seed_secret_args(), "submit", env)
}

fn choose_mode(args: &SubmitArgs) -> Result<Mode, CliError> {
    let mut modes = Vec::new();
    if !args.hash.is_empty() {
        modes.push(Mode::Hash);
    }
    if args.file.is_some() {
        modes.push(Mode::File);
    }
    if args.merkle.is_some() {
        modes.push(Mode::Merkle);
    }
    if args.record.is_some() {
        modes.push(Mode::Record);
    }
    match modes.len() {
        0 => Err(CliError::input(
            "submit: exactly one of --hash / --file / --merkle / --record is required",
        )),
        1 => Ok(modes[0]),
        _ => Err(CliError::input(format!(
            "submit: --hash / --file / --merkle / --record are mutually exclusive (got: {})",
            modes
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Load the `--merkle` leaves input: the leaf set plus the advisory
/// `leaf_alg` to carry into the uploaded leaves-list.
///
/// Two on-disk shapes are accepted:
///
/// - the canonical leaves-list artifact `merkle build` emits
///   (`cardano-poe-merkle-leaves-v1` CBOR) — as raw bytes, or as the hex text
///   the build outcome prints. Its `leaf_alg`, when present, travels into the
///   published leaves-list unchanged;
/// - a plain text file with one 64-hex leaf per line, which carries no
///   `leaf_alg` claim.
fn load_merkle_leaves(path: &str) -> Result<(Vec<MerkleLeaf>, Option<String>), CliError> {
    let raw = std::fs::read(path)
        .map_err(|e| CliError::network(format!("submit: cannot read --merkle {path}: {e}")))?;
    let artifact_error = |e: MerkleLeavesListError| {
        CliError::input(format!(
            "submit: --merkle {path} is not a valid leaves-list artifact: {e}"
        ))
    };
    let Ok(text) = std::str::from_utf8(&raw) else {
        // Not text at all: only the raw-CBOR artifact shape can apply.
        let decoded = decode_leaves_list(&raw).map_err(artifact_error)?;
        return Ok(leaves_input_from_artifact(decoded));
    };
    let trimmed = text.trim();
    // A single hex blob that cannot be one 64-hex leaf line is the artifact in
    // its hex-text form (the shape the `merkle build` outcome prints).
    if !trimmed.is_empty() && trimmed.len() != 64 && is_all_hex(trimmed) {
        let bytes = hex_to_bytes(trimmed)
            .map_err(|e| CliError::input(format!("submit: --merkle {path}: {e}")))?;
        let decoded = decode_leaves_list(&bytes).map_err(artifact_error)?;
        return Ok(leaves_input_from_artifact(decoded));
    }
    let leaves = parse_leaves_file(text, path)?;
    Ok((leaves.into_iter().map(MerkleLeaf::Hex).collect(), None))
}

/// Lower a decoded leaves-list artifact to the publish input's leaf shape.
fn leaves_input_from_artifact(decoded: DecodedLeavesList) -> (Vec<MerkleLeaf>, Option<String>) {
    (
        decoded
            .leaves
            .into_iter()
            .map(|leaf| MerkleLeaf::Bytes(leaf.to_vec()))
            .collect(),
        decoded.leaf_alg,
    )
}

fn parse_leaves_file(text: &str, path: &str) -> Result<Vec<String>, CliError> {
    let mut leaves = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::input(format!(
                "submit: --merkle {path}: line {} is not a 64-hex sha2-256 leaf: \"{t}\"",
                i + 1
            )));
        }
        leaves.push(t.to_lowercase());
    }
    if leaves.is_empty() {
        return Err(CliError::input(format!(
            "submit: --merkle {path} contains no leaves"
        )));
    }
    Ok(leaves)
}

fn emit_outcome(outcome: &SubmitOutcome, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(outcome).expect("SubmitOutcome serialises")
        );
        return;
    }
    println!("ok: {}", outcome.id);
    println!("  status:      {}", outcome.status);
    println!(
        "  tx_hash:     {}",
        outcome.tx_hash.as_deref().unwrap_or("<pending>")
    );
    if let Some(items) = outcome.items_count {
        println!("  items_count: {items}");
    }
    if let Some(root) = &outcome.root {
        println!("  root:        {root}");
        println!("  leaf_count:  {}", outcome.leaf_count.unwrap_or(0));
        println!("  ar_uri:      {}", outcome.ar_uri.as_deref().unwrap_or(""));
    }
    println!(
        "  balance:     {}",
        format_usd_micros(&outcome.balance_after_usd_micros)
    );
    if outcome.replayed == Some(true) {
        println!("  replayed:    true (already anchored; no new debit)");
    }
}

/// The record-shaping inputs the local-build modes share.
struct BuildInputs<'a> {
    signer: Option<&'a dyn Signer>,
    supersedes: Option<&'a [u8]>,
    idempotency_key: Option<&'a str>,
    max_usd_micros: Option<i128>,
}

/// Anchor content items (one `items[i]` per hashes set): build (and optionally
/// sign) the exact record first, quote its precise canonical length, then
/// publish those bytes. Each item may carry several co-hash entries.
fn publish_items(
    poe: &cardanowall::client::PoeNamespace<'_>,
    items_hashes: Vec<Vec<(String, Vec<u8>)>>,
    uris: Option<Vec<String>>,
    inputs: &BuildInputs<'_>,
    mode: Mode,
) -> Result<SubmitOutcome, CliError> {
    let items: Vec<ItemEntry> = items_hashes
        .into_iter()
        .map(|hashes| ItemEntry {
            hashes,
            uris: uris.clone(),
            enc: None,
        })
        .collect();
    let record = PoeRecord {
        v: 1,
        items: Some(items),
        supersedes: inputs.supersedes.map(<[u8]>::to_vec),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record_with_signer(&record, inputs.signer, "submit")?;
    let quote = poe
        .quote(&QuoteInput {
            record_bytes: record_bytes.len() as u64,
            recipient_count: 0,
            file_bytes_total: 0,
        })
        .map_err(|e| map_client_error("submit", e))?;
    enforce_max_usd("submit", inputs.max_usd_micros, &quote)?;
    publish_record_bytes(
        poe,
        record_bytes,
        quote.quote_id,
        inputs.idempotency_key,
        mode,
    )
}

/// POST finalised record bytes against a consumed quote and shape the outcome.
fn publish_record_bytes(
    poe: &cardanowall::client::PoeNamespace<'_>,
    record_bytes: Vec<u8>,
    quote_id: String,
    idempotency_key: Option<&str>,
    mode: Mode,
) -> Result<SubmitOutcome, CliError> {
    let record_hex = bytes_to_hex(&record_bytes);
    let res = poe
        .publish(&PublishInput {
            record: record_bytes,
            quote_id,
            signatures: None,
            idempotency_key: idempotency_key.map(str::to_string),
        })
        .map_err(|e| map_client_error("submit", e))?;
    Ok(SubmitOutcome {
        mode: mode.as_str(),
        id: res.id,
        tx_hash: res.tx_hash,
        status: res.status.normalized().as_str().to_string(),
        record_hex,
        items_count: Some(res.items_count),
        root: None,
        leaf_count: None,
        ar_uri: None,
        replayed: Some(res.dedup_hit),
        balance_after_usd_micros: res.balance_after_usd_micros,
    })
}

/// The `--file --store` path: upload the plaintext content, then publish a
/// record binding the digest AND the returned `ar://` URI (a public
/// attachment). The URI exists only after the upload, so the quote is priced
/// from the exact-width upper-bound estimate; the storage side is the exact
/// content size. The quote is re-checked after the upload in case a large
/// content transfer outlived its TTL.
fn publish_stored_file(
    poe: &cardanowall::client::PoeNamespace<'_>,
    content: Vec<u8>,
    hashes: Vec<(String, Vec<u8>)>,
    mirror_uris: Vec<String>,
    inputs: &BuildInputs<'_>,
) -> Result<SubmitOutcome, CliError> {
    // The record's URIs are the explicit mirrors (known exactly at quote time)
    // plus the to-be-minted `ar://` placeholder for the upload — the estimate
    // charges every mirror at its exact width and the upload URI at the
    // fixed Arweave width, so the quote is an exact upper bound.
    let mut shape_uris = mirror_uris.clone();
    shape_uris.push(arweave_uri_placeholder());
    let shape = RecordShape {
        items: vec![ItemShape {
            hash_algs: hashes.iter().map(|(alg, _)| alg.clone()).collect(),
            uris: shape_uris,
            recipient_count: 0,
            kem: None,
        }],
        signed: inputs.signer.is_some(),
        supersedes: inputs.supersedes.is_some(),
        merkle: None,
    };
    let quote_input = QuoteInput {
        record_bytes: shape.estimate_record_bytes(),
        recipient_count: 0,
        file_bytes_total: content.len() as u64,
    };
    let quote = poe
        .quote(&quote_input)
        .map_err(|e| map_client_error("submit", e))?;
    enforce_max_usd("submit", inputs.max_usd_micros, &quote)?;
    let upload_key = content_upload_idempotency_key(STORED_CONTENT_UPLOAD_ROLE, &content);
    let upload = poe
        .upload_resumable(&ResumableUploadInput {
            target: STORAGE_TARGET_ARWEAVE.to_string(),
            source: ResumableSource::Bytes(content),
            content_type: Some("application/octet-stream".to_string()),
            idempotency_key: Some(upload_key),
            ..ResumableUploadInput::default()
        })
        .map_err(|e| map_upload_error("submit", e))?;
    // The explicit mirrors precede the freshly uploaded `ar://` in the record.
    let mut uris = mirror_uris;
    uris.push(upload.uri.clone());
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes,
            uris: Some(uris),
            enc: None,
        }]),
        supersedes: inputs.supersedes.map(<[u8]>::to_vec),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record_with_signer(&record, inputs.signer, "submit")?;
    let quote = refresh_quote_if_stale(poe, quote, &quote_input, inputs.max_usd_micros, "submit")?;
    let mut outcome = publish_record_bytes(
        poe,
        record_bytes,
        quote.quote_id,
        inputs.idempotency_key,
        Mode::File,
    )?;
    outcome.ar_uri = Some(upload.uri);
    Ok(outcome)
}

/// Load `--record` bytes: a file path or `-` for stdin; hex TEXT is decoded,
/// anything else is treated as raw CBOR (the `sign --in` convention).
fn load_record_bytes(source: &str) -> Result<Vec<u8>, CliError> {
    let raw = if source == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::network(format!("submit: cannot read --record stdin: {e}")))?;
        buf
    } else {
        std::fs::read(source)
            .map_err(|e| CliError::network(format!("submit: cannot read --record {source}: {e}")))?
    };
    let as_text = String::from_utf8_lossy(&raw);
    let trimmed = as_text.trim();
    if is_all_hex(trimmed) {
        hex_to_bytes(trimmed).map_err(|e| CliError::input(format!("submit: --record {e}")))
    } else {
        Ok(raw)
    }
}

/// One content item's co-hash set: `[(alg-id, digest)]`.
type ItemHashes = Vec<(String, Vec<u8>)>;

/// Parse the repeatable `--hash` specs into one hashes set per item (each
/// `--hash` value publishes one `items[]`). The per-value co-hash grammar is
/// shared with `sign --hash`.
fn parse_hash_items(
    values: &[String],
    default_algs: &[ContentHashAlg],
) -> Result<Vec<ItemHashes>, CliError> {
    values
        .iter()
        .map(|value| parse_cohash_spec(value, default_algs, "submit"))
        .collect()
}

/// Run the `submit` command.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code.
pub fn run(args: SubmitArgs) -> Result<(), CliError> {
    let mode = choose_mode(&args)?;
    if args.timeout == 0 {
        return Err(CliError::input("submit: --timeout must be positive"));
    }
    if args.store && mode != Mode::File {
        return Err(CliError::input(
            "submit: --store applies only to --file (it uploads that file's plaintext)",
        ));
    }
    // Content-discovery mirrors attach to content items only; --merkle carries
    // its leaves-list URI and --record is verbatim.
    if !args.uri.is_empty() && matches!(mode, Mode::Merkle | Mode::Record) {
        return Err(CliError::input(
            "submit: --uri attaches content mirrors to --hash / --file items; it does not apply \
             to --merkle or --record",
        ));
    }
    validate_content_uris(&args.uri, "submit")?;
    let hash_algs = resolve_content_hash_algs(&args.hash_alg, "submit")?;
    let supersedes = match (mode, args.supersedes.as_deref()) {
        (_, None) => None,
        (Mode::Record, Some(_)) => {
            return Err(CliError::input(
                "submit: --supersedes cannot be combined with --record — the pre-built record \
                 is published byte-for-byte and already carries (or omits) its own supersedes",
            ));
        }
        (_, Some(value)) => Some(parse_supersedes(value, "submit")?),
    };
    let max_usd_micros = args
        .max_usd
        .as_deref()
        .map(|text| {
            parse_usd_to_micros(text)
                .map_err(|e| CliError::input(format!("submit: --max-usd: {e}")))
        })
        .transpose()?;
    let gateway = resolve_gateway(&args, &SystemSecretEnv)?;
    // A --record publishes byte-for-byte and never signs, so the seed is
    // resolved only for the modes that use it: a stale CARDANOWALL_SEED in the
    // environment must not fail an otherwise valid --record publish, and
    // `--record -` must keep stdin to itself. Explicit seed flags alongside
    // --record are refused rather than silently ignored — the user plainly
    // expected a signature this mode cannot add.
    let signer = if mode == Mode::Record {
        if args.seed.is_some() || args.seed_file.is_some() || args.seed_stdin {
            return Err(CliError::input(
                "submit: --record publishes the pre-built bytes verbatim and never signs; \
                 remove the seed flags (sign the record before assembling it, e.g. with \
                 `sign record` or the prepare/assemble flow)",
            ));
        }
        None
    } else {
        resolve_signer(&args, &SystemSecretEnv)?
    };
    let signer_ref: Option<&dyn Signer> = signer.as_ref().map(|s| s as &dyn Signer);

    let client = Label309Client::new(Label309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("submit: {e}")))?;
    let poe = client.poe();

    let build_inputs = BuildInputs {
        signer: signer_ref,
        supersedes: supersedes.as_deref(),
        idempotency_key: args.idempotency_key.as_deref(),
        max_usd_micros,
    };
    // The explicit content-discovery mirrors attached to every content item.
    let mirror_uris = args.uri.clone();
    let item_uris = if mirror_uris.is_empty() {
        None
    } else {
        Some(mirror_uris.clone())
    };

    let mut outcome = match mode {
        Mode::Hash => {
            let items_hashes = parse_hash_items(&args.hash, &hash_algs)?;
            publish_items(&poe, items_hashes, item_uris, &build_inputs, mode)?
        }
        Mode::File => {
            let path = args.file.as_ref().unwrap();
            let content = std::fs::read(path).map_err(|e| {
                CliError::network(format!("submit: cannot read --file {path}: {e}"))
            })?;
            let hashes = cohash_content(&content, &hash_algs);
            if args.store {
                publish_stored_file(&poe, content, hashes, mirror_uris, &build_inputs)?
            } else {
                publish_items(&poe, vec![hashes], item_uris, &build_inputs, mode)?
            }
        }
        Mode::Record => {
            let record_bytes = load_record_bytes(args.record.as_deref().unwrap())?;
            // Fail fast with the structural validator's own codes: a malformed
            // record must never consume a quote.
            if let ValidateResult::Fail { issues } =
                validate_poe_record(&record_bytes, &ValidatorOptions::default())
            {
                let codes: Vec<&str> = issues.iter().map(|i| i.code.code()).collect();
                return Err(CliError::input(format!(
                    "submit: --record is not a valid Label 309 record: {}",
                    codes.join(", ")
                )));
            }
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: record_bytes.len() as u64,
                    recipient_count: 0,
                    file_bytes_total: 0,
                })
                .map_err(|e| map_client_error("submit", e))?;
            enforce_max_usd("submit", max_usd_micros, &quote)?;
            publish_record_bytes(
                &poe,
                record_bytes,
                quote.quote_id,
                args.idempotency_key.as_deref(),
                mode,
            )?
        }
        Mode::Merkle => {
            let path = args.merkle.as_ref().unwrap();
            let (leaves, leaf_alg) = load_merkle_leaves(path)?;
            // The Merkle registry is rfc9162-sha256 only, so the leaves must be
            // sha2-256; a --hash-alg naming anything else is refused.
            if hash_algs != [ContentHashAlg::Sha2_256] {
                return Err(CliError::input(
                    "submit: --merkle currently supports only sha2-256 leaves".to_string(),
                ));
            }
            // The SDK helper owns the priced flow: it quotes from the
            // exact-width estimate, enforces the cap, uploads the
            // leaves-list, and refreshes a stale price lock before the
            // publish.
            let max_usd_micros_u64: Option<u64> = max_usd_micros
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        CliError::input("submit: --max-usd is out of range".to_string())
                    })
                })
                .transpose()?;
            let mut input = PublishMerkleInput::new(leaves);
            input.leaf_alg = leaf_alg;
            // The Merkle record can supersede an earlier one (SDK S.2); the
            // hex string is re-derived from the validated supersedes bytes.
            input.supersedes = supersedes.as_deref().map(bytes_to_hex);
            input.signer = signer_ref;
            input.max_usd_micros = max_usd_micros_u64;
            input.idempotency_key = args.idempotency_key.clone();
            input.chunk_bytes = args.chunk_bytes;
            let res = poe
                .publish_merkle(&input)
                .map_err(|e| map_publish_error("submit", e))?;
            SubmitOutcome {
                mode: "merkle",
                id: res.id,
                tx_hash: res.tx_hash,
                status: res.status.normalized().as_str().to_string(),
                record_hex: bytes_to_hex(&res.record_bytes),
                items_count: None,
                root: Some(res.root),
                leaf_count: Some(res.leaf_count),
                ar_uri: Some(res.ar_uri),
                replayed: None,
                balance_after_usd_micros: res.balance_after_usd_micros,
            }
        }
    };

    if let Some(target) = args.wait {
        match wait_for_poe_target(&client, &outcome.id, target, args.timeout, "submit")? {
            WaitOutcome::Reached(snapshot) => {
                if let Some(status) = snapshot.status {
                    outcome.status = status.normalized().as_str().to_string();
                }
                if snapshot.tx_hash.is_some() {
                    outcome.tx_hash = snapshot.tx_hash;
                }
            }
            WaitOutcome::TimedOut { last_snapshot } => {
                if let Some(snapshot) = last_snapshot {
                    if let Some(status) = snapshot.status {
                        outcome.status = status.normalized().as_str().to_string();
                    }
                    if snapshot.tx_hash.is_some() {
                        outcome.tx_hash = snapshot.tx_hash;
                    }
                }
                let id = outcome.id.clone();
                let status = outcome.status.clone();
                emit_outcome(&outcome, args.json);
                return Err(CliError::new(
                    3,
                    format!(
                        "submit: timed out after {}s waiting for '{}'; the publish continues on \
                         the gateway (record {id}, status {status})",
                        args.timeout,
                        target.as_str()
                    ),
                ));
            }
        }
    }

    emit_outcome(&outcome, args.json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::publish_common::resolve_required_gateway_with;
    use crate::secret::resolve_service_gateway;
    use crate::secret::test_support::FakeSecretEnv;
    use cardanowall::hash::{blake2b256, sha256};

    fn base_args() -> SubmitArgs {
        SubmitArgs {
            hash: vec![],
            file: None,
            uri: vec![],
            store: false,
            merkle: None,
            record: None,
            hash_alg: vec![],
            supersedes: None,
            max_usd: None,
            api_key: None,
            seed: None,
            seed_file: None,
            seed_stdin: false,
            base_url: None,
            gateway_profile: None,
            chunk_bytes: None,
            idempotency_key: None,
            wait: None,
            timeout: 600,
            json: false,
        }
    }

    fn gateway_args(args: &SubmitArgs) -> GatewayArgs<'_> {
        GatewayArgs {
            base_url: args.base_url.as_deref(),
            api_key: args.api_key.as_deref(),
            gateway_profile: args.gateway_profile.as_deref(),
        }
    }

    #[test]
    fn requires_exactly_one_mode() {
        let mut args = base_args();
        assert_eq!(choose_mode(&args).unwrap_err().code, 4);
        args.hash = vec!["aa".repeat(32)];
        args.file = Some("/x".to_string());
        assert_eq!(choose_mode(&args).unwrap_err().code, 4);
        // --record joins the mutual-exclusion set.
        let mut record_and_hash = base_args();
        record_and_hash.record = Some("-".to_string());
        record_and_hash.hash = vec!["aa".repeat(32)];
        assert_eq!(choose_mode(&record_and_hash).unwrap_err().code, 4);
    }

    #[test]
    fn requires_base_url() {
        // No base URL from any source → input error before any network call.
        let args = base_args();
        let env = FakeSecretEnv::default();
        let config = crate::config::CardanoWallConfig::default();
        let profile = config.select_gateway(None, "submit").unwrap();
        let err = resolve_service_gateway(
            args.base_url.as_deref(),
            args.api_key.as_deref(),
            profile,
            "submit",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn requires_api_key_even_with_base_url() {
        // A base URL but no API key → input error (the gateway API is key-only).
        let mut args = base_args();
        args.base_url = Some("https://gw.example/api/v1".to_string());
        let env = FakeSecretEnv::default();
        let config = crate::config::CardanoWallConfig::default();
        assert_eq!(
            resolve_required_gateway_with(gateway_args(&args), &config, "submit", &env)
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn gateway_profile_supplies_base_url_and_key() {
        // With no flags/env, the active profile fills both slots.
        let mut config = crate::config::CardanoWallConfig::default();
        config.gateways.insert(
            "prod".to_string(),
            crate::config::GatewayProfile {
                base_url: "https://gw.example/api/v1".to_string(),
                api_key: Some("k".to_string()),
            },
        );
        config.default_gateway = Some("prod".to_string());
        let env = FakeSecretEnv::default();
        let gw = resolve_required_gateway_with(gateway_args(&base_args()), &config, "submit", &env)
            .unwrap();
        assert_eq!(gw.base_url, "https://gw.example/api/v1");
        assert_eq!(gw.api_key.as_deref(), Some("k"));
    }

    #[test]
    fn rejects_malformed_seed() {
        let mut args = base_args();
        args.seed = Some("dead".to_string());
        let env = FakeSecretEnv::default();
        assert_eq!(resolve_signer(&args, &env).unwrap_err().code, 4);
    }

    #[test]
    fn no_seed_is_unsigned() {
        let args = base_args();
        let env = FakeSecretEnv::default();
        assert!(resolve_signer(&args, &env).unwrap().is_none());
    }

    #[test]
    fn parses_leaves_file() {
        let text = format!("# header\n{}\n\n{}\n", "ab".repeat(32), "cd".repeat(32));
        let leaves = parse_leaves_file(&text, "f").unwrap();
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn rejects_bad_leaf() {
        assert_eq!(parse_leaves_file("zzz\n", "f").unwrap_err().code, 4);
    }

    /// The canonical leaves-list artifact for two fixed leaves, with the
    /// advisory `leaf_alg` set — what `merkle build --leaf-alg` emits.
    fn leaves_artifact() -> (Vec<[u8; 32]>, Vec<u8>) {
        use cardanowall::merkle::{encode_leaves_list, merkle_root};
        let leaves: Vec<[u8; 32]> = (0u8..2).map(|i| sha256(&[i])).collect();
        let root = merkle_root(&leaves).unwrap();
        let cbor = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();
        (leaves, cbor)
    }

    fn write_merkle_input(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// The raw digest a loaded leaf resolves to, whichever variant carries it.
    fn leaf_digests(leaves: &[MerkleLeaf]) -> Vec<Vec<u8>> {
        leaves
            .iter()
            .map(|leaf| match leaf {
                MerkleLeaf::Bytes(bytes) => bytes.clone(),
                MerkleLeaf::Hex(hex) => hex_to_bytes(hex).unwrap(),
            })
            .collect()
    }

    #[test]
    fn merkle_input_accepts_the_artifact_as_raw_bytes_and_as_hex_text() {
        let dir = tempfile::tempdir().unwrap();
        let (leaves, cbor) = leaves_artifact();
        let expected: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();

        let raw_path = write_merkle_input(&dir, "leaves.cbor", &cbor);
        let (loaded, leaf_alg) = load_merkle_leaves(&raw_path).unwrap();
        assert_eq!(leaf_digests(&loaded), expected);
        assert_eq!(leaf_alg.as_deref(), Some("sha2-256"));

        let hex_path = write_merkle_input(&dir, "leaves.hex", bytes_to_hex(&cbor).as_bytes());
        let (loaded, leaf_alg) = load_merkle_leaves(&hex_path).unwrap();
        assert_eq!(leaf_digests(&loaded), expected);
        assert_eq!(leaf_alg.as_deref(), Some("sha2-256"));
    }

    #[test]
    fn merkle_input_falls_back_to_leaf_lines_with_no_leaf_alg_claim() {
        let dir = tempfile::tempdir().unwrap();
        let lines = format!("{}\n{}\n", "ab".repeat(32), "cd".repeat(32));
        let path = write_merkle_input(&dir, "leaves.txt", lines.as_bytes());
        let (loaded, leaf_alg) = load_merkle_leaves(&path).unwrap();
        assert_eq!(leaf_digests(&loaded), vec![vec![0xab; 32], vec![0xcd; 32]],);
        assert_eq!(leaf_alg, None);

        // A lone 64-hex line is one leaf, never mistaken for an artifact blob.
        let single =
            write_merkle_input(&dir, "one.txt", format!("{}\n", "ef".repeat(32)).as_bytes());
        let (loaded, leaf_alg) = load_merkle_leaves(&single).unwrap();
        assert_eq!(leaf_digests(&loaded), vec![vec![0xef; 32]]);
        assert_eq!(leaf_alg, None);
    }

    #[test]
    fn merkle_input_rejects_a_corrupt_artifact_as_input_error() {
        let dir = tempfile::tempdir().unwrap();
        let (_, mut cbor) = leaves_artifact();
        // Flip a byte inside the root so the codec's root check fails.
        let index = cbor.len() / 2;
        cbor[index] ^= 0xff;
        let path = write_merkle_input(&dir, "corrupt.cbor", &cbor);
        let err = load_merkle_leaves(&path).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(
            err.message.contains("leaves-list artifact"),
            "{}",
            err.message
        );
    }

    #[test]
    fn hash_alg_digests_match_the_sdk_primitives() {
        // The digest computed for --file must be exactly the SDK primitive for
        // the selected algorithm — this is the anchored claim.
        let content = b"submit file content";
        assert_eq!(ContentHashAlg::Sha2_256.digest(content), sha256(content));
        assert_eq!(
            ContentHashAlg::Blake2b256.digest(content),
            blake2b256(content)
        );
    }

    #[test]
    fn parse_hash_items_supports_bare_pairs_and_co_hash_specs() {
        let sha = "ab".repeat(32);
        let blake = "cd".repeat(32);
        // A bare digest takes the lone default alg.
        let items =
            parse_hash_items(std::slice::from_ref(&sha), &[ContentHashAlg::Sha2_256]).unwrap();
        assert_eq!(items, vec![vec![("sha2-256".to_string(), vec![0xab; 32])]]);
        // A bare digest under a single non-default alg.
        let items =
            parse_hash_items(std::slice::from_ref(&sha), &[ContentHashAlg::Blake2b256]).unwrap();
        assert_eq!(
            items,
            vec![vec![("blake2b-256".to_string(), vec![0xab; 32])]]
        );
        // One --hash co-hashing two algorithms → one item, two entries.
        let spec = format!("sha2-256:{sha},blake2b-256:{blake}");
        let items = parse_hash_items(&[spec], &[ContentHashAlg::Sha2_256]).unwrap();
        assert_eq!(
            items,
            vec![vec![
                ("sha2-256".to_string(), vec![0xab; 32]),
                ("blake2b-256".to_string(), vec![0xcd; 32]),
            ]]
        );
        // Two --hash values → two items.
        let items =
            parse_hash_items(&[sha.clone(), blake.clone()], &[ContentHashAlg::Sha2_256]).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn parse_hash_items_rejects_ambiguous_bare_and_repeated_and_bad_shapes() {
        let sha = "ab".repeat(32);
        // A bare digest with several default algs is ambiguous.
        assert_eq!(
            parse_hash_items(
                std::slice::from_ref(&sha),
                &[ContentHashAlg::Sha2_256, ContentHashAlg::Blake2b256]
            )
            .unwrap_err()
            .code,
            4
        );
        // An unknown algorithm token.
        assert_eq!(
            parse_hash_items(&[format!("md5:{sha}")], &[ContentHashAlg::Sha2_256])
                .unwrap_err()
                .code,
            4
        );
        // Repeating an algorithm inside one item.
        assert_eq!(
            parse_hash_items(
                &[format!("sha2-256:{sha},sha2-256:{sha}")],
                &[ContentHashAlg::Sha2_256]
            )
            .unwrap_err()
            .code,
            4
        );
        // A wrong-length digest.
        assert_eq!(
            parse_hash_items(&["abcd".to_string()], &[ContentHashAlg::Sha2_256])
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn submit_args_debug_redacts_seed_and_api_key() {
        let mut args = base_args();
        args.seed = Some("ab".repeat(32));
        args.api_key = Some("super-secret-bearer".to_string());
        args.base_url = Some("https://gw.example/api/v1".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        // Non-secret fields stay visible for debugging.
        assert!(rendered.contains("https://gw.example/api/v1"));
    }

    #[test]
    fn gateway_profile_debug_redacts_api_key() {
        let profile = crate::config::GatewayProfile {
            base_url: "https://gw.example/api/v1".to_string(),
            api_key: Some("super-secret-bearer".to_string()),
        };
        let rendered = format!("{profile:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }

    #[test]
    fn service_gateway_debug_redacts_api_key() {
        let gw = crate::secret::ServiceGateway {
            base_url: "https://gw.example/api/v1".to_string(),
            api_key: Some("super-secret-bearer".to_string()),
        };
        let rendered = format!("{gw:?}");
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }
}
