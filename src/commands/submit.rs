//! `cardanowall submit` — anchor a Label 309 PoE from the command line.
//!
//! Wraps the record-building and publish plumbing as one subcommand with four
//! mutually exclusive modes:
//!
//! - `--hash <64-hex>`         anchor precomputed digests (repeatable: one
//!   `items[i]` per digest; `--alg` applies to all of them)
//! - `--file <path>`           hash the file contents and anchor the digest;
//!   add `--store` to also upload the plaintext and bind its `ar://` URI
//! - `--merkle <leaves-file>`  read one 64-hex leaf per line, build a Merkle tree,
//!   anchor the root + leaves-list (Arweave)
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
use cardanowall::estimate::{ItemShape, MerkleShape, RecordShape};
use cardanowall::hash::{blake2b256, sha256};
use cardanowall::merkle::{encode_leaves_list, merkle_root, MERKLE_ALG_ID};
use cardanowall::poe_standard::{
    validate_poe_record, ItemEntry, PoeRecord, ValidateResult, ValidatorOptions,
};
use cardanowall::seed_derive::SeedSigner;
use clap::Args;
use serde::Serialize;

use crate::commands::publish_common::{
    arweave_uri_placeholder, encode_record_with_signer, enforce_max_usd, map_client_error,
    map_publish_error, map_upload_error, parse_supersedes, refresh_quote_if_stale,
    resolve_optional_signer, resolve_required_gateway, wait_for_poe_target, GatewayArgs,
    WaitOutcome, WaitTargetArg,
};
use crate::secret::{SecretArgs, SecretEnv, ServiceGateway, SystemSecretEnv};
use crate::util::{format_usd_micros, hex_to_bytes, is_all_hex, parse_usd_to_micros, CliError};

/// The storage backend `--store` uploads plaintext content to.
const STORAGE_TARGET_ARWEAVE: &str = "arweave";

const SHA2_256_DIGEST_BYTES: usize = 32;

/// The hash algorithm surface of `--alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlg {
    Sha2_256,
    Blake2b256,
}

impl HashAlg {
    fn as_str(self) -> &'static str {
        match self {
            HashAlg::Sha2_256 => "sha2-256",
            HashAlg::Blake2b256 => "blake2b-256",
        }
    }

    fn digest(self, content: &[u8]) -> [u8; 32] {
        match self {
            HashAlg::Sha2_256 => sha256(content),
            HashAlg::Blake2b256 => blake2b256(content),
        }
    }
}

/// Arguments for `cardanowall submit`.
/// `seed` (the raw argv identity seed) and `api_key` (the bearer token) are
/// secret material, so `Debug` is hand-written to redact both: no `{:?}`, log,
/// or panic-backtrace path can ever surface them.
#[derive(Args)]
pub struct SubmitArgs {
    /// 64-hex precomputed digest (repeatable: N digests publish one record
    /// with N items[]; --alg applies to all of them; default alg sha2-256).
    #[arg(long, value_name = "HEX64", num_args = 1..)]
    pub hash: Vec<String>,
    /// path to a file whose contents will be hashed and anchored.
    #[arg(long)]
    pub file: Option<String>,
    /// with --file: also upload the PLAINTEXT content to storage and bind the
    /// returned ar:// URI into the record (a public attachment).
    #[arg(long)]
    pub store: bool,
    /// file with one 64-hex sha2-256 leaf per line; anchors a Merkle root.
    #[arg(long)]
    pub merkle: Option<String>,
    /// pre-built canonical-CBOR record to publish byte-for-byte (a file path,
    /// or '-' for stdin; hex text or raw bytes). Validated locally before any
    /// network call; never re-encoded or re-signed.
    #[arg(long, value_name = "FILE|-")]
    pub record: Option<String>,
    /// hash algorithm: 'sha2-256' (default) or 'blake2b-256' (--merkle: sha2-256 only).
    #[arg(long)]
    pub alg: Option<String>,
    /// mark this record as superseding an earlier one: the 64-hex Cardano
    /// transaction hash of the record being replaced (--hash / --file modes;
    /// a --record carries its own supersedes inside its bytes).
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
            .field("store", &self.store)
            .field("merkle", &self.merkle)
            .field("record", &self.record)
            .field("alg", &self.alg)
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

fn resolve_hash_alg(args: &SubmitArgs) -> Result<HashAlg, CliError> {
    match args
        .alg
        .as_deref()
        .map(str::to_lowercase)
        .as_deref()
        .unwrap_or("sha2-256")
    {
        "sha2-256" => Ok(HashAlg::Sha2_256),
        "blake2b-256" => Ok(HashAlg::Blake2b256),
        other => Err(CliError::input(format!(
            "submit: --alg must be 'sha2-256' or 'blake2b-256' (got '{other}')"
        ))),
    }
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
    alg: HashAlg,
    signer: Option<&'a dyn Signer>,
    supersedes: Option<&'a [u8]>,
    idempotency_key: Option<&'a str>,
    max_usd_micros: Option<i128>,
}

/// Anchor precomputed digests (one `items[i]` per digest): build (and
/// optionally sign) the exact record first, quote its precise canonical
/// length, then publish those bytes.
fn publish_items(
    poe: &cardanowall::client::PoeNamespace<'_>,
    digests: Vec<Vec<u8>>,
    uris: Option<Vec<String>>,
    inputs: &BuildInputs<'_>,
    mode: Mode,
) -> Result<SubmitOutcome, CliError> {
    let items: Vec<ItemEntry> = digests
        .into_iter()
        .map(|digest| ItemEntry {
            hashes: vec![(inputs.alg.as_str().to_string(), digest)],
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
    digest: Vec<u8>,
    inputs: &BuildInputs<'_>,
) -> Result<SubmitOutcome, CliError> {
    let shape = RecordShape {
        items: vec![ItemShape {
            hash_algs: vec![inputs.alg.as_str().to_string()],
            uris: vec![arweave_uri_placeholder()],
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
    let upload = poe
        .upload_resumable(&ResumableUploadInput {
            target: STORAGE_TARGET_ARWEAVE.to_string(),
            source: ResumableSource::Bytes(content),
            content_type: Some("application/octet-stream".to_string()),
            ..ResumableUploadInput::default()
        })
        .map_err(|e| map_upload_error("submit", e))?;
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(inputs.alg.as_str().to_string(), digest)],
            uris: Some(vec![upload.uri.clone()]),
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

/// Parse the repeatable `--hash` values into raw digests.
fn parse_hash_digests(values: &[String]) -> Result<Vec<Vec<u8>>, CliError> {
    let mut digests = Vec::with_capacity(values.len());
    for value in values {
        let hex = value.trim().to_lowercase();
        let digest =
            hex_to_bytes(&hex).map_err(|e| CliError::input(format!("submit: --hash {e}")))?;
        if digest.len() != SHA2_256_DIGEST_BYTES {
            return Err(CliError::input(format!(
                "submit: --hash must decode to exactly {SHA2_256_DIGEST_BYTES} bytes (got {})",
                digest.len()
            )));
        }
        digests.push(digest);
    }
    Ok(digests)
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
    let supersedes = match (mode, args.supersedes.as_deref()) {
        (_, None) => None,
        (Mode::Record, Some(_)) => {
            return Err(CliError::input(
                "submit: --supersedes cannot be combined with --record — the pre-built record \
                 is published byte-for-byte and already carries (or omits) its own supersedes",
            ));
        }
        (Mode::Merkle, Some(_)) => {
            return Err(CliError::input(
                "submit: --supersedes is not supported with --merkle here — use \
                 `attest --leaf … --supersedes <tx>` to publish a superseding Merkle record",
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

    let build_inputs = |alg: HashAlg| BuildInputs {
        alg,
        signer: signer_ref,
        supersedes: supersedes.as_deref(),
        idempotency_key: args.idempotency_key.as_deref(),
        max_usd_micros,
    };

    let mut outcome = match mode {
        Mode::Hash => {
            let digests = parse_hash_digests(&args.hash)?;
            let alg = resolve_hash_alg(&args)?;
            publish_items(&poe, digests, None, &build_inputs(alg), mode)?
        }
        Mode::File => {
            let path = args.file.as_ref().unwrap();
            let content = std::fs::read(path).map_err(|e| {
                CliError::network(format!("submit: cannot read --file {path}: {e}"))
            })?;
            let alg = resolve_hash_alg(&args)?;
            let digest = alg.digest(&content).to_vec();
            let inputs = build_inputs(alg);
            if args.store {
                publish_stored_file(&poe, content, digest, &inputs)?
            } else {
                publish_items(&poe, vec![digest], None, &inputs, mode)?
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
            let text = std::fs::read_to_string(path).map_err(|e| {
                CliError::network(format!("submit: cannot read --merkle {path}: {e}"))
            })?;
            let leaves_hex = parse_leaves_file(&text, path)?;
            let alg = args
                .alg
                .as_deref()
                .map(str::to_lowercase)
                .unwrap_or_else(|| "sha2-256".to_string());
            if alg != "sha2-256" {
                return Err(CliError::input(format!(
                    "submit: --merkle currently supports only sha2-256 leaves (got '{alg}')"
                )));
            }
            // The exact leaves-list byte count feeds the quote's storage side;
            // the record side is the exact-width upper-bound estimate, because
            // the ar:// URI only exists after the upload the helper performs.
            let leaf_arrays: Vec<[u8; 32]> = leaves_hex
                .iter()
                .map(|h| {
                    let bytes = hex_to_bytes(h).expect("validated 64-hex leaf");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                })
                .collect();
            let root =
                merkle_root(&leaf_arrays).map_err(|e| CliError::input(format!("submit: {e}")))?;
            let leaves_list = encode_leaves_list(&leaf_arrays, &root, None)
                .map_err(|e| CliError::input(format!("submit: {e}")))?;
            let shape = RecordShape {
                items: vec![],
                signed: signer.is_some(),
                supersedes: false,
                merkle: Some(MerkleShape {
                    alg: MERKLE_ALG_ID.to_string(),
                    uris: vec![arweave_uri_placeholder()],
                }),
            };
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: shape.estimate_record_bytes(),
                    recipient_count: 0,
                    file_bytes_total: leaves_list.len() as u64,
                })
                .map_err(|e| map_client_error("submit", e))?;
            enforce_max_usd("submit", max_usd_micros, &quote)?;
            let res = poe
                .publish_merkle(&PublishMerkleInput {
                    leaves: leaves_hex.into_iter().map(MerkleLeaf::Hex).collect(),
                    quote_id: quote.quote_id,
                    hash_alg: None,
                    signer: signer_ref,
                    idempotency_key: args.idempotency_key.clone(),
                    chunk_bytes: args.chunk_bytes,
                })
                .map_err(|e| map_publish_error("submit", e))?;
            SubmitOutcome {
                mode: "merkle",
                id: res.id,
                tx_hash: res.tx_hash,
                status: res.status.normalized().as_str().to_string(),
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

    fn base_args() -> SubmitArgs {
        SubmitArgs {
            hash: vec![],
            file: None,
            store: false,
            merkle: None,
            record: None,
            alg: None,
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

    #[test]
    fn hash_alg_digests_match_the_sdk_primitives() {
        // The digest computed for --file must be exactly the SDK primitive for
        // the selected algorithm — this is the anchored claim.
        let content = b"submit file content";
        assert_eq!(HashAlg::Sha2_256.digest(content), sha256(content));
        assert_eq!(HashAlg::Blake2b256.digest(content), blake2b256(content));
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
