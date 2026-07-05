//! `cardanowall seal` — publish a sealed PoE: encrypt one or more files to a
//! shared recipient set and anchor the proof on Cardano. The plaintext NEVER
//! leaves the machine — only its hash goes on-chain and only the ciphertext
//! goes to storage; recipients discover and decrypt it with their own keys
//! (the `inbox` commands, the web Inbox, or any Label 309 tool).
//!
//! ## Items
//!
//! `--file` is repeatable: each file becomes one item of a single record —
//! one anchor, one debit, every item sealed to the same recipients under one
//! KEM. The flow is two-phase inside: every item is encrypted up front (pure,
//! offline), then one online pass quotes, uploads each ciphertext, and
//! publishes. A failure after any completed upload lists the finished
//! uploads — storage URI, byte count, ciphertext hash — in the error, because
//! that storage work was already paid for.
//!
//! ## Recipients
//!
//! `--to` takes age-style recipient strings, auto-detected by prefix:
//! `age1…` is a classical X25519 recipient, `age1pqc…` is a hybrid X-Wing
//! (ML-KEM-768 + X25519) recipient. All slots of one envelope MUST share one
//! KEM — the standard forbids mixing (a classical slot bolted onto a hybrid
//! envelope would let an X25519 break recover the content key and unseal the
//! content for every recipient, silently defeating the post-quantum
//! protection) — so mixing the two prefixes in one `seal` is refused, never
//! silently downgraded. `--to-self` adds the sender's own decryption slot,
//! derived from the seed, under the same KEM as the other recipients (hybrid
//! when sealing only to yourself, matching the product default).
//!
//! Capacity is bounded by the on-chain record budget: roughly 144 classical
//! or 11 hybrid recipient slots fit a one-item record under the reference
//! gateway's record cap, and every additional item spends its own share of
//! the same budget; an over-capacity shape is refused before any quote or
//! upload.
//!
//! ## Authorship
//!
//! Encryption and authorship are independent: `--sign` (an explicit opt-in)
//! additionally signs the record with the seed's Ed25519 identity key, making
//! the anchor addressable (`GET /records?signer=…`). Omitting it publishes
//! the sealed record unsigned.
//!
//! Re-running `seal` anchors a NEW record and debits again: the encryption is
//! randomized (fresh content key, nonce, ephemeral keys), so the record bytes
//! can never deduplicate. This is by design — a sealed record must not leak
//! that it carries the same content as an earlier one.
//!
//! Exit codes: `0` anchored / `1` gateway rejection, terminal failure, or a
//! quote above `--max-usd` / `2` network or upload failure / `3` `--timeout`
//! elapsed while waiting (outputs still written) / `4` CLI input error.

use cardanowall::client::{
    seal_prepare, Label309Client, Label309ClientConfig, PreparedSeal, SealPrepareInput,
    SealPrepareItem, SealedKemChoice, Signer, SubmitSealedError, SubmitSealedInput,
};
use cardanowall::estimate::{ItemShape, RecordShape, MAX_RECORD_BYTES};
use cardanowall::hash::sha256;
use cardanowall::recipient::{parse_age_recipient, RecipientKem};
use cardanowall::sealed_poe::SealedKem;
use cardanowall::seed_derive::{
    derive_mlkem768x25519_keypair, derive_x25519_keypair, signer_from_seed, SeedSigner,
};
use clap::Args;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::publish_common::{
    arweave_uri_placeholder, map_publish_error, resolve_required_gateway, wait_for_poe_target,
    GatewayArgs, WaitOutcome, WaitTargetArg,
};
use crate::secret::{resolve_secret_bytes, SecretArgs, SecretKind, SystemSecretEnv};
use crate::util::{bytes_to_hex, format_usd_micros, parse_usd_to_micros, CliError};

/// The seal receipt format literal.
const RECEIPT_FORMAT: &str = "label-309-seal-receipt-v1";

/// Arguments for `cardanowall seal`.
///
/// `seed` (the raw argv identity seed) and `api_key` (the bearer token) are
/// secret material, so `Debug` is hand-written to redact both.
#[derive(Args)]
pub struct SealArgs {
    /// a plaintext file to seal (repeatable: each file becomes one item of a
    /// single record, sealed to the same recipients). Hashed (the on-chain
    /// claim) AND encrypted (the stored ciphertext); never uploaded in the
    /// clear.
    #[arg(long, value_name = "PATH", required = true)]
    pub file: Vec<String>,
    /// recipient (repeatable): an `age1…` X25519 or `age1pqc…` X-Wing
    /// recipient string. All recipients of one seal must share one KEM.
    #[arg(long = "to", value_name = "AGE-RECIPIENT", num_args = 1..)]
    pub to: Vec<String>,
    /// also seal to yourself: adds your own decryption slot, derived from the
    /// seed, under the same KEM as the other recipients (hybrid when sealing
    /// only to yourself).
    #[arg(long = "to-self")]
    pub to_self: bool,
    /// additionally sign the record with the seed's Ed25519 identity key
    /// (authorship is independent of encryption; default unsigned).
    #[arg(long)]
    pub sign: bool,
    /// 32-byte master identity seed: 64-digit hex or L309-SEED-1... . Required
    /// for --to-self and --sign. INSECURE on argv; prefer --seed-file /
    /// --seed-stdin / CARDANOWALL_SEED.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin (also `--seed -`).
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or the active
    /// gateway profile). Required.
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// target Label 309 gateway base URL incl. the version segment (or env
    /// CARDANOWALL_BASE_URL, or the active gateway profile). Required.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// lifecycle state to wait for before exiting.
    #[arg(long = "wait", value_enum, default_value_t = WaitTargetArg::Confirmed)]
    pub wait: WaitTargetArg,
    /// wait deadline in seconds. On expiry the outputs are still written and
    /// the process exits 3 (pending) — the publish continues on the gateway.
    #[arg(long = "timeout", default_value_t = 600, value_name = "SECONDS")]
    pub timeout: u64,
    /// refuse to publish when the quoted price exceeds this USD amount.
    #[arg(long = "max-usd", value_name = "USD")]
    pub max_usd: Option<String>,
    /// write a versioned JSON receipt here (never any key material).
    #[arg(long = "receipt-out", value_name = "PATH")]
    pub receipt_out: Option<String>,
    /// chunk size in bytes for a resumable ciphertext upload. A ciphertext
    /// over the resumable threshold uploads in chunks so an interrupted
    /// transfer resumes instead of restarting; the server's per-chunk ceiling
    /// clamps this down when tighter. Omit for the default.
    #[arg(long = "chunk-bytes")]
    pub chunk_bytes: Option<u64>,
    /// emit a machine-readable JSON summary on stdout.
    #[arg(long)]
    pub json: bool,
}

impl std::fmt::Debug for SealArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealArgs")
            .field("file", &self.file)
            .field("to", &self.to)
            .field("to_self", &self.to_self)
            .field("sign", &self.sign)
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("base_url", &self.base_url)
            .field("gateway_profile", &self.gateway_profile)
            .field("wait", &self.wait)
            .field("timeout", &self.timeout)
            .field("max_usd", &self.max_usd)
            .field("receipt_out", &self.receipt_out)
            .field("chunk_bytes", &self.chunk_bytes)
            .field("json", &self.json)
            .finish()
    }
}

impl SealArgs {
    fn seed_secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }
}

/// The resolved recipient set: one KEM, deduplicated raw public keys.
#[derive(Debug)]
struct RecipientSet {
    kem: SealedKemChoice,
    /// Raw public keys (32 B x25519 / 1216 B X-Wing), deduplicated.
    keys: Vec<Vec<u8>>,
    /// Whether a self slot was included.
    to_self: bool,
}

impl RecipientSet {
    fn kem_id(&self) -> &'static str {
        match self.kem {
            SealedKemChoice::X25519 => "x25519",
            SealedKemChoice::Mlkem768X25519 => "mlkem768x25519",
        }
    }

    fn sealed_kem(&self) -> SealedKem {
        match self.kem {
            SealedKemChoice::X25519 => SealedKem::X25519,
            SealedKemChoice::Mlkem768X25519 => SealedKem::Mlkem768X25519,
        }
    }
}

/// Parse and resolve the recipient set: `--to` strings (KEM by prefix, mixing
/// refused per the standard's MUST NOT) plus the optional self slot, all
/// deduplicated by raw public key.
fn resolve_recipients(args: &SealArgs, seed: Option<&[u8; 32]>) -> Result<RecipientSet, CliError> {
    let mut kems: Vec<RecipientKem> = Vec::new();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for (index, to) in args.to.iter().enumerate() {
        let parsed = parse_age_recipient(to)
            .map_err(|e| CliError::input(format!("seal: --to #{}: {e}", index + 1)))?;
        kems.push(parsed.kem);
        keys.push(parsed.public_key);
    }
    if kems.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(CliError::input(
            "seal: recipients mix classical (age1…) and hybrid (age1pqc…) keys — the standard \
             forbids mixed-KEM slots in one envelope, and a classical slot on a hybrid envelope \
             would silently void the post-quantum protection for every recipient. Seal to one \
             kind at a time (each identity has both address forms).",
        ));
    }

    // The envelope KEM: whatever the recipients use, hybrid by default when
    // sealing only to yourself (the product's post-quantum-safe default).
    let kem = match kems.first() {
        Some(RecipientKem::X25519) => SealedKemChoice::X25519,
        Some(RecipientKem::MlKem768X25519) | None => SealedKemChoice::Mlkem768X25519,
    };

    if args.to_self {
        let seed = seed.ok_or_else(|| {
            CliError::input("seal: --to-self needs the seed to derive your decryption key")
        })?;
        let self_key = match kem {
            SealedKemChoice::X25519 => derive_x25519_keypair(seed)
                .map_err(|e| CliError::input(format!("seal: --to-self: {e}")))?
                .public_key
                .to_vec(),
            SealedKemChoice::Mlkem768X25519 => derive_mlkem768x25519_keypair(seed)
                .map_err(|e| CliError::input(format!("seal: --to-self: {e}")))?
                .public_key
                .to_vec(),
        };
        keys.push(self_key);
    }

    // Dedupe by raw key: the same recipient named twice (or --to-self plus
    // your own pasted address) must not receive two slots.
    let mut seen = std::collections::BTreeSet::new();
    keys.retain(|key| seen.insert(key.clone()));

    if keys.is_empty() {
        return Err(CliError::input(
            "seal: at least one recipient is required — pass --to <age-recipient> and/or --to-self",
        ));
    }
    Ok(RecipientSet {
        kem,
        keys,
        to_self: args.to_self,
    })
}

/// The pre-quote capacity gate: the record's estimated canonical size — one
/// item per file, each carrying a full slot set for the recipient list — must
/// fit the on-chain budget, or the shape can never publish.
fn enforce_capacity(
    recipients: &RecipientSet,
    item_count: usize,
    signed: bool,
) -> Result<u64, CliError> {
    let item = ItemShape {
        hash_algs: vec!["sha2-256".to_string()],
        uris: vec![arweave_uri_placeholder()],
        recipient_count: recipients.keys.len() as u64,
        kem: Some(recipients.sealed_kem()),
    };
    let shape = RecordShape {
        items: vec![item; item_count],
        signed,
        supersedes: false,
        merkle: None,
    };
    let estimate = shape.estimate_record_bytes();
    if estimate > MAX_RECORD_BYTES {
        return Err(CliError::input(format!(
            "seal: {item_count} item(s) × {} recipient(s) do not fit one record (estimated \
             {estimate} bytes, budget {MAX_RECORD_BYTES}) — roughly 144 classical (age1…) or \
             11 hybrid (age1pqc…) recipient slots fit a one-item record, and every extra item \
             spends its own share; split the files or the recipient set across records",
            recipients.keys.len()
        )));
    }
    Ok(estimate)
}

// ---------------------------------------------------------------------------
// Receipt + outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct SealReceiptQuote {
    quote_id: String,
    /// The total locked price in USD micro-cents, as a decimal string.
    amount: String,
    currency: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    usd_micros: Option<String>,
}

#[derive(Debug, Serialize)]
struct SealReceiptSealed {
    recipient_count: u64,
    kem: &'static str,
    to_self: bool,
}

#[derive(Debug, Serialize)]
struct SealReceiptItem {
    sha2_256: String,
    ar_uri: String,
    ciphertext_bytes: u64,
}

#[derive(Debug, Serialize)]
struct SealReceiptWait {
    target: &'static str,
    reached: bool,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_time: Option<String>,
    num_confirmations: u64,
}

/// The versioned seal receipt (`label-309-seal-receipt-v1`). NEVER carries
/// key material, recipients' addresses, or the plaintext — only the public
/// facts of the anchor (the signer public key is, by definition, public).
/// `items` holds one entry per sealed file, in input order; `record_hex` is
/// the exact canonical-CBOR record that was published, for byte-for-byte
/// comparison against the on-chain metadata.
#[derive(Debug, Serialize)]
struct SealReceipt {
    format: &'static str,
    sealed: SealReceiptSealed,
    items: Vec<SealReceiptItem>,
    record_hex: String,
    signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_ed25519: Option<String>,
    poe_id: String,
    tx_hash: Option<String>,
    status: String,
    gateway_base_url: String,
    quote: SealReceiptQuote,
    wait: SealReceiptWait,
    balance_after_usd_micros: String,
}

/// One sealed file in the stdout summary, in input order. Unlike the
/// portable receipt this names the local path, so scripts can map results
/// back to their inputs.
#[derive(Debug, Serialize)]
struct SealOutcomeItem {
    file: String,
    sha2_256: String,
    ar_uri: String,
}

/// The machine-readable stdout summary (`--json`).
#[derive(Debug, Serialize)]
struct SealOutcome {
    id: String,
    tx_hash: Option<String>,
    status: String,
    items: Vec<SealOutcomeItem>,
    recipient_count: u64,
    kem: &'static str,
    signed: bool,
    price_usd_micros: String,
    balance_after_usd_micros: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_path: Option<String>,
    wait_target: &'static str,
    wait_reached: bool,
}

fn emit_outcome(outcome: &SealOutcome, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(outcome).expect("SealOutcome serialises")
        );
        return;
    }
    println!("ok: {}", outcome.id);
    println!("  status:      {}", outcome.status);
    println!(
        "  tx_hash:     {}",
        outcome.tx_hash.as_deref().unwrap_or("<pending>")
    );
    let total = outcome.items.len();
    for (index, item) in outcome.items.iter().enumerate() {
        println!("  item {}/{total}:    {}", index + 1, item.file);
        println!("    sha2_256:  {}", item.sha2_256);
        println!("    ar_uri:    {}", item.ar_uri);
    }
    println!(
        "  sealed to:   {} recipient(s), {}",
        outcome.recipient_count, outcome.kem
    );
    println!(
        "  price:       {}",
        format_usd_micros(&outcome.price_usd_micros)
    );
    println!(
        "  balance:     {}",
        format_usd_micros(&outcome.balance_after_usd_micros)
    );
    if let Some(path) = &outcome.receipt_path {
        println!("  receipt:     {path}");
    }
}

/// Map a two-phase submit failure onto the exit-code contract, listing every
/// ciphertext upload that had already completed. Storage uploads are paid
/// work the failure does not refund, so their receipts — file, storage URI,
/// byte count, ciphertext hash — must reach the user instead of vanishing
/// with the error (in JSON mode the same text travels inside the structured
/// error object's `message`).
fn map_submit_sealed_error(
    err: SubmitSealedError,
    files: &[String],
    prepared: &PreparedSeal,
) -> CliError {
    let SubmitSealedError { uploads, source } = err;
    let mut mapped = map_publish_error("seal", source);
    if uploads.is_empty() {
        return mapped;
    }
    mapped.message.push_str(&format!(
        "\nseal: {} ciphertext upload(s) had already completed (paid storage) before the \
         failure:",
        uploads.len()
    ));
    for receipt in &uploads {
        let file = prepared
            .items()
            .iter()
            .position(|item| item.item_id() == receipt.item_id)
            .and_then(|index| files.get(index))
            .map_or("<item>", String::as_str);
        mapped.message.push_str(&format!(
            "\n  {file}: {} ({} bytes, ciphertext sha2-256 {})",
            receipt.uri, receipt.bytes, receipt.item_id
        ));
    }
    mapped
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/// Run the `seal` command.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code (see the module docs).
pub fn run(args: SealArgs) -> Result<(), CliError> {
    if args.timeout == 0 {
        return Err(CliError::input("seal: --timeout must be positive"));
    }
    let max_usd_micros = args
        .max_usd
        .as_deref()
        .map(|text| {
            parse_usd_to_micros(text).map_err(|e| CliError::input(format!("seal: --max-usd: {e}")))
        })
        .transpose()?;
    // The SDK's price cap is a u64 of USD micro-cents; anything outside that
    // range is not a plausible cap for a single publish.
    let max_usd_micros: Option<u64> = max_usd_micros
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| CliError::input("seal: --max-usd is out of range".to_string()))
        })
        .transpose()?;

    // The seed is one secret with two independent uses: the self decryption
    // slot (--to-self) and the record signature (--sign).
    let seed_bytes = resolve_secret_bytes(
        SecretKind::Seed,
        &args.seed_secret_args(),
        false,
        "seal",
        &SystemSecretEnv,
    )?;
    // The working copy stays zeroized like the resolver buffer: it is filled
    // in place, never passing through an unwiped stack temporary.
    let seed: Option<Zeroizing<[u8; 32]>> = match &seed_bytes {
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err(CliError::input("seal: the seed must be exactly 32 bytes"));
            }
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(bytes);
            Some(copy)
        }
        None => None,
    };
    if args.sign && seed.is_none() {
        return Err(CliError::input(
            "seal: --sign needs the seed that owns the signing identity",
        ));
    }

    let recipients = resolve_recipients(&args, seed.as_deref())?;
    enforce_capacity(&recipients, args.file.len(), args.sign)?;

    let signer: Option<SeedSigner> = if args.sign {
        Some(
            signer_from_seed(seed.as_deref().expect("checked above"))
                .map_err(|e| CliError::input(format!("seal: --seed {e}")))?,
        )
    } else {
        None
    };
    let signer_ref: Option<&dyn Signer> = signer.as_ref().map(|s| s as &dyn Signer);
    let signer_pubkey_hex = signer.as_ref().map(|s| bytes_to_hex(&s.signer_pubkey()));

    let gateway = resolve_required_gateway(
        GatewayArgs {
            base_url: args.base_url.as_deref(),
            api_key: args.api_key.as_deref(),
            gateway_profile: args.gateway_profile.as_deref(),
        },
        "seal",
        &SystemSecretEnv,
    )?;

    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(args.file.len());
    for path in &args.file {
        contents.push(
            std::fs::read(path)
                .map_err(|e| CliError::network(format!("seal: cannot read --file {path}: {e}")))?,
        );
    }
    let plaintext_hashes: Vec<[u8; 32]> = contents.iter().map(|c| sha256(c)).collect();

    let gateway_base_url = gateway.base_url.clone();
    let client = Label309Client::new(Label309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("seal: {e}")))?;
    let poe = client.poe();

    // Phase 1 — pure and offline: every file encrypted to the shared
    // recipient set under one KEM. The plaintext never leaves this process.
    let prepare_input = SealPrepareInput::new(
        contents.iter().map(|c| SealPrepareItem::new(c)).collect(),
        recipients.keys.clone(),
    )
    .with_kem(recipients.kem);
    let prepared = seal_prepare(&prepare_input).map_err(|e| map_publish_error("seal", e.into()))?;

    // Phase 2 — online: quote (with the --max-usd cap) → per-item ciphertext
    // upload → refresh a price lock a slow upload outlived → publish. A
    // failure after any completed upload lists the finished (paid) uploads
    // in the error.
    let mut submit_input = SubmitSealedInput::new(&prepared);
    submit_input.signer = signer_ref;
    submit_input.max_usd_micros = max_usd_micros;
    submit_input.chunk_bytes = args.chunk_bytes;
    let submission = poe
        .submit_sealed(&submit_input)
        .map_err(|e| map_submit_sealed_error(e, &args.file, &prepared))?;
    let quote = submission.quote;
    let response = submission.response;
    let record_hex = bytes_to_hex(&submission.record_bytes);
    let uris = submission.uris;

    let wait_result = wait_for_poe_target(&client, &response.id, args.wait, args.timeout, "seal")?;
    let (wait_snapshot, timed_out) = match wait_result {
        WaitOutcome::Reached(snapshot) => (Some(snapshot), false),
        WaitOutcome::TimedOut { last_snapshot } => (last_snapshot, true),
    };

    let mut status = response.status.clone().normalized().as_str().to_string();
    let mut tx_hash = response.tx_hash.clone();
    if let Some(snapshot) = &wait_snapshot {
        if let Some(s) = &snapshot.status {
            status = s.clone().normalized().as_str().to_string();
        }
        if snapshot.tx_hash.is_some() {
            tx_hash = snapshot.tx_hash.clone();
        }
    }

    if let Some(receipt_path) = &args.receipt_out {
        let items: Vec<SealReceiptItem> = plaintext_hashes
            .iter()
            .zip(&uris)
            .zip(prepared.items())
            .map(|((hash, uri), item)| SealReceiptItem {
                sha2_256: bytes_to_hex(hash),
                ar_uri: uri.clone(),
                ciphertext_bytes: item.ciphertext().len() as u64,
            })
            .collect();
        let receipt = SealReceipt {
            format: RECEIPT_FORMAT,
            sealed: SealReceiptSealed {
                recipient_count: recipients.keys.len() as u64,
                kem: recipients.kem_id(),
                to_self: recipients.to_self,
            },
            items,
            record_hex: record_hex.clone(),
            signed: signer_pubkey_hex.is_some(),
            signer_ed25519: signer_pubkey_hex.clone(),
            poe_id: response.id.clone(),
            tx_hash: tx_hash.clone(),
            status: status.clone(),
            gateway_base_url: gateway_base_url.clone(),
            quote: SealReceiptQuote {
                quote_id: quote.quote_id.clone(),
                amount: quote.amount.clone(),
                currency: quote.currency.clone(),
                expires_at: quote.expires_at.clone(),
                usd_micros: quote.usd_micros.clone(),
            },
            wait: SealReceiptWait {
                target: args.wait.as_str(),
                reached: !timed_out,
                timed_out,
                block_height: wait_snapshot.as_ref().and_then(|s| s.block_height),
                block_time: wait_snapshot.as_ref().and_then(|s| s.block_time.clone()),
                num_confirmations: wait_snapshot.as_ref().map_or(0, |s| s.num_confirmations),
            },
            balance_after_usd_micros: response.balance_after_usd_micros.clone(),
        };
        let json = serde_json::to_string_pretty(&receipt).expect("receipt serialises");
        std::fs::write(receipt_path, format!("{json}\n")).map_err(|e| {
            CliError::network(format!(
                "seal: cannot write --receipt-out {receipt_path}: {e}"
            ))
        })?;
    }

    let outcome = SealOutcome {
        id: response.id.clone(),
        tx_hash,
        status: status.clone(),
        items: args
            .file
            .iter()
            .zip(&plaintext_hashes)
            .zip(&uris)
            .map(|((file, hash), uri)| SealOutcomeItem {
                file: file.clone(),
                sha2_256: bytes_to_hex(hash),
                ar_uri: uri.clone(),
            })
            .collect(),
        recipient_count: recipients.keys.len() as u64,
        kem: recipients.kem_id(),
        signed: signer_pubkey_hex.is_some(),
        price_usd_micros: quote.amount.clone(),
        balance_after_usd_micros: response.balance_after_usd_micros.clone(),
        receipt_path: args.receipt_out.clone(),
        wait_target: args.wait.as_str(),
        wait_reached: !timed_out,
    };
    emit_outcome(&outcome, args.json);

    if timed_out {
        return Err(CliError::new(
            3,
            format!(
                "seal: timed out after {}s waiting for '{}'; the publish continues on the \
                 gateway (record {}, status {status})",
                args.timeout,
                args.wait.as_str(),
                response.id
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> SealArgs {
        SealArgs {
            file: vec!["/nonexistent".to_string()],
            to: vec![],
            to_self: false,
            sign: false,
            seed: None,
            seed_file: None,
            seed_stdin: false,
            api_key: None,
            base_url: None,
            gateway_profile: None,
            wait: WaitTargetArg::Confirmed,
            timeout: 600,
            max_usd: None,
            receipt_out: None,
            chunk_bytes: None,
            json: false,
        }
    }

    /// Encode a raw public key as its age recipient string.
    fn age_recipient(kem: RecipientKem, key: &[u8]) -> String {
        let hrp = match kem {
            RecipientKem::X25519 => "age",
            RecipientKem::MlKem768X25519 => "age1pqc",
        };
        cardanowall::recipient::bech32_encode_no_limit(hrp, key).unwrap()
    }

    fn x25519_recipient(seed_byte: u8) -> String {
        let key = derive_x25519_keypair(&[seed_byte; 32]).unwrap().public_key;
        age_recipient(RecipientKem::X25519, &key)
    }

    fn xwing_recipient(seed_byte: u8) -> String {
        let key = derive_mlkem768x25519_keypair(&[seed_byte; 32])
            .unwrap()
            .public_key;
        age_recipient(RecipientKem::MlKem768X25519, &key)
    }

    #[test]
    fn mixed_kem_recipients_are_refused_not_downgraded() {
        let mut args = base_args();
        args.to = vec![x25519_recipient(1), xwing_recipient(2)];
        let err = resolve_recipients(&args, None).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("forbids mixed-KEM"), "{}", err.message);
    }

    #[test]
    fn kem_follows_the_recipients_and_defaults_to_hybrid_for_self_only() {
        let mut classical = base_args();
        classical.to = vec![x25519_recipient(1), x25519_recipient(2)];
        let set = resolve_recipients(&classical, None).unwrap();
        assert_eq!(set.kem, SealedKemChoice::X25519);
        assert_eq!(set.keys.len(), 2);

        let mut hybrid = base_args();
        hybrid.to = vec![xwing_recipient(3)];
        assert_eq!(
            resolve_recipients(&hybrid, None).unwrap().kem,
            SealedKemChoice::Mlkem768X25519
        );

        // Self-only sealing takes the product's post-quantum-safe default and
        // derives the X-Wing key from the seed.
        let seed = [7u8; 32];
        let mut self_only = base_args();
        self_only.to_self = true;
        let set = resolve_recipients(&self_only, Some(&seed)).unwrap();
        assert_eq!(set.kem, SealedKemChoice::Mlkem768X25519);
        assert_eq!(
            set.keys,
            vec![derive_mlkem768x25519_keypair(&seed)
                .unwrap()
                .public_key
                .to_vec()]
        );
    }

    #[test]
    fn to_self_matches_the_recipients_kem_and_dedupes() {
        let seed = [7u8; 32];
        // Classical recipients → the self slot is the seed's x25519 key.
        let mut args = base_args();
        args.to = vec![x25519_recipient(1)];
        args.to_self = true;
        let set = resolve_recipients(&args, Some(&seed)).unwrap();
        assert_eq!(set.kem, SealedKemChoice::X25519);
        assert_eq!(set.keys.len(), 2);
        assert_eq!(
            set.keys[1],
            derive_x25519_keypair(&seed).unwrap().public_key.to_vec()
        );

        // Pasting your own address alongside --to-self yields ONE slot.
        let self_addr = age_recipient(
            RecipientKem::X25519,
            &derive_x25519_keypair(&seed).unwrap().public_key,
        );
        let mut folded = base_args();
        folded.to = vec![self_addr];
        folded.to_self = true;
        assert_eq!(
            resolve_recipients(&folded, Some(&seed)).unwrap().keys.len(),
            1
        );

        // --to-self without a seed is an input error.
        let mut no_seed = base_args();
        no_seed.to_self = true;
        assert_eq!(resolve_recipients(&no_seed, None).unwrap_err().code, 4);
    }

    #[test]
    fn empty_recipient_set_is_refused() {
        let args = base_args();
        assert_eq!(resolve_recipients(&args, None).unwrap_err().code, 4);
    }

    #[test]
    fn capacity_gate_refuses_oversized_hybrid_sets_before_any_network() {
        // 11 hybrid recipients fit a one-item record (even signed); 12 exceed
        // the budget.
        let fits = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 11],
            to_self: false,
        };
        enforce_capacity(&fits, 1, true).unwrap();
        let too_many = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 12],
            to_self: false,
        };
        let err = enforce_capacity(&too_many, 1, false).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("recipient"), "{}", err.message);
        // Classical capacity is far higher: 144 fit even signed.
        let classical = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 144],
            to_self: false,
        };
        enforce_capacity(&classical, 1, true).unwrap();
        let classical_over = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 160],
            to_self: false,
        };
        assert_eq!(
            enforce_capacity(&classical_over, 1, true).unwrap_err().code,
            4
        );
    }

    #[test]
    fn capacity_gate_charges_every_item_a_full_slot_set() {
        // Each item repeats the whole recipient slot set, so the budget is
        // spent per item × per recipient: 2 items × 5 hybrid slots fit, while
        // 4 items × 3 hybrid slots (12 in total) do not.
        let five = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 5],
            to_self: false,
        };
        enforce_capacity(&five, 2, true).unwrap();
        let three = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 3],
            to_self: false,
        };
        let err = enforce_capacity(&three, 4, false).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("item"), "{}", err.message);
    }

    #[test]
    fn seal_args_debug_redacts_seed_and_api_key() {
        let mut args = base_args();
        args.seed = Some("ab".repeat(32));
        args.api_key = Some("super-secret-bearer".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
    }
}
