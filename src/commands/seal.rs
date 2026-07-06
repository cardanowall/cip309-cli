//! `cardanowall seal` — publish a sealed PoE: encrypt one or more files
//! either to a shared recipient set or to a shared passphrase, and anchor the
//! proof on Cardano. The plaintext NEVER leaves the machine — only its hash
//! goes on-chain and only the ciphertext goes to storage; whoever can unwrap
//! the content key (a recipient's private key, or the passphrase) discovers
//! and decrypts it with the `inbox` commands, the web Inbox, or any Label 309
//! tool.
//!
//! ## Items
//!
//! `--file` is repeatable: each file becomes one item of a single record —
//! one anchor, one debit, every item sealed under the same key material. The
//! flow is two-phase inside: every item is encrypted up front (pure,
//! offline), then one online pass quotes, uploads each ciphertext, and
//! publishes. A failure after any completed upload lists the finished
//! uploads — storage URI, byte count, ciphertext hash — in the error, because
//! that storage work was already paid for.
//!
//! ## Recipients, or a passphrase
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
//! `--passphrase` (or `--passphrase-file` / `--passphrase-stdin` / the
//! `CARDANOWALL_PASSPHRASE` env var) seals to a shared passphrase instead:
//! anyone who knows it can open the record, with no recipient keys involved
//! at all. A record is sealed to recipients OR to a passphrase, never both —
//! combining `--to`/`--to-self` with a passphrase source is refused before
//! any file is read.
//!
//! Capacity is bounded by the on-chain record budget: roughly 144 classical
//! or 11 hybrid recipient slots fit a one-item record under the reference
//! gateway's record cap, and every additional item spends its own share of
//! the same budget; an over-capacity shape is refused before any quote or
//! upload. A passphrase-sealed record carries no recipient slots, so this
//! budget never binds on the passphrase path.
//!
//! ## Authorship and supersession
//!
//! Encryption and authorship are independent: `--sign` (an explicit opt-in)
//! additionally signs the record with the seed's Ed25519 identity key, making
//! the anchor addressable (`GET /records?signer=…`). Omitting it publishes
//! the sealed record unsigned. `--supersedes <tx64>` marks the record as
//! superseding an earlier transaction. Both flags work identically under
//! either sealing mode.
//!
//! Re-running `seal` anchors a NEW record and debits again: the encryption is
//! randomized (fresh content key, nonce, ephemeral keys, and — under a
//! passphrase — a fresh Argon2id salt), so the record bytes can never
//! deduplicate. This is by design — a sealed record must not leak that it
//! carries the same content as an earlier one.
//!
//! Exit codes: `0` anchored / `1` gateway rejection, terminal failure, or a
//! quote above `--max-usd` / `2` network or upload failure / `3` `--timeout`
//! elapsed while waiting (outputs still written) / `4` CLI input error.

use std::path::{Path, PathBuf};

use cardanowall::client::{
    passphrase_seal_prepare, seal_prepare, Label309Client, Label309ClientConfig,
    PassphraseKdfParams, PassphraseSealPrepareInput, PreparedSeal, PublishHelperError,
    SealPrepareInput, SealPrepareItem, SealedKemChoice, SealedSubmission, Signer,
    SubmitPassphraseSealedInput, SubmitSealedError, SubmitSealedInput, SupportedHashAlg,
    UploadReceipt,
};
use cardanowall::estimate::{ItemShape, RecordShape, MAX_RECORD_BYTES};
use cardanowall::recipient::{parse_age_recipient, RecipientKem};
use cardanowall::sealed_poe::SealedKem;
use cardanowall::seed_derive::{
    derive_mlkem768x25519_keypair, derive_x25519_keypair, signer_from_seed, SeedSigner,
};
use clap::Args;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::publish_common::{
    arweave_uri_placeholder, cohash_content, map_publish_error, parse_supersedes,
    resolve_content_hash_algs, resolve_required_gateway, wait_for_poe_target, ContentHashAlg,
    GatewayArgs, ItemHashesMap, WaitOutcome, WaitTargetArg,
};
use crate::commands::seal_resume::{self, SealResumeState, RESUME_FORMAT, RESUME_VERSION};
use crate::secret::{
    resolve_secret_bytes, resolve_secret_passphrase, SecretArgs, SecretEnv, SecretKind,
    SystemSecretEnv,
};
use crate::util::{bytes_to_hex, format_usd_micros, parse_usd_to_micros, CliError};

/// The seal receipt format literal.
const RECEIPT_FORMAT: &str = "label-309-seal-receipt-v1";

/// The `kem` value a passphrase seal reports. Not a real KEM identifier — a
/// passphrase seal has no KEM slots at all — but a stable, self-describing
/// value that lets a reader of the receipt or `--json` outcome tell the two
/// sealing modes apart without a separate field.
const PASSPHRASE_KEM_DISPLAY: &str = "passphrase";

/// The Argon2id producer floors the Label 309 wire pins for a passphrase seal
/// (memory in KiB, iterations, parallelism). A conformant validator rejects a
/// record below any of them, so the CLI refuses below-floor overrides up front
/// rather than sealing a record no verifier will accept. The values are the
/// registry floors; they also serve as the producer defaults.
const ARGON2_MIN_M_KIB: u64 = 65_536;
const ARGON2_MIN_T: u64 = 3;
const ARGON2_MIN_P: u64 = 1;

/// Arguments for `cardanowall seal`.
///
/// `seed` (the raw argv identity seed), `passphrase` (the raw argv
/// passphrase-seal secret), and `api_key` (the bearer token) are secret
/// material, so `Debug` is hand-written to redact all three.
#[derive(Args)]
pub struct SealArgs {
    /// a plaintext file to seal (repeatable: each file becomes one item of a
    /// single record, sealed to the same recipients). Hashed (the on-chain
    /// claim) AND encrypted (the stored ciphertext); never uploaded in the
    /// clear.
    #[arg(long, value_name = "PATH", required_unless_present = "resume")]
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
    /// seal to a shared passphrase instead of a recipient set: anyone who
    /// knows it can open the record. Mutually exclusive with --to/--to-self.
    /// INSECURE on argv (shell history / ps / CI logs); prefer
    /// --passphrase-file / --passphrase-stdin / CARDANOWALL_PASSPHRASE.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// read the passphrase from a file (trailing whitespace trimmed).
    #[arg(long = "passphrase-file")]
    pub passphrase_file: Option<String>,
    /// read the passphrase from stdin (also `--passphrase -`).
    #[arg(long = "passphrase-stdin")]
    pub passphrase_stdin: bool,
    /// passphrase-seal Argon2id memory cost in KiB (only with a passphrase
    /// seal; default 65536, the registry floor). A higher value hardens the
    /// KDF at more work per open; below the floor is refused.
    #[arg(long = "passphrase-m", value_name = "KIB")]
    pub passphrase_m: Option<u32>,
    /// passphrase-seal Argon2id iteration count (only with a passphrase seal;
    /// default 3, the registry floor). Below the floor is refused.
    #[arg(long = "passphrase-t", value_name = "ITERS")]
    pub passphrase_t: Option<u32>,
    /// passphrase-seal Argon2id parallelism (only with a passphrase seal;
    /// default 4, floor 1). Below the floor is refused.
    #[arg(long = "passphrase-p", value_name = "LANES")]
    pub passphrase_p: Option<u32>,
    /// content-hash algorithm for the sealed item(s) (repeatable: co-hash each
    /// item under every one, e.g. --hash-alg sha2-256 --hash-alg blake2b-256).
    /// The digests are the on-chain claim and are bound into the sealed
    /// envelope. Default sha2-256.
    #[arg(long = "hash-alg", value_name = "ALG")]
    pub hash_alg: Vec<String>,
    /// mark this sealed record as superseding an earlier one: the 64-hex
    /// Cardano transaction hash of the record being replaced.
    #[arg(long = "supersedes", value_name = "TX64")]
    pub supersedes: Option<String>,
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
    /// resume a recipient seal that failed after a prepared seal existed: load
    /// the resume-state file the failed run wrote, re-quote, finish the
    /// remaining ciphertext uploads (reusing every one already paid for), and
    /// publish. Takes NONE of the input flags (--file/--to/--to-self/
    /// --passphrase.../--hash-alg/--supersedes/--sign); a signed original run
    /// re-requires the seed. Passphrase seals cannot be resumed.
    #[arg(long = "resume", value_name = "PATH")]
    pub resume: Option<String>,
    /// where to write the resume-state file if this recipient seal fails after a
    /// prepared seal exists (default: a name derived from the seal, in the
    /// current directory). Passphrase seals never write one.
    #[arg(long = "resume-state", value_name = "PATH")]
    pub resume_state: Option<String>,
    /// resume WITHOUT re-verifying that the sealed content still matches your
    /// input files. Only with --resume, and only when the original input files
    /// are unavailable at resume time (e.g. a later CI stage). This waives the
    /// guarantee that the resumed record commits to your actual file contents,
    /// so a tampered resume-state could publish a record for content you never
    /// sealed — use it only when you trust the state file's origin.
    #[arg(long = "skip-plaintext-recheck", requires = "resume")]
    pub skip_plaintext_recheck: bool,
}

impl std::fmt::Debug for SealArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealArgs")
            .field("file", &self.file)
            .field("to", &self.to)
            .field("to_self", &self.to_self)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[redacted]"),
            )
            .field("passphrase_file", &self.passphrase_file)
            .field("passphrase_stdin", &self.passphrase_stdin)
            .field("passphrase_m", &self.passphrase_m)
            .field("passphrase_t", &self.passphrase_t)
            .field("passphrase_p", &self.passphrase_p)
            .field("hash_alg", &self.hash_alg)
            .field("supersedes", &self.supersedes)
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
            .field("resume", &self.resume)
            .field("resume_state", &self.resume_state)
            .field("skip_plaintext_recheck", &self.skip_plaintext_recheck)
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

    fn passphrase_secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.passphrase.clone(),
            file: self.passphrase_file.clone(),
            stdin: self.passphrase_stdin,
        }
    }
}

/// Which of the two mutually exclusive ways this invocation seals the
/// record. `--sign` and `--supersedes` are orthogonal to both and behave
/// identically either way.
enum SealMode {
    /// Sealed to a recipient set: one KEM slot per recipient.
    Recipients,
    /// Sealed to a shared passphrase: the content key is derived from it
    /// through Argon2id, and the record carries no recipient slots at all.
    Passphrase(Zeroizing<String>),
}

/// `Zeroizing<String>` deliberately has no `Debug` impl (it exists so a
/// secret never accidentally prints), so this hand-written impl redacts the
/// passphrase the same way [`SealArgs`]'s does.
impl std::fmt::Debug for SealMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealMode::Recipients => f.write_str("Recipients"),
            SealMode::Passphrase(_) => f.write_str("Passphrase([redacted])"),
        }
    }
}

/// Resolve which sealing mode this invocation uses.
///
/// A record is sealed to recipients (`--to`/`--to-self`) OR to a passphrase,
/// never both, so a passphrase source present alongside a recipient is
/// refused here, before any file is read or any network call made.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on a passphrase-source resolution failure
/// (conflicting sources, a missing required source) or on both a passphrase
/// and a recipient being present.
fn select_seal_mode(args: &SealArgs, env: &dyn SecretEnv) -> Result<SealMode, CliError> {
    let passphrase = resolve_secret_passphrase(&args.passphrase_secret_args(), false, "seal", env)?;
    let recipients_present = !args.to.is_empty() || args.to_self;
    match (passphrase, recipients_present) {
        (Some(_), true) => Err(CliError::input(
            "seal: a record is sealed to recipients (--to/--to-self) OR to a passphrase \
             (--passphrase), not both",
        )),
        (Some(passphrase), false) => Ok(SealMode::Passphrase(passphrase)),
        (None, _) => Ok(SealMode::Recipients),
    }
}

/// Resolve the effective passphrase Argon2id cost parameters from the flags.
///
/// The three `--passphrase-*` overrides apply only to a passphrase seal; any of
/// them set for a recipient seal is a usage error. Each unset flag keeps its
/// producer default (the registry floor for `m`/`t`, RFC 9106's recommended
/// `p = 4`). An effective value below the wire floor is refused before sealing.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when an override is set without a passphrase
/// mode, or when the effective parameters fall below the registry floor.
fn resolve_passphrase_kdf_params(
    args: &SealArgs,
    mode: &SealMode,
) -> Result<PassphraseKdfParams, CliError> {
    let overridden =
        args.passphrase_m.is_some() || args.passphrase_t.is_some() || args.passphrase_p.is_some();
    if overridden && !matches!(mode, SealMode::Passphrase(_)) {
        return Err(CliError::input(
            "seal: --passphrase-m/--passphrase-t/--passphrase-p apply only to a passphrase seal \
             (--passphrase); a recipient seal has no passphrase KDF",
        ));
    }
    let defaults = PassphraseKdfParams::default();
    let params = PassphraseKdfParams {
        m: args.passphrase_m.map_or(defaults.m, u64::from),
        t: args.passphrase_t.map_or(defaults.t, u64::from),
        p: args.passphrase_p.map_or(defaults.p, u64::from),
    };
    if params.m < ARGON2_MIN_M_KIB || params.t < ARGON2_MIN_T || params.p < ARGON2_MIN_P {
        return Err(CliError::input(format!(
            "seal: passphrase Argon2id parameters are below the registry floor \
             (need m>={ARGON2_MIN_M_KIB} KiB, t>={ARGON2_MIN_T}, p>={ARGON2_MIN_P}; \
             got m={}, t={}, p={})",
            params.m, params.t, params.p
        )));
    }
    Ok(params)
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

/// The on-wire KEM identifier a receipt / outcome reports for a [`SealedKemChoice`].
fn kem_choice_id(kem: SealedKemChoice) -> &'static str {
    match kem {
        SealedKemChoice::X25519 => "x25519",
        SealedKemChoice::Mlkem768X25519 => "mlkem768x25519",
    }
}

impl RecipientSet {
    fn kem_id(&self) -> &'static str {
        kem_choice_id(self.kem)
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
/// item per file, each carrying a full slot set for the recipient list and one
/// `hashes` entry per co-hash algorithm — must fit the on-chain budget, or the
/// shape can never publish.
fn enforce_capacity(
    recipients: &RecipientSet,
    hash_algs: &[ContentHashAlg],
    item_count: usize,
    signed: bool,
    supersedes: bool,
) -> Result<u64, CliError> {
    let item = ItemShape {
        hash_algs: hash_algs
            .iter()
            .map(|alg| alg.as_str().to_string())
            .collect(),
        uris: vec![arweave_uri_placeholder()],
        recipient_count: recipients.keys.len() as u64,
        kem: Some(recipients.sealed_kem()),
    };
    let shape = RecordShape {
        items: vec![item; item_count],
        signed,
        supersedes,
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

/// Which key material protects the record. For a passphrase seal there is no
/// recipient set at all: `recipient_count` reads `0`, `kem` reads
/// [`PASSPHRASE_KEM_DISPLAY`] (not a real KEM identifier — a reader
/// distinguishes the two modes by this value), and `to_self` reads `false`.
#[derive(Debug, Clone, Copy, Serialize)]
struct SealReceiptSealed {
    recipient_count: u64,
    kem: &'static str,
    to_self: bool,
}

#[derive(Debug, Serialize)]
struct SealReceiptItem {
    /// The item's digests as the spec's alg→digest map (one entry per co-hash
    /// algorithm), the on-chain claim the ciphertext is bound to.
    hashes: ItemHashesMap,
    /// Legacy convenience field, present ONLY when the item carries a sha2-256
    /// digest (older receipt consumers read it). It never carries a non-sha2
    /// digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha2_256: Option<String>,
    ar_uri: String,
    ciphertext_bytes: u64,
}

/// The Argon2id cost parameters a passphrase-sealed record was built under,
/// echoed so a later reader can reproduce or audit the work factor. Present
/// only for a passphrase seal.
#[derive(Debug, Clone, Copy, Serialize)]
struct SealReceiptKdf {
    m: u64,
    t: u64,
    p: u64,
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
    /// The passphrase-seal Argon2id parameters, present only for a passphrase
    /// seal (a recipient seal has no passphrase KDF).
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase_kdf: Option<SealReceiptKdf>,
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
    /// The item's digests as the spec's alg→digest map (one entry per co-hash
    /// algorithm).
    hashes: ItemHashesMap,
    /// Legacy convenience field — the sha2-256 digest, present ONLY when the
    /// item carries a sha2-256 entry. It never carries a non-sha2 digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha2_256: Option<String>,
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
        for (alg, hex) in item.hashes.entries() {
            println!("    {alg}: {hex}");
        }
        println!("    ar_uri:    {}", item.ar_uri);
    }
    if outcome.kem == PASSPHRASE_KEM_DISPLAY {
        println!("  sealed to:   passphrase");
    } else {
        println!(
            "  sealed to:   {} recipient(s), {}",
            outcome.recipient_count, outcome.kem
        );
    }
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
/// error object's `message`). `item_ids` holds each prepared item's stable
/// identity (its ciphertext's SHA-256) in input order; it is built the same
/// way from either the recipient-sealed or the passphrase-sealed prepared
/// artifact, so this one mapper serves both sealing modes.
fn map_submit_sealed_error(
    uploads: &[UploadReceipt],
    source: PublishHelperError,
    files: &[String],
    item_ids: &[String],
) -> CliError {
    let mut mapped = map_publish_error("seal", source);
    if uploads.is_empty() {
        return mapped;
    }
    mapped.message.push_str(&format!(
        "\nseal: {} ciphertext upload(s) had already completed (paid storage) before the \
         failure:",
        uploads.len()
    ));
    for receipt in uploads {
        let file = item_ids
            .iter()
            .position(|id| id == &receipt.item_id)
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

/// Everything the shared tail — the lifecycle wait, the receipt, and the stdout
/// summary — needs from a completed submission, whether it came from a fresh
/// publish or a resume. Both paths converge on [`finish`] so the two can never
/// drift.
struct CompletedSeal {
    /// The gateway's publish response, the exact record bytes, and the quote.
    submission: SealedSubmission,
    /// Each item's ciphertext byte count, in item order (for the receipt).
    ciphertext_bytes: Vec<u64>,
    /// The sealed-to summary (recipient count / KEM / self slot).
    sealed: SealReceiptSealed,
    /// Each item's on-chain hash claim, in item order.
    item_hashes: Vec<Vec<(String, Vec<u8>)>>,
    /// The input file names, in item order — the summary maps each item back.
    files: Vec<String>,
    /// The signer's public key hex when the record was signed.
    signer_pubkey_hex: Option<String>,
    /// The passphrase Argon2id parameters, only for a passphrase seal.
    passphrase_kdf: Option<SealReceiptKdf>,
    /// The gateway base URL the record was published through.
    gateway_base_url: String,
}

/// Parse `--max-usd` into the SDK's `u64` micro-cent price cap.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on a malformed or out-of-range amount.
fn parse_max_usd_micros(args: &SealArgs) -> Result<Option<u64>, CliError> {
    let micros = args
        .max_usd
        .as_deref()
        .map(|text| {
            parse_usd_to_micros(text).map_err(|e| CliError::input(format!("seal: --max-usd: {e}")))
        })
        .transpose()?;
    // The SDK's price cap is a u64 of USD micro-cents; anything outside that
    // range is not a plausible cap for a single publish.
    micros
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| CliError::input("seal: --max-usd is out of range".to_string()))
        })
        .transpose()
}

/// Append the resume instruction — or, when the state file could not be written,
/// a warning that resume is unavailable — to a failed recipient submit's error.
fn append_resume_hint(err: &mut CliError, write_result: Result<(), CliError>, resume_path: &Path) {
    match write_result {
        Ok(()) => err.message.push_str(&format!(
            "\nseal: resume this publish without re-encrypting (and without re-paying any \
             completed upload):\n  cardanowall seal --resume {}",
            resume_path.display()
        )),
        Err(write_err) => err.message.push_str(&format!(
            "\nseal: warning: could not write the resume-state file {}: {} — resume is \
             unavailable for this attempt",
            resume_path.display(),
            write_err.message
        )),
    }
}

/// Reject the input flags that do not belong on a `--resume`. A resume finishes
/// an existing prepared seal, so it takes no content-shaping flags; the seed
/// (for a signed resume), gateway, and output flags are allowed.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) naming every offending flag.
fn reject_resume_input_flags(args: &SealArgs) -> Result<(), CliError> {
    let offenders = [
        ("--file", !args.file.is_empty()),
        ("--to", !args.to.is_empty()),
        ("--to-self", args.to_self),
        ("--passphrase", args.passphrase.is_some()),
        ("--passphrase-file", args.passphrase_file.is_some()),
        ("--passphrase-stdin", args.passphrase_stdin),
        ("--passphrase-m", args.passphrase_m.is_some()),
        ("--passphrase-t", args.passphrase_t.is_some()),
        ("--passphrase-p", args.passphrase_p.is_some()),
        ("--hash-alg", !args.hash_alg.is_empty()),
        ("--supersedes", args.supersedes.is_some()),
        ("--sign", args.sign),
        ("--resume-state", args.resume_state.is_some()),
    ];
    let present: Vec<&str> = offenders
        .iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| *name)
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(CliError::input(format!(
        "seal --resume: a resume finishes an existing prepared seal, so it takes none of the \
         input flags — remove {}. The seed (for a signed resume), gateway, --wait, --timeout, \
         --max-usd, --chunk-bytes, --receipt-out, and --json flags are allowed.",
        present.join(", ")
    )))
}

/// Run the `seal` command: a fresh sealed publish, or — with `--resume` — the
/// completion of one that failed after a prepared seal existed.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code (see the module docs).
pub fn run(args: SealArgs) -> Result<(), CliError> {
    if args.timeout == 0 {
        return Err(CliError::input("seal: --timeout must be positive"));
    }
    match args.resume.clone() {
        Some(path) => run_resume(args, &path),
        None => run_fresh(args),
    }
}

/// A fresh sealed publish. On a recipient-mode failure after the prepared seal
/// exists, a resume-state file is written so the paid uploads are not lost.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code (see the module docs).
fn run_fresh(args: SealArgs) -> Result<(), CliError> {
    let max_usd_micros = parse_max_usd_micros(&args)?;

    // Resolve the content-hash algorithm set once (fail fast on an unknown alg
    // before any secret is read): the same list sizes the capacity gate and
    // co-hashes each sealed item. Defaulting to a single sha2-256 leaves the
    // prepared bytes byte-identical to a seal published before co-hashing.
    let hash_algs = resolve_content_hash_algs(&args.hash_alg, "seal")?;
    let sdk_hash_algs: Vec<SupportedHashAlg> = hash_algs.iter().map(|alg| alg.to_sdk()).collect();

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

    // The seal mode: recipients OR a passphrase, never both. Resolved before
    // any file is read, so a conflicting or malformed passphrase source fails
    // fast.
    let mode = select_seal_mode(&args, &SystemSecretEnv)?;
    let is_passphrase = matches!(mode, SealMode::Passphrase(_));
    // --resume-state names where a recipient failure writes its resume file; a
    // passphrase seal can never resume, so pairing the two is a usage error.
    if is_passphrase && args.resume_state.is_some() {
        return Err(CliError::input(
            "seal: --resume-state applies only to a recipient seal; a passphrase seal cannot be \
             resumed",
        ));
    }
    // The passphrase Argon2id cost parameters (default unless overridden, floor
    // validated). Resolving here refuses a `--passphrase-*` override on a
    // recipient seal, and a below-floor value, before any file is read.
    let kdf_params = resolve_passphrase_kdf_params(&args, &mode)?;

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

    let supersedes_hex: Option<String> = args
        .supersedes
        .as_deref()
        .map(|value| parse_supersedes(value, "seal"))
        .transpose()?
        .map(|bytes| bytes_to_hex(&bytes));

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
    // Each item's on-chain hash claim, co-hashed under the resolved algorithm
    // set. This is computed from the same primitives the SDK seals with, so it
    // matches the published record's `hashes` map byte for byte.
    let item_hashes: Vec<Vec<(String, Vec<u8>)>> = contents
        .iter()
        .map(|c| cohash_content(c, &hash_algs))
        .collect();

    let gateway_base_url = gateway.base_url.clone();
    let client = Label309Client::new(Label309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("seal: {e}")))?;
    let poe = client.poe();

    // Phase 1 (pure, offline) + phase 2 (quote → per-item ciphertext upload →
    // refresh a price lock a slow upload outlived → publish) diverge only in
    // which key material protects the content and which submit helper
    // carries it; `SealedSubmission` and the exit-code mapping are identical
    // downstream of either mode, so only the per-mode pieces the rest of the
    // function needs — the submission, each item's ciphertext size (for the
    // receipt), and the sealed-to summary — leave this match.
    let (submission, ciphertext_bytes, sealed): (SealedSubmission, Vec<u64>, SealReceiptSealed) =
        match mode {
            SealMode::Recipients => {
                let recipients = resolve_recipients(&args, seed.as_deref())?;
                enforce_capacity(
                    &recipients,
                    &hash_algs,
                    args.file.len(),
                    args.sign,
                    supersedes_hex.is_some(),
                )?;

                let prepare_input = SealPrepareInput::new(
                    contents.iter().map(|c| SealPrepareItem::new(c)).collect(),
                    recipients.keys.clone(),
                )
                .with_kem(recipients.kem)
                .with_hash_algs(sdk_hash_algs.clone());
                let prepared = seal_prepare(&prepare_input)
                    .map_err(|e| map_publish_error("seal", e.into()))?;

                let mut submit_input = SubmitSealedInput::new(&prepared);
                submit_input.signer = signer_ref;
                submit_input.max_usd_micros = max_usd_micros;
                submit_input.supersedes = supersedes_hex.clone();
                submit_input.chunk_bytes = args.chunk_bytes;

                let item_ids: Vec<String> = prepared
                    .items()
                    .iter()
                    .map(|item| item.item_id().to_string())
                    .collect();
                let ciphertext_bytes: Vec<u64> = prepared
                    .items()
                    .iter()
                    .map(|item| item.ciphertext().len() as u64)
                    .collect();
                let submission = match poe.submit_sealed(&submit_input) {
                    Ok(submission) => submission,
                    Err(err) => {
                        // A prepared seal exists, so this publish can be resumed
                        // without re-encrypting — and without re-paying any
                        // completed upload. Persist the resume state (regardless
                        // of how many uploads succeeded) and point the user at
                        // the resume command.
                        let resume_path = args
                            .resume_state
                            .clone()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| seal_resume::default_resume_path(&prepared));
                        let SubmitSealedError { uploads, source } = err;
                        let prepared_json = prepared.to_json();
                        let state = SealResumeState {
                            format: RESUME_FORMAT.to_string(),
                            version: RESUME_VERSION,
                            prepared_sha256: seal_resume::prepared_seal_digest(&prepared_json),
                            prepared_seal: prepared_json,
                            uploads: seal_resume::from_sdk_receipts(&uploads),
                            files: args.file.clone(),
                            supersedes: supersedes_hex.clone(),
                            signed: args.sign,
                            to_self: recipients.to_self,
                            gateway_base_url: gateway_base_url.clone(),
                        };
                        let write_result = state.save(&resume_path);
                        let mut cli_err =
                            map_submit_sealed_error(&uploads, source, &args.file, &item_ids);
                        append_resume_hint(&mut cli_err, write_result, &resume_path);
                        return Err(cli_err);
                    }
                };

                (
                    submission,
                    ciphertext_bytes,
                    SealReceiptSealed {
                        recipient_count: recipients.keys.len() as u64,
                        kem: recipients.kem_id(),
                        to_self: recipients.to_self,
                    },
                )
            }
            SealMode::Passphrase(passphrase) => {
                // The record's capacity gate is recipient-slot-shaped
                // (`enforce_capacity` charges per recipient per item); a
                // passphrase envelope carries no slots at all, and the
                // gateway enforces the record cap regardless, so there is no
                // pre-quote gate to run here.
                let prepare_input = PassphraseSealPrepareInput::new(
                    contents.iter().map(|c| SealPrepareItem::new(c)).collect(),
                    passphrase.to_string(),
                )
                .with_hash_algs(sdk_hash_algs.clone())
                .with_params(kdf_params);
                let prepared = passphrase_seal_prepare(&prepare_input)
                    .map_err(|e| map_publish_error("seal", e.into()))?;

                let mut submit_input = SubmitPassphraseSealedInput::new(&prepared);
                submit_input.signer = signer_ref;
                submit_input.max_usd_micros = max_usd_micros;
                submit_input.supersedes = supersedes_hex.clone();
                submit_input.chunk_bytes = args.chunk_bytes;

                let item_ids: Vec<String> = prepared
                    .items()
                    .iter()
                    .map(|item| item.item_id().to_string())
                    .collect();
                let ciphertext_bytes: Vec<u64> = prepared
                    .items()
                    .iter()
                    .map(|item| item.ciphertext().len() as u64)
                    .collect();
                let submission = match poe.submit_passphrase_sealed(&submit_input) {
                    Ok(submission) => submission,
                    Err(err) => {
                        // A passphrase seal derives its content key from the
                        // passphrase, which is never persisted, so there is no
                        // resumable artifact — say so and write no state file.
                        let SubmitSealedError { uploads, source } = err;
                        let mut cli_err =
                            map_submit_sealed_error(&uploads, source, &args.file, &item_ids);
                        cli_err.message.push_str(
                            "\nseal: a passphrase seal cannot be resumed — its content key is \
                             derived from the passphrase, which is never written to disk; re-run \
                             the same command to retry",
                        );
                        return Err(cli_err);
                    }
                };

                (
                    submission,
                    ciphertext_bytes,
                    SealReceiptSealed {
                        recipient_count: 0,
                        kem: PASSPHRASE_KEM_DISPLAY,
                        to_self: false,
                    },
                )
            }
        };
    finish(
        &args,
        &client,
        CompletedSeal {
            submission,
            ciphertext_bytes,
            sealed,
            item_hashes,
            files: args.file.clone(),
            signer_pubkey_hex,
            passphrase_kdf: is_passphrase.then_some(SealReceiptKdf {
                m: kdf_params.m,
                t: kdf_params.t,
                p: kdf_params.p,
            }),
            gateway_base_url,
        },
    )
}

/// Re-anchor a resume to the user's OWN files: every prepared item's hash claim
/// must still match a fresh hash of its recorded input file. This is the
/// load-bearing tamper defense — a swapped prepared seal cannot publish unless it
/// commits to the user's exact plaintext. Runs before any network call or
/// signing.
///
/// A missing or unreadable file is a hard failure, never a silent skip, unless
/// the user explicitly waived the check with `--skip-plaintext-recheck` (for
/// which `skip` is `true`).
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when a file is missing/unreadable (without the
/// waiver), a bound algorithm is unknown, or any item's content no longer hashes
/// to its sealed claim.
fn verify_plaintext_matches(
    prepared: &PreparedSeal,
    files: &[String],
    skip: bool,
) -> Result<(), CliError> {
    if skip {
        return Ok(());
    }
    for (item, path) in prepared.items().iter().zip(files) {
        let content = std::fs::read(path).map_err(|e| {
            CliError::input(format!(
                "seal --resume: cannot re-verify the sealed content against {path}: {e}. If the \
                 input files are unavailable here, pass --skip-plaintext-recheck to resume anyway \
                 (this waives the guarantee that the resumed record commits to your file contents)."
            ))
        })?;
        for (alg_id, expected) in item.hashes() {
            let alg = ContentHashAlg::parse(alg_id).ok_or_else(|| {
                CliError::input(format!(
                    "seal --resume: the prepared seal binds {path} under unknown hash algorithm \
                     {alg_id:?}; cannot re-verify"
                ))
            })?;
            if alg.digest(&content).as_slice() != expected.as_slice() {
                return Err(CliError::input(format!(
                    "seal --resume: {path} no longer matches the sealed record (its {alg_id} hash \
                     differs) — this resume-state does not describe your files. Refusing to \
                     publish a record for content you did not seal."
                )));
            }
        }
    }
    Ok(())
}

/// Print a compact, security-relevant summary of what the resume is about to
/// publish, to stderr, BEFORE any network call or signing. Tampering with the
/// fields not derived from the user's files (supersedes, signed) becomes visible
/// instead of silent; a signed resume also shows the signer identity derived from
/// the supplied seed.
fn print_resume_summary(
    prepared: &PreparedSeal,
    files: &[String],
    supersedes: Option<&str>,
    signer_pubkey_hex: Option<&str>,
    gateway_base_url: &str,
    plaintext_rechecked: bool,
) {
    let short = |digest: &[u8]| {
        let hex = bytes_to_hex(digest);
        format!("{}…", &hex[..hex.len().min(16)])
    };
    let recipient_count = prepared
        .items()
        .first()
        .map_or(0, |item| item.envelope().slots.len());
    eprintln!("seal --resume: about to finish this sealed publish:");
    eprintln!("  gateway:     {gateway_base_url}");
    eprintln!(
        "  recipients:  {recipient_count} ({})",
        kem_choice_id(prepared.kem())
    );
    eprintln!("  supersedes:  {}", supersedes.unwrap_or("none"));
    match signer_pubkey_hex {
        Some(pubkey) => eprintln!("  signed:      yes (signer {pubkey})"),
        None => eprintln!("  signed:      no"),
    }
    if !plaintext_rechecked {
        eprintln!("  plaintext:   NOT re-verified against your files (--skip-plaintext-recheck)");
    }
    eprintln!("  items:");
    for (index, (item, path)) in prepared.items().iter().zip(files).enumerate() {
        let digests: Vec<String> = item
            .hashes()
            .iter()
            .map(|(alg, digest)| format!("{alg} {}", short(digest)))
            .collect();
        eprintln!("    {}. {path}  {}", index + 1, digests.join("  "));
    }
}

/// Finish a recipient seal that failed after a prepared seal existed: load the
/// resume-state file, re-quote, complete any remaining uploads (reusing every
/// receipt already paid for), and publish. On repeated failure the state file
/// is rewritten with the union of receipts; on success it is removed.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code (see the module docs).
fn run_resume(args: SealArgs, resume_path_str: &str) -> Result<(), CliError> {
    let resume_path = PathBuf::from(resume_path_str);
    // A resume finishes an existing prepared seal, so none of the input flags
    // apply. Reject them before touching the file, for a precise message.
    reject_resume_input_flags(&args)?;

    let state = SealResumeState::load(&resume_path)?;
    let prepared = PreparedSeal::from_json(&state.prepared_seal).map_err(|e| {
        CliError::input(format!(
            "seal --resume: {} carries an invalid prepared seal: {e}",
            resume_path.display()
        ))
    })?;
    if state.files.len() != prepared.items().len() {
        return Err(CliError::input(format!(
            "seal --resume: {} lists {} file name(s) for {} prepared item(s)",
            resume_path.display(),
            state.files.len(),
            prepared.items().len()
        )));
    }
    // The load-bearing tamper defense: re-derive the prepared seal's hash claims
    // from the user's OWN input files. A swapped prepared_seal cannot survive
    // this unless it commits to the exact plaintext the user sealed. Runs before
    // any network call or signing.
    verify_plaintext_matches(&prepared, &state.files, args.skip_plaintext_recheck)?;
    let uploaded = seal_resume::to_sdk_receipts(&state.uploads)?;

    // The seed is re-required only when the original run signed it; it is never
    // persisted.
    let seed_bytes = resolve_secret_bytes(
        SecretKind::Seed,
        &args.seed_secret_args(),
        false,
        "seal --resume",
        &SystemSecretEnv,
    )?;
    let signer: Option<SeedSigner> = if state.signed {
        let bytes = seed_bytes.as_deref().ok_or_else(|| {
            CliError::input(
                "seal --resume: the original publish was signed, so the signing seed is required \
                 again — pass --seed / --seed-file / --seed-stdin or set CARDANOWALL_SEED (seeds \
                 are never written to the resume-state file)",
            )
        })?;
        if bytes.len() != 32 {
            return Err(CliError::input(
                "seal --resume: the seed must be exactly 32 bytes",
            ));
        }
        let mut copy = Zeroizing::new([0u8; 32]);
        copy.copy_from_slice(bytes);
        Some(
            signer_from_seed(&*copy)
                .map_err(|e| CliError::input(format!("seal --resume: --seed {e}")))?,
        )
    } else {
        None
    };
    let signer_ref: Option<&dyn Signer> = signer.as_ref().map(|s| s as &dyn Signer);
    let signer_pubkey_hex = signer.as_ref().map(|s| bytes_to_hex(&s.signer_pubkey()));

    let max_usd_micros = parse_max_usd_micros(&args)?;

    // The gateway is resolved EXCLUSIVELY from trusted sources (flag > env >
    // profile), exactly as a fresh publish — the state file's persisted URL
    // carries no authority. It then only cross-checks the resolved gateway
    // against the one the state was created against, so a tampered file can never
    // redirect the authenticated publish (with the real bearer key) elsewhere.
    let gateway = resolve_required_gateway(
        GatewayArgs {
            base_url: args.base_url.as_deref(),
            api_key: args.api_key.as_deref(),
            gateway_profile: args.gateway_profile.as_deref(),
        },
        "seal --resume",
        &SystemSecretEnv,
    )?;
    seal_resume::check_gateway_target(&gateway.base_url, &state)?;
    let gateway_base_url = gateway.base_url.clone();
    let client = Label309Client::new(Label309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("seal --resume: {e}")))?;
    let poe = client.poe();

    // Show what is about to be published BEFORE any network call or signing, so
    // tampering with the fields not derived from the user's files (supersedes,
    // signed) is visible rather than silent.
    print_resume_summary(
        &prepared,
        &state.files,
        state.supersedes.as_deref(),
        signer_pubkey_hex.as_deref(),
        &gateway_base_url,
        !args.skip_plaintext_recheck,
    );

    let mut submit_input = SubmitSealedInput::new(&prepared);
    submit_input.signer = signer_ref;
    submit_input.max_usd_micros = max_usd_micros;
    submit_input.supersedes = state.supersedes.clone();
    submit_input.chunk_bytes = args.chunk_bytes;
    submit_input.uploaded = uploaded;

    let item_ids: Vec<String> = prepared
        .items()
        .iter()
        .map(|item| item.item_id().to_string())
        .collect();
    let ciphertext_bytes: Vec<u64> = prepared
        .items()
        .iter()
        .map(|item| item.ciphertext().len() as u64)
        .collect();

    let submission = match poe.submit_sealed(&submit_input) {
        Ok(submission) => submission,
        Err(err) => {
            let SubmitSealedError { uploads, source } = err;
            // Rewrite the state with the union of receipts so a further resume
            // still skips every paid upload — never dropping one this round did
            // not re-report.
            let merged = seal_resume::merge_receipts(&state.uploads, &uploads);
            let rewritten = SealResumeState {
                uploads: merged,
                ..state.clone()
            };
            let write_result = rewritten.save(&resume_path);
            let mut cli_err = map_submit_sealed_error(&uploads, source, &state.files, &item_ids);
            append_resume_hint(&mut cli_err, write_result, &resume_path);
            return Err(cli_err);
        }
    };

    // The publish landed: the resume-state file has served its purpose.
    match std::fs::remove_file(&resume_path) {
        Ok(()) => eprintln!(
            "seal --resume: published; removed the resume-state file {}",
            resume_path.display()
        ),
        Err(e) => eprintln!(
            "seal --resume: note: could not remove the resume-state file {}: {e}",
            resume_path.display()
        ),
    }

    let sealed = SealReceiptSealed {
        recipient_count: prepared
            .items()
            .first()
            .map_or(0, |item| item.envelope().slots.len() as u64),
        kem: kem_choice_id(prepared.kem()),
        to_self: state.to_self,
    };
    let item_hashes: Vec<Vec<(String, Vec<u8>)>> = prepared
        .items()
        .iter()
        .map(|item| {
            item.hashes()
                .iter()
                .map(|(alg, digest)| (alg.clone(), digest.clone()))
                .collect()
        })
        .collect();

    finish(
        &args,
        &client,
        CompletedSeal {
            submission,
            ciphertext_bytes,
            sealed,
            item_hashes,
            files: state.files.clone(),
            signer_pubkey_hex,
            passphrase_kdf: None,
            gateway_base_url,
        },
    )
}

/// The shared tail: follow the lifecycle stream to the wait target, write the
/// receipt, emit the summary, and map a wait timeout to exit `3`.
///
/// # Errors
///
/// Returns [`CliError`] on a wait failure or a receipt-write failure, and exit
/// `3` when the wait deadline elapses (the publish continues on the gateway).
fn finish(
    args: &SealArgs,
    client: &Label309Client,
    completed: CompletedSeal,
) -> Result<(), CliError> {
    let CompletedSeal {
        submission,
        ciphertext_bytes,
        sealed,
        item_hashes,
        files,
        signer_pubkey_hex,
        passphrase_kdf,
        gateway_base_url,
    } = completed;
    let quote = submission.quote;
    let response = submission.response;
    let record_hex = bytes_to_hex(&submission.record_bytes);
    let uris = submission.uris;

    let wait_result = wait_for_poe_target(client, &response.id, args.wait, args.timeout, "seal")?;
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
        let items: Vec<SealReceiptItem> = item_hashes
            .iter()
            .zip(&uris)
            .zip(&ciphertext_bytes)
            .map(|((hashes, uri), &ciphertext_bytes)| {
                let hashes = ItemHashesMap::from_item_hashes(hashes);
                SealReceiptItem {
                    sha2_256: hashes.sha2_256(),
                    hashes,
                    ar_uri: uri.clone(),
                    ciphertext_bytes,
                }
            })
            .collect();
        let receipt = SealReceipt {
            format: RECEIPT_FORMAT,
            sealed,
            items,
            record_hex: record_hex.clone(),
            signed: signer_pubkey_hex.is_some(),
            signer_ed25519: signer_pubkey_hex.clone(),
            poe_id: response.id.clone(),
            tx_hash: tx_hash.clone(),
            status: status.clone(),
            gateway_base_url,
            passphrase_kdf,
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
        items: files
            .iter()
            .zip(&item_hashes)
            .zip(&uris)
            .map(|((file, hashes), uri)| {
                let hashes = ItemHashesMap::from_item_hashes(hashes);
                SealOutcomeItem {
                    file: file.clone(),
                    sha2_256: hashes.sha2_256(),
                    hashes,
                    ar_uri: uri.clone(),
                }
            })
            .collect(),
        recipient_count: sealed.recipient_count,
        kem: sealed.kem,
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
            passphrase: None,
            passphrase_file: None,
            passphrase_stdin: false,
            passphrase_m: None,
            passphrase_t: None,
            passphrase_p: None,
            hash_alg: vec![],
            supersedes: None,
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
            resume: None,
            resume_state: None,
            skip_plaintext_recheck: false,
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
        let sha2 = [ContentHashAlg::Sha2_256];
        let fits = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 11],
            to_self: false,
        };
        enforce_capacity(&fits, &sha2, 1, true, false).unwrap();
        let too_many = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 12],
            to_self: false,
        };
        let err = enforce_capacity(&too_many, &sha2, 1, false, false).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("recipient"), "{}", err.message);
        // Classical capacity is far higher: 144 fit even signed.
        let classical = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 144],
            to_self: false,
        };
        enforce_capacity(&classical, &sha2, 1, true, false).unwrap();
        let classical_over = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 160],
            to_self: false,
        };
        assert_eq!(
            enforce_capacity(&classical_over, &sha2, 1, true, false)
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn capacity_gate_charges_every_item_a_full_slot_set() {
        // Each item repeats the whole recipient slot set, so the budget is
        // spent per item × per recipient: 2 items × 5 hybrid slots fit, while
        // 4 items × 3 hybrid slots (12 in total) do not.
        let sha2 = [ContentHashAlg::Sha2_256];
        let five = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 5],
            to_self: false,
        };
        enforce_capacity(&five, &sha2, 2, true, false).unwrap();
        let three = RecipientSet {
            kem: SealedKemChoice::Mlkem768X25519,
            keys: vec![vec![0u8; 1216]; 3],
            to_self: false,
        };
        let err = enforce_capacity(&three, &sha2, 4, false, false).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("item"), "{}", err.message);
    }

    /// Resolve the `--hash-alg` argv the way `run` does, then map it to the SDK
    /// enum the prepare builders take — the exact path a co-hashed seal walks.
    fn sdk_algs(values: &[&str]) -> Vec<SupportedHashAlg> {
        let owned: Vec<String> = values.iter().map(|s| (*s).to_string()).collect();
        resolve_content_hash_algs(&owned, "seal")
            .unwrap()
            .iter()
            .map(|alg| alg.to_sdk())
            .collect()
    }

    #[test]
    fn recipient_seal_co_hashes_every_item_under_each_hash_alg() {
        let content = b"sealed co-hash content";
        let recipient = derive_x25519_keypair(&[1u8; 32])
            .unwrap()
            .public_key
            .to_vec();
        let input = SealPrepareInput::new(vec![SealPrepareItem::new(content)], vec![recipient])
            .with_kem(SealedKemChoice::X25519)
            .with_hash_algs(sdk_algs(&["sha2-256", "blake2b-256"]));
        let prepared = seal_prepare(&input).unwrap();

        // The prepared item carries the full multi-entry hashes map bound into
        // the envelope, each digest the SDK primitive over the plaintext.
        let hashes = prepared.items()[0].hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes.get("sha2-256").map(Vec::as_slice),
            Some(cardanowall::hash::sha256(content).as_slice())
        );
        assert_eq!(
            hashes.get("blake2b-256").map(Vec::as_slice),
            Some(cardanowall::hash::blake2b256(content).as_slice())
        );
    }

    #[test]
    fn passphrase_seal_co_hashes_every_item_under_each_hash_alg() {
        let content = b"passphrase co-hash content";
        let input = PassphraseSealPrepareInput::new(
            vec![SealPrepareItem::new(content)],
            "correct horse battery staple".to_string(),
        )
        .with_hash_algs(sdk_algs(&["blake2b-256", "sha2-256"]));
        let prepared = passphrase_seal_prepare(&input).unwrap();

        let hashes = prepared.items()[0].hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes.get("sha2-256").map(Vec::as_slice),
            Some(cardanowall::hash::sha256(content).as_slice())
        );
        assert_eq!(
            hashes.get("blake2b-256").map(Vec::as_slice),
            Some(cardanowall::hash::blake2b256(content).as_slice())
        );
    }

    #[test]
    fn default_seal_stays_byte_identical_to_the_pre_co_hash_builder() {
        // No --hash-alg resolves to the lone sha2-256, so the CLI wiring must
        // leave a default seal's hashes map exactly the one-entry claim a seal
        // published before co-hashing already anchors.
        let content = b"default sealed content";
        let recipient = derive_x25519_keypair(&[2u8; 32])
            .unwrap()
            .public_key
            .to_vec();

        let wired =
            SealPrepareInput::new(vec![SealPrepareItem::new(content)], vec![recipient.clone()])
                .with_kem(SealedKemChoice::X25519)
                .with_hash_algs(sdk_algs(&[]));
        let wired_hashes = seal_prepare(&wired).unwrap().items()[0].hashes().clone();

        // The untouched builder, exactly as the command wrote it before the
        // flag existed. The envelope is randomized so the two ciphertexts
        // differ, but the deterministic hashes map must not.
        let default_builder =
            SealPrepareInput::new(vec![SealPrepareItem::new(content)], vec![recipient])
                .with_kem(SealedKemChoice::X25519);
        let default_hashes = seal_prepare(&default_builder).unwrap().items()[0]
            .hashes()
            .clone();

        assert_eq!(wired_hashes, default_hashes);
        assert_eq!(wired_hashes.len(), 1);
        assert_eq!(
            wired_hashes.get("sha2-256").map(Vec::as_slice),
            Some(cardanowall::hash::sha256(content).as_slice())
        );
    }

    #[test]
    fn capacity_estimate_grows_with_each_co_hash_alg() {
        // A second co-hash entry widens every item, so the estimate the quote
        // is sized from must rise with the algorithm list — a co-hashed seal
        // that priced on a single hash would under-quote.
        let set = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 2],
            to_self: false,
        };
        let single = enforce_capacity(&set, &[ContentHashAlg::Sha2_256], 1, false, false).unwrap();
        let dual = enforce_capacity(
            &set,
            &[ContentHashAlg::Sha2_256, ContentHashAlg::Blake2b256],
            1,
            false,
            false,
        )
        .unwrap();
        assert!(
            dual > single,
            "co-hash estimate {dual} must exceed single-hash {single}"
        );
    }

    #[test]
    fn capacity_estimate_accounts_for_supersedes() {
        // A supersedes link widens the record, so the estimate must include it —
        // a boundary-sized supersede that priced without the link would pass the
        // local gate then fail at quote/publish.
        let set = RecipientSet {
            kem: SealedKemChoice::X25519,
            keys: vec![vec![0u8; 32]; 2],
            to_self: false,
        };
        let plain = enforce_capacity(&set, &[ContentHashAlg::Sha2_256], 1, false, false).unwrap();
        let superseding =
            enforce_capacity(&set, &[ContentHashAlg::Sha2_256], 1, false, true).unwrap();
        assert!(
            superseding > plain,
            "supersede estimate {superseding} must exceed non-supersede {plain}"
        );
    }

    #[test]
    fn unknown_hash_alg_is_rejected_like_submit() {
        // The flag shares submit's resolver, so an unregistered algorithm is
        // the same exit-4 input error, prefixed for this command.
        let err = resolve_content_hash_algs(&["md5".to_string()], "seal").unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.starts_with("seal:"), "{}", err.message);
        assert!(err.message.contains("sha2-256"), "{}", err.message);
    }

    #[test]
    fn passphrase_kdf_params_resolve_default_custom_and_reject_below_floor() {
        // A --passphrase-* override on a recipient seal is a usage error; with
        // no override a recipient seal resolves the (unused) default.
        let recipients = SealMode::Recipients;
        assert_eq!(
            resolve_passphrase_kdf_params(&base_args(), &recipients).unwrap(),
            PassphraseKdfParams::default()
        );
        let mut override_on_recipients = base_args();
        override_on_recipients.passphrase_m = Some(131_072);
        assert_eq!(
            resolve_passphrase_kdf_params(&override_on_recipients, &recipients)
                .unwrap_err()
                .code,
            4
        );

        // A passphrase seal defaults to the producer default unchanged, and
        // custom overrides pass through per field.
        let passphrase = SealMode::Passphrase(Zeroizing::new("pw".to_string()));
        assert_eq!(
            resolve_passphrase_kdf_params(&base_args(), &passphrase).unwrap(),
            PassphraseKdfParams::default()
        );
        let mut custom = base_args();
        custom.passphrase_m = Some(131_072);
        custom.passphrase_t = Some(5);
        custom.passphrase_p = Some(2);
        assert_eq!(
            resolve_passphrase_kdf_params(&custom, &passphrase).unwrap(),
            PassphraseKdfParams {
                m: 131_072,
                t: 5,
                p: 2
            }
        );

        // Each parameter below its registry floor is refused.
        for (m, t, p) in [(1024u32, 3u32, 4u32), (65_536, 2, 4), (65_536, 3, 0)] {
            let mut below = base_args();
            below.passphrase_m = Some(m);
            below.passphrase_t = Some(t);
            below.passphrase_p = Some(p);
            let err = resolve_passphrase_kdf_params(&below, &passphrase).unwrap_err();
            assert_eq!(err.code, 4, "m={m} t={t} p={p}");
            assert!(err.message.contains("floor"), "{}", err.message);
        }
    }

    #[test]
    fn passphrase_seal_binds_custom_kdf_params_into_the_record() {
        use cardanowall::client::passphrase_sealed_record;
        use cardanowall::poe_standard::EncryptionEnvelope;

        // Custom cost parameters (memory held at the floor to keep the KDF
        // cheap; t and p differ from the defaults) must land in the assembled
        // record's on-chain `passphrase.params` block, byte for byte.
        let custom = PassphraseKdfParams {
            m: 65_536,
            t: 4,
            p: 2,
        };
        let prepared = passphrase_seal_prepare(
            &PassphraseSealPrepareInput::new(
                vec![SealPrepareItem::new(b"kdf params content")],
                "correct horse battery staple".to_string(),
            )
            .with_params(custom),
        )
        .unwrap();
        let uri = format!("ar://{}", "A".repeat(43));
        let record = passphrase_sealed_record(&prepared, std::slice::from_ref(&uri), None).unwrap();
        let items = record.items.expect("record carries items");
        let EncryptionEnvelope::Scheme1(enc) = items[0].enc.as_ref().expect("item is sealed")
        else {
            panic!("expected a scheme-1 envelope");
        };
        let params = &enc.passphrase.as_ref().expect("passphrase block").params;
        assert_eq!(
            params,
            &vec![
                ("m".to_string(), 65_536u64),
                ("t".to_string(), 4u64),
                ("p".to_string(), 2u64),
            ]
        );
    }

    #[test]
    fn seal_args_debug_redacts_seed_and_api_key() {
        let mut args = base_args();
        args.seed = Some("ab".repeat(32));
        args.api_key = Some("super-secret-bearer".to_string());
        args.passphrase = Some("correct horse battery staple".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(!rendered.contains("correct horse battery staple"));
        assert!(rendered.contains("[redacted]"));
        // The non-secret passphrase source fields still print.
        assert!(rendered.contains("passphrase_stdin"));
    }

    #[test]
    fn passphrase_and_recipients_are_mutually_exclusive() {
        use crate::secret::test_support::FakeSecretEnv;

        // --passphrase alongside --to.
        let mut via_to = base_args();
        via_to.passphrase = Some("correct horse battery staple".to_string());
        via_to.to = vec![x25519_recipient(1)];
        let err = select_seal_mode(&via_to, &FakeSecretEnv::default()).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("not both"), "{}", err.message);

        // --passphrase alongside --to-self.
        let mut via_to_self = base_args();
        via_to_self.passphrase = Some("correct horse battery staple".to_string());
        via_to_self.to_self = true;
        assert_eq!(
            select_seal_mode(&via_to_self, &FakeSecretEnv::default())
                .unwrap_err()
                .code,
            4
        );

        // An env-sourced passphrase conflicts exactly the same as an argv one.
        let mut via_env = base_args();
        via_env.to = vec![x25519_recipient(1)];
        let env = FakeSecretEnv {
            vars: std::collections::HashMap::from([(
                "CARDANOWALL_PASSPHRASE".to_string(),
                "correct horse battery staple".to_string(),
            )]),
            ..FakeSecretEnv::default()
        };
        assert_eq!(select_seal_mode(&via_env, &env).unwrap_err().code, 4);
    }

    #[test]
    fn passphrase_alone_selects_passphrase_mode() {
        use crate::secret::test_support::FakeSecretEnv;

        let mut args = base_args();
        args.passphrase = Some("correct horse battery staple".to_string());
        match select_seal_mode(&args, &FakeSecretEnv::default()).unwrap() {
            SealMode::Passphrase(passphrase) => {
                assert_eq!(&*passphrase, "correct horse battery staple");
            }
            SealMode::Recipients => panic!("expected passphrase mode"),
        }
    }

    #[test]
    fn no_passphrase_source_selects_recipient_mode() {
        use crate::secret::test_support::FakeSecretEnv;

        let args = base_args();
        match select_seal_mode(&args, &FakeSecretEnv::default()).unwrap() {
            SealMode::Recipients => {}
            SealMode::Passphrase(_) => panic!("expected recipient mode"),
        }
    }
}
