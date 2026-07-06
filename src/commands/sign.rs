//! `cardanowall sign` — offline PATH-1 (identity Ed25519) record signing.
//!
//! Three verbs, all offline (no chain / storage / API interaction):
//!
//! - `sign record`   — derive the signer from `--seed`, build/load the record,
//!   attach a path-1 `sigs[i]` in-process, emit the signed record.
//! - `sign prepare`  — detached step 1: emit the exact `Sig_structure` bytes an
//!   external Ed25519 signer (KMS / HSM / air-gapped) must sign, plus the signer
//!   pubkey + the record CBOR. `--hashed` selects CIP-8 hashed mode, where the
//!   payload slot is `BLAKE2b-224(to_sign)` — for a hardware co-signer whose
//!   signing buffer cannot hold the full `to_sign`.
//! - `sign assemble` — detached step 2: take the external 64-byte signature and
//!   the record, emit the signed record. Never touches a seed. `--hashed` writes
//!   the unprotected `"hashed": true` header so a verifier reconstructs the same
//!   payload the signer saw; it MUST match the mode `prepare` ran in.
//!
//! Both modes commit the same content and produce the same on-wire record size;
//! `--hashed` only shifts which bytes cross the signing boundary, so software
//! signers should stay on the default (non-hashed) mode. To catch a mismatched
//! pair, `prepare` stamps its JSON with a `hashed` marker and `assemble` refuses
//! a `--hashed` flag that disagrees with it (rather than emit a signature no
//! verifier can check).
//!
//! This surface is PATH-1 ONLY (identity Ed25519). The CIP-30 wallet path
//! (path-2) is owned elsewhere.
//!
//! Exit codes: `0` ok / `4` CLI input error (bad seed/hash/signature, structurally
//! invalid record, or a `--hashed` flag that disagrees with the prepare output) /
//! `2` IO error (unreadable `--in` file).

use std::io::Read;

use cardanowall::client::{
    assemble_cose_sign1, assemble_cose_sign1_hashed, prepare_sig_structure,
    prepare_sig_structure_hashed, OffHostSignError, Signer,
};
use cardanowall::poe_standard::{
    encode_poe_record, validate_poe_record, ItemEntry, PoeRecord, ValidateResult, ValidatorOptions,
};
use cardanowall::seed_derive::signer_from_seed;
use clap::{Args, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::publish_common::{parse_cohash_spec, resolve_content_hash_algs};
use crate::secret::{resolve_secret_bytes, SecretEnv, SecretKind, SystemSecretEnv};
use crate::util::{bytes_to_hex, hex_to_bytes, is_all_hex, CliError};

const ED25519_PUBKEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Arguments for `cardanowall sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The signing verb to run.
    #[command(subcommand)]
    pub verb: SignVerb,
}

impl SignArgs {
    /// Whether the active verb's record source was invoked with `--json`. The
    /// `prepare` verb always emits JSON (its consumers are programmatic).
    #[must_use]
    pub fn source_json(&self) -> bool {
        match &self.verb {
            SignVerb::Record(a) => a.source.json,
            SignVerb::Prepare(_) => true,
            SignVerb::Assemble(a) => a.source.json,
        }
    }
}

/// The three signing verbs.
#[derive(Debug, Subcommand)]
pub enum SignVerb {
    /// Sign in-process with the --seed identity (path-1).
    Record(SignRecordArgs),
    /// Detached step 1: emit the exact bytes-to-sign.
    Prepare(SignPrepareArgs),
    /// Detached step 2: attach an external 64-byte signature.
    Assemble(SignAssembleArgs),
}

/// Shared record-source options carried by all three verbs.
#[derive(Debug, Args, Clone)]
pub struct RecordSource {
    /// record source file (CBOR hex/raw or JSON); omit to read stdin.
    #[arg(long)]
    pub r#in: Option<String>,
    /// build a minimal single-item hash-only record from one or more
    /// precomputed digests. A comma-separated list of `alg:digest` pairs
    /// co-hashes the item (e.g. `sha2-256:<hex>,blake2b-256:<hex>`); a bare
    /// `<hex>` takes the lone --hash-alg (default sha2-256).
    #[arg(long)]
    pub hash: Option<String>,
    /// content-hash algorithm for a bare --hash digest (repeatable only to
    /// disambiguate; an explicit alg:digest overrides it). Default sha2-256.
    #[arg(long = "hash-alg", value_name = "ALG")]
    pub hash_alg: Vec<String>,
    /// emit a machine-readable JSON object instead of raw CBOR hex.
    #[arg(long)]
    pub json: bool,
}

/// The seed-input options shared by the verbs that derive a signer from the
/// master seed. Carries the raw flag plus its `*-file` / `*-stdin` variants.
///
/// `seed` carries raw secret material passed on argv, so `Debug` is hand-written
/// to redact it: no `{:?}`, log, or panic-backtrace path can ever surface the
/// value.
#[derive(Args, Clone, Default)]
pub struct SeedSource {
    /// 32-byte master identity seed: 64-digit hex or the checksummed
    /// L309-SEED-1... form. INSECURE on argv (shell history / ps / CI logs);
    /// prefer --seed-file / --seed-stdin / CARDANOWALL_SEED.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin (also `--seed -`).
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
}

impl std::fmt::Debug for SeedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedSource")
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .finish()
    }
}

impl SeedSource {
    fn secret_args(&self) -> crate::secret::SecretArgs {
        crate::secret::SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }

    /// Whether any seed source was supplied on argv (file/stdin/value).
    fn present(&self) -> bool {
        self.secret_args().any_present()
    }
}

/// Arguments for `cardanowall sign record`.
#[derive(Debug, Args)]
pub struct SignRecordArgs {
    /// The record source.
    #[command(flatten)]
    pub source: RecordSource,
    /// The seed source.
    #[command(flatten)]
    pub seed: SeedSource,
}

/// Arguments for `cardanowall sign prepare`.
#[derive(Debug, Args)]
pub struct SignPrepareArgs {
    /// The record source.
    #[command(flatten)]
    pub source: RecordSource,
    /// The seed source (or pass --signer-pubkey for a fully air-gapped seed).
    #[command(flatten)]
    pub seed: SeedSource,
    /// 32-byte raw Ed25519 public key (air-gapped: avoids the seed).
    #[arg(long)]
    pub signer_pubkey: Option<String>,
    /// CIP-8 hashed mode: emit `Sig_structure[3] = BLAKE2b-224(to_sign)` for a
    /// hardware co-signer whose signing buffer cannot hold the full payload.
    /// Software signers should leave this off; `sign assemble` must be given the
    /// same flag.
    #[arg(long)]
    pub hashed: bool,
}

/// Arguments for `cardanowall sign assemble`.
#[derive(Debug, Args)]
pub struct SignAssembleArgs {
    /// The record source.
    #[command(flatten)]
    pub source: RecordSource,
    /// 32-byte raw Ed25519 public key.
    #[arg(long)]
    pub signer_pubkey: Option<String>,
    /// 64-byte raw Ed25519 signature over the prepare-step bytes.
    #[arg(long)]
    pub signature: Option<String>,
    /// CIP-8 hashed mode: the signature covers `BLAKE2b-224(to_sign)` and the
    /// assembled COSE_Sign1 carries the unprotected `"hashed": true` header.
    /// Must match the mode `sign prepare` ran in.
    #[arg(long)]
    pub hashed: bool,
}

#[derive(Debug, Serialize)]
struct SignedRecordOutput {
    record_cbor_hex: String,
    sig_index: usize,
    signer_pubkey_hex: String,
}

/// Run the `sign` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: SignArgs) -> Result<(), CliError> {
    match args.verb {
        SignVerb::Record(a) => run_record(a),
        SignVerb::Prepare(a) => run_prepare(a),
        SignVerb::Assemble(a) => run_assemble(a),
    }
}

fn read_stdin_bytes() -> Result<Vec<u8>, CliError> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| CliError::network(format!("sign: cannot read stdin: {e}")))?;
    Ok(buf)
}

/// Build a minimal single-item hash-only record from a precomputed-hash spec:
/// one or more `alg:digest` pairs co-hashing the item (a bare digest takes the
/// lone `--hash-alg`, default sha2-256).
fn record_from_hash_spec(spec: &str, hash_alg: &[String]) -> Result<PoeRecord, CliError> {
    let default_algs = resolve_content_hash_algs(hash_alg, "sign")?;
    let hashes = parse_cohash_spec(spec, &default_algs, "sign")?;
    Ok(PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes,
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    })
}

/// A resolved record plus, when the source was a `sign prepare` JSON envelope,
/// that envelope's `hashed` marker. `assemble` reads the marker to reject a
/// `--hashed` flag that disagrees with the mode the payload was prepared in,
/// rather than silently emitting a signature no verifier can check.
struct ResolvedRecord {
    record: PoeRecord,
    prepare_hashed: Option<bool>,
}

/// The subset of `sign prepare`'s JSON output that a downstream source consumes:
/// the record to re-sign and the mode marker. The remaining prepare fields
/// (`sig_structure_hex`, `signer_pubkey_hex`, …) are ignored here.
#[derive(serde::Deserialize)]
struct PrepareEnvelope {
    record_cbor_hex: String,
    hashed: Option<bool>,
}

/// Structurally validate CBOR bytes as a Label 309 record, returning the decoded
/// record. The validator both verifies the wire shape AND returns the record.
fn validate_record_cbor(cbor: &[u8], label: &str) -> Result<PoeRecord, CliError> {
    match validate_poe_record(cbor, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => Ok(*record),
        ValidateResult::Fail { issues } => {
            let code = issues.first().map_or("UNKNOWN", |i| i.code.code());
            Err(CliError::input(format!(
                "sign: {label} is not a valid Label 309 record: {code}"
            )))
        }
    }
}

/// Decode a record source's raw bytes. Three shapes are accepted, tried in
/// order: a `sign prepare` JSON envelope (carrying `record_cbor_hex` plus the
/// `hashed` marker, so `assemble` can be piped the prepare step's own output),
/// an all-hex CBOR string, or raw CBOR bytes.
fn record_from_source_bytes(raw: &[u8], label: &str) -> Result<ResolvedRecord, CliError> {
    let as_text = String::from_utf8_lossy(raw);
    let trimmed = as_text.trim();
    if trimmed.starts_with('{') {
        if let Ok(envelope) = serde_json::from_str::<PrepareEnvelope>(trimmed) {
            let cbor = hex_to_bytes(envelope.record_cbor_hex.trim())
                .map_err(|e| CliError::input(format!("sign: {label} record_cbor_hex {e}")))?;
            return Ok(ResolvedRecord {
                record: validate_record_cbor(&cbor, label)?,
                prepare_hashed: envelope.hashed,
            });
        }
    }
    let cbor: Vec<u8> = if is_all_hex(trimmed) {
        hex_to_bytes(trimmed).map_err(|e| CliError::input(format!("sign: {label} {e}")))?
    } else {
        raw.to_vec()
    };
    Ok(ResolvedRecord {
        record: validate_record_cbor(&cbor, label)?,
        prepare_hashed: None,
    })
}

fn resolve_record(source: &RecordSource) -> Result<ResolvedRecord, CliError> {
    if source.hash.is_some() && source.r#in.is_some() {
        return Err(CliError::input(
            "sign: --hash and --in are mutually exclusive",
        ));
    }
    if let Some(hash) = &source.hash {
        return Ok(ResolvedRecord {
            record: record_from_hash_spec(hash.trim(), &source.hash_alg)?,
            prepare_hashed: None,
        });
    }
    if let Some(path) = &source.r#in {
        let raw = std::fs::read(path)
            .map_err(|e| CliError::network(format!("sign: cannot read --in {path}: {e}")))?;
        return record_from_source_bytes(&raw, &format!("--in {path}"));
    }
    let raw = read_stdin_bytes()?;
    if raw.is_empty() {
        return Err(CliError::input(
            "sign: no record source — pass --hash, --in <file>, or pipe to stdin",
        ));
    }
    record_from_source_bytes(&raw, "<stdin>")
}

/// Resolve the master seed through the shared secret layer (file > stdin > argv >
/// env > hidden prompt on a TTY > error). The seed is required here.
fn resolve_seed(source: &SeedSource, env: &dyn SecretEnv) -> Result<Zeroizing<Vec<u8>>, CliError> {
    resolve_secret_bytes(SecretKind::Seed, &source.secret_args(), true, "sign", env)
        .map(|opt| opt.expect("a required seed resolves to Some or errors"))
}

fn resolve_pubkey_hex(hex: Option<&str>, label: &str) -> Result<Vec<u8>, CliError> {
    let hex = hex.map(str::trim).filter(|s| !s.is_empty());
    let Some(hex) = hex else {
        return Err(CliError::input(format!("sign: {label} is required")));
    };
    let bytes = hex_to_bytes(hex).map_err(|e| CliError::input(format!("sign: {label} {e}")))?;
    if bytes.len() != ED25519_PUBKEY_BYTES {
        return Err(CliError::input(format!(
            "sign: {label} must decode to exactly {ED25519_PUBKEY_BYTES} bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn emit_signed_record(
    record: &PoeRecord,
    signer_pubkey: &[u8],
    json: bool,
) -> Result<(), CliError> {
    let cbor = encode_poe_record(record)
        .map_err(|e| CliError::input(format!("sign: record encode failed: {e}")))?;
    let cbor_hex = bytes_to_hex(&cbor);
    if json {
        let payload = SignedRecordOutput {
            record_cbor_hex: cbor_hex,
            sig_index: record.sigs.as_ref().map_or(1, Vec::len).saturating_sub(1),
            signer_pubkey_hex: bytes_to_hex(signer_pubkey),
        };
        println!(
            "{}",
            serde_json::to_string(&payload).expect("SignedRecordOutput serialises")
        );
    } else {
        println!("{cbor_hex}");
    }
    Ok(())
}

fn map_off_host_err(verb: &str, err: OffHostSignError) -> CliError {
    CliError::input(format!("sign {verb}: {err}"))
}

fn run_record(args: SignRecordArgs) -> Result<(), CliError> {
    let seed = resolve_seed(&args.seed, &SystemSecretEnv)?;
    let signer =
        signer_from_seed(&seed).map_err(|e| CliError::input(format!("sign record: {e}")))?;
    let signer_pubkey = signer.signer_pubkey();
    let record = resolve_record(&args.source)?.record;

    let prepared = prepare_sig_structure(&record, &signer_pubkey)
        .map_err(|e| map_off_host_err("record", e))?;
    let signature = signer
        .sign(&prepared.sig_structure_bytes)
        .map_err(|e| CliError::input(format!("sign record: {e}")))?;
    let assembled = assemble_cose_sign1(&record, &signer_pubkey, &signature)
        .map_err(|e| map_off_host_err("record", e))?;

    let mut signed = record;
    let mut sigs = signed.sigs.take().unwrap_or_default();
    sigs.push(assembled.sig_entry);
    signed.sigs = Some(sigs);
    emit_signed_record(&signed, &signer_pubkey, args.source.json)
}

/// The signer pubkey for prepare: from --signer-pubkey when present (so a fully
/// air-gapped seed never touches this host) otherwise derived from the seed.
fn resolve_signer_pubkey_for_prepare(
    args: &SignPrepareArgs,
    env: &dyn SecretEnv,
) -> Result<Vec<u8>, CliError> {
    if args.signer_pubkey.is_some() {
        return resolve_pubkey_hex(args.signer_pubkey.as_deref(), "--signer-pubkey");
    }
    if args.seed.present() {
        let seed = resolve_seed(&args.seed, env)?;
        let signer =
            signer_from_seed(&seed).map_err(|e| CliError::input(format!("sign prepare: {e}")))?;
        return Ok(signer.signer_pubkey());
    }
    Err(CliError::input(
        "sign prepare: pass either --seed (or --seed-file/--seed-stdin/CARDANOWALL_SEED) \
         or --signer-pubkey",
    ))
}

fn run_prepare(args: SignPrepareArgs) -> Result<(), CliError> {
    let signer_pubkey = resolve_signer_pubkey_for_prepare(&args, &SystemSecretEnv)?;
    let record = resolve_record(&args.source)?.record;
    let record_cbor = encode_poe_record(&record)
        .map_err(|e| CliError::input(format!("sign prepare: record encode failed: {e}")))?;
    // JSON only: the external signer + the assemble step consume these fields
    // programmatically, so a single machine-readable object is the right shape.
    // The `hashed` marker travels with the record so `assemble` can reject a
    // mode mismatch instead of emitting an unverifiable signature.
    let payload = if args.hashed {
        let prepared = prepare_sig_structure_hashed(&record, &signer_pubkey)
            .map_err(|e| map_off_host_err("prepare", e))?;
        // `to_sign_hash_hex` exposes the 28-byte BLAKE2b-224 digest the signer
        // commits to; `sig_structure_hex` remains the exact bytes it feeds to
        // Ed25519, symmetric with the non-hashed path.
        serde_json::json!({
            "sig_structure_hex": bytes_to_hex(&prepared.sig_structure_bytes),
            "protected_header_hex": bytes_to_hex(&prepared.protected_header_bytes),
            "to_sign_hash_hex": bytes_to_hex(&prepared.to_sign_hash_bytes),
            "signer_pubkey_hex": bytes_to_hex(&signer_pubkey),
            "record_cbor_hex": bytes_to_hex(&record_cbor),
            "hashed": true,
        })
    } else {
        let prepared = prepare_sig_structure(&record, &signer_pubkey)
            .map_err(|e| map_off_host_err("prepare", e))?;
        serde_json::json!({
            "sig_structure_hex": bytes_to_hex(&prepared.sig_structure_bytes),
            "protected_header_hex": bytes_to_hex(&prepared.protected_header_bytes),
            "signer_pubkey_hex": bytes_to_hex(&signer_pubkey),
            "record_cbor_hex": bytes_to_hex(&record_cbor),
            "hashed": false,
        })
    };
    println!("{payload}");
    Ok(())
}

fn run_assemble(args: SignAssembleArgs) -> Result<(), CliError> {
    let signer_pubkey = resolve_pubkey_hex(args.signer_pubkey.as_deref(), "--signer-pubkey")?;
    let signature_hex = args
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(signature_hex) = signature_hex else {
        return Err(CliError::input("sign assemble: --signature is required"));
    };
    let signature = hex_to_bytes(signature_hex)
        .map_err(|e| CliError::input(format!("sign assemble: --signature {e}")))?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(CliError::input(format!(
            "sign assemble: --signature must decode to exactly {ED25519_SIGNATURE_BYTES} bytes (got {})",
            signature.len()
        )));
    }
    let resolved = resolve_record(&args.source)?;
    if let Some(prepared_hashed) = resolved.prepare_hashed {
        if prepared_hashed != args.hashed {
            return Err(CliError::input(format!(
                "sign assemble: --hashed is {} but the record was prepared in {} mode — \
                 the flag must match `sign prepare` or the signature will not verify",
                args.hashed,
                if prepared_hashed {
                    "hashed"
                } else {
                    "non-hashed"
                },
            )));
        }
    }
    let signed = assemble_signed_record(resolved.record, &signer_pubkey, &signature, args.hashed)?;
    emit_signed_record(&signed, &signer_pubkey, args.source.json)
}

/// Assemble the detached COSE_Sign1 — hashed (CIP-8) or non-hashed per `hashed`
/// — and append it as a new `sigs[]` entry, returning the signed record.
fn assemble_signed_record(
    record: PoeRecord,
    signer_pubkey: &[u8],
    signature: &[u8],
    hashed: bool,
) -> Result<PoeRecord, CliError> {
    let assembled = if hashed {
        assemble_cose_sign1_hashed(&record, signer_pubkey, signature)
            .map_err(|e| map_off_host_err("assemble", e))?
    } else {
        assemble_cose_sign1(&record, signer_pubkey, signature)
            .map_err(|e| map_off_host_err("assemble", e))?
    };
    let mut signed = record;
    let mut sigs = signed.sigs.take().unwrap_or_default();
    sigs.push(assembled.sig_entry);
    signed.sigs = Some(sigs);
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_from_hash(hash: &str) -> RecordSource {
        RecordSource {
            r#in: None,
            hash: Some(hash.to_string()),
            hash_alg: vec![],
            json: true,
        }
    }

    fn source_from_in(path: &str) -> RecordSource {
        RecordSource {
            r#in: Some(path.to_string()),
            hash: None,
            hash_alg: vec![],
            json: true,
        }
    }

    /// Write a `sign prepare`-shaped JSON envelope carrying `record_hex` and the
    /// `hashed` marker, returning its path (so `assemble` can be fed the prepare
    /// step's own output through `--in`).
    fn write_prepare_envelope(
        dir: &tempfile::TempDir,
        name: &str,
        record_hex: &str,
        hashed: bool,
    ) -> String {
        let path = dir.path().join(name);
        let envelope = serde_json::json!({
            "sig_structure_hex": "00",
            "protected_header_hex": "00",
            "signer_pubkey_hex": "00".repeat(32),
            "record_cbor_hex": record_hex,
            "hashed": hashed,
        });
        std::fs::write(&path, envelope.to_string()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn record_prepare_assemble_round_trip() {
        let seed = [3u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let pubkey = signer.signer_pubkey();
        let digest = "11".repeat(32);

        // prepare → sign → assemble must reproduce what `sign record` does inline.
        let record = record_from_hash_spec(&digest, &[]).unwrap();
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let signature = signer.sign(&prepared.sig_structure_bytes).unwrap();
        let from_assemble = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();

        // The in-process `sign record` path signs the same structure.
        let inline_prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let inline_sig = signer.sign(&inline_prepared.sig_structure_bytes).unwrap();
        let inline = assemble_cose_sign1(&record, &pubkey, &inline_sig).unwrap();
        assert_eq!(from_assemble.cose_sign1_bytes, inline.cose_sign1_bytes);
    }

    #[test]
    fn signed_record_validates() {
        let seed = [5u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let pubkey = signer.signer_pubkey();
        let record = record_from_hash_spec(&"22".repeat(32), &[]).unwrap();
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let signature = signer.sign(&prepared.sig_structure_bytes).unwrap();
        let assembled = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();
        let mut signed = record;
        signed.sigs = Some(vec![assembled.sig_entry]);
        let cbor = encode_poe_record(&signed).unwrap();
        assert!(validate_poe_record(&cbor, &ValidatorOptions::default()).is_ok());
    }

    #[test]
    fn rejects_wrong_length_hash() {
        let err = record_from_hash_spec("deadbeef", &[]).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn record_hash_spec_builds_a_cohash_item() {
        // A comma-separated alg:digest spec co-hashes one item under both algs.
        let spec = format!(
            "sha2-256:{},blake2b-256:{}",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let record = record_from_hash_spec(&spec, &[]).unwrap();
        let hashes = &record.items.as_ref().unwrap()[0].hashes;
        assert_eq!(hashes.len(), 2);
        assert!(hashes
            .iter()
            .any(|(a, d)| a == "sha2-256" && d == &vec![0xab; 32]));
        assert!(hashes
            .iter()
            .any(|(a, d)| a == "blake2b-256" && d == &vec![0xcd; 32]));

        // A bare digest takes the single --hash-alg (here blake2b-256).
        let record = record_from_hash_spec(&"ef".repeat(32), &["blake2b-256".to_string()]).unwrap();
        let hashes = &record.items.as_ref().unwrap()[0].hashes;
        assert_eq!(hashes, &vec![("blake2b-256".to_string(), vec![0xef; 32])]);
    }

    #[test]
    fn assemble_rejects_short_signature() {
        let args = SignAssembleArgs {
            source: source_from_hash(&"33".repeat(32)),
            signer_pubkey: Some("00".repeat(32)),
            signature: Some("aa".repeat(10)),
            hashed: false,
        };
        assert_eq!(run_assemble(args).unwrap_err().code, 4);
    }

    #[test]
    fn off_host_round_trip_verifies_in_both_modes() {
        use cardanowall::cose::{cose_sign1_label309_verify, CoseVerifyResult};
        use cardanowall::poe_standard::encode_record_body_for_signing;

        let seed = [7u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let pubkey = signer.signer_pubkey();
        let record = record_from_hash_spec(&"44".repeat(32), &[]).unwrap();
        let body = encode_record_body_for_signing(&record).unwrap();

        // Non-hashed: prepare → sign → assemble → the record's signature
        // verifies. This is the pre-existing path, exercised end to end here.
        let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
        let plain_sig = signer.sign(&prepared.sig_structure_bytes).unwrap();
        let plain = assemble_signed_record(record.clone(), &pubkey, &plain_sig, false).unwrap();
        let plain_cose = &plain.sigs.as_ref().unwrap()[0].cose_sign1;
        assert!(matches!(
            cose_sign1_label309_verify(plain_cose, &body, Some(&pubkey)),
            CoseVerifyResult::Ok { .. }
        ));

        // Hashed: prepare --hashed → sign the hashed Sig_structure → assemble
        // --hashed. The verifier reconstructs Sig_structure[3] =
        // BLAKE2b-224(to_sign) from the unprotected "hashed": true header.
        let prepared_h = prepare_sig_structure_hashed(&record, &pubkey).unwrap();
        assert_eq!(prepared_h.to_sign_hash_bytes.len(), 28);
        let hashed_sig = signer.sign(&prepared_h.sig_structure_bytes).unwrap();
        let hashed = assemble_signed_record(record.clone(), &pubkey, &hashed_sig, true).unwrap();
        let hashed_cose = &hashed.sigs.as_ref().unwrap()[0].cose_sign1;
        assert!(matches!(
            cose_sign1_label309_verify(hashed_cose, &body, Some(&pubkey)),
            CoseVerifyResult::Ok { .. }
        ));

        // The modes are not interchangeable: a hashed signature assembled
        // without the header (and vice versa) reconstructs the wrong payload and
        // fails to verify — which is exactly why `assemble` gates on the marker.
        let hashed_sig_wrong =
            assemble_signed_record(record.clone(), &pubkey, &hashed_sig, false).unwrap();
        let wrong_cose = &hashed_sig_wrong.sigs.as_ref().unwrap()[0].cose_sign1;
        assert!(matches!(
            cose_sign1_label309_verify(wrong_cose, &body, Some(&pubkey)),
            CoseVerifyResult::Err(_)
        ));
        let plain_sig_wrong = assemble_signed_record(record, &pubkey, &plain_sig, true).unwrap();
        let wrong_cose2 = &plain_sig_wrong.sigs.as_ref().unwrap()[0].cose_sign1;
        assert!(matches!(
            cose_sign1_label309_verify(wrong_cose2, &body, Some(&pubkey)),
            CoseVerifyResult::Err(_)
        ));
    }

    #[test]
    fn assemble_rejects_hashed_flag_mode_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let record = record_from_hash_spec(&"55".repeat(32), &[]).unwrap();
        let record_hex = bytes_to_hex(&encode_poe_record(&record).unwrap());

        // prepare stamped hashed=true; assembling WITHOUT --hashed must fail (4)
        // rather than emit a signature no verifier can check.
        let hashed_env = write_prepare_envelope(&dir, "hashed.json", &record_hex, true);
        let args = SignAssembleArgs {
            source: source_from_in(&hashed_env),
            signer_pubkey: Some("00".repeat(32)),
            signature: Some("aa".repeat(64)),
            hashed: false,
        };
        assert_eq!(run_assemble(args).unwrap_err().code, 4);

        // prepare stamped hashed=false; assembling WITH --hashed must fail (4).
        let plain_env = write_prepare_envelope(&dir, "plain.json", &record_hex, false);
        let args = SignAssembleArgs {
            source: source_from_in(&plain_env),
            signer_pubkey: Some("00".repeat(32)),
            signature: Some("aa".repeat(64)),
            hashed: true,
        };
        assert_eq!(run_assemble(args).unwrap_err().code, 4);

        // Matching modes pass the gate and assemble (the fake signature is only
        // rejected later, by a verifier — assembly itself embeds it verbatim).
        let ok_env = write_prepare_envelope(&dir, "match.json", &record_hex, true);
        let args = SignAssembleArgs {
            source: source_from_in(&ok_env),
            signer_pubkey: Some("00".repeat(32)),
            signature: Some("aa".repeat(64)),
            hashed: true,
        };
        assert!(run_assemble(args).is_ok());
    }

    #[test]
    fn seed_source_debug_redacts_seed() {
        let source = SeedSource {
            seed: Some("ab".repeat(32)),
            seed_file: Some("/path/to/seed".to_string()),
            seed_stdin: false,
        };
        let rendered = format!("{source:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("/path/to/seed"));
    }
}
