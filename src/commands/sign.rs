//! `cardanowall sign` — offline PATH-1 (identity Ed25519) record signing.
//!
//! Three verbs, all offline (no chain / storage / API interaction):
//!
//! - `sign record`   — derive the signer from `--seed`, build/load the record,
//!   attach a path-1 `sigs[i]` in-process, emit the signed record.
//! - `sign prepare`  — detached step 1: emit the exact `Sig_structure` bytes an
//!   external Ed25519 signer (KMS / HSM / air-gapped) must sign, plus the signer
//!   pubkey + the record CBOR.
//! - `sign assemble` — detached step 2: take the external 64-byte signature and
//!   the record, emit the signed record. Never touches a seed.
//!
//! This surface is PATH-1 ONLY (identity Ed25519). The CIP-30 wallet path
//! (path-2) is owned elsewhere.
//!
//! Exit codes: `0` ok / `4` CLI input error (bad seed/hash/signature, structurally
//! invalid record) / `2` IO error (unreadable `--in` file).

use std::io::Read;

use cardanowall::client::{assemble_cose_sign1, prepare_sig_structure, OffHostSignError, Signer};
use cardanowall::poe_standard::{
    encode_poe_record, validate_poe_record, ItemEntry, PoeRecord, ValidateResult, ValidatorOptions,
};
use cardanowall::seed_derive::signer_from_seed;
use clap::{Args, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::secret::{resolve_secret_bytes, SecretEnv, SecretKind, SystemSecretEnv};
use crate::util::{bytes_to_hex, hex_to_bytes, is_all_hex, CliError};

const ED25519_PUBKEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SHA2_256_DIGEST_BYTES: usize = 32;

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
    /// build a minimal single-item hash-only record from a 32-byte digest.
    #[arg(long)]
    pub hash: Option<String>,
    /// hash alg for --hash: 'sha2-256' (default) or 'blake2b-256'.
    #[arg(long)]
    pub alg: Option<String>,
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
}

#[derive(Debug, Serialize)]
struct SignedRecordOutput {
    record_cbor_hex: String,
    sig_index: usize,
    signer_pubkey_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlg {
    Sha2_256,
    Blake2b256,
}

impl HashAlg {
    fn id(self) -> &'static str {
        match self {
            HashAlg::Sha2_256 => "sha2-256",
            HashAlg::Blake2b256 => "blake2b-256",
        }
    }
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

fn resolve_hash_alg(alg: Option<&str>) -> Result<HashAlg, CliError> {
    match alg.map(str::to_lowercase).as_deref().unwrap_or("sha2-256") {
        "sha2-256" => Ok(HashAlg::Sha2_256),
        "blake2b-256" => Ok(HashAlg::Blake2b256),
        other => Err(CliError::input(format!(
            "sign: --alg must be 'sha2-256' or 'blake2b-256' (got '{other}')"
        ))),
    }
}

/// Build a minimal single-item hash-only record from a 32-byte content digest.
fn record_from_hash(hash_hex: &str, alg: HashAlg) -> Result<PoeRecord, CliError> {
    let digest =
        hex_to_bytes(hash_hex).map_err(|e| CliError::input(format!("sign: --hash {e}")))?;
    if digest.len() != SHA2_256_DIGEST_BYTES {
        return Err(CliError::input(format!(
            "sign: --hash must decode to {SHA2_256_DIGEST_BYTES} bytes (got {})",
            digest.len()
        )));
    }
    Ok(PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(alg.id().to_string(), digest)],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    })
}

/// Decode bytes as a Label 309 record. An all-hex string is hex-decoded first;
/// otherwise the raw bytes are treated as CBOR. The structural validator both
/// verifies the wire shape AND returns the decoded record.
fn record_from_cbor_bytes(raw: &[u8], label: &str) -> Result<PoeRecord, CliError> {
    let as_text = String::from_utf8_lossy(raw);
    let trimmed = as_text.trim();
    let cbor: Vec<u8> = if is_all_hex(trimmed) {
        hex_to_bytes(trimmed).map_err(|e| CliError::input(format!("sign: {label} {e}")))?
    } else {
        raw.to_vec()
    };
    match validate_poe_record(&cbor, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => Ok(*record),
        ValidateResult::Fail { issues } => {
            let code = issues.first().map_or("UNKNOWN", |i| i.code.code());
            Err(CliError::input(format!(
                "sign: {label} is not a valid Label 309 record: {code}"
            )))
        }
    }
}

fn resolve_record(source: &RecordSource) -> Result<PoeRecord, CliError> {
    if source.hash.is_some() && source.r#in.is_some() {
        return Err(CliError::input(
            "sign: --hash and --in are mutually exclusive",
        ));
    }
    if let Some(hash) = &source.hash {
        return record_from_hash(hash.trim(), resolve_hash_alg(source.alg.as_deref())?);
    }
    if let Some(path) = &source.r#in {
        let raw = std::fs::read(path)
            .map_err(|e| CliError::network(format!("sign: cannot read --in {path}: {e}")))?;
        return record_from_cbor_bytes(&raw, &format!("--in {path}"));
    }
    let raw = read_stdin_bytes()?;
    if raw.is_empty() {
        return Err(CliError::input(
            "sign: no record source — pass --hash, --in <file>, or pipe to stdin",
        ));
    }
    record_from_cbor_bytes(&raw, "<stdin>")
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
    let record = resolve_record(&args.source)?;

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
    let record = resolve_record(&args.source)?;
    let prepared = prepare_sig_structure(&record, &signer_pubkey)
        .map_err(|e| map_off_host_err("prepare", e))?;
    let record_cbor = encode_poe_record(&record)
        .map_err(|e| CliError::input(format!("sign prepare: record encode failed: {e}")))?;
    // JSON only: the external signer + the assemble step consume these fields
    // programmatically, so a single machine-readable object is the right shape.
    let payload = serde_json::json!({
        "sig_structure_hex": bytes_to_hex(&prepared.sig_structure_bytes),
        "protected_header_hex": bytes_to_hex(&prepared.protected_header_bytes),
        "signer_pubkey_hex": bytes_to_hex(&signer_pubkey),
        "record_cbor_hex": bytes_to_hex(&record_cbor),
    });
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
    let record = resolve_record(&args.source)?;
    let assembled = assemble_cose_sign1(&record, &signer_pubkey, &signature)
        .map_err(|e| map_off_host_err("assemble", e))?;
    let mut signed = record;
    let mut sigs = signed.sigs.take().unwrap_or_default();
    sigs.push(assembled.sig_entry);
    signed.sigs = Some(sigs);
    emit_signed_record(&signed, &signer_pubkey, args.source.json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_from_hash(hash: &str) -> RecordSource {
        RecordSource {
            r#in: None,
            hash: Some(hash.to_string()),
            alg: None,
            json: true,
        }
    }

    #[test]
    fn record_prepare_assemble_round_trip() {
        let seed = [3u8; 32];
        let signer = signer_from_seed(&seed).unwrap();
        let pubkey = signer.signer_pubkey();
        let digest = "11".repeat(32);

        // prepare → sign → assemble must reproduce what `sign record` does inline.
        let record = record_from_hash(&digest, HashAlg::Sha2_256).unwrap();
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
        let record = record_from_hash(&"22".repeat(32), HashAlg::Sha2_256).unwrap();
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
        let err = record_from_hash("deadbeef", HashAlg::Sha2_256).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn assemble_rejects_short_signature() {
        let args = SignAssembleArgs {
            source: source_from_hash(&"33".repeat(32)),
            signer_pubkey: Some("00".repeat(32)),
            signature: Some("aa".repeat(10)),
        };
        assert_eq!(run_assemble(args).unwrap_err().code, 4);
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
