//! `cardanowall merkle` — pure off-chain Merkle tooling. Performs ZERO chain or
//! storage interaction.
//!
//! - `merkle verify --root <hex32> [--leaf <hex32>] --proof <file>` — RFC 9162
//!   inclusion-proof verification. Proof JSON shape:
//!   `{ tree_alg, tree_size, index, leaf, proof[] }`. `--leaf` from the CLI
//!   overrides the file's leaf when both are present.
//! - `merkle build [--in <file> | --file <path>…] [--leaf-alg <name>] [--json]` —
//!   build the canonical leaves-list CBOR + root from leaf digests (one 64-hex
//!   leaf per line, from `--in` or stdin) OR from files to hash (`--file`,
//!   repeatable). Any leaf's inclusion proof verifies against the printed root.

use std::io::Read;

use cardanowall::hash::sha256;
use cardanowall::merkle::{
    encode_leaves_list, merkle_root, verify_inclusion, MerkleLeavesListError, MERKLE_ALG_ID,
};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::util::{bytes_to_hex, hex_to_bytes, CliError};

const DIGEST_BYTES: usize = 32;

/// Arguments for `cardanowall merkle`.
#[derive(Debug, Args)]
pub struct MerkleArgs {
    /// The Merkle verb to run.
    #[command(subcommand)]
    pub verb: MerkleVerb,
}

/// The two Merkle verbs.
#[derive(Debug, Subcommand)]
pub enum MerkleVerb {
    /// Verify an off-chain RFC 9162 inclusion proof against a supplied root.
    Verify(MerkleVerifyArgs),
    /// Build a canonical leaves-list + root from leaf digests or files (offline).
    Build(MerkleBuildArgs),
}

impl MerkleArgs {
    /// Whether the active verb was invoked with `--json`.
    #[must_use]
    pub fn json_mode(&self) -> bool {
        match &self.verb {
            MerkleVerb::Verify(a) => a.json,
            MerkleVerb::Build(a) => a.json,
        }
    }
}

/// Run the `merkle` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: MerkleArgs) -> Result<(), CliError> {
    match args.verb {
        MerkleVerb::Verify(a) => run_verify(a),
        MerkleVerb::Build(a) => run_build(a),
    }
}

// ===========================================================================
// merkle verify
// ===========================================================================

/// Arguments for `cardanowall merkle verify`.
#[derive(Debug, Args)]
pub struct MerkleVerifyArgs {
    /// 32-byte Merkle root hex (lowercase, no 0x prefix).
    #[arg(long)]
    pub root: String,
    /// 32-byte leaf hex (overrides leaf in --proof file).
    #[arg(long)]
    pub leaf: Option<String>,
    /// JSON file with tree_alg/tree_size/index/leaf/proof.
    #[arg(long)]
    pub proof: String,
    /// Emit machine-readable JSON outcome.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Deserialize)]
struct ProofFile {
    tree_alg: Option<String>,
    tree_size: Option<i64>,
    index: Option<i64>,
    leaf: Option<String>,
    proof: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct VerifyErr {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct VerifyOutcome {
    ok: bool,
    root_hex: String,
    leaf_hex: String,
    leaf_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<VerifyErr>,
}

fn ensure_hex32(hex: &str, label: &str) -> Result<Vec<u8>, CliError> {
    // Malformed hex is a CLI-input failure (exit 4), not an integrity verdict:
    // the value never reached the proof-reconstruction check. Exit 1 stays
    // reserved for a well-formed proof that does NOT verify. The forwarded hex
    // error is the sanitized internal decoder's — it reports length/offset only,
    // never the input value.
    let bytes = hex_to_bytes(hex)
        .map_err(|e| CliError::input(format!("merkle verify: {label} is not valid hex: {e}")))?;
    if bytes.len() != DIGEST_BYTES {
        return Err(CliError::input(format!(
            "merkle verify: {label} must decode to exactly {DIGEST_BYTES} bytes; got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn ensure_uint(n: Option<i64>, label: &str) -> Result<usize, CliError> {
    // A malformed integer is malformed input (exit 4), the same class as bad hex.
    match n {
        Some(v) if v >= 0 => Ok(v as usize),
        _ => Err(CliError::input(format!(
            "merkle verify: {label} must be a non-negative integer"
        ))),
    }
}

fn run_verify(args: MerkleVerifyArgs) -> Result<(), CliError> {
    let root_bytes = ensure_hex32(&args.root, "--root")?;

    // An unreadable proof file is an IO failure (network class, exit 2), the same
    // class used for every other unreadable file in the CLI — not an integrity
    // verdict on a record.
    let file_text = std::fs::read_to_string(&args.proof).map_err(|e| {
        CliError::network(format!(
            "merkle verify: cannot read --proof file {}: {e}",
            args.proof
        ))
    })?;
    // A proof file that is present but not valid JSON is malformed input (exit 4),
    // the same class as bad hex — the content never reached the inclusion check.
    // Exit 2 stays reserved for an unreadable file (an IO failure a CI retry may
    // legitimately treat as transient); unparseable bytes are not transient.
    let file: ProofFile = serde_json::from_str(&file_text).map_err(|e| {
        CliError::input(format!(
            "merkle verify: proof file {} is not valid JSON: {e}",
            args.proof
        ))
    })?;

    // Every schema check below fails BEFORE the inclusion check runs, so it is
    // malformed input (exit 4), never an integrity verdict — exit 1 stays
    // reserved for a well-formed proof that does not verify.
    if let Some(alg) = &file.tree_alg {
        if alg != MERKLE_ALG_ID {
            return Err(CliError::input(format!(
                "merkle verify: proof file {} carries tree_alg=\"{alg}\"; only \"{MERKLE_ALG_ID}\" is supported",
                args.proof
            )));
        }
    }

    let tree_size = ensure_uint(file.tree_size, "tree_size")?;
    let index = ensure_uint(file.index, "index")?;
    if index >= tree_size {
        return Err(CliError::input(format!(
            "merkle verify: index {index} must be < tree_size {tree_size}"
        )));
    }

    let leaf_hex_source = args
        .leaf
        .as_deref()
        .or(file.leaf.as_deref())
        .ok_or_else(|| {
            CliError::input(
                "merkle verify: --leaf is required when proof file has no \"leaf\" field",
            )
        })?
        .to_string();
    let leaf_bytes = ensure_hex32(&leaf_hex_source, "leaf")?;

    let proof_arr = file.proof.ok_or_else(|| {
        CliError::input(format!(
            "merkle verify: proof file {} must contain a \"proof\" array",
            args.proof
        ))
    })?;
    let mut proof_bytes: Vec<[u8; 32]> = Vec::with_capacity(proof_arr.len());
    for (i, v) in proof_arr.iter().enumerate() {
        let hex = v.as_str().ok_or_else(|| {
            CliError::input(format!("merkle verify: proof[{i}] must be a hex string"))
        })?;
        let b = ensure_hex32(hex, &format!("proof[{i}]"))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        proof_bytes.push(arr);
    }

    let ok = verify_inclusion(&leaf_bytes, index, tree_size, &proof_bytes, &root_bytes);

    let outcome = VerifyOutcome {
        ok,
        root_hex: args.root.to_lowercase(),
        leaf_hex: leaf_hex_source.to_lowercase(),
        leaf_index: index,
        error: if ok {
            None
        } else {
            Some(VerifyErr {
                code: "MERKLE_INCLUSION_FAILED".to_string(),
                message: "recomputed root does not match the supplied --root".to_string(),
            })
        },
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&outcome).expect("VerifyOutcome serialises")
        );
    } else if outcome.ok {
        println!(
            "ok: leaf at index {} verified against root {}",
            outcome.leaf_index, outcome.root_hex
        );
    } else {
        eprintln!(
            "failed: MERKLE_INCLUSION_FAILED: inclusion check did not match the supplied root"
        );
    }

    if ok {
        Ok(())
    } else {
        Err(CliError {
            code: 1,
            message: String::new(),
        })
    }
}

// ===========================================================================
// merkle build
// ===========================================================================

/// Arguments for `cardanowall merkle build`.
#[derive(Debug, Args)]
pub struct MerkleBuildArgs {
    /// leaf-digest file: one 64-hex sha2-256 leaf per line (omit ⇒ stdin).
    #[arg(long)]
    pub r#in: Option<String>,
    /// file to hash into a leaf (repeatable; mutually exclusive with --in/stdin).
    #[arg(long = "file")]
    pub files: Vec<String>,
    /// advisory leaf_alg recorded in the leaves-list (e.g. 'sha2-256').
    #[arg(long)]
    pub leaf_alg: Option<String>,
    /// Emit machine-readable JSON outcome.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct BuildOutcome {
    root: String,
    leaf_count: usize,
    leaves_list_cbor_hex: String,
    leaves: Vec<String>,
}

fn read_stdin_string() -> Result<String, CliError> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| CliError::network(format!("merkle build: cannot read stdin: {e}")))?;
    Ok(buf)
}

fn leaves_from_digest_lines(text: &str, src: &str) -> Result<Vec<[u8; 32]>, CliError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::input(format!(
                "merkle build: {src}: line {} is not a 64-hex sha2-256 leaf: \"{t}\"",
                i + 1
            )));
        }
        let bytes = hex_to_bytes(&t.to_lowercase())
            .map_err(|e| CliError::input(format!("merkle build: {src}: {e}")))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }
    if out.is_empty() {
        return Err(CliError::input(format!(
            "merkle build: {src} contains no leaves"
        )));
    }
    Ok(out)
}

fn leaves_from_files(paths: &[String]) -> Result<Vec<[u8; 32]>, CliError> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let content = std::fs::read(p)
            .map_err(|e| CliError::network(format!("merkle build: cannot read {p}: {e}")))?;
        out.push(sha256(&content));
    }
    Ok(out)
}

fn run_build(args: MerkleBuildArgs) -> Result<(), CliError> {
    let file_mode = !args.files.is_empty();
    let line_file_mode = args.r#in.is_some();
    if file_mode && line_file_mode {
        return Err(CliError::input(
            "merkle build: --file and --in are mutually exclusive",
        ));
    }

    let leaves: Vec<[u8; 32]> = if file_mode {
        leaves_from_files(&args.files)?
    } else {
        let text = match &args.r#in {
            Some(path) => std::fs::read_to_string(path).map_err(|e| {
                CliError::network(format!("merkle build: cannot read --in {path}: {e}"))
            })?,
            None => read_stdin_string()?,
        };
        let src = args.r#in.as_deref().unwrap_or("<stdin>");
        leaves_from_digest_lines(&text, src)?
    };

    let root = merkle_root(&leaves).map_err(|e| CliError::input(format!("merkle build: {e}")))?;
    let cbor = encode_leaves_list(&leaves, &root, args.leaf_alg.as_deref())
        .map_err(|e: MerkleLeavesListError| CliError::input(format!("merkle build: {e}")))?;

    let outcome = BuildOutcome {
        root: bytes_to_hex(&root),
        leaf_count: leaves.len(),
        leaves_list_cbor_hex: bytes_to_hex(&cbor),
        leaves: leaves.iter().map(|l| bytes_to_hex(l)).collect(),
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&outcome).expect("BuildOutcome serialises")
        );
    } else {
        println!("root:        {}", outcome.root);
        println!("leaf_count:  {}", outcome.leaf_count);
        println!("leaves_list: {}", outcome.leaves_list_cbor_hex);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardanowall::merkle::merkle_inclusion_proof;

    #[test]
    fn build_then_verify_round_trips() {
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| sha256(&[i])).collect();
        let root = merkle_root(&leaves).unwrap();
        let proof = merkle_inclusion_proof(&leaves, 2).unwrap();
        assert!(verify_inclusion(&leaves[2], 2, leaves.len(), &proof, &root));
    }

    #[test]
    fn rejects_bad_leaf_line() {
        let err = leaves_from_digest_lines("not-hex\n", "<test>").unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn empty_leaves_input_is_error() {
        let err = leaves_from_digest_lines("# comment only\n\n", "<test>").unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn malformed_hex_is_input_error_and_does_not_echo_value() {
        // Malformed --root/--leaf/proof hex is CLI-input class (exit 4), not an
        // integrity verdict, and the sanitized decoder never echoes the value.
        let planted = format!("{}zz", "ab".repeat(31)); // 64 chars, invalid bytes
        let err = ensure_hex32(&planted, "--root").unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&planted));
        assert!(!err.message.contains(&"ab".repeat(31)));

        // A wrong-length (but valid-hex) value is also input-class.
        let short = ensure_hex32("abcd", "--leaf").unwrap_err();
        assert_eq!(short.code, 4);
    }

    #[test]
    fn malformed_uint_is_input_error() {
        assert_eq!(ensure_uint(Some(-1), "index").unwrap_err().code, 4);
        assert_eq!(ensure_uint(None, "tree_size").unwrap_err().code, 4);
        assert_eq!(ensure_uint(Some(3), "index").unwrap(), 3);
    }

    #[test]
    fn unreadable_proof_file_is_network_error() {
        // An unreadable --proof file is the IO/network class (exit 2).
        let args = MerkleVerifyArgs {
            root: "ab".repeat(32),
            leaf: None,
            proof: "/nonexistent/merkle-proof-does-not-exist.json".to_string(),
            json: false,
        };
        let err = run_verify(args).unwrap_err();
        assert_eq!(err.code, 2);
    }

    #[test]
    fn invalid_json_proof_file_is_input_error() {
        // A present-but-unparseable proof file is malformed input (exit 4), not
        // the transient network class — a CI retry must not treat it as flaky.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.json");
        std::fs::write(&path, "this is not json").unwrap();
        let args = MerkleVerifyArgs {
            root: "ab".repeat(32),
            leaf: None,
            proof: path.to_string_lossy().into_owned(),
            json: false,
        };
        let err = run_verify(args).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn schema_invalid_proof_content_is_input_error() {
        // Content that parses as JSON but fails a schema check (here an
        // unsupported tree_alg) is malformed input (exit 4), aligned with bad
        // hex — never the integrity class, which is reserved for a well-formed
        // proof that does not verify.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "tree_alg": "not-a-real-alg",
                "tree_size": 2,
                "index": 0,
                "leaf": "ab".repeat(32),
                "proof": ["cd".repeat(32)],
            })
            .to_string(),
        )
        .unwrap();
        let args = MerkleVerifyArgs {
            root: "ab".repeat(32),
            leaf: None,
            proof: path.to_string_lossy().into_owned(),
            json: false,
        };
        assert_eq!(run_verify(args).unwrap_err().code, 4);

        // A structurally-present proof whose index is out of range is likewise
        // malformed input, not an integrity verdict.
        let oor = dir.path().join("oor.json");
        std::fs::write(
            &oor,
            serde_json::json!({
                "tree_size": 2,
                "index": 5,
                "leaf": "ab".repeat(32),
                "proof": ["cd".repeat(32)],
            })
            .to_string(),
        )
        .unwrap();
        let oor_args = MerkleVerifyArgs {
            root: "ab".repeat(32),
            leaf: None,
            proof: oor.to_string_lossy().into_owned(),
            json: false,
        };
        assert_eq!(run_verify(oor_args).unwrap_err().code, 4);
    }

    #[test]
    fn malformed_root_hex_via_run_verify_is_input_error() {
        // Even reached through run_verify, a bad --root is input-class (exit 4),
        // and it is checked before the (here absent) proof file is opened.
        let args = MerkleVerifyArgs {
            root: "not-valid-hex".to_string(),
            leaf: None,
            proof: "/unused.json".to_string(),
            json: false,
        };
        let err = run_verify(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains("not-valid-hex"));
    }
}
