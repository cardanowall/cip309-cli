//! `cardanowall attest` — anchor a build, release, dataset, or commit range as
//! one Label 309 Proof of Existence. Built for CI pipelines, equally usable
//! from a local shell; it composes the existing building blocks (hashing,
//! Merkle commitment, publish, inclusion certificates) and introduces no new
//! crypto or wire format.
//!
//! ## Leaf sources (mutually exclusive, each repeatable within itself)
//!
//! - `--paths <glob>` — files mode. Literal paths and glob patterns; the
//!   selection is deduplicated and **byte-sorted by its normalized relative
//!   path** (stable across operating systems), each leaf is the streamed
//!   SHA-256 of the file bytes, and a deterministic `poe-manifest.json`
//!   companion is always written (`--manifest-out`). File bytes never leave
//!   the machine — only hashes (and, in full-tree mode, the bare leaves list)
//!   do.
//! - `--commits <range>` — git mode. Leaves are SHA-256 of the raw commit
//!   object bytes (`git cat-file commit`), ordered by
//!   `git rev-list --reverse <range>`.
//! - `--leaf <hex32>` — pass-through digests computed elsewhere (OCI image
//!   digests, external hashes), in argument order.
//!
//! One leaf total publishes a plain `items[]` record (the standard forbids a
//! one-leaf tree); two or more publish a `merkle[]` commitment. `--publish
//! full-tree` (default) uploads the canonical leaves-list to storage and binds
//! its `ar://` URI on-chain; `--publish root` keeps the leaves private and
//! publishes only `root`/`leaf_count`.
//!
//! `--uri <ar://|ipfs://>` attaches an already-pinned content-discovery mirror
//! to a **single-leaf** `items[]` record (repeatable, the direct analog of
//! `submit --uri`). It does not apply to a Merkle record (2+ leaves), which
//! binds its leaves-list URI via `--publish full-tree` instead.
//!
//! ## Determinism and re-runs
//!
//! The manifest and the Merkle root are pure functions of the selected file
//! bytes: two runs over identical trees produce byte-identical manifests and
//! the same root. In the default `--idempotency-key auto` mode no
//! Idempotency-Key header is sent — the gateway's key contract hashes the
//! whole request body, which carries a fresh `quote_id` every run, so any
//! fixed key would conflict on re-run. Safe re-runs come from the gateway's
//! dedup of byte-identical records instead: a CI retry never double-anchors
//! or double-debits, and the second run reports the first run's record
//! (`replayed`). An explicit `--idempotency-key` is forwarded verbatim under
//! the strict contract (same key ⇒ byte-identical body, else 409).
//!
//! ## Exit codes
//!
//! `0` anchored (target reached) · `1` gateway rejection, terminal publish
//! failure, or a quote above `--max-usd` (the price-cap refusal) · `2`
//! network / IO failure · `3` `--timeout` elapsed while waiting (the publish
//! continues server-side; the receipt and outputs are still written) · `4`
//! CLI input error.

use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use cardanowall::certificate::{
    build_inclusion_certificate, CertificateAnchor, CertificateMerkle, CertificateTarget,
};
use cardanowall::client::{
    Label309Client, Label309ClientConfig, PoeNamespace, PoeStatusSnapshot, PublishInput,
    PublishResponse, QuoteInput, QuoteResponse, ResumableSource, ResumableUploadInput, Signer,
};
use cardanowall::estimate::{MerkleShape, RecordShape};
use cardanowall::hash::sha256;
use cardanowall::merkle::{encode_leaves_list, merkle_root, MERKLE_ALG_ID};
use cardanowall::poe_standard::{ItemEntry, MerkleCommit, PoeRecord};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::commands::certificate::NetworkArg;
use crate::commands::publish_common::{
    arweave_uri_placeholder, cohash_content, content_upload_idempotency_key,
    encode_record_with_signer, enforce_max_usd, map_client_error, map_upload_error,
    parse_supersedes, refresh_quote_if_stale, resolve_content_hash_algs, resolve_optional_signer,
    resolve_required_gateway, validate_content_uris, wait_for_poe_target, ContentHashAlg,
    GatewayArgs, ItemHashesMap, WaitOutcome, WaitTargetArg, LEAVES_LIST_UPLOAD_ROLE,
};
use crate::secret::{SecretArgs, SystemSecretEnv};
use crate::util::rfc3339::rfc3339_to_epoch_seconds;
use crate::util::{bytes_to_hex, format_usd_micros, parse_usd_to_micros, CliError};

/// The manifest format literal.
const MANIFEST_FORMAT: &str = "label-309-poe-manifest-v1";
/// The receipt format literal.
const RECEIPT_FORMAT: &str = "label-309-attest-receipt-v1";
/// The storage backend the full-tree leaves-list uploads to.
const STORAGE_TARGET_ARWEAVE: &str = "arweave";

/// Arguments for `cardanowall attest`.
///
/// `seed` (the raw argv identity seed) and `api_key` (the bearer token) are
/// secret material, so `Debug` is hand-written to redact both.
#[derive(Args)]
pub struct AttestArgs {
    /// files mode: a literal path or glob pattern (repeatable). The selection
    /// is deduplicated and byte-sorted by normalized relative path; each leaf
    /// is the SHA-256 of the file bytes.
    #[arg(long = "paths", value_name = "GLOB", num_args = 1..)]
    pub paths: Vec<String>,
    /// git mode: a rev-list range (e.g. 'v1.0..v1.1' or 'HEAD'). Leaves are
    /// SHA-256 of the raw commit object bytes, oldest first.
    #[arg(long = "commits", value_name = "RANGE")]
    pub commits: Option<String>,
    /// pre-hashed mode: a 64-hex digest computed elsewhere (repeatable, kept
    /// in argument order).
    #[arg(long = "leaf", value_name = "HEX32", num_args = 1..)]
    pub leaves: Vec<String>,
    /// what a Merkle record publishes: 'full-tree' uploads the leaves-list and
    /// binds its ar:// URI on-chain; 'root' publishes only root/leaf_count.
    #[arg(long = "publish", value_enum, default_value_t = PublishModeArg::FullTree)]
    pub publish: PublishModeArg,
    /// append SHA-256(manifest bytes) as the final leaf, anchoring the
    /// name↔hash binding itself (files mode only).
    #[arg(long = "anchor-manifest")]
    pub anchor_manifest: bool,
    /// content-discovery URI to attach to a single-leaf items[] record: an
    /// already-pinned `ar://` / `ipfs://` mirror (repeatable). Applies only to
    /// a single-leaf record; a Merkle record (2+ leaves) binds its leaves-list
    /// URI via --publish full-tree.
    #[arg(long = "uri", value_name = "AR-OR-IPFS-URI")]
    pub uri: Vec<String>,
    /// content-hash algorithm for a single-leaf items[] record (repeatable:
    /// co-hash the lone --paths / --commits source under each, e.g. --hash-alg
    /// sha2-256 --hash-alg blake2b-256). A Merkle record (2+ leaves) commits
    /// sha2-256 leaves only. A single --leaf pass-through digest takes exactly
    /// one --hash-alg, which labels it. Default sha2-256.
    #[arg(long = "hash-alg", value_name = "ALG")]
    pub hash_alg: Vec<String>,
    /// where the deterministic manifest is written (files mode).
    #[arg(long = "manifest-out", default_value = "poe-manifest.json")]
    pub manifest_out: String,
    /// 32-byte identity seed for an optional record signature: 64-digit hex or
    /// L309-SEED-1... . Omit to publish unsigned. INSECURE on argv; prefer
    /// --seed-file / --seed-stdin / CARDANOWALL_SEED.
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
    /// target Label 309 gateway base URL incl. the version segment, e.g.
    /// `https://cardanowall.com/api/v1` (or env CARDANOWALL_BASE_URL, or the
    /// active gateway profile). Required.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// idempotency key. 'auto' (default) sends NO Idempotency-Key header —
    /// safe re-runs come from the gateway's dedup of byte-identical records
    /// instead (the gateway's key contract hashes the whole request body,
    /// which carries a fresh quote_id every run). Any other value is sent
    /// verbatim under that strict contract: reusing it requires a
    /// byte-identical request body, otherwise the publish is rejected (409).
    #[arg(
        long = "idempotency-key",
        default_value = "auto",
        value_name = "auto|KEY"
    )]
    pub idempotency_key: String,
    /// lifecycle state to wait for before exiting.
    #[arg(long = "wait", value_enum, default_value_t = WaitTargetArg::Confirmed)]
    pub wait: WaitTargetArg,
    /// wait deadline in seconds. On expiry the outputs are still written and
    /// the process exits 3 (pending) — the publish continues on the gateway.
    #[arg(long = "timeout", default_value_t = 600, value_name = "SECONDS")]
    pub timeout: u64,
    /// refuse to publish when the quoted price exceeds this USD amount
    /// (e.g. '1.50'). The refusal exits 1 before any upload or publish.
    #[arg(long = "max-usd", value_name = "USD")]
    pub max_usd: Option<String>,
    /// mark this record as superseding an earlier one: the 64-hex Cardano
    /// transaction hash of the record being replaced.
    #[arg(long = "supersedes", value_name = "TX64")]
    pub supersedes: Option<String>,
    /// write a versioned JSON receipt (record, quote, tx, wait snapshot) here.
    #[arg(long = "receipt-out", value_name = "PATH")]
    pub receipt_out: Option<String>,
    /// write one inclusion certificate per leaf into this directory
    /// (Merkle records; requires --wait confirmed).
    #[arg(long = "certificates-dir", value_name = "DIR")]
    pub certificates_dir: Option<String>,
    /// Cardano network recorded in the certificates' anchor and explorer URLs.
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    pub network: NetworkArg,
    /// emit a machine-readable JSON summary on stdout.
    #[arg(long)]
    pub json: bool,
}

impl std::fmt::Debug for AttestArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestArgs")
            .field("paths", &self.paths)
            .field("commits", &self.commits)
            .field("leaves", &self.leaves)
            .field("publish", &self.publish)
            .field("anchor_manifest", &self.anchor_manifest)
            .field("uri", &self.uri)
            .field("hash_alg", &self.hash_alg)
            .field("manifest_out", &self.manifest_out)
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("base_url", &self.base_url)
            .field("gateway_profile", &self.gateway_profile)
            .field("idempotency_key", &self.idempotency_key)
            .field("wait", &self.wait)
            .field("timeout", &self.timeout)
            .field("max_usd", &self.max_usd)
            .field("supersedes", &self.supersedes)
            .field("receipt_out", &self.receipt_out)
            .field("certificates_dir", &self.certificates_dir)
            .field("network", &self.network)
            .field("json", &self.json)
            .finish()
    }
}

/// The `--publish` value surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PublishModeArg {
    /// Upload the canonical leaves-list and bind its `ar://` URI on-chain.
    FullTree,
    /// Publish only `root`/`leaf_count`; the leaf set stays private.
    Root,
}

impl PublishModeArg {
    fn as_str(self) -> &'static str {
        match self {
            PublishModeArg::FullTree => "full-tree",
            PublishModeArg::Root => "root",
        }
    }
}

/// The selected leaf source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafSource {
    Paths,
    Commits,
    Leaves,
}

impl LeafSource {
    fn as_str(self) -> &'static str {
        match self {
            LeafSource::Paths => "paths",
            LeafSource::Commits => "commits",
            LeafSource::Leaves => "leaves",
        }
    }
}

impl AttestArgs {
    fn seed_secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }
}

// ---------------------------------------------------------------------------
// Leaf collection
// ---------------------------------------------------------------------------

/// One manifest row: the normalized relative path, byte size, and content hash
/// of a selected file. Field order is the serialization order — it must stay
/// stable, the manifest is a deterministic public artifact.
#[derive(Debug, Clone, Serialize)]
struct ManifestFile {
    path: String,
    size: u64,
    sha2_256: String,
}

/// The manifest document: byte-sorted rows, no timestamps, so two runs over
/// identical files produce byte-identical manifests.
#[derive(Debug, Serialize)]
struct ManifestV1 {
    format: &'static str,
    files: Vec<ManifestFile>,
}

/// The written-manifest facts recorded in the receipt.
#[derive(Debug, Clone, Serialize)]
struct ManifestOutput {
    path: String,
    sha2_256: String,
    anchored: bool,
}

/// One commit leaf, recorded in the receipt so the anchored digests stay
/// attributable to their commits.
#[derive(Debug, Clone, Serialize)]
struct ReceiptCommit {
    commit: String,
    sha2_256: String,
}

/// The resolved leaf set an attest publishes.
#[derive(Debug)]
struct LeafCollection {
    source: LeafSource,
    /// The leaf digests, in publish order.
    leaves: Vec<[u8; 32]>,
    /// Per-leaf labels (file path / commit sha), recorded in certificates.
    labels: Vec<Option<String>>,
    /// The advisory leaves-list `leaf_alg`: the paths/commits leaves are
    /// genuinely SHA-256 of known bytes; `--leaf` pass-through digests carry
    /// no claim about how they were computed.
    leaf_alg: Option<&'static str>,
    /// The written manifest (files mode only).
    manifest: Option<ManifestOutput>,
    /// The commit shas (git mode only).
    commits: Option<Vec<ReceiptCommit>>,
    /// The lone `--paths` file, retained when the selection is a single file
    /// that stays a single-leaf `items[]` record (no `--anchor-manifest`), so a
    /// `--hash-alg` co-hash can re-hash its bytes without loading them during
    /// collection.
    single_source_path: Option<PathBuf>,
    /// The lone `--commits` commit object bytes, retained when a single commit
    /// is selected, so a `--hash-alg` co-hash can hash them for the item.
    single_source_bytes: Option<Vec<u8>>,
}

/// Pick the leaf source: exactly one of `--paths` / `--commits` / `--leaf`.
fn choose_source(args: &AttestArgs) -> Result<LeafSource, CliError> {
    let mut sources = Vec::new();
    if !args.paths.is_empty() {
        sources.push(LeafSource::Paths);
    }
    if args.commits.is_some() {
        sources.push(LeafSource::Commits);
    }
    if !args.leaves.is_empty() {
        sources.push(LeafSource::Leaves);
    }
    match sources.len() {
        0 => Err(CliError::input(
            "attest: exactly one of --paths / --commits / --leaf is required",
        )),
        1 => Ok(sources[0]),
        _ => Err(CliError::input(format!(
            "attest: --paths / --commits / --leaf are mutually exclusive (got: {})",
            sources
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Whether a `--paths` value is a glob pattern rather than a literal path.
fn contains_glob_meta(pattern: &str) -> bool {
    pattern.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

/// The hard refusal for a path the manifest cannot represent. Named after the
/// offending path so the operator can find and rename it; `{:?}` renders the
/// invalid bytes as escapes instead of a lossy replacement character.
fn non_utf8_path_error(path: &Path) -> CliError {
    CliError::input(format!(
        "attest: path {path:?} is not valid UTF-8 — the manifest and the leaf ordering are a \
         UTF-8 contract, and glob patterns cannot even be tested against such a name; rename \
         the file or exclude its directory from --paths"
    ))
}

/// Normalize a matched path for the manifest: relative to `cwd` when it lies
/// under it, forward slashes on every OS, no `./` prefix. The normalized form
/// is the dedup key and the byte-sort key, so identical trees produce
/// identical manifests regardless of platform or match order.
///
/// A non-UTF-8 component is a hard error, never a lossy projection: two names
/// differing only in invalid bytes would collapse to the same
/// replacement-character string, and one file would silently vanish from the
/// leaf set — the one failure mode a proof tool must never have.
fn normalize_rel_path(path: &Path, cwd: Option<&Path>) -> Result<String, CliError> {
    let relative = cwd.and_then(|c| path.strip_prefix(c).ok()).unwrap_or(path);
    let mut out = String::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::RootDir => out.push('/'),
            Component::Prefix(prefix) => {
                let Some(text) = prefix.as_os_str().to_str() else {
                    return Err(non_utf8_path_error(path));
                };
                out.push_str(text);
            }
            Component::ParentDir => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str("..");
            }
            Component::Normal(part) => {
                let Some(text) = part.to_str() else {
                    return Err(non_utf8_path_error(path));
                };
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(text);
            }
        }
    }
    Ok(out)
}

/// The static (metacharacter-free) directory prefix of a glob pattern — the
/// subtree the pattern can possibly reach. `dist/**/*` → `dist`; `*.bin` and
/// `di*/x.bin` → `.` (the whole working tree).
fn glob_static_prefix(pattern: &str) -> PathBuf {
    let mut prefix = PathBuf::new();
    for component in Path::new(pattern).components() {
        // The pattern arrived as a `String`, so the component is UTF-8.
        if contains_glob_meta(&component.as_os_str().to_string_lossy()) {
            break;
        }
        prefix.push(component.as_os_str());
    }
    if prefix.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        prefix
    }
}

/// Refuse to expand a glob over a subtree that contains a non-UTF-8 entry
/// name. The glob engine skips such names silently (it cannot match what it
/// cannot decode), which would drop a file from the leaf set without a trace;
/// their presence anywhere the pattern could reach is a hard input error
/// instead. Directory symlinks are not followed, so the scan terminates.
fn refuse_non_utf8_under(dir: &Path) -> Result<(), CliError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        // A prefix that does not exist or cannot be listed matches nothing;
        // the glob expansion itself surfaces the error or the empty selection.
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| {
            CliError::network(format!("attest: cannot scan {}: {e}", dir.display()))
        })?;
        let path = entry.path();
        if entry.file_name().to_str().is_none() {
            return Err(non_utf8_path_error(&path));
        }
        let file_type = entry.file_type().map_err(|e| {
            CliError::network(format!("attest: cannot scan {}: {e}", path.display()))
        })?;
        if file_type.is_dir() {
            refuse_non_utf8_under(&path)?;
        }
    }
    Ok(())
}

/// Expand `--paths` values (literals + globs) into a deduplicated selection,
/// byte-sorted by normalized relative path. Every key in the selection is a
/// validated-UTF-8 normalization (never a lossy projection), so two distinct
/// files can never collapse onto one entry.
fn expand_paths(patterns: &[String]) -> Result<Vec<(String, PathBuf)>, CliError> {
    let cwd = std::env::current_dir().ok();
    let mut selected: BTreeMap<String, PathBuf> = BTreeMap::new();
    for pattern in patterns {
        if contains_glob_meta(pattern) {
            refuse_non_utf8_under(&glob_static_prefix(pattern))?;
            let matches = glob::glob(pattern).map_err(|e| {
                CliError::input(format!("attest: --paths pattern \"{pattern}\": {e}"))
            })?;
            for entry in matches {
                let path = entry.map_err(|e| {
                    CliError::network(format!("attest: --paths \"{pattern}\": {e}"))
                })?;
                if path.is_file() {
                    selected.insert(normalize_rel_path(&path, cwd.as_deref())?, path);
                }
            }
        } else {
            let path = PathBuf::from(pattern);
            if path.is_dir() {
                return Err(CliError::input(format!(
                    "attest: --paths \"{pattern}\" is a directory — use a glob such as \
                     \"{pattern}/**/*\" to select the files inside it"
                )));
            }
            if !path.is_file() {
                return Err(CliError::input(format!(
                    "attest: --paths \"{pattern}\": no such file"
                )));
            }
            selected.insert(normalize_rel_path(&path, cwd.as_deref())?, path);
        }
    }
    Ok(selected.into_iter().collect())
}

/// Stream-hash a file (never loading it wholesale), returning the SHA-256 and
/// the byte count actually hashed.
fn sha256_stream_file(path: &Path) -> Result<([u8; 32], u64), CliError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| CliError::network(format!("attest: cannot read {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            CliError::network(format!("attest: cannot read {}: {e}", path.display()))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Serialize the manifest to its canonical bytes (2-space-indented JSON + one
/// trailing newline). Determinism contract: same rows in, same bytes out.
fn render_manifest(files: &[ManifestFile]) -> Vec<u8> {
    let manifest = ManifestV1 {
        format: MANIFEST_FORMAT,
        files: files.to_vec(),
    };
    let json = serde_json::to_string_pretty(&manifest).expect("manifest serialises");
    format!("{json}\n").into_bytes()
}

/// Collect the files-mode leaves: expand, hash, write the manifest, and
/// (optionally) append the manifest hash as the final leaf.
fn collect_path_leaves(args: &AttestArgs) -> Result<LeafCollection, CliError> {
    let selected = expand_paths(&args.paths)?;
    if selected.is_empty() {
        return Err(CliError::input(
            "attest: --paths matched no files; nothing to anchor",
        ));
    }
    let mut files = Vec::with_capacity(selected.len());
    let mut leaves = Vec::with_capacity(selected.len() + 1);
    let mut labels = Vec::with_capacity(selected.len() + 1);
    for (normalized, path) in &selected {
        let (digest, size) = sha256_stream_file(path)?;
        files.push(ManifestFile {
            path: normalized.clone(),
            size,
            sha2_256: bytes_to_hex(&digest),
        });
        leaves.push(digest);
        labels.push(Some(normalized.clone()));
    }

    let manifest_bytes = render_manifest(&files);
    let manifest_sha = sha256(&manifest_bytes);
    std::fs::write(&args.manifest_out, &manifest_bytes).map_err(|e| {
        CliError::network(format!(
            "attest: cannot write --manifest-out {}: {e}",
            args.manifest_out
        ))
    })?;

    if args.anchor_manifest {
        leaves.push(manifest_sha);
        labels.push(Some(args.manifest_out.clone()));
    }

    // A single file with no anchored manifest stays a one-leaf items[] record,
    // so retain its path for a possible `--hash-alg` co-hash of the item.
    let single_source_path =
        (selected.len() == 1 && !args.anchor_manifest).then(|| selected[0].1.clone());

    Ok(LeafCollection {
        source: LeafSource::Paths,
        leaves,
        labels,
        leaf_alg: Some("sha2-256"),
        manifest: Some(ManifestOutput {
            path: args.manifest_out.clone(),
            sha2_256: bytes_to_hex(&manifest_sha),
            anchored: args.anchor_manifest,
        }),
        commits: None,
        single_source_path,
        single_source_bytes: None,
    })
}

/// Collect the git-mode leaves: `git rev-list --reverse <range>` for the
/// order, then SHA-256 over each raw commit object's bytes via
/// `git cat-file --batch`.
fn collect_commit_leaves(range: &str) -> Result<LeafCollection, CliError> {
    let rev_list = Command::new("git")
        .args(["rev-list", "--reverse", range])
        .output()
        .map_err(|e| {
            CliError::input(format!(
                "attest: --commits requires git, which could not be run: {e}"
            ))
        })?;
    if !rev_list.status.success() {
        let stderr = String::from_utf8_lossy(&rev_list.stderr);
        return Err(CliError::input(format!(
            "attest: git rev-list --reverse {range} failed: {}",
            stderr.trim()
        )));
    }
    let shas: Vec<String> = String::from_utf8_lossy(&rev_list.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if shas.is_empty() {
        return Err(CliError::input(format!(
            "attest: --commits {range} selects no commits"
        )));
    }

    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            CliError::input(format!(
                "attest: --commits requires git, which could not be run: {e}"
            ))
        })?;
    // Feed the object list from a separate thread so a long list cannot
    // deadlock against git's output filling the stdout pipe.
    let mut stdin = child.stdin.take().expect("cat-file stdin is piped");
    let request: String = shas.iter().map(|sha| format!("{sha}\n")).collect();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(request.as_bytes());
    });

    let read_err =
        |e: std::io::Error| CliError::network(format!("attest: reading git cat-file: {e}"));
    let stdout = child.stdout.take().expect("cat-file stdout is piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut leaves = Vec::with_capacity(shas.len());
    let mut labels = Vec::with_capacity(shas.len());
    let mut commits = Vec::with_capacity(shas.len());
    // A single commit stays a one-leaf items[] record; retain its object bytes
    // for a possible `--hash-alg` co-hash of the item.
    let mut single_source_bytes: Option<Vec<u8>> = None;
    for sha in &shas {
        let mut header = String::new();
        reader.read_line(&mut header).map_err(read_err)?;
        let fields: Vec<&str> = header.split_whitespace().collect();
        let (object_type, size) = match fields.as_slice() {
            [_, object_type, size] => (*object_type, *size),
            _ => {
                return Err(CliError::input(format!(
                    "attest: git object {sha} could not be read (git said: \"{}\")",
                    header.trim_end()
                )));
            }
        };
        if object_type != "commit" {
            return Err(CliError::input(format!(
                "attest: git object {sha} is a {object_type}, not a commit"
            )));
        }
        let size: usize = size.parse().map_err(|_| {
            CliError::network(format!(
                "attest: git cat-file reported a malformed size for {sha}"
            ))
        })?;
        let mut payload = vec![0u8; size];
        reader.read_exact(&mut payload).map_err(read_err)?;
        let mut trailing = [0u8; 1];
        reader.read_exact(&mut trailing).map_err(read_err)?;

        let digest = sha256(&payload);
        if shas.len() == 1 {
            single_source_bytes = Some(payload);
        }
        leaves.push(digest);
        labels.push(Some(sha.clone()));
        commits.push(ReceiptCommit {
            commit: sha.clone(),
            sha2_256: bytes_to_hex(&digest),
        });
    }
    let _ = writer.join();
    let _ = child.wait();

    Ok(LeafCollection {
        source: LeafSource::Commits,
        leaves,
        labels,
        leaf_alg: Some("sha2-256"),
        manifest: None,
        commits: Some(commits),
        single_source_path: None,
        single_source_bytes,
    })
}

/// Collect the pass-through `--leaf` digests, in argument order.
fn collect_literal_leaves(values: &[String]) -> Result<LeafCollection, CliError> {
    let mut leaves = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim().to_lowercase();
        if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::input(
                "attest: every --leaf must be a 64-hex 32-byte digest",
            ));
        }
        let bytes = crate::util::hex_to_bytes(&trimmed)
            .map_err(|e| CliError::input(format!("attest: --leaf {e}")))?;
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&bytes);
        leaves.push(leaf);
    }
    let labels = vec![None; leaves.len()];
    Ok(LeafCollection {
        source: LeafSource::Leaves,
        leaves,
        labels,
        leaf_alg: None,
        manifest: None,
        commits: None,
        single_source_path: None,
        single_source_bytes: None,
    })
}

// ---------------------------------------------------------------------------
// Publish
// ---------------------------------------------------------------------------

/// Everything the publish phase produced, feeding the receipt and the outcome.
struct PublishedRecord {
    record_bytes: Vec<u8>,
    quote: QuoteResponse,
    /// The Idempotency-Key that was sent, when one was (explicit mode only).
    idempotency_key: Option<String>,
    response: PublishResponse,
    /// The Merkle root, for a `merkle[]` record.
    root: Option<[u8; 32]>,
    /// The leaves-list `ar://` URI, in full-tree mode.
    ar_uri: Option<String>,
    /// The single-leaf `items[0]` record's published `hashes` (alg-id →
    /// digest), retained so the receipt and stdout report each digest under
    /// the algorithm that produced it. `None` for a Merkle record, which
    /// carries no `items[]`.
    item_hashes: Option<Vec<(String, Vec<u8>)>>,
}

/// Resolve the Idempotency-Key to send, if any.
///
/// `auto` (the default) sends NO header: the gateway's Idempotency-Key
/// contract hashes the ENTIRE request body, and every attest run consumes a
/// fresh `quote_id`, so any fixed key would collide with a different body on
/// re-run (409). Safe re-runs come from the gateway's dedup of byte-identical
/// record bytes instead, which delivers exactly the wanted semantics: same
/// record → same tx, no second debit. An explicit key is forwarded verbatim
/// under the strict contract.
fn resolve_idempotency_key(choice: &str) -> Option<String> {
    if choice == "auto" {
        None
    } else {
        Some(choice.to_string())
    }
}

/// Resolve the `--uri` content-discovery mirrors for the record shape the
/// collected leaves imply.
///
/// A single-leaf `items[]` record (the direct analog of `submit`) carries them,
/// validated against the SAME fetch-set grammar the canonical record validator
/// enforces (an absolute `ar://` / `ipfs://` URI, no fragment) — so the CLI's
/// early check and the on-record check can never diverge. An empty list yields
/// `None` (no `uris` field). A Merkle record (2+ leaves) binds its leaves-list
/// URI via `--publish full-tree`, so any `--uri` is a hard input error there.
fn resolve_item_uris(uris: &[String], leaf_count: usize) -> Result<Option<Vec<String>>, CliError> {
    if leaf_count == 1 {
        validate_content_uris(uris, "attest")?;
        Ok((!uris.is_empty()).then(|| uris.to_vec()))
    } else if uris.is_empty() {
        Ok(None)
    } else {
        Err(CliError::input(
            "attest: --uri applies only to a single-leaf attest record; a Merkle record binds \
             its leaves-list URI via --publish full-tree",
        ))
    }
}

/// The item `hashes` for a single-leaf `items[]` record, resolved from the
/// selected `--hash-alg` set.
///
/// A `--leaf` pass-through digest is the output of exactly one algorithm and
/// carries no source bytes to re-hash, so it takes exactly one `--hash-alg`
/// (which labels it — fixing a latent mislabel of a non-sha2-256 pass-through
/// digest). A `--paths` / `--commits` single source co-hashes its bytes under
/// every algorithm; the common `sha2-256`-only case reuses the primary leaf
/// (already streamed at collection time) rather than re-reading.
fn single_leaf_item_hashes(
    collection: &LeafCollection,
    hash_algs: &[ContentHashAlg],
) -> Result<Vec<(String, Vec<u8>)>, CliError> {
    let leaf = &collection.leaves[0];
    let sha2_only = hash_algs == [ContentHashAlg::Sha2_256];
    match collection.source {
        LeafSource::Leaves => {
            if hash_algs.len() != 1 {
                return Err(CliError::input(
                    "attest: a single --leaf pass-through digest is one algorithm's output; pass \
                     exactly one --hash-alg to label it",
                ));
            }
            Ok(vec![(hash_algs[0].as_str().to_string(), leaf.to_vec())])
        }
        LeafSource::Paths => {
            if sha2_only {
                return Ok(vec![("sha2-256".to_string(), leaf.to_vec())]);
            }
            let path = collection
                .single_source_path
                .as_ref()
                .expect("a single-file paths collection retains its source path");
            // Only the co-hash case re-reads the file (the single-leaf shape is
            // one file); the default sha2-256 path above never loads it.
            let content = std::fs::read(path).map_err(|e| {
                CliError::network(format!(
                    "attest: cannot read {} to co-hash: {e}",
                    path.display()
                ))
            })?;
            Ok(cohash_content(&content, hash_algs))
        }
        LeafSource::Commits => {
            if sha2_only {
                return Ok(vec![("sha2-256".to_string(), leaf.to_vec())]);
            }
            let bytes = collection
                .single_source_bytes
                .as_ref()
                .expect("a single-commit collection retains its object bytes");
            Ok(cohash_content(bytes, hash_algs))
        }
    }
}

/// Publish the one-leaf shape: a plain `items[]` record carrying the item's
/// hashes (one or more co-hash entries) plus any `--uri` content-discovery
/// mirrors. The record is built and signed FIRST, so the quote prices its exact
/// canonical length.
fn publish_single_item(
    poe: &PoeNamespace<'_>,
    item_hashes: Vec<(String, Vec<u8>)>,
    uris: Option<Vec<String>>,
    signer: Option<&dyn Signer>,
    args: &AttestArgs,
    max_usd_micros: Option<i128>,
    supersedes: Option<&[u8]>,
) -> Result<PublishedRecord, CliError> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: item_hashes.clone(),
            uris,
            enc: None,
        }]),
        supersedes: supersedes.map(<[u8]>::to_vec),
        ..PoeRecord::default()
    };
    let record_bytes = encode_record_with_signer(&record, signer, "attest")?;
    let quote = poe
        .quote(&QuoteInput {
            record_bytes: record_bytes.len() as u64,
            recipient_count: 0,
            file_bytes_total: 0,
        })
        .map_err(|e| map_client_error("attest", e))?;
    enforce_max_usd("attest", max_usd_micros, &quote)?;
    let idempotency_key = resolve_idempotency_key(&args.idempotency_key);
    let response = poe
        .publish(&PublishInput {
            record: record_bytes.clone(),
            quote_id: quote.quote_id.clone(),
            signatures: None,
            idempotency_key: idempotency_key.clone(),
        })
        .map_err(|e| map_client_error("attest", e))?;
    Ok(PublishedRecord {
        record_bytes,
        quote,
        idempotency_key,
        response,
        root: None,
        ar_uri: None,
        item_hashes: Some(item_hashes),
    })
}

/// Publish the Merkle shape (two or more leaves).
///
/// Full-tree: the final `ar://` URI exists only after the upload, so the quote
/// is priced from the exact-width upper-bound estimate (with the fixed-width
/// Arweave URI placeholder) — guaranteed `≥` the published record, which is
/// what the gateway requires. Root mode has no upload, so the record is final
/// before the quote and is priced exactly.
fn publish_merkle_batch(
    poe: &PoeNamespace<'_>,
    collection: &LeafCollection,
    signer: Option<&dyn Signer>,
    args: &AttestArgs,
    max_usd_micros: Option<i128>,
    supersedes: Option<&[u8]>,
) -> Result<PublishedRecord, CliError> {
    let root =
        merkle_root(&collection.leaves).map_err(|e| CliError::input(format!("attest: {e}")))?;
    let leaf_count = collection.leaves.len() as u64;

    let build_record = |uris: Option<Vec<String>>| PoeRecord {
        v: 1,
        merkle: Some(vec![MerkleCommit {
            alg: MERKLE_ALG_ID.to_string(),
            root: root.to_vec(),
            leaf_count,
            uris,
        }]),
        supersedes: supersedes.map(<[u8]>::to_vec),
        ..PoeRecord::default()
    };

    let (record_bytes, quote, ar_uri) = match args.publish {
        PublishModeArg::FullTree => {
            let leaves_list = encode_leaves_list(&collection.leaves, &root, collection.leaf_alg)
                .map_err(|e| CliError::input(format!("attest: {e}")))?;
            let shape = RecordShape {
                items: vec![],
                signed: signer.is_some(),
                supersedes: supersedes.is_some(),
                merkle: Some(MerkleShape {
                    alg: MERKLE_ALG_ID.to_string(),
                    uris: vec![arweave_uri_placeholder()],
                }),
            };
            let quote_input = QuoteInput {
                record_bytes: shape.estimate_record_bytes(),
                recipient_count: 0,
                file_bytes_total: leaves_list.len() as u64,
            };
            let quote = poe
                .quote(&quote_input)
                .map_err(|e| map_client_error("attest", e))?;
            enforce_max_usd("attest", max_usd_micros, &quote)?;
            let upload_key = content_upload_idempotency_key(LEAVES_LIST_UPLOAD_ROLE, &leaves_list);
            let upload = poe
                .upload_resumable(&ResumableUploadInput {
                    target: STORAGE_TARGET_ARWEAVE.to_string(),
                    source: ResumableSource::Bytes(leaves_list),
                    content_type: Some("application/octet-stream".to_string()),
                    idempotency_key: Some(upload_key),
                    ..ResumableUploadInput::default()
                })
                .map_err(|e| map_upload_error("attest", e))?;
            let record = build_record(Some(vec![upload.uri.clone()]));
            let record_bytes = encode_record_with_signer(&record, signer, "attest")?;
            // A large upload can outlive the quote's TTL; publish only against
            // a live price lock, re-checking --max-usd against the new price.
            let quote = refresh_quote_if_stale(poe, quote, &quote_input, max_usd_micros, "attest")?;
            (record_bytes, quote, Some(upload.uri))
        }
        PublishModeArg::Root => {
            let record = build_record(None);
            let record_bytes = encode_record_with_signer(&record, signer, "attest")?;
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: record_bytes.len() as u64,
                    recipient_count: 0,
                    file_bytes_total: 0,
                })
                .map_err(|e| map_client_error("attest", e))?;
            enforce_max_usd("attest", max_usd_micros, &quote)?;
            (record_bytes, quote, None)
        }
    };

    let idempotency_key = resolve_idempotency_key(&args.idempotency_key);
    let response = poe
        .publish(&PublishInput {
            record: record_bytes.clone(),
            quote_id: quote.quote_id.clone(),
            signatures: None,
            idempotency_key: idempotency_key.clone(),
        })
        .map_err(|e| map_client_error("attest", e))?;
    Ok(PublishedRecord {
        record_bytes,
        quote,
        idempotency_key,
        response,
        root: Some(root),
        ar_uri,
        item_hashes: None,
    })
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// Build one inclusion certificate per leaf into `dir` (named
/// `<index>.certificate.json`, index = leaf position), anchored on the
/// confirmed snapshot. Each file is a complete, standalone certificate that
/// `certificate verify` re-verifies offline.
fn write_certificates(
    dir: &str,
    collection: &LeafCollection,
    root: [u8; 32],
    ar_uri: Option<&String>,
    snapshot: &PoeStatusSnapshot,
    network: NetworkArg,
) -> Result<usize, CliError> {
    let tx_hash = snapshot.tx_hash.as_deref().ok_or_else(|| {
        CliError::network(
            "attest: the confirmed snapshot carries no tx_hash; cannot build certificates",
        )
    })?;
    let block_time_iso = snapshot.block_time.as_deref().ok_or_else(|| {
        CliError::network(
            "attest: the confirmed snapshot carries no block_time; cannot build certificates",
        )
    })?;
    let block_time = rfc3339_to_epoch_seconds(block_time_iso).map_err(|e| {
        CliError::network(format!(
            "attest: cannot parse the snapshot block_time \"{block_time_iso}\": {e}"
        ))
    })?;

    let anchor = CertificateAnchor {
        chain: "cardano".to_string(),
        network: network.name().to_string(),
        tx_hash: tx_hash.to_string(),
        metadata_label: 309,
        block_time,
        block_height: snapshot.block_height.and_then(|h| i64::try_from(h).ok()),
        slot: None,
        confirmations_at_generation: i64::try_from(snapshot.num_confirmations).ok(),
        explorer_urls: Some(network.explorer_urls(tx_hash)),
    };
    let merkle = CertificateMerkle {
        tree_alg: MERKLE_ALG_ID.to_string(),
        root,
        tree_size: collection.leaves.len(),
        leaves_list_uri: ar_uri.cloned(),
        leaves_list_url: None,
    };

    std::fs::create_dir_all(dir).map_err(|e| {
        CliError::network(format!(
            "attest: cannot create --certificates-dir {dir}: {e}"
        ))
    })?;
    for (index, leaf) in collection.leaves.iter().enumerate() {
        let target = CertificateTarget {
            leaf: *leaf,
            leaf_alg: collection.leaf_alg.map(str::to_string),
            label: collection.labels[index].clone(),
        };
        let cert =
            build_inclusion_certificate(&anchor, &merkle, &collection.leaves, &[target], None)
                .map_err(|e| CliError::input(format!("attest: certificate build failed: {e}")))?;
        let json = serde_json::to_string_pretty(&cert).expect("certificate serialises");
        let path = Path::new(dir).join(format!("{index}.certificate.json"));
        std::fs::write(&path, format!("{json}\n")).map_err(|e| {
            CliError::network(format!("attest: cannot write {}: {e}", path.display()))
        })?;
    }
    Ok(collection.leaves.len())
}

// ---------------------------------------------------------------------------
// Receipt + outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ReceiptQuoteBreakdown {
    network_usd_micros: String,
    storage_usd_micros: String,
    service_usd_micros: String,
}

#[derive(Debug, Serialize)]
struct ReceiptQuote {
    quote_id: String,
    /// The total locked price in USD micro-cents, as a decimal string.
    amount: String,
    currency: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    usd_micros: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    breakdown: Option<ReceiptQuoteBreakdown>,
}

#[derive(Debug, Serialize)]
struct ReceiptItem {
    /// The item's digests as the spec's alg→digest map.
    hashes: ItemHashesMap,
    /// Legacy convenience field, present ONLY when the item carries a sha2-256
    /// digest (older receipt consumers read it). It never carries a non-sha2
    /// digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha2_256: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceiptMerkle {
    root: String,
    leaf_count: u64,
    publish: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ar_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceiptWait {
    target: &'static str,
    reached: bool,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_time: Option<String>,
    num_confirmations: u64,
}

/// The versioned attest receipt (`label-309-attest-receipt-v1`), a stable
/// public output contract. Carries everything needed to audit and re-verify
/// the anchor later; NEVER the API key or any seed material (the signer's
/// public key is, by definition, public).
#[derive(Debug, Serialize)]
struct AttestReceipt {
    format: &'static str,
    mode: &'static str,
    record_hex: String,
    signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_ed25519: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Vec<ReceiptItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle: Option<ReceiptMerkle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commits: Option<Vec<ReceiptCommit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes: Option<String>,
    poe_id: String,
    tx_hash: Option<String>,
    status: String,
    gateway_base_url: String,
    /// The consumed price lock. Omitted on a replayed run: the freshly
    /// fetched quote was never consumed and nothing was debited, so echoing
    /// its price would misstate what the run cost.
    #[serde(skip_serializing_if = "Option::is_none")]
    quote: Option<ReceiptQuote>,
    /// The Idempotency-Key that was sent (explicit mode only; the default
    /// `auto` mode sends none and relies on byte-identical record dedup).
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<ManifestOutput>,
    wait: ReceiptWait,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates_written: Option<usize>,
    balance_after_usd_micros: String,
}

/// The machine-readable stdout summary (`--json`), shaped like `submit`'s
/// with the attest-specific fields appended.
#[derive(Debug, Serialize)]
struct AttestOutcome {
    mode: &'static str,
    record: &'static str,
    id: String,
    tx_hash: Option<String>,
    status: String,
    /// The single-item record's digests as the spec's alg→digest map. Absent
    /// for a Merkle record.
    #[serde(skip_serializing_if = "Option::is_none")]
    item_hashes: Option<ItemHashesMap>,
    /// Legacy convenience field — the sha2-256 digest, present ONLY when the
    /// item carries a sha2-256 entry (the CI wrappers that parse it). It never
    /// carries a non-sha2 digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    item_sha2_256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ar_uri: Option<String>,
    /// The consumed quote's total. Omitted on a replayed run (nothing was
    /// debited; `balance_after_usd_micros` is the authoritative figure).
    #[serde(skip_serializing_if = "Option::is_none")]
    price_usd_micros: Option<String>,
    balance_after_usd_micros: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha2_256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates_written: Option<usize>,
    wait_target: &'static str,
    wait_reached: bool,
}

fn emit_outcome(outcome: &AttestOutcome, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(outcome).expect("AttestOutcome serialises")
        );
        return;
    }
    println!("ok: {}", outcome.id);
    println!("  status:       {}", outcome.status);
    println!(
        "  tx_hash:      {}",
        outcome.tx_hash.as_deref().unwrap_or("<pending>")
    );
    if let Some(hashes) = &outcome.item_hashes {
        for (alg, hex) in hashes.entries() {
            println!("  {alg}: {hex}");
        }
    }
    if let Some(root) = &outcome.root {
        println!("  root:         {root}");
        println!("  leaf_count:   {}", outcome.leaf_count.unwrap_or(0));
        if let Some(uri) = &outcome.ar_uri {
            println!("  ar_uri:       {uri}");
        }
    }
    if let Some(price) = &outcome.price_usd_micros {
        println!("  price:        {}", format_usd_micros(price));
    }
    println!(
        "  balance:      {}",
        format_usd_micros(&outcome.balance_after_usd_micros)
    );
    if outcome.replayed {
        println!("  replayed:     true (already anchored; no new debit)");
    }
    if let Some(key) = &outcome.idempotency_key {
        println!("  idempotency:  {key}");
    }
    if let Some(path) = &outcome.manifest_path {
        println!(
            "  manifest:     {path} (sha2-256 {})",
            outcome.manifest_sha2_256.as_deref().unwrap_or("")
        );
    }
    if let Some(path) = &outcome.receipt_path {
        println!("  receipt:      {path}");
    }
    if let Some(written) = outcome.certificates_written {
        println!("  certificates: {written}");
    }
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/// Run the `attest` command.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code (see the module docs).
pub fn run(args: AttestArgs) -> Result<(), CliError> {
    let source = choose_source(&args)?;
    if args.anchor_manifest && source != LeafSource::Paths {
        return Err(CliError::input(
            "attest: --anchor-manifest applies only to --paths (the manifest describes files)",
        ));
    }
    if args.certificates_dir.is_some() && args.wait != WaitTargetArg::Confirmed {
        return Err(CliError::input(
            "attest: --certificates-dir requires --wait confirmed (a certificate anchors on a \
             confirmed block)",
        ));
    }
    if args.timeout == 0 {
        return Err(CliError::input("attest: --timeout must be positive"));
    }
    if args.idempotency_key.is_empty() {
        return Err(CliError::input(
            "attest: --idempotency-key must be 'auto' or a non-empty key",
        ));
    }
    let max_usd_micros = args
        .max_usd
        .as_deref()
        .map(|text| {
            parse_usd_to_micros(text)
                .map_err(|e| CliError::input(format!("attest: --max-usd: {e}")))
        })
        .transpose()?;
    let supersedes = args
        .supersedes
        .as_deref()
        .map(|value| parse_supersedes(value, "attest"))
        .transpose()?;
    let hash_algs = resolve_content_hash_algs(&args.hash_alg, "attest")?;

    let gateway = resolve_required_gateway(
        GatewayArgs {
            base_url: args.base_url.as_deref(),
            api_key: args.api_key.as_deref(),
            gateway_profile: args.gateway_profile.as_deref(),
        },
        "attest",
        &SystemSecretEnv,
    )?;
    let signer = resolve_optional_signer(&args.seed_secret_args(), "attest", &SystemSecretEnv)?;
    let signer_ref: Option<&dyn Signer> = signer.as_ref().map(|s| s as &dyn Signer);
    let signer_pubkey_hex = signer.as_ref().map(|s| bytes_to_hex(&s.signer_pubkey()));

    let collection = match source {
        LeafSource::Paths => collect_path_leaves(&args)?,
        LeafSource::Commits => collect_commit_leaves(args.commits.as_deref().unwrap())?,
        LeafSource::Leaves => collect_literal_leaves(&args.leaves)?,
    };

    let gateway_base_url = gateway.base_url.clone();
    let client = Label309Client::new(Label309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("attest: {e}")))?;
    let poe = client.poe();

    // `--uri` mirrors bind to the single-leaf items[] record only; the decision
    // (validate + thread, or reject on a Merkle record) is settled up front so
    // it fires before either publish path.
    let item_uris = resolve_item_uris(&args.uri, collection.leaves.len())?;

    let published = if collection.leaves.len() == 1 {
        let item_hashes = single_leaf_item_hashes(&collection, &hash_algs)?;
        publish_single_item(
            &poe,
            item_hashes,
            item_uris,
            signer_ref,
            &args,
            max_usd_micros,
            supersedes.as_deref(),
        )?
    } else {
        // The Merkle registry is rfc9162-sha256 only, so a Merkle commitment's
        // leaves are always sha2-256; a --hash-alg naming anything else is
        // refused rather than silently ignored.
        if hash_algs != [ContentHashAlg::Sha2_256] {
            return Err(CliError::input(
                "attest: a Merkle record (2+ leaves) commits sha2-256 leaves only; --hash-alg \
                 cannot select another algorithm here",
            ));
        }
        publish_merkle_batch(
            &poe,
            &collection,
            signer_ref,
            &args,
            max_usd_micros,
            supersedes.as_deref(),
        )?
    };

    // Follow the lifecycle stream. A terminal failure or a stream rejection
    // errors out here; a timeout falls through so every output still lands.
    let wait_result = wait_for_poe_target(
        &client,
        &published.response.id,
        args.wait,
        args.timeout,
        "attest",
    )?;
    let (wait_snapshot, timed_out) = match wait_result {
        WaitOutcome::Reached(snapshot) => (Some(snapshot), false),
        WaitOutcome::TimedOut { last_snapshot } => (last_snapshot, true),
    };

    let mut status = published
        .response
        .status
        .clone()
        .normalized()
        .as_str()
        .to_string();
    let mut tx_hash = published.response.tx_hash.clone();
    if let Some(snapshot) = &wait_snapshot {
        if let Some(s) = &snapshot.status {
            status = s.clone().normalized().as_str().to_string();
        }
        if snapshot.tx_hash.is_some() {
            tx_hash = snapshot.tx_hash.clone();
        }
    }

    // Certificates need a confirmed anchor and a real tree.
    let certificates_written: Option<usize> = match (&args.certificates_dir, timed_out) {
        (Some(_), true) | (None, _) => None,
        (Some(dir), false) => {
            if collection.leaves.len() < 2 {
                eprintln!(
                    "attest: note: --certificates-dir applies to Merkle records (2+ leaves); a \
                     single-item record needs no inclusion proof — the transaction itself is the \
                     proof"
                );
                Some(0)
            } else {
                let snapshot = wait_snapshot
                    .as_ref()
                    .expect("a reached confirmed wait always carries a snapshot");
                Some(write_certificates(
                    dir,
                    &collection,
                    published.root.expect("2+ leaves publish a merkle record"),
                    published.ar_uri.as_ref(),
                    snapshot,
                    args.network,
                )?)
            }
        }
    };

    // The receipt.
    if let Some(receipt_path) = &args.receipt_out {
        let receipt =
            AttestReceipt {
                format: RECEIPT_FORMAT,
                mode: collection.source.as_str(),
                record_hex: bytes_to_hex(&published.record_bytes),
                signed: signer_pubkey_hex.is_some(),
                signer_ed25519: signer_pubkey_hex.clone(),
                // A single-leaf record's item carries its published `hashes`
                // map; a Merkle record has no `items[]` (its leaves are the
                // tree). Reporting the map — not the bare leaf — is what keeps a
                // non-sha2 or co-hash digest labelled by its own algorithm.
                items: published.item_hashes.as_ref().map(|hashes| {
                    let map = ItemHashesMap::from_item_hashes(hashes);
                    vec![ReceiptItem {
                        sha2_256: map.sha2_256(),
                        hashes: map,
                    }]
                }),
                merkle: published.root.map(|root| ReceiptMerkle {
                    root: bytes_to_hex(&root),
                    leaf_count: collection.leaves.len() as u64,
                    publish: args.publish.as_str(),
                    ar_uri: published.ar_uri.clone(),
                }),
                commits: collection.commits.clone(),
                supersedes: supersedes.as_deref().map(bytes_to_hex),
                poe_id: published.response.id.clone(),
                tx_hash: tx_hash.clone(),
                status: status.clone(),
                gateway_base_url: gateway_base_url.clone(),
                // A replayed run consumed no quote and debited nothing: echoing
                // the fresh quote's price would misstate the run's cost.
                quote: if published.response.dedup_hit {
                    None
                } else {
                    Some(ReceiptQuote {
                        quote_id: published.quote.quote_id.clone(),
                        amount: published.quote.amount.clone(),
                        currency: published.quote.currency.clone(),
                        expires_at: published.quote.expires_at.clone(),
                        usd_micros: published.quote.usd_micros.clone(),
                        breakdown: published.quote.breakdown.as_ref().map(|b| {
                            ReceiptQuoteBreakdown {
                                network_usd_micros: b.network_usd_micros.clone(),
                                storage_usd_micros: b.storage_usd_micros.clone(),
                                service_usd_micros: b.service_usd_micros.clone(),
                            }
                        }),
                    })
                },
                idempotency_key: published.idempotency_key.clone(),
                replayed: published.response.dedup_hit,
                manifest: collection.manifest.clone(),
                wait: ReceiptWait {
                    target: args.wait.as_str(),
                    reached: !timed_out,
                    timed_out,
                    block_height: wait_snapshot.as_ref().and_then(|s| s.block_height),
                    block_time: wait_snapshot.as_ref().and_then(|s| s.block_time.clone()),
                    num_confirmations: wait_snapshot.as_ref().map_or(0, |s| s.num_confirmations),
                },
                certificates_dir: args.certificates_dir.clone(),
                certificates_written,
                balance_after_usd_micros: published.response.balance_after_usd_micros.clone(),
            };
        let json = serde_json::to_string_pretty(&receipt).expect("receipt serialises");
        std::fs::write(receipt_path, format!("{json}\n")).map_err(|e| {
            CliError::network(format!(
                "attest: cannot write --receipt-out {receipt_path}: {e}"
            ))
        })?;
    }

    // Both the map and the legacy field derive from the item's published
    // `hashes`, so the sha2-256 convenience field can never carry a non-sha2
    // digest and is simply absent when the item has no sha2-256 entry.
    let item_hashes = published
        .item_hashes
        .as_ref()
        .map(|hashes| ItemHashesMap::from_item_hashes(hashes));
    let item_sha2_256 = item_hashes.as_ref().and_then(ItemHashesMap::sha2_256);

    let outcome = AttestOutcome {
        mode: collection.source.as_str(),
        record: if published.root.is_some() {
            "merkle"
        } else {
            "items"
        },
        id: published.response.id.clone(),
        tx_hash,
        status: status.clone(),
        item_hashes,
        item_sha2_256,
        root: published.root.map(|r| bytes_to_hex(&r)),
        leaf_count: published.root.map(|_| collection.leaves.len() as u64),
        ar_uri: published.ar_uri.clone(),
        price_usd_micros: if published.response.dedup_hit {
            None
        } else {
            Some(published.quote.amount.clone())
        },
        balance_after_usd_micros: published.response.balance_after_usd_micros.clone(),
        idempotency_key: published.idempotency_key.clone(),
        replayed: published.response.dedup_hit,
        manifest_path: collection.manifest.as_ref().map(|m| m.path.clone()),
        manifest_sha2_256: collection.manifest.as_ref().map(|m| m.sha2_256.clone()),
        receipt_path: args.receipt_out.clone(),
        certificates_written,
        wait_target: args.wait.as_str(),
        wait_reached: !timed_out,
    };
    emit_outcome(&outcome, args.json);

    if timed_out {
        return Err(CliError::new(
            3,
            format!(
                "attest: timed out after {}s waiting for '{}'; the publish continues on the \
                 gateway (record {}, status {status}) — re-running the same attest resumes \
                 tracking without re-anchoring",
                args.timeout,
                args.wait.as_str(),
                published.response.id
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> AttestArgs {
        AttestArgs {
            paths: vec![],
            commits: None,
            leaves: vec![],
            publish: PublishModeArg::FullTree,
            anchor_manifest: false,
            uri: vec![],
            hash_alg: vec![],
            manifest_out: "poe-manifest.json".to_string(),
            seed: None,
            seed_file: None,
            seed_stdin: false,
            api_key: None,
            base_url: None,
            gateway_profile: None,
            idempotency_key: "auto".to_string(),
            wait: WaitTargetArg::Confirmed,
            timeout: 600,
            max_usd: None,
            supersedes: None,
            receipt_out: None,
            certificates_dir: None,
            network: NetworkArg::Mainnet,
            json: false,
        }
    }

    #[test]
    fn requires_exactly_one_leaf_source() {
        let args = base_args();
        assert_eq!(choose_source(&args).unwrap_err().code, 4);
        let mut both = base_args();
        both.paths = vec!["*.txt".to_string()];
        both.commits = Some("HEAD".to_string());
        assert_eq!(choose_source(&both).unwrap_err().code, 4);
        let mut one = base_args();
        one.leaves = vec!["ab".repeat(32)];
        assert_eq!(choose_source(&one).unwrap(), LeafSource::Leaves);
    }

    #[test]
    fn anchor_manifest_requires_paths_mode() {
        let mut args = base_args();
        args.commits = Some("HEAD".to_string());
        args.anchor_manifest = true;
        let err = run(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--anchor-manifest"));
    }

    #[test]
    fn certificates_dir_requires_wait_confirmed() {
        let mut args = base_args();
        args.leaves = vec!["ab".repeat(32)];
        // Never written: the flag validation rejects the combination first.
        args.certificates_dir = Some("certs".to_string());
        args.wait = WaitTargetArg::Submitted;
        let err = run(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--certificates-dir"));
    }

    #[test]
    fn normalizes_paths_relative_with_forward_slashes() {
        let cwd = Path::new("/work/repo");
        assert_eq!(
            normalize_rel_path(Path::new("/work/repo/dist/a.bin"), Some(cwd)).unwrap(),
            "dist/a.bin"
        );
        assert_eq!(
            normalize_rel_path(Path::new("./dist/a.bin"), Some(cwd)).unwrap(),
            "dist/a.bin"
        );
        // Outside the cwd the absolute form is preserved (still deterministic).
        assert_eq!(
            normalize_rel_path(Path::new("/elsewhere/b.bin"), Some(cwd)).unwrap(),
            "/elsewhere/b.bin"
        );
    }

    /// Two names differing only in an invalid byte must never collapse onto
    /// one manifest entry: normalization refuses non-UTF-8 outright (exit 4,
    /// naming the path) instead of projecting both to the same
    /// replacement-character string and silently dropping a file.
    #[cfg(unix)]
    #[test]
    fn non_utf8_path_components_are_refused_not_lossily_collapsed() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let first = PathBuf::from(OsStr::from_bytes(b"data/bad\x80.bin"));
        let second = PathBuf::from(OsStr::from_bytes(b"data/bad\x81.bin"));
        // The lossy projections WOULD have been identical — the exact trap.
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        for path in [&first, &second] {
            let err = normalize_rel_path(path, None).unwrap_err();
            assert_eq!(err.code, 4);
            assert!(err.message.contains("not valid UTF-8"), "{}", err.message);
            // The offending path is named (invalid bytes render as escapes).
            assert!(err.message.contains("bad"), "{}", err.message);
        }
    }

    #[cfg(unix)]
    #[test]
    fn subtree_scan_names_a_non_utf8_entry_or_skips_on_strict_filesystems() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok.bin"), b"x").unwrap();
        // Some filesystems (notably APFS) refuse to create non-UTF-8 names at
        // all; there the hazard cannot exist and the scan has nothing to find.
        let bad = dir.path().join(OsStr::from_bytes(b"bad\x80.bin"));
        if std::fs::write(&bad, b"x").is_err() {
            refuse_non_utf8_under(dir.path()).unwrap();
            return;
        }
        let err = refuse_non_utf8_under(dir.path()).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("not valid UTF-8"));
        assert!(err.message.contains("bad"), "{}", err.message);
    }

    #[test]
    fn glob_static_prefix_stops_at_the_first_metacharacter() {
        assert_eq!(glob_static_prefix("dist/**/*"), PathBuf::from("dist"));
        assert_eq!(glob_static_prefix("dist/a[0].bin"), PathBuf::from("dist"));
        assert_eq!(glob_static_prefix("*.bin"), PathBuf::from("."));
        assert_eq!(glob_static_prefix("di*/x.bin"), PathBuf::from("."));
        assert_eq!(glob_static_prefix("a/b/c?.txt"), PathBuf::from("a/b"));
    }

    #[test]
    fn expands_dedupes_and_byte_sorts_paths() {
        let dir = tempfile::tempdir().unwrap();
        // Created out of byte order; a numeric ("natural") sort would put
        // 2.txt before 10.txt, byte order puts "1" < "2" < "a".
        for name in ["a.txt", "2.txt", "10.txt"] {
            std::fs::write(dir.path().join(name), name).unwrap();
        }
        let pattern = format!("{}/*.txt", dir.path().display());
        // The same selection twice (glob + literal) must not duplicate.
        let literal = dir.path().join("a.txt").display().to_string();
        let selected = expand_paths(&[pattern, literal]).unwrap();
        let names: Vec<&str> = selected
            .iter()
            .map(|(n, _)| n.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(names, vec!["10.txt", "2.txt", "a.txt"]);
    }

    #[test]
    fn literal_directory_path_is_an_input_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = expand_paths(&[dir.path().display().to_string()]).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("directory"));
    }

    #[test]
    fn manifest_rendering_is_deterministic_and_timestamp_free() {
        let rows = vec![
            ManifestFile {
                path: "dist/a.bin".to_string(),
                size: 3,
                sha2_256: "ab".repeat(32),
            },
            ManifestFile {
                path: "dist/b.bin".to_string(),
                size: 5,
                sha2_256: "cd".repeat(32),
            },
        ];
        let first = render_manifest(&rows);
        let second = render_manifest(&rows);
        assert_eq!(first, second);
        let text = String::from_utf8(first).unwrap();
        assert!(text.contains("\"format\": \"label-309-poe-manifest-v1\""));
        // Determinism: no clock-derived content.
        assert!(!text.to_lowercase().contains("time"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn auto_mode_sends_no_idempotency_key_and_explicit_passes_verbatim() {
        // `auto` must not synthesize a key: the gateway's key contract hashes
        // the whole request body, and the body carries a fresh quote_id every
        // run, so any fixed key would 409 on re-run. Safe re-runs ride the
        // gateway's byte-identical record dedup instead.
        assert_eq!(resolve_idempotency_key("auto"), None);
        assert_eq!(
            resolve_idempotency_key("ci-run-42"),
            Some("ci-run-42".to_string())
        );
    }

    #[test]
    fn leaf_values_are_validated_and_ordered() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        let collection = collect_literal_leaves(&[b.clone(), a.clone()]).unwrap();
        // Argument order is preserved (no sorting for pass-through digests).
        assert_eq!(bytes_to_hex(&collection.leaves[0]), b);
        assert_eq!(bytes_to_hex(&collection.leaves[1]), a);
        assert!(collection.leaf_alg.is_none());
        assert_eq!(
            collect_literal_leaves(&["zz".to_string()])
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn single_leaf_hashes_label_pass_through_and_reject_multi_alg() {
        let leaf = [0xab; 32];
        let collection = LeafCollection {
            source: LeafSource::Leaves,
            leaves: vec![leaf],
            labels: vec![None],
            leaf_alg: None,
            manifest: None,
            commits: None,
            single_source_path: None,
            single_source_bytes: None,
        };
        // A single --hash-alg labels the pass-through digest (no hardcoded sha2-256).
        assert_eq!(
            single_leaf_item_hashes(&collection, &[ContentHashAlg::Blake2b256]).unwrap(),
            vec![("blake2b-256".to_string(), leaf.to_vec())]
        );
        // Several algorithms for a lone pass-through digest is refused.
        assert_eq!(
            single_leaf_item_hashes(
                &collection,
                &[ContentHashAlg::Sha2_256, ContentHashAlg::Blake2b256]
            )
            .unwrap_err()
            .code,
            4
        );
    }

    #[test]
    fn single_leaf_hashes_cohash_a_byte_backed_source() {
        let bytes = b"commit object bytes".to_vec();
        let leaf = sha256(&bytes);
        let collection = LeafCollection {
            source: LeafSource::Commits,
            leaves: vec![leaf],
            labels: vec![None],
            leaf_alg: Some("sha2-256"),
            manifest: None,
            commits: None,
            single_source_path: None,
            single_source_bytes: Some(bytes.clone()),
        };
        // sha2-256 alone reuses the primary leaf without re-hashing.
        assert_eq!(
            single_leaf_item_hashes(&collection, &[ContentHashAlg::Sha2_256]).unwrap(),
            vec![("sha2-256".to_string(), leaf.to_vec())]
        );
        // Co-hash re-hashes the retained bytes under every algorithm.
        let algs = [ContentHashAlg::Sha2_256, ContentHashAlg::Blake2b256];
        let hashes = single_leaf_item_hashes(&collection, &algs).unwrap();
        assert_eq!(hashes, cohash_content(&bytes, &algs));
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    fn single_leaf_uri_is_validated_threaded_and_defaults_to_none() {
        let ar = format!("ar://{}", "a".repeat(43));
        // A single-leaf record carries the validated mirror on its item.
        assert_eq!(
            resolve_item_uris(std::slice::from_ref(&ar), 1).unwrap(),
            Some(vec![ar.clone()])
        );
        // No --uri means no `uris` field at all.
        assert_eq!(resolve_item_uris(&[], 1).unwrap(), None);
    }

    #[test]
    fn uri_on_a_merkle_record_is_refused() {
        let ar = format!("ar://{}", "a".repeat(43));
        // 2+ leaves publish a Merkle record, which binds its leaves-list URI via
        // --publish full-tree; a --uri item mirror has no meaning there.
        let err = resolve_item_uris(std::slice::from_ref(&ar), 2).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("single-leaf"), "{}", err.message);
        // An empty --uri list on a Merkle record is fine (nothing to bind).
        assert_eq!(resolve_item_uris(&[], 3).unwrap(), None);
    }

    #[test]
    fn single_leaf_uri_rejects_a_malformed_mirror() {
        // Reuses submit's fetch-set grammar: a fragment (and a too-short txid)
        // is rejected before any network call.
        let err = resolve_item_uris(&["ar://bad#fragment".to_string()], 1).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("ar:// or ipfs://"), "{}", err.message);
    }

    #[test]
    fn attest_args_debug_redacts_seed_and_api_key() {
        let mut args = base_args();
        args.seed = Some("ab".repeat(32));
        args.api_key = Some("super-secret-bearer".to_string());
        args.base_url = Some("https://gw.example/api/v1".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains("super-secret-bearer"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("https://gw.example/api/v1"));
    }
}
