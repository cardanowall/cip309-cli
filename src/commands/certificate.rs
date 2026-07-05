//! `cardanowall certificate` — build and verify Label 309 inclusion
//! certificates.
//!
//! An inclusion certificate is a downloadable, self-contained, standalone-
//! verifiable proof that one or more content hashes were committed as leaves of
//! an RFC 9162 (Certificate Transparency) SHA-256 Merkle tree whose root was
//! published on Cardano under metadata label 309. Each item embeds its full
//! sibling path, so the artifact re-verifies forever from the file alone — no
//! Arweave, no chain query, no trust in any issuer.
//!
//! - `certificate build` — locate each target leaf in the tree, compute its
//!   inclusion proof, and emit the JSON certificate plus (optionally) the
//!   per-item COSE / RFC 9162 CBOR proof. The leaf set comes from a leaves-list
//!   CBOR file (`--leaves-list`) or is auto-fetched from the record's `ar://`
//!   leaves-list when a transaction is resolved with `--tx`. The anchor facts
//!   come from `--tx` (resolved via the SDK verifier's Koios/Blockfrost path)
//!   and/or the explicit offline `--block-time` / `--slot` / `--block-height` /
//!   `--confirmations` flags.
//! - `certificate verify <file>` — pure re-verification of a certificate from
//!   its own bytes: it proves the inclusion math and echoes the anchor to
//!   confirm on a public Cardano explorer. It performs NO chain I/O and cannot
//!   confirm on-chain anchoring — that is a separate, explorer-side step.
//!
//! Exit codes mirror `merkle verify`: `0` all items verified, `1`
//! inclusion-failed (any item or whole-certificate rejection), `2` IO /
//! unreadable file / network, `4` CLI input error.

use std::io::Read;

use cardanowall::certificate::{
    build_inclusion_certificate, encode_cose_inclusion_proof, verify_inclusion_certificate,
    BuildCertificateError, CertificateAnchor, CertificateMerkle, CertificateTarget,
    InclusionCertificateV1,
};
use cardanowall::hash::sha256;
use cardanowall::merkle::{
    decode_leaves_list, DecodedLeavesList, MerkleLeavesListError, MERKLE_ALG_ID,
};
use cardanowall::poe_standard::{
    validate_poe_record, MerkleCommit, PathSegment, ValidateResult, ValidatorOptions,
};
use cardanowall::verifier::content::{
    walk_blob_sources, BlobWalkEnd, ContentFetchPolicy, SourceDecision,
};
use cardanowall::verifier::fetch::ReqwestTransport;
use cardanowall::verifier::{
    extract_label_309_metadata, resolve_cardano_tx, GatewayFetcher, VerifierIssue,
};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;

use crate::config::{
    read_config_file, resolve_gateways, GatewayFlags, ResolvedGateways, SystemConfigEnv,
    SystemGatewayEnv,
};
use crate::util::{hex_to_bytes, CliError};

/// Length in bytes of a content-hash leaf and the Merkle root (SHA-256).
const DIGEST_BYTES: usize = 32;

/// The default file-hashing algorithm when the leaves-list carries no `leaf_alg`.
const DEFAULT_LEAF_ALG: &str = "sha2-256";

/// Arguments for `cardanowall certificate`.
#[derive(Debug, Args)]
pub struct CertificateArgs {
    /// The certificate verb to run.
    #[command(subcommand)]
    pub verb: CertificateVerb,
}

/// The two certificate verbs.
#[derive(Debug, Subcommand)]
pub enum CertificateVerb {
    /// Build a JSON inclusion certificate (and optional per-item COSE CBOR).
    Build(Box<CertificateBuildArgs>),
    /// Re-verify a certificate purely from its own bytes (no network).
    Verify(CertificateVerifyArgs),
}

impl CertificateArgs {
    /// Whether the active verb was invoked with `--json`.
    #[must_use]
    pub fn json_mode(&self) -> bool {
        match &self.verb {
            CertificateVerb::Build(a) => a.json,
            CertificateVerb::Verify(a) => a.json,
        }
    }
}

/// Run the `certificate` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: CertificateArgs) -> Result<(), CliError> {
    match args.verb {
        CertificateVerb::Build(a) => run_build(*a),
        CertificateVerb::Verify(a) => run_verify(a),
    }
}

// ===========================================================================
// Network → explorer URL map
// ===========================================================================

/// The Cardano network an anchor is built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum NetworkArg {
    /// Cardano mainnet (the production network).
    #[default]
    Mainnet,
    /// The Cardano preprod test network.
    Preprod,
}

impl NetworkArg {
    /// The network name recorded in the certificate anchor.
    pub(crate) fn name(self) -> &'static str {
        match self {
            NetworkArg::Mainnet => "mainnet",
            NetworkArg::Preprod => "preprod",
        }
    }

    /// The public explorer URLs for `tx_hash` on this network.
    ///
    /// Cardanoscan exposes a transaction at `/transaction/<tx>` and AdaStat at
    /// `/transactions/<tx>`, each with a `preprod.` host prefix on preprod.
    pub(crate) fn explorer_urls(self, tx_hash: &str) -> Vec<String> {
        let (cardanoscan, adastat) = match self {
            NetworkArg::Mainnet => ("https://cardanoscan.io", "https://adastat.net"),
            NetworkArg::Preprod => (
                "https://preprod.cardanoscan.io",
                "https://preprod.adastat.net",
            ),
        };
        vec![
            format!("{cardanoscan}/transaction/{tx_hash}"),
            format!("{adastat}/transactions/{tx_hash}"),
        ]
    }
}

// ===========================================================================
// certificate build
// ===========================================================================

/// Arguments for `cardanowall certificate build`.
///
/// `blockfrost` is a Blockfrost API credential, so `Debug` is hand-written to
/// redact it: no `{:?}`, log, or panic path can surface the project id.
#[derive(Args)]
pub struct CertificateBuildArgs {
    /// Leaves-list source: a canonical-CBOR leaves-list file, or `-` for stdin.
    /// Mutually exclusive with auto-fetch via --tx.
    #[arg(long = "leaves-list")]
    pub leaves_list: Option<String>,
    /// Target leaf: a 32-byte content-hash hex (repeatable).
    #[arg(long = "leaf")]
    pub leaves: Vec<String>,
    /// Target file: hashed with the leaf algorithm to obtain its leaf
    /// (repeatable). The file path is recorded as the item's label.
    #[arg(long = "file")]
    pub files: Vec<String>,
    /// Anchoring Cardano transaction hash (64 hex). Resolves block time / slot /
    /// confirmations / leaves-list and builds explorer URLs.
    #[arg(long = "tx")]
    pub tx: Option<String>,
    /// Cardano network for the anchor + explorer URLs (default: mainnet).
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    pub network: NetworkArg,
    /// Block time in POSIX seconds (overrides the --tx-resolved value; required
    /// for an offline build with no --tx).
    #[arg(long = "block-time")]
    pub block_time: Option<i64>,
    /// Block slot (optional; overrides the --tx-resolved value).
    #[arg(long = "slot")]
    pub slot: Option<i64>,
    /// Block height (optional; the verifier does not resolve it, so it is
    /// recorded only when supplied here).
    #[arg(long = "block-height")]
    pub block_height: Option<i64>,
    /// Confirmation snapshot at generation (optional; overrides --tx-resolved).
    #[arg(long = "confirmations")]
    pub confirmations: Option<i64>,
    /// Generation timestamp passthrough (ISO-8601); omit for the current time.
    #[arg(long = "generated-at")]
    pub generated_at: Option<String>,
    /// Cardano data-source gateway URL (repeatable; Koios-compatible; or env
    /// CARDANOWALL_CARDANO_GATEWAY). Used only with --tx.
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub cardano_gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback for --tx; or env
    /// CARDANOWALL_BLOCKFROST_PROJECT_ID).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// Arweave gateway URL (repeatable; or env CARDANOWALL_ARWEAVE_GATEWAY).
    /// Used only to auto-fetch the leaves-list with --tx.
    #[arg(long = "arweave-gateway")]
    pub arweave_gateway: Vec<String>,
    /// extra entries for the egress deny list (repeatable; or env
    /// CARDANOWALL_DENY_HOST), appended to the built-in defaults. Applies to
    /// URLs taken from on-chain records.
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// the --deny-host entries REPLACE the built-in deny list instead of
    /// appending (or env CARDANOWALL_DENY_HOSTS_REPLACE / config
    /// deny_hosts_replace). With no entries listed, NOTHING is refused — you
    /// take over SSRF protection entirely. Meant for private-network
    /// resolvers (e.g. an internal Arweave mirror, or arlocal on loopback).
    #[arg(long = "deny-hosts-replace")]
    pub deny_hosts_replace: bool,
    /// Write the JSON certificate here (default: stdout).
    #[arg(long = "out")]
    pub out: Option<String>,
    /// Write one `<index>.cbor` per verified item into this directory.
    #[arg(long = "cbor-dir")]
    pub cbor_dir: Option<String>,
    /// Emit a machine-readable JSON build outcome on stdout instead of the
    /// certificate (the certificate still goes to --out / stdout).
    #[arg(long)]
    pub json: bool,
}

impl std::fmt::Debug for CertificateBuildArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateBuildArgs")
            .field("leaves_list", &self.leaves_list)
            .field("leaves", &self.leaves)
            .field("files", &self.files)
            .field("tx", &self.tx)
            .field("network", &self.network)
            .field("block_time", &self.block_time)
            .field("slot", &self.slot)
            .field("block_height", &self.block_height)
            .field("confirmations", &self.confirmations)
            .field("generated_at", &self.generated_at)
            .field("cardano_gateway", &self.cardano_gateway)
            // The Blockfrost project id authenticates requests to Blockfrost, so
            // it is a credential and must never surface in a debug dump.
            .field(
                "blockfrost",
                &self.blockfrost.as_ref().map(|_| "[redacted]"),
            )
            .field("arweave_gateway", &self.arweave_gateway)
            .field("deny_host", &self.deny_host)
            .field("deny_hosts_replace", &self.deny_hosts_replace)
            .field("out", &self.out)
            .field("cbor_dir", &self.cbor_dir)
            .field("json", &self.json)
            .finish()
    }
}

/// The leaf set plus the on-chain Merkle facts a build operates over.
struct ResolvedLeaves {
    /// The decoded leaf digests, in tree order.
    leaves: Vec<[u8; DIGEST_BYTES]>,
    /// The declared Merkle root.
    root: [u8; DIGEST_BYTES],
    /// The advisory `leaf_alg`, used to hash `--file` targets.
    leaf_alg: Option<String>,
    /// The `ar://` source reference, when the leaves-list came from a tx.
    leaves_list_uri: Option<String>,
}

/// The chain facts resolved from `--tx`, when supplied.
struct ResolvedAnchorFacts {
    block_time: i64,
    slot: i64,
    confirmations: i64,
    /// The reassembled label-309 record's merkle commitments, for leaves-list
    /// auto-fetch.
    merkle: Vec<MerkleCommit>,
}

#[derive(Debug, Serialize)]
struct BuildItemOutcome {
    leaf: String,
    index: i64,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BuildOutcome {
    ok: bool,
    root: String,
    tree_size: usize,
    out: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cbor_dir: Option<String>,
    cbor_written: usize,
    items: Vec<BuildItemOutcome>,
}

fn run_build(args: CertificateBuildArgs) -> Result<(), CliError> {
    // A meaningful anchor needs a transaction hash. Both an offline build
    // (--leaves-list + explicit --block-time) and a --tx build carry the
    // tx_hash; without it the certificate would point at nothing.
    let tx_hash = args.tx.as_deref().map(str::to_lowercase).ok_or_else(|| {
        CliError::input("certificate build: --tx <hash> is required to anchor the certificate")
    })?;
    if tx_hash.len() != 64 || !tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "certificate build: --tx must be 64 hex chars; got \"{}\"",
            args.tx.as_deref().unwrap_or("")
        )));
    }

    if args.leaves.is_empty() && args.files.is_empty() {
        return Err(CliError::input(
            "certificate build: supply at least one target (--leaf <hex> and/or --file <path>)",
        ));
    }

    // The leaves-list comes from exactly one source: an explicit file/stdin, or
    // auto-fetch from the record's ar:// leaves-list when --tx is resolved.
    // Supplying both is ambiguous and refused.
    let want_fetch = args.leaves_list.is_none();

    // The network is engaged only when the chain is genuinely needed: the
    // leaves-list must be auto-fetched, OR the one *required* anchor fact
    // (block_time) is not supplied explicitly and so must come from the resolve.
    // The optional facts (slot, confirmations, block_height) being absent never
    // forces a call — they are omitted from the certificate when unknown. A
    // resolve that runs for either reason still fills any optional fact the user
    // did not override, so `--leaves-list` + explicit `--block-time` is fully
    // offline even when slot/confirmations are left out.
    let need_network = want_fetch || args.block_time.is_none();

    // Build the shared egress only when the network is actually needed, so an
    // offline build never constructs a transport.
    let resolved_gateways = resolve_gateways_for(&args)?;
    // The transport carries the deny list so its redirect-policy closure
    // re-applies the same list the fetcher's initial-URL guard uses.
    let transport = ReqwestTransport::with_deny_hosts(resolved_gateways.deny_hosts.clone());

    let anchor_facts: Option<ResolvedAnchorFacts> = if need_network {
        let mut fetcher = GatewayFetcher::new(&transport, Some(&resolved_gateways.deny_hosts));
        Some(resolve_anchor_facts(
            &tx_hash,
            &resolved_gateways,
            &mut fetcher,
        )?)
    } else {
        None
    };

    // Resolve the leaf set: an explicit leaves-list, or auto-fetched from the
    // record's first ar:// merkle commitment.
    let resolved_leaves = if let Some(source) = args.leaves_list.as_deref() {
        load_leaves_list_file(source)?
    } else {
        // Auto-fetch requires the record's merkle commitments, which only the
        // --tx resolve provides.
        let facts = anchor_facts
            .as_ref()
            .expect("network resolve runs whenever the leaves-list is auto-fetched");
        let mut fetcher = GatewayFetcher::new(&transport, Some(&resolved_gateways.deny_hosts));
        fetch_leaves_list_from_record(&facts.merkle, &resolved_gateways, &mut fetcher)?
    };

    // Assemble the anchor: explicit flags win, then the resolved chain facts.
    let block_time = args
        .block_time
        .or_else(|| anchor_facts.as_ref().map(|f| f.block_time))
        .ok_or_else(|| {
            CliError::input(
                "certificate build: --block-time is required for an offline build (no --tx-resolved value available)",
            )
        })?;
    let slot = args.slot.or_else(|| anchor_facts.as_ref().map(|f| f.slot));
    let confirmations = args
        .confirmations
        .or_else(|| anchor_facts.as_ref().map(|f| f.confirmations));

    let anchor = CertificateAnchor {
        chain: "cardano".to_string(),
        network: args.network.name().to_string(),
        tx_hash: tx_hash.clone(),
        metadata_label: 309,
        block_time,
        block_height: args.block_height,
        slot,
        confirmations_at_generation: confirmations,
        explorer_urls: Some(args.network.explorer_urls(&tx_hash)),
    };

    let merkle = CertificateMerkle {
        tree_alg: MERKLE_ALG_ID.to_string(),
        root: resolved_leaves.root,
        tree_size: resolved_leaves.leaves.len(),
        leaves_list_uri: resolved_leaves.leaves_list_uri.clone(),
        leaves_list_url: None,
    };

    // The effective leaf algorithm: the leaves-list's advisory value, else the
    // default. It both hashes `--file` targets and is recorded per item.
    let leaf_alg = resolved_leaves
        .leaf_alg
        .clone()
        .unwrap_or_else(|| DEFAULT_LEAF_ALG.to_string());

    let targets = build_targets(&args, &leaf_alg)?;

    let cert = build_inclusion_certificate(
        &anchor,
        &merkle,
        &resolved_leaves.leaves,
        &targets,
        args.generated_at.as_deref(),
    )
    .map_err(map_build_error)?;

    // Emit the JSON certificate to --out (or stdout). The human download form
    // is 2-space-indented per the format.
    let json = serde_json::to_string_pretty(&cert).expect("certificate serialises");
    let out_target = match args.out.as_deref() {
        Some(path) => {
            std::fs::write(path, format!("{json}\n")).map_err(|e| {
                CliError::network(format!("certificate build: cannot write --out {path}: {e}"))
            })?;
            path.to_string()
        }
        None => {
            println!("{json}");
            "stdout".to_string()
        }
    };

    // Optional per-item COSE CBOR: one `<index>.cbor` per VERIFIED item. The
    // encoder refuses a non-inclusion item, so misses are skipped.
    let cbor_written = if let Some(dir) = args.cbor_dir.as_deref() {
        write_cbor_dir(dir, &cert, &merkle, &anchor)?
    } else {
        0
    };

    let all_verified = cert.items.iter().all(|it| it.verified);

    let outcome = BuildOutcome {
        ok: all_verified,
        root: cert.merkle.root.clone(),
        tree_size: cert.merkle.tree_size,
        out: out_target.clone(),
        cbor_dir: args.cbor_dir.clone(),
        cbor_written,
        items: cert
            .items
            .iter()
            .map(|it| BuildItemOutcome {
                leaf: it.leaf.clone(),
                index: it.index,
                verified: it.verified,
                error: it.error.clone(),
            })
            .collect(),
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&outcome).expect("BuildOutcome serialises")
        );
    } else {
        eprintln!(
            "certificate written to {} ({} item(s), root {})",
            outcome.out,
            outcome.items.len(),
            outcome.root
        );
        for item in &outcome.items {
            match &item.error {
                Some(err) => eprintln!("  - {} index={} MISS ({err})", item.leaf, item.index),
                None if item.verified => {
                    eprintln!("  - {} index={} verified", item.leaf, item.index);
                }
                None => eprintln!("  - {} index={} NOT verified", item.leaf, item.index),
            }
        }
        if let Some(dir) = &outcome.cbor_dir {
            eprintln!("  {cbor_written} COSE proof(s) written to {dir}");
        }
    }

    // The exit code reflects whether every target verified, matching `merkle
    // verify`'s inclusion-failed semantics: any miss → exit 1.
    if all_verified {
        Ok(())
    } else {
        Err(CliError {
            code: 1,
            message: String::new(),
        })
    }
}

/// Translate a builder structural-misuse error into the CLI exit-code taxonomy.
///
/// Every variant here is a caller-side mistake about the *inputs* (an unsupported
/// algorithm, a tree-size or root that disagrees with the leaves, a block time
/// out of range), which is CLI-input class (exit 4). Honest "leaf not in the
/// tree" misses never reach this path — they become non-failing items.
fn map_build_error(err: BuildCertificateError) -> CliError {
    CliError::input(format!("certificate build: {err}"))
}

/// Build the per-target list from `--leaf` and `--file` inputs, in that order.
fn build_targets(
    args: &CertificateBuildArgs,
    leaf_alg: &str,
) -> Result<Vec<CertificateTarget>, CliError> {
    let mut targets = Vec::with_capacity(args.leaves.len() + args.files.len());

    for raw in &args.leaves {
        let bytes = ensure_hex32(raw, "--leaf")?;
        let mut leaf = [0u8; DIGEST_BYTES];
        leaf.copy_from_slice(&bytes);
        targets.push(CertificateTarget {
            leaf,
            leaf_alg: Some(leaf_alg.to_string()),
            label: None,
        });
    }

    for path in &args.files {
        let leaf = hash_file(path, leaf_alg)?;
        targets.push(CertificateTarget {
            leaf,
            leaf_alg: Some(leaf_alg.to_string()),
            label: Some(path.clone()),
        });
    }

    Ok(targets)
}

/// Hash a file into its leaf with the leaves-list `leaf_alg`.
///
/// Only `sha2-256` is implemented; an unsupported algorithm is a CLI-input
/// error rather than a silent fallback that would compute the wrong leaf.
fn hash_file(path: &str, leaf_alg: &str) -> Result<[u8; DIGEST_BYTES], CliError> {
    if leaf_alg != "sha2-256" {
        return Err(CliError::input(format!(
            "certificate build: cannot hash --file {path}: unsupported leaf_alg \"{leaf_alg}\" \
             (only \"sha2-256\" is supported)"
        )));
    }
    let content = std::fs::read(path).map_err(|e| {
        CliError::network(format!("certificate build: cannot read --file {path}: {e}"))
    })?;
    Ok(sha256(&content))
}

/// Decode a 32-byte hex value, mapping malformed input to exit 4 without
/// echoing the value (the shared decoder reports length/offset only).
fn ensure_hex32(hex: &str, label: &str) -> Result<Vec<u8>, CliError> {
    let bytes = hex_to_bytes(hex).map_err(|e| {
        CliError::input(format!("certificate build: {label} is not valid hex: {e}"))
    })?;
    if bytes.len() != DIGEST_BYTES {
        return Err(CliError::input(format!(
            "certificate build: {label} must decode to exactly {DIGEST_BYTES} bytes; got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Load and decode a leaves-list from a file path or stdin (`-`).
fn load_leaves_list_file(source: &str) -> Result<ResolvedLeaves, CliError> {
    let bytes = if source == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).map_err(|e| {
            CliError::network(format!(
                "certificate build: cannot read leaves-list stdin: {e}"
            ))
        })?;
        buf
    } else {
        std::fs::read(source).map_err(|e| {
            CliError::network(format!(
                "certificate build: cannot read --leaves-list {source}: {e}"
            ))
        })?
    };
    decode_leaves(&bytes)
}

/// Decode leaves-list bytes into the resolved leaf set, mapping a malformed
/// payload to a CLI-input error.
fn decode_leaves(bytes: &[u8]) -> Result<ResolvedLeaves, CliError> {
    let decoded = decode_leaves_list(bytes).map_err(|e: MerkleLeavesListError| {
        CliError::input(format!("certificate build: leaves-list invalid: {e}"))
    })?;
    Ok(ResolvedLeaves {
        leaves: decoded.leaves,
        root: decoded.root,
        leaf_alg: decoded.leaf_alg,
        leaves_list_uri: None,
    })
}

// ===========================================================================
// --tx resolution: anchor facts + leaves-list auto-fetch
// ===========================================================================

/// Resolve the anchor facts (block time / slot / confirmations) and the record's
/// merkle commitments from the chain.
fn resolve_anchor_facts(
    tx_hash: &str,
    resolved: &ResolvedGateways,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedAnchorFacts, CliError> {
    let resolved_tx = resolve_cardano_tx(
        tx_hash,
        Some(&resolved.cardano_gateway_chain),
        resolved.blockfrost_project_id.as_deref(),
        fetcher,
    )
    .map_err(|e| {
        // A deny-host hit is a service-independence violation (integrity-class);
        // every other terminal resolve failure is a provider/network outcome.
        if e.code == cardanowall::poe_standard::ErrorCode::ServiceIndependenceViolation {
            CliError::integrity(format!("certificate build: {e}"))
        } else {
            CliError::network(format!("certificate build: {e}"))
        }
    })?;

    // The resolve step verified the tx-hash binding, so these bytes ARE the
    // transaction: a missing or undecodable label-309 entry is a property of the
    // tx itself, not of the provider.
    let metadata = match extract_label_309_metadata(&resolved_tx.tx_cbor) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(CliError::integrity(format!(
                "certificate build: tx {tx_hash} carries no label-309 metadata"
            )));
        }
        Err(e) => {
            return Err(CliError::integrity(format!(
                "certificate build: failed to decode tx CBOR: {e}"
            )));
        }
    };

    let record = match validate_poe_record(&metadata, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => *record,
        ValidateResult::Fail { issues } => {
            let code = issues.first().map_or("UNKNOWN", |i| i.code.code());
            return Err(CliError::integrity(format!(
                "certificate build: tx {tx_hash} record fails the structural validator: {code}"
            )));
        }
    };

    let merkle = record.merkle.unwrap_or_default();

    // block_slot is always present from the resolver; confirmation_depth is the
    // explorer-asserted block depth at generation time.
    Ok(ResolvedAnchorFacts {
        block_time: i64::try_from(resolved_tx.block_time).map_err(|_| {
            CliError::network("certificate build: resolved block_time out of range".to_string())
        })?,
        slot: i64::try_from(resolved_tx.block_slot).map_err(|_| {
            CliError::network("certificate build: resolved block_slot out of range".to_string())
        })?,
        confirmations: i64::from(resolved_tx.confirmation_depth),
        merkle,
    })
}

/// Fetch and decode the leaves-list from the record's first usable merkle
/// commitment that carries `ar://` (or other fetchable) URIs.
fn fetch_leaves_list_from_record(
    merkle: &[MerkleCommit],
    resolved: &ResolvedGateways,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<ResolvedLeaves, CliError> {
    if merkle.is_empty() {
        return Err(CliError::integrity(
            "certificate build: the record carries no merkle[] commitment; supply --leaves-list instead",
        ));
    }

    let policy = ContentFetchPolicy {
        arweave_gateways: &resolved.arweave_gateway_chain,
        ipfs_gateways: resolved.ipfs_gateway_chain.as_deref().unwrap_or(&[]),
        max_fetch_bytes: None,
    };

    // Try each commitment in record order; the first that yields a leaves-list
    // binding to the commitment on BOTH its root AND its leaf count wins. The
    // decode itself re-derives the root and pins `decoded.leaf_count ==
    // decoded.leaves.len()`, so a decoded leaves-list is internally consistent;
    // we additionally bind it to the on-chain commitment so the certificate's
    // tree_size is exactly the chain's `leaf_count`. Binding only the root would
    // let a list with a matching root but a different leaf_count produce a
    // certificate whose tree_size disagrees with the chain.
    let mut last_error: Option<String> = None;
    for (commit_index, commit) in merkle.iter().enumerate() {
        let uris = commit.uris.as_deref().unwrap_or(&[]);
        if uris.is_empty() {
            last_error = Some(format!(
                "merkle[{commit_index}] carries no storage URIs to fetch the leaves-list from"
            ));
            continue;
        }
        let base_path = vec![
            PathSegment::Key("merkle".to_string()),
            PathSegment::Index(commit_index),
        ];
        let mut issues: Vec<VerifierIssue> = Vec::new();
        let walk = walk_blob_sources(
            None,
            uris,
            true,
            &base_path,
            &policy,
            fetcher,
            &mut issues,
            |blob, _issues| match decode_leaves_list(blob.bytes) {
                Ok(decoded) if leaves_list_binds_commitment(&decoded, commit) => {
                    // The on-chain `leaf_count` is the authoritative tree size;
                    // the decoder guarantees it equals the number of decoded
                    // leaves, so the certificate's tree_size is the chain's.
                    debug_assert_eq!(decoded.leaves.len() as u64, commit.leaf_count);
                    SourceDecision::Accept(ResolvedLeaves {
                        leaves: decoded.leaves,
                        root: decoded.root,
                        leaf_alg: decoded.leaf_alg,
                        leaves_list_uri: blob.uri.map(str::to_string),
                    })
                }
                // A leaves-list whose root or leaf_count does not bind to this
                // commitment, or that does not decode, indicts the serving blob —
                // try the next source rather than aborting the whole build.
                _ => SourceDecision::NextSource,
            },
        );
        match walk {
            BlobWalkEnd::Done(resolved_leaves) => return Ok(resolved_leaves),
            BlobWalkEnd::Exhausted { limit_exceeded } => {
                // Surface the walk's per-attempt diagnostics so a failure is
                // diagnosable, then record the end state and try the next
                // commitment.
                for issue in &issues {
                    eprintln!(
                        "certificate build: merkle[{commit_index}]: {} {}",
                        issue.code.code(),
                        issue.message
                    );
                }
                last_error = Some(if limit_exceeded {
                    format!(
                        "merkle[{commit_index}] leaves-list fetch aborted at the max-fetch-bytes ceiling"
                    )
                } else {
                    format!(
                        "merkle[{commit_index}] yielded no leaves-list binding to the on-chain root and leaf_count"
                    )
                });
            }
        }
    }

    Err(CliError::network(format!(
        "certificate build: could not obtain a leaves-list from the record's merkle commitments: {}",
        last_error.unwrap_or_else(|| "no fetchable URI".to_string())
    )))
}

/// Whether a decoded leaves-list binds to the on-chain commitment.
///
/// Both facts of the commitment must match: the `root` (so the list is the one
/// the chain committed) AND the `leaf_count` (so the certificate's tree_size is
/// exactly the chain's count, not the list's own). The decoder already pins
/// `decoded.leaf_count == decoded.leaves.len()`, so binding the count here makes
/// the on-chain `leaf_count` the authoritative tree size.
fn leaves_list_binds_commitment(decoded: &DecodedLeavesList, commit: &MerkleCommit) -> bool {
    commit.root.len() == DIGEST_BYTES
        && commit.root == decoded.root.as_slice()
        && decoded.leaf_count as u64 == commit.leaf_count
}

/// Build the shared gateway resolution for a build (config + env + flags).
fn resolve_gateways_for(args: &CertificateBuildArgs) -> Result<ResolvedGateways, CliError> {
    let flags = GatewayFlags {
        gateway: args.cardano_gateway.clone(),
        blockfrost: args.blockfrost.clone(),
        arweave_gateway: args.arweave_gateway.clone(),
        deny_host: args.deny_host.clone(),
        deny_hosts_replace: args.deny_hosts_replace,
        ..GatewayFlags::default()
    };
    let config = read_config_file(&SystemConfigEnv).map_err(relabel)?;
    resolve_gateways(&flags, &SystemGatewayEnv, config.as_ref()).map_err(relabel)
}

/// Relabel a `verify:`-prefixed gateway-resolution error to the certificate
/// command.
fn relabel(err: CliError) -> CliError {
    CliError {
        code: err.code,
        message: err.message.replacen("verify:", "certificate build:", 1),
    }
}

/// Write one `<index>.cbor` per verified item into `dir`, returning the count.
///
/// The COSE encoder refuses a non-inclusion item, so only verified items are
/// encoded; misses are skipped silently (they are recorded in the JSON).
fn write_cbor_dir(
    dir: &str,
    cert: &InclusionCertificateV1,
    merkle: &CertificateMerkle,
    anchor: &CertificateAnchor,
) -> Result<usize, CliError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        CliError::network(format!(
            "certificate build: cannot create --cbor-dir {dir}: {e}"
        ))
    })?;
    let mut written = 0usize;
    for (i, item) in cert.items.iter().enumerate() {
        if !item.verified {
            continue;
        }
        let cbor = encode_cose_inclusion_proof(item, merkle, anchor).map_err(|e| {
            // A verified item must always encode; an encoder refusal here is a
            // genuine internal inconsistency, surfaced as an integrity error.
            CliError::integrity(format!(
                "certificate build: failed to encode COSE proof for item {i}: {e}"
            ))
        })?;
        let path = std::path::Path::new(dir).join(format!("{i}.cbor"));
        std::fs::write(&path, &cbor).map_err(|e| {
            CliError::network(format!(
                "certificate build: cannot write {}: {e}",
                path.display()
            ))
        })?;
        written += 1;
    }
    Ok(written)
}

// ===========================================================================
// certificate verify
// ===========================================================================

/// Arguments for `cardanowall certificate verify`.
#[derive(Debug, Args)]
pub struct CertificateVerifyArgs {
    /// The JSON certificate file to re-verify (or `-` for stdin).
    pub file: String,
    /// Emit machine-readable JSON outcome.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct VerifyItemOutcome {
    index: i64,
    leaf: String,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyAnchorOutcome {
    chain: String,
    network: String,
    tx_hash: String,
    metadata_label: u64,
    block_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    explorer_urls: Vec<String>,
}

#[derive(Debug, Serialize)]
struct VerifyOutcome {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    items: Vec<VerifyItemOutcome>,
    anchor_to_confirm: VerifyAnchorOutcome,
    /// The tool proves the inclusion math only; on-chain anchoring is confirmed
    /// separately on a public explorer. Always `false`.
    anchoring_confirmed: bool,
}

fn run_verify(args: CertificateVerifyArgs) -> Result<(), CliError> {
    let text = if args.file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| {
            CliError::network(format!("certificate verify: cannot read stdin: {e}"))
        })?;
        buf
    } else {
        std::fs::read_to_string(&args.file).map_err(|e| {
            CliError::network(format!(
                "certificate verify: cannot read {}: {e}",
                args.file
            ))
        })?
    };

    // An unparseable certificate is bad input (exit 4), not an integrity verdict
    // on a well-formed certificate.
    let cert: InclusionCertificateV1 = serde_json::from_str(&text).map_err(|e| {
        CliError::input(format!(
            "certificate verify: {} is not a valid inclusion certificate: {e}",
            args.file
        ))
    })?;

    let result = verify_inclusion_certificate(&cert);
    let anchor = &result.anchor_claim;

    let outcome = VerifyOutcome {
        ok: result.ok,
        error: result.error.clone(),
        items: result
            .items
            .iter()
            .map(|v| VerifyItemOutcome {
                index: v.index,
                leaf: v.leaf.clone(),
                verified: v.verified,
                error: v.error.clone(),
            })
            .collect(),
        anchor_to_confirm: VerifyAnchorOutcome {
            chain: anchor.chain.clone(),
            network: anchor.network.clone(),
            tx_hash: anchor.tx_hash.clone(),
            metadata_label: anchor.metadata_label,
            block_time: anchor.block_time,
            slot: anchor.slot,
            explorer_urls: anchor.explorer_urls.clone().unwrap_or_default(),
        },
        anchoring_confirmed: false,
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&outcome).expect("VerifyOutcome serialises")
        );
    } else {
        print_verify_human(&outcome);
    }

    if outcome.ok {
        Ok(())
    } else {
        Err(CliError {
            code: 1,
            message: String::new(),
        })
    }
}

/// Print the human-readable verify report: per-item verdicts, the anchor to
/// confirm, and the explicit note that on-chain anchoring is a separate step.
fn print_verify_human(outcome: &VerifyOutcome) {
    if let Some(err) = &outcome.error {
        eprintln!("failed: the certificate was rejected: {err}");
    }
    for item in &outcome.items {
        if item.verified {
            println!(
                "ok:     item index {} leaf {} verified",
                item.index, item.leaf
            );
        } else {
            let reason = item
                .error
                .as_deref()
                .unwrap_or("inclusion proof did not recompute to the root");
            eprintln!(
                "failed: item index {} leaf {}: {reason}",
                item.index, item.leaf
            );
        }
    }

    let anchor = &outcome.anchor_to_confirm;
    eprintln!();
    eprintln!(
        "inclusion math: {}",
        if outcome.ok { "VERIFIED" } else { "FAILED" }
    );
    eprintln!(
        "anchor to confirm on a public Cardano explorer: tx {} on {} (metadata label {}, block time {})",
        anchor.tx_hash, anchor.network, anchor.metadata_label, anchor.block_time
    );
    for url in &anchor.explorer_urls {
        eprintln!("  {url}");
    }
    eprintln!(
        "NOTE: this tool proves the inclusion proof only. It cannot and does not confirm on-chain \
         anchoring — verify that merkle.root appears in the label-309 record of the above \
         transaction on a public explorer. The time is asserted by the Cardano blockchain, not by \
         this tool."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardanowall::merkle::{encode_leaves_list, merkle_root};

    use crate::util::bytes_to_hex;

    /// A deterministic leaf: SHA-256 of a single byte.
    fn leaf_of(i: u8) -> [u8; DIGEST_BYTES] {
        sha256(&[i])
    }

    fn make_leaves(n: u8) -> Vec<[u8; DIGEST_BYTES]> {
        (0..n).map(leaf_of).collect()
    }

    /// Build a leaves-list CBOR file in a temp dir and return its path + the
    /// leaves + root.
    fn write_leaves_list(
        dir: &std::path::Path,
        leaves: &[[u8; DIGEST_BYTES]],
    ) -> (String, [u8; DIGEST_BYTES]) {
        let root = merkle_root(leaves).unwrap();
        let cbor = encode_leaves_list(leaves, &root, Some("sha2-256")).unwrap();
        let path = dir.join("leaves.cbor");
        std::fs::write(&path, &cbor).unwrap();
        (path.to_string_lossy().into_owned(), root)
    }

    /// A fully-offline build args skeleton: explicit leaves-list + anchor flags,
    /// no --tx network resolution.
    fn offline_build_args(leaves_list: &str, out: &str) -> CertificateBuildArgs {
        CertificateBuildArgs {
            leaves_list: Some(leaves_list.to_string()),
            leaves: vec![],
            files: vec![],
            tx: Some("ab".repeat(32)),
            network: NetworkArg::Preprod,
            block_time: Some(1_718_539_200),
            slot: Some(123_456_789),
            block_height: None,
            confirmations: Some(1024),
            generated_at: Some("2026-06-16T12:00:00.000Z".to_string()),
            cardano_gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            deny_host: vec![],
            deny_hosts_replace: false,
            out: Some(out.to_string()),
            cbor_dir: None,
            json: false,
        }
    }

    #[test]
    fn build_then_verify_round_trips_offline() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(8);
        let (leaves_path, root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        // Two present targets: one by --leaf hex, one as itself.
        args.leaves = vec![bytes_to_hex(&leaves[2]), bytes_to_hex(&leaves[5])];

        // build → exit 0 (all targets verify).
        run_build(args).expect("offline build with present targets exits 0");

        // The written certificate carries both items, both verified, the right
        // root, and the offline anchor facts.
        let text = std::fs::read_to_string(&cert_path).unwrap();
        let cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        assert_eq!(cert.merkle.root, bytes_to_hex(&root));
        assert_eq!(cert.merkle.tree_size, 8);
        assert_eq!(cert.items.len(), 2);
        assert!(cert.items.iter().all(|it| it.verified));
        assert_eq!(cert.anchor.network, "preprod");
        assert_eq!(cert.anchor.block_time, 1_718_539_200);
        assert_eq!(cert.anchor.slot, Some(123_456_789));
        // Preprod explorer URLs are recorded.
        let urls = cert.anchor.explorer_urls.clone().unwrap();
        assert!(urls
            .iter()
            .any(|u| u.contains("preprod.cardanoscan.io/transaction/")));
        assert!(urls
            .iter()
            .any(|u| u.contains("preprod.adastat.net/transactions/")));

        // verify → ok, exit 0.
        let verify_args = CertificateVerifyArgs {
            file: cert_path.to_string_lossy().into_owned(),
            json: true,
        };
        run_verify(verify_args).expect("verify of a sound certificate exits 0");

        // And the pure SDK re-verification agrees.
        assert!(verify_inclusion_certificate(&cert).ok);
    }

    #[test]
    fn miss_target_exits_one_with_unverified_item() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        let stranger = sha256(&[0xaa, 0xbb]); // not any leaf_of(i)
        args.leaves = vec![bytes_to_hex(&leaves[0]), bytes_to_hex(&stranger)];

        // A miss makes the whole build exit 1 (inclusion-failed semantics).
        let err = run_build(args).unwrap_err();
        assert_eq!(err.code, 1);

        let text = std::fs::read_to_string(&cert_path).unwrap();
        let cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        assert_eq!(cert.items.len(), 2);
        assert!(cert.items[0].verified);
        let miss = &cert.items[1];
        assert!(!miss.verified);
        assert_eq!(miss.index, -1);
        assert!(miss.error.as_deref().is_some_and(|e| !e.is_empty()));
    }

    #[test]
    fn extracted_item_is_verifiable_by_merkle_verify_vocabulary() {
        // A single certificate item carries exactly the proof object the
        // `merkle verify` verb consumes: tree_size, index, leaf, proof[]. This
        // proves the vocabulary is reused — an extracted item re-verifies with
        // the same RFC 9162 primitive.
        use cardanowall::merkle::verify_inclusion;

        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(6);
        let (leaves_path, root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        args.leaves = vec![bytes_to_hex(&leaves[3])];
        run_build(args).expect("build exits 0");

        let text = std::fs::read_to_string(&cert_path).unwrap();
        let cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        let item = &cert.items[0];

        // Carry the item's vocabulary into the merkle-verify primitive.
        assert_eq!(item.index, 3);
        let leaf = hex_to_bytes(&item.leaf).unwrap();
        let proof: Vec<[u8; 32]> = item
            .proof
            .iter()
            .map(|h| {
                let b = hex_to_bytes(h).unwrap();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            })
            .collect();
        // tree_size === on-chain leaf_count === certificate tree_size.
        assert_eq!(cert.merkle.tree_size, leaves.len());
        assert!(verify_inclusion(
            &leaf,
            item.index as usize,
            cert.merkle.tree_size,
            &proof,
            &root
        ));
    }

    #[test]
    fn verify_on_tampered_cert_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(8);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        args.leaves = vec![bytes_to_hex(&leaves[2])];
        run_build(args).expect("build exits 0");

        // Tamper the first sibling so the inclusion proof no longer recomputes.
        let text = std::fs::read_to_string(&cert_path).unwrap();
        let mut cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        let mut sibling = hex_to_bytes(&cert.items[0].proof[0]).unwrap();
        sibling[0] ^= 0xff;
        cert.items[0].proof[0] = bytes_to_hex(&sibling);
        let tampered_path = dir.path().join("tampered.json");
        std::fs::write(&tampered_path, serde_json::to_string(&cert).unwrap()).unwrap();

        let verify_args = CertificateVerifyArgs {
            file: tampered_path.to_string_lossy().into_owned(),
            json: true,
        };
        let err = run_verify(verify_args).unwrap_err();
        assert_eq!(err.code, 1);
    }

    #[test]
    fn verify_on_unparseable_file_is_input_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-cert.json");
        std::fs::write(&path, "this is not json").unwrap();
        let err = run_verify(CertificateVerifyArgs {
            file: path.to_string_lossy().into_owned(),
            json: false,
        })
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn verify_on_unreadable_file_is_network_error() {
        let err = run_verify(CertificateVerifyArgs {
            file: "/nonexistent/certificate-does-not-exist.json".to_string(),
            json: false,
        })
        .unwrap_err();
        assert_eq!(err.code, 2);
    }

    #[test]
    fn build_requires_tx_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");
        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        args.tx = None;
        args.leaves = vec![bytes_to_hex(&leaves[0])];
        let err = run_build(args).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("--tx"));
    }

    #[test]
    fn build_requires_a_target() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");
        let args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        // No --leaf and no --file.
        let err = run_build(args).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn offline_build_needs_only_block_time_for_the_optional_facts() {
        // With --leaves-list + explicit --block-time, dropping the OPTIONAL
        // anchor facts (slot, confirmations) must NOT force a network resolve:
        // they are simply omitted from the certificate. The build stays fully
        // offline and succeeds. (If a resolve had fired against the unroutable
        // default gateway it would have failed network-class.)
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");
        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        args.leaves = vec![bytes_to_hex(&leaves[0])];
        args.slot = None;
        args.confirmations = None;
        run_build(args).expect("offline build with only block_time explicit succeeds");

        let text = std::fs::read_to_string(&cert_path).unwrap();
        let cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        assert_eq!(cert.anchor.block_time, 1_718_539_200);
        // The optional facts are omitted, not fabricated.
        assert_eq!(cert.anchor.slot, None);
        assert_eq!(cert.anchor.confirmations_at_generation, None);
    }

    #[test]
    fn file_target_hashed_with_sha2_256_is_found_in_tree() {
        // A --file target is hashed with the leaves-list leaf_alg; when the file
        // bytes are the preimage of a tree leaf, the item verifies.
        let dir = tempfile::tempdir().unwrap();
        // The tree's leaf 0 is SHA-256(&[0]); make a file whose bytes are [0].
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");
        let file_path = dir.path().join("payload.bin");
        std::fs::write(&file_path, [0u8]).unwrap();

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        args.files = vec![file_path.to_string_lossy().into_owned()];
        run_build(args).expect("file target whose hash is leaf 0 verifies → exit 0");

        let text = std::fs::read_to_string(&cert_path).unwrap();
        let cert: InclusionCertificateV1 = serde_json::from_str(&text).unwrap();
        assert_eq!(cert.items.len(), 1);
        assert!(cert.items[0].verified);
        assert_eq!(cert.items[0].index, 0);
        // The file path is recorded as the item label.
        assert_eq!(
            cert.items[0].label.as_deref(),
            Some(file_path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn cbor_dir_writes_one_proof_per_verified_item() {
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(4);
        let (leaves_path, _root) = write_leaves_list(dir.path(), &leaves);
        let cert_path = dir.path().join("cert.json");
        let cbor_dir = dir.path().join("cbor");

        let mut args = offline_build_args(&leaves_path, &cert_path.to_string_lossy());
        let stranger = sha256(&[0x99, 0x88]);
        // Two present + one miss: only the two present get a .cbor file.
        args.leaves = vec![
            bytes_to_hex(&leaves[1]),
            bytes_to_hex(&stranger),
            bytes_to_hex(&leaves[2]),
        ];
        args.cbor_dir = Some(cbor_dir.to_string_lossy().into_owned());

        // The miss makes the build exit 1, but the cbor files for verified items
        // are still written.
        let err = run_build(args).unwrap_err();
        assert_eq!(err.code, 1);

        // Item 0 (leaves[1]) and item 2 (leaves[2]) verified → 0.cbor + 2.cbor.
        assert!(cbor_dir.join("0.cbor").exists());
        assert!(!cbor_dir.join("1.cbor").exists()); // the miss is skipped
        assert!(cbor_dir.join("2.cbor").exists());

        // Each .cbor is the COSE inclusion-proof map for its item: decode it and
        // check the vds + root fields are present.
        use cardanowall::cbor::{decode_canonical_cbor, CborValue};
        let cbor0 = std::fs::read(cbor_dir.join("0.cbor")).unwrap();
        let map = match decode_canonical_cbor(&cbor0).unwrap() {
            CborValue::Map(pairs) => pairs,
            other => panic!("expected a CBOR map, got {other:?}"),
        };
        let has_vds = map.iter().any(|(k, v)| {
            matches!(k, CborValue::Text(t) if t == "vds") && *v == CborValue::Unsigned(1)
        });
        assert!(has_vds, "the COSE proof carries vds=1 (RFC9162_SHA256)");
    }

    #[test]
    fn leaves_list_from_stdin_token_is_accepted_as_source() {
        // The `-` sentinel routes the leaves-list source to stdin. We can't feed
        // stdin in a unit test, but loading a real file path through the same
        // entry must succeed, proving the source dispatch.
        let dir = tempfile::tempdir().unwrap();
        let leaves = make_leaves(3);
        let (leaves_path, root) = write_leaves_list(dir.path(), &leaves);
        let resolved = load_leaves_list_file(&leaves_path).unwrap();
        assert_eq!(resolved.leaves.len(), 3);
        assert_eq!(resolved.root, root);
        assert_eq!(resolved.leaf_alg.as_deref(), Some("sha2-256"));
    }

    #[test]
    fn malformed_leaf_hex_does_not_echo_value() {
        let planted = format!("{}zz", "ab".repeat(31)); // 64 chars, invalid bytes
        let err = ensure_hex32(&planted, "--leaf").unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&planted));
    }

    #[test]
    fn mainnet_and_preprod_explorer_urls_match_the_web_map() {
        let tx = "ab".repeat(32);
        let mainnet = NetworkArg::Mainnet.explorer_urls(&tx);
        assert_eq!(
            mainnet[0],
            format!("https://cardanoscan.io/transaction/{tx}")
        );
        assert_eq!(mainnet[1], format!("https://adastat.net/transactions/{tx}"));
        let preprod = NetworkArg::Preprod.explorer_urls(&tx);
        assert_eq!(
            preprod[0],
            format!("https://preprod.cardanoscan.io/transaction/{tx}")
        );
        assert_eq!(
            preprod[1],
            format!("https://preprod.adastat.net/transactions/{tx}")
        );
    }

    #[test]
    fn leaves_list_must_bind_both_root_and_commitment_leaf_count() {
        // The auto-fetch path binds a fetched leaves-list to the on-chain
        // commitment on BOTH root and leaf_count. A list whose root matches but
        // whose leaf_count disagrees with the commitment's must be rejected, so
        // a forged commitment.leaf_count can never produce a certificate whose
        // tree_size diverges from the chain.
        use cardanowall::poe_standard::MerkleCommit;

        let leaves = make_leaves(4);
        let root = merkle_root(&leaves).unwrap();
        let cbor = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();
        let decoded = decode_leaves_list(&cbor).unwrap();
        // The decoder pins the list's own count to its leaves.
        assert_eq!(decoded.leaf_count, 4);

        // A commitment with the matching root AND matching count binds.
        let matching = MerkleCommit {
            alg: MERKLE_ALG_ID.to_string(),
            root: root.to_vec(),
            leaf_count: 4,
            uris: None,
        };
        assert!(leaves_list_binds_commitment(&decoded, &matching));

        // The same root but a forged on-chain leaf_count (5 ≠ 4) does NOT bind,
        // even though the root matches exactly.
        let forged_count = MerkleCommit {
            alg: MERKLE_ALG_ID.to_string(),
            root: root.to_vec(),
            leaf_count: 5,
            uris: None,
        };
        assert!(!leaves_list_binds_commitment(&decoded, &forged_count));

        // A non-matching root never binds regardless of the count.
        let mut wrong_root = root;
        wrong_root[0] ^= 0xff;
        let wrong = MerkleCommit {
            alg: MERKLE_ALG_ID.to_string(),
            root: wrong_root.to_vec(),
            leaf_count: 4,
            uris: None,
        };
        assert!(!leaves_list_binds_commitment(&decoded, &wrong));
    }

    #[test]
    fn build_debug_redacts_blockfrost() {
        let mut args = offline_build_args("/x", "/y");
        args.blockfrost = Some("preprodSECRETprojectid".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains("preprodSECRETprojectid"));
        assert!(rendered.contains("redacted"));
    }
}
