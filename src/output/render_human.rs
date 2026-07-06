//! Human-readable transcript of a [`VerifyReport`].
//!
//! A read-only renderer of the verifier report into a structured transcript. The
//! rendered transcript goes to stdout; diagnostics belong on stderr (the caller's
//! concern). The field labels mirror the wire-shaped report so a reader can map
//! the human view back to the `--json` output one-to-one: the record's claimed
//! hashes / URIs / supersedes pointer, the flat issue list, the positional
//! `items[]` / `merkle[]` per-claim entries, and the audit trail. An absent
//! confirmation depth (or block time) renders as `unknown` / is omitted — the
//! verifier never fabricates a chain fact, and neither does this view.

use cardanowall::poe_standard::PoeRecord;
use cardanowall::verifier::{
    ItemReportEntry, MerkleReportEntry, SignatureCheck, VerifierIssue, VerifyReport,
};

use crate::util::bytes_to_hex;

/// Render the report as a multi-line human transcript on stdout.
pub fn render_human_report(report: &VerifyReport) {
    // Single write; the builder terminates every line, so no extra newline.
    print!("{}", build_transcript(report));
}

/// Build the full human transcript for a report. Separated from the stdout
/// write so the rendering is directly testable on its string output.
fn build_transcript(report: &VerifyReport) -> String {
    let mut out = String::new();
    macro_rules! line {
        ($($arg:tt)*) => {{
            out.push_str(&format!($($arg)*));
            out.push('\n');
        }};
    }

    // The transaction hash is absent in local (`--record`) mode: there is no
    // transaction, so name the input as a local record rather than an empty line.
    let source = if report.tx_hash.is_empty() {
        "(local record)"
    } else {
        &report.tx_hash
    };
    line!("Transaction:    {source}");
    line!("Network:        {}", report.network);
    line!("Verdict:        {}", report.verdict.as_str());
    line!("Profile:        {}", report.profile.as_str());
    let depth = report
        .confirmation_depth
        .map_or_else(|| "unknown".to_string(), |d| d.to_string());
    line!(
        "Confirmations:  {}  (threshold: {})",
        depth,
        report.confirmation_threshold
    );
    if let Some(t) = report.block_time {
        line!("Block time:     {t}");
    }
    if let Some(s) = report.block_slot {
        line!("Block slot:     {s}");
    }
    line!("");

    render_record(report.record.as_ref(), &mut out);
    render_issues(&report.issues, &mut out);
    render_signatures(report.record_signatures.as_deref(), &mut out);
    render_items(&report.items, &mut out);
    render_merkle(&report.merkle, &mut out);
    render_audit_trail(report, &mut out);

    out
}

/// Render the record's own claims — the digest map per item, storage URIs, the
/// Merkle commitments, and the supersedes pointer — so a default-mode reader
/// sees the committed values, not only the per-claim check outcomes. Absent in
/// the pre-structural-failure reports that carry no decoded record.
fn render_record(record: Option<&PoeRecord>, out: &mut String) {
    let Some(record) = record else {
        return;
    };
    out.push_str("Record:\n");
    out.push_str(&format!("  version:      {}\n", record.v));
    if let Some(supersedes) = &record.supersedes {
        out.push_str(&format!("  supersedes:   {}\n", bytes_to_hex(supersedes)));
    }
    if let Some(items) = record.items.as_ref().filter(|i| !i.is_empty()) {
        out.push_str(&format!("  hashes ({}):\n", items.len()));
        for (i, item) in items.iter().enumerate() {
            let digests = item
                .hashes
                .iter()
                .map(|(alg, digest)| format!("{alg}={}", bytes_to_hex(digest)))
                .collect::<Vec<_>>()
                .join("  ");
            out.push_str(&format!("    [{i}]  {digests}\n"));
            if let Some(uris) = item.uris.as_ref().filter(|u| !u.is_empty()) {
                out.push_str(&format!("         uris: {}\n", uris.join("  ")));
            }
        }
    }
    if let Some(commits) = record.merkle.as_ref().filter(|m| !m.is_empty()) {
        out.push_str(&format!("  merkle ({}):\n", commits.len()));
        for (i, commit) in commits.iter().enumerate() {
            out.push_str(&format!(
                "    [{i}]  alg={}  root={}  leaf_count={}\n",
                commit.alg,
                bytes_to_hex(&commit.root),
                commit.leaf_count
            ));
            if let Some(uris) = commit.uris.as_ref().filter(|u| !u.is_empty()) {
                out.push_str(&format!("         uris: {}\n", uris.join("  ")));
            }
        }
    }
    out.push('\n');
}

/// Render an issue path as its dotted display form (empty path → `(record)`).
fn path_display(issue: &VerifierIssue) -> String {
    if issue.path.is_empty() {
        return "(record)".to_string();
    }
    issue
        .path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn render_issues(issues: &[VerifierIssue], out: &mut String) {
    if issues.is_empty() {
        out.push_str("Issues:         none\n");
    } else {
        out.push_str(&format!("Issues:         {}\n", issues.len()));
        for i in issues {
            out.push_str(&format!(
                "  - [{}] {} at {}: {}\n",
                severity_str(i.severity),
                i.code.code(),
                path_display(i),
                i.message
            ));
        }
    }
    out.push('\n');
}

fn severity_str(severity: cardanowall::poe_standard::Severity) -> &'static str {
    match severity {
        cardanowall::poe_standard::Severity::Error => "error",
        cardanowall::poe_standard::Severity::Warning => "warning",
        cardanowall::poe_standard::Severity::Info => "info",
    }
}

fn render_signatures(sigs: Option<&[SignatureCheck]>, out: &mut String) {
    let Some(sigs) = sigs.filter(|s| !s.is_empty()) else {
        return;
    };
    out.push_str(&format!("Signatures ({}):\n", sigs.len()));
    for s in sigs {
        let type_part = s
            .signer_type
            .map(|t| format!("signer_type={}  ", t.as_str()))
            .unwrap_or_default();
        out.push_str(&format!(
            "  [{}]  {}verdict={}\n",
            s.index,
            type_part,
            s.verdict_str()
        ));
        if let Some(pub_) = &s.signer_pub {
            out.push_str(&format!("       signer_pub={pub_}\n"));
        }
        if let Some(reason) = s.reason {
            out.push_str(&format!("       reason={}\n", reason.as_str()));
        }
    }
    out.push('\n');
}

fn render_items(items: &[ItemReportEntry], out: &mut String) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("Items ({}):\n", items.len()));
    for (i, entry) in items.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}]  content_check={}\n",
            entry.content_check.as_str()
        ));
        if let Some(d) = &entry.decryption {
            out.push_str(&format!("       decrypted={}\n", d.decrypted));
            if let Some(ok) = d.plaintext_hash_ok {
                out.push_str(&format!("       plaintext_hash_ok={ok}\n"));
            }
            if let Some(code) = d.code {
                out.push_str(&format!("       code={}\n", code.code()));
            }
        }
    }
    out.push('\n');
}

fn render_merkle(entries: &[MerkleReportEntry], out: &mut String) {
    if entries.is_empty() {
        return;
    }
    out.push_str(&format!("Merkle ({}):\n", entries.len()));
    for (i, entry) in entries.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}]  content_check={}\n",
            entry.content_check.as_str()
        ));
    }
    out.push('\n');
}

fn render_audit_trail(report: &VerifyReport, out: &mut String) {
    let calls = &report.audit_trail;
    out.push_str(&format!("HTTP audit ({} calls):\n", calls.len()));
    for c in calls {
        // A refused or transport-failed call has no HTTP status; render the
        // no-response reading explicitly rather than a fabricated code.
        let status = c.status.map_or_else(|| "-".to_string(), |s| s.to_string());
        out.push_str(&format!(
            "  {} {}  →  status={}  duration_ms={}\n",
            c.method.as_str(),
            c.url,
            status,
            c.duration_ms
        ));
    }
}

/// Render a 32-byte digest as lowercase hex (for any caller that needs it).
#[must_use]
pub fn digest_hex(bytes: &[u8]) -> String {
    bytes_to_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cardanowall::poe_standard::{ItemEntry, MerkleCommit, PoeRecord};
    use cardanowall::verifier::{Profile, Verdict, VerifyReport};

    fn report_with_record(record: Option<PoeRecord>) -> VerifyReport {
        VerifyReport {
            tx_hash: String::new(),
            verdict: Verdict::Valid,
            profile: Profile::Signed,
            network: "cardano:preprod",
            confirmation_threshold: 15,
            confirmation_depth: None,
            block_time: None,
            block_slot: None,
            issues: Vec::new(),
            items: Vec::new(),
            merkle: Vec::new(),
            audit_trail: Vec::new(),
            record,
            record_signatures: None,
            tx_witnesses: None,
            tx_summary: None,
            metadata_labels: None,
        }
    }

    #[test]
    fn record_section_shows_claimed_hashes_uris_and_supersedes() {
        let digest = vec![0x11_u8; 32];
        let prior_tx = vec![0xab_u8; 32];
        let record = PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![
                    ("sha2-256".to_string(), digest.clone()),
                    ("blake2b-256".to_string(), vec![0x22_u8; 32]),
                ],
                uris: Some(vec!["ar://the-content-tx-id".to_string()]),
                enc: None,
            }]),
            merkle: None,
            supersedes: Some(prior_tx.clone()),
            sigs: None,
            crit: None,
            extensions: Vec::new(),
        };
        let transcript = build_transcript(&report_with_record(Some(record)));

        // The claimed digest, its algorithm, the storage URI, and the
        // supersedence pointer all appear in the default (non-JSON) view.
        assert!(transcript.contains(&bytes_to_hex(&digest)));
        assert!(transcript.contains("sha2-256"));
        assert!(transcript.contains("blake2b-256"));
        assert!(transcript.contains("ar://the-content-tx-id"));
        assert!(transcript.contains(&bytes_to_hex(&prior_tx)));
        assert!(transcript.contains("supersedes"));
    }

    #[test]
    fn record_section_shows_merkle_commitment_claims() {
        let root = vec![0x33_u8; 32];
        let record = PoeRecord {
            v: 1,
            items: None,
            merkle: Some(vec![MerkleCommit {
                alg: "cardano-poe-merkle-sha256-v1".to_string(),
                root: root.clone(),
                leaf_count: 7,
                uris: Some(vec!["ipfs://bafyleaves".to_string()]),
            }]),
            supersedes: None,
            sigs: None,
            crit: None,
            extensions: Vec::new(),
        };
        let transcript = build_transcript(&report_with_record(Some(record)));

        assert!(transcript.contains("cardano-poe-merkle-sha256-v1"));
        assert!(transcript.contains(&bytes_to_hex(&root)));
        assert!(transcript.contains("leaf_count=7"));
        assert!(transcript.contains("ipfs://bafyleaves"));
    }

    #[test]
    fn no_record_section_and_local_source_label_when_record_absent() {
        // A report with no decoded record (a pre-structural failure) omits the
        // record section; an empty tx hash renders as the local-record label.
        let transcript = build_transcript(&report_with_record(None));
        assert!(!transcript.contains("Record:"));
        assert!(transcript.contains("(local record)"));
        // An absent confirmation depth reads as unknown, never a fabricated value.
        assert!(transcript.contains("Confirmations:  unknown"));
    }
}
