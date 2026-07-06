//! The `seal --resume` state file: a machine-readable record of a sealed
//! publish that failed AFTER a prepared seal existed — often after paying for
//! some or all of its Arweave uploads — so the publish can be finished without
//! re-encrypting the content or re-paying storage.
//!
//! Recipient-sealed only. A passphrase seal derives its content key from the
//! passphrase and persists NO key material, so it has no resumable artifact and
//! writes no state file.
//!
//! ## Secret-safety
//!
//! The file carries ONLY material that is already public once the record
//! anchors: the SDK's `prepared_seal_json_v1` document (the record header,
//! per-recipient KEM slots, and the ciphertext — the content key is wrapped to
//! the recipients, never stored), the completed upload receipts (public Arweave
//! URIs and ciphertext digests), the input file names, and the non-secret
//! publish parameters. It NEVER carries the identity seed, a passphrase, the API
//! key, or any key-derived material beyond what the SDK's own `to_json` emits.
//!
//! ## Zero authority
//!
//! The file is written into the working directory (or a CI workspace) where an
//! attacker who can hand a victim a "here, resume this" file can also edit it,
//! so NOTHING in it is trusted as authority:
//!
//! - The `gateway_base_url` never selects the endpoint. At resume the gateway is
//!   resolved from trusted sources only (flag > env > profile, exactly as a
//!   fresh run) and the persisted URL is a consistency check against it — a
//!   tampered URL is refused, never adopted (see [`check_gateway_target`]).
//! - `prepared_sha256` is the file's own integrity tag over the `prepared_seal`
//!   string, rejected on mismatch at load — it catches corruption and casual
//!   edits (a determined attacker can recompute it, so it is not the real
//!   defense).
//! - The load-bearing defense lives in the command: at resume the prepared
//!   seal's hash claims are re-derived from the user's OWN input files, so a
//!   swapped `prepared_seal` cannot publish unless it commits to the user's
//!   exact plaintext.
//!
//! The schema version stays `1`: the format only GAINS the required
//! `prepared_sha256` field, and the loader refuses a file that lacks it.

use std::path::{Path, PathBuf};

use cardanowall::client::{PreparedSeal, UploadReceipt};
use cardanowall::hash::sha256;
use serde::{Deserialize, Serialize};

use crate::util::{bytes_to_hex, hex_to_bytes, CliError};

/// The self-describing format tag the resume-state file carries.
pub const RESUME_FORMAT: &str = "label-309-seal-resume";
/// The schema version. A file that declares any other version is refused (exit
/// `4`) rather than being read with a mismatched interpretation.
pub const RESUME_VERSION: u32 = 1;
/// The resume-state filename extension (after the seal-fingerprint stem).
pub const RESUME_EXTENSION: &str = "l309-seal-resume.json";

/// One completed ciphertext upload, in the resume file's own shape. Mirrors the
/// SDK's [`UploadReceipt`] with the 32-byte digest hex-encoded for the JSON
/// document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeUpload {
    /// The prepared item this receipt covers (its ciphertext's SHA-256, hex).
    pub item_id: String,
    /// The storage URI the upload committed (`ar://<43-char txid>`).
    pub uri: String,
    /// The lowercase-hex SHA-256 of the uploaded ciphertext.
    pub ciphertext_sha256: String,
    /// The uploaded byte count.
    pub bytes: u64,
}

/// The `seal --resume` state document.
///
/// Not `deny_unknown_fields`: a newer producer may add fields, and this reader
/// still parses the shared core and reports a clean version mismatch rather than
/// an opaque parse error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealResumeState {
    /// The format tag ([`RESUME_FORMAT`]).
    pub format: String,
    /// The schema version ([`RESUME_VERSION`]).
    pub version: u32,
    /// The SDK's canonical `prepared_seal_json_v1` document, verbatim — the
    /// authenticated, self-verifying prepared seal the resume finishes.
    pub prepared_seal: String,
    /// The lowercase-hex SHA-256 of the [`prepared_seal`](Self::prepared_seal)
    /// string — the file's own integrity tag over it, required and verified at
    /// load. Required (a file lacking it is refused).
    pub prepared_sha256: String,
    /// The completed upload receipts, in item order.
    pub uploads: Vec<ResumeUpload>,
    /// The input file names, in item order — used both to re-derive the prepared
    /// seal's hash claims from the user's own files at resume and to map each
    /// item back to its source file in the summary.
    pub files: Vec<String>,
    /// The 64-hex transaction hash this record supersedes, when any. Not derived
    /// from the user's files, so a resume surfaces it in the pre-publish summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Whether the original run requested a record signature. A signed resume
    /// re-requires the seed (never persisted); an unsigned one never signs. Not
    /// derived from the user's files, so a resume surfaces it in the summary.
    pub signed: bool,
    /// Whether the original run added a self slot (`--to-self`) — a display-only
    /// fact echoed so the resumed receipt matches the original.
    pub to_self: bool,
    /// The gateway base URL the original run resolved. Carries ZERO authority: at
    /// resume it is only a consistency check against the gateway independently
    /// resolved from trusted sources (see [`check_gateway_target`]). Never a key.
    pub gateway_base_url: String,
}

impl SealResumeState {
    /// Load and validate a resume-state file.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] (exit `4`) when the file is missing, is not valid
    /// JSON for the schema (including a missing `prepared_sha256`), carries an
    /// unrecognized format tag, declares a version this CLI does not implement,
    /// or fails the `prepared_sha256` integrity check.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            CliError::input(format!(
                "seal --resume: cannot read the resume-state file {}: {e}",
                path.display()
            ))
        })?;
        let state: SealResumeState = serde_json::from_str(&text).map_err(|e| {
            CliError::input(format!(
                "seal --resume: {} is not a valid resume-state file: {e}",
                path.display()
            ))
        })?;
        if state.format != RESUME_FORMAT {
            return Err(CliError::input(format!(
                "seal --resume: {} is not a Label 309 seal resume-state file (format {:?})",
                path.display(),
                state.format
            )));
        }
        if state.version != RESUME_VERSION {
            return Err(CliError::input(format!(
                "seal --resume: {} declares resume-state version {}, but this CLI understands \
                 version {RESUME_VERSION} — upgrade the CLI to resume it",
                path.display(),
                state.version
            )));
        }
        // Integrity tag over the prepared-seal string: catches corruption and
        // casual edits. (A determined attacker can recompute it, so the
        // load-bearing tamper defense is the plaintext re-anchor in the command.)
        let expected = prepared_seal_digest(&state.prepared_seal);
        if state.prepared_sha256 != expected {
            return Err(CliError::input(format!(
                "seal --resume: {} fails its prepared-seal integrity check — the prepared_seal \
                 field was altered or corrupted. Refusing to resume.",
                path.display()
            )));
        }
        Ok(state)
    }

    /// Write the resume-state file (pretty JSON, trailing newline).
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] (exit `2`) when the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let json = serde_json::to_string_pretty(self).expect("resume state serialises");
        std::fs::write(path, format!("{json}\n")).map_err(|e| {
            CliError::network(format!(
                "seal: cannot write the resume-state file {}: {e}",
                path.display()
            ))
        })
    }
}

/// The default resume-state path: `<prepared-fingerprint>.l309-seal-resume.json`
/// in the current directory. Deterministic in the prepared seal's fingerprint,
/// so the same failed publish always maps to the same file.
#[must_use]
pub fn default_resume_path(prepared: &PreparedSeal) -> PathBuf {
    PathBuf::from(format!("{}.{RESUME_EXTENSION}", prepared.prepared_sha256()))
}

/// The lowercase-hex SHA-256 of the prepared-seal JSON string — the state file's
/// own integrity tag for the [`SealResumeState::prepared_seal`] field.
#[must_use]
pub fn prepared_seal_digest(prepared_seal: &str) -> String {
    bytes_to_hex(&sha256(prepared_seal.as_bytes()))
}

/// The persisted gateway URL carries ZERO authority: it is only a consistency
/// check against the gateway the resume independently resolved from trusted
/// sources (flag > env > profile — the same resolution a fresh publish uses). A
/// tampered state file therefore cannot redirect the authenticated publish (with
/// the real bearer key) to another endpoint — the mismatch is refused instead.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the trusted-resolved gateway differs from
/// the one the state was created against.
pub fn check_gateway_target(resolved_base: &str, state: &SealResumeState) -> Result<(), CliError> {
    if resolved_base != state.gateway_base_url {
        return Err(CliError::input(format!(
            "seal --resume: this resume state was created against {}; you are resuming against \
             {}. If that is intended, pass --base-url / --gateway-profile explicitly to select \
             the gateway.",
            state.gateway_base_url, resolved_base
        )));
    }
    Ok(())
}

/// Lower the SDK's completed upload receipts into the resume file's shape.
#[must_use]
pub fn from_sdk_receipts(uploads: &[UploadReceipt]) -> Vec<ResumeUpload> {
    uploads
        .iter()
        .map(|r| ResumeUpload {
            item_id: r.item_id.clone(),
            uri: r.uri.clone(),
            ciphertext_sha256: bytes_to_hex(&r.ciphertext_sha256),
            bytes: r.bytes,
        })
        .collect()
}

/// Reconstruct the SDK upload receipts a resume passes back to the submit path.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when a persisted `ciphertext_sha256` is not a
/// 32-byte lowercase-hex digest.
pub fn to_sdk_receipts(uploads: &[ResumeUpload]) -> Result<Vec<UploadReceipt>, CliError> {
    uploads
        .iter()
        .map(|u| {
            let digest = hex_to_bytes(&u.ciphertext_sha256).map_err(|e| {
                CliError::input(format!(
                    "seal --resume: upload receipt for {} has a malformed ciphertext_sha256: {e}",
                    u.item_id
                ))
            })?;
            let ciphertext_sha256: [u8; 32] = digest.try_into().map_err(|_| {
                CliError::input(format!(
                    "seal --resume: upload receipt for {} has a ciphertext_sha256 that is not 32 \
                     bytes",
                    u.item_id
                ))
            })?;
            Ok(UploadReceipt {
                item_id: u.item_id.clone(),
                uri: u.uri.clone(),
                ciphertext_sha256,
                bytes: u.bytes,
            })
        })
        .collect()
}

/// Merge freshly-completed receipts into the persisted set, keyed by `item_id`,
/// keeping the union so a rewrite never drops a previously-persisted receipt.
///
/// An item uploads at most once and its ciphertext is immutable, so the union by
/// `item_id` is monotonic: a resume that completes more uploads before failing
/// again grows the set; a resume that fails before any upload leaves it intact.
#[must_use]
pub fn merge_receipts(existing: &[ResumeUpload], fresh: &[UploadReceipt]) -> Vec<ResumeUpload> {
    let mut out = existing.to_vec();
    for receipt in fresh {
        if !out.iter().any(|u| u.item_id == receipt.item_id) {
            out.push(ResumeUpload {
                item_id: receipt.item_id.clone(),
                uri: receipt.uri.clone(),
                ciphertext_sha256: bytes_to_hex(&receipt.ciphertext_sha256),
                bytes: receipt.bytes,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> SealResumeState {
        let prepared_seal = "{}".to_string();
        SealResumeState {
            format: RESUME_FORMAT.to_string(),
            version: RESUME_VERSION,
            prepared_sha256: prepared_seal_digest(&prepared_seal),
            prepared_seal,
            uploads: vec![ResumeUpload {
                item_id: "aa".repeat(32),
                uri: format!("ar://{}", "T".repeat(43)),
                ciphertext_sha256: "bb".repeat(32),
                bytes: 42,
            }],
            files: vec!["a.bin".to_string()],
            supersedes: None,
            signed: false,
            to_self: false,
            gateway_base_url: "https://gw.example/api/v1".to_string(),
        }
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();
        state.save(&path).unwrap();
        let loaded = SealResumeState::load(&path).unwrap();
        assert_eq!(loaded.uploads.len(), 1);
        assert_eq!(loaded.gateway_base_url, state.gateway_base_url);
        assert_eq!(loaded.files, state.files);
    }

    #[test]
    fn load_rejects_an_unknown_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = sample_state();
        state.version = 999;
        state.save(&path).unwrap();
        let err = SealResumeState::load(&path).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("version 999"), "{}", err.message);
    }

    #[test]
    fn load_rejects_a_foreign_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = sample_state();
        state.format = "something-else".to_string();
        state.save(&path).unwrap();
        assert_eq!(SealResumeState::load(&path).unwrap_err().code, 4);
    }

    #[test]
    fn load_rejects_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let err = SealResumeState::load(&dir.path().join("nope.json")).unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn receipts_round_trip_through_the_sdk_shape() {
        let sdk = to_sdk_receipts(&sample_state().uploads).unwrap();
        assert_eq!(sdk.len(), 1);
        assert_eq!(sdk[0].bytes, 42);
        assert_eq!(sdk[0].ciphertext_sha256.to_vec(), vec![0xbbu8; 32]);
        let back = from_sdk_receipts(&sdk);
        assert_eq!(back[0].ciphertext_sha256, "bb".repeat(32));
    }

    #[test]
    fn to_sdk_receipts_rejects_a_short_digest() {
        let bad = vec![ResumeUpload {
            item_id: "aa".repeat(32),
            uri: format!("ar://{}", "T".repeat(43)),
            ciphertext_sha256: "bb".to_string(),
            bytes: 1,
        }];
        assert_eq!(to_sdk_receipts(&bad).unwrap_err().code, 4);
    }

    #[test]
    fn merge_receipts_keeps_the_union_and_dedupes_by_item() {
        let existing = sample_state().uploads;
        // A fresh receipt for a NEW item joins; a duplicate of an existing item
        // does not add a second entry.
        let fresh = vec![
            UploadReceipt {
                item_id: existing[0].item_id.clone(),
                uri: existing[0].uri.clone(),
                ciphertext_sha256: [0xbb; 32],
                bytes: 42,
            },
            UploadReceipt {
                item_id: "cc".repeat(32),
                uri: format!("ar://{}2", "T".repeat(42)),
                ciphertext_sha256: [0xdd; 32],
                bytes: 7,
            },
        ];
        let merged = merge_receipts(&existing, &fresh);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].item_id, "cc".repeat(32));
    }

    #[test]
    fn load_rejects_a_tampered_prepared_seal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = sample_state();
        // The integrity tag no longer covers the altered prepared_seal.
        state.prepared_seal = "{\"tampered\":true}".to_string();
        state.save(&path).unwrap();
        let err = SealResumeState::load(&path).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("integrity"), "{}", err.message);
    }

    #[test]
    fn load_rejects_a_file_missing_the_integrity_tag() {
        // A document without prepared_sha256 fails to deserialize (the field is
        // required), so an older state file that predates the tag is refused.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"format":"label-309-seal-resume","version":1,"prepared_seal":"{}",
               "uploads":[],"files":[],"signed":false,"to_self":false,
               "gateway_base_url":"https://gw.example/api/v1"}"#,
        )
        .unwrap();
        assert_eq!(SealResumeState::load(&path).unwrap_err().code, 4);
    }

    #[test]
    fn gateway_target_check_matches_and_rejects() {
        let state = sample_state();
        // The independently-resolved gateway must equal the persisted one.
        check_gateway_target(&state.gateway_base_url, &state).unwrap();
        let err = check_gateway_target("https://attacker.example/api/v1", &state).unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("created against"), "{}", err.message);
        assert!(
            err.message.contains(&state.gateway_base_url),
            "{}",
            err.message
        );
    }
}
