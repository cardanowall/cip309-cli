//! End-to-end tests for `seal` — sealed-PoE sending through the real binary
//! against the stub gateway. The load-bearing assertions: the plaintext never
//! leaves the process except as a hash (the uploaded bytes are ciphertext),
//! the published record carries a well-formed envelope with one slot per
//! recipient under one KEM, and the self slot really decrypts.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cardanowall::hash::sha256;
use cardanowall::poe_standard::EncryptionEnvelope;
use cardanowall::sealed_poe::{ecies_sealed_poe_unwrap, UnwrapKeys, UnwrapResult};
use cardanowall::seed_derive::{derive_mlkem768x25519_keypair, derive_x25519_keypair};

use common::stub_gateway::{
    captured_publish_record, cli, multipart_file_bytes, stub_ar_uri, stub_upload_uri,
    PublishBehavior, StubConfig, StubGateway,
};

/// Encode a raw public key as its age recipient string.
fn age_recipient(hrp: &str, key: &[u8]) -> String {
    cardanowall::recipient::bech32_encode_no_limit(hrp, key).unwrap()
}

const PLAINTEXT: &[u8] = b"the sealed payload: confidential draft, hashes-only on chain";

#[test]
fn seal_uploads_ciphertext_not_plaintext_and_publishes_the_envelope() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipients: Vec<String> = [1u8, 2]
        .iter()
        .map(|i| age_recipient("age", &derive_x25519_keypair(&[*i; 32]).unwrap().public_key))
        .collect();

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipients[0],
            "--to",
            &recipients[1],
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Exactly one storage upload, and its bytes are NOT the plaintext: the
    // plaintext appears nowhere in the multipart body, and the extracted file
    // part has the STREAM ciphertext length (plaintext + one 16-byte tag).
    let uploads = stub.requests_to("/poe/uploads");
    assert_eq!(uploads.len(), 1);
    assert!(
        !uploads[0]
            .body
            .windows(PLAINTEXT.len())
            .any(|w| w == PLAINTEXT),
        "the plaintext must never be uploaded"
    );
    let ciphertext = multipart_file_bytes(&uploads[0]);
    assert_eq!(ciphertext.len(), PLAINTEXT.len() + 16);
    assert_ne!(&ciphertext[..PLAINTEXT.len()], PLAINTEXT);

    // The record: one item, sha2-256 of the plaintext, the storage URI, and a
    // scheme-1 envelope with one classical slot per recipient.
    let (record_bytes, record) = captured_publish_record(&stub);
    let items = record.items.expect("sealed record carries items[]");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].hashes[0].0, "sha2-256");
    assert_eq!(items[0].hashes[0].1, sha256(PLAINTEXT).to_vec());
    assert_eq!(items[0].uris.as_deref(), Some(&[stub_ar_uri()][..]));
    let EncryptionEnvelope::Scheme1(env) = items[0].enc.as_ref().expect("enc present") else {
        panic!("expected a scheme-1 envelope");
    };
    assert_eq!(env.kem.as_deref(), Some("x25519"));
    let slots = env.slots.as_ref().expect("slots present");
    assert_eq!(slots.len(), 2, "one slot per recipient");
    assert!(slots.iter().all(|s| s.epk.is_some() && s.kem_ct.is_none()));

    // The quote priced the real shape: both recipients and the exact
    // ciphertext size.
    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    assert_eq!(quote_body["recipient_count"], 2);
    assert_eq!(
        quote_body["file_bytes_total"].as_u64().unwrap(),
        (PLAINTEXT.len() + 16) as u64
    );

    // The receipt names the public facts only, and archives the exact
    // published record bytes.
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r.json")).unwrap()).unwrap();
    assert_eq!(receipt["format"], "label-309-seal-receipt-v1");
    assert_eq!(receipt["sealed"]["recipient_count"], 2);
    assert_eq!(receipt["sealed"]["kem"], "x25519");
    let receipt_items = receipt["items"].as_array().expect("items[] present");
    assert_eq!(receipt_items.len(), 1);
    assert_eq!(receipt_items[0]["ar_uri"].as_str().unwrap(), stub_ar_uri());
    assert_eq!(
        receipt_items[0]["sha2_256"].as_str().unwrap(),
        hex::encode(sha256(PLAINTEXT))
    );
    assert_eq!(
        receipt["record_hex"].as_str().unwrap(),
        hex::encode(&record_bytes),
        "the receipt archives the exact published record bytes"
    );
    assert_eq!(receipt["status"], "confirmed");
}

#[test]
fn seal_multiple_files_publishes_one_record_with_one_item_per_file() {
    let dir = tempfile::tempdir().unwrap();
    let first: &[u8] = b"first sealed item";
    let second: &[u8] = b"second sealed item, a little longer";
    std::fs::write(dir.path().join("a.bin"), first).unwrap();
    std::fs::write(dir.path().join("b.bin"), second).unwrap();
    let recipients: Vec<String> = [1u8, 2]
        .iter()
        .map(|i| age_recipient("age", &derive_x25519_keypair(&[*i; 32]).unwrap().public_key))
        .collect();

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "a.bin",
            "--file",
            "b.bin",
            "--to",
            &recipients[0],
            "--to",
            &recipients[1],
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "multi-file seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // One ciphertext upload per file, in input order, each the STREAM size of
    // its own plaintext.
    let uploads = stub.requests_to("/poe/uploads");
    assert_eq!(uploads.len(), 2);
    assert_eq!(
        multipart_file_bytes(&uploads[0]).len(),
        first.len() + 16,
        "upload 1 carries the first file's ciphertext"
    );
    assert_eq!(
        multipart_file_bytes(&uploads[1]).len(),
        second.len() + 16,
        "upload 2 carries the second file's ciphertext"
    );

    // ONE published record with items[] in input order: each item binds its
    // own plaintext hash, its own storage URI, and a full recipient slot set.
    let (record_bytes, record) = captured_publish_record(&stub);
    let items = record.items.expect("items[] present");
    assert_eq!(items.len(), 2);
    for (item, (plaintext, uri)) in items
        .iter()
        .zip([(first, stub_upload_uri(1)), (second, stub_upload_uri(2))])
    {
        assert_eq!(item.hashes[0].1, sha256(plaintext).to_vec());
        assert_eq!(item.uris.as_deref(), Some(&[uri][..]));
        let EncryptionEnvelope::Scheme1(env) = item.enc.as_ref().expect("enc present") else {
            panic!("expected a scheme-1 envelope");
        };
        assert_eq!(env.slots.as_ref().unwrap().len(), 2);
    }

    // ONE quote priced the whole shape: 2 items × 2 recipients = 4 slots, and
    // the storage total is the sum of both ciphertexts.
    let quotes = stub.requests_to("/poe/quote");
    assert_eq!(quotes.len(), 1, "one quote covers the whole multi-item run");
    assert_eq!(quotes[0].body_json()["recipient_count"], 4);
    assert_eq!(
        quotes[0].body_json()["file_bytes_total"].as_u64().unwrap(),
        (first.len() + 16 + second.len() + 16) as u64
    );

    // The receipt carries one entry per item plus the exact record bytes.
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r.json")).unwrap()).unwrap();
    let receipt_items = receipt["items"].as_array().unwrap();
    assert_eq!(receipt_items.len(), 2);
    for (entry, (plaintext, uri)) in receipt_items
        .iter()
        .zip([(first, stub_upload_uri(1)), (second, stub_upload_uri(2))])
    {
        assert_eq!(
            entry["sha2_256"].as_str().unwrap(),
            hex::encode(sha256(plaintext))
        );
        assert_eq!(entry["ar_uri"].as_str().unwrap(), uri);
        assert_eq!(
            entry["ciphertext_bytes"].as_u64().unwrap(),
            (plaintext.len() + 16) as u64
        );
    }
    assert_eq!(
        receipt["record_hex"].as_str().unwrap(),
        hex::encode(&record_bytes)
    );

    // The stdout summary maps every item back to its input file.
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let outcome_items = outcome["items"].as_array().unwrap();
    assert_eq!(outcome_items.len(), 2);
    assert_eq!(outcome_items[0]["file"], "a.bin");
    assert_eq!(outcome_items[1]["file"], "b.bin");
    assert_eq!(
        outcome_items[1]["ar_uri"].as_str().unwrap(),
        stub_upload_uri(2)
    );
}

#[test]
fn seal_publish_failure_after_paid_uploads_reports_the_completed_uploads() {
    let scripted = StubConfig {
        publish: PublishBehavior::Reject,
        ..StubConfig::default()
    };
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[4u8; 32]).unwrap().public_key,
    );

    // Human mode: the gateway rejection is integrity-class (exit 1) and the
    // diagnostic lists each completed upload — file, storage URI, byte count,
    // ciphertext hash — because that storage work was already paid for.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), PLAINTEXT).unwrap();
    std::fs::write(dir.path().join("b.bin"), PLAINTEXT).unwrap();
    let stub = StubGateway::start(scripted.clone());
    let out = cli(&stub, dir.path())
        .args([
            "seal", "--file", "a.bin", "--file", "b.bin", "--to", &recipient,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stub.requests_to("/poe/uploads").len(),
        2,
        "both uploads completed before the publish was rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("record-rejected"), "stderr: {stderr}");
    for (file, uri) in [("a.bin", stub_upload_uri(1)), ("b.bin", stub_upload_uri(2))] {
        assert!(
            stderr.contains(&format!("{file}: {uri}")),
            "stderr must list the paid upload for {file}: {stderr}"
        );
    }

    // JSON mode: the same diagnostic travels inside the structured error
    // object, so automation sees the completed uploads too.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), PLAINTEXT).unwrap();
    let stub = StubGateway::start(scripted);
    let out = cli(&stub, dir.path())
        .args(["seal", "--file", "a.bin", "--to", &recipient, "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let error: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stderr).trim())
            .expect("JSON mode emits a structured error object");
    assert_eq!(error["error"]["code"], 1);
    assert_eq!(error["error"]["command"], "seal");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("a.bin: {}", stub_upload_uri(1))),
        "message must list the paid upload: {message}"
    );
    assert!(out.stdout.is_empty(), "no summary on a failed publish");
}

#[test]
fn seal_to_self_hybrid_slot_really_decrypts() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("note.bin"), PLAINTEXT).unwrap();
    let seed_hex = "5e".repeat(32);

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["seal", "--file", "note.bin", "--to-self", "--json"])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "seal --to-self failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Self-only sealing takes the hybrid (post-quantum) default: one X-Wing
    // slot.
    let (_, record) = captured_publish_record(&stub);
    let items = record.items.expect("items present");
    let EncryptionEnvelope::Scheme1(env) = items[0].enc.as_ref().unwrap() else {
        panic!("expected a scheme-1 envelope");
    };
    assert_eq!(env.kem.as_deref(), Some("mlkem768x25519"));
    let slots = env.slots.as_ref().unwrap();
    assert_eq!(slots.len(), 1);
    assert!(slots[0].kem_ct.is_some() && slots[0].epk.is_none());

    // The uploaded ciphertext opens with the seed's own recipient bundle and
    // recovers the exact plaintext — the slot is genuinely addressed to self.
    let ciphertext = multipart_file_bytes(&stub.requests_to("/poe/uploads")[0]);
    let identity =
        cardanowall_cli::inbox::identity::resolve_identity(Some(&seed_hex), None, "seal test")
            .unwrap();
    let envelope =
        cardanowall_cli::inbox::envelope::envelope_from_item(&items[0]).expect("sealed item");
    let hashes: BTreeMap<String, Vec<u8>> = items[0].hashes.iter().cloned().collect();
    let unwrap = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        &hashes,
        UnwrapKeys::Bundle(&identity.recipient_key_bundle()),
        None,
    )
    .unwrap();
    match unwrap {
        UnwrapResult::Matched { plaintext } => assert_eq!(plaintext, PLAINTEXT),
        UnwrapResult::NotMatched { reason } => {
            panic!("the self slot did not decrypt: {}", reason.as_str())
        }
    }
}

#[test]
fn seal_cohash_reports_the_hashes_map_in_stdout_and_receipt() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[1u8; 32]).unwrap().public_key,
    );
    let sha = hex::encode(sha256(PLAINTEXT));
    let blake = hex::encode(cardanowall::hash::blake2b256(PLAINTEXT));

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--hash-alg",
            "sha2-256",
            "--hash-alg",
            "blake2b-256",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "co-hash seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The published record binds BOTH digests, each under its own algorithm
    // label — the on-chain claim the ciphertext is bound to.
    let (_, record) = captured_publish_record(&stub);
    let hashes: BTreeMap<String, Vec<u8>> =
        record.items.unwrap()[0].hashes.iter().cloned().collect();
    assert_eq!(hashes.get("sha2-256").unwrap(), &sha256(PLAINTEXT).to_vec());
    assert_eq!(
        hashes.get("blake2b-256").unwrap(),
        &cardanowall::hash::blake2b256(PLAINTEXT).to_vec()
    );

    // stdout summary: the per-item `hashes` map carries every algorithm, and the
    // legacy `sha2_256` scalar stays populated because a sha2-256 entry exists.
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let item = &outcome["items"][0];
    assert_eq!(item["hashes"]["sha2-256"].as_str().unwrap(), sha);
    assert_eq!(item["hashes"]["blake2b-256"].as_str().unwrap(), blake);
    assert_eq!(item["sha2_256"].as_str().unwrap(), sha);

    // The receipt item mirrors the same shape exactly.
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r.json")).unwrap()).unwrap();
    let r_item = &receipt["items"][0];
    assert_eq!(r_item["hashes"]["sha2-256"].as_str().unwrap(), sha);
    assert_eq!(r_item["hashes"]["blake2b-256"].as_str().unwrap(), blake);
    assert_eq!(r_item["sha2_256"].as_str().unwrap(), sha);
}

#[test]
fn seal_blake2b_only_labels_the_digest_and_omits_the_sha2_legacy_field() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[1u8; 32]).unwrap().public_key,
    );
    let blake = hex::encode(cardanowall::hash::blake2b256(PLAINTEXT));

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--hash-alg",
            "blake2b-256",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "blake2b-only seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout: the map carries only blake2b-256, no sha2-256 entry, and the
    // legacy `sha2_256` scalar is omitted entirely (never a mislabelled digest).
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let item = &outcome["items"][0];
    assert_eq!(item["hashes"]["blake2b-256"].as_str().unwrap(), blake);
    assert!(item["hashes"]["sha2-256"].is_null());
    assert!(
        item.get("sha2_256").is_none(),
        "sha2_256 must be absent for a blake2b-only item: {item}"
    );

    // The receipt mirrors it: a blake2b-only map, no legacy sha2_256 field.
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r.json")).unwrap()).unwrap();
    let r_item = &receipt["items"][0];
    assert_eq!(r_item["hashes"]["blake2b-256"].as_str().unwrap(), blake);
    assert!(r_item["hashes"]["sha2-256"].is_null());
    assert!(
        r_item.get("sha2_256").is_none(),
        "receipt sha2_256 must be absent for a blake2b-only item: {r_item}"
    );
}

#[test]
fn seal_mixed_kem_recipients_are_refused_before_any_network() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.bin"), b"x").unwrap();
    let classical = age_recipient(
        "age",
        &derive_x25519_keypair(&[1u8; 32]).unwrap().public_key,
    );
    let hybrid = age_recipient(
        "age1pqc",
        &derive_mlkem768x25519_keypair(&[2u8; 32])
            .unwrap()
            .public_key,
    );

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal", "--file", "x.bin", "--to", &classical, "--to", &hybrid,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("forbids mixed-KEM"), "stderr: {stderr}");
    assert!(
        stub.requests().is_empty(),
        "the refusal must fire before any network call"
    );
}

#[test]
fn seal_sign_attaches_the_identity_signature_and_leaks_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.bin"), PLAINTEXT).unwrap();
    let seed_hex = "6f".repeat(32);
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[3u8; 32]).unwrap().public_key,
    );

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "x.bin",
            "--to",
            &recipient,
            "--sign",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "seal --sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The published record validates AND carries a path-1 signature from the
    // seed's identity key.
    let (_, record) = captured_publish_record(&stub);
    assert!(record.sigs.is_some(), "--sign must attach a signature");
    let seed: [u8; 32] = hex::decode(&seed_hex).unwrap().try_into().unwrap();
    let signer = cardanowall::seed_derive::signer_from_seed(&seed).unwrap();
    let expected_pubkey = {
        use cardanowall::client::Signer as _;
        hex::encode(signer.signer_pubkey())
    };
    let receipt_text = std::fs::read_to_string(dir.path().join("r.json")).unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipt_text).unwrap();
    assert_eq!(receipt["signed"], true);
    assert_eq!(receipt["signer_ed25519"].as_str().unwrap(), expected_pubkey);

    // No secret crosses any output surface.
    let stdout_text = String::from_utf8_lossy(&out.stdout);
    for surface in [receipt_text.as_str(), &stdout_text] {
        assert!(!surface.contains(&seed_hex), "the seed leaked");
        assert!(!surface.contains("stub-test-key"), "the API key leaked");
    }

    // Signing is an explicit opt-in: without --sign the record is unsigned.
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::write(dir2.path().join("x.bin"), PLAINTEXT).unwrap();
    let stub2 = StubGateway::start(StubConfig::default());
    let out2 = cli(&stub2, dir2.path())
        .args(["seal", "--file", "x.bin", "--to", &recipient, "--json"])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    let (_, unsigned) = captured_publish_record(&stub2);
    assert!(
        unsigned.sigs.is_none(),
        "encryption must not imply authorship"
    );
}

// ---------------------------------------------------------------------------
// seal --resume: finishing a sealed publish that failed after paying uploads
// ---------------------------------------------------------------------------

/// Every resume-state file in a directory (by the reserved extension).
fn resume_state_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.ends_with(".l309-seal-resume.json"))
        })
        .collect()
}

/// The decoded record bytes of every `POST /poe/publish` the stub captured, in
/// order. A reject-then-accept run has two (the rejected original + the accepted
/// resume), so tests read the last.
fn published_records(stub: &StubGateway) -> Vec<Vec<u8>> {
    stub.requests_to("/poe/publish")
        .iter()
        .map(|r| hex::decode(r.body_json()["record"].as_str().unwrap()).unwrap())
        .collect()
}

/// Structurally validate and decode published record bytes.
fn decode_record(bytes: &[u8]) -> cardanowall::poe_standard::PoeRecord {
    use cardanowall::poe_standard::{validate_poe_record, ValidateResult, ValidatorOptions};
    match validate_poe_record(bytes, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => *record,
        ValidateResult::Fail { issues } => panic!("published record is invalid: {issues:?}"),
    }
}

/// Read a resume-state file to a JSON value.
fn read_state(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Rewrite a resume-state file from a mutated JSON value (simulating a tamper).
fn write_state(path: &Path, state: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string_pretty(state).unwrap()).unwrap();
}

#[test]
fn seal_recipient_failure_writes_a_secret_free_resume_state_and_names_the_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("note.bin"), PLAINTEXT).unwrap();
    // --to-self exercises a seed WITHOUT signing: the seed derives the self slot
    // but is never persisted, so the file must not carry the seed hex.
    let seed_hex = "5e".repeat(32);

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::Reject,
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "note.bin",
            "--to-self",
            "--resume-state",
            "resume.json",
        ])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // The single item uploaded before the publish was rejected, so the paid
    // upload is in the state file.
    assert_eq!(stub.requests_to("/poe/uploads").len(), 1);
    let state_path = dir.path().join("resume.json");
    let text = std::fs::read_to_string(&state_path).expect("resume-state file written");
    let state: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(state["version"], 1);
    assert_eq!(state["format"], "label-309-seal-resume");
    let uploads = state["uploads"].as_array().unwrap();
    assert_eq!(uploads.len(), 1, "the completed upload is recorded");
    assert_eq!(uploads[0]["uri"].as_str().unwrap(), stub_upload_uri(1));
    assert_eq!(state["to_self"], true);
    assert_eq!(state["signed"], false);

    // ZERO secrets: neither the seed nor the API key may appear anywhere in the
    // state file.
    assert!(
        !text.contains(&seed_hex),
        "the seed leaked into the state file"
    );
    assert!(
        !text.contains("stub-test-key"),
        "the API key leaked into the state file"
    );

    // stderr names the exact resume command.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cardanowall seal --resume resume.json"),
        "stderr must name the resume command: {stderr}"
    );
}

#[test]
fn seal_resume_reuses_paid_uploads_and_publishes_a_byte_identical_record() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[9u8; 32]).unwrap().public_key,
    );

    // One gateway serves both attempts: it rejects the first publish (the failed
    // run) and accepts the second (the resume). The resume MUST target the same
    // gateway the state was created against — the security model requires it.
    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::RejectFirstThenAccept,
        ..StubConfig::default()
    });

    // Attempt 1: the upload succeeds, the publish is rejected → a resume-state
    // file captures the prepared seal and the paid upload.
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--resume-state",
            "state.json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(stub.requests_to("/poe/uploads").len(), 1);

    // The exact record the resume must publish: the persisted prepared seal
    // assembled over the persisted (already-paid) storage URI. Same prepared
    // seal → same record, so this is the strongest possible cross-check.
    let state = read_state(&dir.path().join("state.json"));
    let prepared =
        cardanowall::client::PreparedSeal::from_json(state["prepared_seal"].as_str().unwrap())
            .unwrap();
    let paid_uri = state["uploads"][0]["uri"].as_str().unwrap().to_string();
    let expected_record =
        cardanowall::client::encode_sealed_record(&prepared, &[paid_uri], None, None).unwrap();

    // Attempt 2: resume against the same gateway. It must NOT re-upload the
    // ciphertext, and it must publish the exact same record bytes.
    let resumed = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "resume failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        stub.requests_to("/poe/uploads").len(),
        1,
        "the resume must reuse the paid upload — the upload count stays 1 across both runs"
    );
    let records = published_records(&stub);
    assert_eq!(
        records.last().unwrap(),
        &expected_record,
        "the resumed record must be byte-identical to an uninterrupted publish of the same seal"
    );

    // A successful resume removes the state file.
    assert!(
        !dir.path().join("state.json").exists(),
        "the resume must delete the state file on success"
    );
}

#[test]
fn seal_resume_refuses_any_input_flag() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    // --resume together with a content-shaping flag is a usage error, caught
    // before the state file is even read (so the path need not exist).
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--resume",
            "nonexistent.json",
            "--file",
            "whatever.bin",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--file"),
        "stderr must name --file: {stderr}"
    );
    assert!(
        stub.requests().is_empty(),
        "the refusal must fire before any network call"
    );
}

#[test]
fn seal_resume_of_a_signed_publish_requires_the_seed_then_signs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.bin"), PLAINTEXT).unwrap();
    let seed_hex = "7a".repeat(32);
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[8u8; 32]).unwrap().public_key,
    );

    // A signed publish that fails after the upload → the state records signed:true.
    // One gateway serves the failed run and the resume (reject then accept).
    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::RejectFirstThenAccept,
        ..StubConfig::default()
    });
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "x.bin",
            "--to",
            &recipient,
            "--sign",
            "--resume-state",
            "state.json",
        ])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(read_state(&dir.path().join("state.json"))["signed"], true);

    // Resume WITHOUT the seed: refused (exit 4), and the state file is left in
    // place for a retry that supplies the seed. No network call is made.
    let before = stub.requests().len();
    let no_seed = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json"])
        .output()
        .unwrap();
    assert_eq!(no_seed.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&no_seed.stderr);
    assert!(stderr.contains("signed"), "stderr: {stderr}");
    assert!(stderr.contains("--seed"), "stderr: {stderr}");
    assert!(
        dir.path().join("state.json").exists(),
        "a refused resume must not delete the state file"
    );
    assert_eq!(
        stub.requests().len(),
        before,
        "the seed is required before any network call"
    );

    // Resume WITH the seed: the published record carries the seed's signature,
    // and the pre-publish summary announces the signer.
    let signed_resume = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json", "--receipt-out", "r.json"])
        .env("CARDANOWALL_SEED", &seed_hex)
        .output()
        .unwrap();
    assert_eq!(
        signed_resume.status.code(),
        Some(0),
        "signed resume failed: {}",
        String::from_utf8_lossy(&signed_resume.stderr)
    );
    let seed: [u8; 32] = hex::decode(&seed_hex).unwrap().try_into().unwrap();
    let signer = cardanowall::seed_derive::signer_from_seed(&seed).unwrap();
    let expected_pubkey = {
        use cardanowall::client::Signer as _;
        hex::encode(signer.signer_pubkey())
    };
    // The published wire record actually carries the signature.
    let record = decode_record(published_records(&stub).last().unwrap());
    assert!(record.sigs.is_some(), "the resumed record must be signed");
    // The summary announced the signer identity before publishing.
    let signed_stderr = String::from_utf8_lossy(&signed_resume.stderr);
    assert!(
        signed_stderr.contains(&format!("signer {expected_pubkey}")),
        "the summary must announce the signer: {signed_stderr}"
    );
    // The receipt binds the same identity.
    let receipt = read_state(&dir.path().join("r.json"));
    assert_eq!(receipt["signed"], true);
    assert_eq!(
        receipt["signer_ed25519"].as_str().unwrap(),
        expected_pubkey,
        "the signature must be from the resumed seed's identity"
    );
}

#[test]
fn seal_resume_refuses_a_gateway_the_state_was_not_created_against() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[3u8; 32]).unwrap().public_key,
    );

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::Reject,
        ..StubConfig::default()
    });
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--resume-state",
            "state.json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));

    // Tamper the persisted gateway URL to an attacker endpoint, keeping the
    // prepared-seal integrity tag intact (only the URL was changed).
    let state_path = dir.path().join("state.json");
    let mut state = read_state(&state_path);
    state["gateway_base_url"] = serde_json::json!("http://attacker.example.invalid/api/v1");
    write_state(&state_path, &state);

    // The resume resolves the gateway from trusted sources (env points at the
    // real stub), sees it differs from the persisted URL, and refuses — WITHOUT
    // contacting either the real gateway or the attacker endpoint.
    let before = stub.requests().len();
    let resumed = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json"])
        .output()
        .unwrap();
    assert_eq!(resumed.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        stderr.contains("created against") && stderr.contains("attacker.example.invalid"),
        "stderr must flag the gateway mismatch: {stderr}"
    );
    assert_eq!(
        stub.requests().len(),
        before,
        "a mismatched-gateway resume must make no network call (bearer key stays put)"
    );
}

#[test]
fn seal_resume_refuses_a_swapped_prepared_seal_that_does_not_match_the_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[4u8; 32]).unwrap().public_key,
    );

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::Reject,
        ..StubConfig::default()
    });
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--resume-state",
            "state.json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));

    // Forge a DIFFERENT but perfectly valid prepared seal (over content the user
    // never sealed) and fix the integrity tag, defeating layer (a). The
    // load-bearing plaintext re-anchor must still reject it: draft.bin does not
    // hash to the swapped seal's claims.
    let swapped = {
        use cardanowall::client::{
            seal_prepare, SealPrepareInput, SealPrepareItem, SealedKemChoice,
        };
        let key = derive_x25519_keypair(&[5u8; 32])
            .unwrap()
            .public_key
            .to_vec();
        let input =
            SealPrepareInput::new(vec![SealPrepareItem::new(b"attacker content")], vec![key])
                .with_kem(SealedKemChoice::X25519);
        seal_prepare(&input).unwrap().to_json()
    };
    let digest = hex::encode(cardanowall::hash::sha256(swapped.as_bytes()));
    let state_path = dir.path().join("state.json");
    let mut state = read_state(&state_path);
    state["prepared_seal"] = serde_json::json!(swapped);
    state["prepared_sha256"] = serde_json::json!(digest);
    write_state(&state_path, &state);

    let before = stub.requests().len();
    let resumed = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json"])
        .output()
        .unwrap();
    assert_eq!(resumed.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        stderr.contains("no longer matches") || stderr.contains("did not seal"),
        "stderr must flag the plaintext mismatch: {stderr}"
    );
    assert_eq!(
        stub.requests().len(),
        before,
        "the plaintext re-anchor must fail before any network call"
    );
}

#[test]
fn seal_resume_surfaces_a_tampered_supersedes_in_the_summary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[6u8; 32]).unwrap().public_key,
    );

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::RejectFirstThenAccept,
        ..StubConfig::default()
    });
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--resume-state",
            "state.json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));

    // Inject a supersedes link the original run never had (it is not derived
    // from the user's files, so the re-anchor cannot catch it).
    let tx = "ab".repeat(32);
    let state_path = dir.path().join("state.json");
    let mut state = read_state(&state_path);
    state["supersedes"] = serde_json::json!(tx);
    write_state(&state_path, &state);

    let resumed = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json"])
        .output()
        .unwrap();
    assert_eq!(
        resumed.status.code(),
        Some(0),
        "resume failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    // The pre-publish summary makes the injected supersedes visible.
    let stderr = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        stderr.contains(&format!("supersedes:  {tx}")),
        "the summary must surface the tampered supersedes: {stderr}"
    );
}

#[test]
fn seal_resume_requires_the_files_unless_the_recheck_is_explicitly_waived() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("draft.bin"), PLAINTEXT).unwrap();
    let recipient = age_recipient(
        "age",
        &derive_x25519_keypair(&[7u8; 32]).unwrap().public_key,
    );

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::RejectFirstThenAccept,
        ..StubConfig::default()
    });
    let first = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "draft.bin",
            "--to",
            &recipient,
            "--resume-state",
            "state.json",
        ])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(1));

    // The input file is gone at resume time.
    std::fs::remove_file(dir.path().join("draft.bin")).unwrap();

    // Without the waiver: a hard failure that names the escape hatch, and no
    // network call.
    let before = stub.requests().len();
    let missing = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("--skip-plaintext-recheck"),
        "stderr must name the opt-out: {stderr}"
    );
    assert_eq!(
        stub.requests().len(),
        before,
        "no network before the waiver"
    );

    // With the waiver: the resume proceeds and the summary flags the waived check.
    let waived = cli(&stub, dir.path())
        .args(["seal", "--resume", "state.json", "--skip-plaintext-recheck"])
        .output()
        .unwrap();
    assert_eq!(
        waived.status.code(),
        Some(0),
        "waived resume failed: {}",
        String::from_utf8_lossy(&waived.stderr)
    );
    assert!(
        String::from_utf8_lossy(&waived.stderr).contains("NOT re-verified"),
        "the summary must flag the waived recheck"
    );
}

#[test]
fn seal_passphrase_failure_writes_no_state_and_says_it_cannot_resume() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.bin"), PLAINTEXT).unwrap();

    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::Reject,
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args([
            "seal",
            "--file",
            "secret.bin",
            "--passphrase",
            "correct horse battery staple",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // No resume-state file anywhere: a passphrase seal has no resumable artifact.
    assert!(
        resume_state_files(dir.path()).is_empty(),
        "a passphrase seal must not write a resume-state file"
    );

    // The error explains why, in one line.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be resumed"),
        "stderr must explain that a passphrase seal cannot be resumed: {stderr}"
    );
}
