//! End-to-end tests for `seal` — sealed-PoE sending through the real binary
//! against the stub gateway. The load-bearing assertions: the plaintext never
//! leaves the process except as a hash (the uploaded bytes are ciphertext),
//! the published record carries a well-formed envelope with one slot per
//! recipient under one KEM, and the self slot really decrypts.

mod common;

use std::collections::BTreeMap;

use cardanowall::hash::sha256;
use cardanowall::poe_standard::EncryptionEnvelope;
use cardanowall::sealed_poe::{ecies_sealed_poe_unwrap, UnwrapKeys, UnwrapResult};
use cardanowall::seed_derive::{derive_mlkem768x25519_keypair, derive_x25519_keypair};

use common::stub_gateway::{
    captured_publish_record, cli, multipart_file_bytes, stub_ar_uri, StubConfig, StubGateway,
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
    let (_, record) = captured_publish_record(&stub);
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

    // The receipt names the public facts only.
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r.json")).unwrap()).unwrap();
    assert_eq!(receipt["format"], "label-309-seal-receipt-v1");
    assert_eq!(receipt["sealed"]["recipient_count"], 2);
    assert_eq!(receipt["sealed"]["kem"], "x25519");
    assert_eq!(receipt["item"]["ar_uri"].as_str().unwrap(), stub_ar_uri());
    assert_eq!(receipt["status"], "confirmed");
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
