//! End-to-end tests for `attest` (and the `submit` wait/quote upgrades),
//! driving the real binary against an in-process stub gateway.
//!
//! The stub records every request, so the assertions pin the wire contract:
//! exact quote sizing for items records, upper-bound sizing for Merkle
//! records, the idempotency header, dedup-replay normalization, the SSE wait
//! loop (success and timeout), the pre-publish `--max-usd` refusal, and the
//! determinism of the manifest / root across runs.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use cardanowall::hash::sha256;
use cardanowall::merkle::{encode_leaves_list, merkle_root};
use cardanowall::poe_standard::{validate_poe_record, PoeRecord, ValidateResult, ValidatorOptions};

use common::stub_gateway::{
    snapshot_json, stub_tx_hash, PublishBehavior, SseFrame, StubConfig, StubGateway, STUB_POE_ID,
};

/// Path to the freshly-built `cardanowall` binary under test.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cardanowall"))
}

/// A command pointed at the stub gateway with fully isolated config/home, so
/// tests never read the developer's real `~/.cardanowall` or leak env.
fn cli(stub: &StubGateway, workdir: &Path) -> Command {
    let home = workdir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut c = Command::new(bin());
    c.current_dir(workdir)
        .env("CARDANOWALL_CONFIG_PATH", workdir.join("config.toml"))
        .env("HOME", &home)
        .env("CARDANOWALL_BASE_URL", stub.base_url())
        .env("CARDANOWALL_API_KEY", "stub-test-key")
        .env_remove("CARDANOWALL_SEED")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    c
}

/// Decode the record the stub captured on `POST /poe/publish`.
fn captured_record(stub: &StubGateway) -> (Vec<u8>, PoeRecord) {
    let publishes = stub.requests_to("/poe/publish");
    assert_eq!(publishes.len(), 1, "expected exactly one publish");
    let record_hex = publishes[0].body_json()["record"]
        .as_str()
        .expect("publish body carries the record hex")
        .to_string();
    let bytes = hex::decode(&record_hex).unwrap();
    match validate_poe_record(&bytes, &ValidatorOptions::default()) {
        ValidateResult::Ok { record, .. } => (bytes, *record),
        ValidateResult::Fail { issues } => panic!("published record is invalid: {issues:?}"),
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Manifest determinism
// ---------------------------------------------------------------------------

#[test]
fn attest_paths_manifest_is_deterministic_and_byte_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("sub")).unwrap();
    // Created deliberately out of byte order.
    std::fs::write(data.join("b.txt"), b"bravo").unwrap();
    std::fs::write(data.join("A.txt"), b"alpha-upper").unwrap();
    std::fs::write(data.join("sub/c.bin"), [0u8, 1, 2, 3]).unwrap();

    let run = |manifest: &str, receipt: &str| {
        let stub = StubGateway::start(StubConfig::default());
        let out = cli(&stub, dir.path())
            .args([
                "attest",
                "--paths",
                "data/**/*",
                "--manifest-out",
                manifest,
                "--receipt-out",
                receipt,
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "attest failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run("m1.json", "r1.json");
    run("m2.json", "r2.json");

    // Byte-identical manifests across runs over the identical tree.
    let m1 = std::fs::read(dir.path().join("m1.json")).unwrap();
    let m2 = std::fs::read(dir.path().join("m2.json")).unwrap();
    assert_eq!(m1, m2, "the manifest must be byte-deterministic");

    // Rows are byte-sorted by normalized relative path ('A' < 'a' < 's').
    let manifest = read_json(&dir.path().join("m1.json"));
    assert_eq!(manifest["format"], "label-309-poe-manifest-v1");
    let paths: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, vec!["data/A.txt", "data/b.txt", "data/sub/c.bin"]);
    // Each row's hash and size describe the real file bytes.
    let first = &manifest["files"][0];
    assert_eq!(first["size"], 11);
    assert_eq!(
        first["sha2_256"].as_str().unwrap(),
        hex::encode(sha256(b"alpha-upper"))
    );

    // Both runs derived the same root.
    let r1 = read_json(&dir.path().join("r1.json"));
    let r2 = read_json(&dir.path().join("r2.json"));
    assert_eq!(r1["merkle"]["root"], r2["merkle"]["root"]);
    assert_eq!(r1["merkle"]["leaf_count"], 3);
}

// ---------------------------------------------------------------------------
// 2. Root correctness against the conformance vectors
// ---------------------------------------------------------------------------

#[test]
fn attest_leaf_mode_reproduces_the_conformance_root() {
    let kat = common::read_fixture_json(
        &common::sdk_py_fixtures().join("merkle/rfc9162-sha256-root-kat.json"),
    );
    let vector = kat["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "4-leaf")
        .expect("the 4-leaf KAT vector exists");
    let leaves: Vec<String> = vector["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    let expected_root = vector["root"].as_str().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let mut cmd = cli(&stub, dir.path());
    cmd.args([
        "attest",
        "--publish",
        "root",
        "--receipt-out",
        "r.json",
        "--json",
    ]);
    for leaf in &leaves {
        cmd.args(["--leaf", leaf]);
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let receipt = read_json(&dir.path().join("r.json"));
    assert_eq!(receipt["merkle"]["root"].as_str().unwrap(), expected_root);
    assert_eq!(receipt["merkle"]["leaf_count"], 4);
    // Root mode publishes no leaves-list: no upload happened, no ar_uri exists.
    assert!(stub.requests_to("/poe/uploads").is_empty());
    assert!(receipt["merkle"]["ar_uri"].is_null());
}

// ---------------------------------------------------------------------------
// 3. Mode selection: 1 leaf → items, 2 → merkle, --anchor-manifest adds one
// ---------------------------------------------------------------------------

#[test]
fn attest_single_file_publishes_a_plain_items_record() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("only.txt"), b"single artifact").unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["attest", "--paths", "only.txt", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let (_, record) = captured_record(&stub);
    let items = record.items.expect("a 1-leaf attest publishes items[]");
    assert!(record.merkle.is_none(), "one leaf must not build a tree");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].hashes[0].0, "sha2-256");
    assert_eq!(items[0].hashes[0].1, sha256(b"single artifact").to_vec());
}

#[test]
fn attest_two_files_publish_a_merkle_record() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), b"first").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"second").unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--paths",
            "a.bin",
            "--paths",
            "b.bin",
            "--publish",
            "root",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let (_, record) = captured_record(&stub);
    assert!(record.items.is_none());
    let merkle = record.merkle.expect("two leaves publish merkle[]");
    assert_eq!(merkle[0].leaf_count, 2);
    let expected = merkle_root(&[sha256(b"first"), sha256(b"second")]).unwrap();
    assert_eq!(merkle[0].root, expected.to_vec());
}

#[test]
fn attest_anchor_manifest_appends_the_manifest_hash_as_the_final_leaf() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("only.txt"), b"single artifact").unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--paths",
            "only.txt",
            "--anchor-manifest",
            "--publish",
            "root",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    // One file + the manifest leaf → a 2-leaf tree, manifest hash LAST.
    let manifest_bytes = std::fs::read(dir.path().join("poe-manifest.json")).unwrap();
    let (_, record) = captured_record(&stub);
    let merkle = record.merkle.expect("--anchor-manifest makes it a tree");
    assert_eq!(merkle[0].leaf_count, 2);
    let expected = merkle_root(&[sha256(b"single artifact"), sha256(&manifest_bytes)]).unwrap();
    assert_eq!(
        merkle[0].root,
        expected.to_vec(),
        "the manifest hash must be the final leaf"
    );
}

// ---------------------------------------------------------------------------
// 4. Quote sizing: exact for items, upper bound for merkle
// ---------------------------------------------------------------------------

#[test]
fn attest_quotes_items_records_at_their_exact_encoded_length() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["attest", "--leaf", &"ab".repeat(32), "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let quotes = stub.requests_to("/poe/quote");
    assert_eq!(quotes.len(), 1);
    let quote_body = quotes[0].body_json();
    let (record_bytes, _) = captured_record(&stub);
    assert_eq!(
        quote_body["record_bytes"].as_u64().unwrap(),
        record_bytes.len() as u64,
        "an items record is quoted at its exact canonical length"
    );
    assert_eq!(quote_body["file_bytes_total"], 0);
}

#[test]
fn attest_quotes_merkle_records_as_an_upper_bound_with_exact_storage_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| sha256(&[i])).collect();
    let stub = StubGateway::start(StubConfig::default());
    let mut cmd = cli(&stub, dir.path());
    cmd.args(["attest", "--json"]);
    for leaf in &leaves {
        cmd.args(["--leaf", &hex::encode(leaf)]);
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    let (record_bytes, _) = captured_record(&stub);
    let quoted = quote_body["record_bytes"].as_u64().unwrap();
    assert!(
        quoted >= record_bytes.len() as u64,
        "the merkle quote ({quoted}) must cover the published record ({})",
        record_bytes.len()
    );
    // The storage side is exact: the canonical leaves-list byte count
    // (pass-through leaves carry no advisory leaf_alg).
    let root = merkle_root(&leaves).unwrap();
    let leaves_list = encode_leaves_list(&leaves, &root, None).unwrap();
    assert_eq!(
        quote_body["file_bytes_total"].as_u64().unwrap(),
        leaves_list.len() as u64
    );
    // Full-tree mode really uploaded the leaves-list once.
    assert_eq!(stub.requests_to("/poe/uploads").len(), 1);
}

// ---------------------------------------------------------------------------
// 5. Idempotency: auto = no header (content dedup); explicit = strict contract
// ---------------------------------------------------------------------------

/// The default `auto` mode must NOT send an Idempotency-Key: the gateway's
/// key contract hashes the whole request body, and every run consumes a fresh
/// quote_id, so any fixed key would 409 on re-run. Safe re-runs ride the
/// gateway's byte-identical record dedup instead; the replayed summary shows
/// no price (nothing was debited).
#[test]
fn attest_auto_mode_sends_no_key_and_content_dedup_replay_reports_normalized() {
    let leaf = "ef".repeat(32);
    let submitted_frames = vec![SseFrame {
        event: "state",
        data: snapshot_json("submitted", true),
    }];

    // Run 1: fresh publish — no Idempotency-Key header on the wire.
    let dir1 = tempfile::tempdir().unwrap();
    let stub1 = StubGateway::start(StubConfig {
        sse_frames: submitted_frames.clone(),
        ..StubConfig::default()
    });
    let out1 = cli(&stub1, dir1.path())
        .args(["attest", "--leaf", &leaf, "--wait", "submitted", "--json"])
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(0));
    assert!(
        stub1.requests_to("/poe/publish")[0]
            .header("idempotency-key")
            .is_none(),
        "auto mode must not send an Idempotency-Key header"
    );
    let outcome1: serde_json::Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(outcome1["replayed"], false);
    assert_eq!(outcome1["price_usd_micros"], "1500000");

    // Run 2: identical input against a gateway whose CONTENT dedup fires —
    // 200 echoing the stored row with the RAW engine `submitted` status.
    let dir2 = tempfile::tempdir().unwrap();
    let stub2 = StubGateway::start(StubConfig {
        publish: PublishBehavior::DedupRawSubmitted,
        sse_frames: submitted_frames,
        ..StubConfig::default()
    });
    let out2 = cli(&stub2, dir2.path())
        .args(["attest", "--leaf", &leaf, "--wait", "submitted", "--json"])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0), "a dedup replay is a success");
    assert!(stub2.requests_to("/poe/publish")[0]
        .header("idempotency-key")
        .is_none());

    let outcome: serde_json::Value =
        serde_json::from_slice(&out2.stdout).expect("stdout is the JSON outcome");
    assert_eq!(outcome["replayed"], true);
    // The raw engine `submitted` never leaks: it reports as `confirming`.
    assert_eq!(outcome["status"], "confirming");
    assert_eq!(outcome["id"], STUB_POE_ID);
    // Nothing was debited, so the misleading fresh-quote price is omitted.
    assert!(outcome.get("price_usd_micros").is_none());
}

/// An explicit key with a byte-identical request body replays cleanly (the
/// stub mirrors the real gateway: it stores the body hash per key and echoes
/// the original response on an exact match).
#[test]
fn attest_explicit_key_with_identical_body_replays_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    // A constant quote id makes the two publish bodies byte-identical — the
    // only shape under which the strict key contract permits a replay.
    let stub = StubGateway::start(StubConfig {
        sequential_quote_ids: false,
        ..StubConfig::default()
    });
    let run = || {
        cli(&stub, dir.path())
            .args([
                "attest",
                "--leaf",
                &"12".repeat(32),
                "--idempotency-key",
                "release-v1.2.3",
                "--json",
            ])
            .output()
            .unwrap()
    };
    let out1 = run();
    assert_eq!(
        out1.status.code(),
        Some(0),
        "first run failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let out2 = run();
    assert_eq!(
        out2.status.code(),
        Some(0),
        "identical-body replay failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    // Both publishes carried the explicit key; the replay reported the same
    // record.
    let publishes = stub.requests_to("/poe/publish");
    assert_eq!(publishes.len(), 2);
    for publish in &publishes {
        assert_eq!(publish.header("idempotency-key"), Some("release-v1.2.3"));
    }
    let o1: serde_json::Value = serde_json::from_slice(&out1.stdout).unwrap();
    let o2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(o1["id"], o2["id"]);
}

/// An explicit key with a DIFFERENT body (the fresh quote_id of a re-run) is
/// the strict contract's 409 — surfaced as a clear typed gateway error. This
/// is exactly the trap the default auto mode avoids by sending no key.
#[test]
fn attest_explicit_key_with_different_body_surfaces_the_409_conflict() {
    let dir = tempfile::tempdir().unwrap();
    // Sequential quote ids (the realistic default): run 2's body differs.
    let stub = StubGateway::start(StubConfig::default());
    let run = || {
        cli(&stub, dir.path())
            .args([
                "attest",
                "--leaf",
                &"34".repeat(32),
                "--idempotency-key",
                "release-v9.9.9",
            ])
            .output()
            .unwrap()
    };
    let out1 = run();
    assert_eq!(out1.status.code(), Some(0));
    let out2 = run();
    assert_eq!(
        out2.status.code(),
        Some(1),
        "same key + different body is a gateway rejection"
    );
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(
        stderr.contains("409") && stderr.contains("idempotency-key-conflict"),
        "the 409 surfaces as a typed error: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 6. Wait: confirmed success + timeout semantics
// ---------------------------------------------------------------------------

#[test]
fn attest_wait_confirmed_lands_the_snapshot_in_the_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--leaf",
            &"aa".repeat(32),
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let receipt = read_json(&dir.path().join("r.json"));
    assert_eq!(receipt["format"], "label-309-attest-receipt-v1");
    assert_eq!(receipt["status"], "confirmed");
    assert_eq!(receipt["tx_hash"].as_str().unwrap(), stub_tx_hash());
    assert_eq!(receipt["wait"]["reached"], true);
    assert_eq!(receipt["wait"]["timed_out"], false);
    assert_eq!(receipt["wait"]["block_height"], 123_456);
    assert_eq!(receipt["wait"]["num_confirmations"], 6);
    assert_eq!(
        receipt["gateway_base_url"].as_str().unwrap(),
        stub.base_url()
    );
}

#[test]
fn attest_wait_timeout_exits_3_with_complete_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig {
        // The record reaches `confirming` and then nothing but keep-alives.
        sse_frames: vec![
            SseFrame {
                event: "state",
                data: snapshot_json("submitting", false),
            },
            SseFrame {
                event: "poe_status_changed",
                data: snapshot_json("confirming", true),
            },
        ],
        sse_pings_after: true,
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--leaf",
            &"bb".repeat(32),
            "--timeout",
            "2",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "a wait timeout exits 3 (pending)"
    );

    // The outputs are complete: the outcome landed on stdout, the receipt on
    // disk with the last observed status, and the structured error on stderr.
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(outcome["wait_reached"], false);
    assert_eq!(outcome["status"], "confirming");
    let receipt = read_json(&dir.path().join("r.json"));
    assert_eq!(receipt["status"], "confirming");
    assert_eq!(receipt["wait"]["timed_out"], true);
    let err: serde_json::Value =
        serde_json::from_slice(String::from_utf8_lossy(&out.stderr).trim().as_bytes()).unwrap();
    assert_eq!(err["error"]["code"], 3);
}

// ---------------------------------------------------------------------------
// 7. --max-usd refusal happens before any spend
// ---------------------------------------------------------------------------

#[test]
fn attest_max_usd_refuses_before_upload_and_publish() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), b"first").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"second").unwrap();
    // The stub quotes $1.50; the cap is $1.00.
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--paths",
            "a.bin",
            "--paths",
            "b.bin",
            "--max-usd",
            "1.00",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "the price-cap refusal exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--max-usd"), "stderr: {stderr}");

    // The refusal fired after the quote and before any spend.
    assert_eq!(stub.requests_to("/poe/quote").len(), 1);
    assert!(stub.requests_to("/poe/uploads").is_empty());
    assert!(stub.requests_to("/poe/publish").is_empty());
}

// ---------------------------------------------------------------------------
// 8. --commits: raw commit objects, rev-list --reverse order
// ---------------------------------------------------------------------------

#[test]
fn attest_commits_hashes_raw_commit_objects_oldest_first() {
    let dir = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    git(&["init", "-q"]);
    for i in 0..3 {
        std::fs::write(dir.path().join("f.txt"), format!("rev {i}")).unwrap();
        git(&["add", "f.txt"]);
        git(&[
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            &format!("commit {i}"),
        ]);
    }
    // The expected leaves: SHA-256 of each raw commit object, oldest first.
    let rev_list = String::from_utf8(git(&["rev-list", "--reverse", "HEAD"])).unwrap();
    let shas: Vec<&str> = rev_list.lines().collect();
    assert_eq!(shas.len(), 3);
    let expected_leaves: Vec<[u8; 32]> = shas
        .iter()
        .map(|sha| sha256(&git(&["cat-file", "commit", sha])))
        .collect();
    let expected_root = merkle_root(&expected_leaves).unwrap();

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--commits",
            "HEAD",
            "--publish",
            "root",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "attest --commits failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let receipt = read_json(&dir.path().join("r.json"));
    assert_eq!(
        receipt["merkle"]["root"].as_str().unwrap(),
        hex::encode(expected_root),
        "root over sha256(raw commit objects) in rev-list --reverse order"
    );
    // The receipt attributes every leaf to its commit, in order.
    let commits = receipt["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 3);
    for (i, sha) in shas.iter().enumerate() {
        assert_eq!(commits[i]["commit"].as_str().unwrap(), *sha);
        assert_eq!(
            commits[i]["sha2_256"].as_str().unwrap(),
            hex::encode(expected_leaves[i])
        );
    }
}

// ---------------------------------------------------------------------------
// 9. Certificates: written on a confirmed anchor, verifiable offline
// ---------------------------------------------------------------------------

#[test]
fn attest_certificates_are_written_and_verify_offline() {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in [("a.bin", "one"), ("b.bin", "two"), ("c.bin", "three")] {
        std::fs::write(dir.path().join(name), content).unwrap();
    }
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--paths",
            "*.bin",
            "--certificates-dir",
            "certs",
            "--receipt-out",
            "r.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let receipt = read_json(&dir.path().join("r.json"));
    assert_eq!(receipt["certificates_written"], 3);

    for (index, expected_label) in ["a.bin", "b.bin", "c.bin"].iter().enumerate() {
        let path = dir.path().join(format!("certs/{index}.certificate.json"));
        assert!(path.exists(), "missing {}", path.display());
        let cert = read_json(&path);
        assert_eq!(cert["items"][0]["label"].as_str().unwrap(), *expected_label);
        assert_eq!(cert["anchor"]["tx_hash"].as_str().unwrap(), stub_tx_hash());

        // Every certificate re-verifies offline through the real verb.
        let verify = cli(&stub, dir.path())
            .args(["certificate", "verify", path.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert_eq!(
            verify.status.code(),
            Some(0),
            "certificate {index} failed to verify: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Signed attest + secret hygiene
// ---------------------------------------------------------------------------

#[test]
fn attest_with_seed_signs_the_record_and_leaks_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let seed_hex = "cd".repeat(32);
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--leaf",
            &"11".repeat(32),
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
        "signed attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The published record carries a path-1 signature from the seed's key.
    let (_, record) = captured_record(&stub);
    assert!(record.sigs.is_some(), "the record must be signed");
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

    // Neither output surface carries the seed or the API key.
    let stdout_text = String::from_utf8_lossy(&out.stdout);
    for surface in [receipt_text.as_str(), &stdout_text] {
        assert!(!surface.contains(&seed_hex), "the seed leaked");
        assert!(!surface.contains("stub-test-key"), "the API key leaked");
    }
}

// ---------------------------------------------------------------------------
// 11. submit upgrades: exact quote, --idempotency-key, --wait
// ---------------------------------------------------------------------------

#[test]
fn submit_hash_quotes_exactly_waits_and_sends_the_idempotency_key() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "submit",
            "--hash",
            &"aa".repeat(32),
            "--idempotency-key",
            "ci-run-42",
            "--wait",
            "confirmed",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "submit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    let (record_bytes, _) = captured_record(&stub);
    assert_eq!(
        quote_body["record_bytes"].as_u64().unwrap(),
        record_bytes.len() as u64,
        "submit --hash is quoted at the exact canonical length"
    );
    assert_eq!(
        stub.requests_to("/poe/publish")[0]
            .header("idempotency-key")
            .unwrap(),
        "ci-run-42"
    );
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(outcome["status"], "confirmed", "--wait updates the summary");
    assert_eq!(outcome["tx_hash"].as_str().unwrap(), stub_tx_hash());
}

#[test]
fn submit_merkle_quote_covers_the_actual_record_and_storage_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let leaves: Vec<[u8; 32]> = (0u8..2).map(|i| sha256(&[0x40 + i])).collect();
    let leaves_file = dir.path().join("leaves.txt");
    std::fs::write(
        &leaves_file,
        leaves
            .iter()
            .map(|l| format!("{}\n", hex::encode(l)))
            .collect::<String>(),
    )
    .unwrap();

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "submit",
            "--merkle",
            leaves_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "submit --merkle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    let (record_bytes, record) = captured_record(&stub);
    let quoted = quote_body["record_bytes"].as_u64().unwrap();
    assert!(
        quoted >= record_bytes.len() as u64,
        "quote ({quoted}) must cover the record ({}) — the old 320-byte constant undershot",
        record_bytes.len()
    );
    // The record genuinely carries the ar:// URI that made it bigger.
    let merkle = record.merkle.unwrap();
    assert!(merkle[0].uris.as_ref().is_some_and(|u| !u.is_empty()));
    // The storage side is the exact canonical leaves-list byte count.
    let root = merkle_root(&leaves).unwrap();
    let leaves_list = encode_leaves_list(&leaves, &root, None).unwrap();
    assert_eq!(
        quote_body["file_bytes_total"].as_u64().unwrap(),
        leaves_list.len() as u64
    );
}

// ---------------------------------------------------------------------------
// Regressions: non-UTF-8 paths and quote-TTL expiry across the upload
// ---------------------------------------------------------------------------

/// A non-UTF-8 filename inside a globbed tree must be a loud exit-4 refusal
/// naming the path — never a silent omission. The glob engine cannot even
/// test such a name against the pattern, and two names differing only in
/// their invalid byte would lossily collapse onto one manifest entry.
#[cfg(unix)]
#[test]
fn attest_refuses_non_utf8_paths_instead_of_silently_dropping_them() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("good.bin"), b"good").unwrap();
    // Two names differing ONLY in their invalid byte: the lossy projections
    // are identical, so a lossy dedupe key would silently drop one of them.
    let bad_names: [&[u8]; 2] = [b"bad\x80.bin", b"bad\x81.bin"];
    for raw in bad_names {
        if std::fs::write(data.join(OsStr::from_bytes(raw)), b"x").is_err() {
            // This filesystem (e.g. APFS) refuses non-UTF-8 names outright,
            // so the hazard cannot exist here; the refusal path is covered by
            // the unit tests over in-memory paths.
            eprintln!("skipping: the filesystem refuses non-UTF-8 names");
            return;
        }
    }

    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["attest", "--paths", "data/*.bin", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "a non-UTF-8 name must refuse, not drop: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid UTF-8"), "stderr: {stderr}");
    assert!(
        stderr.contains("bad"),
        "the offending path is named: {stderr}"
    );
    // The refusal fired before any network traffic or manifest write.
    assert!(stub.requests().is_empty());
    assert!(!dir.path().join("poe-manifest.json").exists());
}

/// When the leaves-list upload outlives the quote TTL, attest re-quotes and
/// publishes exactly once against the fresh price lock.
#[test]
fn attest_requotes_when_the_price_lock_expires_before_publish() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig {
        expired_quotes: 1,
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--leaf",
            &"aa".repeat(32),
            "--leaf",
            &"bb".repeat(32),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The stale lock was replaced: two quotes, ONE publish, and the publish
    // consumed the fresh quote id.
    assert_eq!(stub.requests_to("/poe/quote").len(), 2);
    assert_eq!(stub.requests_to("/poe/uploads").len(), 1);
    let publishes = stub.requests_to("/poe/publish");
    assert_eq!(publishes.len(), 1, "exactly one publish");
    assert_eq!(publishes[0].body_json()["quote_id"], "q_2");
}

/// The --max-usd cap is a promise about what gets spent, so a re-quote after
/// an expired lock re-enforces it against the NEW price: a fresh quote above
/// the cap refuses before the publish even though the original quote passed.
#[test]
fn attest_requote_reenforces_max_usd_against_the_fresh_price() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig {
        expired_quotes: 1,
        // First quote $0.90 (under the $1.00 cap), the re-quote $1.50 (over).
        quote_amounts: vec!["900000".to_string(), "1500000".to_string()],
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args([
            "attest",
            "--leaf",
            &"cc".repeat(32),
            "--leaf",
            &"dd".repeat(32),
            "--max-usd",
            "1.00",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "the re-quote refusal exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--max-usd"), "stderr: {stderr}");

    // The original quote passed, the upload ran, the fresh quote refused —
    // and nothing was published.
    assert_eq!(stub.requests_to("/poe/quote").len(), 2);
    assert_eq!(stub.requests_to("/poe/uploads").len(), 1);
    assert!(stub.requests_to("/poe/publish").is_empty());
}

// ---------------------------------------------------------------------------
// submit items surface: --record, multi --hash, --supersedes, --store
// ---------------------------------------------------------------------------

/// The air-gap loop closes: a record built and signed elsewhere (the
/// `sign prepare` → external signer → `sign assemble` chain) publishes
/// byte-for-byte — no re-encoding, no re-signing.
#[test]
fn submit_record_publishes_prebuilt_bytes_verbatim() {
    use cardanowall::client::{assemble_cose_sign1, prepare_sig_structure, Signer as _};
    use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};

    // Build + sign the record exactly the way the air-gap flow would.
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(
                "sha2-256".to_string(),
                sha256(b"air-gapped content").to_vec(),
            )],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let signer = cardanowall::seed_derive::signer_from_seed(&[0x42u8; 32]).unwrap();
    let pubkey = signer.signer_pubkey();
    let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
    let signature = signer.sign(&prepared.sig_structure_bytes).unwrap();
    let assembled = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();
    let mut signed = record;
    signed.sigs = Some(vec![assembled.sig_entry]);
    let signed_bytes = encode_poe_record(&signed).unwrap();
    let signed_hex = hex::encode(&signed_bytes);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("record.hex"), &signed_hex).unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["submit", "--record", "record.hex", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "submit --record failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Byte-preserving: the gateway received EXACTLY the pre-built bytes.
    let publish_body = stub.requests_to("/poe/publish")[0].body_json();
    assert_eq!(publish_body["record"].as_str().unwrap(), signed_hex);
    // And the quote priced the exact canonical length.
    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    assert_eq!(
        quote_body["record_bytes"].as_u64().unwrap(),
        signed_bytes.len() as u64
    );
}

/// A malformed --record fails the local structural validator: exit 4 with the
/// validator's own error codes, before any network call.
#[test]
fn submit_record_rejects_invalid_cbor_with_validator_codes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("junk.bin"), [0x00u8, 0x01, 0x02, 0xff]).unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["submit", "--record", "junk.bin"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a valid Label 309 record"),
        "stderr: {stderr}"
    );
    assert!(stub.requests().is_empty(), "no quote for an invalid record");
}

/// Repeatable --hash publishes one record with one items[i] per digest, in
/// argument order, quoted at its exact canonical length.
#[test]
fn submit_multi_hash_publishes_one_item_per_digest() {
    let first = sha256(b"artifact one");
    let second = sha256(b"artifact two");
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "submit",
            "--hash",
            &hex::encode(first),
            "--hash",
            &hex::encode(second),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "multi --hash failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (record_bytes, record) = captured_record(&stub);
    let items = record.items.expect("items present");
    assert_eq!(items.len(), 2, "one item per digest");
    assert_eq!(items[0].hashes[0].1, first.to_vec());
    assert_eq!(items[1].hashes[0].1, second.to_vec());
    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    assert_eq!(
        quote_body["record_bytes"].as_u64().unwrap(),
        record_bytes.len() as u64
    );
}

/// --supersedes lands in the record's supersedes field, on submit and attest.
#[test]
fn supersedes_lands_in_the_record_on_submit_and_attest() {
    let old_tx = "1f".repeat(32);

    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args([
            "submit",
            "--hash",
            &"aa".repeat(32),
            "--supersedes",
            &old_tx,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let (_, record) = captured_record(&stub);
    assert_eq!(record.supersedes, Some(vec![0x1f; 32]));

    let dir2 = tempfile::tempdir().unwrap();
    let stub2 = StubGateway::start(StubConfig::default());
    let out2 = cli(&stub2, dir2.path())
        .args([
            "attest",
            "--leaf",
            &"bb".repeat(32),
            "--leaf",
            &"cc".repeat(32),
            "--publish",
            "root",
            "--supersedes",
            &old_tx,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    let (_, merkle_record) = captured_record(&stub2);
    assert_eq!(merkle_record.supersedes, Some(vec![0x1f; 32]));
    assert!(merkle_record.merkle.is_some());
}

/// --store uploads the PLAINTEXT (a public attachment, the opposite of seal)
/// and binds the returned ar:// URI into the record.
#[test]
fn submit_store_uploads_content_and_binds_the_uri() {
    let content = b"public whitepaper content, stored alongside its hash";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("paper.bin"), content).unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["submit", "--file", "paper.bin", "--store", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "submit --store failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The content itself went to storage (public attachment semantics).
    let uploads = stub.requests_to("/poe/uploads");
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].body.windows(content.len()).any(|w| w == content));

    // The record binds hash + URI; the quote covered the record and priced
    // the exact content size on the storage side.
    let (record_bytes, record) = captured_record(&stub);
    let items = record.items.expect("items present");
    assert_eq!(items[0].hashes[0].1, sha256(content).to_vec());
    assert_eq!(
        items[0].uris.as_deref(),
        Some(&[common::stub_gateway::stub_ar_uri()][..])
    );
    let quote_body = stub.requests_to("/poe/quote")[0].body_json();
    assert!(quote_body["record_bytes"].as_u64().unwrap() >= record_bytes.len() as u64);
    assert_eq!(
        quote_body["file_bytes_total"].as_u64().unwrap(),
        content.len() as u64
    );

    // The summary surfaces the storage URI.
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        outcome["ar_uri"].as_str().unwrap(),
        common::stub_gateway::stub_ar_uri()
    );
}

/// A stale or broken CARDANOWALL_SEED in the environment must not fail a
/// --record publish: that mode never signs, so the seed is never resolved.
#[test]
fn submit_record_ignores_a_garbage_seed_in_the_environment() {
    use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![(
                "sha2-256".to_string(),
                sha256(b"env-seed-agnostic").to_vec(),
            )],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let record_hex = hex::encode(encode_poe_record(&record).unwrap());

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("record.hex"), &record_hex).unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["submit", "--record", "record.hex", "--json"])
        .env("CARDANOWALL_SEED", "not-a-valid-seed-at-all")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a garbage env seed must not break --record: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        stub.requests_to("/poe/publish")[0].body_json()["record"]
            .as_str()
            .unwrap(),
        record_hex
    );
}

/// Explicit seed flags alongside --record are refused with a clear message —
/// the mode cannot sign, and `--seed-stdin` would fight `--record -` for
/// stdin.
#[test]
fn submit_record_refuses_explicit_seed_flags() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig::default());
    let out = cli(&stub, dir.path())
        .args(["submit", "--record", "-", "--seed-stdin"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("never signs"),
        "the refusal explains itself: {stderr}"
    );
    assert!(
        stub.requests().is_empty(),
        "refused before any network call"
    );
}

/// A submit dedup replay (the gateway's 200 for byte-identical record bytes)
/// surfaces as `replayed: true` — the caller can tell nothing new was
/// anchored and nothing was debited.
#[test]
fn submit_dedup_replay_reports_replayed_with_no_new_debit() {
    let dir = tempfile::tempdir().unwrap();
    let stub = StubGateway::start(StubConfig {
        publish: PublishBehavior::DedupRawSubmitted,
        ..StubConfig::default()
    });
    let out = cli(&stub, dir.path())
        .args(["submit", "--hash", &"9d".repeat(32), "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a dedup replay is a success: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let outcome: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(outcome["replayed"], true);
    // The raw engine `submitted` status never leaks.
    assert_eq!(outcome["status"], "confirming");
    assert_eq!(outcome["balance_after_usd_micros"], "8500000");
}
