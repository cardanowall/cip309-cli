//! Integration tests for the ergonomics + secret-hygiene surface:
//!
//! - gateway profiles: add (key from stdin) → list (key masked) → use → show →
//!   remove, with the config file written `0600` and existing data-gateway fields
//!   round-tripped intact;
//! - the structured JSON error object on a failing `--json` command;
//! - shell completion generation;
//! - the `--cardano-gateway` rename plus its `--gateway` alias.
//!
//! Every test drives the real binary so the clap wiring, env handling, and file
//! permissions are exercised end-to-end. Secret input never depends on a real
//! TTY: profiles read the API key from stdin and high-secrets from stdin/env.

use std::path::PathBuf;
use std::process::Command;

/// Path to the freshly-built `cardanowall` binary under test.
fn bin() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for the crate's binary targets.
    PathBuf::from(env!("CARGO_BIN_EXE_cardanowall"))
}

/// A command pre-pointed at an isolated config file so tests never read or write
/// the developer's real `~/.cardanowall/config.toml`. `HOME` is also redirected so
/// nothing leaks into a real home directory.
fn cmd(config_path: &std::path::Path, home: &std::path::Path) -> Command {
    let mut c = Command::new(bin());
    c.env("CARDANOWALL_CONFIG_PATH", config_path)
        .env("HOME", home)
        .env_remove("CARDANOWALL_BASE_URL")
        .env_remove("CARDANOWALL_API_KEY")
        .env_remove("CARDANOWALL_SEED")
        .env_remove("CARDANOWALL_RECIPIENT_KEY")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    c
}

#[test]
fn gateway_profiles_round_trip_with_0600_and_preserved_fields() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    // Seed a hand-edited config with a data-gateway field that must survive the
    // gateway-profile writes untouched.
    std::fs::write(
        &config,
        "cardano_gateway = \"https://koios.example/api/v1\"\nconfirmation_depth_threshold = 9\n",
    )
    .unwrap();

    // add (API key from stdin) → first profile becomes the default.
    let out = cmd(&config, &home)
        .args(["gateway", "add", "prod", "--base-url", "https://gw.example"])
        .arg("--api-key-stdin")
        .stdin(piped("super-secret-key\n"))
        .output()
        .unwrap();
    assert!(out.status.success(), "gateway add failed: {out:?}");

    // The file is 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config.toml must be written 0600");
    }

    // The hand-edited data-gateway fields survived.
    let body = std::fs::read_to_string(&config).unwrap();
    assert!(
        body.contains("cardano_gateway") && body.contains("koios.example"),
        "existing cardano_gateway must round-trip; got:\n{body}"
    );
    assert!(body.contains("confirmation_depth_threshold"));
    // The key is on disk (it is a stored credential, not a transient secret).
    assert!(body.contains("super-secret-key"));

    // list (JSON) masks the key and marks the default.
    let list = cmd(&config, &home)
        .args(["gateway", "list", "--json"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let prof = &v["gateways"][0];
    assert_eq!(prof["name"], "prod");
    assert_eq!(prof["base_url"], "https://gw.example");
    assert_eq!(prof["api_key"], "********", "list must mask the API key");
    assert_eq!(prof["has_api_key"], true);
    assert_eq!(prof["is_default"], true);

    // A second profile, then `use` switches the default.
    let add2 = cmd(&config, &home)
        .args([
            "gateway",
            "add",
            "staging",
            "--base-url",
            "https://stg.example",
        ])
        .arg("--api-key-stdin")
        .stdin(piped("")) // empty → key-less profile
        .output()
        .unwrap();
    assert!(add2.status.success());

    let use_out = cmd(&config, &home)
        .args(["gateway", "use", "staging"])
        .output()
        .unwrap();
    assert!(use_out.status.success());

    // show (JSON) for the now-default profile, key masked unless --reveal.
    let show = cmd(&config, &home)
        .args(["gateway", "show", "staging", "--json"])
        .output()
        .unwrap();
    let sv: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(sv["is_default"], true);
    assert_eq!(sv["has_api_key"], false);

    // remove clears the default it pointed at.
    let rm = cmd(&config, &home)
        .args(["gateway", "remove", "staging"])
        .output()
        .unwrap();
    assert!(rm.status.success());
    let after = std::fs::read_to_string(&config).unwrap();
    assert!(
        !after.contains("staging"),
        "removed profile must be gone; got:\n{after}"
    );
}

#[test]
fn unknown_gateway_profile_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = cmd(&config, &home)
        .args(["gateway", "use", "nope"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
}

#[test]
fn json_error_object_on_failing_command() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    // `submit --json` with no creds and no mode → CLI input error (4) carrying a
    // structured JSON error object on stderr.
    let out = cmd(&config, &home)
        .args(["submit", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8(out.stderr).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("stderr must be a JSON error object");
    assert_eq!(v["error"]["code"], 4);
    assert_eq!(v["error"]["command"], "submit");
    assert!(v["error"]["message"].as_str().unwrap().contains("submit"));
    // The data stream stays clean: no JSON error leaks to stdout.
    assert!(out.stdout.is_empty());
}

#[test]
fn submit_chunk_bytes_flag_parses_and_is_numeric() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    // A numeric `--chunk-bytes` parses, so the command proceeds past clap to its
    // own credential-resolution input error and emits the STRUCTURED submit JSON
    // error (a clap parse failure would print plain usage text, not this object).
    // That structured object is the proof the typed `u64` flag was accepted.
    let leaves = dir.path().join("leaves.txt");
    std::fs::write(&leaves, format!("{}\n", "ab".repeat(32))).unwrap();
    let ok = cmd(&config, &home)
        .args([
            "submit",
            "--merkle",
            leaves.to_str().unwrap(),
            "--chunk-bytes",
            "67108864",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(4), "no creds → input error");
    let stderr = String::from_utf8(ok.stderr).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim())
        .expect("a parsed --chunk-bytes reaches the structured submit error");
    assert_eq!(v["error"]["command"], "submit");

    // A non-numeric `--chunk-bytes` is a clap type error: still exit 4, but plain
    // usage text on stderr rather than the structured submit JSON object — which
    // confirms the flag is a typed integer, not a free string.
    let bad = cmd(&config, &home)
        .args(["submit", "--chunk-bytes", "not-a-number"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(4));
    let bad_stderr = String::from_utf8(bad.stderr).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(bad_stderr.trim()).is_err(),
        "a clap type error is plain usage text, not a JSON error object"
    );
}

#[test]
fn global_json_flag_also_triggers_structured_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // Global `--json` (before the subcommand) on a verb without its own --json.
    let out = cmd(&config, &home)
        .args(["--json", "verify", "not-a-hex"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8(out.stderr).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error"]["command"], "verify");
}

#[test]
fn completion_emits_nonempty_script_for_each_shell() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = cmd(&config, &home)
            .args(["completion", shell])
            .output()
            .unwrap();
        assert!(out.status.success(), "completion {shell} failed");
        let script = String::from_utf8(out.stdout).unwrap();
        assert!(!script.is_empty(), "completion {shell} was empty");
        assert!(
            script.contains("cardanowall"),
            "completion {shell} must reference the binary name"
        );
    }
}

#[test]
fn seed_from_stdin_drives_identity_json() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let seed = "ab".repeat(32);
    let out = cmd(&config, &home)
        .args(["identity", "--seed-stdin", "--json"])
        .stdin(piped(&format!("{seed}\n")))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "identity --seed-stdin failed: {out:?}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["fingerprint"].as_str().unwrap().contains('-'));
    assert!(v["age_recipient"].as_str().unwrap().starts_with("age1"));
}

#[test]
fn seed_from_env_drives_identity() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = cmd(&config, &home)
        .args(["identity", "--json"])
        .env("CARDANOWALL_SEED", "cd".repeat(32))
        .output()
        .unwrap();
    assert!(out.status.success(), "identity via env failed: {out:?}");
}

#[test]
fn cardano_gateway_flag_and_alias_both_parse() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let tx = "0".repeat(64);

    // The new spelling rejects a bad URL at parse/resolve time (exit 4).
    let new = cmd(&config, &home)
        .args(["verify", &tx, "--cardano-gateway", "not-a-url"])
        .output()
        .unwrap();
    assert_eq!(new.status.code(), Some(4));

    // The legacy `--gateway` alias still resolves to the same slot.
    let alias = cmd(&config, &home)
        .args(["verify", &tx, "--gateway", "not-a-url"])
        .output()
        .unwrap();
    assert_eq!(alias.status.code(), Some(4));
}

#[test]
fn no_color_help_runs() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = cmd(&config, &home)
        .args(["--help"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// Build a piped stdin from a string for a child process.
fn piped(content: &str) -> std::process::Stdio {
    use std::io::Write;
    // A temp file gives a real, seekable fd the child can read fully; this avoids
    // the deadlock of writing to a pipe whose reader hasn't been spawned yet.
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(0)).unwrap();
    std::process::Stdio::from(f)
}

#[test]
fn identity_generate_mints_a_usable_seed_once() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = cmd(&config, &home)
        .args(["identity", "--generate", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "identity --generate failed: {out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let l309 = v["seed"]["l309"].as_str().unwrap();
    let hex = v["seed"]["hex"].as_str().unwrap();
    assert!(l309.starts_with("L309-SEED-1"));
    assert_eq!(hex.len(), 64);
    assert!(v["age_recipient"].as_str().unwrap().starts_with("age1"));
    assert!(v["age1pqc_recipient"]
        .as_str()
        .unwrap()
        .starts_with("age1pqc1"));

    // The minted seed round-trips: feeding it back derives the SAME identity.
    let back = cmd(&config, &home)
        .args(["identity", "--json"])
        .env("CARDANOWALL_SEED", l309)
        .output()
        .unwrap();
    assert!(back.status.success());
    let b: serde_json::Value = serde_json::from_slice(&back.stdout).unwrap();
    assert_eq!(b["fingerprint"], v["fingerprint"]);
    assert_eq!(b["age1pqc_recipient"], v["age1pqc_recipient"]);
    // A supplied seed is never echoed back.
    assert!(b.get("seed").is_none());

    // --generate refuses to combine with a seed source.
    let conflict = cmd(&config, &home)
        .args(["identity", "--generate", "--seed", &"ab".repeat(32)])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(4));
}
