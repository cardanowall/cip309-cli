//! Documentation ↔ binary drift guard: every `cardanowall …` line inside a
//! ```bash fence of README.md and docs/GUIDE.md must name a real subcommand,
//! and every `--flag` it shows must exist in that subcommand's `--help`.
//!
//! This does not execute the examples (they need gateways, seeds, funds); it
//! pins the one property docs rot breaks first — flag names that no longer
//! parse — so a renamed or removed flag fails CI until the docs follow.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Subcommands whose first positional token is itself a verb, so `--help`
/// must be asked of the two-token form.
const NESTED_PARENTS: &[&str] = &["gateway", "sign", "merkle", "certificate", "inbox"];

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cardanowall"))
}

/// One documented invocation: the subcommand path and the flags it shows.
#[derive(Debug)]
struct DocumentedCall {
    source: String,
    subcommand: Vec<String>,
    flags: Vec<String>,
}

/// Extract every `cardanowall …` invocation from the ```bash fences of a
/// markdown document, joining backslash continuations and stripping pipes,
/// redirections, and comments.
fn extract_calls(markdown: &str, source_name: &str) -> Vec<DocumentedCall> {
    let mut calls = Vec::new();
    let mut in_bash = false;
    let mut pending = String::new();
    for raw_line in markdown.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with("```") {
            in_bash = trimmed.trim_start_matches('`').trim().starts_with("bash");
            pending.clear();
            continue;
        }
        if !in_bash {
            continue;
        }
        // Join continuation lines into one logical command.
        let (fragment, continues) = match trimmed.strip_suffix('\\') {
            Some(head) => (head, true),
            None => (trimmed, false),
        };
        pending.push_str(fragment);
        pending.push(' ');
        if continues {
            continue;
        }
        let logical = std::mem::take(&mut pending);
        if let Some(call) = parse_call(&logical, source_name) {
            calls.push(call);
        }
    }
    calls
}

/// Parse one logical shell line into a documented invocation, when it invokes
/// `cardanowall` at all.
fn parse_call(logical: &str, source_name: &str) -> Option<DocumentedCall> {
    // Strip a trailing comment (a ` #` outside quotes is close enough for the
    // docs' shape) and take the segment after the last pipe, where the
    // `cardanowall` invocation lives in `printf … | cardanowall …` examples.
    let no_comment = match logical.find(" #") {
        Some(pos) => &logical[..pos],
        None => logical,
    };
    let segment = no_comment.rsplit('|').next().unwrap_or(no_comment).trim();
    let mut tokens = segment.split_whitespace();
    if tokens.next()? != "cardanowall" {
        return None;
    }

    let mut subcommand: Vec<String> = Vec::new();
    let mut flags: Vec<String> = Vec::new();
    for token in tokens {
        // A redirection or here-string ends the argv of interest.
        if token.starts_with('>') || token.starts_with("<<<") {
            break;
        }
        if let Some(flag) = token.strip_prefix("--") {
            let name = flag.split('=').next().unwrap_or(flag);
            if !name.is_empty() {
                flags.push(format!("--{name}"));
            }
            continue;
        }
        // Placeholders (`<tx-hash>`) and values are not part of the command
        // path; only leading bare words select the subcommand.
        if token.starts_with('<') {
            continue;
        }
        let extends_path = subcommand.is_empty()
            || (subcommand.len() == 1
                && NESTED_PARENTS.contains(&subcommand[0].as_str())
                && flags.is_empty());
        if extends_path {
            subcommand.push(token.to_string());
        }
    }
    if subcommand.is_empty() {
        // e.g. `cardanowall <command> --help` — a placeholder subcommand.
        return None;
    }
    Some(DocumentedCall {
        source: format!("{source_name}: {}", segment.trim()),
        subcommand,
        flags,
    })
}

/// The set of `--flags` a subcommand's `--help` admits.
fn help_flags(subcommand: &[String]) -> BTreeSet<String> {
    let output = Command::new(bin())
        .args(subcommand)
        .arg("--help")
        .output()
        .expect("run cardanowall --help");
    assert!(
        output.status.success(),
        "documented subcommand `cardanowall {}` does not exist (--help failed):\n{}",
        subcommand.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let mut flags = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if &bytes[i..i + 2] == b"--" && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-') {
                end += 1;
            }
            if end > start {
                flags.insert(format!("--{}", &text[start..end]));
            }
            i = end;
        } else {
            i += 1;
        }
    }
    flags
}

#[test]
fn every_documented_example_names_real_subcommands_and_flags() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        ("README.md", root.join("README.md")),
        ("docs/GUIDE.md", root.join("docs/GUIDE.md")),
    ];

    let mut checked = 0usize;
    for (name, path) in sources {
        let markdown = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        for call in extract_calls(&markdown, name) {
            let known = help_flags(&call.subcommand);
            for flag in &call.flags {
                assert!(
                    known.contains(flag),
                    "{}\n  documents `{}` but `cardanowall {} --help` does not list it \
                     (known flags: {:?})",
                    call.source,
                    flag,
                    call.subcommand.join(" "),
                    known
                );
            }
            checked += 1;
        }
    }
    // The docs genuinely carry examples; a silent zero would make this vacuous.
    assert!(
        checked >= 25,
        "expected the docs to carry at least 25 cardanowall invocations, found {checked}"
    );
}
