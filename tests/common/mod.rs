//! Shared test helpers: resolve the cross-implementation fixture trees by path.
//!
//! These fixtures are the canonical cross-implementation conformance vectors,
//! vendored under `tests/fixtures/` so this repository verifies the CLI's
//! verify-report exit-code contract entirely on its own. They are byte-identical
//! to the vectors the TypeScript and Python SDKs load.
#![allow(dead_code)]

pub mod stub_gateway;

use std::path::{Path, PathBuf};

/// Absolute path to the TypeScript SDK fixture tree (the verify-report goldens).
pub fn sdk_ts_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-ts")
}

/// Absolute path to the Python SDK fixture tree (the mainnet corpus).
pub fn sdk_py_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-py")
}

/// Read and parse a JSON fixture file, panicking with a path-tagged message.
pub fn read_fixture_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}
