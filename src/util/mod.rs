//! Cross-cutting CLI utilities: the exit-code-bearing error type, hex helpers,
//! USD money rendering/parsing, RFC 3339 parsing, and the build-stamped
//! version string.

pub mod base64;
pub mod color;
pub mod error;
pub mod hex;
pub mod rfc3339;
pub mod usd;
pub mod version;

pub use color::{should_color, ColorChoice, ColorEnv, Stream, SystemColorEnv};
pub use error::CliError;
pub use hex::{bytes_to_hex, hex_to_bytes, is_all_hex};
pub use usd::{format_usd_micros, parse_usd_to_micros};
