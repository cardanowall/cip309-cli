//! The subcommand handlers. Each module owns one top-level command's argument
//! struct(s) and its `run` entry, returning `Result<(), CliError>` so the
//! dispatcher in [`crate::cli`] can map the error to a process exit code.
//! `publish_common` carries the plumbing the anchoring commands (`submit`,
//! `attest`) share.

pub mod attest;
pub mod certificate;
pub mod completion;
pub mod gateway;
pub mod identity;
pub mod inbox;
pub mod merkle;
pub mod publish_common;
pub mod seal;
pub mod sign;
pub mod submit;
pub mod verify;
