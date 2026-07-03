//! The clap command tree and the top-level dispatcher with the exit-code mapping.
//!
//! [`run`] is the single entry point shared by the binary and the integration
//! tests: it parses argv, routes to a command handler, and collapses the
//! handler's `Result<(), CliError>` into the process exit code. Clap's own parse
//! failures (bad flags, unknown subcommands, missing required args) map to `4`;
//! `--help` / `--version` map to `0`.
//!
//! ## Global flags
//!
//! `--color <auto|always|never>` / `--no-color` set the color policy (honoured
//! together with `NO_COLOR` / `CLICOLOR_FORCE` / `is_terminal()`), `--quiet`
//! suppresses non-essential stderr chatter, and a global `--json` puts the active
//! command into machine-output mode (its own `--json` works too). When the active
//! command is in JSON mode and fails, the dispatcher emits a structured error
//! object on stderr instead of the plain `cardanowall: <message>` line.
//!
//! ## Environment
//!
//! Every secret / config flag has a consistent env fallback used on ALL commands:
//!
//! - `CARDANOWALL_BASE_URL`      ← `--base-url`
//! - `CARDANOWALL_API_KEY`       ← `--api-key`
//! - `CARDANOWALL_SEED`          ← `--seed`        (identity, sign, submit, inbox)
//! - `CARDANOWALL_RECIPIENT_KEY` ← `--secret-key`  (verify, inbox)
//! - `CARDANOWALL_CARDANO_GATEWAY` / `CARDANOWALL_ARWEAVE_GATEWAY` /
//!   `CARDANOWALL_IPFS_GATEWAY` / `CARDANOWALL_BLOCKFROST_PROJECT_ID` /
//!   `CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD` / `CARDANOWALL_DENY_HOST`
//! - `CARDANOWALL_CONFIG_PATH` overrides `~/.cardanowall/config.toml`.

use std::ffi::OsString;

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::util::color::ColorChoice;
use crate::util::version::version_string;

/// The `cardanowall` CLI: a standalone Label 309 Proof-of-Existence toolkit.
#[derive(Debug, Parser)]
#[command(
    name = "cardanowall",
    bin_name = "cardanowall",
    about = "Label 309 standalone verifier and Proof-of-Existence toolkit",
    long_about = "Label 309 standalone verifier and Proof-of-Existence toolkit.\n\n\
        ENVIRONMENT (consistent across every command):\n  \
        CARDANOWALL_BASE_URL       gateway base URL incl. version, e.g. .../api/v1  (--base-url)\n  \
        CARDANOWALL_API_KEY        opaque bearer API key   (--api-key)\n  \
        CARDANOWALL_SEED           identity seed: hex or L309-SEED-1...  (--seed)\n  \
        CARDANOWALL_RECIPIENT_KEY  X25519 recipient key (hex)  (--secret-key)\n  \
        CARDANOWALL_CARDANO_GATEWAY / CARDANOWALL_ARWEAVE_GATEWAY /\n  \
        CARDANOWALL_IPFS_GATEWAY / CARDANOWALL_BLOCKFROST_PROJECT_ID /\n  \
        CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD / CARDANOWALL_DENY_HOST\n  \
        CARDANOWALL_CONFIG_PATH    overrides ~/.cardanowall/config.toml\n\n\
        High-secret flags (--seed, --secret-key) also accept a *-file / *-stdin\n\
        variant and, on a TTY, a hidden interactive prompt. --seed takes 64-digit\n\
        hex or the checksummed L309-SEED-1... form; the raw --seed / --secret-key\n\
        argv flag is INSECURE (shell history / ps / CI logs).",
    version = version_string(),
    disable_version_flag = true
)]
pub struct Cli {
    /// Print the package version, git SHA, and build date.
    #[arg(long, action = clap::ArgAction::Version)]
    version: Option<bool>,

    /// Global color / quiet / json flags shared by every command.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Cross-command flags marked `global = true` so they may appear before OR after
/// the subcommand, e.g. `cardanowall --no-color verify …` or `cardanowall verify
/// … --quiet`.
#[derive(Debug, Clone, Default, Args)]
pub struct GlobalArgs {
    /// Color policy: auto (default), always, or never.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,
    /// Disable colored output (shorthand for --color never).
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Suppress non-essential stderr chatter.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,
    /// Machine-output mode: structured JSON on stdout, structured errors on stderr.
    #[arg(long, global = true)]
    pub json: bool,
}

/// The `--color` value surface (a clap value-enum mirror of [`ColorChoice`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ColorMode {
    /// Decide from env + TTY.
    #[default]
    Auto,
    /// Always colorize.
    Always,
    /// Never colorize.
    Never,
}

impl GlobalArgs {
    /// The effective color choice: `--no-color` forces `Never`, else `--color`.
    #[must_use]
    pub fn color_choice(&self) -> ColorChoice {
        if self.no_color {
            return ColorChoice::Never;
        }
        match self.color {
            ColorMode::Auto => ColorChoice::Auto,
            ColorMode::Always => ColorChoice::Always,
            ColorMode::Never => ColorChoice::Never,
        }
    }
}

/// The top-level subcommand set.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify a Label 309 PoE record at a Cardano transaction hash.
    Verify(commands::verify::VerifyArgs),
    /// Anchor a Label 309 PoE on Cardano (hash / file / Merkle).
    Submit(commands::submit::SubmitArgs),
    /// Anchor files, git commits, or digests as one PoE (CI-oriented).
    Attest(commands::attest::AttestArgs),
    /// Publish a sealed PoE: encrypt a file to recipients and anchor it.
    Seal(commands::seal::SealArgs),
    /// Offline PATH-1 (identity Ed25519) record signing.
    Sign(commands::sign::SignArgs),
    /// Derive and print the public identity from a 32-byte master seed (offline).
    Identity(commands::identity::IdentityArgs),
    /// Off-chain Merkle tooling.
    Merkle(commands::merkle::MerkleArgs),
    /// Build and verify Label 309 inclusion certificates.
    Certificate(commands::certificate::CertificateArgs),
    /// Sealed-PoE inbox commands.
    Inbox(commands::inbox::InboxArgs),
    /// Manage named service-gateway profiles (endpoint + API key).
    Gateway(commands::gateway::GatewayArgs),
    /// Print a shell completion script.
    Completion(commands::completion::CompletionArgs),
}

impl Command {
    /// The command's short name, used in the structured JSON-error object.
    fn name(&self) -> &'static str {
        match self {
            Command::Verify(_) => "verify",
            Command::Submit(_) => "submit",
            Command::Attest(_) => "attest",
            Command::Seal(_) => "seal",
            Command::Sign(_) => "sign",
            Command::Identity(_) => "identity",
            Command::Merkle(_) => "merkle",
            Command::Certificate(_) => "certificate",
            Command::Inbox(_) => "inbox",
            Command::Gateway(_) => "gateway",
            Command::Completion(_) => "completion",
        }
    }

    /// Whether this command was invoked in JSON (machine-output) mode, OR-ing the
    /// per-command `--json` with the global one so either placement works.
    fn json_mode(&self, global_json: bool) -> bool {
        global_json || self.local_json()
    }

    /// The per-command `--json` flag, where the command has one.
    fn local_json(&self) -> bool {
        match self {
            Command::Verify(a) => a.json,
            Command::Submit(a) => a.json,
            Command::Attest(a) => a.json,
            Command::Seal(a) => a.json,
            Command::Sign(a) => a.source_json(),
            Command::Identity(a) => a.json,
            Command::Merkle(a) => a.json_mode(),
            Command::Certificate(a) => a.json_mode(),
            Command::Inbox(a) => a.json_mode(),
            Command::Gateway(a) => a.json_mode(),
            Command::Completion(_) => false,
        }
    }
}

/// Cross-command runtime context resolved once from the global flags: the color
/// choice and quiet mode, plus the JSON mode the dispatcher computed.
#[derive(Debug, Clone, Copy)]
pub struct GlobalContext {
    /// The resolved color choice.
    pub color: ColorChoice,
    /// Whether non-essential stderr chatter is suppressed.
    pub quiet: bool,
    /// Whether the active command is in JSON (machine-output) mode.
    pub json: bool,
}

/// Parse `args`, dispatch, and return the process exit code (`0`–`4`).
///
/// A clap parse error or unknown subcommand maps to `4`; `--help` / `--version`
/// short-circuit to `0`. A handler's [`CliError`](crate::util::CliError) is
/// printed to stderr — as `cardanowall: <message>` in human mode, or as a
/// structured `{"error":{…}}` object in JSON mode — and its code returned.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            // `--help` / `--version` are reported as "errors" by clap but are a
            // success exit; everything else (bad flag, unknown subcommand,
            // missing required arg) is a CLI input error → 4.
            use clap::error::ErrorKind;
            let kind = err.kind();
            // Print to the stream clap intends (stdout for help/version).
            let _ = err.print();
            if matches!(
                kind,
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                return 0;
            }
            return 4;
        }
    };

    let json = cli.command.json_mode(cli.global.json);
    let command_name = cli.command.name();
    let ctx = GlobalContext {
        color: cli.global.color_choice(),
        quiet: cli.global.quiet,
        json,
    };

    let result = match cli.command {
        Command::Verify(args) => commands::verify::run(args),
        Command::Submit(args) => commands::submit::run(args),
        Command::Attest(args) => commands::attest::run(args),
        Command::Seal(args) => commands::seal::run(args),
        Command::Sign(args) => commands::sign::run(args),
        Command::Identity(args) => commands::identity::run(args),
        Command::Merkle(args) => commands::merkle::run(args),
        Command::Certificate(args) => commands::certificate::run(args),
        Command::Inbox(args) => commands::inbox::run(args),
        Command::Gateway(args) => commands::gateway::run(args),
        Command::Completion(args) => commands::completion::run(args),
    };

    match result {
        Ok(()) => 0,
        Err(err) => {
            report_error(&err, command_name, &ctx);
            err.code
        }
    }
}

/// Write a command failure to stderr.
///
/// In human mode this is the familiar `cardanowall: <message>` line, with the
/// prefix dyed red when color is enabled (silent when the message is empty — e.g.
/// `verify` already printed its report). In JSON mode it is a single structured
/// object so automation can parse the failure:
/// `{"error":{"code":<exit_code>,"message":"<text>","command":"<name>"}}`.
fn report_error(err: &crate::util::CliError, command: &str, ctx: &GlobalContext) {
    if ctx.json {
        let value = serde_json::json!({
            "error": {
                "code": err.code,
                "message": err.message,
                "command": command,
            }
        });
        eprintln!("{value}");
    } else if !err.message.is_empty() {
        use crate::util::color::{should_color, Stream, SystemColorEnv};
        use owo_colors::OwoColorize;
        let colored = should_color(ctx.color, false, Stream::Stderr, &SystemColorEnv);
        if colored {
            eprintln!("{}: {}", "cardanowall".red(), err.message);
        } else {
            eprintln!("cardanowall: {}", err.message);
        }
    }
}
