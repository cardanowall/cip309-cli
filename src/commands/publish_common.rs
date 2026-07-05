//! Shared plumbing for the anchoring commands (`submit`, `attest`, `seal`):
//! gateway resolution, optional record signing, canonical-record encoding,
//! gateway error mapping, quote freshness and the `--max-usd` cap, and the
//! lifecycle wait loop with its exit-code contract.
//!
//! These commands quote → publish → (optionally) wait against the same gateway
//! surface, so the pieces that must behave identically — which sources supply
//! the gateway endpoint, how a gateway rejection maps to an exit code, what a
//! wait timeout means — live here once.

use std::time::Duration;

use cardanowall::client::{
    assemble_cose_sign1, prepare_sig_structure, ClientError, Label309Client, PoeEventsError,
    PoeNamespace, PoeStatusSnapshot, PoeWaitError, PoeWaitInput, PoeWaitTarget, PublishError,
    PublishHelperError, QuoteInput, QuoteResponse, ResumableUploadError, SealPrepareError, Signer,
    DEFAULT_EVENTS_BACKOFF,
};
use cardanowall::poe_standard::{encode_poe_record, PoeRecord};
use cardanowall::seed_derive::{signer_from_seed, SeedSigner};

use crate::config::{load_config_for_edit, CardanoWallConfig, SystemConfigEnv};
use crate::secret::{
    resolve_secret_bytes, resolve_service_gateway, SecretArgs, SecretEnv, SecretKind,
    ServiceGateway,
};
use crate::util::rfc3339::rfc3339_to_epoch_seconds;
use crate::util::{format_usd_micros, hex_to_bytes, CliError};

/// A worst-case-width stand-in for the `ar://<tx>` URI a leaves-list upload
/// will mint. An Arweave transaction id is always 43 base64url characters, so
/// the final URI is exactly this wide — using it in a pre-upload record-size
/// estimate keeps the quoted `record_bytes` an upper bound of the published
/// record.
#[must_use]
pub fn arweave_uri_placeholder() -> String {
    format!("ar://{}", "A".repeat(43))
}

/// Idempotency-key role prefix for a merkle leaves-list storage upload. It is
/// the same scheme the SDK merkle-publish helper uses, so a given leaves-list
/// batch presents an identical key whether it is anchored inline (`attest
/// --publish full-tree`) or through the SDK helper (`submit --merkle`).
pub const LEAVES_LIST_UPLOAD_ROLE: &str = "merkle1-";

/// Idempotency-key role prefix for a stored plaintext-content upload
/// (`submit --file --store`). It is distinct from the leaves-list role so the
/// same bytes uploaded in the two roles can never collide on one key.
pub const STORED_CONTENT_UPLOAD_ROLE: &str = "content1-";

/// How many leading hex digits of the content digest a storage-upload
/// idempotency key carries. 128 bits is comfortably collision-resistant while
/// keeping the key short; the SDK merkle/sealed upload keys use the same width.
const UPLOAD_KEY_DIGEST_CHARS: usize = 32;

/// Derive a deterministic idempotency key for a storage upload from the exact
/// bytes being uploaded.
///
/// A storage upload is billed and lands before the record that references it is
/// published. If the process dies in that gap and the command is re-run, a
/// fresh upload session would bill the storage a second time. Keying the upload
/// on a pure function of its content means the retry presents the same key, so
/// the gateway replays the recorded upload instead of charging twice.
///
/// `role` names what is being uploaded (see the `*_UPLOAD_ROLE` prefixes) so two
/// upload kinds never share a key even on identical bytes.
#[must_use]
pub fn content_upload_idempotency_key(role: &str, blob: &[u8]) -> String {
    let digest = cardanowall::hex::encode(&cardanowall::hash::sha256(blob));
    format!("{role}{}", &digest[..UPLOAD_KEY_DIGEST_CHARS])
}

/// The gateway inputs an anchoring command collects from argv.
#[derive(Debug, Clone, Copy, Default)]
pub struct GatewayArgs<'a> {
    /// `--base-url`, when supplied.
    pub base_url: Option<&'a str>,
    /// `--api-key`, when supplied.
    pub api_key: Option<&'a str>,
    /// `--gateway-profile`, when supplied.
    pub gateway_profile: Option<&'a str>,
}

/// Resolve the required service gateway (base URL + API key) through
/// `flag > env > active gateway profile`, requiring a non-empty API key —
/// publishing is a billed, authenticated operation on every gateway.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when no base URL or no API key resolves.
pub fn resolve_required_gateway(
    args: GatewayArgs<'_>,
    command: &str,
    env: &dyn SecretEnv,
) -> Result<ServiceGateway, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    resolve_required_gateway_with(args, &config, command, env)
}

/// The config-injected core of [`resolve_required_gateway`], so tests need no
/// on-disk file.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when no base URL or no API key resolves.
pub fn resolve_required_gateway_with(
    args: GatewayArgs<'_>,
    config: &CardanoWallConfig,
    command: &str,
    env: &dyn SecretEnv,
) -> Result<ServiceGateway, CliError> {
    let profile = config.select_gateway(args.gateway_profile, command)?;
    let gateway = resolve_service_gateway(args.base_url, args.api_key, profile, command, env)?;
    if gateway.api_key.as_deref().is_none_or(str::is_empty) {
        return Err(CliError::input(format!(
            "{command}: an API key is required — pass --api-key, set CARDANOWALL_API_KEY, \
             or configure a gateway profile with a key"
        )));
    }
    Ok(gateway)
}

/// Build the optional seed signer via the shared secret layer; a malformed
/// seed is a CLI input error. The seed is OPTIONAL (omit to publish unsigned),
/// so the hidden prompt never fires — only file/stdin/argv/env supply it.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a malformed or unreadable seed.
pub fn resolve_optional_signer(
    args: &SecretArgs,
    command: &str,
    env: &dyn SecretEnv,
) -> Result<Option<SeedSigner>, CliError> {
    let Some(seed) = resolve_secret_bytes(SecretKind::Seed, args, false, command, env)? else {
        return Ok(None);
    };
    signer_from_seed(&seed)
        .map(Some)
        .map_err(|e| CliError::input(format!("{command}: --seed {e}")))
}

/// Encode a record to its canonical CBOR, attaching a path-1 COSE_Sign1
/// signature first when a signer is supplied. The returned bytes are final:
/// they are what `/poe/publish` receives, what an exact quote is sized from,
/// and what a content-derived idempotency key hashes.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the record cannot be encoded or the
/// signer misbehaves (wrong key/signature shape).
pub fn encode_record_with_signer(
    record: &PoeRecord,
    signer: Option<&dyn Signer>,
    command: &str,
) -> Result<Vec<u8>, CliError> {
    let Some(signer) = signer else {
        return encode_poe_record(record)
            .map_err(|e| CliError::input(format!("{command}: cannot encode the record: {e}")));
    };
    let pubkey = signer.signer_pubkey();
    let prepared = prepare_sig_structure(record, &pubkey)
        .map_err(|e| CliError::input(format!("{command}: cannot prepare the signature: {e}")))?;
    let signature = signer
        .sign(&prepared.sig_structure_bytes)
        .map_err(|e| CliError::input(format!("{command}: signer: {e}")))?;
    let assembled = assemble_cose_sign1(record, &pubkey, &signature)
        .map_err(|e| CliError::input(format!("{command}: cannot assemble the signature: {e}")))?;
    let mut signed = record.clone();
    signed.sigs = Some(vec![assembled.sig_entry]);
    encode_poe_record(&signed)
        .map_err(|e| CliError::input(format!("{command}: cannot encode the signed record: {e}")))
}

/// Map a bare `ClientError` (quote / low-level publish) onto the anchoring
/// exit-code contract: a typed gateway rejection is integrity-class (`1`),
/// everything else network-class (`2`).
#[must_use]
pub fn map_client_error(command: &str, err: ClientError) -> CliError {
    match err {
        ClientError::Http(http) => {
            let request_id = if http.request_id().is_empty() {
                String::new()
            } else {
                format!(" (x-request-id: {})", http.request_id())
            };
            CliError::integrity(format!(
                "{command}: HTTP {} {}: {}{request_id}",
                http.http_status(),
                http.code(),
                http.problem().detail
            ))
        }
        other => CliError::network(format!("{command}: {other}")),
    }
}

/// Map a publish-helper error onto the anchoring exit-code contract.
#[must_use]
pub fn map_publish_error(command: &str, err: PublishHelperError) -> CliError {
    match err {
        PublishHelperError::Validation(e) => {
            // Pre-network input/shape error → CLI input error (4).
            CliError::new(4, format!("{command}: {}: {e}", PublishError::code(e)))
        }
        PublishHelperError::Signer(e) => CliError::new(4, format!("{command}: signer: {e}")),
        PublishHelperError::PartialUpload(e) => {
            let indices = e
                .failed_indices()
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            CliError::network(format!(
                "{command}: partial-upload-failure (indices: {indices})"
            ))
        }
        PublishHelperError::Http(client_error) => map_client_error(command, client_error),
        PublishHelperError::Crypto(msg) => CliError::network(format!("{command}: {msg}")),
        // A sealed prepare/assembly failure: a crypto fault is network-class
        // like the legacy Crypto arm; everything else is a pre-network
        // input/shape error.
        PublishHelperError::Prepare(e) => match e {
            SealPrepareError::Crypto(_) => CliError::network(format!("{command}: {e}")),
            other => CliError::input(format!("{command}: {other}")),
        },
        // The SDK-enforced price cap mirrors enforce_max_usd's refusal:
        // integrity-class, nothing further gets spent.
        PublishHelperError::MaxUsdExceeded {
            quoted_usd_micros,
            max_usd_micros,
        } => CliError::integrity(format!(
            "{command}: quoted price {} exceeds --max-usd {}; refusing to publish",
            format_usd_micros(&quoted_usd_micros),
            format_usd_micros(&max_usd_micros.to_string())
        )),
        PublishHelperError::InvalidUploadReceipt { detail } => {
            CliError::input(format!("{command}: INVALID_UPLOAD_RECEIPT: {detail}"))
        }
    }
}

/// The quote-expiry safety margin: a quote expiring within this window is
/// refreshed rather than raced against the gateway's TTL check at consume
/// time.
const QUOTE_EXPIRY_SKEW_SECONDS: i64 = 30;

/// Whether the price lock is still comfortably inside its TTL. An unparseable
/// `expires_at` reads as fresh: the CLI cannot assess it, a re-quote would
/// carry an equally unparseable one, and the gateway stays the authority at
/// consume time.
#[must_use]
pub fn quote_is_fresh(quote: &QuoteResponse) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    quote_is_fresh_at(quote, now)
}

/// The clock-injected core of [`quote_is_fresh`].
#[must_use]
pub fn quote_is_fresh_at(quote: &QuoteResponse, now: i64) -> bool {
    let Ok(expires) = rfc3339_to_epoch_seconds(&quote.expires_at) else {
        return true;
    };
    now + QUOTE_EXPIRY_SKEW_SECONDS < expires
}

/// Re-establish the price lock when a slow step (a storage upload) outlived
/// the quote's TTL: fetch a fresh quote for the same shape and re-enforce the
/// `--max-usd` cap against the NEW price — FX may have moved while the upload
/// ran, and the cap is a promise about what gets spent.
///
/// # Errors
///
/// Returns [`CliError`] on a re-quote failure or a fresh price above the cap.
pub fn refresh_quote_if_stale(
    poe: &PoeNamespace<'_>,
    quote: QuoteResponse,
    input: &QuoteInput,
    max_usd_micros: Option<i128>,
    command: &str,
) -> Result<QuoteResponse, CliError> {
    if quote_is_fresh(&quote) {
        return Ok(quote);
    }
    let fresh = poe.quote(input).map_err(|e| map_client_error(command, e))?;
    enforce_max_usd(command, max_usd_micros, &fresh)?;
    Ok(fresh)
}

/// Refuse to proceed when the quoted price exceeds the `--max-usd` cap. The
/// refusal is integrity-class (exit `1`): the inputs were valid, the quoted
/// price failed the caller's policy bound — nothing further gets spent.
///
/// # Errors
///
/// Returns [`CliError`] exit `1` on a price above the cap, exit `2` on an
/// unparseable quote amount.
pub fn enforce_max_usd(
    command: &str,
    max_usd_micros: Option<i128>,
    quote: &QuoteResponse,
) -> Result<(), CliError> {
    let Some(cap) = max_usd_micros else {
        return Ok(());
    };
    let quoted: i128 = quote.amount.parse().map_err(|_| {
        CliError::network(format!(
            "{command}: the gateway quote amount \"{}\" is not a decimal micro-USD string",
            quote.amount
        ))
    })?;
    if quoted > cap {
        return Err(CliError::integrity(format!(
            "{command}: quoted price {} exceeds --max-usd {}; refusing to publish",
            format_usd_micros(&quote.amount),
            format_usd_micros(&cap.to_string())
        )));
    }
    Ok(())
}

/// Map a storage-upload failure onto the exit-code contract.
#[must_use]
pub fn map_upload_error(command: &str, err: ResumableUploadError) -> CliError {
    match err {
        ResumableUploadError::Http(client) => map_client_error(command, client),
        ResumableUploadError::InsufficientFunds(http) => {
            map_client_error(command, ClientError::Http(http))
        }
        ResumableUploadError::UploadRejected(e) => CliError::network(format!(
            "{command}: storage upload rejected: {} {}",
            e.code, e.detail
        )),
        other => CliError::network(format!("{command}: storage upload failed: {other}")),
    }
}

/// Parse a `--supersedes` value into the 32-byte transaction hash the record's
/// `supersedes` field carries.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for anything but 64 hex characters.
pub fn parse_supersedes(value: &str, command: &str) -> Result<Vec<u8>, CliError> {
    let trimmed = value.trim().to_lowercase();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "{command}: --supersedes must be the 64-hex hash of the transaction being superseded"
        )));
    }
    hex_to_bytes(&trimmed).map_err(|e| CliError::input(format!("{command}: --supersedes {e}")))
}

/// The `--wait` value surface shared by the anchoring commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WaitTargetArg {
    /// The transaction reached the network (normalized `confirming` or better).
    Submitted,
    /// The transaction crossed the confirmation threshold.
    Confirmed,
}

impl WaitTargetArg {
    /// The SDK wait target this argument selects.
    #[must_use]
    pub fn to_sdk(self) -> PoeWaitTarget {
        match self {
            WaitTargetArg::Submitted => PoeWaitTarget::Submitted,
            WaitTargetArg::Confirmed => PoeWaitTarget::Confirmed,
        }
    }

    /// The lowercase flag value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WaitTargetArg::Submitted => "submitted",
            WaitTargetArg::Confirmed => "confirmed",
        }
    }
}

/// The disposition of a bounded lifecycle wait.
#[derive(Debug)]
pub enum WaitOutcome {
    /// The record reached the target; the final snapshot is attached.
    Reached(PoeStatusSnapshot),
    /// The timeout elapsed first. The publish continues server-side; the last
    /// snapshot seen (if any frame arrived) is attached. The caller emits its
    /// outputs and exits `3` (pending).
    TimedOut {
        /// The last snapshot delivered before the deadline.
        last_snapshot: Option<PoeStatusSnapshot>,
    },
}

/// Follow the record's SSE lifecycle stream until it reaches `target`, fails
/// terminally, or `timeout_seconds` elapses.
///
/// A timeout is NOT an error here — the publish keeps progressing on the
/// gateway — so it comes back as [`WaitOutcome::TimedOut`] and the caller
/// finishes its outputs before exiting `3`.
///
/// # Errors
///
/// Returns [`CliError`] exit `1` when the publish fails terminally or the
/// stream is rejected with a typed gateway error, and exit `2` on a transport
/// or egress failure.
pub fn wait_for_poe_target(
    client: &Label309Client,
    poe_id: &str,
    target: WaitTargetArg,
    timeout_seconds: u64,
    command: &str,
) -> Result<WaitOutcome, CliError> {
    let input = PoeWaitInput {
        target: target.to_sdk(),
        timeout: Duration::from_secs(timeout_seconds),
        backoff: DEFAULT_EVENTS_BACKOFF.to_vec(),
    };
    match client.poe().wait(poe_id, &input) {
        Ok(snapshot) => Ok(WaitOutcome::Reached(snapshot)),
        Err(PoeWaitError::TimedOut { last_snapshot, .. }) => Ok(WaitOutcome::TimedOut {
            last_snapshot: last_snapshot.map(|s| *s),
        }),
        Err(PoeWaitError::Failed(snapshot)) => {
            let status = snapshot
                .status
                .as_ref()
                .map_or("failed", |s| s.as_str())
                .to_string();
            let tx = snapshot
                .tx_hash
                .as_deref()
                .map(|t| format!(" (tx {t})"))
                .unwrap_or_default();
            Err(CliError::integrity(format!(
                "{command}: publish {poe_id} failed terminally (status: {status}){tx}"
            )))
        }
        Err(PoeWaitError::Events(PoeEventsError::Http(http))) => {
            Err(map_client_error(command, ClientError::Http(http)))
        }
        Err(PoeWaitError::Events(err)) => Err(CliError::network(format!("{command}: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayProfile;
    use crate::secret::test_support::FakeSecretEnv;
    use cardanowall::poe_standard::ItemEntry;

    fn hash_only_record() -> PoeRecord {
        PoeRecord {
            v: 1,
            items: Some(vec![ItemEntry {
                hashes: vec![("sha2-256".to_string(), vec![0xab; 32])],
                uris: None,
                enc: None,
            }]),
            ..PoeRecord::default()
        }
    }

    #[test]
    fn gateway_resolution_requires_base_url_and_key() {
        let env = FakeSecretEnv::default();
        let config = CardanoWallConfig::default();
        // Nothing anywhere → base-URL input error.
        let err = resolve_required_gateway_with(GatewayArgs::default(), &config, "attest", &env)
            .unwrap_err();
        assert_eq!(err.code, 4);
        // A base URL but no key → key input error.
        let err = resolve_required_gateway_with(
            GatewayArgs {
                base_url: Some("https://gw.example/api/v1"),
                ..GatewayArgs::default()
            },
            &config,
            "attest",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        assert!(err.message.contains("API key"));
    }

    #[test]
    fn gateway_profile_supplies_both_slots() {
        let mut config = CardanoWallConfig::default();
        config.gateways.insert(
            "prod".to_string(),
            GatewayProfile {
                base_url: "https://gw.example/api/v1".to_string(),
                api_key: Some("k".to_string()),
            },
        );
        config.default_gateway = Some("prod".to_string());
        let env = FakeSecretEnv::default();
        let gw =
            resolve_required_gateway_with(GatewayArgs::default(), &config, "attest", &env).unwrap();
        assert_eq!(gw.base_url, "https://gw.example/api/v1");
        assert_eq!(gw.api_key.as_deref(), Some("k"));
    }

    #[test]
    fn unsigned_and_signed_encodings_differ_only_by_sigs() {
        let record = hash_only_record();
        let unsigned = encode_record_with_signer(&record, None, "attest").unwrap();
        let signer = signer_from_seed(&[0x11u8; 32]).unwrap();
        let signed =
            encode_record_with_signer(&record, Some(&signer as &dyn Signer), "attest").unwrap();
        assert!(signed.len() > unsigned.len());
        // Ed25519 signing is deterministic, so re-encoding reproduces the bytes —
        // the property the content-derived idempotency key relies on.
        let signed_again =
            encode_record_with_signer(&record, Some(&signer as &dyn Signer), "attest").unwrap();
        assert_eq!(signed, signed_again);
    }

    #[test]
    fn placeholder_uri_has_the_real_arweave_width() {
        // `ar://` (5) + a 43-character transaction id.
        assert_eq!(arweave_uri_placeholder().len(), 48);
    }

    fn quote_with(amount: &str, expires_at: &str) -> QuoteResponse {
        QuoteResponse {
            quote_id: "q".to_string(),
            amount: amount.to_string(),
            currency: "USD".to_string(),
            expires_at: expires_at.to_string(),
            usd_micros: None,
            breakdown: None,
            margin_pct: None,
            margin_source: None,
            fx_age_seconds: None,
        }
    }

    #[test]
    fn quote_freshness_honours_expiry_and_the_skew_window() {
        // 2026-07-03T10:15:30Z — pinned in the rfc3339 parser tests.
        let expires = 1_783_073_730i64;
        let q = quote_with("1", "2026-07-03T10:15:30Z");
        // Comfortably before the skew window → fresh.
        assert!(quote_is_fresh_at(
            &q,
            expires - QUOTE_EXPIRY_SKEW_SECONDS - 1
        ));
        // Expiring inside the skew window counts as stale: the publish must
        // not race the gateway's TTL check.
        assert!(!quote_is_fresh_at(&q, expires - QUOTE_EXPIRY_SKEW_SECONDS));
        assert!(!quote_is_fresh_at(&q, expires - 1));
        // Already expired → stale.
        assert!(!quote_is_fresh_at(&q, expires + 1));
        // An unparseable expiry reads as fresh (the gateway stays the
        // authority; a re-quote could not be assessed either).
        assert!(quote_is_fresh_at(
            &quote_with("1", "not-a-timestamp"),
            expires
        ));
    }

    #[test]
    fn max_usd_refuses_above_cap_with_exit_1() {
        let quote = quote_with("1500000", "2100-01-01T00:00:00Z");
        // $1.00 cap against a $1.50 quote → integrity-class refusal.
        let err = enforce_max_usd("attest", Some(1_000_000), &quote).unwrap_err();
        assert_eq!(err.code, 1);
        assert!(err.message.contains("--max-usd"));
        // An exact-cap quote passes ("at most this much").
        enforce_max_usd("attest", Some(1_500_000), &quote).unwrap();
        enforce_max_usd("attest", None, &quote).unwrap();
    }

    #[test]
    fn supersedes_requires_a_64_hex_tx_hash() {
        let ok = parse_supersedes(&"AB".repeat(32), "submit").unwrap();
        assert_eq!(ok, vec![0xab; 32]);
        for bad in ["", "abcd", &"zz".repeat(32)[..]] {
            assert_eq!(parse_supersedes(bad, "submit").unwrap_err().code, 4);
        }
    }
}
