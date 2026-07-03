//! A minimal in-process Label 309 gateway stub for driving the real binary.
//!
//! Serves the four surfaces the anchoring commands touch — `POST /poe/quote`,
//! `POST /poe/uploads`, `POST /poe/publish`, and the SSE
//! `GET /poe/events/{id}` — over a plain `TcpListener`, recording every
//! request (method, path, headers, body) so tests can assert on the exact
//! bytes the CLI sent. Each connection serves one request and closes, so no
//! keep-alive state machine is needed.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A `cardanowall` binary invocation pointed at the stub gateway with fully
/// isolated config/home, so tests never read the developer's real
/// `~/.cardanowall` or leak env.
pub fn cli(stub: &StubGateway, workdir: &Path) -> Command {
    let home = workdir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_cardanowall"));
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

/// Decode and structurally validate the record the stub captured on
/// `POST /poe/publish`, returning its exact bytes and the decoded form.
pub fn captured_publish_record(
    stub: &StubGateway,
) -> (Vec<u8>, cardanowall::poe_standard::PoeRecord) {
    use cardanowall::poe_standard::{validate_poe_record, ValidateResult, ValidatorOptions};
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

/// Extract the first uploaded file's raw bytes from a captured multipart
/// `POST /poe/uploads` body (the single-shot storage upload the stub serves).
pub fn multipart_file_bytes(upload: &CapturedRequest) -> Vec<u8> {
    let content_type = upload
        .header("content-type")
        .expect("multipart content-type");
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("multipart boundary")
        .trim()
        .to_string();
    let delimiter = format!("--{boundary}");
    let body = &upload.body;
    // Split on the boundary delimiter and find the part carrying a filename.
    let text_probe = |window: &[u8], needle: &str| -> Option<usize> {
        window
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
    };
    let mut cursor = 0usize;
    loop {
        let start = text_probe(&body[cursor..], &delimiter).map(|p| cursor + p + delimiter.len());
        let Some(part_start) = start else {
            panic!("no file part found in the multipart body")
        };
        // The part's headers end at the first blank line.
        let Some(headers_end) = text_probe(&body[part_start..], "\r\n\r\n") else {
            panic!("malformed multipart part")
        };
        let headers = &body[part_start..part_start + headers_end];
        let content_start = part_start + headers_end + 4;
        let Some(next_delim) = text_probe(&body[content_start..], &delimiter) else {
            panic!("unterminated multipart part")
        };
        // The content runs up to the CRLF that precedes the next delimiter.
        let content_end = content_start + next_delim - 2;
        if text_probe(headers, "filename=").is_some() {
            return body[content_start..content_end].to_vec();
        }
        cursor = content_start;
    }
}

/// The fixed record id / tx hash / storage URI the stub hands out.
pub const STUB_POE_ID: &str = "poe_0123456789abcdefghijklmn";
pub fn stub_tx_hash() -> String {
    "ab".repeat(32)
}
pub fn stub_ar_uri() -> String {
    format!("ar://{}", "T".repeat(43))
}

/// How `POST /poe/publish` responds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishBehavior {
    /// `202 Accepted`, a fresh record: `status: submitting`, no tx yet.
    Fresh,
    /// `200 OK`, the dedup hit: the RAW engine `submitted` status plus the tx —
    /// exactly what the gateway echoes for a byte-identical re-POST.
    DedupRawSubmitted,
}

/// One scripted SSE frame.
#[derive(Debug, Clone)]
pub struct SseFrame {
    pub event: &'static str,
    pub data: String,
}

/// Build the standard snapshot JSON an SSE frame carries.
pub fn snapshot_json(status: &str, with_anchor: bool) -> String {
    if with_anchor {
        format!(
            "{{\"id\":\"{STUB_POE_ID}\",\"status\":\"{status}\",\"tx_hash\":\"{}\",\
             \"block_height\":123456,\"block_time\":\"2026-07-03T10:15:30Z\",\
             \"num_confirmations\":6}}",
            stub_tx_hash()
        )
    } else {
        format!("{{\"id\":\"{STUB_POE_ID}\",\"status\":\"{status}\"}}")
    }
}

/// The canonical happy-path script: submitting → confirming → confirmed.
pub fn confirmed_script() -> Vec<SseFrame> {
    vec![
        SseFrame {
            event: "state",
            data: snapshot_json("submitting", false),
        },
        SseFrame {
            event: "poe_status_changed",
            data: snapshot_json("confirming", true),
        },
        SseFrame {
            event: "poe_status_changed",
            data: snapshot_json("confirmed", true),
        },
    ]
}

/// The stub's scripted behaviour.
#[derive(Debug, Clone)]
pub struct StubConfig {
    /// Per-quote totals (USD micro-cents, decimal strings): the Nth quote
    /// answers with `quote_amounts[min(N-1, last)]`.
    pub quote_amounts: Vec<String>,
    /// The first N quotes carry an already-expired `expires_at`, so a client
    /// that checks the TTL must re-quote before publishing.
    pub expired_quotes: usize,
    /// Whether each quote mints a fresh id (`q_1`, `q_2`, …) like a real
    /// gateway. `false` reuses the constant `q_1`, scripting the contrived
    /// same-price-lock scenario a byte-identical publish replay needs.
    pub sequential_quote_ids: bool,
    pub publish: PublishBehavior,
    /// The frames every `GET /poe/events/{id}` connection replays.
    pub sse_frames: Vec<SseFrame>,
    /// After the frames, keep the connection alive with `ping` frames (so a
    /// wait deadline expires on a live stream instead of racing reconnects).
    pub sse_pings_after: bool,
}

impl Default for StubConfig {
    fn default() -> Self {
        Self {
            quote_amounts: vec!["1500000".to_string()],
            expired_quotes: 0,
            sequential_quote_ids: true,
            publish: PublishBehavior::Fresh,
            sse_frames: confirmed_script(),
            sse_pings_after: false,
        }
    }
}

/// The stored side of one seen Idempotency-Key, mirroring the real gateway's
/// contract: the key binds to a hash of the ENTIRE request body; the same key
/// with the same body replays the original response verbatim, the same key
/// with a different body is a 409 conflict.
struct StoredPublish {
    body_sha256: [u8; 32],
    status: u16,
    body: String,
}

type IdempotencyMemory = Arc<Mutex<std::collections::HashMap<String, StoredPublish>>>;

/// One captured request.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("captured body is JSON")
    }
}

/// The running stub: its base URL and the captured request log.
pub struct StubGateway {
    port: u16,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl StubGateway {
    /// Start the stub on an ephemeral port.
    pub fn start(config: StubConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub gateway");
        let port = listener.local_addr().unwrap().port();
        let requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let idempotency: IdempotencyMemory = Arc::default();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = config.clone();
                let log = Arc::clone(&log);
                let idempotency = Arc::clone(&idempotency);
                std::thread::spawn(move || handle_connection(stream, &config, &log, &idempotency));
            }
        });
        Self { port, requests }
    }

    /// The data-plane base URL to hand the CLI (includes the version segment).
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/api/v1", self.port)
    }

    /// A snapshot of the captured requests.
    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// The captured requests whose path ends with `suffix`.
    pub fn requests_to(&self, suffix: &str) -> Vec<CapturedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.path.ends_with(suffix))
            .collect()
    }
}

/// Build the configured publish response (status, body).
fn publish_response(config: &StubConfig) -> (u16, String) {
    match config.publish {
        PublishBehavior::Fresh => (
            202,
            format!(
                "{{\"id\":\"{STUB_POE_ID}\",\"tx_hash\":null,\"status\":\"submitting\",\
                 \"items_count\":1,\"signed\":false,\"sealed\":false,\
                 \"items\":[{{\"item_idx\":0,\"hashes\":{{}},\"uris\":[\"{}\"],\"enc\":null}}],\
                 \"conformance_profile\":\"core\",\"balance_after_usd_micros\":\"8500000\"}}",
                stub_ar_uri()
            ),
        ),
        PublishBehavior::DedupRawSubmitted => (
            200,
            format!(
                "{{\"id\":\"{STUB_POE_ID}\",\"tx_hash\":\"{}\",\"status\":\"submitted\",\
                 \"items_count\":1,\"signed\":false,\"sealed\":false,\"items\":[],\
                 \"conformance_profile\":\"core\",\"balance_after_usd_micros\":\"8500000\"}}",
                stub_tx_hash()
            ),
        ),
    }
}

fn handle_connection(
    stream: TcpStream,
    config: &StubConfig,
    log: &Arc<Mutex<Vec<CapturedRequest>>>,
    idempotency: &IdempotencyMemory,
) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let Some(request) = read_request(&mut reader) else {
        return;
    };
    log.lock().unwrap().push(request.clone());
    let mut stream = stream;

    if request.method == "POST" && request.path.ends_with("/poe/quote") {
        // The 1-based sequence number of THIS quote (the log already holds it).
        let seq = log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.ends_with("/poe/quote"))
            .count();
        let amount = config
            .quote_amounts
            .get(seq.saturating_sub(1))
            .or_else(|| config.quote_amounts.last())
            .cloned()
            .unwrap_or_else(|| "1500000".to_string());
        let expires_at = if seq <= config.expired_quotes {
            "2000-01-01T00:00:00Z"
        } else {
            "2100-01-01T00:00:00Z"
        };
        let quote_id = if config.sequential_quote_ids { seq } else { 1 };
        let body = format!(
            "{{\"quote_id\":\"q_{quote_id}\",\"amount\":\"{amount}\",\"currency\":\"USD\",\
             \"expires_at\":\"{expires_at}\",\"usd_micros\":\"{amount}\",\
             \"breakdown\":{{\"network_usd_micros\":\"500000\",\
             \"storage_usd_micros\":\"200000\",\"service_usd_micros\":\"800000\"}}}}"
        );
        write_json(&mut stream, 200, &body);
    } else if request.method == "POST" && request.path.ends_with("/poe/uploads") {
        let body = format!(
            "{{\"uploads\":[{{\"idx\":0,\"ok\":true,\"uri\":\"{}\",\"sha256\":\"{}\",\
             \"bytes\":{}}}]}}",
            stub_ar_uri(),
            "0".repeat(64),
            request.body.len()
        );
        write_json(&mut stream, 200, &body);
    } else if request.method == "POST" && request.path.ends_with("/poe/publish") {
        // The real gateway's Idempotency-Key contract: the key binds to a
        // hash of the ENTIRE request body. Same key + same body → replay the
        // stored response verbatim; same key + different body → 409.
        if let Some(key) = request.header("idempotency-key").map(str::to_string) {
            let body_sha256 = cardanowall::hash::sha256(&request.body);
            let mut memory = idempotency.lock().unwrap();
            if let Some(stored) = memory.get(&key) {
                if stored.body_sha256 == body_sha256 {
                    let (status, body) = (stored.status, stored.body.clone());
                    drop(memory);
                    write_response(
                        &mut stream,
                        status,
                        &[("Idempotent-Replayed", "true")],
                        &body,
                    );
                } else {
                    drop(memory);
                    write_json(
                        &mut stream,
                        409,
                        "{\"type\":\"about:blank\",\"title\":\"Conflict\",\"status\":409,\
                         \"code\":\"idempotency-key-conflict\",\"detail\":\"the Idempotency-Key \
                         was already used with a different request body\"}",
                    );
                }
                return;
            }
            let (status, body) = publish_response(config);
            memory.insert(
                key,
                StoredPublish {
                    body_sha256,
                    status,
                    body: body.clone(),
                },
            );
            drop(memory);
            write_json(&mut stream, status, &body);
            return;
        }
        let (status, body) = publish_response(config);
        write_json(&mut stream, status, &body);
    } else if request.method == "GET" && request.path.contains("/poe/events/") {
        serve_sse(&mut stream, config);
    } else {
        write_json(
            &mut stream,
            404,
            "{\"type\":\"about:blank\",\"code\":\"not-found\",\"detail\":\"stub: no route\"}",
        );
    }
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Option<CapturedRequest> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
    write_response(stream, status, &[], body);
}

fn write_response(stream: &mut TcpStream, status: u16, extra_headers: &[(&str, &str)], body: &str) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        404 => "Not Found",
        409 => "Conflict",
        _ => "OK",
    };
    let extras: String = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n{extras}Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn serve_sse(stream: &mut TcpStream, config: &StubConfig) {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    for (i, frame) in config.sse_frames.iter().enumerate() {
        let chunk = format!(
            "id: {}\nevent: {}\ndata: {}\n\n",
            i + 1,
            frame.event,
            frame.data
        );
        if stream.write_all(chunk.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();
    }
    if config.sse_pings_after {
        // Keep the stream alive well past any test deadline; stop as soon as
        // the client hangs up (the write fails).
        for i in 0..300 {
            std::thread::sleep(Duration::from_millis(100));
            let chunk = format!(
                "id: {}\nevent: ping\ndata: {{}}\n\n",
                config.sse_frames.len() + i + 1
            );
            if stream.write_all(chunk.as_bytes()).is_err() {
                return;
            }
            let _ = stream.flush();
        }
    }
}
