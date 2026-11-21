// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C `export` command (§6C-6 endpoint, §6C-7 OTLP push, §6C-8
//! delivery): std-only HTTP scrape serving + OTLP/HTTP push.
//! Collection, scrape serving, and pushes are separated (item 18):
//! the loop refreshes snapshots and accepts scrapes (each scrape
//! served on its own bounded thread), while a push worker owns the
//! OTLP queue + retry discipline off the scrape path.
use super::budget::Budget;
use super::snapshot::{OperatorSnapshot, Presenter, checkpoint_default};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

const HELP: &str = "usage: osslscope export --out DIR [--listen ADDR] [--poll-seconds S] [--otlp-enable] [--otlp-endpoint URL] [--otlp-push-seconds S] [--checkpoint PATH]\nServe Prometheus exposition on GET /metrics (default 127.0.0.1:9464) and optionally push OTLP/HTTP metrics. Read-only on the out-DIR.\n";

/// Default scrape endpoint (§6C-6).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9464";
/// Default OTLP/HTTP endpoint (§6C-7).
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/metrics";
/// Per-scrape socket I/O deadlines (complete request deadlines —
/// no accepted socket blocks the server past these).
pub const SCRAPE_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Max concurrent scrape threads (excess connections shed).
pub const MAX_CONCURRENT_SCRAPES: usize = 8;
/// Pending-push handoff cap (bounded drop-oldest, §6C-7).
pub const PUSH_QUEUE_CAP: usize = 4;
/// Per-push deadline (frozen retry/drop discipline, §6C-7).
pub const PUSH_DEADLINE: Duration = Duration::from_secs(45);
/// Push attempts per queued payload (frozen discipline).
pub const PUSH_ATTEMPTS: u32 = 5;
/// Collector response cap (P2fix2 item 21 — the end-to-end deadline
/// includes response size: past this the body truncates and the
/// push accounts malformed instead of hanging or ballooning).
pub const MAX_OTLP_RESPONSE_BYTES: u64 = 64 * 1024;

pub struct Options {
    pub out: PathBuf,
    pub listen: String,
    pub poll_secs: u64,
    pub otlp: Option<OtlpConfig>,
    pub checkpoint: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub push_secs: u64,
}

/// Scrape-observation callback (test seam; thread-safe — scrapes
/// serve concurrently).
pub type ScrapeCallback = Arc<dyn Fn(&str) + Send + Sync>;

fn parse(args: &[String]) -> Result<Options, ()> {
    if args.first().map(String::as_str) != Some("export") {
        return Err(());
    }
    let mut out: Option<PathBuf> = None;
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut poll_secs = 5u64;
    let mut otlp_enable = false;
    let mut otlp_endpoint: Option<String> = None;
    let mut otlp_push_secs: Option<u64> = None;
    let mut checkpoint: Option<PathBuf> = None;
    let mut it = args[1..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--out" if out.is_none() => {
                out = Some(PathBuf::from(it.next().ok_or(())?));
            }
            "--listen" => {
                listen = it.next().ok_or(())?.clone();
            }
            "--poll-seconds" => {
                let v: u64 = it.next().ok_or(())?.parse().map_err(|_| ())?;
                if !(1..=3600).contains(&v) {
                    return Err(());
                }
                poll_secs = v;
            }
            "--otlp-enable" if !otlp_enable => otlp_enable = true,
            "--otlp-endpoint" if otlp_endpoint.is_none() => {
                otlp_endpoint = Some(it.next().ok_or(())?.clone());
            }
            "--otlp-push-seconds" => {
                let v: u64 = it.next().ok_or(())?.parse().map_err(|_| ())?;
                if !(5..=3600).contains(&v) {
                    return Err(());
                }
                otlp_push_secs = Some(v);
            }
            "--checkpoint" if checkpoint.is_none() => {
                checkpoint = Some(PathBuf::from(it.next().ok_or(())?));
            }
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(()),
        }
    }
    let out = out.ok_or(())?;
    // Presence of either flag enables OTLP; a push interval without
    // pushes is a usage error (§6C-6).
    let otlp = match (otlp_enable, otlp_endpoint, otlp_push_secs) {
        (false, None, Some(_)) => return Err(()),
        (false, None, None) => None,
        (enabled, endpoint, push) => {
            let _ = enabled;
            Some(OtlpConfig {
                endpoint: endpoint.unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string()),
                push_secs: push.unwrap_or(60),
            })
        }
    };
    Ok(Options {
        out,
        listen,
        poll_secs,
        otlp,
        checkpoint,
    })
}

/// Handle one scrape connection (minimal HTTP/1.0 GET) with
/// complete request deadlines (a slow peer stalls only its own
/// bounded thread, never the server).
fn handle_scrape(stream: TcpStream, body: &str) {
    let mut stream = stream;
    if stream.set_read_timeout(Some(SCRAPE_IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(SCRAPE_IO_TIMEOUT)).is_err()
    {
        return;
    }
    let mut request = [0u8; 4096];
    let Ok(n) = stream.read(&mut request) else {
        return;
    };
    let head = String::from_utf8_lossy(&request[..n]);
    let line = head.lines().next().unwrap_or_default();
    let (response, payload) = if line.starts_with("GET /metrics") {
        (
            format!(
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ),
            body,
        )
    } else {
        let not_found = "not found\n";
        (
            format!(
                "HTTP/1.0 404 Not Found\r\nContent-Length: {}\r\n\r\n",
                not_found.len()
            ),
            not_found,
        )
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(payload.as_bytes());
}

/// Minimal OTLP/HTTP POST over std TCP (http:// URLs only).
/// Returns the status + raw body (the body carries
/// `partialSuccess`, which a bare 2xx must not hide) or Err(note).
#[derive(Debug)]
struct PostResponse {
    status: u16,
    body: String,
    /// The response body exceeded the cap (truncated read — the
    /// body is a prefix, never complete: accounts malformed
    /// downstream, never acceptance).
    over_cap: bool,
    /// The response body is not valid UTF-8 (P2fix5 NEW-24 — set
    /// by the strict body decode; accounts malformed downstream,
    /// never lossy-normalized acceptance).
    body_invalid: bool,
    /// Malformed framing AFTER a recognized status (P2fix6
    /// NEW-39 — bad header line, bad/conflicting Content-Length,
    /// transfer coding, truncated body: the status parsed, so
    /// the push may have landed (2xx) or the rejection stands
    /// (non-2xx) — accounts WITHOUT retry, never a transport
    /// error).
    framing_invalid: bool,
}

/// Malformed framing after a recognized status (P2fix6 NEW-39):
/// the status is known but the framing is not — the discipline
/// accounts it without retry (never redelivers).
fn framing_invalid(status: u16) -> PostResponse {
    PostResponse {
        status,
        body: String::new(),
        over_cap: false,
        body_invalid: false,
        framing_invalid: true,
    }
}

/// HTTP token character (RFC 7230 §3.2.6 `tchar`) — the
/// supported field-name alphabet (P2fix7 NEW-43). No whitespace:
/// whitespace before the colon (or inside the name) is malformed
/// framing, never trimmed past.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Strict status-line parse (P2fix7 NEW-43): the supported
/// grammar is version SP code with single spaces, plus an
/// optional SP reason — `HTTP/<digit>.<digit>` exactly (the
/// P2fix4 NEW-8 version rule) + a 3-digit code. The line must be
/// clean visible-ASCII + SP/HTAB (no CTLs — CR/LF inside the
/// line, non-ASCII bytes, or any other control fails
/// recognition, so the response stays a transport error like
/// any other unreadable response). The reason phrase needs no
/// further shape (any allowed bytes).
fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    if line.is_empty()
        || !line
            .iter()
            .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
    {
        return Err("read: bad HTTP status line".to_string());
    }
    let mut parts = line.split(|b| *b == b' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    let vb = version;
    let version_ok = vb.len() == 8
        && vb[..5] == *b"HTTP/"
        && vb[5].is_ascii_digit()
        && vb[6] == b'.'
        && vb[7].is_ascii_digit();
    if !version_ok || code.len() != 3 || !code.iter().all(|b| b.is_ascii_digit()) {
        return Err("read: bad HTTP status line".to_string());
    }
    Ok(code.iter().fold(0u16, |n, b| n * 10 + u16::from(b - b'0')))
}

fn otlp_post(endpoint: &str, payload: &str, budget: Duration) -> Result<PostResponse, String> {
    // Absolute deadline (P2fix3 NEW-8): EVERY I/O rechecks it —
    // each read/write takes min(5s, remaining) with the remaining
    // recomputed per call, so a PROGRESSING peer (bytes inside
    // every inactivity timeout) still aborts at the budget instead
    // of running past it. HTTP framing validates strictly: a
    // truncated or unparseable response BEFORE the status line is
    // a transport error (retryable), never a success with an
    // empty body — while malformed framing AFTER a recognized
    // status returns `framing_invalid` (P2fix6 NEW-39: accounts
    // without retry, never redelivers a possibly-accepted push).
    let end = std::time::Instant::now() + budget;
    let remaining = || end.saturating_duration_since(std::time::Instant::now());
    let check_end = |what: &str| -> Result<(), String> {
        if std::time::Instant::now() >= end {
            return Err(format!("{what}: absolute deadline exceeded"));
        }
        Ok(())
    };
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// endpoints supported".to_string())?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let dial = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    check_end("connect")?;
    let mut stream = TcpStream::connect_timeout(
        &dial
            .parse()
            .map_err(|_| format!("unresolvable endpoint: {dial}"))?,
        Duration::from_secs(5).min(remaining()),
    )
    .map_err(|e| format!("connect: {e}"))?;
    let request = format!(
        "POST {path} HTTP/1.0\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    );
    // Write loop (no write_all: every write() rechecks the
    // absolute deadline — a slow-draining peer aborts at it).
    let mut written = 0usize;
    let bytes = request.as_bytes();
    while written < bytes.len() {
        check_end("write")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5).min(remaining())))
            .map_err(|e| format!("timeout: {e}"))?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err("write: connection closed".to_string()),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("write: {e}")),
        }
    }
    // Header loop (P2fix7 NEW-43 — STATUS FIRST): the status
    // line parses from the incoming bytes BEFORE the remaining
    // framing. Once a complete valid status is recognized, EVERY
    // subsequent failure (header decode, truncation, framing,
    // body) is `framing_invalid` (counted once, never
    // redelivered — the 2xx may have landed). Only a status that
    // is itself unreadable (undecodable/truncated/malformed
    // status line) stays a transport error. Every read()
    // rechecks the deadline; EOF before the blank line is
    // truncation, never an empty body.
    let transport_or_framing = |status: Option<u16>, msg: &str| -> Result<PostResponse, String> {
        match status {
            Some(code) => Ok(framing_invalid(code)),
            None => Err(msg.to_string()),
        }
    };
    let mut head: Vec<u8> = Vec::new();
    let mut status: Option<u16> = None;
    let mut status_end: usize = 0;
    let body_start = loop {
        // Recognize the status from buffered bytes (the status
        // line ends at the first CRLF — parsed from bytes, never
        // past undecodable framing).
        if status.is_none() {
            if let Some(i) = head.windows(2).position(|w| w == b"\r\n") {
                status_end = i + 2;
                match parse_status_line(&head[..i]) {
                    Ok(code) => status = Some(code),
                    Err(e) => return Err(e),
                }
            }
        }
        if status.is_some() {
            if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        }
        if check_end("read").is_err() {
            return transport_or_framing(status, "read: absolute deadline exceeded");
        }
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5).min(remaining()))) {
            // Post-recognition the response is unverifiable (the
            // 2xx may have landed) — framing, never redelivery.
            let msg = format!("read: timeout setup failed: {e}");
            return transport_or_framing(status, &msg);
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return transport_or_framing(status, "read: truncated response headers"),
            Ok(n) => head.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return transport_or_framing(status, &format!("read: {e}")),
        }
        if head.len() > MAX_OTLP_RESPONSE_BYTES as usize + 4096 {
            return transport_or_framing(status, "read: response headers exceed cap");
        }
    };
    let status = status.expect("status recognized (the break requires it)");
    // Strict header decode (P2fix6 NEW-39, routing P2fix7 NEW-43):
    // no lossy normalization — undecodable header bytes AFTER
    // the recognized status are `framing_invalid` (header decode
    // must not discard an already readable status into the
    // transport path).
    let head_text = match String::from_utf8(head[status_end..body_start].to_vec()) {
        Ok(text) => text,
        Err(_) => return Ok(framing_invalid(status)),
    };
    // Supported line grammar (P2fix7 NEW-43): every header line
    // ends CRLF — bare CR/LF reject — and the block ends with
    // the blank line. The block scan guarantees a trailing CRLF
    // pair (the last split piece is its artifact).
    let mut pieces: Vec<&str> = head_text.split('\n').collect();
    if pieces.pop() != Some("") {
        return Ok(framing_invalid(status));
    }
    let mut lines: Vec<&str> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let Some(line) = piece.strip_suffix('\r') else {
            return Ok(framing_invalid(status));
        };
        if line.contains('\r') {
            return Ok(framing_invalid(status));
        }
        lines.push(line);
    }
    let Some((terminator, fields)) = lines.split_last() else {
        return Ok(framing_invalid(status));
    };
    if !terminator.is_empty() {
        return Ok(framing_invalid(status));
    }
    // Framing: Content-Length (exact body) XOR close-delimited
    // (absent length reads to EOF, HTTP/1.0 style) — those are the
    // exact expectations. ANY Transfer-Encoding rejects (P2fix5
    // NEW-24 — we decode no transfer coding, so any coding, any
    // coding list, and any TE+Content-Length conflict fail closed
    // instead of falling through to Content-Length and counting
    // as acceptance). Every header line carries a colon (P2fix4
    // NEW-8 — a colon-less line is malformed framing, never
    // ignored). Field names are strict tokens (P2fix7 NEW-43 —
    // no whitespace before the colon, none inside — checked on
    // EVERY line, not just recognized fields) and values trim
    // HTTP OWS (SP/HTAB only — never general whitespace) AND
    // validate the RFC 9110 field-content charset on EVERY line
    // including ignored headers (P2fix8 NEW-52 — VCHAR /
    // obs-text / SP / HTAB only; NUL/CTL/DEL reject). The
    // status is RECOGNIZED past this point, so every framing
    // failure below returns `framing_invalid` (P2fix6 NEW-39 —
    // accounts without retry, never a transport error: the 2xx
    // may have landed).
    let mut content_length: Option<u64> = None;
    for line in fields {
        if line.is_empty() {
            return Ok(framing_invalid(status));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Ok(framing_invalid(status));
        };
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Ok(framing_invalid(status));
        }
        // Field-value grammar (P2fix8 NEW-52 — RFC 9110 §5.5, on
        // EVERY line including IGNORED headers): after OWS
        // trimming the content is VCHAR / obs-text / SP / HTAB
        // only — NUL and other CTLs + DEL reject (an unchecked
        // ignored value would otherwise survive decoding and
        // earn success credit for a possibly-corrupt 2xx).
        let content = value.trim_matches(|c| c == ' ' || c == '\t');
        let value_ok = content
            .bytes()
            .all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b) || b >= 0x80);
        if !value_ok {
            return Ok(framing_invalid(status));
        }
        if name.eq_ignore_ascii_case("content-length") {
            // Supported length grammar (P2fix6 NEW-39, OWS P2fix7
            // NEW-43): 1*DIGIT after HTTP-OWS trimming — signed,
            // empty, interior-spaced, or general-whitespace-
            // padded lengths never parse (integer parsing alone
            // accepts `+2`; general trimming accepts VT/FF).
            let digits = value.trim_matches(|c| c == ' ' || c == '\t');
            let digits_ok = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
            let n: Option<u64> = if digits_ok { digits.parse().ok() } else { None };
            let Some(n) = n else {
                return Ok(framing_invalid(status));
            };
            if content_length.is_some_and(|old| old != n) {
                return Ok(framing_invalid(status));
            }
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Ok(framing_invalid(status));
        }
    }
    let mut body: Vec<u8> = head[body_start..].to_vec();
    let mut over_cap = false;
    match content_length {
        Some(n) => {
            // Exact body (EOF early is truncation; past the cap the
            // read stops and flags over-cap — a prefix body never
            // parses as acceptance downstream).
            let want = (n as usize).min(MAX_OTLP_RESPONSE_BYTES as usize + 1);
            over_cap = n > MAX_OTLP_RESPONSE_BYTES;
            while body.len() < want {
                // Post-status I/O failures are framing failures
                // (P2fix6 NEW-39 — the status parsed, so no retry).
                if check_end("read").is_err() {
                    return Ok(framing_invalid(status));
                }
                if stream
                    .set_read_timeout(Some(Duration::from_secs(5).min(remaining())))
                    .is_err()
                {
                    return Ok(framing_invalid(status));
                }
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        return Ok(framing_invalid(status));
                    }
                    Ok(n) => body.extend_from_slice(&chunk[..n.min(want - body.len())]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Ok(framing_invalid(status)),
                }
            }
            // Exactly the claimed body (or its cap+1 prefix when
            // over cap — a prefix never parses as acceptance).
            body.truncate(want);
        }
        None => {
            // Close-delimited (every read rechecks the deadline;
            // past the cap the read stops and flags over-cap).
            loop {
                if body.len() > MAX_OTLP_RESPONSE_BYTES as usize {
                    over_cap = true;
                    body.truncate(MAX_OTLP_RESPONSE_BYTES as usize + 1);
                    break;
                }
                if check_end("read").is_err() {
                    return Ok(framing_invalid(status));
                }
                if stream
                    .set_read_timeout(Some(Duration::from_secs(5).min(remaining())))
                    .is_err()
                {
                    return Ok(framing_invalid(status));
                }
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Ok(framing_invalid(status)),
                }
            }
        }
    }
    // Strict body decode (P2fix5 NEW-24): no lossy
    // normalization — invalid bytes flag the response (the 2xx
    // arm below accounts it malformed, never acceptance).
    let (text, body_invalid) = match String::from_utf8(body) {
        Ok(text) => (text, false),
        Err(_) => (String::new(), true),
    };
    Ok(PostResponse {
        status,
        body: text,
        over_cap,
        body_invalid,
        framing_invalid: false,
    })
}

/// Typed 2xx body classification (P2fix3 NEW-8): empty implies {}
/// (clean accept); otherwise the body must be a JSON OBJECT whose
/// `partialSuccess` block (when present) is an OBJECT with a
/// well-typed `rejectedDataPoints` (absent/null/0 reads clean) and
/// `errorMessage`. Anything else is malformed (drop, never
/// pushed) — a mistyped success is unverifiable acceptance.
#[derive(Debug, PartialEq, Eq)]
enum SuccessBody {
    Clean,
    Rejected(u64),
    Malformed,
}

fn classify_success_body(body: &str) -> SuccessBody {
    if body.is_empty() {
        return SuccessBody::Clean;
    }
    // Duplicate members reject BEFORE counting acceptance (P2fix4
    // NEW-8 — JSON last-wins must not hide a prior
    // `partialSuccess` behind a later clean block).
    if crate::schema::check_otlp_response_raw_duplicates(body).is_err() {
        return SuccessBody::Malformed;
    }
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return SuccessBody::Malformed,
    };
    if !v.is_object() {
        return SuccessBody::Malformed;
    }
    let ps = &v["partialSuccess"];
    if ps.is_null() {
        return SuccessBody::Clean;
    }
    let ps = match ps.as_object() {
        Some(o) => o,
        None => return SuccessBody::Malformed,
    };
    let rejected = match ps.get("rejectedDataPoints") {
        None | Some(serde_json::Value::Null) => 0,
        Some(serde_json::Value::String(s)) => match s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return SuccessBody::Malformed,
        },
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(v) => v,
            None => return SuccessBody::Malformed,
        },
        Some(_) => return SuccessBody::Malformed,
    };
    match ps.get("errorMessage") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(_)) => {}
        Some(_) => return SuccessBody::Malformed,
    }
    if rejected == 0 {
        SuccessBody::Clean
    } else {
        SuccessBody::Rejected(rejected)
    }
}

/// One push attempt-series outcome (accounted, never silent).
#[derive(Debug, PartialEq, Eq)]
struct PushOutcome {
    /// The push fully landed (2xx without partial rejection).
    pushed: bool,
    /// Transport attempts consumed.
    attempts: u32,
    /// Data points the collector partially rejected (2xx).
    partial_rejected: u64,
    /// The 2xx body was malformed (non-empty unparseable — never
    /// counted as acceptance, P2fix2 item 21).
    malformed: bool,
    /// Stderr note (None on a clean first-try push).
    note: Option<String>,
}

/// Push one payload with the frozen retry/drop discipline (§6C-7):
/// end-to-end deadline binding transport timeouts AND backoffs
/// (P2fix2 item 21 — each attempt receives its remaining budget;
/// backoff sleeps never overshoot it), exponential backoff 1s→60s
/// cap, [`PUSH_ATTEMPTS`] attempts, then DROP (supersession).
/// Transport errors retry; non-2xx, 2xx-partial, and 2xx-malformed
/// drop WITHOUT retry (the next push supersedes — resending would
/// duplicate the accepted points). Every outcome is accounted
/// (attempts + partial/malformed counts + note). The transport,
/// sleeper, and deadline inject for tests.
fn push_with_discipline(
    post: &mut impl FnMut(Duration) -> Result<PostResponse, String>,
    sleep: &mut impl FnMut(Duration),
    deadline: Duration,
) -> PushOutcome {
    let end = std::time::Instant::now() + deadline;
    let mut backoff = Duration::from_secs(1);
    let mut consumed = 0u32;
    for attempt in 1..=PUSH_ATTEMPTS {
        let remaining = end.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        consumed = attempt;
        match post(remaining) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                // Typed success (P2fix3 NEW-8, P2fix5 NEW-24,
                // P2fix6 NEW-39): an over-cap body is a prefix
                // (never complete), an invalid-encoding body is
                // undecodable (never lossy-normalized), malformed
                // framing after the recognized status is
                // unverifiable, and a mistyped body is
                // unverifiable acceptance — all are malformed
                // (drop with accounting, NO retry: the 2xx may
                // have landed, so resending would duplicate the
                // accepted points). Empty implies {} (clean
                // accept); only a well-typed zero rejection counts
                // as pushed.
                if resp.over_cap || resp.body_invalid || resp.framing_invalid {
                    let why = if resp.body_invalid {
                        "invalid encoding"
                    } else if resp.framing_invalid {
                        "invalid framing"
                    } else {
                        "over cap"
                    };
                    return PushOutcome {
                        pushed: false,
                        attempts: attempt,
                        partial_rejected: 0,
                        malformed: true,
                        note: Some(format!(
                            "osslscope: otlp push malformed response (http {}, {why}, attempt {attempt})",
                            resp.status
                        )),
                    };
                }
                match classify_success_body(&resp.body) {
                    SuccessBody::Malformed => {
                        return PushOutcome {
                            pushed: false,
                            attempts: attempt,
                            partial_rejected: 0,
                            malformed: true,
                            note: Some(format!(
                                "osslscope: otlp push malformed response (http {}, attempt {attempt})",
                                resp.status
                            )),
                        };
                    }
                    SuccessBody::Clean => {
                        return PushOutcome {
                            pushed: true,
                            attempts: attempt,
                            partial_rejected: 0,
                            malformed: false,
                            note: if attempt == 1 {
                                None
                            } else {
                                Some(format!(
                                    "osslscope: otlp push landed after {attempt} attempts"
                                ))
                            },
                        };
                    }
                    SuccessBody::Rejected(partial) => {
                        // 2xx MUST NOT hide partial rejection: drop
                        // the rejected points with accounting, NO
                        // retry.
                        return PushOutcome {
                            pushed: false,
                            attempts: attempt,
                            partial_rejected: partial,
                            malformed: false,
                            note: Some(format!(
                                "osslscope: otlp push partially rejected (http {}, {partial} points, attempt {attempt})",
                                resp.status
                            )),
                        };
                    }
                }
            }
            Ok(resp) => {
                return PushOutcome {
                    pushed: false,
                    attempts: attempt,
                    partial_rejected: 0,
                    malformed: false,
                    note: Some(format!(
                        "osslscope: otlp push rejected (http {}, attempt {attempt})",
                        resp.status
                    )),
                };
            }
            Err(e) => {
                if attempt == PUSH_ATTEMPTS {
                    return PushOutcome {
                        pushed: false,
                        attempts: attempt,
                        partial_rejected: 0,
                        malformed: false,
                        note: Some(format!(
                            "osslscope: otlp push dropped after {PUSH_ATTEMPTS} attempts ({e})"
                        )),
                    };
                }
                // Backoff counts within the deadline (never
                // overshoots it — the loop breaks expired).
                let remaining = end.saturating_duration_since(std::time::Instant::now());
                sleep(backoff.min(Duration::from_secs(60)).min(remaining));
                backoff = backoff.saturating_mul(2);
            }
        }
    }
    PushOutcome {
        pushed: false,
        attempts: consumed,
        partial_rejected: 0,
        malformed: false,
        note: Some("osslscope: otlp push dropped (deadline)".to_string()),
    }
}

/// One queued push: the last-good snapshot + its shared admission
/// set + accumulation starts (rendered at push time so served
/// freshness advances at the source cadence even across outages).
#[derive(Clone)]
struct QueuedPush {
    snap: OperatorSnapshot,
    admitted: super::prometheus::Admitted,
    epoch_start: u64,
    run_start: u64,
}

/// Bounded drop-oldest OTLP handoff (P2fix2 item 21): THE queue
/// on the push path (no unbounded channel anywhere — a stalled
/// collector evicts the oldest payload and counts the drop instead
/// of growing memory). `send` never blocks (over-cap evicts, and
/// post-close sends drop counted); `recv` blocks until an item or
/// `close` (drains first, then ends).
struct PushHandoff<T> {
    state: Mutex<HandoffState<T>>,
    cv: Condvar,
    cap: usize,
}

struct HandoffState<T> {
    queue: VecDeque<T>,
    dropped: u64,
    closed: bool,
}

impl<T> PushHandoff<T> {
    fn new(cap: usize) -> Self {
        Self {
            state: Mutex::new(HandoffState {
                queue: VecDeque::new(),
                dropped: 0,
                closed: false,
            }),
            cv: Condvar::new(),
            cap,
        }
    }

    fn send(&self, item: T) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }
        if state.queue.len() >= self.cap {
            state.queue.pop_front();
            state.dropped = state.dropped.saturating_add(1);
        }
        state.queue.push_back(item);
        self.cv.notify_one();
    }

    fn recv(&self) -> Option<T> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(item) = state.queue.pop_front() {
                return Some(item);
            }
            if state.closed {
                return None;
            }
            state = self.cv.wait(state).unwrap();
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.cv.notify_all();
    }

    fn dropped(&self) -> u64 {
        self.state.lock().unwrap().dropped
    }
}

/// Cumulative push accounting (worker-owned; every event notes via
/// stderr with running totals — retries and partial rejections are
/// counted, never silent).
#[derive(Default)]
struct PushStats {
    pushed: u64,
    attempts: u64,
    dropped_queue: u64,
    dropped_push: u64,
    partial_rejected: u64,
    malformed_responses: u64,
}

impl std::fmt::Display for PushStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pushed={} attempts={} dropped_queue={} dropped_push={} partial_rejected={} malformed_responses={}",
            self.pushed,
            self.attempts,
            self.dropped_queue,
            self.dropped_push,
            self.partial_rejected,
            self.malformed_responses
        )
    }
}

/// Push worker (off the scrape path): takes payloads oldest-first
/// off the bounded drop-oldest handoff and pushes them with the
/// frozen discipline. Backoff sleeps poll `stop` (prompt shutdown);
/// on stop the handoff closes and the worker drains-then-ends.
fn push_worker(
    handoff: Arc<PushHandoff<QueuedPush>>,
    endpoint: String,
    window_fallback_secs: u64,
    stop: Arc<AtomicBool>,
) {
    let mut stats = PushStats::default();
    let mut last_dropped = 0u64;
    loop {
        // Handoff drops first (bounded drop-oldest accounting —
        // counted, never silent).
        let dropped = handoff.dropped();
        stats.dropped_queue = stats
            .dropped_queue
            .saturating_add(dropped.saturating_sub(last_dropped));
        last_dropped = dropped;
        match handoff.recv() {
            Some(p) => {
                // Shutdown drain: pending payloads drop fast with
                // accounting (never a 4×45s shutdown stall against
                // a dead collector).
                if stop.load(Ordering::Relaxed) {
                    stats.dropped_queue = stats.dropped_queue.saturating_add(1);
                    continue;
                }
                // Render at push time (serve-time freshness — stale
                // last-good counters advance at the source cadence).
                // Stale health points sample NOW (P2fix2 item 21 —
                // the sample timestamp is the push instant, never
                // the stale production time).
                let mut snap = p.snap.clone();
                let (age, stale) = super::snapshot::snapshot_freshness(
                    snap.window.as_ref(),
                    window_fallback_secs,
                    super::snapshot::monotonic_ns(),
                );
                snap.health.snapshot_age_ns = age;
                snap.health.stale = stale;
                let payload = super::otel::render_admitted_at(
                    &snap,
                    &p.admitted,
                    p.epoch_start,
                    p.run_start,
                    super::snapshot::wall_ns(),
                );
                let stop2 = stop.clone();
                let mut sleep = move |d: Duration| {
                    // Interruptible backoff (100ms slices).
                    let end = std::time::Instant::now() + d;
                    while std::time::Instant::now() < end {
                        if stop2.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(
                            Duration::from_millis(100)
                                .min(end.saturating_duration_since(std::time::Instant::now())),
                        );
                    }
                };
                let outcome = push_with_discipline(
                    &mut |remaining| otlp_post(&endpoint, &payload, remaining),
                    &mut sleep,
                    PUSH_DEADLINE,
                );
                stats.attempts = stats.attempts.saturating_add(outcome.attempts as u64);
                if outcome.pushed {
                    stats.pushed = stats.pushed.saturating_add(1);
                } else {
                    stats.dropped_push = stats.dropped_push.saturating_add(1);
                }
                stats.partial_rejected = stats
                    .partial_rejected
                    .saturating_add(outcome.partial_rejected);
                if outcome.malformed {
                    stats.malformed_responses = stats.malformed_responses.saturating_add(1);
                }
                if let Some(note) = outcome.note {
                    eprintln!("{note} ({stats})");
                }
            }
            None => break,
        }
    }
    if stats.dropped_queue > 0 || stats.dropped_push > 0 {
        eprintln!("osslscope: otlp worker stopping ({stats})");
    }
}

/// Render one scrape exposition from last-good with serve-time
/// freshness (stale last-good counters advance at the source
/// cadence; frozen counters untouched).
fn render_serve_exposition(qp: &QueuedPush, window_fallback_secs: u64) -> String {
    let (age, stale) = super::snapshot::snapshot_freshness(
        qp.snap.window.as_ref(),
        window_fallback_secs,
        super::snapshot::monotonic_ns(),
    );
    let mut samples = qp.admitted.samples.clone();
    super::prometheus::refresh_freshness_samples(&mut samples, age, stale);
    super::prometheus::render_samples(&samples)
}

/// Test-only one-shot: fail the next joint checkpoint commit
/// (P2fix4 NEW-16 — the production path takes the exact
/// flush-failure arm, as if the write failed; inert unless
/// armed).
#[cfg(test)]
thread_local! { static FAIL_NEXT_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Export-loop refresh state (P2fix3 NEW-9): the budget,
/// accumulation starts, and generation tracker live here so the
/// first-refresh sequence (restore → compare → admit →
/// checkpoint) is one testable step.
#[derive(Default)]
struct RefreshState {
    budget: Budget,
    epoch_start: u64,
    run_start: u64,
    last_gen: Option<u64>,
}

impl RefreshState {
    /// Restore loop state from a freshly opened presenter: the
    /// budget restores AND the generation tracker seeds from the
    /// restored admission's window binding — a same-generation
    /// first refresh never resets (P2fix3 NEW-9) — AND the
    /// accumulation starts restore (P2fix4 NEW-16 — a
    /// same-generation restart keeps the epoch's start instead
    /// of emitting zero). The restore PEEKS (P2fix6 NEW-33): the
    /// live presenter KEEPS the last committed admission/starts,
    /// so a failed first refresh leaves them in place and a
    /// shutdown flush re-persists them — restore-then-fail-then-
    /// shutdown can no longer null the intact checkpoint.
    fn restore(presenter: &mut Presenter) -> Self {
        let mut state = RefreshState::default();
        if let Some(admission) = presenter.peek_admission() {
            state.last_gen = admission.window_id.as_ref().and_then(|w| w.1);
            state.budget.restore(admission);
        }
        if let Some((epoch_start, run_start)) = presenter.peek_export_starts() {
            state.epoch_start = epoch_start;
            state.run_start = run_start;
        }
        state
    }
}

/// One collection refresh: stage, admit with the shared budget,
/// commit jointly, publish. Returns the fresh payload (served by
/// the caller) or the error (the caller keeps last-good — an
/// outage never clears the served snapshot).
fn refresh_once(presenter: &mut Presenter, state: &mut RefreshState) -> Result<QueuedPush, String> {
    // Staged joint commit (P2fix5 NEW-22): the fold state +
    // watermark + generation + admission + omission totals +
    // start times stage AWAY from live state (cloned presenter +
    // budget + local trackers) and commit ONCE — the checkpoint
    // write runs against the STAGED presenter, and only its
    // success commits staged→live. ANY failure (fold, admission,
    // or flush) leaves live state byte-identical, so the next
    // refresh retries the whole transaction instead of resuming
    // mid-fold past a failed flush.
    let mut staged = presenter.clone();
    let mut budget = state.budget.clone();
    let mut snap = staged.build_service_staged()?;
    let run_start = if state.run_start == 0 {
        snap.produced_wall_ns
    } else {
        state.run_start
    };
    let changed = state.last_gen != snap.source.generation;
    if changed {
        budget.reset_epoch();
    }
    // Shared admission, computed ONCE (§6C-12 lockstep).
    let mut admitted = super::prometheus::admit(&snap, &mut budget);
    staged.adopt_overflow(budget.overflow());
    staged.save_admission(budget.snapshot());
    // First refresh binds provisionally too (a pre-first-window
    // epoch start is provisional — the first generation change
    // rebinds it — so no refresh ever publishes a zero start).
    let bind_start = changed || state.epoch_start == 0;
    let epoch_start = if bind_start {
        snap.produced_wall_ns
    } else {
        state.epoch_start
    };
    staged.save_export_starts(epoch_start, run_start);
    #[cfg(test)]
    if FAIL_NEXT_COMMIT.with(|f| f.replace(false)) {
        return Err("osslscope: checkpoint flush: injected failure".to_string());
    }
    staged
        .flush_checkpoint()
        .map_err(|e| format!("osslscope: checkpoint flush: {e}"))?;
    // Commit (infallible from here): the staged fold state +
    // budget + trackers become live, and the published snapshot
    // carries the SAME committed values — both sinks render the
    // post-admission omission total (P-14), never the
    // pre-admission snapshot's (like serve-time freshness, the
    // P-14 sample value is publish-time truth).
    let committed_overflow = staged.committed_series_overflow();
    snap.presenter.series_overflow = committed_overflow;
    for (metric, labelset, value) in admitted.samples.iter_mut() {
        if metric == "osslscope_exporter_series_overflow_total" && labelset.is_empty() {
            *value = committed_overflow.to_string();
        }
    }
    if bind_start {
        state.epoch_start = snap.produced_wall_ns;
    }
    if changed {
        state.last_gen = snap.source.generation;
    }
    state.run_start = run_start;
    state.budget = budget;
    *presenter = staged;
    Ok(QueuedPush {
        snap,
        admitted,
        epoch_start: state.epoch_start,
        run_start: state.run_start,
    })
}

/// Shutdown persist (P2fix5 NEW-22): the collector calls this once
/// after its last refresh. It must persist WITHOUT folding newly
/// landed windows (a fresh fold without admission would commit a
/// new watermark beside a stale admission — the shutdown bypass).
fn shutdown_flush(presenter: &mut Presenter) {
    // Flush ONLY (P2fix5 NEW-22 — the old final build folded
    // newly landed windows without admission, checkpointing a new
    // watermark beside a stale admission; the next open folds
    // those windows normally, so nothing is lost).
    let _ = presenter.flush_checkpoint();
}

/// Serve until `stop` is set (export loop with shared admission +
/// real accumulation starts). Collection (refresh), scrape
/// serving (bounded threads), and pushes (worker) are separated —
/// a stalled push or slow peer never blocks the others.
pub fn serve_with_shutdown(
    opts: Options,
    stop: Arc<AtomicBool>,
    on_scrape: Option<ScrapeCallback>,
) -> ExitCode {
    let checkpoint = opts
        .checkpoint
        .clone()
        .unwrap_or_else(|| checkpoint_default(&opts.out));
    let window_fallback_secs = super::snapshot::WINDOW_SECS_FALLBACK;
    let mut presenter = match Presenter::open_with_checkpoint(
        &opts.out,
        &checkpoint,
        window_fallback_secs,
        "export",
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("osslscope: {e}");
            return ExitCode::from(1);
        }
    };
    let listener = match TcpListener::bind(opts.listen.as_str()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("osslscope: listen {}: {e}", opts.listen);
            return ExitCode::from(1);
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("osslscope: listen: {e}");
        return ExitCode::from(1);
    }
    // Push worker (off the scrape path; only when OTLP configured).
    // The handoff IS the bounded drop-oldest queue (P2fix2 item 21 —
    // no unbounded channel on the push path).
    let handoff = Arc::new(PushHandoff::new(PUSH_QUEUE_CAP));
    let worker = opts.otlp.clone().map(|cfg| {
        let stop = stop.clone();
        let handoff = handoff.clone();
        std::thread::spawn(move || push_worker(handoff, cfg.endpoint, window_fallback_secs, stop))
    });
    // Collector thread (P2fix3 NEW-1): collection refreshes on
    // its own thread and publishes last-good behind a lock — a
    // slow or wedged refresh never stalls the listener (or the
    // OTLP handoff cadence below). Refreshes FIRST, then checks
    // stop (the first tick is immediate, like the old
    // ancient-instant start).
    let last_good: Arc<Mutex<Option<QueuedPush>>> = Arc::new(Mutex::new(None));
    let poll_secs = opts.poll_secs;
    let collector = {
        let stop = stop.clone();
        let last_good = last_good.clone();
        std::thread::spawn(move || {
            let mut state = RefreshState::restore(&mut presenter);
            loop {
                match refresh_once(&mut presenter, &mut state) {
                    Ok(qp) => {
                        *last_good.lock().unwrap() = Some(qp);
                    }
                    Err(e) => {
                        // Outage: last-good keeps serving (stale,
                        // frozen — never extrapolated, §6C-8;
                        // freshness advances at serve time).
                        eprintln!("osslscope: refresh: {e}");
                    }
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let tick_end = std::time::Instant::now() + Duration::from_secs(poll_secs);
                while std::time::Instant::now() < tick_end {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(tick_end.saturating_duration_since(std::time::Instant::now())),
                    );
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            // Shutdown flush (P2fix2 item 13, P2fix5 NEW-22):
            // persist WITHOUT folding (the checkpoint write is
            // the point — a fresh fold without admission is the
            // shutdown bypass).
            shutdown_flush(&mut presenter);
        })
    };
    let mut last_push = std::time::Instant::now();
    let in_flight = Arc::new(AtomicUsize::new(0));
    // Scrape serving runs CONTINUOUSLY on this thread; collection
    // refreshes on the collector thread (serving never pauses
    // between collection ticks AND never blocks on a refresh).
    while !stop.load(Ordering::Relaxed) {
        // OTLP handoff on its own cadence (current snapshot only, no
        // replay — the bounded handoff + worker own queueing +
        // discipline off this path). Independent of the collection
        // tick (a 30 s poll cadence still pushes every 5 s).
        if let Some(cfg) = opts.otlp.as_ref() {
            if last_push.elapsed() >= Duration::from_secs(cfg.push_secs) {
                last_push = std::time::Instant::now();
                if let Some(qp) = last_good.lock().unwrap().clone() {
                    handoff.send(qp);
                }
            }
        }
        // Accept scrapes (nonblocking, short slice): each accepted
        // socket serves on its own bounded thread (slow peers shed
        // past the concurrency cap, never blocking the server).
        let slice_end = std::time::Instant::now() + Duration::from_millis(100);
        while std::time::Instant::now() < slice_end && !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_SCRAPES {
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        drop(stream);
                        continue;
                    }
                    // Clone under the lock, render after it drops
                    // (the collector never waits on a render).
                    let current = last_good.lock().unwrap().clone();
                    let body = match current.as_ref() {
                        Some(qp) => render_serve_exposition(qp, window_fallback_secs),
                        None => "# no snapshot yet\n# EOF\n".to_string(),
                    };
                    if let Some(cb) = on_scrape.clone() {
                        cb(&body);
                    }
                    let in_flight = in_flight.clone();
                    std::thread::spawn(move || {
                        handle_scrape(stream, &body);
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }
    // Join the collector (it ran the shutdown flush above),
    // then close the handoff (the worker drains-then-ends with
    // accounting) and join it.
    let _ = collector.join();
    handoff.close();
    if let Some(worker) = worker {
        let _ = worker.join();
    }
    ExitCode::SUCCESS
}

/// Export entry (runs until terminated).
pub fn run(args: &[String]) -> ExitCode {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(()) => {
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    };
    serve_with_shutdown(opts, Arc::new(AtomicBool::new(false)), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_200(body: &str) -> Result<PostResponse, String> {
        Ok(PostResponse {
            status: 200,
            body: body.to_string(),
            over_cap: false,
            body_invalid: false,
            framing_invalid: false,
        })
    }

    #[test]
    fn new9_first_refresh_preserves_restored_generation() {
        // P2fix3 NEW-9: the export loop's exact first-refresh
        // sequence preserves a restored same-generation budget (no
        // reset — membership + omissions survive), and a
        // generation change checkpoints the new watermark +
        // admission TOGETHER before the new snapshot serves.
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix3-new9-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        // Run 1: refresh (admit) + spike the budget with an extra
        // member (the reset detector — re-admission cannot
        // reproduce it) + persist + drop.
        let first_overflow = {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::default();
            let qp = refresh_once(&mut p, &mut state).expect("first refresh");
            assert_eq!(qp.snap.source.generation, Some(0));
            state.budget.admit_series("zzz_new9_probe", "x=1");
            assert!(state.budget.is_admitted("zzz_new9_probe", "x=1"));
            p.save_admission(state.budget.snapshot());
            p.build_service().unwrap();
            state.budget.overflow()
        };
        // Restart with no new windows: the first refresh must NOT
        // reset the restored same-generation budget.
        {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::restore(&mut p);
            assert!(
                state.budget.is_admitted("zzz_new9_probe", "x=1"),
                "test premise: admission persists in the checkpoint"
            );
            let qp = refresh_once(&mut p, &mut state).expect("restart refresh");
            assert_eq!(qp.snap.source.generation, Some(0));
            assert!(
                state.budget.is_admitted("zzz_new9_probe", "x=1"),
                "restored membership must survive the first refresh (no same-generation reset)"
            );
            assert_eq!(
                state.budget.overflow(),
                first_overflow,
                "omissions stay exact (no recount)"
            );
            // Persist like the loop's shutdown flush (the next open
            // takes it).
            p.build_service().unwrap();
        }
        // Generation change: the checkpoint carries the new
        // watermark + the new admission TOGETHER once the new
        // snapshot serves.
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&snapshot::test_envelope(1, 1, run, 10)).unwrap(),
        )
        .unwrap();
        {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::restore(&mut p);
            assert!(
                state.budget.is_admitted("zzz_new9_probe", "x=1"),
                "test premise: admission persists in the checkpoint"
            );
            let qp = refresh_once(&mut p, &mut state).expect("gen-change refresh");
            assert_eq!(qp.snap.source.generation, Some(1), "new epoch serves");
            let body = std::fs::read(&ckpt).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["watermark_seq"], 1);
            assert_eq!(
                v["accumulators"]["admission"]["window_id"][1], 1,
                "new watermark + new admission checkpoint together: {v:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new16_refresh_commits_once_before_publishing() {
        // P2fix4 NEW-16/NEW-9: snapshot + watermark + admission +
        // omissions commit ONCE per refresh BEFORE publishing —
        // every refresh, not just generation changes. After a
        // same-generation second refresh the checkpoint file
        // carries the NEW watermark with the NEW admission
        // (pre-fix: the file lags one build — new watermark with
        // the previous admission).
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix4-new16a-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::default();
        refresh_once(&mut p, &mut state).expect("first refresh");
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&snapshot::test_envelope(1, 0, run, 10)).unwrap(),
        )
        .unwrap();
        refresh_once(&mut p, &mut state).expect("second refresh");
        let body = std::fs::read(&ckpt).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["watermark_seq"], 1);
        assert_eq!(
            v["accumulators"]["admission"]["window_id"][2], 1,
            "same-generation refresh commits the new admission with the new watermark: {v:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new16_failed_commit_mutates_nothing() {
        // P2fix4 NEW-16: a failed joint commit mutates NEITHER the
        // checkpoint file NOR the generation tracker — the next
        // refresh retries the flush instead of bypassing it
        // (pre-fix: the intermediate checkpoint lands and last_gen
        // advances past the failed flush).
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix4-new16b-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::default();
        refresh_once(&mut p, &mut state).expect("first refresh");
        assert_eq!(state.last_gen, Some(0));
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&snapshot::test_envelope(1, 1, run, 10)).unwrap(),
        )
        .unwrap();
        FAIL_NEXT_COMMIT.with(|f| f.set(true));
        assert!(
            refresh_once(&mut p, &mut state).is_err(),
            "injected commit failure must fail the refresh"
        );
        assert_eq!(
            state.last_gen,
            Some(0),
            "a failed commit must not advance the generation tracker"
        );
        let body = std::fs::read(&ckpt).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["watermark_seq"], 0,
            "a failed commit must leave the checkpoint file on the old watermark: {v:?}"
        );
        // Retry serves the new epoch with its joint commit.
        let qp = refresh_once(&mut p, &mut state).expect("retry refresh");
        assert_eq!(qp.snap.source.generation, Some(1));
        assert_eq!(state.last_gen, Some(1));
        let body = std::fs::read(&ckpt).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["watermark_seq"], 1);
        assert_eq!(
            v["accumulators"]["admission"]["window_id"][1], 1,
            "retry commits the new watermark + admission jointly: {v:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new16_otlp_epoch_start_survives_restart() {
        // P2fix4 NEW-16: the OTLP epoch start persists across
        // restart — a same-generation post-restart refresh keeps
        // the epoch's start (pre-fix: zero, and the renderer
        // emits that zero as startTimeUnixNano).
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix4-new16c-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let (e1, r1) = {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::default();
            let qp = refresh_once(&mut p, &mut state).expect("first refresh");
            assert!(qp.epoch_start > 0 && qp.run_start > 0);
            (qp.epoch_start, qp.run_start)
        };
        {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::restore(&mut p);
            let qp = refresh_once(&mut p, &mut state).expect("restart refresh");
            assert_eq!(
                qp.epoch_start, e1,
                "epoch start survives restart (never zero)"
            );
            assert_eq!(qp.run_start, r1, "run start survives restart");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new22_failed_refresh_mutates_no_live_state() {
        // P2fix5 NEW-22: fold state + watermark + generation +
        // admissions + omission totals + start times stage AWAY
        // from live state and commit ONCE — a failed refresh
        // mutates NOTHING live (pre-fix: the staged fold lands in
        // the live presenter + budget before the flush, so the
        // failure leaves live ahead of the checkpoint file). The
        // retry then commits exactly what a twin that never
        // failed commits (NEW-9 single-transaction equivalence).
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix5-new22a-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::default();
        refresh_once(&mut p, &mut state).expect("first refresh");
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&snapshot::test_envelope(1, 1, run, 10)).unwrap(),
        )
        .unwrap();
        let fp_before = p.test_live_fingerprint();
        let budget_before = state.budget.snapshot();
        let gen_before = state.last_gen;
        let epoch_before = state.epoch_start;
        let run_before = state.run_start;
        let file_before = std::fs::read(&ckpt).unwrap();
        FAIL_NEXT_COMMIT.with(|f| f.set(true));
        assert!(
            refresh_once(&mut p, &mut state).is_err(),
            "injected commit failure must fail the refresh"
        );
        assert_eq!(
            p.test_live_fingerprint(),
            fp_before,
            "a failed refresh must not mutate live presenter state"
        );
        assert_eq!(
            state.budget.snapshot(),
            budget_before,
            "a failed refresh must not mutate the live budget"
        );
        assert_eq!(state.last_gen, gen_before, "last_gen untouched");
        assert_eq!(state.epoch_start, epoch_before, "epoch_start untouched");
        assert_eq!(state.run_start, run_before, "run_start untouched");
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            file_before,
            "a failed refresh must not touch the checkpoint file"
        );
        // Retry equivalence: the retry commits exactly what a twin
        // that never failed commits (minus the volatile owner
        // block and wall-anchored starts).
        let qp = refresh_once(&mut p, &mut state).expect("retry refresh");
        assert_eq!(qp.snap.source.generation, Some(1));
        let dir2 = std::env::temp_dir().join(format!("{}.twin", dir.display()));
        std::fs::create_dir_all(&dir2).unwrap();
        for name in ["window-0000000000.json", "window-0000000001.json"] {
            std::fs::copy(dir.join(name), dir2.join(name)).unwrap();
        }
        let ckpt2 = std::path::PathBuf::from(format!("{}.checkpoint.json", dir2.display()));
        {
            let mut t =
                snapshot::Presenter::open_with_checkpoint(&dir2, &ckpt2, 1, "export").unwrap();
            let mut tstate = RefreshState::default();
            refresh_once(&mut t, &mut tstate).expect("twin first refresh");
            refresh_once(&mut t, &mut tstate).expect("twin second refresh");
        }
        let scrub = |path: &std::path::Path| {
            let mut v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            v.as_object_mut().unwrap().remove("owner");
            // Wall-anchored starts differ run to run (asserted
            // sane separately below).
            let e1 = v["accumulators"]["export_starts"].take();
            assert!(e1.is_array(), "starts persist: {v:?}");
            // The out-DIR binding differs by construction.
            v.as_object_mut().unwrap().remove("out_dir");
            // The content hash covers the scrubbed volatile
            // fields, so it differs by construction too.
            v.as_object_mut().unwrap().remove("sha256");
            v
        };
        assert_eq!(
            scrub(&ckpt),
            scrub(&ckpt2),
            "failed retry commits exactly one successful transaction"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn new22_shutdown_flush_folds_nothing() {
        // P2fix5 NEW-22/NEW-9: shutdown must not
        // fresh-fold-without-admission — a window landing after
        // the last refresh stays unfolded (watermark + admission
        // jointly behind), and the next open folds it normally
        // (no loss). Pre-fix the shutdown build folds the window
        // and checkpoints a new watermark beside the stale
        // admission.
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix5-new22b-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::default();
        refresh_once(&mut p, &mut state).expect("first refresh");
        // A window lands after the last refresh (shutdown window).
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&snapshot::test_envelope(1, 0, run, 10)).unwrap(),
        )
        .unwrap();
        shutdown_flush(&mut p);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(
            v["watermark_seq"], 0,
            "shutdown must not fold the newly landed window: {v:?}"
        );
        assert_eq!(
            v["accumulators"]["admission"]["window_id"][2], 0,
            "watermark + admission stay jointly behind: {v:?}"
        );
        drop(p);
        // The next open folds the window normally (no loss).
        let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state2 = RefreshState::restore(&mut p2);
        let qp = refresh_once(&mut p2, &mut state2).expect("post-shutdown refresh");
        assert_eq!(qp.snap.source.window_seq, Some(1));
        let v2: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v2["watermark_seq"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new45_staged_refresh_recovers_after_stage_failures() {
        // P2fix7 NEW-45: staged export retries reuse the live
        // presenter's committed sequence (the staged clone
        // discards its bump on failure) — 20 consecutive
        // stage-write failures each fail WITHOUT committing
        // (live byte-identical, checkpoint file untouched, zero
        // residue); disarm (storage recovers) → the retry
        // commits. Pre-fix: the same-seq stages leak and the
        // post-recovery retry wedges on "staging crowded".
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix7-new45-staged-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::restore(&mut p);
        refresh_once(&mut p, &mut state).expect("baseline refresh commits");
        let file_before = std::fs::read(&ckpt).unwrap();
        let fp_before = p.test_live_fingerprint();
        let parent = ckpt.parent().unwrap().to_path_buf();
        // Residue scoped to THIS run's target (the checkpoint
        // parent is the shared temp dir — a bare `.staging-`
        // filter would trip on other runs' files).
        let target = ckpt.file_name().unwrap().to_string_lossy().into_owned();
        let residue = || {
            std::fs::read_dir(&parent)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(&target) && n.contains(".staging-"))
                .collect::<Vec<_>>()
        };
        snapshot::stage_fault::arm(20);
        for i in 0..20 {
            let err = refresh_once(&mut p, &mut state)
                .err()
                .expect("injected failure fails refresh");
            assert!(
                !err.contains("crowded"),
                "attempt {i}: never crowded: {err:?}"
            );
            assert_eq!(
                p.test_live_fingerprint(),
                fp_before,
                "attempt {i}: live stays byte-identical"
            );
            assert_eq!(
                std::fs::read(&ckpt).unwrap(),
                file_before,
                "attempt {i}: checkpoint file untouched"
            );
            assert!(
                residue().is_empty(),
                "attempt {i}: zero residue: {:?}",
                residue()
            );
        }
        let qp = refresh_once(&mut p, &mut state).expect("post-recovery retry commits");
        assert_eq!(qp.snap.source.generation, Some(0));
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], 0);
        assert!(
            residue().is_empty(),
            "zero residue after recovery: {:?}",
            residue()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new33_failed_first_refresh_then_shutdown_preserves_checkpoint() {
        // P2fix6 NEW-33: restore must not strip the live
        // presenter — restore + failed first refresh + shutdown
        // preserves the last committed checkpoint (no
        // null-overwrite of admission/starts), and restart
        // retains the same admission + omission count +
        // accumulation starts. Pre-fix: restore TAKES the fields
        // out of the presenter, so the failed refresh leaves them
        // absent and the shutdown flush overwrites the intact
        // checkpoint with nulls.
        use super::super::snapshot;
        let dir = std::env::temp_dir().join(format!(
            "p2fix6-new33-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        // Run 1: refresh (commits admission + starts + the
        // checkpoint) + spike the admission with a probe member
        // (the reset detector — re-admission cannot reproduce
        // it) and persist.
        let (admission, overflow, epoch_start, run_start) = {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::default();
            let qp = refresh_once(&mut p, &mut state).expect("first refresh");
            state.budget.admit_series("zzz_new33_probe", "x=1");
            assert!(state.budget.is_admitted("zzz_new33_probe", "x=1"));
            p.save_admission(state.budget.snapshot());
            p.build_service().unwrap();
            (
                state.budget.snapshot(),
                state.budget.overflow(),
                qp.epoch_start,
                qp.run_start,
            )
        };
        assert!(epoch_start > 0 && run_start > 0, "premise: starts bind");
        // Restart: restore + FAILED first refresh + shutdown (the
        // loop's exact shutdown path after a failed refresh).
        {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let mut state = RefreshState::restore(&mut p);
            assert!(
                state.budget.is_admitted("zzz_new33_probe", "x=1"),
                "premise: restore recovers the committed admission"
            );
            FAIL_NEXT_COMMIT.with(|f| f.set(true));
            assert!(
                refresh_once(&mut p, &mut state).is_err(),
                "the injected commit failure must fail the refresh"
            );
            shutdown_flush(&mut p);
        }
        // The checkpoint file still carries the committed values
        // (no null-overwrite of admission/starts).
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert!(
            v["accumulators"]["admission"].is_object(),
            "shutdown must not null the committed admission: {v:?}"
        );
        assert!(
            v["accumulators"]["admission"]["admitted"]
                .as_array()
                .is_some_and(|m| m.iter().any(|k| k
                    .as_array()
                    .is_some_and(|k| k.first().is_some_and(|n| n == "zzz_new33_probe")))),
            "the committed membership survives: {v:?}"
        );
        assert_eq!(
            v["accumulators"]["admission"]["overflow"].as_u64(),
            Some(overflow),
            "the committed omission count survives: {v:?}"
        );
        assert_eq!(
            v["accumulators"]["export_starts"],
            serde_json::json!([epoch_start, run_start]),
            "the committed starts survive: {v:?}"
        );
        // Restart again: the same admission + omission count +
        // accumulation starts restore.
        {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            let state = RefreshState::restore(&mut p);
            assert_eq!(
                state.budget.snapshot(),
                admission,
                "restart retains the committed admission"
            );
            assert_eq!(
                state.budget.overflow(),
                overflow,
                "restart retains the omission count (no recount)"
            );
            assert_eq!(
                (state.epoch_start, state.run_start),
                (epoch_start, run_start),
                "restart retains the accumulation starts"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new22_p14_equal_across_checkpoint_scrape_otlp() {
        // P2fix5 NEW-22: both sinks render POST-admission omissions
        // — the checkpoint, the scrape set, and the OTLP payload
        // agree on P-14 IMMEDIATELY (pre-fix: the published
        // snapshot carries the pre-admission total, so the sinks
        // lag the checkpoint by one refresh).
        use super::super::{budget, otel, prometheus, snapshot};
        let dir = std::env::temp_dir().join(format!(
            "p2fix5-new22c-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&snapshot::test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        // Probe (throwaway presenter + budget): the offered-order
        // rank of P-14 among the default candidates.
        let probe_ckpt = std::path::PathBuf::from(format!("{}.probe.json", dir.display()));
        let snap_probe = snapshot::Presenter::open_with_checkpoint(&dir, &probe_ckpt, 1, "export")
            .unwrap()
            .build_service_staged()
            .expect("probe stage");
        let mut probe_budget = budget::Budget::new();
        let probe = prometheus::admit(&snap_probe, &mut probe_budget);
        let mut keys: Vec<(String, String)> = probe
            .samples
            .iter()
            .map(|(m, l, _)| (m.clone(), l.clone()))
            .collect();
        keys.sort();
        let rank = keys
            .iter()
            .position(|(m, l)| m == "osslscope_exporter_series_overflow_total" && l.is_empty())
            .expect("premise: P-14 is offered");
        let total = keys.len();
        assert!(
            rank + 1 < total,
            "premise: offers after P-14 exist to omit (rank {rank} of {total})"
        );
        // Pre-fill the loop budget so P-14 is the LAST admitted
        // offer (every later offer omits — positive omissions).
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let mut state = RefreshState::default();
        let prefill = budget::EPOCH_SERIES_CAP - (rank + 1);
        for i in 0..prefill {
            // The per-window cap binds the fill rate (open a fresh
            // window each 256 — the epoch-scoped admitted set
            // persists across them).
            if i % budget::WINDOW_NEW_SERIES_CAP == 0 {
                state.budget.begin_window();
            }
            assert!(
                state
                    .budget
                    .admit_series("zzz_new22_prefill", &format!("i={i}"))
            );
        }
        assert_eq!(state.budget.admitted_len(), prefill);
        // Restored same-generation loop state (what
        // `RefreshState::restore` produces after a restart — the
        // nearly-full epoch budget survives, so this refresh
        // counts omissions instead of resetting).
        state.last_gen = Some(0);
        let qp = refresh_once(&mut p, &mut state).expect("refresh with omissions");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let vckpt: u64 = serde_json::from_value(v["accumulators"]["series_overflow"].clone())
            .expect("checkpoint P-14");
        assert_eq!(
            vckpt,
            (total - (rank + 1)) as u64,
            "premise: positive post-admission omissions"
        );
        assert!(vckpt > 0);
        // Scrape set.
        let vserve: u64 = qp
            .admitted
            .samples
            .iter()
            .find(|(m, l, _)| m == "osslscope_exporter_series_overflow_total" && l.is_empty())
            .expect("P-14 is admitted")
            .2
            .parse()
            .expect("P-14 parses");
        assert_eq!(vserve, vckpt, "scrape-set P-14 equals the checkpoint");
        // Scrape text.
        let text = render_serve_exposition(&qp, snapshot::WINDOW_SECS_FALLBACK);
        assert!(
            text.contains(&format!(
                "osslscope_exporter_series_overflow_total {vckpt}\n"
            )),
            "scrape text carries post-admission P-14"
        );
        // OTLP payload.
        let payload = otel::render_admitted_at(
            &qp.snap,
            &qp.admitted,
            qp.epoch_start,
            qp.run_start,
            qp.snap.produced_wall_ns,
        );
        let ov: serde_json::Value = serde_json::from_str(&payload).expect("otlp json");
        let mut votlp: Option<u64> = None;
        for rm in ov["resourceMetrics"].as_array().unwrap() {
            for sm in rm["scopeMetrics"].as_array().unwrap() {
                for m in sm["metrics"].as_array().unwrap() {
                    if m["name"] == "osslscope.exporter.series.overflow" {
                        votlp = Some(
                            m["sum"]["dataPoints"][0]["asInt"]
                                .as_str()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                    }
                }
            }
        }
        assert_eq!(
            votlp,
            Some(vckpt),
            "OTLP P-14 equals the checkpoint: {payload:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new1_collection_never_blocks_the_listener() {
        // P2fix3 NEW-1: collection runs off the listener — a
        // wedged refresh (a FIFO window file blocks the
        // collector's read) must NOT stall scrape serving: a
        // scrape answers promptly (pre-first-window — nothing
        // collected yet) while the collector is stuck.
        use std::io::{Read, Write};
        use std::sync::{Arc, atomic::AtomicBool};
        let dir = std::env::temp_dir().join(format!(
            "p2fix3-new1-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A FIFO window file: the collector's read blocks until a
        // writer arrives (none does until teardown).
        let fifo = dir.join("window-0000000000.json");
        // SAFETY: mkfifo on a fresh private path.
        assert_eq!(
            unsafe {
                libc::mkfifo(
                    std::ffi::CString::new(fifo.to_str().unwrap())
                        .unwrap()
                        .as_ptr(),
                    0o600,
                )
            },
            0
        );
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            port
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let out = dir.clone();
        let checkpoint = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let handle = std::thread::spawn(move || {
            serve_with_shutdown(
                Options {
                    out,
                    listen: format!("127.0.0.1:{port}"),
                    poll_secs: 1,
                    otlp: None,
                    checkpoint: Some(checkpoint),
                },
                stop2,
                None,
            )
        });
        // The scrape must answer promptly despite the wedged
        // collector (5 s read bound — pre-fix this times out).
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut stream = None;
        let dial_end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while stream.is_none() && std::time::Instant::now() < dial_end {
            stream =
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
                    .ok();
        }
        let mut stream = stream.expect("listener accepts while collector wedges");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut body = String::new();
        stream
            .read_to_string(&mut body)
            .expect("scrape answers promptly");
        assert!(
            body.contains("no snapshot yet"),
            "pre-first-window serve: {body:?}"
        );
        // Teardown: stop, then rendezvous the stuck collector
        // read ONCE (writer open + instant close reads EOF): the
        // wedged refresh errors, sees stop, and breaks; the
        // shutdown flush is write-only (P2fix5 NEW-22 — no
        // re-read, so no second rendezvous: a second writer-open
        // would block forever with no reader left).
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handoff_is_bounded_drop_oldest() {
        // P2fix2 item 21 (codex NEW-P2a): the OTLP handoff itself is
        // the bounded drop-oldest queue (no unbounded channel
        // anywhere on the push path) — over-cap sends evict the
        // oldest payload and count the drop; close drains then ends.
        let h = PushHandoff::new(2);
        h.send("a");
        h.send("b");
        assert_eq!(h.dropped(), 0);
        h.send("c");
        assert_eq!(h.dropped(), 1);
        assert_eq!(h.recv(), Some("b"));
        assert_eq!(h.recv(), Some("c"));
        h.close();
        assert!(h.recv().is_none());
        // Sends after close drop (counted, never block).
        h.send("d");
        assert_eq!(h.dropped(), 2);
    }

    #[test]
    fn malformed_success_is_not_full_acceptance() {
        // P2fix2 item 21: a 2xx with a non-empty unparseable body is
        // NOT full acceptance (the collector may have rejected
        // everything — unverifiable acceptance never counts as
        // pushed); an empty body still implies {} (clean accept).
        let noop_sleep = &mut |_: Duration| {};
        let out = push_with_discipline(
            &mut |_| ok_200("not json{{"),
            noop_sleep,
            Duration::from_secs(45),
        );
        assert!(!out.pushed, "malformed success must not push");
        assert!(out.malformed);
        assert_eq!(out.attempts, 1);
        let out = push_with_discipline(&mut |_| ok_200(""), noop_sleep, Duration::from_secs(45));
        assert!(out.pushed, "empty body still accepts");
        assert!(!out.malformed);
    }

    #[test]
    fn end_to_end_deadline_binds_stalled_attempts() {
        // P2fix2 item 21: the end-to-end deadline binds transport
        // timeouts AND backoffs — a stalled attempt (1 byte then
        // silence: per-read timeouts would reset forever) aborts at
        // the deadline instead of running the full attempt series.
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done2 = done.clone();
        let filler = std::thread::spawn(move || {
            // One byte then silence (hold the connection open until
            // the test releases it).
            if let Ok((mut s, _)) = stub.accept() {
                let _ = s.write_all(b"X");
                while !done2.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let t0 = std::time::Instant::now();
        let out = push_with_discipline(
            &mut |remaining| otlp_post(&url, "{}", remaining),
            &mut |d| std::thread::sleep(d),
            std::time::Duration::from_secs(3),
        );
        let dt = t0.elapsed();
        assert!(!out.pushed);
        assert!(
            dt < std::time::Duration::from_secs(10),
            "stalled attempt must abort at the deadline, took {dt:?}"
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        filler.join().unwrap();
    }

    #[test]
    fn partial_success_counts_both_spellings() {
        // (P2fix3 NEW-8: typed through classify_success_body —
        // well-typed spellings classify, mistyped ones are
        // malformed, never silent zeros.)
        assert_eq!(classify_success_body("{}"), SuccessBody::Clean);
        assert_eq!(classify_success_body(""), SuccessBody::Clean);
        assert_eq!(
            classify_success_body(r#"{"partialSuccess":{}}"#),
            SuccessBody::Clean
        );
        assert_eq!(
            classify_success_body(r#"{"partialSuccess":{"rejectedDataPoints":"5"}}"#),
            SuccessBody::Rejected(5)
        );
        assert_eq!(
            classify_success_body(r#"{"partialSuccess":{"rejectedDataPoints":7}}"#),
            SuccessBody::Rejected(7)
        );
        assert_eq!(classify_success_body("not json"), SuccessBody::Malformed);
        assert_eq!(
            classify_success_body(r#"{"partialSuccess":{"rejectedDataPoints":"bogus"}}"#),
            SuccessBody::Malformed
        );
    }

    // --- P2fix3 NEW-8 RED pins (absolute deadline per I/O, HTTP
    // framing, typed partialSuccess) ---

    #[test]
    fn new8_progressing_peer_aborts_at_absolute_deadline() {
        // P2fix3 NEW-8: a progressing peer (1 byte per 500ms —
        // inside every inactivity timeout) must NOT push the push
        // past the absolute budget: each I/O rechecks it.
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                // Progress past any absolute budget (10s of bytes).
                for _ in 0..20 {
                    if s.write_all(b"x").is_err() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let t0 = std::time::Instant::now();
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(2));
        let dt = t0.elapsed();
        assert!(
            res.is_err(),
            "progressing peer must abort at the absolute deadline, got {res:?}"
        );
        assert!(
            dt < std::time::Duration::from_secs(7),
            "deadline abort must be prompt, took {dt:?}"
        );
        filler.join().unwrap();
    }

    #[test]
    fn new8_truncated_headers_never_push() {
        // P2fix3 NEW-8: headers cut before the blank line are
        // truncated, never a 2xx-with-empty-body accept.
        // [p2fix7 NEW-43: after a recognized 2xx the truncation
        // is `framing_invalid` (malformed WITHOUT retry — the
        // 2xx may have landed), never a transport error.]
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                // No blank line, then close: truncated framing.
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        let resp = res.expect("the recognized 2xx parses");
        assert_eq!(resp.status, 200);
        assert!(
            resp.framing_invalid,
            "truncated headers must flag invalid framing, got {resp:?}"
        );
        filler.join().unwrap();
    }

    #[test]
    fn new8_short_body_never_pushes() {
        // P2fix3 NEW-8 (+ P2fix6 NEW-39 routing): a body shorter
        // than Content-Length is truncated, never acceptance.
        // [p2fix6 NEW-39: after a recognized 2xx the truncation
        // is `framing_invalid` (malformed WITHOUT retry — the
        // 2xx may have landed), never a transport error.]
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nshort");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        let resp = res.expect("the recognized 2xx parses");
        assert_eq!(resp.status, 200);
        assert!(
            resp.framing_invalid,
            "short body must flag invalid framing, got {resp:?}"
        );
        filler.join().unwrap();
    }

    #[test]
    fn new8_strict_version_and_headers_reject() {
        // P2fix4 NEW-8 (+ P2fix6 NEW-39 routing): ambiguous framing
        // rejects — an arbitrary `HTTP/` version word is a
        // framing error before any recognized status (transport
        // error → retry), never parsed past (pre-fix: any `HTTP/`
        // prefix passes and colon-less lines are ignored).
        // [p2fix6 NEW-39: a colon-less line AFTER a recognized
        // 2xx is `framing_invalid` (malformed WITHOUT retry),
        // never a transport error.]
        use std::io::Write;
        use std::net::TcpListener;
        for (what, head) in [
            (
                "bogus-version",
                b"HTTP/bogus 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            ),
            (
                "short-version",
                b"HTTP/1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(head);
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
            assert!(res.is_err(), "{what} must error, got {res:?}");
            filler.join().unwrap();
        }
        // Colon-less line after a recognized 2xx: invalid
        // framing, no retry (see `new39_malformed_2xx_framing_never_retries`).
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ =
                    s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nGarbageLine\r\n\r\n{}");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        let resp = res.expect("the recognized 2xx parses");
        assert!(
            resp.framing_invalid,
            "colon-less header must flag invalid framing, got {resp:?}"
        );
        filler.join().unwrap();
        // Strict-but-valid framing still parses (both 1.x minors).
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(
                        format!("{version} 200 OK\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes(),
                    );
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
            assert!(res.is_ok(), "{version} must parse, got {res:?}");
            filler.join().unwrap();
        }
    }

    #[test]
    fn new8_duplicate_response_members_reject_before_acceptance() {
        // P2fix4 NEW-8: duplicate response members reject BEFORE
        // counting acceptance — JSON last-wins must not hide a
        // prior `partialSuccess` (or a prior count) behind a
        // later clean block (pre-fix: last-wins → Clean → pushed).
        let noop_sleep = &mut |_: Duration| {};
        for body in [
            r#"{"partialSuccess": {"rejectedDataPoints": 5}, "partialSuccess": {}}"#,
            r#"{"partialSuccess": {"rejectedDataPoints": 5, "rejectedDataPoints": 0}}"#,
            r#"{"partialSuccess": {}, "partialSuccess": {"rejectedDataPoints": 5}}"#,
        ] {
            let out =
                push_with_discipline(&mut |_| ok_200(body), noop_sleep, Duration::from_secs(45));
            assert!(
                !out.pushed && out.malformed,
                "duplicated members must not push: {body}"
            );
        }
        // Distinct members still classify (control).
        let out = push_with_discipline(
            &mut |_| ok_200(r#"{"partialSuccess": {"rejectedDataPoints": 7}}"#),
            noop_sleep,
            Duration::from_secs(45),
        );
        assert!(!out.pushed && out.partial_rejected == 7);
    }

    #[test]
    fn new39_content_length_grammar_is_digits_only() {
        // P2fix6 NEW-39: the supported length grammar is 1*DIGIT
        // — a signed, empty, or interior-spaced Content-Length
        // never parses (pre-fix: integer parsing accepts `+2`,
        // counting a misframed body as acceptance).
        use std::io::Write;
        use std::net::TcpListener;
        for (what, head) in [
            (
                "signed-plus",
                b"HTTP/1.0 200 OK\r\nContent-Length: +2\r\n\r\n{}".as_slice(),
            ),
            (
                "signed-minus",
                b"HTTP/1.0 200 OK\r\nContent-Length: -2\r\n\r\n{}".as_slice(),
            ),
            (
                "empty",
                b"HTTP/1.0 200 OK\r\nContent-Length:\r\n\r\n{}".as_slice(),
            ),
            (
                "interior-space",
                b"HTTP/1.0 200 OK\r\nContent-Length: 1 1\r\n\r\n{}".as_slice(),
            ),
            (
                "trailing-junk",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2x\r\n\r\n{}".as_slice(),
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(head);
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let noop_sleep = &mut |_: Duration| {};
            let out = push_with_discipline(
                &mut |remaining| otlp_post(&url, "{}", remaining),
                noop_sleep,
                Duration::from_secs(45),
            );
            assert!(
                !out.pushed && out.malformed && out.attempts == 1,
                "{what} must malformed-drop without retry: {out:?}"
            );
            filler.join().unwrap();
        }
        // Plain digits still parse (control — incl. OWS + leading
        // zeros, which the 1*DIGIT grammar allows).
        for head in [
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.0 200 OK\r\nContent-Length:   2  \r\n\r\n{}".as_slice(),
            b"HTTP/1.0 200 OK\r\nContent-Length: 002\r\n\r\n{}".as_slice(),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(head);
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
            assert!(res.is_ok(), "digits must parse, got {res:?}");
            filler.join().unwrap();
        }
    }

    #[test]
    fn new39_invalid_header_encoding_rejects() {
        // P2fix6 NEW-39, ROUTING NARROWED [p2fix7 NEW-43]: only an
        // undecodable/truncated STATUS LINE stays a transport
        // error (the status is unrecognized, like any other
        // unreadable response). Undecodable bytes AFTER a
        // recognized status are `framing_invalid` (malformed
        // WITHOUT retry — the 2xx may have landed), pinned in
        // `new43_invalid_header_encoding_after_status_never_retries`.
        use std::io::Write;
        use std::net::TcpListener;
        for (what, head) in [
            (
                "status-line-garbage",
                b"\xff\xfe not a status\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            ),
            ("status-line-truncated", b"HTTP/1.0 20".as_slice()),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(head);
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
            assert!(
                res.is_err(),
                "{what} must stay a transport error, got {res:?}"
            );
            filler.join().unwrap();
        }
    }

    #[test]
    fn new43_truncated_headers_after_status_never_retries() {
        // P2fix7 NEW-43: the status parses BEFORE the remaining
        // framing — headers truncated (EOF before the blank line)
        // AFTER a complete readable 2xx are `framing_invalid`
        // (malformed WITHOUT retry — the 2xx may have landed).
        // Pre-fix: truncation is a transport error, so the worker
        // retries a possibly-accepted push up to PUSH_ATTEMPTS.
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        stub.set_nonblocking(true).unwrap();
        let port = stub.local_addr().unwrap().port();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done2 = done.clone();
        let filler = std::thread::spawn(move || {
            loop {
                match stub.accept() {
                    Ok((mut s, _)) => {
                        let mut buf = [0u8; 4096];
                        let _ = std::io::Read::read(&mut s, &mut buf);
                        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n");
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => break,
                }
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let noop_sleep = &mut |_: Duration| {};
        let out = push_with_discipline(
            &mut |remaining| otlp_post(&url, "{}", remaining),
            noop_sleep,
            Duration::from_secs(45),
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            !out.pushed && out.malformed && out.attempts == 1,
            "truncated headers after 2xx must malformed-drop on the first attempt: {out:?}"
        );
        filler.join().unwrap();
    }

    #[test]
    fn new43_invalid_header_encoding_after_status_never_retries() {
        // P2fix7 NEW-43: undecodable header bytes AFTER a complete
        // readable 2xx are `framing_invalid` (malformed WITHOUT
        // retry — header decode must not discard an already
        // readable status into the transport path). Pre-fix: any
        // undecodable header block is a transport error (retried).
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        stub.set_nonblocking(true).unwrap();
        let port = stub.local_addr().unwrap().port();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done2 = done.clone();
        let filler = std::thread::spawn(move || {
            loop {
                match stub.accept() {
                    Ok((mut s, _)) => {
                        let mut buf = [0u8; 4096];
                        let _ = std::io::Read::read(&mut s, &mut buf);
                        let _ = s.write_all(
                            b"HTTP/1.0 200 OK\r\nX-Bin: \xff\xfe\r\nContent-Length: 2\r\n\r\n{}",
                        );
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => break,
                }
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        let resp = res.expect("post-status garbage must not be a transport error");
        assert!(
            resp.framing_invalid && resp.status == 200,
            "post-status garbage is framing_invalid(200): {resp:?}"
        );
        let noop_sleep = &mut |_: Duration| {};
        let out = push_with_discipline(
            &mut |remaining| otlp_post(&url, "{}", remaining),
            noop_sleep,
            Duration::from_secs(45),
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            !out.pushed && out.malformed && out.attempts == 1,
            "post-status garbage must malformed-drop on the first attempt: {out:?}"
        );
        filler.join().unwrap();
    }

    #[test]
    fn new43_field_and_line_grammar() {
        // P2fix7 NEW-43: the supported field + line grammar —
        // field names are strict tokens (no whitespace before the
        // colon, no whitespace inside), values trim HTTP OWS
        // (SP/HTAB only — never general whitespace), lines end
        // CRLF (no bare CR/LF), the status line is `version SP
        // code [SP reason]` with single spaces. Violations after
        // a recognized 2xx are `framing_invalid` (malformed
        // WITHOUT retry); violations IN the status line leave it
        // unrecognized (transport error). Pre-fix: names trim
        // (whitespace-before-colon parses), values general-trim
        // (VT/FF parse), lines split loosely (bare CR/LF parse),
        // and the status splits on any whitespace run.
        use std::io::Write;
        use std::net::TcpListener;
        // (what, response bytes, expect): Framing = malformed
        // with attempts == 1; TransportErr = otlp_post Err.
        #[derive(PartialEq, Eq, Debug)]
        enum Expect {
            Framing,
            TransportErr,
            Pushed,
        }
        for (what, head, expect) in [
            (
                "space-before-colon",
                b"HTTP/1.0 200 OK\r\nContent-Length : 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "space-in-name",
                b"HTTP/1.0 200 OK\r\nX Bad: y\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "vt-in-value",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\x0b\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "bare-lf",
                b"HTTP/1.0 200 OK\r\nX: a\nY: b\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "bare-cr",
                b"HTTP/1.0 200 OK\r\nX: a\rb\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "double-space-status",
                b"HTTP/1.0  200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::TransportErr,
            ),
            (
                "tab-status-separator",
                b"HTTP/1.1\t200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::TransportErr,
            ),
            (
                "ows-tabs-control",
                b"HTTP/1.0 200 OK\r\nContent-Length:\t2\t\r\n\r\n{}".as_slice(),
                Expect::Pushed,
            ),
            (
                "empty-reason-control",
                b"HTTP/1.0 200\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Pushed,
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            stub.set_nonblocking(true).unwrap();
            let port = stub.local_addr().unwrap().port();
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done2 = done.clone();
            let filler = std::thread::spawn(move || {
                loop {
                    match stub.accept() {
                        Ok((mut s, _)) => {
                            let mut buf = [0u8; 4096];
                            let _ = std::io::Read::read(&mut s, &mut buf);
                            let _ = s.write_all(head);
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        _ => break,
                    }
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let noop_sleep = &mut |_: Duration| {};
            let out = push_with_discipline(
                &mut |remaining| otlp_post(&url, "{}", remaining),
                noop_sleep,
                Duration::from_secs(45),
            );
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            match expect {
                Expect::Framing => assert!(
                    !out.pushed && out.malformed && out.attempts == 1,
                    "{what} must malformed-drop on the first attempt: {out:?}"
                ),
                Expect::TransportErr => assert!(
                    !out.pushed && !out.malformed && out.attempts == PUSH_ATTEMPTS,
                    "{what} must stay a retried transport error: {out:?}"
                ),
                Expect::Pushed => assert!(
                    out.pushed && out.attempts == 1,
                    "{what} must push cleanly: {out:?}"
                ),
            }
            filler.join().unwrap();
        }
    }

    #[test]
    fn new52_field_value_grammar() {
        // P2fix8 NEW-52: EVERY field value validates (including
        // IGNORED headers — RFC 9110 field rules: after OWS
        // trimming the content is VCHAR / obs-text / SP / HTAB
        // only — NUL and other CTLs + DEL reject). A recognized
        // 2xx with an invalid control in an ignored header is
        // `framing_invalid` (malformed WITHOUT retry — the 2xx
        // may have landed). Pre-fix: ignored values skip
        // validation, so a NUL in an ordinary response header
        // survives decoding and earns success credit (RED).
        use std::io::Write;
        use std::net::TcpListener;
        #[derive(PartialEq, Eq, Debug)]
        enum Expect {
            Framing,
            Pushed,
        }
        for (what, head, expect) in [
            (
                "nul-in-ignored-value",
                b"HTTP/1.0 200 OK\r\nX-Trace: a\x00b\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "ctl-in-ignored-value",
                b"HTTP/1.0 200 OK\r\nX-Trace: a\x01b\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "del-in-ignored-value",
                b"HTTP/1.0 200 OK\r\nX-Trace: a\x7fb\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "lf-in-ignored-value",
                b"HTTP/1.0 200 OK\r\nX-Trace: a\x0ab\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "nul-in-content-length",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\x00\r\n\r\n{}".as_slice(),
                Expect::Framing,
            ),
            (
                "ows-htab-interior-control",
                b"HTTP/1.0 200 OK\r\nX-Trace: a\tb c\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Pushed,
            ),
            (
                "obs-text-control",
                b"HTTP/1.0 200 OK\r\nX-Trace: caf\xc3\xa9\r\nContent-Length: 2\r\n\r\n{}"
                    .as_slice(),
                Expect::Pushed,
            ),
            (
                "empty-value-control",
                b"HTTP/1.0 200 OK\r\nX-Trace:\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
                Expect::Pushed,
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            stub.set_nonblocking(true).unwrap();
            let port = stub.local_addr().unwrap().port();
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done2 = done.clone();
            let filler = std::thread::spawn(move || {
                loop {
                    match stub.accept() {
                        Ok((mut s, _)) => {
                            let mut buf = [0u8; 4096];
                            let _ = std::io::Read::read(&mut s, &mut buf);
                            let _ = s.write_all(head);
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        _ => break,
                    }
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let noop_sleep = &mut |_: Duration| {};
            let out = push_with_discipline(
                &mut |remaining| otlp_post(&url, "{}", remaining),
                noop_sleep,
                Duration::from_secs(45),
            );
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            match expect {
                Expect::Framing => assert!(
                    !out.pushed && out.malformed && out.attempts == 1,
                    "{what} must malformed-drop on the first attempt: {out:?}"
                ),
                Expect::Pushed => assert!(
                    out.pushed && out.attempts == 1,
                    "{what} must push cleanly: {out:?}"
                ),
            }
            filler.join().unwrap();
        }
    }

    #[test]
    fn new39_malformed_2xx_framing_never_retries() {
        // P2fix6 NEW-39: malformed framing AFTER a recognized 2xx
        // accounts malformed WITHOUT retry (the 2xx may have
        // landed — resending would duplicate the accepted
        // points). Pre-fix: framing failures return transport
        // errors, so the worker retries a possibly-accepted push
        // up to PUSH_ATTEMPTS. Cases: transfer coding,
        // conflicting lengths, colon-less header, truncated body.
        use std::io::Write;
        use std::net::TcpListener;
        for (what, head, hold_open) in [
            (
                "transfer-coding",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip\r\n\r\n{}"
                    .as_slice(),
                false,
            ),
            (
                "conflicting-length",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
                false,
            ),
            (
                "colon-less",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nbogus line\r\n\r\n{}".as_slice(),
                false,
            ),
            (
                "truncated-body",
                b"HTTP/1.0 200 OK\r\nContent-Length: 200\r\n\r\n{}".as_slice(),
                true,
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            stub.set_nonblocking(true).unwrap();
            let port = stub.local_addr().unwrap().port();
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let done2 = done.clone();
            let filler = std::thread::spawn(move || {
                // Serve every attempt the worker makes (pre-fix
                // retries — the stub must survive them to count
                // them) until the test releases it.
                loop {
                    match stub.accept() {
                        Ok((mut s, _)) => {
                            let mut buf = [0u8; 4096];
                            let _ = std::io::Read::read(&mut s, &mut buf);
                            let _ = s.write_all(head);
                            if hold_open {
                                // Truncated body: hold briefly so
                                // the short read races
                                // deterministically, then close
                                // (EOF) to deliver the truncation.
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        _ => break,
                    }
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let noop_sleep = &mut |_: Duration| {};
            let out = push_with_discipline(
                &mut |remaining| otlp_post(&url, "{}", remaining),
                noop_sleep,
                Duration::from_secs(45),
            );
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(
                !out.pushed && out.malformed && out.attempts == 1,
                "{what} must malformed-drop on the first attempt: {out:?}"
            );
            filler.join().unwrap();
        }
    }

    #[test]
    fn new24_unsupported_transfer_coding_rejects_before_acceptance() {
        // P2fix5 NEW-24 (+ P2fix6 NEW-39 routing): any transfer
        // coding beyond the exact expectations (Content-Length
        // XOR close-delimited) rejects BEFORE counting acceptance
        // — other codings, coding lists, and Content-Length
        // fall-through all fail (pre-fix: only the literal
        // `chunked` rejects; `gzip`, lists, and `identity` fall
        // through to Content-Length and can count as acceptance).
        // [p2fix6 NEW-39: after a recognized 2xx the failure is
        // `framing_invalid` (malformed WITHOUT retry — the 2xx
        // may have landed), never a transport error.]
        use std::io::Write;
        use std::net::TcpListener;
        for (what, head) in [
            (
                "gzip-with-length",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip\r\n\r\n{}".as_slice(),
            ),
            (
                "coding-list",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{}".as_slice(),
            ),
            (
                "coding-without-length",
                b"HTTP/1.0 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}".as_slice(),
            ),
            (
                "identity",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: identity\r\n\r\n{}".as_slice(),
            ),
            (
                "chunked-control",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}".as_slice(),
            ),
        ] {
            let stub = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = stub.local_addr().unwrap().port();
            let filler = std::thread::spawn(move || {
                if let Ok((mut s, _)) = stub.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut s, &mut buf);
                    let _ = s.write_all(head);
                }
            });
            let url = format!("http://127.0.0.1:{port}/v1/metrics");
            let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
            let resp = res.expect("{what} parses the recognized 2xx");
            assert_eq!(resp.status, 200);
            assert!(
                resp.framing_invalid,
                "{what} must flag invalid framing, got {resp:?}"
            );
            filler.join().unwrap();
        }
        // Coding-free framing still parses (control).
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        assert!(res.is_ok(), "coding-free framing must parse, got {res:?}");
        filler.join().unwrap();
    }

    #[test]
    fn new24_invalid_body_encoding_malformed_never_pushes() {
        // P2fix5 NEW-24: an invalid body encoding rejects BEFORE
        // counting acceptance — no lossy normalization (pre-fix:
        // `from_utf8_lossy` turns `{"note":"<0xff>"}` into valid
        // JSON that classifies Clean and counts as pushed).
        // Through the worker's exact accounting path
        // (`push_with_discipline` over `otlp_post`): malformed
        // drops WITHOUT retry (the 2xx may have landed — resending
        // would duplicate the accepted points).
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                // `{"note":"\xff"}` (11 bytes): lossy-normalizes to
                // valid clean JSON, but the bytes are not UTF-8.
                let _ = s
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\n{\"note\":\"\xff\"}");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let noop_sleep = &mut |_: Duration| {};
        let out = push_with_discipline(
            &mut |remaining| otlp_post(&url, "{}", remaining),
            noop_sleep,
            Duration::from_secs(45),
        );
        assert!(
            !out.pushed && out.malformed && out.attempts == 1,
            "invalid body encoding must malformed-drop without retry: {out:?}"
        );
        filler.join().unwrap();
        // Struct-level twin (the flag the strict decode sets).
        let out = push_with_discipline(
            &mut |_| {
                Ok(PostResponse {
                    status: 200,
                    body: String::new(),
                    over_cap: false,
                    body_invalid: true,
                    framing_invalid: false,
                })
            },
            noop_sleep,
            Duration::from_secs(45),
        );
        assert!(
            !out.pushed && out.malformed && out.attempts == 1,
            "body_invalid must malformed-drop without retry: {out:?}"
        );
    }

    #[test]
    fn new8_garbage_status_line_errors() {
        // P2fix3 NEW-8: no parseable HTTP status line is a framing
        // error (transport error → retry), never status 0.
        use std::io::Write;
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let filler = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ = s.write_all(b"GARBAGE\r\n\r\n");
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let res = otlp_post(&url, "{}", std::time::Duration::from_secs(5));
        assert!(res.is_err(), "garbage status must error, got {res:?}");
        filler.join().unwrap();
    }

    #[test]
    fn new8_mistyped_partial_success_never_pushes() {
        // P2fix3 NEW-8: typed partialSuccess — a mistyped block or
        // count is malformed (drop, never pushed), not a silent
        // full accept.
        let noop_sleep = &mut |_: Duration| {};
        for body in [
            r#"{"partialSuccess":5}"#,
            r#"{"partialSuccess":{"rejectedDataPoints":true}}"#,
            r#"{"partialSuccess":{"rejectedDataPoints":-1}}"#,
            r#"{"partialSuccess":{"rejectedDataPoints":"bogus"}}"#,
            r#"{"partialSuccess":{"rejectedDataPoints":7,"errorMessage":9}}"#,
        ] {
            let out =
                push_with_discipline(&mut |_| ok_200(body), noop_sleep, Duration::from_secs(45));
            assert!(
                !out.pushed && out.malformed,
                "mistyped success must not push: {body}"
            );
        }
        // Well-typed spellings keep their contract (object, both
        // count spellings, empty block, string errorMessage).
        for (body, pushed, partial) in [
            ("{}", true, 0u64),
            ("", true, 0),
            (r#"{"partialSuccess":{}}"#, true, 0),
            (r#"{"partialSuccess":{"rejectedDataPoints":"5"}}"#, false, 5),
            (r#"{"partialSuccess":{"rejectedDataPoints":7}}"#, false, 7),
            (
                r#"{"partialSuccess":{"rejectedDataPoints":0,"errorMessage":"m"}}"#,
                true,
                0,
            ),
        ] {
            let out =
                push_with_discipline(&mut |_| ok_200(body), noop_sleep, Duration::from_secs(45));
            assert_eq!(
                (out.pushed, out.partial_rejected),
                (pushed, partial),
                "{body}"
            );
        }
    }

    #[test]
    fn new8_slow_drain_write_aborts_at_absolute_deadline() {
        // P2fix3 NEW-8: a peer that drains steadily (every write()
        // succeeds inside its inactivity timeout) still lets a big
        // write run past the absolute budget — each I/O must
        // recheck it. The drain runs 6s (past the 2s budget) then
        // holds the connection open without reading.
        use std::net::TcpListener;
        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = stub.local_addr().unwrap().port();
        let drain = std::thread::spawn(move || {
            if let Ok((mut s, _)) = stub.accept() {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let mut chunk = [0u8; 1024];
                let end = std::time::Instant::now() + std::time::Duration::from_secs(6);
                // ~50KB/s drain (every sender write() succeeds).
                while std::time::Instant::now() < end {
                    if std::io::Read::read(&mut s, &mut chunk).is_err() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/metrics");
        let big = "x".repeat(50_000_000);
        let t0 = std::time::Instant::now();
        let res = otlp_post(&url, &big, std::time::Duration::from_secs(2));
        let dt = t0.elapsed();
        assert!(
            res.is_err(),
            "slow-drain write must abort at the absolute deadline, got {res:?}"
        );
        assert!(
            dt < std::time::Duration::from_secs(5),
            "deadline abort must be prompt, took {dt:?}"
        );
        drain.join().unwrap();
    }

    #[test]
    fn push_discipline_accounts_every_outcome() {
        // P2fix1 item 18: transport errors retry with backoff;
        // non-2xx and 2xx-partial drop WITHOUT retry (supersession);
        // every outcome accounted (attempts + partial + note).
        let noop_sleep = &mut |_: Duration| {};
        // Clean first-try push: silent success.
        let out = push_with_discipline(&mut |_| ok_200("{}"), noop_sleep, Duration::from_secs(45));
        assert_eq!(
            out,
            PushOutcome {
                pushed: true,
                attempts: 1,
                partial_rejected: 0,
                malformed: false,
                note: None,
            }
        );
        // Two transport errors then success: 3 attempts, backoff
        // 1s, 2s, landed note.
        let mut calls = 0u32;
        let mut sleeps = vec![];
        let out = push_with_discipline(
            &mut |_| {
                calls += 1;
                if calls < 3 {
                    Err("connect: refused".to_string())
                } else {
                    ok_200("{}")
                }
            },
            &mut |d| sleeps.push(d),
            Duration::from_secs(45),
        );
        assert!(out.pushed);
        assert_eq!(out.attempts, 3);
        assert_eq!(sleeps, vec![Duration::from_secs(1), Duration::from_secs(2)]);
        assert!(out.note.unwrap().contains("landed after 3 attempts"));
        // 2xx MUST NOT hide partial rejection: drop + count, 1 attempt.
        let out = push_with_discipline(
            &mut |_| ok_200(r#"{"partialSuccess":{"rejectedDataPoints":"5"}}"#),
            noop_sleep,
            Duration::from_secs(45),
        );
        assert_eq!(
            out,
            PushOutcome {
                pushed: false,
                attempts: 1,
                partial_rejected: 5,
                malformed: false,
                note: Some(
                    "osslscope: otlp push partially rejected (http 200, 5 points, attempt 1)"
                        .to_string()
                ),
            }
        );
        // Non-2xx: drop + count, 1 attempt, no retry.
        let mut calls = 0u32;
        let out = push_with_discipline(
            &mut |_| {
                calls += 1;
                Ok(PostResponse {
                    status: 500,
                    body: String::new(),
                    over_cap: false,
                    body_invalid: false,
                    framing_invalid: false,
                })
            },
            noop_sleep,
            Duration::from_secs(45),
        );
        assert!(!out.pushed);
        assert_eq!((out.attempts, calls), (1, 1));
        // Persistent transport failure: 5 attempts, backoff
        // 1/2/4/8, then drop with the error noted.
        let mut sleeps = vec![];
        let out = push_with_discipline(
            &mut |_| Err::<PostResponse, String>("connect: refused".to_string()),
            &mut |d| sleeps.push(d),
            Duration::from_secs(45),
        );
        assert!(!out.pushed);
        assert_eq!(out.attempts, 5);
        assert_eq!(
            sleeps,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8)
            ]
        );
        assert!(out.note.unwrap().contains("dropped after 5 attempts"));
        // Expired deadline drops without attempting.
        let mut calls = 0u32;
        let out = push_with_discipline(
            &mut |_| {
                calls += 1;
                ok_200("{}")
            },
            noop_sleep,
            Duration::from_secs(0),
        );
        assert!(!out.pushed);
        assert_eq!(calls, 0);
        assert!(out.note.unwrap().contains("deadline"));
    }
}
