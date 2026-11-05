//! SPDX-License-Identifier: GPL-3.0-or-later
//! Tap states, framing recovery (§5.2), slow-consumer discipline
//! (§5.3), and the bounded tail reader behind rotation/TAP
//! reconciliation (§§6.1/7.2) and L6 resync-completion.
//!
//! Delivery unit: one newline-terminated physical line. A record is
//! delivered iff its bytes occupy exactly one physical line that
//! parses as a `StreamRecord`. Reconcile is UNIFORM content match:
//! a folded record whose exact content appears as a complete tail
//! line counts delivered (strike + `tap_recovered`) — this covers
//! late-P3 landings AND L6 resync completions (a resync `\n`
//! completing a partial line into the full record) with no special
//! case.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

/// Resolved tap identity (fstat-verified, §4.1).
#[derive(Debug, Clone)]
pub struct TapIdentity {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub is_fifo: bool,
}

/// Tap states (§5.3): `pending` (no open fd) / `open`.
pub enum Tap {
    Pending,
    Open(OpenTap),
}

pub struct OpenTap {
    file: File,
    pub ident: TapIdentity,
    /// False after ANY interruption (writer emits ONE resync `\n`
    /// BEFORE its next record, §5.2).
    clean: bool,
    /// Bytes appended through this fd (rotation threshold source).
    pub written: u64,
}

/// Record-write outcome (worker-receipt source, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Record + `\n` landed whole.
    Complete { bytes: u64 },
    /// `written` of `total` bytes landed (whole-record rule: the
    /// FULL record counts undelivered until reconcile proves a
    /// content match — L6).
    Partial { written: u64, total: u64 },
    /// Nothing landed (`errno` on the stderr line).
    Failed { errno: i32 },
}

/// Resolve `--stream PATH` (§6.1): an existing directory PATH
/// resolves to `PATH/stream.jsonl`; any other PATH resolves to
/// itself. The parent must exist pre-start.
pub fn resolve_stream(path: &Path) -> Result<PathBuf, String> {
    if path.is_dir() {
        return Ok(path.join("stream.jsonl"));
    }
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() && !p.is_dir() => {
            Err("service --stream parent directory does not exist".to_string())
        }
        _ => Ok(path.to_path_buf()),
    }
}

/// In-flight tap record (dispatch-known, bounded: at most
/// `MAX_OUTSTANDING_TAP` × `--queue-bytes`, §6.1).
#[derive(Debug, Clone)]
pub struct InflightRecord {
    pub op_id: u64,
    /// Record content WITHOUT the terminating newline.
    pub content: Vec<u8>,
    /// Record kind word (`window-ref` / `drop-marker`).
    pub kind: String,
    pub seq: Option<u64>,
    pub span: Option<(u64, u64)>,
    /// Tap type at dispatch (the reconcile path needs it after the
    /// fd went with the worker — FIFOs reconcile uncertain,
    /// regular files tail-re-read).
    pub fifo: bool,
}

impl InflightRecord {
    pub fn full_bytes(&self) -> u64 {
        self.content.len() as u64 + 1
    }
}

impl Tap {
    pub fn pending() -> Self {
        Tap::Pending
    }

    /// Open the resolved tap (§5.3 type rule on the RESOLVED file).
    /// FIFO with no reader fails ENXIO → caller keeps `pending`.
    /// Regular files open append (+create); the tail byte decides
    /// clean vs needs-resync.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::symlink_metadata(path).ok();
        let is_fifo = meta
            .as_ref()
            .map(|m| m.file_type().is_fifo())
            .unwrap_or(false);
        if let Some(m) = meta {
            let ft = m.file_type();
            if ft.is_dir() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stream tap must be a regular file or FIFO",
                ));
            }
            if ft.is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stream tap must not be a symlink",
                ));
            }
        }
        if is_fifo {
            let file = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?;
            let (dev, ino) = dev_ino(&file)?;
            // FIFO open success means a reader holds it; a fresh
            // open after ANY interruption still resyncs (the writer
            // never resumes mid-record — the abandoned prefix, if
            // any, belongs to a dead writer).
            return Ok(Tap::Open(OpenTap {
                file,
                ident: TapIdentity {
                    path: path.to_path_buf(),
                    dev,
                    ino,
                    is_fifo: true,
                },
                clean: false,
                written: 0,
            }));
        }
        // O_RDWR: the tail-byte check reads; all writes append.
        let mut file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)?;
        let (dev, ino) = dev_ino(&file)?;
        // Tail-byte check: empty or ends-with-`\n` ⟹ clean.
        let clean = tail_is_clean(&mut file)?;
        Ok(Tap::Open(OpenTap {
            file,
            ident: TapIdentity {
                path: path.to_path_buf(),
                dev,
                ino,
                is_fifo: false,
            },
            clean,
            written: 0,
        }))
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Tap::Open(_))
    }
}

fn dev_ino(file: &File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}

fn tail_is_clean(file: &mut File) -> std::io::Result<bool> {
    use std::io::Seek as _;
    let end = file.seek(std::io::SeekFrom::End(0))?;
    if end == 0 {
        return Ok(true);
    }
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut b = [0u8; 1];
    file.read_exact(&mut b)?;
    file.seek(std::io::SeekFrom::End(0))?;
    Ok(b[0] == b'\n')
}

impl OpenTap {
    /// Write one record (content WITHOUT newline) with the §5.2
    /// resync rule. Runs on a tap worker (§7.2); short writes and
    /// errors mark the tap interrupted (regular files stay open;
    /// the caller closes + pendings FIFOs on EPIPE).
    pub fn write_record(&mut self, content: &[u8]) -> WriteOutcome {
        let total = content.len() as u64 + 1;
        if !self.clean {
            // ONE resync `\n` BEFORE the record (never resumed
            // mid-record). On a clean boundary this emits a blank
            // line, which readers skip.
            match self.file.write_all(b"\n") {
                Ok(()) => self.written += 1,
                Err(e) => {
                    return WriteOutcome::Failed {
                        errno: e.raw_os_error().unwrap_or(-1),
                    };
                }
            }
            self.clean = true;
        }
        // Bounded single-record write: each `write` either lands or
        // errors; short writes (pipes, injected faults) surface as
        // partial progress below.
        match self.write_full(content) {
            Ok(()) => {}
            Err((k, e)) => {
                self.clean = false;
                if k == 0 {
                    return WriteOutcome::Failed {
                        errno: e.raw_os_error().unwrap_or(-1),
                    };
                }
                return WriteOutcome::Partial { written: k, total };
            }
        }
        self.clean = true;
        WriteOutcome::Complete { bytes: total }
    }

    fn write_full(&mut self, content: &[u8]) -> Result<(), (u64, std::io::Error)> {
        let mut done = 0u64;
        for chunk in [content, b"\n".as_slice()] {
            let mut off = 0;
            while off < chunk.len() {
                match self.file.write(&chunk[off..]) {
                    Ok(0) => {
                        let e =
                            std::io::Error::new(std::io::ErrorKind::WriteZero, "short tap write");
                        return Err((done, e));
                    }
                    Ok(k) => {
                        off += k;
                        done += k as u64;
                        self.written += k as u64;
                    }
                    Err(e) => return Err((done, e)),
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Bounded tail reader (§§6.1/7.2): the last `max_bytes` of a
/// regular file split into COMPLETE lines (the trailing
/// unterminated prefix is held, never a line). Blank lines are kept
/// (the caller skips them — resync artifacts, never counted).
pub fn read_tail_lines(path: &Path, max_bytes: u64) -> std::io::Result<Vec<Vec<u8>>> {
    use std::io::Seek as _;
    let mut file = File::open(path)?;
    let end = file.seek(std::io::SeekFrom::End(0))?;
    let want = end.min(max_bytes);
    file.seek(std::io::SeekFrom::End(-(want as i64)))?;
    let mut buf = vec![0u8; want as usize];
    file.read_exact(&mut buf)?;
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, b) in buf.iter().enumerate() {
        if *b == b'\n' {
            lines.push(buf[start..i].to_vec());
            start = i + 1;
        }
    }
    // Trailing bytes without `\n` are a held prefix, not a line.
    Ok(lines)
}

/// Uniform reconcile (§7.2 TAP + L6): every in-flight record whose
/// EXACT content appears as a complete tail line counts delivered.
/// Returns the delivered op ids (the caller strikes + `tap_recovered`
/// each exactly once).
pub fn reconcile_tail(lines: &[Vec<u8>], inflight: &[InflightRecord]) -> Vec<u64> {
    let mut delivered = Vec::new();
    for rec in inflight {
        if lines.contains(&rec.content) {
            delivered.push(rec.op_id);
        }
    }
    delivered
}

/// Parse tail lines into delivered `StreamRecord`s (seqs for
/// `rotation_tail` span extension, §6.1). Blank lines skipped;
/// unparseable non-blank lines are abandoned prefixes (counted
/// reader-side, never delivered).
pub fn parse_tail_records(lines: &[Vec<u8>]) -> (Vec<serde_json::Value>, u64) {
    let mut records = Vec::new();
    let mut skipped = 0u64;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<serde_json::Value>(line) {
            Ok(v) => records.push(v),
            Err(_) => skipped += 1,
        }
    }
    (records, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sixb-tap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn resolve_directory_to_stream_jsonl() {
        let d = dir("resolve");
        assert_eq!(resolve_stream(&d).unwrap(), d.join("stream.jsonl"));
        assert_eq!(
            resolve_stream(&d.join("tap.jsonl")).unwrap(),
            d.join("tap.jsonl")
        );
        assert!(resolve_stream(&d.join("nope").join("tap.jsonl")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn resync_after_interruption_never_fuses() {
        let d = dir("resync");
        let path = d.join("tap.jsonl");
        // Simulate an abandoned prefix (no trailing newline).
        std::fs::write(&path, b"{\"schema\":\"ser").unwrap();
        let tap = Tap::open(&path).unwrap();
        let Tap::Open(mut t) = tap else {
            panic!("regular file opens");
        };
        let out = t.write_record(&serde_json::to_vec(&serde_json::json!({"a": 1})).unwrap());
        assert!(matches!(out, WriteOutcome::Complete { .. }));
        drop(t);
        let body = std::fs::read(&path).unwrap();
        // Prefix terminated into its own skippable line; record clean.
        assert_eq!(body, b"{\"schema\":\"ser\n{\"a\":1}\n");
        let lines = read_tail_lines(&path, 1 << 20).unwrap();
        assert_eq!(lines.len(), 2);
        let (records, skipped) = parse_tail_records(&lines);
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clean_open_writes_no_blank_resync() {
        let d = dir("clean");
        let path = d.join("tap.jsonl");
        let Tap::Open(mut t) = Tap::open(&path).unwrap() else {
            panic!("opens");
        };
        let _ = t.write_record(b"{\"a\":1}");
        drop(t);
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l6_resync_completion_counts_delivered() {
        // Short write stopping at newline-minus-one + resync `\n` =
        // the full record as one complete line → content match →
        // delivered (reclassified in the gross equation).
        let d = dir("l6");
        let path = d.join("tap.jsonl");
        let content = b"{\"kind\":\"window-ref\",\"seq\":9}".to_vec();
        // Partial: all but the newline.
        std::fs::write(&path, &content).unwrap();
        // Resync completes the line.
        std::fs::write(&path, [content.clone(), b"\n".to_vec()].concat()).unwrap();
        let lines = read_tail_lines(&path, 1 << 20).unwrap();
        assert_eq!(lines, vec![content.clone()]);
        let inflight = vec![InflightRecord {
            op_id: 7,
            content: content.clone(),
            kind: "window-ref".to_string(),
            seq: Some(9),
            span: None,
            fifo: false,
        }];
        assert_eq!(reconcile_tail(&lines, &inflight), vec![7]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn held_prefix_is_never_a_line() {
        let d = dir("prefix");
        let path = d.join("tap.jsonl");
        std::fs::write(&path, b"{\"a\":1}\n{\"b\":2").unwrap();
        let lines = read_tail_lines(&path, 1 << 20).unwrap();
        assert_eq!(lines, vec![b"{\"a\":1}".to_vec()]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
