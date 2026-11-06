//! SPDX-License-Identifier: GPL-3.0-or-later
//! §5.1 staging protocol: per-tick staging caps, the spill path,
//! carried ticks, and the accumulation-budget cut decision.
//!
//! The coordinator pulls each tick as a record stream (one
//! unrendered record held at a time) and admits records here in
//! arrival order. Records stage in RAM (charged to the window
//! budget) or spill to per-record tmps (streamed through a bounded
//! buffer, never held). The budget decision runs at tick end:
//! carry the tick (chain its bytes + spills into the next window)
//! or cut the window (admit-whole + close).
//!
//! Memory discipline (MEM): every staged byte and every parsed
//! value is charged at materialization against `MEM_CAP` via
//! `account::Meter`; over-cap is unconstructable (staging refuses
//! past the caps — bytes take the spill path instead, which holds
//! only `SPILL_BUF_BYTES`).

use crate::service::account::{
    MAX_RECORD_BYTES, MAX_TICK_BYTES, Meter, RECORD_OVERHEAD, SERVICE_ACCUM_BYTES, SPILL_BUF_BYTES,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One staged (RAM-held) record: the verbatim rendered line plus
/// its parsed value (parsed values are charged separately — DOM
/// costs real memory — and released with the window).
pub struct StagedRecord {
    /// Verbatim rendered bytes WITHOUT the trailing newline.
    pub raw: Vec<u8>,
    /// Parsed envelope (for `crypto_watch[]` re-render + sealed
    /// extraction). `None` when the line is not valid JSON — a
    /// non-JSON line stages verbatim but never parses (honest
    /// bytes, no fabricated envelope).
    pub value: Option<serde_json::Value>,
    /// Admission tick id (the coordinator's tick index).
    pub tick: u64,
}

/// One spilled record: rendered ONCE, streaming, into its tmp.
/// Only the identity + byte count ride RAM.
#[derive(Debug, Clone)]
pub struct SpilledRecord {
    pub tmp: PathBuf,
    pub bytes: u64,
    pub tick: u64,
    /// Spill-time JSON validity (classified at admission from the
    /// in-RAM line — assembly streams valid tmps WITHOUT re-parsing,
    /// R1 finding 2b).
    pub valid: bool,
    /// `Some(segment)` iff the spilled line is a
    /// `process_observation` seal (spill-time classification — the
    /// sealed map reads only flagged tmps, one at a time).
    pub seal_segment: Option<u64>,
    /// SHA-256 over the spilled line (WITHOUT the trailing newline —
    /// the assembly verifier re-hashes the streamed bytes; a
    /// mismatch is post-admission tamper, skipped + counted exactly
    /// like an unparseable spill, never spliced).
    pub content_sha: [u8; 32],
}

/// A tick's staged piece: the records of the tick currently being
/// pulled, before the tick-end budget decision.
pub struct TickPiece {
    pub tick: u64,
    pub staged: Vec<StagedRecord>,
    pub spilled: Vec<SpilledRecord>,
    /// Staged bytes of this tick (RAM only — spill bytes excluded).
    pub staged_bytes: u64,
    /// TOTAL bytes of this tick (staged + spilled — the lone-tick
    /// exceed rule measures the whole tick, §5.1).
    pub total_bytes: u64,
    /// Spill stickiness (§5.1): once the first over-cap record of
    /// this tick spills, every later record of the tick spills.
    spilling: bool,
}

impl TickPiece {
    pub fn open(tick: u64) -> Self {
        Self {
            tick,
            staged: Vec::new(),
            spilled: Vec::new(),
            staged_bytes: 0,
            total_bytes: 0,
            spilling: false,
        }
    }
}

/// The window's staging account: admitted staged records + spill
/// identities + the carry from the previous window.
pub struct Staging {
    /// Admitted staged records in admission order (this window's
    /// own ticks; carried records are prepended at budget time —
    /// see `Carry`).
    pub staged: Vec<StagedRecord>,
    /// Admitted spilled records in admission order.
    pub spilled: Vec<SpilledRecord>,
    /// Admitted STAGED bytes (RAM; spill bytes ride the note).
    pub staged_bytes: u64,
    /// The live meter (charged at materialization, released at
    /// window close).
    pub meter: Meter,
    /// Spill-file registry: tmp path → bytes (for publish assembly
    /// + crash-orphan audit; tmps match `.*.tmp.*`, §4.4 cleanup).
    pub spill_files: HashMap<PathBuf, u64>,
}

impl Default for Staging {
    fn default() -> Self {
        Self::new()
    }
}

impl Staging {
    pub fn new() -> Self {
        Self {
            staged: Vec::new(),
            spilled: Vec::new(),
            staged_bytes: 0,
            meter: Meter::new(),
            spill_files: HashMap::new(),
        }
    }

    /// Open a carried window: the previous window's carried tick
    /// (staged bytes + spills) opens this window's account
    /// (admitted-first accounting — every window consumes at
    /// least its carried tick, so carry chains terminate).
    pub fn with_carry(carry: Carry) -> Self {
        let mut s = Self::new();
        for r in carry.staged {
            s.staged_bytes += r.raw.len() as u64 + RECORD_OVERHEAD;
            s.staged.push(r);
        }
        for r in carry.spilled {
            s.spilled.push(r);
        }
        s
    }

    /// Admit one rendered record line (WITHOUT trailing newline)
    /// into the tick piece: stage in arrival order while the
    /// tick's staged bytes stay within caps, else spill. Returns
    /// the placement. Staging charges RAM at materialization;
    /// spilling streams through the bounded buffer. `spill_write`
    /// performs the spill file write + fsync (the coordinator
    /// supplies a worker-backed sink — spill I/O never runs
    /// coordinator-direct, R1 finding 3; tests pass
    /// `spill_write_direct`).
    pub fn admit_record(
        &mut self,
        piece: &mut TickPiece,
        dir: &Path,
        run_tag: &str,
        line: &[u8],
        tick_seq: u64,
        spill_write: &mut dyn FnMut(&Path, &[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<Placement> {
        let line_cost = line.len() as u64 + RECORD_OVERHEAD;
        let tick_staged_after = piece.staged_bytes + line_cost;
        // Spill stickiness: the first spill latches the tick.
        if piece.spilling {
            return self.spill_record(piece, dir, run_tag, line, tick_seq, spill_write);
        }
        let over_tick_cap = tick_staged_after > MAX_TICK_BYTES;
        let over_record_cap = line.len() as u64 > MAX_RECORD_BYTES;
        // Staging must ALSO fit the window RAM ceiling: staging is
        // ≤ SERVICE_ACCUM_BYTES + MAX_TICK_BYTES EXACTLY (no
        // escape clause — over-cap bytes never enter staging).
        let window_staged_after = self.staged_bytes + tick_staged_after;
        let over_window_cap = window_staged_after > SERVICE_ACCUM_BYTES + MAX_TICK_BYTES;
        if !over_tick_cap && !over_record_cap && !over_window_cap {
            // Stage: charge rendered + parsed-DOM at materialization.
            // A MEM trip spills EXACTLY like an over-cap record
            // (size changes only the placement, never admittance).
            if self.meter.charge_record(line.len() as u64).is_ok() {
                let value = serde_json::from_slice::<serde_json::Value>(line).ok();
                let dom_ok = value.is_none() || self.meter.charge_parsed(line.len() as u64).is_ok();
                if dom_ok {
                    piece.staged_bytes = tick_staged_after;
                    piece.total_bytes += line.len() as u64 + 1;
                    piece.staged.push(StagedRecord {
                        raw: line.to_vec(),
                        value,
                        tick: tick_seq,
                    });
                    return Ok(Placement::Staged);
                }
                self.meter.release_rendered(line.len() as u64, 1);
            }
        }
        // Spill: render ONCE, streaming, through the bounded buffer.
        self.spill_record(piece, dir, run_tag, line, tick_seq, spill_write)
    }

    /// The spill path (shared by the first spill + sticky spills).
    fn spill_record(
        &mut self,
        piece: &mut TickPiece,
        dir: &Path,
        run_tag: &str,
        line: &[u8],
        tick_seq: u64,
        spill_write: &mut dyn FnMut(&Path, &[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<Placement> {
        piece.spilling = true;
        let idx = piece.spilled.len() as u64;
        let tmp_name = format!(".{run_tag}.tmp.spill.{tick_seq}.{idx}");
        let tmp = dir.join(&tmp_name);
        spill_write(&tmp, line)?;
        let bytes = line.len() as u64 + 1;
        self.spill_files.insert(tmp.clone(), bytes);
        piece.total_bytes += bytes;
        // Spill-time classification (O(1) heap — no DOM) + content
        // hash (the assembly verifier re-hashes the streamed bytes).
        let (valid, seal_segment) = spill_classify(line);
        let content_sha = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(line);
            h.finalize().into()
        };
        piece.spilled.push(SpilledRecord {
            tmp,
            bytes,
            tick: tick_seq,
            valid,
            seal_segment,
            content_sha,
        });
        Ok(Placement::Spilled)
    }
}

/// Record placement from `admit_record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Staged,
    Spilled,
}

/// The spill file write proper (create-new + chunked streaming
/// write + fsync): runs on a worker in production (the
/// coordinator's sink calls this inside the op) and direct in
/// unit tests.
pub fn spill_write_direct(tmp: &Path, line: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)?;
    for chunk in line.chunks(SPILL_BUF_BYTES) {
        f.write_all(chunk)?;
    }
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

/// True iff the line's bracket-nesting depth exceeds 127 (the
/// `serde_json::Value` recursion-failure boundary, calibrated:
/// total depth 127 parses, 128 fails — `IgnoredAny`'s iterative
/// ignore path enforces NO limit, so the classifier re-checks it
/// here). String-aware (brackets inside strings + escapes don't
/// count); O(n) time, O(1) space. Only meaningful for
/// syntactically-valid JSON (invalid lines fail elsewhere).
fn json_depth_exceeds_127(line: &[u8]) -> bool {
    let mut depth = 0u32;
    let mut in_string = false;
    let mut escape = false;
    for b in line.iter() {
        if in_string {
            if escape {
                escape = false;
            } else if *b == b'\\' {
                escape = true;
            } else if *b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > 127 {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Spill-time classification (R1 finding 2b): full-JSON validity +
/// seal detection in O(1) heap (no DOM — a hostile 100 MiB spilled
/// line must not transiently triple in RAM at admission). Returns
/// `(valid_json, seal_segment)`. The validity verdict is EXACTLY
/// `from_slice::<Value>`'s (same parser + grammar via `IgnoredAny`,
/// same 127-deep recursion boundary via the pre-scan);
/// seal detection compares the (un)escaped kind + u64 segment.
fn spill_classify(line: &[u8]) -> (bool, Option<u64>) {
    use serde::de::{Deserializer, Error, Visitor};
    if json_depth_exceeds_127(line) {
        return (false, None);
    }
    if serde_json::from_slice::<serde::de::IgnoredAny>(line).is_err() {
        return (false, None);
    }
    #[derive(Default)]
    struct IsObservation(bool);
    struct KindVisitor;
    impl Visitor<'_> for KindVisitor {
        type Value = IsObservation;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a kind string")
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<IsObservation, E> {
            Ok(IsObservation(v == "process_observation"))
        }
        fn visit_string<E: Error>(self, v: String) -> Result<IsObservation, E> {
            Ok(IsObservation(v == "process_observation"))
        }
        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<IsObservation, E> {
            Ok(IsObservation(v == b"process_observation"))
        }
    }
    impl<'de> serde::Deserialize<'de> for IsObservation {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(KindVisitor)
        }
    }
    #[derive(Default)]
    struct MaybeU64(Option<u64>);
    struct U64Visitor;
    impl Visitor<'_> for U64Visitor {
        type Value = MaybeU64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a u64 segment")
        }
        fn visit_u64<E: Error>(self, v: u64) -> Result<MaybeU64, E> {
            Ok(MaybeU64(Some(v)))
        }
        fn visit_i64<E: Error>(self, v: i64) -> Result<MaybeU64, E> {
            Ok(MaybeU64(u64::try_from(v).ok()))
        }
    }
    impl<'de> serde::Deserialize<'de> for MaybeU64 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(U64Visitor)
        }
    }
    #[derive(serde::Deserialize, Default)]
    struct SealHead {
        #[serde(default)]
        kind: IsObservation,
        #[serde(default)]
        segment: MaybeU64,
    }
    match serde_json::from_slice::<SealHead>(line) {
        Ok(h) if h.kind.0 => (true, h.segment.0),
        _ => (true, None),
    }
}

/// A carried tick: the over-budget tick's staged records + spills
/// (window-independent identity — zero renames on carry).
pub struct Carry {
    pub staged: Vec<StagedRecord>,
    pub spilled: Vec<SpilledRecord>,
    /// Staged bytes of the carried tick (charged to the next
    /// window at open).
    pub staged_bytes: u64,
    /// The seq whose budget decision carried them.
    pub from_seq: u64,
}

/// Tick-end budget decision (§5.1, ONE admission rule).
pub enum TickDecision {
    /// The tick fits: its piece joins the window's staging.
    Admit,
    /// The tick is within budget but admitting it would exceed:
    /// close the window at the last fully-admitted tick and carry
    /// this tick into the next window's open.
    Carry,
    /// The lone tick exceeds the budget alone: admit WHOLE
    /// (staged up to caps, spilled beyond) + cut immediately +
    /// `accum_exceeded` note. Never carried, never a ghost window.
    AdmitWholeExceed {
        /// Admitted staged bytes over budget (bounded by
        /// `MAX_TICK_BYTES`).
        bytes_over: u64,
    },
}

impl Staging {
    /// The tick-end budget decision for `piece` (window `seq`).
    /// The piece's records are already placed (staged/spilled);
    /// this decides Admit vs Carry vs AdmitWholeExceed.
    pub fn decide_tick(&self, piece: &TickPiece, seq: u64) -> TickDecision {
        let _ = seq;
        // Lone-tick exceed (frozen precedence): a tick whose TOTAL
        // records (staged + spilled) exceed SERVICE_ACCUM_BYTES
        // alone is ALWAYS admitted whole + cut. The note carries
        // the admitted STAGED bytes over budget (bounded by
        // MAX_TICK_BYTES); spilled bytes ride the spill note.
        if piece.total_bytes > SERVICE_ACCUM_BYTES {
            return TickDecision::AdmitWholeExceed {
                bytes_over: piece.staged_bytes.saturating_sub(SERVICE_ACCUM_BYTES),
            };
        }
        if self.staged_bytes + piece.staged_bytes > SERVICE_ACCUM_BYTES {
            return TickDecision::Carry;
        }
        TickDecision::Admit
    }

    /// Admit the tick piece into the window's staging (decision was
    /// Admit or AdmitWholeExceed).
    pub fn admit_piece(&mut self, piece: TickPiece) {
        self.staged_bytes += piece.staged_bytes;
        self.staged.extend(piece.staged);
        self.spilled.extend(piece.spilled);
    }

    /// Build the carry for the next window (decision was Carry).
    pub fn carry_piece(piece: TickPiece, from_seq: u64) -> Carry {
        Carry {
            staged: piece.staged,
            spilled: piece.spilled,
            staged_bytes: piece.staged_bytes,
            from_seq,
        }
    }

    /// Release all staged charges (window published/sealed — the
    /// RAM frees; spill tmps are consumed separately at publish).
    pub fn release(&mut self) {
        let rendered: u64 = self.staged.iter().map(|r| r.raw.len() as u64).sum();
        let records = self.staged.len() as u64;
        self.meter.release_rendered(rendered, records);
        // Parsed-DOM charges have no itemized release: the DOMs die
        // with the staging vec. Rebuild the meter at the post-window
        // floor (rendered 0 — the carry re-charges at open).
        self.meter = Meter::new();
        self.staged.clear();
        self.spilled.clear();
        self.staged_bytes = 0;
        self.spill_files.clear();
    }
}

/// Assemble the window tmp's `crypto_watch[]` array content in
/// admission order: staged raws inline + spill tmps streamed
/// through the bounded buffer (each spill tmp unlinked after
/// absorption). Returns the assembled JSON array bytes (WITHOUT
/// surrounding envelope) + the spill note + carried counts.
///
/// Only VALID-JSON records assemble (the envelope is JSON —
/// non-JSON staged lines and unparseable spill content are
/// skipped + counted, never spliced: they have no valid envelope
/// representation, and splicing them would corrupt the file).
/// Skips are caller-diagnosed (worker-bounded) — never silent.
///
/// `carried_tick` = the carried tick's id (its valid records count
/// into `carried_records`); `carried_from_seq` = the seq whose
/// budget decision carried them.
///
/// `unlink` absorbs the spill tmps (the publish consume step).
/// Lossless two-phase use (§7.2): assemble with `unlink = false`
/// first (abandonment-safe — tmps intact, retry re-assembles
/// completely), then unlink the consumed list with `unlink = true`
/// (or a dedicated op) once the bytes are coordinator-held — a
/// leak reconciles via retry + §4.4 cleanup, never a loss.
/// Streaming assembly counts (no bytes — the bytes went to the
/// caller's writer).
pub struct AssembledCounts {
    pub spilled_records: u64,
    pub spilled_bytes: u64,
    pub carried_records: u32,
    pub carried_from_seq: Option<u64>,
    pub first_tick: Option<u64>,
    pub last_tick: Option<u64>,
    pub skipped_invalid: u64,
    /// Array-inner bytes written (excludes the wrapping brackets).
    pub inner_len: u64,
}

/// Assemble the `crypto_watch[]` array INNER bytes (`e1,e2,...`)
/// into `out` through BOUNDED buffers (R1 finding 2b): staged raws
/// write through (already in RAM — no second hold); each spill tmp
/// streams in 64 KiB chunks (hash-verified against its spill-time
/// content hash BEFORE splicing — two passes, same observable
/// behavior as the old hold-and-parse: invalid/tampered spills
/// skip + count, valid spills splice verbatim). No record is ever
/// truncated or refused (D-record §5.1); on `Err` the caller MUST
/// discard `out` (partial bytes may have been written — the window
/// tmp is unlinked, never linked).
pub fn assemble_inner_into<W: std::io::Write>(
    staged: &[StagedRecord],
    spilled: &[SpilledRecord],
    carried_tick: Option<u64>,
    carried_from_seq: Option<u64>,
    unlink: bool,
    out: &mut W,
) -> std::io::Result<AssembledCounts> {
    // Admission order = tick order, staged-vs-spilled interleaved
    // by arrival. Staged and spilled vecs each preserve arrival
    // order; merge by (tick, arrival index). Arrival index is
    // positional within the tick — rebuild it: staged records of
    // tick T precede spilled records of tick T (spill starts at the
    // first over-cap record and every LATER record of that tick
    // spills — so within a tick, all staged precede all spilled).
    // (References only — the index holds no record bytes.)
    let mut by_tick: HashMap<u64, (Vec<&[u8]>, Vec<&SpilledRecord>)> = HashMap::new();
    for r in staged {
        // Non-JSON staged lines never splice (counted below).
        if r.value.is_some() {
            by_tick.entry(r.tick).or_default().0.push(&r.raw);
        }
    }
    for r in spilled {
        by_tick.entry(r.tick).or_default().1.push(r);
    }
    let skipped_invalid = staged.iter().filter(|r| r.value.is_none()).count() as u64;
    let mut skipped_spilled_invalid = 0u64;
    let mut ticks: Vec<u64> = by_tick.keys().copied().collect();
    ticks.sort_unstable();
    let mut spilled_records = 0u64;
    let mut spilled_bytes = 0u64;
    let mut carried_records = 0u32;
    let mut inner_len = 0u64;
    let mut first = true;
    // Ticks that contributed ≥1 valid record (the `tick_span` —
    // spans exactly the written array's admission ticks).
    let mut spanned: Vec<u64> = Vec::new();
    for t in ticks.iter().copied() {
        let (staged_here, spilled_here) = &by_tick[&t];
        let mut tick_valid = 0u32;
        for raw in staged_here {
            if !first {
                out.write_all(b",")?;
                inner_len += 1;
            }
            first = false;
            out.write_all(raw)?;
            inner_len += raw.len() as u64;
            tick_valid += 1;
        }
        for s in spilled_here {
            spilled_records += 1;
            spilled_bytes += s.bytes;
            // Verify BEFORE the separator (the comma precedes the
            // element — a skipped spill emits nothing at all).
            if !verify_spill(s, unlink)? {
                skipped_spilled_invalid += 1;
                continue;
            }
            if !first {
                out.write_all(b",")?;
                inner_len += 1;
            }
            first = false;
            inner_len += copy_spill(s, unlink, out)?;
            tick_valid += 1;
        }
        if tick_valid > 0 {
            spanned.push(t);
        }
        if Some(t) == carried_tick {
            carried_records += tick_valid;
        }
    }
    Ok(AssembledCounts {
        spilled_records,
        spilled_bytes,
        carried_records,
        carried_from_seq,
        first_tick: spanned.first().copied(),
        last_tick: spanned.last().copied(),
        skipped_invalid: skipped_invalid + skipped_spilled_invalid,
        inner_len,
    })
}

/// Pass 1 — verify one spill tmp without splicing: the
/// spill-time validity flag gates (invalid ⟹ consumed + skipped,
/// exactly like the old unparseable path); then the tmp streams
/// through the bounded buffer re-hashing its line bytes (trailing
/// newline excluded, same rule as the old strip-one-`\n`). A hash
/// mismatch is post-admission tamper — consumed + skipped + counted
/// (never spliced). Returns true iff the spill may splice.
fn verify_spill(s: &SpilledRecord, unlink: bool) -> std::io::Result<bool> {
    use sha2::Digest as _;
    if !s.valid {
        if unlink {
            std::fs::remove_file(&s.tmp)?;
        }
        return Ok(false);
    }
    let mut f = std::fs::File::open(&s.tmp)?;
    let len = f.metadata()?.len();
    if len == 0 {
        // Truncated-to-empty post-admission: same as unparseable.
        if unlink {
            std::fs::remove_file(&s.tmp)?;
        }
        return Ok(false);
    }
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; SPILL_BUF_BYTES];
    let mut remaining = len - 1;
    use std::io::Read as _;
    while remaining > 0 {
        let want = remaining.min(SPILL_BUF_BYTES as u64) as usize;
        f.read_exact(&mut buf[..want])?;
        h.update(&buf[..want]);
        remaining -= want as u64;
    }
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    if last[0] != b'\n' {
        h.update(last);
    }
    if h.finalize().as_slice() != s.content_sha {
        // Post-admission tamper: consumed, never spliced.
        if unlink {
            std::fs::remove_file(&s.tmp)?;
        }
        return Ok(false);
    }
    Ok(true)
}

/// Pass 2 — copy one VERIFIED spill tmp's line bytes (trailing
/// newline stripped) into `out` through the bounded buffer.
/// Returns the line length written. Unlinks on success when asked
/// (read errors keep the tmp — same as the old read-all path).
fn copy_spill(
    s: &SpilledRecord,
    unlink: bool,
    out: &mut dyn std::io::Write,
) -> std::io::Result<u64> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(&s.tmp)?;
    let len = f.metadata()?.len();
    // Verified non-empty in pass 1 (a concurrent truncation errors
    // out loudly below — never silent).
    let mut buf = vec![0u8; SPILL_BUF_BYTES];
    let mut remaining = len.saturating_sub(1);
    let mut written = 0u64;
    while remaining > 0 {
        let want = remaining.min(SPILL_BUF_BYTES as u64) as usize;
        f.read_exact(&mut buf[..want])?;
        out.write_all(&buf[..want])?;
        written += want as u64;
        remaining -= want as u64;
    }
    if len > 0 {
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        if last[0] != b'\n' {
            out.write_all(&last)?;
            written += 1;
        }
    }
    drop(f);
    if unlink {
        std::fs::remove_file(&s.tmp)?;
    }
    Ok(written)
}

/// Materializing assembly over the streaming core (small-data /
/// test use only — production streams into the window tmp via
/// [`assemble_inner_into`]).
pub fn assemble_crypto_watch(
    staged: &[StagedRecord],
    spilled: &[SpilledRecord],
    carried_tick: Option<u64>,
    carried_from_seq: Option<u64>,
    unlink: bool,
) -> std::io::Result<Assembled> {
    let mut inner = Vec::new();
    let c = assemble_inner_into(
        staged,
        spilled,
        carried_tick,
        carried_from_seq,
        unlink,
        &mut inner,
    )?;
    Ok(Assembled {
        array_inner: inner,
        spilled_records: c.spilled_records,
        spilled_bytes: c.spilled_bytes,
        carried_records: c.carried_records,
        carried_from_seq: c.carried_from_seq,
        first_tick: c.first_tick,
        last_tick: c.last_tick,
        skipped_invalid: c.skipped_invalid,
    })
}

/// Assembled `crypto_watch[]` array inner bytes + notes.
pub struct Assembled {
    /// `e1,e2,...` (the array's inner bytes; the envelope wraps
    /// `[` + inner + `]`).
    pub array_inner: Vec<u8>,
    pub spilled_records: u64,
    pub spilled_bytes: u64,
    pub carried_records: u32,
    pub carried_from_seq: Option<u64>,
    pub first_tick: Option<u64>,
    pub last_tick: Option<u64>,
    /// Valid-JSON skips (staged non-JSON + unparseable spills).
    pub skipped_invalid: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ossl-staging-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn small_tick_stages_and_assembles_verbatim() {
        let dir = scratch("small");
        let mut s = Staging::new();
        let mut piece = TickPiece::open(0);
        let a = br#"{"kind":"start","sequence":0}"#;
        let b = br#"{"kind":"gap","sequence":1}"#;
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", a, 0, &mut spill_write_direct)
                .unwrap(),
            Placement::Staged
        );
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", b, 0, &mut spill_write_direct)
                .unwrap(),
            Placement::Staged
        );
        assert!(matches!(s.decide_tick(&piece, 0), TickDecision::Admit));
        s.admit_piece(piece);
        let asm = assemble_crypto_watch(&s.staged, &s.spilled, None, None, true).unwrap();
        let mut expect = Vec::new();
        expect.extend_from_slice(a);
        expect.push(b',');
        expect.extend_from_slice(b);
        assert_eq!(asm.array_inner, expect);
        assert_eq!(asm.spilled_records, 0);
        assert_eq!((asm.first_tick, asm.last_tick), (Some(0), Some(0)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn over_cap_record_spills_and_streams_back_in_order() {
        let dir = scratch("spill");
        let mut s = Staging::new();
        let mut piece = TickPiece::open(3);
        let small = br#"{"kind":"start"}"#;
        // One record just over the 8 MiB staged-record cap.
        let mut big = vec![b'x'; MAX_RECORD_BYTES as usize + 1];
        big[0] = b'"';
        s.admit_record(&mut piece, &dir, "t", small, 3, &mut spill_write_direct)
            .unwrap();
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", &big, 3, &mut spill_write_direct)
                .unwrap(),
            Placement::Spilled
        );
        // A later record of the same tick spills too (spill sticks).
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", small, 3, &mut spill_write_direct)
                .unwrap(),
            Placement::Spilled
        );
        s.admit_piece(piece);
        assert_eq!(s.staged.len(), 1);
        assert_eq!(s.spilled.len(), 2);
        let asm = assemble_crypto_watch(&s.staged, &s.spilled, Some(3), Some(7), true).unwrap();
        // The big record is invalid JSON (skipped); the small staged
        // + small spilled records are valid (one carried tick).
        assert_eq!(asm.skipped_invalid, 1);
        assert_eq!(asm.carried_records, 2);
        assert_eq!(asm.carried_from_seq, Some(7));
        assert_eq!(asm.spilled_records, 2);
        assert_eq!(
            asm.spilled_bytes,
            big.len() as u64 + 1 + small.len() as u64 + 1
        );
        // Spill tmps are consumed at publish (unlinked).
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spill_classify_matches_value_verdict() {
        // (line, expect_valid, expect_seal)
        let nest = |arrays: usize| {
            format!("{{\"a\":{}}}", "[".repeat(arrays) + &"]".repeat(arrays)).into_bytes()
        };
        // Calibrated boundary: total depth 127 parses, 128 fails
        // (guards serde_json upgrades — the verdict must track
        // `Value` exactly at every depth).
        let mut cases: Vec<(Vec<u8>, bool, Option<u64>)> = (120usize..=135)
            .map(|arrays| {
                let line = nest(arrays);
                let valid = serde_json::from_slice::<serde_json::Value>(&line).is_ok();
                (line, valid, None)
            })
            .collect();
        // Brackets inside strings (and escapes) never count toward
        // depth: 200 brackets in a string + shallow structure parses.
        cases.push((
            format!("{{\"a\":\"{}\"}}", "[".repeat(200)).into_bytes(),
            true,
            None,
        ));
        cases.push((
            format!("{{\"a\":\"\\\"\u{005b}{}\"}}", "]".repeat(200)).into_bytes(),
            true,
            None,
        ));
        let deep = nest(200);
        cases.extend([
            (br#"{"kind":"gap","sequence":1}"#.to_vec(), true, None),
            (
                br#"{"kind":"process_observation","segment":7}"#.to_vec(),
                true,
                Some(7),
            ),
            // Escaped kind still seals (same as the close-path `as_str`).
            (
                br#"{"kind":"process_observatio\u006e","segment":9}"#.to_vec(),
                true,
                Some(9),
            ),
            // Non-u64 / missing segments: valid, not a seal.
            (
                br#"{"kind":"process_observation","segment":"x"}"#.to_vec(),
                true,
                None,
            ),
            (
                br#"{"kind":"process_observation","segment":-1}"#.to_vec(),
                true,
                None,
            ),
            (br#"{"kind":"process_observation"}"#.to_vec(), true, None),
            (br#"{"kind":5,"segment":7}"#.to_vec(), true, None),
            // Any valid JSON stages (objects or not).
            (b"5".to_vec(), true, None),
            (b"[1,2]".to_vec(), true, None),
            (b"\"s\"".to_vec(), true, None),
            // Invalid JSON (verdict identical to `Value`'s).
            (b"".to_vec(), false, None),
            (b"{".to_vec(), false, None),
            (b"{\"a\":}".to_vec(), false, None),
            (b"{\"a\":1} trailing".to_vec(), false, None),
            (deep, false, None),
        ]);
        for (line, expect_valid, expect_seal) in &cases {
            let dom_valid = serde_json::from_slice::<serde_json::Value>(line).is_ok();
            assert_eq!(dom_valid, *expect_valid, "fixture: {line:?}");
            assert_eq!(
                spill_classify(line),
                (*expect_valid, *expect_seal),
                "classify: {line:?}"
            );
        }
    }

    #[test]
    fn tampered_spill_skips_never_splices() {
        let dir = scratch("tamper");
        let mut s = Staging::new();
        let mut piece = TickPiece::open(3);
        // Force a spill with a small MEM trip: over-record-cap line
        // that IS valid JSON (a big quoted string).
        let mut big = vec![b'y'; MAX_RECORD_BYTES as usize + 1];
        big[0] = b'"';
        *big.last_mut().unwrap() = b'"';
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", &big, 3, &mut spill_write_direct)
                .unwrap(),
            Placement::Spilled
        );
        assert!(piece.spilled[0].valid);
        s.admit_piece(piece);
        // Tamper post-admission (flip one content byte).
        let tmp = s.spilled[0].tmp.clone();
        let mut body = std::fs::read(&tmp).unwrap();
        let mid = body.len() / 2;
        body[mid] = body[mid].wrapping_add(1);
        std::fs::write(&tmp, &body).unwrap();
        let asm = assemble_crypto_watch(&s.staged, &s.spilled, None, None, true).unwrap();
        assert_eq!(asm.skipped_invalid, 1, "tamper skips + counts");
        assert_eq!(asm.spilled_records, 1, "admission truth kept");
        assert!(asm.array_inner.is_empty(), "tamper never splices");
        assert!(!tmp.exists(), "tampered tmp consumed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn seal_flag_flows_from_admission() {
        let dir = scratch("sealflag");
        let mut s = Staging::new();
        let mut piece = TickPiece::open(1);
        let mut seal = br#"{"kind":"process_observation","segment":7}"#.to_vec();
        seal.resize(MAX_RECORD_BYTES as usize + 1, b' ');
        // Trailing spaces keep it valid JSON (object + whitespace).
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", &seal, 1, &mut spill_write_direct)
                .unwrap(),
            Placement::Spilled
        );
        assert!(piece.spilled[0].valid);
        assert_eq!(piece.spilled[0].seal_segment, Some(7));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn carry_decision_chains_bytes_into_next_window() {
        let s = Staging::new();
        // Simulate a nearly-full window: charge directly.
        let mut s = s;
        s.staged_bytes = SERVICE_ACCUM_BYTES - 10;
        let mut piece = TickPiece::open(9);
        piece.staged.push(StagedRecord {
            raw: vec![b'j'; 100],
            value: None,
            tick: 9,
        });
        piece.staged_bytes = 100 + RECORD_OVERHEAD;
        piece.total_bytes = 100 + RECORD_OVERHEAD;
        assert!(matches!(s.decide_tick(&piece, 4), TickDecision::Carry));
        let carry = Staging::carry_piece(piece, 4);
        assert_eq!(carry.from_seq, 4);
        assert_eq!(carry.staged_bytes, 100 + RECORD_OVERHEAD);
        let next = Staging::with_carry(carry);
        assert_eq!(next.staged_bytes, 100 + RECORD_OVERHEAD);
        // Small tick against an empty window admits.
        let empty = Staging::new();
        let mut p2 = TickPiece::open(10);
        p2.staged_bytes = 100;
        p2.total_bytes = 100;
        assert!(matches!(empty.decide_tick(&p2, 5), TickDecision::Admit));
    }
}
