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
pub struct SpilledRecord {
    pub tmp: PathBuf,
    pub bytes: u64,
    pub tick: u64,
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
    /// spilling streams through the bounded buffer.
    pub fn admit_record(
        &mut self,
        piece: &mut TickPiece,
        dir: &Path,
        run_tag: &str,
        line: &[u8],
        tick_seq: u64,
    ) -> std::io::Result<Placement> {
        let line_cost = line.len() as u64 + RECORD_OVERHEAD;
        let tick_staged_after = piece.staged_bytes + line_cost;
        // Spill stickiness: the first spill latches the tick.
        if piece.spilling {
            return self.spill_record(piece, dir, run_tag, line, tick_seq);
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
        self.spill_record(piece, dir, run_tag, line, tick_seq)
    }

    /// The spill path (shared by the first spill + sticky spills).
    fn spill_record(
        &mut self,
        piece: &mut TickPiece,
        dir: &Path,
        run_tag: &str,
        line: &[u8],
        tick_seq: u64,
    ) -> std::io::Result<Placement> {
        piece.spilling = true;
        let idx = piece.spilled.len() as u64;
        let tmp_name = format!(".{run_tag}.tmp.spill.{tick_seq}.{idx}");
        let tmp = dir.join(&tmp_name);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            for chunk in line.chunks(SPILL_BUF_BYTES) {
                f.write_all(chunk)?;
            }
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        let bytes = line.len() as u64 + 1;
        self.spill_files.insert(tmp.clone(), bytes);
        piece.total_bytes += bytes;
        piece.spilled.push(SpilledRecord {
            tmp,
            bytes,
            tick: tick_seq,
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
pub fn assemble_crypto_watch(
    staged: &[StagedRecord],
    spilled: &[SpilledRecord],
    carried_tick: Option<u64>,
    carried_from_seq: Option<u64>,
    unlink: bool,
) -> std::io::Result<Assembled> {
    use std::io::Read;
    // Admission order = tick order, staged-vs-spilled interleaved
    // by arrival. Staged and spilled vecs each preserve arrival
    // order; merge by (tick, arrival index). Arrival index is
    // positional within the tick — rebuild it: staged records of
    // tick T precede spilled records of tick T (spill starts at the
    // first over-cap record and every LATER record of that tick
    // spills — so within a tick, all staged precede all spilled).
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
    let mut out = Vec::new();
    let mut spilled_records = 0u64;
    let mut spilled_bytes = 0u64;
    let mut carried_records = 0u32;
    let mut first = true;
    // Ticks that contributed ≥1 valid record (the `tick_span` —
    // spans exactly the written array's admission ticks).
    let mut spanned: Vec<u64> = Vec::new();
    for t in ticks.iter().copied() {
        let (staged_here, spilled_here) = &by_tick[&t];
        let mut tick_valid = 0u32;
        for raw in staged_here {
            if !first {
                out.push(b',');
            }
            first = false;
            out.extend_from_slice(raw);
            tick_valid += 1;
        }
        for s in spilled_here {
            // Stream the spill tmp through the bounded buffer (its
            // trailing newline is stripped — elements join by `,`).
            // Unparseable spill content is consumed (tmp unlinked)
            // but never spliced.
            let mut f = std::fs::File::open(&s.tmp)?;
            let mut buf = vec![0u8; SPILL_BUF_BYTES];
            let mut content: Vec<u8> = Vec::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                content.extend_from_slice(&buf[..n]);
            }
            if content.last() == Some(&b'\n') {
                content.pop();
            }
            let valid = serde_json::from_slice::<serde_json::Value>(&content).is_ok();
            if unlink {
                std::fs::remove_file(&s.tmp)?;
            }
            spilled_records += 1;
            spilled_bytes += s.bytes;
            if !valid {
                skipped_spilled_invalid += 1;
                continue;
            }
            if !first {
                out.push(b',');
            }
            first = false;
            out.extend_from_slice(&content);
            tick_valid += 1;
        }
        if tick_valid > 0 {
            spanned.push(t);
        }
        if Some(t) == carried_tick {
            carried_records += tick_valid;
        }
    }
    Ok(Assembled {
        array_inner: out,
        spilled_records,
        spilled_bytes,
        carried_records,
        carried_from_seq,
        first_tick: spanned.first().copied(),
        last_tick: spanned.last().copied(),
        skipped_invalid: skipped_invalid + skipped_spilled_invalid,
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
            s.admit_record(&mut piece, &dir, "t", a, 0).unwrap(),
            Placement::Staged
        );
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", b, 0).unwrap(),
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
        s.admit_record(&mut piece, &dir, "t", small, 3).unwrap();
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", &big, 3).unwrap(),
            Placement::Spilled
        );
        // A later record of the same tick spills too (spill sticks).
        assert_eq!(
            s.admit_record(&mut piece, &dir, "t", small, 3).unwrap(),
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
