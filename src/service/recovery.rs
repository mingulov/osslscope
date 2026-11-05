//! SPDX-License-Identifier: GPL-3.0-or-later
//! §4.4 startup recovery: the frozen disposition matrix, orphan-tail
//! carriers, close-timestamp triage, and the saturating floor.
//!
//! Inputs are already-read DIR truth (lock, latch check, tmp cleanup,
//! state/summary reads happen in the coordinator per the §4.4 order).
//! MAXGATE legs (five MAX shapes on synthetic DIRs + saturating-floor
//! units) are the `maxgate_*` tests below.

use std::path::Path;

use crate::service::envelope::{
    AbandonedNote, CommitRecovered, CutTail, OrphanCutTail, RunSummary,
};
use crate::service::state::{AbandonReason, Reservation, ReservationState, RunId, SequenceState};

/// Startup refusal (§4.4). The coordinator maps these to exits:
/// `SequenceStateMissing` → 4, the rest → 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Missing or corrupt `sequence.json` with existing windows —
    /// never invent seq 0.
    SequenceStateMissing,
    /// Terminal seal claims a decided MAX the DIR does not hold, or
    /// a reservation verification failed.
    Integrity(String),
    /// No window after MAX is representable.
    Exhausted,
}

/// Recovery disposition for one startup.
#[derive(Debug, Clone)]
pub struct Recovery {
    /// The seq the new run opens (meaningless when `refuse` is set,
    /// except the TERMINAL row which still records its note).
    pub next_seq: u64,
    /// Adoption note (open+present / abandoned+present rows).
    pub commit_recovered: Option<CommitRecovered>,
    /// Gap note for the dead run's attempt (absent rows).
    pub abandoned: Option<AbandonedNote>,
    /// Reconciled reservation for an adopted window (`committed`).
    pub reconciled: Option<Reservation>,
    /// This recovery's orphan-tail carrier (§4.4).
    pub orphan_cut_tail: Option<OrphanCutTail>,
    /// Triaged unmeasured close (≤1 seq, §4.4).
    pub close_unmeasured: Vec<u64>,
    /// Startup refusal (the run must not open any window).
    pub refuse: Option<Refusal>,
}

/// Saturating successor (§4.2: never wraps, never traps).
pub fn sat_succ(v: u64) -> u64 {
    v.saturating_add(1)
}

/// The recovery floor: `next = max(file.next_seq, sat(M+1),
/// sat(dead_attempted+1))` where `M+1` is 0 when `M` is undefined
/// and `dead_attempted` is −1 (no gap) for `null`, clean
/// `committed`, and fresh `open` reservations.
pub fn recovery_floor(file_next: u64, highest: Option<u64>, reserved: Option<&Reservation>) -> u64 {
    let m1 = highest.map(sat_succ).unwrap_or(0);
    let dead1 = match reserved {
        Some(r)
            if (r.state == ReservationState::Open && r.started)
                || r.state == ReservationState::Abandoned =>
        {
            sat_succ(r.seq)
        }
        _ => 0,
    };
    file_next.max(m1).max(dead1)
}

/// Minimal envelope facts recovery needs (parsed tolerantly from
/// one window file; `None` when absent/corrupt — never a block).
#[derive(Debug, Clone)]
pub struct EnvelopeFacts {
    pub seq: u64,
    pub generation: u64,
    pub run_id: RunId,
    pub accum_cut: bool,
    pub effective_start_ns: u64,
    pub effective_end_ns: u64,
    pub requested_end_ns: u64,
}

pub fn read_envelope_facts(dir: &Path, seq: u64) -> Option<EnvelopeFacts> {
    let bytes = std::fs::read(dir.join(crate::service::state::window_name(seq))).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let w = v.get("window")?;
    let run = v.get("run_id")?;
    Some(EnvelopeFacts {
        seq: v.get("seq")?.as_u64()?,
        generation: v.get("generation")?.as_u64()?,
        run_id: RunId {
            pid: run.get("pid")?.as_u64()? as u32,
            starttime: run.get("starttime")?.as_u64()?,
            boot_id: run.get("boot_id")?.as_str()?.to_string(),
        },
        accum_cut: w.get("accum_cut")?.as_bool()?,
        effective_start_ns: w.get("effective_start_ns")?.as_u64()?,
        effective_end_ns: w.get("effective_end_ns")?.as_u64()?,
        requested_end_ns: w.get("requested_end_ns")?.as_u64()?,
    })
}

/// Run the §4.4 disposition matrix.
///
/// `state_missing` = `sequence.json` missing or corrupt (with
/// `highest` telling whether windows exist).
pub fn recover(
    dir: &Path,
    state: Option<&SequenceState>,
    state_missing: bool,
    highest: Option<u64>,
    prev_summary: Option<&RunSummary>,
) -> Recovery {
    // Missing/corrupt state with existing windows REFUSES (exit 4).
    if state_missing && highest.is_some() {
        return Recovery {
            next_seq: 0,
            commit_recovered: None,
            abandoned: None,
            reconciled: None,
            orphan_cut_tail: None,
            close_unmeasured: Vec::new(),
            refuse: Some(Refusal::SequenceStateMissing),
        };
    }
    // Missing state with NO windows = fresh DIR (generation 0).
    let state = match state {
        Some(s) => s.clone(),
        None => SequenceState::fresh(
            RunId {
                pid: 0,
                starttime: 0,
                boot_id: String::new(),
            },
            0,
        ),
    };
    // `exhausted: true` with M != MAX is a fatal integrity refusal.
    if state.exhausted && highest != Some(u64::MAX) {
        return refuse1(
            Recovery::blank(0),
            Refusal::Integrity("exhausted seal without decided MAX".to_string()),
        );
    }
    let floor = recovery_floor(state.next_seq, highest, state.reserved.as_ref());
    let reserved = state.reserved.clone();
    let file_present = |seq: u64| dir.join(crate::service::state::window_name(seq)).is_file();

    // TERMINAL row (OVERRIDES the generic absent rows when N == MAX):
    // gap-worthy (attempted open or any abandoned, fresh or not) and
    // absent → note + REFUSE (resuming at MAX would re-attempt the
    // spent terminal slot).
    if let Some(r) = reserved.clone() {
        let gap_worthy = (r.state == ReservationState::Open && r.started)
            || r.state == ReservationState::Abandoned;
        if r.seq == u64::MAX && gap_worthy && !file_present(u64::MAX) {
            let mut rec = Recovery::blank(floor);
            rec.abandoned = Some(gap_note(dir, &r, prev_summary));
            rec.refuse = Some(Refusal::Exhausted);
            // Triage + orphan carrier still run (notes preserved).
            rec.orphan_cut_tail =
                orphan_carrier(dir, highest, prev_summary, rec.abandoned.as_ref());
            rec.close_unmeasured = triage(&state, highest, dir, prev_summary);
            return rec;
        }
    }
    // Decided MAX (present): no window after it is representable.
    // Adopt bookkeeping first (open+present semantics), then refuse.
    if highest == Some(u64::MAX) {
        let mut rec = Recovery::blank(floor);
        if let Some(r) = reserved.clone() {
            if r.seq == u64::MAX {
                let mut adopted = r.clone();
                adopted.state = ReservationState::Committed;
                adopted.reason = None;
                rec.reconciled = Some(adopted);
                rec.commit_recovered = Some(CommitRecovered { seq: u64::MAX });
            }
        }
        rec.refuse = Some(Refusal::Exhausted);
        rec.orphan_cut_tail = orphan_carrier(dir, highest, prev_summary, None);
        rec.close_unmeasured = triage(&state, highest, dir, prev_summary);
        return rec;
    }

    let mut rec = Recovery::blank(floor);
    match reserved.clone() {
        None => { /* clean start at floor */ }
        Some(r) if r.state == ReservationState::Committed => { /* seal: floor confirms */ }
        Some(r) if r.state == ReservationState::Open && !r.started => {
            if file_present(r.seq) {
                // Impossible in correct operation (publish needs the
                // 1b flip) — adopt like open+present.
                rec.adopt(r.seq, r);
            } else {
                // Fresh: resume AT N (no gap, no note).
                rec.next_seq = r.seq;
            }
        }
        Some(r) if r.state == ReservationState::Open && r.started => {
            if file_present(r.seq) {
                rec.adopt(r.seq, r);
            } else {
                rec.abandoned = Some(gap_note(dir, &r, prev_summary));
                rec.next_seq = sat_succ(r.seq);
            }
        }
        Some(r) => {
            debug_assert_eq!(r.state, ReservationState::Abandoned);
            if file_present(r.seq) {
                // Late-worker link supersedes the note for evidence.
                rec.adopt(r.seq, r);
            } else {
                rec.abandoned = Some(gap_note(dir, &r, prev_summary));
                rec.next_seq = sat_succ(r.seq);
            }
        }
    }
    // The floor governs: never open an existing or spent seq.
    rec.next_seq = rec.next_seq.max(floor);
    rec.orphan_cut_tail = orphan_carrier(dir, highest, prev_summary, rec.abandoned.as_ref());
    rec.close_unmeasured = triage(&state, highest, dir, prev_summary);
    rec
}

impl Recovery {
    fn blank(next_seq: u64) -> Self {
        Self {
            next_seq,
            commit_recovered: None,
            abandoned: None,
            reconciled: None,
            orphan_cut_tail: None,
            close_unmeasured: Vec::new(),
            refuse: None,
        }
    }

    fn adopt(&mut self, seq: u64, r: Reservation) {
        let mut adopted = r;
        adopted.state = ReservationState::Committed;
        adopted.reason = None;
        self.reconciled = Some(adopted);
        self.commit_recovered = Some(CommitRecovered { seq });
        self.next_seq = sat_succ(seq);
    }
}

fn refuse1(mut rec: Recovery, refusal: Refusal) -> Recovery {
    rec.refuse = Some(refusal);
    rec
}

/// Build the gap note for a dead attempt (§4.4 absent rows).
/// Requested bounds come from the PERSISTED reservation, never from
/// memory. `reason` is `dir_fsync_lost` iff the identity-bound dead
/// summary carries `durability_uncertain: { seq: N }`, else the
/// recorded reason (`crash` for open+attempted).
fn gap_note(dir: &Path, r: &Reservation, prev: Option<&RunSummary>) -> AbandonedNote {
    let uncertain = prev
        .filter(|s| summary_speaks_for(s, &r.run_id, r.generation))
        .and_then(|s| s.durability_uncertain.as_ref())
        .is_some_and(|u| u.seq == r.seq);
    let reason = if uncertain {
        AbandonReason::DirFsyncLost
    } else {
        match r.state {
            ReservationState::Abandoned => r.reason.unwrap_or(AbandonReason::Crash),
            _ => AbandonReason::Crash,
        }
    };
    AbandonedNote {
        seq: r.seq,
        run_id: r.run_id.clone(),
        generation: r.generation,
        requested_start_ns: r.requested_start_ns,
        requested_end_ns: r.requested_end_ns,
        reason,
        cut_tail_ns: gap_cut_tail(dir, r.seq, prev),
    }
}

/// `cut_tail_ns`: the previous window's orphaned `accum_cut` tail
/// (read from durable window N−1) when N−1 cut AND no window covered
/// its tail AND the sealing run's identity-bound summary does not
/// already carry it — else null.
///
/// Coverage proof (tiling + W-chaining + no cross-run chaining): the
/// ONLY window that can chain-continue N−1's tail is N itself (same
/// run, `effective_start[N] == effective_end[N−1]`); later runs open
/// from their own acquisition, never from N−1's tail. In a gap row N
/// is absent by premise, so no window covered its tail ⟺ true. The
/// single-carrier rule then keys on the sealing summary consult.
fn gap_cut_tail(dir: &Path, n: u64, prev: Option<&RunSummary>) -> Option<CutTail> {
    let m = n.checked_sub(1)?;
    let facts = read_envelope_facts(dir, m)?;
    if !facts.accum_cut {
        return None;
    }
    // Sealed tails stay single-carried: the sealing run's summary
    // (bound to window M's envelope) already carrying M wins.
    if let Some(s) = prev {
        if summary_speaks_for(s, &facts.run_id, facts.generation) {
            if let Some(o) = s.orphan_cut_tail.as_ref() {
                if o.seq == m {
                    return None;
                }
            }
        }
    }
    Some(CutTail {
        effective_end_ns: facts.effective_end_ns,
        requested_end_ns: facts.requested_end_ns,
    })
}

/// Identity binding (§4.4): a summary speaks only for the run whose
/// `(generation, run_id)` it names. Absence, corruption (caller-side
/// `None`), or mismatch ⟹ the field is absent — never borrowed.
fn summary_speaks_for(s: &RunSummary, run_id: &RunId, generation: u64) -> bool {
    s.generation == generation && s.run_id == *run_id
}

/// The RECOVERING run's orphan carrier (§4.4): emit M's tail iff M
/// cut AND the previous summary does not already carry it for M
/// under the binding key AND this recovery's gap note does not carry
/// it as `cut_tail_ns`. One carrier per tail, never two.
fn orphan_carrier(
    dir: &Path,
    highest: Option<u64>,
    prev: Option<&RunSummary>,
    gap_note: Option<&AbandonedNote>,
) -> Option<OrphanCutTail> {
    let m = highest?;
    let facts = read_envelope_facts(dir, m)?;
    if !facts.accum_cut {
        return None;
    }
    if let Some(s) = prev {
        if summary_speaks_for(s, &facts.run_id, facts.generation) {
            if let Some(o) = s.orphan_cut_tail.as_ref() {
                if o.seq == m {
                    return None;
                }
            }
        }
    }
    // The gap note for M+1 carries it when M+1 gaps.
    if let Some(g) = gap_note {
        if g.seq == m.saturating_add(1) && g.cut_tail_ns.is_some() {
            return None;
        }
    }
    Some(OrphanCutTail {
        seq: m,
        effective_end_ns: facts.effective_end_ns,
        requested_end_ns: facts.requested_end_ns,
    })
}

/// Close-timestamp triage (§4.4): every committed close is either
/// measured or honestly unmeasured. The previous summary is
/// consulted FIRST under the binding key; a non-null
/// `final_close_completed_ns` with `last_seq == W` measures W.
fn triage(
    state: &SequenceState,
    highest: Option<u64>,
    dir: &Path,
    prev: Option<&RunSummary>,
) -> Vec<u64> {
    // Candidate rows: (a) commit landed, 1b seal never ran; (b) state
    // lost its history under existing evidence; (c) seal landed but
    // the summary never did.
    let candidate: Option<(u64, Option<RunId>, u64)> = match &state.reserved {
        Some(r) if r.state == ReservationState::Committed => {
            Some((r.seq, Some(r.run_id.clone()), r.generation))
        }
        _ if state.close_completed_ns.is_none() && state.next_seq > 0 => {
            let expected = state.reserved.as_ref().map(|r| r.run_id.clone());
            let gen_no = state
                .reserved
                .as_ref()
                .map(|r| r.generation)
                .unwrap_or(state.generation);
            Some((state.next_seq - 1, expected, gen_no))
        }
        _ if state.close_completed_ns.is_none() && state.next_seq == 0 && highest.is_some() => {
            let m = highest.unwrap();
            let facts = read_envelope_facts(dir, m);
            match facts {
                Some(f) => Some((m, Some(f.run_id), f.generation)),
                None => Some((m, None, state.generation)),
            }
        }
        _ => None,
    };
    let (w, expected_run, expected_gen) = match candidate {
        Some(c) => c,
        None => return Vec::new(),
    };
    // Summary consult: measured ONLY under the binding key.
    if let (Some(s), Some(run)) = (prev, expected_run.as_ref()) {
        if summary_speaks_for(s, run, expected_gen)
            && s.final_close_completed_ns.is_some()
            && s.last_seq == Some(w)
        {
            return Vec::new();
        }
    }
    vec![w]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::state::{SCHEMA_SEQ, window_name};

    fn run_id(pid: u32) -> RunId {
        RunId {
            pid,
            starttime: 100 + u64::from(pid),
            boot_id: "boot".to_string(),
        }
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sixb-rec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn seq_state(next: u64, reserved: Option<Reservation>) -> SequenceState {
        SequenceState {
            schema: SCHEMA_SEQ.to_string(),
            generation: 0,
            next_seq: next,
            updated_wall_ns: 1,
            close_completed_ns: None,
            exhausted: false,
            run_id: run_id(1),
            reserved,
        }
    }

    fn reserv(seq: u64, state: ReservationState, started: bool) -> Reservation {
        Reservation {
            seq,
            run_id: run_id(1),
            generation: 0,
            requested_start_ns: 10,
            requested_end_ns: 20,
            state,
            reason: None,
            started,
        }
    }

    /// Minimal durable window: envelope facts recovery reads.
    fn write_window(dir: &Path, seq: u64, accum_cut: bool, eff_start: u64, eff_end: u64) {
        let v = serde_json::json!({
            "schema": "service-window-v1", "seq": seq, "generation": 0,
            "run_id": {"pid": 1, "starttime": 101, "boot_id": "boot"},
            "window": {
                "requested_start_ns": 10, "requested_end_ns": 20,
                "effective_start_ns": eff_start, "effective_end_ns": eff_end,
                "signal_cut": false, "accum_cut": accum_cut,
            },
        });
        std::fs::write(dir.join(window_name(seq)), serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn highest(dir: &Path) -> Option<u64> {
        crate::service::state::scan_highest_seq(dir).unwrap()
    }

    #[test]
    fn floor_saturates_never_wraps() {
        assert_eq!(sat_succ(u64::MAX), u64::MAX);
        assert_eq!(sat_succ(7), 8);
        // Dead open MAX floors at MAX (recovered per matrix).
        let r = reserv(u64::MAX, ReservationState::Open, true);
        assert_eq!(recovery_floor(0, None, Some(&r)), u64::MAX);
        // M = MAX floors at MAX.
        assert_eq!(recovery_floor(0, Some(u64::MAX), None), u64::MAX);
        // Fresh reservations name no gap.
        let f = reserv(9, ReservationState::Open, false);
        assert_eq!(recovery_floor(9, Some(8), Some(&f)), 9);
        // Committed seals name no gap.
        let c = reserv(8, ReservationState::Committed, true);
        assert_eq!(recovery_floor(9, Some(8), Some(&c)), 9);
    }

    #[test]
    fn fresh_dir_starts_at_zero() {
        let d = dir("fresh");
        let rec = recover(&d, None, false, None, None);
        assert!(rec.refuse.is_none());
        assert_eq!(rec.next_seq, 0);
        assert!(rec.abandoned.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_state_with_windows_refuses_exit4() {
        let d = dir("missing");
        write_window(&d, 0, false, 10, 20);
        let rec = recover(&d, None, true, highest(&d), None);
        assert_eq!(rec.refuse, Some(Refusal::SequenceStateMissing));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn open_attempted_absent_gaps_with_persisted_bounds() {
        let d = dir("gap");
        write_window(&d, 4, false, 10, 20);
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, true)));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(rec.refuse.is_none());
        assert_eq!(rec.next_seq, 6);
        let g = rec.abandoned.unwrap();
        assert_eq!(g.seq, 5);
        assert_eq!(g.reason, AbandonReason::Crash);
        assert_eq!((g.requested_start_ns, g.requested_end_ns), (10, 20));
        // No identical-note re-emit: floor moved past.
        assert!(rec.commit_recovered.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn open_present_adopts_without_note() {
        let d = dir("adopt");
        write_window(&d, 5, false, 10, 20);
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, true)));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(rec.refuse.is_none());
        assert_eq!(rec.next_seq, 6);
        assert!(rec.abandoned.is_none());
        assert_eq!(rec.commit_recovered.unwrap().seq, 5);
        assert_eq!(rec.reconciled.unwrap().state, ReservationState::Committed);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fresh_reservation_resumes_without_gap() {
        let d = dir("resume");
        write_window(&d, 4, false, 10, 20);
        // Step-5-commit shape: next = 5, reserved 5 fresh.
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, false)));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(rec.refuse.is_none());
        assert_eq!(rec.next_seq, 5);
        assert!(rec.abandoned.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dir_fsync_lost_by_summary_consult() {
        let d = dir("dirsync");
        write_window(&d, 4, false, 10, 20);
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, true)));
        let mut prev = RunSummary::blank(run_id(1), 0, 0);
        prev.durability_uncertain = Some(crate::service::envelope::DurabilityUncertain { seq: 5 });
        let rec = recover(&d, Some(&st), false, highest(&d), Some(&prev));
        assert_eq!(rec.abandoned.unwrap().reason, AbandonReason::DirFsyncLost);
        // Identity mismatch: a stranger's timestamp never speaks.
        let mut alien = RunSummary::blank(run_id(2), 0, 0);
        alien.durability_uncertain = Some(crate::service::envelope::DurabilityUncertain { seq: 5 });
        let rec2 = recover(&d, Some(&st), false, highest(&d), Some(&alien));
        assert_eq!(rec2.abandoned.unwrap().reason, AbandonReason::Crash);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn orphan_tail_single_carrier() {
        let d = dir("orphan");
        // M = 4 cut; the sealing run died without a summary.
        write_window(&d, 4, true, 10, 15);
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, true)));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        // The M+1 gap note carries the tail → no orphan carrier.
        let g = rec.abandoned.as_ref().unwrap();
        assert_eq!(g.seq, 5);
        let tail = g.cut_tail_ns.as_ref().unwrap();
        assert_eq!((tail.effective_end_ns, tail.requested_end_ns), (15, 20));
        assert!(rec.orphan_cut_tail.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn orphan_carrier_when_gap_note_absent() {
        let d = dir("orphan2");
        write_window(&d, 4, true, 10, 15);
        // Clean seal of 4 (no gap note coming): recovery carries it.
        let mut r = reserv(4, ReservationState::Committed, true);
        r.requested_start_ns = 10;
        r.requested_end_ns = 20;
        let st = seq_state(5, Some(r));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(rec.abandoned.is_none());
        let o = rec.orphan_cut_tail.unwrap();
        assert_eq!(o.seq, 4);
        assert_eq!((o.effective_end_ns, o.requested_end_ns), (15, 20));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn triage_measures_sealed_close() {
        let d = dir("triage");
        write_window(&d, 4, false, 10, 20);
        // Commit landed, 1b seal never ran: W = next−1 = 4.
        let st = seq_state(5, Some(reserv(5, ReservationState::Open, false)));
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert_eq!(rec.close_unmeasured, vec![4]);
        // Bound summary with the seal timestamp measures it.
        let mut prev = RunSummary::blank(run_id(1), 0, 0);
        prev.final_close_completed_ns = Some(999);
        prev.last_seq = Some(4);
        let rec2 = recover(&d, Some(&st), false, highest(&d), Some(&prev));
        assert!(rec2.close_unmeasured.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- MAXGATE: the five-shape MAX qual leg on synthetic DIRs ---

    fn max_state(next: u64, r: Option<Reservation>) -> SequenceState {
        SequenceState {
            exhausted: false,
            ..seq_state(next, r)
        }
    }

    #[test]
    fn maxgate_fresh_max_opens() {
        // Shape 1: fresh `started: false` reservation of MAX → open MAX.
        let d = dir("max-fresh");
        let st = max_state(
            u64::MAX,
            Some(reserv(u64::MAX, ReservationState::Open, false)),
        );
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(rec.refuse.is_none());
        assert_eq!(rec.next_seq, u64::MAX);
        assert!(rec.abandoned.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn maxgate_attempted_absent_notes_and_refuses() {
        // Shape 2: attempted-absent MAX → note + "sequence exhausted".
        let d = dir("max-attempted");
        let st = max_state(
            u64::MAX,
            Some(reserv(u64::MAX, ReservationState::Open, true)),
        );
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert_eq!(rec.refuse, Some(Refusal::Exhausted));
        assert_eq!(rec.abandoned.unwrap().seq, u64::MAX);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn maxgate_present_before_commit_adopts_then_refuses() {
        // Shape 3: present-before-commit MAX → adopt, then refuse.
        let d = dir("max-present");
        write_window(&d, u64::MAX, false, 10, 20);
        let st = max_state(
            u64::MAX,
            Some(reserv(u64::MAX, ReservationState::Open, true)),
        );
        let rec = recover(
            &d,
            Some(&st),
            false,
            highest(&d),
            Some(&RunSummary::blank(run_id(9), 0, 0)),
        );
        assert_eq!(rec.refuse, Some(Refusal::Exhausted));
        assert_eq!(rec.commit_recovered.unwrap().seq, u64::MAX);
        assert!(rec.abandoned.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn maxgate_committed_max_refuses() {
        // Shape 4: committed (terminal-sealed) MAX → refuse.
        let d = dir("max-committed");
        write_window(&d, u64::MAX, false, 10, 20);
        let mut st = max_state(
            u64::MAX,
            Some(reserv(u64::MAX, ReservationState::Committed, true)),
        );
        st.exhausted = true;
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert_eq!(rec.refuse, Some(Refusal::Exhausted));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn maxgate_inconsistent_seal_is_integrity_refusal() {
        // Shape 5: `exhausted: true` with M != MAX → integrity refusal.
        let d = dir("max-inconsistent");
        write_window(&d, 4, false, 10, 20);
        let mut st = max_state(5, Some(reserv(5, ReservationState::Open, false)));
        st.exhausted = true;
        let rec = recover(&d, Some(&st), false, highest(&d), None);
        assert!(matches!(rec.refuse, Some(Refusal::Integrity(_))));
        let _ = std::fs::remove_dir_all(&d);
    }
}
