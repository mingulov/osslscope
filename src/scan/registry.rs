//! SPDX-License-Identifier: GPL-3.0-or-later
//! Thread birth registry (P7 item 3, subtask E, R18 §5): maps live
//! target tids to u16 births and programs the members-object BIRTH
//! map. Pure supersede logic over `&mut BirthState`, driven
//! explicitly by the harness (no sleeps — deterministic); the
//! daemon 100ms-loop integration is item 5.
//!
//! Rules: a never-seen tid mints birth 0; a tid absent from a poll
//! keeps its birth (dead tids orphan — the map is never deleted);
//! a tid that REAPPEARS after an absence supersedes to birth+1
//! (the entry's SEQ step resets on birth mismatch, so the new
//! incarnation's invocations never reuse the old one's ids); a tid
//! at birth `u16::MAX` freezes (no future admits — the entry
//! skips cause 3 on it). The tid SOURCE is parameterized by the
//! TARGET pid (R18 sol F11 — production attaches to another PID,
//! so an unconditional `/proc/self/task` source would register the
//! wrong threads; the external-child leg pins this).

use std::collections::{HashMap, HashSet};
use std::os::fd::OwnedFd;

/// Frozen birth (64k incarnations exhausted — fail-closed SKIP).
pub const FROZEN: u16 = u16::MAX;

/// Registry state: last-issued birth per observed tid, plus the set
/// of tids present at the last poll (absence→reappearance is the
/// supersede signal).
#[derive(Debug, Default)]
pub struct BirthState {
    births: HashMap<u32, u16>,
    present: HashSet<u32>,
}

impl BirthState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Last-issued birth for a tid, if ever observed.
    pub fn birth_of(&self, tid: u32) -> Option<u16> {
        self.births.get(&tid).copied()
    }

    /// Pure supersede over one observed tid set: returns the
    /// (tid, birth) pairs to program (new tids, superseded
    /// reappearances, and first-seen frozen replays — every
    /// observed tid whose map row must exist or advance). Tids
    /// absent from `tids` keep their rows untouched (orphan, never
    /// deleted); tids at `FROZEN` never advance.
    pub fn poll(&mut self, tids: &[u32]) -> Vec<(u32, u16)> {
        let mut out = Vec::new();
        let mut now = HashSet::new();
        for &tid in tids {
            if !now.insert(tid) {
                continue; // Duplicates program once.
            }
            match self.births.get(&tid).copied() {
                None => {
                    // Never seen: mint birth 0.
                    self.births.insert(tid, 0);
                    out.push((tid, 0));
                }
                Some(b) if b == FROZEN => {
                    // Frozen: replay the row (idempotent — the
                    // entry skips cause 3 on it either way).
                    out.push((tid, b));
                }
                Some(b) if !self.present.contains(&tid) => {
                    // Reappeared after an absence: supersede.
                    let next = b.saturating_add(1);
                    self.births.insert(tid, next);
                    out.push((tid, next));
                }
                Some(_) => {
                    // Still present: row already current.
                }
            }
        }
        self.present = now;
        out
    }
}

/// Thread-id source, parameterized by TARGET pid (R18 sol F11).
pub trait TidSource {
    /// Live tids of the target (contents, not paths — callers never
    /// see raw argv/payloads, only numeric tids).
    fn tids(&self) -> std::io::Result<Vec<u32>>;
}

/// `/proc/<pid>/task` source: the production source for an
/// attached target pid (observed reuse/supersede included).
pub struct ProcTaskSource {
    pid: u32,
}

impl ProcTaskSource {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }
}

impl TidSource for ProcTaskSource {
    fn tids(&self) -> std::io::Result<Vec<u32>> {
        let mut out = Vec::new();
        let dir = std::fs::read_dir(format!("/proc/{}/task", self.pid))?;
        for entry in dir {
            let name = entry?.file_name();
            if let Some(s) = name.to_str() {
                if let Ok(tid) = s.parse::<u32>() {
                    out.push(tid);
                }
            }
        }
        Ok(out)
    }
}

/// Program BIRTH rows into the members object (aya HashMap
/// tid→u16). Insert failure (4k-full) is a HARD error (propagated
/// — the registry cannot register, the leg/daemon fails loud,
/// never silently unregistered).
pub fn program_births(maps: &HashMap<String, OwnedFd>, rows: &[(u32, u16)]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    if rows.is_empty() {
        return Ok(());
    }
    let fd = maps
        .get("BIRTH")
        .context("BIRTH map missing")?
        .try_clone()
        .context("clone BIRTH")?;
    #[cfg(test)]
    birth_boundary_effect(std::os::fd::AsRawFd::as_raw_fd(&fd));
    let data = MapData::from_fd(fd).context("BIRTH mapdata")?;
    let map = Map::from_map_data(data).context("BIRTH map")?;
    let mut births =
        AyaHashMap::<_, u32, u16>::try_from(map).context("BIRTH map shape (u32 -> u16)")?;
    for (tid, birth) in rows {
        births
            .insert(tid, birth, 0)
            .with_context(|| format!("insert BIRTH[{tid}] (map full = hard error)"))?;
    }
    Ok(())
}

pub(crate) fn program_births_preparing(
    maps: &HashMap<String, OwnedFd>,
    rows: &[(u32, u16)],
    setup: Option<&crate::capture_setup::SetupLinks>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::fd::AsFd as _;
    let Some(setup) = setup else {
        return program_births(maps, rows);
    };
    if rows.is_empty() {
        return Ok(());
    }
    let result = (|| {
        let fd = maps.get("BIRTH").context("BIRTH map missing")?;
        #[cfg(test)]
        birth_boundary_effect(std::os::fd::AsRawFd::as_raw_fd(fd));
        let map = crate::loader::BorrowedMap::checked(
            fd.as_fd(),
            setup,
            crate::capture::BoundaryStage::Traversal,
        )?;
        map.shape(&[1], 4, 2)?;
        for (tid, birth) in rows {
            map.update(
                crate::loader::pod_bytes(tid),
                crate::loader::pod_bytes(birth),
            )
            .with_context(|| format!("insert BIRTH[{tid}] (map full = hard error)"))?;
        }
        Ok(())
    })();
    // BIRTH is a hard baseline failure, unlike handled discovery map loss.
    setup.retain_result(result, crate::capture::BoundaryStage::Traversal)
}
#[cfg(test)]
std::thread_local! { static BIRTH_BOUNDARY_TEST: std::cell::RefCell<Option<(u8, std::sync::Arc<crate::capture_setup::NativeTestGate>, crate::capture_setup::SetupLinks)>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
fn birth_boundary_effect(fd: i32) {
    BIRTH_BOUNDARY_TEST.with(|slot| {
        if let Some((mode, gate, links)) = slot.borrow().as_ref() {
            links.test_retained_fd(fd);
            gate.hold();
            assert_ne!(*mode, 2, "actual BIRTH map-info unwind");
        }
    });
}
#[cfg(test)]
pub(crate) fn w079_birth_boundary(
    links: &crate::capture_setup::SetupLinks,
    control: &crate::capture_setup::SetupControl,
    gate: std::sync::Arc<crate::capture_setup::NativeTestGate>,
    mode: u8,
) -> anyhow::Result<()> {
    use crate::capture::BoundaryStage;
    use crate::capture_setup::SetupResource;
    let _slot = links.temporary(control, BoundaryStage::Traversal, 1)?;
    // This is the actual map FD owner; the old helper duplicates this FD into
    // Aya. The controlled helper must instead borrow this guarded owner.
    let maps = SetupResource::guarded(
        HashMap::from([("BIRTH".to_owned(), std::fs::File::open("/dev/null")?.into())]),
        links,
        BoundaryStage::Traversal,
    );
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            BIRTH_BOUNDARY_TEST.with(|s| {
                s.borrow_mut().take();
            });
        }
    }
    BIRTH_BOUNDARY_TEST.with(|s| *s.borrow_mut() = Some((mode, gate, links.clone())));
    let _scope = Scope;
    links.retain_result(
        program_births_preparing(&maps, &[(1, 0)], Some(links)),
        BoundaryStage::Traversal,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_new_tid_mints_zero() {
        let mut s = BirthState::new();
        assert_eq!(s.poll(&[100, 200]), vec![(100, 0), (200, 0)]);
        assert_eq!(s.birth_of(100), Some(0));
        // Still present: no re-program.
        assert!(s.poll(&[100, 200]).is_empty());
    }

    #[test]
    fn unfold_absence_then_reappearance_supersedes() {
        let mut s = BirthState::new();
        assert_eq!(s.poll(&[7]), vec![(7, 0)]);
        // Absent one poll: row untouched (orphan, kept).
        assert!(s.poll(&[8]).iter().all(|(t, _)| *t == 8));
        assert_eq!(s.birth_of(7), Some(0));
        // Reappears: supersede to 1.
        assert_eq!(s.poll(&[7]), vec![(7, 1)]);
        assert_eq!(s.birth_of(7), Some(1));
    }

    #[test]
    fn freeze_at_max_never_advances() {
        let mut s = BirthState::new();
        // Seed MAX-1 as currently present (both maps, as a real
        // poll sequence would leave them).
        s.births.insert(9, FROZEN - 1);
        s.present.insert(9);
        assert!(s.poll(&[9]).is_empty(), "still present: no program");
        // Absent one poll, then reappears: supersede reaches MAX.
        assert!(s.poll(&[10]).iter().all(|(t, _)| *t == 10));
        assert_eq!(s.poll(&[9]), vec![(9, FROZEN)]);
        // Frozen: replays the row, never advances past MAX.
        assert!(s.poll(&[11]).iter().all(|(t, _)| *t == 11));
        assert_eq!(s.poll(&[9]), vec![(9, FROZEN)]);
        assert_eq!(s.birth_of(9), Some(FROZEN));
    }

    #[test]
    fn monotonic_and_duplicate_inputs_program_once() {
        let mut s = BirthState::new();
        // Duplicate tids in one poll program once.
        assert_eq!(s.poll(&[5, 5, 5]), vec![(5, 0)]);
        // Births never decrease across polls.
        let mut last = 0u16;
        for _ in 0..4 {
            s.poll(&[6]);
            let rows = s.poll(&[5]);
            assert_eq!(rows.len(), 1);
            assert!(rows[0].1 >= last);
            last = rows[0].1;
        }
    }

    #[test]
    fn supersede_only_affects_reappearing_tids() {
        let mut s = BirthState::new();
        assert_eq!(s.poll(&[1, 2, 3]).len(), 3);
        // 2 absent one poll; 1 and 3 stay.
        assert!(s.poll(&[1, 3]).is_empty());
        // Only 2 supersedes on return.
        assert_eq!(s.poll(&[1, 2, 3]), vec![(2, 1)]);
        assert_eq!(s.birth_of(1), Some(0));
        assert_eq!(s.birth_of(3), Some(0));
    }

    #[test]
    fn proc_source_lists_self_tasks() {
        // The source enumerates /proc/<pid>/task for the GIVEN pid
        // (self here — the external-child LIVE leg pins the
        // target-pid parameterization against a spawned child).
        let src = ProcTaskSource::new(std::process::id());
        let tids = src.tids().unwrap();
        assert!(!tids.is_empty(), "self has at least one task");
    }

    #[test]
    fn proc_source_missing_pid_errors() {
        // Nonexistent pid fails loud (never an empty silent set —
        // an empty set would orphan every registration).
        let src = ProcTaskSource::new(u32::MAX - 1);
        assert!(src.tids().is_err());
    }
}
