//! SPDX-License-Identifier: GPL-3.0-or-later
//! Item-4 backend (integration commit): the production
//! drain → join → warm → control loop over the members object.
//! Owns the attached links, the [`Oracle`](crate::scan::oracle::Oracle),
//! the tier-2/3 policies, and the userspace map writes (GEN
//! install, T_CACHE warm, SKIP-ALL control).
//!
//! Report/check compose this alongside the harvest discovery
//! session (opt-in per run — see the R19 role decision). The
//! probe legs drive the same API with the real object (proof
//! legs), so the production path is the tested path.
//!
//! Fail-closed rules: unknown ring kinds bail (version skew can
//! only come from a mismatched set — the shape pins exclude it);
//! TRUNC/LOSS reads are checked (a failed map iteration is an
//! error, never a silent partial sum); T_CACHE warms ONLY on
//! fresh-Proven completes (never on partial/stale evidence).

use super::governor::{DutyThrottle, StormAction, StormDetector, ThrottleAction};
use super::registry::BirthState;
use crate::loader::{Loaded, MembersAttached};
use crate::scan::oracle::{
    AbandonReason, Correction, Finding, Oracle, OracleScope, ScanBatch, TrueT, WalkDone,
};
use anyhow::Context as _;
use osslscope_ebpf_common as wire;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Backend attach config (retained for tier-3 re-attach).
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub obj: PathBuf,
    pub exe: CString,
    pub off: u64,
    pub pid: u32,
    pub ctrl: wire::CtrlValue,
    /// Attached member slots (512 = full; fewer = selective).
    pub slots: Vec<u32>,
}

/// Actions the backend took during a poll (capture logs these;
/// the lane asserts them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendAction {
    SkipAllEngaged,
    SkipAllReleased,
    Detached,
    Reattached,
    CacheWarmed { arr: u64, t: u64 },
    CacheUpdated { arr: u64, t: u64 },
    CacheInvalidated { arr: u64 },
}

/// Cache-healing decision for one closed invocation (pure: the
/// oracle names the contradiction, the backend applies it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Healing {
    /// Shrink: the fresh terminator is authoritative — overwrite
    /// the cached T (self-correcting, verdict stays partial).
    Update { t: u64 },
    /// Grow / generation turnover: drop the cached row (cold
    /// re-probe heals).
    Invalidate,
}

/// Map one closed invocation to its healing action, if any. Only
/// partials heal (completes either warm or re-prove the standing
/// entry); mixed-generation evidence heals nothing (untrusted).
pub fn healing_action(w: &WalkDone) -> Option<Healing> {
    if w.arr == 0 {
        return None;
    }
    let crate::scan::oracle::Outcome::Partial { reasons } = &w.outcome else {
        return None;
    };
    if reasons
        .iter()
        .any(|r| matches!(r, crate::scan::oracle::PartialReason::GenMixed))
    {
        return None;
    }
    for r in reasons {
        if let crate::scan::oracle::PartialReason::CacheShrink { observed, .. } = r {
            return Some(Healing::Update { t: *observed });
        }
    }
    for r in reasons {
        if matches!(
            r,
            crate::scan::oracle::PartialReason::CacheStale { .. }
                | crate::scan::oracle::PartialReason::GenStale { .. }
        ) {
            return Some(Healing::Invalidate);
        }
    }
    None
}

/// One poll's outputs (records + actions taken).
#[derive(Debug, Default)]
pub struct PollDelta {
    pub done: Vec<WalkDone>,
    pub findings: Vec<Finding>,
    pub actions: Vec<BackendAction>,
    /// Post-drain verdict corrections (rewrites for already-
    /// drained keys — every downstream holder applies them by
    /// (tid, seq), or the false verdict survives there).
    pub corrections: Vec<Correction>,
    /// Admitted-query census snapshot (CALLS per op, cumulative
    /// since attach): honest observation metadata (reported,
    /// never billed into executions).
    pub admitted: BTreeMap<u32, u64>,
    /// Ops with records in this delta but no census entry while
    /// the census lost increments (map pressure): their counts
    /// are UNKNOWN, never zero (a missing key reads zero only
    /// while [`census_loss`](PollDelta::census_loss) is zero).
    pub admitted_unknown: BTreeSet<u32>,
    /// Cumulative admitted-increment loss (LOSS_MAP_CALLS total
    /// since attach): nonzero means the census snapshot is
    /// incomplete (some admission went uncounted).
    pub census_loss: u64,
}

/// Point-in-time backend state (no record clones — long runs
/// take incrementally via [`ScanBackend::take_completed`]).
#[derive(Debug, Clone)]
pub struct BackendSnapshot {
    pub open: usize,
    pub done_total: u64,
    pub findings_total: u64,
    pub throttled: bool,
    pub detached: bool,
    pub stats: crate::scan::oracle::DrainStats,
}

/// The production traversal backend.
pub struct ScanBackend {
    cfg: BackendConfig,
    loaded: Loaded,
    links: Option<BackendLinks>,
    /// Tier-3 storm cut: member links dropped + SKIP_ALL set; the
    /// entry link stays (the ATTEMPT census stays live, so the
    /// re-attach gate observes the real rate — a full detach
    /// would freeze the census it decides on).
    storm_detached: bool,
    /// Window-edge close in progress (set by [`ScanBackend::finish`]
    /// before its settle poll, never cleared — finish is
    /// terminal): tier actions freeze (no storm observe/detach/
    /// reattach, no throttle age/observe — the gate SKIP_ALL set
    /// at finish entry stays engaged past the close, and the
    /// trailing evidence closes through the backstop instead of
    /// being storm-abandoned). End-state flags report the last
    /// in-window tier state.
    finishing: bool,
    ring: aya::maps::RingBuf<aya::maps::MapData>,
    oracle: Oracle,
    throttle: DutyThrottle,
    storm: StormDetector,
    births: BirthState,
    epoch_start: Instant,
    /// Capture-monotonic ns at attach (production passes its clock
    /// — batch times land in the capture domain, so WALK-DONE
    /// event instants join the evidence document honestly; 0 in
    /// legs = backend-local domain).
    clock_base_ns: u64,
    last_loss: BTreeMap<u32, u64>,
    /// TRUNC consumed mask (per-op sticky bits already
    /// attributed) + last-seen per-op flag-event generation:
    /// the lossless drain baseline — fresh bits report always,
    /// repeats re-report on generation advance, quiet re-drains
    /// report nothing, and nothing is ever cleared.
    trunc_consumed: BTreeMap<u32, u64>,
    trunc_seq: BTreeMap<u32, u64>,
    done_total: u64,
    findings_total: u64,
    /// Selective-attach failures (load/attach stage per slot —
    /// reported, never silent; the oracle scope excludes them).
    failed_slots: Vec<crate::loader::FailedSlot>,
}

/// Owned link fds (never read — the fds ARE the attachment;
/// drop detaches).
#[allow(dead_code)]
struct BackendLinks {
    entry: OwnedFd,
    members: Vec<OwnedFd>,
}

impl ScanBackend {
    /// Attach the members object (full 512 when `slots` is None,
    /// else exactly `slots` with `ctrl.expected == slots.len()`)
    /// and build the oracle scope over the attached set.
    pub fn attach(
        obj: &Path,
        exe: &CString,
        off: u64,
        pid: u32,
        ctrl: &wire::CtrlValue,
        slots: Option<&[u32]>,
        clock_base_ns: u64,
    ) -> anyhow::Result<Self> {
        let bytes = std::fs::read(obj)
            .with_context(|| format!("read {}", obj.display()))
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        Self::attach_bytes(&bytes, obj, exe, off, pid, ctrl, slots, clock_base_ns)
    }

    /// Attach over verified bytes (no path re-read — the caller
    /// hashes these same bytes for provenance, so identity and
    /// loading cannot drift). Selective attaches keep good
    /// members and report failed slots (the oracle scope covers
    /// exactly what attached — failed slots are unobserved
    /// PARTIAL there, never holes).
    #[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
    pub fn attach_bytes(
        bytes: &[u8],
        obj: &Path,
        exe: &CString,
        off: u64,
        pid: u32,
        ctrl: &wire::CtrlValue,
        slots: Option<&[u32]>,
        clock_base_ns: u64,
    ) -> anyhow::Result<Self> {
        // The snapshot was size-bounded at resolution; refuse an
        // over-cap caller buffer anyway (no post-onboarding
        // enlargement bypass — identity and loading share these
        // exact bytes).
        if bytes.len() as u64 > crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES {
            anyhow::bail!(
                "members snapshot {} bytes exceeds the {} cap",
                bytes.len(),
                crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES
            );
        }
        let (attached, attached_slots, failed): (
            MembersAttached,
            BTreeSet<u32>,
            Vec<crate::loader::FailedSlot>,
        ) = match slots {
            None => {
                let a = crate::loader::attach_members_from_bytes(bytes, exe, off, pid, ctrl)?;
                (a, (0..512).collect(), Vec::new())
            }
            Some(s) => {
                let sub =
                    crate::loader::attach_members_subset_from_bytes(bytes, exe, off, pid, ctrl, s)?;
                let set: BTreeSet<u32> = sub.slots.iter().copied().collect();
                (sub.attached, set, sub.failed)
            }
        };
        // Populate the member classifier from the single registry
        // (production attachment classifies exactly like the
        // harvest plane — legs must not hand-populate it).
        populate_alg_class(&attached.loaded.maps)?;
        let scope = OracleScope {
            expected: attached_slots.len() as u32,
            attached: attached_slots.clone(),
            epoch: ctrl.epoch,
            known_t: BTreeMap::new(),
        };
        let ring_fd = attached
            .loaded
            .maps
            .get("EVENTS")
            .context("members EVENTS map")?
            .try_clone()
            .context("clone EVENTS")?;
        let data = aya::maps::MapData::from_fd(ring_fd).context("EVENTS mapdata")?;
        let map = aya::maps::Map::from_map_data(data).context("EVENTS map")?;
        let ring = aya::maps::RingBuf::try_from(map).context("EVENTS ringbuf")?;
        let mut sorted: Vec<u32> = attached_slots.into_iter().collect();
        sorted.sort_unstable();
        Ok(Self {
            cfg: BackendConfig {
                obj: obj.to_path_buf(),
                exe: exe.clone(),
                off,
                pid,
                ctrl: *ctrl,
                slots: sorted,
            },
            loaded: attached.loaded,
            links: Some(BackendLinks {
                entry: attached.entry,
                members: attached.members,
            }),
            storm_detached: false,
            finishing: false,
            ring,
            oracle: Oracle::new(scope),
            throttle: DutyThrottle::new(),
            storm: StormDetector::new(),
            births: BirthState::new(),
            epoch_start: Instant::now(),
            clock_base_ns,
            last_loss: BTreeMap::new(),
            trunc_consumed: BTreeMap::new(),
            trunc_seq: BTreeMap::new(),
            done_total: 0,
            findings_total: 0,
            failed_slots: failed,
        })
    }

    /// Attached object (legs assert retire/loss end-state through
    /// it — the same maps the backend drains; ALG_CLASS arrives
    /// populated from production attach, never hand-filled).
    pub fn loaded(&self) -> &Loaded {
        &self.loaded
    }

    /// Selective-attach failures, if any (empty on full attaches
    /// and clean subsets — failed slots are unobserved PARTIAL in
    /// the oracle scope, and this list names them for the report).
    pub fn failed_slots(&self) -> &[crate::loader::FailedSlot] {
        &self.failed_slots
    }

    /// Register tids through the production registry path
    /// (BIRTH insert failure is a HARD error — the registry
    /// cannot register, so the run fails loud, never silently
    /// unregistered).
    pub fn register(&mut self, tids: &[u32]) -> anyhow::Result<Vec<(u32, u16)>> {
        let rows = self.births.poll(tids);
        super::registry::program_births(&self.loaded.maps, &rows)?;
        Ok(rows)
    }

    /// Abandon every open invocation (window-edge fence: the
    /// baseline poll's opens are pre-window — they are closed
    /// explicitly, never joined to in-window returns).
    pub fn abandon_opens(&mut self, reason: AbandonReason) {
        self.oracle.abandon_all(reason);
    }

    /// Drop completed records + findings without reporting them
    /// (baseline poll: pre-window completions AND fence records
    /// never become in-window evidence — same discipline as the
    /// discovery baseline seed; call AFTER `abandon_opens` so the
    /// fence records land in the same dropped take).
    pub fn drop_completed(&mut self) {
        self.oracle.take_done();
        self.oracle.take_findings();
        self.oracle.take_corrections();
    }

    /// Baseline poll (window-edge fence): drain the setup slice,
    /// fence pre-window opens (a setup-slice CALL can never join
    /// an in-window return), then drop the whole pre-window take.
    /// Completions AND fence records are discarded — the next
    /// poll's take must not see them. Setup-slice storm/throttle
    /// needs no reason (pre-window loss is dropped evidence, not
    /// in-window loss); a storm still in force at close surfaces
    /// through the end-state flags.
    pub fn baseline(&mut self) -> anyhow::Result<()> {
        let _ = self.poll()?;
        self.abandon_opens(AbandonReason::PreWindow);
        self.drop_completed();
        Ok(())
    }

    pub fn snapshot(&self) -> BackendSnapshot {
        BackendSnapshot {
            open: self.oracle.open_count(),
            done_total: self.done_total,
            findings_total: self.findings_total,
            throttled: self.throttle.throttled(),
            detached: self.storm_detached,
            stats: self.oracle.stats(),
        }
    }

    /// Take completed records + findings (incremental drain).
    pub fn take_completed(&mut self) -> (Vec<WalkDone>, Vec<Finding>) {
        (self.oracle.take_done(), self.oracle.take_findings())
    }

    /// Take pending post-drain corrections (salvage path: rewrites
    /// for already-held verdicts — taken alongside records and
    /// findings so failure recovery never strands a false
    /// verdict).
    pub fn take_corrections(&mut self) -> Vec<Correction> {
        self.oracle.take_corrections()
    }

    /// Poll once at `now` (drain → join → tiers → warm).
    /// `quiesced` = no query in flight (retirement/stall inference
    /// is only sound quiesced — legs pass true after joining
    /// workers; capture passes false mid-window... except capture
    /// cannot observe in-flight queries, so capture passes
    /// quiesced=false ALWAYS (opens close on successor takes, the
    /// sound cross-batch rule — quiesced inference is a leg-only
    /// acceleration, never load-bearing for production joins).
    pub fn poll_at(&mut self, now: Instant, quiesced: bool) -> anyhow::Result<PollDelta> {
        let mut delta = PollDelta::default();
        let now_ns = self
            .clock_base_ns
            .saturating_add(now.duration_since(self.epoch_start).as_nanos() as u64);
        // Every poll drains (even storm-detached: the entry still
        // emits skip CALLs, and the ring must not fill with them).
        let batch = self.drain_batch(quiesced, now_ns)?;
        self.oracle.ingest(&batch);
        // Tier-3 (storm owns the gate): ATTEMPT total. The entry
        // link stays attached through a storm cut, so this census
        // remains live while detached. Frozen while finishing
        // (a storm-detach would abandon the trailing evidence
        // the backstop is about to close WITH that evidence; a
        // reattach would reactivate members past the close).
        let attempts = read_attempt_total(&self.loaded.maps)?;
        if !self.finishing {
            match self.storm.observe(now_ns, attempts) {
                Some(StormAction::Detach) if !self.storm_detached => {
                    self.detach()?;
                    self.oracle.abandon_all(AbandonReason::Detached);
                    delta.actions.push(BackendAction::Detached);
                }
                Some(StormAction::Reattach) if self.storm_detached => {
                    self.reattach()?;
                    delta.actions.push(BackendAction::Reattached);
                }
                _ => {}
            }
        }
        // Tier-2 aging runs on EVERY poll (idle polls release an
        // engaged throttle once the trailing cost decays — the
        // storm owns SKIP_ALL while detached, so a storm-time
        // release only flips state, never the map). Frozen while
        // finishing (the gate set at finish entry stays engaged
        // past the close — members must not stay active after
        // counting closed).
        if !self.finishing {
            if let Some(ThrottleAction::ReleaseSkipAll) = self.throttle.age(now_ns) {
                if !self.storm_detached {
                    self.set_skip_all(false)?;
                    delta.actions.push(BackendAction::SkipAllReleased);
                }
            }
        }
        // Tier-2 + cache warms/heals over newly closed invocations.
        // (Corrections take AFTER the fallible cache loop below:
        // a cache write error must not drop rewrites for already-
        // held verdicts — untaken corrections stay in the oracle
        // for the next poll or the salvage take. The census read
        // likewise precedes its takes — see take_after_census.)
        let maps = &self.loaded.maps;
        let oracle = &mut self.oracle;
        let (fresh_admitted, fresh, fresh_findings) = take_after_census(
            || read_calls_by_op(maps),
            || (oracle.take_done(), oracle.take_findings()),
        )?;
        self.done_total += fresh.len() as u64;
        self.findings_total += fresh_findings.len() as u64;
        for w in &fresh {
            // Cost proxy: proven T for completes, joined-ALG
            // count otherwise (walked evidence ≈ paid cost;
            // skipped/tainted/abandoned scale by what fired).
            // While storm-detached the storm owns the gate (skip
            // records charge nothing). Frozen while finishing
            // (trailing closes must not flip the gate).
            if !self.storm_detached && !self.finishing {
                let t_eff = match &w.outcome {
                    crate::scan::oracle::Outcome::Complete { true_t, .. } => *true_t,
                    _ => w.alg_count as u64,
                };
                match self.throttle.observe(now_ns, t_eff) {
                    Some(ThrottleAction::EngageSkipAll) => {
                        self.set_skip_all(true)?;
                        delta.actions.push(BackendAction::SkipAllEngaged);
                    }
                    Some(ThrottleAction::ReleaseSkipAll) => {
                        self.set_skip_all(false)?;
                        delta.actions.push(BackendAction::SkipAllReleased);
                    }
                    None => {}
                }
            }
            // Warm the cache ONLY on fresh-Proven completes: the
            // table's termination is proven AND the cache doesn't
            // already hold it (cached completes re-prove the
            // standing entry — no write needed — and so do cold
            // re-proofs, which prove the same T uncached when the
            // successor fired pre-close). Warming is idempotent:
            // an identical rewrite reports no CacheWarmed (the
            // event means the cache changed). NO_STORE can never
            // warm (it never completes).
            if let crate::scan::oracle::Outcome::Complete {
                true_t,
                cached: false,
            } = &w.outcome
            {
                let proven = matches!(w.true_t, TrueT::Proven(t) if t == *true_t);
                if proven && w.arr != 0 {
                    let incarnation = ensure_gen(&self.loaded.maps, w.arr)?;
                    let standing = self.oracle.warm_belief(w.arr);
                    if standing != Some((*true_t, incarnation)) {
                        write_tcache(&self.loaded.maps, w.arr, *true_t, incarnation)?;
                        self.oracle.note_warm(w.arr, *true_t, incarnation);
                        delta.actions.push(BackendAction::CacheWarmed {
                            arr: w.arr,
                            t: *true_t,
                        });
                    }
                }
            }
            // Heal the cache from the oracle's contradiction
            // reasons (shrink updates, grow/turnover invalidates).
            match healing_action(w) {
                Some(Healing::Update { t }) => {
                    let incarnation = ensure_gen(&self.loaded.maps, w.arr)?;
                    write_tcache(&self.loaded.maps, w.arr, t, incarnation)?;
                    self.oracle.note_warm(w.arr, t, incarnation);
                    delta
                        .actions
                        .push(BackendAction::CacheUpdated { arr: w.arr, t });
                }
                Some(Healing::Invalidate) => {
                    delete_tcache(&self.loaded.maps, w.arr)?;
                    self.oracle.note_invalidate(w.arr);
                    delta
                        .actions
                        .push(BackendAction::CacheInvalidated { arr: w.arr });
                }
                None => {}
            }
        }
        // Corrections take here (after every fallible map write
        // above — a cache error above leaves them in the oracle
        // for the next poll or salvage, never dropped).
        let fresh_corrections: Vec<Correction> = self.oracle.take_corrections();
        // Census honesty: ops observed here but missing from the
        // snapshot are UNKNOWN once increments were lost (never
        // silently zero). The CALLS-loss high-water is current —
        // drain_batch refreshed it before the takes above.
        let calls_loss = self
            .last_loss
            .get(&wire::LOSS_MAP_CALLS)
            .copied()
            .unwrap_or(0);
        delta.admitted_unknown = census_unknown_ops(&fresh, &fresh_admitted, calls_loss);
        delta.census_loss = calls_loss;
        delta.done = fresh;
        delta.findings = fresh_findings;
        delta.corrections = fresh_corrections;
        delta.admitted = fresh_admitted;
        Ok(delta)
    }

    /// Window-edge close: freeze tiers FIRST, quiesce the gate
    /// (the Runner calls finish after counting closes — no new
    /// query may start past the window; SKIP_ALL keeps
    /// post-window hits honest-skipped, never half-observed,
    /// while in-flight scans still retire), then one settle drain
    /// (the trailing records land), then the oracle backstop
    /// closes every remaining open. The gate stays engaged past
    /// the close (frozen tiers: no age-release, no reattach, no
    /// storm-detach abandoning the trailing evidence — members
    /// must not stay active after counting closed); the
    /// end-state flags report the last in-window state.
    pub fn finish(&mut self) -> anyhow::Result<PollDelta> {
        // Freeze tiers FIRST (never cleared — finish is
        // terminal): the settle poll below drains trailing
        // records but takes no tier action (no age-release, no
        // reattach, no storm-detach), so the gate set here stays
        // engaged past the close.
        self.finishing = true;
        if !self.storm_detached {
            self.set_skip_all(true)?;
        }
        let mut delta = self.poll()?;
        let now_ns = self
            .clock_base_ns
            .saturating_add(Instant::now().duration_since(self.epoch_start).as_nanos() as u64);
        self.oracle.finish(now_ns);
        let (done, findings) = self.take_completed();
        self.done_total += done.len() as u64;
        self.findings_total += findings.len() as u64;
        // Backstop closes may observe ops the settle poll never
        // saw — union their unknown-flags into the poll's set
        // (same snapshot the poll read; no drain ran since).
        delta.admitted_unknown.extend(census_unknown_ops(
            &done,
            &delta.admitted,
            delta.census_loss,
        ));
        delta.done.extend(done);
        delta.findings.extend(findings);
        delta.corrections.extend(self.oracle.take_corrections());
        // No second census read: SKIP_ALL froze admits at finish
        // entry (the entry gate precedes the CALLS bump, so no
        // admission lands past it), and the settle poll above
        // already snapshotted that frozen census — a re-read
        // would add only a post-take failure mode stranding the
        // batch it just took. Nothing after the takes above can
        // fail, so the full batch + corrections always survive.
        Ok(delta)
    }

    /// Provider turnover (discovery fenced a generation): in-flight
    /// opens abandon as Churned (their arrays may be freed/reused
    /// by the new provider), and every GEN/T_CACHE row retires
    /// with the oracle beliefs (no cached T survives the epoch —
    /// the next scans re-probe cold).
    pub fn note_provider_turnover(&mut self) -> anyhow::Result<()> {
        self.oracle.abandon_all(AbandonReason::Churned);
        clear_u64_map(&self.loaded.maps, "GEN")?;
        clear_tcache(&self.loaded.maps)?;
        self.oracle.reset_beliefs();
        Ok(())
    }

    /// Poll once at now (quiesced=false — the production rule;
    /// see [`ScanBackend::poll_at`]).
    pub fn poll(&mut self) -> anyhow::Result<PollDelta> {
        let now = Instant::now();
        self.poll_at(now, false)
    }

    fn set_skip_all(&mut self, on: bool) -> anyhow::Result<()> {
        let mut ctrl = crate::loader::read_ctrl(&self.loaded.maps)?;
        ctrl.skip_all = u8::from(on);
        crate::loader::program_ctrl(&self.loaded.maps, &ctrl)?;
        self.cfg.ctrl.skip_all = u8::from(on);
        Ok(())
    }

    /// Tier-3 detach: drop the member links + set SKIP_ALL (the
    /// entry link stays — its ATTEMPT bumps keep the re-attach
    /// census live, and SKIP_ALL keeps new queries honest-skipped
    /// instead of half-observed). The loaded object stays.
    fn detach(&mut self) -> anyhow::Result<()> {
        if let Some(links) = self.links.as_mut() {
            links.members.clear();
        }
        self.storm_detached = true;
        self.set_skip_all(true)
    }

    /// Tier-3 re-attach: re-create the member links from the
    /// retained config (no reload — the object stayed loaded) and
    /// release SKIP_ALL unless tier-2 still holds it.
    fn reattach(&mut self) -> anyhow::Result<()> {
        use anyhow::Context as _;
        let mut members = Vec::with_capacity(self.cfg.slots.len());
        for j in self.cfg.slots.clone() {
            let name = format!("member_{j:03}");
            let prog = self
                .loaded
                .progs
                .get(&name)
                .with_context(|| format!("prog {name} missing"))?;
            members.push(
                ossl_bpf_sys::link_create_uretprobe_multi(
                    prog.as_raw_fd(),
                    &self.cfg.exe,
                    &[self.cfg.off],
                    &[u64::from(j)],
                    self.cfg.pid,
                )
                .with_context(|| format!("re-attach {name}"))?,
            );
        }
        let links = self.links.as_mut().context("entry link retained")?;
        links.members = members;
        self.storm_detached = false;
        if !self.throttle.throttled() {
            self.set_skip_all(false)?;
        }
        Ok(())
    }

    /// Drain the ring + sample cells/counters into one batch.
    /// Counter reads are checked (a failed map iteration errors,
    /// never a silent partial sum); LOSS deltas are computed
    /// against the last poll's totals; TRUNC deltas are
    /// snapshot-minus-consumed (sticky bits never clear, so no
    /// concurrent flag can be erased — every flag lands in
    /// exactly one delta).
    fn drain_batch(&mut self, quiesced: bool, now_ns: u64) -> anyhow::Result<ScanBatch> {
        let mut b = ScanBatch {
            quiesced,
            now_ns,
            ..ScanBatch::default()
        };
        while let Some(item) = self.ring.next() {
            let bytes = item.to_vec();
            decode_ring_record(&bytes, &mut b)?;
        }
        debug_assert!(b.order_sound(), "drain preserves ring order");
        for (tid, v) in read_u64_all(&self.loaded.maps, "RCOUNT")? {
            b.rcount.insert(tid, wire::split_rcount(v));
        }
        for (tid, v) in read_u64_all(&self.loaded.maps, "SEQ")? {
            let (birth, ctr) = wire::split_seq(v);
            b.seq.insert(tid, (birth, ctr));
        }
        for (id, total) in read_percpu_all(&self.loaded.maps, "LOSS", false)? {
            let last = self.last_loss.get(&id).copied().unwrap_or(0);
            if total >= last {
                if total > last {
                    b.loss.insert(id, total - last);
                }
                self.last_loss.insert(id, total);
            }
            // Dips (row eviction + recount) keep the high-water
            // baseline — same discipline as the harvest core.
        }
        // TRUNC is sticky bits (OR-fold) plus the per-op
        // flag-event generation: fresh bits report, repeats
        // re-report on generation advance, quiet re-drains
        // report nothing — and nothing is ever cleared, so no
        // concurrent flag can be erased in any producer order.
        b.trunc = drain_trunc_flags(
            &mut self.trunc_consumed,
            &mut self.trunc_seq,
            &self.loaded.maps,
            None,
        )?;
        Ok(b)
    }
}

/// Decode one ring record into the batch (fail-closed: short
/// items, unknown kinds, and bad payloads bail — a mismatched
/// set is the only source, and the shape pins exclude it).
fn decode_ring_record(bytes: &[u8], b: &mut ScanBatch) -> anyhow::Result<()> {
    if bytes.len() < 4 {
        anyhow::bail!("short ring item: {} bytes", bytes.len());
    }
    let kind = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    match kind {
        wire::KIND_SCAN_CALL => {
            let e = wire::parse_scan_call_event(bytes)
                .map_err(|e| anyhow::anyhow!("parse scan CALL: {e:?}"))?;
            b.push_call(e);
        }
        wire::KIND_SCAN_RET => {
            let e = wire::parse_scan_ret_event(bytes)
                .map_err(|e| anyhow::anyhow!("parse scan RET: {e:?}"))?;
            b.push_ret(e);
        }
        wire::KIND_GUARD => {
            let e = wire::parse_guard_event(bytes)
                .map_err(|e| anyhow::anyhow!("parse GUARD: {e:?}"))?;
            b.push_guard(e);
        }
        wire::KIND_SCAN_ALG => {
            let e = wire::parse_scan_alg_event(bytes)
                .map_err(|e| anyhow::anyhow!("parse scan ALG: {e:?}"))?;
            b.push_alg(e);
        }
        wire::KIND_SCAN_ROW => {
            let e = wire::parse_scan_row_event(bytes)
                .map_err(|e| anyhow::anyhow!("parse scan ROW: {e:?}"))?;
            b.push_row(e);
        }
        k => anyhow::bail!("unexpected ring kind {k} (members emits 7/8/9/10/11 only)"),
    }
    Ok(())
}

/// Read every row of a u32→u64 hash (RCOUNT/SEQ): checked
/// iteration (any failed row errors the poll).
fn read_u64_all(
    maps: &std::collections::HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<Vec<(u32, u64)>> {
    use anyhow::Context as _;
    let fd = maps
        .get(name)
        .with_context(|| format!("map {name} missing"))?
        .try_clone()
        .with_context(|| format!("clone {name}"))?;
    let data = aya::maps::MapData::from_fd(fd).with_context(|| format!("{name} mapdata"))?;
    let map = aya::maps::Map::from_map_data(data).with_context(|| format!("{name} map"))?;
    let m = aya::maps::HashMap::<_, u32, u64>::try_from(map)
        .with_context(|| format!("{name} hash shape"))?;
    let mut out = Vec::new();
    for r in m.iter() {
        let (k, v) = r.with_context(|| format!("{name} iter"))?;
        out.push((k, v));
    }
    Ok(out)
}

/// Fold every row of a u32→u64 percpu hash (LOSS sums, TRUNC
/// ORs): checked iteration (any failed row errors the poll).
fn read_percpu_all(
    maps: &std::collections::HashMap<String, OwnedFd>,
    name: &str,
    or: bool,
) -> anyhow::Result<Vec<(u32, u64)>> {
    use anyhow::Context as _;
    let fd = maps
        .get(name)
        .with_context(|| format!("map {name} missing"))?
        .try_clone()
        .with_context(|| format!("clone {name}"))?;
    let data = aya::maps::MapData::from_fd(fd).with_context(|| format!("{name} mapdata"))?;
    let map = aya::maps::Map::from_map_data(data).with_context(|| format!("{name} map"))?;
    let m = aya::maps::PerCpuHashMap::<_, u32, u64>::try_from(map)
        .with_context(|| format!("{name} percpu shape"))?;
    let mut out = Vec::new();
    for r in m.iter() {
        let (k, slots) = r.with_context(|| format!("{name} iter"))?;
        let fold = slots
            .iter()
            .fold(0u64, |a, &x| if or { a | x } else { a.wrapping_add(x) });
        out.push((k, fold));
    }
    Ok(out)
}

/// ATTEMPT total (percpu array, single key 0).
fn read_attempt_total(maps: &std::collections::HashMap<String, OwnedFd>) -> anyhow::Result<u64> {
    use anyhow::Context as _;
    let fd = maps
        .get("ATTEMPT")
        .context("map ATTEMPT missing")?
        .try_clone()
        .context("clone ATTEMPT")?;
    let data = aya::maps::MapData::from_fd(fd).context("ATTEMPT mapdata")?;
    let map = aya::maps::Map::from_map_data(data).context("ATTEMPT map")?;
    let m = aya::maps::PerCpuArray::<_, u64>::try_from(map).context("ATTEMPT percpu shape")?;
    let slots = m.get(&0, 0).context("ATTEMPT[0]")?;
    Ok(slots.iter().fold(0u64, |a, &x| a.wrapping_add(x)))
}

/// Pure accumulate core (host-testable): per op, fresh bits
/// (snapshot minus consumed) report always (first sightings
/// never need the generation — a flag visible before its
/// generation bump still reports); when the op's generation
/// advanced since the last drain, the op's full set bits
/// re-report (a repeat fault re-flagged an already-set bit —
/// recurring faults stay visible instead of hiding under their
/// sticky bit, which would fail open on flag-only evidence).
/// Consumed and last-seen generation advance to the snapshots.
/// Nothing is ever cleared, so no interleaving in either
/// producer order can erase a flag (a flag past our snapshot
/// lands next drain via stickiness and/or the generation
/// advance — delayed, never lost, never tainted).
fn accumulate_trunc(
    consumed: &mut BTreeMap<u32, u64>,
    last_seq: &mut BTreeMap<u32, u64>,
    snap: BTreeMap<u32, u64>,
    seq: BTreeMap<u32, u64>,
) -> BTreeMap<u32, u64> {
    let mut delta: BTreeMap<u32, u64> = BTreeMap::new();
    for (op, bits) in snap.iter() {
        let fresh = bits & !consumed.get(op).copied().unwrap_or(0);
        let advanced = seq.get(op).copied().unwrap_or(0) != last_seq.get(op).copied().unwrap_or(0);
        if fresh != 0 || (advanced && *bits != 0) {
            delta.insert(*op, if advanced { *bits } else { fresh });
        }
    }
    for (op, bits) in snap {
        *consumed.entry(op).or_insert(0) |= bits;
    }
    for (op, s) in seq {
        last_seq.insert(op, s);
    }
    delta
}

/// Admitted-query census snapshot (CALLS per op, summed across
/// CPUs — cumulative since attach). Honest observation metadata
/// (reported, never billed into executions). A missing key reads
/// zero ONLY while the census never lost an increment (see
/// [`census_unknown_ops`]); past CALLS map pressure the count
/// for an observed-but-missing op is UNKNOWN, never zero.
fn read_calls_by_op(
    maps: &std::collections::HashMap<String, OwnedFd>,
) -> anyhow::Result<BTreeMap<u32, u64>> {
    Ok(read_percpu_all(maps, "CALLS", false)?
        .into_iter()
        .filter(|(_, v)| *v != 0)
        .collect())
}

/// Ordered-take outputs: census snapshot + records + findings.
type CensusTake = (BTreeMap<u32, u64>, Vec<WalkDone>, Vec<Finding>);

/// Ordered take: the fallible census read runs BEFORE any
/// oracle take, so a read failure leaves every record and
/// finding in the oracle for the next poll or the salvage take
/// (taking first would strand them in a dropped delta while
/// salvage finds nothing). The closures keep this host-testable
/// with a real oracle: production passes the map read and the
/// oracle takes.
fn take_after_census(
    read_census: impl FnOnce() -> anyhow::Result<BTreeMap<u32, u64>>,
    take: impl FnOnce() -> (Vec<WalkDone>, Vec<Finding>),
) -> anyhow::Result<CensusTake> {
    let census = read_census()?;
    let (done, findings) = take();
    Ok((census, done, findings))
}

/// Ops with records in `done` but no census entry (pure,
/// host-testable): present CALLS keys are exact (plain-hash
/// keys never evict), so a missing key is zero only while
/// `census_loss` is zero — once increments were lost, an
/// observed-but-missing op is UNKNOWN. Skipped-only ops never
/// flag (skips are never admitted, so their absence is a true
/// zero), and UNKNOWN_OP never flags (taint-forced, not a real
/// op — its admission is unattributable by design).
fn census_unknown_ops(
    done: &[WalkDone],
    admitted: &BTreeMap<u32, u64>,
    census_loss: u64,
) -> BTreeSet<u32> {
    if census_loss == 0 {
        return BTreeSet::new();
    }
    done.iter()
        .filter(|w| {
            w.op != crate::scan::oracle::UNKNOWN_OP
                && !matches!(w.outcome, crate::scan::oracle::Outcome::Skipped { .. })
                && !admitted.contains_key(&w.op)
        })
        .map(|w| w.op)
        .collect()
}

/// Lossless TRUNC drain: sticky per-op flag bits plus the
/// per-op flag-event generation, never cleared. First sightings
/// report via freshness; repeats re-report via the generation
/// advance (no taint — re-faults are real faults, not races).
///
/// `hook` runs AFTER the snapshots: production passes `None`;
/// the live control injects a flag there (a flag landing just
/// after our read) to prove it appears in the NEXT drain —
/// deterministic stickiness, no timing dependence.
pub fn drain_trunc_flags(
    consumed: &mut BTreeMap<u32, u64>,
    last_seq: &mut BTreeMap<u32, u64>,
    maps: &std::collections::HashMap<String, OwnedFd>,
    hook: Option<&dyn Fn()>,
) -> anyhow::Result<BTreeMap<u32, u64>> {
    let snap: BTreeMap<u32, u64> = read_percpu_all(maps, "TRUNC", true)?.into_iter().collect();
    // Per-op generation, summed across CPUs (single-writer
    // slots — the sum is the exact event count, rollback-free).
    let seq: BTreeMap<u32, u64> = read_percpu_all(maps, "TRUNC_SEQ", false)?
        .into_iter()
        .collect();
    if let Some(h) = hook {
        h();
    }
    Ok(accumulate_trunc(consumed, last_seq, snap, seq))
}

/// Single u64-cell lookup (GEN): None on ENOENT, error otherwise.
fn lookup_u64(
    maps: &std::collections::HashMap<String, OwnedFd>,
    name: &str,
    key: u64,
) -> anyhow::Result<Option<u64>> {
    use anyhow::Context as _;
    let fd = maps
        .get(name)
        .with_context(|| format!("map {name} missing"))?
        .as_raw_fd();
    let mut val = [0u8; 8];
    match unsafe { ossl_bpf_sys::map_lookup_elem(fd, &key.to_le_bytes(), &mut val) } {
        Ok(()) => Ok(Some(u64::from_le_bytes(val))),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        // No key in the diagnostic: GEN keys are array addresses
        // (allowlist §2 — never printed, M3 precedent).
        Err(e) => Err(anyhow::anyhow!("lookup {name} failed: {e}")),
    }
}

/// Install GEN[arr] = 1 when absent (array epoch born); returns
/// the current incarnation.
fn ensure_gen(maps: &std::collections::HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<u64> {
    if let Some(g) = lookup_u64(maps, "GEN", arr)? {
        return Ok(g);
    }
    let fd = maps.get("GEN").context("map GEN missing")?.as_raw_fd();
    let key = arr.to_le_bytes();
    let val = 1u64.to_le_bytes();
    unsafe { ossl_bpf_sys::map_update_elem(fd, &key, &val, 0u64) }.context("GEN install")?;
    Ok(1)
}

/// Warm T_CACHE[arr] = (t, gen) (single-userspace-writer: this
/// backend owns the triplet's cache row).
fn write_tcache(
    maps: &std::collections::HashMap<String, OwnedFd>,
    arr: u64,
    t: u64,
    generation: u64,
) -> anyhow::Result<()> {
    let fd = maps
        .get("T_CACHE")
        .context("map T_CACHE missing")?
        .as_raw_fd();
    let key = arr.to_le_bytes();
    let mut val = [0u8; 16];
    val[0..8].copy_from_slice(&t.to_le_bytes());
    val[8..16].copy_from_slice(&generation.to_le_bytes());
    unsafe { ossl_bpf_sys::map_update_elem(fd, &key, &val, 0u64) }.context("T_CACHE warm")
}

/// Populate the member object's `ALG_CLASS` from the single
/// registry (same entries the harvest plane classifies with —
/// production attachment classifies identically; legs must not
/// hand-populate it). Members carry no TRIP_CLASS (scan-plane
/// only), so only the ALG arm applies.
fn populate_alg_class(maps: &std::collections::HashMap<String, OwnedFd>) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let fd = maps
        .get("ALG_CLASS")
        .context("members ALG_CLASS map missing")?;
    for (h, v) in crate::discovery::harvest::build_alg_entries()? {
        // SAFETY: lengths are exact per MEMBER_MAPS — ALG_CLASS is
        // key 8 / value 42 (same encoder as the harvest plane);
        // plain HASH map, fd live from `load()`.
        unsafe {
            ossl_bpf_sys::map_update_elem(
                fd.as_raw_fd(),
                &h.to_le_bytes(),
                &wire::alg_value_bytes(&v),
                0,
            )
        }
        .context("populate members ALG_CLASS")?;
    }
    Ok(())
}

/// Drop T_CACHE[arr] (cache healing: grown tables and generation
/// turnover invalidate — absent is cold, never an error).
fn delete_tcache(
    maps: &std::collections::HashMap<String, OwnedFd>,
    arr: u64,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let fd = maps
        .get("T_CACHE")
        .context("map T_CACHE missing")?
        .try_clone()
        .context("clone T_CACHE")?;
    let data = aya::maps::MapData::from_fd(fd).context("T_CACHE mapdata")?;
    let map = aya::maps::Map::from_map_data(data).context("T_CACHE map")?;
    let mut m = aya::maps::HashMap::<_, u64, [u8; 16]>::try_from(map)
        .context("T_CACHE hash shape (u64 -> [u8; 16])")?;
    match m.remove(&arr) {
        Ok(()) => Ok(()),
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.raw_os_error() == Some(libc::ENOENT) =>
        {
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("T_CACHE delete: {e}")),
    }
}

/// Delete every row of a u64-keyed plain hash (provider turnover
/// retires the whole epoch — GEN rows and beliefs together).
fn clear_u64_map(
    maps: &std::collections::HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let fd = maps
        .get(name)
        .with_context(|| format!("map {name} missing"))?
        .try_clone()
        .with_context(|| format!("clone {name}"))?;
    let data = aya::maps::MapData::from_fd(fd).with_context(|| format!("{name} mapdata"))?;
    let map = aya::maps::Map::from_map_data(data).with_context(|| format!("{name} map"))?;
    let mut m = aya::maps::HashMap::<_, u64, u64>::try_from(map)
        .with_context(|| format!("{name} hash shape (u64 -> u64)"))?;
    let mut keys = Vec::new();
    for r in m.iter() {
        let (k, _) = r.with_context(|| format!("{name} iter"))?;
        keys.push(k);
    }
    for k in keys {
        m.remove(&k)
            .with_context(|| format!("{name} delete (turnover retire)"))?;
    }
    Ok(())
}

/// Delete every T_CACHE row (provider turnover retires the whole
/// cache epoch with the oracle beliefs).
fn clear_tcache(maps: &std::collections::HashMap<String, OwnedFd>) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let fd = maps
        .get("T_CACHE")
        .context("map T_CACHE missing")?
        .try_clone()
        .context("clone T_CACHE")?;
    let data = aya::maps::MapData::from_fd(fd).context("T_CACHE mapdata")?;
    let map = aya::maps::Map::from_map_data(data).context("T_CACHE map")?;
    let mut m = aya::maps::HashMap::<_, u64, [u8; 16]>::try_from(map)
        .context("T_CACHE hash shape (u64 -> [u8; 16])")?;
    let mut keys = Vec::new();
    for r in m.iter() {
        let (k, _) = r.context("T_CACHE iter")?;
        keys.push(k);
    }
    for k in keys {
        m.remove(&k).context("T_CACHE delete (turnover retire)")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_bytes() -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0..4].copy_from_slice(&wire::KIND_SCAN_CALL.to_le_bytes());
        b[4..8].copy_from_slice(&7u32.to_le_bytes());
        b[8..12].copy_from_slice(&4242u32.to_le_bytes());
        b[12..16].copy_from_slice(&wire::make_call_flags(false, wire::SKIP_ADMITTED).to_le_bytes());
        b[16..24].copy_from_slice(&0u64.to_le_bytes());
        b
    }

    #[test]
    fn decode_call_ok() {
        let mut b = ScanBatch::default();
        decode_ring_record(&call_bytes(), &mut b).unwrap();
        assert_eq!(b.calls.len(), 1);
        assert_eq!(b.calls[0].tid, 4242);
    }

    #[test]
    fn decode_short_bails() {
        let mut b = ScanBatch::default();
        assert!(decode_ring_record(&[7u8, 0, 0], &mut b).is_err());
    }

    #[test]
    fn fix3_accumulate_trunc_lossless_with_repeats() {
        use std::collections::BTreeMap;
        // No-clear accumulate + per-op generation: fresh bits
        // report (first sighting, seq-independent); a quiet
        // re-drain (same bits, same generation) reports nothing;
        // a REPEAT fault (same bits, generation advanced)
        // re-reports the op's set bits (recurring faults stay
        // visible — hiding them would fail open on flag-only
        // evidence). Nothing is ever cleared, so no interleaving
        // in either producer order can erase a flag (a flag past
        // our snapshot lands next drain via stickiness and/or the
        // generation advance — delayed, never lost).
        let mut consumed: BTreeMap<u32, u64> = BTreeMap::new();
        let mut last_seq: BTreeMap<u32, u64> = BTreeMap::new();
        let snap = |pairs: &[(u32, u64)]| -> BTreeMap<u32, u64> { pairs.iter().copied().collect() };
        // First sighting reports (generation observed).
        let d1 = accumulate_trunc(
            &mut consumed,
            &mut last_seq,
            snap(&[(1, 0b011)]),
            snap(&[(1, 2)]),
        );
        assert_eq!(d1.get(&1), Some(&0b011));
        // Identical re-snapshot, same generation: nothing.
        let d2 = accumulate_trunc(
            &mut consumed,
            &mut last_seq,
            snap(&[(1, 0b011)]),
            snap(&[(1, 2)]),
        );
        assert!(d2.is_empty(), "quiet re-drain reports nothing");
        // New bits report (generation advances with them).
        let d3 = accumulate_trunc(
            &mut consumed,
            &mut last_seq,
            snap(&[(1, 0b111), (2, 0b001)]),
            snap(&[(1, 3), (2, 1)]),
        );
        assert_eq!(
            d3.get(&1),
            Some(&0b111),
            "advanced op re-reports its set bits"
        );
        assert_eq!(d3.get(&2), Some(&0b001), "new op reports");
        // Repeat fault, same bits, generation advanced:
        // re-reports (never hidden).
        let d4 = accumulate_trunc(
            &mut consumed,
            &mut last_seq,
            snap(&[(1, 0b111), (2, 0b001)]),
            snap(&[(1, 5), (2, 1)]),
        );
        assert_eq!(d4.get(&1), Some(&0b111), "repeat fault re-reports");
        assert!(!d4.contains_key(&2), "quiet op stays quiet");
        // A flag landing after our snapshot is present (sticky)
        // next drain — first sighting then, regardless of seq.
        let d5 = accumulate_trunc(
            &mut consumed,
            &mut last_seq,
            snap(&[(1, 0b111), (2, 0b011)]),
            snap(&[(1, 5), (2, 1)]),
        );
        assert_eq!(d5.get(&2), Some(&0b010), "new bit reports via freshness");
    }

    #[test]
    fn fix5_census_unknown_ops_under_map_pressure() {
        use crate::scan::oracle::{Outcome, TrueT, UNKNOWN_OP};
        use std::collections::{BTreeMap, BTreeSet};
        let walk = |op: u32, outcome: Outcome| WalkDone {
            tid: 1,
            seq: 1,
            op,
            arr: 0,
            outcome,
            true_t: TrueT::Proven(1),
            alg_count: 0,
            row_count: 0,
            guard: None,
            algs: Vec::new(),
            event_ns: 0,
            rows: Vec::new(),
        };
        let complete = || Outcome::Complete {
            true_t: 1,
            cached: false,
        };
        // No loss: a missing key is a true zero (never unknown).
        assert_eq!(
            census_unknown_ops(&[walk(99, complete())], &BTreeMap::new(), 0),
            BTreeSet::new()
        );
        // Loss + observed-but-missing op: UNKNOWN (never zero).
        assert_eq!(
            census_unknown_ops(&[walk(99, complete())], &BTreeMap::new(), 3),
            BTreeSet::from([99])
        );
        // Loss + present key: exact (never flagged).
        assert_eq!(
            census_unknown_ops(&[walk(7, complete())], &BTreeMap::from([(7, 10)]), 3),
            BTreeSet::new()
        );
        // Loss + skipped-only op: true zero (skips never admit).
        assert_eq!(
            census_unknown_ops(
                &[walk(5, Outcome::Skipped { cause: 1 })],
                &BTreeMap::new(),
                3
            ),
            BTreeSet::new()
        );
        // Loss + taint-forced op: unattributable (never flagged).
        assert_eq!(
            census_unknown_ops(
                &[walk(UNKNOWN_OP, Outcome::Tainted { by_seq: 2 })],
                &BTreeMap::new(),
                3
            ),
            BTreeSet::new()
        );
        // Mixed batch flags exactly the observed-but-missing op.
        assert_eq!(
            census_unknown_ops(
                &[
                    walk(99, complete()),
                    walk(7, complete()),
                    walk(5, Outcome::Skipped { cause: 1 }),
                    walk(UNKNOWN_OP, Outcome::Tainted { by_seq: 2 }),
                ],
                &BTreeMap::from([(7, 10)]),
                3
            ),
            BTreeSet::from([99])
        );
    }

    /// Oracle holding one closed record + one finding (a
    /// cold T=1 close plus an orphan RET for an unknown key —
    /// the batch the failure-ordering controls take from).
    /// Asserts non-consumingly (the batch stays for the take).
    fn oracle_with_batch() -> Oracle {
        use crate::scan::oracle::{Oracle, OracleScope, ScanBatch};
        let mut o = Oracle::new(OracleScope::full());
        let mut b = ScanBatch {
            quiesced: true,
            ..ScanBatch::default()
        };
        b.rcount.insert(4242, (0, wire::RCOUNT_STATE_IDLE));
        b.push_call(wire::ScanCallEvent {
            kind: wire::KIND_SCAN_CALL,
            op: 7,
            tid: 4242,
            flags: wire::make_call_flags(false, wire::SKIP_ADMITTED),
            seq: 0,
        });
        b.push_ret(wire::ScanRetEvent {
            kind: wire::KIND_SCAN_RET,
            op: 7,
            flags: 0,
            tid: 4242,
            seq: 0,
            arr: 0x7000,
            generation: 0,
        });
        b.push_alg(wire::ScanAlgEvent {
            kind: wire::KIND_SCAN_ALG,
            op: 7,
            class: 1,
            status: wire::ALG_OK,
            weak: 0,
            _pad: 0,
            arr: 0x7000,
            idx: 0,
            generation: 0,
            tid: 4242,
            _pad2: 0,
            seq: 0,
        });
        b.push_alg(wire::ScanAlgEvent {
            kind: wire::KIND_SCAN_ALG,
            op: 7,
            class: wire::OTHER_CLASS,
            status: wire::ALG_EMPTY,
            weak: 0,
            _pad: 0,
            arr: 0x7000,
            idx: 1,
            generation: 0,
            tid: 4242,
            _pad2: 0,
            seq: 0,
        });
        b.push_ret(wire::ScanRetEvent {
            kind: wire::KIND_SCAN_RET,
            op: 7,
            flags: 0,
            tid: 4242,
            seq: 9,
            arr: 0x7000,
            generation: 0,
        });
        o.ingest(&b);
        assert_eq!(o.done().len(), 1, "setup closes one record");
        assert_eq!(o.findings().len(), 1, "setup raises one finding");
        o
    }

    #[test]
    fn fix5_census_failure_preserves_takes() {
        use std::cell::Cell;
        // A failing census read consumes NOTHING: the takes never
        // run, and the full output batch (records + findings)
        // stays in the oracle for the next poll or the salvage
        // take.
        let mut o = oracle_with_batch();
        let takes = Cell::new(0u32);
        let r = take_after_census(
            || anyhow::bail!("injected census failure"),
            || {
                takes.set(takes.get() + 1);
                (o.take_done(), o.take_findings())
            },
        );
        assert!(r.is_err(), "the read failure must propagate");
        assert_eq!(takes.get(), 0, "failing read must not consume takes");
        assert_eq!(o.take_done().len(), 1, "the record stays for salvage");
        assert_eq!(o.take_findings().len(), 1, "the finding stays for salvage");
    }

    #[test]
    fn fix5_census_success_takes_batch_once() {
        use std::cell::Cell;
        // A passing census read takes the full batch exactly once
        // (records + findings + snapshot all flow through).
        let mut o = oracle_with_batch();
        let takes = Cell::new(0u32);
        let (census, done, findings) = take_after_census(
            || Ok(BTreeMap::from([(7u32, 10u64)])),
            || {
                takes.set(takes.get() + 1);
                (o.take_done(), o.take_findings())
            },
        )
        .expect("passing read takes");
        assert_eq!(takes.get(), 1, "takes run exactly once");
        assert_eq!(census.get(&7), Some(&10));
        assert_eq!(done.len(), 1, "the record flows through");
        assert_eq!(findings.len(), 1, "the finding flows through");
    }

    #[test]
    fn attach_bytes_refuses_over_cap_before_bpf() {
        // Finding 11: the onboarding cap binds loading too — an
        // over-cap caller buffer refuses before any BPF work (no
        // post-onboarding enlargement bypass). Host-safe: the
        // refusal precedes the loader, so no privilege needed.
        let big = vec![0u8; (crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES + 1) as usize];
        let exe = CString::new("/exe").unwrap();
        let ctrl = wire::ctrl_value(512, 1, 1 << 22);
        let e = ScanBackend::attach_bytes(&big, Path::new("obj"), &exe, 0, 0, &ctrl, None, 0)
            .err()
            .expect("over-cap refuses");
        // The backend layer's own message (the loader repeats the
        // check deeper — defense in depth with a distinct text).
        let want = format!(
            "exceeds the {} cap",
            crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES
        );
        assert!(e.to_string().contains(&want), "{e:#}");
    }

    #[test]
    fn decode_unknown_kind_bails() {
        let mut raw = call_bytes();
        raw[0..4].copy_from_slice(&99u32.to_le_bytes());
        let mut b = ScanBatch::default();
        let e = decode_ring_record(&raw, &mut b).unwrap_err();
        assert!(e.to_string().contains("unexpected ring kind 99"), "{e:#}");
    }

    #[test]
    fn decode_bad_payload_bails() {
        // Valid kind, out-of-range cause (fail-closed vocabulary).
        let mut raw = call_bytes();
        raw[12..16].copy_from_slice(&wire::make_call_flags(false, 11).to_le_bytes());
        let mut b = ScanBatch::default();
        assert!(decode_ring_record(&raw, &mut b).is_err());
    }

    #[test]
    fn decode_preserves_ring_order() {
        // Interleaved records decode into kind vecs with the
        // cross-kind drain order intact (the oracle's causal
        // join input).
        let mut b = ScanBatch::default();
        decode_ring_record(&call_bytes(), &mut b).unwrap();
        let mut ret = vec![0u8; 40];
        ret[0..4].copy_from_slice(&wire::KIND_SCAN_RET.to_le_bytes());
        decode_ring_record(&ret, &mut b).unwrap();
        decode_ring_record(&call_bytes(), &mut b).unwrap();
        assert_eq!(b.calls.len(), 2);
        assert_eq!(b.rets.len(), 1);
        assert!(b.order_sound());
        assert_eq!(
            b.order,
            vec![
                crate::scan::oracle::BatchPos::Call(0),
                crate::scan::oracle::BatchPos::Ret(0),
                crate::scan::oracle::BatchPos::Call(1),
            ]
        );
    }

    fn partial(arr: u64, reasons: Vec<crate::scan::oracle::PartialReason>) -> WalkDone {
        WalkDone {
            tid: 1,
            seq: 0,
            op: 7,
            arr,
            outcome: crate::scan::oracle::Outcome::Partial { reasons },
            true_t: crate::scan::oracle::TrueT::Proven(4),
            alg_count: 5,
            row_count: 0,
            guard: None,
            algs: Vec::new(),
            event_ns: 0,
            rows: Vec::new(),
        }
    }

    #[test]
    fn healing_action_matrix() {
        use crate::scan::oracle::PartialReason as R;
        // Shrink updates to the fresh terminator.
        assert_eq!(
            healing_action(&partial(
                0x7000,
                vec![R::CacheShrink {
                    cached: 9,
                    observed: 4
                }]
            )),
            Some(Healing::Update { t: 4 })
        );
        // Grow invalidates (cold re-probe heals).
        assert_eq!(
            healing_action(&partial(0x7000, vec![R::CacheStale { cached: 2 }])),
            Some(Healing::Invalidate)
        );
        // Generation turnover invalidates.
        assert_eq!(
            healing_action(&partial(
                0x7000,
                vec![R::GenStale {
                    expected: 5,
                    observed: 6
                }]
            )),
            Some(Healing::Invalidate)
        );
        // Mixed-generation evidence heals nothing (untrusted —
        // even beside a shrink signal).
        assert_eq!(
            healing_action(&partial(
                0x7000,
                vec![
                    R::CacheShrink {
                        cached: 9,
                        observed: 4
                    },
                    R::GenMixed
                ]
            )),
            None
        );
        // Plain holes heal nothing (loss, not contradiction).
        assert_eq!(
            healing_action(&partial(0x7000, vec![R::Holes(vec![1])])),
            None
        );
        // No array, no cache row.
        assert_eq!(
            healing_action(&partial(0, vec![R::CacheStale { cached: 2 }])),
            None
        );
        // Completes never heal (they warm or re-prove instead).
        let mut w = partial(0x7000, vec![R::CacheStale { cached: 2 }]);
        w.outcome = crate::scan::oracle::Outcome::Complete {
            true_t: 2,
            cached: true,
        };
        assert_eq!(healing_action(&w), None);
    }
}
