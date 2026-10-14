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
    AbandonReason, Finding, Oracle, OracleScope, ScanBatch, TrueT, WalkDone,
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
    ring: aya::maps::RingBuf<aya::maps::MapData>,
    oracle: Oracle,
    throttle: DutyThrottle,
    storm: StormDetector,
    births: BirthState,
    epoch_start: Instant,
    last_loss: BTreeMap<u32, u64>,
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
    ) -> anyhow::Result<Self> {
        let bytes = std::fs::read(obj)
            .with_context(|| format!("read {}", obj.display()))
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        Self::attach_bytes(&bytes, obj, exe, off, pid, ctrl, slots)
    }

    /// Attach over verified bytes (no path re-read — the caller
    /// hashes these same bytes for provenance, so identity and
    /// loading cannot drift). Selective attaches keep good
    /// members and report failed slots (the oracle scope covers
    /// exactly what attached — failed slots are unobserved
    /// PARTIAL there, never holes).
    pub fn attach_bytes(
        bytes: &[u8],
        obj: &Path,
        exe: &CString,
        off: u64,
        pid: u32,
        ctrl: &wire::CtrlValue,
        slots: Option<&[u32]>,
    ) -> anyhow::Result<Self> {
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
            ring,
            oracle: Oracle::new(scope),
            throttle: DutyThrottle::new(),
            storm: StormDetector::new(),
            births: BirthState::new(),
            epoch_start: Instant::now(),
            last_loss: BTreeMap::new(),
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
        let now_ns = now.duration_since(self.epoch_start).as_nanos() as u64;
        // Every poll drains (even storm-detached: the entry still
        // emits skip CALLs, and the ring must not fill with them).
        let batch = self.drain_batch(quiesced, now_ns)?;
        self.oracle.ingest(&batch);
        // Tier-3 (storm owns the gate): ATTEMPT total. The entry
        // link stays attached through a storm cut, so this census
        // remains live while detached.
        let attempts = read_attempt_total(&self.loaded.maps)?;
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
        // Tier-2 aging runs on EVERY poll (idle polls release an
        // engaged throttle once the trailing cost decays — the
        // storm owns SKIP_ALL while detached, so a storm-time
        // release only flips state, never the map).
        if let Some(ThrottleAction::ReleaseSkipAll) = self.throttle.age(now_ns) {
            if !self.storm_detached {
                self.set_skip_all(false)?;
                delta.actions.push(BackendAction::SkipAllReleased);
            }
        }
        // Tier-2 + cache warms/heals over newly closed invocations.
        let fresh: Vec<WalkDone> = self.oracle.take_done();
        let fresh_findings: Vec<Finding> = self.oracle.take_findings();
        self.done_total += fresh.len() as u64;
        self.findings_total += fresh_findings.len() as u64;
        for w in &fresh {
            // Cost proxy: proven T for completes, joined-ALG
            // count otherwise (walked evidence ≈ paid cost;
            // skipped/tainted/abandoned scale by what fired).
            // While storm-detached the storm owns the gate (skip
            // records charge nothing).
            if !self.storm_detached {
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
            // standing entry — no write needed). NO_STORE can
            // never warm (it never completes).
            if let crate::scan::oracle::Outcome::Complete {
                true_t,
                cached: false,
            } = &w.outcome
            {
                let proven = matches!(w.true_t, TrueT::Proven(t) if t == *true_t);
                if proven && w.arr != 0 {
                    let incarnation = ensure_gen(&self.loaded.maps, w.arr)?;
                    write_tcache(&self.loaded.maps, w.arr, *true_t, incarnation)?;
                    self.oracle.note_warm(w.arr, *true_t, incarnation);
                    delta.actions.push(BackendAction::CacheWarmed {
                        arr: w.arr,
                        t: *true_t,
                    });
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
        delta.done = fresh;
        delta.findings = fresh_findings;
        Ok(delta)
    }

    /// Window-edge close: one settle drain (the trailing records
    /// land), then the oracle backstop closes every remaining open
    /// (RET-joined evaluate, RET-less dangle — explicit PARTIAL,
    /// never dropped). Tier-2 ages once more so the end-state
    /// flags settle honestly.
    pub fn finish(&mut self) -> anyhow::Result<PollDelta> {
        let mut delta = self.poll()?;
        let now_ns = Instant::now().duration_since(self.epoch_start).as_nanos() as u64;
        self.oracle.finish(now_ns);
        if let Some(ThrottleAction::ReleaseSkipAll) = self.throttle.age(now_ns) {
            if !self.storm_detached {
                self.set_skip_all(false)?;
                delta.actions.push(BackendAction::SkipAllReleased);
            }
        }
        let (done, findings) = self.take_completed();
        self.done_total += done.len() as u64;
        self.findings_total += findings.len() as u64;
        delta.done.extend(done);
        delta.findings.extend(findings);
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
    /// against the last poll's totals; TRUNC bits are
    /// clear-on-read (every drain's read is that drain's delta,
    /// so repeated faults re-appear instead of hiding under the
    /// sticky bit they set before).
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
        // TRUNC is sticky bits (OR-fold): the read IS this drain's
        // delta, then the rows clear so the next drain sees only
        // new faults. Residual race (bounded, µs): a fault landing
        // between this read and the clear below is lost — READ /
        // NAME faults stay covered regardless (their aborts leave
        // missing records = holes); DISPATCH / ALGS / NO_STORE
        // depend on the bit. The window is one map round-trip per
        // drain; faults are per-scan events correlated with ring
        // records that surface independently.
        for (op, bits) in read_percpu_all(&self.loaded.maps, "TRUNC", true)? {
            if bits != 0 {
                b.trunc.insert(op, bits);
            }
        }
        clear_percpu_all(&self.loaded.maps, "TRUNC")?;
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

/// Zero every row of a u32→u64 percpu hash (TRUNC clear-on-read:
/// each drain's read is that drain's delta — repeated faults
/// re-appear instead of hiding under their sticky bit).
fn clear_percpu_all(
    maps: &std::collections::HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::convert::TryFrom as _;
    let fd = maps
        .get(name)
        .with_context(|| format!("map {name} missing"))?
        .try_clone()
        .with_context(|| format!("clone {name}"))?;
    let data = aya::maps::MapData::from_fd(fd).with_context(|| format!("{name} mapdata"))?;
    let map = aya::maps::Map::from_map_data(data).with_context(|| format!("{name} map"))?;
    let mut m = aya::maps::PerCpuHashMap::<_, u32, u64>::try_from(map)
        .with_context(|| format!("{name} percpu shape"))?;
    let mut rows: Vec<(u32, usize)> = Vec::new();
    for r in m.iter() {
        let (k, slots) = r.with_context(|| format!("{name} iter"))?;
        rows.push((k, slots.len()));
    }
    for (k, ncpu) in rows {
        let zeros = aya::maps::PerCpuValues::<u64>::try_from(vec![0u64; ncpu])
            .with_context(|| format!("{name} zero widths"))?;
        m.insert(k, zeros, 0)
            .with_context(|| format!("{name} clear"))?;
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
