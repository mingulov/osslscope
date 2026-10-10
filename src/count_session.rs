//! SPDX-License-Identifier: GPL-3.0-or-later
//! T07 immutable count session (spec R01/R02/R05).
//!
//! [`CountSession`] consumes typed discovery deltas ([`CountDelta`]),
//! plans them through [`crate::plan`] (cookies identify verified
//! physical backing — device, inode, file offset — never the link
//! path), attaches count probes through a [`CountBackend`], and
//! drains per-generation conserved [`SiteExecution`](crate::evidence::SiteExecution)
//! records into a [`CountDrain`].
//!
//! Provenance is immutable: once a cookie is minted for a backing
//! triple, its site key never changes, and a changed candidate set
//! versions at a fence — the fenced generation keeps the old
//! meaning, the new generation carries the new one. Old links keep
//! their old meaning; drains and fences preserve every candidate,
//! weak metadata included.
//!
//! The spec's `DiscoveryDelta` producer lands in T06
//! (`src/discovery/session.rs`); [`CountDelta`] is this session's
//! consumer-side projection of it with identical site, candidate,
//! coverage and loss fields, so the T08 adapter is mechanical (see
//! the handoff for the field map). The live-maps/file-bytes context
//! rides as explicit [`attach`](CountSession::attach_delta)
//! parameters so planning stays pure and host-testable; T08 passes
//! `read_maps(pid)` plus pre-read file bytes at each poll.
//!
//! Backends: [`LiveBackend`] drives the real BPF maps/links (needs
//! caps); [`FakeCountBackend`] is a deterministic host double that
//! models the kernel `TARGET`/window/`GEN` admission semantics
//! exactly, including map-full drops, so the identity, deadline and
//! conservation contracts pin without privileges.

use crate::discovery::maps;
use crate::evidence::{
    CandidateCoverage, CandidateIdentity, CounterKind, CounterSource, CounterUnits,
    FencedGeneration, GapCounter, SiteExecution, SiteKey,
};
use crate::plan;
use osslscope_ebpf_common::{CountValue, make_key, split_key};
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::time::{Duration, Instant};

/// One discovered site: its physical key, the candidate identities
/// that could explain entry there, and whether that candidate set is
/// itself complete. The `(device, inode, offset)` triple is the
/// verified backing identity (R02); pathnames are locators only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredSite {
    pub site: SiteKey,
    pub candidates: Vec<CandidateIdentity>,
    pub candidates_coverage: CandidateCoverage,
}

impl DiscoveredSite {
    fn normalize(&mut self) {
        for c in &mut self.candidates {
            c.algorithm_classes.sort();
            c.algorithm_classes.dedup();
        }
        self.candidates.sort();
        self.candidates.dedup();
    }
}

/// Consumer-side discovery delta: new/changed classified sites plus
/// source-tagged discovery losses to carry into the drain. T06's
/// producer `DiscoveryDelta` maps onto this field-for-field (T08
/// adapts; see the handoff).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountDelta {
    pub discovered: Vec<DiscoveredSite>,
    pub losses: Vec<GapCounter>,
}

/// Raw output of one backend drain: per-key CPU-folded totals plus
/// the kernel drop counter and any drain shortfall. Routing (delta
/// reads, generation split, attribution) lives in the session, not
/// the backend, so both backends share one routing proof.
#[derive(Debug, Clone, Default)]
pub struct DrainedCounts {
    /// `(COUNTS key, CPU-folded total)` rows with nonzero counts.
    pub rows: Vec<(u64, CountValue)>,
    /// Monotonic `DROPFAIL` total (map-full insert failures).
    pub dropfail_total: u64,
    /// Keys left unprocessed when the drain deadline expired.
    pub shortfall: u64,
}

/// Kernel side of the count session: attach, window programming and
/// raw drains. [`LiveBackend`] implements this over aya; tests use
/// [`FakeCountBackend`].
pub trait CountBackend {
    /// Attached link handle, held alive by the session (RAII).
    type Link;

    /// Attach one multi-link group. Returns live links plus the
    /// positions (into `offsets`/`cookies`) the kernel refused, in
    /// ascending unique order. The session normalizes defensively,
    /// so backends SHOULD return sorted indices but a valid backend
    /// is never misread when it does not.
    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<Self::Link>, Vec<usize>);

    /// Open the count window: arm `TARGET`, `GEN` and the monotonic
    /// `[start_ns, deadline_ns)` admission interval.
    fn open_window(
        &mut self,
        tgid: u64,
        generation: u32,
        start_ns: u64,
        deadline_ns: u64,
    ) -> anyhow::Result<()>;

    /// Program a new `GEN` epoch after a fence.
    fn set_generation(&mut self, generation: u32) -> anyhow::Result<()>;

    /// Close the window in-kernel (`TARGET=0`, drop-all).
    fn close_window(&mut self) -> anyhow::Result<()>;

    /// Drain raw counts. `deadline` bounds grace drains: keys left
    /// unread past it count exactly into
    /// [`DrainedCounts::shortfall`].
    fn drain(&mut self, deadline: Option<Instant>) -> anyhow::Result<DrainedCounts>;
}

/// Why a fence generation boundary was taken. Mapping/exec reasons
/// mirror the capture fence kinds; `CandidatesChanged` versions an
/// attribution-set change (R02: never relabel a live cookie).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceReason {
    MappingsChanged,
    ProviderChanged,
    Exec,
    CandidatesChanged,
}

/// Immutable meaning of one cookie: the physical site, the candidate
/// set explaining it, that set's coverage, and the link path the
/// probe attached through (locator, not identity — recorded on
/// successful attach only, empty before that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub site: SiteKey,
    pub candidates: Vec<CandidateIdentity>,
    pub candidates_coverage: CandidateCoverage,
    pub link_path: String,
}

/// Attribution update staged by [`CountSession::attach_delta`],
/// applied to the new generation by [`CountSession::fence`]. Carries
/// the full site key (not just candidates): a changed object
/// fingerprint for one backing triple — modified-in-place content or
/// inode reuse — versions the same way, so the fenced generation
/// keeps the old fingerprint and the new one carries the new.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingMeaning {
    site: SiteKey,
    candidates: Vec<CandidateIdentity>,
    coverage: CandidateCoverage,
}

/// Normalize backend refuse-indices into per-position flags.
/// Defensive: out-of-range indices are ignored, order and
/// duplicates do not matter — a refused site must never read as
/// attached just because a backend returned an odd list.
fn normalize_bad(bad: Vec<usize>, n: usize) -> Vec<bool> {
    let mut out = vec![false; n];
    for b in bad {
        if let Some(slot) = out.get_mut(b) {
            *slot = true;
        }
    }
    out
}

/// What one [`CountSession::attach_delta`] call did.
#[derive(Debug, Clone)]
pub struct AttachReport {
    /// Sites newly attached by this call.
    pub attached: u64,
    /// Planned sites skipped (probes already live).
    pub reused: u64,
    /// Plan-time and attach-time rejects (all counted loud).
    pub missed: Vec<plan::Missed>,
    /// Kernel-refused offsets this call (bisection survivors).
    pub unresolved: u64,
    /// A delta changed a live cookie's candidate set: the caller
    /// must [`fence`](CountSession::fence) with
    /// [`FenceReason::CandidatesChanged`] before the new meaning
    /// takes effect; until then the old meaning stands.
    pub candidates_changed: bool,
}

/// Final session output: current-generation executions, fenced
/// generations (each with the candidate meaning then current), and
/// typed loss/activity counters. T08 merges window, coverage and
/// object records around this.
#[derive(Debug, Clone)]
pub struct CountDrain {
    pub current: Vec<SiteExecution>,
    pub fenced: Vec<FencedGeneration>,
    pub counters: Vec<GapCounter>,
}

impl CountDrain {
    /// Conserved total across current and fenced sites.
    pub fn total_calls(&self) -> u64 {
        let current = SiteExecution::sum_calls(&self.current);
        self.fenced.iter().fold(current, |acc, g| {
            acc.saturating_add(SiteExecution::sum_calls(&g.sites))
        })
    }
}

/// Merge one loss counter into the store: same (name, kind, units,
/// source) sums, zero values add nothing, and a clean delta never
/// erases an earlier gap.
fn merge_counter(store: &mut Vec<GapCounter>, next: GapCounter) {
    if next.value == 0 {
        return;
    }
    if let Some(slot) = store.iter_mut().find(|c| {
        c.name == next.name
            && c.kind == next.kind
            && c.units == next.units
            && c.source == next.source
    }) {
        slot.value = slot.value.saturating_add(next.value);
    } else {
        store.push(next);
    }
}

fn counter(
    name: &str,
    kind: CounterKind,
    units: CounterUnits,
    source: CounterSource,
    value: u64,
) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind,
        units,
        source,
        value,
    }
}

/// Plan-metadata identity for one candidate set. The planner's
/// single-`alg_class` [`plan::Identity`] cannot hold a set, so the
/// deterministic sort-first candidate rides as canonical with the
/// remaining set folded into a `+`-joined class list — a composite
/// rendering, never a canonical-algorithm claim. Real attribution
/// always comes from [`Provenance`], never from this row.
fn canonical_identity(candidates: &[CandidateIdentity], offset: u64) -> plan::Identity {
    let mut sorted = candidates.to_vec();
    sorted.sort();
    sorted.dedup();
    match sorted.first() {
        Some(c) => {
            let mut classes: Vec<&str> = sorted
                .iter()
                .flat_map(|c| c.algorithm_classes.iter().map(String::as_str))
                .collect();
            classes.sort_unstable();
            classes.dedup();
            plan::Identity {
                provider: c.provider.0.clone(),
                op: c.op,
                funcid: c.funcid,
                alg_class: if classes.is_empty() {
                    "other".to_string()
                } else {
                    classes.join("+")
                },
                offset,
            }
        }
        None => plan::Identity {
            provider: "unknown".to_string(),
            op: 0,
            funcid: 0,
            alg_class: "other".to_string(),
            offset,
        },
    }
}

/// Fold a drained delta into a site execution record.
fn fold_exec_calls(exec: &mut SiteExecution, delta: u64, first_ns: u64, last_ns: u64) {
    if exec.calls == 0 {
        exec.first_ns = first_ns;
        exec.last_ns = last_ns;
    } else {
        exec.first_ns = exec.first_ns.min(first_ns);
        exec.last_ns = exec.last_ns.max(last_ns);
    }
    exec.calls = exec.calls.saturating_add(delta);
}

/// Immutable planner identity + count window session, generic over
/// the [`CountBackend`]. Owns cookie provenance, generation epochs,
/// link RAII and drain routing; T08 holds one for the whole
/// observation and feeds it deltas incrementally.
pub struct CountSession<B: CountBackend> {
    pid: u32,
    backend: B,
    links: Vec<B::Link>,
    stable: plan::StableCookies,
    provenance: HashMap<u32, Provenance>,
    pending: HashMap<u32, PendingMeaning>,
    /// (device, inode, offset) triples with live probes. Re-plans
    /// skip survivors: inode probes persist across remaps, and
    /// re-attaching would double-fire every hit.
    attached: HashSet<(u64, u64, u64)>,
    known: HashSet<u32>,
    current: HashMap<u32, CountValue>,
    fenced: Vec<FencedGeneration>,
    /// (generation, cookie) → meaning then current, for exact
    /// straggler routing after a fence.
    retired: HashMap<(u32, u32), Provenance>,
    /// Last folded total per (cookie, generation): drains are
    /// delta-reads (map keys persist across fence drains — folding
    /// totals twice would double-count, and deleting keys mid-window
    /// would race in-flight increments).
    seen: HashMap<(u32, u32), u64>,
    last_dropfail: u64,
    generation: u32,
    window_open: bool,
    closed: bool,
    passthrough: Vec<GapCounter>,
    dropfail: u64,
    unattributed: u64,
    shortfall: u64,
    missed_attaches: u64,
    unresolved: u64,
    stale_events: u64,
    fences: u64,
    drained_keys: u64,
}

impl<B: CountBackend> CountSession<B> {
    pub fn new(pid: u32, backend: B) -> Self {
        Self {
            pid,
            backend,
            links: Vec::new(),
            stable: plan::StableCookies::default(),
            provenance: HashMap::new(),
            pending: HashMap::new(),
            attached: HashSet::new(),
            known: HashSet::new(),
            current: HashMap::new(),
            fenced: Vec::new(),
            retired: HashMap::new(),
            seen: HashMap::new(),
            last_dropfail: 0,
            generation: 0,
            window_open: false,
            closed: false,
            passthrough: Vec::new(),
            dropfail: 0,
            unattributed: 0,
            shortfall: 0,
            missed_attaches: 0,
            unresolved: 0,
            stale_events: 0,
            fences: 0,
            drained_keys: 0,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn window_open(&self) -> bool {
        self.window_open
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Cookies minted so far.
    pub fn cookie_count(&self) -> usize {
        self.stable.len()
    }

    /// The cookie minted for a backing triple, if any.
    pub fn cookie_for(&self, device: u64, inode: u64, offset: u64) -> Option<u32> {
        self.stable
            .lookup(&plan::render_device(device), inode, offset)
    }

    /// Immutable meaning of a cookie, if minted.
    pub fn provenance(&self, cookie: u32) -> Option<&Provenance> {
        self.provenance.get(&cookie)
    }

    /// Known cookies, sorted (coverage input for T08).
    pub fn cookies(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.known.iter().copied().collect();
        out.sort_unstable();
        out
    }

    /// Plan one discovery delta against live mappings and attach the
    /// not-yet-attached sites at the current generation. `live` is
    /// the target's current `/proc/pid/maps` view and `files` maps
    /// link-path → pre-read file bytes (T08 refreshes both per poll).
    ///
    /// New backing triples mint cookies and immutable provenance;
    /// surviving triples reuse both and skip re-attach. A changed
    /// candidate set for a live cookie stages a [`PendingMeaning`]
    /// and reports `candidates_changed` — the old meaning stands
    /// until [`fence`](Self::fence) versions it. Every planned link
    /// path is open-file verified against its backing triple just
    /// before attach; a replaced path is skipped as `replaced`, loud.
    pub fn attach_delta(
        &mut self,
        delta: &CountDelta,
        live: &[maps::Mapping],
        files: &HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<AttachReport> {
        if self.closed {
            anyhow::bail!("count session is closed");
        }
        // Merge duplicate backing triples within one delta: their
        // candidate sets union (a site's aliases are simultaneous,
        // never competing updates) and coverage degrades to Unknown
        // when either side is incomplete. Conflicting object
        // fingerprints for one triple are a producer contradiction:
        // fail closed rather than silently keeping the first.
        let mut merged: HashMap<(u64, u64, u64), DiscoveredSite> = HashMap::new();
        for mut site in delta.discovered.clone() {
            site.normalize();
            let key = (site.site.device, site.site.inode, site.site.offset);
            match merged.get_mut(&key) {
                None => {
                    merged.insert(key, site);
                }
                Some(prior) => {
                    if prior.site.object != site.site.object {
                        anyhow::bail!("conflicting object identity for one backing triple");
                    }
                    prior.candidates.extend(site.candidates);
                    if site.candidates_coverage == CandidateCoverage::Unknown {
                        prior.candidates_coverage = CandidateCoverage::Unknown;
                    }
                }
            }
        }
        let mut normalized: Vec<DiscoveredSite> = merged.into_values().collect();
        for site in &mut normalized {
            site.normalize();
        }
        normalized.sort_by(|a, b| a.site.cmp(&b.site));
        let rows: Vec<plan::PlanRow> = normalized
            .iter()
            .map(|s| plan::PlanRow {
                dev: plan::render_device(s.site.device),
                ino: s.site.inode,
                offset: s.site.offset,
                id: canonical_identity(&s.candidates, s.site.offset),
            })
            .collect();
        let planned = plan::plan_rows(&rows, live, files, self.generation, &mut self.stable)?;
        let mut report = AttachReport {
            attached: 0,
            reused: 0,
            missed: planned.missed.clone(),
            unresolved: 0,
            candidates_changed: false,
        };
        // Mint or version provenance, row by row. Cookie/site-key
        // bindings are append-only while the meaning is live; a
        // changed site key, candidate set or coverage stages a full
        // update for the fence, and a delta re-affirming the live
        // meaning cancels any staged update. Rows that miss now but
        // hold an old cookie (dormant sites) still version their
        // meaning — the inode probes are live and the fence applies
        // it. Link paths record on successful attach only.
        for (row, site) in rows.iter().zip(normalized.iter()) {
            let Some(cookie) = self.stable.lookup(&row.dev, row.ino, row.offset) else {
                continue;
            };
            self.known.insert(cookie);
            let same = self.provenance.get(&cookie).is_some_and(|current| {
                current.site == site.site
                    && current.candidates == site.candidates
                    && current.candidates_coverage == site.candidates_coverage
            });
            match self.provenance.entry(cookie) {
                Entry::Vacant(vacant) => {
                    vacant.insert(Provenance {
                        site: site.site.clone(),
                        candidates: site.candidates.clone(),
                        candidates_coverage: site.candidates_coverage,
                        link_path: String::new(),
                    });
                }
                Entry::Occupied(_) if same => {
                    // Newest delta wins: the live meaning stands, so
                    // any staged update is stale and must not install
                    // later.
                    self.pending.remove(&cookie);
                }
                Entry::Occupied(_) => {
                    // Attribution-set change: never relabel the live
                    // cookie — stage the new meaning for the fence.
                    self.pending.insert(
                        cookie,
                        PendingMeaning {
                            site: site.site.clone(),
                            candidates: site.candidates.clone(),
                            coverage: site.candidates_coverage,
                        },
                    );
                    report.candidates_changed = true;
                }
            }
        }
        self.missed_attaches += report.missed.len() as u64;
        // Attach survivors are skipped; every attached path is
        // open-file verified against its own backing triple.
        for group in plan::groups(&planned) {
            let mut offs: Vec<u64> = Vec::new();
            let mut cks: Vec<u64> = Vec::new();
            for (offset, cookie) in group.offsets.iter().zip(group.cookies.iter()) {
                let cookie = *cookie as u32;
                let Some(prov) = self.provenance.get(&cookie) else {
                    continue;
                };
                let key = (prov.site.device, prov.site.inode, *offset);
                if self.attached.contains(&key) {
                    report.reused += 1;
                    continue;
                }
                match plan::verify_backing(&group.path, prov.site.device, prov.site.inode) {
                    Ok(()) => {
                        offs.push(*offset);
                        cks.push(cookie as u64);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        report.missed.push(plan::Missed {
                            dev: plan::render_device(prov.site.device),
                            ino: prov.site.inode,
                            offset: *offset,
                            reason: "replaced",
                        });
                        self.missed_attaches += 1;
                    }
                    Err(_) => {
                        report.missed.push(plan::Missed {
                            dev: plan::render_device(prov.site.device),
                            ino: prov.site.inode,
                            offset: *offset,
                            reason: "unreadable",
                        });
                        self.missed_attaches += 1;
                    }
                }
            }
            if offs.is_empty() {
                continue;
            }
            // The path is verified above and re-sampled across the
            // attach: `uprobe_multi` resolves the path itself, so a
            // path that moves mid-attach may bind either side. Fresh
            // links from a moved path are dropped loud as `replaced`
            // — they must never attribute to stale provenance under
            // an already-known cookie.
            let pre = plan::sample_backing(&group.path).ok();
            let (links, bad) = self.backend.attach(&group.path, &offs, &cks);
            let post = plan::sample_backing(&group.path).ok();
            if pre != post {
                drop(links);
                for (offset, cookie) in offs.iter().zip(cks.iter()) {
                    let cookie = *cookie as u32;
                    if let Some(prov) = self.provenance.get(&cookie) {
                        report.missed.push(plan::Missed {
                            dev: plan::render_device(prov.site.device),
                            ino: prov.site.inode,
                            offset: *offset,
                            reason: "replaced",
                        });
                        self.missed_attaches += 1;
                    }
                }
                continue;
            }
            self.links.extend(links);
            let refused = normalize_bad(bad, offs.len());
            for (j, (offset, cookie)) in offs.iter().zip(cks.iter()).enumerate() {
                if refused[j] {
                    report.unresolved += 1;
                    self.unresolved += 1;
                    continue;
                }
                let cookie = *cookie as u32;
                if let Some(prov) = self.provenance.get_mut(&cookie) {
                    self.attached
                        .insert((prov.site.device, prov.site.inode, *offset));
                    prov.link_path = group.path.clone();
                    report.attached += 1;
                }
            }
        }
        for loss in &delta.losses {
            merge_counter(&mut self.passthrough, loss.clone());
        }
        Ok(report)
    }

    /// Open the count window: arm the target TGID guard, the current
    /// generation and the monotonic `[start_ns, deadline_ns)`
    /// admission interval. Counts are admitted only inside the
    /// declared interval; an empty or inverted window is a
    /// fail-closed error. Called once per session, at target release
    /// (T08); attach deltas may precede or follow it.
    pub fn open_window(&mut self, start_ns: u64, deadline_ns: u64) -> anyhow::Result<()> {
        if self.closed {
            anyhow::bail!("count session is closed");
        }
        if self.window_open {
            anyhow::bail!("count window is already open");
        }
        if start_ns >= deadline_ns {
            anyhow::bail!("empty count window: start {start_ns} >= deadline {deadline_ns}");
        }
        self.backend
            .open_window(self.pid as u64, self.generation, start_ns, deadline_ns)?;
        self.window_open = true;
        Ok(())
    }

    /// Drain-then-fence: drain fully, bucket the current generation
    /// with the candidate meaning then current, retire every known
    /// cookie's meaning for exact straggler routing, apply staged
    /// attribution updates to the new generation, and bump `GEN`.
    /// The fenced bucket always exists (possibly empty) so the
    /// generation sequence stays auditable.
    pub fn fence(&mut self, reason: FenceReason) -> anyhow::Result<()> {
        if self.closed {
            anyhow::bail!("count session is closed");
        }
        let drained = self.backend.drain(None)?;
        let _ = self.route(drained);
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("generation space exhausted"))?;
        // Commit the kernel epoch BEFORE userspace state: if
        // `set_generation` fails the session is untouched (still the
        // old generation everywhere, current counts intact) and the
        // fence is cleanly retryable. Committing userspace first
        // would strand a usable session on a stale kernel epoch.
        self.backend.set_generation(next)?;
        let mut sites: Vec<SiteExecution> = Vec::new();
        for (cookie, total) in &self.current {
            if total.count == 0 {
                continue;
            }
            let Some(prov) = self.provenance.get(cookie) else {
                continue;
            };
            sites.push(SiteExecution {
                site: prov.site.clone(),
                generation: self.generation,
                candidates: prov.candidates.clone(),
                candidates_coverage: prov.candidates_coverage,
                calls: total.count,
                first_ns: total.first_ns,
                last_ns: total.last_ns,
            });
        }
        sites.sort();
        eprintln!(
            "COUNT fence reason={reason:?} generation={} keys={}",
            self.generation,
            sites.len(),
        );
        self.fenced.push(FencedGeneration {
            generation: self.generation,
            sites,
        });
        for cookie in self.known.iter() {
            if let Some(prov) = self.provenance.get(cookie) {
                self.retired
                    .insert((self.generation, *cookie), prov.clone());
            }
        }
        for (cookie, staged) in self.pending.drain() {
            if let Some(prov) = self.provenance.get_mut(&cookie) {
                prov.site = staged.site;
                prov.candidates = staged.candidates;
                prov.candidates_coverage = staged.coverage;
            }
        }
        self.current.clear();
        self.generation = next;
        self.fences += 1;
        Ok(())
    }

    /// Close the window in-kernel first (`TARGET=0`, drop-all — no
    /// userspace delay can extend counting past this point), then
    /// drain under the grace deadline and finalize the [`CountDrain`].
    /// Keys left unread past the grace expiry count exactly into the
    /// drain-shortfall loss counter. The final drain quiesces: while
    /// a pass routes new deltas (an increment admitted pre-close
    /// landing after the previous scan), another bounded pass runs,
    /// so in-flight hits settle instead of vanishing. No userspace
    /// loop can quiesce an increment that lands after the last scan
    /// — that nanosecond-scale residual matches the capture engine's
    /// single-scan behavior and is documented, not hidden; a
    /// kernel-side admitted-hits ledger would be needed to count it
    /// loud. Consumes the session for further attach/fence calls.
    pub fn close_and_drain(&mut self, grace: Duration) -> anyhow::Result<CountDrain> {
        if self.closed {
            anyhow::bail!("count session is already drained");
        }
        self.backend.close_window()?;
        self.window_open = false;
        let deadline = Instant::now().checked_add(grace);
        // Bounded quiesce: at most three passes, stopping early on a
        // clean pass, grace expiry, or any shortfall (re-scanning an
        // expired drain would recount the same keys as shortfall).
        let mut progress = true;
        let mut passes = 0u32;
        while progress && passes < 3 {
            let drained = self.backend.drain(deadline)?;
            let had_shortfall = drained.shortfall > 0;
            progress = self.route(drained);
            passes += 1;
            if had_shortfall {
                break;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
        }
        let mut current: Vec<SiteExecution> = Vec::new();
        for (cookie, total) in &self.current {
            if total.count == 0 {
                continue;
            }
            let Some(prov) = self.provenance.get(cookie) else {
                continue;
            };
            current.push(SiteExecution {
                site: prov.site.clone(),
                generation: self.generation,
                candidates: prov.candidates.clone(),
                candidates_coverage: prov.candidates_coverage,
                calls: total.count,
                first_ns: total.first_ns,
                last_ns: total.last_ns,
            });
        }
        current.sort();
        let mut counters = vec![
            counter(
                "count.map_insert_dropped",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::KernelMap,
                self.dropfail,
            ),
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.unattributed,
            ),
            counter(
                "count.drain_shortfall",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Drain,
                self.shortfall,
            ),
            counter(
                "count.missed_attaches",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Attach,
                self.missed_attaches,
            ),
            counter(
                "count.unresolved_offsets",
                CounterKind::Loss,
                CounterUnits::Probes,
                CounterSource::Attach,
                self.unresolved,
            ),
            counter(
                "count.stale_events",
                CounterKind::Activity,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.stale_events,
            ),
            counter(
                "count.fences",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.fences,
            ),
            counter(
                "count.drained_keys",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                self.drained_keys,
            ),
        ];
        counters.extend(self.passthrough.iter().cloned());
        counters.sort();
        self.closed = true;
        Ok(CountDrain {
            current,
            fenced: self.fenced.clone(),
            counters,
        })
    }

    /// Route one raw drain: delta-reads per (cookie, generation),
    /// current-generation hits fold per cookie, unknown cookies are
    /// loud unattributed loss, and old-generation stragglers route
    /// exactly into their fenced bucket under the retired meaning
    /// (with a staleness memo) instead of merging into the new
    /// meaning. A known cookie with a generation that was never
    /// fenced (or a future one — backend bug) is unattributed loss:
    /// folding it into `current` would stamp it with a generation
    /// and candidate meaning it never had. Every drained delta lands
    /// in exactly one bucket — current, fenced, or unattributed —
    /// so counts are conserved per generation. Returns whether any
    /// count delta routed (the close quiesce loop's progress bit).
    fn route(&mut self, drained: DrainedCounts) -> bool {
        let mut progress = false;
        self.drained_keys += drained.rows.len() as u64;
        for (key, total) in drained.rows {
            if total.count == 0 {
                continue;
            }
            let (cookie, generation) = split_key(key);
            let prev = self.seen.insert((cookie, generation), total.count);
            let delta = total.count.saturating_sub(prev.unwrap_or(0));
            if delta == 0 {
                continue;
            }
            progress = true;
            if !self.known.contains(&cookie) {
                // Unknown cookie (any generation): truly
                // unattributable — loud loss, never silent.
                self.unattributed += delta;
                continue;
            }
            if generation == self.generation {
                self.current.entry(cookie).or_default().fold(&CountValue {
                    count: delta,
                    first_ns: total.first_ns,
                    last_ns: total.last_ns,
                });
                continue;
            }
            // Straggler: a known cookie's old-generation events
            // landing after their fence drain. The count stays
            // attributed under its own generation's meaning while
            // the staleness memo records the fence crossing.
            let retired = self.retired.get(&(generation, cookie)).cloned();
            let bucket = self.fenced.iter_mut().find(|b| b.generation == generation);
            match (retired, bucket) {
                (Some(old), Some(bucket)) => {
                    self.stale_events += delta;
                    if let Some(exec) = bucket.sites.iter_mut().find(|s| s.site == old.site) {
                        fold_exec_calls(exec, delta, total.first_ns, total.last_ns);
                    } else {
                        bucket.sites.push(SiteExecution {
                            site: old.site,
                            generation,
                            candidates: old.candidates,
                            candidates_coverage: old.candidates_coverage,
                            calls: delta,
                            first_ns: total.first_ns,
                            last_ns: total.last_ns,
                        });
                        bucket.sites.sort();
                    }
                }
                _ => {
                    // Defensive: a generation we never fenced. The
                    // count is conserved as explicit unattributed
                    // loss rather than misattributed to the live
                    // meaning.
                    self.unattributed += delta;
                }
            }
        }
        self.dropfail += drained.dropfail_total.saturating_sub(self.last_dropfail);
        self.last_dropfail = drained.dropfail_total;
        self.shortfall += drained.shortfall;
        progress
    }
}

/// Attached-link handle for [`FakeCountBackend`]: a plain record,
/// held for RAII symmetry with the live backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeLink {
    pub cookie: u32,
    pub path: String,
    pub offset: u64,
}

/// Deterministic host double for the count kernel side. [`fire`](Self::fire)
/// models `count_entry` admission exactly: closed window or foreign
/// TGID drops silently, out-of-window timestamps drop, and inserts
/// past `capacity` fail loud into the drop counter (map-full model).
/// The per-(cookie, generation) ledger is the test oracle: each
/// provider mapping's executions land only under its own cookie.
#[derive(Debug, Clone)]
pub struct FakeCountBackend {
    tgid: u64,
    generation: u32,
    start_ns: u64,
    deadline_ns: u64,
    open: bool,
    attached: HashMap<u32, (String, u64)>,
    ledger: HashMap<(u32, u32), CountValue>,
    dropfail: u64,
    capacity: usize,
    poison: HashSet<u64>,
    shortfall_hook: u64,
    programmed: Vec<(u64, u32, u64, u64)>,
}

impl FakeCountBackend {
    pub fn new() -> Self {
        Self {
            tgid: 0,
            generation: 0,
            start_ns: 0,
            deadline_ns: 0,
            open: false,
            attached: HashMap::new(),
            ledger: HashMap::new(),
            dropfail: 0,
            capacity: usize::MAX,
            poison: HashSet::new(),
            shortfall_hook: 0,
            programmed: Vec::new(),
        }
    }

    /// Model a bounded `COUNTS` map: at most `cap` distinct keys;
    /// further inserts fail into the drop counter.
    pub fn with_capacity(cap: usize) -> Self {
        let mut out = Self::new();
        out.capacity = cap;
        out
    }

    /// Refuse one offset at attach (kernel-EINVAL model).
    pub fn poison_offset(&mut self, offset: u64) {
        self.poison.insert(offset);
    }

    /// Script shortfall keys for the next drain (grace-expiry model).
    pub fn set_shortfall(&mut self, n: u64) {
        self.shortfall_hook = n;
    }

    /// Model one batch of `count_entry` hits: `n` entries into
    /// `cookie` from `tgid` at monotonic `now_ns`.
    pub fn fire(&mut self, tgid: u32, cookie: u32, now_ns: u64, n: u64) {
        if n == 0 {
            return;
        }
        if !self.open || u64::from(tgid) != self.tgid {
            return;
        }
        if now_ns < self.start_ns || now_ns >= self.deadline_ns {
            return;
        }
        let key = (cookie, self.generation);
        if let Some(slot) = self.ledger.get_mut(&key) {
            slot.count = slot.count.saturating_add(n);
            slot.last_ns = now_ns;
            return;
        }
        if self.ledger.len() >= self.capacity {
            self.dropfail = self.dropfail.saturating_add(n);
            return;
        }
        self.ledger.insert(
            key,
            CountValue {
                count: n,
                first_ns: now_ns,
                last_ns: now_ns,
            },
        );
    }

    /// Independent ledger total for one (cookie, generation).
    pub fn ledger_total(&self, cookie: u32, generation: u32) -> u64 {
        self.ledger
            .get(&(cookie, generation))
            .map(|v| v.count)
            .unwrap_or(0)
    }

    /// Inject a raw ledger row, bypassing admission (models a hit the
    /// kernel admitted pre-close, or a backend anomaly for the
    /// defensive-routing tests). Test hook only.
    pub fn inject_row(&mut self, cookie: u32, generation: u32, value: CountValue) {
        self.ledger
            .entry((cookie, generation))
            .or_default()
            .fold(&value);
    }

    /// Link path a cookie attached through, if any.
    pub fn attached_path(&self, cookie: u32) -> Option<&str> {
        self.attached.get(&cookie).map(|(p, _)| p.as_str())
    }

    /// `open_window` programming log: (tgid, generation, start, deadline).
    pub fn programmed(&self) -> &[(u64, u32, u64, u64)] {
        &self.programmed
    }
}

impl Default for FakeCountBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CountBackend for FakeCountBackend {
    type Link = FakeLink;

    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<Self::Link>, Vec<usize>) {
        let mut links = Vec::new();
        let mut bad = Vec::new();
        for (i, (offset, cookie)) in offsets.iter().zip(cookies.iter()).enumerate() {
            if self.poison.contains(offset) {
                bad.push(i);
                continue;
            }
            let Ok(cookie) = u32::try_from(*cookie) else {
                // Wider-than-u32 cookies are a userspace bug: loud
                // drop, never silent truncation (kernel parity).
                self.dropfail = self.dropfail.saturating_add(1);
                bad.push(i);
                continue;
            };
            self.attached.insert(cookie, (path.to_string(), *offset));
            links.push(FakeLink {
                cookie,
                path: path.to_string(),
                offset: *offset,
            });
        }
        bad.sort_unstable();
        (links, bad)
    }

    fn open_window(
        &mut self,
        tgid: u64,
        generation: u32,
        start_ns: u64,
        deadline_ns: u64,
    ) -> anyhow::Result<()> {
        if start_ns >= deadline_ns {
            anyhow::bail!("empty count window: start {start_ns} >= deadline {deadline_ns}");
        }
        self.tgid = tgid;
        self.generation = generation;
        self.start_ns = start_ns;
        self.deadline_ns = deadline_ns;
        self.open = true;
        self.programmed
            .push((tgid, generation, start_ns, deadline_ns));
        Ok(())
    }

    fn set_generation(&mut self, generation: u32) -> anyhow::Result<()> {
        self.generation = generation;
        Ok(())
    }

    fn close_window(&mut self) -> anyhow::Result<()> {
        self.open = false;
        Ok(())
    }

    fn drain(&mut self, _deadline: Option<Instant>) -> anyhow::Result<DrainedCounts> {
        // Host double drains instantly; grace-expiry shortfall is
        // scripted through `set_shortfall` instead.
        let mut rows: Vec<(u64, CountValue)> = self
            .ledger
            .iter()
            .filter(|(_, v)| v.count > 0)
            .map(|((cookie, generation), v)| (make_key(*cookie, *generation), *v))
            .collect();
        rows.sort_by_key(|(k, _)| *k);
        let shortfall = std::mem::take(&mut self.shortfall_hook);
        Ok(DrainedCounts {
            rows,
            dropfail_total: self.dropfail,
            shortfall,
        })
    }
}

/// Production backend: drives the real `osslscope-count` maps and
/// multi-links through aya (needs BPF caps). Attach reuses
/// [`plan::bisect_attach`] so one kernel-refused offset cannot sink
/// good siblings; drains are the same bounded per-CPU iteration the
/// capture engine uses, minus routing (the session routes).
pub struct LiveBackend {
    loaded: crate::loader::Loaded,
    pid: u32,
}

impl LiveBackend {
    pub fn new(loaded: crate::loader::Loaded, pid: u32) -> Self {
        Self { loaded, pid }
    }

    fn program(&self, map: &str, key: u32, value: &[u8]) -> anyhow::Result<()> {
        use anyhow::Context as _;
        use std::os::fd::AsRawFd as _;
        let fd = self
            .loaded
            .maps
            .get(map)
            .context(format!("no {map} map"))?
            .as_raw_fd();
        ossl_bpf_sys::map_update_elem(fd, &key.to_le_bytes(), value, ossl_bpf_sys::BPF_ANY)
            .with_context(|| format!("program {map}[{key}]"))?;
        Ok(())
    }
}

impl CountBackend for LiveBackend {
    type Link = std::os::fd::OwnedFd;

    fn attach(
        &mut self,
        path: &str,
        offsets: &[u64],
        cookies: &[u64],
    ) -> (Vec<Self::Link>, Vec<usize>) {
        use std::os::fd::AsRawFd as _;
        let Some(prog) = self.loaded.progs.get("count_entry") else {
            return (Vec::new(), (0..offsets.len()).collect());
        };
        let prog_fd = prog.as_raw_fd();
        let pid = self.pid;
        let sites: Vec<(u64, u64)> = offsets
            .iter()
            .zip(cookies.iter())
            .map(|(o, c)| (*o, *c))
            .collect();
        plan::bisect_attach(
            &|slice| {
                let offs: Vec<u64> = slice.iter().map(|t| t.0).collect();
                let cks: Vec<u64> = slice.iter().map(|t| t.1).collect();
                plan::attach_group(prog_fd, pid, path, &offs, &cks)
            },
            &sites,
        )
    }

    fn open_window(
        &mut self,
        tgid: u64,
        generation: u32,
        start_ns: u64,
        deadline_ns: u64,
    ) -> anyhow::Result<()> {
        if start_ns >= deadline_ns {
            anyhow::bail!("empty count window: start {start_ns} >= deadline {deadline_ns}");
        }
        self.program("GEN", 0, &generation.to_le_bytes())?;
        self.program("TARGET", 0, &tgid.to_le_bytes())?;
        // The kernel WINDOW admission interval lands with the
        // count-window ABI (T07 commit 2); until then the userspace
        // `close_window` (`TARGET=0`) is the sole deadline on the
        // live path. The fake backend enforces the full interval
        // from commit 1.
        let _ = (start_ns, deadline_ns);
        Ok(())
    }

    fn set_generation(&mut self, generation: u32) -> anyhow::Result<()> {
        self.program("GEN", 0, &generation.to_le_bytes())
    }

    fn close_window(&mut self) -> anyhow::Result<()> {
        self.program("TARGET", 0, &0u64.to_le_bytes())
    }

    fn drain(&mut self, deadline: Option<Instant>) -> anyhow::Result<DrainedCounts> {
        // Bounded like the capture engine's drain (same code shape):
        // past the deadline the rest counts exactly as shortfall
        // rather than abandoned — exactness beats grace to the
        // microsecond, and the first sub-64 slice may fold past an
        // already-expired deadline by design. Shortfall is exact
        // bookkeeping, not a sampling artifact.
        use anyhow::Context as _;
        use aya::maps::{Map, MapData};
        let dup = |name: &str| -> anyhow::Result<Map> {
            let fd = self
                .loaded
                .maps
                .get(name)
                .context(format!("no {name} map"))?
                .try_clone()?;
            let data = MapData::from_fd(fd).map_err(|e| anyhow::anyhow!("{name} mapdata: {e}"))?;
            Map::from_map_data(data).map_err(|e| anyhow::anyhow!("{name} map: {e}"))
        };
        let mut out = DrainedCounts {
            rows: Vec::new(),
            dropfail_total: 0,
            shortfall: 0,
        };
        let counts = dup("COUNTS")?;
        let map = aya::maps::PerCpuHashMap::<_, u64, CountValue>::try_from(counts)
            .map_err(|e| anyhow::anyhow!("COUNTS typed: {e}"))?;
        let mut n = 0u64;
        let mut expired = false;
        for r in map.iter() {
            let (key, per_cpu) = r.map_err(|e| anyhow::anyhow!("COUNTS iter: {e}"))?;
            n += 1;
            if expired {
                // Keys-only tail: counted exactly, never folded, and
                // never recorded — grace expiry happens at the final
                // drain only, so no later drain re-adds.
                out.shortfall += 1;
                continue;
            }
            if n % 64 == 0 {
                if let Some(d) = deadline {
                    if Instant::now() >= d {
                        expired = true;
                        out.shortfall += 1;
                        continue;
                    }
                }
            }
            let mut total = CountValue::default();
            for v in per_cpu.iter() {
                total.fold(v);
            }
            if total.count == 0 {
                continue;
            }
            out.rows.push((key, total));
        }
        let drops = dup("DROPFAIL")?;
        let drops = aya::maps::PerCpuArray::<_, u64>::try_from(drops)
            .map_err(|e| anyhow::anyhow!("DROPFAIL typed: {e}"))?;
        let mut total_drop = 0u64;
        for r in drops.iter() {
            let per_cpu = r.map_err(|e| anyhow::anyhow!("DROPFAIL iter: {e}"))?;
            total_drop += per_cpu.iter().sum::<u64>();
        }
        out.dropfail_total = total_drop;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_indices_normalize_defensively() {
        // Order, duplicates and out-of-range positions never
        // misread: only in-range refused positions flag.
        assert_eq!(normalize_bad(vec![], 3), vec![false, false, false]);
        assert_eq!(normalize_bad(vec![2, 0, 2], 3), vec![true, false, true]);
        assert_eq!(normalize_bad(vec![9], 1), vec![false]);
        assert_eq!(normalize_bad(vec![0, 1, 2], 2), vec![true, true]);
    }

    #[test]
    fn loss_merge_sums_and_keeps_gaps() {
        let mut store = Vec::new();
        let loss = |v| {
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::Drain,
                v,
            )
        };
        merge_counter(&mut store, loss(3));
        merge_counter(&mut store, loss(0));
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].value, 3);
        // A clean delta never erases the earlier gap.
        merge_counter(&mut store, loss(4));
        assert_eq!(store[0].value, 7);
        // A different source is a different counter.
        merge_counter(
            &mut store,
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::KernelMap,
                1,
            ),
        );
        assert_eq!(store.len(), 2);
    }
}
