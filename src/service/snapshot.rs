//! SPDX-License-Identifier: GPL-3.0-or-later
//! §11.1 per-window document producer: non-destructive snapshot
//! deltas, same-site cross-member merge, `FinalizeInput` assembly,
//! loss set-difference, and window policy evaluation.
//!
//! The engine query surface is the `SnapshotSource` trait (T7.4
//! names/types): cumulative per-site counts, count-generation
//! markers, incarnation ledgers, session tallies, sealed in-window
//! hit bounds, and close-point gauges — all as monotone cumulative
//! values plus sealed pairs. Deltas derive ONLY from the stored
//! open/close pair, never from a re-read. Absent ⟺ zero (mid-window
//! admits, CPUs online at close but absent at open).
//!
//! T7.4 conformance judgments (see the T7.4 report): `corpse_wait`
//! is always `None` (no owned-corpse retirement in service
//! windows); retired members' window contributors carry L2-unknown
//! bounds (no sealed in-window bounds exist for dead members — the
//! sealed rows ride verbatim in `crypto_watch[]`); still-open
//! members contribute EMPTY api deltas (provider aggregates are not
//! readable without finishing sessions, which W4 forbids);
//! `traversal` is null; per-member openssl is `unknown()` (no
//! snapshot version source — same as the finish path); empty-window
//! targets fall back along listed → run-observed → selection pid.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, CaptureWindow, CounterKind,
    CounterSource, CounterUnits, DispositionRecord, EngineObservation, EngineWindow, ExpectedScope,
    FencedGeneration, FinalizeInput, GapCounter, LegacyCallPartition, ObjectId, ObjectRecord,
    OpensslVersion, ScopeCoverage, SiteExecution, SiteKey, TargetRecord,
};
use crate::policy::{PolicyOutcome, PolicyRule};
use crate::service::envelope::{
    ContributorEntry, MemberEntry, SiteRef, SiteSourceEntry, UNKNOWN_FIRST_NS, UNKNOWN_LAST_NS,
    WindowSpan,
};
use crate::service::state::{PolicyIdentity, RunId};

/// Cumulative per-(site-cookie, count-generation) counts + the
/// sealed in-window hit bounds (the epoch-N pair unioned over the
/// member's CPUs; `None` ⟺ every CPU's pair is empty).
#[derive(Debug, Clone)]
pub struct SiteCounts {
    pub cookie: u32,
    pub generation: u32,
    pub calls: u64,
    pub sealed_bounds: Option<(u64, u64)>,
}

/// Live-admission binding: cookie → site identity + candidates.
#[derive(Debug, Clone)]
pub struct SiteBinding {
    pub cookie: u32,
    pub site: SiteKey,
    pub candidates: Vec<CandidateIdentity>,
    pub coverage: CandidateCoverage,
    pub installed_at: Option<u64>,
}

/// Cumulative incarnation loss ledger (LossSummary shape, §4.1).
#[derive(Debug, Clone, Default)]
pub struct LossView {
    pub loss: u64,
    pub deferred_ticks: u64,
    pub deferred_first: u64,
    pub deferred_last: u64,
    pub lost: Vec<LostView>,
    pub coalesced: u64,
}

/// One cumulative lost interval `[start_tick, end_tick)`.
#[derive(Debug, Clone)]
pub struct LostView {
    pub start_tick: u64,
    pub end_tick: u64,
    pub cause: &'static str,
}

/// Cumulative ENGINE-plane row (fold state).
#[derive(Debug, Clone)]
pub struct EngineRow {
    pub key: SiteKey,
    pub generation: u64,
    pub entrypoint: u16,
    pub calls: u64,
}

/// One member's cumulative snapshot state.
#[derive(Debug, Clone)]
pub struct MemberView {
    pub pid: u32,
    pub starttime: u64,
    pub segment: u64,
    pub image_epoch: u64,
    pub sites: Vec<SiteCounts>,
    /// Current count-generation marker (GEN).
    pub gen_marker: u32,
    pub bindings: Vec<SiteBinding>,
    pub loss: LossView,
    /// Cumulative session ring tallies.
    pub ring: [u64; 8],
    /// Cumulative gap tallies (fold gaps).
    pub gaps: Vec<GapCounter>,
    pub engine: Vec<EngineRow>,
    /// Close-point gauges (discovered, attached).
    pub gauges: (u64, u64),
    pub target: TargetRecord,
}

/// Run-level cumulative lifecycle lanes (RunState).
#[derive(Debug, Clone, Default)]
pub struct RunTallies {
    pub scan_loss: u64,
    pub signal_dropped: u64,
    pub prefix_unwitnessed: u64,
    pub drain_pending: u64,
}

/// One boundary snapshot: the stored open/close pair input. `stable`
/// is false when any CPU exhausted the 64-retry seqlock bound or was
/// unreadable mid-pass (⟹ `snapshot_unstable` PARTIAL via the
/// existing `forces_partial` mechanism).
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Close: the first monotonic read after the last epoch flip.
    /// Open: the acquisition read instant.
    pub at_ns: u64,
    pub stable: bool,
    pub members: Vec<MemberView>,
    pub run: RunTallies,
    pub polling: bool,
}

/// The additive engine query surface (§11.1). `flip_to` flips every
/// member's bound-epoch to the closing window's seq before reading
/// (close seal); `None` reads without flipping (run-open
/// acquisition). The snapshot OWNS its copies (deep copy at query).
pub trait SnapshotSource {
    fn snapshot(&mut self, flip_to: Option<u64>) -> Snapshot;
}

/// Window production context (coordinator-side facts).
#[derive(Debug, Clone)]
pub struct WindowCtx {
    pub seq: u64,
    pub generation: u64,
    pub run_id: RunId,
    pub span: WindowSpan,
    /// Tick span from effective-ns bounds via `Start.run_origin_ns`.
    pub open_tick: u64,
    pub close_tick: u64,
    /// Active policy rules (empty when observe-only).
    pub policy_rules: Vec<PolicyRule>,
    pub active_policy: Option<PolicyIdentity>,
    /// Coordinator-recorded FIRST fatal this window (event order),
    /// else None. Members never contribute fatal.
    pub fatal: Option<crate::evidence::FatalKind>,
    /// Least (pid, starttime) over the RUN's observed members (the
    /// empty-window target fallback).
    pub run_member_floor: Option<(u32, u64)>,
    /// First selection pid (the last-resort target fallback).
    pub selection_pid: u32,
}

/// Produced window: the finalized document + envelope provenance.
#[derive(Debug, Clone)]
pub struct Produced {
    pub document: CaptureDocument,
    pub members: Vec<MemberEntry>,
    pub site_sources: Vec<SiteSourceEntry>,
    /// Policy outcome for the §7.3 fold.
    pub outcome: PolicyOutcome,
    /// True when either endpoint was unstable.
    pub unstable: bool,
}

/// One merged contributor before row assembly.
#[derive(Debug, Clone)]
struct Contributor {
    segment: u64,
    image_epoch: u64,
    calls: u64,
    bounds: Option<(u64, u64)>,
    candidates: Vec<CandidateIdentity>,
    coverage: CandidateCoverage,
    installed_at: Option<u64>,
    /// Current-side (window `sites`) vs fenced-side placement vote.
    current_side: bool,
}

/// Produce one window from the stored open/close pair (§11.1).
/// `sealed` maps retired segments to their consumed seals
/// (verbatim sealed document + seal-record identity, parsed from
/// the admitted `ProcessObservation`s — staged or spilled).
pub fn produce(
    open: &Snapshot,
    close: &Snapshot,
    sealed: &HashMap<u64, SealedRetirement>,
    ctx: &WindowCtx,
) -> Produced {
    let unstable = !open.stable || !close.stable;
    let open_members = index_members(&open.members);
    let close_members = index_members(&close.members);

    // Per-member deltas keyed by merged row (SiteKey, generation).
    let mut rows: BTreeMap<(SiteKey, u32), Vec<Contributor>> = BTreeMap::new();
    let mut member_facts: BTreeMap<(u32, u64, u64), MemberFact> = BTreeMap::new();
    let mut extra_counters: Vec<GapCounter> = Vec::new();

    // Still-open members: close − open (saturating) + clamp.
    for (id, cm) in &close_members {
        let om = open_members.get(id).copied();
        let mut fact = MemberFact::new(cm, false);
        let open_sites = om.map(|m| index_sites(&m.sites)).unwrap_or_default();
        for sc in &cm.sites {
            let open_calls = open_sites
                .get(&(sc.cookie, sc.generation))
                .copied()
                .unwrap_or(0);
            let delta = sc.calls.saturating_sub(open_calls);
            fact.clamp += open_calls.saturating_sub(sc.calls);
            if delta == 0 {
                continue;
            }
            let binding = cm.bindings.iter().find(|b| b.cookie == sc.cookie);
            let (site, candidates, installed_at, coverage) = match binding {
                Some(b) => (
                    b.site.clone(),
                    b.candidates.clone(),
                    b.installed_at,
                    b.coverage,
                ),
                // Unbound cookie: the site key is unknown — the row
                // still counts (calls are definite) under a
                // documented unknown key, never dropped.
                None => (
                    SiteKey {
                        object: crate::evidence::ObjectId(format!("unknown-cookie-{}", sc.cookie)),
                        device: 0,
                        inode: 0,
                        offset: 0,
                    },
                    Vec::new(),
                    None,
                    CandidateCoverage::Unknown,
                ),
            };
            fact.calls += delta;
            rows.entry((site, sc.generation))
                .or_default()
                .push(Contributor {
                    segment: cm.segment,
                    image_epoch: cm.image_epoch,
                    calls: delta,
                    bounds: sc.sealed_bounds,
                    candidates,
                    coverage,
                    installed_at,
                    current_side: sc.generation == cm.gen_marker,
                });
        }
        // Loss intersection + gap/engine deltas for this member.
        let loss = member_loss(om, cm, ctx.open_tick, ctx.close_tick);
        fact.loss = loss;
        fact.gap_delta = gap_deltas(om.map(|m| &m.gaps), &cm.gaps);
        fact.engine_delta = engine_deltas(om.map(|m| &m.engine), &cm.engine);
        member_facts.insert(*id, fact);
    }

    // Retired members: sealed − open per (SiteKey, generation);
    // bounds L2-unknown (no sealed in-window bounds exist for dead
    // members — the sealed rows ride verbatim in `crypto_watch[]`).
    // Absent-open (admitted after open, retired before close — R1
    // finding 4): identity from the seal record, open ⟺ 0 (the
    // module's Absent ⟺ zero rule), clamp 0 (nothing to clamp
    // against), candidates honestly Unknown (no live-admission
    // binding was ever snapshotted).
    for (seg, seal) in sealed {
        let doc = &seal.doc;
        let found = open_members
            .iter()
            .find(|(_, m)| m.segment == *seg)
            .map(|(id, _)| *id);
        let id = found.unwrap_or((seal.pid, seal.starttime, *seg));
        let om = found.map(|id| &open_members[&id]);
        let open_by_key: HashMap<(SiteKey, u32), u64> =
            om.map(|o| open_keyed(o)).unwrap_or_default();
        let mut fact = member_facts.remove(&id).unwrap_or_else(|| match om {
            Some(o) => MemberFact::sealed(o),
            None => MemberFact::sealed_absent(seal.image_epoch, doc.target.clone()),
        });
        fact.retired = true;
        let epoch = om.map(|o| o.image_epoch).unwrap_or(seal.image_epoch);
        for (key, sealed_calls, sealed_side_current) in sealed_rows(doc) {
            let open_calls = open_by_key.get(&key).copied().unwrap_or(0);
            let delta = sealed_calls.saturating_sub(open_calls);
            fact.clamp += open_calls.saturating_sub(sealed_calls);
            if delta == 0 {
                continue;
            }
            let binding = om.and_then(|o| {
                o.bindings.iter().find(|b| {
                    let k = (b.site.clone(), key.1);
                    k == key
                })
            });
            let (candidates, installed_at, coverage) = match binding {
                Some(b) => (b.candidates.clone(), b.installed_at, b.coverage),
                None => (Vec::new(), None, CandidateCoverage::Unknown),
            };
            fact.calls += delta;
            // Sealed disposition rides the envelope member when this
            // window retires exactly one member (set below).
            fact.sealed_disposition = doc.disposition;
            rows.entry(key).or_default().push(Contributor {
                segment: *seg,
                image_epoch: epoch,
                calls: delta,
                bounds: None,
                candidates,
                coverage,
                installed_at,
                current_side: sealed_side_current,
            });
        }
        // Certified sealed ENGINE merge (R1 finding 4): the seal's
        // `engine_observations` (finish-built, `InWindow`) close at
        // the sealed totals minus the open rows (absent-open ⟺
        // full sealed calls). Zero deltas drop (same rule as the
        // live `engine_deltas`); windows merge weakest below.
        let open_engines: &[EngineRow] = om.map(|o| o.engine.as_slice()).unwrap_or(&[]);
        for obs in doc.engine_observations.iter() {
            let oc = open_engines
                .iter()
                .find(|r| {
                    r.key == obs.key
                        && r.generation == obs.generation
                        && r.entrypoint == obs.entrypoint
                })
                .map(|r| r.calls)
                .unwrap_or(0);
            let calls = obs.calls.saturating_sub(oc);
            if calls == 0 {
                continue;
            }
            fact.engine_delta.push(EngineDelta {
                key: obs.key.clone(),
                generation: obs.generation,
                entrypoint: obs.entrypoint,
                calls,
                window: obs.window,
            });
        }
        // Retired loss: sealed totals ARE the close (the seal's
        // `ProcessObservation.loss` rides verbatim; the window
        // projection closes at the sealed ledger — sourced from the
        // sealed doc is impossible (docs carry no ledger), so the
        // window carries the open→seal SATURATING deltas of the
        // ledger scalars as zero-or-known: the ledger AT SEAL is
        // unreadable post-hoc — the honest projection is the
        // open-anchored unknown: loss intervals ride the SEALED
        // record verbatim, and the window loss covers only what the
        // open snapshot proves. Concretely: empty window loss (the
        // seal's loss is certified in `crypto_watch[]`, never
        // re-derived here).
        member_facts.insert(id, fact);
    }

    // Vanished without a seal: unquantified-loss marker (the
    // `SessionGap{finalization_failed}` rides `crypto_watch[]`).
    for (id, om) in &open_members {
        if !close_members.contains_key(id) {
            let retired_here = sealed.contains_key(&om.segment);
            if !retired_here {
                extra_counters.push(GapCounter {
                    name: "snapshot.member_unsealed".to_string(),
                    kind: CounterKind::Loss,
                    units: CounterUnits::Calls,
                    source: CounterSource::Drain,
                    value: 0,
                });
                // Listed with zero calls so the retirement attempt
                // stays visible in `members[]`.
                let mut fact = MemberFact::sealed(om);
                fact.retired = true;
                member_facts.insert(*id, fact);
            }
        }
    }

    // Merge rows (deterministic): calls Σ; bounds min/max over
    // KNOWN (L2 — unknown never merged); candidates union/dedupe/
    // sorted; coverage weakest then downgraded to ≤
    // AmbiguousComplete; installed_at min present.
    let mut sites: Vec<SiteExecution> = Vec::new();
    let mut fenced: BTreeMap<u32, Vec<SiteExecution>> = BTreeMap::new();
    let mut site_sources: Vec<SiteSourceEntry> = Vec::new();
    for ((site, generation), contributors) in &rows {
        let calls: u64 = contributors.iter().map(|c| c.calls).sum();
        if calls == 0 {
            continue;
        }
        let known: Vec<(u64, u64)> = contributors.iter().filter_map(|c| c.bounds).collect();
        let hit_interval_known = !known.is_empty();
        let (first_ns, last_ns) = if hit_interval_known {
            (
                known.iter().map(|b| b.0).min().unwrap(),
                known.iter().map(|b| b.1).max().unwrap(),
            )
        } else {
            (UNKNOWN_FIRST_NS, UNKNOWN_LAST_NS)
        };
        let mut candidates: Vec<CandidateIdentity> = contributors
            .iter()
            .flat_map(|c| c.candidates.clone())
            .collect();
        candidates.sort();
        candidates.dedup();
        let weakest = contributors
            .iter()
            .map(|c| c.coverage)
            .max()
            .unwrap_or(CandidateCoverage::Unknown);
        let coverage = if weakest == CandidateCoverage::Complete {
            CandidateCoverage::AmbiguousComplete
        } else {
            weakest
        };
        let installed_at = contributors.iter().filter_map(|c| c.installed_at).min();
        let row = SiteExecution {
            site: site.clone(),
            generation: *generation,
            candidates,
            candidates_coverage: coverage,
            calls,
            first_ns,
            last_ns,
            installed_at,
        };
        // Placement: `sites` iff ALL contributors current-side, else
        // the fenced bucket (fail-closed toward fenced).
        if contributors.iter().all(|c| c.current_side) {
            sites.push(row);
        } else {
            fenced.entry(*generation).or_default().push(row);
        }
        site_sources.push(SiteSourceEntry {
            site: SiteRef {
                object: site.object.clone(),
                device: site.device,
                inode: site.inode,
                offset: site.offset,
            },
            generation: *generation,
            calls,
            hit_interval_known,
            contributors: contributors
                .iter()
                .map(|c| ContributorEntry {
                    segment: c.segment,
                    image_epoch: c.image_epoch,
                    calls: c.calls,
                    first_ns: c.bounds.map(|b| b.0),
                    last_ns: c.bounds.map(|b| b.1),
                    bounds_known: c.bounds.is_some(),
                })
                .collect(),
        });
    }
    sites.sort_by(|a, b| (&a.site, a.generation).cmp(&(&b.site, b.generation)));

    // members[]: listed iff delta calls > 0 OR retired this window.
    let retired_here: Vec<(u32, u64, u64)> = member_facts
        .iter()
        .filter(|(_, f)| f.retired)
        .map(|(id, _)| *id)
        .collect();
    let single_disposition = if retired_here.len() == 1 {
        member_facts[&retired_here[0]].sealed_disposition
    } else {
        None
    };
    let mut members: Vec<MemberEntry> = Vec::new();
    for (id, fact) in &member_facts {
        // Listed iff delta calls > 0 OR retired this window OR
        // clamp > 0 (L3: clamps are residual-formula inputs — a
        // zero-delta clamped member contributes no rows but its
        // note must survive).
        if fact.calls == 0 && !fact.retired && fact.clamp == 0 {
            continue;
        }
        members.push(MemberEntry {
            pid: id.0,
            starttime: id.1,
            segment: id.2,
            image_epoch: fact.image_epoch,
            target: fact.target.clone(),
            openssl: OpensslVersion::unknown(),
            disposition: if retired_here.len() == 1 && retired_here[0] == *id {
                fact.sealed_disposition
            } else {
                None
            },
            retired: fact.retired,
            clamp: fact.clamp,
            loss: fact.loss.clone(),
        });
    }
    members.sort_by_key(|m| (m.pid, m.starttime, m.segment));

    // Document assembly (frozen field by field, §11.1).
    let window = CaptureWindow {
        requested_start_ns: ctx.span.requested_start_ns,
        requested_end_ns: ctx.span.requested_end_ns,
        effective_start_ns: ctx.span.effective_start_ns,
        effective_end_ns: ctx.span.effective_end_ns,
        signal_cut: ctx.span.signal_cut,
        count_admission: None,
    };
    let mut counters = extra_counters;
    // Per-member gap deltas merged by (name, kind, units, source).
    let mut gap_merge: BTreeMap<(String, CounterKind, CounterUnits, CounterSource), u64> =
        BTreeMap::new();
    for fact in member_facts.values() {
        for g in &fact.gap_delta {
            let slot = gap_merge
                .entry((g.name.clone(), g.kind, g.units, g.source))
                .or_default();
            *slot = (*slot).saturating_add(g.value);
        }
    }
    for ((name, kind, units, source), value) in gap_merge {
        counters.push(GapCounter {
            name,
            kind,
            units,
            source,
            value,
        });
    }
    // Run-lane deltas (existing `lifecycle.*` names, delta > 0 only)
    // + `polling_fallback` close value.
    lane_counter(
        &mut counters,
        "lifecycle.scan_loss",
        close.run.scan_loss.saturating_sub(open.run.scan_loss),
    );
    lane_counter(
        &mut counters,
        "lifecycle.signal_dropped",
        close
            .run
            .signal_dropped
            .saturating_sub(open.run.signal_dropped),
    );
    lane_counter(
        &mut counters,
        "lifecycle.signal_prefix_unwitnessed",
        close
            .run
            .prefix_unwitnessed
            .saturating_sub(open.run.prefix_unwitnessed),
    );
    lane_counter(
        &mut counters,
        "lifecycle.drain_pending",
        close
            .run
            .drain_pending
            .saturating_sub(open.run.drain_pending),
    );
    if close.polling {
        counters.push(GapCounter {
            name: "lifecycle.polling_fallback".to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Events,
            source: CounterSource::Lifecycle,
            value: 1,
        });
    }
    if unstable {
        counters.push(GapCounter {
            name: "snapshot_unstable".to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Events,
            source: CounterSource::Drain,
            value: 1,
        });
    }
    if ctx.span.accum_cut {
        // PARTIAL by construction (PRD §6) via the existing
        // `forces_partial` mechanism (no new COMPLETE witnesses).
        counters.push(GapCounter {
            name: "window.accum_cut".to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Events,
            source: CounterSource::Drain,
            value: 1,
        });
    }

    // Target: single contributor's record, else least
    // (pid, starttime); empty windows fall back along run-observed
    // → selection pid (always REAL — never `unknown()`).
    let target = if members.len() == 1 {
        members[0].target.clone()
    } else if !members.is_empty() {
        // Least (pid, starttime) contributor's record.
        members
            .iter()
            .min_by_key(|m| (m.pid, m.starttime))
            .unwrap()
            .target
            .clone()
    } else if let Some((pid, _)) = ctx.run_member_floor {
        TargetRecord::new(pid, "unknown".to_string(), String::new(), String::new())
    } else {
        TargetRecord::new(
            ctx.selection_pid,
            "unknown".to_string(),
            String::new(),
            String::new(),
        )
    };

    // Coverage: per-member CLOSE-POINT gauges, concatenated, NEVER
    // differenced (finish-path shape).
    let coverage: Vec<ScopeCoverage> = member_facts
        .iter()
        .filter(|(_, f)| f.calls > 0 || f.retired || f.clamp > 0)
        .map(|(_, f)| ScopeCoverage {
            scope: "focused.execution".to_string(),
            expected: ExpectedScope::Unknown,
            discovered: f.gauges.0,
            attached: f.gauges.1,
        })
        .collect();

    // Objects: union by full-record equality (finish-path shape).
    let mut objects: Vec<ObjectRecord> = Vec::new();
    {
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<(ObjectId, u64, u64)> = BTreeSet::new();
        let mut push = |id: ObjectId, device: u64, inode: u64| {
            if seen.insert((id.clone(), device, inode)) {
                objects.push(ObjectRecord {
                    id,
                    device,
                    inode,
                    display_locator: "unknown".to_string(),
                });
            }
        };
        for row in sites.iter().chain(fenced.values().flatten()) {
            push(row.site.object.clone(), row.site.device, row.site.inode);
            for c in &row.candidates {
                push(c.provider.clone(), 0, 0);
            }
        }
    }

    // Legacy partition: the frozen lane rules from `project`
    // (empty candidates → unfenced_tails, else shared_ambiguous).
    let mut legacy_partition = LegacyCallPartition::default();
    for row in sites.iter().chain(fenced.values().flatten()) {
        if row.candidates.is_empty() {
            legacy_partition.unfenced_tails =
                legacy_partition.unfenced_tails.saturating_add(row.calls);
        } else {
            legacy_partition.shared_ambiguous =
                legacy_partition.shared_ambiguous.saturating_add(row.calls);
        }
    }

    // Engine observations merged by (key, generation, entrypoint):
    // calls Σ, window weakest (Untimed > PreWindow > InWindow —
    // live rows are InWindow-only; sealed rows ride their sealed
    // window, certified `InWindow` by the finish builder).
    let mut engine_merge: BTreeMap<(SiteKey, u64, u16), (u64, EngineWindow)> = BTreeMap::new();
    for fact in member_facts.values() {
        for e in &fact.engine_delta {
            let slot = engine_merge
                .entry((e.key.clone(), e.generation, e.entrypoint))
                .or_insert((0, EngineWindow::InWindow));
            slot.0 = slot.0.saturating_add(e.calls);
            slot.1 = weakest_window(slot.1, e.window);
        }
    }
    let engine_observations: Vec<EngineObservation> = engine_merge
        .into_iter()
        .map(
            |((key, generation, entrypoint), (calls, window))| EngineObservation {
                key,
                generation,
                entrypoint,
                calls,
                window,
            },
        )
        .collect();

    // api_activity: retired-verbatim rows + open-empty, concatenated
    // in segment order then stable-sorted by serialized bytes
    // (duplicates preserved).
    let mut api_rows: Vec<(u64, crate::api_activity::ApiActivityRow)> = Vec::new();
    for (id, fact) in &member_facts {
        if fact.retired {
            if let Some(seal) = sealed.get(&id.2) {
                for row in &seal.doc.api_activity {
                    api_rows.push((id.2, row.clone()));
                }
            }
        }
    }
    api_rows.sort_by_key(|(seg, _)| *seg);
    let mut api_activity: Vec<crate::api_activity::ApiActivityRow> =
        api_rows.into_iter().map(|(_, r)| r).collect();
    api_activity.sort_by_cached_key(|r| serde_json::to_vec(r).unwrap_or_default());

    let input = FinalizeInput {
        corpse_wait: None,
        window,
        sites,
        fenced: fenced
            .into_iter()
            .map(|(generation, sites)| FencedGeneration { generation, sites })
            .collect(),
        objects,
        coverage,
        counters,
        fatal: ctx.fatal.clone(),
        target,
        openssl: OpensslVersion::unknown(),
        disposition: single_disposition,
        policy: None,
        legacy_partition,
        engine_observations,
        traversal: None,
    };
    let mut document = crate::evidence::finalize(input);
    document.api_activity = api_activity;

    // Policy evaluation under the window's active policy (no
    // cross-window verdict state; segment boundaries never carry
    // verdicts). Observe-only ⟹ the `report`-path map (fatal →
    // NoVerdict, else Pass — the code truth, report.rs:230-232).
    let outcome = if ctx.policy_rules.is_empty() {
        document.policy = None;
        if matches!(document.status, crate::evidence::Completeness::Fatal { .. }) {
            PolicyOutcome::NoVerdict
        } else {
            PolicyOutcome::Pass
        }
    } else {
        let (verdict, checked) = crate::check::assemble_checked_document(
            &ctx.policy_rules,
            document,
            &serde_json::Value::Null,
        );
        document = checked;
        verdict.overall()
    };

    Produced {
        document,
        members,
        site_sources,
        outcome,
        unstable,
    }
}

fn weakest_window(a: EngineWindow, b: EngineWindow) -> EngineWindow {
    use EngineWindow::*;
    match (a, b) {
        (Untimed, _) | (_, Untimed) => Untimed,
        (PreWindow, _) | (_, PreWindow) => PreWindow,
        (InWindow, InWindow) => InWindow,
    }
}

fn lane_counter(counters: &mut Vec<GapCounter>, name: &str, delta: u64) {
    if delta > 0 {
        counters.push(GapCounter {
            name: name.to_string(),
            kind: CounterKind::Loss,
            units: CounterUnits::Events,
            source: CounterSource::Lifecycle,
            value: delta,
        });
    }
}

/// Per-member accumulation across the producer.
#[derive(Debug, Clone)]
struct MemberFact {
    image_epoch: u64,
    target: TargetRecord,
    gauges: (u64, u64),
    calls: u64,
    clamp: u64,
    retired: bool,
    loss: crate::service::envelope::MemberWindowLoss,
    gap_delta: Vec<GapCounter>,
    engine_delta: Vec<EngineDelta>,
    sealed_disposition: Option<DispositionRecord>,
}

#[derive(Debug, Clone)]
struct EngineDelta {
    key: SiteKey,
    generation: u64,
    entrypoint: u16,
    calls: u64,
    window: EngineWindow,
}

impl MemberFact {
    fn new(m: &MemberView, retired: bool) -> Self {
        Self {
            image_epoch: m.image_epoch,
            target: m.target.clone(),
            gauges: m.gauges,
            calls: 0,
            clamp: 0,
            retired,
            loss: crate::service::envelope::MemberWindowLoss::default(),
            gap_delta: Vec::new(),
            engine_delta: Vec::new(),
            sealed_disposition: None,
        }
    }

    fn sealed(m: &MemberView) -> Self {
        Self::new(m, true)
    }

    /// Absent-open seal (R1 finding 4): identity from the seal
    /// record (image epoch + sealed target); gauges unknown
    /// (no close point was ever snapshotted).
    fn sealed_absent(image_epoch: u64, target: TargetRecord) -> Self {
        Self {
            image_epoch,
            target,
            gauges: (0, 0),
            calls: 0,
            clamp: 0,
            retired: true,
            loss: crate::service::envelope::MemberWindowLoss::default(),
            gap_delta: Vec::new(),
            engine_delta: Vec::new(),
            sealed_disposition: None,
        }
    }
}

fn index_members(members: &[MemberView]) -> BTreeMap<(u32, u64, u64), &MemberView> {
    members
        .iter()
        .map(|m| ((m.pid, m.starttime, m.segment), m))
        .collect()
}

fn index_sites(sites: &[SiteCounts]) -> HashMap<(u32, u32), u64> {
    sites
        .iter()
        .map(|s| ((s.cookie, s.generation), s.calls))
        .collect()
}

/// A consumed retirement seal: the verbatim sealed document plus
/// the seal record's identity (incarnation + image epoch — the
/// absent-open member's ONLY identity source, R1 finding 4).
#[derive(Debug, Clone)]
pub struct SealedRetirement {
    pub doc: CaptureDocument,
    pub pid: u32,
    pub starttime: u64,
    pub image_epoch: u64,
}

/// Extract one seal from a `process_observation` envelope value
/// (`None` ⟺ not a seal / malformed — the record still rides
/// `crypto_watch[]` verbatim; only seal consumption skips).
fn seal_of(v: &serde_json::Value) -> Option<(u64, SealedRetirement)> {
    if v.get("kind").and_then(|k| k.as_str()) != Some("process_observation") {
        return None;
    }
    let seg = v.get("segment")?.as_u64()?;
    let doc_v = v.get("document")?;
    let doc: CaptureDocument = serde_json::from_value(doc_v.clone()).ok()?;
    let incarnation = v.get("incarnation")?;
    let pid: u32 = incarnation.get("pid")?.as_u64()?.try_into().ok()?;
    let starttime = incarnation.get("starttime")?.as_u64()?;
    let image_epoch = v.get("image_epoch")?.as_u64()?;
    Some((
        seg,
        SealedRetirement {
            doc,
            pid,
            starttime,
            image_epoch,
        },
    ))
}

/// Extract retirement seals from staged AND spilled values
/// (`ProcessObservation` records → `(segment, seal)`), filtered to
/// close-absent segments (retired ⟺ absent from close — a sealed
/// doc for a close-present member is a drain-order artifact whose
/// counts the still-open path already carries; its doc still rides
/// `crypto_watch[]` verbatim).
pub(crate) fn sealed_map(
    staged: &[crate::service::staging::StagedRecord],
    spilled: &[crate::service::staging::SpilledRecord],
    close_segments: &BTreeSet<u64>,
) -> HashMap<u64, SealedRetirement> {
    let mut out = HashMap::new();
    for r in staged {
        let Some(v) = r.value.as_ref() else {
            continue;
        };
        if let Some((seg, seal)) = seal_of(v) {
            if !close_segments.contains(&seg) {
                out.insert(seg, seal);
            }
        }
    }
    // Spilled seals (MEM pressure pushed the retirement record to
    // disk — R1 finding 4): one tmp at a time (one in-transit
    // record; the bytes drop before the next read — never the
    // whole window). Staged wins ties (a record lives in exactly
    // one place; first-wins either way).
    for r in spilled {
        let Ok(bytes) = std::fs::read(&r.tmp) else {
            continue;
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes);
        drop(bytes);
        let Ok(v) = parsed else {
            continue;
        };
        if let Some((seg, seal)) = seal_of(&v) {
            if !close_segments.contains(&seg) {
                out.entry(seg).or_insert(seal);
            }
        }
    }
    out
}

fn open_keyed(open: &MemberView) -> HashMap<(SiteKey, u32), u64> {
    let mut map: HashMap<(SiteKey, u32), u64> = HashMap::new();
    for s in &open.sites {
        let site = open
            .bindings
            .iter()
            .find(|b| b.cookie == s.cookie)
            .map(|b| b.site.clone());
        if let Some(site) = site {
            let slot = map.entry((site, s.generation)).or_default();
            *slot = (*slot).saturating_add(s.calls);
        }
    }
    map
}

/// Sealed rows as (key, calls, current-side?) — placement follows the
/// sealed doc's OWN split (`sites` ⟹ current-side).
fn sealed_rows(doc: &CaptureDocument) -> Vec<((SiteKey, u32), u64, bool)> {
    let mut rows = Vec::new();
    for r in &doc.sites {
        rows.push(((r.site.clone(), r.generation), r.calls, true));
    }
    for f in &doc.fenced {
        for r in &f.sites {
            rows.push(((r.site.clone(), r.generation), r.calls, false));
        }
    }
    rows
}

/// Per-member saturating gap-value deltas (merged later by
/// (name, kind, units, source)).
fn gap_deltas(open: Option<&Vec<GapCounter>>, close: &[GapCounter]) -> Vec<GapCounter> {
    let open_map: HashMap<(&str, CounterKind, CounterUnits, CounterSource), u64> = open
        .map(|v| {
            v.iter()
                .map(|g| ((g.name.as_str(), g.kind, g.units, g.source), g.value))
                .collect()
        })
        .unwrap_or_default();
    close
        .iter()
        .map(|g| GapCounter {
            name: g.name.clone(),
            kind: g.kind,
            units: g.units,
            source: g.source,
            value: g.value.saturating_sub(
                open_map
                    .get(&(g.name.as_str(), g.kind, g.units, g.source))
                    .copied()
                    .unwrap_or(0),
            ),
        })
        .collect()
}

/// Per-member engine-call deltas by (key, generation, entrypoint).
fn engine_deltas(open: Option<&Vec<EngineRow>>, close: &[EngineRow]) -> Vec<EngineDelta> {
    let open_map: HashMap<(&SiteKey, u64, u16), u64> = open
        .map(|v| {
            v.iter()
                .map(|e| ((&e.key, e.generation, e.entrypoint), e.calls))
                .collect()
        })
        .unwrap_or_default();
    close
        .iter()
        .map(|e| EngineDelta {
            key: e.key.clone(),
            generation: e.generation,
            entrypoint: e.entrypoint,
            calls: e.calls.saturating_sub(
                open_map
                    .get(&(&e.key, e.generation, e.entrypoint))
                    .copied()
                    .unwrap_or(0),
            ),
            window: EngineWindow::InWindow,
        })
        .filter(|d| d.calls > 0)
        .collect()
}

/// Loss intersection (§11.1): the window's loss is the SET
/// DIFFERENCE close−open CLIPPED to `[open_tick, close_tick]` —
/// half-open `[start, end)` tick ranges covered by close intervals
/// but NOT by open intervals, re-attached to the close interval's
/// cause. Identical sets contribute nothing (no scalar subtraction
/// of interval ledgers).
fn member_loss(
    open: Option<&MemberView>,
    close: &MemberView,
    open_tick: u64,
    close_tick: u64,
) -> crate::service::envelope::MemberWindowLoss {
    use crate::service::envelope::{LostWindowView, MemberWindowLoss};
    let empty = LossView::default();
    let o = open.map(|m| &m.loss).unwrap_or(&empty);
    let c = &close.loss;
    let mut lost_windows = Vec::new();
    for ci in &c.lost {
        // Subtract every open interval (coverage is cause-agnostic),
        // then clip to the window span.
        let mut pieces = vec![(ci.start_tick, ci.end_tick)];
        for oi in &o.lost {
            pieces = subtract_interval(pieces, (oi.start_tick, oi.end_tick));
        }
        for (s, e) in pieces {
            let cs = s.max(open_tick);
            let ce = e.min(close_tick);
            if cs < ce {
                lost_windows.push(LostWindowView {
                    start_tick: cs,
                    end_tick: ce,
                    cause: ci.cause.to_string(),
                });
            }
        }
    }
    lost_windows.sort_by_key(|w| (w.start_tick, w.end_tick));
    let deferred_grew = c.deferred_ticks > o.deferred_ticks;
    let mut ring_delta = [0u64; 8];
    let open_ring = open.map(|m| m.ring).unwrap_or([0u64; 8]);
    for i in 0..8 {
        ring_delta[i] = close.ring[i].saturating_sub(open_ring[i]);
    }
    MemberWindowLoss {
        loss_delta: c.loss.saturating_sub(o.loss),
        lost_windows,
        coalesced_delta: c.coalesced.saturating_sub(o.coalesced),
        deferred_ticks_delta: c.deferred_ticks.saturating_sub(o.deferred_ticks),
        deferred_first_tick: if deferred_grew { c.deferred_first } else { 0 },
        deferred_last_tick: if deferred_grew { c.deferred_last } else { 0 },
        ring_delta,
    }
}

/// Subtract one half-open interval from a list of half-open pieces.
fn subtract_interval(pieces: Vec<(u64, u64)>, cut: (u64, u64)) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for (s, e) in pieces {
        if cut.1 <= s || cut.0 >= e {
            out.push((s, e));
        } else {
            if cut.0 > s {
                out.push((s, cut.0));
            }
            if cut.1 < e {
                out.push((cut.1, e));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Completeness, ObjectId};

    fn site(object: &str) -> SiteKey {
        SiteKey {
            object: ObjectId(object.to_string()),
            device: 7,
            inode: 8,
            offset: 9,
        }
    }

    fn target(pid: u32) -> TargetRecord {
        TargetRecord::new(pid, "t".to_string(), String::new(), String::new())
    }

    fn member(
        pid: u32,
        segment: u64,
        sites: Vec<SiteCounts>,
        bindings: Vec<SiteBinding>,
    ) -> MemberView {
        MemberView {
            pid,
            starttime: 100,
            segment,
            image_epoch: 0,
            sites,
            gen_marker: 1,
            bindings,
            loss: LossView::default(),
            ring: [0; 8],
            gaps: Vec::new(),
            engine: Vec::new(),
            gauges: (2, 2),
            target: target(pid),
        }
    }

    fn binding(cookie: u32, object: &str) -> SiteBinding {
        SiteBinding {
            cookie,
            site: site(object),
            candidates: Vec::new(),
            coverage: CandidateCoverage::Complete,
            installed_at: Some(5),
        }
    }

    fn snap(members: Vec<MemberView>) -> Snapshot {
        Snapshot {
            at_ns: 0,
            stable: true,
            members,
            run: RunTallies::default(),
            polling: false,
        }
    }

    fn seal(doc: CaptureDocument, pid: u32, starttime: u64, image_epoch: u64) -> SealedRetirement {
        SealedRetirement {
            doc,
            pid,
            starttime,
            image_epoch,
        }
    }

    fn ctx() -> WindowCtx {
        WindowCtx {
            seq: 0,
            generation: 0,
            run_id: RunId {
                pid: 1,
                starttime: 1,
                boot_id: "b".to_string(),
            },
            span: WindowSpan {
                requested_start_ns: 0,
                requested_end_ns: 100,
                effective_start_ns: 0,
                effective_end_ns: 100,
                signal_cut: false,
                accum_cut: false,
            },
            open_tick: 0,
            close_tick: 10,
            policy_rules: Vec::new(),
            active_policy: None,
            fatal: None,
            run_member_floor: Some((9, 100)),
            selection_pid: 9,
        }
    }

    fn sealed_doc(rows: Vec<(SiteKey, u32, u64)>) -> CaptureDocument {
        sealed_doc_eng(rows, Vec::new())
    }

    fn sealed_doc_eng(
        rows: Vec<(SiteKey, u32, u64)>,
        engines: Vec<EngineObservation>,
    ) -> CaptureDocument {
        let sites: Vec<SiteExecution> = rows
            .into_iter()
            .map(|(site, generation, calls)| SiteExecution {
                site,
                generation,
                candidates: Vec::new(),
                candidates_coverage: CandidateCoverage::Complete,
                calls,
                first_ns: 1,
                last_ns: 90,
                installed_at: None,
            })
            .collect();
        crate::evidence::finalize(FinalizeInput {
            corpse_wait: None,
            window: CaptureWindow {
                requested_start_ns: 0,
                requested_end_ns: 100,
                effective_start_ns: 0,
                effective_end_ns: 100,
                signal_cut: false,
                count_admission: None,
            },
            sites,
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: target(9),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: engines,
            traversal: None,
        })
    }

    /// R1 finding 4 (absent-open retirement): a member admitted
    /// after the open snapshot and retired before close has NO
    /// open anchor — its sealed counts must still project (open ⟺
    /// 0, clamp 0 shown), listed retired in `members[]`.
    #[test]
    fn absent_open_retirement_projects_at_zero() {
        let open = snap(Vec::new());
        let close = snap(Vec::new());
        let mut sealed = HashMap::new();
        sealed.insert(7, seal(sealed_doc(vec![(site("lib"), 1, 25)]), 9, 100, 3));
        let p = produce(&open, &close, &sealed, &ctx());
        assert_eq!(p.members.len(), 1, "absent-open retiree is listed");
        let m = &p.members[0];
        assert_eq!((m.pid, m.starttime, m.segment), (9, 100, 7));
        assert_eq!(m.image_epoch, 3, "epoch from the seal record");
        assert!(m.retired);
        assert_eq!(m.clamp, 0, "no open anchor — nothing to clamp");
        assert_eq!(p.document.sites.len(), 1);
        assert_eq!(p.document.sites[0].calls, 25, "sealed − 0");
    }

    /// R1 finding 4 (sealed ENGINE merge): a retired member's
    /// certified sealed `engine_observations` merge into the
    /// window document (the finish path emits them —
    /// `focused_capture.rs` finish; the snapshot path previously
    /// dropped them).
    #[test]
    fn retired_sealed_engine_rows_merge() {
        let open = snap(vec![member(9, 1, Vec::new(), Vec::new())]);
        let close = snap(Vec::new());
        let mut sealed = HashMap::new();
        sealed.insert(
            1,
            seal(
                sealed_doc_eng(
                    vec![(site("lib"), 1, 25)],
                    vec![EngineObservation {
                        key: site("lib"),
                        generation: 2,
                        entrypoint: 3,
                        calls: 11,
                        window: EngineWindow::InWindow,
                    }],
                ),
                9,
                100,
                0,
            ),
        );
        let p = produce(&open, &close, &sealed, &ctx());
        assert_eq!(p.document.engine_observations.len(), 1);
        let e = &p.document.engine_observations[0];
        assert_eq!(e.calls, 11);
        assert_eq!(e.generation, 2);
        assert_eq!(e.entrypoint, 3);
    }

    /// R1 finding 4 (spilled seals): a retirement record that
    /// spilled to disk (MEM pressure) must still feed the sealed
    /// map — `sealed_map` reads spill tmps one at a time (one
    /// in-transit record, never the whole window).
    #[test]
    fn spilled_retirement_seals_consume() {
        let dir = std::env::temp_dir().join(format!("ossl-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = sealed_doc(vec![(site("lib"), 1, 25)]);
        let rec = serde_json::json!({
            "kind": "process_observation",
            "incarnation": {"pid": 9u32, "starttime": 100u64},
            "segment": 7u64,
            "document": serde_json::to_value(&doc).unwrap(),
            "image_epoch": 3u64,
        });
        let tmp = dir.join("spill.seal.json");
        std::fs::write(&tmp, serde_json::to_vec(&rec).unwrap()).unwrap();
        let spilled = vec![crate::service::staging::SpilledRecord {
            tmp: tmp.clone(),
            bytes: 1,
            tick: 0,
        }];
        let close_segments = BTreeSet::new();
        let m = sealed_map(&[], &spilled, &close_segments);
        assert_eq!(m.len(), 1, "spilled seal consumed");
        let s = &m[&7];
        assert_eq!((s.pid, s.starttime, s.image_epoch), (9, 100, 3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Control 7 mirror: two processes sharing one site — merged
    /// calls == Σ contributors, bounds == min/max, every row
    /// calls > 0, members/site_sources jointly complete.
    #[test]
    fn shared_site_merges_exactly() {
        let open = snap(vec![
            member(
                11,
                1,
                vec![SiteCounts {
                    cookie: 1,
                    generation: 1,
                    calls: 10,
                    sealed_bounds: None,
                }],
                vec![binding(1, "lib")],
            ),
            member(
                12,
                2,
                vec![SiteCounts {
                    cookie: 2,
                    generation: 1,
                    calls: 20,
                    sealed_bounds: None,
                }],
                vec![binding(2, "lib")],
            ),
        ]);
        let close = snap(vec![
            member(
                11,
                1,
                vec![SiteCounts {
                    cookie: 1,
                    generation: 1,
                    calls: 13,
                    sealed_bounds: Some((10, 40)),
                }],
                vec![binding(1, "lib")],
            ),
            member(
                12,
                2,
                vec![SiteCounts {
                    cookie: 2,
                    generation: 1,
                    calls: 27,
                    sealed_bounds: Some((30, 80)),
                }],
                vec![binding(2, "lib")],
            ),
        ]);
        let p = produce(&open, &close, &HashMap::new(), &ctx());
        assert_eq!(p.document.sites.len(), 1);
        let row = &p.document.sites[0];
        assert_eq!(row.calls, 3 + 7);
        assert!(row.calls > 0);
        assert_eq!((row.first_ns, row.last_ns), (10, 80));
        // Merged rows are differenced: never Complete.
        assert_eq!(
            row.candidates_coverage,
            CandidateCoverage::AmbiguousComplete
        );
        // site_sources cross-check from DIR truth alone.
        assert_eq!(p.site_sources.len(), 1);
        let src = &p.site_sources[0];
        assert!(src.hit_interval_known);
        assert_eq!(src.calls, row.calls);
        let csum: u64 = src.contributors.iter().map(|c| c.calls).sum();
        assert_eq!(csum, row.calls);
        // Joint completeness: every contributor names a member.
        for c in &src.contributors {
            assert!(p.members.iter().any(|m| m.segment == c.segment));
        }
        assert_eq!(p.members.len(), 2);
        // Skew-tolerant containment.
        let (s, e) = (0u64, 100u64);
        let len = e - s;
        assert!(row.first_ns >= s.saturating_sub(len) && row.last_ns <= e + len);
    }

    /// L2: positive-count/empty-bounds rows carry EXPLICITLY UNKNOWN
    /// intervals — no fallback endpoints enter `first_ns`/`last_ns`.
    #[test]
    fn l2_unknown_bounds_marked_never_fallback() {
        let open = snap(vec![member(
            11,
            1,
            vec![SiteCounts {
                cookie: 1,
                generation: 1,
                calls: 10,
                sealed_bounds: None,
            }],
            vec![binding(1, "lib")],
        )]);
        let close = snap(vec![member(
            11,
            1,
            vec![SiteCounts {
                cookie: 1,
                generation: 1,
                calls: 15,
                sealed_bounds: None,
            }],
            vec![binding(1, "lib")],
        )]);
        let p = produce(&open, &close, &HashMap::new(), &ctx());
        assert_eq!(p.document.sites.len(), 1);
        let row = &p.document.sites[0];
        assert_eq!(row.calls, 5);
        // NOT the window span (forbidden fallback).
        assert_ne!((row.first_ns, row.last_ns), (0, 100));
        assert_eq!(
            (row.first_ns, row.last_ns),
            (UNKNOWN_FIRST_NS, UNKNOWN_LAST_NS)
        );
        assert!(!p.site_sources[0].hit_interval_known);
        assert!(!p.site_sources[0].contributors[0].bounds_known);
        assert_eq!(p.site_sources[0].contributors[0].first_ns, None);
    }

    /// L3: exact whole-segment equality on entirely-stable chains;
    /// retired members close at sealed totals.
    #[test]
    fn l3_stable_chain_conserves_exactly() {
        let b = binding(1, "lib");
        // Window 0: 0 → 10.
        let open0 = snap(vec![member(
            11,
            1,
            vec![SiteCounts {
                cookie: 1,
                generation: 1,
                calls: 0,
                sealed_bounds: None,
            }],
            vec![b.clone()],
        )]);
        let close0 = snap(vec![member(
            11,
            1,
            vec![SiteCounts {
                cookie: 1,
                generation: 1,
                calls: 10,
                sealed_bounds: Some((1, 50)),
            }],
            vec![b.clone()],
        )]);
        // Window 1: 10 → seal at 25 (retired).
        let open1 = close0.clone();
        let close1 = snap(vec![]);
        let mut sealed = HashMap::new();
        sealed.insert(1, seal(sealed_doc(vec![(site("lib"), 1, 25)]), 11, 100, 0));
        let p0 = produce(&open0, &close0, &HashMap::new(), &ctx());
        let p1 = produce(&open1, &close1, &sealed, &ctx());
        let sum: u64 = p0
            .document
            .sites
            .iter()
            .chain(p1.document.sites.iter())
            .map(|r| r.calls)
            .sum();
        assert_eq!(sum, 25);
        // Retired member listed with L2-unknown window bounds.
        assert!(p1.members.iter().any(|m| m.retired));
        assert!(!p1.site_sources[0].hit_interval_known);
        // Clamps are zero on stable windows.
        assert!(p0.members.iter().all(|m| m.clamp == 0));
        assert!(p1.members.iter().all(|m| m.clamp == 0));
    }

    /// L3 residual formula (T7.4): chained baselines telescope,
    /// so per segment Σ_reported − T_sealed == Σ_window_clamps
    /// EXACTLY (stable windows contribute clamp 0 and reduce to
    /// exact equality). Checked from DIR truth alone (deltas +
    /// clamp notes + sealed doc) — any invented/dropped count
    /// breaks it (non-vacuous).
    #[test]
    fn l3_residual_formula_exact() {
        let b = binding(1, "lib");
        let m = |calls, bounds| {
            member(
                11,
                1,
                vec![SiteCounts {
                    cookie: 1,
                    generation: 1,
                    calls,
                    sealed_bounds: bounds,
                }],
                vec![b.clone()],
            )
        };
        // w0 (stable): 0 → 10, delta 10, clamp 0.
        let (open0, close0) = (snap(vec![m(0, None)]), snap(vec![m(10, Some((1, 50)))]));
        // w1 (UNSTABLE): open 10 → stale close 8: delta 0, clamp 2.
        let open1 = close0.clone();
        let mut close1 = snap(vec![m(8, Some((1, 50)))]);
        close1.stable = false;
        // w2: open 8 (chained) → retire, sealed 12: delta 4.
        let open2 = snap(vec![m(8, None)]);
        let close2 = snap(vec![]);
        let mut sealed = HashMap::new();
        sealed.insert(1, seal(sealed_doc(vec![(site("lib"), 1, 12)]), 11, 100, 0));
        let p0 = produce(&open0, &close0, &HashMap::new(), &ctx());
        let p1 = produce(&open1, &close1, &HashMap::new(), &ctx());
        let p2 = produce(&open2, &close2, &sealed, &ctx());
        assert_eq!(p0.members[0].clamp, 0);
        assert_eq!(p1.members[0].clamp, 2);
        assert_eq!(p2.members[0].clamp, 0);
        assert!(p1.unstable);
        assert!(matches!(p1.document.status, Completeness::Partial { .. }));
        let sum: u64 = [&p0, &p1, &p2]
            .iter()
            .flat_map(|p| p.document.sites.iter())
            .map(|r| r.calls)
            .sum();
        // Σ − T == Σclamp: 14 − 12 == 2 (the stale close
        // under-stated w1 and inflated w2 by exactly the clamp).
        assert_eq!(sum, 14);
        assert_eq!(sum - 12, 2);
    }

    #[test]
    fn loss_intersection_clips_to_span() {
        // Close grew [0,10) → [0,14): only [10,14) is new, clipped
        // to the window span [5,12) → [10,12) under close's cause.
        let b = binding(1, "lib");
        let sites = |calls| {
            vec![SiteCounts {
                cookie: 1,
                generation: 1,
                calls,
                sealed_bounds: Some((1, 2)),
            }]
        };
        let open = Snapshot {
            at_ns: 0,
            stable: true,
            members: vec![MemberView {
                loss: LossView {
                    loss: 3,
                    deferred_ticks: 0,
                    deferred_first: 0,
                    deferred_last: 0,
                    lost: vec![LostView {
                        start_tick: 0,
                        end_tick: 10,
                        cause: "a",
                    }],
                    coalesced: 0,
                },
                ..member(11, 1, sites(0), vec![b.clone()])
            }],
            run: RunTallies::default(),
            polling: false,
        };
        let close = Snapshot {
            at_ns: 0,
            stable: true,
            members: vec![MemberView {
                loss: LossView {
                    loss: 5,
                    deferred_ticks: 0,
                    deferred_first: 0,
                    deferred_last: 0,
                    lost: vec![LostView {
                        start_tick: 0,
                        end_tick: 14,
                        cause: "b",
                    }],
                    coalesced: 1,
                },
                ..member(11, 1, sites(1), vec![b.clone()])
            }],
            run: RunTallies::default(),
            polling: false,
        };
        let mut c = ctx();
        c.open_tick = 5;
        c.close_tick = 12;
        let p = produce(&open, &close, &HashMap::new(), &c);
        let loss = &p.members[0].loss;
        assert_eq!(loss.loss_delta, 2);
        assert_eq!(loss.coalesced_delta, 1);
        assert_eq!(loss.lost_windows.len(), 1);
        assert_eq!(loss.lost_windows[0].start_tick, 10);
        assert_eq!(loss.lost_windows[0].end_tick, 12);
        assert_eq!(loss.lost_windows[0].cause, "b");
        // Identical sets contribute nothing (counts move, loss
        // identical → member listed, loss empty).
        let mut close2 = close.clone();
        close2.members[0].sites[0].calls = 2;
        let p2 = produce(&close, &close2, &HashMap::new(), &c);
        assert_eq!(p2.members.len(), 1);
        assert!(p2.members[0].loss.lost_windows.is_empty());
        assert_eq!(p2.members[0].loss.loss_delta, 0);
    }

    #[test]
    fn unstable_forces_partial_via_existing_mechanism() {
        let mut open = snap(vec![]);
        open.stable = false;
        let close = snap(vec![]);
        let p = produce(&open, &close, &HashMap::new(), &ctx());
        assert!(p.unstable);
        assert!(matches!(p.document.status, Completeness::Partial { .. }));
        let counter = p
            .document
            .counters
            .iter()
            .find(|g| g.name == "snapshot_unstable")
            .unwrap();
        assert!(counter.forces_partial());
    }
}
