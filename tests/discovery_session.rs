//! SPDX-License-Identifier: GPL-3.0-or-later
//! T06 persistent-discovery-session gates.
//!
//! Host tests drive the real [`SessionCore`] state machine with
//! synthetic wire event streams, canned `/proc` maps, staged BPF map
//! snapshots and a controllable link/pin environment — the same unit
//! the live [`DiscoverySession`] polls. Only the late-query, legacy
//! and live-loss cases need a privileged lane; they stay NOT-RUN here
//! (lane pending) and are covered by the C4 suite.

use osslscope::discovery::coverage::{HOST_DRAIN_SHORTFALL, HOST_ORPHAN_ROW, loss_source_name};
use osslscope::discovery::legacy::{Probe, ProbeSet};
use osslscope::discovery::maps::Mapping;
use osslscope::discovery::session::{
    DiscoverySnapshot, MapSnapshots, PollBudget, SessionCore, SessionEnv,
};
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

const OP_DIGEST: u32 = 1;
const PROVIDER: &str = "/p/provider.so";
const LIBCRYPTO: &str = "/p/libcrypto.so.3";
const LEGACY_SO: &str = "/p/ossl-modules/legacy.so";

// ---------------------------------------------------------------------------
// Synthetic wire encoders (field layouts mirror ebpf-common repr(C) structs).
// ---------------------------------------------------------------------------

fn enc_row(kind: u32, op: u32, funcid: u32, addr: u64, aux: u64, idx: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(&op.to_le_bytes());
    b.extend_from_slice(&funcid.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&addr.to_le_bytes());
    b.extend_from_slice(&aux.to_le_bytes());
    b.extend_from_slice(&idx.to_le_bytes());
    b
}

fn enc_alg(op: u32, class: u16, status: u8, weak: u8, arr: u64, idx: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(&wire::KIND_ALG.to_le_bytes());
    b.extend_from_slice(&op.to_le_bytes());
    b.extend_from_slice(&class.to_le_bytes());
    b.push(status);
    b.push(weak);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&arr.to_le_bytes());
    b.extend_from_slice(&idx.to_le_bytes());
    b
}

fn enc_trip(cookie: u32, class: u16, status: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&wire::KIND_TRIP.to_le_bytes());
    b.extend_from_slice(&cookie.to_le_bytes());
    b.extend_from_slice(&class.to_le_bytes());
    b.push(status);
    b.push(0u8);
    b.extend_from_slice(&0u32.to_le_bytes());
    b
}

fn enc_init(addr: u64, cookie: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(&wire::KIND_INIT_RET.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&addr.to_le_bytes());
    b.extend_from_slice(&cookie.to_le_bytes());
    b
}

fn query_ret(op: u32, arr: u64, slot: u64) -> Vec<u8> {
    enc_row(wire::KIND_QUERY_RET, op, 0, arr, 0, slot)
}

fn ok_alg(op: u32, arr: u64, idx: u64) -> Vec<u8> {
    enc_alg(op, 0, wire::ALG_OK, 0, arr, idx)
}

fn dispatch_row(op: u32, funcid: u32, impl_addr: u64, arr: u64, idx: u64) -> Vec<u8> {
    enc_row(wire::KIND_ROW, op, funcid, impl_addr, arr, idx)
}

// ---------------------------------------------------------------------------
// Test environment: synthetic ring, maps, BPF snapshots, links, pin.
// ---------------------------------------------------------------------------

fn mapping(start: u64, len: u64, x: bool, offset: u64, dev: &str, ino: u64, path: &str) -> Mapping {
    Mapping {
        start,
        end: start + len,
        x,
        offset,
        dev: dev.to_string(),
        ino,
        path: path.to_string(),
    }
}

/// Live-shape maps: provider + libcrypto + legacy file mappings
/// (adjacent, non-overlapping ranges).
fn live_maps() -> Vec<Mapping> {
    vec![
        mapping(0x7f00_0000, 0x10000, true, 0, "08:01", 100, PROVIDER),
        mapping(0x7f01_0000, 0x10000, true, 0, "08:01", 200, LIBCRYPTO),
        mapping(0x7f02_0000, 0x10000, true, 0, "08:01", 300, LEGACY_SO),
    ]
}

fn canned_probe_set() -> ProbeSet {
    ProbeSet {
        probes: vec![
            Probe {
                cookie: 7,
                symbol: "ENGINE_by_id".to_string(),
                offset: 0x1000,
                module: LIBCRYPTO.to_string(),
                family: None,
                str_arg: Some(0),
                program: "trip_str0",
            },
            Probe {
                cookie: 8,
                symbol: "OSSL_PROVIDER_load".to_string(),
                offset: 0x2000,
                module: LIBCRYPTO.to_string(),
                family: None,
                str_arg: Some(0),
                program: "trip_str1",
            },
            Probe {
                cookie: 9,
                symbol: "DES_ecb_encrypt".to_string(),
                offset: 0x3000,
                module: LIBCRYPTO.to_string(),
                family: Some("DES"),
                str_arg: None,
                program: "trip_count",
            },
        ],
        by_id_cookies: HashSet::from([7]),
        load_cookies: HashSet::from([8]),
        ..Default::default()
    }
}

struct TestEnv {
    events: VecDeque<Vec<u8>>,
    maps: Vec<Mapping>,
    staged: MapSnapshots,
    stage2: Vec<(u64, u64, String)>,
    stage2_failures: u32,
    trip_links_live: u64,
    trip_install_calls: u32,
    probe_set: Option<ProbeSet>,
    pin_ok: bool,
    quiesced: bool,
    evicted: Vec<u64>,
    evict_fail: bool,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            maps: live_maps(),
            staged: MapSnapshots::default(),
            stage2: Vec::new(),
            stage2_failures: 0,
            trip_links_live: 0,
            trip_install_calls: 0,
            probe_set: None,
            pin_ok: true,
            quiesced: false,
            evicted: Vec::new(),
            evict_fail: false,
        }
    }

    fn push(&mut self, ev: Vec<u8>) {
        self.events.push_back(ev);
    }

    fn link_counts_now(&self) -> (u64, u64) {
        if self.quiesced {
            (0, 0)
        } else {
            (self.stage2.len() as u64, self.trip_links_live)
        }
    }
}

impl SessionEnv for TestEnv {
    fn next_event(&mut self) -> Option<Vec<u8>> {
        self.events.pop_front()
    }

    fn current_maps(&mut self) -> Vec<Mapping> {
        self.maps.clone()
    }

    fn join_maps(&mut self) -> MapSnapshots {
        self.staged.clone()
    }

    fn install_stage2(
        &mut self,
        cookie: u64,
        offset: u64,
        path: &Path,
        _pid: u32,
    ) -> anyhow::Result<()> {
        if self.stage2_failures > 0 {
            self.stage2_failures -= 1;
            anyhow::bail!("injected stage-2 failure for cookie {cookie}");
        }
        self.stage2
            .push((cookie, offset, path.to_string_lossy().into_owned()));
        Ok(())
    }

    fn install_trips(&mut self, set: &ProbeSet, _pid: u32) -> anyhow::Result<Option<String>> {
        self.trip_install_calls += 1;
        self.trip_links_live += set.probes.len() as u64;
        Ok(None)
    }

    fn plan_trips(&mut self, _maps: &[Mapping]) -> anyhow::Result<Option<ProbeSet>> {
        Ok(self.probe_set.clone())
    }

    fn pretouch(&mut self, _cookie: u64, _addr: u64) {}

    fn evict_array_state(&mut self, arr: u64) -> anyhow::Result<()> {
        if self.evict_fail {
            anyhow::bail!("injected evict failure");
        }
        // Faithful fake: eviction deletes kernel state, so later
        // joins stop reporting the retired proof.
        self.staged.termd.retain(|(a, _)| *a != arr);
        self.evicted.push(arr);
        Ok(())
    }

    fn verify_pin(&self) -> anyhow::Result<()> {
        if self.pin_ok {
            Ok(())
        } else {
            anyhow::bail!("pid recycled")
        }
    }

    fn quiesce(&mut self) {
        self.quiesced = true;
        self.stage2.clear();
        self.trip_links_live = 0;
    }

    fn link_counts(&self) -> (u64, u64) {
        self.link_counts_now()
    }
}

fn test_core(legacy: bool) -> SessionCore {
    SessionCore::new(PathBuf::from(PROVIDER), String::new(), legacy, 4242)
}

fn ample_budget() -> PollBudget {
    PollBudget::new(65536, 64)
}

fn label0() -> &'static str {
    osslscope::kinds::alg_class_label(0).expect("registry class 0 exists")
}

fn losses_of(snap: &DiscoverySnapshot) -> HashMap<u32, u64> {
    snap.losses.iter().copied().collect()
}

#[test]
fn late_query_existing_mapping_emits_delta() {
    // A pre-loaded provider (mapped, never init-observed) issues a
    // query for an existing mapping: the session emits a typed delta
    // with classified candidates carrying correct advertising
    // (array owner) and backing (impl triple) identities.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    // Settle one idle poll first: no trigger, no candidates, and the
    // wait is retryable rather than terminal.
    let d0 = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d0.candidates.is_empty());
    assert!(!core.snapshot().dispatch.trigger_observed);

    let arr = 0x7f00_1000u64;
    let imp = 0x7f00_2000u64;
    env.push(query_ret(OP_DIGEST, arr, 3));
    for idx in 0..4u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    env.push(dispatch_row(OP_DIGEST, 3, imp, arr, 3));
    let d1 = core.poll(&mut env, ample_budget()).unwrap();
    assert!(!d1.budget_exhausted);
    assert_eq!(d1.candidates.len(), 1);
    let c = &d1.candidates[0];
    assert_eq!(c.op, OP_DIGEST);
    assert_eq!(c.funcid, 3);
    assert_eq!(c.class, label0());
    assert!(!c.weak);
    assert_eq!(c.status, "ok");
    // Advertising identity is the array owner's locator; backing is
    // the implementation's verified triple — never conflated.
    assert_eq!(c.advertising, PROVIDER);
    let b = c.backing.as_ref().expect("backed candidate");
    assert_eq!((b.dev.as_str(), b.ino, b.offset), ("08:01", 100, 0x2000));
    assert_eq!(d1.queries_delta, 1);

    // Newly observed backing objects travel typed (no JSON reparse).
    assert_eq!(d1.objects.len(), 1);
    assert_eq!(d1.objects[0].display_locator, PROVIDER);

    let snap = core.snapshot();
    assert!(snap.dispatch.trigger_observed);
    assert_eq!(snap.candidates.len(), 1);
    assert_eq!(snap.queries_observed, 1);
    // The later slot's table is a walked prefix (no proof joined).
    assert_eq!(snap.tables.len(), 1);
    assert!(matches!(
        snap.tables[0].state,
        osslscope::discovery::session::CoverageState::InProgress { walked: 4 }
    ));
}

#[test]
fn no_query_can_retry() {
    // A mapped-but-quiet provider and a failed stage-2 attach are
    // both retryable: no permanent "harvested" bit blocks a later
    // real query or a later init.
    let mut env = TestEnv::new();
    let mut core = test_core(false);

    // Quiet polls leave the session waiting, never terminal.
    for _ in 0..3 {
        let d = core.poll(&mut env, ample_budget()).unwrap();
        assert!(d.candidates.is_empty());
        assert!(!d.budget_exhausted);
    }
    let snap = core.snapshot();
    assert!(!snap.dispatch.trigger_observed);
    assert!(snap.dispatch.attach_failures.is_empty());

    // A stage-2 attach that fails is recorded and retried on the
    // next init — the session stays alive.
    env.stage2_failures = 1;
    env.push(enc_init(0x7f00_3000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.attaches.len(), 1);
    assert!(d.attaches[0].failed.is_some());
    assert_eq!(core.snapshot().dispatch.attach_failures.len(), 1);
    assert!(env.stage2.is_empty());

    // The retry succeeds; the earlier failure clears.
    env.push(enc_init(0x7f00_3000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.attaches.iter().all(|a| a.failed.is_none()));
    assert_eq!(env.stage2.len(), 1);
    assert!(core.snapshot().dispatch.attach_failures.is_empty());

    // An unresolvable init (stale address) records a retryable
    // failure too, and a repeat init after a good install is a
    // witnessed reload, not a second install. Use the legacy
    // cookie: the target cookie is already attached.
    env.push(enc_init(0xdead_beef, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.attaches.len(), 1);
    assert!(d.attaches[0].failed.is_some());
    assert_eq!(env.stage2.len(), 1);
    env.push(enc_init(0x7f00_3000, 0));
    env.push(enc_init(0x7f02_1000, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.attaches.iter().all(|a| a.failed.is_none()));
    assert_eq!(env.stage2.len(), 2);
    let snap = core.snapshot();
    assert_eq!(snap.dispatch.attach_failures.len(), 0);
    assert!(snap.dispatch.reloads.contains(&(0, 1)));

    // A repeat init at a MOVED callback re-attaches (no stale
    // offset), while a same-target repeat only faults pages in.
    env.push(enc_init(0x7f00_4000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.attaches.len(), 1);
    assert!(d.attaches[0].failed.is_none());
    assert_eq!(env.stage2.len(), 3);
    assert_eq!(env.stage2[2].1, 0x4000);
    env.push(enc_init(0x7f00_4000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.attaches.is_empty());
    assert_eq!(env.stage2.len(), 3);
    assert!(core.snapshot().dispatch.reloads.contains(&(0, 3)));

    // And a real query after the quiet wait still emits.
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.candidates.len(), 1);
    assert!(core.snapshot().dispatch.trigger_observed);
}

#[test]
fn partial_reharvest_preserved() {
    // Gaps accumulate across polls and incarnations: a prefix in
    // epoch 0 stays visible after a clean poll and after the table's
    // mapping incarnation changes, and prior rows are preserved.
    let mut env = TestEnv::new();
    let mut core = test_core(false);

    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 1));
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    // A len-4 proof over a 2-slot walk: an honest prefix, plus one
    // kernel-side loss.
    env.staged.termd = vec![(arr, wire::make_termd(OP_DIGEST, 4))];
    env.staged.losses = vec![(wire::LOSS_RING_ROW, 2)];
    let d1 = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d1.candidates.len(), 1);
    assert_eq!(d1.losses.len(), 1);
    assert_eq!(d1.losses[0].source, wire::LOSS_RING_ROW);
    assert_eq!(d1.losses[0].count, 2);
    let snap = core.snapshot();
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
    assert_eq!(losses_of(&snap)[&wire::LOSS_RING_ROW], 2);

    // A clean poll retains every earlier gap (monotonic joins emit
    // no fresh delta for unchanged cumulative counters).
    let d2 = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d2.losses.is_empty());
    assert!(d2.candidates.is_empty());
    let snap = core.snapshot();
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
    assert_eq!(losses_of(&snap)[&wire::LOSS_RING_ROW], 2);
    assert_eq!(snap.candidates.len(), 1);

    // Provider reload at a new incarnation: the old array is
    // unmapped, so epoch 0 retires — its rows and reasons survive
    // while the new table starts unproven.
    env.maps = vec![
        mapping(0x7f05_0000, 0x10000, true, 0, "08:01", 101, PROVIDER),
        mapping(0x7f01_0000, 0x20000, true, 0, "08:01", 200, LIBCRYPTO),
    ];
    env.staged.termd = vec![];
    let arr2 = 0x7f05_1000u64;
    env.push(query_ret(OP_DIGEST, arr2, 0));
    env.push(ok_alg(OP_DIGEST, arr2, 0));
    let d3 = core.poll(&mut env, ample_budget()).unwrap();
    assert!(!d3.budget_exhausted);
    // The turnover retires epoch 0 with its gap (delta-visible)
    // and evicts the retired array's kernel walker state so no
    // stale proof or cursor can satisfy the next incarnation.
    assert_eq!(d3.retirements.len(), 1);
    assert_eq!(d3.retirements[0].op, OP_DIGEST);
    assert_eq!(d3.retirements[0].epoch, 0);
    assert_eq!(
        d3.retirements[0].gap.reasons,
        vec!["prefix-walk".to_string()]
    );
    assert_eq!(env.evicted, vec![arr]);
    let snap = core.snapshot();
    // Epoch-0 rows preserved.
    assert_eq!(snap.candidates.len(), 1);
    assert_eq!(snap.candidates[0].epoch, 0);
    // Epoch-0 prefix reason preserved alongside the new epoch.
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
    assert_eq!(losses_of(&snap)[&wire::LOSS_RING_ROW], 2);
    // The new incarnation's table is a fresh unproven epoch: the
    // stale len-4 proof cannot terminate it.
    assert_eq!(snap.tables.len(), 1);
    assert_eq!(snap.tables[0].epoch, 1);
    assert!(matches!(
        snap.tables[0].state,
        osslscope::discovery::session::CoverageState::InProgress { walked: 1 }
    ));
    for (src, _) in &snap.losses {
        assert!(
            loss_source_name(*src).is_some(),
            "loss source {src} must have a name"
        );
    }
}

#[test]
fn poll_budget_stops_busy_ring() {
    // A busy ring is consumed in bounded batches: each poll stops
    // at the budget, flags exhaustion (not loss), and resumes where
    // it left off. Only close-time leftovers become shortfall.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    for idx in 0..500u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    let budget = PollBudget::new(100, 64);
    let mut consumed = 0u64;
    for _ in 0..5 {
        let d = core.poll(&mut env, budget.clone()).unwrap();
        consumed += d.events_consumed;
        assert!(d.budget_exhausted);
        assert!(d.losses.is_empty());
    }
    assert_eq!(consumed, 500);
    // The tail drains on the next poll without an exhaustion flag.
    let d = core.poll(&mut env, budget).unwrap();
    assert_eq!(d.events_consumed, 1);
    assert!(!d.budget_exhausted);
    let snap = core.snapshot();
    assert!(!losses_of(&snap).contains_key(&HOST_DRAIN_SHORTFALL));

    // Items still queued at close are labeled exactly once.
    for idx in 500..510u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    let snap = core.close(&mut env).unwrap();
    assert_eq!(losses_of(&snap)[&HOST_DRAIN_SHORTFALL], 10);
}

#[test]
fn load_query_is_not_execution() {
    // Provider loads and query arrivals are query/load counters,
    // never executed calls: legacy `executed_calls` derives only
    // from the executed-query ledger, and query counters stay
    // separate from tripwire counters.
    let mut env = TestEnv::new();
    env.probe_set = Some(canned_probe_set());
    let mut core = test_core(true);

    // Loads observed + queries arrived: no execution yet.
    env.push(enc_trip(8, wire::LOAD_LEGACY, wire::TRIP_OK));
    env.push(enc_trip(8, wire::LOAD_LEGACY, wire::TRIP_OK));
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.staged.trip = vec![(8, 2)];
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.tripwire.hits.len(), 2);
    assert_eq!(d.queries_delta, 1);
    let snap = core.snapshot();
    assert_eq!(snap.queries_observed, 1);
    assert_eq!(snap.legacy.executed_queries, 0);
    assert_eq!(snap.legacy.hits.len(), 2);
    // Query and tripwire counters are separate fields.
    assert_eq!(snap.legacy.trip.get(&8), Some(&2));

    // Only the executed-query ledger moves execution.
    env.staged.lgcalls = 3;
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.tripwire.executed_legacy_queries_delta, 3);
    assert_eq!(d.queries_delta, 0);
    let snap = core.snapshot();
    assert_eq!(snap.legacy.executed_queries, 3);

    // The rendered legacy section agrees: loads are loads,
    // executed_calls is execution.
    let set = snap.legacy.set.as_ref().expect("planned probe set");
    let doc = osslscope::discovery::legacy::section(&osslscope::discovery::legacy::SectionInputs {
        set,
        trip: &snap.legacy.trip,
        trip_hits: &snap.legacy.hits,
        legacy_queries: snap.legacy.executed_queries,
        legacy_classes: vec![],
        extra_findings: &[],
    });
    assert_eq!(doc["legacy_provider"]["executed_calls"], 3);
    assert_eq!(doc["legacy_provider"]["loads"]["legacy"], 2);
}

#[test]
fn legacy_links_live_until_close() {
    // Tripwire and stage-2 links installed at attach stay live
    // across polls and dispatch activity; quiesce at close drops
    // them exactly once, and the closed session rejects polls.
    let mut env = TestEnv::new();
    env.probe_set = Some(canned_probe_set());
    let mut core = test_core(true);

    // Idle poll plans and installs the tripwires.
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(env.trip_install_calls, 1);
    assert_eq!(d.attaches.len(), 1);
    let snap = core.snapshot();
    assert!(snap.legacy.planned);
    assert_eq!(snap.links_live.tripwire, 3);
    assert_eq!(snap.links_live.dispatch, 0);

    // Dispatch activity (init + stage-2 + rows) leaves tripwire
    // links live and adds the dispatch link.
    env.push(enc_init(0x7f00_3000, 0));
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    // An orphan row is counted, never fatal to the links.
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2100, arr, 99));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.candidates.len(), 1);
    assert!(
        d.losses
            .iter()
            .any(|l| l.source == HOST_ORPHAN_ROW && l.count == 1)
    );
    let snap = core.snapshot();
    assert_eq!(snap.links_live.tripwire, 3);
    assert_eq!(snap.links_live.dispatch, 1);

    // Close quiesces: every link drops, and the session is done.
    let snap = core.close(&mut env).unwrap();
    assert_eq!((snap.links_live.dispatch, snap.links_live.tripwire), (0, 0));
    assert_eq!(env.link_counts(), (0, 0));
    assert!(core.poll(&mut env, ample_budget()).is_err());
}

#[test]
fn nostore_sample_never_terminates() {
    // A `no_store` table is sampled, never walked to proof: slot-0
    // samples across many queries plus the NO_STORE bit stay an
    // explicit prefix, and no termination proof is ever honored
    // for the uncacheable array.
    use osslscope::discovery::session::CoverageState;
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.staged.trunc = vec![(OP_DIGEST, wire::TRUNC_NO_STORE)];
    for _ in 0..3 {
        env.push(query_ret(OP_DIGEST, arr, 0));
        env.push(ok_alg(OP_DIGEST, arr, 0));
        let d = core.poll(&mut env, ample_budget()).unwrap();
        assert!(!d.budget_exhausted);
    }
    let snap = core.snapshot();
    assert_eq!(snap.tables.len(), 1);
    assert!(matches!(
        snap.tables[0].state,
        CoverageState::InProgress { walked: 1 }
    ));
    assert_eq!(
        snap.tables[0].trunc_bits & wire::TRUNC_NO_STORE,
        wire::TRUNC_NO_STORE
    );
    assert!(snap.reasons.contains(&"truncated-walk".to_string()));
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
    assert_eq!(snap.truncated_ops, vec![(OP_DIGEST, wire::TRUNC_NO_STORE)]);
}

#[test]
fn shrinkage_proof_does_not_carry() {
    // A len-5 proof terminates epoch 0; after the mapping
    // incarnation changes, the stale proof cannot terminate the
    // new epoch (shrinkage-OOB guard) — and the terminated epoch
    // retires silently while its rows survive.
    use osslscope::discovery::session::CoverageState;
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    for idx in 0..5u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    env.staged.termd = vec![(arr, wire::make_termd(OP_DIGEST, 5))];
    core.poll(&mut env, ample_budget()).unwrap();
    let snap = core.snapshot();
    assert!(matches!(
        snap.tables[0].state,
        CoverageState::Terminated { len: 5 }
    ));
    assert!(snap.reasons.is_empty());

    // Same array address, new incarnation (replacement inode): the
    // epoch turns over, the kernel proof is evicted (later joins
    // stop reporting it), rows stay.
    env.maps = vec![
        mapping(0x7f00_0000, 0x10000, true, 0, "08:01", 101, PROVIDER),
        mapping(0x7f01_0000, 0x20000, true, 0, "08:01", 200, LIBCRYPTO),
    ];
    env.staged.termd = vec![(arr, wire::make_termd(OP_DIGEST, 5))];
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(env.evicted, vec![arr]);
    assert!(env.staged.termd.is_empty());
    // The terminated epoch retires silently (no gap carried).
    assert_eq!(d.retirements.len(), 1);
    assert_eq!(d.retirements[0].epoch, 0);
    assert!(d.retirements[0].gap.reasons.is_empty());
    let snap = core.snapshot();
    assert_eq!(snap.candidates.len(), 1);
    assert_eq!(snap.candidates[0].epoch, 0);
    assert_eq!(snap.tables.len(), 1);
    assert_eq!(snap.tables[0].epoch, 1);
    // One walked slot against a stale len-5 proof is a prefix, and
    // the new epoch must re-prove from scratch.
    assert!(matches!(
        snap.tables[0].state,
        CoverageState::InProgress { walked: 1 }
    ));
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
}

#[test]
fn shared_impl_stays_distinct_per_array() {
    // Two providers sharing one implementation stay distinct per
    // offering array: each advertising identity is preserved with
    // its backing triple (R02), never collapsed.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let imp = 0x7f00_2000u64;
    let arr_a = 0x7f00_1000u64;
    let arr_b = 0x7f02_1000u64;
    for (arr, slot) in [(arr_a, 0u64), (arr_b, 1u64)] {
        env.push(query_ret(OP_DIGEST, arr, slot));
        env.push(ok_alg(OP_DIGEST, arr, slot));
        env.push(dispatch_row(OP_DIGEST, 7, imp, arr, slot));
    }
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.candidates.len(), 2);
    assert_eq!(d.candidates[0].advertising, PROVIDER);
    assert_eq!(d.candidates[1].advertising, LEGACY_SO);
    for c in &d.candidates {
        let b = c.backing.as_ref().expect("backed candidate");
        assert_eq!((b.dev.as_str(), b.ino, b.offset), ("08:01", 100, 0x2000));
    }
    assert_eq!(core.snapshot().candidates.len(), 2);
}

#[test]
fn attach_budget_gates_tripwires() {
    // Tripwire installs share the attach budget: a zero budget
    // stages the plan without installing (flagged, retryable), and
    // the next funded poll installs exactly once.
    let mut env = TestEnv::new();
    env.probe_set = Some(canned_probe_set());
    let mut core = test_core(true);
    let d = core.poll(&mut env, PollBudget::new(65536, 0)).unwrap();
    assert!(d.budget_exhausted);
    assert!(d.attaches.is_empty());
    assert_eq!(env.trip_install_calls, 0);
    assert!(!core.snapshot().legacy.planned);
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(!d.budget_exhausted);
    assert_eq!(d.attaches.len(), 1);
    assert_eq!(env.trip_install_calls, 1);
    assert!(core.snapshot().legacy.planned);
}

#[test]
fn counter_dips_do_not_double_count() {
    // Baselines are high-water marks: a dipped or partial read
    // (5→0→5) reports five once, not twice, across losses,
    // tripwire counters, and the executed-query ledger.
    let mut env = TestEnv::new();
    env.probe_set = Some(canned_probe_set());
    let mut core = test_core(true);
    env.staged.losses = vec![(wire::LOSS_RING_ROW, 5)];
    env.staged.trip = vec![(8, 5)];
    env.staged.lgcalls = 5;
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(
        d.losses,
        vec![osslscope::discovery::session::DiscoveryLoss {
            source: wire::LOSS_RING_ROW,
            count: 5,
        }]
    );
    assert_eq!(d.tripwire.counter_deltas, vec![(8, 5)]);
    assert_eq!(d.tripwire.executed_legacy_queries_delta, 5);
    // The dip: keys vanish (partial read). No fresh deltas, and no
    // baseline regression.
    env.staged.losses = vec![];
    env.staged.trip = vec![];
    env.staged.lgcalls = 0;
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.losses.is_empty());
    assert!(d.tripwire.counter_deltas.is_empty());
    assert_eq!(d.tripwire.executed_legacy_queries_delta, 0);
    // Recovery to the same cumulative values emits nothing new.
    env.staged.losses = vec![(wire::LOSS_RING_ROW, 5)];
    env.staged.trip = vec![(8, 5)];
    env.staged.lgcalls = 5;
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.losses.is_empty());
    assert!(d.tripwire.counter_deltas.is_empty());
    assert_eq!(d.tripwire.executed_legacy_queries_delta, 0);
    let snap = core.snapshot();
    assert_eq!(losses_of(&snap)[&wire::LOSS_RING_ROW], 5);
    assert_eq!(snap.legacy.trip.get(&8), Some(&5));
    assert_eq!(snap.legacy.executed_queries, 5);
    // Genuine growth past the mark still reports the increment.
    env.staged.losses = vec![(wire::LOSS_RING_ROW, 7)];
    env.staged.lgcalls = 6;
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.losses[0].count, 2);
    assert_eq!(d.tripwire.executed_legacy_queries_delta, 1);
}

#[test]
fn map_only_completion_emits_table() {
    // A table that transitions purely by map join (late proof, no
    // ring events this poll) still appears in the delta with its
    // new state.
    use osslscope::discovery::session::CoverageState;
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(matches!(
        d.tables[0].state,
        CoverageState::InProgress { walked: 2 }
    ));
    // No events: the len-2 proof lands by join alone.
    env.staged.termd = vec![(arr, wire::make_termd(OP_DIGEST, 2))];
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.events_consumed, 0);
    assert_eq!(d.tables.len(), 1);
    assert!(matches!(
        d.tables[0].state,
        CoverageState::Terminated { len: 2 }
    ));
    // Steady state: no transition, no table in the delta.
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.tables.is_empty());
}

#[test]
fn evict_failure_is_loss() {
    // A failed kernel-state eviction retires honestly anyway (gap
    // retained) and records explicit loss — which forces PARTIAL
    // downstream, containing any surviving stale proof.
    use osslscope::discovery::coverage::HOST_EVICT_FAILED;
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    core.poll(&mut env, ample_budget()).unwrap();
    env.evict_fail = true;
    env.maps = vec![mapping(
        0x7f05_0000,
        0x10000,
        true,
        0,
        "08:01",
        101,
        PROVIDER,
    )];
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.retirements.len(), 1);
    assert!(
        d.losses
            .iter()
            .any(|l| l.source == HOST_EVICT_FAILED && l.count == 1)
    );
    let snap = core.snapshot();
    assert_eq!(losses_of(&snap)[&HOST_EVICT_FAILED], 1);
    assert!(snap.reasons.contains(&"prefix-walk".to_string()));
    assert!(snap.retained_reasons.contains(&"prefix-walk".to_string()));
}
