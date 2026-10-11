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
    DiscoverySnapshot, MapSnapshots, PollBudget, Recycled, SessionCore, SessionEnv,
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

/// Stat-able provider identity for stat-or-None resolution: the
/// test binary itself (always exists; its /proc/self/maps line gives
/// the (dev, ino) string without libc). Libcrypto/legacy mappings
/// stay synthetic (path-matched only, never stat-resolved).
fn provider_file() -> (PathBuf, String, u64) {
    use std::os::unix::fs::MetadataExt;
    let exe = std::env::current_exe().unwrap();
    let want_ino = std::fs::metadata(&exe).unwrap().ino();
    let base = exe.file_name().unwrap().to_string_lossy().into_owned();
    for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6
            && f[5].rsplit('/').next() == Some(base.as_str())
            && f[4].parse::<u64>().ok() == Some(want_ino)
        {
            return (exe, f[3].to_string(), want_ino);
        }
    }
    panic!("self mapping not found in /proc/self/maps");
}

/// Live-shape maps: provider + libcrypto + legacy file mappings
/// (adjacent, non-overlapping ranges).
fn live_maps() -> Vec<Mapping> {
    let (exe, dev, ino) = provider_file();
    let exe = exe.to_string_lossy().into_owned();
    vec![
        mapping(0x7f00_0000, 0x10000, true, 0, &dev, ino, &exe),
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

/// Recorded stage-2 install: (cookie, offset, path, expected raw identity).
type Stage2Install = (u64, u64, String, Option<(u64, u64)>);

struct TestEnv {
    events: VecDeque<Vec<u8>>,
    maps: Vec<Mapping>,
    staged: MapSnapshots,
    stage2: Vec<Stage2Install>,
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
        expected: Option<(u64, u64)>,
    ) -> anyhow::Result<()> {
        if self.stage2_failures > 0 {
            self.stage2_failures -= 1;
            anyhow::bail!("injected stage-2 failure for cookie {cookie}");
        }
        self.stage2.push((
            cookie,
            offset,
            path.to_string_lossy().into_owned(),
            expected,
        ));
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
    SessionCore::new(provider_file().0, String::new(), legacy, 4242)
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
    let (exe, dev, ino) = provider_file();
    let exe = exe.to_string_lossy().into_owned();
    assert_eq!(c.advertising, exe);
    let b = c.backing.as_ref().expect("backed candidate");
    assert_eq!(
        (b.dev.as_str(), b.ino, b.offset),
        (dev.as_str(), ino, 0x2000)
    );
    assert_eq!(d1.queries_delta, 1);

    // Newly observed backing objects travel typed (no JSON reparse).
    assert_eq!(d1.objects.len(), 1);
    assert_eq!(d1.objects[0].display_locator, exe);

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
            .any(|l| l.source == HOST_ORPHAN_ROW && l.count == 1 && l.op == Some(OP_DIGEST))
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
fn one_query_full_walk_covers_late_slot() {
    // Host-side contract for a future complete walker (T14r5: the
    // in-kernel multi-slot walk proved verifier-infeasible — see the
    // round-5 handoff — so the kernel still emits prefix streams;
    // this pins the session accounting a future walker feeds): the
    // G02 ECDSA shape — a 30-slot signature table (op 12) with ECDSA
    // at slot 29, observed through ONE query — terminates with a
    // one-query oracle.
    use osslscope::discovery::session::CoverageState;
    const OP_SIGNATURE: u32 = 12;
    let ecdsa_class = osslscope::kinds::ALG_NAMES
        .iter()
        .position(|a| a.name == "ECDSA-SHA2-256")
        .expect("registry carries ECDSA-SHA2-256") as u16;
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    let imp = 0x7f00_2000u64;
    env.push(query_ret(OP_SIGNATURE, arr, 0));
    for idx in 0..30u64 {
        if idx == 29 {
            env.push(enc_alg(
                OP_SIGNATURE,
                ecdsa_class,
                wire::ALG_OK,
                0,
                arr,
                idx,
            ));
        } else {
            env.push(ok_alg(OP_SIGNATURE, arr, idx));
        }
    }
    env.push(dispatch_row(OP_SIGNATURE, 3, imp, arr, 29));
    env.staged.termd = vec![(arr, wire::make_termd(OP_SIGNATURE, 30))];
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(!d.budget_exhausted);
    // Few-query oracle: exactly one query observed, yet slot 29 is
    // covered — under the sampler this stream would need 30.
    assert_eq!(d.queries_delta, 1);
    let snap = core.snapshot();
    assert_eq!(snap.queries_observed, 1);
    assert_eq!(snap.tables.len(), 1);
    assert!(matches!(
        snap.tables[0].state,
        CoverageState::Terminated { len: 30 }
    ));
    assert!(snap.reasons.is_empty());
    let late = snap
        .candidates
        .iter()
        .find(|c| c.op == OP_SIGNATURE && c.funcid == 3)
        .expect("slot-29 candidate present after one query");
    assert!(
        late.class.contains("ECDSA"),
        "slot-29 class must be ECDSA, got {}",
        late.class
    );
    assert_eq!(late.arr, arr);
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
    // The rebirth inherits nothing — not even same-poll walks
    // (F-A/A4: the drain precedes reconcile, so turnover-poll
    // events keep the old era; only post-turnover polls walk the
    // new epoch).
    assert!(matches!(snap.tables[0].state, CoverageState::Unseen));
    // A post-turnover walk (unambiguously new-era) starts a
    // prefix: one walked slot against the evicted len-5 proof,
    // and the new epoch must re-prove from scratch.
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    core.poll(&mut env, ample_budget()).unwrap();
    let snap = core.snapshot();
    assert_eq!(snap.tables.len(), 1);
    assert_eq!(snap.tables[0].epoch, 1);
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
    let (exe, dev, ino) = provider_file();
    assert_eq!(
        d.candidates[0].advertising,
        exe.to_string_lossy().into_owned()
    );
    assert_eq!(d.candidates[1].advertising, LEGACY_SO);
    for c in &d.candidates {
        let b = c.backing.as_ref().expect("backed candidate");
        assert_eq!(
            (b.dev.as_str(), b.ino, b.offset),
            (dev.as_str(), ino, 0x2000)
        );
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
            op: None,
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

#[test]
fn close_recycle_carries_prewip_final() {
    // Close after a pin failure (reaped owned child): the wipe
    // still discards tainted state, but the error carries the
    // pre-wipe final (polls' joins + close-time tail count) so
    // custody-holding callers lose neither the evidence nor the
    // close-time magnitude (G07: the doc records the event AND its
    // count, never stderr-only).
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.candidates.len(), 1);
    assert!(core.snapshot().queries_observed >= 1);
    // Tail queued at close + pin dead (reaped): recycle error ...
    for idx in 1..4u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    env.pin_ok = false;
    let err = core.close(&mut env).unwrap_err();
    let rec = err.downcast_ref::<Recycled>().expect("typed recycle");
    // ... with the wiped discard snapshot (taint-safe contract) ...
    assert!(rec.snapshot.candidates.is_empty());
    assert_eq!(rec.snapshot.queries_observed, 0);
    // ... AND the pre-wipe final: the poll's candidate + query plus
    // the 3 close-time tail items as shortfall magnitude.
    let fin = rec.final_snapshot.as_ref().expect("close carries final");
    assert_eq!(fin.candidates.len(), 1);
    assert!(fin.queries_observed >= 1);
    assert_eq!(losses_of(fin)[&HOST_DRAIN_SHORTFALL], 3);
}

#[test]
fn close_reaped_child_keeps_sites_no_retire_all() {
    // Close after a REAPED owned child: /proc is gone, so the
    // close-time maps read is empty. Reconciling against empty
    // maps must NOT retire every table (incarnation None != live
    // fingerprint): the last-good epochs stand, the final keeps
    // the poll's candidate, and the tail still counts (T14r4 w1:
    // retire-all wiped 581 late sites to a 0-site doc).
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    env.push(query_ret(OP_DIGEST, arr, 0));
    env.push(ok_alg(OP_DIGEST, arr, 0));
    env.push(dispatch_row(OP_DIGEST, 7, 0x7f00_2000, arr, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.candidates.len(), 1);
    for idx in 1..4u64 {
        env.push(ok_alg(OP_DIGEST, arr, idx));
    }
    // Reaped: pin dead AND maps gone (LiveEnv reads nothing).
    env.pin_ok = false;
    env.maps.clear();
    let err = core.close(&mut env).unwrap_err();
    let rec = err.downcast_ref::<Recycled>().expect("typed recycle");
    assert!(rec.snapshot.candidates.is_empty());
    let fin = rec.final_snapshot.as_ref().expect("close carries final");
    assert_eq!(fin.candidates.len(), 1);
    // Live-epoch tables survive (sites render from live tables;
    // retire-all empties them and the doc collapses to 0 sites).
    assert_eq!(
        fin.tables.len(),
        1,
        "empty maps must not retire live tables"
    );
    assert!(
        fin.retained_reasons.is_empty(),
        "no retire gaps: {:?}",
        fin.retained_reasons
    );
    assert!(fin.queries_observed >= 1);
    assert_eq!(losses_of(fin)[&HOST_DRAIN_SHORTFALL], 3);
}

#[test]
fn stage2_reattach_on_same_path_replacement() {
    // T14r4-2b: attach reuse compares backing identity, not just
    // offset+path. A same-path replacement (same path+offset, new
    // inode, target remapped) must RE-ATTACH, never reuse the stale
    // install pinned to the old bytes.
    use std::os::unix::fs::MetadataExt;
    let dir = std::env::temp_dir().join(format!("osslscope-reuse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let prov = dir.join("idprov.so");
    std::fs::write(&prov, b"v1").unwrap();
    let ino1 = std::fs::metadata(&prov).unwrap().ino();
    let exe = prov.to_string_lossy().into_owned();
    let mut env = TestEnv::new();
    env.maps = vec![mapping(0x7f00_0000, 0x10000, true, 0, "08:01", ino1, &exe)];
    let mut core = SessionCore::new(prov.clone(), String::new(), false, 4242);
    // First init attaches and records ino1.
    env.push(enc_init(0x7f00_3000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.attaches.iter().all(|a| a.failed.is_none()));
    assert_eq!(env.stage2.len(), 1);
    // A1: the install carries the resolve-time raw identity for
    // expected-binding (not just the maps-text triple).
    let meta1 = std::fs::metadata(&prov).unwrap();
    assert_eq!(env.stage2[0].3, Some((meta1.dev(), meta1.ino())));
    // Replace the path (new inode, same path); the target remaps
    // the new file at the same address (same offset).
    std::fs::remove_file(&prov).unwrap();
    std::fs::write(&prov, b"v2-longer").unwrap();
    let ino2 = std::fs::metadata(&prov).unwrap().ino();
    assert_ne!(ino2, ino1);
    env.maps = vec![mapping(0x7f00_0000, 0x10000, true, 0, "08:01", ino2, &exe)];
    env.push(enc_init(0x7f00_3000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.attaches.iter().all(|a| a.failed.is_none()));
    assert_eq!(env.stage2.len(), 2, "replacement must re-attach, not reuse");
    std::fs::remove_dir_all(&dir).unwrap_or_default();
}

// ---------------------------------------------------------------------------
// F-A/A4: incarnation binding — repeat-init suspects tables, stragglers
// keep their era, re-walks heal the epoch.
// ---------------------------------------------------------------------------

/// Walk one row of a table: query + alg + row; returns the new
/// candidate's epoch.
fn walk_row(env: &mut TestEnv, core: &mut SessionCore, arr: u64, idx: u64, funcid: u32, imp: u64) {
    env.push(query_ret(OP_DIGEST, arr, idx));
    env.push(ok_alg(OP_DIGEST, arr, idx));
    env.push(dispatch_row(OP_DIGEST, funcid, imp, arr, idx));
    core.poll(env, ample_budget()).unwrap();
}

fn epoch_of(cands: &[osslscope::discovery::session::DiscoveredCandidate], arr: u64) -> u64 {
    cands.iter().find(|c| c.arr == arr).unwrap().epoch
}

#[test]
fn repeat_init_retires_provider_tables() {
    // F-A/A4: a repeat init re-resolves to the provider file — its
    // tables retire (same retirement as maps turnover: proof
    // dropped, alg join pruned, kernel evicted, rebirth visible).
    // Another file's tables are untouched.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    env.push(enc_init(0x7f00_3000, 0));
    core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(env.stage2.len(), 1);

    let arr_a = 0x7f00_1000u64;
    let arr_b = 0x7f01_1000u64;
    walk_row(&mut env, &mut core, arr_a, 0, 7, 0x7f00_2000);
    walk_row(&mut env, &mut core, arr_b, 0, 7, 0x7f01_2000);
    let snap = core.snapshot();
    let e_a = epoch_of(&snap.candidates, arr_a);
    let e_b = epoch_of(&snap.candidates, arr_b);
    assert_ne!(e_a, e_b);

    env.push(enc_init(0x7f00_3000, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(env.stage2.len(), 1, "same bytes: install stands");
    assert_eq!(d.retirements.len(), 1);
    assert_eq!(
        (d.retirements[0].op, d.retirements[0].epoch),
        (OP_DIGEST, e_a)
    );
    assert_eq!(env.evicted, vec![arr_a]);
    // The rebirth is delta-visible and unproven; the other file's
    // epoch never turned over.
    let rb = d
        .tables
        .iter()
        .map(|t| t.epoch)
        .find(|e| *e != e_a && *e != e_b)
        .expect("rebirth table");
    assert!(core.snapshot().tables.iter().any(|t| t.epoch == rb));
    assert!(core.snapshot().tables.iter().any(|t| t.epoch == e_b));
}

#[test]
fn repeat_init_suspects_anonymous_arrays_globally() {
    // F-A/A4: anonymous arrays carry no verifiable identity, so any
    // repeat init suspects them — while file-backed tables outside
    // the init's provider file survive.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    env.push(enc_init(0x7f02_1000, 1));
    core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(env.stage2.len(), 1);

    let arr_p = 0x7f00_1000u64;
    let arr_l = 0x7f01_1000u64;
    let arr_x = 0x6000_1000u64;
    walk_row(&mut env, &mut core, arr_p, 0, 7, 0x7f00_2000);
    walk_row(&mut env, &mut core, arr_l, 0, 7, 0x7f01_2000);
    walk_row(&mut env, &mut core, arr_x, 0, 7, 0x7f00_2000);
    let snap = core.snapshot();
    let e_p = epoch_of(&snap.candidates, arr_p);
    let e_l = epoch_of(&snap.candidates, arr_l);
    let e_x = epoch_of(&snap.candidates, arr_x);

    // Repeat init resolving to the libcrypto file.
    env.push(enc_init(0x7f01_3000, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    let retired: std::collections::HashSet<u64> = d.retirements.iter().map(|r| r.epoch).collect();
    assert!(retired.contains(&e_l), "matching file retires: {retired:?}");
    assert!(
        retired.contains(&e_x),
        "anonymous is globally suspect: {retired:?}"
    );
    assert!(!retired.contains(&e_p), "other file survives: {retired:?}");
    assert!(env.evicted.contains(&arr_x));
    assert!(!env.evicted.contains(&arr_p));
}

#[test]
fn repeat_init_unresolvable_suspects_anon_only() {
    // F-A/A4: an init whose address resolves nowhere cannot scope
    // to a file — but anonymous arrays are still suspect. Live
    // file-backed tables stand (their file is mapped, so an
    // unresolvable init is not theirs).
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    env.push(enc_init(0x7f00_3000, 0));
    core.poll(&mut env, ample_budget()).unwrap();

    let arr_p = 0x7f00_1000u64;
    let arr_x = 0x6000_1000u64;
    walk_row(&mut env, &mut core, arr_p, 0, 7, 0x7f00_2000);
    walk_row(&mut env, &mut core, arr_x, 0, 7, 0x7f00_2000);
    let snap = core.snapshot();
    let e_p = epoch_of(&snap.candidates, arr_p);
    let e_x = epoch_of(&snap.candidates, arr_x);

    env.push(enc_init(0xdead_beef, 0));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    let retired: std::collections::HashSet<u64> = d.retirements.iter().map(|r| r.epoch).collect();
    assert_eq!(retired, std::collections::HashSet::from([e_x]));
    assert!(!retired.contains(&e_p));
}

#[test]
fn stragglers_keep_old_epoch_across_turnover() {
    // F-A/A4: the drain runs before reconcile, so a late-arriving
    // row for a never-before-seen slot joins the OLD epoch — never
    // the rebirth. (Reconcile-first stamped it with the new epoch:
    // A's evidence attributed to B.)
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    walk_row(&mut env, &mut core, arr, 0, 7, 0x7f00_2000);
    let e0 = epoch_of(&core.snapshot().candidates, arr);

    // Same address, replacement inode + a straggler for a fresh slot.
    env.maps = vec![
        mapping(0x7f00_0000, 0x10000, true, 0, "08:01", 101, PROVIDER),
        mapping(0x7f01_0000, 0x20000, true, 0, "08:01", 200, LIBCRYPTO),
    ];
    env.push(ok_alg(OP_DIGEST, arr, 9));
    env.push(dispatch_row(OP_DIGEST, 8, 0x7f00_2010, arr, 9));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.retirements.len(), 1);
    assert_eq!(d.retirements[0].epoch, e0);
    assert_eq!(d.candidates.len(), 1);
    assert_eq!(
        d.candidates[0].epoch, e0,
        "straggler must keep its era, not the rebirth"
    );
}

#[test]
fn rebirth_rewalk_heals_candidate_epoch() {
    // F-A/A4: new-epoch rows first arrive stamped with the retired
    // epoch (one poll stale — the drain precedes reconcile); the
    // next re-walk refreshes them to the live epoch and re-emits.
    let mut env = TestEnv::new();
    let mut core = test_core(false);
    let arr = 0x7f00_1000u64;
    walk_row(&mut env, &mut core, arr, 0, 7, 0x7f00_2000);
    let e0 = epoch_of(&core.snapshot().candidates, arr);

    env.maps = vec![
        mapping(0x7f00_0000, 0x10000, true, 0, "08:01", 101, PROVIDER),
        mapping(0x7f01_0000, 0x20000, true, 0, "08:01", 200, LIBCRYPTO),
    ];
    env.push(query_ret(OP_DIGEST, arr, 1));
    env.push(ok_alg(OP_DIGEST, arr, 1));
    env.push(dispatch_row(OP_DIGEST, 8, 0x7f00_2010, arr, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert_eq!(d.retirements.len(), 1);
    assert_eq!(d.candidates.len(), 1);
    assert_eq!(d.candidates[0].epoch, e0, "transitional old stamp");

    // Same rows re-walked: epoch heals to the rebirth and re-emits
    // (the refresh carries the epoch, not just remap identity).
    env.push(query_ret(OP_DIGEST, arr, 1));
    env.push(ok_alg(OP_DIGEST, arr, 1));
    env.push(dispatch_row(OP_DIGEST, 8, 0x7f00_2010, arr, 1));
    let d = core.poll(&mut env, ample_budget()).unwrap();
    assert!(d.retirements.is_empty());
    assert_eq!(d.candidates.len(), 1, "epoch heal must re-emit");
    let e1 = d.candidates[0].epoch;
    assert_ne!(e1, e0);
    assert!(
        core.snapshot().tables.iter().any(|t| t.epoch == e1),
        "healed epoch is the live table"
    );
}
