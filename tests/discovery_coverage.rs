//! SPDX-License-Identifier: GPL-3.0-or-later
//! T03 discovery-coverage gates: traversal completion, honest loss,
//! and single-query later-slot coverage.
//!
//! Host accounting tests feed synthetic event streams and map
//! snapshots into the real [`CoverageTracker`] (the unit
//! `harvest::run` uses), plus `schema::emit` for the PARTIAL
//! contract. Only `one_query_later_slot` (and the `nostore` live
//! check) need a privileged lane; they are `#[ignore]`d here and
//! run via the C4 harness with the prepared fixtures under
//! `crates/ossl-discover/tests/fixture/`.

use osslscope::discovery::coverage::{
    CoverageDelta, CoverageTracker, HOST_BAD_EVENT, HOST_ORPHAN_ROW, HOST_SHORT_EVENT,
    HOST_UNKNOWN_KIND, TableState, loss_source_name,
};
use osslscope::discovery::schema::{self, Row, Stats};
use osslscope_ebpf_common as wire;
use std::path::Path;

const OP_DIGEST: u32 = 1;
const ARR: u64 = 0x7f00_1000;

/// Backed maps into the test exe: addrs land in a real x PT_LOAD so
/// rows back (same shape as the schema unit tests).
fn backed_exe_maps() -> (Vec<u8>, Vec<osslscope::discovery::maps::Mapping>) {
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let elf = osslscope::discovery::elf::parse_elf(&exe).unwrap();
    let ph = elf
        .program_headers
        .iter()
        .find(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD
                && ph.p_flags & goblin::elf::program_header::PF_X != 0
        })
        .unwrap();
    let maps = vec![osslscope::discovery::maps::Mapping {
        start: 0x1000,
        end: 0x1000 + ph.p_filesz,
        x: true,
        offset: ph.p_offset,
        dev: "08:01".to_string(),
        ino: 42,
        path: "t".to_string(),
    }];
    (exe, maps)
}

fn ok_row(funcid: u32, n: u64) -> Row {
    Row {
        op: OP_DIGEST,
        alg_class: "SHA2-256".into(),
        weak: false,
        status: "ok".into(),
        funcid,
        impl_addr: 0x1000 + n * 0x10,
        arr: ARR,
    }
}

fn stats_from_tracker(t: &CoverageTracker) -> Stats {
    Stats {
        builtin: true,
        queries_observed: 9,
        unterminated_ops: t.unterminated_ops(),
        losses: t.losses(),
        lossy_slots: t.lossy_slots(),
        ..Stats::trivial()
    }
}

#[test]
fn later_unreadable_slot_is_partial() {
    // Slots 0..2 walk clean, slot 3's name is unreadable, and the
    // table terminates at 4: the walk is terminated but the doc is
    // PARTIAL — the lost identity is explicit, never silent.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    for idx in 0..3u64 {
        t.note_alg(OP_DIGEST, ARR, idx, false);
    }
    t.note_alg(OP_DIGEST, ARR, 3, true);
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 4))]);
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::Terminated { len: 4 }
    );
    assert!(t.unterminated_ops().is_empty());
    assert_eq!(t.lossy_slots(), 1);
    assert!(!t.is_complete());

    let (exe, maps) = backed_exe_maps();
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0), ok_row(7, 1)],
        true,
        &stats_from_tracker(&t),
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    assert_eq!(doc["reason"], "unreadable-alg");
    assert_eq!(doc["lossy_slots"], 1);
}

#[test]
fn empty_impl_does_not_silently_stall() {
    // An implementation-less slot is skipped (the walk advances past
    // it to the terminator) and the skip is explicit: the NOIMP
    // TRUNC bit forces PARTIAL with the bit visible in
    // `truncated_ops`. A stall (frozen counter, no flag) would leave
    // the table unterminated with no reason — that shape is rejected.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    t.note_alg(OP_DIGEST, ARR, 0, false);
    // Slot 1 is impl-less: no ALG record, but the walk continues.
    t.note_alg(OP_DIGEST, ARR, 2, false);
    t.ingest_trunc(&[(OP_DIGEST, wire::TRUNC_WALK_NOIMP)]);
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 3))]);
    // The skipped slot's content was never observed (not even its
    // name), so exact coverage fails: in progress with two
    // retained reasons, truncation ranked first.
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::InProgress { walked: 2 }
    );
    assert_eq!(
        t.reasons(),
        vec!["truncated-walk".to_string(), "prefix-walk".to_string()]
    );
    assert!(!t.is_complete());

    let (exe, maps) = backed_exe_maps();
    let mut stats = stats_from_tracker(&t);
    stats.truncated = vec![(OP_DIGEST, wire::TRUNC_WALK_NOIMP)];
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0), ok_row(7, 1)],
        true,
        &stats,
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    assert_eq!(doc["reason"], "truncated-walk");
    assert_eq!(
        doc["truncated_ops"],
        serde_json::json!({ "1": wire::TRUNC_WALK_NOIMP })
    );

    // The BPF contract behind this host accounting: the impl-less
    // path advances the per-array counter (no stall) and flags
    // NOIMP (no silence). Pinned by source shape (same precedent as
    // the privacy allowlist pins).
    let bpf = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/src/bin/harvest.rs"),
    )
    .unwrap();
    let imp_pos = bpf.find("imp == 0").expect("impl-less path must exist");
    let window = &bpf[imp_pos..(imp_pos + 600).min(bpf.len())];
    assert!(
        window.contains("advance_next") || window.contains("QUERY_NEXT.insert"),
        "impl-less slots must advance past, not freeze: {window}"
    );
    assert!(
        window.contains("TRUNC_WALK_NOIMP"),
        "impl-less skips must flag NOIMP: {window}"
    );
}

#[test]
fn bounds_512_513() {
    // Absent: an empty tracker is vacuously complete (absence is
    // explained by the caller's no-trigger doctrine, not here).
    let t = CoverageTracker::new();
    assert!(t.is_complete());
    assert_eq!(t.table_state(OP_DIGEST, ARR), TableState::Unseen);

    // One: a single alg plus terminator is complete.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    t.note_alg(OP_DIGEST, ARR, 0, false);
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 1))]);
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::Terminated { len: 1 }
    );
    assert!(t.is_complete());

    // 512: every slot walked, terminator proven at 512 by the
    // overrun guard — complete, and the doc keeps its shape.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    for idx in 0..512u64 {
        t.note_alg(OP_DIGEST, ARR, idx, false);
    }
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 512))]);
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::Terminated { len: 512 }
    );
    assert!(t.is_complete());
    let (exe, maps) = backed_exe_maps();
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0)],
        true,
        &stats_from_tracker(&t),
    )
    .unwrap();
    assert!(doc.get("status").is_none(), "512-entry table is COMPLETE");
    assert!(doc.get("losses").is_none());
    assert!(doc.get("unterminated_ops").is_none());

    // 513: slot 512 is live past the bound — TRUNC_ALGS, PARTIAL,
    // and no termination proof is recorded for the overlong array.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    for idx in 0..512u64 {
        t.note_alg(OP_DIGEST, ARR, idx, false);
    }
    t.ingest_trunc(&[(OP_DIGEST, wire::TRUNC_ALGS)]);
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::InProgress { walked: 512 }
    );
    assert_eq!(t.unterminated_ops(), vec![OP_DIGEST]);
    assert!(!t.is_complete());
    let mut stats = stats_from_tracker(&t);
    stats.truncated = vec![(OP_DIGEST, wire::TRUNC_ALGS)];
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0)],
        true,
        &stats,
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    // Overflow outranks the prefix it implies.
    assert_eq!(doc["reason"], "truncated-walk");
    assert_eq!(doc["unterminated_ops"], serde_json::json!([OP_DIGEST]));
}

#[test]
fn stale_proof_does_not_terminate() {
    // ABA growth: a len-5 proof reused by a reloaded longer array
    // at the same base, with slots 0..=6 walked and no counter
    // fired. Exact coverage fails (7 walked past a len-5 proof):
    // prefix PARTIAL, never silent COMPLETE.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    for idx in 0..7u64 {
        t.note_alg(OP_DIGEST, ARR, idx, false);
    }
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 5))]);
    assert_eq!(
        t.table_state(OP_DIGEST, ARR),
        TableState::InProgress { walked: 7 }
    );
    assert_eq!(t.unterminated_ops(), vec![OP_DIGEST]);
    assert!(!t.is_complete());

    let (exe, maps) = backed_exe_maps();
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0)],
        true,
        &stats_from_tracker(&t),
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    assert_eq!(doc["reason"], "prefix-walk");
}

#[test]
fn lost_alg_or_row_is_accounted() {
    // Ring reserve failures (BPF LOSS map) and userspace orphans /
    // undecodable events all land in one source-tagged loss ledger
    // that forces PARTIAL with reason `discovery-loss`.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    t.note_alg(OP_DIGEST, ARR, 0, false);
    t.ingest_losses(&[(wire::LOSS_RING_ROW, 5), (wire::LOSS_MAP_TRUNC, 1)]);
    t.note_orphan_row();
    t.note_orphan_row();
    t.note_bad_event(HOST_SHORT_EVENT);
    t.note_bad_event(HOST_UNKNOWN_KIND);
    t.note_bad_event(HOST_BAD_EVENT);
    t.ingest_termd(&[(ARR, wire::make_termd(OP_DIGEST, 1))]);
    let losses = t.losses();
    assert_eq!(
        losses,
        vec![
            (wire::LOSS_RING_ROW, 5),
            (wire::LOSS_MAP_TRUNC, 1),
            (HOST_ORPHAN_ROW, 2),
            (HOST_BAD_EVENT, 1),
            (HOST_SHORT_EVENT, 1),
            (HOST_UNKNOWN_KIND, 1),
        ]
    );
    assert!(!t.is_complete());

    // Every loss source has a stable public name.
    for (src, _) in &losses {
        assert!(
            loss_source_name(*src).is_some(),
            "loss source {src} must have a name"
        );
    }
    assert_eq!(loss_source_name(wire::LOSS_RING_ROW), Some("ring_row"));
    assert_eq!(loss_source_name(HOST_ORPHAN_ROW), Some("orphan_row"));

    let (exe, maps) = backed_exe_maps();
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0)],
        true,
        &stats_from_tracker(&t),
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    assert_eq!(doc["reason"], "discovery-loss");
    let lj = doc["losses"].as_object().unwrap();
    assert_eq!(lj["ring_row"], 5);
    assert_eq!(lj["orphan_row"], 2);
}

#[test]
fn pending_map_full_is_accounted() {
    // A full PENDING map (insert failures at entry) and returns
    // without entries (missed entries) are counted by source and
    // force PARTIAL — a query the walker never saw is a gap.
    let mut t = CoverageTracker::new();
    t.ingest_losses(&[
        (wire::LOSS_PENDING_QUERY_FULL, 3),
        (wire::LOSS_PENDING_QUERY_MISS, 1),
    ]);
    assert_eq!(
        t.losses(),
        vec![
            (wire::LOSS_PENDING_QUERY_FULL, 3),
            (wire::LOSS_PENDING_QUERY_MISS, 1),
        ]
    );
    assert_eq!(
        loss_source_name(wire::LOSS_PENDING_QUERY_FULL),
        Some("pending_query_full")
    );
    assert_eq!(
        loss_source_name(wire::LOSS_PENDING_QUERY_MISS),
        Some("pending_query_miss")
    );
    assert!(!t.is_complete());

    let (exe, maps) = backed_exe_maps();
    let doc = schema::emit(
        "t",
        Path::new("t"),
        "",
        &exe,
        &maps,
        &[ok_row(7, 0)],
        true,
        &stats_from_tracker(&t),
    )
    .unwrap();
    assert_eq!(doc["status"], "PARTIAL");
    assert_eq!(doc["reason"], "discovery-loss");
}

#[test]
fn partial_delta_retains_reasons() {
    // Gaps accumulate across polls and are never dropped: a later
    // clean poll does not erase an earlier prefix, and loss counters
    // sum. This is the retention contract T06's DiscoveryDelta
    // consumes.
    let mut acc = CoverageDelta::default();
    acc.accumulate(&CoverageDelta {
        reasons: vec!["prefix-walk".to_string()],
        losses: vec![(wire::LOSS_RING_ALG, 2)],
    });
    assert_eq!(acc.reasons, vec!["prefix-walk".to_string()]);
    acc.accumulate(&CoverageDelta {
        reasons: vec!["discovery-loss".to_string()],
        losses: vec![(wire::LOSS_RING_ALG, 3), (HOST_ORPHAN_ROW, 1)],
    });
    assert_eq!(
        acc.reasons,
        vec!["discovery-loss".to_string(), "prefix-walk".to_string()]
    );
    assert_eq!(
        acc.losses,
        vec![(wire::LOSS_RING_ALG, 5), (HOST_ORPHAN_ROW, 1)]
    );
    // A clean poll retains everything.
    acc.accumulate(&CoverageDelta::default());
    assert_eq!(acc.reasons.len(), 2);
    assert_eq!(acc.losses.len(), 2);

    // The tracker feeds the same vocabulary: an unterminated table
    // plus a loss yields both reasons, ranked.
    let mut t = CoverageTracker::new();
    t.note_query_ret(OP_DIGEST, ARR);
    t.note_alg(OP_DIGEST, ARR, 0, false);
    t.ingest_losses(&[(wire::LOSS_RING_ROW, 1)]);
    assert_eq!(
        t.reasons(),
        vec!["discovery-loss".to_string(), "prefix-walk".to_string()]
    );
}

/// Live single-query later-slot coverage (NOT-RUN here: needs a
/// privileged lane + C2-built BPF object + compiled fixtures).
///
/// Fixture: `later_slot_provider` offers 4 digest algs with the
/// oracle target `T03-LATE` at slot 3; `later_query_driver` issues
/// exactly ONE direct `query_operation` call, then sleeps. The
/// provider oracle (`$T03_ORACLE_FILE`) proves the query count is
/// bounded (one ordinary query, not hundreds of repeated trigger
/// rounds); the harvest doc must cover the slot-3 callback rows.
///
/// With the one-slot-per-query walker this FAILS honestly (prefix
/// PARTIAL, slot 3 uncovered) — it passes only under a complete
/// valid-lifetime traversal. Run on the lane via C4; never in CI.
#[test]
#[ignore = "live lane only: privileged BPF + fixtures (see doc comment)"]
fn one_query_later_slot() {
    let live = std::env::var("OSSL_T03_LIVE").unwrap_or_default();
    if live != "1" {
        eprintln!("one_query_later_slot: set OSSL_T03_LIVE=1 on the lane; skipping");
        return;
    }
    let provider = std::env::var("OSSL_T03_PROVIDER")
        .expect("OSSL_T03_PROVIDER=<later_slot_provider.so> on the lane");
    let driver =
        std::env::var("OSSL_T03_DRIVER").expect("OSSL_T03_DRIVER=<later_query_driver> on the lane");
    let object = std::env::var("OSSL_T03_OBJECT").expect("OSSL_T03_OBJECT=<harvest BPF .o>");
    let oracle_path =
        std::env::var("OSSL_T03_ORACLE").unwrap_or_else(|_| "/tmp/t03-oracle.log".to_string());
    let _ = std::fs::remove_file(&oracle_path);

    let mut child = std::process::Command::new(&driver)
        .arg(&provider)
        .arg("1")
        .env("T03_ORACLE_FILE", &oracle_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn later_query_driver");
    let pid = child.id();
    // GO flows only after every attach is installed: harvest runs
    // on a thread and releases the driver through `on_attached`
    // (sending GO earlier races the init probes and the single
    // query would miss stage-2).
    let (tx, rx) = std::sync::mpsc::channel();
    let cfg = osslscope::discovery::harvest::Config {
        pid,
        provider: provider.into(),
        object: object.into(),
        settle: std::time::Duration::from_millis(300),
        timeout: std::time::Duration::from_secs(20),
        cmdline_marker: None,
        builtin: false,
        legacy: false,
        table: None,
        force_offset: None,
    };
    let harvest = std::thread::spawn(move || {
        osslscope::discovery::harvest::run_detailed(
            &cfg,
            &|| {
                tx.send(()).map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(())
            },
            &|| false,
        )
    });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("harvest attached");
    use std::io::Write as _;
    writeln!(child.stdin.as_mut().unwrap(), "GO").unwrap();
    let (doc, _) = harvest
        .join()
        .expect("harvest thread")
        .expect("harvest run");
    // The driver sleeps 120s after its query; killing it is the
    // expected teardown (no exit-status assertion — the oracle
    // file, not the exit code, proves driver health).
    let _ = child.kill();
    let _ = child.wait();

    // Oracle: exactly one query_operation call for op 1.
    let oracle = std::fs::read_to_string(&oracle_path).unwrap_or_default();
    let queries = oracle.lines().filter(|l| l.starts_with("QUERY ")).count();
    assert_eq!(queries, 1, "oracle ledger must show one query: {oracle:?}");

    // Coverage: the slot-3 alg's rows are present despite one query.
    let rows = doc["rows"].as_array().expect("rows array");
    assert!(
        rows.iter()
            .any(|r| r["op"] == 1 && r["alg_class"] == "other" && r["funcid"] == 3),
        "slot-3 rows missing after one query: {doc}"
    );
}

/// Live no_store explicitness (NOT-RUN here; same lane gate).
/// A provider whose query sets `*no_store=1` must surface as
/// PARTIAL with the NO_STORE bit — a sampled slot plus an explicit
/// reason, never silent COMPLETE.
#[test]
#[ignore = "live lane only: privileged BPF + fixtures (see doc comment)"]
fn nostore_table_is_explicit_partial() {
    let live = std::env::var("OSSL_T03_LIVE").unwrap_or_default();
    if live != "1" {
        eprintln!("nostore_table_is_explicit_partial: set OSSL_T03_LIVE=1 on the lane; skipping");
        return;
    }
    let provider = std::env::var("OSSL_T03_NOSTORE_PROVIDER")
        .expect("OSSL_T03_NOSTORE_PROVIDER=<nostore_provider.so> on the lane");
    let driver =
        std::env::var("OSSL_T03_DRIVER").expect("OSSL_T03_DRIVER=<later_query_driver> on the lane");
    let object = std::env::var("OSSL_T03_OBJECT").expect("OSSL_T03_OBJECT=<harvest BPF .o>");
    let oracle_path =
        std::env::var("OSSL_T03_ORACLE").unwrap_or_else(|_| "/tmp/t03-oracle.log".to_string());
    let _ = std::fs::remove_file(&oracle_path);

    let mut child = std::process::Command::new(&driver)
        .arg(&provider)
        .arg("1")
        .env("T03_ORACLE_FILE", &oracle_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn later_query_driver");
    let pid = child.id();
    // GO flows only after every attach is installed (see
    // `one_query_later_slot`): sending it earlier races the init
    // probes.
    let (tx, rx) = std::sync::mpsc::channel();
    let cfg = osslscope::discovery::harvest::Config {
        pid,
        provider: provider.into(),
        object: object.into(),
        settle: std::time::Duration::from_millis(300),
        timeout: std::time::Duration::from_secs(20),
        cmdline_marker: None,
        builtin: false,
        legacy: false,
        table: None,
        force_offset: None,
    };
    let harvest = std::thread::spawn(move || {
        osslscope::discovery::harvest::run_detailed(
            &cfg,
            &|| {
                tx.send(()).map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(())
            },
            &|| false,
        )
    });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("harvest attached");
    use std::io::Write as _;
    writeln!(child.stdin.as_mut().unwrap(), "GO").unwrap();
    let (doc, _) = harvest
        .join()
        .expect("harvest thread")
        .expect("harvest run");
    // Killing the post-query sleep is the expected teardown (the
    // oracle file, not the exit code, proves driver health).
    let _ = child.kill();
    let _ = child.wait();
    let oracle = std::fs::read_to_string(&oracle_path).unwrap_or_default();
    assert!(
        oracle.contains("no_store=1"),
        "oracle must show no_store=1: {oracle:?}"
    );
    assert_eq!(doc["status"], "PARTIAL");
    let bits = doc["truncated_ops"]["1"].as_u64().unwrap_or(0);
    assert!(
        bits & wire::TRUNC_NO_STORE != 0,
        "NO_STORE bit must be set: {doc}"
    );
}
