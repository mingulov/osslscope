// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C compat fixtures (§6C-13): frozen golden exporter payloads +
//! terminal frames, generated FROM REAL RUNS by the ignored
//! generator below, then frozen byte-identical. The compat test
//! parses + re-renders every golden on every run.
use std::path::PathBuf;
use std::process::Command;

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/compat")
}

fn golden_sets() -> Vec<&'static str> {
    vec![
        "partial-fallback",
        "partial-cut",
        "oneshot",
        "trace",
        // P2fix1 DELTA-9: real focused latency/status documents
        // (guest focused captures; the trace set stays frozen as
        // the supplemental adapter fixture).
        "focused-latency",
        "focused-status",
    ]
}

/// Parse + re-render every golden (runs always). Additive fields
/// need new goldens; frozen ones never change.
#[test]
fn compat_goldens_parse_and_rerender() {
    let root = compat_dir();
    for set in golden_sets() {
        let snap_path = root
            .join("presentation-v1")
            .join(format!("snapshot-{set}.json"));
        let body = std::fs::read_to_string(&snap_path)
            .unwrap_or_else(|_| panic!("missing golden: {}", snap_path.display()));
        // Tolerant parse (unknown fields ignored, additive defaulted).
        let snap: osslscope::presentation::OperatorSnapshot =
            serde_json::from_str(&body).expect("golden parses");
        snap.check_unknown_invariant().expect("golden invariant");
        // Prometheus: byte-exact re-render.
        let prom_path = root
            .join("prometheus-v1")
            .join(format!("metrics-{set}.txt"));
        let want_prom = std::fs::read_to_string(&prom_path).expect("prom golden");
        let got_prom = osslscope::presentation::prometheus::render(&snap);
        assert_eq!(got_prom, want_prom, "prometheus golden {set}");
        // OTel: series-equal re-render (deployment identity —
        // service.version/instance.id — is not a series).
        let otel_path = root.join("otel-v1").join(format!("metrics-{set}.json"));
        let want_otel = std::fs::read_to_string(&otel_path).expect("otel golden");
        let got_otel = osslscope::presentation::otel::render(&snap);
        assert_otel_series_equal(&want_otel, &got_otel, set);
        // Terminal frame: byte-exact re-render.
        let frame_path = root.join("frame-v1").join(format!("frame-{set}.txt"));
        let want_frame = std::fs::read_to_string(&frame_path).expect("frame golden");
        let got_frame = osslscope::presentation::watch::render_frame(&snap);
        assert_eq!(got_frame, want_frame, "frame golden {set}");
    }
}

fn assert_otel_series_equal(want: &str, got: &str, set: &str) {
    let w: serde_json::Value = serde_json::from_str(want).expect("want json");
    let g: serde_json::Value = serde_json::from_str(got).expect("got json");
    let wmetrics = &w["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
    let gmetrics = &g["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
    assert_eq!(wmetrics, gmetrics, "otel metrics {set}");
    assert_eq!(
        w["resourceMetrics"][0]["scopeMetrics"][0]["scope"],
        g["resourceMetrics"][0]["scopeMetrics"][0]["scope"],
        "otel scope {set}"
    );
    assert_eq!(
        w["resourceMetrics"][0]["resource"]["attributes"][0],
        g["resourceMetrics"][0]["resource"]["attributes"][0],
        "otel service.name {set}"
    );
}

// --- Generator (test helper, NOT shipped code) ---

fn fresh_dir(name: &str) -> PathBuf {
    let root = std::env::var("OSSL_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = root.join(format!(
        "compatgen-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Normalize volatile/incidental fields for byte-freezing
/// (documented §6C-13 normalization): produced clocks → fixed
/// constants (age 13, stale recomputed), run identity → fixed
/// constants. Windows, counts, loss, completeness, policy, and
/// window bytes/sha stay REAL.
fn normalize(
    mut snap: osslscope::presentation::OperatorSnapshot,
) -> osslscope::presentation::OperatorSnapshot {
    use osslscope::presentation::snapshot as s;
    snap.produced_wall_ns = 1_700_000_000_000_000_000;
    if let Some(w) = snap.window.as_ref() {
        snap.produced_monotonic_ns = w.effective_end_ns.saturating_add(13);
        snap.health.snapshot_age_ns = Some(13);
        snap.health.stale = false;
    } else {
        snap.produced_monotonic_ns = 1_700_000_000_000_000_000;
    }
    if snap.source.run_id.is_some() {
        snap.source.run_id = Some(s::RunIdShape {
            pid: 1,
            starttime: 2,
            boot_id: "00000000-0000-0000-0000-000000000000".to_string(),
        });
    }
    snap.check_unknown_invariant()
        .expect("normalized invariant");
    snap
}

fn freeze(set: &str, snap: &osslscope::presentation::OperatorSnapshot) {
    let root = compat_dir();
    for sub in ["presentation-v1", "prometheus-v1", "otel-v1", "frame-v1"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    let snap_json = serde_json::to_string_pretty(snap).unwrap() + "\n";
    std::fs::write(
        root.join("presentation-v1")
            .join(format!("snapshot-{set}.json")),
        snap_json,
    )
    .unwrap();
    let prom = osslscope::presentation::prometheus::render(snap);
    std::fs::write(
        root.join("prometheus-v1")
            .join(format!("metrics-{set}.txt")),
        prom,
    )
    .unwrap();
    let otel = osslscope::presentation::otel::render(snap);
    std::fs::write(
        root.join("otel-v1").join(format!("metrics-{set}.json")),
        otel,
    )
    .unwrap();
    let frame = osslscope::presentation::watch::render_frame(snap);
    std::fs::write(
        root.join("frame-v1").join(format!("frame-{set}.txt")),
        frame,
    )
    .unwrap();
}

/// Regenerate goldens from REAL service runs (run explicitly with
/// `--ignored`; review the diff before accepting).
#[test]
#[ignore = "golden regen only (COMPAT_REGEN=1 + explicit)"]
fn compat_regen_from_real_runs() {
    if std::env::var("COMPAT_REGEN").unwrap_or_default() != "1" {
        eprintln!("compat regen: set COMPAT_REGEN=1; skipping");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_osslscope");
    // Real run: 1s windows vs a live sleeper, SIGTERM close.
    let dir = fresh_dir("run");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = Command::new(exe)
        .arg("service")
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status.code(), Some(3), "cancel-after-windows exits 3");
    assert!(dir.join("window-0000000000.json").is_file());
    // Golden 1: window-0 prefix state (faithful mid-run state: the
    // real window-0 file + real sequence file, no summary yet).
    let prefix = fresh_dir("prefix");
    std::fs::copy(
        dir.join("window-0000000000.json"),
        prefix.join("window-0000000000.json"),
    )
    .unwrap();
    // Sequence at window-0 time: next_seq=1, same generation/run.
    let seq: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("sequence.json")).unwrap()).unwrap();
    let mut seq0 = seq.clone();
    seq0["next_seq"] = serde_json::json!(1);
    std::fs::write(
        prefix.join("sequence.json"),
        serde_json::to_string(&seq0).unwrap(),
    )
    .unwrap();
    if dir.join("policy-status.json").is_file() {
        std::fs::copy(
            dir.join("policy-status.json"),
            prefix.join("policy-status.json"),
        )
        .unwrap();
    }
    let snap = {
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", prefix.display()));
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &prefix, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    freeze("partial-fallback", &normalize(snap));
    // Golden 2: full end-state fold (all windows + summary).
    let snap = {
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()));
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &dir, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    // Sanity: the real run ends in a signal cut with loss reasons.
    assert!(snap.window.as_ref().unwrap().signal_cut, "real cut");
    assert_eq!(snap.completeness.state.as_deref(), Some("partial"));
    assert!(!snap.loss.counters.is_empty(), "real loss counters");
    freeze("partial-cut", &normalize(snap));
    // Golden 3: oneshot over the real window-0 document.
    let win0: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("window-0000000000.json")).unwrap())
            .unwrap();
    let doc = win0["document"].clone();
    let snap = osslscope::presentation::snapshot::Presenter::oneshot(&doc).unwrap();
    freeze("oneshot", &normalize(snap));
    // Golden 4: oneshot over the LIVE guest trace doc (100%
    // live-real trace plane + real api_activity; doc shell is the
    // standard empty fixture — disclosed, not hand-written).
    let trace_input =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/compat/inputs/trace-golden-doc.json");
    let trace_doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trace_input).expect("live trace input"))
            .expect("live trace input parses");
    assert_eq!(trace_doc["schema"], "observed-crypto-v2.9");
    let snap = osslscope::presentation::snapshot::Presenter::oneshot(&trace_doc).unwrap();
    assert!(snap.trace.is_some(), "live trace block projects");
    assert!(snap.histograms.is_some(), "live histograms project");
    freeze("trace", &normalize(snap));
    // Publish the reviewed goldens (the test wrote them; the diff is
    // reviewable in git status).
    for set in golden_sets() {
        eprintln!("froze golden set: {set}");
    }
}

/// Regenerate ONLY the clean-COMPLETE service golden from a REAL
/// guest service run (run explicitly with `--ignored` in the
/// BPF guest lane; review the diff before accepting). The host
/// lane forces PARTIAL via polling fallback, so this set needs
/// the guest: 1s windows vs a live sleeper, SIGTERM close — the
/// window-0 prefix finalized COMPLETE before the cut.
#[test]
#[ignore = "golden regen only (COMPAT_REGEN=1 + COMPAT_GUEST_BPF=1, guest lane)"]
fn compat_regen_clean_complete_from_guest() {
    if std::env::var("COMPAT_REGEN").unwrap_or_default() != "1"
        || std::env::var("COMPAT_GUEST_BPF").unwrap_or_default() != "1"
    {
        eprintln!(
            "clean-complete regen: set COMPAT_REGEN=1 + COMPAT_GUEST_BPF=1 in the guest; skipping"
        );
        return;
    }
    let exe = env!("CARGO_BIN_EXE_osslscope");
    let dir = fresh_dir("cc-run");
    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().to_string();
    let mut svc = Command::new(exe)
        .arg("service")
        .arg("--out")
        .arg(&dir)
        .arg("--pid")
        .arg(&pid)
        .arg("--window")
        .arg("1")
        .arg("--interval")
        .arg("0.2")
        .spawn()
        .expect("spawn service");
    std::thread::sleep(std::time::Duration::from_secs(3));
    unsafe { libc::kill(svc.id() as i32, libc::SIGTERM) };
    let status = svc.wait().expect("wait service");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status.code(), Some(3), "cancel-after-windows exits 3");
    assert!(dir.join("window-0000000000.json").is_file());
    // Window-0 prefix state (the real window-0 file + real
    // sequence file at next_seq=1 — same construction as the
    // partial-fallback golden, but the guest lane finalizes it
    // COMPLETE).
    let prefix = fresh_dir("cc-prefix");
    std::fs::copy(
        dir.join("window-0000000000.json"),
        prefix.join("window-0000000000.json"),
    )
    .unwrap();
    let seq: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("sequence.json")).unwrap()).unwrap();
    let mut seq0 = seq.clone();
    seq0["next_seq"] = serde_json::json!(1);
    std::fs::write(
        prefix.join("sequence.json"),
        serde_json::to_string(&seq0).unwrap(),
    )
    .unwrap();
    if dir.join("policy-status.json").is_file() {
        std::fs::copy(
            dir.join("policy-status.json"),
            prefix.join("policy-status.json"),
        )
        .unwrap();
    }
    let snap = {
        let ckpt = std::path::PathBuf::from(format!("{}.checkpoint.json", prefix.display()));
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &prefix, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    // The qualification requirement: a REAL clean-COMPLETE
    // service window (fails loudly if the lane forces PARTIAL).
    eprintln!(
        "complete-diag: state={:?} reasons={:?} cuts={:?}/{:?} counters={} epoch_partial={:?}",
        snap.completeness.state,
        snap.completeness.reasons,
        snap.window.as_ref().map(|w| w.signal_cut),
        snap.window.as_ref().map(|w| w.accum_cut),
        snap.loss.counters.len(),
        snap.completeness.epoch_partial_by_class,
    );
    assert_eq!(snap.completeness.state.as_deref(), Some("complete"));
    assert!(!snap.window.as_ref().unwrap().signal_cut);
    assert!(
        snap.loss.counters.is_empty(),
        "clean means no loss counters"
    );
    freeze("complete-service", &normalize(snap));
    eprintln!("froze golden set: complete-service");
}

/// Freeze the focused latency/status golden sets from the REAL
/// guest focused documents (run explicitly with `--ignored` after
/// the c023 focused-docs leg copies its outputs to
/// tests/compat/inputs/; review the diff before accepting).
#[test]
#[ignore = "golden freeze only (COMPAT_REGEN=1 + inputs present)"]
/// Focused goldens freeze from REVIEWED public fixtures
/// (`tests/compat/inputs/focused-*-doc.json` — derived
/// workspace-privately from the guest receipts with clocks kept
/// monotonic-relative, sites redacted to their count, and trace
/// counts/loss/completeness verbatim; P2fix2 item 25). Raw guest
/// documents NEVER enter this tree (normalization-before-entry);
/// the receipts stay in the private workspace.
fn compat_freeze_focused_docs() {
    if std::env::var("COMPAT_REGEN").unwrap_or_default() != "1" {
        eprintln!("focused freeze: set COMPAT_REGEN=1; skipping");
        return;
    }
    for (set, mode, want_hist) in [
        ("focused-latency", "latency", true),
        ("focused-status", "status", false),
    ] {
        let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/compat/inputs/focused-{mode}-doc.json"));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&input).expect("live focused input"))
                .expect("focused input parses");
        assert_eq!(doc["schema"], "observed-crypto-v2.9");
        assert_eq!(doc["trace_summary"]["mode"], mode);
        let snap = osslscope::presentation::snapshot::Presenter::oneshot(&doc).unwrap();
        assert!(snap.trace.is_some(), "live trace block projects");
        assert_eq!(snap.histograms.is_some(), want_hist);
        snap.check_unknown_invariant().expect("focused invariant");
        freeze(set, &normalize(snap));
        eprintln!("froze golden set: {set}");
    }
}

/// The adopted service golden (P2fix2 item 11, codex DELTA-9 +
/// AMEND-A6-REVISE): the genuine polling-fallback PARTIAL window is
/// the aggregate slice's service golden — PARTIAL solely on
/// `loss:lifecycle.polling_fallback` (loss class 1, every other
/// class 0), both cuts false, real loss counter. The
/// complete-service golden stays blocked (no complete window
/// observed — see the fix report), so this PARTIAL shape is the
/// frozen service contract until re-qualification.
#[test]
fn service_golden_is_polling_fallback_partial() {
    let root = compat_dir();
    let snap: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("presentation-v1/snapshot-partial-fallback.json"))
            .expect("service golden present"),
    )
    .expect("service golden parses");
    assert_eq!(snap["completeness"]["state"], "partial");
    assert_eq!(
        snap["completeness"]["reasons"],
        serde_json::json!(["loss:lifecycle.polling_fallback"])
    );
    let epoch = &snap["completeness"]["epoch_partial_by_class"];
    assert_eq!(epoch["loss"], 1);
    for class in [
        "unknown_denominator",
        "undiscovered_sites",
        "unattached_sites",
        "unattributed_calls",
        "startup_gap",
        "tail_gap",
        "signal_cut",
        "visibility_lost",
        "no_reasons",
    ] {
        assert_eq!(epoch[class], 0, "solely polling-fallback: {class}");
    }
    assert_eq!(snap["window"]["signal_cut"], false);
    assert_eq!(snap["window"]["accum_cut"], false);
    assert_eq!(
        snap["loss"]["counters"],
        serde_json::json!([{
            "kind": "Loss",
            "name": "lifecycle.polling_fallback",
            "source": "Lifecycle",
            "units": "Events",
            "value": 1,
        }])
    );
}

/// Compat goldens exist and are non-empty (fails loudly on a fresh
/// checkout without frozen fixtures).
#[test]
fn compat_goldens_present() {
    let root = compat_dir();
    for set in golden_sets() {
        for (sub, file) in [
            ("presentation-v1", format!("snapshot-{set}.json")),
            ("prometheus-v1", format!("metrics-{set}.txt")),
            ("otel-v1", format!("metrics-{set}.json")),
            ("frame-v1", format!("frame-{set}.txt")),
        ] {
            let path = root.join(sub).join(&file);
            let meta = std::fs::metadata(&path)
                .unwrap_or_else(|_| panic!("missing golden: {}", path.display()));
            assert!(meta.len() > 0, "empty golden: {}", path.display());
        }
    }
}
