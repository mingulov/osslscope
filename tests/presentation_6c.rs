// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C presenter/exporter contract pins (T8.2b): snapshot schema,
//! labels, budget, Prometheus/OTel adapters, watch/export commands.
//! See `tests/compat/` for frozen golden payloads.
use osslscope::presentation::{
    PRESENTATION_SCHEMA, Presenter, budget, labels, otel, prometheus, snapshot,
};

fn out_dir(name: &str) -> std::path::PathBuf {
    let root = std::env::var("OSSL_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = root.join(format!(
        "p6c-{}-{}-{}",
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

#[test]
fn schema_word_is_frozen() {
    assert_eq!(PRESENTATION_SCHEMA, "osslscope-presentation-v1");
}

#[test]
fn pre_first_window_shape_is_honest() {
    let dir = out_dir("pre-first");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    assert_eq!(snap.schema, PRESENTATION_SCHEMA);
    assert_eq!(snap.snapshot_seq, 0);
    assert!(snap.window.is_none());
    assert!(snap.trace.is_none());
    assert!(snap.histograms.is_none());
    assert!(snap.health.stale);
    assert!(snap.health.snapshot_age_ns.is_none());
    assert_eq!(snap.counts.calls_total, 0);
    assert_eq!(snap.counts.lanes, snapshot::Lanes::default());
    assert!(snap.counts.calls_window.is_none());
    assert!(snap.counts.site_rows.is_none());
    assert_eq!(snap.members.retired_epoch, 0);
    assert!(snap.members.observed.is_none());
    assert!(snap.loss.counters.is_empty());
    // Unknown-registry invariant: every null has exactly one entry.
    snap.check_unknown_invariant().unwrap();
}

#[test]
fn label_allowlist_is_closed() {
    assert!(labels::is_name_allowed("outcome"));
    assert!(labels::is_name_allowed("outcome_class"));
    assert!(labels::is_name_allowed("le"));
    assert!(labels::is_name_allowed("api"));
    assert!(!labels::is_name_allowed("algorithm"));
    assert!(!labels::is_name_allowed("pid"));
    assert!(!labels::is_name_allowed("path"));
    assert!(!labels::is_name_allowed("command"));
    // Closed value vocabularies.
    assert!(labels::is_value_allowed("outcome", "no_verdict"));
    assert!(!labels::is_value_allowed("outcome", "NoVerdict"));
    assert!(labels::is_value_allowed("lane", "shared_ambiguous"));
    assert!(!labels::is_value_allowed("lane", "other"));
    assert!(labels::is_value_allowed("le", "+Inf"));
    assert!(!labels::is_value_allowed("le", "inf"));
    assert!(labels::is_value_allowed("api", "42"));
    assert!(!labels::is_value_allowed("api", "EVP_Digest"));
}

#[test]
fn spelling_rule_vectors() {
    // Ordered steps: drop suffix, split CamelCase, '-' → '_', lowercase.
    assert_eq!(labels::fold_word("NoVerdict"), "no_verdict");
    assert_eq!(labels::fold_word("visibility-lost:x"), "visibility_lost");
    assert_eq!(labels::fold_word("loss:depth"), "loss");
    assert_eq!(
        labels::fold_word("unknown-denominator"),
        "unknown_denominator"
    );
    assert_eq!(labels::fold_word("CorpseWait"), "corpse_wait");
}

#[test]
fn budget_caps_and_default_max() {
    assert_eq!(budget::EPOCH_SERIES_CAP, 1024);
    assert_eq!(budget::WINDOW_NEW_SERIES_CAP, 256);
    // Precomputed default-schema maximum (§6C-12 proof): 159.
    assert_eq!(budget::default_series_max(), 159);
}

#[test]
fn budget_overflow_is_counted_not_silent() {
    let mut b = budget::Budget::new();
    b.begin_window();
    // Admit the full default schema: 159 series, zero overflow.
    for i in 0..159 {
        assert!(b.admit_series("m", &format!("l={i:03}")));
    }
    assert_eq!(b.overflow(), 0);
    // By-api overflow (§6C-12 recomputed first-window example):
    // 159 + 4 whole units admitted = 243; 261 units omitted whole.
    let mut omitted_units = 0u64;
    for api in 20..=72u32 {
        for class in ["empty", "failure", "retry", "success", "unknown"] {
            let unit: Vec<budget::SeriesKey> = (0..budget::UNIT_SERIES)
                .map(|s| {
                    (
                        "osslscope_dispatch_duration_nanoseconds".to_string(),
                        format!("api=\"{api}\",outcome_class=\"{class}\",s={s:02}"),
                    )
                })
                .collect();
            if !b.admit_unit(&unit) {
                omitted_units += 1;
            }
        }
    }
    assert_eq!(omitted_units, 261);
    assert_eq!(b.overflow(), 261 * budget::UNIT_SERIES as u64);
}

#[test]
fn prometheus_names_help_types_exact() {
    let table = prometheus::series_table();
    let names: Vec<&str> = table.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        names,
        [
            "osslscope_epoch_calls_total",
            "osslscope_window_site_rows",
            "osslscope_members_observed",
            "osslscope_members_retired_total",
            "osslscope_policy_outcome_info",
            "osslscope_window_completeness_info",
            "osslscope_window_cut_info",
            "osslscope_loss_events_total",
            "osslscope_epoch_partial_total",
            "osslscope_stream_drops_total",
            "osslscope_snapshot_age_nanoseconds",
            "osslscope_snapshot_stale",
            "osslscope_epoch_changes_total",
            "osslscope_exporter_series_overflow_total",
            "osslscope_window_exit_code",
            "osslscope_trace_calls_total",
            "osslscope_dispatch_duration_nanoseconds",
        ]
    );
    for (name, help, ty) in &table {
        assert!(!help.is_empty(), "{name}");
        assert!(matches!(*ty, "counter" | "gauge" | "histogram"), "{name}");
    }
    // Spot-check frozen help strings verbatim.
    let help_of = |n: &str| table.iter().find(|(m, _, _)| *m == n).unwrap().1;
    assert_eq!(
        help_of("osslscope_epoch_calls_total"),
        "Provider dispatch callback entries in the current epoch, by legacy partition lane."
    );
    assert_eq!(
        help_of("osslscope_dispatch_duration_nanoseconds"),
        "Paired public API duration in nanoseconds, by return class. Absent when trace mode is off, metadata, or status. Buckets are the frozen 6D edges."
    );
}

#[test]
fn prometheus_omission_never_zero_fills() {
    let dir = out_dir("omit");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    let text = prometheus::render(&snap);
    assert!(text.ends_with("# EOF\n"));
    // Unknown ⇒ series absent.
    assert!(!text.contains("osslscope_stream_drops_total"));
    assert!(!text.contains("osslscope_trace_calls_total"));
    assert!(!text.contains("osslscope_dispatch_duration_nanoseconds"));
    assert!(!text.contains("osslscope_policy_outcome_info"));
    // Defined-zero accumulators ARE present.
    assert!(text.contains("osslscope_epoch_calls_total"));
    assert!(text.contains("osslscope_loss_events_total"));
}

#[test]
fn otel_instruments_and_lockstep() {
    let table = otel::instrument_table();
    let names: Vec<&str> = table.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        names,
        [
            "osslscope.epoch.calls",
            "osslscope.window.site.rows",
            "osslscope.members.observed",
            "osslscope.members.retired",
            "osslscope.policy.outcome.info",
            "osslscope.window.completeness.info",
            "osslscope.window.cut.info",
            "osslscope.loss.events",
            "osslscope.epoch.partial",
            "osslscope.stream.drops",
            "osslscope.snapshot.age.nanoseconds",
            "osslscope.snapshot.stale",
            "osslscope.epoch.changes",
            "osslscope.exporter.series.overflow",
            "osslscope.window.exit.code",
            "osslscope.trace.calls",
            "osslscope.dispatch.duration.nanoseconds",
        ]
    );
    // Lockstep: same snapshot ⇒ same series presence in both adapters.
    let dir = out_dir("lockstep");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    let prom = prometheus::render(&snap);
    let payload = otel::render(&snap);
    let prom_table = prometheus::series_table();
    for (inst, _, _) in &table {
        // P-17 histogram families: presence of the instrument is
        // what lockstep pins (spellings differ by convention).
        if *inst == "osslscope.dispatch.duration.nanoseconds" {
            let prom_has = prom.contains("osslscope_dispatch_duration_nanoseconds_bucket");
            let otel_has = payload.contains(&format!("\"name\":\"{inst}\""));
            assert_eq!(prom_has, otel_has, "lockstep for {inst}");
            continue;
        }
        let otel_idx = table.iter().position(|(n, _, _)| n == inst).unwrap();
        let prom_name = prom_table[otel_idx].0;
        let prom_has = prom.lines().any(|l| {
            l.starts_with(&format!("{prom_name}{{")) || l.starts_with(&format!("{prom_name} "))
        });
        let otel_has = payload.contains(&format!("\"name\":\"{inst}\""));
        assert_eq!(prom_has, otel_has, "lockstep for {inst}");
    }
}

#[test]
fn epoch_fold_resets_on_generation_change() {
    let dir = out_dir("epoch-reset");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Two windows in generation 0, then one in generation 1.
    for (seq, generation, calls) in [(0u64, 0u64, 10u64), (1, 0, 20), (2, 1, 5)] {
        let env = snapshot::test_envelope(seq, generation, run.clone(), calls);
        p.fold_test_envelope(&env, "00").unwrap();
    }
    let snap = p.snapshot().unwrap();
    assert_eq!(snap.presenter.epoch_changes, 1);
    assert_eq!(snap.counts.calls_total, 5);
    assert_eq!(snap.counts.calls_window, Some(5));
    snap.check_unknown_invariant().unwrap();
}

#[test]
fn dual_path_service_doc_json_agree() {
    // C-08 dual path: the same CaptureDocument consumed via a
    // service envelope and via oneshot doc_json yields identical
    // shared signals (completeness, policy outcome, exit hint,
    // lanes, site rows).
    let dir = out_dir("dual-path");
    let doc = snapshot::test_document(7, "complete");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let env = snapshot::test_envelope_with_doc(0, 0, run, doc.clone());
    p.fold_test_envelope(&env, "00").unwrap();
    let service = p.snapshot().unwrap();
    let oneshot = Presenter::oneshot(&doc).unwrap();
    assert_eq!(service.completeness.state, oneshot.completeness.state);
    assert_eq!(service.completeness.reasons, oneshot.completeness.reasons);
    assert_eq!(service.policy.outcome, oneshot.policy.outcome);
    assert_eq!(service.exit_hint, oneshot.exit_hint);
    assert_eq!(service.counts.calls_window, oneshot.counts.calls_window);
    assert_eq!(service.counts.lanes_window, oneshot.counts.lanes_window);
    assert_eq!(service.counts.site_rows, oneshot.counts.site_rows);
    service.check_unknown_invariant().unwrap();
    oneshot.check_unknown_invariant().unwrap();
}

#[test]
fn privacy_negatives_hold_everywhere() {
    let dir = out_dir("privacy");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    let prom = prometheus::render(&snap);
    let payload = otel::render(&snap);
    let json = serde_json::to_string(&snap).unwrap();
    let frame = osslscope::presentation::watch::render_frame(&snap);
    // No cursor control sequences in v1 (plain re-print per refresh
    // — resize-safe by construction, §6C-9).
    assert!(!frame.contains('\x1b'), "frame carries escape codes");
    for (name, body) in [
        ("prometheus", prom.as_str()),
        ("otel", payload.as_str()),
        ("json", json.as_str()),
        ("frame", frame.as_str()),
    ] {
        for needle in [
            "argv",
            "command_line",
            "exe_path",
            "path=",
            "/bin/",
            "/usr/",
            "hostname",
            "username",
            "container",
            "env:",
        ] {
            assert!(!body.contains(needle), "{name} leaks {needle}");
        }
    }
}

#[test]
fn watch_non_tty_renders_one_frame_exit_zero() {
    let dir = out_dir("watch-once");
    let code = osslscope::presentation::watch::run(&[
        "watch".to_string(),
        "--out".to_string(),
        dir.to_str().unwrap().to_string(),
    ]);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}

#[test]
fn watch_usage_errors_are_exit_two() {
    assert_eq!(
        osslscope::presentation::watch::run(&["watch".to_string()]),
        std::process::ExitCode::from(2)
    );
    assert_eq!(
        osslscope::presentation::watch::run(&[
            "watch".to_string(),
            "--out".to_string(),
            "/nonexistent-p6c-dir".to_string(),
        ]),
        std::process::ExitCode::from(1)
    );
}

/// Sibling checkpoint path (P2fix3 NEW-13 — checkpoints resolve
/// OUTSIDE the producer out-DIR; consumers stay read-only on it).
fn ckpt_for(dir: &std::path::Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.checkpoint.json", dir.display()))
}

fn read_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Follow-banner coalesced count (P2fix5 NEW-29): parses
/// `--- frame <seq> coalesced=<K> ---` from a `text.split("---
/// frame")` chunk (banner line first). `None` when the banner
/// carries no count (pre-fix shape).
fn banner_coalesced(chunk: &str) -> Option<u64> {
    let banner = chunk.lines().next().unwrap_or_default();
    banner
        .split_whitespace()
        .find_map(|w| w.strip_prefix("coalesced=").and_then(|v| v.parse().ok()))
}

/// Full-shape clean activity rows (P2fix3 GATE29 — every covered
/// claim needs supporting rows with all gap flags clear).
fn clean_rows(apis: &[u32]) -> serde_json::Value {
    serde_json::Value::Array(
        apis.iter()
            .map(|api| {
                serde_json::json!({
                    "api": api, "entries": 1,
                    "observed_success": 1, "observed_failure": 0,
                    "verification_mismatch": 0, "unsupported": 0,
                    "gaps": {
                        "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                        "unsupported_return": 0, "saturated": false,
                        "not_attached": false, "read_receipt": true,
                        "attachment": false, "finality": false,
                    },
                })
            })
            .collect(),
    )
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scrape(port: u16, path: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    body
}

fn seed_windows(dir: &std::path::Path, count: u64) {
    use osslscope::presentation::snapshot;
    for seq in 0..count {
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        let env = snapshot::test_envelope(seq, 0, run, 10 * (seq + 1));
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": count, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
}

#[test]
fn export_serves_metrics_with_real_exposition() {
    use osslscope::presentation::export;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("serve");
    seed_windows(&dir, 2);
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // Wait for the endpoint, then scrape twice. (P2fix3 NEW-1:
    // the listener serves before the first publish — a
    // well-formed "# EOF" page may still be the pre-publish
    // empty one — so wait for CONTENT, not just EOF.)
    let mut body = String::new();
    for _ in 0..50 {
        if let Ok(b) = std::panic::catch_unwind(|| scrape(port, "/metrics")) {
            body = b;
            if body.contains("osslscope_epoch_calls_total{lane=\"legacy_exclusive\"} 30") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(body.contains("200 OK"), "scrape status: {body:?}");
    assert!(body.contains("osslscope_epoch_calls_total{lane=\"legacy_exclusive\"} 30"));
    assert!(body.contains("osslscope_window_site_rows 0"));
    assert!(body.trim_end().ends_with("# EOF"));
    let not_found = scrape(port, "/nope");
    assert!(not_found.contains("404"));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
}

#[test]
fn export_otlp_push_posts_to_collector_stub() {
    use osslscope::presentation::export;
    use std::io::{Read, Write};
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("otlp-stub");
    seed_windows(&dir, 1);
    let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen2 = seen.clone();
    let stub_stop = Arc::new(AtomicBool::new(false));
    let stub_stop2 = stub_stop.clone();
    let stub_handle = std::thread::spawn(move || {
        stub.set_nonblocking(true).unwrap();
        while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match stub.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    seen2
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: Some(export::OtlpConfig {
                    endpoint: format!("http://127.0.0.1:{stub_port}/v1/metrics"),
                    push_secs: 5,
                }),
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // One push cycle (5s floor) + margin.
    std::thread::sleep(std::time::Duration::from_secs(8));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    stub_handle.join().unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "collector stub saw no push");
    let req = &seen[0];
    assert!(req.starts_with("POST /v1/metrics"), "push path: {req:?}");
    assert!(req.contains("Content-Type: application/json"));
    let payload = req.split("\r\n\r\n").nth(1).unwrap_or("{}");
    let v: serde_json::Value = serde_json::from_str(payload).expect("otlp json");
    let metrics = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
    assert!(metrics.is_array() && !metrics.as_array().unwrap().is_empty());
    assert_eq!(
        v["resourceMetrics"][0]["resource"]["attributes"][0]["key"],
        "service.name"
    );
}

#[test]
fn newpriv_otlp_sink_carries_admitted_values_never_canary() {
    // P2fix4 PRIVACY: at the real OTLP sink — admitted values
    // fold into the pushed payload (epoch calls + partial
    // classes) while canary text never appears (rejected
    // upstream at intake; dotted counter names never render
    // into OTLP labels). A canary-named document pushes nothing.
    use osslscope::presentation::{export, snapshot};
    use std::io::{Read, Write};
    use std::sync::{Arc, atomic::AtomicBool};
    let good_doc = serde_json::json!({
        "status": {"Partial": {"reasons": [
            {"Loss": {"counter": "lifecycle.polling_fallback", "source": "Lifecycle", "value": 7}},
        ]}},
        "legacy_partition": {"legacy_exclusive": 3, "non_legacy_exclusive": 0, "shared_ambiguous": 0, "unfenced_tails": 0},
        "sites": [],
        "counters": [
            {"name": "lifecycle.polling_fallback", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 7},
        ],
        "policy": {"verdict": "Pass"},
        "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"},
    });
    let run_case = |tag: &str, doc: &serde_json::Value| {
        let dir = out_dir(tag);
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        let env = snapshot::test_envelope_with_doc(0, 0, run, doc.clone());
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
        let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stub_port = stub.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        let stub_stop = Arc::new(AtomicBool::new(false));
        let stub_stop2 = stub_stop.clone();
        let stub_handle = std::thread::spawn(move || {
            stub.set_nonblocking(true).unwrap();
            while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
                match stub.accept() {
                    Ok((mut s, _)) => {
                        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let mut buf = vec![0u8; 65536];
                        let n = s.read(&mut buf).unwrap_or(0);
                        seen2
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                        let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
                }
            }
        });
        let port = free_port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let out = dir.clone();
        let checkpoint = ckpt_for(&dir);
        let handle = std::thread::spawn(move || {
            export::serve_with_shutdown(
                export::Options {
                    out,
                    listen: format!("127.0.0.1:{port}"),
                    poll_secs: 1,
                    otlp: Some(export::OtlpConfig {
                        endpoint: format!("http://127.0.0.1:{stub_port}/v1/metrics"),
                        push_secs: 1,
                    }),
                    checkpoint: Some(checkpoint),
                },
                stop2,
                None,
            )
        });
        std::thread::sleep(std::time::Duration::from_secs(4));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
        stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        stub_handle.join().unwrap();
        std::mem::take(&mut *seen.lock().unwrap())
    };
    // Good: admitted values push; no canary text anywhere.
    let pushes = run_case("newpriv-otlp-good", &good_doc);
    assert!(!pushes.is_empty(), "good doc must push");
    let payload = pushes[0].split("\r\n\r\n").nth(1).unwrap_or("{}");
    let v: serde_json::Value = serde_json::from_str(payload).expect("otlp json");
    let metrics = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .expect("metrics array");
    let point = |metric: &str, attr_key: &str, attr_val: &str| {
        metrics
            .iter()
            .find(|m| m["name"] == metric)
            .and_then(|m| m["sum"]["dataPoints"].as_array())
            .and_then(|pts| {
                pts.iter().find(|p| {
                    p["attributes"].as_array().is_some_and(|attrs| {
                        attrs
                            .iter()
                            .any(|a| a["key"] == attr_key && a["value"]["stringValue"] == attr_val)
                    })
                })
            })
    };
    // Admitted calls (3) fold into epoch.calls.
    let calls: u64 = metrics
        .iter()
        .find(|m| m["name"] == "osslscope.epoch.calls")
        .and_then(|m| m["sum"]["dataPoints"][0]["asInt"].as_str())
        .and_then(|s| s.parse().ok())
        .expect("epoch.calls point");
    assert_eq!(calls, 3, "admitted calls value pushes");
    // Admitted partial-loss window folds into epoch.partial.
    let loss = point("osslscope.epoch.partial", "gap_class", "loss")
        .and_then(|p| p["asInt"].as_str())
        .expect("partial loss point");
    assert_eq!(loss, "1", "admitted partial value pushes");
    for canary in ["EVP_Digest", "CANARY", "polling_fallback"] {
        assert!(
            !payload.contains(canary),
            "canary text {canary:?} must not reach OTLP"
        );
    }
    // Bad: a canary-named document pushes nothing.
    let mut bad_doc = good_doc.clone();
    bad_doc["counters"] = serde_json::json!([
        {"name": "EVP_Digest_CANARY", "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
    ]);
    let pushes = run_case("newpriv-otlp-bad", &bad_doc);
    assert!(pushes.is_empty(), "canary doc must push nothing");
}

#[test]
fn export_push_failure_recovers_without_stalling_scrapes() {
    // P2fix1 item 18: pushes run off the scrape path — a failing
    // collector (connection refused: 5 attempts + backoffs per
    // push) must not stall scrapes, and pushes recover once the
    // collector appears.
    use osslscope::presentation::export;
    use std::io::{Read, Write};
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("push-sep");
    seed_windows(&dir, 1);
    // No collector yet: pushes fail fast-refused with backoffs.
    let dead_port = free_port();
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: Some(export::OtlpConfig {
                    endpoint: format!("http://127.0.0.1:{dead_port}/v1/metrics"),
                    push_secs: 5,
                }),
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // Wait for the endpoint, then scrape DURING the failing-push
    // phase (first push at t≈5 with ~15s of backoffs): every
    // scrape must stay fast.
    std::thread::sleep(std::time::Duration::from_secs(2));
    for _ in 0..3 {
        let t0 = std::time::Instant::now();
        let body = scrape(port, "/metrics");
        let dt = t0.elapsed();
        assert!(body.contains("200 OK"), "scrape status: {body:?}");
        assert!(
            dt < std::time::Duration::from_secs(5),
            "scrape stalled by failing pushes: {dt:?}"
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    // The collector appears: the next push lands (recovery).
    let stub = std::net::TcpListener::bind(("127.0.0.1", dead_port)).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(0u64));
    let seen2 = seen.clone();
    let stub_stop = Arc::new(AtomicBool::new(false));
    let stub_stop2 = stub_stop.clone();
    let stub_handle = std::thread::spawn(move || {
        stub.set_nonblocking(true).unwrap();
        while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match stub.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    if buf[..n].starts_with(b"POST /v1/metrics") {
                        *seen2.lock().unwrap() += 1;
                    }
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if *seen.lock().unwrap() > 0 || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(*seen.lock().unwrap() > 0, "push never recovered");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    stub_handle.join().unwrap();
}

#[test]
fn export_serve_time_freshness_advances_at_source_cadence() {
    // P2fix1 item 18: served freshness (age/stale) advances at the
    // source cadence per scrape (never frozen build-time values),
    // and the stale threshold derives from the source's requested
    // span (1s here — NOT the 30s hard-code).
    use osslscope::presentation::export;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("fresh");
    let now = osslscope::presentation::snapshot::monotonic_ns();
    // Effective end 10s ago, requested span exactly 1s: age ≈10s
    // (advancing), stale (10 > 2×1).
    let end = now - 10_000_000_000;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env = snapshot::test_envelope(0, 0, run, 10);
    env["window"] = serde_json::json!({
        "requested_start_ns": end - 1_000_000_000,
        "requested_end_ns": end,
        "effective_start_ns": end - 1_000_000_000,
        "effective_end_ns": end,
        "signal_cut": false,
        "accum_cut": false,
    });
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    fn age_of(body: &str) -> u64 {
        body.lines()
            .find(|l| l.starts_with("osslscope_snapshot_age_nanoseconds "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .expect("age sample present")
    }
    // Wait for the endpoint. (P2fix3 NEW-1: the listener serves
    // before the first publish, so wait for CONTENT — a bare
    // "# EOF" page may be the pre-publish empty one.)
    let mut b1 = String::new();
    for _ in 0..50 {
        if let Ok(b) = std::panic::catch_unwind(|| scrape(port, "/metrics")) {
            b1 = b;
            if b1.contains("# EOF") && b1.contains("osslscope_snapshot_stale 1") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Stale by the 1s-span rule (a 30s hard-code would read fresh).
    assert!(b1.contains("osslscope_snapshot_stale 1"), "{b1:?}");
    // Outage (remove the out-DIR): last-good keeps serving with
    // serve-time freshness — age advances between scrapes (frozen
    // build-time values would read equal) while counters freeze.
    std::fs::remove_dir_all(&dir).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let b2 = scrape(port, "/metrics");
    assert!(b2.contains("200 OK"), "{b2:?}");
    assert!(age_of(&b2) > age_of(&b1), "{b1:?} vs {b2:?}");
    let calls = |b: &str| {
        b.lines()
            .find(|l| l.starts_with("osslscope_epoch_calls_total{lane=\"legacy_exclusive\"}"))
            .unwrap()
            .to_string()
    };
    assert_eq!(calls(&b1), calls(&b2));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
}

#[test]
fn export_concurrent_scrapes_and_slow_peer() {
    // P2fix1 item 18: scrapes serve concurrently with complete
    // request deadlines — parallel scrapes all land, and a slow
    // peer never blocks a fast one.
    use osslscope::presentation::export;
    use std::io::Write;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("conc");
    seed_windows(&dir, 1);
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // Wait for the endpoint.
    for _ in 0..50 {
        if let Ok(b) = std::panic::catch_unwind(|| scrape(port, "/metrics")) {
            if b.contains("# EOF") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Four parallel scrapes all land.
    let mut hs = vec![];
    for _ in 0..4 {
        hs.push(std::thread::spawn(move || scrape(port, "/metrics")));
    }
    for h in hs {
        let b = h.join().unwrap();
        assert!(b.contains("200 OK") && b.contains("# EOF"), "{b:?}");
    }
    // A slow peer (silent 4s, then GET) must not block a fast one.
    let slow = std::thread::spawn(move || {
        use std::io::Read;
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(4));
        write!(s, "GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        body
    });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let t0 = std::time::Instant::now();
    let fast = scrape(port, "/metrics");
    let dt = t0.elapsed();
    assert!(fast.contains("200 OK"), "{fast:?}");
    assert!(
        dt < std::time::Duration::from_secs(2),
        "fast scrape stalled: {dt:?}"
    );
    let slow_body = slow.join().unwrap();
    assert!(slow_body.contains("200 OK"), "{slow_body:?}");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
}

#[test]
fn export_outage_serves_last_good_and_reconnect_advances() {
    use osslscope::presentation::export;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("outage");
    seed_windows(&dir, 1);
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    let mut first = String::new();
    for _ in 0..50 {
        if let Ok(b) = std::panic::catch_unwind(|| scrape(port, "/metrics")) {
            if b.contains("# EOF") && b.contains("legacy_exclusive\"} 10") {
                first = b;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(first.contains("legacy_exclusive\"} 10"), "first: {first:?}");
    // Outage: remove the out-DIR — the exporter keeps serving
    // last-good (stale, frozen, never extrapolated).
    std::fs::remove_dir_all(&dir).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let during = scrape(port, "/metrics");
    assert!(
        during.contains("legacy_exclusive\"} 10"),
        "outage: {during:?}"
    );
    // Reconnect: restore with an advanced window — the exporter
    // advances to the newest finalized window.
    std::fs::create_dir_all(&dir).unwrap();
    seed_windows(&dir, 2);
    let mut advanced = String::new();
    for _ in 0..60 {
        let b = scrape(port, "/metrics");
        if b.contains("legacy_exclusive\"} 30") {
            advanced = b;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        advanced.contains("legacy_exclusive\"} 30"),
        "reconnect: {advanced:?}"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
}

#[test]
fn high_churn_stays_within_budget() {
    use osslscope::presentation::snapshot;
    // ≥10 incarnations through one epoch: series ≤ 159, overflow 0.
    let dir = out_dir("churn");
    let mut p = Presenter::open(&dir, 30).unwrap();
    for seq in 0..10u64 {
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        let mut env = snapshot::test_envelope(seq, 0, run, 5);
        // Churn members every window (new pid/segment incarnations).
        env["members"] = serde_json::json!([
            {"pid": 100 + seq, "starttime": 2, "segment": 1, "retired": false},
            {"pid": 200 + seq, "starttime": 3, "segment": 2, "retired": seq % 2 == 0},
        ]);
        p.fold_test_envelope(&env, "00").unwrap();
    }
    let snap = p.snapshot().unwrap();
    snap.check_unknown_invariant().unwrap();
    let text = prometheus::render(&snap);
    let series = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .count();
    assert!(series <= 159, "series {series} exceed default max");
    assert_eq!(snap.presenter.series_overflow, 0);
    assert_eq!(snap.counts.calls_total, 50);
}

#[test]
fn oneshot_trace_summary_projects_blocks_and_series() {
    use osslscope::provider_observation::trace as t;
    // Real fold → summarize → doc → oneshot: trace, histograms,
    // by_outcome, P-16/P-17 all flow; the invariant holds.
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 1,
        tid: 2,
        generation: 1,
        cookie: 9,
        invocation: 1,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1500,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 {
                "covered".to_string()
            } else {
                "not_attached".to_string()
            },
        );
    }
    let summary = t::summarize(&window, &totals, "latency", Some(&avail));
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    doc["api_activity"] = clean_rows(&[20]);
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("trace block");
    assert_eq!(trace.paired, 1);
    assert_eq!(trace.mode, "latency");
    assert_eq!(trace.class_epoch.as_ref().unwrap().success, 1);
    let by = snap.counts.by_outcome.expect("by_outcome");
    assert_eq!((by.success, by.failure, by.unknown), (1, 0, 0));
    let hist = snap.histograms.as_ref().expect("histograms");
    assert_eq!(hist.edges, "6d-frozen-18");
    assert_eq!(hist.success.count, 1);
    assert_eq!(hist.success.sum, 500);
    let by_api = hist.by_api.as_ref().expect("by_api");
    assert_eq!(by_api.len(), 1);
    assert!(by_api.contains_key("20"));
    assert_eq!(hist.by_api_availability.as_ref().unwrap().len(), 53);
    // P-16/P-17 series render.
    let text = prometheus::render(&snap);
    assert!(text.contains("osslscope_trace_calls_total{outcome_class=\"success\"} 1"));
    assert!(text.contains(
        "osslscope_dispatch_duration_nanoseconds_bucket{le=\"500\",outcome_class=\"success\"} 1"
    ));
    assert!(
        text.contains("osslscope_dispatch_duration_nanoseconds_count{outcome_class=\"success\"} 1")
    );
    // Opt-in unit renders (api="20").
    assert!(text.contains("api=\"20\""));
    // No unknown entries for the projected paths.
    assert!(!snap.unknown.iter().any(|e| e.path == "trace"));
    assert!(!snap.unknown.iter().any(|e| e.path == "histograms"));
    assert!(!snap.unknown.iter().any(|e| e.path == "counts.by_outcome"));
}

#[test]
fn status_mode_carries_classes_without_histograms() {
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_STATUS);
    let k = t::PairKey {
        pid: 1,
        tid: 2,
        generation: 1,
        cookie: 9,
        invocation: 1,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1500,
        outcome: 2,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let summary = t::summarize(&window, &totals, "status", None);
    assert!(summary.histograms.is_none());
    let mut doc = snapshot::test_document(1, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    assert!(snap.trace.is_some());
    assert!(snap.histograms.is_none());
    let by = snap.counts.by_outcome.expect("by_outcome");
    assert_eq!((by.success, by.failure, by.unknown), (0, 1, 0));
    let text = prometheus::render(&snap);
    assert!(text.contains("osslscope_trace_calls_total{outcome_class=\"failure\"} 1"));
    assert!(!text.contains("osslscope_dispatch_duration_nanoseconds"));
}

#[test]
fn checkpoint_restart_reserves_last_good() {
    // Restart with no new windows re-serves last-good (the I2
    // ingestion cell caught pre-first-window here — regression pin).
    let dir = out_dir("restart");
    seed_windows(&dir, 2);
    let first = {
        let mut p = Presenter::open(&dir, 1).unwrap();
        p.build_service().unwrap()
    };
    assert_eq!(first.source.window_seq, Some(1));
    assert_eq!(first.counts.calls_total, 30);
    let second = {
        let mut p = Presenter::open(&dir, 1).unwrap();
        p.build_service().unwrap()
    };
    assert_eq!(second.source.window_seq, Some(1));
    assert_eq!(second.source.window_sha256, first.source.window_sha256);
    assert_eq!(second.counts.calls_total, 30);
    assert_eq!(second.counts.calls_window, Some(20));
    assert_eq!(second.completeness.state, Some("complete".to_string()));
    second.check_unknown_invariant().unwrap();
}

#[test]
fn export_usage_errors_are_exit_two() {
    assert_eq!(
        osslscope::presentation::export::run(&["export".to_string()]),
        std::process::ExitCode::from(2)
    );
    // Push interval without OTLP enabled is a usage error.
    let dir = out_dir("export-usage");
    assert_eq!(
        osslscope::presentation::export::run(&[
            "export".to_string(),
            "--out".to_string(),
            dir.to_str().unwrap().to_string(),
            "--otlp-push-seconds".to_string(),
            "30".to_string(),
        ]),
        std::process::ExitCode::from(2)
    );
}

fn seal_record(pid: u64, starttime: u64, segment: u64, cause: &str) -> serde_json::Value {
    // REAL producer shape (crypto_watch flattened `kind` record —
    // internally tagged, segment on the record).
    serde_json::json!({
        "schema_version": "crypto-watch-v1",
        "sequence": 1,
        "kind": "process_observation",
        "incarnation": {"pid": pid, "starttime": starttime, "namespaces": {}},
        "segment": segment,
        "retirement": "sampled",
        "document": {},
        "image_epoch": 0,
        "loss": {"loss": 1, "deferred": {"ticks": 0, "first_tick": 0, "last_tick": 0}, "lost_windows": [{"start_tick": 0, "end_tick": 1, "cause": cause}], "coalesced": 0},
    })
}

fn end_record(depth: u64, ring0: u64) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "crypto-watch-v1",
        "sequence": 2,
        "kind": "end",
        "reason": "duration",
        "segments": 1,
        "peak_accounted_bytes": 0,
        "coverage": "complete",
        "peak_deferred_depth": depth,
        "deferred_drops": 0,
        "deferred_removed": {"exited": 0, "reused": 0, "ineligible": 0, "closed": 0},
        "session_loss": {"ring": [ring0, 0, 0, 0, 0, 0, 0, 0], "connector_drops": 0, "connector_enobufs": 0, "scan_loss": 0, "signal_dropped": 0, "signal_prefix_unwitnessed": 0, "drain_pending": 0, "unsealed_members": 0, "polling_fallback": false, "unattributed_events": 0, "admitted_exit_artifacts": 0, "lost_intervals": [], "coalesced": 0},
    })
}

#[test]
fn service_loss_flows_from_flattened_kind_records() {
    // P2fix1 item 19 (codex NEW-P2b): the presenter consumes the
    // REAL flattened `kind` records (seal ledgers + end tallies)
    // with the record's actual segment — positive service loss
    // folds exactly once, end tallies project.
    let dir = out_dir("svc-loss");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
    env["crypto_watch"] = serde_json::json!([seal_record(1, 2, 0, "ring_loss"), end_record(7, 3)]);
    p.fold_test_envelope(&env, "00").unwrap();
    // Refold the same envelope (idempotent replay): exactly-once
    // per interval — no double count.
    p.fold_test_envelope(&env, "00").unwrap();
    let snap = p.snapshot().unwrap();
    snap.check_unknown_invariant().unwrap();
    assert_eq!(snap.loss.epoch_by_cause.ring_loss, 1);
    let session = snap.loss.session.as_ref().expect("session loss");
    assert_eq!(session.ring[0], 3);
    assert_eq!(snap.members.deferred_depth, Some(7));
    // The legacy nested fiction never folds (unknown shapes skip —
    // this fixture parses under the OLD nested readers, so it pins
    // the shape cutover).
    let dir = out_dir("svc-loss-nested");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
    env["members"] =
        serde_json::json!([{"pid": 1, "starttime": 2, "segment": 0, "retired": false}]);
    env["crypto_watch"] = serde_json::json!([{"record": {"ProcessObservation": {"incarnation": {"pid": 1, "starttime": 2}, "loss": {"lost_windows": [{"start_tick": 0, "end_tick": 1, "cause": "ring_loss"}]}}}}, {"record": {"End": {"peak_deferred_depth": 9, "session_loss": {}}}}]);
    p.fold_test_envelope(&env, "00").unwrap();
    let snap = p.snapshot().unwrap();
    assert_eq!(snap.loss.epoch_by_cause.ring_loss, 0);
    assert!(snap.loss.session.is_none());
}

#[test]
fn stream_gross_counts_one_authoritative_value_per_run() {
    // P2fix1 item 19: a current run's summary merges into the live
    // close gross (no double count); departed runs seal; the
    // accounting survives a presenter restart (checkpoint).
    let dir = out_dir("gross");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Window 0: close gross 10 records for run A.
    let mut env0 =
        snapshot::test_envelope_with_doc(0, 0, run.clone(), snapshot::test_document(5, "complete"));
    env0["stream_gross_close"] = serde_json::json!({"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 10, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    // Run A's summary agrees (same run, second read — must NOT add).
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}, "stream_configured": true, "stream_drops": {"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 10, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": 1, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let snap = {
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &dir, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!((drops.records, drops.bytes), (10, 100), "one gross per run");
    // Restart with no new windows: same gross (no re-add).
    let snap2 = {
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &dir, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    let drops2 = snap2.stream.as_ref().expect("stream").drops;
    assert_eq!(
        (drops2.records, drops2.bytes),
        (10, 100),
        "restart keeps one gross"
    );
}

#[test]
fn summary_adoption_binds_generation_run_and_flags_disagreement() {
    // P2fix2 item 13 (codex NEW-P2b) as corrected by P2fix3
    // NEW-P2b: summary adoption binds to its generation AND run
    // (a foreign-generation summary never merges); close/summary
    // disagreement flags across ALL record and byte components —
    // mixed lead/lag AND uniform above/below (any difference is a
    // disagreement); only an exact match merges clean.
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let close10 = serde_json::json!({"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 10, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    let build_with = |tag: &str, close: &serde_json::Value, summary: &serde_json::Value| {
        let dir = out_dir(tag);
        let mut env0 = snapshot::test_envelope_with_doc(
            0,
            0,
            run.clone(),
            snapshot::test_document(5, "complete"),
        );
        env0["stream_gross_close"] = close.clone();
        env0["stream_configured"] = serde_json::json!(true);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env0).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("run-summary.json"),
            serde_json::to_string(summary).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("sequence.json"),
            serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": 1, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &dir, &ckpt, 1, "export",
        )
        .unwrap();
        p.build_service().unwrap()
    };
    let summary_for = |generation: u64, drops: &serde_json::Value| serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}, "generation": generation, "stream_configured": true, "stream_drops": drops});
    // Foreign generation: ignored (gross stays close-only 10/100).
    let drops20 = serde_json::json!({"records": 20, "bytes": 200, "by_reason": {"queue_full": {"records": 20, "bytes": 200}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    let snap = build_with("adopt-gen", &close10, &summary_for(1, &drops20));
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!(
        (drops.records, drops.bytes),
        (10, 100),
        "foreign-generation summary never merges"
    );
    // Mixed disagreement (records lead, bytes lag): merges the max
    // AND flags (components disagree about which read is newer).
    let mixed = serde_json::json!({"records": 20, "bytes": 50, "by_reason": {"queue_full": {"records": 20, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    let snap = build_with("adopt-mixed", &close10, &summary_for(0, &mixed));
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!(
        (drops.records, drops.bytes),
        (20, 100),
        "mixed merges component maxima"
    );
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "stream.drops" && e.reason == "unstable_snapshot"),
        "mixed disagreement flags: {:?}",
        snap.unknown
    );
    // Pure convergence (summary uniformly newer): merges the max
    // AND flags (P2fix3 NEW-P2b — a uniformly different summary
    // is a disagreement with the last folded close, never silent
    // convergence; only an exact match merges clean).
    let snap = build_with("adopt-pure", &close10, &summary_for(0, &drops20));
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!((drops.records, drops.bytes), (20, 200));
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "stream.drops" && e.reason == "unstable_snapshot"),
        "uniform difference flags: {:?}",
        snap.unknown
    );
    // Exact match: merges clean (no flag — the reads agree).
    let snap = build_with("adopt-exact", &close10, &summary_for(0, &close10));
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!((drops.records, drops.bytes), (10, 100));
    assert!(
        !snap
            .unknown
            .iter()
            .any(|e| e.path == "stream.drops" && e.reason == "unstable_snapshot"),
        "exact match stays silent: {:?}",
        snap.unknown
    );
}

#[test]
fn admission_snapshot_preserves_admission_and_omissions() {
    // P2fix2 item 13 (codex NEW-P2c): the budget snapshot preserves
    // admission (admitted set + window binding) and omissions
    // (overflow) across a restart — a restored budget re-renders
    // the same window through the non-counting filter (no
    // re-admission churn, no recount), and a new window continues
    // its per-window count.
    use osslscope::presentation::budget::Budget;
    let mut before = Budget::new();
    let id_a = (
        "service".to_string(),
        Some(0u64),
        Some(7u64),
        Some("a".to_string()),
    );
    assert!(before.begin_window_for(id_a.clone()));
    for i in 0..200 {
        assert!(before.admit_series("m", &format!("l={i:03}")));
    }
    // Fill the window cap (256) + overflow 44.
    for i in 200..300 {
        before.admit_series("m", &format!("l={i:03}"));
    }
    assert_eq!(before.overflow(), 44);
    let snap = before.snapshot();
    // Restart: restore into a fresh budget.
    let mut after = Budget::new();
    after.restore(snap);
    assert_eq!(after.overflow(), 44, "omissions persist");
    // Same window: non-counting (admitted pass, omitted stay
    // omitted, overflow frozen).
    assert!(!after.begin_window_for(id_a));
    assert!(after.is_admitted("m", "l=000"));
    assert!(!after.is_admitted("m", "l=299"));
    assert_eq!(after.overflow(), 44, "no recount on re-render");
    // New window: fresh per-window budget (§6C-12 rule — the
    // restored epoch set carries over, so all 100 fresh series fit
    // and overflow stays put).
    let id_b = (
        "service".to_string(),
        Some(0u64),
        Some(8u64),
        Some("b".to_string()),
    );
    assert!(after.begin_window_for(id_b));
    for i in 300..400 {
        assert!(after.admit_series("m", &format!("l={i:03}")));
    }
    assert_eq!(after.overflow(), 44);
    assert_eq!(after.admitted_len(), 256 + 100);
}

#[test]
fn restart_preserves_export_admission_exactly() {
    // P2fix2 item 13 (codex NEW-P2c): end-to-end through real window
    // files + the source-bound checkpoint + the export loop's exact
    // admit sequence — a restart restores admission (same-window
    // re-renders stay non-counting) and omissions (overflow exact,
    // never recounted). (Steady state is zero omissions — DELTA-2
    // withholds service histograms so the default schema always
    // fits; the mechanism above pins nonzero preservation.)
    use osslscope::presentation::budget::Budget;
    use osslscope::presentation::prometheus;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("adm-restart");
    let env = snapshot::test_envelope(0, 0, run.clone(), 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": 1, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    // First run: build + admit (the export loop's exact sequence) +
    // save + shutdown flush (final build persists the admission).
    let first = {
        let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
            &dir, &ckpt, 1, "export",
        )
        .unwrap();
        let mut budget = Budget::new();
        let snap = p.build_service().unwrap();
        let text = prometheus::render_with_budget(&snap, &mut budget);
        p.adopt_overflow(budget.overflow());
        p.save_admission(budget.snapshot());
        p.build_service().unwrap();
        (text, budget.overflow())
    };
    // Restart: restore the budget from the checkpoint, rebuild with
    // no new windows (same-window re-render).
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    let mut budget = Budget::new();
    budget.restore(p.take_admission().expect("admission persists"));
    assert_eq!(budget.overflow(), first.1, "overflow restores exactly");
    let snap = p.build_service().unwrap();
    let text = prometheus::render_with_budget(&snap, &mut budget);
    // Identical modulo the wall-clock age sample (freshness
    // advances every build by design — admission is what must
    // match, series for series).
    let strip_age = |t: &str| {
        t.lines()
            .filter(|l| !l.starts_with("osslscope_snapshot_age_nanoseconds "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(strip_age(&text), strip_age(&first.0), "re-render identical");
    assert_eq!(
        budget.overflow(),
        first.1,
        "no recount on post-restart re-render"
    );
}

#[test]
fn envelope_validates_before_mutating_epoch_state() {
    // P2fix2 item 22 (codex NEW-2): the envelope (fields +
    // filename sequence) validates BEFORE any epoch mutation — a
    // filename/envelope seq mismatch rejects, and a rejected
    // newer-generation document never resets the live epoch first
    // (the established epoch survives intact for the rebuild after
    // the bad file is removed).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("envelope-first");
    // Window 0 gen 0 (establishes the live epoch: 10 calls).
    let env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    // Misnamed file (filename seq 5, envelope seq 6): rejects.
    let env_bad = snapshot::test_envelope(6, 0, run.clone(), 10);
    std::fs::write(
        dir.join("window-0000000005.json"),
        serde_json::to_string(&env_bad).unwrap(),
    )
    .unwrap();
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    let err = p.build_service().expect_err("seq mismatch must reject");
    assert!(err.contains('5') || err.contains('6'), "{err:?}");
    std::fs::remove_file(dir.join("window-0000000005.json")).unwrap();
    // Rejected newer-generation document (unreadable document):
    // rejects WITHOUT resetting the live epoch first.
    let mut env1 =
        snapshot::test_envelope_with_doc(1, 1, run.clone(), snapshot::test_document(5, "complete"));
    env1["document"] = serde_json::json!({"nope": true});
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    let err = p.build_service().expect_err("bad document must reject");
    assert!(!err.is_empty());
    // Remove the bad file and rebuild: the live gen-0 epoch is
    // intact (10 calls — never zeroed by the rejected gen-1 doc).
    std::fs::remove_file(dir.join("window-0000000001.json")).unwrap();
    let snap = p.build_service().unwrap();
    assert_eq!(snap.counts.calls_total, 10, "live epoch survives reject");
    assert_eq!(snap.source.generation, Some(0));
}

#[test]
fn checkpoint_binds_source_dir_and_validates_restored_state() {
    // P2fix2 item 22 (codex NEW-2): checkpoints bind to their source
    // directory (a foreign out-DIR refuses loudly, never applies),
    // and restored state validates BEFORE the watermark applies (a
    // valid-hash checkpoint with corrupt accumulators refuses
    // loudly instead of silently defaulting).
    use osslscope::presentation::snapshot::Presenter;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir_a = out_dir("ckpt-src-a");
    let env = snapshot::test_envelope(0, 0, run.clone(), 10);
    std::fs::write(
        dir_a.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir_a);
    {
        let mut p = Presenter::open_with_checkpoint(&dir_a, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    // Same checkpoint opened against another out-DIR: refuses.
    let dir_b = out_dir("ckpt-src-b");
    std::fs::write(
        dir_b.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let err = Presenter::open_with_checkpoint(&dir_b, &ckpt, 1, "export")
        .err()
        .expect("foreign out-DIR must refuse");
    assert!(
        err.to_string().contains("out-DIR") || err.to_string().contains("source"),
        "{err:?}"
    );
    // Same dir still opens cleanly (control).
    Presenter::open_with_checkpoint(&dir_a, &ckpt, 1, "export").unwrap();
    // Corrupt accumulators under a valid hash: refuses loudly.
    let body = std::fs::read(&ckpt).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["accumulators"]["lanes"] = serde_json::json!(["x", "y"]);
    v["accumulators"]["counted"] = serde_json::json!({"k": "not-ranges"});
    // Recompute the hash (well-formed envelope, invalid content —
    // the restore must validate content, not just integrity).
    v.as_object_mut().unwrap().remove("sha256");
    let bytes = serde_json::to_vec(&v).unwrap();
    let hash = osslscope::presentation::snapshot::sha256_hex(&bytes);
    v.as_object_mut()
        .unwrap()
        .insert("sha256".to_string(), serde_json::json!(hash));
    std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    Presenter::open_with_checkpoint(&dir_a, &ckpt, 1, "export")
        .err()
        .expect("corrupt accumulators must refuse");
}

#[test]
fn open_fence_withholds_classes_and_exemplars_on_service_path() {
    // P2fix2 items 24+9 (codex NEW-3 + DELTA-7): while C023
    // acceptance is OPEN, public persisted-window consumption
    // (watch/export --out) is aggregate-only — a stored
    // OPERATIONAL summary (certain latency seal with classes +
    // exemplars) projects raw counters/lanes/loss only; interpreted
    // classes and exemplars withhold (the fence lifts only via the
    // re-qualification amendment flipping ACCEPTANCE_OPEN).
    use osslscope::provider_observation::trace as t;
    assert!(
        osslscope::provider_observation::c023::ACCEPTANCE_OPEN,
        "premise: acceptance OPEN (fence active)"
    );
    // Certain operational seal with classes + an exemplar (orphan
    // attempt finalized for the exemplar).
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    for i in 0..3u64 {
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 500 + i,
            invocation: 100 + i,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i * 100,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1050 + i * 100,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    p.attempt(t::AttemptEdge {
        key: t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 599,
            invocation: 200,
        },
        api: 22,
        monotonic_ns: 2000,
        start_time_ns: 1,
        seed: 1,
    });
    p.finalize(9000);
    let window = p.close_window(0, 9000, [0; 8]);
    assert_eq!(window.paired, 3);
    assert!(!window.exemplars.is_empty());
    let totals = p.totals();
    let summary = t::summarize(&window, &totals, "latency", None);
    summary.validate().expect("operational seal validates");
    assert!(summary.window.class_window.is_some());
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    // Through the SERVICE path (public persisted-window reader).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("open-fence");
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), doc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    let snap = p.build_service().unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block kept");
    // Permitted aggregate + loss evidence flows.
    assert_eq!(trace.paired, 3);
    assert_eq!(trace.trace_unpaired_entries, 1);
    // Interpreted classes + exemplars withhold while OPEN.
    assert!(
        trace.class_window.is_none(),
        "operational classes must withhold while OPEN"
    );
    assert!(
        trace.exemplars.is_empty(),
        "exemplars must withhold while OPEN"
    );
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "trace.class_window" && e.reason == "trace_disabled"),
        "withheld classes carry the unknown entry: {:?}",
        snap.unknown
    );
    // Aggregate-only content flows: a fallback-mode summary (the
    // producer gates operational pairing there) projects its
    // fetch-only classes on the same path.
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_METADATA);
    p.set_fallback(true);
    for i in 0..2u64 {
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 700 + i,
            invocation: 300 + i,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 10,
            monotonic_ns: 1000 + i * 100,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 10,
            monotonic_ns: 1050 + i * 100,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let summary = t::summarize(&window, &totals, "metadata", None);
    summary.validate().expect("fallback seal validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    let dir = out_dir("open-fence-fallback");
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), doc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block kept");
    let cw = trace
        .class_window
        .as_ref()
        .expect("fallback classes project");
    assert_eq!((cw.success, cw.unknown), (0, 2));
}

#[test]
fn persisted_counters_type_and_bound_before_exposure() {
    // P2fix2 items 24+7 (codex NEW-4 + PRIVACY): persisted counter
    // records type-check (closed kind/units/source vocabs, u64
    // value) and bound (nonempty name ≤128 chars, no controls, no
    // path separators) BEFORE snapshot JSON, terminal, or OTLP
    // output — through the REAL release entry points with canaries
    // (rejected) + an admitted-value control (projected).
    use osslscope::presentation::snapshot;
    // Canaries per intake spelling (producer PascalCase, doc_json
    // kebab): each malformed shape rejects the document — only the
    // targeted defect differs from a valid record.
    let shapes = [
        (
            "kind",
            "Bogus",
            "bogus",
            "Events",
            "events",
            "Lifecycle",
            "lifecycle",
        ),
        (
            "units",
            "Loss",
            "loss",
            "Parsecs",
            "parsecs",
            "Lifecycle",
            "lifecycle",
        ),
        (
            "source",
            "Loss",
            "loss",
            "Events",
            "events",
            "Elsewhere",
            "elsewhere",
        ),
    ];
    for (tag, kind_p, kind_d, units_p, units_d, source_p, source_d) in shapes {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([
            {"name": "focused.read_unknown", "kind": kind_p, "units": units_p, "source": source_p, "value": 1},
        ]);
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "producer intake must reject bad-{tag}"
        );
        assert!(
            snapshot::Presenter::oneshot(&doc).is_err(),
            "oneshot must reject bad-{tag}"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([
            {"name": "focused.read_unknown", "kind": kind_d, "units": units_d, "source": source_d, "value": 1},
        ]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_none(),
            "doc_json intake must reject bad-{tag}"
        );
    }
    for (tag, counter_p, counter_d) in [
        (
            "bad-value",
            serde_json::json!({"name": "focused.read_unknown", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": "1"}),
            serde_json::json!({"name": "focused.read_unknown", "kind": "loss", "units": "events", "source": "lifecycle", "value": "1"}),
        ),
        (
            "empty-name",
            serde_json::json!({"name": "", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 1}),
            serde_json::json!({"name": "", "kind": "loss", "units": "events", "source": "lifecycle", "value": 1}),
        ),
        (
            "long-name",
            serde_json::json!({"name": "n".repeat(129), "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 1}),
            serde_json::json!({"name": "n".repeat(129), "kind": "loss", "units": "events", "source": "lifecycle", "value": 1}),
        ),
        (
            "control-name",
            serde_json::json!({"name": "x\x1by", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 1}),
            serde_json::json!({"name": "x\x1by", "kind": "loss", "units": "events", "source": "lifecycle", "value": 1}),
        ),
        (
            "path-name",
            serde_json::json!({"name": "/tmp/evil", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 1}),
            serde_json::json!({"name": "/tmp/evil", "kind": "loss", "units": "events", "source": "lifecycle", "value": 1}),
        ),
    ] {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([counter_p]);
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "producer intake must reject {tag}"
        );
        assert!(
            snapshot::Presenter::oneshot(&doc).is_err(),
            "oneshot must reject {tag}"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([counter_d]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_none(),
            "doc_json intake must reject {tag}"
        );
    }
    // Admitted-value control: a well-formed counter (a REAL
    // producer vocabulary name — P2fix3 PRIVACY admits vocabulary
    // only) projects through every real sink (snapshot JSON,
    // frame, both adapters) with its exact name/value.
    let mut doc = snapshot::test_document(3, "complete");
    doc["counters"] = serde_json::json!([
        {"name": "lifecycle.polling_fallback", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 7},
    ]);
    let snap = snapshot::Presenter::oneshot(&doc).unwrap();
    let json = serde_json::to_string(&snap).unwrap();
    assert!(
        json.contains("lifecycle.polling_fallback"),
        "snapshot JSON carries it"
    );
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(
        frame.contains("lifecycle.polling_fallback"),
        "frame carries it: {frame:?}"
    );
    // No path canary anywhere in any render (strict no-path —
    // the live temp dir itself must never surface either).
    let tmpdir = std::env::temp_dir().to_string_lossy().into_owned();
    for body in [
        json,
        frame,
        osslscope::presentation::prometheus::render(&snap),
        osslscope::presentation::otel::render(&snap),
    ] {
        assert!(!body.contains("/tmp/"), "path leak: {body:?}");
        assert!(!body.contains(&tmpdir), "tmpdir leak: {body:?}");
        assert!(!body.contains('\x1b'), "escape leak");
    }
}

/// Minimal doc_json-shaped document (oneshot C-07 spellings).
fn doc_json_shell() -> serde_json::Value {
    serde_json::json!({
        "completeness": {"status": "COMPLETE", "reasons": [], "counters": []},
        "legacy_partition": {"legacy_exclusive_calls": 3, "non_legacy_exclusive_calls": 0, "shared_ambiguous_calls": 0, "unfenced_tail_calls": 0},
        "sites": [],
        "policy": null,
        "window": {"requested_start_ns": 1, "requested_end_ns": 2, "effective_start_ns": 3, "effective_end_ns": 4, "signal_cut": false},
    })
}

#[test]
fn persisted_causes_and_reasons_validate_before_exposure() {
    // P2fix2 items 24+7: lost-interval causes keep the closed
    // 12-word vocabulary (unknown causes reject the window — never
    // copied verbatim), and completeness reason words bound
    // (≤512 chars, no controls, no path separators) before any
    // sink. Admitted values project.
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Unknown cause through the service path: the window rejects.
    let dir = out_dir("cause-reject");
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
    env["crypto_watch"] = serde_json::json!([{
        "kind": "end",
        "peak_deferred_depth": 1,
        "session_loss": {"ring": [0, 0, 0, 0, 0, 0, 0, 0], "lost_intervals": [{"start_tick": 0, "end_tick": 1, "cause": "not_a_cause"}]},
    }]);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    assert!(
        p.build_service().is_err(),
        "unknown loss cause must reject the window"
    );
    // Admitted cause projects (interval renders in the frame).
    let dir = out_dir("cause-admit");
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
    env["crypto_watch"] = serde_json::json!([{
        "kind": "end",
        "peak_deferred_depth": 1,
        "session_loss": {"ring": [0, 0, 0, 0, 0, 0, 0, 0], "lost_intervals": [{"start_tick": 0, "end_tick": 1, "cause": "ring_loss"}]},
    }]);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(frame.contains("ring_loss"), "{frame:?}");
    // Poisoned reason words reject on both intakes (control char +
    // overlong + path separator via doc_json free strings).
    for (tag, reason) in [
        (
            "control",
            serde_json::json!({"kind": "loss", "counter": "x\x07y"}),
        ),
        (
            "overlong",
            serde_json::json!({"kind": "loss", "counter": "c".repeat(600)}),
        ),
        (
            "path",
            serde_json::json!({"kind": "loss", "counter": "/etc/x"}),
        ),
    ] {
        let mut dj = doc_json_shell();
        dj["completeness"]["status"] = serde_json::json!("PARTIAL");
        dj["completeness"]["reasons"] = serde_json::json!([reason]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_none(),
            "doc_json must reject {tag} reason"
        );
    }
    // Producer-path poisoned reason (typed Loss with a bad counter
    // string) rejects too.
    let mut doc = snapshot::test_document(3, "complete");
    doc["status"] = serde_json::json!({"Partial": {"reasons": [{"Loss": {"counter": "a/b", "source": "Lifecycle", "value": 1}}]}});
    assert!(
        snapshot::signals_from_producer(&doc).is_none(),
        "producer intake must reject path reason"
    );
    // Admitted reason projects through the real oneshot sink set.
    let doc = snapshot::test_document(3, "partial");
    let snap = snapshot::Presenter::oneshot(&doc).unwrap();
    assert_eq!(snap.completeness.state.as_deref(), Some("partial"));
    assert!(!snap.completeness.reasons.is_empty());
}

#[test]
fn persisted_identities_and_digests_validate_before_exposure() {
    // P2fix2 items 24+7: run identities type (pid/starttime u64,
    // boot_id 1..=64 chars, no controls, no path separators) and
    // policy digests keep 64-hex before any sink; the OTLP resource
    // never carries raw boot-ID text (bounded take + sanitized).
    // Admitted values project (run tag + instance id).
    use osslscope::presentation::snapshot;
    // Poisoned run_ids reject (envelope intake).
    for (tag, run) in [
        (
            "boot-too-long",
            serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0".repeat(65)}),
        ),
        (
            "boot-control",
            serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "b\x01d"}),
        ),
        (
            "boot-path",
            serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "/x"}),
        ),
        (
            "pid-overflow",
            serde_json::json!({"pid": 4294967296u64, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}),
        ),
    ] {
        let dir = out_dir(&format!("runid-{tag}"));
        let env = snapshot::test_envelope(0, 0, run, 10);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        assert!(
            p.build_service().is_err(),
            "envelope intake must reject {tag} run_id"
        );
    }
    // Malformed policy digests fail closed to None (context, not
    // evidence — the window survives, the digest never shows).
    let dir = out_dir("policy-digest");
    let mut env = snapshot::test_envelope(
        0,
        0,
        serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}),
        10,
    );
    env["policy"] = serde_json::json!({"sha256": "xyz", "version": 1, "rule_count": 2});
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    assert!(
        snap.policy.active.is_none(),
        "malformed digest must not project"
    );
    // Admitted identity projects (bounded take in run tag +
    // sanitized OTLP instance id — full 36-char boot id never
    // lands raw in any resource).
    let dir = out_dir("runid-admit");
    let env = snapshot::test_envelope(
        0,
        0,
        serde_json::json!({"pid": 7, "starttime": 8, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}),
        10,
    );
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(frame.contains("7-8-12345678"), "{frame:?}");
    let otel = osslscope::presentation::otel::render(&snap);
    assert!(otel.contains("7-8-12345678"), "{otel:?}");
    assert!(
        !otel.contains("12345678-9abc"),
        "full boot id never lands raw in resources: {otel:?}"
    );
}

#[test]
fn one_frame_carries_its_build_markers() {
    // P2fix2 item 13 (codex NEW-P2h): a one-frame render delivers
    // the snapshot's own folded-window markers (first applicable
    // frame — not an empty marker set).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("markers-first");
    let env =
        snapshot::test_envelope_with_doc(0, 0, run.clone(), snapshot::test_document(3, "partial"));
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    assert!(!snap.markers.is_empty(), "folded window leaves markers");
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(
        frame.contains("MARKER partial seq=0"),
        "first frame carries its markers: {frame:?}"
    );
}

#[test]
fn markers_bind_to_their_generation() {
    // P2fix2 item 13 (codex NEW-P2h): folded-window markers bind to
    // their generation — a multi-generation scan surfaces ONLY the
    // current generation's markers (pending markers never cross
    // generations; the epoch reset scopes them like every other
    // epoch accumulator).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("markers-gen");
    for (seq, generation) in [(0u64, 0u64), (1u64, 1u64)] {
        let env = snapshot::test_envelope_with_doc(
            seq,
            generation,
            run.clone(),
            snapshot::test_document(3, "partial"),
        );
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    assert_eq!(snap.source.generation, Some(1));
    assert!(
        snap.markers.iter().all(|m| m.contains("seq=1")),
        "only gen-1 markers surface: {:?}",
        snap.markers
    );
    assert!(
        !snap.markers.iter().any(|m| m.contains("seq=0")),
        "gen-0 markers must not cross: {:?}",
        snap.markers
    );
}

#[test]
fn watch_follow_first_markers_and_outage_recovery() {
    // P2fix2 items 13+21 (codex NEW-P2h + NEW-1) as corrected by
    // P2fix3 NEW-1: EXECUTABLE follow checks through the REAL
    // watch binary — the first frame already carries its build's
    // markers (import-before-render); a generation change binds
    // markers (new markers only + PREVIOUS EPOCH); a window-file
    // outage KEEPS PUBLISHING last-good (same snapshot, refreshed
    // staleness — no exit — stderr note) and recovery advances.
    use std::io::BufRead;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("watch-follow");
    let win0 =
        snapshot::test_envelope_with_doc(0, 0, run.clone(), snapshot::test_document(3, "partial"));
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&win0).unwrap(),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "watch",
            "--out",
            dir.to_str().unwrap(),
            "--follow",
            "--poll-seconds",
            "1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send((true, line)).is_err() {
                break;
            }
        }
    });
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if tx2.send((false, line)).is_err() {
                break;
            }
        }
    });
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn drain_until(
        rx: &std::sync::mpsc::Receiver<(bool, String)>,
        out_lines: &mut Vec<String>,
        err_lines: &mut Vec<String>,
        deadline: Instant,
        want_out: &str,
    ) {
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for {want_out:?}; out={out_lines:?} err={err_lines:?}");
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok((is_out, line)) => {
                    if is_out {
                        out_lines.push(line);
                    } else {
                        err_lines.push(line);
                    }
                }
                Err(_) => continue,
            }
            if out_lines.iter().any(|l| l.contains(want_out)) {
                return;
            }
        }
    }
    let mut child = OwnedChild(child);
    let mut out_lines: Vec<String> = vec![];
    let mut err_lines: Vec<String> = vec![];
    // Stage 1: first frame carries its build's markers. Then wait
    // for frame 2's banner (frames 0+1 fully drained + steady
    // follow proven) before scripting the outage.
    drain_until(
        &rx,
        &mut out_lines,
        &mut err_lines,
        Instant::now() + Duration::from_secs(15),
        "MARKER partial seq=0",
    );
    drain_until(
        &rx,
        &mut out_lines,
        &mut err_lines,
        Instant::now() + Duration::from_secs(15),
        // [p2fix5 NEW-29: banners carry `coalesced=K` now —
        // match the frame-2 banner prefix (no `--- frame 20`
        // collision: the trailing space pins the seq word).]
        "--- frame 2 ",
    );
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "follow must keep running"
    );
    // Stage 2: outage (remove the out-DIR) — P2fix3 NEW-1: the
    // loop KEEPS PUBLISHING last-good (same snapshot_seq on every
    // outage banner — no exit — stderr note). Then recovery with
    // a gen-1 window. Frames count by banner (bodies trail their
    // banner — only new banners prove new frames).
    let banner_count =
        |lines: &[String]| lines.iter().filter(|l| l.starts_with("--- frame")).count();
    let banner_seqs = |lines: &[String]| {
        lines
            .iter()
            .filter_map(|l| {
                // [p2fix5 NEW-29: `--- frame <seq> coalesced=<K> ---`.]
                l.strip_prefix("--- frame ").and_then(|s| {
                    s.split_whitespace()
                        .next()
                        .and_then(|w| w.parse::<u64>().ok())
                })
            })
            .collect::<Vec<_>>()
    };
    std::fs::remove_dir_all(&dir).unwrap();
    let outage_mark = banner_count(&out_lines);
    let outage_seqs = banner_seqs(&out_lines);
    let last_seq_before = *outage_seqs.last().expect("frames before outage");
    std::thread::sleep(Duration::from_secs(3));
    // Drain whatever arrived (new banners must repeat the
    // last-good snapshot_seq).
    while let Ok((is_out, line)) = rx.try_recv() {
        if is_out {
            out_lines.push(line);
        } else {
            err_lines.push(line);
        }
    }
    let outage_banners = banner_count(&out_lines) - outage_mark;
    assert!(
        outage_banners >= 2,
        "outage must keep publishing last-good frames: {out_lines:?}"
    );
    for seq in banner_seqs(&out_lines).iter().skip(outage_seqs.len()) {
        assert_eq!(
            *seq, last_seq_before,
            "outage frames repeat the last-good snapshot"
        );
    }
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "follow must survive the outage"
    );
    assert!(
        err_lines.iter().any(|l| l.contains("retaining last-good")),
        "outage notes on stderr: {err_lines:?}"
    );
    // Stage 3: recovery advances with generation-bound markers.
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&win0).unwrap(),
    )
    .unwrap();
    let win1 =
        snapshot::test_envelope_with_doc(1, 1, run.clone(), snapshot::test_document(3, "partial"));
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&win1).unwrap(),
    )
    .unwrap();
    drain_until(
        &rx,
        &mut out_lines,
        &mut err_lines,
        Instant::now() + Duration::from_secs(15),
        "PREVIOUS EPOCH",
    );
    drain_until(
        &rx,
        &mut out_lines,
        &mut err_lines,
        Instant::now() + Duration::from_secs(15),
        "MARKER partial seq=1",
    );
    // Generation binding: no gen-0 marker after the boundary.
    let boundary = out_lines
        .iter()
        .position(|l| l.contains("PREVIOUS EPOCH"))
        .unwrap();
    for line in out_lines.iter().skip(boundary) {
        if line.contains("MARKER") {
            assert!(
                !line.contains("seq=0"),
                "gen-0 marker crossed generations: {line:?}"
            );
        }
    }
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "follow keeps running after recovery"
    );
}

#[test]
fn new1_watch_outage_publishes_last_good_with_fresh_staleness() {
    // P2fix3 NEW-1: during a window-file outage the follow loop
    // keeps publishing last-good with FRESH staleness (recomputed
    // per frame — never the frozen build-time age): a window that
    // is fresh when the outage starts flips to STALE across
    // outage frames while the snapshot_seq repeats.
    use std::io::BufRead;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("watch-outage-stale");
    // Fresh window: effective end ≈ now, 3 s span (stale past
    // 6 s — startup + settle stay fresh, the outage flips it).
    let now = osslscope::presentation::snapshot::monotonic_ns();
    let start = now.saturating_sub(3_000_000_000);
    let mut env = snapshot::test_envelope(0, 0, run, 10);
    env["window"] = serde_json::json!({
        "requested_start_ns": start,
        "requested_end_ns": now,
        "effective_start_ns": start,
        "effective_end_ns": now,
        "signal_cut": false,
        "accum_cut": false,
    });
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "watch",
            "--out",
            dir.to_str().unwrap(),
            "--follow",
            "--poll-seconds",
            "1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(child);
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    // Header lines: (seq, age, stale).
    fn headers(lines: &[String]) -> Vec<(u64, u64, bool)> {
        lines
            .iter()
            .filter(|l| l.starts_with("osslscope "))
            .filter_map(|l| {
                let seq = l
                    .split("seq=")
                    .nth(1)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()?;
                let age = l
                    .split("age=")
                    .nth(1)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()?;
                Some((seq, age, l.contains("STALE")))
            })
            .collect()
    }
    // Stage 1: first frame fresh (no STALE).
    let mut lines: Vec<String> = vec![];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() >= deadline {
            panic!("no fresh first frame: {lines:?}");
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => lines.push(line),
            Err(_) => continue,
        }
        if let Some((_, _, stale)) = headers(&lines).first() {
            assert!(!stale, "first frame must be fresh: {lines:?}");
            break;
        }
    }
    // Stage 2: outage — headers keep coming with the SAME seq
    // as the last pre-outage frame, growing age, flipping to
    // STALE. Settle first (in-flight pre-outage frames drain),
    // then anchor on the last header so far.
    std::fs::remove_dir_all(&dir).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    let pre_outage = headers(&lines);
    let anchor = *pre_outage.last().expect("pre-outage header");
    assert!(!anchor.2, "anchor frame fresh: {lines:?}");
    let outage_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() >= outage_deadline {
            panic!("staleness never flipped during the outage: {lines:?}");
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => lines.push(line),
            Err(_) => continue,
        }
        let hs = headers(&lines);
        let outage = &hs[pre_outage.len().min(hs.len())..];
        if outage.len() >= 2 {
            let last = outage[outage.len() - 1];
            if last.0 == anchor.0 && last.1 > anchor.1 && last.2 {
                // Every outage frame repeats the anchor seq.
                assert!(
                    outage.iter().all(|h| h.0 == anchor.0),
                    "outage repeats last-good: {outage:?}"
                );
                break;
            }
        }
    }
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "follow must survive the outage"
    );
}

#[test]
fn newp2h_follow_json_matches_human_generation_facts() {
    // P2fix3 NEW-P2h: follow-mode JSON emits the SAME
    // generation-bound facts as human frames (the sticky marker
    // set — not just the current build's), across slow-reader
    // builds AND generation resets. Both formats run the same
    // script: frame 1 folds w0 ({m0}); a slow reader then sees w1
    // land ({m0, m1} — accumulation, not replacement); a gen-1
    // window resets ({m2} only).
    use std::io::BufRead;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let script = |format_json: bool, tag: &str| {
        let dir = out_dir(tag);
        let win0 = snapshot::test_envelope_with_doc(
            0,
            0,
            run.clone(),
            snapshot::test_document(3, "partial"),
        );
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&win0).unwrap(),
        )
        .unwrap();
        let mut args = vec![
            "watch".to_string(),
            "--out".to_string(),
            dir.to_str().unwrap().to_string(),
            "--follow".to_string(),
            "--poll-seconds".to_string(),
            "1".to_string(),
        ];
        if format_json {
            args.push("--format".to_string());
            args.push("json".to_string());
        }
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = OwnedChild(child);
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // Split stdout into banner-delimited frames; extract each
        // COMPLETE frame's marker set (JSON array or MARKER
        // lines). A trailing partial body (killed mid-flush)
        // skips — never a parse panic.
        let frames_of = |lines: &[String]| -> Vec<std::collections::BTreeSet<String>> {
            let mut frames: Vec<std::collections::BTreeSet<String>> = vec![];
            let mut current: Vec<String> = vec![];
            let mut seen_banner = false;
            for line in lines {
                if line.starts_with("--- frame") {
                    if seen_banner && !current.is_empty() {
                        if let Some(m) = markers_of(&current, format_json) {
                            frames.push(m);
                        }
                    }
                    current.clear();
                    seen_banner = true;
                    continue;
                }
                if seen_banner {
                    current.push(line.clone());
                }
            }
            frames
        };
        fn markers_of(
            lines: &[String],
            format_json: bool,
        ) -> Option<std::collections::BTreeSet<String>> {
            if format_json {
                let v: serde_json::Value = serde_json::from_str(&lines.join("\n")).ok()?;
                return Some(
                    v["markers"]
                        .as_array()?
                        .iter()
                        .map(|m| m.as_str().unwrap().to_string())
                        .collect(),
                );
            }
            Some(
                lines
                    .iter()
                    .filter(|l| l.starts_with("MARKER "))
                    .map(|l| l["MARKER ".len()..].to_string())
                    .collect(),
            )
        }
        let mut lines: Vec<String> = vec![];
        let wait_frames = |rx: &std::sync::mpsc::Receiver<String>,
                           lines: &mut Vec<String>,
                           n: usize,
                           what: &str| {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for {what}; lines={lines:?}");
                }
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(line) => lines.push(line),
                    Err(_) => continue,
                }
                // A frame is complete when its successor's banner
                // arrives (or, for the wait below, when enough
                // banners prove enough bodies).
                let banners = lines.iter().filter(|l| l.starts_with("--- frame")).count();
                if banners > n {
                    return;
                }
            }
        };
        // Frame 1 folds w0 only.
        wait_frames(&rx, &mut lines, 1, "frame 1");
        // Slow reader: w1 lands after frame 1 served.
        let win1 = snapshot::test_envelope_with_doc(
            1,
            0,
            run.clone(),
            snapshot::test_document(5, "partial"),
        );
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&win1).unwrap(),
        )
        .unwrap();
        wait_frames(&rx, &mut lines, 2, "frame 2");
        // Generation reset: gen-1 w2.
        let win2 = snapshot::test_envelope_with_doc(
            2,
            1,
            run.clone(),
            snapshot::test_document(7, "partial"),
        );
        std::fs::write(
            dir.join("window-0000000002.json"),
            serde_json::to_string(&win2).unwrap(),
        )
        .unwrap();
        // One more banner past the m2 frame (its body completes
        // only when the successor banner delimits it).
        wait_frames(&rx, &mut lines, 4, "frame 4");
        // Settle, then drain.
        std::thread::sleep(Duration::from_millis(1500));
        while let Ok(line) = rx.try_recv() {
            lines.push(line);
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "follow keeps running"
        );
        frames_of(&lines)
    };
    for format_json in [false, true] {
        let what = if format_json { "json" } else { "human" };
        let frames = script(format_json, &format!("newp2h-{what}"));
        assert!(!frames.is_empty(), "{what}: frames served");
        // First frame: w0's marker, nothing else.
        assert!(
            frames[0].iter().any(|m| m.contains("seq=0")),
            "{what} first frame carries m0: {:?}",
            frames[0]
        );
        assert!(
            !frames[0]
                .iter()
                .any(|m| m.contains("seq=1") || m.contains("seq=2")),
            "{what} first frame has only m0: {:?}",
            frames[0]
        );
        // Slow reader: the first frame showing m1 ALSO shows m0
        // (accumulation across builds — the JSON/human parity).
        let acc = frames
            .iter()
            .find(|f| f.iter().any(|m| m.contains("seq=1")))
            .unwrap_or_else(|| panic!("{what}: no frame shows m1: {frames:?}"));
        assert!(
            acc.iter().any(|m| m.contains("seq=0")),
            "{what} slow-reader frame accumulates m0+m1: {acc:?}"
        );
        // Generation reset: the first frame showing m2 shows
        // NEITHER m0 nor m1 (generation binding, both formats).
        let reset = frames
            .iter()
            .find(|f| f.iter().any(|m| m.contains("seq=2")))
            .unwrap_or_else(|| panic!("{what}: no frame shows m2: {frames:?}"));
        assert!(
            !reset
                .iter()
                .any(|m| m.contains("seq=0") || m.contains("seq=1")),
            "{what} reset frame binds to gen 1: {reset:?}"
        );
    }
}

#[test]
fn newp2h_follow_backpressure_blocks_then_recovers() {
    // P2fix4 NEW-P2h: ACTUAL blocked output + recovery — a
    // stopped reader fills the (4 KiB) stdout pipe and the
    // follow child blocks mid-write (proven via pipe-write
    // wchan samples + a banner stall far past the 1s cadence —
    // NOT a continuously drained channel). Recovery coalesces: the
    // post-stall frame jumps win 0→2 with coalesced=1 and
    // markers {m0,m1,m2} (w1 never framed, its marker imports);
    // a gen-1 window then resets to {m3}. Both formats.
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Fat partial docs (150 real counters — every frame exceeds
    // pipe + one read-ahead chunk (8 KiB), so the FIRST stall
    // frame blocks deterministically in both formats).
    let fat_doc = |calls: u64| {
        let mut doc = snapshot::test_document(calls, "partial");
        doc["counters"] = serde_json::json!(
            (0..150)
                .map(|_| serde_json::json!({"name": "lifecycle.polling_fallback", "kind": "Loss", "units": "Events", "source": "Lifecycle", "value": 1}))
                .collect::<Vec<_>>()
        );
        doc
    };
    for format_json in [false, true] {
        let what = if format_json { "json" } else { "human" };
        let dir = out_dir(&format!("newp2h-bp-{what}"));
        let win0 = snapshot::test_envelope_with_doc(0, 0, run.clone(), fat_doc(3));
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&win0).unwrap(),
        )
        .unwrap();
        let mut args = vec![
            "watch".to_string(),
            "--out".to_string(),
            dir.to_str().unwrap().to_string(),
            "--follow".to_string(),
            "--poll-seconds".to_string(),
            "1".to_string(),
        ];
        if format_json {
            args.push("--format".to_string());
            args.push("json".to_string());
        }
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = OwnedChild(child);
        let pid = child.0.id();
        let stdout = child.0.stdout.take().unwrap();
        // Shrink the pipe to one page (backpressure in ~1
        // frame, both formats).
        let rc = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        assert_eq!(rc, 4096, "{what}: pipe shrink");
        // Rendezvous reader (NOT an unbounded drain): each chunk
        // send blocks until the test receives, so a test pause
        // is exact stdout backpressure.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(0);
        std::thread::spawn(move || {
            let mut stdout = stdout;
            loop {
                let mut chunk = vec![0u8; 4096];
                match stdout.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        chunk.truncate(n);
                        if tx.send(chunk).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        // Collect timestamped lines until `enough` holds or the
        // deadline passes. Returns all lines + banner times.
        let mut text = String::new();
        let mut banners: Vec<Instant> = vec![];
        let collect_until = |text: &mut String,
                             banners: &mut Vec<Instant>,
                             rx: &std::sync::mpsc::Receiver<Vec<u8>>,
                             secs: u64,
                             enough: &dyn Fn(&str) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < deadline {
                if enough(text) {
                    return;
                }
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(chunk) => {
                        let s = String::from_utf8_lossy(&chunk).into_owned();
                        for line in s.split_inclusive('\n') {
                            if line.starts_with("--- frame") {
                                banners.push(Instant::now());
                            }
                        }
                        text.push_str(&s);
                    }
                    Err(_) => continue,
                }
            }
            assert!(enough(text), "{what}: timed out collecting");
        };
        let banner_count = |text: &str| text.lines().filter(|l| l.starts_with("--- frame")).count();
        // Phase A: flow (2 banners prove the 1s cadence runs).
        collect_until(&mut text, &mut banners, &rx, 15, &|t| banner_count(t) >= 2);
        // Land w1+w2 (gen 0) — they fold during the stall below.
        for (seq, calls) in [(1u64, 5u64), (2, 7)] {
            let win = snapshot::test_envelope_with_doc(seq, 0, run.clone(), fat_doc(calls));
            std::fs::write(
                dir.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&win).unwrap(),
            )
            .unwrap();
        }
        // Phase B: STOP receiving for 11s (exact backpressure).
        // Once the pipe fills (~1 frame JSON, ~4 frames human —
        // human frames summarize counters at ~1.2 KiB), the child
        // must sleep in `pipe_write` (blocked output, not idle —
        // it emits every 1s when unblocked). Sampled 3× past the
        // fill point.
        std::thread::sleep(Duration::from_secs(5));
        for sample in 0..3 {
            let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
            assert!(
                ["pipe_write", "anon_pipe_write"].contains(&wchan.trim()),
                "{what}: stall sample {sample} must catch a blocked pipe write, got {wchan:?}"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{what}: blocked child stays alive"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
        let banners_pre = banners.len();
        // Phase C: resume — the banner gap proves the stall, then
        // the coalesced frame lands (win 0→2, coalesced=1,
        // markers {m0,m1,m2}). Waits need COMPLETE frames (a
        // header/markers arrive over several chunks).
        let complete_win = |t: &str, win: u64| {
            if format_json {
                t.split("--- frame").skip(1).any(|f| {
                    let body = f.lines().skip(1).collect::<Vec<_>>().join("\n");
                    serde_json::from_str::<serde_json::Value>(&body)
                        .map(|v| v["source"]["window_seq"] == win)
                        .unwrap_or(false)
                })
            } else {
                let mut seen = false;
                let want = format!("win={win}");
                for line in t.lines() {
                    if line.starts_with("osslscope ") && line.split_whitespace().any(|w| w == want)
                    {
                        seen = true;
                    } else if seen && line.starts_with("--- frame") {
                        return true;
                    }
                }
                false
            }
        };
        collect_until(&mut text, &mut banners, &rx, 20, &|t| complete_win(t, 2));
        // Gap measured across the stall: last pre-stall banner to
        // first post-resume banner.
        let pre_last = banners[..banners_pre].last().copied();
        let post_first = banners[banners_pre..].first().copied();
        match (pre_last, post_first) {
            (Some(a), Some(b)) => assert!(
                b.saturating_duration_since(a) >= Duration::from_secs(4),
                "{what}: banner stall must far exceed the 1s cadence: {:?}",
                b.saturating_duration_since(a)
            ),
            _ => panic!("{what}: banner gap unmeasurable"),
        }
        // Split post-stall frames (banner line stripped); find the
        // win=2 frame.
        let frames: Vec<String> = text
            .split("--- frame")
            .skip(1)
            .map(|f| f.lines().skip(1).collect::<Vec<_>>().join("\n"))
            .collect();
        let frame_of = |pred: &dyn Fn(&str) -> bool| -> String {
            frames
                .iter()
                .find(|f: &&String| pred(f.as_str()))
                .cloned()
                .unwrap_or_else(|| panic!("{what}: coalesced frame missing"))
        };
        if format_json {
            let wins: Vec<u64> = frames
                .iter()
                .filter_map(|f| {
                    let v: serde_json::Value = serde_json::from_str(f).ok()?;
                    v["source"]["window_seq"].as_u64()
                })
                .collect();
            assert!(
                !wins.contains(&1),
                "{what}: w1 never framed (coalesced): {wins:?}"
            );
            assert!(wins.contains(&2), "{what}: win jumps to 2: {wins:?}");
            let f2 = frame_of(&|f| {
                serde_json::from_str::<serde_json::Value>(f)
                    .map(|v| v["source"]["window_seq"] == 2)
                    .unwrap_or(false)
            });
            let v: serde_json::Value = serde_json::from_str(&f2).unwrap();
            let ms: Vec<String> = v["markers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .collect();
            for seq in ["seq=0", "seq=1", "seq=2"] {
                assert!(
                    ms.iter().any(|m| m.contains(seq)),
                    "{what}: coalesced frame carries {seq}: {ms:?}"
                );
            }
            // [p2fix5 NEW-29: the exact coalesced-window count rides
            // the follow banner in JSON output too — the blocked-
            // output jump frame (win 0→2) carries coalesced=1.]
            let chunks: Vec<&str> = text.split("--- frame").skip(1).collect();
            let jump = chunks
                .iter()
                .find(|c| {
                    let body = c.lines().skip(1).collect::<Vec<_>>().join("\n");
                    serde_json::from_str::<serde_json::Value>(&body)
                        .map(|v| v["source"]["window_seq"] == 2)
                        .unwrap_or(false)
                })
                .unwrap_or_else(|| panic!("{what}: coalesced frame missing"));
            assert_eq!(
                banner_coalesced(jump),
                Some(1),
                "{what}: JSON jump frame banners coalesced=1"
            );
        } else {
            let header = |f: &str, key: &str| {
                f.lines()
                    .find(|l| l.starts_with("osslscope "))
                    .and_then(|l| {
                        l.split_whitespace()
                            .find(|w| w.starts_with(&format!("{key}=")))
                            .and_then(|w| w.split_once('=').map(|(_, v)| v.to_string()))
                    })
            };
            let wins: Vec<String> = frames.iter().filter_map(|f| header(f, "win")).collect();
            assert!(
                !wins.iter().any(|w| w == "1"),
                "{what}: w1 never framed (coalesced): {wins:?}"
            );
            let f2 = frame_of(&|f| header(f, "win").as_deref() == Some("2"));
            assert_eq!(
                header(&f2, "coalesced").as_deref(),
                Some("1"),
                "{what}: coalesced count rides the frame"
            );
            let ms: Vec<String> = f2
                .lines()
                .filter(|l| l.starts_with("MARKER "))
                .map(|l| l["MARKER ".len()..].to_string())
                .collect();
            for seq in ["seq=0", "seq=1", "seq=2"] {
                assert!(
                    ms.iter().any(|m| m.contains(seq)),
                    "{what}: coalesced frame carries {seq}: {ms:?}"
                );
            }
            // [p2fix5 NEW-29: the banner count matches the header
            // count on the human jump frame too.]
            let hchunks: Vec<&str> = text.split("--- frame").skip(1).collect();
            let hjump = hchunks
                .iter()
                .find(|c| {
                    let body = c.lines().skip(1).collect::<Vec<_>>().join("\n");
                    header(&body, "win").as_deref() == Some("2")
                })
                .unwrap_or_else(|| panic!("{what}: coalesced frame missing"));
            assert_eq!(
                banner_coalesced(hjump),
                Some(1),
                "{what}: human jump frame banners coalesced=1"
            );
        }
        // Phase D: gen-1 w3 in normal flow resets to {m3}.
        let win3 = snapshot::test_envelope_with_doc(3, 1, run.clone(), fat_doc(9));
        std::fs::write(
            dir.join("window-0000000003.json"),
            serde_json::to_string(&win3).unwrap(),
        )
        .unwrap();
        collect_until(&mut text, &mut banners, &rx, 20, &|t| complete_win(t, 3));
        let frames: Vec<String> = text
            .split("--- frame")
            .skip(1)
            .map(|f| f.lines().skip(1).collect::<Vec<_>>().join("\n"))
            .collect();
        let has_seq = |f: &str, seq: &str| {
            if format_json {
                serde_json::from_str::<serde_json::Value>(f)
                    .map(|v| {
                        v["markers"].as_array().is_some_and(|ms| {
                            ms.iter()
                                .any(|m| m.as_str().is_some_and(|s| s.contains(seq)))
                        })
                    })
                    .unwrap_or(false)
            } else {
                f.lines()
                    .any(|l| l.starts_with("MARKER ") && l["MARKER ".len()..].contains(seq))
            }
        };
        let reset = frames
            .iter()
            .find(|f| has_seq(f, "seq=3"))
            .unwrap_or_else(|| panic!("{what}: no frame shows m3"));
        for seq in ["seq=0", "seq=1", "seq=2"] {
            assert!(
                !has_seq(reset, seq),
                "{what}: reset frame drops {seq}: {reset:?}"
            );
        }
        // [p2fix5 NEW-29: the generation-reset frame banners
        // coalesced=0 (both formats — the epoch boundary resets
        // the span).]
        let dchunks: Vec<&str> = text.split("--- frame").skip(1).collect();
        let rchunk = dchunks
            .iter()
            .find(|c| {
                let body = c.lines().skip(1).collect::<Vec<_>>().join("\n");
                has_seq(&body, "seq=3")
            })
            .unwrap_or_else(|| panic!("{what}: no frame shows m3"));
        assert_eq!(
            banner_coalesced(rchunk),
            Some(0),
            "{what}: reset frame banners coalesced=0"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "{what}: follow keeps running"
        );
    }
}

#[test]
fn envelope_duplicate_keys_reject_before_folding() {
    // P2fix2 item 13 (codex NEW-P2f): repeated envelope keys
    // (top-level `document`, nested `status`, ...) reject the
    // window BEFORE folding — a repeated `document` would conceal
    // the unchecked section under last-wins. Service envelopes are
    // machine-written (never legitimately duplicated), so the
    // whole envelope walks strict (the v2-document historical
    // last-wins scope outside trace sections is unchanged).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let doc_a = snapshot::test_document(5, "complete");
    let doc_b = snapshot::test_document(9, "complete");
    // Duplicate top-level `document` (B would win last-wins).
    let dir = out_dir("dupe-doc");
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 5);
    env["document"] = doc_b.clone();
    let text = serde_json::to_string(&env).unwrap();
    let inner = &text[1..text.len() - 1];
    let duped = format!(
        "{{\"document\":{},{}",
        serde_json::to_string(&doc_a).unwrap(),
        &inner[inner.find("\"document\"").unwrap()..]
    );
    // Sanity: the spliced text parses with B winning (the
    // concealment the check must refuse).
    let parsed: serde_json::Value = serde_json::from_str(&format!("{duped}}}")).unwrap();
    assert_eq!(
        parsed["document"]["legacy_partition"]["legacy_exclusive"],
        9
    );
    std::fs::write(dir.join("window-0000000000.json"), format!("{duped}}}")).unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    assert!(
        p.build_service().is_err(),
        "repeated envelope `document` must reject"
    );
    // Duplicate nested key inside the document.
    let dir = out_dir("dupe-nested");
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 5);
    let text = serde_json::to_string(&env).unwrap();
    let duped = text.replacen("\"status\":", "\"status\":\"Complete\",\"status\":", 1);
    std::fs::write(dir.join("window-0000000000.json"), duped).unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    assert!(
        p.build_service().is_err(),
        "repeated nested key must reject"
    );
}

#[test]
fn one_fail_closed_contract_across_all_trace_gates() {
    // P2fix2 item 6 (codex GATE29): ONE fail-closed contract across
    // raw intake + both presenter inputs + restored checkpoints — a
    // malformed trace section (status mode carrying distributions)
    // rejects IDENTICALLY at every gate, while the valid section
    // passes every gate.
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    // A valid certain latency seal (real fold).
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let good = t::summarize(&window, &totals, "latency", None);
    good.validate().expect("valid seal passes");
    // Gate 1 — raw intake (full v2 document text).
    let mut doc = osslscope::capture::empty_document();
    osslscope::evidence::stamp_trace_summary(&mut doc, good.clone());
    let text = osslscope::report::render_json(&doc).expect("renders");
    let text = String::from_utf8(text).unwrap();
    osslscope::schema::check_v2_document_text(&text).expect("raw intake passes valid");
    let mut bad_value: serde_json::Value = serde_json::from_str(&text).unwrap();
    bad_value["trace_summary"]["mode"] = serde_json::json!("status");
    bad_value["trace_summary"]["window"]["mode"] = serde_json::json!("status");
    let bad_text = serde_json::to_string(&bad_value).unwrap();
    assert!(
        osslscope::schema::check_v2_document_text(&bad_text).is_err(),
        "raw intake must reject status-with-distributions"
    );
    // Gate 2 — producer presenter input.
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&good).unwrap();
    assert!(snapshot::signals_from_producer(&pdoc).is_some());
    let mut bad = t::summarize(&window, &totals, "latency", None);
    bad.mode = "status".to_string();
    bad.window.mode = "status".to_string();
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&bad).unwrap();
    assert!(
        snapshot::signals_from_producer(&pdoc).is_none(),
        "producer input must reject status-with-distributions"
    );
    // Gate 3 — doc_json presenter input (same malformed section in
    // doc_json clothing; the trace gate is shape-independent).
    let mut dj = doc_json_shell();
    dj["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    dj["trace_summary"] = serde_json::to_value(&good).unwrap();
    assert!(snapshot::signals_from_doc_json(&dj).is_some());
    let mut dj = doc_json_shell();
    dj["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    dj["trace_summary"] = serde_json::to_value(&bad).unwrap();
    assert!(
        snapshot::signals_from_doc_json(&dj).is_none(),
        "doc_json input must reject status-with-distributions"
    );
    // Gate 4 — restored checkpoint (a bad sealed trace in `latest`
    // refuses the restore instead of applying it).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("gate29-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&good).unwrap();
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    let body = std::fs::read(&ckpt).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["accumulators"]["latest"]["signals"]["trace"]["mode"] = serde_json::json!("status");
    v["accumulators"]["latest"]["signals"]["trace"]["window"]["mode"] = serde_json::json!("status");
    v.as_object_mut().unwrap().remove("sha256");
    let bytes = serde_json::to_vec(&v).unwrap();
    let hash = snapshot::sha256_hex(&bytes);
    v.as_object_mut()
        .unwrap()
        .insert("sha256".to_string(), serde_json::json!(hash));
    std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .err()
        .expect("restore must reject bad sealed trace");
}

#[test]
fn gate29_contract_triggers_and_coverage_across_all_paths() {
    // P2fix3 GATE29: the ONE document-level contract runs the
    // section/version triggers (both directions) + coverage-vs-
    // api_activity reconciliation IDENTICALLY at all four gates
    // (raw intake, both presenter inputs, restored checkpoints).
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    // A valid seal WITH the by-api opt-in (API 20 covered).
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 { "covered" } else { "not_attached" }.to_string(),
        );
    }
    let good = t::summarize(&window, &totals, "latency", Some(&avail));
    good.validate().expect("covered seal passes");
    // Full-shape supporting row (API 20, all gap flags clear).
    let clean_row = |api: u32, attached: bool| {
        serde_json::json!({
            "api": api, "entries": 1,
            "observed_success": 1, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {
                "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                "unsupported_return": 0, "saturated": false,
                "not_attached": false, "read_receipt": true,
                "attachment": attached, "finality": attached,
            },
        })
    };
    let rows = serde_json::json!([clean_row(20, false)]);
    // Gate 1 — raw intake (full v2 document text).
    let mut doc = osslscope::capture::empty_document();
    osslscope::evidence::stamp_trace_summary(&mut doc, good.clone());
    let mut text_value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&doc).expect("renders")).unwrap();
    text_value["api_activity"] = rows.clone();
    let text = serde_json::to_string(&text_value).unwrap();
    osslscope::schema::check_v2_document_text(&text).expect("raw passes covered+rows");
    // Covered without rows rejects.
    let mut norows = text_value.clone();
    norows.as_object_mut().unwrap().remove("api_activity");
    assert!(
        osslscope::schema::check_v2_document_text(&serde_json::to_string(&norows).unwrap())
            .is_err(),
        "raw must reject covered-without-rows"
    );
    // Covered with a gappy row rejects.
    let mut gappy = text_value.clone();
    gappy["api_activity"] = serde_json::json!([clean_row(20, true)]);
    assert!(
        osslscope::schema::check_v2_document_text(&serde_json::to_string(&gappy).unwrap()).is_err(),
        "raw must reject covered-with-gappy-row"
    );
    // Minor 9 without the section rejects.
    let mut nosection = text_value.clone();
    nosection.as_object_mut().unwrap().remove("trace_summary");
    assert!(
        osslscope::schema::check_v2_document_text(&serde_json::to_string(&nosection).unwrap())
            .is_err(),
        "raw must reject minor-9-without-section"
    );
    // Section with minor 8 rejects.
    let mut oldminor = text_value.clone();
    oldminor["schema_version"] = serde_json::json!("observed-crypto-v2.8");
    assert!(
        osslscope::schema::check_v2_document_text(&serde_json::to_string(&oldminor).unwrap())
            .is_err(),
        "raw must reject section-with-minor-8"
    );
    // Gates 2+3 — presenter inputs (producer + doc_json).
    for shape in ["producer", "doc_json"] {
        let mut shell = if shape == "producer" {
            let mut d = snapshot::test_document(3, "complete");
            d["schema"] = serde_json::json!("observed-crypto-v2.9");
            d
        } else {
            let mut d = doc_json_shell();
            d["schema_version"] = serde_json::json!("observed-crypto-v2.9");
            d
        };
        let read = |d: &serde_json::Value| {
            if shape == "producer" {
                snapshot::signals_from_producer(d).is_some()
            } else {
                snapshot::signals_from_doc_json(d).is_some()
            }
        };
        shell["trace_summary"] = serde_json::to_value(&good).unwrap();
        shell["api_activity"] = rows.clone();
        assert!(read(&shell), "{shape} passes covered+rows");
        shell.as_object_mut().unwrap().remove("api_activity");
        assert!(!read(&shell), "{shape} rejects covered-without-rows");
        shell["api_activity"] = serde_json::json!([clean_row(20, true)]);
        assert!(!read(&shell), "{shape} rejects covered-with-gappy-row");
        shell["api_activity"] = rows.clone();
        shell.as_object_mut().unwrap().remove("trace_summary");
        assert!(!read(&shell), "{shape} rejects minor-9-without-section");
        shell["trace_summary"] = serde_json::to_value(&good).unwrap();
        if shape == "producer" {
            shell["schema"] = serde_json::json!("observed-crypto-v2.8");
        } else {
            shell["schema_version"] = serde_json::json!("observed-crypto-v2.8");
        }
        assert!(!read(&shell), "{shape} rejects section-with-minor-8");
    }
    // Gate 4 — restored checkpoint (tampered coverage support /
    // minor refuses the restore).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("gate29-contract-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&good).unwrap();
    pdoc["api_activity"] = rows.clone();
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes covered+rows");
    let retamper = |f: &dyn Fn(&mut serde_json::Value)| {
        let body = std::fs::read(&ckpt).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        f(&mut v);
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hash = snapshot::sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hash));
        std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    retamper(&|v| {
        v["accumulators"]["latest"]["api_activity"] = serde_json::json!([]);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject covered-without-rows"
    );
    retamper(&|v| {
        v["accumulators"]["latest"]["api_activity"] = serde_json::json!([clean_row(20, true)]);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject covered-with-gappy-row"
    );
    retamper(&|v| {
        v["accumulators"]["latest"]["api_activity"] = rows.clone();
        v["accumulators"]["latest"]["schema_minor"] = serde_json::json!(8u64);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject section-with-minor-8"
    );
}

#[test]
fn gate29_worst_wins_binds_every_availability_word() {
    // P2fix4 GATE29 (+ P2fix6 NEW-37 shape tightening): EVERY
    // availability word binds to the producer's worst-wins rule
    // over the activity rows — not just positive `covered`
    // claims. not_attached over clean rows, partial over clean
    // rows, covered over partial rows, and unrankable rows all
    // reject, identically at every gate; exact worst-wins
    // matches (covered/partial/not_attached) accept.
    // [p2fix6 NEW-37: rows carry the COMPLETE shape with one row
    // per api (duplicates reject — pinned in
    // `new37_duplicate_coverage_inputs_reject_everywhere`); the
    // old multi-row-per-api worst-wins input is retired.]
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let k2 = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 501,
        invocation: 101,
    };
    p.attempt(t::AttemptEdge {
        key: k2,
        api: 21,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k2,
        api: 21,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    // Availability: 20 covered, 21 partial, rest not_attached.
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 {
                "covered"
            } else if id == 21 {
                "partial_coverage"
            } else {
                "not_attached"
            }
            .to_string(),
        );
    }
    let good = t::summarize(&window, &totals, "latency", Some(&avail));
    good.validate().expect("mixed seal passes");
    // [p2fix6 NEW-37: complete-shape rows, one per api.]
    let row = |api: u32, not_attached: bool, attachment: bool, finality: bool| {
        serde_json::json!({
            "api": api, "entries": 1,
            "observed_success": 1, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {
                "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                "unsupported_return": 0, "saturated": false,
                "not_attached": not_attached, "attachment": attachment, "finality": finality,
            },
        })
    };
    // Worst-wins-exact rows: 20 clean (covered), 21 attachment
    // (partial), 22+ rowless (not_attached).
    let rows = serde_json::json!([row(20, false, false, false), row(21, false, true, false),]);
    for shape in ["producer", "doc_json"] {
        let shell = |section: &serde_json::Value, activity: &serde_json::Value| {
            let mut d = if shape == "producer" {
                let mut d = snapshot::test_document(3, "complete");
                d["schema"] = serde_json::json!("observed-crypto-v2.9");
                d
            } else {
                let mut d = doc_json_shell();
                d["schema_version"] = serde_json::json!("observed-crypto-v2.9");
                d
            };
            d["trace_summary"] = section.clone();
            d["api_activity"] = activity.clone();
            d
        };
        let read = |d: &serde_json::Value| {
            if shape == "producer" {
                snapshot::signals_from_producer(d).is_some()
            } else {
                snapshot::signals_from_doc_json(d).is_some()
            }
        };
        let good_json = serde_json::to_value(&good).unwrap();
        assert!(
            read(&shell(&good_json, &rows)),
            "{shape} passes worst-wins-exact"
        );
        // not_attached claimed over clean rows (API 20 clean row
        // present, word flipped to not_attached).
        let mut flip20 = good_json.clone();
        flip20["by_api_availability"]["20"] = serde_json::json!("not_attached");
        flip20["by_api"].as_object_mut().unwrap().remove("20");
        assert!(
            !read(&shell(&flip20, &rows)),
            "{shape} rejects not_attached over clean rows"
        );
        // partial claimed over all-clean rows (API 20 word
        // flipped to partial, entry dropped so intake
        // validation passes and the CONTRACT decides).
        let mut part20 = good_json.clone();
        part20["by_api_availability"]["20"] = serde_json::json!("partial_coverage");
        part20["by_api"].as_object_mut().unwrap().remove("20");
        assert!(
            !read(&shell(&part20, &rows)),
            "{shape} rejects partial over clean rows"
        );
        // covered claimed over partial rows (API 21 word flipped
        // to covered with a cloned entry so intake validation
        // passes and the CONTRACT decides).
        let mut cov21 = good_json.clone();
        cov21["by_api_availability"]["21"] = serde_json::json!("covered");
        let e20 = cov21["by_api"]["20"].clone();
        cov21["by_api"]["21"] = e20;
        assert!(
            !read(&shell(&cov21, &rows)),
            "{shape} rejects covered over partial rows"
        );
        // Unrankable row (gaps missing) rejects.
        let badrows = serde_json::json!([{"api": 20, "entries": 1}]);
        assert!(
            !read(&shell(&good_json, &badrows)),
            "{shape} rejects unrankable rows"
        );
    }
}

/// Complete-shape activity row (P2fix6 NEW-37 — the raw
/// schema's required keys with exact types).
fn new37_complete_row(
    api: u32,
    not_attached: bool,
    attachment: bool,
    finality: bool,
) -> serde_json::Value {
    serde_json::json!({
        "api": api, "entries": 1,
        "observed_success": 1, "observed_failure": 0,
        "verification_mismatch": 0, "unsupported": 0,
        "gaps": {
            "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
            "unsupported_return": 0, "saturated": false,
            "not_attached": not_attached, "attachment": attachment, "finality": finality,
        },
    })
}

/// Minimal activity row (P2fix6 NEW-37 — the reported shape: API
/// + the three ranking flags only, violating the raw row
/// schema).
fn new37_minimal_row(
    api: u32,
    not_attached: bool,
    attachment: bool,
    finality: bool,
) -> serde_json::Value {
    serde_json::json!({
        "api": api, "entries": 1,
        "gaps": {"not_attached": not_attached, "attachment": attachment, "finality": finality},
    })
}

/// Covered-20 latency seal JSON (P2fix6 NEW-37 — mirrors the
/// gate29/new27 seal for the everywhere pins).
fn new37_covered20_seal() -> serde_json::Value {
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 { "covered" } else { "not_attached" }.to_string(),
        );
    }
    let good = t::summarize(&window, &totals, "latency", Some(&avail));
    good.validate().expect("covered seal passes");
    serde_json::to_value(&good).unwrap()
}

/// Full v2 document text carrying a trace section + activity
/// rows (P2fix6 NEW-37 raw-intake gate).
fn new37_doc_text(section: &serde_json::Value, activity: &serde_json::Value) -> String {
    use osslscope::provider_observation::trace as t;
    let good: t::TraceSummary = serde_json::from_value(section.clone()).unwrap();
    let mut doc = osslscope::capture::empty_document();
    osslscope::evidence::stamp_trace_summary(&mut doc, good);
    let mut text_value: serde_json::Value =
        serde_json::from_slice(&osslscope::report::render_json(&doc).expect("renders")).unwrap();
    text_value["api_activity"] = activity.clone();
    serde_json::to_string(&text_value).unwrap()
}

#[test]
fn new37_incomplete_rows_reject_everywhere() {
    // P2fix6 NEW-37: a row containing only API + the three
    // ranking flags rejects on EVERY reader (raw intake, both
    // presenter inputs, restored checkpoints) — API+flags alone
    // is insufficient everywhere, identically. Pre-fix: the
    // presenter reconciles the minimal row while raw intake
    // rejects it. Complete rows pass all four (controls).
    use osslscope::presentation::snapshot;
    let good_json = new37_covered20_seal();
    let complete = serde_json::json!([new37_complete_row(20, false, false, false)]);
    let minimal = serde_json::json!([new37_minimal_row(20, false, false, false)]);
    // Gate 1 — raw intake.
    osslscope::schema::check_v2_document_text(&new37_doc_text(&good_json, &complete))
        .expect("raw passes complete rows");
    assert!(
        osslscope::schema::check_v2_document_text(&new37_doc_text(&good_json, &minimal)).is_err(),
        "raw rejects minimal rows"
    );
    // Gates 2+3 — presenter inputs.
    for shape in ["producer", "doc_json"] {
        assert!(
            new27_read(shape, &new27_shell(shape, &good_json, Some(&complete))),
            "{shape} passes complete rows"
        );
        assert!(
            !new27_read(shape, &new27_shell(shape, &good_json, Some(&minimal))),
            "{shape} rejects minimal rows"
        );
    }
    // Gate 4 — restored checkpoint.
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new37-incomplete-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = good_json;
    pdoc["api_activity"] = complete;
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes complete rows");
    let body = std::fs::read(&ckpt).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["accumulators"]["latest"]["api_activity"] = minimal;
    v.as_object_mut().unwrap().remove("sha256");
    let bytes = serde_json::to_vec(&v).unwrap();
    let hash = snapshot::sha256_hex(&bytes);
    v.as_object_mut()
        .unwrap()
        .insert("sha256".to_string(), serde_json::json!(hash));
    std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore rejects minimal rows"
    );
}

#[test]
fn new37_duplicate_coverage_inputs_reject_everywhere() {
    // P2fix6 NEW-37: duplicate coverage inputs (two complete rows
    // for one api with different flags) reject on EVERY reader —
    // availability-driving duplicates are never silently
    // normalized. Pre-fix: the presenter worst-wins them while
    // raw intake rejects. Single rows pass all four (controls).
    // The seal claims WORST-WINS-EXACT words (api 20 partial —
    // the worst of the duplicate pair), so ONLY the duplicate
    // rule convicts (a word mismatch must not share the blame).
    use osslscope::presentation::snapshot;
    let good_json = new37_covered20_seal();
    let single = serde_json::json!([new37_complete_row(20, false, false, false)]);
    let mut partial_json = good_json.clone();
    partial_json["by_api_availability"]["20"] = serde_json::json!("partial_coverage");
    partial_json["by_api"].as_object_mut().unwrap().remove("20");
    let dupes = serde_json::json!([
        new37_complete_row(20, false, false, false),
        new37_complete_row(20, false, true, false),
    ]);
    // Gate 1 — raw intake.
    osslscope::schema::check_v2_document_text(&new37_doc_text(&good_json, &single))
        .expect("raw passes single rows");
    assert!(
        osslscope::schema::check_v2_document_text(&new37_doc_text(&partial_json, &dupes)).is_err(),
        "raw rejects duplicate coverage inputs"
    );
    // Gates 2+3 — presenter inputs.
    for shape in ["producer", "doc_json"] {
        assert!(
            new27_read(shape, &new27_shell(shape, &good_json, Some(&single))),
            "{shape} passes single rows"
        );
        assert!(
            !new27_read(shape, &new27_shell(shape, &partial_json, Some(&dupes))),
            "{shape} rejects duplicate coverage inputs"
        );
    }
    // Gate 4 — restored checkpoint (fold the partial claim over
    // one attachment row, then tamper rows-only to the
    // worst-wins-identical duplicate pair — only the duplicate
    // rule can convict).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new37-dupe-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = partial_json;
    pdoc["api_activity"] = serde_json::json!([new37_complete_row(20, false, true, false)]);
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes single rows");
    let body = std::fs::read(&ckpt).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["accumulators"]["latest"]["api_activity"] = dupes;
    v.as_object_mut().unwrap().remove("sha256");
    let bytes = serde_json::to_vec(&v).unwrap();
    let hash = snapshot::sha256_hex(&bytes);
    v.as_object_mut()
        .unwrap()
        .insert("sha256".to_string(), serde_json::json!(hash));
    std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore rejects duplicate coverage inputs"
    );
}

#[test]
fn new37_canonical_exemplar_spelling() {
    // P2fix6 NEW-37: exemplar hashes spell canonical lowercase on
    // EVERY reader (the raw `^[0-9a-f]{16}$`) — uppercase hex
    // rejects at the typed reader and at raw intake alike.
    // Pre-fix: the typed reader admits uppercase the raw gate
    // excludes. Lowercase passes both (controls).
    use osslscope::provider_observation::trace as t;
    let good_json = new37_covered20_seal();
    let with_exemplar = |hash: &str| {
        let mut section = good_json.clone();
        section["window"]["exemplars"] = serde_json::json!([
            {"dir": "entry", "key_hash16": hash, "api": 20, "age_ns": 100},
        ]);
        section
    };
    // Typed reader.
    let lower: t::TraceSummary = serde_json::from_value(with_exemplar("814dd7b9784d57c1")).unwrap();
    lower.validate().expect("typed passes lowercase");
    let upper: t::TraceSummary = serde_json::from_value(with_exemplar("814DD7B9784D57C1")).unwrap();
    assert!(upper.validate().is_err(), "typed rejects uppercase hex");
    // Raw intake.
    let rows = serde_json::json!([new37_complete_row(20, false, false, false)]);
    osslscope::schema::check_v2_document_text(&new37_doc_text(
        &with_exemplar("814dd7b9784d57c1"),
        &rows,
    ))
    .expect("raw passes lowercase");
    assert!(
        osslscope::schema::check_v2_document_text(&new37_doc_text(
            &with_exemplar("814DD7B9784D57C1"),
            &rows,
        ))
        .is_err(),
        "raw rejects uppercase hex"
    );
}

/// Certain latency seal WITHOUT the by-api opt-in (P2fix7
/// NEW-42 — no `by_api`/`by_api_availability`: the typed gate
/// must still validate supplied activity rows).
fn new42_plain_seal() -> serde_json::Value {
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let plain = t::summarize(&window, &totals, "latency", None);
    plain.validate().expect("plain seal passes");
    let json = serde_json::to_value(&plain).unwrap();
    assert!(
        json.get("by_api_availability").is_none(),
        "premise: no availability opt-in"
    );
    json
}

#[test]
fn new42_rows_validate_without_availability_everywhere() {
    // P2fix7 NEW-42: complete row validation applies to supplied
    // v2.9 trace evidence even with the by-api opt-in DISABLED
    // (no availability-absent skip) on EVERY reader (raw intake,
    // both presenter inputs, restored checkpoints). Pre-fix: the
    // typed gate skips activity shape entirely without an
    // availability map, so malformed rows project. Complete rows
    // pass all four (controls).
    use osslscope::presentation::snapshot;
    let plain = new42_plain_seal();
    let complete = serde_json::json!([new37_complete_row(20, false, false, false)]);
    let bads: Vec<(&str, serde_json::Value)> = vec![
        (
            "minimal",
            serde_json::json!([new37_minimal_row(20, false, false, false)]),
        ),
        (
            "dup-api",
            serde_json::json!([
                new37_complete_row(20, false, false, false),
                new37_complete_row(20, false, true, false),
            ]),
        ),
        (
            "out-of-range",
            serde_json::json!([new37_complete_row(19, false, false, false)]),
        ),
        (
            "bad-gaps-type",
            serde_json::json!([{
                "api": 20, "entries": 1,
                "observed_success": 1, "observed_failure": 0,
                "verification_mismatch": 0, "unsupported": 0,
                "gaps": {
                    "map": "0", "depth": 0, "unpaired": 0, "tail": 0,
                    "unsupported_return": 0, "saturated": false,
                    "not_attached": false, "attachment": false, "finality": false,
                },
            }]),
        ),
        ("non-array", serde_json::json!({"api": 20})),
        (
            "unknown-field",
            serde_json::json!([{
                "api": 20, "entries": 1,
                "observed_success": 1, "observed_failure": 0,
                "verification_mismatch": 0, "unsupported": 0,
                "bogus": 1,
                "gaps": {
                    "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                    "unsupported_return": 0, "saturated": false,
                    "not_attached": false, "attachment": false, "finality": false,
                },
            }]),
        ),
    ];
    // Gate 1 — raw intake.
    osslscope::schema::check_v2_document_text(&new37_doc_text(&plain, &complete))
        .expect("raw passes complete rows without availability");
    for (what, bad) in &bads {
        assert!(
            osslscope::schema::check_v2_document_text(&new37_doc_text(&plain, bad)).is_err(),
            "raw rejects {what} rows without availability"
        );
    }
    // Gates 2+3 — presenter inputs.
    for shape in ["producer", "doc_json"] {
        assert!(
            new27_read(shape, &new27_shell(shape, &plain, Some(&complete))),
            "{shape} passes complete rows without availability"
        );
        for (what, bad) in &bads {
            assert!(
                !new27_read(shape, &new27_shell(shape, &plain, Some(bad))),
                "{shape} rejects {what} rows without availability"
            );
        }
    }
    // Gate 4 — restored checkpoint (tamper rows-only to minimal,
    // then to the duplicate pair — both must convict).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new42-noavail-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = plain;
    pdoc["api_activity"] = complete;
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes complete rows without availability");
    for (what, bad) in &bads[..2] {
        let body = std::fs::read(&ckpt).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["accumulators"]["latest"]["api_activity"] = bad.clone();
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hash = snapshot::sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hash));
        std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(
            snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
            "restore rejects {what} rows without availability"
        );
    }
}

#[test]
fn new42_api_activity_raw_duplicates_reject() {
    // P2fix7 NEW-42 (+ NEW-37-OPEN): duplicate RAW JSON members
    // across the coverage inputs reject BEFORE Value
    // normalization — within one activity row, within its nested
    // gaps, and a repeated top-level `api_activity` member. Each
    // bad text last-wins to a typed-valid shape, so ONLY the raw
    // check convicts (Value-constructed rows cannot exercise
    // this). Pre-fix: raw document intake accepts all three.
    // Presenter BYTES paths (window envelopes, checkpoint files)
    // already reject whole-tree (controls — pinned, not fixed).
    use osslscope::presentation::snapshot;
    let good_json = new37_covered20_seal();
    let single = serde_json::json!([new37_complete_row(20, false, false, false)]);
    let clean = new37_doc_text(&good_json, &single);
    osslscope::schema::check_v2_document_text(&clean).expect("raw passes the clean text");
    assert_eq!(
        clean.matches("\"api_activity\"").count(),
        1,
        "premise: exactly one api_activity member to splice"
    );
    let splice = |text: &str, anchor: &str, insert: &str| {
        let at = text.find(anchor).expect("premise: anchor present");
        let mut out = text.to_string();
        out.insert_str(at + anchor.len(), insert);
        out
    };
    // Duplicate member inside one row (last-wins to api 20 —
    // typed-valid, only the raw check convicts).
    let rowdup = splice(&clean, "\"api_activity\":[{", "\"api\":99,");
    // Duplicate member inside the row's nested gaps (last-wins to
    // map 0 — typed-valid, only the raw check convicts): the
    // FIRST gaps block after the activity array opens.
    let act_at = clean
        .find("\"api_activity\":[")
        .expect("premise: activity array");
    let gaps_rel = clean[act_at..]
        .find("\"gaps\":{")
        .expect("premise: row gaps block");
    let mut gapsdup = clean.clone();
    gapsdup.insert_str(act_at + gaps_rel + "\"gaps\":{".len(), "\"map\":7,");
    // Repeated top-level section (last-wins to the same valid
    // rows — typed-valid, only the raw check convicts).
    let single_text = serde_json::to_string(&single).unwrap();
    let sectiondup = format!(
        "{},\"api_activity\":{}}}",
        clean
            .trim_end()
            .strip_suffix('}')
            .expect("premise: doc ends with }"),
        single_text
    );
    for (what, bad) in [
        ("row-member", rowdup),
        ("gaps-member", gapsdup),
        ("section", sectiondup),
    ] {
        // Premise: still valid JSON, last-wins to a typed-valid
        // shape (serde parses; the typed gate alone would pass).
        let v: serde_json::Value = serde_json::from_str(&bad)
            .unwrap_or_else(|e| panic!("premise: {what} stays valid JSON: {e}"));
        assert_eq!(
            v.get("api_activity"),
            Some(&single),
            "premise: {what} last-wins to the valid rows"
        );
        assert!(
            osslscope::schema::check_v2_document_text(&bad).is_err(),
            "raw intake rejects duplicate {what}"
        );
    }
    // Presenter BYTES controls: the same duplicate members inside
    // a window envelope / checkpoint file already reject
    // whole-tree (pre-fix green — coverage proof, not the fix).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new42-rawdup-bytes");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = good_json;
    pdoc["api_activity"] = single;
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    let env_text = serde_json::to_string(&env).unwrap();
    assert_eq!(
        env_text.matches("\"api_activity\"").count(),
        1,
        "premise: exactly one envelope api_activity member to splice"
    );
    let env_dup = splice(&env_text, "\"api_activity\":[{", "\"api\":99,");
    std::fs::write(dir.join("window-0000000000.json"), &env_dup).unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("premise: open succeeds before the fold");
    assert!(
        p.build_service().is_err(),
        "envelope fold rejects duplicate raw members"
    );
}

/// Valid certain latency seal (API 20 covered, rest not_attached)
/// + worst-wins-exact rows (P2fix5 NEW-27 baseline for the
/// shape-agreement pins).
fn new27_baseline() -> (serde_json::Value, serde_json::Value) {
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 { "covered" } else { "not_attached" }.to_string(),
        );
    }
    let good = t::summarize(&window, &totals, "latency", Some(&avail));
    good.validate().expect("covered seal passes");
    // [p2fix6 NEW-37: the baseline row carries the COMPLETE
    // activity-row shape (API+flags alone now rejects).]
    let rows = serde_json::json!([{
        "api": 20, "entries": 1,
        "observed_success": 1, "observed_failure": 0,
        "verification_mismatch": 0, "unsupported": 0,
        "gaps": {
            "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
            "unsupported_return": 0, "saturated": false,
            "not_attached": false, "attachment": false, "finality": false,
        },
    }]);
    (serde_json::to_value(&good).unwrap(), rows)
}

fn new27_shell(
    shape: &str,
    section: &serde_json::Value,
    activity: Option<&serde_json::Value>,
) -> serde_json::Value {
    use osslscope::presentation::snapshot;
    let mut d = if shape == "producer" {
        let mut d = snapshot::test_document(3, "complete");
        d["schema"] = serde_json::json!("observed-crypto-v2.9");
        d
    } else {
        let mut d = doc_json_shell();
        d["schema_version"] = serde_json::json!("observed-crypto-v2.9");
        d
    };
    d["trace_summary"] = section.clone();
    match activity {
        Some(a) => d["api_activity"] = a.clone(),
        None => {
            d.as_object_mut().unwrap().remove("api_activity");
        }
    }
    d
}

fn new27_read(shape: &str, d: &serde_json::Value) -> bool {
    use osslscope::presentation::snapshot;
    if shape == "producer" {
        snapshot::signals_from_producer(d).is_some()
    } else {
        snapshot::signals_from_doc_json(d).is_some()
    }
}

#[test]
fn new27_extra_properties_reject_at_every_typed_reader() {
    // P2fix5 NEW-27: ONE pre-normalization trace shape — the typed
    // readers enforce the raw schema's closed shape (extra
    // properties reject, never discard) at both presenter inputs
    // (pre-fix: serde ignores unknown fields, so the raw gate
    // rejects what the typed readers accept). The restore twin
    // rides `new27_checkpoint_tamper_rejects`.
    let (good_json, rows) = new27_baseline();
    for shape in ["producer", "doc_json"] {
        assert!(
            new27_read(shape, &new27_shell(shape, &good_json, Some(&rows))),
            "{shape} passes the baseline"
        );
        for (what, mut section) in [
            ("top", good_json.clone()),
            ("window", good_json.clone()),
            ("distribution", good_json.clone()),
            ("by-api-entry", good_json.clone()),
        ] {
            match what {
                "top" => section["bogus_extra"] = serde_json::json!(1),
                "window" => section["window"]["bogus_extra"] = serde_json::json!(1),
                "distribution" => {
                    section["histograms"]["success"]["bogus_extra"] = serde_json::json!(1);
                }
                _ => section["by_api"]["20"]["success"]["bogus_extra"] = serde_json::json!(1),
            }
            assert!(
                !new27_read(shape, &new27_shell(shape, &section, Some(&rows))),
                "{shape} rejects extra property ({what})"
            );
        }
    }
}

#[test]
fn new27_malformed_activity_rows_reject() {
    // P2fix5 NEW-27 (+ P2fix6 NEW-37 shape tightening): complete
    // row validation on every path — a PRESENT-but-malformed
    // activity collection rejects (never read-as-absent), EVERY
    // row carries the complete raw-schema shape with its api in
    // 20..=72 and no duplicate apis (no skips, no
    // short-circuit), on both presenter inputs. Pre-fix: non-array
    // collections read absent, malformed rows skip, and
    // not_attached short-circuits its sibling flags.
    // [p2fix6 NEW-37: API+flags-only rows, out-of-range apis, and
    // duplicate apis now reject on every reader (same
    // pre-normalization rules as raw intake) — the old
    // tolerate-foreign control is inverted below.]
    let (good_json, rows) = new27_baseline();
    let poisoned = |extra: serde_json::Value| {
        let mut all = rows.as_array().unwrap().clone();
        all.push(extra);
        serde_json::Value::Array(all)
    };
    // All-not_attached twin (no covered claims — consistent with
    // rowless evidence): empty L1 + dense not_attached words.
    let mut bare_json = good_json.clone();
    bare_json["by_api"] = serde_json::json!({});
    let mut bare_avail = serde_json::Map::new();
    for id in 20..=72u32 {
        bare_avail.insert(id.to_string(), serde_json::json!("not_attached"));
    }
    bare_json["by_api_availability"] = serde_json::Value::Object(bare_avail);
    for shape in ["producer", "doc_json"] {
        assert!(
            new27_read(shape, &new27_shell(shape, &good_json, Some(&rows))),
            "{shape} passes the baseline"
        );
        assert!(
            new27_read(
                shape,
                &new27_shell(shape, &bare_json, Some(&serde_json::json!([])))
            ),
            "{shape} passes rowless not_attached"
        );
        // Absent activity reads rowless (conservative — claims
        // nothing covered) on the not_attached twin (control).
        assert!(
            new27_read(shape, &new27_shell(shape, &bare_json, None)),
            "{shape} reads absent activity as rowless"
        );
        // Well-formed out-of-range row REJECTS (the api range
        // binds like every other reader — [p2fix6 NEW-37]).
        let foreign = serde_json::json!({
            "api": 10, "entries": 1,
            "observed_success": 1, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {
                "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                "unsupported_return": 0, "saturated": false,
                "not_attached": true, "attachment": false, "finality": false,
            },
        });
        assert!(
            !new27_read(
                shape,
                &new27_shell(shape, &good_json, Some(&poisoned(foreign)))
            ),
            "{shape} rejects out-of-range rows"
        );
        // PRESENT-but-malformed collections reject (never
        // read-as-absent).
        for (what, activity) in [
            ("object", serde_json::json!({"x": 1})),
            ("number", serde_json::json!(42)),
            ("string", serde_json::json!("nope")),
        ] {
            assert!(
                !new27_read(shape, &new27_shell(shape, &bare_json, Some(&activity))),
                "{shape} rejects non-array activity ({what})"
            );
        }
        // Malformed rows reject (each added beside the valid
        // baseline row, so only row validation can convict).
        for (what, extra) in [
            (
                "string-api",
                serde_json::json!({
                    "api": "20", "entries": 1,
                    "gaps": {"not_attached": true, "attachment": false, "finality": false},
                }),
            ),
            (
                "missing-api",
                serde_json::json!({
                    "entries": 1,
                    "gaps": {"not_attached": true, "attachment": false, "finality": false},
                }),
            ),
            (
                "short-circuit-flag",
                serde_json::json!({
                    "api": 22, "entries": 1,
                    "gaps": {"not_attached": true, "attachment": "bogus", "finality": false},
                }),
            ),
            (
                "malformed-foreign",
                serde_json::json!({
                    "api": 10, "entries": 1,
                    "gaps": {"not_attached": true, "attachment": false},
                }),
            ),
        ] {
            assert!(
                !new27_read(
                    shape,
                    &new27_shell(shape, &good_json, Some(&poisoned(extra)))
                ),
                "{shape} rejects malformed row ({what})"
            );
        }
        // Non-object elements reject.
        let mut mixed = rows.as_array().unwrap().clone();
        mixed.push(serde_json::json!(42));
        assert!(
            !new27_read(
                shape,
                &new27_shell(shape, &good_json, Some(&serde_json::Value::Array(mixed)))
            ),
            "{shape} rejects non-object rows"
        );
    }
}

#[test]
fn new27_checkpoint_tamper_rejects() {
    // P2fix5 NEW-27: the restore reader enforces the SAME
    // pre-normalization trace shape — a hash-valid checkpoint
    // carrying an extra trace property refuses (typed readers
    // deny unknown fields instead of discarding), and a
    // hash-valid checkpoint carrying a duplicate member refuses
    // (raw duplicates reject before normalization erases them).
    // Pre-fix: extras discard and dups collapse, so both tampers
    // restore cleanly.
    use osslscope::presentation::snapshot;
    let dir = out_dir("new27-tamper");
    let (good_json, rows) = new27_baseline();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = good_json;
    doc["api_activity"] = rows;
    let env = snapshot::test_envelope_with_doc(0, 0, run, doc);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
            .expect("premise: valid trace folds");
        p.build_service().expect("premise: valid trace checkpoints");
    }
    // Splice + rehash: textual tamper, then a self-consistent
    // content hash (mirrors the writer: sha over the bare body).
    // A broken rehash would torn-replay (Ok) instead of refusing,
    // so post-fix GREEN itself proves the hash is self-consistent.
    let rehash = |text: &str| {
        let v: serde_json::Value = serde_json::from_str(text).expect("tampered text parses");
        let old = v["sha256"].as_str().unwrap().to_string();
        let mut bare = v.clone();
        bare.as_object_mut().unwrap().remove("sha256");
        let new = snapshot::sha256_hex(&serde_json::to_vec(&bare).unwrap());
        text.replacen(
            &format!("\"sha256\":\"{old}\""),
            &format!("\"sha256\":\"{new}\""),
            1,
        )
    };
    let file = std::fs::read_to_string(&ckpt).unwrap();
    // Tamper 1: extra property inside the stored trace object.
    assert_eq!(
        file.match_indices("\"trace\":{").count(),
        1,
        "premise: one stored trace object to splice"
    );
    let extra = file.replacen("\"trace\":{", "\"trace\":{\"bogus_extra\":1,", 1);
    std::fs::write(&ckpt, rehash(&extra)).unwrap();
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore refuses the extra trace property"
    );
    // Tamper 2: duplicated member (collapse-before-validation
    // would erase it — the FIRST calls_total occurrence doubles).
    let at = file
        .find("\"calls_total\":")
        .expect("premise: calls_total stored");
    let rest = &file[at..];
    let digits: usize = rest["\"calls_total\":".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .count();
    assert!(digits > 0, "premise: numeric calls_total");
    let mut dup = file.clone();
    let pair = file[at..at + "\"calls_total\":".len() + digits].to_string();
    dup.insert_str(at + pair.len(), &format!(",{pair}"));
    std::fs::write(&ckpt, rehash(&dup)).unwrap();
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore refuses the duplicated member"
    );
    // Control: the untampered checkpoint restores.
    std::fs::write(&ckpt, &file).unwrap();
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("untampered checkpoint restores");
}

#[test]
fn new19_required_nullable_presence_and_null_rules_across_all_gates() {
    // P2fix4 NEW-19 + GATE29: identical presence + null rules at
    // all four gates (raw intake, both presenter inputs, restored
    // checkpoints). Required-nullable fields (class_epoch,
    // window.class_window) must be EXPLICITLY present (absent
    // rejects — it must not collapse to withheld-None); explicit
    // null for non-nullable optionals (histograms, by_api,
    // by_api_availability) rejects; explicit-null
    // class_epoch/class_window on an uncertain shape accepts.
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    // Certain seal with the by-api opt-in (API 20 covered).
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if id == 20 { "covered" } else { "not_attached" }.to_string(),
        );
    }
    let good = t::summarize(&window, &totals, "latency", Some(&avail));
    good.validate().expect("covered seal passes");
    // [p2fix6 NEW-37: the supporting row carries the COMPLETE
    // activity-row shape (API+flags alone now rejects).]
    let rows = serde_json::json!([{
        "api": 20, "entries": 1,
        "observed_success": 1, "observed_failure": 0,
        "verification_mismatch": 0, "unsupported": 0,
        "gaps": {
            "map": 0, "depth": 0, "unpaired": 0, "tail": 0,
            "unsupported_return": 0, "saturated": false,
            "not_attached": false, "attachment": false, "finality": false,
        },
    }]);
    // Uncertain seal (explicit-null classes — the ACCEPT shape).
    let mut q = t::TraceProducer::new();
    q.set_mode(t::TRACE_MODE_LATENCY);
    let kq = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 501,
        invocation: 100,
    };
    q.attempt(t::AttemptEdge {
        key: kq,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    q.result(t::ResultEdge {
        key: kq,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    q.reject_unknown();
    let qw = q.close_window(0, 9000, [0; 8]);
    let qt = q.totals();
    let uncertain = t::summarize(&qw, &qt, "latency", None);
    uncertain.validate().expect("uncertain seal passes");
    assert!(uncertain.class_epoch.is_none() && uncertain.window.class_window.is_none());
    let uval = serde_json::to_value(&uncertain).unwrap();
    assert!(uval.get("class_epoch").is_some() && uval["class_epoch"].is_null());
    assert!(
        uval["window"].get("class_window").is_some() && uval["window"]["class_window"].is_null()
    );
    // Shape mutators over the certain seal JSON.
    let good_json = serde_json::to_value(&good).unwrap();
    let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good_json.clone();
        f(&mut v);
        v
    };
    // Gate 2+3 — presenter inputs.
    for shape in ["producer", "doc_json"] {
        let shell = |section: &serde_json::Value| {
            let mut d = if shape == "producer" {
                let mut d = snapshot::test_document(3, "complete");
                d["schema"] = serde_json::json!("observed-crypto-v2.9");
                d
            } else {
                let mut d = doc_json_shell();
                d["schema_version"] = serde_json::json!("observed-crypto-v2.9");
                d
            };
            d["trace_summary"] = section.clone();
            d["api_activity"] = rows.clone();
            d
        };
        let read = |d: &serde_json::Value| {
            if shape == "producer" {
                snapshot::signals_from_producer(d).is_some()
            } else {
                snapshot::signals_from_doc_json(d).is_some()
            }
        };
        assert!(read(&shell(&good_json)), "{shape} passes the seal");
        assert!(read(&shell(&uval)), "{shape} passes explicit-null classes");
        // Absent classes ride the UNCERTAIN seal (the NEW-19
        // shape: absent must not collapse to withheld-None).
        let mutate_u = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = uval.clone();
            f(&mut v);
            v
        };
        let absent_epoch = mutate_u(&|v| {
            v.as_object_mut().unwrap().remove("class_epoch");
        });
        assert!(
            !read(&shell(&absent_epoch)),
            "{shape} rejects absent class_epoch"
        );
        let absent_window = mutate_u(&|v| {
            v["window"].as_object_mut().unwrap().remove("class_window");
        });
        assert!(
            !read(&shell(&absent_window)),
            "{shape} rejects absent window.class_window"
        );
        let null_hist = mutate(&|v| {
            v["histograms"] = serde_json::Value::Null;
        });
        // Certain + histograms null: raw rejects (no null
        // variant); typed gates must agree (pre-fix: the
        // latency-without-histograms arm rejects this one
        // already — kept as the null-rule witness).
        assert!(!read(&shell(&null_hist)), "{shape} rejects null histograms");
        let null_by_api = mutate(&|v| {
            v["by_api"] = serde_json::Value::Null;
            v["by_api_availability"] = serde_json::Value::Null;
        });
        assert!(
            !read(&shell(&null_by_api)),
            "{shape} rejects null by_api pair"
        );
    }
    // Gate 4 — restored checkpoint (tampered presence/null
    // refuses the restore; the explicit-null uncertain shape
    // restores).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new19-restore");
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&good).unwrap();
    pdoc["api_activity"] = rows.clone();
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes the seal");
    let retamper = |f: &dyn Fn(&mut serde_json::Value)| {
        let body = std::fs::read(&ckpt).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        f(&mut v);
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hash = snapshot::sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hash));
        std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    // Absent classes ride the UNCERTAIN shape (present-null
    // applies; absent refuses — the preserved distinction).
    retamper(&|v| {
        v["accumulators"]["latest"]["signals"]["trace"] = uval.clone();
        v["accumulators"]["latest"]["signals"]["trace"]
            .as_object_mut()
            .unwrap()
            .remove("class_epoch");
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject absent class_epoch"
    );
    retamper(&|v| {
        // Re-seal a valid trace first (prior tamper persists in
        // the file), then drop window.class_window.
        v["accumulators"]["latest"]["signals"]["trace"] = uval.clone();
        v["accumulators"]["latest"]["signals"]["trace"]["window"]
            .as_object_mut()
            .unwrap()
            .remove("class_window");
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject absent window.class_window"
    );
    retamper(&|v| {
        v["accumulators"]["latest"]["signals"]["trace"] = good_json.clone();
        v["accumulators"]["latest"]["signals"]["trace"]["by_api"] = serde_json::Value::Null;
        v["accumulators"]["latest"]["signals"]["trace"]["by_api_availability"] =
            serde_json::Value::Null;
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restore must reject null by_api pair"
    );
    // The explicit-null uncertain shape restores (distinction
    // preserved: present-null applies, absent refuses).
    retamper(&|v| {
        v["accumulators"]["latest"]["signals"]["trace"] = uval.clone();
        v["accumulators"]["latest"]["api_activity"] = serde_json::json!([]);
    });
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("restore passes explicit-null classes");
}

#[test]
fn new10_fallback_operational_exemplar_rejects_at_public_intake() {
    // P2fix3 NEW-10: a fallback record carrying an operational
    // exemplar ID rejects through PUBLIC watch + export intake
    // (both presenter readers, oneshot, the fold seam, and the
    // real watch binary) — never projects.
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_METADATA);
    p.set_fallback(true);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    p.attempt(t::AttemptEdge {
        key: k,
        api: 10,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    p.result(t::ResultEdge {
        key: k,
        api: 10,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut bad = t::summarize(&window, &totals, "metadata", None);
    bad.validate().expect("fallback seal passes");
    bad.window.exemplars = vec![t::TraceExemplarJson {
        dir: "entry".to_string(),
        key_hash16: "814dd7b9784d57c1".to_string(),
        api: 20,
        age_ns: 5,
    }];
    assert!(bad.validate().is_err(), "operational exemplar rejects");
    // Both presenter readers.
    let mut pdoc = snapshot::test_document(3, "complete");
    pdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    pdoc["trace_summary"] = serde_json::to_value(&bad).unwrap();
    assert!(
        snapshot::signals_from_producer(&pdoc).is_none(),
        "producer intake rejects"
    );
    let mut dj = doc_json_shell();
    dj["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    dj["trace_summary"] = serde_json::to_value(&bad).unwrap();
    assert!(
        snapshot::signals_from_doc_json(&dj).is_none(),
        "doc_json intake rejects"
    );
    // Oneshot + the export fold seam.
    assert!(
        snapshot::Presenter::oneshot(&pdoc).is_err(),
        "oneshot rejects"
    );
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new10-intake");
    let env = snapshot::test_envelope_with_doc(0, 0, run, pdoc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        assert!(
            p.build_service().is_err(),
            "export intake (build_service) rejects"
        );
    }
    // The real watch binary refuses the bad window (exit 1, never
    // a frame).
    let wckpt = format!("{}-w.checkpoint.json", dir.display());
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "watch",
            "--out",
            dir.to_str().unwrap(),
            "--checkpoint",
            &wckpt,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "watch must refuse");
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "no frame on rejection"
    );
    // P2fix4 NEW-17/DELTA-7 positive: a fallback record carrying
    // an EXPANDED-FETCH exemplar (73) is legitimate producer
    // output and ACCEPTS through both presenter readers +
    // oneshot (pre-fix: rejected — the DELTA-7 regression).
    let mut good = t::summarize(&window, &totals, "metadata", None);
    good.window.exemplars = vec![t::TraceExemplarJson {
        dir: "entry".to_string(),
        key_hash16: "814dd7b9784d57c1".to_string(),
        api: 73,
        age_ns: 5,
    }];
    good.validate().expect("expanded-fetch fallback validates");
    let mut gdoc = snapshot::test_document(3, "complete");
    gdoc["schema"] = serde_json::json!("observed-crypto-v2.9");
    gdoc["trace_summary"] = serde_json::to_value(&good).unwrap();
    assert!(
        snapshot::signals_from_producer(&gdoc).is_some(),
        "producer intake accepts expanded-fetch fallback"
    );
    let mut gdj = doc_json_shell();
    gdj["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    gdj["trace_summary"] = serde_json::to_value(&good).unwrap();
    assert!(
        snapshot::signals_from_doc_json(&gdj).is_some(),
        "doc_json intake accepts expanded-fetch fallback"
    );
    assert!(
        snapshot::Presenter::oneshot(&gdoc).is_ok(),
        "oneshot accepts expanded-fetch fallback"
    );
}

#[test]
fn newp2e_frame_withholds_unbound_paired() {
    // P2fix3 NEW-P2e: the operator frame withholds an unbound
    // window's paired count as evidence (the snapshot retains
    // the scope-marked diagnostic); clean frames show the count.
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    let seal = |cut: u64| {
        let mut p = t::TraceProducer::new();
        p.set_mode(t::TRACE_MODE_LATENCY);
        let k = t::PairKey {
            pid: 7,
            tid: 8,
            generation: 1,
            cookie: 500,
            invocation: 100,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1100,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
        p.note_global_cut(cut);
        let window = p.close_window(0, 9000, [0; 8]);
        let totals = p.totals();
        t::summarize(&window, &totals, "latency", None)
    };
    // Late-cut seal: snapshot marks scope, frame withholds paired.
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(seal(50)).unwrap();
    let snap = snapshot::Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let v: serde_json::Value = serde_json::to_value(&snap).unwrap();
    assert_eq!(v["trace"]["cut_unbound"], true, "scope marked");
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(
        frame.contains("paired=withheld (late-cut)"),
        "frame withholds unbound paired: {frame:?}"
    );
    // Clean seal: count shows, no mark.
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(seal(10_000)).unwrap();
    let snap = snapshot::Presenter::oneshot(&doc).unwrap();
    let v: serde_json::Value = serde_json::to_value(&snap).unwrap();
    assert!(v["trace"].get("cut_unbound").is_none(), "clean unmarked");
    let frame = osslscope::presentation::watch::render_frame(&snap);
    assert!(frame.contains("paired=1"), "clean count shows: {frame:?}");
}

#[test]
fn newp2c_gap_ranges_survive_mid_scan_generation_reset() {
    // P2fix3 NEW-P2c: a retention gap detected mid-scan keeps its
    // flags AND its missing ranges when a later window in the SAME
    // scan adopts a new generation (the reset must not erase the
    // just-detected hole).
    use osslscope::presentation::snapshot;
    use osslscope::provider_observation::trace as t;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("newp2c-ranges");
    for seq in 0..=5u64 {
        let env = snapshot::test_envelope(seq, 0, run.clone(), 10);
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    // Window 7 (gen 0 — retention hole at 6) + window 8 (gen 1 with
    // a real trace seal — resets the epoch mid-scan, AFTER the
    // hole is detected).
    let env7 = snapshot::test_envelope(7, 0, run.clone(), 10);
    std::fs::write(
        dir.join("window-0000000007.json"),
        serde_json::to_string(&env7).unwrap(),
    )
    .unwrap();
    let mut prod = t::TraceProducer::new();
    prod.set_mode(t::TRACE_MODE_LATENCY);
    let k = t::PairKey {
        pid: 7,
        tid: 8,
        generation: 1,
        cookie: 500,
        invocation: 100,
    };
    prod.attempt(t::AttemptEdge {
        key: k,
        api: 20,
        monotonic_ns: 1000,
        start_time_ns: 1,
        seed: 1,
    });
    prod.result(t::ResultEdge {
        key: k,
        api: 20,
        monotonic_ns: 1100,
        outcome: 1,
        start_time_ns: 1,
        seed: 1,
    });
    let w = prod.close_window(0, 9000, [0; 8]);
    let totals = prod.totals();
    let seal = t::summarize(&w, &totals, "latency", None);
    let mut doc8 = snapshot::test_document(10, "complete");
    doc8["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc8["trace_summary"] = serde_json::to_value(&seal).unwrap();
    let env8 = snapshot::test_envelope_with_doc(8, 1, run, doc8);
    std::fs::write(
        dir.join("window-0000000008.json"),
        serde_json::to_string(&env8).unwrap(),
    )
    .unwrap();
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    // The missing range survives (merged hole 6 + folded-but-null
    // 7 — the reset must not erase either).
    let trace = snap.trace.as_ref().expect("trace projects");
    assert_eq!(
        trace.unmeasured_seqs,
        vec![[6u64, 7u64]],
        "missing ranges survive the mid-scan reset"
    );
    // ... and the recovery flags survive with them.
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "recovery flags survive: {:?}",
        snap.unknown
            .iter()
            .map(|e| (&e.path, &e.reason))
            .collect::<Vec<_>>()
    );
}

#[test]
fn newp2c_executable_restart_preserves_admission_exactly() {
    // P2fix3 NEW-P2c: a REAL executable restart (SIGKILL + respawn
    // — the checkpoint is the only bridge) preserves admission +
    // omissions exactly: the post-restart exposition matches the
    // pre-kill one series-for-series (modulo the wall-clock age
    // sample) — no re-admission churn, no omission recount.
    use std::process::Stdio;
    let dir = out_dir("newp2c-exec-restart");
    seed_windows(&dir, 1);
    let ckpt = ckpt_for(&dir);
    let spawn_export = |port: u16| {
        std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args([
                "export",
                "--out",
                dir.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--poll-seconds",
                "1",
                "--checkpoint",
                ckpt.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let strip_age = |t: &str| {
        t.lines()
            .filter(|l| !l.starts_with("osslscope_snapshot_age_nanoseconds "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let port1 = free_port();
    let mut child = spawn_export(port1);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let before = scrape(port1, "/metrics");
    assert!(before.contains("osslscope_epoch_calls_total"), "{before:?}");
    child.kill().unwrap();
    child.wait().unwrap();
    let port2 = free_port();
    let mut child = spawn_export(port2);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let after = scrape(port2, "/metrics");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        strip_age(&after),
        strip_age(&before),
        "post-restart exposition identical (no churn, no recount)"
    );
}

#[test]
fn newp2b_run_identity_is_full() {
    // P2fix3 NEW-P2b: summary adoption uses the FULL run identity
    // (pid + starttime + FULL boot_id) — two runs sharing an
    // 8-char boot prefix are DISTINCT runs with separate grosses
    // (truncated tags would merge them and lose a gross).
    use osslscope::presentation::snapshot;
    let dir = out_dir("newp2b-identity");
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-aaaa-bbbb-cccc-ddeeff001122"});
    let run_b = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-bbbb-cccc-dddd-eeff00112233"});
    let mut env_a = snapshot::test_envelope(0, 0, run_a, 10);
    env_a["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env_a["stream_configured"] = serde_json::json!(true);
    let mut env_b = snapshot::test_envelope(1, 0, run_b, 10);
    env_b["stream_gross_close"] = serde_json::json!({"records": 3, "bytes": 30, "by_reason": {"queue_full": {"records": 3, "bytes": 30}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env_b["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env_a).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env_b).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    // Distinct runs: sealed A (5) + current B (3) = 8 (a merged
    // tag would max to 5 and lose B's gross).
    let drops = snap.stream.as_ref().expect("stream configured").drops;
    assert_eq!(drops.records, 8, "full identity keeps both grosses");
    assert_eq!(drops.bytes, 80);
}

#[test]
fn newp2b_close_reconciles_every_component() {
    // P2fix3 NEW-P2b: the close-GROSS rule reconciles EACH reason
    // + byte component (not just aggregate totals) — a per-reason
    // decrease flags even when the totals hold.
    use osslscope::presentation::snapshot;
    let dir = out_dir("newp2b-close");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 10, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    let mut env1 = snapshot::test_envelope(1, 0, run, 10);
    // Totals hold (10/100) but queue_full.records DECREASED 10→7
    // (shifted to epipe): corrupt per the frozen rule.
    env1["stream_gross_close"] = serde_json::json!({"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 7, "bytes": 70}, "epipe": {"records": 3, "bytes": 30}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env1["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let snap = p.build_service().unwrap();
    assert!(
        snap.stream.is_some(),
        "stream configured: {:?}",
        snap.unknown
    );
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "stream.drops" && e.reason == "unstable_snapshot"),
        "per-reason decrease flags: {:?}",
        snap.unknown
            .iter()
            .map(|e| (&e.path, &e.reason))
            .collect::<Vec<_>>()
    );
    // ... while the running max keeps the peak component values.
    let drops = snap.stream.as_ref().unwrap().drops;
    assert_eq!(drops.queue_full.records, 10);
    assert_eq!(drops.epipe.records, 3);
}

#[test]
fn newp2c_repeated_gap_flags_survive_mid_scan_reset() {
    // P2fix4 NEW-P2c: flags record PER ENCOUNTERED GAP (no
    // set-difference loss) — a flag already set from an earlier
    // build, raised AGAIN by a gap in this scan, survives a
    // mid-scan generation reset with the ranges (pre-fix: the
    // set difference excludes the already-set flag, and the
    // reset drops it — a gap this scan encountered leaves no
    // flag).
    use osslscope::presentation::snapshot;
    let dir = out_dir("newp2c-repeat-flags");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Build 1: gap at seq 1 (windows 0 + 2) sets the epoch
    // flags (persisted in the checkpoint).
    for seq in [0u64, 2] {
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&snapshot::test_envelope(seq, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
    }
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let s1 = p.build_service().unwrap();
    assert!(
        s1.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "premise: build 1 flags the retention gap"
    );
    // Build 2: window 3 (gen 0) + window 5 (gen 1) — a NEW gap
    // at seq 4 (same flags, already set) then a mid-scan
    // generation reset.
    for (seq, generation) in [(3u64, 0u64), (5, 1)] {
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&snapshot::test_envelope(seq, generation, run.clone(), 10))
                .unwrap(),
        )
        .unwrap();
    }
    let s2 = p.build_service().unwrap();
    assert!(
        s2.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "repeated gap flags survive the mid-scan reset: {:?}",
        s2.unknown
            .iter()
            .map(|e| (&e.path, &e.reason))
            .collect::<Vec<_>>()
    );
}

#[test]
fn new15_one_authoritative_gross_while_current() {
    // P2fix4 NEW-15/NEW-P2b: ONE authoritative gross at every
    // refresh — a summary adopted BEFORE its run's windows (sealed
    // 8) must not sum with the later close (5) into 13 while that
    // run is current. The intermediate frame (run current, no
    // successor yet) publishes the max with mismatch flagged, and
    // a restart preserves it. (The existing pin adds the
    // successor before asserting, so it misses this frame.)
    use osslscope::presentation::snapshot;
    let case = |close: u64, expect: u64, what: &str| {
        let dir = out_dir(&format!("new15-order-{what}"));
        let run_s = serde_json::json!({"pid": 1, "starttime": 3, "boot_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"});
        let run_t = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"});
        let run_u = serde_json::json!({"pid": 1, "starttime": 4, "boot_id": "cccccccc-dddd-eeee-ffff-000000000000"});
        std::fs::write(
            dir.join("run-summary.json"),
            serde_json::json!({
                "schema": "service-run-v1",
                "generation": 0,
                "run_id": {"pid": 1, "starttime": 2, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
                "stream_configured": true,
                "stream_drops": {"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}},
            })
            .to_string(),
        )
        .unwrap();
        let env_s = snapshot::test_envelope(0, 0, run_s, 10);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env_s).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
        // T's windows (close gross) arrive after T's summary; NO
        // successor yet — the intermediate frame.
        let mut env_t = snapshot::test_envelope(1, 0, run_t, 10);
        env_t["stream_gross_close"] = serde_json::json!({"records": close, "bytes": close * 10, "by_reason": {"queue_full": {"records": close, "bytes": close * 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
        env_t["stream_configured"] = serde_json::json!(true);
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&env_t).unwrap(),
        )
        .unwrap();
        let mid = p.build_service().unwrap();
        let drops = mid.stream.as_ref().expect("stream configured").drops;
        assert_eq!(drops.records, expect, "{what}: intermediate gross");
        assert!(
            mid.unknown.iter().any(|e| e.path == "stream.drops"
                && e.reason == "unstable_snapshot"
                && e.note
                    .as_deref()
                    .is_some_and(|n| n.contains("summary_mismatch"))),
            "{what}: intermediate mismatch flagged: {:?}",
            mid.unknown
                .iter()
                .map(|e| (&e.path, &e.reason, &e.note))
                .collect::<Vec<_>>()
        );
        // Restart: the intermediate gross survives (no double
        // count, no loss).
        drop(p);
        let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let re = p2.build_service().unwrap();
        let drops = re.stream.as_ref().expect("stream configured").drops;
        assert_eq!(drops.records, expect, "{what}: post-restart gross");
        // Successor seals T: the final gross stands with mismatch
        // (the existing pin's frame, kept).
        let env_u = snapshot::test_envelope(2, 0, run_u, 10);
        std::fs::write(
            dir.join("window-0000000002.json"),
            serde_json::to_string(&env_u).unwrap(),
        )
        .unwrap();
        let fin = p2.build_service().unwrap();
        let drops = fin.stream.as_ref().expect("stream configured").drops;
        assert_eq!(drops.records, expect, "{what}: final gross");
        assert!(
            fin.unknown.iter().any(|e| e.path == "stream.drops"
                && e.reason == "unstable_snapshot"
                && e.note
                    .as_deref()
                    .is_some_and(|n| n.contains("summary_mismatch"))),
            "{what}: final mismatch flagged",
        );
    };
    // Close 5 under summary 8 → 8 throughout (pre-fix: 16 —
    // sealed 8 beside adopted-into-current 8).
    case(5, 8, "close-below");
    // Close 10 over summary 8 → 10 throughout (pre-fix: 18).
    case(10, 10, "close-above");
}

#[test]
fn new30_successor_summary_seals_departed_run() {
    // P2fix5 NEW-30: seal-on-transition fires on the FIRST
    // adopted summary naming a NEW run_id (frozen rule — not just
    // on its first window): the departed run seals with its
    // missing-summary marker, and the live slot parks empty until
    // the successor's first window. Pre-fix: the departed run
    // stays unsealed beside the adopted successor summary.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let run_b = serde_json::json!({"pid": 3, "starttime": 4, "boot_id": boot});
    let tag_a = format!("1-2-{boot}");
    let tag_b = format!("3-4-{boot}");
    let dir = out_dir("new30-seal");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("A folds");
    // Successor summary lands with NO successor windows yet.
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 3, "starttime": 4, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    let snap = p.build_service().expect("summary-only transition builds");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert!(
        sealed.get(&tag_a).is_some(),
        "the departed run seals on the successor summary: {sealed:?}"
    );
    assert_eq!(
        sealed[&tag_a]["tail_note"], "sealed_from_close_no_summary",
        "missing-summary marker: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(sealed[&tag_a]["records"], 5);
    assert_eq!(sealed[&tag_a]["bytes"], 50);
    assert_eq!(
        v["accumulators"]["current_run"],
        serde_json::Value::Null,
        "no live run parks until the successor's first window"
    );
    assert_eq!(sealed[&tag_b]["source"], "summary");
    assert_eq!(
        v["accumulators"]["stream_sealed_note"], true,
        "sealed note sticks"
    );
    // Totals control (attribution moves, totals conserve).
    let drops = snap.stream.as_ref().expect("stream projects").drops.clone();
    assert_eq!((drops.records, drops.bytes), (13, 130));
    // The successor's first window then transitions cleanly (its
    // sealed entry unseals into the adopted slot — no double
    // gross).
    let mut env1 = snapshot::test_envelope(1, 0, run_b, 10);
    env1["stream_gross_close"] = serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env1["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    let snap = p.build_service().expect("successor window folds");
    let drops = snap.stream.as_ref().expect("stream projects").drops.clone();
    assert_eq!(
        (drops.records, drops.bytes),
        (13, 130),
        "exact agreement seals clean with one gross"
    );
}

#[test]
fn new30_mixed_provenance_survives_restart() {
    // P2fix5 NEW-30: the seal derives provenance from the
    // SEPARATELY retained observed-close + summary vectors (a
    // seeded vector cannot show mixed lead/lag), and both vectors
    // survive restart: a successor summary seals the run AFTER a
    // reopen with `mixed` provenance and per-component maxima.
    // Pre-fix: the successor summary never seals (the run stays
    // live), and the seeded reconcile cannot identify mixed
    // provenance.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let run_b = serde_json::json!({"pid": 3, "starttime": 4, "boot_id": boot});
    let tag_b = format!("3-4-{boot}");
    let dir = out_dir("new30-mixed");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("A folds");
    // B summary first (records-high, bytes-low).
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 3, "starttime": 4, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 10, "bytes": 50, "by_reason": {"queue_full": {"records": 10, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    p.build_service().expect("B summary adopts");
    // B window (records-low, bytes-high — cross lead/lag).
    let mut env1 = snapshot::test_envelope(1, 0, run_b, 10);
    env1["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 100, "by_reason": {"queue_full": {"records": 5, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env1["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    p.build_service().expect("B window folds");
    drop(p);
    // Restart: the checkpoint is the only bridge for the
    // observed-close + summary vectors.
    let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("reopen restores both vectors");
    // Successor summary seals B (no C windows at all).
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 5, "starttime": 6, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 1, "bytes": 10, "by_reason": {"queue_full": {"records": 1, "bytes": 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    let snap = p2.build_service().expect("successor summary seals B");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert!(
        sealed.get(&tag_b).is_some(),
        "B seals on the successor summary: {sealed:?}"
    );
    assert_eq!(
        sealed[&tag_b]["source"], "mixed",
        "cross lead/lag provenances mixed: {:?}",
        sealed[&tag_b]
    );
    assert_eq!(sealed[&tag_b]["records"], 10);
    assert_eq!(sealed[&tag_b]["bytes"], 100);
    assert_eq!(sealed[&tag_b]["queue_full"]["records"], 10);
    assert_eq!(sealed[&tag_b]["queue_full"]["bytes"], 100);
    assert_eq!(
        v["accumulators"]["stream_mismatch_note"], true,
        "close/summary disagreement flags"
    );
    // Totals control: A(5,50) + B(10,100) + C(1,10).
    let drops = snap.stream.as_ref().expect("stream projects").drops.clone();
    assert_eq!((drops.records, drops.bytes), (16, 160));
}

#[test]
fn new35_current_summary_reconciles_on_successor_replacement() {
    // P2fix6 NEW-35: a CURRENT run's validated summary gross (8,
    // above its close gross 5) is RETAINED separately — when the
    // singleton run-summary file is replaced by a successor
    // summary before the next refresh, the departed run seals
    // from the retained summary (records 8, source `summary`) and
    // invents NO missing-summary marker. Pre-fix: ordinary
    // adoption updates only `current_gross`, so the seal reads
    // `current_close` 5 + the invented
    // `sealed_from_close_no_summary` marker (the adopted 8 is
    // lost).
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let tag_a = format!("1-2-{boot}");
    let dir = out_dir("new35-replace");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("A folds");
    // A's summary lands while A is current (close 5, summary 8).
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 1, "starttime": 2, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    p.build_service().expect("A summary adopts while current");
    // The singleton file is replaced by B's summary before the
    // next refresh.
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 3, "starttime": 4, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 1, "bytes": 10, "by_reason": {"queue_full": {"records": 1, "bytes": 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    p.build_service().expect("successor summary seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert!(
        sealed.get(&tag_a).is_some(),
        "A seals on the successor summary: {sealed:?}"
    );
    assert_eq!(
        sealed[&tag_a]["records"], 8,
        "the retained current-run summary reconciles into the seal: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(
        sealed[&tag_a]["bytes"], 80,
        "bytes reconcile too: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(
        sealed[&tag_a]["source"], "summary",
        "summary-above-close provenances summary: {:?}",
        sealed[&tag_a]
    );
    assert!(
        sealed[&tag_a]["tail_note"].is_null(),
        "no invented missing-summary marker: {:?}",
        sealed[&tag_a]
    );
}

#[test]
fn new35_current_summary_survives_restart() {
    // P2fix6 NEW-35 restart twin: the retained current-run
    // summary persists through the checkpoint — adopt A's
    // summary (8 over close 5), restart, THEN replace the file
    // with B's summary: A still seals 8/`summary` with no
    // invented marker. Pre-fix: the adopted 8 never reaches any
    // persisted slot, so the post-restart seal reads close 5 +
    // the invented marker.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let tag_a = format!("1-2-{boot}");
    let dir = out_dir("new35-restart");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("A folds");
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 1, "starttime": 2, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    p.build_service().expect("A summary adopts while current");
    drop(p);
    // Restart: the checkpoint is the only bridge for the
    // retained current-run summary.
    let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("reopen restores the retained summary");
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 3, "starttime": 4, "boot_id": boot}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 1, "bytes": 10, "by_reason": {"queue_full": {"records": 1, "bytes": 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    p2.build_service().expect("successor summary seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert!(
        sealed.get(&tag_a).is_some(),
        "A seals on the successor summary: {sealed:?}"
    );
    assert_eq!(
        sealed[&tag_a]["records"], 8,
        "the retained current-run summary survives restart into the seal: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(
        sealed[&tag_a]["source"], "summary",
        "summary-above-close provenances summary: {:?}",
        sealed[&tag_a]
    );
    assert!(
        sealed[&tag_a]["tail_note"].is_null(),
        "no invented missing-summary marker: {:?}",
        sealed[&tag_a]
    );
}

/// Valid typed gross drops (P2fix7 NEW-46 controls).
fn new46_valid_drops(records: u64, bytes: u64) -> serde_json::Value {
    serde_json::json!({"records": records, "bytes": bytes, "by_reason": {"queue_full": {"records": records, "bytes": bytes}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}})
}

/// `run-summary.json` body for (pid, starttime) with the given
/// drops + a valid configured marker (P2fix7 NEW-46; [p2fix8
/// NEW-53: exact source identity — sourceless summaries no
/// longer adopt]).
fn new46_summary(pid: u32, starttime: u64, drops: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": pid, "starttime": starttime, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}, "generation": 0, "stream_configured": true, "stream_drops": drops})
}

/// Malformed gross drops, one per corruption shape (P2fix7
/// NEW-46 — every one zero-defaults under the lenient reader).
fn new46_malformed_drops() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "missing-records",
            serde_json::json!({"bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "string-records",
            serde_json::json!({"records": "8", "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "null-bytes",
            serde_json::json!({"records": 8, "bytes": null, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "bad-reason-shape",
            serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": [1], "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "missing-reason",
            serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}}}),
        ),
        (
            "flat-missing-reason",
            serde_json::json!({"records": 8, "bytes": 80, "queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}}),
        ),
    ]
}

/// Fold run A (close gross 5/50) in a fresh dir (P2fix7 NEW-46).
fn new46_open_a(
    name: &str,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    osslscope::presentation::snapshot::Presenter,
) {
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let dir = out_dir(name);
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = serde_json::json!({"records": 5, "bytes": 50, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("A folds");
    (dir, ckpt, p)
}

#[test]
fn new46_malformed_current_summary_ignored() {
    // P2fix7 NEW-46: a malformed CURRENT-run summary never
    // reaches the authority slot — no zero-defaulted gross
    // merges into `current_gross`/`current_summary`, no mismatch
    // latches, and the later seal reads the observed close with
    // the HONEST no-summary note. Pre-fix: the lenient reader
    // zero-defaults every corruption shape, so the zeros merge
    // (mismatch latches against close 5) and the seal
    // reconciles the phantom zero-summary (sourceless note).
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let mut variants = new46_malformed_drops();
    // Malformed SOURCE shape (valid gross, non-bool marker —
    // drops equal the close so only the marker convicts).
    let mut bad_configured = new46_summary(1, 2, new46_valid_drops(5, 50));
    bad_configured["stream_configured"] = serde_json::json!("yes");
    variants.push(("bad-configured", bad_configured["stream_drops"].clone()));
    for (what, drops) in &variants {
        let (dir, ckpt, mut p) = new46_open_a(&format!("new46-current-{what}"));
        let mut summary = new46_summary(1, 2, drops.clone());
        if *what == "bad-configured" {
            summary["stream_configured"] = serde_json::json!("yes");
        }
        std::fs::write(dir.join("run-summary.json"), summary.to_string()).unwrap();
        p.build_service()
            .expect("malformed current summary never fails the build");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let acc = &v["accumulators"];
        assert_eq!(
            acc["stream_mismatch_note"], false,
            "{what}: no mismatch latches on an ignored summary: {acc:?}"
        );
        assert!(
            acc["unstable"]
                .as_array()
                .is_none_or(|u| !u.contains(&serde_json::json!("stream.drops"))),
            "{what}: stream.drops stays stable: {acc:?}"
        );
        assert!(
            acc["current_summary"].is_null(),
            "{what}: nothing reaches the authority slot: {acc:?}"
        );
        assert_eq!(
            acc["current_gross"]["records"], 5,
            "{what}: the observed close stands: {acc:?}"
        );
        // A valid successor seals A from the observed close with
        // the HONEST no-summary note (no valid summary ever
        // existed for A).
        std::fs::write(
            dir.join("run-summary.json"),
            new46_summary(3, 4, new46_valid_drops(1, 10)).to_string(),
        )
        .unwrap();
        p.build_service().expect("successor summary seals A");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let sealed = &v["accumulators"]["sealed"];
        assert_eq!(
            sealed[&tag_a]["records"], 5,
            "{what}: the seal reads the observed close: {:?}",
            sealed[&tag_a]
        );
        assert_eq!(
            sealed[&tag_a]["source"], "close",
            "{what}: close-only provenance: {:?}",
            sealed[&tag_a]
        );
        assert_eq!(
            sealed[&tag_a]["tail_note"],
            serde_json::json!(snapshot::NOTE_SEALED_FROM_CLOSE),
            "{what}: the honest no-summary note rides the seal: {:?}",
            sealed[&tag_a]
        );
    }
}

#[test]
fn new46_malformed_successor_summary_ignored() {
    // P2fix7 NEW-46: a malformed SUCCESSOR summary never
    // triggers the seal-on-transition — the departed run stays
    // current (unsealed) until a VALID successor arrives, and no
    // departed run seals on a defaulted summary. Pre-fix: the
    // transition fires on the zero-defaulted gross, sealing A
    // early and parking the phantom B gross. Valid controls both
    // sides (A's valid summary adopts; the later valid B seals A
    // from it).
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let (dir, ckpt, mut p) = new46_open_a("new46-successor");
    // A's valid summary adopts while current (control).
    std::fs::write(
        dir.join("run-summary.json"),
        new46_summary(1, 2, new46_valid_drops(8, 80)).to_string(),
    )
    .unwrap();
    p.build_service().expect("A summary adopts while current");
    for (what, drops) in new46_malformed_drops().iter().take(4) {
        std::fs::write(
            dir.join("run-summary.json"),
            new46_summary(3, 4, drops.clone()).to_string(),
        )
        .unwrap();
        p.build_service()
            .expect("malformed successor never fails the build");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let acc = &v["accumulators"];
        assert!(
            acc["sealed"].get(&tag_a).is_none(),
            "{what}: A stays unsealed (still current): {acc:?}"
        );
        assert_eq!(
            acc["current_run"],
            serde_json::json!(tag_a),
            "{what}: A stays current: {acc:?}"
        );
    }
    // The malformed file never poisoned the authority slot: a
    // valid B seals A from the retained valid summary.
    std::fs::write(
        dir.join("run-summary.json"),
        new46_summary(3, 4, new46_valid_drops(1, 10)).to_string(),
    )
    .unwrap();
    p.build_service().expect("valid successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert_eq!(
        sealed[&tag_a]["records"], 8,
        "A seals from the retained valid summary: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(
        sealed[&tag_a]["source"], "summary",
        "summary-above-close provenances summary: {:?}",
        sealed[&tag_a]
    );
    assert!(
        sealed[&tag_a]["tail_note"].is_null(),
        "no missing-summary marker beside a reconciled summary: {:?}",
        sealed[&tag_a]
    );
}

#[test]
fn new46_malformed_summary_ignored_across_restart() {
    // P2fix7 NEW-46 restart twin: malformed summaries stay
    // ignored across a checkpoint restart — nothing persists a
    // phantom gross, and the post-restart seal reads the
    // observed close with the honest note. The valid twin
    // (control) proves restart adoption still works.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let (dir, ckpt, mut p) = new46_open_a("new46-restart");
    let (_, drops) = &new46_malformed_drops()[0];
    std::fs::write(
        dir.join("run-summary.json"),
        new46_summary(1, 2, drops.clone()).to_string(),
    )
    .unwrap();
    p.build_service()
        .expect("malformed current never fails the build");
    drop(p);
    let mut p2 =
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").expect("reopen works");
    let (_, drops_b) = &new46_malformed_drops()[1];
    std::fs::write(
        dir.join("run-summary.json"),
        new46_summary(3, 4, drops_b.clone()).to_string(),
    )
    .unwrap();
    p2.build_service()
        .expect("malformed successor never fails the build");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert!(
        v["accumulators"]["sealed"].get(&tag_a).is_none(),
        "A stays unsealed across restart: {:?}",
        v["accumulators"]
    );
    std::fs::write(
        dir.join("run-summary.json"),
        new46_summary(3, 4, new46_valid_drops(1, 10)).to_string(),
    )
    .unwrap();
    p2.build_service().expect("valid successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert_eq!(
        sealed[&tag_a]["records"], 5,
        "the seal reads the observed close: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(
        sealed[&tag_a]["tail_note"],
        serde_json::json!(snapshot::NOTE_SEALED_FROM_CLOSE),
        "the honest no-summary note survives restart: {:?}",
        sealed[&tag_a]
    );
    // Valid twin (control): valid adoption still crosses restart.
    let (dir2, ckpt2, mut q) = new46_open_a("new46-restart-valid");
    std::fs::write(
        dir2.join("run-summary.json"),
        new46_summary(1, 2, new46_valid_drops(8, 80)).to_string(),
    )
    .unwrap();
    q.build_service().expect("valid summary adopts");
    drop(q);
    let mut q2 = snapshot::Presenter::open_with_checkpoint(&dir2, &ckpt2, 1, "export")
        .expect("reopen works");
    std::fs::write(
        dir2.join("run-summary.json"),
        new46_summary(3, 4, new46_valid_drops(1, 10)).to_string(),
    )
    .unwrap();
    q2.build_service().expect("valid successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt2).unwrap()).unwrap();
    let sealed = &v["accumulators"]["sealed"];
    assert_eq!(
        sealed[&tag_a]["records"], 8,
        "valid adoption still crosses restart: {:?}",
        sealed[&tag_a]
    );
    assert_eq!(sealed[&tag_a]["source"], "summary");
}

#[test]
fn new53_malformed_current_summary_ignored() {
    // P2fix8 NEW-53: a CURRENT-run summary with a WRONG source
    // identity, MISSING identity, DUPLICATE raw keys, or a
    // NON-CONSERVING gross never reaches the authority slot —
    // validation runs BEFORE the summary mutates fold state
    // (all-or-nothing, like NEW-46). Pre-fix: the reader
    // accepts any `schema`, collapses raw duplicates into
    // `Value`, and adopts gross totals inconsistent with the
    // per-reason accounting (RED — the authority slot fills and
    // mismatch latches against close 5).
    use osslscope::presentation::snapshot;
    let nonconserving = serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    for (what, text) in [
        ("wrong-schema", {
            let mut s = new46_summary(1, 2, new46_valid_drops(8, 80));
            s["schema"] = serde_json::json!("service-window-v1");
            s.to_string()
        }),
        ("missing-schema", {
            let mut s = new46_summary(1, 2, new46_valid_drops(8, 80));
            s.as_object_mut().unwrap().remove("schema");
            s.to_string()
        }),
        ("duplicate-keys", {
            let mut s = new46_summary(1, 2, new46_valid_drops(8, 80));
            s["schema"] = serde_json::json!("service-run-v1");
            let mut t = s.to_string();
            t = t.replacen(
                "\"stream_drops\"",
                "\"stream_drops\":{},\"stream_drops\"",
                1,
            );
            t
        }),
        ("non-conserving", {
            let mut s = new46_summary(1, 2, nonconserving);
            s["schema"] = serde_json::json!("service-run-v1");
            s.to_string()
        }),
    ] {
        let (dir, ckpt, mut p) = new46_open_a(&format!("new53-current-{what}"));
        std::fs::write(dir.join("run-summary.json"), &text).unwrap();
        p.build_service()
            .expect("malformed current summary never fails the build");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let acc = &v["accumulators"];
        assert_eq!(
            acc["stream_mismatch_note"], false,
            "{what}: no mismatch latches on an ignored summary: {acc:?}"
        );
        assert!(
            acc["current_summary"].is_null(),
            "{what}: nothing reaches the authority slot: {acc:?}"
        );
        assert_eq!(
            acc["current_gross"]["records"], 5,
            "{what}: the observed close stands: {acc:?}"
        );
    }
    // Valid twin (control): exact identity + conserving gross
    // adopts (mismatch latches against close 5 — the adoption
    // path stays intact).
    let (dir, ckpt, mut p) = new46_open_a("new53-current-valid");
    let mut s = new46_summary(1, 2, new46_valid_drops(8, 80));
    s["schema"] = serde_json::json!("service-run-v1");
    std::fs::write(dir.join("run-summary.json"), s.to_string()).unwrap();
    p.build_service().expect("valid summary adopts");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["current_gross"]["records"], 8,
        "the valid gross adopts: {:?}",
        v["accumulators"]
    );
}

#[test]
fn new53_malformed_successor_summary_ignored() {
    // P2fix8 NEW-53 successor twin: a SUCCESSOR summary with a
    // wrong identity or a non-conserving gross never triggers
    // the seal-on-transition — the departed run stays current
    // until a VALID successor seals it. Pre-fix: the transition
    // fires on the malformed gross, sealing A early (RED).
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let nonconserving = serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    for (what, text) in [
        ("wrong-schema", {
            let mut s = new46_summary(3, 4, new46_valid_drops(1, 10));
            s["schema"] = serde_json::json!("service-window-v1");
            s.to_string()
        }),
        ("non-conserving", {
            let mut s = new46_summary(3, 4, nonconserving);
            s["schema"] = serde_json::json!("service-run-v1");
            s.to_string()
        }),
    ] {
        let (dir, ckpt, mut p) = new46_open_a(&format!("new53-successor-{what}"));
        std::fs::write(dir.join("run-summary.json"), &text).unwrap();
        p.build_service()
            .expect("malformed successor never fails the build");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let acc = &v["accumulators"];
        assert!(
            acc["sealed"].get(&tag_a).is_none(),
            "{what}: A stays unsealed (still current): {acc:?}"
        );
        assert_eq!(
            acc["current_run"],
            serde_json::json!(tag_a),
            "{what}: A stays current: {acc:?}"
        );
        // A valid successor still seals A from the observed
        // close with the honest note.
        let mut s = new46_summary(3, 4, new46_valid_drops(1, 10));
        s["schema"] = serde_json::json!("service-run-v1");
        std::fs::write(dir.join("run-summary.json"), s.to_string()).unwrap();
        p.build_service().expect("valid successor seals A");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(
            v["accumulators"]["sealed"][&tag_a]["source"], "close",
            "{what}: close-only provenance: {:?}",
            v["accumulators"]["sealed"][&tag_a]
        );
    }
}

#[test]
fn new53_malformed_summary_ignored_across_restart() {
    // P2fix8 NEW-53 restart twin: malformed current + successor
    // artifacts stay ignored across a checkpoint restart —
    // nothing persists a phantom gross, and the post-restart
    // seal reads the observed close with the honest note. The
    // valid twin (control) proves restart adoption still works.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let nonconserving = serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    let (dir, ckpt, mut p) = new46_open_a("new53-restart");
    let mut bad = new46_summary(1, 2, nonconserving);
    bad["schema"] = serde_json::json!("service-window-v1");
    std::fs::write(dir.join("run-summary.json"), bad.to_string()).unwrap();
    p.build_service()
        .expect("malformed current never fails the build");
    drop(p);
    let mut p2 =
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").expect("reopen works");
    let mut bad_b = new46_summary(3, 4, new46_valid_drops(1, 10));
    bad_b["schema"] = serde_json::json!("service-window-v1");
    std::fs::write(dir.join("run-summary.json"), bad_b.to_string()).unwrap();
    p2.build_service()
        .expect("malformed successor never fails the build");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert!(
        v["accumulators"]["sealed"].get(&tag_a).is_none(),
        "A stays unsealed across restart: {:?}",
        v["accumulators"]
    );
    assert!(
        v["accumulators"]["current_summary"].is_null(),
        "nothing reaches the authority slot across restart: {:?}",
        v["accumulators"]
    );
    let mut good_b = new46_summary(3, 4, new46_valid_drops(1, 10));
    good_b["schema"] = serde_json::json!("service-run-v1");
    std::fs::write(dir.join("run-summary.json"), good_b.to_string()).unwrap();
    p2.build_service().expect("valid successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["sealed"][&tag_a]["tail_note"],
        serde_json::json!(snapshot::NOTE_SEALED_FROM_CLOSE),
        "the honest no-summary note survives restart: {:?}",
        v["accumulators"]["sealed"][&tag_a]
    );
    // Valid twin (control): valid adoption still crosses restart.
    let (dir2, ckpt2, mut q) = new46_open_a("new53-restart-valid");
    let mut s = new46_summary(1, 2, new46_valid_drops(8, 80));
    s["schema"] = serde_json::json!("service-run-v1");
    std::fs::write(dir2.join("run-summary.json"), s.to_string()).unwrap();
    q.build_service().expect("valid summary adopts");
    drop(q);
    let mut q2 = snapshot::Presenter::open_with_checkpoint(&dir2, &ckpt2, 1, "export")
        .expect("reopen works");
    let mut s2 = new46_summary(3, 4, new46_valid_drops(1, 10));
    s2["schema"] = serde_json::json!("service-run-v1");
    std::fs::write(dir2.join("run-summary.json"), s2.to_string()).unwrap();
    q2.build_service().expect("valid successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt2).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["sealed"][&tag_a]["records"], 8,
        "valid adoption still crosses restart: {:?}",
        v["accumulators"]["sealed"][&tag_a]
    );
}

#[test]
fn new53_malformed_window_gross_rejects_envelope() {
    // P2fix8 NEW-53 window twin: a PRESENT `stream_gross_close`
    // validates strict shape + conservation BEFORE the window
    // mutates fold state — a malformed gross rejects the whole
    // envelope (like the End tallies). ABSENT stays the
    // documented legacy zeros (control). Pre-fix: the
    // zero-defaulting reader folds every corruption shape
    // (RED).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    for (what, gross) in [
        (
            "missing-records",
            serde_json::json!({"bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "string-bytes",
            serde_json::json!({"records": 8, "bytes": "80", "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
        (
            "non-conserving",
            serde_json::json!({"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 5, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}),
        ),
    ] {
        let dir = out_dir(&format!("new53-window-{what}"));
        let mut env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
        env0["stream_gross_close"] = gross;
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env0).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        assert!(
            p.build_service().is_err(),
            "{what}: a malformed window gross rejects the envelope"
        );
    }
    // Absent-gross legacy control: folds with zeros.
    let dir = out_dir("new53-window-absent");
    let env0 = snapshot::test_envelope(0, 0, run, 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service()
        .expect("absent gross folds (legacy zeros)");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["current_gross"]["records"], 0,
        "absent gross reads legacy zeros: {:?}",
        v["accumulators"]
    );
}

#[test]
fn new57_malformed_current_window_rejects_envelope() {
    // P2fix9 NEW-57 (+ NEW-P2b/NEW-53-OPEN): window intake
    // checks exact source identity, distinguishes raw key
    // ABSENCE (legacy zeros) from EVERY supplied invalid
    // shape, and validates a supplied configuration marker —
    // all BEFORE mutation. A present non-object gross
    // (null/scalar/array), a wrong-schema envelope, or a
    // non-bool marker rejects the WHOLE envelope. Pre-fix:
    // `obj_at` folds every non-object gross as legacy zeros,
    // wrong-schema windows enter, and non-bool markers read
    // as false (RED).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let gross = new46_valid_drops(5, 50);
    for (what, mutate) in [
        (
            "gross-null",
            serde_json::json!({"stream_gross_close": null}),
        ),
        ("gross-number", serde_json::json!({"stream_gross_close": 8})),
        (
            "gross-string",
            serde_json::json!({"stream_gross_close": "8"}),
        ),
        (
            "gross-bool",
            serde_json::json!({"stream_gross_close": true}),
        ),
        ("gross-array", serde_json::json!({"stream_gross_close": []})),
        (
            "wrong-schema",
            serde_json::json!({"schema": "service-run-v1"}),
        ),
        ("schema-null", serde_json::json!({"schema": null})),
        ("schema-number", serde_json::json!({"schema": 1})),
        ("marker-number", serde_json::json!({"stream_configured": 1})),
        (
            "marker-string",
            serde_json::json!({"stream_configured": "true"}),
        ),
    ] {
        let dir = out_dir(&format!("new57-current-{what}"));
        let mut env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
        for (k, v) in mutate.as_object().unwrap() {
            env0[k] = v.clone();
        }
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env0).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        assert!(
            p.build_service().is_err(),
            "{what}: the malformed window rejects the envelope"
        );
    }
    // Missing-schema twin (key removal, not a value shape).
    let dir = out_dir("new57-current-missing-schema");
    let mut env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
    env0.as_object_mut().unwrap().remove("schema");
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    assert!(
        p.build_service().is_err(),
        "missing-schema: the window rejects the envelope"
    );
    // Valid twin (control): exact identity + valid gross +
    // bool marker folds.
    let dir = out_dir("new57-current-valid");
    let mut env0 = snapshot::test_envelope(0, 0, run.clone(), 10);
    env0["stream_gross_close"] = gross;
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("valid window folds");
    // Rejection advances nothing: the folded window keeps its
    // exact checkpoint bytes across a rejected successor.
    let mut env1 = snapshot::test_envelope(1, 0, run, 10);
    env1["stream_gross_close"] = serde_json::json!(null);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    let good = std::fs::read(&ckpt).unwrap();
    assert!(
        p.build_service().is_err(),
        "the null-gross successor rejects"
    );
    assert_eq!(
        std::fs::read(&ckpt).unwrap(),
        good,
        "a rejected window persists nothing"
    );
}

#[test]
fn new57_malformed_successor_window_rejects_envelope() {
    // P2fix9 NEW-57 successor twin: a next-run window with a
    // malformed gross rejects WITHOUT sealing the departed
    // run (seal-on-transition never fires on a rejected
    // window) and persists nothing; repairing the successor
    // seals A from the observed close with the honest note.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let run_b = serde_json::json!({"pid": 3, "starttime": 4, "boot_id": boot});
    let dir = out_dir("new57-successor");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = new46_valid_drops(5, 50);
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("run A folds");
    let good = std::fs::read(&ckpt).unwrap();
    let mut env1 = snapshot::test_envelope(1, 0, run_b.clone(), 10);
    env1["stream_gross_close"] = serde_json::json!([1, 2]);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    assert!(
        p.build_service().is_err(),
        "the array-gross successor rejects"
    );
    assert_eq!(
        std::fs::read(&ckpt).unwrap(),
        good,
        "a rejected successor persists nothing"
    );
    let v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    assert!(
        v["accumulators"]["sealed"].get(&tag_a).is_none(),
        "A stays unsealed: {:?}",
        v["accumulators"]
    );
    // Repair the successor: valid gross seals A honestly.
    let mut env1 = snapshot::test_envelope(1, 0, run_b, 10);
    env1["stream_gross_close"] = new46_valid_drops(1, 10);
    env1["stream_configured"] = serde_json::json!(false);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    p.build_service().expect("repaired successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["sealed"][&tag_a]["records"], 5,
        "A seals from the observed close: {:?}",
        v["accumulators"]["sealed"][&tag_a]
    );
    assert_eq!(
        v["accumulators"]["sealed"][&tag_a]["tail_note"],
        serde_json::json!(snapshot::NOTE_SEALED_FROM_CLOSE),
        "the honest no-summary note: {:?}",
        v["accumulators"]["sealed"][&tag_a]
    );
}

#[test]
fn new57_malformed_window_rejected_across_restart() {
    // P2fix9 NEW-57 restart twin: a rejected window leaves
    // watermark, generation, and sealed gross intact across a
    // checkpoint restart — nothing persists a phantom gross,
    // and the post-restart seal reads the observed close.
    use osslscope::presentation::snapshot;
    let boot = "12345678-9abc-def0-1234-56789abcdef0";
    let tag_a = format!("1-2-{boot}");
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
    let run_b = serde_json::json!({"pid": 3, "starttime": 4, "boot_id": boot});
    let dir = out_dir("new57-restart");
    let mut env0 = snapshot::test_envelope(0, 0, run_a, 10);
    env0["stream_gross_close"] = new46_valid_drops(5, 50);
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("run A folds");
    drop(p);
    let mut p2 =
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").expect("reopen works");
    let mut env1 = snapshot::test_envelope(1, 0, run_b.clone(), 10);
    env1["stream_gross_close"] = serde_json::json!("5");
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    assert!(
        p2.build_service().is_err(),
        "the scalar-gross successor rejects after restart"
    );
    drop(p2);
    let mut p3 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("second reopen works");
    p3.build_service()
        .expect_err("the bad window still rejects");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(v["watermark_seq"], 0, "watermark intact: {v:?}");
    assert_eq!(v["generation"], 0, "generation intact: {v:?}");
    assert!(
        v["accumulators"]["sealed"].get(&tag_a).is_none(),
        "A stays unsealed: {:?}",
        v["accumulators"]
    );
    assert_eq!(
        v["accumulators"]["current_gross"]["records"], 5,
        "sealed gross intact: {:?}",
        v["accumulators"]
    );
    // Repair: the valid successor seals A honestly.
    let mut env1 = snapshot::test_envelope(1, 0, run_b, 10);
    env1["stream_gross_close"] = new46_valid_drops(1, 10);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    p3.build_service().expect("repaired successor seals A");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(
        v["accumulators"]["sealed"][&tag_a]["tail_note"],
        serde_json::json!(snapshot::NOTE_SEALED_FROM_CLOSE),
        "the honest note survives restart: {:?}",
        v["accumulators"]["sealed"][&tag_a]
    );
}

#[test]
fn newp2b_summary_before_window_preserves_one_gross() {
    // P2fix3 NEW-P2b: when the summary arrives BEFORE the run's
    // windows, the later seal-from-close reconciles (compare-
    // then-mark) instead of silently dropping the close gross —
    // exactly one gross survives, with provenance. Two builds:
    // build 1 adopts T's summary while S is current (T has no
    // windows yet); build 2 folds T's windows, then U seals T.
    use osslscope::presentation::snapshot;
    let case = |close: u64, expect: u64, what: &str| {
        let dir = out_dir(&format!("newp2b-order-{what}"));
        let run_s = serde_json::json!({"pid": 1, "starttime": 3, "boot_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"});
        let run_t = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"});
        let run_u = serde_json::json!({"pid": 1, "starttime": 4, "boot_id": "cccccccc-dddd-eeee-ffff-000000000000"});
        std::fs::write(
            dir.join("run-summary.json"),
            serde_json::json!({
                "schema": "service-run-v1",
                "generation": 0,
                "run_id": {"pid": 1, "starttime": 2, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
                "stream_configured": true,
                "stream_drops": {"records": 8, "bytes": 80, "by_reason": {"queue_full": {"records": 8, "bytes": 80}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}},
            })
            .to_string(),
        )
        .unwrap();
        let env_s = snapshot::test_envelope(0, 0, run_s, 10);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env_s).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
        // T's windows (close gross) arrive after T's summary; U
        // seals T.
        let mut env_t = snapshot::test_envelope(1, 0, run_t, 10);
        env_t["stream_gross_close"] = serde_json::json!({"records": close, "bytes": close * 10, "by_reason": {"queue_full": {"records": close, "bytes": close * 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
        env_t["stream_configured"] = serde_json::json!(true);
        let env_u = snapshot::test_envelope(2, 0, run_u, 10);
        std::fs::write(
            dir.join("window-0000000001.json"),
            serde_json::to_string(&env_t).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("window-0000000002.json"),
            serde_json::to_string(&env_u).unwrap(),
        )
        .unwrap();
        let snap = p.build_service().unwrap();
        let drops = snap.stream.as_ref().expect("stream configured").drops;
        assert_eq!(drops.records, expect, "{what}: surviving gross");
        assert!(
            snap.unknown.iter().any(|e| e.path == "stream.drops"
                && e.reason == "unstable_snapshot"
                && e.note
                    .as_deref()
                    .is_some_and(|n| n.contains("summary_mismatch"))),
            "{what}: mismatch flagged: {:?}",
            snap.unknown
                .iter()
                .map(|e| (&e.path, &e.reason, &e.note))
                .collect::<Vec<_>>()
        );
    };
    // Close 10 over summary 8 → sealed rises to 10 (pre-fix the 10
    // vanishes and 8 stands).
    case(10, 10, "close-above");
    // Close 5 under summary 8 → sealed keeps 8 (epoch counters
    // never decrease) + mismatch (pre-fix silent).
    case(5, 8, "close-below");
}

#[test]
fn newp2b_current_run_summary_cross_checked_strictly() {
    // P2fix3 NEW-P2b: a current-run summary cross-checks STRICTLY
    // against the last folded close — a UNIFORM difference (all
    // above or all below) flags like a mixed one; only an exact
    // match merges clean.
    use osslscope::presentation::snapshot;
    let case = |close: u64, summary: u64, expect_flag: bool, what: &str| {
        let dir = out_dir(&format!("newp2b-strict-{what}"));
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
        env["stream_gross_close"] = serde_json::json!({"records": close, "bytes": close * 10, "by_reason": {"queue_full": {"records": close, "bytes": close * 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
        env["stream_configured"] = serde_json::json!(true);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("run-summary.json"),
            serde_json::json!({
                "schema": "service-run-v1",
                "generation": 0,
                "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"},
                "stream_configured": true,
                "stream_drops": {"records": summary, "bytes": summary * 10, "by_reason": {"queue_full": {"records": summary, "bytes": summary * 10}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}},
            })
            .to_string(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let snap = p.build_service().unwrap();
        let flagged = snap.unknown.iter().any(|e| {
            e.path == "stream.drops"
                && e.reason == "unstable_snapshot"
                && e.note.as_deref() == Some("summary_mismatch")
        });
        assert_eq!(
            flagged, expect_flag,
            "{what}: close={close} summary={summary}"
        );
        // The surviving gross is the max either way (epoch
        // counters never decrease).
        let drops = snap.stream.as_ref().expect("stream configured").drops;
        assert_eq!(drops.records, close.max(summary), "{what}: gross");
    };
    case(5, 8, true, "uniform-above-flags");
    case(8, 5, true, "uniform-below-flags");
    case(8, 8, false, "exact-match-clean");
}

#[test]
fn new2_restore_rejects_unbound_watermark() {
    // P2fix3 NEW-2: restore binds the watermark to the restored
    // latest window — a hash-valid watermark unrelated to
    // latest.seq/generation (or a latest/watermark presence
    // mismatch) refuses loudly, never applies.
    use osslscope::presentation::snapshot;
    let dir = out_dir("new2-binding");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    for seq in 0..=1u64 {
        let env = snapshot::test_envelope(seq, 0, run.clone(), 10);
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    let retamper = |f: &dyn Fn(&mut serde_json::Value)| {
        let body = std::fs::read(&ckpt).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        f(&mut v);
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hash = snapshot::sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hash));
        std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    // Sanity: the untampered checkpoint restores.
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    // Watermark unrelated to latest.seq.
    retamper(&|v| {
        v["watermark_seq"] = serde_json::json!(99u64);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "watermark unrelated to latest.seq must refuse"
    );
    // Generation unrelated to latest.generation.
    retamper(&|v| {
        v["watermark_seq"] = serde_json::json!(1u64);
        v["generation"] = serde_json::json!(99u64);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "generation unrelated to latest must refuse"
    );
    // Latest dropped but watermark kept (presence mismatch).
    retamper(&|v| {
        v["generation"] = serde_json::json!(0u64);
        v["accumulators"]["latest"] = serde_json::Value::Null;
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "latest/watermark presence mismatch must refuse"
    );
}

#[test]
fn new2_snapshot_validates_before_checkpoint_commits() {
    // P2fix3 NEW-2: the completed snapshot validates BEFORE the
    // checkpoint commits — the sequence never reuses across a
    // restart (each build's snapshot_seq is used once).
    use osslscope::presentation::snapshot;
    let dir = out_dir("new2-order");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let env = snapshot::test_envelope(0, 0, run, 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        let s0 = p.build_service().unwrap();
        let s1 = p.build_service().unwrap();
        assert_eq!((s0.snapshot_seq, s1.snapshot_seq), (0, 1));
    }
    // Restart: the next snapshot continues the sequence (a
    // commit-before-validate checkpoint would re-serve 1).
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    let s2 = p.build_service().unwrap();
    assert_eq!(s2.snapshot_seq, 2, "sequence never reuses across restart");
}

#[test]
fn new11_absent_ring_is_legacy_but_mistyped_ring_rejects() {
    // P2fix3 NEW-11: an ABSENT legacy `session_loss.ring` reads
    // eight zeros (backward compatible), but a PRESENT ring of
    // the wrong JSON type rejects before publishing or
    // checkpointing a quiet loss state (never silent zeros).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let fold_with_ring = |tag: &str, ring: serde_json::Value| {
        let dir = out_dir(tag);
        let mut p = Presenter::open(&dir, 30).unwrap();
        let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
        let mut end = end_record(4, 5);
        end["session_loss"]["ring"] = ring;
        env["crypto_watch"] = serde_json::json!([end]);
        (p.fold_test_envelope(&env, "00"), p)
    };
    // Absent member: eight legacy zeros (folds + projects).
    {
        let dir = out_dir("new11-absent");
        let mut p = Presenter::open(&dir, 30).unwrap();
        let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
        let mut end = end_record(4, 5);
        end["session_loss"].as_object_mut().unwrap().remove("ring");
        env["crypto_watch"] = serde_json::json!([end]);
        p.fold_test_envelope(&env, "00").unwrap();
        let snap = p.snapshot().unwrap();
        assert_eq!(
            snap.loss.session.as_ref().expect("session").ring,
            [0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
    // Explicit null: REJECTS (P2fix4 NEW-11 — the legacy
    // default is reserved for ABSENT data; a supplied null is a
    // supplied invalid shape, never quiet zeros).
    {
        let (res, _) = fold_with_ring("new11-null", serde_json::Value::Null);
        assert!(res.is_err(), "null ring must reject");
    }
    // Present-but-mistyped: rejects (string, number, object —
    // never quiet zeros).
    for (what, ring) in [
        ("string", serde_json::json!("nope")),
        ("number", serde_json::json!(7)),
        ("object", serde_json::json!({"lanes": 8})),
        ("short-array", serde_json::json!([1, 2, 3])),
        (
            "non-u64-lane",
            serde_json::json!([0, 0, 0, 0, 0, 0, 0, "x"]),
        ),
    ] {
        let (res, _) = fold_with_ring(&format!("new11-bad-{what}"), ring);
        assert!(res.is_err(), "{what} ring must reject");
    }
    // Present-but-nonobject session_loss: rejects (string,
    // number, array, null — never skipped). Absent stays
    // skipped (no loss evidence on the record).
    for (what, loss) in [
        ("string", serde_json::json!("nope")),
        ("number", serde_json::json!(7)),
        ("array", serde_json::json!([1])),
        ("null", serde_json::Value::Null),
    ] {
        let dir = out_dir(&format!("new11-badloss-{what}"));
        let mut p = Presenter::open(&dir, 30).unwrap();
        let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
        let mut end = end_record(4, 5);
        end["session_loss"] = loss;
        env["crypto_watch"] = serde_json::json!([end]);
        assert!(
            p.fold_test_envelope(&env, "00").is_err(),
            "{what} session_loss must reject"
        );
    }
    {
        let dir = out_dir("new11-noloss");
        let mut p = Presenter::open(&dir, 30).unwrap();
        let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
        let mut end = end_record(4, 5);
        end.as_object_mut().unwrap().remove("session_loss");
        env["crypto_watch"] = serde_json::json!([end]);
        p.fold_test_envelope(&env, "00")
            .expect("absent session_loss skips");
    }
}

#[test]
fn newpriv_counter_names_validate_actual_vocabulary() {
    // P2fix3 PRIVACY as corrected by P2fix4 PRIVACY: counter
    // names validate against the PRODUCER-OWNED vocabulary
    // (closed per-family tables — no free text in recognized
    // families). The colon spelling, engine.poll_loss, and
    // discovery.table_aborted pinned here in fix3 have NO
    // counter producer (FD tags / test-only fixtures) and now
    // reject (see newpriv_producer_owned_vocabularies_are_closed).
    use osslscope::presentation::snapshot;
    let good = [
        "focused.read_unknown",
        "focused.ambiguity",
        "count.owner_failed",
        "lifecycle.polling_fallback",
        "kernel.kptr_restrict",
        "legacy.lowlevel_uninstrumented",
        "engine.observation_unkeyed",
        "snapshot.member_unsealed",
        "snapshot_unstable",
        "capture.no_observation",
        "window.accum_cut",
        "trace_dropped",
        "trace_rejected_unknown_api",
        // Every discovery loss-source word (cross-checks the
        // reverse-mapped table — no drift between the table and
        // the intake rule).
        "ring_alg",
        "ring_row",
        "ring_trip",
        "ring_init",
        "map_query_next",
        "map_trunc",
        "map_calls",
        "map_trip",
        "map_lgcalls",
        "map_termd",
        "pending_init_full",
        "pending_query_full",
        "pending_init_miss",
        "pending_query_miss",
        "init_scan",
        "orphan_row",
        "bad_event",
        "short_event",
        "unknown_kind",
        "map_snapshot",
        "drain_shortfall",
        "evict_failed",
        "maps_read",
        "straggler",
        "baseline_mismatch",
        "unknown_42",
        "typed_pin_missing",
        "focused_dropfail",
    ];
    let bad = [
        "EVP_Digest",
        "x",
        "foo.bar",
        "focused.",
        ".x",
        "a..b",
        "UPPER",
        "has space",
        "semi;colon",
        "trace.",
        "unknown_foo",
        "unknown_",
        "focused..x",
        "count.Upper",
        "count.has-dash",
    ];
    for name in good {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([
            {"name": name, "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_producer(&doc).is_some(),
            "real name {name:?} passes producer intake"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([
            {"name": name, "kind": "loss", "units": "events", "source": "discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_some(),
            "real name {name:?} passes doc_json intake"
        );
    }
    for name in bad {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([
            {"name": name, "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "non-vocabulary name {name:?} must reject (producer)"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([
            {"name": name, "kind": "loss", "units": "events", "source": "discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_none(),
            "non-vocabulary name {name:?} must reject (doc_json)"
        );
    }
}

#[test]
fn newpriv_producer_owned_vocabularies_are_closed() {
    // P2fix4 PRIVACY: counter/reason suffixes validate against
    // PRODUCER-OWNED vocabularies (closed per-family tables cited
    // to emission sites) — no free text in recognized families.
    // Covers every family (incl. the fix3-missed target./
    // traversal. producers) on both presenter paths; phantom
    // members (colon spellings, test-only names, free-text
    // suffixes) reject.
    use osslscope::presentation::snapshot;
    let good = [
        "count.map_insert_dropped",
        "count.lat_bucket_07",
        "count.lat_bucket_15",
        "count.lat_samples",
        "capture.over_budget",
        "discovery.queries_observed",
        "engine.observation_unkeyed",
        "focused.read_unknown",
        "focused_dropfail",
        "focused_read",
        "kernel.kptr_restrict",
        "legacy.meth_uninstrumented",
        "lifecycle.polling_fallback",
        "snapshot.member_unsealed",
        "snapshot_unstable",
        "target.finish_failed",
        "trace_dropped",
        "traversal.storm",
        "traversal.unjoined",
        "window.accum_cut",
        "unknown_7",
        "typed_pin_missing",
        "ring_alg",
    ];
    let bad = [
        // Phantom members (no producer emits these).
        "legacy:lowlevel_uninstrumented",
        "legacy:meth",
        "legacy:lowlevel",
        "legacy.lowlevel",
        "engine.tripwire",
        "engine:tripwire",
        "engine.poll_loss",
        "discovery.table_aborted",
        "focused.test",
        "focused.execution",
        // Free text in recognized families.
        "count.anything_evil",
        "capture.anything_evil",
        "discovery.anything_evil",
        "engine.anything_evil",
        "focused.anything_evil",
        "kernel.anything_evil",
        "legacy.anything_evil",
        "lifecycle.anything_evil",
        "snapshot.anything_evil",
        "target.anything_evil",
        "traversal.anything_evil",
        "window.anything_evil",
        "trace_anything_evil",
        "focused_anything_evil",
        "snapshot_anything_evil",
        "count.lat_bucket_16",
        "count.lat_bucket_1",
        "count.lat_bucket_xx",
        "unknown_12345678901",
    ];
    for name in good {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([
            {"name": name, "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_producer(&doc).is_some(),
            "produced name {name:?} passes producer intake"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([
            {"name": name, "kind": "loss", "units": "events", "source": "discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_some(),
            "produced name {name:?} passes doc_json intake"
        );
    }
    for name in bad {
        let mut doc = snapshot::test_document(3, "complete");
        doc["counters"] = serde_json::json!([
            {"name": name, "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "non-produced name {name:?} must reject (producer)"
        );
        let mut dj = doc_json_shell();
        dj["completeness"]["counters"] = serde_json::json!([
            {"name": name, "kind": "loss", "units": "events", "source": "discovery", "value": 1},
        ]);
        assert!(
            snapshot::signals_from_doc_json(&dj).is_none(),
            "non-produced name {name:?} must reject (doc_json)"
        );
    }
    // Reason scopes: the producer catalogue-identity rule
    // (profile.rs parse_catalogue: 1..=128 alnum + `-_`, no dots).
    let dj_case = |kind: &str, field: &str, value: &str, expect_ok: bool| {
        let mut dj = doc_json_shell();
        dj["completeness"]["status"] = serde_json::json!("PARTIAL");
        dj["completeness"]["reasons"] = serde_json::json!([{ "kind": kind, field: value }]);
        assert_eq!(
            snapshot::signals_from_doc_json(&dj).is_some(),
            expect_ok,
            "doc_json {kind}:{value}"
        );
    };
    dj_case(
        "unknown-denominator",
        "scope",
        "profile:ubuntu2604-openssl355-v1",
        true,
    );
    dj_case("unknown-denominator", "scope", "profile:UPPER-1_v2", true);
    dj_case("unknown-denominator", "scope", "profile:has.dot", false);
    dj_case("unknown-denominator", "scope", "profile:", false);
    dj_case(
        "unknown-denominator",
        "scope",
        &format!("profile:{}", "a".repeat(129)),
        false,
    );
}

#[test]
fn newpriv_reason_suffixes_validate_vocabularies() {
    // P2fix3 PRIVACY: reason suffixes validate per kind (loss
    // counters, scopes, causes) — arbitrary suffixes reject on
    // both presenter paths.
    use osslscope::presentation::snapshot;
    // doc_json path (plain reason objects).
    let dj_case = |kind: &str, field: &str, value: &str, expect_ok: bool| {
        let mut dj = doc_json_shell();
        dj["completeness"]["status"] = serde_json::json!("PARTIAL");
        dj["completeness"]["reasons"] = serde_json::json!([{ "kind": kind, field: value }]);
        assert_eq!(
            snapshot::signals_from_doc_json(&dj).is_some(),
            expect_ok,
            "doc_json {kind}:{value}"
        );
    };
    dj_case("loss", "counter", "focused.read_unknown", true);
    dj_case("loss", "counter", "EVP_Digest", false);
    dj_case("unknown-denominator", "scope", "legacy", true);
    dj_case("unknown-denominator", "scope", "dispatch", true);
    dj_case("unknown-denominator", "scope", "focused.execution", true);
    dj_case("unknown-denominator", "scope", "op:3", true);
    dj_case(
        "unknown-denominator",
        "scope",
        "profile:stock-openssl3-v1",
        true,
    );
    dj_case("unknown-denominator", "scope", "../../etc", false);
    dj_case("unknown-denominator", "scope", "op:abc", false);
    dj_case("unknown-denominator", "scope", "EVIL", false);
    dj_case("visibility-lost", "cause", "corpse_wait", true);
    dj_case("visibility-lost", "cause", "rm-rf", false);
    dj_case("signal-cut", "scope", "ignored", true);
    // Producer path (typed reasons with String suffixes).
    let prod_case = |reason: serde_json::Value, expect_ok: bool, what: &str| {
        let mut doc = snapshot::test_document(3, "partial");
        doc["status"] = serde_json::json!({"Partial": {"reasons": [reason]}});
        assert_eq!(
            snapshot::signals_from_producer(&doc).is_some(),
            expect_ok,
            "producer {what}"
        );
    };
    prod_case(
        serde_json::json!({"Loss": {"counter": "focused.read_unknown", "source": "Discovery", "value": 1}}),
        true,
        "loss:real-counter",
    );
    prod_case(
        serde_json::json!({"Loss": {"counter": "EVP_Digest", "source": "Discovery", "value": 1}}),
        false,
        "loss:arbitrary-counter",
    );
    prod_case(
        serde_json::json!({"UnknownDenominator": {"scope": "legacy"}}),
        true,
        "scope:legacy",
    );
    prod_case(
        serde_json::json!({"UnknownDenominator": {"scope": "../../etc"}}),
        false,
        "scope:arbitrary",
    );
    prod_case(
        serde_json::json!({"VisibilityLost": {"cause": "corpse_wait", "start_ns": 1, "end_ns": 2}}),
        true,
        "cause:corpse_wait",
    );
    prod_case(
        serde_json::json!({"VisibilityLost": {"cause": "rm-rf", "start_ns": 1, "end_ns": 2}}),
        false,
        "cause:arbitrary",
    );
}

#[test]
fn newpriv_boot_id_validates_uuid_format() {
    // P2fix3 PRIVACY: boot IDs validate as kernel UUID text
    // (8-4-4-4-12 hex) — short/arbitrary identities reject at
    // envelope intake, never flow into run tags or resources.
    use osslscope::presentation::snapshot;
    let fold_with_boot = |tag: &str, boot: &str| {
        let dir = out_dir(tag);
        let mut p = Presenter::open(&dir, 30).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": boot});
        let env = snapshot::test_envelope(0, 0, run, 10);
        p.fold_test_envelope(&env, "00")
    };
    fold_with_boot("newpriv-boot-good", "12345678-9abc-def0-1234-56789abcdef0")
        .expect("uuid boot folds");
    for (what, boot) in [
        ("short", "b"),
        ("word", "boot"),
        ("slashes", "/x"),
        ("wrong-groups", "12345678-9abc-def0-1234-56789abcde"),
        ("non-hex", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
        ("empty", ""),
        ("no-dashes", "123456789abcdef0123456789abcdef0"),
    ] {
        assert!(
            fold_with_boot(&format!("newpriv-boot-{what}"), boot).is_err(),
            "{what} boot id must reject"
        );
    }
}

#[test]
fn new4_restore_revalidates_typed_state() {
    // P2fix3 NEW-4: checkpoint restoration applies the SAME typed
    // validation as fresh intake — a restored window carrying a
    // non-vocabulary counter, reason suffix, boot ID, loss cause,
    // or digest refuses instead of applying.
    use osslscope::presentation::snapshot;
    let dir = out_dir("new4-restore");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let env = snapshot::test_envelope(0, 0, run, 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    {
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        p.build_service().unwrap();
    }
    snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("untampered checkpoint restores");
    let retamper = |f: &dyn Fn(&mut serde_json::Value)| {
        let body = std::fs::read(&ckpt).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        f(&mut v);
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hash = snapshot::sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hash));
        std::fs::write(&ckpt, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    // Non-vocabulary counter in restored signals.
    retamper(&|v| {
        v["accumulators"]["latest"]["signals"]["counters"] = serde_json::json!([
            {"name": "EVP_Digest", "kind": "Loss", "units": "Events", "source": "Discovery", "value": 1},
        ]);
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restored bad counter must refuse"
    );
    // Non-vocabulary boot ID in restored run identity.
    retamper(&|v| {
        v["accumulators"]["latest"]["signals"]["counters"] = serde_json::json!([]);
        v["accumulators"]["latest"]["run_id"]["boot_id"] = serde_json::json!("evil");
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restored bad boot id must refuse"
    );
    // Invalid loss cause in restored session loss.
    retamper(&|v| {
        v["accumulators"]["latest"]["run_id"]["boot_id"] =
            serde_json::json!("12345678-9abc-def0-1234-56789abcdef0");
        v["accumulators"]["latest"]["session_loss"] = serde_json::json!({
            "ring": [0, 0, 0, 0, 0, 0, 0, 0],
            "connector_drops": 0, "connector_enobufs": 0, "scan_loss": 0,
            "signal_dropped": 0, "signal_prefix_unwitnessed": 0, "drain_pending": 0,
            "polling_fallback": false, "unattributed_events": 0,
            "admitted_exit_artifacts": 0,
            "lost_intervals": [{"start_tick": 0, "end_tick": 1, "cause": "rm-rf"}],
            "coalesced": 0,
        });
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restored bad loss cause must refuse"
    );
    // Non-digest latest.sha in restored state.
    retamper(&|v| {
        v["accumulators"]["latest"]["session_loss"] = serde_json::Value::Null;
        v["accumulators"]["latest"]["sha"] = serde_json::json!("evil");
    });
    assert!(
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
        "restored bad latest.sha must refuse"
    );
}

#[test]
fn new4_rejected_input_stays_out_of_diagnostics() {
    // P2fix3 NEW-4: rejected input never echoes into terminal
    // diagnostics — the loss-cause refusal names the FIELD, never
    // the supplied value.
    use osslscope::presentation::snapshot;
    let dir = out_dir("new4-noecho");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env = snapshot::test_envelope(0, 0, run, 10);
    let mut end = end_record(4, 5);
    end["session_loss"]["lost_intervals"] =
        serde_json::json!([{"start_tick": 0, "end_tick": 3, "cause": "EVIL_CAUSE_N0ECHO"}]);
    env["crypto_watch"] = serde_json::json!([end]);
    let err = p
        .fold_test_envelope(&env, "00")
        .expect_err("bad cause must reject");
    assert!(
        !err.contains("EVIL_CAUSE_N0ECHO"),
        "rejected value must not echo: {err:?}"
    );
}

#[test]
fn new13_checkpoint_lives_outside_the_producer_dir() {
    // P2fix3 NEW-13: the checkpoint resolves OUTSIDE the producer
    // out-DIR — the trailing-slash default lands beside the
    // directory (never inside it), and an explicit --checkpoint
    // inside the directory refuses loudly (consumers stay
    // read-only on the producer dir).
    use osslscope::presentation::snapshot;
    // Default: trailing slashes strip before the suffix appends.
    assert_eq!(
        snapshot::checkpoint_default(std::path::Path::new("/a/b")),
        std::path::PathBuf::from("/a/b.checkpoint.json")
    );
    assert_eq!(
        snapshot::checkpoint_default(std::path::Path::new("/a/b/")),
        std::path::PathBuf::from("/a/b.checkpoint.json"),
        "trailing slash must not route inside"
    );
    assert_eq!(
        snapshot::checkpoint_default(std::path::Path::new("/a/b//")),
        std::path::PathBuf::from("/a/b.checkpoint.json")
    );
    // Explicit inside path refuses (both spellings).
    let dir = out_dir("new13-inside");
    seed_windows(&dir, 1);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    for ckpt in [dir.join("x.checkpoint.json"), dir.join("sub/x.json")] {
        assert!(
            snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").is_err(),
            "inside checkpoint must refuse: {ckpt:?}"
        );
    }
    // Explicit outside path opens.
    let outside = dir.parent().unwrap().join("new13-outside.checkpoint.json");
    snapshot::Presenter::open_with_checkpoint(&dir, &outside, 1, "export")
        .expect("outside checkpoint opens");
    // Trailing-slash default opens outside too.
    let slashed = format!("{}/", dir.to_str().unwrap());
    let mut p = snapshot::Presenter::open_with_checkpoint(
        std::path::Path::new(&slashed),
        &snapshot::checkpoint_default(std::path::Path::new(&slashed)),
        1,
        "export",
    )
    .expect("trailing-slash default opens");
    p.build_service().unwrap();
}

#[test]
fn new13_executable_trailing_slash_pins_placement() {
    // P2fix3 NEW-13: through the REAL watch binary — `--out DIR/`
    // (trailing slash) checkpoints BESIDE the directory (the dir
    // gains no files — read-only) and serves; an explicit
    // --checkpoint inside the dir exits 1.
    let dir = out_dir("new13-exec");
    seed_windows(&dir, 1);
    let before: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    // Trailing-slash out-DIR through the real binary.
    let slashed = format!("{}/", dir.to_str().unwrap());
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["watch", "--out", &slashed])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "watch serves: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("osslscope-presentation-v1"),
        "frame renders"
    );
    let after: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(before, after, "producer dir gains no files");
    let sibling = format!("{}.checkpoint.json", dir.to_str().unwrap());
    assert!(
        std::path::Path::new(&sibling).exists(),
        "checkpoint lands beside the dir"
    );
    let _ = std::fs::remove_file(&sibling);
    // Explicit inside checkpoint through the real binary: exit 1.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "watch",
            "--out",
            dir.to_str().unwrap(),
            "--checkpoint",
            dir.join("x.checkpoint.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "inside checkpoint refuses");
    assert!(
        !dir.join("x.checkpoint.json").exists(),
        "refused checkpoint writes nothing"
    );
}

#[test]
fn new18_executable_dot_out_relative_checkpoint_refuses() {
    // P2fix4 NEW-18: through the REAL watch binary with the
    // producer directory as the working directory —
    // `--out . --checkpoint ckpt.json` refuses (exit 1, nothing
    // written) — the empty checkpoint parent resolves against
    // the CWD, which IS the producer dir (pre-fix: the guard
    // skips empty parents and the checkpoint lands inside).
    let dir = out_dir("new18-dot");
    seed_windows(&dir, 1);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .current_dir(&dir)
        .args(["watch", "--out", ".", "--checkpoint", "ckpt.json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "dot-out relative checkpoint refuses: {out:?}"
    );
    assert!(
        !dir.join("ckpt.json").exists(),
        "refused checkpoint writes nothing"
    );
    assert!(
        !dir.join("ckpt.checkpoint.tmp").exists(),
        "no tmp residue either"
    );
}

#[test]
fn new18_placement_holds_when_absent_dirs_appear() {
    // P2fix4 NEW-13/NEW-18: placement enforces at EVERY write —
    // an initially absent checkpoint parent defers the open-time
    // check (outage flow), but once the directory becomes
    // available INSIDE the producer dir the write refuses loudly
    // (pre-fix: the write lands inside). The outside control
    // recovers (outage-then-recover still works).
    use osslscope::presentation::snapshot;
    let dir = out_dir("new18-late");
    seed_windows(&dir, 1);
    let ckpt = dir.join("late-sub/ckpt.json");
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export")
        .expect("open defers while the parent is unresolvable");
    std::fs::create_dir_all(dir.join("late-sub")).unwrap();
    assert!(
        p.build_service().is_err(),
        "write-time placement must refuse inside"
    );
    assert!(!ckpt.exists(), "refused write lands nothing");
    // Outside control: absent-then-available outside recovers.
    let dir2 = out_dir("new18-late-ok");
    seed_windows(&dir2, 1);
    let late = dir2.parent().unwrap().join(format!(
        "late-out-ok-{}-{}/ckpt2.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir2, &late, 1, "export")
        .expect("open defers while the parent is unresolvable");
    std::fs::create_dir_all(late.parent().unwrap()).unwrap();
    p2.build_service().expect("outside placement recovers");
    assert!(late.exists(), "outside checkpoint commits");
}

#[test]
fn new34_parent_replacement_fails_closed() {
    // P2fix6 NEW-34: canonical path strings do not hold directory
    // identity — the write anchors to the VALIDATED parent, so a
    // parent replaced after open fails closed (loudly) instead of
    // landing the checkpoint in the substituted directory.
    // Pre-fix: canonicalize-at-write resolves the NEW dir and the
    // write lands there.
    use osslscope::presentation::snapshot;
    let dir = out_dir("new34-replace");
    seed_windows(&dir, 1);
    let parent = dir.parent().unwrap().join(format!(
        "new34-parent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&parent).unwrap();
    let ckpt = parent.join("ckpt.json");
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("first write commits");
    let committed = std::fs::read(&ckpt).unwrap();
    // Replace the parent AFTER open: move the real dir aside and
    // substitute a fresh directory at the same path.
    let aside = dir.parent().unwrap().join(format!(
        "new34-aside-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::rename(&parent, &aside).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    assert!(
        p.build_service().is_err(),
        "a replaced parent must fail the write closed"
    );
    assert!(
        std::fs::read_dir(&parent).unwrap().next().is_none(),
        "nothing lands in the substituted directory"
    );
    assert_eq!(
        std::fs::read(aside.join("ckpt.json")).unwrap(),
        committed,
        "the original checkpoint stands intact"
    );
}

#[test]
fn new34_concurrent_distinct_checkpoints_share_no_staging() {
    // P2fix6 NEW-34: distinct checkpoint filenames sharing a stem
    // share NO staging file, and no writer ever unlinks another
    // writer's stage — two presenters over stem-sharing names in
    // one directory flush concurrently (barrier-started) with
    // every write succeeding and both checkpoints valid. Pre-fix:
    // both names stage through `<stem>.checkpoint.tmp`, so the
    // writers cross-unlink + collide (EEXIST/ENOENT races).
    use osslscope::presentation::snapshot;
    let dir = out_dir("new34-concurrent");
    seed_windows(&dir, 1);
    let parent = dir.parent().unwrap().join(format!(
        "new34-shared-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&parent).unwrap();
    // Same stem, different extensions → the same legacy staging
    // name (`w.checkpoint.tmp`).
    let ckpt_a = parent.join("w.json");
    let ckpt_b = parent.join("w.bak");
    assert_eq!(
        ckpt_a.with_extension("checkpoint.tmp"),
        ckpt_b.with_extension("checkpoint.tmp"),
        "premise: stem-sharing names collide on the legacy staging name"
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker = |dir: std::path::PathBuf, ckpt: std::path::PathBuf| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let mut p =
                snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
            barrier.wait();
            for _ in 0..50 {
                p.build_service().expect("concurrent flush succeeds");
            }
        })
    };
    let a = worker(dir.clone(), ckpt_a.clone());
    let b = worker(dir.clone(), ckpt_b.clone());
    a.join().unwrap();
    b.join().unwrap();
    // Both checkpoints are valid + independent (hash-verified
    // reload, distinct watermark/seq state, no staging residue).
    for ckpt in [&ckpt_a, &ckpt_b] {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], 0);
        assert!(
            v["checkpoint_seq"].as_u64().unwrap() >= 50,
            "every flush committed: {v:?}"
        );
        let _ = snapshot::Presenter::open_with_checkpoint(&dir, ckpt, 1, "export")
            .expect("checkpoint reloads");
    }
    let residue: Vec<_> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "w.json" && n != "w.bak")
        .collect();
    assert!(residue.is_empty(), "no staging residue: {residue:?}");
}

#[test]
fn new26_staging_alias_refuses_without_touching_producer() {
    // P2fix5 NEW-26, mechanism SUPERSEDED [p2fix6 NEW-34]:
    // staging names are unique per (target, pid, seq, attempt)
    // and no writer ever unlinks a foreign stage — so a planted
    // ALIAS (or stale regular file) at the LEGACY predictable
    // `<ckpt>.checkpoint.tmp` name is INERT: the write SUCCEEDS
    // without touching it (success-without-touch replaces
    // refuse-without-touch — the predictable-name redirect
    // threat is eliminated, not refused; the producer files stay
    // untouched either way).
    use osslscope::presentation::snapshot;
    let dir = out_dir("new26-alias");
    seed_windows(&dir, 1);
    let sentinel = dir.join("sentinel.dat");
    std::fs::write(&sentinel, b"producer bytes intact").unwrap();
    let before: Vec<String> = read_names(&dir);
    let ckpt = ckpt_for(&dir);
    let staging = ckpt.with_extension("checkpoint.tmp");
    std::os::unix::fs::symlink(&sentinel, &staging).unwrap();
    let mut p =
        snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").expect("open succeeds");
    p.build_service()
        .expect("unique staging ignores the legacy alias");
    assert!(
        std::fs::symlink_metadata(&staging)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the planted alias stands untouched"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"producer bytes intact",
        "producer files untouched"
    );
    assert!(ckpt.exists(), "checkpoint commits");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
    assert_eq!(v["watermark_seq"], 0);
    assert_eq!(read_names(&dir), before, "no new producer files");
    drop(p);
    // Stale-regular control: residue at the legacy name is never
    // unlinked and never adopted — the write succeeds AND the
    // foreign file stands byte-identical.
    std::fs::remove_file(&staging).unwrap();
    std::fs::write(&staging, b"stale junk").unwrap();
    let mut p2 = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p2.build_service()
        .expect("write succeeds past legacy residue");
    assert!(ckpt.exists(), "checkpoint commits past residue");
    assert_eq!(
        std::fs::read(&staging).unwrap(),
        b"stale junk",
        "foreign residue never unlinked"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"producer bytes intact",
        "producer files untouched"
    );
}

#[test]
fn new18_executable_absent_out_becoming_available_holds() {
    // P2fix4 NEW-18 (binary control): `--out <absent>` with a
    // checkpoint inside-once-created — run 1 outages (no
    // out-DIR), and after the directory becomes available run 2
    // still refuses (placement holds across availability).
    let dir = out_dir("new18-avail");
    let prod = dir.join("prod");
    let ckpt = prod.join("ckpt.json");
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args([
                "watch",
                "--out",
                prod.to_str().unwrap(),
                "--checkpoint",
                ckpt.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let r1 = run();
    assert_eq!(r1.status.code(), Some(1), "absent out-DIR outages");
    std::fs::create_dir_all(&prod).unwrap();
    seed_windows(&prod, 1);
    let r2 = run();
    assert_eq!(
        r2.status.code(),
        Some(1),
        "placement holds once available: {r2:?}"
    );
    assert!(!ckpt.exists(), "refused checkpoint writes nothing");
}

/// Stub OTLP/HTTP collector (P2fix6 NEW-39): counts requests
/// and answers every one with fixed response bytes. Returns the
/// port, the request counter, and a join handle released via the
/// done flag.
fn new39_stub(
    response: &'static [u8],
) -> (
    u16,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    use std::io::Read;
    let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    stub.set_nonblocking(true).unwrap();
    let port = stub.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen2 = seen.clone();
    let done2 = done.clone();
    let handle = std::thread::spawn(move || {
        loop {
            match stub.accept() {
                Ok((mut s, _)) => {
                    use std::io::Write;
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    // Read the request head + its Content-Length body
                    // (so the client never RSTs on a half-read).
                    let mut data = Vec::new();
                    let mut buf = [0u8; 4096];
                    let want = loop {
                        match s.read(&mut buf) {
                            Ok(0) => break 0,
                            Ok(n) => {
                                data.extend_from_slice(&buf[..n]);
                                if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                                    let head = String::from_utf8_lossy(&data[..i]);
                                    let mut len = 0;
                                    for line in head.lines() {
                                        if let Some((k, v)) = line.split_once(':') {
                                            if k.trim().eq_ignore_ascii_case("content-length") {
                                                len = v.trim().parse().unwrap_or(0);
                                            }
                                        }
                                    }
                                    if data.len() >= i + 4 + len {
                                        break len;
                                    }
                                }
                            }
                            Err(_) => break 0,
                        }
                    };
                    let _ = want;
                    seen2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = s.write_all(response);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && !done2.load(std::sync::atomic::Ordering::Relaxed) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
    });
    (port, seen, done, handle)
}

#[test]
fn new39_framing_counts_through_executable() {
    // P2fix6 NEW-39: acceptance/drop/attempt counts through the
    // EXECUTABLE worker (parser + helper pins alone are
    // insufficient) — the real `export` binary pushes against a
    // stub collector: clean responses push silently (acceptance);
    // malformed-2xx framing (transfer coding) drops WITHOUT
    // retry (attempts == drops — the 2xx may have landed, so no
    // redelivery); transport failures still retry to the frozen
    // 5 attempts (the no-retry rule never leaks to transport).
    // Pre-fix: malformed-2xx framing retries 5× per push.
    use std::io::BufRead;
    use std::process::Stdio;
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let run_export = |dir: &std::path::Path,
                      ckpt: &std::path::Path,
                      endpoint: &str,
                      secs: u64|
     -> (Vec<String>, Vec<String>) {
        let mut child = OwnedChild(
            std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
                .args([
                    "export",
                    "--out",
                    dir.to_str().unwrap(),
                    "--listen",
                    &format!("127.0.0.1:{}", free_port()),
                    "--poll-seconds",
                    "1",
                    "--otlp-enable",
                    "--otlp-endpoint",
                    endpoint,
                    "--otlp-push-seconds",
                    "5",
                    "--checkpoint",
                    ckpt.to_str().unwrap(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let stderr = child.0.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send((true, line)).is_err() {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if tx2.send((false, line)).is_err() {
                    break;
                }
            }
        });
        std::thread::sleep(std::time::Duration::from_secs(secs));
        drop(child);
        let mut out_lines = vec![];
        let mut err_lines = vec![];
        while let Ok((is_out, line)) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            if is_out {
                out_lines.push(line);
            } else {
                err_lines.push(line);
            }
        }
        (out_lines, err_lines)
    };
    // Last cumulative worker stats from the stderr notes
    // (`... (pushed=A attempts=B dropped_queue=C dropped_push=D
    // partial_rejected=E malformed_responses=F)`).
    let last_stats = |err: &[String]| -> (u64, u64, u64, u64) {
        let line = err
            .iter()
            .filter(|l| l.contains("otlp push"))
            .last()
            .expect("premise: worker notes exist");
        let num = |key: &str| {
            line.split_whitespace()
                .find_map(|w| w.trim_start_matches('(').strip_prefix(&format!("{key}=")))
                .and_then(|v| v.trim_end_matches(')').parse::<u64>().ok())
                .unwrap()
        };
        (
            num("pushed"),
            num("attempts"),
            num("dropped_push"),
            num("malformed_responses"),
        )
    };
    // Phase A — clean responses push silently (acceptance
    // control: 1 push in 7 s, first-try clean ⇒ no notes).
    {
        let dir = out_dir("new39-exec-clean");
        seed_windows(&dir, 1);
        let ckpt = ckpt_for(&dir);
        let (port, seen, done, stub) =
            new39_stub(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let (_out, err) = run_export(
            &dir,
            &ckpt,
            &format!("http://127.0.0.1:{port}/v1/metrics"),
            8,
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        stub.join().unwrap();
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one push reaches the collector: {err:?}"
        );
        assert!(
            !err.iter().any(|l| l.contains("otlp push")),
            "clean first-try pushes note nothing: {err:?}"
        );
    }
    // Phase B — malformed-2xx framing drops WITHOUT retry
    // (attempts == drops on every push; the stub cross-checks).
    {
        let dir = out_dir("new39-exec-framing");
        seed_windows(&dir, 1);
        let ckpt = ckpt_for(&dir);
        let (port, seen, done, stub) = new39_stub(
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip\r\n\r\n{}",
        );
        let (_out, err) = run_export(
            &dir,
            &ckpt,
            &format!("http://127.0.0.1:{port}/v1/metrics"),
            17,
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        stub.join().unwrap();
        assert!(
            err.iter().any(|l| l.contains("malformed response")),
            "malformed framing notes: {err:?}"
        );
        let (pushed, attempts, dropped, malformed) = last_stats(&err);
        assert_eq!(pushed, 0, "nothing pushes: {err:?}");
        assert!(
            dropped >= 2,
            "several pushes account (17 s window): {err:?}"
        );
        assert_eq!(
            attempts, dropped,
            "one attempt per push (never redelivered): {err:?}"
        );
        assert_eq!(
            malformed, dropped,
            "every drop is a malformed response: {err:?}"
        );
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::Relaxed),
            attempts,
            "the stub cross-checks the attempt count"
        );
    }
    // Phase C — transport failures still retry (control: refused
    // connections exhaust all 5 attempts per push).
    {
        let dir = out_dir("new39-exec-transport");
        seed_windows(&dir, 1);
        let ckpt = ckpt_for(&dir);
        let dead = free_port();
        let (_out, err) = run_export(
            &dir,
            &ckpt,
            &format!("http://127.0.0.1:{dead}/v1/metrics"),
            27,
        );
        let (pushed, attempts, dropped, malformed) = last_stats(&err);
        assert_eq!(pushed, 0, "nothing pushes: {err:?}");
        assert_eq!(
            malformed, 0,
            "transport failures are not malformed: {err:?}"
        );
        assert!(
            dropped >= 1,
            "at least one push drops (27 s window): {err:?}"
        );
        assert_eq!(
            attempts,
            5 * dropped,
            "transport failures exhaust all 5 attempts: {err:?}"
        );
    }
}

#[test]
fn new43_framing_grammar_counts_through_executable() {
    // P2fix7 NEW-43 (+ NEW-24-OPEN, NEW-39-OPEN): field-grammar
    // + body-encoding accounting through the EXECUTABLE worker
    // (unit pins alone are insufficient) — the real `export`
    // binary pushes against a stub collector. Malformed headers
    // after a 2xx (whitespace before the colon) drop WITHOUT
    // retry (attempts == drops — the 2xx may have landed, so no
    // redelivery); invalid response-body encoding drops the same
    // way (one attempt per malformed push — the executable never
    // redelivers it). Pre-fix: the whitespace-before-colon
    // response PUSHES (the name trims and parses).
    use std::io::BufRead;
    use std::process::Stdio;
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let run_export = |dir: &std::path::Path,
                      ckpt: &std::path::Path,
                      endpoint: &str,
                      secs: u64|
     -> (Vec<String>, Vec<String>) {
        let mut child = OwnedChild(
            std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
                .args([
                    "export",
                    "--out",
                    dir.to_str().unwrap(),
                    "--listen",
                    &format!("127.0.0.1:{}", free_port()),
                    "--poll-seconds",
                    "1",
                    "--otlp-enable",
                    "--otlp-endpoint",
                    endpoint,
                    "--otlp-push-seconds",
                    "5",
                    "--checkpoint",
                    ckpt.to_str().unwrap(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let stderr = child.0.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send((true, line)).is_err() {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if tx2.send((false, line)).is_err() {
                    break;
                }
            }
        });
        std::thread::sleep(std::time::Duration::from_secs(secs));
        drop(child);
        let mut out_lines = vec![];
        let mut err_lines = vec![];
        while let Ok((is_out, line)) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            if is_out {
                out_lines.push(line);
            } else {
                err_lines.push(line);
            }
        }
        (out_lines, err_lines)
    };
    let last_stats = |err: &[String]| -> (u64, u64, u64, u64) {
        let line = err
            .iter()
            .filter(|l| l.contains("otlp push"))
            .last()
            .expect("premise: worker notes exist");
        let num = |key: &str| {
            line.split_whitespace()
                .find_map(|w| w.trim_start_matches('(').strip_prefix(&format!("{key}=")))
                .and_then(|v| v.trim_end_matches(')').parse::<u64>().ok())
                .unwrap()
        };
        (
            num("pushed"),
            num("attempts"),
            num("dropped_push"),
            num("malformed_responses"),
        )
    };
    let cases: [(&str, &'static [u8]); 2] = [
        (
            "whitespace-before-colon",
            b"HTTP/1.0 200 OK\r\nContent-Length : 2\r\n\r\n{}".as_slice(),
        ),
        (
            "invalid-body-encoding",
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe".as_slice(),
        ),
    ];
    for (what, response) in cases {
        let dir = out_dir(&format!("new43-exec-{what}"));
        seed_windows(&dir, 1);
        let ckpt = ckpt_for(&dir);
        let (port, seen, done, stub) = new39_stub(response);
        let (_out, err) = run_export(
            &dir,
            &ckpt,
            &format!("http://127.0.0.1:{port}/v1/metrics"),
            13,
        );
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        stub.join().unwrap();
        assert!(
            err.iter().any(|l| l.contains("malformed response")),
            "{what} notes malformed responses: {err:?}"
        );
        let (pushed, attempts, dropped, malformed) = last_stats(&err);
        assert_eq!(pushed, 0, "{what}: nothing pushes: {err:?}");
        assert!(
            dropped >= 2,
            "{what}: several pushes account (13 s window): {err:?}"
        );
        assert_eq!(
            attempts, dropped,
            "{what}: one attempt per push (never redelivered): {err:?}"
        );
        assert_eq!(
            malformed, dropped,
            "{what}: every drop is a malformed response: {err:?}"
        );
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::Relaxed),
            attempts,
            "{what}: the stub cross-checks the attempt count"
        );
    }
}

#[test]
fn new51_canonical_discriminator_binds_per_shape() {
    // P2fix8 NEW-51 (+ GATE29-OPEN): validation binds the
    // CANONICAL discriminator per input shape (`schema` for
    // producer docs, `schema_version` for doc_json/raw docs) —
    // a foreign discriminator alias never overrides it, and
    // conflicts + duplicate raw discriminators reject. The
    // bypass (RED pre-fix): a producer-shaped v2.9 document
    // with an added earlier-version alias omits `trace_summary`
    // and enters the fold (the shared selector reads the alias
    // minor 8, so the v2.9 trigger never fires). Post-fix every
    // gate below rejects it while legacy + v2.9 controls pass.
    use osslscope::presentation::snapshot;
    // Bypass shell: producer v2.9, NO trace_summary, alias v2.8.
    let mut bypass = snapshot::test_document(3, "complete");
    bypass["schema"] = serde_json::json!("observed-crypto-v2.9");
    bypass["schema_version"] = serde_json::json!("observed-crypto-v2.8");
    assert!(
        snapshot::signals_from_producer(&bypass).is_none(),
        "producer v2.9 + earlier alias without its section rejects"
    );
    // Legacy control: producer v2.8, no section, no alias —
    // legitimately sectionless (trigger only at 9+).
    let mut legacy = snapshot::test_document(3, "complete");
    legacy["schema"] = serde_json::json!("observed-crypto-v2.8");
    assert!(
        snapshot::signals_from_producer(&legacy).is_some(),
        "producer legacy v2.8 without a section passes"
    );
    // v2.9 control: producer v2.9 WITH its section, no alias.
    let plain = new42_plain_seal();
    let mut v29 = snapshot::test_document(3, "complete");
    v29["schema"] = serde_json::json!("observed-crypto-v2.9");
    v29["trace_summary"] = plain.clone();
    assert!(
        snapshot::signals_from_producer(&v29).is_some(),
        "producer v2.9 with its section passes"
    );
    // Agreeing alias control: producer v2.9 + alias v2.9 WITH
    // its section — the foreign discriminator still rejects
    // (each shape carries exactly its canonical field).
    let mut agree = v29.clone();
    agree["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    assert!(
        snapshot::signals_from_producer(&agree).is_none(),
        "producer v2.9 + agreeing alias rejects"
    );
    // doc_json shape: canonical `schema_version`; a `schema`
    // alias never overrides it.
    let mut d29 = doc_json_shell();
    d29["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    d29["trace_summary"] = plain.clone();
    assert!(
        snapshot::signals_from_doc_json(&d29).is_some(),
        "doc_json v2.9 with its section passes"
    );
    let mut d29_alias = d29.clone();
    d29_alias["schema"] = serde_json::json!("observed-crypto-v2.8");
    assert!(
        snapshot::signals_from_doc_json(&d29_alias).is_none(),
        "doc_json v2.9 + earlier `schema` alias rejects"
    );
    let mut d8 = doc_json_shell();
    d8["schema_version"] = serde_json::json!("observed-crypto-v2.8");
    assert!(
        snapshot::signals_from_doc_json(&d8).is_some(),
        "doc_json legacy v2.8 without a section passes"
    );
    // Checkpoint persistence binds canonical too: the bypass
    // document must reject the WINDOW (never fold + persist a
    // bypassed minor).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("new51-bypass-fold");
    let env = snapshot::test_envelope_with_doc(0, 0, run, bypass);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    assert!(
        p.build_service().is_err(),
        "the bypass document rejects the window (never folds)"
    );
}

#[test]
fn new58_invalid_canonical_version_rejects_without_trace() {
    // P2fix9 NEW-58 (+ GATE29/NEW-51-OPEN): the presenter
    // requires supported version syntax + a valid minor
    // before admission or persistence — a supplied malformed
    // or unsupported canonical value rejects (no
    // invalid→None→admit-sectionless path), through service
    // intake AND both oneshot shapes. Documented legacy forms
    // (absent discriminator, valid pre-9 minors without a
    // section) still pass. Pre-fix: every invalid value below
    // maps to None and admits sectionless (RED).
    use osslscope::presentation::snapshot;
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let bad_values = [
        "observed-crypto-v9.9",
        "observed-crypto-v1.0",
        "observed-crypto-v2.x",
        "observed-crypto-v2.",
        "observed-crypto-v2",
        "v2.9",
        "",
    ];
    // Service intake: a window carrying the invalid producer
    // version rejects (never folds + persists a None minor).
    for bad in bad_values {
        // NOTE: "observed-crypto-v2" (implicit .0) is VALID
        // syntax per the raw gate — it belongs to the legacy
        // controls below, not the reject set.
        if bad == "observed-crypto-v2" {
            continue;
        }
        let dir = out_dir(&format!("new58-service-{bad}"));
        let mut doc = snapshot::test_document(3, "complete");
        doc["schema"] = serde_json::json!(bad);
        let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), doc);
        std::fs::write(
            dir.join("window-0000000000.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
        let ckpt = ckpt_for(&dir);
        let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
        assert!(
            p.build_service().is_err(),
            "service intake rejects canonical {bad:?}"
        );
    }
    // Non-string canonicals reject on every path.
    for (what, raw) in [
        ("null", serde_json::json!(null)),
        ("number", serde_json::json!(9)),
        ("bool", serde_json::json!(true)),
        ("array", serde_json::json!([])),
        ("object", serde_json::json!({})),
    ] {
        let mut doc = snapshot::test_document(3, "complete");
        doc["schema"] = raw.clone();
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "producer-shaped {what} canonical rejects"
        );
        assert!(
            snapshot::Presenter::oneshot(&doc).is_err(),
            "producer oneshot rejects {what} canonical"
        );
        let mut dd = doc_json_shell();
        dd["schema_version"] = raw;
        assert!(
            snapshot::signals_from_doc_json(&dd).is_none(),
            "doc_json {what} canonical rejects"
        );
        assert!(
            snapshot::Presenter::oneshot(&dd).is_err(),
            "doc_json oneshot rejects {what} canonical"
        );
    }
    // String rejects on the direct + oneshot paths too.
    for bad in [
        "observed-crypto-v9.9",
        "observed-crypto-v1.0",
        "observed-crypto-v2.x",
        "observed-crypto-v2.",
        "v2.9",
        "",
    ] {
        let mut doc = snapshot::test_document(3, "complete");
        doc["schema"] = serde_json::json!(bad);
        assert!(
            snapshot::signals_from_producer(&doc).is_none(),
            "producer-shaped {bad:?} rejects"
        );
        assert!(
            snapshot::Presenter::oneshot(&doc).is_err(),
            "producer oneshot rejects {bad:?}"
        );
        let mut dd = doc_json_shell();
        dd["schema_version"] = serde_json::json!(bad);
        assert!(
            snapshot::signals_from_doc_json(&dd).is_none(),
            "doc_json {bad:?} rejects"
        );
        assert!(
            snapshot::Presenter::oneshot(&dd).is_err(),
            "doc_json oneshot rejects {bad:?}"
        );
    }
    // Legacy controls: absent discriminator + valid pre-9
    // minors without a section pass on every path.
    let doc = snapshot::test_document(3, "complete");
    assert!(
        snapshot::signals_from_producer(&doc).is_some(),
        "absent producer discriminator passes"
    );
    assert!(
        snapshot::Presenter::oneshot(&doc).is_ok(),
        "absent-discriminator producer oneshot passes"
    );
    let dd = doc_json_shell();
    assert!(
        snapshot::signals_from_doc_json(&dd).is_some(),
        "absent doc_json discriminator passes"
    );
    assert!(
        snapshot::Presenter::oneshot(&dd).is_ok(),
        "absent-discriminator doc_json oneshot passes"
    );
    for good in [
        "observed-crypto-v2",
        "observed-crypto-v2.0",
        "observed-crypto-v2.8",
    ] {
        let mut doc = snapshot::test_document(3, "complete");
        doc["schema"] = serde_json::json!(good);
        assert!(
            snapshot::signals_from_producer(&doc).is_some(),
            "producer legacy {good:?} passes"
        );
        assert!(
            snapshot::Presenter::oneshot(&doc).is_ok(),
            "producer oneshot legacy {good:?} passes"
        );
        let mut dd = doc_json_shell();
        dd["schema_version"] = serde_json::json!(good);
        assert!(
            snapshot::signals_from_doc_json(&dd).is_some(),
            "doc_json legacy {good:?} passes"
        );
        assert!(
            snapshot::Presenter::oneshot(&dd).is_ok(),
            "doc_json oneshot legacy {good:?} passes"
        );
    }
    // Service-intake legacy control: v2.8 without a section
    // folds + persists its minor.
    let dir = out_dir("new58-service-legacy");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.8");
    let env = snapshot::test_envelope_with_doc(0, 0, run, doc);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = snapshot::Presenter::open_with_checkpoint(&dir, &ckpt, 1, "export").unwrap();
    p.build_service().expect("service intake folds legacy v2.8");
}

#[test]
fn new51_duplicate_raw_discriminators_reject() {
    // P2fix8 NEW-51: duplicate raw discriminator members reject
    // BEFORE normalization (last-wins must not pick one version
    // for the trigger). Pre-fix: the duplicated member
    // last-wins into a typed-valid shape and raw intake accepts
    // (RED).
    let plain = new42_plain_seal();
    let complete = serde_json::json!([new37_complete_row(20, false, false, false)]);
    let good_text = new37_doc_text(&plain, &complete);
    osslscope::schema::check_v2_document_text(&good_text).expect("premise: valid text passes");
    // Duplicate the top-level `schema_version` (first v2.8, then
    // the original v2.9 — last-wins would read 9 and pass).
    let dup = good_text.replacen(
        "\"schema_version\"",
        "\"schema_version\":\"observed-crypto-v2.8\",\"schema_version\"",
        1,
    );
    assert_ne!(dup, good_text, "premise: the text gained a member");
    assert!(
        osslscope::schema::check_v2_document_text(&dup).is_err(),
        "raw intake rejects duplicate discriminators"
    );
}

#[test]
fn new52_ignored_header_control_counts_through_executable() {
    // P2fix8 NEW-52 (+ NEW-P2a-OPEN, NEW-8-OPEN, NEW-39-OPEN,
    // NEW-43-OPEN): a recognized 2xx with an invalid control
    // (NUL) in an IGNORED header value through the EXECUTABLE
    // worker — the real `export` binary pushes against a stub
    // collector. One malformed drop per push, zero redelivery
    // (attempts == drops, every drop malformed, nothing pushes,
    // the stub cross-checks the attempt count). Pre-fix: the
    // NUL survives decoding and the push SUCCEEDS (RED).
    use std::io::BufRead;
    use std::process::Stdio;
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = out_dir("new52-exec-nul");
    seed_windows(&dir, 1);
    let ckpt = ckpt_for(&dir);
    let response: &'static [u8] =
        b"HTTP/1.0 200 OK\r\nX-Trace: a\x00b\r\nContent-Length: 2\r\n\r\n{}";
    let (port, seen, done, stub) = new39_stub(response);
    let mut child = OwnedChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
            .args([
                "export",
                "--out",
                dir.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{}", free_port()),
                "--poll-seconds",
                "1",
                "--otlp-enable",
                "--otlp-endpoint",
                &format!("http://127.0.0.1:{port}/v1/metrics"),
                "--otlp-push-seconds",
                "5",
                "--checkpoint",
                ckpt.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let stderr = child.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send((true, line)).is_err() {
                break;
            }
        }
    });
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if tx2.send((false, line)).is_err() {
                break;
            }
        }
    });
    std::thread::sleep(std::time::Duration::from_secs(13));
    drop(child);
    let mut err_lines = vec![];
    while let Ok((is_out, line)) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
        if !is_out {
            err_lines.push(line);
        }
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    stub.join().unwrap();
    assert!(
        err_lines.iter().any(|l| l.contains("malformed response")),
        "notes malformed responses: {err_lines:?}"
    );
    let line = err_lines
        .iter()
        .filter(|l| l.contains("otlp push"))
        .last()
        .expect("premise: worker notes exist");
    let num = |key: &str| {
        line.split_whitespace()
            .find_map(|w| w.trim_start_matches('(').strip_prefix(&format!("{key}=")))
            .and_then(|v| v.trim_end_matches(')').parse::<u64>().ok())
            .unwrap()
    };
    let (pushed, attempts, dropped, malformed) = (
        num("pushed"),
        num("attempts"),
        num("dropped_push"),
        num("malformed_responses"),
    );
    assert_eq!(pushed, 0, "nothing pushes: {err_lines:?}");
    assert!(
        dropped >= 2,
        "several pushes account (13 s window): {err_lines:?}"
    );
    assert_eq!(
        attempts, dropped,
        "one attempt per push (never redelivered): {err_lines:?}"
    );
    assert_eq!(
        malformed, dropped,
        "every drop is a malformed response: {err_lines:?}"
    );
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        attempts,
        "the stub cross-checks the attempt count"
    );
}

#[test]
fn export_serves_scrapes_between_collection_ticks() {
    // P2fix2 item 21 (codex NEW-P2a): scrape serving never pauses
    // between collection ticks — with a 10 s poll cadence, a scrape
    // mid-sleep answers immediately (not at the next tick).
    use osslscope::presentation::export;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("serve-gap");
    seed_windows(&dir, 1);
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 10,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // First collection + margin, then scrape mid-sleep (t≈2 of a
    // 10 s tick).
    std::thread::sleep(std::time::Duration::from_secs(2));
    let t0 = std::time::Instant::now();
    let body = scrape(port, "/metrics");
    let dt = t0.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    assert!(body.contains("200 OK"), "scrape status: {body:?}");
    assert!(
        dt < std::time::Duration::from_secs(5),
        "scrape must not wait for the next tick: {dt:?}"
    );
}

#[test]
fn stale_otlp_push_carries_fresh_sample_time() {
    // P2fix2 item 21: a stale last-good push samples NOW — the
    // payload's point timestamps sit at the push instant (within
    // seconds of arrival), never at the stale production time,
    // while the age gauge still tells the staleness honestly.
    use osslscope::presentation::export;
    use std::io::{Read, Write};
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("otlp-fresh");
    seed_windows(&dir, 1);
    let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<(u64, String)>::new()));
    let seen2 = seen.clone();
    let stub_stop = Arc::new(AtomicBool::new(false));
    let stub_stop2 = stub_stop.clone();
    let stub_handle = std::thread::spawn(move || {
        stub.set_nonblocking(true).unwrap();
        while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match stub.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let arrival = osslscope::presentation::snapshot::wall_ns();
                    seen2
                        .lock()
                        .unwrap()
                        .push((arrival, String::from_utf8_lossy(&buf[..n]).into_owned()));
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 30,
                otlp: Some(export::OtlpConfig {
                    endpoint: format!("http://127.0.0.1:{stub_port}/v1/metrics"),
                    push_secs: 5,
                }),
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // One push cycle (5 s floor) + margin: the pushed snapshot was
    // produced at t≈0 and pushed at t≈5 (5 s stale).
    std::thread::sleep(std::time::Duration::from_secs(8));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    stub_handle.join().unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "collector stub saw no push");
    let (arrival_ns, req) = &seen[0];
    let payload = req.split("\r\n\r\n").nth(1).unwrap_or("{}");
    let v: serde_json::Value = serde_json::from_str(payload).expect("otlp json");
    // Every point's timeUnixNano sits at the push instant (fresh),
    // while the age gauge still reports the ~5 s staleness.
    let mut points = 0u32;
    let mut max_skew: u64 = 0;
    for rm in v["resourceMetrics"].as_array().unwrap() {
        for sm in rm["scopeMetrics"].as_array().unwrap() {
            for m in sm["metrics"].as_array().unwrap() {
                for kind in ["sum", "gauge"] {
                    for dp in m[kind]["dataPoints"].as_array().unwrap_or(&vec![]) {
                        let t: u64 = dp["timeUnixNano"].as_str().unwrap().parse().unwrap();
                        max_skew = max_skew.max(arrival_ns.saturating_sub(t));
                        points += 1;
                    }
                }
            }
        }
    }
    assert!(points > 0, "no points pushed");
    assert!(
        max_skew < 3_000_000_000,
        "stale sample timestamps (skew {max_skew}ns)"
    );
}

#[test]
fn otlp_recovery_pushes_frozen_values_with_fresh_timestamps() {
    // P2fix2 item 2 (codex INGESTION-OPEN): recovered OTLP point
    // VALUES + timestamps on the corrected paths — during a
    // window-file outage the pushes carry the frozen last-good
    // values (never extrapolated) with FRESH sample timestamps
    // (never the stale production time); after recovery the values
    // advance.
    use osslscope::presentation::export;
    use std::io::{Read, Write};
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("otlp-recover");
    seed_windows(&dir, 1);
    let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<(u64, String)>::new()));
    let seen2 = seen.clone();
    let stub_stop = Arc::new(AtomicBool::new(false));
    let stub_stop2 = stub_stop.clone();
    let stub_handle = std::thread::spawn(move || {
        stub.set_nonblocking(true).unwrap();
        while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match stub.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    seen2.lock().unwrap().push((
                        osslscope::presentation::snapshot::wall_ns(),
                        String::from_utf8_lossy(&buf[..n]).into_owned(),
                    ));
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: Some(export::OtlpConfig {
                    endpoint: format!("http://127.0.0.1:{stub_port}/v1/metrics"),
                    push_secs: 5,
                }),
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // Push 1 lands (t≈5, calls=10). Then outage before push 2.
    std::thread::sleep(std::time::Duration::from_secs(7));
    assert!(!seen.lock().unwrap().is_empty(), "first push lands");
    std::fs::remove_dir_all(&dir).unwrap();
    // Push 2 fires during the outage (t≈10-11): frozen values.
    std::thread::sleep(std::time::Duration::from_secs(6));
    // Recovery with an advanced window; push 3 carries new values.
    std::fs::create_dir_all(&dir).unwrap();
    seed_windows(&dir, 2);
    std::thread::sleep(std::time::Duration::from_secs(7));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    stub_handle.join().unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 3, "three pushes: {}", seen.len());
    let calls_of = |req: &str| -> u64 {
        let payload = req.split("\r\n\r\n").nth(1).unwrap_or("{}");
        let v: serde_json::Value = serde_json::from_str(payload).unwrap();
        for rm in v["resourceMetrics"].as_array().unwrap() {
            for sm in rm["scopeMetrics"].as_array().unwrap() {
                for m in sm["metrics"].as_array().unwrap() {
                    if m["name"] == "osslscope.epoch.calls" {
                        let dp = &m["sum"]["dataPoints"][0];
                        return dp["asInt"].as_str().unwrap().parse().unwrap();
                    }
                }
            }
        }
        panic!("no epoch.calls in {payload:?}");
    };
    let skew_of = |arrival: u64, req: &str| -> u64 {
        let payload = req.split("\r\n\r\n").nth(1).unwrap_or("{}");
        let v: serde_json::Value = serde_json::from_str(payload).unwrap();
        let mut max_skew = 0u64;
        for rm in v["resourceMetrics"].as_array().unwrap() {
            for sm in rm["scopeMetrics"].as_array().unwrap() {
                for m in sm["metrics"].as_array().unwrap() {
                    for kind in ["sum", "gauge"] {
                        for dp in m[kind]["dataPoints"].as_array().unwrap_or(&vec![]) {
                            let t: u64 = dp["timeUnixNano"].as_str().unwrap().parse().unwrap();
                            max_skew = max_skew.max(arrival.saturating_sub(t));
                        }
                    }
                }
            }
        }
        max_skew
    };
    // Push 1: calls=10, fresh.
    assert_eq!(calls_of(&seen[0].1), 10);
    assert!(skew_of(seen[0].0, &seen[0].1) < 3_000_000_000);
    // Push 2 (outage): values FROZEN at 10, timestamps still fresh.
    assert_eq!(calls_of(&seen[1].1), 10, "outage freezes values");
    assert!(
        skew_of(seen[1].0, &seen[1].1) < 3_000_000_000,
        "outage samples fresh"
    );
    // Push 3 (recovered): values ADVANCE to 30, timestamps fresh.
    assert_eq!(calls_of(&seen[2].1), 30, "recovery advances values");
    assert!(
        skew_of(seen[2].0, &seen[2].1) < 3_000_000_000,
        "recovery samples fresh"
    );
}

#[test]
fn otlp_partial_rejection_accounted_through_the_binary() {
    // P2fix2 item 2 (codex INGESTION-OPEN): partial-rejection
    // accounting on the corrected paths, through the REAL export
    // binary — a stub collector answering partialSuccess lands in
    // the stderr accounting (dropped_push + partial_rejected, never
    // counted as pushed).
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("otlp-partial");
    seed_windows(&dir, 1);
    let stub = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stub_port = stub.local_addr().unwrap().port();
    let stub_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stub_stop2 = stub_stop.clone();
    let stub_handle = std::thread::spawn(move || {
        stub.set_nonblocking(true).unwrap();
        while !stub_stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match stub.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = vec![0u8; 65536];
                    let _ = s.read(&mut buf);
                    let body = r#"{"partialSuccess":{"rejectedDataPoints":"5"}}"#;
                    let _ = s.write_all(
                        format!(
                            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });
    let port = free_port();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args([
            "export",
            "--out",
            dir.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--poll-seconds",
            "1",
            "--otlp-enable",
            "--otlp-endpoint",
            &format!("http://127.0.0.1:{stub_port}/v1/metrics"),
            "--otlp-push-seconds",
            "5",
            "--checkpoint",
            ckpt_for(&dir).to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // One push cycle (5 s floor) + margin, then stop and read the
    // accounting off stderr.
    std::thread::sleep(std::time::Duration::from_secs(8));
    child.kill().unwrap();
    let out = child.wait_with_output().unwrap();
    stub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    stub_handle.join().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("partially rejected") && err.contains("partial_rejected=5"),
        "partial accounting on stderr: {err:?}"
    );
    assert!(
        err.contains("pushed=0") && err.contains("dropped_push=1"),
        "never counted as pushed: {err:?}"
    );
}

#[test]
fn export_serves_positive_service_loss_and_stream_drops() {
    // P2fix2 item 2 (codex INGESTION-OPEN): positive service loss +
    // stream drops flow end-to-end (window files → exporter →
    // scrape) on the corrected paths — loss evidence is never a
    // silent zero.
    use osslscope::presentation::export;
    use std::sync::{Arc, atomic::AtomicBool};
    let dir = out_dir("loss-drops");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env = snapshot::test_envelope(0, 0, run, 10);
    let mut end = end_record(4, 5);
    end["session_loss"]["lost_intervals"] =
        serde_json::json!([{"start_tick": 0, "end_tick": 3, "cause": "ring_loss"}]);
    env["crypto_watch"] = serde_json::json!([seal_record(9, 9, 1, "ring_loss"), end]);
    env["stream_gross_close"] = serde_json::json!({"records": 7, "bytes": 70, "by_reason": {"queue_full": {"records": 7, "bytes": 70}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    let port = free_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let out = dir.clone();
    let checkpoint = ckpt_for(&dir);
    let handle = std::thread::spawn(move || {
        export::serve_with_shutdown(
            export::Options {
                out,
                listen: format!("127.0.0.1:{port}"),
                poll_secs: 1,
                otlp: None,
                checkpoint: Some(checkpoint),
            },
            stop2,
            None,
        )
    });
    // P2fix3 NEW-1: the listener serves before the first
    // publish — wait for CONTENT, not just a "# EOF" page (the
    // pre-publish page is well-formed but empty).
    let mut body = String::new();
    for _ in 0..50 {
        if let Ok(b) = std::panic::catch_unwind(|| scrape(port, "/metrics")) {
            body = b;
            if body.contains("# EOF") && body.contains("osslscope_loss_events_total") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(handle.join().unwrap(), std::process::ExitCode::SUCCESS);
    assert!(body.contains("200 OK"), "scrape status: {body:?}");
    let loss_line = body
        .lines()
        .find(|l| l.starts_with("osslscope_loss_events_total") && l.contains("ring_loss"))
        .expect("loss metric flows");
    let loss_value: u64 = loss_line
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(loss_value, 1, "ring_loss folds exactly once: {body:?}");
    let drops_line = body
        .lines()
        .find(|l| l.starts_with("osslscope_stream_drops_total") && l.contains("queue_full"))
        .expect("stream drops flow");
    let drops_value: u64 = drops_line
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(drops_value, 7, "queue_full drops flow: {body:?}");
}

#[test]
fn retention_hole_survives_mid_scan_generation_reset() {
    // P2fix2 item 13 (codex NEW-P2c): a retention hole detected
    // during the scan (missing seq 6 below) survives the
    // generation reset its own scan triggers (window 5 gen 0,
    // window 7 gen 1) — the epoch accumulators flag
    // unstable_snapshot (just-detected recovery evidence is never
    // erased by a later reset in the same build).
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("retention-reset");
    for (seq, generation) in [(5u64, 0u64), (7u64, 1u64)] {
        let env = snapshot::test_envelope(seq, generation, run.clone(), 10);
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 1, "next_seq": 8, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    let snap = p.build_service().unwrap();
    snap.check_unknown_invariant().unwrap();
    // The retention hole (seq 6) flags the epoch accumulators even
    // though a generation reset ran mid-scan.
    for path in [
        "counts.calls_total",
        "counts.lanes",
        "members.retired_epoch",
    ] {
        assert!(
            snap.unknown
                .iter()
                .any(|e| e.path == path && e.reason == "unstable_snapshot"),
            "hole flags {path}: {:?}",
            snap.unknown
        );
    }
}

#[test]
fn sealed_summary_compares_all_byte_components() {
    // P2fix2 item 13 (codex NEW-P2b): the departed-run
    // compare-then-mark tests ALL record AND byte components — a
    // summary leading only in per-reason bytes still adds its delta
    // (with the mismatch flag), never silently kept-below.
    let run_a = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "dddddddd-eeee-ffff-0000-111111111111"});
    let run_b = serde_json::json!({"pid": 3, "starttime": 4, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let dir = out_dir("adopt-bytes");
    // Run A window 0: close gross records 10, queue_full bytes 50
    // ([p2fix8 NEW-53: self-consistent totals — records 10 /
    // bytes 50 with matching reasons; the summary below still
    // leads on bytes only).
    let mut env0 = snapshot::test_envelope_with_doc(
        0,
        0,
        run_a.clone(),
        snapshot::test_document(5, "complete"),
    );
    env0["stream_gross_close"] = serde_json::json!({"records": 10, "bytes": 50, "by_reason": {"queue_full": {"records": 10, "bytes": 50}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env0["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env0).unwrap(),
    )
    .unwrap();
    // Run B window 1: seals run A from its close on transition.
    let mut env1 = snapshot::test_envelope_with_doc(
        1,
        0,
        run_b.clone(),
        snapshot::test_document(5, "complete"),
    );
    env1["stream_gross_close"] = serde_json::json!({"records": 0, "bytes": 0, "by_reason": {"queue_full": {"records": 0, "bytes": 0}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}});
    env1["stream_configured"] = serde_json::json!(true);
    std::fs::write(
        dir.join("window-0000000001.json"),
        serde_json::to_string(&env1).unwrap(),
    )
    .unwrap();
    // Run A's summary: records agree, queue_full bytes lead (100).
    std::fs::write(
        dir.join("run-summary.json"),
        serde_json::json!({"schema": "service-run-v1", "run_id": {"pid": 1, "starttime": 2, "boot_id": "dddddddd-eeee-ffff-0000-111111111111"}, "generation": 0, "stream_configured": true, "stream_drops": {"records": 10, "bytes": 100, "by_reason": {"queue_full": {"records": 10, "bytes": 100}, "epipe": {"records": 0, "bytes": 0}, "stream_abandoned": {"records": 0, "bytes": 0}}}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": 2, "run_id": {"pid": 3, "starttime": 4, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    let snap = p.build_service().unwrap();
    let drops = snap.stream.as_ref().expect("stream").drops;
    assert_eq!(
        drops.queue_full.bytes, 100,
        "bytes-only lead adds its delta"
    );
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "stream.drops" && e.reason == "unstable_snapshot"),
        "bytes-only disagreement flags: {:?}",
        snap.unknown
    );
}

fn by_api_doc(apis: &[u32]) -> serde_json::Value {
    // A producer-shaped document whose trace plane carries the
    // by-api opt-in over the given covered APIs (REAL fold).
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    p.set_histogram_by_api(true);
    for (i, api) in apis.iter().enumerate() {
        let k = t::PairKey {
            pid: 1,
            tid: 2,
            generation: 1,
            cookie: 9100 + i as u64,
            invocation: i as u64 + 1,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: *api,
            monotonic_ns: 1000 + i as u64 * 100,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: *api,
            monotonic_ns: 1050 + i as u64 * 100,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let mut avail = std::collections::BTreeMap::new();
    for id in 20..=72u32 {
        avail.insert(
            id,
            if apis.contains(&id) {
                "covered".to_string()
            } else {
                "not_attached".to_string()
            },
        );
    }
    let summary = t::summarize(&window, &totals, "latency", Some(&avail));
    summary.validate().expect("test by_api validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    doc["api_activity"] = clean_rows(apis);
    doc
}

#[test]
fn same_window_rerenders_neither_admit_nor_recount() {
    // P2fix1 item 20: admission/omission accounting binds to window
    // identity — re-rendering one finalized window neither admits
    // more opt-in series nor recounts overflow; a new window
    // refreshes the per-window budget (exact recomputed counts).
    let snap_a = Presenter::oneshot(&by_api_doc(&(20..=30u32).collect::<Vec<_>>())).unwrap();
    snap_a.check_unknown_invariant().unwrap();
    let mut budget = budget::Budget::new();
    let first = prometheus::render_with_budget(&snap_a, &mut budget);
    // Default schema here is 155 (159 minus absent P-10×3 and
    // P-03); + 4 whole units (84) admit = 239; the other 51 units
    // (11 apis × 5 classes − 4) omit whole: 51 × 21 = 1071.
    assert_eq!(budget.overflow(), 51 * 21);
    let admitted_len = budget.admitted_len();
    assert_eq!(admitted_len, 155 + 4 * budget::UNIT_SERIES);
    // Same window again: byte-identical, zero new accounting.
    let second = prometheus::render_with_budget(&snap_a, &mut budget);
    assert_eq!(first, second);
    assert_eq!(budget.overflow(), 51 * 21);
    assert_eq!(budget.admitted_len(), admitted_len);
    // A new window (distinct doc sha) refreshes: its 55 fresh units
    // offer against 256 new-series budget → 12 more units admit
    // (252 series), 43 omit (903).
    let snap_b = Presenter::oneshot(&by_api_doc(&(31..=41u32).collect::<Vec<_>>())).unwrap();
    let _ = prometheus::render_with_budget(&snap_b, &mut budget);
    assert_eq!(budget.overflow(), 51 * 21 + 43 * 21);
    assert_eq!(
        budget.admitted_len(),
        admitted_len + 12 * budget::UNIT_SERIES
    );
}

#[test]
fn recovery_flags_survive_first_epoch_adoption() {
    // P2fix1 item 20: torn-checkpoint and retention-gap recovery
    // flags describe the adopted epoch's own prefix — the first
    // epoch adoption must NOT clear them (later adoptions start
    // clean).
    // Pre-retention prefix (oldest window 3 > 0): flags survive.
    let dir = out_dir("pre-retention");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    for seq in 3..5u64 {
        let env = snapshot::test_envelope(seq, 0, run.clone(), 10);
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    snap.check_unknown_invariant().unwrap();
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "pre-retention flag must survive: {:?}",
        snap.unknown
            .iter()
            .map(|e| format!("{}:{}", e.path, e.reason))
            .collect::<Vec<_>>()
    );
    // Mid-epoch retention hole: ranges ride the trace block and the
    // flags survive (window 4 missing between traced windows).
    let dir = out_dir("hole");
    for seq in [3u64, 5u64] {
        let env = snapshot::test_envelope_with_doc(seq, 0, run.clone(), trace_doc(1, false));
        std::fs::write(
            dir.join(format!("window-{seq:010}.json")),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();
    }
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block");
    assert_eq!(trace.unmeasured_seqs, vec![[4u64, 4u64]]);
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "retention-gap flag must survive"
    );
    // Torn checkpoint: flags survive the replay.
    let dir = out_dir("torn");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let env = snapshot::test_envelope(0, 0, run, 10);
    std::fs::write(
        dir.join("window-0000000000.json"),
        serde_json::to_string(&env).unwrap(),
    )
    .unwrap();
    std::fs::write(snapshot::checkpoint_default(&dir), b"{torn-json").unwrap();
    let mut p = Presenter::open(&dir, 30).unwrap();
    let snap = p.build_service().unwrap();
    assert!(
        snap.unknown
            .iter()
            .any(|e| e.path == "counts.calls_total" && e.reason == "unstable_snapshot"),
        "torn-checkpoint flag must survive"
    );
}

#[test]
fn skipped_window_markers_carry_through_the_fold() {
    // P2fix1 item 25: EVERY folded window's loss/cut/
    // partial/fatal/violation markers ride the snapshot (not just
    // the latest); the drain empties when no window folds.
    let dir = out_dir("markers");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    // Window 0: partial (SignalCut reason → loss class).
    let env0 =
        snapshot::test_envelope_with_doc(0, 0, run.clone(), snapshot::test_document(5, "partial"));
    p.fold_test_envelope(&env0, "00").unwrap();
    // Window 1: signal cut.
    let mut env1 = snapshot::test_envelope(1, 0, run.clone(), 7);
    env1["window"]["signal_cut"] = serde_json::json!(true);
    p.fold_test_envelope(&env1, "01").unwrap();
    // Window 2: complete with loss counters.
    let mut doc2 = snapshot::test_document(9, "complete");
    doc2["counters"] = serde_json::json!([{"kind": "Loss", "name": "focused.limit", "units": "Events", "source": "Discovery", "value": 3}]);
    let env2 = snapshot::test_envelope_with_doc(2, 0, run.clone(), doc2);
    p.fold_test_envelope(&env2, "02").unwrap();
    let snap = p.snapshot().unwrap();
    snap.check_unknown_invariant().unwrap();
    assert!(
        snap.markers.iter().any(|m| m.starts_with("partial seq=0 ")),
        "window 0 partial marker: {:?}",
        snap.markers
    );
    assert!(
        snap.markers
            .iter()
            .any(|m| m == "cut seq=1 signal=true accum=false"),
        "window 1 cut marker: {:?}",
        snap.markers
    );
    assert!(
        snap.markers
            .iter()
            .any(|m| m.starts_with("loss seq=2 counters=1")),
        "window 2 loss marker: {:?}",
        snap.markers
    );
    // No new folds: the drain is empty (watch stickiness keeps the
    // old set — no duplicates, no loss).
    let snap2 = p.snapshot().unwrap();
    assert!(snap2.markers.is_empty());
    // The markers render sticky in frames.
    let frame =
        osslscope::presentation::watch::render_frame_with_prev(&snap, None, 2, &snap.markers);
    assert!(frame.contains("MARKER partial seq=0"), "{frame:?}");
    assert!(frame.contains("MARKER cut seq=1"), "{frame:?}");
    assert!(frame.contains("MARKER loss seq=2"), "{frame:?}");
}

#[test]
fn frame_cap_holds_500_with_conserved_overflow() {
    // P2fix1 item 25: the frame is at most 500 lines WITH the
    // overflow line inside the cap (never line 501), and the
    // overflow count is conserved exactly.
    let doc = snapshot::test_document(3, "complete");
    let base = Presenter::oneshot(&doc).unwrap();
    let small_frame = osslscope::presentation::watch::render_frame(&base);
    let small_lines = small_frame.lines().count();
    assert!(small_lines < 500, "{small_lines}");
    assert!(!small_frame.contains("more frame lines"));
    let mut big = base.clone();
    for i in 0..600 {
        big.unknown.push(snapshot::UnknownEntry {
            path: format!("x_{i}"),
            reason: "not_yet_observed".to_string(),
            note: None,
        });
    }
    let frame = osslscope::presentation::watch::render_frame(&big);
    let lines: Vec<&str> = frame.lines().collect();
    assert_eq!(lines.len(), 500);
    let total = small_lines + 600;
    assert_eq!(
        lines[499],
        format!("+{} more frame lines", total - 499),
        "conserved overflow"
    );
}

#[test]
fn accum_cut_oneshot_false_service_independent() {
    // DELTA-5 (ENDORSED, pinned against regression): oneshot
    // accum_cut=false is genuine (single-shot capture has no
    // accumulation phase — never a default masking a cut); the
    // service envelope carries its own independent
    // accumulation-cut field that flows verbatim.
    let doc = snapshot::test_document(3, "complete");
    assert!(doc["window"].get("accum_cut").is_none());
    let snap = Presenter::oneshot(&doc).unwrap();
    assert!(!snap.window.as_ref().unwrap().accum_cut);
    let dir = out_dir("accum-cut");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let mut env = snapshot::test_envelope(0, 0, run.clone(), 10);
    env["window"]["accum_cut"] = serde_json::json!(true);
    p.fold_test_envelope(&env, "00").unwrap();
    let snap = p.snapshot().unwrap();
    assert!(snap.window.as_ref().unwrap().accum_cut);
    let env = snapshot::test_envelope(1, 0, run, 10);
    p.fold_test_envelope(&env, "01").unwrap();
    let snap = p.snapshot().unwrap();
    assert!(!snap.window.as_ref().unwrap().accum_cut);
}

fn trace_doc(pairs: u64, uncertain: bool) -> serde_json::Value {
    // A producer-shaped document carrying a REAL summarized trace
    // plane (certain or uncertainty-tainted, always valid).
    use osslscope::provider_observation::trace as t;
    let mut p = t::TraceProducer::new();
    p.set_mode(t::TRACE_MODE_LATENCY);
    for i in 0..pairs {
        let k = t::PairKey {
            pid: 1,
            tid: 2,
            generation: 1,
            cookie: 9000 + i,
            invocation: i + 1,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000 + i * 100,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1050 + i * 100,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
    }
    if uncertain {
        p.reject_unknown();
    }
    let window = p.close_window(0, 9000, [0; 8]);
    let totals = p.totals();
    let summary = t::summarize(&window, &totals, "latency", None);
    summary.validate().expect("test trace validates");
    let mut doc = snapshot::test_document(3, "complete");
    doc["schema"] = serde_json::json!("observed-crypto-v2.9");
    doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
    doc
}

#[test]
fn service_path_withholds_epoch_trace_series() {
    // DELTA-2 rescope: service windows carry run-cumulative
    // projections, not per-window additive fields — epoch trace
    // series (class_epoch, histograms, by_outcome, P-16/P-17)
    // withhold on the service path even for CERTAIN summaries;
    // the raw per-window block still projects.
    let dir = out_dir("svc-withhold");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    for seq in 0..3u64 {
        let env = snapshot::test_envelope_with_doc(seq, 0, run.clone(), trace_doc(2, false));
        p.fold_test_envelope(&env, "00").unwrap();
    }
    let snap = p.snapshot().unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block projects");
    assert_eq!(trace.paired, 2);
    assert_eq!(trace.mode, "latency");
    // P2fix2 item 24 (codex NEW-3 supersedes the fix1 window-class
    // projection for OPERATIONAL content): the latency summary's
    // window classes withhold while OPEN (raw paired/unpaired/lanes
    // above still project).
    assert!(
        trace.class_window.is_none(),
        "operational window classes withhold while OPEN"
    );
    assert!(!trace.pairing_uncertain);
    assert!(trace.class_epoch.is_none(), "epoch classes withhold");
    assert!(snap.histograms.is_none(), "histograms withhold");
    assert!(snap.counts.by_outcome.is_none(), "by_outcome withholds");
    for path in [
        "trace.class_window",
        "trace.class_epoch",
        "histograms",
        "counts.by_outcome",
    ] {
        assert!(
            snap.unknown
                .iter()
                .any(|e| e.path == path && e.reason == "trace_disabled"),
            "missing unknown entry for {path}"
        );
    }
    let text = prometheus::render(&snap);
    assert!(!text.contains("osslscope_trace_calls_total"), "{text:?}");
    assert!(
        !text.contains("osslscope_dispatch_duration_nanoseconds_bucket"),
        "{text:?}"
    );
}

#[test]
fn uncertain_oneshot_withholds_interpreted_keeps_raw() {
    // Item 3 presenter leg: an uncertain-but-valid summary
    // withholds interpreted distributions and keeps raw evidence
    // through oneshot (latest-wins survives only for clean
    // cumulative snapshots from one verified producer run).
    let doc = trace_doc(3, true);
    let snap = Presenter::oneshot(&doc).unwrap();
    snap.check_unknown_invariant().unwrap();
    let trace = snap.trace.as_ref().expect("raw trace block kept");
    assert_eq!(trace.paired, 3);
    assert!(trace.pairing_uncertain);
    assert!(trace.class_window.is_none() && trace.class_epoch.is_none());
    assert!(snap.histograms.is_none());
    assert!(snap.counts.by_outcome.is_none());
    for path in [
        "trace.class_window",
        "trace.class_epoch",
        "histograms",
        "counts.by_outcome",
    ] {
        assert!(
            snap.unknown
                .iter()
                .any(|e| e.path == path && e.reason == "trace_disabled"),
            "missing unknown entry for {path}"
        );
    }
    // The certain twin flows fully (control).
    let doc = trace_doc(3, false);
    let snap = Presenter::oneshot(&doc).unwrap();
    assert!(snap.trace.as_ref().unwrap().class_epoch.is_some());
    assert!(snap.histograms.is_some());
    assert!(snap.counts.by_outcome.is_some());
}

#[test]
fn invalid_trace_rejects_on_both_presenter_paths() {
    // Item 4 (GATE29): malformed trace sections reject identically
    // on both presenter paths (never a silent None) — same rules
    // as raw intake.
    let mut doc = trace_doc(2, false);
    // Break class/paired conservation.
    doc["trace_summary"]["window"]["class_window"]["success"] = serde_json::json!(99);
    assert!(Presenter::oneshot(&doc).is_err(), "oneshot must reject");
    let dir = out_dir("reject-svc");
    let mut p = Presenter::open(&dir, 30).unwrap();
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let env = snapshot::test_envelope_with_doc(0, 0, run, doc);
    assert!(
        p.fold_test_envelope(&env, "00").is_err(),
        "service must reject"
    );
    // Fallback with operational classes rejects too.
    let mut doc = trace_doc(2, false);
    doc["trace_summary"]["mode"] = serde_json::json!("metadata");
    doc["trace_summary"]["fallback"] = serde_json::json!(true);
    assert!(
        Presenter::oneshot(&doc).is_err(),
        "fallback+operational rejects"
    );
    // doc_json path rejects identically (minimal doc_json shape).
    let mut dj = serde_json::json!({
        "completeness": {"status": "COMPLETE"},
        "legacy_partition": {
            "legacy_exclusive_calls": 3,
            "non_legacy_exclusive_calls": 0,
            "shared_ambiguous_calls": 0,
            "unfenced_tail_calls": 0,
        },
        "sites": [],
    });
    let good = trace_doc(2, false);
    dj["schema_version"] = serde_json::json!("observed-crypto-v2.9");
    dj["trace_summary"] = good["trace_summary"].clone();
    assert!(Presenter::oneshot(&dj).is_ok(), "valid doc_json flows");
    dj["trace_summary"]["window"]["class_window"]["success"] = serde_json::json!(99);
    assert!(Presenter::oneshot(&dj).is_err(), "doc_json must reject");
}

#[test]
fn envelope_raw_duplicate_trace_keys_reject() {
    // Item 23: duplicate keys under document.trace_summary in
    // window BYTES reject the build (the Value path is blind).
    let dir = out_dir("rawdup");
    let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
    let doc = trace_doc(1, false);
    let env = snapshot::test_envelope_with_doc(0, 0, run.clone(), doc);
    let mut text = serde_json::to_string(&env).unwrap();
    // Sanity: the clean bytes build.
    std::fs::write(dir.join("window-0000000000.json"), &text).unwrap();
    std::fs::write(
        dir.join("sequence.json"),
        serde_json::json!({"schema": "service-seq-v1", "generation": 0, "next_seq": 1, "run_id": {"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"}}).to_string(),
    )
    .unwrap();
    let ckpt = ckpt_for(&dir);
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt, 1, "export",
    )
    .unwrap();
    assert!(p.build_service().is_ok(), "clean bytes build");
    // Doubled mode key inside trace_summary convicts.
    let at = text
        .find(r#""mode":"latency""#)
        .expect("premise: mode word");
    text.insert_str(at, r#""mode":"latency","#);
    std::fs::write(dir.join("window-0000000000.json"), &text).unwrap();
    let ckpt2 = std::path::PathBuf::from(format!("{}-t2.checkpoint.json", dir.display()));
    let mut p = osslscope::presentation::snapshot::Presenter::open_with_checkpoint(
        &dir, &ckpt2, 1, "export",
    )
    .unwrap();
    let err = p.build_service().expect_err("dup mode key must reject");
    assert!(err.contains("duplicate field"), "{err}");
    assert!(!err.contains("`mode`"), "key must not echo: {err}");
}
