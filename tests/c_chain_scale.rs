// SPDX-License-Identifier: GPL-3.0-or-later

//! P5a C2–C5: chain scale, hole tolerance, pressure completion.
//!
//! Live legs (NOT RUN in CI: need caps + the chain probe object via
//! OSSL_C1_LIVE=1, OSSL_C1_OBJECT=<harvest BPF .o> — the C1 live
//! lane, shared object). Self-contained fixtures: gcc-built N-alg
//! providers (N generated per leg) + the direct-query python3
//! vehicle (one load, N paced queries — see the C1 file for why
//! fresh-ctx-per-round churn is forbidden).
//!
//! K = number of tail hops (callee invocations): K=1 (C1) walks 2
//! slots/query; K=4 (C2/C4) walks 5; K=8 (C3/C5) walks 9. Each slot
//! carries a distinct 7-leg dispatch table, so rows ==
//! slots_walked × 7 in every leg (no userside dedup collapse).
//!
//! - C2 (`k4_five_slots_per_query`): 20 algs, 4 queries, no hole →
//!   rows == queries × 35.
//! - C3 (`k8_nine_slots_per_query`): 36 algs, 4 queries, no hole →
//!   rows == queries × 63.
//! - C4 (`hole_degrades_rate_not_coverage`): K=4 object, two legs on
//!   the same 20-alg fixture. Leg A (no hole) → ×35. Leg B
//!   (`OSSL_JUMPS_HOLE=1`, probe hook) → the chain stops after hop
//!   0: rows == queries × 14 AND every row hash unique (8 distinct
//!   tables, contiguous — a hole cuts the rate, never the coverage).
//!   The A/B DELTA is the assertion (it is absent pre-hook: RED).
//! - C5 (`k8_pressure_complete`): 64 algs + terminator, 9 queries →
//!   the terminator lands mid-chain on the 8th observed query
//!   (slot 64 via hop 0): rows == 448 exactly, queries ≥ 8,
//!   termination proof, no loss. 9 vehicle rounds tolerate one
//!   H10 stage-2 miss on query 1 either way.
//!
//! Legs serialize on a process-wide lock: `OSSL_JUMPS_HOLE` is
//! process-global (the session reads the test binary's env), so
//! C4's holed leg must not overlap any other leg.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

static LEG_LOCK: Mutex<()> = Mutex::new(());

/// Generate an N-alg provider: per-alg distinct 7-leg digest tables
/// (C1 pattern — real stub legs so fetch validates, distinct
/// addresses so userside never dedups across slots), N live slots +
/// terminator. Names CK000.. (all classify `other`; the join key is
/// (array, index), the row identity (funcid, addr)).
fn prov_src(n: usize) -> String {
    let mut s = String::from(
        r#"
#include <stddef.h>
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#define CK_DIGEST_ALG(id) \
    static void *id##_newctx(void *provctx) \
    { (void)provctx; return malloc(1); } \
    static void id##_freectx(void *ctx) { free(ctx); } \
    static int id##_init(void *ctx, const OSSL_PARAM p[]) \
    { (void)ctx; (void)p; return 1; } \
    static int id##_update(void *ctx, const unsigned char *in, size_t len) \
    { (void)ctx; (void)in; (void)len; return 1; } \
    static int id##_final(void *ctx, unsigned char *out, size_t *outl, \
                          size_t outsz) \
    { (void)ctx; (void)out; (void)outsz; *outl = 0; return 1; } \
    static const OSSL_PARAM *id##_gettable(void *provctx) \
    { (void)provctx; \
      static const OSSL_PARAM known[] = { \
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL), \
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL), \
        OSSL_PARAM_END \
      }; \
      return known; } \
    static int id##_get_params(OSSL_PARAM p[]) \
    { OSSL_PARAM *q; \
      q = OSSL_PARAM_locate(p, OSSL_DIGEST_PARAM_BLOCK_SIZE); \
      if (q != NULL && !OSSL_PARAM_set_size_t(q, 64)) return 0; \
      q = OSSL_PARAM_locate(p, OSSL_DIGEST_PARAM_SIZE); \
      if (q != NULL && !OSSL_PARAM_set_size_t(q, 32)) return 0; \
      return 1; } \
    static const OSSL_DISPATCH id##_dispatch[] = { \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))id##_newctx }, \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))id##_freectx }, \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))id##_init }, \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))id##_update }, \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))id##_final }, \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))id##_gettable }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))id##_get_params }, \
        { 0, NULL } \
    };
"#,
    );
    for i in 0..n {
        s.push_str(&format!("CK_DIGEST_ALG(ck{i:03})\n"));
    }
    s.push_str("static const OSSL_ALGORITHM algs[] = {\n");
    for i in 0..n {
        s.push_str(&format!(
            "    {{ \"CK{i:03}\", \"provider=ckprov\", ck{i:03}_dispatch, NULL }},\n"
        ));
    }
    s.push_str(
        r#"    { NULL, NULL, NULL, NULL },
};
static const OSSL_ALGORITHM *query_fn(void *provctx, int op, int *no_store) {
    (void)provctx;
    if (op == 1) { *no_store = 0; return algs; }
    return NULL;
}
static const OSSL_DISPATCH prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query_fn },
    { 0, NULL },
};
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx) {
    (void)handle; (void)in; (void)provctx;
    *out = prov_dispatch;
    *provctx = NULL;
    return 1;
}
"#,
    );
    s
}

const CK_VEHICLE_PY: &str = r#"
import ctypes, os, sys, time
c = ctypes
lc_path = sys.argv[1]
rounds = int(sys.argv[2])
lc = c.CDLL(lc_path)
lc.OPENSSL_init_crypto.argtypes = [c.c_uint64, c.c_void_p]
lc.OSSL_PROVIDER_load.restype = c.c_void_p
lc.OSSL_PROVIDER_load.argtypes = [c.c_void_p, c.c_char_p]
lc.OSSL_PROVIDER_query_operation.restype = c.c_void_p
lc.OSSL_PROVIDER_query_operation.argtypes = [c.c_void_p, c.c_int, c.POINTER(c.c_int)]
lc.OPENSSL_init_crypto(0, None)
# V2-64: 8s pre-init sleep outlives observer attach (~3.59s measured)
time.sleep(8)
prov = lc.OSSL_PROVIDER_load(None, b"ckprov")
print("CKPROV", "ok" if prov else "FAIL", flush=True)
if not prov:
    time.sleep(5)
    sys.exit(0)
time.sleep(1)
n = 0
for i in range(rounds):
    nc = c.c_int(0)
    addr = lc.OSSL_PROVIDER_query_operation(prov, 1, c.byref(nc))
    slots = -1
    if addr:
        arr = (c.c_void_p * 512).from_address(addr)
        slots = 0
        while arr[slots * 4]:
            slots += 1
        n += 1
    print("CKQUERY", i, slots, flush=True)
    time.sleep(0.3)
print("CKQUERIES", n, flush=True)
time.sleep(5)
"#;

fn gated() -> Option<PathBuf> {
    if std::env::var("OSSL_C1_LIVE").unwrap_or_default() != "1" {
        eprintln!("ck live leg: set OSSL_C1_LIVE=1; skipping");
        return None;
    }
    let object: PathBuf = std::env::var("OSSL_C1_OBJECT")
        .expect("OSSL_C1_OBJECT=<harvest BPF .o>")
        .into();
    Some(object)
}

fn have(cmd: &str, probe: &[&str]) -> bool {
    Command::new(cmd)
        .args(probe)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn system_libcrypto() -> Option<PathBuf> {
    for p in [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib64/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
    ] {
        if Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osslscope-cklive-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn prereqs() -> Option<(PathBuf, PathBuf)> {
    let object = gated()?;
    if !have("gcc", &["--version"]) {
        eprintln!("SKIP ck: no gcc (fixture build unavailable)");
        return None;
    }
    if !have("python3", &["--version"]) {
        eprintln!("SKIP ck: no python3 (vehicle unavailable)");
        return None;
    }
    if !Path::new("/usr/include/openssl/core_dispatch.h").exists() {
        eprintln!("SKIP ck: no system openssl headers");
        return None;
    }
    let Some(libcrypto) = system_libcrypto() else {
        eprintln!("SKIP ck: no system libcrypto");
        return None;
    };
    Some((object, libcrypto))
}

/// One scale leg: build the N-alg fixture, run `rounds` direct
/// queries under harvest, return the doc + vehicle log. `hole`
/// sets the `OSSL_JUMPS_HOLE` probe hook for the harvest run only.
/// Holds the process leg lock (env safety) for the whole leg.
fn run_leg(
    _guard: &MutexGuard<'_, ()>,
    tag: &str,
    object: &Path,
    libcrypto: &Path,
    n_algs: usize,
    rounds: usize,
    hole: Option<u32>,
) -> (serde_json::Value, String, u64) {
    let dir = stage(tag);
    std::fs::write(dir.join("ckprov.c"), prov_src(n_algs)).unwrap();
    let prov = dir.join("ckprov.so");
    let st = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O1"])
        .arg("-o")
        .arg(&prov)
        .arg(dir.join("ckprov.c"))
        .arg("-lcrypto")
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "gcc fixture build failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let vehicle = dir.join("ckvehicle.py");
    std::fs::write(&vehicle, CK_VEHICLE_PY).unwrap();
    let vlog = dir.join("vehicle.log");
    let vlog_file = std::fs::File::create(&vlog).unwrap();
    let verr_file = std::fs::File::create(dir.join("vehicle.err")).unwrap();
    let mut child = Command::new("python3")
        .arg(&vehicle)
        .arg(libcrypto)
        .arg(rounds.to_string())
        .env("OPENSSL_MODULES", &dir)
        .stdin(std::process::Stdio::null())
        .stdout(vlog_file)
        .stderr(verr_file)
        .spawn()
        .expect("spawn ck vehicle");
    let pid = child.id();
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(child.try_wait().unwrap().is_none(), "vehicle exited early");
    let cfg = osslscope::discovery::harvest::Config {
        object_bytes: None,
        pid,
        provider: prov.clone(),
        object: object.to_path_buf(),
        settle: std::time::Duration::from_millis(1500),
        timeout: std::time::Duration::from_secs(30),
        cmdline_marker: None,
        builtin: false,
        legacy: false,
        table: None,
        force_offset: None,
        observed_from_birth: false,
    };
    // SAFETY: the leg lock (`_guard`) serializes every env touch
    // and every harvest run (the only reader) in this process; no
    // other thread touches the environment concurrently.
    unsafe {
        if let Some(h) = hole {
            std::env::set_var("OSSL_JUMPS_HOLE", h.to_string());
        } else {
            std::env::remove_var("OSSL_JUMPS_HOLE");
        }
    }
    // Query volume from the exact in-memory totals, not the doc
    // field: `schema::emit` reports `queries_observed` only when
    // `builtin || partial`, so a clean COMPLETE doc omits it
    // (a leg that reads the doc field goes 0 when no gap fires).
    let (doc, totals) = osslscope::discovery::harvest::run_detailed(&cfg, &|| Ok(()), &|| false)
        .expect("harvest run");
    unsafe {
        std::env::remove_var("OSSL_JUMPS_HOLE");
    }
    let _ = child.kill();
    let _ = child.wait();
    let vlog_text = std::fs::read_to_string(&vlog).unwrap_or_default();
    assert!(
        vlog_text.contains("CKPROV ok"),
        "vehicle failed to load ckprov: {:?}",
        vlog_text
    );
    assert!(
        vlog_text.contains(&format!("CKQUERIES {rounds}")),
        "vehicle did not complete {rounds} queries: {vlog_text:?}"
    );
    (doc, vlog_text, totals.queries_observed)
}

fn dispatch_rows(doc: &serde_json::Value) -> Vec<serde_json::Value> {
    let rows = doc["rows"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        rows.iter().filter(|r| r["funcid"] == 0).count(),
        0,
        "unexpected non-dispatch rows in doc"
    );
    rows
}

/// C2: K=4 hops → 5 slots × 7 legs per query. 20 algs = 4 queries
/// × 5 exactly (terminator never read — same discipline as C1).
#[test]
#[ignore = "live lane only (see module docs)"]
fn k4_five_slots_per_query() {
    let Some((object, libcrypto)) = prereqs() else {
        return;
    };
    let guard = LEG_LOCK.lock().unwrap();
    let (doc, _, queries_raw) = run_leg(&guard, "k4", &object, &libcrypto, 20, 4, None);
    let rows = dispatch_rows(&doc);
    let queries = queries_raw as usize;
    assert!(
        queries >= 2,
        "too few queries observed for a ratio ({queries}), flaky attach?"
    );
    assert_eq!(
        rows.len(),
        queries * 35,
        "K=4 must walk 5 slots x 7 legs per query: rows={} queries={queries}",
        rows.len(),
    );
}

/// C3: K=8 hops → 9 slots × 7 legs per query. 36 algs = 4 × 9
/// exactly (terminator never read).
#[test]
#[ignore = "live lane only (see module docs)"]
fn k8_nine_slots_per_query() {
    let Some((object, libcrypto)) = prereqs() else {
        return;
    };
    let guard = LEG_LOCK.lock().unwrap();
    let (doc, _, queries_raw) = run_leg(&guard, "k8", &object, &libcrypto, 36, 4, None);
    let rows = dispatch_rows(&doc);
    let queries = queries_raw as usize;
    assert!(
        queries >= 2,
        "too few queries observed for a ratio ({queries}), flaky attach?"
    );
    assert_eq!(
        rows.len(),
        queries * 63,
        "K=8 must walk 9 slots x 7 legs per query: rows={} queries={queries}",
        rows.len(),
    );
}

/// C4: a jump-table hole cuts the RATE, never the coverage. Same
/// 20-alg K=4 fixture, two legs: no hole → ×35 (C2 rate); hole at
/// index 1 → the chain stops after hop 0 → ×14 (C1 rate) with every
/// row hash unique (contiguous distinct tables — no repeat walks,
/// no skips). The A/B delta is the assertion.
#[test]
#[ignore = "live lane only (see module docs)"]
fn hole_degrades_rate_not_coverage() {
    let Some((object, libcrypto)) = prereqs() else {
        return;
    };
    let guard = LEG_LOCK.lock().unwrap();
    let (doc_a, _, queries_a_raw) = run_leg(&guard, "hole-a", &object, &libcrypto, 20, 4, None);
    let rows_a = dispatch_rows(&doc_a);
    let queries_a = queries_a_raw as usize;
    assert!(queries_a >= 2, "leg A too few queries ({queries_a})");
    assert_eq!(
        rows_a.len(),
        queries_a * 35,
        "leg A (no hole) must run the C2 rate: rows={} queries={queries_a}",
        rows_a.len(),
    );
    let (doc_b, _, queries_b_raw) = run_leg(&guard, "hole-b", &object, &libcrypto, 20, 4, Some(1));
    let rows_b = dispatch_rows(&doc_b);
    let queries_b = queries_b_raw as usize;
    assert!(queries_b >= 2, "leg B too few queries ({queries_b})");
    assert_eq!(
        rows_b.len(),
        queries_b * 14,
        "leg B (hole@1) must degrade to the C1 rate: rows={} queries={queries_b}",
        rows_b.len(),
    );
    let mut hashes: Vec<&str> = rows_b
        .iter()
        .map(|r| r["addr_hash"].as_str().unwrap_or(""))
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        rows_b.len(),
        "holed chain must walk contiguous distinct tables (no repeats/skips)"
    );
}

/// C5: K=8 pressure to honest completion. 64 algs + terminator, 9
/// vehicle rounds: the 8th observed query walks slot 63 then hits
/// the terminator at 64 mid-chain (hop 0) → proof, freeze, stop.
/// rows == 448 exactly (64 tables × 7, then frozen — later queries
/// re-read the terminator and add nothing), queries ≥ 8 (one H10
/// stage-2 miss tolerated), no loss, no PARTIAL (the schema marks
/// PARTIAL-or-absent: absence is the honest-complete signal).
#[test]
#[ignore = "live lane only (see module docs)"]
fn k8_pressure_complete() {
    let Some((object, libcrypto)) = prereqs() else {
        return;
    };
    let guard = LEG_LOCK.lock().unwrap();
    let (doc, _, queries_raw) = run_leg(&guard, "k8p", &object, &libcrypto, 64, 9, None);
    let rows = dispatch_rows(&doc);
    let queries = queries_raw as usize;
    assert!(
        queries >= 8,
        "C5 needs 8 observed queries to reach the terminator ({queries})"
    );
    assert_eq!(
        rows.len(),
        448,
        "C5 must walk exactly 64 tables then freeze at the terminator: rows={} queries={queries}",
        rows.len(),
    );
    let losses_empty = doc["losses"].as_object().is_none_or(|o| o.is_empty());
    assert!(losses_empty, "C5 must be lossless: {}", doc["losses"]);
    assert!(
        doc["status"].is_null(),
        "C5 must terminate honestly (no PARTIAL): status={} reason={}",
        doc["status"],
        doc["reason"]
    );
}

/// Frozen-shape extension for the K=8 chain: all eight callees
/// present in their section (entry tails `JUMPS[0]`; hop i tails
/// `JUMPS[i+1]`; the last hop advances without tailing).
#[test]
fn ck_frozen_shape_has_eight_callees() {
    let progs = osslscope::loader::HARVEST_PROGS;
    for i in 0..8 {
        let name = format!("c{i}");
        let callee = progs
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("HARVEST_PROGS carries {name}"));
        assert_eq!(callee.section, "uretprobe", "{name} section");
    }
    let maps = osslscope::loader::HARVEST_MAPS;
    assert!(
        maps.iter().any(|m| m.name == "JUMPS"),
        "HARVEST_MAPS carries JUMPS"
    );
    assert!(
        maps.iter().all(|m| m.name != "CURSOR"),
        "no CURSOR at any K: the handoff rides PENDING_QUERY + QUERY_NEXT"
    );
}
