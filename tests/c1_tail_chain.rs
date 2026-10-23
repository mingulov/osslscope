//! P5a-C1 tail-call chain probe: one query walks TWO alg slots
//! (entry walks j, callee walks j+1, advance by 2).
//!
//! Live leg (NOT RUN in C1: needs caps + nightly-built probe object
//! via OSSL_C1_LIVE=1, OSSL_C1_OBJECT=<harvest BPF .o>). Self-contained
//! fixtures: gcc-built 8-alg provider + python3 ctypes vehicle making
//! DIRECT OSSL_PROVIDER_query_operation calls (one provider load, then
//! N paced queries); no staged libcrypto needed (file-provider mode
//! resolves the query anchor from the provider's own symtab +
//! init-return walk). Direct calls, not fetch-per-fresh-ctx: every
//! re-load re-runs provider_init, and the session's repeat-init
//! suspect (F-A/A4) retires+rebirths the epoch on every re-init —
//! that round's records then drop as stragglers (observed 17/24 in
//! the red run) and the eviction resets the walk cursor, so a
//! churny vehicle can never exhibit multi-slot progress.
//!
//! Assertion is the rows-per-query RATIO (robust to the H10 stage-2
//! install race on query 1): chain → 14.0, sampler → 7.0 (7 dispatch
//! legs per walked slot, 2 slots vs 1 per query).

use std::path::{Path, PathBuf};
use std::process::Command;

const QUERIES: usize = 4;

/// 8 dummy digest algs with PER-ALG DISTINCT 7-entry dispatch tables:
/// every walked slot emits exactly 7 ROWs, so rows == 7 x slots walked
/// (a shared table would dedupe userside by (funcid, addr) and collapse
/// the ratio — observed 7 rows for 3 queries in the red run). 8 == 2
/// slots x 4 queries exactly: the terminator at slot 8 is never
/// reached, so no query ends early (grow both together). Chain ratio
/// rows/queries = 14, sampler baseline = 7.
const C1_PROV_SRC: &str = r#"
#include <stddef.h>
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
/* Real (stub) digest legs per alg (min-provider.c precedent): fetch
 * validates provider functions, so every table carries full legs.
 * Distinct statics per alg => distinct addresses => no userside
 * (funcid, addr) dedup across slots (ICF is off by default; the 7x
 * sampler-baseline ratio re-verifies distinctness every red run). */
#define C1_DIGEST_ALG(id) \
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
C1_DIGEST_ALG(c1a0)
C1_DIGEST_ALG(c1a1)
C1_DIGEST_ALG(c1a2)
C1_DIGEST_ALG(c1a3)
C1_DIGEST_ALG(c1a4)
C1_DIGEST_ALG(c1a5)
C1_DIGEST_ALG(c1a6)
C1_DIGEST_ALG(c1a7)
static const OSSL_ALGORITHM algs[] = {
    { "C1A0", "provider=c1prov", c1a0_dispatch, NULL },
    { "C1A1", "provider=c1prov", c1a1_dispatch, NULL },
    { "C1A2", "provider=c1prov", c1a2_dispatch, NULL },
    { "C1A3", "provider=c1prov", c1a3_dispatch, NULL },
    { "C1A4", "provider=c1prov", c1a4_dispatch, NULL },
    { "C1A5", "provider=c1prov", c1a5_dispatch, NULL },
    { "C1A6", "provider=c1prov", c1a6_dispatch, NULL },
    { "C1A7", "provider=c1prov", c1a7_dispatch, NULL },
    { NULL, NULL, NULL, NULL },
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
"#;

const C1_VEHICLE_PY: &str = r#"
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
prov = lc.OSSL_PROVIDER_load(None, b"c1prov")
print("C1PROV", "ok" if prov else "FAIL", flush=True)
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
        arr = (c.c_void_p * 64).from_address(addr)
        slots = 0
        while arr[slots * 4]:
            slots += 1
        n += 1
    print("C1QUERY", i, slots, flush=True)
    time.sleep(0.3)
print("C1QUERIES", n, flush=True)
time.sleep(5)
"#;

fn gated() -> Option<PathBuf> {
    if std::env::var("OSSL_C1_LIVE").unwrap_or_default() != "1" {
        eprintln!("c1 live leg: set OSSL_C1_LIVE=1; skipping");
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
    let dir = std::env::temp_dir().join(format!("osslscope-c1live-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[ignore = "live lane only (see module docs)"]
fn c1_two_slots_per_query() {
    let Some(object) = gated() else {
        return;
    };
    if !have("gcc", &["--version"]) {
        eprintln!("SKIP c1: no gcc (fixture build unavailable)");
        return;
    }
    if !have("python3", &["--version"]) {
        eprintln!("SKIP c1: no python3 (vehicle unavailable)");
        return;
    }
    if !Path::new("/usr/include/openssl/core_dispatch.h").exists() {
        eprintln!("SKIP c1: no system openssl headers");
        return;
    }
    let Some(libcrypto) = system_libcrypto() else {
        eprintln!("SKIP c1: no system libcrypto");
        return;
    };
    let dir = stage("chain");
    let src_path = dir.join("c1prov.c");
    std::fs::write(&src_path, C1_PROV_SRC).unwrap();
    let prov = dir.join("c1prov.so");
    let st = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O1"])
        .arg("-o")
        .arg(&prov)
        .arg(&src_path)
        .arg("-lcrypto")
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "gcc fixture build failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let vehicle = dir.join("c1vehicle.py");
    std::fs::write(&vehicle, C1_VEHICLE_PY).unwrap();
    let vlog = dir.join("vehicle.log");
    let vlog_file = std::fs::File::create(&vlog).unwrap();
    let verr_file = std::fs::File::create(dir.join("vehicle.err")).unwrap();
    let mut child = Command::new("python3")
        .arg(&vehicle)
        .arg(&libcrypto)
        .arg(QUERIES.to_string())
        .env("OPENSSL_MODULES", &dir)
        .stdin(std::process::Stdio::null())
        .stdout(vlog_file)
        .stderr(verr_file)
        .spawn()
        .expect("spawn c1 vehicle");
    let pid = child.id();
    // Quiescence window: python is still starting up (no queries yet).
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(child.try_wait().unwrap().is_none(), "vehicle exited early");
    let cfg = osslscope::discovery::harvest::Config {
        object_bytes: None,
        pid,
        provider: prov.clone(),
        object: object.clone(),
        settle: std::time::Duration::from_millis(1500),
        timeout: std::time::Duration::from_secs(25),
        cmdline_marker: None,
        builtin: false,
        legacy: false,
        table: None,
        force_offset: None,
        observed_from_birth: false,
    };
    // Query volume from the exact in-memory totals, not the doc
    // field (R21 finding 6 — same trap c_chain_scale::run_leg
    // documents: a clean COMPLETE doc omits `queries_observed`).
    let (doc, totals) = osslscope::discovery::harvest::run_detailed(&cfg, &|| Ok(()), &|| false)
        .expect("harvest run");
    let _ = child.kill();
    let _ = child.wait();
    let vlog_text = std::fs::read_to_string(&vlog).unwrap_or_default();
    assert!(
        vlog_text.contains("C1PROV ok"),
        "vehicle failed to load c1prov: {:?}",
        vlog_text
    );
    assert!(
        vlog_text.contains(&format!("C1QUERIES {}", QUERIES)),
        "vehicle did not complete {} queries: {:?}",
        QUERIES,
        vlog_text
    );
    let rows = doc["rows"].as_array().cloned().unwrap_or_default();
    let dispatch_rows = rows.iter().filter(|r| r["funcid"] != 0).count();
    let queries = totals.queries_observed as usize;
    assert!(
        queries >= 2,
        "too few queries observed for a ratio ({}), flaky attach?",
        queries
    );
    assert_eq!(
        dispatch_rows,
        queries * 14,
        "chain must walk 2 slots x 7 legs per query (sampler walks 1x7): rows={} queries={}",
        dispatch_rows,
        queries
    );
    assert_eq!(
        rows.len(),
        dispatch_rows,
        "unexpected non-dispatch rows in doc"
    );
}

/// Frozen-shape extension for the C1 probe: the jump table
/// (prog-array) + the first-hop callee (`c0` — renamed from `c_slot`
/// when the chain grew to eight hops in C2–C5; the eight-callee
/// shape lives in the scale file). No handoff map: the chain rides
/// `PENDING_QUERY` + `QUERY_NEXT` (a dedicated 72-byte `CURSOR` was
/// prototyped and rejected — stash materialization breaks the
/// classifier's loop-state merging and the kernel forbids tail calls
/// from subprograms without BTF).
#[test]
fn c1_frozen_shape_has_chain_support() {
    let maps = osslscope::loader::HARVEST_MAPS;
    let jumps = maps
        .iter()
        .find(|m| m.name == "JUMPS")
        .expect("HARVEST_MAPS carries JUMPS");
    assert_eq!(
        (
            jumps.map_type,
            jumps.key_size,
            jumps.value_size,
            jumps.max_entries,
            jumps.flags
        ),
        (3, 4, 4, 8, 0),
        "JUMPS is a prog-array of 8"
    );
    assert!(
        maps.iter().all(|m| m.name != "CURSOR"),
        "no CURSOR: the handoff rides PENDING_QUERY + QUERY_NEXT"
    );
    let progs = osslscope::loader::HARVEST_PROGS;
    let callee = progs
        .iter()
        .find(|p| p.name == "c0")
        .expect("HARVEST_PROGS carries c0");
    assert_eq!(callee.section, "uretprobe");
}

/// R21 finding 6: the c1 leg must read query volume from the
/// exact in-memory totals (`run_detailed`), never the doc field
/// — `schema::emit` reports `queries_observed` only when
/// `builtin || partial`, so a clean COMPLETE doc omits it and a
/// leg reading the field goes 0 (live FAIL). Host-runnable
/// self-scan: this file must not index the doc for it.
#[test]
fn c1_leg_reads_in_memory_totals_not_the_doc_field() {
    let src = std::fs::read_to_string(file!()).unwrap();
    // (Built piecewise so this scan's own source never trips it.)
    let doc_field = ["doc[", "\"queries_observed\"]"].concat();
    assert!(
        !src.contains(&doc_field),
        "c1 leg reads the conditionally-omitted doc field (R21 finding 6)"
    );
    assert!(
        src.contains("run_detailed") && src.contains("totals.queries_observed"),
        "c1 leg must use run_detailed in-memory totals like c_chain_scale::run_leg"
    );
}
