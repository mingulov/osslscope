//! c7 count-side adoption-P6 live leg (NOT RUN in CI: need caps +
//! /opt/openssl-live + OSSL_P6_LIVE=1 on the live lane).
//!
//! One observed process loads provider A (8 digest algs), executes
//! EVP digests through it, unloads it, then loads provider B (16
//! algs) and executes through that. The doc must version the
//! replacement: fenced gen 0 keeps A's exact candidate meaning
//! (no relabel — compared against a pure-A reference run),
//! current carries B, ledger clean, A/A swap rerun exact.

use std::path::{Path, PathBuf};
use std::process::Command;

const OPT_CRYPTO: &str = "/opt/openssl-live/lib64/libcrypto.so";
const OPT_INC: &str = "/opt/openssl-live/include";
const OPT_LIB: &str = "/opt/openssl-live/lib64";
const N_ALGS_A: usize = 8;
const N_ALGS_B: usize = 16;
const ROUNDS: usize = 4;

/// Generate an N-alg provider (c_chain_scale CK pattern): per-alg
/// distinct 7-leg digest tables, N live slots + terminator.
fn prov_src(lower: &str, upper: &str, provider: &str, n: usize) -> String {
    let head = r#"
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
"#
    .replace("CK_DIGEST_ALG", &format!("{upper}_DIGEST_ALG"));
    let mut s = head;
    for i in 0..n {
        s.push_str(&format!("{upper}_DIGEST_ALG({lower}{i:03})\n"));
    }
    s.push_str("static const OSSL_ALGORITHM algs[] = {\n");
    for i in 0..n {
        s.push_str(&format!(
            "    {{ \"{upper}{i:03}\", \"provider={provider}\", {lower}{i:03}_dispatch, NULL }},\n"
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
/// Two-phase EVP vehicle: load provider, fetch alg 000, execute
/// `rounds` real digests (counted leg executions, not just
/// queries), unload; then the same for phase B. Fixed bytes only.
const SWAP_VEHICLE_PY: &str = r#"
import ctypes, sys, time
c = ctypes
lc_path, rounds_a, rounds_b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lc = c.CDLL(lc_path)
lc.OPENSSL_init_crypto.argtypes = [c.c_uint64, c.c_void_p]
lc.OSSL_PROVIDER_load.restype = c.c_void_p
lc.OSSL_PROVIDER_load.argtypes = [c.c_void_p, c.c_char_p]
lc.OSSL_PROVIDER_unload.restype = c.c_int
lc.OSSL_PROVIDER_unload.argtypes = [c.c_void_p]
lc.EVP_MD_fetch.restype = c.c_void_p
lc.EVP_MD_fetch.argtypes = [c.c_void_p, c.c_char_p, c.c_char_p]
lc.EVP_MD_free.argtypes = [c.c_void_p]
lc.EVP_MD_CTX_new.restype = c.c_void_p
lc.EVP_MD_CTX_free.argtypes = [c.c_void_p]
lc.EVP_DigestInit_ex.restype = c.c_int
lc.EVP_DigestInit_ex.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
lc.EVP_DigestUpdate.restype = c.c_int
lc.EVP_DigestUpdate.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
lc.EVP_DigestFinal_ex.restype = c.c_int
lc.EVP_DigestFinal_ex.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_uint)]
lc.OPENSSL_init_crypto(0, None)
time.sleep(3)
MSG = b"p6 known-N payload (fixed bytes, no secrets)"
def phase(name, alg, rounds):
    prov = lc.OSSL_PROVIDER_load(None, name.encode())
    print("CKPHASE", name, "ok" if prov else "FAIL", flush=True)
    if not prov:
        return 0
    md = lc.EVP_MD_fetch(None, alg.encode(), ("provider=%s" % name).encode())
    print("CKFETCH", name, alg, "ok" if md else "FAIL", flush=True)
    if not md:
        return 0
    time.sleep(1)
    n = 0
    for i in range(rounds):
        ctx = lc.EVP_MD_CTX_new()
        out = (c.c_ubyte * 64)()
        outl = c.c_uint(0)
        ok = lc.EVP_DigestInit_ex(ctx, md, None)
        ok = ok and lc.EVP_DigestUpdate(ctx, MSG, len(MSG))
        ok = ok and lc.EVP_DigestFinal_ex(ctx, out, c.byref(outl))
        lc.EVP_MD_CTX_free(ctx)
        if ok:
            n += 1
        time.sleep(0.2)
    lc.EVP_MD_free(md)
    lc.OSSL_PROVIDER_unload(prov)
    print("CKQUERIES", name, n, flush=True)
    return n
na = phase("aprov", "AP000", rounds_a)
nb = phase("bprov", "BP000", rounds_b) if rounds_b > 0 else 0
print("CKSWAP", na, nb, flush=True)
time.sleep(5)
"#;

fn gated() -> Option<()> {
    if std::env::var("OSSL_P6_LIVE").unwrap_or_default() != "1" {
        eprintln!("p6 live leg: set OSSL_P6_LIVE=1; skipping");
        return None;
    }
    Some(())
}

fn have(cmd: &str, probe: &[&str]) -> bool {
    Command::new(cmd)
        .args(probe)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn prereqs() -> Option<PathBuf> {
    gated()?;
    if !have("gcc", &["--version"]) {
        eprintln!("SKIP p6: no gcc");
        return None;
    }
    if !have("python3", &["--version"]) {
        eprintln!("SKIP p6: no python3 (vehicle unavailable)");
        return None;
    }
    if !Path::new("/opt/openssl-live/include/openssl/core_dispatch.h").exists() {
        eprintln!("SKIP p6: no /opt openssl headers");
        return None;
    }
    if !Path::new(OPT_CRYPTO).exists() {
        eprintln!("SKIP p6: no {OPT_CRYPTO}");
        return None;
    }
    Some(PathBuf::from(env!("CARGO_BIN_EXE_osslscope")))
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osslscope-p6live-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn out_dir() -> PathBuf {
    match std::env::var("OSSL_P6_OUT") {
        Ok(d) => {
            let p = PathBuf::from(d);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        Err(_) => stage("out"),
    }
}

/// Build one provider .so against /opt (rpath-pinned).
fn build_prov(dir: &Path, file: &str, lower: &str, upper: &str, provider: &str, n: usize) {
    std::fs::write(
        dir.join(format!("{lower}.c")),
        prov_src(lower, upper, provider, n),
    )
    .unwrap();
    let st = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(dir.join(file))
        .arg(dir.join(format!("{lower}.c")))
        .arg(format!("-I{OPT_INC}"))
        .arg(format!("-L{OPT_LIB}"))
        .arg("-lcrypto")
        .arg(format!("-Wl,-rpath,{OPT_LIB}"))
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "gcc {file} build failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}
/// One observed swap run; returns (doc, vehicle log).
///
/// The target libcrypto is named explicitly (`--provider` +
/// `--builtin`): pre-exec auto-discovery predicts "no NEEDED
/// libcrypto" for the vehicle shape (observed `sh -c ...` resolves
/// to /usr/sbin/sh; the python grandchild dlopens libcrypto at
/// runtime, so it links none either) and refuses the exe with exit
/// 4. In-guest `doctor --exe` on both shapes verdicts FAIL-CLOSED;
/// an explicit-provider probe over `sh -c` reaches INSPECT via
/// symtab. Explicit provider is the product-sanctioned path
/// (`docs/usage.md`); all leg assertions are unaffected.
fn run_swap(
    bin: &Path,
    dir: &Path,
    tag: &str,
    vehicle: &Path,
    rounds_a: usize,
    rounds_b: usize,
) -> (serde_json::Value, String) {
    let doc_path = dir.join(format!("{tag}.json"));
    let vlog_path = dir.join(format!("{tag}.vlog"));
    let prov_lib = format!("{OPT_LIB}/libcrypto.so.3");
    // The vehicle log goes to a file via sh redirect (robust
    // whether or not the product surfaces child stdout).
    let script = format!(
        "python3 '{}' '{}' {} {} > '{}' 2>&1",
        vehicle.to_string_lossy(),
        OPT_CRYPTO,
        rounds_a,
        rounds_b,
        vlog_path.to_string_lossy(),
    );
    let out = Command::new("timeout")
        .arg("400")
        .arg(bin)
        .args([
            "report",
            "--format",
            "json",
            "--out",
            &doc_path.to_string_lossy(),
            "--duration",
            "100",
            "--timeout",
            "120",
            "--provider",
            &prov_lib,
            "--builtin",
            "run",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("OPENSSL_MODULES", dir)
        .output()
        .unwrap();
    let code = out.status.code();
    assert!(
        matches!(code, Some(0) | Some(3)),
        "report run {tag} exit {code:?}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let text = std::fs::read_to_string(&doc_path).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let vlog = std::fs::read_to_string(&vlog_path).unwrap_or_default();
    (doc, vlog)
}

/// Sorted per-site candidate fingerprints (calls excluded: timing
/// varies, meaning must not).
fn candidates_multiset(sites: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = sites
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| serde_json::to_string(&s["candidates"]).unwrap())
        .collect();
    v.sort();
    v
}

fn counter(doc: &serde_json::Value, name: &str) -> Option<u64> {
    doc["completeness"]["counters"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .and_then(|c| c["value"].as_u64())
}

/// P6 live: A->B replacement versions; fenced gen 0 keeps A's exact
/// candidate meaning (no relabel vs the pure-A reference); current
/// carries B; ledger clean; swap rerun exact.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_P6_LIVE=1)"]
fn p6_live_replacement_keeps_old_meaning() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("swap");
    build_prov(&dir, "aprov.so", "ap", "AP", "aprov", N_ALGS_A);
    build_prov(&dir, "bprov.so", "bp", "BP", "bprov", N_ALGS_B);
    let vehicle = dir.join("swap.py");
    std::fs::write(&vehicle, SWAP_VEHICLE_PY).unwrap();
    // Reference: pure-A run (B rounds = 0 skips phase B).
    let (doc_a, vlog_a) = run_swap(&bin, &dir, "p6-refa", &vehicle, ROUNDS, 0);
    assert!(
        vlog_a.contains("CKPHASE aprov ok"),
        "reference vehicle did not load A: {vlog_a:?}"
    );
    assert!(
        !doc_a["sites"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "reference run observed no sites"
    );
    // Swap run + determinism rerun.
    let (doc_s, vlog_s) = run_swap(&bin, &dir, "p6-swap", &vehicle, ROUNDS, ROUNDS);
    assert!(
        vlog_s.contains("CKPHASE aprov ok") && vlog_s.contains("CKPHASE bprov ok"),
        "swap vehicle did not run both phases: {vlog_s:?}"
    );
    let fenced = doc_s["fenced"].as_array().cloned().unwrap_or_default();
    assert!(
        !fenced.is_empty(),
        "no replacement versioned live (fenced empty): status={} reasons={}",
        doc_s["completeness"]["status"],
        doc_s["completeness"]["reasons"],
    );
    let gen0 = fenced
        .iter()
        .find(|g| g["generation"] == 0)
        .expect("gen 0 sealed");
    assert_eq!(
        candidates_multiset(&gen0["sites"]),
        candidates_multiset(&doc_a["sites"]),
        "fenced gen 0 must keep A's exact candidate meaning (no relabel)"
    );
    assert_eq!(
        gen0["sites"].as_array().map(|s| s.len()),
        doc_a["sites"].as_array().map(|s| s.len()),
        "fenced gen 0 must keep A's 8-site shape"
    );
    assert!(
        !doc_s["sites"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "swap run current (B phase) is empty"
    );
    assert_eq!(counter(&doc_s, "count.ledger_delta"), Some(0));
    assert_eq!(counter(&doc_a, "count.ledger_delta"), Some(0));
    let (doc_r, _) = run_swap(&bin, &dir, "p6-rerun", &vehicle, ROUNDS, ROUNDS);
    let calls = |d: &serde_json::Value| {
        let mut v: Vec<u64> = d["sites"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|s| s["calls"].as_u64().unwrap_or(0))
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(calls(&doc_s), calls(&doc_r), "swap rerun must be exact");
    let out = out_dir();
    for f in ["p6-refa.json", "p6-swap.json", "p6-rerun.json"] {
        std::fs::copy(dir.join(f), out.join(f)).unwrap();
    }
}
