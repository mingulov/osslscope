//! SPDX-License-Identifier: GPL-3.0-or-later
//! Live harvest driver: two-stage attach + ring drain + settle,
//! promoted behavior-identical from the P0-4 spike. The fixture-only
//! `evp_driver` cmdline guard is now a caller-supplied marker
//! (`None` = any target — what `inspect --pid` uses at P1 exit 1).
//!
//! P1 exit 2 adds builtin mode (`--builtin`): single-stage attach to
//! the core-static `ossl_provider_query_operation` resolved via the
//! build-id ladder (no init anchor exists for the in-libcrypto
//! default provider), coverage counters, and PARTIAL documents.
//!
//! P2 migrates load+attach to the raw multi loader (same BPF
//! programs, same cookie id space — P1 goldens match byte-for-byte).
//! Aya stays only for typed map/ringbuf reads over dup'd fds.
use crate::discovery::{builtin, coverage, elf, legacy, maps, schema};
use crate::loader::Loaded;
use anyhow::{Context as _, anyhow, bail};
use aya::maps::{Map, MapData, RingBuf};
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn debug_harvest() -> bool {
    std::env::var("OSSL_DEBUG_HARVEST").is_ok()
}

/// Debug-only alg line over an already-classified record (logs are
/// artifacts: table labels, ids, and counters only — never target
/// strings, string lengths, or runtime addresses, even under the
/// debug flag).
fn debug_alg_line(op: u32, idx: u64, class: &str, weak: bool, status: u8) -> String {
    format!(
        "HARVESTDBG alg op={op} idx={idx} class={class} weak={} status={status}",
        u8::from(weak)
    )
}

/// Fault in the provider file's mapped pages (best-effort, one byte
/// per page via process_vm_readv). BPF probe reads are nofault: a
/// query whose alg tables were never touched aborts the walk
/// (TRUNC_WALK_*) even though the table is valid — reloading a
/// provider is exactly the cold-page case (lane-A proven). Called at
/// stage-2 attach, before any query the pair can see; failures only
/// degrade to abort-retry + loud TRUNC, never to silence.
fn pretouch_mappings(pid: u32, live: &[maps::Mapping], path: &Path, canon: &str) {
    let arg = path.to_string_lossy();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut pages: Vec<u64> = Vec::new();
    for m in live {
        if m.ino == 0
            || !(m.path == arg || m.path == canon || (!canon.is_empty() && m.path.ends_with(canon)))
        {
            continue;
        }
        let mut p = m.start & !(page - 1);
        while p < m.end {
            pages.push(p);
            p += page;
        }
    }
    if pages.is_empty() {
        return;
    }
    // One local byte per remote page; chunk under UIO_MAXIOV (1024).
    let mut sink = vec![0u8; pages.len().min(1000)];
    for chunk in pages.chunks(1000) {
        sink.resize(chunk.len(), 0);
        let local = libc::iovec {
            iov_base: sink.as_mut_ptr() as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        let remote: Vec<libc::iovec> = chunk
            .iter()
            .map(|p| libc::iovec {
                iov_base: *p as *mut libc::c_void,
                iov_len: 1,
            })
            .collect();
        let n = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                &local,
                1,
                remote.as_ptr(),
                remote.len() as libc::c_ulong,
                0,
            )
        };
        if n < 0 && debug_harvest() {
            eprintln!(
                "HARVESTDBG pretouch pid={pid} pages={} err={}",
                chunk.len(),
                std::io::Error::last_os_error()
            );
        }
    }
}
/// Legacy-query attach cookie (primary query/init use 0).
const LEGACY_COOKIE: u64 = 1;

/// Build the `ALG_CLASS` kernel table entries from the single
/// registry: every registered name (class = registry index) plus
/// every weak-only name (class = `OTHER`, weak set). Fails closed on
/// a hash collision or an over-capacity name — the kernel confirms
/// exact bytes after the hash prefilter, so a collision would be
/// unrepresentable.
pub fn build_alg_entries() -> anyhow::Result<Vec<(u64, wire::AlgClassValue)>> {
    let mut out: Vec<(u64, wire::AlgClassValue)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut push = |name: &str, class: u16, weak: bool| -> anyhow::Result<()> {
        if name.len() > wire::MAX_ALG_NAME {
            bail!("registry name over kernel cap: {name:?}");
        }
        let h = wire::fnv1a64(name.as_bytes());
        if !seen.insert(h) {
            bail!("classifier hash collision on {name:?}");
        }
        let mut bytes = [0u8; wire::MAX_ALG_NAME];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        out.push((
            h,
            wire::AlgClassValue {
                class,
                weak: u8::from(weak),
                len: name.len() as u8,
                name: bytes,
            },
        ));
        Ok(())
    };
    for (i, a) in crate::kinds::ALG_NAMES.iter().enumerate() {
        let class = u16::try_from(i).map_err(|_| anyhow!("registry exceeds class id space"))?;
        if class == wire::OTHER_CLASS {
            bail!("registry exceeds class id space");
        }
        push(a.name, class, crate::kinds::is_weak_alg(a.name))?;
    }
    for w in crate::kinds::WEAK_ALGS {
        if !crate::kinds::is_known_alg(w) {
            push(w, wire::OTHER_CLASS, true)?;
        }
    }
    Ok(out)
}

/// Build the `TRIP_CLASS` kernel table entries from the single trip
/// taxonomy: the dynamic id, the built-in engine ids, and the load
/// names. Each entry carries both taxonomy classes (today's patterns
/// belong to exactly one taxonomy each).
pub fn build_trip_entries() -> anyhow::Result<Vec<(u64, wire::TripClassValue)>> {
    let mut out: Vec<(u64, wire::TripClassValue)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut push = |name: &str, engine: u16, load: u16| -> anyhow::Result<()> {
        if name.len() > wire::MAX_TRIP_NAME {
            bail!("trip pattern over kernel cap: {name:?}");
        }
        let h = wire::fnv1a64(name.as_bytes());
        if !seen.insert(h) {
            bail!("trip table hash collision on {name:?}");
        }
        let mut bytes = [0u8; wire::MAX_TRIP_NAME];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        out.push((
            h,
            wire::TripClassValue {
                engine,
                load,
                len: name.len() as u16,
                name: bytes,
            },
        ));
        Ok(())
    };
    push("dynamic", wire::ENGINE_DYNAMIC, wire::TRIP_OTHER)?;
    for id in legacy::BUILTIN_ENGINE_IDS {
        push(id, wire::ENGINE_BUILTIN, wire::TRIP_OTHER)?;
    }
    let loads = [
        ("legacy", wire::LOAD_LEGACY),
        ("default", wire::LOAD_DEFAULT),
        ("fips", wire::LOAD_FIPS),
    ];
    for (name, class) in loads {
        if !legacy::LOAD_NAMES.contains(&name) {
            bail!("load taxonomy drift: {name:?} left the registry");
        }
        push(name, wire::TRIP_OTHER, class)?;
    }
    Ok(out)
}

/// Populate the kernel classifier tables right after map creation,
/// before any attach can fire. Observer-owned registry bytes only;
/// no target memory is involved.
fn populate_classifier_maps(maps: &HashMap<String, OwnedFd>) -> anyhow::Result<()> {
    let put = |map: &str, key: &[u8], value: &[u8]| -> anyhow::Result<()> {
        let fd = maps
            .get(map)
            .ok_or_else(|| anyhow!("missing classifier map {map}"))?;
        ossl_bpf_sys::map_update_elem(fd.as_raw_fd(), key, value, 0)
            .with_context(|| format!("populate {map}"))?;
        Ok(())
    };
    for (h, v) in build_alg_entries()? {
        put("ALG_CLASS", &h.to_le_bytes(), &wire::alg_value_bytes(&v))?;
    }
    for (h, v) in build_trip_entries()? {
        put("TRIP_CLASS", &h.to_le_bytes(), &wire::trip_value_bytes(&v))?;
    }
    Ok(())
}

/// Decode one trip verdict against the probe taxonomy: the cookie
/// selects engine vs load decoding, and the class id must be valid
/// for that taxonomy. `None` (unknown cookie or out-of-taxonomy
/// class) fails closed to a dropped hit.
fn decode_trip_hit(
    cookie: u64,
    class: u16,
    status: u8,
    set: &legacy::ProbeSet,
) -> Option<legacy::TripHit> {
    if set.by_id_cookies.contains(&cookie) {
        wire::engine_class_name(class)?;
    } else if set.is_load_cookie(cookie) {
        wire::load_class_name(class)?;
    } else {
        return None;
    }
    Some(legacy::TripHit {
        cookie,
        class,
        status,
    })
}

/// Resolve a BPF-reported query-fn address to its (file offset,
/// object path) for stage-2 attach. Errors carry the provider path
/// and cookie (observer inputs) — never the runtime address (stderr
/// is a scanned artifact, so error paths redact like emission).
fn resolve_query_target(
    live: &[maps::Mapping],
    provider: &Path,
    canon: &str,
    addr: u64,
    cookie: u64,
) -> anyhow::Result<(u64, PathBuf)> {
    if cookie == LEGACY_COOKIE {
        let m = live
            .iter()
            .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
            .ok_or_else(|| {
                anyhow!("legacy stage-2 attach has no file mapping (cookie {cookie})")
            })?;
        Ok((addr - m.start + m.offset, PathBuf::from(&m.path)))
    } else {
        let m = maps::provider_mapping(live, provider, canon, addr).ok_or_else(|| {
            anyhow!(
                "stage-2 attach has no provider mapping for {}",
                provider.display()
            )
        })?;
        Ok((addr - m.start + m.offset, provider.to_path_buf()))
    }
}

/// Load-mandated init anchor, present even in stripped modules.
const INIT_ANCHOR: &str = "OSSL_provider_init";

/// Harvest run configuration.
pub struct Config {
    pub pid: u32,
    pub provider: PathBuf,
    pub object: PathBuf,
    pub settle: Duration,
    pub timeout: Duration,
    /// Required cmdline marker (fixture guard), or None for any target.
    pub cmdline_marker: Option<String>,
    /// Builtin mode: harvest the in-libcrypto default provider.
    pub builtin: bool,
    /// Legacy tripwires: ENGINE / meth_new / provider-load /
    /// low-level-family probes on the target libcrypto plus the
    /// legacy-provider query attachment (the `legacy` doc section).
    pub legacy: bool,
    /// Override build-id table (forensics/redacted-table gates).
    pub table: Option<PathBuf>,
    /// Forced query-fn file offset (forensics escape hatch).
    pub force_offset: Option<u64>,
}

/// Load the frozen harvest shape: `prepare` asserts dims vs the
/// object (fail-closed on drift), `load` creates maps + progs raw
/// with `expected_attach_type=UPROBE_MULTI`. Verifier failures
/// surface before any attach.
fn load_frozen(obj_bytes: &[u8]) -> anyhow::Result<Loaded> {
    let prep = crate::loader::prepare(
        obj_bytes,
        &crate::loader::HARVEST_MAPS,
        &crate::loader::HARVEST_PROGS,
    )?;
    crate::loader::load(&prep)
}

/// Owned multi links (drop = detach; a handful per run, so the P1
/// parallel-detach guard retired with the ~830 perf pairs).
#[derive(Default)]
struct Links(Vec<OwnedFd>);

/// Path for a multi link: the kernel resolves it per mapping, so
/// the caller's (possibly relative) path is passed through as-is.
fn link_path(path: &Path) -> anyhow::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("attach path contains NUL: {}", path.display()))
}

fn prog_fd(loaded: &Loaded, name: &str) -> anyhow::Result<std::os::fd::RawFd> {
    loaded
        .progs
        .get(name)
        .map(AsRawFd::as_raw_fd)
        .ok_or_else(|| anyhow!("missing program {name}"))
}

#[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
fn attach_pair(
    loaded: &Loaded,
    links: &mut Links,
    entry: &str,
    ret: &str,
    offset: u64,
    path: &Path,
    pid: u32,
    cookie: u64,
) -> anyhow::Result<()> {
    let cpath = link_path(path)?;
    let entry_link = ossl_bpf_sys::link_create_uprobe_multi(
        prog_fd(loaded, entry)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {entry}@{offset:#x}: {e}"))?;
    links.0.push(entry_link);
    let ret_link = ossl_bpf_sys::link_create_uretprobe_multi(
        prog_fd(loaded, ret)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {ret}@{offset:#x}: {e}"))?;
    links.0.push(ret_link);
    Ok(())
}

/// Attach legacy tripwires: one multi link per (module, program)
/// with the probes' offsets + cookies batched (same cookie id
/// space as the P1 perf singles — goldens unaffected).
fn attach_trips(
    loaded: &Loaded,
    links: &mut Links,
    set: &legacy::ProbeSet,
    pid: u32,
) -> anyhow::Result<()> {
    type OffsetsCookies = (Vec<u64>, Vec<u64>);
    let mut groups: HashMap<(&str, &str), OffsetsCookies> = HashMap::new();
    for p in &set.probes {
        let (offs, cookies) = groups.entry((p.module.as_str(), p.program)).or_default();
        offs.push(p.offset);
        cookies.push(p.cookie);
    }
    let mut keys: Vec<(&str, &str)> = groups.keys().copied().collect();
    keys.sort_unstable();
    for (module, prog_name) in keys {
        let (offsets, cookies) = &groups[&(module, prog_name)];
        let cpath = link_path(Path::new(module))?;
        let link = ossl_bpf_sys::link_create_uprobe_multi(
            prog_fd(loaded, prog_name)?,
            &cpath,
            offsets,
            cookies,
            pid,
        )
        .map_err(|e| anyhow!("attach {prog_name}@{module}+{}: {e}", offsets.len()))?;
        links.0.push(link);
    }
    Ok(())
}

/// Plan + attach legacy tripwires against the CURRENT image.
/// Returns `(None, None)` when libcrypto isn't mapped (pre-exec or
/// statically linked) — the caller defers or goes blind.
fn plan_legacy_trips(
    cfg: &Config,
    loaded: &Loaded,
    links: &mut Links,
    pid: u32,
) -> anyhow::Result<(Option<legacy::ProbeSet>, Option<String>)> {
    let maps0 = maps::read_maps(cfg.pid).unwrap_or_default();
    let Some(lc_path) = legacy::find_libcrypto(&maps0) else {
        return Ok((None, None));
    };
    let lc_bytes =
        std::fs::read(&lc_path).with_context(|| format!("read target libcrypto {lc_path}"))?;
    // Caller modules for low-level PLT planning. Unreadable
    // files (deleted-but-mapped, permissions) are loud
    // findings: their imports stay unknown.
    let mut mod_bytes: Vec<(String, Vec<u8>)> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for path in legacy::target_modules(&maps0, &lc_path) {
        match std::fs::read(&path) {
            Ok(bytes) => mod_bytes.push((path, bytes)),
            Err(_) => unreadable.push(path),
        }
    }
    let modules: Vec<legacy::Module> = mod_bytes
        .iter()
        .map(|(p, b)| legacy::Module { path: p, bytes: b })
        .collect();
    let mut set = legacy::probes_for(&lc_path, &lc_bytes, &modules)?;
    for path in &unreadable {
        set.findings
            .push(format!("unreadable module: {path} (imports unknown)"));
    }
    attach_trips(loaded, links, &set, pid)?;
    eprintln!("INSPECT stage=legacy trips={}", set.probes.len());
    let mut note = None;
    for cand in legacy_candidates(cfg.pid, &lc_path) {
        let off = std::fs::read(&cand)
            .ok()
            .and_then(|b| elf::dynsym_file_offset(&b, INIT_ANCHOR).ok());
        // No init anchor in the candidate: a pre-loaded
        // legacy stays unattributed (documented edge).
        if let Some(off) = off {
            if let Err(e) = attach_pair(
                loaded,
                links,
                "init_entry",
                "init_return",
                off,
                &cand,
                pid,
                LEGACY_COOKIE,
            ) {
                // Loud in-doc (executed_calls would read a
                // false 0); the run continues for tripwires.
                note = Some(format!("legacy tripwire attach failed: {e:#}"));
                eprintln!("INSPECT legacy attach failed: {e:#}");
            }
        }
    }
    Ok((Some(set), note))
}

/// Candidate legacy.so paths for pre-mapping init attach: the
/// target's OPENSSL_MODULES dir plus libcrypto's ossl-modules dir
/// (existing files only; whichever loads fires the cookie-1 init).
fn legacy_candidates(pid: u32, libcrypto: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut consider = |p: PathBuf| {
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
        for kv in env.split(|b| *b == 0) {
            if let Some(v) = kv
                .strip_prefix(b"OPENSSL_MODULES=")
                .and_then(|v| std::str::from_utf8(v).ok())
            {
                for dir in v.split(':') {
                    consider(PathBuf::from(dir).join("legacy.so"));
                }
            }
        }
    }
    if let Some(dir) = Path::new(libcrypto).parent() {
        consider(dir.join("ossl-modules").join("legacy.so"));
    }
    out
}

/// Emit a PARTIAL document for a failed bootstrap (anchor unresolvable).
/// Never a bare "none": the reason + uninstrumented depth travel in-band.
/// With `--legacy`, the blind legacy section travels too (computed by
/// the caller — no tripwire attach was possible).
#[allow(clippy::too_many_arguments, reason = "one coherent doc identity")]
fn partial_doc(
    provider_name: &str,
    provider: &Path,
    canon: &str,
    elf_bytes: &[u8],
    reason: &str,
    builtin: bool,
    legacy_section: Option<serde_json::Value>,
    pid_recycled: u64,
    tracker: Option<&coverage::CoverageTracker>,
) -> anyhow::Result<serde_json::Value> {
    // Post-drain callers pass the joined tracker so walk-shape bits
    // and losses travel even on bootstrap-failure PARTIALs;
    // pre-drain/discard callers pass None (nothing was observed, or
    // the evidence is tainted and discarded).
    let empty = coverage::CoverageTracker::new();
    let t = tracker.unwrap_or(&empty);
    let mut doc = schema::emit(
        provider_name,
        provider,
        canon,
        elf_bytes,
        &[],
        &[],
        false,
        &schema::Stats {
            builtin,
            truncated: t.truncated(),
            unterminated_ops: t.unterminated_ops(),
            losses: t.losses(),
            lossy_slots: t.lossy_slots(),
            reason: Some(reason.to_string()),
            pid_recycled,
            ..schema::Stats::trivial()
        },
    )?;
    if let Some(l) = legacy_section {
        doc["legacy"] = l;
    }
    Ok(doc)
}

/// Pid recycle mid-run: carries the pre-built PARTIAL(pid-recycled)
/// discard doc (`inspect` prints it and exits 4 — evidence paths
/// never emit rows for the wrong task).
#[derive(Debug)]
pub struct Recycled {
    pub doc: serde_json::Value,
}

impl std::fmt::Display for Recycled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "target recycled mid-run (evidence discarded; see PARTIAL doc)"
        )
    }
}

impl std::error::Error for Recycled {}

/// Re-verify the target pin; on recycle build the discard doc (zero
/// rows; blind legacy at most — trip data is pid-scoped, hence
/// tainted too) and return it as `Recycled`.
#[allow(clippy::too_many_arguments, reason = "one coherent doc identity")]
fn check_pin(
    pin: &crate::pin::TargetPin,
    provider_name: &str,
    provider: &Path,
    canon: &str,
    elf_bytes: &[u8],
    builtin: bool,
    legacy: bool,
) -> anyhow::Result<()> {
    if pin.verify().is_err() {
        let blind = legacy.then(blind_legacy_section);
        let doc = partial_doc(
            provider_name,
            provider,
            canon,
            elf_bytes,
            "pid-recycled",
            builtin,
            blind,
            1,
            None,
        )?;
        return Err(anyhow::Error::new(Recycled { doc }));
    }
    Ok(())
}

/// Blind legacy section: no tripwire attach was possible (no
/// libcrypto mapping — statically linked or crypto-free target).
/// Pure userspace: full registry-size gaps plus the mandated
/// finding (which lives in the blind set itself).
fn blind_legacy_section() -> serde_json::Value {
    let set = legacy::blind_probe_set();
    legacy::section(&legacy::SectionInputs {
        set: &set,
        trip: &HashMap::new(),
        trip_hits: &[],
        legacy_queries: 0,
        legacy_classes: Vec::new(),
        extra_findings: &[],
    })
}

/// Typed hash-map read over a dup'd raw fd (aya in its P2 role:
/// typed reads only — load/attach went raw). Missing/foreign maps
/// read as empty (frozen shape always carries them; the fallback is
/// for shape drift, which `prepare` already refused).
fn read_kv<K, V>(maps: &HashMap<String, OwnedFd>, name: &str) -> Vec<(K, V)>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    read_kv_checked(maps, name).0
}

/// Checked variant: returns the rows plus whether the snapshot
/// failed (setup or iteration). T03-critical maps (TRUNC/TERMD/LOSS)
/// use this so a failed snapshot becomes explicit snapshot loss,
/// never a silent "no truncation / no loss" read.
fn read_kv_checked<K, V>(maps: &HashMap<String, OwnedFd>, name: &str) -> (Vec<(K, V)>, bool)
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    let fd = match maps.get(name).and_then(|f| f.try_clone().ok()) {
        Some(fd) => fd,
        None => return (Vec::new(), true),
    };
    let data = match MapData::from_fd(fd) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), true),
    };
    let map = match Map::from_map_data(data) {
        Ok(m) => m,
        Err(_) => return (Vec::new(), true),
    };
    let Ok(map) = aya::maps::HashMap::<_, K, V>::try_from(map) else {
        return (Vec::new(), true);
    };
    let mut out = Vec::new();
    let mut failed = false;
    for r in map.iter() {
        match r {
            Ok(kv) => out.push(kv),
            Err(_) => failed = true,
        }
    }
    (out, failed)
}

/// Drain the TRUNC overflow map: (op, bits) plus snapshot failure.
fn read_trunc(maps: &HashMap<String, OwnedFd>) -> (Vec<(u32, u64)>, bool) {
    read_kv_checked(maps, "TRUNC")
}

/// Drain the TERMD termination-proof map: (array base, packed op/len).
fn read_termd(maps: &HashMap<String, OwnedFd>) -> (Vec<(u64, u64)>, bool) {
    read_kv_checked(maps, "TERMD")
}

/// Drain the LOSS failure-counter map: (source id, count).
fn read_losses(maps: &HashMap<String, OwnedFd>) -> (Vec<(u32, u64)>, bool) {
    read_kv_checked(maps, "LOSS")
}

/// Join the T03-critical map snapshots into the tracker on EVERY
/// post-drain path (trigger and no-trigger alike): termination
/// proofs, walk-shape bits, and failure counters meet the decoded
/// event stream. Failed snapshots become explicit snapshot loss,
/// never silent empties. Callers read TRUNC rows back from the
/// tracker (single filtered source for `truncated_ops`).
fn ingest_completion(loaded: &Loaded, tracker: &mut coverage::CoverageTracker) {
    let (truncated, trunc_fail) = read_trunc(&loaded.maps);
    let (termd, termd_fail) = read_termd(&loaded.maps);
    let (losses, loss_fail) = read_losses(&loaded.maps);
    tracker.ingest_termd(&termd);
    tracker.ingest_trunc(&truncated);
    tracker.ingest_losses(&losses);
    for failed in [trunc_fail, termd_fail, loss_fail] {
        if failed {
            tracker.note_map_snapshot();
        }
    }
}

/// Tracker gaps as a `Stats` fragment (no-trigger returns spread
/// this under their explicit reasons).
fn gap_stats(t: &coverage::CoverageTracker) -> schema::Stats {
    schema::Stats {
        truncated: t.truncated(),
        unterminated_ops: t.unterminated_ops(),
        losses: t.losses(),
        lossy_slots: t.lossy_slots(),
        ..schema::Stats::trivial()
    }
}

/// Sum the CALLS per-op map (empty → the caller falls back to the
/// QUERY_RET event count).
fn read_calls(maps: &HashMap<String, OwnedFd>) -> Option<u64> {
    let rows: Vec<(u32, u64)> = read_kv(maps, "CALLS");
    if rows.is_empty() && !maps.contains_key("CALLS") {
        return None;
    }
    Some(rows.iter().map(|(_, n)| n).sum())
}

/// TRIP map contents.
fn read_trip(maps: &HashMap<String, OwnedFd>) -> HashMap<u64, u64> {
    read_kv::<u64, u64>(maps, "TRIP").into_iter().collect()
}

/// Sum the LGCALLS per-op map.
fn read_lgcalls(maps: &HashMap<String, OwnedFd>) -> u64 {
    read_kv::<u32, u64>(maps, "LGCALLS")
        .iter()
        .map(|(_, n)| n)
        .sum()
}

/// Exact in-memory harvest totals for capture callers (the doc
/// only carries them when builtin/PARTIAL — cold-gap accounting
/// needs them always).
#[derive(Debug, Clone, Copy, Default)]
pub struct HarvestTotals {
    pub queries_observed: u64,
}

/// Run the harvest; returns the emitted document on success.
pub fn run(cfg: &Config) -> anyhow::Result<serde_json::Value> {
    Ok(run_detailed(cfg, &|| Ok(()), &|| false)?.0)
}

/// `run` with spawn-mode hooks: `on_attached` fires after the
/// post-attach pin check (SIGCONT goes here — the child stays
/// stopped until every attach is installed); `should_stop` is
/// polled each drain iteration (child-death short-circuits the
/// settle wait for short-lived targets). Returns the document +
/// exact in-memory totals.
pub fn run_detailed(
    cfg: &Config,
    on_attached: &dyn Fn() -> anyhow::Result<()>,
    should_stop: &dyn Fn() -> bool,
) -> anyhow::Result<(serde_json::Value, HarvestTotals)> {
    let pid = NonZeroU32::new(cfg.pid).ok_or_else(|| anyhow!("pid must be non-zero"))?;
    // Pin FIRST: every later /proc/<pid> read and every pid-scoped
    // attach is verified against this identity (exit-6).
    let pin = crate::pin::pin(cfg.pid)?;
    if let Some(marker) = &cfg.cmdline_marker {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", cfg.pid))?;
        let m = marker.as_bytes();
        if !cmdline.windows(m.len()).any(|w| w == m) {
            bail!("pid {} cmdline lacks marker {marker}", cfg.pid);
        }
    }
    let elf_bytes = std::fs::read(&cfg.provider)?;
    let canon = std::fs::canonicalize(&cfg.provider)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let obj_bytes = std::fs::read(&cfg.object)?;
    let provider_name: String = if cfg.builtin {
        "default".to_string()
    } else {
        cfg.provider
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string())
    };
    check_pin(
        &pin,
        &provider_name,
        &cfg.provider,
        &canon,
        &elf_bytes,
        cfg.builtin,
        cfg.legacy,
    )?;

    let loaded = load_frozen(&obj_bytes)?;
    // Classifier tables before any attach can fire: the kernel
    // classifies every string-bearing event against these.
    populate_classifier_maps(&loaded.maps)?;
    // Owns every multi link (drop = detach, all paths).
    let mut links = Links::default();
    let mut resolution: Option<String> = None;
    // Dispatch-blind runs preset their PARTIAL reason but still drain
    // for legacy tripwires (dispatch and legacy observe independently).
    let mut preset_reason: Option<String> = None;
    if cfg.builtin {
        let table = match &cfg.table {
            Some(path) => {
                let text = std::fs::read_to_string(path)?;
                builtin::load_table_str(&text)?
            }
            None => builtin::shipped_table(),
        };
        match builtin::resolve_query_offset(&elf_bytes, &table, cfg.force_offset) {
            Ok((off, r)) => {
                if r != builtin::Resolution::Table {
                    resolution = Some(r.as_str().to_string());
                }
                attach_pair(
                    &loaded,
                    &mut links,
                    "query_entry",
                    "query_return",
                    off,
                    &cfg.provider,
                    pid.get(),
                    0,
                )?;
                eprintln!("INSPECT stage=builtin off={off:#x} via={}", r.as_str());
            }
            Err(e) => {
                eprintln!("INSPECT builtin unresolved: {e:#}");
                preset_reason = Some("anchor-unresolved".to_string());
            }
        }
    } else {
        // Init ladder: load-mandated dynsym first, debug symtab second.
        let init_off = elf::dynsym_file_offset(&elf_bytes, INIT_ANCHOR)
            .map(|off| (off, None))
            .or_else(|_| {
                elf::symtab_file_offset(&elf_bytes, INIT_ANCHOR)
                    .map(|off| (off, Some("symtab".to_string())))
            });
        match init_off {
            Ok((off, res)) => {
                resolution = res;
                attach_pair(
                    &loaded,
                    &mut links,
                    "init_entry",
                    "init_return",
                    off,
                    &cfg.provider,
                    pid.get(),
                    0,
                )?;
            }
            Err(e) => {
                eprintln!("INSPECT anchor unresolved: {e:#}");
                preset_reason = Some("anchor-unresolved".to_string());
            }
        }
        // Machine-readable progress on stderr (stdout stays pure JSON):
        // harnesses gate fixture GO lines on these.
        eprintln!("INSPECT stage=init attached=2");
    }

    // Legacy tripwires (dispatch-independent: attach even when the
    // dispatch anchor failed — a blind dispatch can still observe
    // legacy calls; only a missing libcrypto mapping is truly blind).
    // Planned now when libcrypto is already mapped (--pid, re-harvest)
    // and deferred to the first post-exec drain round otherwise
    // (run-mode pre-exec images can't plan them — P3).
    let mut probe_set: Option<legacy::ProbeSet> = None;
    let mut legacy_note: Option<String> = None;
    if cfg.legacy {
        let (set, note) = plan_legacy_trips(cfg, &loaded, &mut links, pid.get())?;
        probe_set = set;
        legacy_note = note;
        if probe_set.is_none() {
            eprintln!("INSPECT stage=legacy blind=no-libcrypto-mapping");
        }
    }

    // Early return only when NOTHING can be observed: dispatch blind
    // and no tripwires (statically linked target). Blind legacy
    // section travels when --legacy is set, nothing otherwise
    // (exit-1/2 behavior identical).
    if preset_reason.is_some() && probe_set.is_none() {
        let blind = if cfg.legacy {
            Some(blind_legacy_section())
        } else {
            None
        };
        let reason = preset_reason.clone().unwrap();
        return partial_doc(
            &provider_name,
            &cfg.provider,
            &canon,
            &elf_bytes,
            &reason,
            cfg.builtin,
            blind,
            0,
            None,
        )
        .map(|d| (d, HarvestTotals::default()));
    }
    // Post-attach verify: every maps read and attach above resolved
    // through /proc/<pid> — confirm the identity before draining.
    check_pin(
        &pin,
        &provider_name,
        &cfg.provider,
        &canon,
        &elf_bytes,
        cfg.builtin,
        cfg.legacy,
    )?;
    // Spawn mode releases the stopped child here: every attach is
    // installed, so the post-exec query wave is fully observed.
    on_attached()?;

    let ev_fd = loaded
        .maps
        .get("EVENTS")
        .context("no EVENTS map")?
        .try_clone()?;
    let ev_data = MapData::from_fd(ev_fd).map_err(|e| anyhow!("EVENTS mapdata: {e}"))?;
    let ev_map = Map::from_map_data(ev_data).map_err(|e| anyhow!("EVENTS map: {e}"))?;
    let mut ring = RingBuf::try_from(ev_map)?;
    let start = Instant::now();
    let mut last_event = None;
    let mut trigger_observed = false;
    // Stage-2 query attachments by cookie (0 = target, 1 = legacy);
    // builtin mode pre-attaches its query pair (cookie 0).
    let mut attached_queries: HashSet<u64> = HashSet::new();
    if cfg.builtin && preset_reason.is_none() {
        attached_queries.insert(0);
    }
    let mut primary_init_observed = false;
    let mut trip_hits: Vec<legacy::TripHit> = Vec::new();
    let mut rows: Vec<schema::Row> = Vec::new();
    // Identity includes the impl address: scaled tables cycle funcids,
    // so the triple alone collapses distinct dispatch entries (72 vs
    // 504 observed). Weak and kernel status ride the key too: two
    // alias lists sharing a primary class but differing in evidence
    // or verdict stay distinct.
    // Index (not unit): duplicate keys arbitrate the stored array below.
    let mut seen: HashMap<(u32, String, bool, String, u32, u64), usize> = HashMap::new();
    // Pre-drain maps snapshot for duplicate arbitration (mappings are
    // stable — providers stay loaded for the whole harvest; a failed
    // read degrades to first-seen-wins).
    let early_maps = maps::read_maps(cfg.pid).unwrap_or_default();
    let mut queries_observed: u64 = 0;
    let mut ops_hit: HashSet<u32> = HashSet::new();
    // (Array address, alg index) → kernel verdict (table label,
    // weak, status label): ROW events join here (BPF emits one
    // classified ALG record per walked alg; the array disambiguates
    // providers sharing (op, index)).
    let mut alg_records: HashMap<(u64, u64), (String, bool, String)> = HashMap::new();
    let class_count = crate::kinds::ALG_NAMES.len() as u16;
    // T03 completion + loss accounting: the drain feeds decoded
    // events below; map snapshots join after the drain.
    let mut tracker = coverage::CoverageTracker::new();

    while start.elapsed() < cfg.timeout {
        // Short-lived targets (and signals): no more events can
        // arrive — end the drain instead of idling out the settle.
        if should_stop() {
            break;
        }
        // Deferred legacy planning (P3): run-mode pre-exec images
        // have no libcrypto; plan at the first round where it
        // appears (post-exec). One attempt per round, attach once.
        if cfg.legacy && probe_set.is_none() {
            let maps_now = maps::read_maps(cfg.pid).unwrap_or_default();
            if legacy::find_libcrypto(&maps_now).is_some() {
                let (set, note) = plan_legacy_trips(cfg, &loaded, &mut links, pid.get())?;
                probe_set = set;
                if legacy_note.is_none() {
                    legacy_note = note;
                }
            }
        }
        let mut fresh = false;
        while let Some(item) = ring.next() {
            fresh = true;
            last_event = Some(Instant::now());
            let b: &[u8] = &item;
            if b.len() < 4 {
                eprintln!("short event: {} bytes", b.len());
                tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
                continue;
            }
            let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
            // Ring payloads are small numerics-only structs (shared
            // wire ABI v2): unknown kinds cannot be sized, so they
            // are dropped here, before any field is read.
            let want = match kind {
                wire::KIND_INIT_RET => size_of::<wire::InitRetEvent>(),
                wire::KIND_QUERY_RET | wire::KIND_ROW => size_of::<wire::RowEvent>(),
                wire::KIND_ALG => size_of::<wire::AlgEvent>(),
                wire::KIND_TRIP => size_of::<wire::TripEvent>(),
                k => {
                    eprintln!("unknown event kind {k}");
                    tracker.note_bad_event(coverage::HOST_UNKNOWN_KIND);
                    continue;
                }
            };
            if b.len() < want {
                eprintln!("short event: {} bytes", b.len());
                tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
                continue;
            }
            match kind {
                wire::KIND_INIT_RET => {
                    let Ok(ev) = wire::parse_init_ret_event(b) else {
                        eprintln!("bad init-ret event");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    // aux carries the attach cookie: 0 = target
                    // provider, 1 = legacy.
                    let cookie = ev.aux;
                    if attached_queries.contains(&cookie) {
                        // Re-pretouch on repeat inits (unload/reload
                        // cycles): the new mapping's pages are cold and
                        // nofault BPF reads fail on them (exit-8 P4:
                        // 3.x TRUNC_WALK_NAME on the reload query).
                        // Best-effort, never fatal.
                        let addr = ev.addr;
                        if let Ok(live) = maps::read_maps(cfg.pid) {
                            let path = if cookie == LEGACY_COOKIE {
                                live.iter()
                                    .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
                                    .map(|m| PathBuf::from(&m.path))
                            } else {
                                Some(cfg.provider.clone())
                            };
                            if let Some(p) = path {
                                pretouch_mappings(pid.get(), &live, &p, &canon);
                            }
                        }
                        continue;
                    }
                    if cookie == 0 {
                        primary_init_observed = true;
                    }
                    // Tainted events (post-recycle firings from the new
                    // occupant) must not drive stage-2 attaches.
                    check_pin(
                        &pin,
                        &provider_name,
                        &cfg.provider,
                        &canon,
                        &elf_bytes,
                        cfg.builtin,
                        cfg.legacy,
                    )?;
                    let addr = ev.addr;
                    let live = maps::read_maps(cfg.pid).with_context(|| {
                        format!("read maps of {} (target may have exited)", cfg.pid)
                    })?;
                    // Resolve in the init's own file: the target
                    // provider for cookie 0, the mapped legacy.so for
                    // cookie 1 (mapped by now — its init just ran).
                    let (off, path) =
                        resolve_query_target(&live, &cfg.provider, &canon, addr, cookie)?;
                    attach_pair(
                        &loaded,
                        &mut links,
                        "query_entry",
                        "query_return",
                        off,
                        Path::new(&path),
                        pid.get(),
                        cookie,
                    )?;
                    attached_queries.insert(cookie);
                    pretouch_mappings(pid.get(), &live, &path, &canon);
                    eprintln!("INSPECT stage=query off={off:#x} cookie={cookie}");
                }
                wire::KIND_QUERY_RET => {
                    let Ok(ev) = wire::parse_row_event(b) else {
                        eprintln!("bad query-ret event");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    if ev.kind != wire::KIND_QUERY_RET || ev.funcid != 0 {
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    }
                    trigger_observed = true;
                    queries_observed += 1;
                    ops_hit.insert(ev.op);
                    tracker.note_query_ret(ev.op, ev.addr);
                    if debug_harvest() {
                        eprintln!("HARVESTDBG query_ret op={} slot={}", ev.op, ev.aux);
                    }
                }
                wire::KIND_ALG => {
                    let Ok(ev) = wire::parse_alg_event(b, class_count) else {
                        eprintln!("bad alg event");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    trigger_observed = true;
                    let Some(label) = crate::kinds::alg_class_label(ev.class) else {
                        eprintln!("alg event with out-of-range class {}", ev.class);
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    let Some(status) = wire::alg_status_name(ev.status) else {
                        eprintln!("alg event with out-of-range status {}", ev.status);
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    if debug_harvest() {
                        eprintln!(
                            "{}",
                            debug_alg_line(ev.op, ev.idx, label, ev.weak != 0, ev.status)
                        );
                    }
                    // Unreadable/overlong names lose the slot's
                    // identity (no retained prefix); unknown names
                    // are explicit `other` evidence, not loss.
                    let lossy =
                        ev.status == wire::ALG_UNREADABLE || ev.status == wire::ALG_OVERLONG;
                    tracker.note_alg(ev.op, ev.arr, ev.idx, lossy);
                    alg_records.insert(
                        (ev.arr, ev.idx),
                        (label.to_string(), ev.weak != 0, status.to_string()),
                    );
                }
                wire::KIND_ROW => {
                    let Ok(ev) = wire::parse_row_event(b) else {
                        eprintln!("bad row event");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    if ev.kind != wire::KIND_ROW {
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    }
                    trigger_observed = true;
                    let Some((label, weak, status)) = alg_records.get(&(ev.aux, ev.idx)).cloned()
                    else {
                        eprintln!("orphan row: op={} idx={}", ev.op, ev.idx);
                        tracker.note_orphan_row();
                        continue;
                    };
                    let key = (
                        ev.op,
                        label.clone(),
                        weak,
                        status.clone(),
                        ev.funcid,
                        ev.addr,
                    );
                    if let Some(&i) = seen.get(&key) {
                        // Duplicate key: multi-libctx re-query, or two
                        // providers sharing one implementation (default +
                        // legacy both expose RIPEMD-160 funcid 3). Prefer
                        // a provider-owned array so keep/drop is
                        // arrival-order independent.
                        if cfg.builtin
                            && maps::provider_mapping(
                                &early_maps,
                                &cfg.provider,
                                &canon,
                                rows[i].arr,
                            )
                            .is_none()
                            && maps::provider_mapping(&early_maps, &cfg.provider, &canon, ev.aux)
                                .is_some()
                        {
                            rows[i].arr = ev.aux;
                        }
                    } else {
                        seen.insert(key, rows.len());
                        rows.push(schema::Row {
                            op: ev.op,
                            alg_class: label,
                            weak,
                            status,
                            funcid: ev.funcid,
                            impl_addr: ev.addr,
                            arr: ev.aux,
                        });
                    }
                }
                wire::KIND_TRIP => {
                    // Deliberately NOT a dispatch trigger (doctrine in
                    // the no-trigger block below): tripwires observe
                    // independently of the dispatch harvest.
                    let Ok(ev) = wire::parse_trip_event(b) else {
                        eprintln!("bad trip event");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    // Trip events imply attached tripwires, which imply
                    // a planned probe set (same statement attaches and
                    // records); without one the cookie cannot be
                    // validated, so the hit is dropped.
                    let Some(set) = &probe_set else {
                        eprintln!("trip hit before probe plan");
                        tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        continue;
                    };
                    match decode_trip_hit(ev.cookie as u64, ev.class, ev.status, set) {
                        Some(hit) => trip_hits.push(hit),
                        None => {
                            eprintln!(
                                "trip hit outside taxonomy: cookie={} class={}",
                                ev.cookie, ev.class
                            );
                            tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                        }
                    }
                }
                // Unreachable: unknown kinds are dropped at the sizing
                // match above, before any field is read.
                _ => continue,
            }
        }
        if trigger_observed && !fresh {
            if let Some(t) = last_event {
                if t.elapsed() > cfg.settle {
                    break;
                }
            }
        }
        // Sleep only when idle: the inventory trigger bursts ~1MB in
        // milliseconds and the drain must not lag a fixed quantum.
        if !fresh {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    // Drain tail: stop/timeout can exit with items still queued.
    // They are already unprocessed — consuming them here only labels
    // the shortfall. Counted in two phases: first with producers
    // attached (bounded — an unbounded tail could spin on a hot
    // target), then links drop (quiesce: no later use of `links`
    // exists past this point) and the remainder is counted exactly,
    // so no post-stop arrival escapes accounting. (T06 sessions own
    // quiesce-then-PROCESS teardown; this run labels the gap.)
    let mut shortfall: u64 = 0;
    while ring.next().is_some() {
        shortfall += 1;
        if shortfall >= 65536 {
            break;
        }
    }
    drop(links);
    while ring.next().is_some() {
        shortfall += 1;
    }
    if shortfall > 0 {
        eprintln!("drain shortfall: {shortfall} unprocessed ring items at stop");
    }
    tracker.note_drain_shortfall(shortfall);
    // Post-drain backstop: discards ALL observations (rows and trips
    // alike) when the pid recycled under the drain.
    check_pin(
        &pin,
        &provider_name,
        &cfg.provider,
        &canon,
        &elf_bytes,
        cfg.builtin,
        cfg.legacy,
    )?;
    // Tripwire observations (read before the no-trigger decision:
    // loads distinguish "wrong attach" from "quiet target").
    let trip = read_trip(&loaded.maps);
    let lgcalls = read_lgcalls(&loaded.maps);
    // Per-cookie trip dump (all paths: the no-trigger path needs it
    // most — a quiet dispatch with firing tripwires).
    if cfg.legacy && std::env::var("OSSL_DEBUG_TRIP").is_ok() {
        if let Some(set) = &probe_set {
            let by_cookie: HashMap<u64, &legacy::Probe> =
                set.probes.iter().map(|p| (p.cookie, p)).collect();
            let mut keys: Vec<u64> = trip.keys().copied().collect();
            keys.sort_unstable();
            for k in keys {
                let p = by_cookie.get(&k);
                eprintln!(
                    "TRIPDBG cookie={k} n={} sym={} fam={:?} mod={} off={}",
                    trip[&k],
                    p.map(|p| p.symbol.as_str()).unwrap_or("??"),
                    p.and_then(|p| p.family),
                    p.map(|p| p.module.as_str()).unwrap_or("??"),
                    p.map(|p| format!("{:#x}", p.offset)).unwrap_or("??".into()),
                );
            }
        }
    }
    let mut extra_findings: Vec<&str> = Vec::new();
    if let Some(n) = &legacy_note {
        extra_findings.push(n);
    }
    // Live legacy section (None without --legacy; blind when no
    // tripwires attached). Row classes arrive post-partition; the
    // no-trigger paths below reuse this with empty classes.
    let legacy_live = if cfg.legacy {
        match &probe_set {
            Some(set) => Some(legacy::section(&legacy::SectionInputs {
                set,
                trip: &trip,
                trip_hits: &trip_hits,
                legacy_queries: lgcalls,
                legacy_classes: Vec::new(),
                extra_findings: &extra_findings,
            })),
            None => Some(blind_legacy_section()),
        }
    } else {
        None
    };
    if !trigger_observed {
        // Doctrine: tripwires are NOT dispatch triggers. Silence means:
        // - target gone → hard error (nothing observable, not even maps).
        // - preset reason (anchor failed) → PARTIAL(preset) + legacy.
        // - provider mapped but primary init never fired → PARTIAL
        //   (no-query-trigger): pre-loaded provider (dlopen/config
        //   blindness) + legacy.
        // - provider mapped and primary init fired, but zero rows
        //   (queries raced the stage-2 attach) → PARTIAL
        //   (init-without-queries): the trigger was observed, so
        //   silence fails loud (verdict 2026-09-18).
        // - provider never mapped (provider mode) → COMPLETE-EMPTY.
        // - builtin mode → PARTIAL(no-query-trigger), UNLESS legacy
        //   mode with zero loads observed (quiet/engine-only target)
        //   → COMPLETE-EMPTY.
        let live_now = maps::read_maps(cfg.pid).unwrap_or_default();
        if live_now.is_empty() && !Path::new(&format!("/proc/{}", cfg.pid)).exists() {
            bail!("target {} exited before trigger", cfg.pid);
        }
        // Join map snapshots here too: quiet paths must not hide
        // host-side drops or kernel-side failures behind a clean
        // no-trigger verdict.
        ingest_completion(&loaded, &mut tracker);
        if let Some(reason) = preset_reason.clone() {
            return partial_doc(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &reason,
                cfg.builtin,
                legacy_live,
                0,
                Some(&tracker),
            )
            .map(|d| (d, HarvestTotals { queries_observed }));
        }
        if !cfg.builtin {
            let arg = cfg.provider.to_string_lossy().into_owned();
            let provider_mapped = live_now.iter().any(|m| {
                m.path == arg || m.path == canon || (!canon.is_empty() && m.path.ends_with(&canon))
            });
            if provider_mapped && !primary_init_observed {
                let stats = schema::Stats {
                    resolution: resolution.clone(),
                    reason: Some("no-query-trigger".to_string()),
                    ..gap_stats(&tracker)
                };
                let mut doc = schema::emit(
                    &provider_name,
                    &cfg.provider,
                    &canon,
                    &elf_bytes,
                    &[],
                    &[],
                    false,
                    &stats,
                )?;
                if let Some(l) = legacy_live {
                    doc["legacy"] = l;
                }
                return Ok((doc, HarvestTotals { queries_observed }));
            }
            if provider_mapped && primary_init_observed {
                // Init fired post-attach but its queries raced the
                // stage-2 attach (trig P2/P3 shape): the evidence is
                // NOT whole — blind PARTIAL, never COMPLETE-EMPTY
                // (verdict 2026-09-18; race-miss vs idle is
                // indistinguishable post-hoc, and the trigger was
                // observed, so silence fails loud).
                let stats = schema::Stats {
                    resolution: resolution.clone(),
                    reason: Some("init-without-queries".to_string()),
                    ..gap_stats(&tracker)
                };
                let mut doc = schema::emit(
                    &provider_name,
                    &cfg.provider,
                    &canon,
                    &elf_bytes,
                    &[],
                    &[],
                    false,
                    &stats,
                )?;
                if let Some(l) = legacy_live {
                    doc["legacy"] = l;
                }
                return Ok((doc, HarvestTotals { queries_observed }));
            }
            // COMPLETE-EMPTY only when the tracker is also clean:
            // any gap flips the doc to PARTIAL below.
            let mut doc = schema::emit(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &[],
                &[],
                false,
                &gap_stats(&tracker),
            )?;
            if let Some(l) = legacy_live {
                doc["legacy"] = l;
            }
            return Ok((doc, HarvestTotals { queries_observed }));
        }
        let loads_observed = probe_set
            .as_ref()
            .is_some_and(|set| trip_hits.iter().any(|h| set.is_load_cookie(h.cookie)));
        if cfg.legacy && !loads_observed {
            // Quiet target: COMPLETE-EMPTY. Stats.builtin=false
            // suppresses the inventory counters (nothing was
            // inventoried — uninstrumented=14 would lie). Gaps
            // still flip the doc to PARTIAL below.
            let mut doc = schema::emit(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &[],
                &[],
                false,
                &gap_stats(&tracker),
            )?;
            if let Some(l) = legacy_live {
                doc["legacy"] = l;
            }
            return Ok((doc, HarvestTotals { queries_observed }));
        }
        eprintln!("INSPECT builtin: no query trigger before timeout");
        let mut stats = schema::Stats {
            builtin: true,
            queries_observed,
            resolution: resolution.clone(),
            reason: Some("no-query-trigger".to_string()),
            ..gap_stats(&tracker)
        };
        stats.zero_row_ops = ops_hit.into_iter().collect();
        let mut doc = schema::emit(
            &provider_name,
            &cfg.provider,
            &canon,
            &elf_bytes,
            &[],
            &[],
            false,
            &stats,
        )?;
        if let Some(l) = legacy_live {
            doc["legacy"] = l;
        }
        return Ok((doc, HarvestTotals { queries_observed }));
    }

    // Post-drain maps for attribution. A target that exits after the
    // trigger (fallback cell: driver gone by drain end) leaves an
    // empty re-read — attributing against that drops every row as
    // foreign. Mappings are stable within a run (providers stay
    // loaded), so an empty re-read falls back to the pre-drain
    // snapshot. Live targets are unaffected (non-empty re-read wins,
    // covering mid-run provider loads the snapshot misses).
    let live = {
        let reread = maps::read_maps(cfg.pid).unwrap_or_default();
        if reread.is_empty() {
            eprintln!("INSPECT maps: target gone, attributing against pre-drain snapshot");
            early_maps.clone()
        } else {
            reread
        }
    };
    // Legacy partition FIRST: legacy-array rows are attributed (to
    // legacy_provider.algs), not foreign, so they leave before the
    // builtin filter counts drops.
    let mut legacy_rows: Vec<schema::Row> = Vec::new();
    if cfg.legacy {
        rows.retain(|r| {
            let is_leg = live.iter().any(|m| {
                m.start <= r.arr && r.arr < m.end && m.path.rsplit('/').next() == Some("legacy.so")
            });
            if is_leg {
                legacy_rows.push(r.clone());
                false
            } else {
                true
            }
        });
    }
    // Builtin mode shares the core wrapper with every provider in the
    // target: attribute by ARRAY mapping, not implementation address —
    // legacy rows can point at shared libcrypto code (MD4/MDC2 proved
    // it) while their arrays sit in legacy.so.
    let mut foreign_dropped: u64 = 0;
    if cfg.builtin {
        let before = rows.len();
        rows.retain(|r| {
            if maps::provider_mapping(&live, &cfg.provider, &canon, r.arr).is_some() {
                // Array owned by the provider file.
                return true;
            }
            if live
                .iter()
                .any(|m| m.start <= r.arr && r.arr < m.end && m.ino != 0)
            {
                // Array owned by another FILE (ino != 0): definitively
                // foreign. Anonymous mappings (heap/malloc, ino == 0 —
                // the 4.0 default cipher array lives in one) fall
                // through to implementation attribution below.
                return false;
            }
            // Anonymous or unmapped array: attribute by implementation
            // address instead.
            maps::provider_mapping(&live, &cfg.provider, &canon, r.impl_addr).is_some()
        });
        foreign_dropped = (before - rows.len()) as u64;
    }
    let mut ops_with_rows: HashSet<u32> = rows.iter().map(|r| r.op).collect();
    ops_with_rows.extend(legacy_rows.iter().map(|r| r.op));
    let mut zero_row_ops: Vec<u32> = ops_hit.difference(&ops_with_rows).copied().collect();
    zero_row_ops.sort_unstable();
    // T03 completion + loss join: termination proofs, walk-shape
    // bits, and failure counters meet the decoded event stream.
    ingest_completion(&loaded, &mut tracker);
    let truncated = tracker.truncated();
    // Call volume from the CALLS map (QUERY_RET events are
    // first-hit-only; the event count is the pre-exit-2 fallback).
    // Best-effort under threads: shared-map increments are
    // read-modify-write, so concurrent hits may undercount; the
    // cold-gap trigger (>0) is robust to that, only the counter
    // value may read low.
    if let Some(calls) = read_calls(&loaded.maps) {
        queries_observed = calls;
    }
    // Validation: the known-op trigger must yield rows.
    let reason = if cfg.builtin && rows.is_empty() {
        Some("zero-rows".to_string())
    } else {
        None
    };
    let mut doc = schema::emit(
        &provider_name,
        &cfg.provider,
        &canon,
        &elf_bytes,
        &live,
        &rows,
        trigger_observed,
        &schema::Stats {
            builtin: cfg.builtin,
            queries_observed,
            zero_row_ops,
            truncated,
            unterminated_ops: tracker.unterminated_ops(),
            losses: tracker.losses(),
            lossy_slots: tracker.lossy_slots(),
            resolution,
            reason,
            foreign_dropped,
            pid_recycled: 0,
        },
    )?;
    if cfg.legacy {
        // Rows arrive pre-classified (kernel verdicts resolved at
        // ring decode); legacy classes are carried, not recomputed.
        let classes: Vec<String> = legacy_rows.iter().map(|r| r.alg_class.clone()).collect();
        let l = match &probe_set {
            Some(set) => legacy::section(&legacy::SectionInputs {
                set,
                trip: &trip,
                trip_hits: &trip_hits,
                legacy_queries: lgcalls,
                legacy_classes: classes,
                extra_findings: &extra_findings,
            }),
            None => blind_legacy_section(),
        };
        doc["legacy"] = l;
    }
    Ok((doc, HarvestTotals { queries_observed }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn row_key_includes_addr_weak_and_status() {
        // Regression pin for the scaled-table collapse (72 vs 504):
        // same (op, class, funcid) at distinct addrs are distinct
        // rows; weak evidence and kernel status survive alias
        // collapse (same class, different verdicts stay distinct).
        let a = (
            1u32,
            "X".to_string(),
            false,
            "ok".to_string(),
            7u32,
            0x1000u64,
        );
        let b = (
            1u32,
            "X".to_string(),
            false,
            "ok".to_string(),
            7u32,
            0x2000u64,
        );
        let c = (
            1u32,
            "X".to_string(),
            true,
            "ok".to_string(),
            7u32,
            0x1000u64,
        );
        let d = (
            1u32,
            "other".to_string(),
            false,
            "overlong".to_string(),
            7u32,
            0x1000u64,
        );
        let e = (
            1u32,
            "other".to_string(),
            false,
            "unknown".to_string(),
            7u32,
            0x1000u64,
        );
        let mut s: std::collections::HashSet<(u32, String, bool, String, u32, u64)> =
            std::collections::HashSet::new();
        assert!(s.insert(a));
        assert!(s.insert(b));
        assert!(s.insert(c));
        assert!(s.insert(d));
        assert!(s.insert(e));
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn debug_alg_line_prints_classified_fields_only() {
        // Table labels, ids, and counters only: no addresses, no
        // lengths, and no slot for raw names (the signature takes a
        // pre-classified record).
        let line = super::debug_alg_line(1, 0, "other", false, super::wire::ALG_UNKNOWN);
        assert_eq!(
            line,
            "HARVESTDBG alg op=1 idx=0 class=other weak=0 status=1"
        );
        let line = super::debug_alg_line(1, 3, "SHA2-256", false, super::wire::ALG_OK);
        assert_eq!(
            line,
            "HARVESTDBG alg op=1 idx=3 class=SHA2-256 weak=0 status=0"
        );
        assert!(!line.contains("0x"), "address leaked: {line}");
        assert!(!line.contains("len="), "length leaked: {line}");
    }

    #[test]
    fn resolve_query_target_redacts_errors() {
        use std::path::Path;
        let live = vec![super::maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0x500,
            dev: "08:01".into(),
            ino: 7,
            path: "/prov.so".into(),
        }];
        // Happy paths resolve to file offsets.
        let (off, path) =
            super::resolve_query_target(&live, Path::new("/prov.so"), "", 0x1400, 0).unwrap();
        assert_eq!((off, path), (0x900, std::path::PathBuf::from("/prov.so")));
        let (off, path) =
            super::resolve_query_target(&live, Path::new("/prov.so"), "", 0x1400, 1).unwrap();
        assert_eq!((off, path), (0x900, std::path::PathBuf::from("/prov.so")));
        // Failure paths redact the runtime address (both hex and
        // decimal forms) while keeping observer context.
        for cookie in [0u64, 1] {
            let addr = 0x7f00_deed_beefu64;
            let err = super::resolve_query_target(&live, Path::new("/prov.so"), "", addr, cookie)
                .unwrap_err()
                .to_string();
            assert!(
                !err.contains(&format!("{addr:#x}")),
                "hex addr leaked: {err}"
            );
            assert!(!err.contains(&addr.to_string()), "addr leaked: {err}");
        }
    }

    #[test]
    fn trip_hit_decode_validates_taxonomy() {
        use std::collections::HashSet;
        let set = super::legacy::ProbeSet {
            load_cookies: HashSet::from([9]),
            by_id_cookies: HashSet::from([10]),
            ..Default::default()
        };
        // Right taxonomy, valid class: accepted (any status).
        assert!(
            super::decode_trip_hit(9, super::wire::LOAD_LEGACY, super::wire::TRIP_OK, &set)
                .is_some()
        );
        assert!(
            super::decode_trip_hit(
                9,
                super::wire::TRIP_OTHER,
                super::wire::TRIP_UNREADABLE,
                &set
            )
            .is_some()
        );
        assert!(
            super::decode_trip_hit(10, super::wire::ENGINE_DYNAMIC, super::wire::TRIP_OK, &set)
                .is_some()
        );
        // The cookie selects the decoder (numeric spaces overlap by
        // design): class 3 is LOAD_FIPS under a load cookie but
        // invalid under an engine cookie. Unknown cookies and
        // out-of-range classes are dropped.
        assert!(
            super::decode_trip_hit(9, super::wire::LOAD_FIPS, super::wire::TRIP_OK, &set).is_some()
        );
        assert!(
            super::decode_trip_hit(10, super::wire::LOAD_FIPS, super::wire::TRIP_OK, &set)
                .is_none()
        );
        assert!(
            super::decode_trip_hit(11, super::wire::TRIP_OTHER, super::wire::TRIP_OK, &set)
                .is_none()
        );
        assert!(super::decode_trip_hit(9, 99, super::wire::TRIP_OK, &set).is_none());
        assert!(super::decode_trip_hit(10, 99, super::wire::TRIP_OK, &set).is_none());
    }
}
