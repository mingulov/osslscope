//! Live harvest driver: two-stage attach + ring drain + settle,
//! promoted behavior-identical from the P0-4 spike. The fixture-only
//! `evp_driver` cmdline guard is now a caller-supplied marker
//! (`None` = any target — what `inspect --pid` uses at P1 exit 1).
//!
//! P1 exit 2 adds builtin mode (`--builtin`): single-stage attach to
//! the core-static `ossl_provider_query_operation` resolved via the
//! build-id ladder (no init anchor exists for the in-libcrypto
//! default provider), coverage counters, and PARTIAL documents.
use crate::discovery::{builtin, elf, legacy, maps, schema};
use anyhow::{Context as _, anyhow, bail};
use aya::maps::RingBuf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLink, UProbeScope};
use aya::{Ebpf, EbpfLoader};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const KIND_INIT_RET: u32 = 1;
const KIND_QUERY_RET: u32 = 2;
const KIND_ROW: u32 = 3;
const KIND_ALG: u32 = 4;
const KIND_TRIP: u32 = 5;
const EVENT_LEN: usize = 160;
const ROW_EVENT_LEN: usize = 40;
const NAME_OFF: usize = 32;
const NAME_LEN: usize = 128;
/// KIND_TRIP string bytes (bounded 32B at offset 8).
const TRIP_ARG_OFF: usize = 8;
const TRIP_ARG_LEN: usize = 32;
/// Legacy-query attach cookie (primary query/init use 0).
const LEGACY_COOKIE: u64 = 1;

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

/// Load every harvest program once, up front (verifier failures
/// surface before any attach; aya refuses a second load of the same
/// program, so attach sites must never load).
fn load_programs(bpf: &mut Ebpf) -> anyhow::Result<()> {
    for name in [
        "init_entry",
        "init_return",
        "query_entry",
        "query_return",
        "trip_count",
        "trip_str0",
        "trip_str1",
    ] {
        let prog: &mut UProbe = bpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("missing program {name}"))?
            .try_into()?;
        prog.load().with_context(|| format!("load {name}"))?;
    }
    Ok(())
}

/// Owned uprobe links, detached in parallel on drop. Each link
/// close pays a kernel SRCU/RCU grace period (~90ms in CI VMs), so
/// ~830 sequential detaches stall exit by ~75s; concurrent closes
/// share grace periods (~2s). Taken out of aya's managed links at
/// attach time so every return path detaches via this guard.
#[derive(Default)]
struct Links(Vec<UProbeLink>);

impl Drop for Links {
    fn drop(&mut self) {
        let links = std::mem::take(&mut self.0);
        if links.len() < 2 {
            return;
        }
        // Round-robin buckets: drops only sleep in kernel, so
        // oversubscription is fine and grace periods overlap.
        let n = 16usize.min(links.len());
        let mut buckets: Vec<Vec<UProbeLink>> = (0..n).map(|_| Vec::new()).collect();
        for (i, l) in links.into_iter().enumerate() {
            buckets[i % n].push(l);
        }
        std::thread::scope(|s| {
            for b in buckets {
                s.spawn(|| drop(b));
            }
        });
    }
}

#[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
fn attach_pair(
    bpf: &mut Ebpf,
    links: &mut Links,
    entry: &str,
    ret: &str,
    offset: u64,
    path: &Path,
    pid: NonZeroU32,
    cookie: Option<u64>,
) -> anyhow::Result<()> {
    for name in [entry, ret] {
        let prog: &mut UProbe = bpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("missing program {name}"))?
            .try_into()?;
        let point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(offset),
            cookie,
        };
        let id = prog
            .attach(point, path, UProbeScope::OneProcess(pid))
            .map_err(|e| anyhow!("attach {name}@{offset:#x}: {e}"))?;
        links.0.push(prog.take_link(id)?);
    }
    Ok(())
}

/// Attach legacy tripwires: each probe = its program at its offset
/// in its module with its cookie (programs loaded once; API-surface
/// probes live in libcrypto, low-level probes in caller PLTs).
fn attach_trips(
    bpf: &mut Ebpf,
    links: &mut Links,
    set: &legacy::ProbeSet,
    pid: NonZeroU32,
) -> anyhow::Result<()> {
    let mut by_prog: HashMap<&str, Vec<&legacy::Probe>> = HashMap::new();
    for p in &set.probes {
        by_prog.entry(p.program).or_default().push(p);
    }
    for (prog_name, probes) in &by_prog {
        let prog: &mut UProbe = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow!("missing program {prog_name}"))?
            .try_into()?;
        for p in probes {
            let point = UProbeAttachPoint {
                location: UProbeAttachLocation::AbsoluteOffset(p.offset),
                cookie: Some(p.cookie),
            };
            let id = prog
                .attach(point, Path::new(&p.module), UProbeScope::OneProcess(pid))
                .map_err(|e| anyhow!("attach {}@{:#x}: {e}", p.symbol, p.offset))?;
            links.0.push(prog.take_link(id)?);
        }
    }
    Ok(())
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
) -> anyhow::Result<serde_json::Value> {
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
        trip_strs: &[],
        legacy_queries: 0,
        legacy_classes: Vec::new(),
        extra_findings: &[],
    })
}

/// Drain the TRUNC overflow map (missing on pre-exit-2 objects → empty).
fn read_trunc(bpf: &mut Ebpf) -> Vec<(u32, u64)> {
    let Some(map) = bpf.take_map("TRUNC") else {
        return Vec::new();
    };
    let Ok(map) = aya::maps::HashMap::<_, u32, u64>::try_from(map) else {
        return Vec::new();
    };
    map.iter().filter_map(|r| r.ok()).collect()
}

/// Sum the CALLS per-op map (missing on pre-exit-2 objects → the
/// caller falls back to the QUERY_RET event count).
fn read_calls(bpf: &mut Ebpf) -> Option<u64> {
    let map = bpf.take_map("CALLS")?;
    let map = aya::maps::HashMap::<_, u32, u64>::try_from(map).ok()?;
    Some(map.iter().filter_map(|r| r.ok()).map(|(_, n)| n).sum())
}

/// TRIP map contents (missing on pre-exit-3 objects → empty).
fn read_trip(bpf: &mut Ebpf) -> HashMap<u64, u64> {
    let Some(map) = bpf.take_map("TRIP") else {
        return HashMap::new();
    };
    let Ok(map) = aya::maps::HashMap::<_, u64, u64>::try_from(map) else {
        return HashMap::new();
    };
    map.iter().filter_map(|r| r.ok()).collect()
}

/// Sum the LGCALLS per-op map (missing on pre-exit-3 objects → 0).
fn read_lgcalls(bpf: &mut Ebpf) -> u64 {
    let Some(map) = bpf.take_map("LGCALLS") else {
        return 0;
    };
    let Ok(map) = aya::maps::HashMap::<_, u32, u64>::try_from(map) else {
        return 0;
    };
    map.iter().filter_map(|r| r.ok()).map(|(_, n)| n).sum()
}

/// Run the harvest; returns the emitted document on success.
pub fn run(cfg: &Config) -> anyhow::Result<serde_json::Value> {
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

    let mut bpf = EbpfLoader::new().load(&obj_bytes)?;
    load_programs(&mut bpf)?;
    // Owns every uprobe link (parallel detach on drop, all paths).
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
                    &mut bpf,
                    &mut links,
                    "query_entry",
                    "query_return",
                    off,
                    &cfg.provider,
                    pid,
                    Some(0),
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
                    &mut bpf,
                    &mut links,
                    "init_entry",
                    "init_return",
                    off,
                    &cfg.provider,
                    pid,
                    Some(0),
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
    let mut probe_set: Option<legacy::ProbeSet> = None;
    let mut legacy_note: Option<String> = None;
    if cfg.legacy {
        let maps0 = maps::read_maps(cfg.pid).unwrap_or_default();
        if let Some(lc_path) = legacy::find_libcrypto(&maps0) {
            let lc_bytes = std::fs::read(&lc_path)
                .with_context(|| format!("read target libcrypto {lc_path}"))?;
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
            attach_trips(&mut bpf, &mut links, &set, pid)?;
            eprintln!("INSPECT stage=legacy trips={}", set.probes.len());
            for cand in legacy_candidates(cfg.pid, &lc_path) {
                let off = std::fs::read(&cand)
                    .ok()
                    .and_then(|b| elf::dynsym_file_offset(&b, INIT_ANCHOR).ok());
                // No init anchor in the candidate: a pre-loaded
                // legacy stays unattributed (documented edge).
                if let Some(off) = off {
                    if let Err(e) = attach_pair(
                        &mut bpf,
                        &mut links,
                        "init_entry",
                        "init_return",
                        off,
                        &cand,
                        pid,
                        Some(LEGACY_COOKIE),
                    ) {
                        // Loud in-doc (executed_calls would read a
                        // false 0); the run continues for tripwires.
                        legacy_note = Some(format!("legacy tripwire attach failed: {e:#}"));
                        eprintln!("INSPECT legacy attach failed: {e:#}");
                    }
                }
            }
            probe_set = Some(set);
        } else {
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
        );
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

    let map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("no EVENTS map"))?;
    let mut ring = RingBuf::try_from(map)?;
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
    let mut trip_strs: Vec<(u64, String)> = Vec::new();
    let mut rows: Vec<schema::Row> = Vec::new();
    // Identity includes addr: scaled tables cycle funcids, so the triple
    // alone collapses distinct dispatch entries (72 vs 504 observed).
    // Index (not unit): duplicate keys arbitrate the stored array below.
    let mut seen: HashMap<(u32, String, u32, u64), usize> = HashMap::new();
    // Pre-drain maps snapshot for duplicate arbitration (mappings are
    // stable — providers stay loaded for the whole harvest; a failed
    // read degrades to first-seen-wins).
    let early_maps = maps::read_maps(cfg.pid).unwrap_or_default();
    let mut queries_observed: u64 = 0;
    let mut ops_hit: HashSet<u32> = HashSet::new();
    // (Array address, alg index) → names; ROW events join here (BPF
    // emits the 128B name once per walked alg; the array disambiguates
    // providers sharing (op, index)).
    let mut alg_names: HashMap<(u64, u64), String> = HashMap::new();

    while start.elapsed() < cfg.timeout {
        let mut fresh = false;
        while let Some(item) = ring.next() {
            fresh = true;
            last_event = Some(Instant::now());
            let b: &[u8] = &item;
            if b.len() < 8 {
                eprintln!("short event: {} bytes", b.len());
                continue;
            }
            let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            let u64at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            let want =
                if u32at(0) == KIND_ROW || u32at(0) == KIND_QUERY_RET || u32at(0) == KIND_TRIP {
                    ROW_EVENT_LEN
                } else {
                    EVENT_LEN
                };
            if b.len() < want {
                eprintln!("short event: {} bytes", b.len());
                continue;
            }
            match u32at(0) {
                KIND_INIT_RET => {
                    // aux carries the attach cookie: 0 = target
                    // provider, 1 = legacy.
                    let cookie = u64at(24);
                    if attached_queries.contains(&cookie) {
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
                    let addr = u64at(16);
                    let live = maps::read_maps(cfg.pid).with_context(|| {
                        format!("read maps of {} (target may have exited)", cfg.pid)
                    })?;
                    // Resolve in the init's own file: the target
                    // provider for cookie 0, the mapped legacy.so for
                    // cookie 1 (mapped by now — its init just ran).
                    let (off, path) = if cookie == LEGACY_COOKIE {
                        let m = live
                            .iter()
                            .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
                            .ok_or_else(|| {
                                anyhow!("legacy query addr {addr:#x} outside file mappings")
                            })?;
                        (addr - m.start + m.offset, PathBuf::from(&m.path))
                    } else {
                        let m = maps::provider_mapping(&live, &cfg.provider, &canon, addr)
                            .ok_or_else(|| {
                                anyhow!("query addr {addr:#x} outside provider mappings")
                            })?;
                        (addr - m.start + m.offset, cfg.provider.clone())
                    };
                    attach_pair(
                        &mut bpf,
                        &mut links,
                        "query_entry",
                        "query_return",
                        off,
                        Path::new(&path),
                        pid,
                        Some(cookie),
                    )?;
                    attached_queries.insert(cookie);
                    eprintln!("INSPECT stage=query addr={addr:#x} off={off:#x} cookie={cookie}");
                }
                KIND_QUERY_RET if u32at(8) == 0 => {
                    trigger_observed = true;
                    queries_observed += 1;
                    ops_hit.insert(u32at(4));
                }
                KIND_ALG => {
                    trigger_observed = true;
                    let name = &b[NAME_OFF..NAME_OFF + NAME_LEN];
                    let len = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                    let alg = String::from_utf8_lossy(&name[..len]).into_owned();
                    alg_names.insert((u64at(16), u64at(24)), alg);
                }
                KIND_ROW => {
                    trigger_observed = true;
                    let arr = u64at(24);
                    let Some(alg) = alg_names.get(&(arr, u64at(32))).cloned() else {
                        eprintln!("orphan row: op={} arr={arr:#x} idx={}", u32at(4), u64at(32));
                        continue;
                    };
                    let key = (u32at(4), alg.clone(), u32at(8), u64at(16));
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
                            && maps::provider_mapping(&early_maps, &cfg.provider, &canon, arr)
                                .is_some()
                        {
                            rows[i].arr = arr;
                        }
                    } else {
                        seen.insert(key, rows.len());
                        rows.push(schema::Row {
                            op: u32at(4),
                            alg,
                            funcid: u32at(8),
                            addr: u64at(16),
                            arr,
                        });
                    }
                }
                KIND_TRIP => {
                    // Deliberately NOT a dispatch trigger (doctrine in
                    // the no-trigger block below): tripwires observe
                    // independently of the dispatch harvest.
                    let s = &b[TRIP_ARG_OFF..TRIP_ARG_OFF + TRIP_ARG_LEN];
                    let len = s.iter().position(|c| *c == 0).unwrap_or(s.len());
                    trip_strs.push((
                        u32at(4) as u64,
                        String::from_utf8_lossy(&s[..len]).into_owned(),
                    ));
                }
                k => eprintln!("unknown event kind {k}"),
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
    let trip = read_trip(&mut bpf);
    let lgcalls = read_lgcalls(&mut bpf);
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
                trip_strs: &trip_strs,
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
        // - provider never mapped (provider mode) → COMPLETE-EMPTY.
        // - builtin mode → PARTIAL(no-query-trigger), UNLESS legacy
        //   mode with zero loads observed (quiet/engine-only target)
        //   → COMPLETE-EMPTY.
        let live_now = maps::read_maps(cfg.pid).unwrap_or_default();
        if live_now.is_empty() && !Path::new(&format!("/proc/{}", cfg.pid)).exists() {
            bail!("target {} exited before trigger", cfg.pid);
        }
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
            );
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
                    ..schema::Stats::trivial()
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
                return Ok(doc);
            }
            let mut doc = schema::emit(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &[],
                &[],
                false,
                &schema::Stats::trivial(),
            )?;
            if let Some(l) = legacy_live {
                doc["legacy"] = l;
            }
            return Ok(doc);
        }
        let loads_observed = probe_set
            .as_ref()
            .is_some_and(|set| trip_strs.iter().any(|(c, _)| set.is_load_cookie(*c)));
        if cfg.legacy && !loads_observed {
            // Quiet target: COMPLETE-EMPTY. Stats.builtin=false
            // suppresses the inventory counters (nothing was
            // inventoried — uninstrumented=14 would lie).
            let mut doc = schema::emit(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &[],
                &[],
                false,
                &schema::Stats::trivial(),
            )?;
            if let Some(l) = legacy_live {
                doc["legacy"] = l;
            }
            return Ok(doc);
        }
        eprintln!("INSPECT builtin: no query trigger before timeout");
        let mut stats = schema::Stats {
            builtin: true,
            queries_observed,
            resolution: resolution.clone(),
            reason: Some("no-query-trigger".to_string()),
            ..schema::Stats::trivial()
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
        return Ok(doc);
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
            maps::provider_mapping(&live, &cfg.provider, &canon, r.addr).is_some()
        });
        foreign_dropped = (before - rows.len()) as u64;
    }
    let mut ops_with_rows: HashSet<u32> = rows.iter().map(|r| r.op).collect();
    ops_with_rows.extend(legacy_rows.iter().map(|r| r.op));
    let mut zero_row_ops: Vec<u32> = ops_hit.difference(&ops_with_rows).copied().collect();
    zero_row_ops.sort_unstable();
    let truncated = read_trunc(&mut bpf);
    // Exact call volume from the CALLS map (QUERY_RET events are
    // first-hit-only; the event count is the pre-exit-2 fallback).
    if let Some(calls) = read_calls(&mut bpf) {
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
            resolution,
            reason,
            foreign_dropped,
            pid_recycled: 0,
        },
    )?;
    if cfg.legacy {
        let classes: Vec<String> = legacy_rows
            .iter()
            .map(|r| crate::kinds::classify_alg(&r.alg).0.to_string())
            .collect();
        let l = match &probe_set {
            Some(set) => legacy::section(&legacy::SectionInputs {
                set,
                trip: &trip,
                trip_strs: &trip_strs,
                legacy_queries: lgcalls,
                legacy_classes: classes,
                extra_findings: &extra_findings,
            }),
            None => blind_legacy_section(),
        };
        doc["legacy"] = l;
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    #[test]
    fn row_key_includes_addr() {
        // Regression pin for the scaled-table collapse (72 vs 504):
        // same (op, alg, funcid) at distinct addrs are distinct rows.
        let a = (1u32, "X".to_string(), 7u32, 0x1000u64);
        let b = (1u32, "X".to_string(), 7u32, 0x2000u64);
        let mut s: std::collections::HashSet<(u32, String, u32, u64)> =
            std::collections::HashSet::new();
        assert!(s.insert(a));
        assert!(s.insert(b));
        assert_eq!(s.len(), 2);
    }
}
