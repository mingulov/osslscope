//! SPDX-License-Identifier: GPL-3.0-or-later
//! Live harvest driver (T06): run-policy over [`session::DiscoverySession`].
//!
//! This module owns the one-shot harvest run contract — attach,
//! settle/timeout polling with spawn-mode hooks, the trigger
//! doctrine, and the harvest JSON document — while the session owns
//! the mechanism (loaded programs/maps, links, ring, pin, decode,
//! epochs, joins). `inspect` wraps [`run`]; capture wraps
//! [`run_detailed`]; both inherit the session engine. Durations and
//! hooks are caller run-policy; the session itself never blocks on
//! a full harvest.
//!
//! Behavior contract (preserved from the pre-session driver):
//! machine-readable `INSPECT` progress on stderr (stdout stays pure
//! JSON), the fixture-only `evp_driver` cmdline marker as a
//! caller-supplied option (`None` = any target), builtin mode
//! (`--builtin`), legacy tripwires, and byte-identical documents
//! for identical observations.

use crate::discovery::{legacy, maps, schema, session};
use anyhow::bail;
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Legacy-query attach cookie (primary query/init use 0).
pub(crate) const LEGACY_COOKIE: u64 = 1;

/// Build the `ALG_CLASS` kernel table entries from the single
/// registry: every registered name (class = registry index) plus
/// every weak-only name (class = `OTHER`, weak set). Fails closed on
/// a hash collision or an over-capacity name — the kernel matches
/// hash+exact-length, so a within-table collision would map one key
/// to two classes.
pub fn build_alg_entries() -> anyhow::Result<Vec<(u64, wire::AlgClassValue)>> {
    let mut out: Vec<(u64, wire::AlgClassValue)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    // Semantic ids (R01): verified equivalence from
    // `kinds::algorithm_semantic_id` — deterministic, BPF-internal
    // (only the mixed flag leaves the kernel). Synonyms share one
    // id so multi-spelling lists stay OK; distinct algorithms —
    // even in one macro family — mix.
    let mut push = |name: &str, class: u16, weak: bool, canon: u16| -> anyhow::Result<()> {
        if name.len() > wire::MAX_ALG_NAME {
            anyhow::bail!("registry name over kernel cap: {name:?}");
        }
        let h = wire::fnv1a64(name.as_bytes());
        if !seen.insert(h) {
            anyhow::bail!("classifier hash collision on {name:?}");
        }
        if class != wire::OTHER_CLASS && canon == wire::OTHER_CLASS {
            anyhow::bail!("canon id exhausted (H3 sentinel reserved)");
        }
        let mut bytes = [0u8; wire::MAX_ALG_NAME];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        out.push((
            h,
            wire::AlgClassValue {
                class,
                weak: u8::from(weak),
                len: name.len() as u8,
                canon,
                name: bytes,
            },
        ));
        Ok(())
    };
    for (i, a) in crate::kinds::ALG_NAMES.iter().enumerate() {
        let class =
            u16::try_from(i).map_err(|_| anyhow::anyhow!("registry exceeds class id space"))?;
        if class == wire::OTHER_CLASS {
            anyhow::bail!("registry exceeds class id space");
        }
        let canon = crate::kinds::algorithm_semantic_id(a.name)
            .ok_or_else(|| anyhow::anyhow!("registry name has no semantic id: {0:?}", a.name))?;
        push(a.name, class, crate::kinds::is_weak_alg(a.name), canon)?;
    }
    for w in crate::kinds::WEAK_ALGS {
        if !crate::kinds::is_known_alg(w) {
            push(w, wire::OTHER_CLASS, true, wire::OTHER_CLASS)?;
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
            anyhow::bail!("trip pattern over kernel cap: {name:?}");
        }
        let h = wire::fnv1a64(name.as_bytes());
        if !seen.insert(h) {
            anyhow::bail!("trip table hash collision on {name:?}");
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
            anyhow::bail!("load taxonomy drift: {name:?} left the registry");
        }
        push(name, wire::TRIP_OTHER, class)?;
    }
    Ok(out)
}

/// Decode one trip verdict against the probe taxonomy: the cookie
/// selects engine vs load decoding, and the class id must be valid
/// for that taxonomy. `None` (unknown cookie or out-of-taxonomy
/// class) fails closed to a dropped hit.
pub(crate) fn decode_trip_hit(
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

/// Resolved stage-2 attach target: file offset, object path,
/// stat-domain backing identity (H5; maps-text fallback when
/// unstatable), and the resolve-time raw (dev, ino) the install
/// must bind against (`None` when unstatable — install fails
/// closed).
#[derive(Debug)]
pub(crate) struct ResolvedTarget {
    pub off: u64,
    pub path: PathBuf,
    pub dev: String,
    pub ino: u64,
    pub expected: Option<(u64, u64)>,
}

/// Resolve a BPF-reported query-fn address to its stage-2 attach
/// target. The backing identity rides along so attach reuse
/// compares bytes, not just the locator: a same-path replacement
/// keeps path+offset but changes (dev,ino) and must re-attach
/// (T14r4-2b). Errors are approved-vocabulary literals (round 2,
/// residual F): they surface in `attach_diagnostics`, so they
/// carry no provider path and no cookie — the cookie already rides
/// structurally (`AttachKind::Stage2`), and stderr is a scanned
/// artifact, so error paths redact like emission.
pub(crate) fn resolve_query_target(
    live: &[maps::Mapping],
    provider: &Path,
    canon: &str,
    addr: u64,
    cookie: u64,
) -> anyhow::Result<ResolvedTarget> {
    if cookie == LEGACY_COOKIE {
        let m = live
            .iter()
            .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
            .ok_or_else(|| anyhow::anyhow!("legacy stage-2 attach has no file mapping"))?;
        // Expected identity pins the maps-time inode (the VMA pins
        // it — a same-path replacement cannot reuse the number)
        // with the resolve-time raw dev; unstatable paths bind
        // nothing and fail closed at install.
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(&m.path).ok();
        let expected = meta.as_ref().map(|meta| (meta.dev(), m.ino));
        // H5: target dev is STAT-domain (rendered resolve-time
        // fstat), falling back to maps text when unstatable —
        // retry idents and reuse tuples compare in one domain.
        let dev = meta
            .as_ref()
            .map(|meta| crate::plan::render_stat_dev(meta.dev()))
            .unwrap_or_else(|| m.dev.clone());
        Ok(ResolvedTarget {
            off: addr - m.start + m.offset,
            path: PathBuf::from(&m.path),
            dev,
            ino: m.ino,
            expected,
        })
    } else {
        let (m, raw) = maps::provider_mapping(live, provider, canon, addr)
            .ok_or_else(|| anyhow::anyhow!("stage-2 attach has no provider mapping"))?;
        // H5: `raw` is the provider's resolve-time stat identity
        // (provider_mapping binds stat-vs-stat) — render it for
        // the target dev (stat-domain, like the legacy branch).
        Ok(ResolvedTarget {
            off: addr - m.start + m.offset,
            path: provider.to_path_buf(),
            dev: crate::plan::render_stat_dev(raw.0),
            ino: m.ino,
            expected: Some(raw),
        })
    }
}

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
    /// Observation started at process birth: the target performed no
    /// observable behavior before attach (spawn-held-stopped until
    /// attaches installed, or caller-enforced pre-attach silence such
    /// as GO-gating). Attach-mode callers pass false: mid-life quiet
    /// cannot exclude pre-attach cached callbacks/loads, so a quiet
    /// attach is PARTIAL (unknown), never COMPLETE-EMPTY (F-B/A14).
    pub observed_from_birth: bool,
}

/// Proven-quiet contract (F-B/A14, shared by legacy + file
/// providers per H6): a quiet target is proven-empty only with
/// something watching (`watched` — tripwires attached for
/// legacy, load hook armed AND quiet for file providers; an
/// unwatchable surface is blind, not quiet) AND observation
/// from process birth (attach-mode quiet cannot exclude
/// pre-attach cached callbacks/loads/queries). Gap signals
/// still flip to PARTIAL inside `schema::emit`.
fn proven_quiet(watched: bool, observed_from_birth: bool) -> bool {
    watched && observed_from_birth
}

/// Provider presence by identity (H6/A-7-a): the EXPECTED
/// provider file (bootstrap pin identity) is PRESENT iff some
/// live mapping stats to the same (dev, ino) — stat-vs-stat
/// (H5), never pathname. A hardlink-alias mapping reads
/// present (same file); a same-path replacement reads absent
/// (the doc is about P — the expected file never mapped).
/// Unstatable mappings cannot match (no maps-fallback here —
/// that would reintroduce cross-domain joins); no bootstrap
/// binding reads absent (conservative).
fn provider_present_by_identity(
    live: &[maps::Mapping],
    expected: Option<&(String, String, u64)>,
) -> bool {
    let Some((_, dev, ino)) = expected else {
        return false;
    };
    live.iter()
        .any(|m| m.ino == *ino && session::stat_dev_of(&m.path).as_deref() == Some(dev.as_str()))
}

/// Provider-load hook state (H6/A-7-c): the hook is armed AND
/// quiet iff a tripwire set is attached and no load-cookie hit
/// arrived all run (hits accumulate in the snapshot — an
/// end-quiet read covers every poll). Any `OSSL_PROVIDER_load`
/// / `try_load` firing breaks quiet regardless of name
/// taxonomy (classification drops unlisted names, but the raw
/// hit still counts here).
fn load_hook_armed_and_quiet(set: Option<&legacy::ProbeSet>, hits: &[legacy::TripHit]) -> bool {
    set.is_some_and(|s| !hits.iter().any(|h| s.is_load_cookie(h.cookie)))
}

/// File-provider quiet verdict (H6/A-7): pure decision over
/// the end-of-run evidence. Returns the PARTIAL reason to
/// emit, or `None` for COMPLETE-EMPTY (gap signals still flip
/// to PARTIAL inside `schema::emit`).
///
/// - init fired but silent → PARTIAL always (2026-09-18
///   verdict stands: race-miss vs idle indistinguishable
///   post-hoc, even at birth).
/// - mapped-but-silent + birth → COMPLETE-EMPTY (the
///   loss machinery closes the stage-2 blind window — a
///   clean snapshot proves quiet); warm → PARTIAL
///   (`no-query-trigger`: pre-attach queries cannot be
///   excluded).
/// - absent + proven-quiet (birth + load hook armed and
///   quiet) → COMPLETE-EMPTY (affirmative absence: owned
///   children are held stopped until hooks arm, so no
///   load cycle can hide from both census and hook).
/// - absent otherwise → PARTIAL (`no-query-trigger`,
///   reusing the frozen reason: silence without trigger
///   is exactly what happened — a new `absence-*`
///   reason would need runbook + consumer updates for
///   zero new information, so it stays frozen by
///   recorded rationale, never silently).
fn file_quiet_verdict(
    provider_present: bool,
    primary_init_observed: bool,
    observed_from_birth: bool,
    load_armed_and_quiet: bool,
) -> Option<&'static str> {
    if primary_init_observed {
        return Some("init-without-queries");
    }
    if provider_present {
        if observed_from_birth {
            return None;
        }
        return Some("no-query-trigger");
    }
    if proven_quiet(load_armed_and_quiet, observed_from_birth) {
        return None;
    }
    Some("no-query-trigger")
}

/// Ops with at least one live-epoch table lacking termination
/// proof, sorted. Retired epochs survive in retained reasons, not
/// in this op list.
fn unterminated_ops_of(snap: &session::DiscoverySnapshot) -> Vec<u32> {
    let mut ops: Vec<u32> = snap
        .tables
        .iter()
        .filter(|t| !matches!(t.state, session::CoverageState::Terminated { .. }))
        .map(|t| t.op)
        .collect();
    ops.sort_unstable();
    ops.dedup();
    ops
}

/// Tracker-equivalent gap fragment from a session snapshot: the
/// per-poll joins already merged termination proofs, walk-shape
/// bits, and failure counters, so every post-drain path reads one
/// cumulative view.
fn snap_gap_stats(snap: &session::DiscoverySnapshot) -> schema::Stats {
    schema::Stats {
        truncated: snap.truncated_ops.clone(),
        unterminated_ops: unterminated_ops_of(snap),
        losses: snap.losses.clone(),
        lossy_slots: snap.lossy_slots,
        retained_reasons: snap.retained_reasons.clone(),
        ..schema::Stats::trivial()
    }
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
    gaps: Option<schema::Stats>,
) -> anyhow::Result<serde_json::Value> {
    // Post-drain callers pass the snapshot gap fragment so
    // walk-shape bits and losses travel even on bootstrap-failure
    // PARTIALs; pre-drain/discard callers pass None (nothing was
    // observed, or the evidence is tainted and discarded).
    let mut stats = gaps.unwrap_or_else(schema::Stats::trivial);
    stats.builtin = builtin;
    stats.reason = Some(reason.to_string());
    stats.pid_recycled = pid_recycled;
    let mut doc = schema::emit(
        provider_name,
        provider,
        canon,
        elf_bytes,
        &[],
        &[],
        false,
        &stats,
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

/// Map a session error onto the harvest contract: a session-level
/// recycle becomes the harvest discard doc (zero rows; blind legacy
/// at most), anything else propagates unchanged.
#[allow(clippy::too_many_arguments, reason = "one coherent doc identity")]
fn map_session_err(
    cfg: &Config,
    provider_name: &str,
    canon: &str,
    elf_bytes: &[u8],
    e: anyhow::Error,
) -> anyhow::Error {
    if e.downcast_ref::<session::Recycled>().is_some() {
        let blind = cfg.legacy.then(blind_legacy_section);
        match partial_doc(
            provider_name,
            &cfg.provider,
            canon,
            elf_bytes,
            "pid-recycled",
            cfg.builtin,
            blind,
            1,
            None,
        ) {
            Ok(doc) => anyhow::Error::new(Recycled { doc }),
            Err(e2) => e2,
        }
    } else {
        e
    }
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
        call_partition: legacy::CallPartition::default(),
    })
}

/// Exact in-memory harvest totals for capture callers (the doc
/// only carries them when builtin/PARTIAL — cold-gap accounting
/// needs them always).
#[derive(Debug, Clone, Default)]
pub struct HarvestTotals {
    pub queries_observed: u64,
    /// Per-op query arrivals, sorted by op (P5d attribution; same
    /// source as the total — see the session field).
    pub queries_by_op: Vec<(u32, u64)>,
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
    let elf_bytes = std::fs::read(&cfg.provider)?;
    let canon = std::fs::canonicalize(&cfg.provider)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let provider_name: String = if cfg.builtin {
        "default".to_string()
    } else {
        cfg.provider
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string())
    };
    let session_cfg = session::DiscoveryConfig {
        provider: cfg.provider.clone(),
        object: cfg.object.clone(),
        object_bytes: None,
        builtin: cfg.builtin,
        legacy: cfg.legacy,
        table: cfg.table.clone(),
        force_offset: cfg.force_offset,
        explicit_offsets: cfg.table.is_some() || cfg.force_offset.is_some(),
        cmdline_marker: cfg.cmdline_marker.clone(),
    };
    let mut sess = match session::DiscoverySession::attach(&session_cfg, cfg.pid) {
        Ok(s) => s,
        Err(e) => {
            return Err(map_session_err(cfg, &provider_name, &canon, &elf_bytes, e));
        }
    };
    // Early return only when NOTHING can be observed: dispatch blind
    // and no tripwires (statically linked target). Blind legacy
    // section travels when --legacy is set, nothing otherwise
    // (exit-1/2 behavior identical).
    {
        let snap = sess.snapshot();
        if snap.dispatch.preset_reason.is_some() && !snap.legacy.planned {
            let blind = if cfg.legacy {
                Some(blind_legacy_section())
            } else {
                None
            };
            let reason = snap.dispatch.preset_reason.clone().unwrap();
            let doc = partial_doc(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &reason,
                cfg.builtin,
                blind,
                0,
                None,
            )?;
            drop(sess);
            return Ok((doc, HarvestTotals::default()));
        }
    }
    // Spawn mode releases the stopped child here: every attach is
    // installed, so the post-exec query wave is fully observed.
    on_attached()?;

    // Pre-poll maps snapshot for the attribution fallback below
    // (mappings are stable — providers stay loaded for the whole
    // run; a failed read degrades to an empty fallback).
    let early_maps = maps::read_maps(cfg.pid).unwrap_or_default();
    let start = Instant::now();
    let mut last_event = None;
    let budget = session::PollBudget::default();
    while start.elapsed() < cfg.timeout {
        // Short-lived targets (and signals): no more events can
        // arrive — end the drain instead of idling out the settle.
        if should_stop() {
            break;
        }
        let delta = match sess.poll(budget.clone()) {
            Ok(d) => d,
            Err(e) => {
                return Err(map_session_err(cfg, &provider_name, &canon, &elf_bytes, e));
            }
        };
        let fresh = delta.events_consumed > 0;
        if fresh {
            last_event = Some(Instant::now());
        }
        // Every stage-2 failure fails fast with the installer's own
        // error (the old immediate-`?` behavior): this one-shot
        // wrapper has no PARTIAL vocabulary for a half-attached
        // dispatch plane, so it errors rather than silently keeping
        // a blind run. Event-driven retry lives in the session for
        // persistent (T08) consumers.
        if let Some(msg) = delta.attaches.iter().find_map(|a| a.failed.clone()) {
            bail!("{msg}");
        }
        if delta.trigger_observed && !fresh {
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
    // Quiesce-then-PROCESS close: links drop, the ring tail
    // joins the snapshot (bounded — only the residual past one
    // poll budget counts into shortfall, P6 §6ii), maps join once
    // more, and the pin verifies (recycle discards everything
    // above).
    let snap = match sess.close() {
        Ok(s) => s,
        Err(e) => {
            return Err(map_session_err(cfg, &provider_name, &canon, &elf_bytes, e));
        }
    };
    // Per-cookie trip dump (all paths: the no-trigger path needs it
    // most — a quiet dispatch with firing tripwires).
    if cfg.legacy && std::env::var("OSSL_DEBUG_TRIP").is_ok() {
        if let Some(set) = &snap.legacy.set {
            let by_cookie: HashMap<u64, &legacy::Probe> =
                set.probes.iter().map(|p| (p.cookie, p)).collect();
            let mut keys: Vec<u64> = snap.legacy.trip.keys().copied().collect();
            keys.sort_unstable();
            for k in keys {
                let p = by_cookie.get(&k);
                eprintln!(
                    "TRIPDBG cookie={k} n={} sym={} fam={:?} mod={} off={}",
                    snap.legacy.trip[&k],
                    p.map(|p| p.symbol.as_str()).unwrap_or("??"),
                    p.and_then(|p| p.family),
                    p.map(|p| p.module.as_str()).unwrap_or("??"),
                    p.map(|p| format!("{:#x}", p.offset)).unwrap_or("??".into()),
                );
            }
        }
    }
    let extra_findings: Vec<&str> = snap
        .legacy
        .extra_findings
        .iter()
        .map(|s| s.as_str())
        .collect();
    // Live legacy section (None without --legacy; blind when no
    // tripwires attached). Row classes arrive post-partition; the
    // no-trigger paths below reuse this with empty classes.
    let legacy_live = if cfg.legacy {
        match &snap.legacy.set {
            Some(set) => Some(legacy::section(&legacy::SectionInputs {
                set,
                trip: &snap.legacy.trip,
                trip_hits: &snap.legacy.hits,
                legacy_queries: snap.legacy.executed_queries,
                legacy_classes: Vec::new(),
                extra_findings: &extra_findings,
                call_partition: legacy::CallPartition::default(),
            })),
            None => Some(blind_legacy_section()),
        }
    } else {
        None
    };
    if !snap.dispatch.trigger_observed {
        // Doctrine: tripwires are NOT dispatch triggers. Silence means:
        // - target gone → hard error (nothing observable, not even maps).
        // - preset reason (anchor failed) → PARTIAL(preset) + legacy.
        // - file-provider mode → the H6 quiet table
        //   (`file_quiet_verdict`): presence by bootstrap
        //   identity (never pathname); mapped-but-silent
        //   completes ONLY from birth (warm stays PARTIAL);
        //   init-without-queries stays PARTIAL always
        //   (verdict 2026-09-18); absence completes ONLY
        //   proven-quiet (birth + load hook armed and
        //   quiet), else PARTIAL(no-query-trigger).
        // - builtin mode → PARTIAL(no-query-trigger), UNLESS legacy
        //   mode with zero loads observed (quiet/engine-only target)
        //   → COMPLETE-EMPTY.
        let live_now = maps::read_maps(cfg.pid).unwrap_or_default();
        if live_now.is_empty() && !Path::new(&format!("/proc/{}", cfg.pid)).exists() {
            bail!("target {} exited before trigger", cfg.pid);
        }
        // No separate completion join here: the session joined map
        // snapshots on every poll, so quiet paths already carry
        // host-side drops and kernel-side failures in the snapshot.
        if let Some(reason) = snap.dispatch.preset_reason.clone() {
            return partial_doc(
                &provider_name,
                &cfg.provider,
                &canon,
                &elf_bytes,
                &reason,
                cfg.builtin,
                legacy_live,
                0,
                Some(snap_gap_stats(&snap)),
            )
            .map(|d| {
                (
                    d,
                    HarvestTotals {
                        queries_observed: snap.queries_observed,
                        queries_by_op: snap.queries_by_op.clone(),
                    },
                )
            });
        }
        if !cfg.builtin {
            // H6: presence by bootstrap identity (never pathname),
            // verdict by the shared quiet table. COMPLETE-EMPTY
            // only when the snapshot is also clean: any gap flips
            // the doc to PARTIAL below.
            let present =
                provider_present_by_identity(&live_now, snap.dispatch.bootstrap_binding.as_ref());
            let hook_quiet = load_hook_armed_and_quiet(snap.legacy.set.as_ref(), &snap.legacy.hits);
            let verdict = file_quiet_verdict(
                present,
                snap.dispatch.primary_init_observed,
                cfg.observed_from_birth,
                hook_quiet,
            );
            let stats = match verdict {
                Some(reason) => schema::Stats {
                    resolution: snap.dispatch.resolution.clone(),
                    reason: Some(reason.to_string()),
                    ..snap_gap_stats(&snap)
                },
                None => snap_gap_stats(&snap),
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
            return Ok((
                doc,
                HarvestTotals {
                    queries_observed: snap.queries_observed,
                    queries_by_op: snap.queries_by_op.clone(),
                },
            ));
        }
        let loads_observed = snap.legacy.set.as_ref().is_some_and(|set| {
            snap.legacy
                .hits
                .iter()
                .any(|h| set.is_load_cookie(h.cookie))
        });
        // F-B/A14: COMPLETE-EMPTY only for proven-quiet (tripwires
        // attached + observed from birth). Anything else falls
        // through to PARTIAL(no-query-trigger) below with the
        // (possibly blind) legacy section attached.
        if cfg.legacy
            && !loads_observed
            && proven_quiet(snap.legacy.set.is_some(), cfg.observed_from_birth)
        {
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
                &snap_gap_stats(&snap),
            )?;
            if let Some(l) = legacy_live {
                doc["legacy"] = l;
            }
            return Ok((
                doc,
                HarvestTotals {
                    queries_observed: snap.queries_observed,
                    queries_by_op: snap.queries_by_op.clone(),
                },
            ));
        }
        eprintln!("INSPECT builtin: no query trigger before timeout");
        let mut stats = schema::Stats {
            builtin: true,
            queries_observed: snap.queries_observed,
            resolution: snap.dispatch.resolution.clone(),
            reason: Some("no-query-trigger".to_string()),
            ..snap_gap_stats(&snap)
        };
        stats.zero_row_ops = snap.ops_hit.clone();
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
        return Ok((
            doc,
            HarvestTotals {
                queries_observed: snap.queries_observed,
                queries_by_op: snap.queries_by_op.clone(),
            },
        ));
    }

    // Rows from retained session candidates (all providers; the
    // legacy partition and builtin filter below are emit-time views,
    // not ingest drops).
    let mut rows: Vec<schema::Row> = snap
        .candidates
        .iter()
        .map(|c| schema::Row {
            op: c.op,
            alg_class: c.class.clone(),
            weak: c.weak,
            status: c.status.clone(),
            funcid: c.funcid,
            impl_addr: c.impl_addr,
            arr: c.arr,
        })
        .collect();
    // Post-drain maps for attribution. A target that exits after the
    // trigger (fallback cell: driver gone by drain end) leaves an
    // empty re-read — attributing against that drops every row as
    // foreign. Mappings are stable within a run (providers stay
    // loaded), so an empty re-read falls back to the pre-poll
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
    let ops_hit: HashSet<u32> = snap.ops_hit.iter().copied().collect();
    let mut zero_row_ops: Vec<u32> = ops_hit.difference(&ops_with_rows).copied().collect();
    zero_row_ops.sort_unstable();
    // No separate completion join here: the session joined
    // termination proofs, walk-shape bits, and failure counters on
    // every poll, and call volume below is the CALLS-joined total
    // (QUERY_RET events are first-hit-only; the event count is the
    // pre-exit-2 fallback when the map is absent). Best-effort under
    // threads: shared-map increments are read-modify-write, so
    // concurrent hits may undercount; the cold-gap trigger (>0) is
    // robust to that, only the counter value may read low.
    let queries_observed = snap.queries_observed;
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
        true,
        &schema::Stats {
            builtin: cfg.builtin,
            queries_observed,
            zero_row_ops,
            truncated: snap.truncated_ops.clone(),
            unterminated_ops: unterminated_ops_of(&snap),
            losses: snap.losses.clone(),
            lossy_slots: snap.lossy_slots,
            retained_reasons: snap.retained_reasons.clone(),
            resolution: snap.dispatch.resolution.clone(),
            reason,
            foreign_dropped,
            pid_recycled: 0,
        },
    )?;
    if cfg.legacy {
        // Rows arrive pre-classified (kernel verdicts resolved at
        // ring decode); legacy classes are carried, not recomputed.
        let classes: Vec<String> = legacy_rows.iter().map(|r| r.alg_class.clone()).collect();
        let l = match &snap.legacy.set {
            Some(set) => legacy::section(&legacy::SectionInputs {
                set,
                trip: &snap.legacy.trip,
                trip_hits: &snap.legacy.hits,
                legacy_queries: snap.legacy.executed_queries,
                legacy_classes: classes,
                extra_findings: &extra_findings,
                // Discovery-only: no executions exist to partition.
                call_partition: legacy::CallPartition::default(),
            }),
            None => blind_legacy_section(),
        };
        doc["legacy"] = l;
    }
    Ok((
        doc,
        HarvestTotals {
            queries_observed,
            queries_by_op: snap.queries_by_op.clone(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osslscope_ebpf_common as wire;

    #[test]
    fn legacy_quiet_complete_needs_attached_tripwires_and_birth_observation() {
        // F-B/A14 truth table: COMPLETE-EMPTY only with tripwires
        // attached (something was watching) AND observation from
        // process birth (attach-mode quiet cannot exclude pre-attach
        // cached callbacks/loads).
        assert!(proven_quiet(true, true));
        assert!(!proven_quiet(false, true));
        assert!(!proven_quiet(true, false));
        assert!(!proven_quiet(false, false));
    }

    #[test]
    fn h6_t1_provider_present_is_identity_not_pathname() {
        // H6 (A-7/a): the mapped check binds the EXPECTED
        // file's (dev, ino) — a hardlink-alias mapping reads
        // PRESENT; a same-path different file reads ABSENT.
        // RED pre-H6 (pathname match inline in run; no
        // identity check exists).
        let dir = std::env::temp_dir().join(format!("osslscope-h6t1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let orig = dir.join("prov.so");
        let alias = dir.join("alias.so");
        std::fs::write(&orig, b"provider-bytes").unwrap();
        std::fs::hard_link(&orig, &alias).unwrap();
        let other = dir.join("other.so");
        std::fs::write(&other, b"different-bytes").unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(&orig).unwrap();
        let expected = (
            orig.to_string_lossy().into_owned(),
            crate::plan::render_stat_dev(meta.dev()),
            meta.ino(),
        );
        // Hardlink alias mapped (different path, same file):
        // PRESENT. The maps dev-string is forged divergent
        // (btrfs-shape) — identity never consults it.
        let live = vec![maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0,
            dev: "00:22".to_string(),
            ino: meta.ino(),
            path: alias.to_string_lossy().into_owned(),
        }];
        assert!(provider_present_by_identity(&live, Some(&expected)));
        // Same path, different file (replaced): ABSENT.
        let live2 = vec![maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0,
            dev: "00:22".to_string(),
            ino: std::fs::metadata(&other).unwrap().ino(),
            path: orig.to_string_lossy().into_owned(),
        }];
        assert!(!provider_present_by_identity(&live2, Some(&expected)));
        // No bootstrap binding: ABSENT (conservative).
        assert!(!provider_present_by_identity(&live, None));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn h6_t2_warm_mapped_quiet_stays_partial_birth_completes() {
        // H6 (A-7/b): mapped-but-silent completes ONLY with
        // birth (the loss machinery closes the stage-2 blind
        // window — a clean snapshot proves quiet); warm
        // attach stays PARTIAL (pre-attach queries cannot be
        // excluded). The load hook is irrelevant once mapped
        // (pinned both ways).
        assert_eq!(
            file_quiet_verdict(true, false, false, false),
            Some("no-query-trigger")
        );
        assert_eq!(
            file_quiet_verdict(true, false, false, true),
            Some("no-query-trigger")
        );
        assert_eq!(file_quiet_verdict(true, false, true, false), None);
        assert_eq!(file_quiet_verdict(true, false, true, true), None);
    }

    #[test]
    fn h6_t3_absence_needs_birth_and_quiet_hook() {
        // H6 (A-7/c): absent + birth + load hook armed and
        // quiet → COMPLETE-EMPTY (affirmative absence);
        // absent + birth + hook unarmed → PARTIAL (absence
        // unprovable — frozen reason reused by rationale).
        assert_eq!(file_quiet_verdict(false, false, true, true), None);
        assert_eq!(
            file_quiet_verdict(false, false, true, false),
            Some("no-query-trigger")
        );
        assert_eq!(
            file_quiet_verdict(false, false, false, true),
            Some("no-query-trigger")
        );
    }

    #[test]
    fn h6_t4_load_hook_firing_breaks_absence() {
        // H6 (A-7/c): the hook catches what census misses — a
        // dlopen-cycle (mapped in no poll) that fired the load
        // tripwire reads NOT-quiet (→ PARTIAL at the verdict).
        // Any load-cookie hit breaks quiet regardless of name
        // taxonomy (class/status irrelevant here); non-load
        // hits don't; no set at all reads unarmed.
        let mut set = legacy::ProbeSet::default();
        set.load_cookies.insert(7);
        let load_hit = legacy::TripHit {
            cookie: 7,
            class: 0,
            status: 0,
        };
        let other_hit = legacy::TripHit {
            cookie: 9,
            class: 0,
            status: 0,
        };
        assert!(!load_hook_armed_and_quiet(Some(&set), &[load_hit]));
        assert!(load_hook_armed_and_quiet(Some(&set), &[other_hit]));
        assert!(load_hook_armed_and_quiet(Some(&set), &[]));
        assert!(!load_hook_armed_and_quiet(None, &[]));
        assert!(!load_hook_armed_and_quiet(None, &[other_hit]));
    }

    #[test]
    fn h6_t5_init_without_queries_stays_partial() {
        // H6 (no-regression pin of the 2026-09-18 verdict):
        // init fired but silent → PARTIAL always, even at
        // birth (race-miss vs idle indistinguishable).
        assert_eq!(
            file_quiet_verdict(true, true, true, true),
            Some("init-without-queries")
        );
        assert_eq!(
            file_quiet_verdict(true, true, false, false),
            Some("init-without-queries")
        );
    }

    #[test]
    fn row_key_includes_addr_array_weak_and_status() {
        // Regression pin for the scaled-table collapse (72 vs 504):
        // same (op, class, funcid) at distinct addrs are distinct
        // rows; weak evidence and kernel status survive alias
        // collapse (same class, different verdicts stay distinct);
        // and two providers sharing one implementation stay
        // distinct per offering array (R02 advertising identity).
        // The session core dedupes on this same key.
        let a = (
            1u32,
            "X".to_string(),
            false,
            "ok".to_string(),
            7u32,
            0x1000u64,
            0x5000u64,
        );
        let b = (
            1u32,
            "X".to_string(),
            false,
            "ok".to_string(),
            7u32,
            0x2000u64,
            0x5000u64,
        );
        let c = (
            1u32,
            "X".to_string(),
            true,
            "ok".to_string(),
            7u32,
            0x1000u64,
            0x5000u64,
        );
        let d = (
            1u32,
            "other".to_string(),
            false,
            "overlong".to_string(),
            7u32,
            0x1000u64,
            0x5000u64,
        );
        let e = (
            1u32,
            "other".to_string(),
            false,
            "unknown".to_string(),
            7u32,
            0x1000u64,
            0x5000u64,
        );
        let f = (
            1u32,
            "X".to_string(),
            false,
            "ok".to_string(),
            7u32,
            0x1000u64,
            0x6000u64,
        );
        let mut s: std::collections::HashSet<(u32, String, bool, String, u32, u64, u64)> =
            std::collections::HashSet::new();
        assert!(s.insert(a));
        assert!(s.insert(b));
        assert!(s.insert(c));
        assert!(s.insert(d));
        assert!(s.insert(e));
        assert!(s.insert(f));
        assert_eq!(s.len(), 6);
    }

    #[test]
    fn resolve_query_target_redacts_errors() {
        use std::os::unix::fs::MetadataExt;
        // Real provider file: stat-or-None resolution needs a
        // stat-able path whose (dev,ino) backs the staged mapping.
        let dir = std::env::temp_dir().join(format!("osslscope-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prov = dir.join("prov.so");
        std::fs::write(&prov, b"resolve-bytes").unwrap();
        let meta = std::fs::metadata(&prov).unwrap();
        let dev = format!(
            "{:02x}:{:02x}",
            libc::major(meta.dev()),
            libc::minor(meta.dev())
        );
        let live = vec![super::maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0x500,
            dev: dev.clone(),
            ino: meta.ino(),
            path: prov.to_string_lossy().into_owned(),
        }];
        // Happy paths resolve to file offsets plus backing identity.
        let t = super::resolve_query_target(&live, &prov, "", 0x1400, 0).unwrap();
        assert_eq!((t.off, t.dev, t.ino), (0x900, dev.clone(), meta.ino()));
        assert_eq!(t.path, prov);
        assert_eq!(t.expected, Some((meta.dev(), meta.ino())));
        let t = super::resolve_query_target(&live, &prov, "", 0x1400, 1).unwrap();
        assert_eq!((t.off, t.dev, t.ino), (0x900, dev.clone(), meta.ino()));
        assert_eq!(t.path, prov);
        assert_eq!(t.expected, Some((meta.dev(), meta.ino())));
        // Failure paths redact the runtime address (both hex and
        // decimal forms) while keeping observer context.
        for cookie in [0u64, 1] {
            let addr = 0x7f00_deed_beefu64;
            let err = super::resolve_query_target(&live, &prov, "", addr, cookie)
                .unwrap_err()
                .to_string();
            assert!(
                !err.contains(&format!("{addr:#x}")),
                "hex addr leaked: {err}"
            );
            assert!(!err.contains(&addr.to_string()), "addr leaked: {err}");
        }
        std::fs::remove_dir_all(&dir).unwrap_or_default();
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
        assert!(super::decode_trip_hit(9, wire::LOAD_LEGACY, wire::TRIP_OK, &set).is_some());
        assert!(super::decode_trip_hit(9, wire::TRIP_OTHER, wire::TRIP_UNREADABLE, &set).is_some());
        assert!(super::decode_trip_hit(10, wire::ENGINE_DYNAMIC, wire::TRIP_OK, &set).is_some());
        // The cookie selects the decoder (numeric spaces overlap by
        // design): class 3 is LOAD_FIPS under a load cookie but
        // invalid under an engine cookie. Unknown cookies and
        // out-of-range classes are dropped.
        assert!(super::decode_trip_hit(9, wire::LOAD_FIPS, wire::TRIP_OK, &set).is_some());
        assert!(super::decode_trip_hit(10, wire::LOAD_FIPS, wire::TRIP_OK, &set).is_none());
        assert!(super::decode_trip_hit(11, wire::TRIP_OTHER, wire::TRIP_OK, &set).is_none());
        assert!(super::decode_trip_hit(9, 99, wire::TRIP_OK, &set).is_none());
        assert!(super::decode_trip_hit(10, 99, wire::TRIP_OK, &set).is_none());
    }

    /// Round 2, residual F (diagnostics vocabulary): resolve
    /// failures surface in `attach_diagnostics`, whose approved
    /// vocabulary (allowlist-v1) is producer-literal failure texts
    /// — no paths, no pointers, no target strings, no runtime
    /// addresses. The query cookie already rides structurally
    /// (`AttachKind::Stage2`), so the text carries no numbers
    /// either — pure literals.
    #[test]
    fn resolve_failures_use_literal_diagnostics() {
        // Legacy cookie, no file mapping for the address.
        let err = super::resolve_query_target(
            &[],
            std::path::Path::new("/opt/lib/libprovider.so"),
            "canon",
            0x1000,
            super::LEGACY_COOKIE,
        )
        .expect_err("unmapped legacy address must fail");
        assert_eq!(
            format!("{err:#}"),
            "legacy stage-2 attach has no file mapping"
        );
        // Provider cookie, provider unmapped.
        let err = super::resolve_query_target(
            &[],
            std::path::Path::new("/opt/lib/libprovider.so"),
            "canon",
            0x1000,
            42,
        )
        .expect_err("unmapped provider must fail");
        let text = format!("{err:#}");
        assert_eq!(text, "stage-2 attach has no provider mapping");
        assert!(
            !text.contains('/'),
            "diagnostics carry no pathnames: {text}"
        );
    }
}
