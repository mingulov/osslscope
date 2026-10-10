//! SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy tripwires (P1 exit 3): ENGINE / meth_new / provider-load /
//! low-level-family uprobe plan from the frozen registry × target
//! dynsym, string-argument taxonomy, and the `legacy` doc section.
//!
//! Cookies are sequential in probe order (engine, meth_new, load,
//! lowlevel); userspace decodes via the same `ProbeSet` (consistent
//! within a run — no fixed id space to version).
use crate::discovery::{elf, maps};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Frozen finding: libcrypto mapped but zero ENGINE symbols (4.0 and
/// no-engine 3.x). COMPLETE doc, never an error.
pub const FINDING_ENGINE_ABSENT: &str = "ENGINE API absent";
/// Frozen finding: statically linked target, no usable libcrypto
/// dynsym. The doc is PARTIAL (dispatch anchor also unresolvable).
pub const FINDING_LOWLEVEL_NODYNSYM: &str = "low-level coverage unavailable (no .dynsym)";

/// Known upstream built-in engine ids (best-effort; unknown → other).
/// Single home of the trip taxonomy strings: the harvest-time kernel
/// table population reads this list, so BPF and userspace cannot drift.
pub const BUILTIN_ENGINE_IDS: &[&str] = &[
    "padlock",
    "capi",
    "dasync",
    "afalg",
    "loader_attic",
    "ossltest",
];

/// Provider-load names with dedicated classes (same single-home rule).
pub const LOAD_NAMES: &[&str] = &["legacy", "default", "fips"];

/// One tripwire attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub cookie: u64,
    pub symbol: String,
    pub offset: u64,
    /// Attach file: libcrypto for API-surface probes, the calling
    /// module for caller-attributed PLT probes.
    pub module: String,
    /// Low-level family (aggregation key), else None.
    pub family: Option<&'static str>,
    /// String-argument index (`trip_str0`/`trip_str1`) vs hot counter
    /// (`trip_count`, None).
    pub str_arg: Option<usize>,
    /// BPF program name for this probe.
    pub program: &'static str,
}

/// One address-taken (GLOB_DAT) import resolved to exactly one
/// FUNC definition: the symbol, the defining object, and its file
/// offset. Diagnostic fact only, never a probe: attaching at the
/// definition would count every caller including libcrypto
/// internals, corrupting caller-attributed tripwire semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    pub symbol: String,
    pub object: String,
    pub offset: u64,
}

/// One address-taken import defined in two or more scanned
/// objects: attaching to either would misattribute the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousImport {
    pub symbol: String,
    pub objects: Vec<String>,
}

/// Address-taken (GLOB_DAT) import resolution over scanned
/// objects: every import lands in exactly one bucket. Resolution
/// sharpens the diagnosis only — all three buckets stay
/// uninstrumented gaps (the `lowlevel-fallback-uninstrumented`
/// reason is never resolved away).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressTakenResolution {
    pub resolved: Vec<ResolvedImport>,
    pub ambiguous: Vec<AmbiguousImport>,
    pub absent: Vec<String>,
}

/// Outcome of one address-taken import for [`ProbeSet::address_taken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressTakenOutcome {
    Resolved { object: String, offset: u64 },
    Ambiguous { objects: Vec<String> },
    Absent,
}

/// One module's address-taken import with its resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTakenRecord {
    pub symbol: String,
    pub module: String,
    pub outcome: AddressTakenOutcome,
}

/// Resolved probe plan + coverage gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeSet {
    pub probes: Vec<Probe>,
    pub engine_uninstrumented: u64,
    pub meth_uninstrumented: u64,
    pub lowlevel_uninstrumented: u64,
    /// Address-taken (GLOB_DAT) taxonomy imports with their
    /// defining-object resolution, grouped by module in scan order,
    /// symbols sorted within each outcome bucket.
    /// Diagnostic facts only, never probes (see [`ResolvedImport`]).
    pub address_taken: Vec<AddressTakenRecord>,
    /// Unprobed symbols per class (sorted, deduped): matched in the
    /// target but stub-less (per-entry `uninstrumented` states).
    pub unprobed_engine_syms: Vec<String>,
    pub unprobed_meth_syms: Vec<String>,
    pub unprobed_lowlevel_syms: Vec<String>,
    pub findings: Vec<String>,
    /// `ENGINE_by_id` probe cookies (engine-id taxonomy).
    pub by_id_cookies: HashSet<u64>,
    /// Provider-load probe cookies (load-name taxonomy).
    pub load_cookies: HashSet<u64>,
}

impl ProbeSet {
    /// Engine/fallback-surface rollup (the static-cell trip signal).
    pub fn engine_fallback_uninstrumented(&self) -> u64 {
        self.engine_uninstrumented + self.meth_uninstrumented
    }

    /// True for provider-load probe cookies (loads accounting).
    pub fn is_load_cookie(&self, cookie: u64) -> bool {
        self.load_cookies.contains(&cookie)
    }
}

/// One classified tripwire hit: the kernel verdict for a single
/// string-bearing probe firing. `class` is a taxonomy-relative class
/// id (`TRIP_OTHER`/`ENGINE_*`/`LOAD_*`), `status` the read verdict
/// (`TRIP_OK`/`TRIP_UNREADABLE`/`TRIP_OVERLONG`). Raw argument bytes
/// never cross the ring (T02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TripHit {
    pub cookie: u64,
    pub class: u16,
    pub status: u8,
}

/// A target module to scan for caller-attributed low-level imports.
pub struct Module<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// Per-module plan: caller-attributed probes for all three
/// call-site classes (ENGINE, meth_new, low-level) plus per-symbol
/// gaps (imported but without a stub in THIS module — a probed
/// sibling elsewhere must not mask a missed import here).
pub struct ModulePlan {
    pub probes: Vec<Probe>,
    pub unprobed_engine: Vec<String>,
    pub unprobed_meth: Vec<String>,
    pub unprobed_lowlevel: Vec<String>,
}

/// Plan one module's probes: taxonomy-matching PLT stubs become
/// probes (ENGINE, then meth, then low-level by stub offset —
/// deterministic cookie order); taxonomy-matching imports without a
/// stub (-fno-plt calls, data refs) surface as per-symbol gaps.
/// Same-offset aliases keep the first probe (two cookies on one stub
/// would double-count every call).
pub fn module_plan(
    module: &str,
    und: &HashSet<String>,
    plt: &HashMap<String, u64>,
    cookie_start: u64,
) -> (ModulePlan, u64) {
    let mut plan = ModulePlan {
        probes: Vec::new(),
        unprobed_engine: Vec::new(),
        unprobed_meth: Vec::new(),
        unprobed_lowlevel: Vec::new(),
    };
    let mut cookie = cookie_start;
    let mut seen_off: HashSet<u64> = HashSet::new();
    // family is explicit per class: ENGINE/METH probes carry None even
    // when the symbol text matches a low-level prefix (RSA_meth_new vs
    // RSA_) — section() routes family=None to engine/meth calls.
    let mut push = |plan: &mut ModulePlan,
                    symbol: &str,
                    off: u64,
                    family: Option<&'static str>,
                    cookie: &mut u64| {
        if !seen_off.insert(off) {
            return;
        }
        let (program, str_arg) = if symbol == "ENGINE_by_id" {
            ("trip_str0", Some(0))
        } else {
            ("trip_count", None)
        };
        plan.probes.push(Probe {
            cookie: *cookie,
            symbol: symbol.to_string(),
            offset: off,
            module: module.to_string(),
            family,
            str_arg,
            program,
        });
        *cookie += 1;
    };
    for e in crate::kinds::ENGINE {
        if matches!(e.class, crate::kinds::EngineClass::Other) {
            continue;
        }
        match plt.get(e.name) {
            Some(&off) => push(&mut plan, e.name, off, None, &mut cookie),
            None if und.contains(e.name) => plan.unprobed_engine.push(e.name.to_string()),
            None => {}
        }
    }
    for m in crate::kinds::METH_NEW {
        match plt.get(m.name) {
            Some(&off) => push(&mut plan, m.name, off, None, &mut cookie),
            None if und.contains(m.name) => plan.unprobed_meth.push(m.name.to_string()),
            None => {}
        }
    }
    // Exact-class symbols (ENGINE/METH) are claimed above even when
    // their text matches a low-level prefix (RSA_meth_new vs RSA_):
    // one probe, one section, no double route.
    let exact_class = |n: &str| {
        crate::kinds::ENGINE.iter().any(|e| e.name == n)
            || crate::kinds::METH_NEW.iter().any(|m| m.name == n)
    };
    // PLT entries that are taxonomy imports but match no exact name:
    // low-level prefix scan (offset-sorted for determinism).
    let mut hits: Vec<(&String, &u64)> = plt
        .iter()
        .filter(|(n, _)| lowlevel_family(n).is_some() && !exact_class(n))
        .collect();
    hits.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)));
    for (name, off) in hits {
        let family = lowlevel_family(name);
        push(&mut plan, name, *off, family, &mut cookie);
    }
    let mut und_hits: Vec<&String> = und
        .iter()
        .filter(|n| lowlevel_family(n).is_some() && !plt.contains_key(*n) && !exact_class(n))
        .collect();
    und_hits.sort();
    plan.unprobed_lowlevel.extend(und_hits.into_iter().cloned());
    plan.unprobed_engine.sort();
    plan.unprobed_meth.sort();
    (plan, cookie)
}

/// Low-level family for a symbol, if any taxonomy prefix matches.
fn lowlevel_family(name: &str) -> Option<&'static str> {
    crate::kinds::LOWLEVEL
        .iter()
        .find(|f| f.prefixes.iter().any(|p| name.starts_with(p)))
        .map(|f| f.family)
}

/// True iff the symbol is tripwire taxonomy (exact ENGINE/METH
/// name or low-level prefix): the same membership rule as
/// [`module_plan`], shared so the two planners cannot drift.
fn is_taxonomy(name: &str) -> bool {
    lowlevel_family(name).is_some()
        || crate::kinds::ENGINE
            .iter()
            .any(|e| e.name == name && !matches!(e.class, crate::kinds::EngineClass::Other))
        || crate::kinds::METH_NEW.iter().any(|m| m.name == name)
}

/// Resolve address-taken imports against defining objects: each
/// import is looked up as a DEFINED FUNC symbol in every definer.
/// Exactly one (object, offset) definition resolves; two or more
/// (shared implementations, or versioned duplicates inside one
/// object) are ambiguous; none is absent. Only FUNC definitions
/// count (a data symbol can never execute). Deterministic: inputs
/// are visited sorted, ambiguous object lists sorted and deduped.
/// Unparseable definer bytes fail the whole resolution (resolving
/// over a silent subset could claim `Resolved` where the full set
/// is `Ambiguous`); callers record the definer as unscannable.
pub fn resolve_address_taken(
    imports: &[String],
    definers: &[Module],
) -> anyhow::Result<AddressTakenResolution> {
    let mut tables: Vec<(&str, Vec<(String, u64)>)> = Vec::new();
    for d in definers {
        tables.push((d.path, elf::dynsym_func_entries(d.bytes)?));
    }
    let mut sorted: Vec<&String> = imports.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut out = AddressTakenResolution::default();
    for name in sorted {
        let mut hits: Vec<(&str, u64)> = tables
            .iter()
            .flat_map(|(path, entries)| {
                entries
                    .iter()
                    .filter(|(n, _)| n.as_str() == name.as_str())
                    .map(|(_, o)| (*path, *o))
            })
            .collect();
        hits.sort();
        hits.dedup();
        match hits.len() {
            0 => out.absent.push(name.clone()),
            1 => out.resolved.push(ResolvedImport {
                symbol: name.clone(),
                object: hits[0].0.to_string(),
                offset: hits[0].1,
            }),
            _ => {
                let mut objects: Vec<String> = hits.iter().map(|(p, _)| p.to_string()).collect();
                objects.sort();
                objects.dedup();
                out.ambiguous.push(AmbiguousImport {
                    symbol: name.clone(),
                    objects,
                });
            }
        }
    }
    Ok(out)
}

/// Machine slug for a finding string (check/CI consume `flags`;
/// humans read `findings`). Exact/prefix rules for the producer
/// templates; slugify fallback (lowercase alnum runs joined by `-`,
/// capped at 40 chars) never fails.
pub fn flag_for(finding: &str) -> String {
    if finding == FINDING_ENGINE_ABSENT {
        return "engine-api-absent".to_string();
    }
    if finding == FINDING_LOWLEVEL_NODYNSYM {
        return "lowlevel-no-dynsym".to_string();
    }
    for (prefix, slug) in [
        ("unreadable module: ", "unreadable-module"),
        ("tripwire cap (", "tripwire-cap-exceeded"),
        ("unprobed import: ", "unprobed-imports"),
        ("address-taken import", "unprobed-imports"),
        ("…and ", "unprobed-imports"),
        ("legacy tripwire attach failed: ", "legacy-attach-failed"),
        (
            "provider loads with unreadable names",
            "unreadable-load-names",
        ),
        (
            "engine-id lookups with unreadable ids",
            "unreadable-engine-ids",
        ),
    ] {
        if finding.starts_with(prefix) {
            return slug.to_string();
        }
    }
    let mut slug = String::new();
    let mut dash = false;
    for c in finding.chars().take(60) {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !slug.is_empty() {
            slug.push('-');
            dash = true;
        }
    }
    slug.trim_matches('-').chars().take(40).collect()
}

/// Named findings for unprobed (symbol, module) pairs, sorted for
/// determinism, capped at 16 with an exact overflow line (bounded
/// docs; totals stay exact in the counters).
pub fn gap_findings(pairs: &[(String, String)]) -> Vec<String> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut out: Vec<String> = sorted
        .iter()
        .take(16)
        .map(|(sym, module)| format!("unprobed import: {sym} ({module})"))
        .collect();
    if sorted.len() > 16 {
        out.push(format!("…and {} more unprobed imports", sorted.len() - 16));
    }
    out
}

/// Max tripwire probes per run. The BPF TRIP map holds 128 entries;
/// 120 leaves margin 8 and keeps cookies far below the u32 TripEvent
/// field. Overflow drops low-priority probes (never loads/by_id) and
/// returns them for gap accounting — never silent.
pub const MAX_TRIP_PROBES: usize = 120;

/// Probe class (exact: program + family + registry lookup — never
/// symbol-text heuristics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeClass {
    Load,
    Engine,
    Meth,
    Lowlevel,
}

/// Classify a planned probe for cap priority and gap routing.
pub fn probe_class(p: &Probe) -> ProbeClass {
    if p.program == "trip_str1" {
        ProbeClass::Load
    } else if p.family.is_some() {
        ProbeClass::Lowlevel
    } else if crate::kinds::METH_NEW.iter().any(|m| m.name == p.symbol) {
        ProbeClass::Meth
    } else {
        // ENGINE entries incl. by_id (exact-class probes carry
        // family=None by construction; see module_plan).
        ProbeClass::Engine
    }
}

/// Enforce [`MAX_TRIP_PROBES`] (stable priority: loads pinned, then
/// by_id, ENGINE, meth, low-level). Returns dropped probes for gap
/// accounting — never silent. Priority is drop-order only; any kept
/// subset is still exact.
pub fn apply_trip_cap(probes: &mut Vec<Probe>) -> Vec<Probe> {
    if probes.len() <= MAX_TRIP_PROBES {
        return Vec::new();
    }
    // Loads pinned: PROVIDER_LOAD holds 2 entries (registry fact),
    // so loads can never overflow the cap alone.
    let (loads, mut rest): (Vec<Probe>, Vec<Probe>) =
        probes.drain(..).partition(|p| p.program == "trip_str1");
    let rank = |p: &Probe| -> u8 {
        match probe_class(p) {
            ProbeClass::Load => 0,
            ProbeClass::Engine if p.symbol == "ENGINE_by_id" => 1,
            ProbeClass::Engine => 2,
            ProbeClass::Meth => 3,
            ProbeClass::Lowlevel => 4,
        }
    };
    let mut idx: Vec<usize> = (0..rest.len()).collect();
    idx.sort_by_key(|&i| rank(&rest[i]));
    let keep_rest = MAX_TRIP_PROBES.saturating_sub(loads.len());
    let drop: HashSet<usize> = idx[keep_rest.min(idx.len())..].iter().copied().collect();
    let mut kept = loads;
    let mut dropped = Vec::new();
    for (i, p) in rest.drain(..).enumerate() {
        if drop.contains(&i) {
            dropped.push(p);
        } else {
            kept.push(p);
        }
    }
    *probes = kept;
    dropped
}

/// Blind probe set (no libcrypto scanned): no probes, full
/// registry-size gaps, the single coverage finding. ENGINE-absent is
/// deliberately NOT claimed — presence in unscanned code is unknown.
pub fn blind_probe_set() -> ProbeSet {
    let eng: Vec<String> = crate::kinds::ENGINE
        .iter()
        .filter(|e| !matches!(e.class, crate::kinds::EngineClass::Other))
        .map(|e| e.name.to_string())
        .collect();
    let meth: Vec<String> = crate::kinds::METH_NEW
        .iter()
        .map(|m| m.name.to_string())
        .collect();
    // Lowlevel entries are per-family: one sentinel symbol per family
    // (entries map unprobed symbols back to families by prefix).
    let low: Vec<String> = crate::kinds::LOWLEVEL
        .iter()
        .map(|f| f.prefixes[0].to_string())
        .collect();
    ProbeSet {
        engine_uninstrumented: eng.len() as u64,
        meth_uninstrumented: meth.len() as u64,
        lowlevel_uninstrumented: low.len() as u64,
        unprobed_engine_syms: eng,
        unprobed_meth_syms: meth,
        unprobed_lowlevel_syms: low,
        findings: vec![FINDING_LOWLEVEL_NODYNSYM.to_string()],
        ..Default::default()
    }
}

/// Target modules to scan: file-backed executable mappings except
/// libcrypto itself (its internal direct calls are implementation,
/// not usage), first-seen order.
pub fn target_modules(maps: &[maps::Mapping], libcrypto: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in maps {
        if !m.x || m.ino == 0 || m.path.is_empty() || m.path == libcrypto {
            continue;
        }
        if !out.contains(&m.path) {
            out.push(m.path.clone());
        }
    }
    out
}

/// Target's mapped libcrypto path (tripwire attach file), if any.
pub fn find_libcrypto(maps: &[maps::Mapping]) -> Option<String> {
    maps.iter()
        .find(|m| {
            m.ino != 0
                && m.path
                    .rsplit('/')
                    .next()
                    .is_some_and(|b| b.starts_with("libcrypto.so."))
        })
        .map(|m| m.path.clone())
}

/// Route one address-taken gap pair to its class bucket.
/// Exact-class priority mirrors [`module_plan`]: ENGINE/METH exact
/// names win over low-level prefix text (`RSA_meth_new` is meth,
/// not low-level). Callers pass taxonomy names only; anything else
/// lands in low-level rather than vanishing.
fn route_gap(
    engine: &mut Vec<(String, String)>,
    meth: &mut Vec<(String, String)>,
    lowlevel: &mut Vec<(String, String)>,
    symbol: String,
    module: &str,
) {
    let pair = (symbol.clone(), module.to_string());
    let is_engine = crate::kinds::ENGINE
        .iter()
        .any(|e| e.name == symbol && !matches!(e.class, crate::kinds::EngineClass::Other));
    if is_engine {
        engine.push(pair);
    } else if crate::kinds::METH_NEW.iter().any(|m| m.name == symbol) {
        meth.push(pair);
    } else {
        lowlevel.push(pair);
    }
}

/// Build the probe plan. Provider loads stay on libcrypto (global
/// events — internal auto-loads are real loads and must count);
/// ENGINE, meth_new, and low-level are caller-attributed per-module
/// PLT probes (libcrypto's internal direct calls are implementation,
/// not usage — on 3.x they fire ENGINE_register_* during init).
/// Address-taken (GLOB_DAT) taxonomy imports resolve to precise
/// diagnosed gaps: a symbol with a PLT probe AND a GLOB_DAT slot is
/// still partially blind (pointer calls miss the stub probe), and
/// a symbol with only a GLOB_DAT slot keeps its exact gap pair
/// under a precise finding instead of the generic unprobed line.
/// Gaps count (symbol, module) pairs among SCANNED modules; skipped
/// modules say so loudly (their imports are unknown).
/// dlsym/JIT callers are a known gap (no PLT to probe).
pub fn probes_for(
    libcrypto_path: &str,
    libcrypto_elf: &[u8],
    modules: &[Module],
) -> anyhow::Result<ProbeSet> {
    let entries = elf::dynsym_func_entries(libcrypto_elf)?;
    let by_name: HashMap<&str, u64> = entries.iter().map(|(n, o)| (n.as_str(), *o)).collect();
    let mut set = ProbeSet::default();
    let mut cookie = 0u64;
    // Loads first (cookies 0..2, pinned under the cap).
    let mut seen_load = HashSet::new();
    for name in crate::kinds::PROVIDER_LOAD {
        if let Some(&off) = by_name.get(*name) {
            if !seen_load.insert(off) {
                continue;
            }
            set.probes.push(Probe {
                cookie,
                symbol: name.to_string(),
                offset: off,
                module: libcrypto_path.to_string(),
                family: None,
                str_arg: Some(1),
                program: "trip_str1",
            });
            cookie += 1;
        }
    }
    let mut gaps_engine: Vec<(String, String)> = Vec::new();
    let mut gaps_meth: Vec<(String, String)> = Vec::new();
    let mut gaps_lowlevel: Vec<(String, String)> = Vec::new();
    // Pass 1: scan every module (PLT + address-taken). Unscannable
    // modules are loud unknowns and do not join the definers.
    struct Scan {
        und: HashSet<String>,
        plt: HashMap<String, u64>,
        globdat: Vec<String>,
    }
    let mut scans: Vec<Option<Scan>> = Vec::with_capacity(modules.len());
    for m in modules {
        let scanned = match (
            elf::und_imports(m.bytes),
            elf::plt_stub_offsets(m.bytes),
            elf::glob_dat_imports(m.bytes),
        ) {
            (Ok(u), Ok(p), Ok(g)) => Some(Scan {
                und: u.into_iter().collect(),
                plt: p,
                globdat: g,
            }),
            _ => {
                set.findings
                    .push(format!("unscannable module: {} (imports unknown)", m.path));
                None
            }
        };
        scans.push(scanned);
    }
    // Definers for address-taken resolution: libcrypto plus every
    // scanned module (an unscannable module's definitions are
    // unknown, covered by its loud finding above).
    let mut definers: Vec<Module> = Vec::with_capacity(modules.len() + 1);
    definers.push(Module {
        path: libcrypto_path,
        bytes: libcrypto_elf,
    });
    for (m, s) in modules.iter().zip(scans.iter()) {
        if s.is_some() {
            definers.push(Module {
                path: m.path,
                bytes: m.bytes,
            });
        }
    }
    // Pass 2: plan PLT probes, then resolve address-taken imports.
    let mut addr_findings: Vec<String> = Vec::new();
    for (m, scan) in modules.iter().zip(scans.iter()) {
        let Some(scan) = scan else {
            continue;
        };
        let (mut plan, next) = module_plan(m.path, &scan.und, &scan.plt, cookie);
        cookie = next;
        // Address-taken taxonomy imports, partitioned out of the
        // generic unprobed lists so each (symbol, module) pair is
        // counted once, under its precise finding.
        let addr_taken: Vec<String> = scan
            .globdat
            .iter()
            .filter(|n| is_taxonomy(n))
            .cloned()
            .collect();
        let addr_set: HashSet<String> = addr_taken.iter().cloned().collect();
        plan.unprobed_engine.retain(|n| !addr_set.contains(n));
        plan.unprobed_meth.retain(|n| !addr_set.contains(n));
        plan.unprobed_lowlevel.retain(|n| !addr_set.contains(n));
        gaps_engine.extend(
            plan.unprobed_engine
                .into_iter()
                .map(|s| (s, m.path.to_string())),
        );
        gaps_meth.extend(
            plan.unprobed_meth
                .into_iter()
                .map(|s| (s, m.path.to_string())),
        );
        gaps_lowlevel.extend(
            plan.unprobed_lowlevel
                .into_iter()
                .map(|s| (s, m.path.to_string())),
        );
        set.probes.extend(plan.probes);
        if addr_taken.is_empty() {
            continue;
        }
        let r = match resolve_address_taken(&addr_taken, &definers) {
            Ok(r) => r,
            Err(_) => {
                set.findings.push(format!(
                    "unscannable module: {} (address-taken imports unknown)",
                    m.path
                ));
                // Fall back to generic gap pairs (the und path may
                // not have covered non-import slots).
                for n in addr_taken {
                    route_gap(
                        &mut gaps_engine,
                        &mut gaps_meth,
                        &mut gaps_lowlevel,
                        n,
                        m.path,
                    );
                }
                continue;
            }
        };
        for h in &r.resolved {
            addr_findings.push(format!(
                "address-taken import: {} ({} -> {}@0x{:x}): no PLT stub; execution unobserved",
                h.symbol, m.path, h.object, h.offset
            ));
            set.address_taken.push(AddressTakenRecord {
                symbol: h.symbol.clone(),
                module: m.path.to_string(),
                outcome: AddressTakenOutcome::Resolved {
                    object: h.object.clone(),
                    offset: h.offset,
                },
            });
            route_gap(
                &mut gaps_engine,
                &mut gaps_meth,
                &mut gaps_lowlevel,
                h.symbol.clone(),
                m.path,
            );
        }
        for h in &r.ambiguous {
            addr_findings.push(format!(
                "address-taken import: {} ({}): shared by {} objects; unattributable",
                h.symbol,
                m.path,
                h.objects.len()
            ));
            set.address_taken.push(AddressTakenRecord {
                symbol: h.symbol.clone(),
                module: m.path.to_string(),
                outcome: AddressTakenOutcome::Ambiguous {
                    objects: h.objects.clone(),
                },
            });
            route_gap(
                &mut gaps_engine,
                &mut gaps_meth,
                &mut gaps_lowlevel,
                h.symbol.clone(),
                m.path,
            );
        }
        for n in &r.absent {
            addr_findings.push(format!(
                "address-taken import without definition: {n} ({})",
                m.path
            ));
            set.address_taken.push(AddressTakenRecord {
                symbol: n.clone(),
                module: m.path.to_string(),
                outcome: AddressTakenOutcome::Absent,
            });
            route_gap(
                &mut gaps_engine,
                &mut gaps_meth,
                &mut gaps_lowlevel,
                n.clone(),
                m.path,
            );
        }
    }
    // Precise address-taken findings join the finding list under
    // the same 16-line bound as generic gap findings (counters
    // stay exact regardless).
    addr_findings.sort();
    set.findings.extend(addr_findings.into_iter().take(16));
    if set.address_taken.len() > 16 {
        set.findings.push(format!(
            "…and {} more address-taken imports",
            set.address_taken.len() - 16
        ));
    }
    // Cap overflow rejoins the gaps (classified exactly).
    let dropped = apply_trip_cap(&mut set.probes);
    if !dropped.is_empty() {
        set.findings.push(format!(
            "tripwire cap ({}) exceeded: {} imports unprobed",
            MAX_TRIP_PROBES,
            dropped.len()
        ));
    }
    for p in &dropped {
        let pair = (p.symbol.clone(), p.module.clone());
        match probe_class(p) {
            // Loads pinned by the cap: unreachable (see apply_trip_cap).
            ProbeClass::Load => gaps_engine.push(pair),
            ProbeClass::Engine => gaps_engine.push(pair),
            ProbeClass::Meth => gaps_meth.push(pair),
            ProbeClass::Lowlevel => gaps_lowlevel.push(pair),
        }
    }
    set.engine_uninstrumented = gaps_engine.len() as u64;
    set.meth_uninstrumented = gaps_meth.len() as u64;
    set.lowlevel_uninstrumented = gaps_lowlevel.len() as u64;
    let syms = |gaps: &[(String, String)]| {
        let mut v: Vec<String> = gaps.iter().map(|(s, _)| s.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    set.unprobed_engine_syms = syms(&gaps_engine);
    set.unprobed_meth_syms = syms(&gaps_meth);
    set.unprobed_lowlevel_syms = syms(&gaps_lowlevel);
    let mut gaps = gaps_engine;
    gaps.extend(gaps_meth);
    gaps.extend(gaps_lowlevel);
    set.findings.extend(gap_findings(&gaps));
    // Cookie sets from KEPT probes only (no post-hoc removal exists,
    // so the sets cannot go stale).
    for p in &set.probes {
        if p.symbol == "ENGINE_by_id" {
            set.by_id_cookies.insert(p.cookie);
        } else if p.str_arg.is_some() {
            set.load_cookies.insert(p.cookie);
        }
    }
    if !entries.iter().any(|(n, _)| n.starts_with("ENGINE_")) {
        set.findings.push(FINDING_ENGINE_ABSENT.to_string());
    }
    Ok(set)
}

/// Inputs for the `legacy` doc section.
pub struct SectionInputs<'a> {
    pub set: &'a ProbeSet,
    /// TRIP map contents: cookie → hit count.
    pub trip: &'a HashMap<u64, u64>,
    /// KIND_TRIP classified hits: (cookie, class, status).
    pub trip_hits: &'a [TripHit],
    /// LGCALLS sum: executed legacy-provider queries (deny signal).
    pub legacy_queries: u64,
    /// Legacy-partitioned row classes (sorted/deduped here).
    pub legacy_classes: Vec<String>,
    /// Extra findings (the blind path adds its mandated string).
    pub extra_findings: &'a [&'a str],
}

/// Typed tripwire/query rollup: every aggregate the `legacy` doc
/// section reports, computed once here. The T06 session consumes
/// this for typed tripwire deltas (no JSON reparse in the count
/// loop); [`section`] renders it byte-identically to before.
///
/// Query and tripwire counters stay separate throughout:
/// `executed_queries` (the LGCALLS executed-query ledger) is the
/// sole source of `legacy_provider.executed_calls` — provider-load
/// tripwire hits and query arrivals never become execution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacySummary {
    /// ENGINE entrypoint calls by symbol (trip counters, summed
    /// across probed modules).
    pub engine_calls: BTreeMap<String, u64>,
    /// `*_meth_new` calls by symbol.
    pub meth_calls: BTreeMap<String, u64>,
    /// ENGINE-id taxonomy classes (`dynamic`/`builtin`/`other`).
    pub engine_id_class: BTreeMap<String, u64>,
    /// Provider-load taxonomy classes
    /// (`legacy`/`default`/`fips`/`other`).
    pub loads: BTreeMap<String, u64>,
    /// Low-level family calls by family.
    pub family_calls: BTreeMap<String, u64>,
    /// Legacy-partitioned row classes (sorted, deduped).
    pub legacy_classes: Vec<String>,
    /// Weak subset of `legacy_classes` (sorted, deduped).
    pub weak_legacy_algs: Vec<String>,
    /// Unreadable load names, including the TRIP/hit delta (ring
    /// events lost between the counter and the classified hit).
    pub load_unreadable: u64,
    /// Unreadable engine ids, including the TRIP/hit delta.
    pub id_unreadable: u64,
    /// Executed legacy-provider queries (LGCALLS ledger only).
    pub executed_queries: u64,
    /// Findings (probe-set + extra + unreadable verdicts).
    pub findings: Vec<String>,
    /// Machine flags, one slug per finding (sorted).
    pub flags: Vec<String>,
    /// Tripwires attached.
    pub attached: u64,
    /// Capability misses (engine + meth + low-level).
    pub missed: u64,
}

/// Aggregate tripwire/query inputs into a [`LegacySummary`]. Pure:
/// the same inputs always yield the same summary, and [`section`]
/// renders it without recomputation.
pub fn summarize(inp: &SectionInputs) -> LegacySummary {
    let count = |c: u64| inp.trip.get(&c).copied().unwrap_or(0);
    let mut engine_calls = BTreeMap::new();
    let mut meth_calls = BTreeMap::new();
    for p in inp
        .set
        .probes
        .iter()
        .filter(|p| p.family.is_none() && !inp.set.load_cookies.contains(&p.cookie))
    {
        let is_meth = crate::kinds::METH_NEW.iter().any(|m| m.name == p.symbol);
        // Sum across modules: the same symbol probed in two callers
        // is two cookies for one entrypoint (insert would silently
        // drop every module but the last).
        *(if is_meth {
            &mut meth_calls
        } else {
            &mut engine_calls
        })
        .entry(p.symbol.clone())
        .or_insert(0) += count(p.cookie);
    }
    let mut id_class: BTreeMap<String, u64> = [("dynamic", 0), ("builtin", 0), ("other", 0)]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let mut loads: BTreeMap<String, u64> =
        [("legacy", 0), ("default", 0), ("fips", 0), ("other", 0)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
    // Explicit unreadable verdicts (NULL/unreadable/overlong args):
    // counted per taxonomy straight from the kernel status, never
    // folded into `other` classes.
    let mut id_unreadable: u64 = 0;
    let mut load_unreadable: u64 = 0;
    for hit in inp.trip_hits {
        if inp.set.by_id_cookies.contains(&hit.cookie) {
            if hit.status != osslscope_ebpf_common::TRIP_OK {
                id_unreadable += 1;
                continue;
            }
            let Some(label) = osslscope_ebpf_common::engine_class_name(hit.class) else {
                continue;
            };
            *id_class.get_mut(label).unwrap() += 1;
        } else if inp.set.load_cookies.contains(&hit.cookie) {
            if hit.status != osslscope_ebpf_common::TRIP_OK {
                load_unreadable += 1;
                continue;
            }
            let Some(label) = osslscope_ebpf_common::load_class_name(hit.class) else {
                continue;
            };
            *loads.get_mut(label).unwrap() += 1;
        }
    }
    let mut fam_calls: BTreeMap<String, u64> = crate::kinds::LOWLEVEL
        .iter()
        .map(|f| (f.family.to_string(), 0))
        .collect();
    for p in inp.set.probes.iter().filter_map(|p| {
        p.family
            .map(|f| (f, count(p.cookie)))
            .filter(|(_, n)| *n > 0)
    }) {
        *fam_calls.get_mut(p.0).unwrap() += p.1;
    }
    let mut classes = inp.legacy_classes.clone();
    classes.sort();
    classes.dedup();
    let mut findings: Vec<String> = inp.set.findings.clone();
    findings.extend(inp.extra_findings.iter().map(|s| s.to_string()));
    // String-bearing probes fire TRIP always and emit a classified
    // hit for every firing (readable, unreadable, and overlong
    // alike): a TRIP/hit delta means ring events were lost, not that
    // calls hid — findings, not silent undercount. The delta rides
    // with the explicit unreadable verdicts above (both are
    // merge-summable); finding strings stay count-free so
    // cross-harvest merges dedupe exactly.
    let fires = |cookies: &HashSet<u64>| cookies.iter().map(|c| count(*c)).sum::<u64>();
    let hits = |cookies: &HashSet<u64>| {
        inp.trip_hits
            .iter()
            .filter(|h| cookies.contains(&h.cookie))
            .count() as u64
    };
    load_unreadable += fires(&inp.set.load_cookies).saturating_sub(hits(&inp.set.load_cookies));
    if load_unreadable > 0 {
        findings.push("provider loads with unreadable names".to_string());
    }
    id_unreadable += fires(&inp.set.by_id_cookies).saturating_sub(hits(&inp.set.by_id_cookies));
    if id_unreadable > 0 {
        findings.push("engine-id lookups with unreadable ids".to_string());
    }
    // Machine flags: one slug per finding (check/CI consume these;
    // humans read `findings`). Deltas map directly; the rest via
    // flag_for (exact/prefix rules + slugify fallback, all tested).
    let mut flags: BTreeSet<String> = findings.iter().map(|f| flag_for(f)).collect();
    if load_unreadable > 0 {
        flags.insert("unreadable-load-names".to_string());
    }
    if id_unreadable > 0 {
        flags.insert("unreadable-engine-ids".to_string());
    }
    let mut weak_algs: Vec<String> = inp
        .legacy_classes
        .iter()
        .filter(|c| crate::kinds::is_weak_alg(c))
        .cloned()
        .collect();
    weak_algs.sort();
    weak_algs.dedup();
    LegacySummary {
        engine_calls,
        meth_calls,
        engine_id_class: id_class,
        loads,
        family_calls: fam_calls,
        legacy_classes: classes,
        weak_legacy_algs: weak_algs,
        load_unreadable,
        id_unreadable,
        executed_queries: inp.legacy_queries,
        findings,
        flags: flags.into_iter().collect(),
        attached: inp.set.probes.len() as u64,
        missed: inp.set.engine_uninstrumented
            + inp.set.meth_uninstrumented
            + inp.set.lowlevel_uninstrumented,
    }
}

/// Emit the `legacy` doc section (design §3 shapes) by rendering a
/// [`LegacySummary`]. The JSON shape is unchanged by the T06
/// extraction: same keys, same order, same values.
pub fn section(inp: &SectionInputs) -> serde_json::Value {
    let s = summarize(inp);
    // Per-entry states over the CONSIDERED set (registry order =
    // byte-stable): exact-name ENGINE (non-Other) + METH_NEW
    // symbols, LOWLEVEL families (prefix taxonomy), LOAD classes.
    // observed = calls attributed; uninstrumented = matched but
    // stub-less; absent = not observed (probed-quiet or not in
    // target — `probed` disambiguates; PRD absence doctrine).
    let eng_fired: HashSet<&str> = s
        .engine_calls
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(s, _)| s.as_str())
        .collect();
    let meth_fired: HashSet<&str> = s
        .meth_calls
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(s, _)| s.as_str())
        .collect();
    let eng_un: HashSet<&str> = inp
        .set
        .unprobed_engine_syms
        .iter()
        .map(|s| s.as_str())
        .collect();
    let meth_un: HashSet<&str> = inp
        .set
        .unprobed_meth_syms
        .iter()
        .map(|s| s.as_str())
        .collect();
    let mut entries: Vec<serde_json::Value> = Vec::new();
    for e in crate::kinds::ENGINE {
        if matches!(e.class, crate::kinds::EngineClass::Other) {
            continue; // out of tripwire scope (P1 exit-3 design)
        }
        let state = if eng_fired.contains(e.name) {
            "observed"
        } else if eng_un.contains(e.name) {
            "uninstrumented"
        } else {
            "absent"
        };
        entries.push(serde_json::json!({
            "name": e.name, "class": "engine", "state": state,
            "probed": s.engine_calls.contains_key(e.name),
        }));
    }
    for m in crate::kinds::METH_NEW {
        let state = if meth_fired.contains(m.name) {
            "observed"
        } else if meth_un.contains(m.name) {
            "uninstrumented"
        } else {
            "absent"
        };
        entries.push(serde_json::json!({
            "name": m.name, "class": "meth", "state": state,
            "probed": s.meth_calls.contains_key(m.name),
        }));
    }
    for f in crate::kinds::LOWLEVEL {
        let fam_probed = inp.set.probes.iter().any(|p| p.family == Some(f.family));
        let fam_un = inp
            .set
            .unprobed_lowlevel_syms
            .iter()
            .any(|s| lowlevel_family(s) == Some(f.family));
        let state = if s.family_calls.get(f.family).copied().unwrap_or(0) > 0 {
            "observed"
        } else if fam_un {
            "uninstrumented"
        } else {
            "absent"
        };
        entries.push(serde_json::json!({
            "name": f.family, "class": "lowlevel", "state": state, "probed": fam_probed,
        }));
    }
    let loads_probed = !inp.set.load_cookies.is_empty();
    for class in ["legacy", "default", "fips", "other"] {
        let state = if s.loads.get(class).copied().unwrap_or(0) > 0 {
            "observed"
        } else if !loads_probed {
            "uninstrumented"
        } else {
            "absent"
        };
        entries.push(serde_json::json!({
            "name": class, "class": "load", "state": state, "probed": loads_probed,
        }));
    }
    let mut legacy = serde_json::json!({
        "engine": {"calls_by_entrypoint": s.engine_calls, "engine_id_class": s.engine_id_class},
        "meth_new": {"calls_by_entrypoint": s.meth_calls},
        "lowlevel": {"calls_by_family": s.family_calls},
        "legacy_provider": {"loads": s.loads, "executed_calls": s.executed_queries,
                            "algs": s.legacy_classes},
        "entries": entries,
        "capability": {"syms_present": s.attached + s.missed,
                       "tripwires_attached": s.attached, "tripwires_missed": s.missed},
        "flags": s.flags,
        "weak": {"legacy_algs": s.weak_legacy_algs},
        "unreadable": {"load_names": s.load_unreadable, "engine_ids": s.id_unreadable},
    });
    if inp.set.engine_uninstrumented > 0 {
        legacy["engine"]["uninstrumented"] = inp.set.engine_uninstrumented.into();
    }
    if inp.set.meth_uninstrumented > 0 {
        legacy["meth_new"]["uninstrumented"] = inp.set.meth_uninstrumented.into();
    }
    if inp.set.lowlevel_uninstrumented > 0 {
        legacy["lowlevel"]["uninstrumented"] = inp.set.lowlevel_uninstrumented.into();
    }
    if inp.set.engine_fallback_uninstrumented() > 0 {
        legacy["engine_fallback_uninstrumented"] = inp.set.engine_fallback_uninstrumented().into();
    }
    if !s.findings.is_empty() {
        legacy["findings"] = s.findings.into();
    }
    legacy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_classes() {
        // Kernel class ids (populated from this taxonomy) decode to
        // the frozen labels; anything else is rejected, never
        // mislabeled. (End-to-end classifier pins live in the
        // discovery-protocol integration tests.)
        use osslscope_ebpf_common as wire;
        assert_eq!(
            wire::engine_class_name(wire::ENGINE_DYNAMIC),
            Some("dynamic")
        );
        assert_eq!(
            wire::engine_class_name(wire::ENGINE_BUILTIN),
            Some("builtin")
        );
        assert_eq!(wire::engine_class_name(wire::TRIP_OTHER), Some("other"));
        assert_eq!(wire::engine_class_name(99), None);
        assert_eq!(wire::load_class_name(wire::LOAD_LEGACY), Some("legacy"));
        assert_eq!(wire::load_class_name(wire::LOAD_DEFAULT), Some("default"));
        assert_eq!(wire::load_class_name(wire::LOAD_FIPS), Some("fips"));
        assert_eq!(wire::load_class_name(wire::TRIP_OTHER), Some("other"));
        assert_eq!(wire::load_class_name(99), None);
        assert!(BUILTIN_ENGINE_IDS.contains(&"padlock"));
        assert_eq!(LOAD_NAMES, &["legacy", "default", "fips"]);
    }

    #[test]
    fn libcrypto_discovery() {
        let maps = maps::parse_maps(
            "7f00-7f10 r-xp 00000000 08:01 99 /opt/ossl/lib64/libcrypto.so.4\n\
             7f10-7f20 r-xp 00000000 08:01 77 /lib/x86_64-linux-gnu/libc.so.6\n",
        );
        assert_eq!(
            find_libcrypto(&maps).as_deref(),
            Some("/opt/ossl/lib64/libcrypto.so.4")
        );
        let nomaps =
            maps::parse_maps("7f10-7f20 r-xp 00000000 08:01 77 /lib/x86_64-linux-gnu/libc.so.6\n");
        assert_eq!(find_libcrypto(&nomaps), None);
    }

    #[test]
    fn module_plan_probes_all_classes() {
        let und = [
            "ENGINE_by_id",
            "ENGINE_init",
            "RSA_meth_new",
            "DES_ecb_encrypt",
            "malloc",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let plt = HashMap::from([
            ("ENGINE_by_id".to_string(), 0x1000u64),
            ("ENGINE_init".to_string(), 0x1010u64),
            ("RSA_meth_new".to_string(), 0x1020u64),
            ("DES_ecb_encrypt".to_string(), 0x1030u64),
        ]);
        let (plan, next) = module_plan("/app", &und, &plt, 7);
        assert_eq!(next, 11);
        assert_eq!(plan.probes.len(), 4);
        // ENGINE_by_id captures arg0 (id string) via trip_str0.
        let by_id = &plan.probes[0];
        assert_eq!(by_id.cookie, 7);
        assert_eq!(by_id.symbol, "ENGINE_by_id");
        assert_eq!(by_id.offset, 0x1000);
        assert_eq!(by_id.module, "/app");
        assert_eq!(by_id.program, "trip_str0");
        assert_eq!(by_id.str_arg, Some(0));
        assert_eq!(by_id.family, None);
        // Plain counters for the rest.
        assert_eq!(plan.probes[1].program, "trip_count");
        assert_eq!(plan.probes[1].symbol, "ENGINE_init");
        assert_eq!(plan.probes[2].symbol, "RSA_meth_new");
        assert_eq!(plan.probes[3].symbol, "DES_ecb_encrypt");
        assert_eq!(plan.probes[3].family, Some("cipher/block"));
        assert!(plan.unprobed_engine.is_empty());
        assert!(plan.unprobed_meth.is_empty());
        assert!(plan.unprobed_lowlevel.is_empty());
    }

    #[test]
    fn module_plan_gaps_are_per_symbol() {
        // Imported but no stub (-fno-plt call or data ref): a gap
        // per symbol, not per family (a probed sibling must not mask
        // a missed import).
        let und = ["BN_new", "BN_free", "ENGINE_init"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let plt = HashMap::from([("BN_new".to_string(), 0x2000u64)]);
        let (plan, next) = module_plan("/app", &und, &plt, 0);
        assert_eq!(next, 1);
        assert_eq!(plan.probes.len(), 1);
        assert_eq!(plan.probes[0].symbol, "BN_new");
        assert_eq!(plan.unprobed_engine, vec!["ENGINE_init".to_string()]);
        assert!(plan.unprobed_meth.is_empty());
        assert_eq!(plan.unprobed_lowlevel, vec!["BN_free".to_string()]);
    }

    #[test]
    fn gap_findings_capped_with_overflow() {
        // 17 unprobed pairs: 16 named findings + one overflow line
        // (bounded docs; totals stay exact in the counters).
        let pairs: Vec<(String, String)> = (0..17)
            .map(|i| (format!("SYM_{i:02}"), "/app".to_string()))
            .collect();
        let out = gap_findings(&pairs);
        assert_eq!(out.len(), 17);
        assert!(out[0].contains("SYM_00"));
        assert!(out[15].contains("SYM_15"));
        assert_eq!(out[16], "…and 1 more unprobed imports");
        let out0 = gap_findings(&[]);
        assert!(out0.is_empty());
    }

    #[test]
    fn trip_cap_drops_lowlevel_first() {
        // 120 cap (TRIP map holds 128): loads/by_id pinned, engine
        // and meth next, lowlevel truncated. Dropped probes return
        // for gap accounting (never silent).
        let mut probes: Vec<Probe> = Vec::new();
        for i in 0..2u64 {
            probes.push(Probe {
                cookie: i,
                symbol: "OSSL_PROVIDER_load".into(),
                offset: i,
                module: "lc".into(),
                family: None,
                str_arg: Some(1),
                program: "trip_str1",
            });
        }
        probes.push(Probe {
            cookie: 2,
            symbol: "ENGINE_by_id".into(),
            offset: 2,
            module: "/app".into(),
            family: None,
            str_arg: Some(0),
            program: "trip_str0",
        });
        for i in 0..200u64 {
            probes.push(Probe {
                cookie: 3 + i,
                symbol: format!("BN_fake_{i}"),
                offset: 0x1000 + i,
                module: "/app".into(),
                family: Some("bn"),
                str_arg: None,
                program: "trip_count",
            });
        }
        let dropped = apply_trip_cap(&mut probes);
        assert_eq!(probes.len(), 120);
        assert_eq!(dropped.len(), 83);
        assert!(probes.iter().any(|p| p.program == "trip_str1"));
        assert!(probes.iter().any(|p| p.symbol == "ENGINE_by_id"));
        assert!(dropped.iter().all(|p| p.family == Some("bn")));
    }

    #[test]
    fn blind_set_is_full_gaps_single_finding() {
        // Blind (no libcrypto scanned): full registry-size gaps, the
        // single coverage finding — never ENGINE-absent (presence in
        // unscanned code is unknown, not absent).
        let set = blind_probe_set();
        assert!(set.probes.is_empty());
        let want_engine = crate::kinds::ENGINE
            .iter()
            .filter(|e| !matches!(e.class, crate::kinds::EngineClass::Other))
            .count() as u64;
        assert_eq!(set.engine_uninstrumented, want_engine);
        assert_eq!(set.meth_uninstrumented, crate::kinds::METH_NEW.len() as u64);
        assert_eq!(
            set.lowlevel_uninstrumented,
            crate::kinds::LOWLEVEL.len() as u64
        );
        assert_eq!(set.findings, vec![FINDING_LOWLEVEL_NODYNSYM.to_string()]);
    }

    #[test]
    fn null_names_are_loud_findings() {
        // TRIP fires with explicit unreadable hits (NULL args) plus a
        // lost-event delta: the calls happened — findings and
        // merge-summable counts, not silent undercount.
        use osslscope_ebpf_common as wire;
        let set = ProbeSet {
            probes: vec![
                Probe {
                    cookie: 9,
                    symbol: "OSSL_PROVIDER_load".into(),
                    offset: 1,
                    module: "lc".into(),
                    family: None,
                    str_arg: Some(1),
                    program: "trip_str1",
                },
                Probe {
                    cookie: 10,
                    symbol: "ENGINE_by_id".into(),
                    offset: 2,
                    module: "/app".into(),
                    family: None,
                    str_arg: Some(0),
                    program: "trip_str0",
                },
            ],
            load_cookies: HashSet::from([9]),
            by_id_cookies: HashSet::from([10]),
            ..Default::default()
        };
        let trip = HashMap::from([(9u64, 2u64), (10u64, 3u64)]);
        let doc = section(&SectionInputs {
            set: &set,
            trip: &trip,
            trip_hits: &[
                TripHit {
                    cookie: 9,
                    class: wire::TRIP_OTHER,
                    status: wire::TRIP_UNREADABLE,
                },
                TripHit {
                    cookie: 10,
                    class: wire::ENGINE_DYNAMIC,
                    status: wire::TRIP_OK,
                },
            ],
            legacy_queries: 0,
            legacy_classes: Vec::new(),
            extra_findings: &[],
        });
        let findings = doc["findings"].as_array().unwrap();
        let texts: Vec<&str> = findings.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(
            texts.contains(&"provider loads with unreadable names"),
            "load finding missing: {texts:?}"
        );
        assert!(
            texts.contains(&"engine-id lookups with unreadable ids"),
            "by_id finding missing: {texts:?}"
        );
        // Load: 1 explicit unreadable hit + 1 lost-event delta (2
        // fires, 1 hit). Engine: 2 lost-event delta (3 fires, 1 hit).
        assert_eq!(doc["unreadable"]["load_names"], 2);
        assert_eq!(doc["unreadable"]["engine_ids"], 2);
        // Explicit unreadable hits never inflate `other` classes.
        assert_eq!(doc["legacy_provider"]["loads"]["other"], 0);
        assert_eq!(doc["engine"]["engine_id_class"]["dynamic"], 1);
        let flags = doc["flags"].as_array().unwrap();
        let slugs: Vec<&str> = flags.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(slugs.contains(&"unreadable-load-names"), "{slugs:?}");
        assert!(slugs.contains(&"unreadable-engine-ids"), "{slugs:?}");
    }

    #[test]
    fn flag_for_pins_all_producer_templates() {
        assert_eq!(flag_for(FINDING_ENGINE_ABSENT), "engine-api-absent");
        assert_eq!(flag_for(FINDING_LOWLEVEL_NODYNSYM), "lowlevel-no-dynsym");
        assert_eq!(
            flag_for("unreadable module: /x.so (imports unknown)"),
            "unreadable-module"
        );
        assert_eq!(
            flag_for("tripwire cap (120) exceeded: 5 imports unprobed"),
            "tripwire-cap-exceeded"
        );
        assert_eq!(flag_for("unprobed import: FOO (/app)"), "unprobed-imports");
        assert_eq!(flag_for("…and 3 more unprobed imports"), "unprobed-imports");
        assert_eq!(
            flag_for("legacy tripwire attach failed: EINVAL"),
            "legacy-attach-failed"
        );
        assert_eq!(flag_for("Some New Finding! 123"), "some-new-finding-123");
        assert_eq!(flag_for(""), "");
    }

    #[test]
    fn entries_cover_considered_set_with_states() {
        // ENGINE_by_id observed + RSA_meth_new uninstrumented + the
        // rest absent; blind set is all-uninstrumented.
        let set = ProbeSet {
            probes: vec![Probe {
                cookie: 1,
                symbol: "ENGINE_by_id".into(),
                offset: 0x100,
                module: "/app".into(),
                family: None,
                str_arg: Some(0),
                program: "trip_str0",
            }],
            unprobed_meth_syms: vec!["RSA_meth_new".into()],
            by_id_cookies: HashSet::from([1]),
            ..Default::default()
        };
        let doc = section(&SectionInputs {
            set: &set,
            trip: &HashMap::from([(1u64, 4u64)]),
            trip_hits: &[TripHit {
                cookie: 1,
                class: osslscope_ebpf_common::ENGINE_DYNAMIC,
                status: osslscope_ebpf_common::TRIP_OK,
            }],
            legacy_queries: 0,
            legacy_classes: vec!["MD4".into()],
            extra_findings: &[],
        });
        let entries = doc["entries"].as_array().unwrap();
        let get = |name: &str| {
            entries
                .iter()
                .find(|e| e["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        assert_eq!(get("ENGINE_by_id")["state"], "observed");
        assert_eq!(get("ENGINE_by_id")["class"], "engine");
        assert_eq!(get("ENGINE_by_id")["probed"], true);
        assert_eq!(get("RSA_meth_new")["state"], "uninstrumented");
        assert_eq!(get("RSA_meth_new")["probed"], false);
        assert_eq!(get("ENGINE_init")["state"], "absent");
        assert_eq!(get("digest/sha")["class"], "lowlevel");
        assert_eq!(get("legacy")["class"], "load");
        assert_eq!(doc["weak"]["legacy_algs"], serde_json::json!(["MD4"]));
        assert_eq!(doc["capability"]["tripwires_attached"], 1);

        let blind = blind_probe_set();
        let bdoc = section(&SectionInputs {
            set: &blind,
            trip: &HashMap::new(),
            trip_hits: &[],
            legacy_queries: 0,
            legacy_classes: Vec::new(),
            extra_findings: &[],
        });
        let bentries = bdoc["entries"].as_array().unwrap();
        assert!(!bentries.is_empty());
        assert!(bentries.iter().all(|e| e["state"] == "uninstrumented"));
        assert_eq!(bdoc["capability"]["tripwires_attached"], 0);
    }

    #[test]
    fn entrypoint_calls_sum_across_modules() {
        // Same entrypoint probed in two caller modules: the section
        // sums both cookies (per-module insert would drop one).
        let set = ProbeSet {
            probes: vec![
                Probe {
                    cookie: 1,
                    symbol: "ENGINE_init".into(),
                    offset: 0x100,
                    module: "/app".into(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
                Probe {
                    cookie: 2,
                    symbol: "ENGINE_init".into(),
                    offset: 0x200,
                    module: "/lib/spike.so".into(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
            ],
            ..Default::default()
        };
        let trip = HashMap::from([(1u64, 3u64), (2u64, 5u64)]);
        let doc = section(&SectionInputs {
            set: &set,
            trip: &trip,
            trip_hits: &[],
            legacy_queries: 0,
            legacy_classes: Vec::new(),
            extra_findings: &[],
        });
        assert_eq!(doc["engine"]["calls_by_entrypoint"]["ENGINE_init"], 8);
    }

    #[test]
    fn target_modules_lists_exec_files_not_libcrypto() {
        let maps = maps::parse_maps(
            "7f00-7f10 r-xp 00000000 08:01 11 /app/evp_driver\n\
             7f10-7f20 r-xp 00000000 08:01 99 /opt/ossl/lib64/libcrypto.so.4\n\
             7f20-7f30 r--p 00000000 08:01 99 /opt/ossl/lib64/libcrypto.so.4\n\
             7f30-7f40 r-xp 00000000 08:01 77 /lib/x86_64-linux-gnu/libc.so.6\n\
             7f40-7f50 r-xp 00000000 00:00 0 [vdso]\n\
             7f50-7f60 rwxp 00000000 00:00 0 \n",
        );
        assert_eq!(
            target_modules(&maps, "/opt/ossl/lib64/libcrypto.so.4"),
            vec!["/app/evp_driver", "/lib/x86_64-linux-gnu/libc.so.6"]
        );
    }

    #[test]
    fn probes_vacuous_without_callers() {
        // libc as libcrypto, no caller modules: no loads resolve,
        // nothing imported → empty plan, zero gaps (nothing missed),
        // absent finding (libc has no ENGINE API). Real libcrypto
        // plans are gate-proven.
        let b = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"]
            .into_iter()
            .find_map(|p| std::fs::read(p).ok())
            .expect("no libc — broken test env");
        let set = probes_for("libc.so.6", &b, &[]).unwrap();
        assert!(set.probes.is_empty());
        assert_eq!(set.engine_uninstrumented, 0);
        assert_eq!(set.meth_uninstrumented, 0);
        assert_eq!(set.lowlevel_uninstrumented, 0);
        assert_eq!(set.findings, vec![FINDING_ENGINE_ABSENT.to_string()]);
        assert_eq!(set.engine_fallback_uninstrumented(), 0);
    }

    #[test]
    fn section_shape() {
        let set = ProbeSet {
            probes: vec![
                Probe {
                    cookie: 0,
                    symbol: "ENGINE_by_id".into(),
                    offset: 1,
                    module: "lc".into(),
                    family: None,
                    str_arg: Some(0),
                    program: "trip_str0",
                },
                Probe {
                    cookie: 1,
                    symbol: "ENGINE_init".into(),
                    offset: 2,
                    module: "lc".into(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
                Probe {
                    cookie: 2,
                    symbol: "OSSL_PROVIDER_load".into(),
                    offset: 3,
                    module: "lc".into(),
                    family: None,
                    str_arg: Some(1),
                    program: "trip_str1",
                },
                Probe {
                    cookie: 3,
                    symbol: "SHA256_Init".into(),
                    offset: 4,
                    module: "lc".into(),
                    family: Some("digest/sha"),
                    str_arg: None,
                    program: "trip_count",
                },
            ],
            engine_uninstrumented: 0,
            meth_uninstrumented: 2,
            lowlevel_uninstrumented: 0,
            unprobed_engine_syms: vec![],
            unprobed_meth_syms: vec!["RSA_meth_new".into(), "DSA_meth_new".into()],
            unprobed_lowlevel_syms: vec![],
            findings: vec![],
            address_taken: vec![],
            by_id_cookies: [0].into_iter().collect(),
            load_cookies: [2].into_iter().collect(),
        };
        let trip: HashMap<u64, u64> = [(0, 1), (1, 5), (2, 2), (3, 9)].into_iter().collect();
        let hits = vec![
            TripHit {
                cookie: 0,
                class: osslscope_ebpf_common::ENGINE_DYNAMIC,
                status: osslscope_ebpf_common::TRIP_OK,
            },
            TripHit {
                cookie: 2,
                class: osslscope_ebpf_common::LOAD_LEGACY,
                status: osslscope_ebpf_common::TRIP_OK,
            },
            TripHit {
                cookie: 2,
                class: osslscope_ebpf_common::TRIP_OTHER,
                status: osslscope_ebpf_common::TRIP_OK,
            },
        ];
        let doc = section(&SectionInputs {
            set: &set,
            trip: &trip,
            trip_hits: &hits,
            legacy_queries: 7,
            legacy_classes: vec!["B".into(), "A".into(), "A".into()],
            extra_findings: &[],
        });
        assert_eq!(doc["engine"]["calls_by_entrypoint"]["ENGINE_init"], 5);
        assert_eq!(doc["engine"]["engine_id_class"]["dynamic"], 1);
        assert_eq!(doc["engine"]["engine_id_class"]["other"], 0);
        assert!(doc["engine"].get("uninstrumented").is_none());
        assert_eq!(doc["meth_new"]["uninstrumented"], 2);
        assert_eq!(doc["lowlevel"]["calls_by_family"]["digest/sha"], 9);
        assert_eq!(doc["legacy_provider"]["loads"]["legacy"], 1);
        assert_eq!(doc["legacy_provider"]["loads"]["other"], 1);
        assert_eq!(doc["legacy_provider"]["executed_calls"], 7);
        assert_eq!(
            doc["legacy_provider"]["algs"],
            serde_json::json!(["A", "B"])
        );
        assert_eq!(doc["engine_fallback_uninstrumented"], 2);
        assert!(doc.get("findings").is_none());
    }
}
