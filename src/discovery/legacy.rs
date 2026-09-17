//! Legacy tripwires (P1 exit 3): ENGINE / meth_new / provider-load /
//! low-level-family uprobe plan from the frozen registry × target
//! dynsym, string-argument taxonomy, and the `legacy` doc section.
//!
//! Cookies are sequential in probe order (engine, meth_new, load,
//! lowlevel); userspace decodes via the same `ProbeSet` (consistent
//! within a run — no fixed id space to version).
use crate::discovery::{elf, maps};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Frozen finding: libcrypto mapped but zero ENGINE symbols (4.0 and
/// no-engine 3.x). COMPLETE doc, never an error.
pub const FINDING_ENGINE_ABSENT: &str = "ENGINE API absent";
/// Frozen finding: statically linked target, no usable libcrypto
/// dynsym. The doc is PARTIAL (dispatch anchor also unresolvable).
pub const FINDING_LOWLEVEL_NODYNSYM: &str = "low-level coverage unavailable (no .dynsym)";

/// Known upstream built-in engine ids (best-effort; unknown → other).
const BUILTIN_ENGINE_IDS: &[&str] = &[
    "padlock",
    "capi",
    "dasync",
    "afalg",
    "loader_attic",
    "ossltest",
];

/// One tripwire attachment.
#[derive(Debug, Clone)]
pub struct Probe {
    pub cookie: u64,
    pub symbol: String,
    pub offset: u64,
    /// Low-level family (aggregation key), else None.
    pub family: Option<&'static str>,
    /// String-argument index (`trip_str0`/`trip_str1`) vs hot counter
    /// (`trip_count`, None).
    pub str_arg: Option<usize>,
    /// BPF program name for this probe.
    pub program: &'static str,
}

/// Resolved probe plan + coverage gaps.
#[derive(Debug, Clone, Default)]
pub struct ProbeSet {
    pub probes: Vec<Probe>,
    pub engine_uninstrumented: u64,
    pub meth_uninstrumented: u64,
    pub lowlevel_uninstrumented: u64,
    pub findings: Vec<String>,
    by_id_cookies: HashSet<u64>,
    load_cookies: HashSet<u64>,
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

/// `ENGINE_by_id` argument class (raw ids never serialized).
pub fn engine_id_class(id: &str) -> &'static str {
    if id == "dynamic" {
        "dynamic"
    } else if BUILTIN_ENGINE_IDS.contains(&id) {
        "builtin"
    } else {
        "other"
    }
}

/// Provider-load argument class.
pub fn load_class(name: &str) -> &'static str {
    match name {
        "legacy" => "legacy",
        "default" => "default",
        "fips" => "fips",
        _ => "other",
    }
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

/// Build the probe plan for libcrypto ELF bytes: registry probe-set
/// (Tripwire/Register/Interception ENGINE + all meth_new + both load
/// entrypoints + per-family low-level prefix matches) × dynsym.
pub fn probes_for(libcrypto_elf: &[u8]) -> anyhow::Result<ProbeSet> {
    let entries = elf::dynsym_func_entries(libcrypto_elf)?;
    let by_name: HashMap<&str, u64> = entries.iter().map(|(n, o)| (n.as_str(), *o)).collect();
    let mut set = ProbeSet::default();
    let mut cookie = 0u64;
    let mut push = |set: &mut ProbeSet,
                    symbol: &str,
                    offset: u64,
                    family: Option<&'static str>,
                    str_arg: Option<usize>| {
        let program = match str_arg {
            None => "trip_count",
            Some(0) => "trip_str0",
            Some(_) => "trip_str1",
        };
        if symbol == "ENGINE_by_id" {
            set.by_id_cookies.insert(cookie);
        } else if str_arg.is_some() {
            set.load_cookies.insert(cookie);
        }
        set.probes.push(Probe {
            cookie,
            symbol: symbol.to_string(),
            offset,
            family,
            str_arg,
            program,
        });
        cookie += 1;
    };
    for e in crate::kinds::ENGINE.iter().filter(|e| {
        matches!(
            e.class,
            crate::kinds::EngineClass::Tripwire
                | crate::kinds::EngineClass::Register
                | crate::kinds::EngineClass::Interception
        )
    }) {
        match by_name.get(e.name) {
            Some(&off) => push(
                &mut set,
                e.name,
                off,
                None,
                (e.name == "ENGINE_by_id").then_some(0),
            ),
            None => set.engine_uninstrumented += 1,
        }
    }
    for m in crate::kinds::METH_NEW {
        match by_name.get(m.name) {
            Some(&off) => push(&mut set, m.name, off, None, None),
            None => set.meth_uninstrumented += 1,
        }
    }
    for name in crate::kinds::PROVIDER_LOAD {
        if let Some(&off) = by_name.get(*name) {
            push(&mut set, name, off, None, Some(1));
        }
    }
    for fam in crate::kinds::LOWLEVEL {
        let mut hits = entries
            .iter()
            .filter(|(n, _)| fam.prefixes.iter().any(|p| n.starts_with(p)))
            .peekable();
        if hits.peek().is_none() {
            set.lowlevel_uninstrumented += 1;
            continue;
        }
        for (n, off) in hits {
            push(&mut set, n, *off, Some(fam.family), None);
        }
    }
    if !entries.iter().any(|(n, _)| n.starts_with("ENGINE_")) {
        set.findings.push(FINDING_ENGINE_ABSENT.to_string());
    }
    // Same-offset aliases would double-count (two cookies fire per
    // call): keep the first probe per offset (zero aliases on lanes;
    // fail-safe, not dead code).
    let mut seen_off = HashSet::new();
    set.probes.retain(|p| seen_off.insert(p.offset));
    Ok(set)
}

/// Inputs for the `legacy` doc section.
pub struct SectionInputs<'a> {
    pub set: &'a ProbeSet,
    /// TRIP map contents: cookie → hit count.
    pub trip: &'a HashMap<u64, u64>,
    /// KIND_TRIP string hits: (cookie, arg0).
    pub trip_strs: &'a [(u64, String)],
    /// LGCALLS sum: executed legacy-provider queries (deny signal).
    pub legacy_queries: u64,
    /// Legacy-partitioned row classes (sorted/deduped here).
    pub legacy_classes: Vec<String>,
    /// Extra findings (the blind path adds its mandated string).
    pub extra_findings: &'a [&'a str],
}

/// Emit the `legacy` doc section (design §3 shapes).
pub fn section(inp: &SectionInputs) -> serde_json::Value {
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
        (if is_meth {
            &mut meth_calls
        } else {
            &mut engine_calls
        })
        .insert(p.symbol.clone(), count(p.cookie));
    }
    let mut id_class: BTreeMap<&str, u64> = [("dynamic", 0), ("builtin", 0), ("other", 0)]
        .into_iter()
        .collect();
    let mut loads: BTreeMap<&str, u64> = [("legacy", 0), ("default", 0), ("fips", 0), ("other", 0)]
        .into_iter()
        .collect();
    for (c, s) in inp.trip_strs {
        if inp.set.by_id_cookies.contains(c) {
            *id_class.get_mut(engine_id_class(s)).unwrap() += 1;
        } else if inp.set.load_cookies.contains(c) {
            *loads.get_mut(load_class(s)).unwrap() += 1;
        }
    }
    let mut fam_calls: BTreeMap<&str, u64> = crate::kinds::LOWLEVEL
        .iter()
        .map(|f| (f.family, 0))
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
    let mut legacy = serde_json::json!({
        "engine": {"calls_by_entrypoint": engine_calls, "engine_id_class": id_class},
        "meth_new": {"calls_by_entrypoint": meth_calls},
        "lowlevel": {"calls_by_family": fam_calls},
        "legacy_provider": {"loads": loads, "executed_calls": inp.legacy_queries,
                            "algs": classes},
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
    if !findings.is_empty() {
        legacy["findings"] = findings.into();
    }
    legacy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_classes() {
        assert_eq!(engine_id_class("dynamic"), "dynamic");
        assert_eq!(engine_id_class("padlock"), "builtin");
        assert_eq!(engine_id_class("wat"), "other");
        assert_eq!(engine_id_class(""), "other");
        assert_eq!(load_class("legacy"), "legacy");
        assert_eq!(load_class("default"), "default");
        assert_eq!(load_class("fips"), "fips");
        assert_eq!(load_class("spike"), "other");
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
    fn probes_on_libc_are_all_uninstrumented() {
        // libc: no ENGINE/METH/LOAD/low-level symbols → empty plan, full
        // gaps, absent finding. Real libcrypto plans are gate-proven.
        let b = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"]
            .into_iter()
            .find_map(|p| std::fs::read(p).ok())
            .expect("no libc — broken test env");
        let set = probes_for(&b).unwrap();
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
        assert_eq!(set.findings, vec![FINDING_ENGINE_ABSENT.to_string()]);
        assert_eq!(
            set.engine_fallback_uninstrumented(),
            want_engine + crate::kinds::METH_NEW.len() as u64
        );
    }

    #[test]
    fn section_shape() {
        let set = ProbeSet {
            probes: vec![
                Probe {
                    cookie: 0,
                    symbol: "ENGINE_by_id".into(),
                    offset: 1,
                    family: None,
                    str_arg: Some(0),
                    program: "trip_str0",
                },
                Probe {
                    cookie: 1,
                    symbol: "ENGINE_init".into(),
                    offset: 2,
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
                Probe {
                    cookie: 2,
                    symbol: "OSSL_PROVIDER_load".into(),
                    offset: 3,
                    family: None,
                    str_arg: Some(1),
                    program: "trip_str1",
                },
                Probe {
                    cookie: 3,
                    symbol: "SHA256_Init".into(),
                    offset: 4,
                    family: Some("digest/sha"),
                    str_arg: None,
                    program: "trip_count",
                },
            ],
            engine_uninstrumented: 0,
            meth_uninstrumented: 2,
            lowlevel_uninstrumented: 0,
            findings: vec![],
            by_id_cookies: [0].into_iter().collect(),
            load_cookies: [2].into_iter().collect(),
        };
        let trip: HashMap<u64, u64> = [(0, 1), (1, 5), (2, 2), (3, 9)].into_iter().collect();
        let strs = vec![
            (0u64, "dynamic".to_string()),
            (2u64, "legacy".to_string()),
            (2u64, "spike".to_string()),
        ];
        let doc = section(&SectionInputs {
            set: &set,
            trip: &trip,
            trip_strs: &strs,
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
