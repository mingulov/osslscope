//! SPDX-License-Identifier: GPL-3.0-or-later
//! Built-in default-provider bootstrap (P1 exit 2): resolve the file
//! offset of the core-static `ossl_provider_query_operation` (no
//! `.dynsym` entry — uprobes need an absolute file offset).
//!
//! Ladder (first hit wins; every rung is validated functionally by the
//! harvest — a wrong offset yields zero rows → PARTIAL, never wrong
//! attribution):
//! 1. `--force-offset` (forensics escape hatch).
//! 2. build-id table hit (`etc/build-id-table.json`, stripped-proof:
//!    GNU build-ids survive stripping, section layout is unchanged).
//! 3. `.symtab` direct lookup (unstripped/debug builds).
//! 4. dynsym-anchor + version-keyed delta (`OSSL_PROVIDER_available`,
//!    the stable export immediately below the query fn on all lanes).
use crate::discovery::elf;
use crate::discovery::provider::validate_build_id;
use crate::kinds::Version;
use anyhow::{Context as _, anyhow, bail};
use std::collections::HashMap;

/// Core-static query fn (identical signature on 3.0/3.5/4.0).
pub const QUERY_SYMBOL: &str = "ossl_provider_query_operation";

/// Which ladder rung resolved the offset (emitted as `resolution`
/// when it differs from the mode default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Forced,
    Table,
    Symtab,
    AnchorFallback,
}

impl Resolution {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resolution::Forced => "force",
            Resolution::Table => "table",
            Resolution::Symtab => "symtab",
            Resolution::AnchorFallback => "anchor+delta",
        }
    }
}

/// One frozen build-id → offset entry.
#[derive(Debug, Clone)]
pub struct TableEntry {
    pub openssl: String,
    pub query_offset: u64,
    pub anchor: String,
    pub anchor_offset: u64,
}

/// One version-keyed anchor+delta fallback.
#[derive(Debug, Clone)]
pub struct FallbackEntry {
    pub anchor: String,
    pub delta: u64,
}

/// Parsed build-id table (shipped frozen; `--table` overrides).
#[derive(Debug, Clone, Default)]
pub struct Table {
    by_id: HashMap<String, TableEntry>,
    fallback: HashMap<Version, FallbackEntry>,
}

impl Table {
    pub fn empty() -> Self {
        Table::default()
    }

    pub fn by_build_id(&self, id: &str) -> Option<&TableEntry> {
        self.by_id.get(id)
    }

    pub fn fallback(&self, v: Version) -> Option<&FallbackEntry> {
        self.fallback.get(&v)
    }

    pub fn entry_count(&self) -> usize {
        self.by_id.len()
    }

    pub fn fallback_count(&self) -> usize {
        self.fallback.len()
    }
}

/// Parse table JSON (schema `table_version: 1`).
pub fn load_table_str(s: &str) -> anyhow::Result<Table> {
    let v: serde_json::Value = serde_json::from_str(s).context("table JSON parse")?;
    if v.get("table_version").and_then(|n| n.as_u64()) != Some(1) {
        bail!("unsupported table_version (want 1)");
    }
    let mut t = Table::empty();
    for e in v
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let id = e
            .get("build_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("table entry lacks build_id"))?;
        validate_build_id(id)?;
        t.by_id.insert(
            id.to_string(),
            TableEntry {
                openssl: e
                    .get("openssl")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string(),
                query_offset: e
                    .get("query_offset")
                    .and_then(|n| n.as_u64())
                    .ok_or_else(|| anyhow!("table entry lacks query_offset"))?,
                anchor: e
                    .get("anchor")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| anyhow!("table entry lacks anchor"))?
                    .to_string(),
                anchor_offset: e
                    .get("anchor_offset")
                    .and_then(|n| n.as_u64())
                    .ok_or_else(|| anyhow!("table entry lacks anchor_offset"))?,
            },
        );
    }
    for f in v
        .get("fallback")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let ver = f
            .get("openssl")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("fallback lacks openssl version"))?;
        let (maj, min) = ver
            .split_once('.')
            .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
            .ok_or_else(|| anyhow!("bad fallback version {ver}"))?;
        t.fallback.insert(
            (maj, min),
            FallbackEntry {
                anchor: f
                    .get("anchor")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| anyhow!("fallback lacks anchor"))?
                    .to_string(),
                delta: f
                    .get("delta")
                    .and_then(|n| n.as_u64())
                    .ok_or_else(|| anyhow!("fallback lacks delta"))?,
            },
        );
    }
    Ok(t)
}

/// The frozen shipped table. A corrupt embedded table is a build bug
/// and fails loudly (never a silent empty ladder).
pub fn shipped_table() -> Table {
    load_table_str(include_str!("../../etc/build-id-table.json"))
        .expect("shipped build-id table corrupt")
}

/// Resolve the query-fn file offset via the ladder.
pub fn resolve_query_offset(
    elf_bytes: &[u8],
    table: &Table,
    force: Option<u64>,
) -> anyhow::Result<(u64, Resolution)> {
    resolve_symbol_offset(elf_bytes, table, force, QUERY_SYMBOL)
}

/// Ladder over a caller-chosen symbol (the query symbol in production;
/// the seam that keeps every rung hermetically testable).
pub fn resolve_symbol_offset(
    elf_bytes: &[u8],
    table: &Table,
    force: Option<u64>,
    symbol: &str,
) -> anyhow::Result<(u64, Resolution)> {
    if let Some(off) = force {
        return Ok((off, Resolution::Forced));
    }
    let elf = elf::parse_elf(elf_bytes)?;
    if let Some(id) = elf::read_build_id(elf_bytes)
        && let Some(e) = table.by_build_id(&id)
    {
        // T09 shape check: the recorded anchor must resolve to the
        // recorded offset in THESE bytes. A build-id mislabel or a
        // table/object mismatch fails closed with an actionable
        // error instead of probing a wrong offset (a wrong offset
        // yields zero rows → PARTIAL at best; the check exists so a
        // stale table can never silently resolve).
        let live = elf::dynsym_file_offset(elf_bytes, &e.anchor).map_err(|_| {
            anyhow!(
                "build-id table entry for {id}: anchor {} not exported",
                e.anchor
            )
        })?;
        if live != e.anchor_offset {
            bail!(
                "build-id table entry for {id}: anchor {} at 0x{live:x} (table says 0x{:x}); re-enroll this build",
                e.anchor,
                e.anchor_offset
            );
        }
        return Ok((e.query_offset, Resolution::Table));
    }
    if let Ok(off) = elf::symtab_file_offset(elf_bytes, symbol) {
        return Ok((off, Resolution::Symtab));
    }
    let dynstr = dynamic_strtab(&elf, elf_bytes)
        .ok_or_else(|| anyhow!("no PT_DYNAMIC strtab for version scan"))?;
    let names = dynstr
        .split(|b| *b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok());
    let version =
        elf::max_openssl_version(names).ok_or_else(|| anyhow!("no OPENSSL_ version in dynstr"))?;
    let fb = table
        .fallback(version)
        .ok_or_else(|| anyhow!("no fallback delta for OpenSSL {version:?}"))?;
    let off = resolve_via_anchor(elf_bytes, &fb.anchor, fb.delta)?;
    Ok((off, Resolution::AnchorFallback))
}

/// Anchor rung: exported anchor file offset + version delta.
pub fn resolve_via_anchor(elf_bytes: &[u8], anchor: &str, delta: u64) -> anyhow::Result<u64> {
    Ok(elf::dynsym_file_offset(elf_bytes, anchor)? + delta)
}

/// Raw `.dynstr` bytes via PT_DYNAMIC (strip-proof: the loader needs
/// it; no section headers required).
fn dynamic_strtab<'a>(elf: &goblin::elf::Elf<'_>, elf_bytes: &'a [u8]) -> Option<&'a [u8]> {
    let dyn_info = elf.dynamic.as_ref()?;
    let off = elf::vaddr_to_offset(elf, dyn_info.info.strtab as u64)?;
    let len = dyn_info.info.strsz;
    elf_bytes.get(off as usize..(off as usize).checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn libc_bytes() -> Vec<u8> {
        for p in ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"] {
            if let Ok(b) = std::fs::read(p) {
                return b;
            }
        }
        panic!("no libc at standard paths — broken test env");
    }

    #[test]
    fn force_short_circuits_garbage() {
        let (off, r) = resolve_query_offset(b"junk", &Table::empty(), Some(0x42)).unwrap();
        assert_eq!((off, r), (0x42, Resolution::Forced));
    }

    #[test]
    fn table_hit_on_libc_build_id() {
        let b = libc_bytes();
        let id = elf::read_build_id(&b).unwrap();
        let anchor_off = elf::dynsym_file_offset(&b, "printf").unwrap();
        let s = format!(
            r#"{{"table_version":1,
                "entries":[{{"build_id":"{id}","openssl":"9.9",
                             "query_offset":57005,"anchor":"printf",
                             "anchor_offset":{anchor_off}}}],
                "fallback":[]}}"#
        );
        let t = load_table_str(&s).unwrap();
        let (off, r) = resolve_query_offset(&b, &t, None).unwrap();
        assert_eq!((off, r), (57005, Resolution::Table));
    }

    #[test]
    fn table_hit_verifies_anchor_shape() {
        // Stale table (anchor moved) fails closed with re-enroll
        // guidance; it must not resolve to a wrong offset.
        let b = libc_bytes();
        let id = elf::read_build_id(&b).unwrap();
        let anchor_off = elf::dynsym_file_offset(&b, "printf").unwrap();
        let stale = format!(
            r#"{{"table_version":1,
                "entries":[{{"build_id":"{id}","openssl":"9.9",
                             "query_offset":57005,"anchor":"printf",
                             "anchor_offset":{}}}]}}"#,
            anchor_off + 0x1000
        );
        let t = load_table_str(&stale).unwrap();
        let e = resolve_query_offset(&b, &t, None).unwrap_err();
        assert!(format!("{e:#}").contains("re-enroll"), "got: {e:#}");
        // Missing anchor fails closed too.
        let missing = format!(
            r#"{{"table_version":1,
                "entries":[{{"build_id":"{id}","openssl":"9.9",
                             "query_offset":57005,"anchor":"OSSLscope_NoSuch_Xyz",
                             "anchor_offset":1}}]}}"#
        );
        let t = load_table_str(&missing).unwrap();
        assert!(resolve_query_offset(&b, &t, None).is_err());
    }

    #[test]
    fn table_rejects_malformed_build_id() {
        let bad = r#"{"table_version":1,
            "entries":[{"build_id":"xyz","openssl":"9.9",
                        "query_offset":1,"anchor":"a",
                        "anchor_offset":1}]}"#;
        assert!(load_table_str(bad).is_err());
    }

    #[test]
    fn symtab_rung_on_self_anchor() {
        crate::discovery::elf::osslscope_test_symtab_anchor();
        let b = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let (off, r) =
            resolve_symbol_offset(&b, &Table::empty(), None, "osslscope_test_symtab_anchor")
                .unwrap();
        assert_eq!(r, Resolution::Symtab);
        assert!(off < b.len() as u64);
    }

    #[test]
    fn ladder_exhaustion_errs_on_libc() {
        // libc: unknown build-id, no symtab hit for the query symbol,
        // no OPENSSL_ version names → anchor rung fails closed.
        let b = libc_bytes();
        assert!(resolve_query_offset(&b, &Table::empty(), None).is_err());
    }

    #[test]
    fn load_validates_shape() {
        assert!(load_table_str("{bad json").is_err());
        assert!(load_table_str(r#"{"table_version":2}"#).is_err());
        assert!(load_table_str(r#"{"table_version":1}"#).is_ok());
        assert!(load_table_str(r#"{"table_version":1,"entries":[{"build_id":"x"}]}"#).is_err());
        assert!(
            load_table_str(
                r#"{"table_version":1,"fallback":[{"openssl":"4.x","anchor":"a","delta":1}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn shipped_table_loads_with_spot_checks() {
        let t = shipped_table();
        assert_eq!(t.entry_count(), 10);
        assert_eq!(t.fallback_count(), 4);
        let e = t
            .by_build_id("b12cd44337cb70619dd290b2396ab5dfcaea230f")
            .unwrap();
        assert_eq!(e.query_offset, 0x24a760);
        assert_eq!(e.anchor_offset, 0x24a570);
        let r = t
            .by_build_id("e75382d022854b5d4422329b9b440a81c5a03520")
            .unwrap();
        assert_eq!(r.query_offset, 0x25c870);
        assert_eq!(r.anchor_offset, 0x25c6e0);
        let a = t
            .by_build_id("dd9d645699b0c01198228b42ae8092374ff539a5")
            .unwrap();
        assert_eq!(a.query_offset, 0x2824b0);
        assert_eq!(a.anchor_offset, 0x282300);
        let f = t
            .by_build_id("8b1a3899602a4001a02b1dd2e0ada063db39a92d")
            .unwrap();
        assert_eq!(f.query_offset, 0x192240);
        assert_eq!(f.anchor_offset, 0x192090);
        assert_eq!(t.fallback((4, 0)).unwrap().delta, 0x1f0);
        assert_eq!(t.fallback((3, 0)).unwrap().delta, 0x180);
        assert_eq!(t.fallback((3, 5)).unwrap().delta, 0x1e0);
        assert_eq!(t.fallback((3, 6)).unwrap().delta, 0x1b0);
    }

    #[test]
    fn anchor_math_on_libc_printf() {
        let b = libc_bytes();
        let base = elf::dynsym_file_offset(&b, "printf").unwrap();
        assert_eq!(resolve_via_anchor(&b, "printf", 0).unwrap(), base);
        assert_eq!(resolve_via_anchor(&b, "printf", 0x10).unwrap(), base + 0x10);
        assert!(resolve_via_anchor(&b, "OSSLscope_NoSuch_Xyz", 0).is_err());
    }
}
