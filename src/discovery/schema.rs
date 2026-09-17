//! Harvest document schema: one row per (op, alg, funcid, addr)
//! plus relocation backing. `addr_hash` (frozen preimage: the attested
//! backing triple, NOT the runtime address) is the golden-comparable
//! identity; raw `addr` is redacted before golden comparison.
use crate::discovery::{elf, maps};
use std::path::Path;

/// One harvested dispatch entry. `alg` is the provider's raw name
/// bytes — classification input ONLY, never serialized: `emit` maps it
/// to a registry class at emission (goldens forbid verbatim provider
/// strings).
#[derive(Clone, Debug)]
pub struct Row {
    pub op: u32,
    pub alg: String,
    pub funcid: u32,
    pub addr: u64,
    /// Query-returned array base (join key + provider attribution: the
    /// array's mapping identifies the owning provider even when the
    /// implementation address is shared libcrypto code).
    pub arr: u64,
}

/// Harvest-run statistics (P1 exit 2): coverage counters + PARTIAL
/// state. Every field is emitted ONLY when non-trivial AND the doc is
/// a builtin-inventory or PARTIAL doc — COMPLETE provider docs keep
/// the exact P1-exit-1 shape.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Builtin-inventory mode (default-provider harvest).
    pub builtin: bool,
    /// Non-null query calls observed (exact, from the CALLS map).
    pub queries_observed: u64,
    /// Op ids observed with zero rows across all rounds.
    pub zero_row_ops: Vec<u32>,
    /// `(op, TRUNC bits)` walk overflows (1 = alg array, 2 = dispatch).
    pub truncated: Vec<(u32, u64)>,
    /// Non-default resolution label (`symtab`, `anchor+delta`, `force`).
    pub resolution: Option<String>,
    /// Explicit PARTIAL reason (frozen vocabulary: `anchor-unresolved`,
    /// `no-query-trigger`, `zero-rows`, `zero-row-ops`, `truncated-walk`).
    pub reason: Option<String>,
    /// Builtin rows dropped (other providers' arrays — they share
    /// the core wrapper; attributed by array mapping, by
    /// implementation for runtime-built anonymous arrays).
    pub foreign_dropped: u64,
}

impl Stats {
    pub fn trivial() -> Self {
        Stats::default()
    }
}

/// Relocate every row against current maps + disk ELF, then emit the
/// harvest document. A row is `addr_backed` iff its address sits in an
/// executable provider mapping whose file offset lands in an executable
/// LOAD segment (same rule the P0 oracle proved at 26/26 stripped).
// Eight params is the honest seam (identity + relocation + run stats);
// bundling would churn the exit-1 call shape for no behavioral gain.
#[allow(clippy::too_many_arguments)]
pub fn emit(
    provider_name: &str,
    provider: &Path,
    canon: &str,
    elf_bytes: &[u8],
    live_maps: &[maps::Mapping],
    rows: &[Row],
    trigger_observed: bool,
    stats: &Stats,
) -> anyhow::Result<serde_json::Value> {
    let elf = elf::parse_elf(elf_bytes)?;
    // Foreign-file ELF bytes (shared-code rows): path → bytes, failures
    // cached as empty (parse then fails → unbacked, no repeated reads).
    let mut elf_cache: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut jrows = Vec::with_capacity(rows.len());
    for r in rows {
        let (backed, dev, ino, off) =
            match maps::provider_mapping(live_maps, provider, canon, r.addr) {
                Some(m) => {
                    let o = r.addr - m.start + m.offset;
                    let ok = m.x && elf::offset_in_x_segment(&elf, o);
                    (ok, m.dev.clone(), m.ino, o)
                }
                None => match live_maps
                    .iter()
                    .find(|m| m.start <= r.addr && r.addr < m.end && m.ino != 0)
                {
                    // Shared-code row (e.g. legacy re-exporting libcrypto
                    // implementations): relocate against the containing
                    // file, not the provider.
                    Some(m) => {
                        let o = r.addr - m.start + m.offset;
                        let bytes = elf_cache
                            .entry(m.path.clone())
                            .or_insert_with(|| std::fs::read(&m.path).unwrap_or_default());
                        let ok = m.x
                            && elf::parse_elf(bytes)
                                .map(|e| elf::offset_in_x_segment(&e, o))
                                .unwrap_or(false);
                        (ok, m.dev.clone(), m.ino, o)
                    }
                    None => (false, String::new(), 0, 0),
                },
            };
        let (alg_class, weak) = crate::kinds::classify_alg(&r.alg);
        jrows.push(serde_json::json!({
            "provider": provider_name,
            "op": r.op,
            "alg_class": alg_class,
            "weak": weak,
            "funcid": r.funcid,
            "addr": r.addr,
            "addr_hash": crate::kinds::addr_hash(&dev, ino, off),
            "addr_backed": backed,
            "backing": {"dev": dev, "ino": ino, "offset": off},
            "gen": 0,
        }));
    }
    let mut doc = serde_json::json!({
        "provider": provider_name,
        "trigger_observed": trigger_observed,
        "gen": 0,
        "rows": jrows,
    });
    // PARTIAL iff an explicit reason, a zero-row op, or a walk
    // overflow; derived reason ranks truncation above zero-row-ops.
    let partial =
        stats.reason.is_some() || !stats.zero_row_ops.is_empty() || !stats.truncated.is_empty();
    let counts = stats.builtin || partial;
    if partial {
        let reason = stats.reason.clone().unwrap_or_else(|| {
            if stats.truncated.is_empty() {
                "zero-row-ops".to_string()
            } else {
                "truncated-walk".to_string()
            }
        });
        doc["status"] = "PARTIAL".into();
        doc["reason"] = reason.into();
    }
    if let Some(resolution) = &stats.resolution {
        doc["resolution"] = resolution.clone().into();
    }
    if counts {
        if stats.queries_observed > 0 {
            doc["queries_observed"] = stats.queries_observed.into();
        }
        if !stats.zero_row_ops.is_empty() {
            let mut ops = stats.zero_row_ops.clone();
            ops.sort_unstable();
            doc["zero_row_ops"] = ops.into();
        }
        if !stats.truncated.is_empty() {
            let mut map = serde_json::Map::new();
            for (op, bits) in &stats.truncated {
                map.insert(op.to_string(), (*bits).into());
            }
            doc["truncated_ops"] = map.into();
        }
        if stats.foreign_dropped > 0 {
            doc["foreign_rows_dropped"] = stats.foreign_dropped.into();
        }
        // Registry ops without rows (inventory scope / PARTIAL depth).
        let covered: std::collections::HashSet<u32> = rows.iter().map(|r| r.op).collect();
        let uninstrumented = crate::kinds::OPS
            .iter()
            .filter(|op| !covered.contains(&op.id))
            .count();
        if uninstrumented > 0 {
            doc["uninstrumented_ops"] = uninstrumented.into();
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rows() -> Vec<Row> {
        vec![
            Row {
                op: 1,
                alg: "SHA2-256:SHA256".into(),
                funcid: 7,
                addr: 0x1000,
                arr: 0,
            },
            Row {
                op: 1,
                alg: "canary-DOOM-7QZ".into(),
                funcid: 1,
                addr: 0x2000,
                arr: 0,
            },
            Row {
                op: 1,
                alg: "MD5".into(),
                funcid: 2,
                addr: 0x3000,
                arr: 0,
            },
        ]
    }

    #[test]
    fn doc_shape_and_hash_preimage() {
        let rows = vec![
            Row {
                op: 1,
                alg: "SHA2-256:SHA256".into(),
                funcid: 7,
                addr: 0x1000,
                arr: 0,
            },
            Row {
                op: 1,
                alg: "canary-DOOM-7QZ".into(),
                funcid: 1,
                addr: 0x2000,
                arr: 0,
            },
            Row {
                op: 1,
                alg: "MD5".into(),
                funcid: 2,
                addr: 0x3000,
                arr: 0,
            },
        ];
        // Deferred mapping: no maps → unbacked, but shape + hash hold.
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let doc = emit(
            "t",
            Path::new("t"),
            "",
            &exe,
            &[],
            &rows,
            true,
            &Stats::trivial(),
        )
        .unwrap();
        let jrows = doc["rows"].as_array().unwrap();
        assert_eq!(jrows.len(), 3);
        assert_eq!(jrows[0]["alg_class"], "SHA2-256");
        assert_eq!(jrows[0]["weak"], false);
        // Canary bytes never survive emission.
        assert_eq!(jrows[1]["alg_class"], "other");
        assert!(jrows[1].get("alg").is_none());
        assert_eq!(jrows[2]["alg_class"], "MD5");
        assert_eq!(jrows[2]["weak"], true);
        let r = &jrows[0];
        assert_eq!(r["addr_backed"], false);
        // Unbacked triple → the documented degenerate hash.
        assert_eq!(r["addr_hash"], crate::kinds::addr_hash("", 0, 0));
    }

    fn emit_with(rows: &[Row], stats: &Stats) -> serde_json::Value {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        emit("t", Path::new("t"), "", &exe, &[], rows, true, stats).unwrap()
    }

    #[test]
    fn trivial_stats_preserves_exit1_shape() {
        // P1-exit-1 byte-compat: COMPLETE provider docs gain NO keys.
        let doc = emit_with(&sample_rows(), &Stats::trivial());
        for k in [
            "status",
            "reason",
            "resolution",
            "queries_observed",
            "zero_row_ops",
            "uninstrumented_ops",
            "truncated_ops",
            "foreign_rows_dropped",
        ] {
            assert!(doc.get(k).is_none(), "leaked key {k}");
        }
        assert_eq!(doc["rows"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn partial_doc_shape_anchor_unresolved() {
        let stats = Stats {
            reason: Some("anchor-unresolved".into()),
            ..Stats::trivial()
        };
        let doc = emit_with(&[], &stats);
        assert_eq!(doc["status"], "PARTIAL");
        assert_eq!(doc["reason"], "anchor-unresolved");
        assert_eq!(doc["uninstrumented_ops"], crate::kinds::OPS.len());
        // Zero-valued counters stay omitted.
        assert!(doc.get("queries_observed").is_none());
        assert!(doc.get("zero_row_ops").is_none());
        assert!(doc.get("truncated_ops").is_none());
    }

    #[test]
    fn counters_emitted_when_nontrivial() {
        let stats = Stats {
            builtin: true,
            queries_observed: 5,
            zero_row_ops: vec![3],
            truncated: vec![(12, 1)],
            resolution: Some("anchor+delta".into()),
            reason: None,
            foreign_dropped: 2,
        };
        let doc = emit_with(&sample_rows(), &stats);
        assert_eq!(doc["status"], "PARTIAL");
        // Truncation outranks zero-row-ops in the derived reason.
        assert_eq!(doc["reason"], "truncated-walk");
        assert_eq!(doc["resolution"], "anchor+delta");
        assert_eq!(doc["queries_observed"], 5);
        assert_eq!(doc["zero_row_ops"], serde_json::json!([3]));
        assert_eq!(doc["truncated_ops"], serde_json::json!({"12": 1}));
        assert_eq!(doc["foreign_rows_dropped"], 2);
        // Sample rows cover op 1 only → 13 of 14 registry ops rowless.
        assert_eq!(doc["uninstrumented_ops"], crate::kinds::OPS.len() - 1);
    }

    #[test]
    fn complete_builtin_omits_status_but_counts() {
        let stats = Stats {
            builtin: true,
            queries_observed: 9,
            ..Stats::trivial()
        };
        let doc = emit_with(&sample_rows(), &stats);
        assert!(doc.get("status").is_none());
        assert!(doc.get("reason").is_none());
        assert_eq!(doc["queries_observed"], 9);
        assert_eq!(doc["uninstrumented_ops"], crate::kinds::OPS.len() - 1);
    }

    #[test]
    fn shared_code_row_relocates_to_containing_file() {
        // Legacy re-exports libcrypto implementations: rows outside the
        // provider file relocate against their containing mapping.
        let libc = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .expect("no libc at standard paths — broken test env");
        let bytes = std::fs::read(libc).unwrap();
        let off = elf::dynsym_file_offset(&bytes, "printf").unwrap();
        let base = 0x7f00_0000_0000u64;
        let live = vec![maps::Mapping {
            start: base,
            end: base + 0x100000,
            x: true,
            offset: 0,
            dev: "08:01".into(),
            ino: 999,
            path: libc.into(),
        }];
        let rows = vec![
            Row {
                op: 1,
                alg: "SHA1".into(),
                funcid: 3,
                addr: base + off,
                arr: 0,
            },
            Row {
                op: 1,
                alg: "SHA1".into(),
                funcid: 3,
                addr: 0x1234,
                arr: 0,
            },
        ];
        let doc = emit(
            "t",
            Path::new("/fake/provider.so"),
            "",
            &bytes,
            &live,
            &rows,
            true,
            &Stats::trivial(),
        )
        .unwrap();
        let jrows = doc["rows"].as_array().unwrap();
        assert_eq!(jrows[0]["addr_backed"], true);
        assert_eq!(jrows[0]["backing"]["offset"], off);
        assert_eq!(
            jrows[0]["addr_hash"],
            crate::kinds::addr_hash("08:01", 999, off)
        );
        // Unmapped rows keep the degenerate triple.
        assert_eq!(jrows[1]["addr_backed"], false);
        assert_eq!(jrows[1]["backing"]["offset"], 0);
    }
}
