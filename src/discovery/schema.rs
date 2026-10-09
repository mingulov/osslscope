//! SPDX-License-Identifier: GPL-3.0-or-later
//! Harvest document schema: one row per (op, class, funcid) plus
//! relocation backing. `addr_hash` (frozen preimage: the attested
//! backing triple, NOT the runtime address) is the golden-comparable
//! identity. Raw runtime addresses are internal relocation input
//! only and are never serialized (T02).
use crate::discovery::{coverage, elf, maps};
use std::path::Path;

/// One harvested dispatch entry. Rows arrive pre-classified: the
/// kernel maps the provider's raw name bytes to a registry class id
/// before ring emission, and the ring decoder resolves the id to its
/// table label here. `alg_class` is therefore always a registry
/// label or `"other"` — never target bytes. `weak` is the kernel's
/// alias-list weak verdict and `status` its read verdict (`ok`,
/// `unknown`, `overlong`, or `truncated`) for the same record, so
/// classification uncertainty survives to the artifact instead of
/// collapsing into an ordinary-looking row.
#[derive(Clone, Debug)]
pub struct Row {
    pub op: u32,
    pub alg_class: String,
    pub weak: bool,
    pub status: String,
    pub funcid: u32,
    /// Implementation code address: INTERNAL relocation input,
    /// consumed against live mappings below and never serialized.
    pub impl_addr: u64,
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
    /// Ops with at least one observed array lacking termination
    /// proof (T03: a prefix, never COMPLETE).
    pub unterminated_ops: Vec<u32>,
    /// `(loss source id, count)` failures (T03: ring-reserve,
    /// map-update, pending, orphan, undecodable — see
    /// `coverage::loss_source_name`).
    pub losses: Vec<(u32, u64)>,
    /// Walked slots whose identity was lost (T03:
    /// unreadable/overlong names; unreadable slots emit no rows, so
    /// this count — not the rows — carries the gap).
    pub lossy_slots: u64,
    /// Non-default resolution label (`symtab`, `anchor+delta`, `force`).
    pub resolution: Option<String>,
    /// Explicit PARTIAL reason (frozen vocabulary: `anchor-unresolved`,
    /// `no-query-trigger`, `zero-rows`, `zero-row-ops`, `truncated-walk`,
    /// `prefix-walk`, `unreadable-alg`, `discovery-loss`, `fenced-rows`,
    /// `pid-recycled`).
    pub reason: Option<String>,
    /// Pid-recycle detections this run (exit-6 pin): rows are always
    /// discarded on recycle, so this only ever reads 1.
    pub pid_recycled: u64,
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
/// harvest document. A row is `addr_backed` iff its implementation
/// address sits in an executable provider mapping whose file offset
/// lands in an executable LOAD segment (same rule the P0 oracle
/// proved at 26/26 stripped).
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
    // Deterministic row order (exit-1 hardening): arrival order is
    // race-dependent (GO1 queries may predate the stage-2 attach, so
    // rotation starts mid-array). Rows sort by (op, class, status,
    // funcid, attested backing triple) — never by runtime address:
    // same-key multi-impl rows span files (provider + shared
    // libcrypto), whose ASLR slides differ, so an addr tiebreak
    // would flip run to run. Upstream seen-set keys (op, class,
    // weak, status, funcid, impl addr) uniquely, and one file maps
    // once per process (dlopen dedupes by (dev, ino)), so the key is
    // total in practice. Backing resolves before the sort so the
    // tiebreak sees stable triples.
    //
    // M4 fence (P1 exit 4, revised per exit-2 parity): ONLY impls in
    // no file-backed x mapping fence (forged pointers — the claim
    // "provider offers this address" is unverifiable there). Same
    // (op, class, funcid) at several BACKED addrs is legitimate
    // multi-impl (default provider: DH ×4 impls, 255 such keys) or
    // property-dependent dispatch — every such row is a true,
    // attributable claim, so all emit. A same-name second table is
    // not a lie (libcrypto resolves first-wins); cross-query table
    // shifting is out of P1 scope (no wild incidence; catching it
    // needs per-query row tags).
    //
    // Foreign-file ELF bytes (shared-code rows): path → bytes, failures
    // cached as empty (parse then fails → unbacked, no repeated reads).
    let mut elf_cache: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut resolved: Vec<(&Row, bool, String, u64, u64)> = Vec::with_capacity(rows.len());
    for r in rows {
        let (backed, dev, ino, off) =
            match maps::provider_mapping(live_maps, provider, canon, r.impl_addr) {
                Some(m) => {
                    let o = r.impl_addr - m.start + m.offset;
                    let ok = m.x && elf::offset_in_x_segment(&elf, o);
                    (ok, m.dev.clone(), m.ino, o)
                }
                None => match live_maps
                    .iter()
                    .find(|m| m.start <= r.impl_addr && r.impl_addr < m.end && m.ino != 0)
                {
                    // Shared-code row (e.g. legacy re-exporting libcrypto
                    // implementations): relocate against the containing
                    // file, not the provider.
                    Some(m) => {
                        let o = r.impl_addr - m.start + m.offset;
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
        resolved.push((r, backed, dev, ino, off));
    }
    resolved.sort_by(|a, b| {
        (
            a.0.op,
            &a.0.alg_class,
            &a.0.status,
            a.0.funcid,
            &a.2,
            a.3,
            a.4,
        )
            .cmp(&(
                b.0.op,
                &b.0.alg_class,
                &b.0.status,
                b.0.funcid,
                &b.2,
                b.3,
                b.4,
            ))
    });
    let mut jrows = Vec::with_capacity(resolved.len());
    let mut fenced: u64 = 0;
    for (r, backed, dev, ino, off) in resolved {
        // Fence: impl in no file-backed x mapping (forged pointer;
        // JIT/anon-x equally un-pinnable — PRD no_attribution: no
        // stable store → count-only). Shared-code rows (impl in
        // ANOTHER file) stay: their backing triple is truthful, and
        // alias-audit reports the sharing. Fenced rows leave no
        // attribution (no class, no backing) — the count is the
        // whole signal.
        if !backed {
            fenced += 1;
            continue;
        }
        jrows.push(serde_json::json!({
            "provider": provider_name,
            "op": r.op,
            "alg_class": r.alg_class,
            "weak": r.weak,
            "status": r.status,
            "funcid": r.funcid,
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
    // PARTIAL iff an explicit reason, a fenced row, a zero-row op,
    // a walk overflow, an unterminated table, any loss, or a lossy
    // slot; the derived reason is the single shared ranking in
    // `coverage::primary_reason` (integrity > completeness).
    let has_loss = stats.losses.iter().any(|(_, n)| *n > 0);
    let partial = stats.reason.is_some()
        || fenced > 0
        || !stats.zero_row_ops.is_empty()
        || !stats.truncated.is_empty()
        || !stats.unterminated_ops.is_empty()
        || has_loss
        || stats.lossy_slots > 0;
    let counts = stats.builtin || partial;
    if partial {
        let reason = stats.reason.clone().unwrap_or_else(|| {
            coverage::primary_reason(&coverage::ReasonFlags {
                fenced: fenced > 0,
                loss: has_loss,
                unreadable: stats.lossy_slots > 0,
                truncated: !stats.truncated.is_empty(),
                prefix: !stats.unterminated_ops.is_empty(),
                zero_row: !stats.zero_row_ops.is_empty(),
            })
            .expect("partial implies a gap")
            .to_string()
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
        if !stats.unterminated_ops.is_empty() {
            let mut ops = stats.unterminated_ops.clone();
            ops.sort_unstable();
            ops.dedup();
            doc["unterminated_ops"] = ops.into();
        }
        // Loss ledger, keyed by stable source name (the JSON map
        // keeps output order). Unknown ids (newer BPF than
        // userspace) keep their counts under `unknown_<id>` rather
        // than vanishing.
        let mut sums: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        let mut unknowns: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
        for (src, n) in &stats.losses {
            if *n == 0 {
                continue;
            }
            match coverage::loss_source_name(*src) {
                Some(name) => {
                    let e = sums.entry(name).or_default();
                    *e = e.saturating_add(*n);
                }
                None => {
                    let e = unknowns.entry(*src).or_default();
                    *e = e.saturating_add(*n);
                }
            }
        }
        if !sums.is_empty() || !unknowns.is_empty() {
            let mut map = serde_json::Map::new();
            let mut names: Vec<&str> = sums.keys().copied().collect();
            names.sort_unstable();
            for name in names {
                map.insert(name.to_string(), sums[name].into());
            }
            let mut ids: Vec<u32> = unknowns.keys().copied().collect();
            ids.sort_unstable();
            for id in ids {
                map.insert(format!("unknown_{id}"), unknowns[&id].into());
            }
            doc["losses"] = map.into();
        }
        if stats.lossy_slots > 0 {
            doc["lossy_slots"] = stats.lossy_slots.into();
        }
        if stats.foreign_dropped > 0 {
            doc["foreign_rows_dropped"] = stats.foreign_dropped.into();
        }
        if stats.pid_recycled > 0 {
            doc["pid_recycled"] = stats.pid_recycled.into();
        }
        if fenced > 0 {
            doc["fenced_rows"] = fenced.into();
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
                alg_class: "SHA2-256".into(),
                weak: false,
                status: "ok".into(),
                funcid: 7,
                impl_addr: 0x1000,
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "other".into(),
                weak: false,
                status: "unknown".into(),
                funcid: 1,
                impl_addr: 0x2000,
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "MD5".into(),
                weak: true,
                status: "ok".into(),
                funcid: 2,
                impl_addr: 0x3000,
                arr: 0,
            },
        ]
    }

    /// Backed maps into the test exe: addrs land in a real x
    /// PT_LOAD (computed, never hardcoded) so rows back.
    fn backed_maps() -> (Vec<u8>, Vec<crate::discovery::maps::Mapping>) {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let elf = crate::discovery::elf::parse_elf(&exe).unwrap();
        let ph = elf
            .program_headers
            .iter()
            .find(|ph| {
                ph.p_type == goblin::elf::program_header::PT_LOAD
                    && ph.p_flags & goblin::elf::program_header::PF_X != 0
            })
            .unwrap();
        let maps = vec![crate::discovery::maps::Mapping {
            start: 0x1000,
            end: 0x1000 + ph.p_filesz,
            x: true,
            offset: ph.p_offset,
            dev: "08:01".to_string(),
            ino: 42,
            path: "t".to_string(),
        }];
        (exe, maps)
    }

    fn backed_addr(i: u64) -> u64 {
        0x1000 + i * 0x10
    }

    #[test]
    fn doc_shape_and_hash_preimage() {
        let rows = vec![
            Row {
                op: 1,
                alg_class: "SHA2-256".into(),
                weak: false,
                status: "ok".into(),
                funcid: 7,
                impl_addr: backed_addr(0),
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "other".into(),
                weak: false,
                status: "unknown".into(),
                funcid: 1,
                impl_addr: backed_addr(1),
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "MD5".into(),
                weak: true,
                status: "ok".into(),
                funcid: 2,
                impl_addr: backed_addr(2),
                arr: 0,
            },
        ];
        let (exe, maps) = backed_maps();
        let doc = emit(
            "t",
            Path::new("t"),
            "",
            &exe,
            &maps,
            &rows,
            true,
            &Stats::trivial(),
        )
        .unwrap();
        let jrows = doc["rows"].as_array().unwrap();
        assert_eq!(jrows.len(), 3);
        // Sorted by (op, class, funcid): MD5 < SHA2-256 < other.
        let classes: Vec<&str> = jrows
            .iter()
            .map(|r| r["alg_class"].as_str().unwrap())
            .collect();
        assert_eq!(classes, vec!["MD5", "SHA2-256", "other"]);
        assert_eq!(jrows[1]["weak"], false);
        // Raw names and runtime addresses never survive emission.
        assert!(jrows[2].get("alg").is_none());
        for r in jrows {
            assert!(r.get("addr").is_none(), "raw addr leaked: {r}");
        }
        assert_eq!(jrows[0]["weak"], true);
        // Kernel verdict statuses ride the rows: uncertainty stays
        // explicit instead of collapsing into ordinary rows.
        let statuses: Vec<&str> = jrows
            .iter()
            .map(|r| r["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, vec!["ok", "ok", "unknown"]);
        let r = &jrows[1];
        assert_eq!(r["addr_backed"], true);
        assert_eq!(
            r["addr_hash"],
            crate::kinds::addr_hash("08:01", 42, r["backing"]["offset"].as_u64().unwrap())
        );
    }

    fn emit_with(rows: &[Row], stats: &Stats) -> serde_json::Value {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        emit("t", Path::new("t"), "", &exe, &[], rows, true, stats).unwrap()
    }

    fn emit_backed(rows: &[Row], stats: &Stats) -> serde_json::Value {
        let (exe, maps) = backed_maps();
        emit("t", Path::new("t"), "", &exe, &maps, rows, true, stats).unwrap()
    }

    #[test]
    fn trivial_stats_preserves_exit1_shape() {
        // P1-exit-1 byte-compat: COMPLETE provider docs gain NO keys.
        let rows: Vec<Row> = sample_rows()
            .into_iter()
            .enumerate()
            .map(|(i, mut r)| {
                r.impl_addr = backed_addr(i as u64);
                r
            })
            .collect();
        let doc = emit_backed(&rows, &Stats::trivial());
        for k in [
            "status",
            "reason",
            "resolution",
            "queries_observed",
            "zero_row_ops",
            "uninstrumented_ops",
            "truncated_ops",
            "unterminated_ops",
            "losses",
            "lossy_slots",
            "foreign_rows_dropped",
            "fenced_rows",
        ] {
            assert!(doc.get(k).is_none(), "leaked key {k}");
        }
        assert_eq!(doc["rows"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn multi_impl_rows_all_emit() {
        // Same (op, name, funcid) at two BACKED addrs (DH-style
        // multi-impl — dumper-proven legitimate on the default
        // provider): every row is a true, attributable claim, so
        // all emit and nothing fences. (The old disagreement
        // fence ate 1260 such real rows — exit-2 parity 0.79.)
        let rows = vec![
            Row {
                op: 1,
                alg_class: "DH".into(),
                weak: false,
                status: "ok".into(),
                funcid: 10,
                impl_addr: backed_addr(1),
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "other".into(),
                weak: false,
                status: "unknown".into(),
                funcid: 3,
                impl_addr: backed_addr(2),
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "DH".into(),
                weak: false,
                status: "ok".into(),
                funcid: 10,
                impl_addr: backed_addr(0),
                arr: 0,
            },
        ];
        let doc = emit_backed(&rows, &Stats::trivial());
        assert!(doc.get("status").is_none());
        assert!(doc.get("fenced_rows").is_none());
        let jrows = doc["rows"].as_array().unwrap();
        assert_eq!(jrows.len(), 3);
        // DH pair first (name order), ascending file offset (NOT
        // arrival order — the pair arrived reversed above).
        let offs: Vec<u64> = jrows
            .iter()
            .map(|r| r["backing"]["offset"].as_u64().unwrap())
            .collect();
        assert_eq!(offs[1] - offs[0], 0x10);
        assert_eq!(offs[2] - offs[1], 0x10);
    }

    #[test]
    fn multi_impl_order_ignores_arrival_and_slide() {
        // Same-key rows arrive in race order under a random ASLR
        // slide, but must emit byte-identically: reversed arrival
        // and a re-slid mapping both converge on offset order.
        let mk = |addrs: &[u64]| -> Vec<Row> {
            addrs
                .iter()
                .map(|&a| Row {
                    op: 1,
                    alg_class: "DH".into(),
                    weak: false,
                    status: "ok".into(),
                    funcid: 10,
                    impl_addr: a,
                    arr: 0,
                })
                .collect()
        };
        let fwd = mk(&[backed_addr(0), backed_addr(1), backed_addr(2)]);
        let rev = mk(&[backed_addr(2), backed_addr(0), backed_addr(1)]);
        let a = emit_backed(&fwd, &Stats::trivial());
        let b = emit_backed(&rev, &Stats::trivial());
        assert_eq!(a, b);
        // Re-slide: same triples at moved addrs → same doc modulo
        // raw addr (hashes derive from triples, so they hold too).
        let (exe, mut maps) = backed_maps();
        for m in maps.iter_mut() {
            let len = m.end - m.start;
            m.start += 0x5000;
            m.end = m.start + len;
        }
        let slid: Vec<Row> = fwd
            .iter()
            .map(|r| Row {
                impl_addr: r.impl_addr + 0x5000,
                ..r.clone()
            })
            .collect();
        let c = emit(
            "t",
            Path::new("t"),
            "",
            &exe,
            &maps,
            &slid,
            true,
            &Stats::trivial(),
        )
        .unwrap();
        // Re-slide: same triples at moved addrs → byte-identical docs
        // (no runtime address is serialized at all since T02, so no
        // redaction step remains).
        assert_eq!(a, c);
    }

    #[test]
    fn multi_impl_order_uses_backing_not_addr() {
        // Cross-file same-key rows (provider + shared libcrypto):
        // runtime addr order follows per-file ASLR slides, so the
        // tiebreak must use the backing triple instead. Here addr
        // order and triple order INVERT: the smaller addr sits in
        // the larger (dev, ino, offset).
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let elf = crate::discovery::elf::parse_elf(&exe).unwrap();
        let base = elf
            .program_headers
            .iter()
            .find(|ph| {
                ph.p_type == goblin::elf::program_header::PT_LOAD
                    && ph.p_flags & goblin::elf::program_header::PF_X != 0
            })
            .unwrap()
            .p_offset;
        let maps = vec![
            crate::discovery::maps::Mapping {
                start: 0x1000,
                end: 0x2000,
                x: true,
                offset: base,
                dev: "08:02".to_string(),
                ino: 43,
                path: "t".to_string(),
            },
            crate::discovery::maps::Mapping {
                start: 0x8000,
                end: 0x9000,
                x: true,
                offset: base,
                dev: "08:01".to_string(),
                ino: 42,
                path: "t".to_string(),
            },
        ];
        let rows = vec![
            Row {
                op: 1,
                alg_class: "DH".into(),
                weak: false,
                status: "ok".into(),
                funcid: 10,
                impl_addr: 0x1000,
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "DH".into(),
                weak: false,
                status: "ok".into(),
                funcid: 10,
                impl_addr: 0x8010,
                arr: 0,
            },
        ];
        let doc = emit(
            "t",
            Path::new("t"),
            "",
            &exe,
            &maps,
            &rows,
            true,
            &Stats::trivial(),
        )
        .unwrap();
        let jrows = doc["rows"].as_array().unwrap();
        assert_eq!(jrows.len(), 2);
        // ("08:01", 42, base+0x10) < ("08:02", 43, base): the
        // LARGER addr emits first. An addr tiebreak would flip this
        // whenever the slides invert.
        assert_eq!(jrows[0]["backing"]["dev"], "08:01");
        assert_eq!(jrows[1]["backing"]["dev"], "08:02");
    }

    #[test]
    fn fence_unbacked_impls() {
        // Impl in no file mapping (forged pointer): fenced even
        // with a unique claim.
        let rows = vec![Row {
            op: 1,
            alg_class: "other".into(),
            weak: false,
            status: "unknown".into(),
            funcid: 3,
            impl_addr: 0x7f00_0000_0000,
            arr: 0,
        }];
        let doc = emit_backed(&rows, &Stats::trivial());
        assert_eq!(doc["reason"], "fenced-rows");
        assert_eq!(doc["fenced_rows"], 1);
        assert!(doc["rows"].as_array().unwrap().is_empty());
    }

    #[test]
    fn fence_reason_yields_to_explicit() {
        // Explicit PARTIAL reasons (blind dispatch, empty rows)
        // keep their name; fence ranks above walk-completeness.
        let rows = vec![Row {
            op: 1,
            alg_class: "other".into(),
            weak: false,
            status: "unknown".into(),
            funcid: 3,
            impl_addr: 0x7f00_0000_0000,
            arr: 0,
        }];
        let stats = Stats {
            reason: Some("anchor-unresolved".into()),
            ..Stats::trivial()
        };
        let doc = emit_backed(&rows, &stats);
        assert_eq!(doc["reason"], "anchor-unresolved");
        let stats = Stats {
            truncated: vec![(1, 1)],
            ..Stats::trivial()
        };
        let doc = emit_backed(&rows, &stats);
        assert_eq!(doc["reason"], "fenced-rows");
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
        assert!(doc.get("unterminated_ops").is_none());
        assert!(doc.get("losses").is_none());
        assert!(doc.get("lossy_slots").is_none());
        assert!(doc.get("fenced_rows").is_none());
    }

    #[test]
    fn counters_emitted_when_nontrivial() {
        let stats = Stats {
            builtin: true,
            queries_observed: 5,
            zero_row_ops: vec![3],
            truncated: vec![(12, 1)],
            unterminated_ops: vec![12],
            losses: vec![(osslscope_ebpf_common::LOSS_RING_ROW, 2)],
            lossy_slots: 1,
            resolution: Some("anchor+delta".into()),
            reason: None,
            foreign_dropped: 2,
            pid_recycled: 1,
        };
        let rows: Vec<Row> = sample_rows()
            .into_iter()
            .enumerate()
            .map(|(i, mut r)| {
                r.impl_addr = backed_addr(i as u64);
                r
            })
            .collect();
        let doc = emit_backed(&rows, &stats);
        assert_eq!(doc["status"], "PARTIAL");
        // Pipeline loss outranks truncation outranks zero-row-ops.
        assert_eq!(doc["reason"], "discovery-loss");
        assert_eq!(doc["resolution"], "anchor+delta");
        assert_eq!(doc["queries_observed"], 5);
        assert_eq!(doc["zero_row_ops"], serde_json::json!([3]));
        assert_eq!(doc["truncated_ops"], serde_json::json!({"12": 1}));
        assert_eq!(doc["unterminated_ops"], serde_json::json!([12]));
        assert_eq!(doc["losses"], serde_json::json!({"ring_row": 2}));
        assert_eq!(doc["lossy_slots"], 1);
        assert_eq!(doc["foreign_rows_dropped"], 2);
        assert_eq!(doc["pid_recycled"], 1);
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
        let rows: Vec<Row> = sample_rows()
            .into_iter()
            .enumerate()
            .map(|(i, mut r)| {
                r.impl_addr = backed_addr(i as u64);
                r
            })
            .collect();
        let doc = emit_backed(&rows, &stats);
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
                alg_class: "SHA1".into(),
                weak: true,
                status: "ok".into(),
                funcid: 3,
                impl_addr: base + off,
                arr: 0,
            },
            Row {
                op: 1,
                alg_class: "other".into(),
                weak: false,
                status: "unknown".into(),
                funcid: 3,
                impl_addr: 0x1234,
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
        // Unmapped rows are fenced (count-only, never attributed).
        assert_eq!(jrows.len(), 1);
        assert_eq!(doc["status"], "PARTIAL");
        assert_eq!(doc["reason"], "fenced-rows");
        assert_eq!(doc["fenced_rows"], 1);
    }
}
