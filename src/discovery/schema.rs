//! Harvest document schema: one row per (op, alg, funcid, addr)
//! plus relocation backing. `addr_hash` is the golden-comparable
//! identity; raw `addr` is redacted before golden comparison.
use crate::discovery::{elf, maps};
use std::path::Path;

/// One harvested dispatch entry. `alg` is the provider's raw name
/// bytes here — P1 exit 1 classifies to a registry class AT EMISSION
/// (goldens forbid verbatim provider strings); the classifier plugs in
/// at `emit` without touching the relocation leg.
#[derive(Clone, Debug)]
pub struct Row {
    pub op: u32,
    pub alg: String,
    pub funcid: u32,
    pub addr: u64,
}

/// Relocate every row against current maps + disk ELF, then emit the
/// harvest document. A row is `addr_backed` iff its address sits in an
/// executable provider mapping whose file offset lands in an executable
/// LOAD segment (same rule the P0 oracle proved at 26/26 stripped).
pub fn emit(
    provider_name: &str,
    provider: &Path,
    canon: &str,
    elf_bytes: &[u8],
    live_maps: &[maps::Mapping],
    rows: &[Row],
    trigger_observed: bool,
) -> anyhow::Result<serde_json::Value> {
    let elf = elf::parse_elf(elf_bytes)?;
    let mut jrows = Vec::with_capacity(rows.len());
    for r in rows {
        let (backed, dev, ino, off) =
            match maps::provider_mapping(live_maps, provider, canon, r.addr) {
                Some(m) => {
                    let o = r.addr - m.start + m.offset;
                    let ok = m.x && elf::offset_in_x_segment(&elf, o);
                    (ok, m.dev.clone(), m.ino, o)
                }
                None => (false, String::new(), 0, 0),
            };
        jrows.push(serde_json::json!({
            "provider": provider_name,
            "op": r.op,
            "alg": r.alg,
            "funcid": r.funcid,
            "addr": r.addr,
            "addr_hash": crate::kinds::addr_hash(r.addr),
            "addr_backed": backed,
            "backing": {"dev": dev, "ino": ino, "offset": off},
            "gen": 0,
        }));
    }
    Ok(serde_json::json!({
        "provider": provider_name,
        "trigger_observed": trigger_observed,
        "gen": 0,
        "rows": jrows,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_shape_and_hash_preimage() {
        let rows = vec![Row {
            op: 1,
            alg: "SHA256".into(),
            funcid: 7,
            addr: 0x1000,
        }];
        // Deferred mapping: no maps → unbacked, but shape + hash hold.
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let doc = emit("t", Path::new("t"), "", &exe, &[], &rows, true).unwrap();
        assert_eq!(doc["rows"].as_array().unwrap().len(), 1);
        let r = &doc["rows"][0];
        assert_eq!(r["addr_backed"], false);
        assert_eq!(r["addr_hash"], crate::kinds::addr_hash(0x1000));
        assert!(r.get("backing").unwrap().get("offset").is_some());
        assert_eq!(doc["trigger_observed"], true);
    }
}
