//! etc/build-id-table.json shape pins (entry 11 = v0.2 profile B
//! /opt source build, enrolled from live receipts).

use std::collections::HashSet;

fn table() -> serde_json::Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/etc/build-id-table.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn build_id_table_has_eleven_entries() {
    let t = table();
    assert_eq!(t["table_version"], 1);
    let entries = t["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 11, "entry 11 (v0.2 profile B) missing");
    let mut ids = HashSet::new();
    for e in entries {
        let id = e["build_id"].as_str().unwrap();
        assert!((16..=128).contains(&id.len()) && id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ids.insert(id.to_string()), "duplicate build-id {id}");
        assert!(!e["openssl"].as_str().unwrap().is_empty());
        assert!(e["query_offset"].as_u64().unwrap() > 0);
        assert!(e["anchor_offset"].as_u64().unwrap() > 0);
    }
    let last = entries.last().unwrap();
    assert_eq!(last["anchor"].as_str().unwrap(), "OSSL_PROVIDER_available");
    let q = last["query_offset"].as_u64().unwrap();
    let a = last["anchor_offset"].as_u64().unwrap();
    assert!(a < q && q - a < 100000, "entry 11 offsets implausible");
}
