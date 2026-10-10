//! SPDX-License-Identifier: GPL-3.0-or-later
//! Privacy allowlist pins: the checked-in BPF map inventory and the
//! complete target-memory read list must match the sources. Any drift
//! is a release blocker, not a doc nit.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn inventory_from_doc() -> BTreeSet<String> {
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut in_block = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("```") {
            if !in_block && t.contains("map-inventory") {
                in_block = true;
                continue;
            }
            if in_block {
                break;
            }
            continue;
        }
        if !in_block {
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        assert!(
            t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
            "inventory names are BPF map idents, found {t:?}"
        );
        out.insert(t.to_string());
    }
    assert!(!out.is_empty(), "map-inventory block missing/empty");
    out
}

fn maps_from_source(path: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(path).unwrap();
    let mut out = BTreeSet::new();
    let mut armed = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "#[map]" {
            armed = true;
            continue;
        }
        if !armed {
            continue;
        }
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        let Some(rest) = t.strip_prefix("static ") else {
            armed = false;
            continue;
        };
        let name: String = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .map(|b| b as char)
            .collect();
        assert!(!name.is_empty(), "unparseable map line: {t:?}");
        out.insert(name);
        armed = false;
    }
    out
}

#[test]
fn map_inventory_matches_sources() {
    let expected = inventory_from_doc();
    let mut actual = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/harvest.rs"));
    actual.extend(maps_from_source(
        &manifest_dir().join("crates/ebpf/src/bin/count.rs"),
    ));
    assert_eq!(actual.len(), 17, "unexpected map count: {actual:?}");
    assert_eq!(
        expected, actual,
        "allowlist inventory drifted from eBPF maps"
    );
}

#[test]
fn probe_read_allowlist_is_complete() {
    let harvest =
        fs::read_to_string(manifest_dir().join("crates/ebpf/src/bin/harvest.rs")).unwrap();
    let count = fs::read_to_string(manifest_dir().join("crates/ebpf/src/bin/count.rs")).unwrap();
    assert!(
        !count.contains("bpf_probe_read_user"),
        "count program must read no target memory"
    );
    let total = harvest.match_indices("bpf_probe_read_user").count();
    let str_reads = harvest
        .match_indices("bpf_probe_read_user_str_bytes")
        .count();
    assert_eq!(total, 21, "expected 21 probe-read sites, found {total}");
    assert_eq!(str_reads, 5, "expected 5 string reads, found {str_reads}");
    assert!(harvest.contains("[0u8; 32]"), "trip string bound missing");
    assert!(
        harvest.contains("[0u8; 128]"),
        "alg-name string bound missing"
    );
}

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn userspace_target_memory_reads_are_pinned() {
    let root = manifest_dir();
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    for member in [
        "ossl-discover",
        "manifest",
        "ebpf-common",
        "bpf-sys",
        "ebpf",
    ] {
        let dir = root.join("crates").join(member).join("src");
        if dir.is_dir() {
            rust_sources(&dir, &mut files);
        }
    }
    let mut readers = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path).unwrap();
        assert!(
            !text.contains("process_vm_writev"),
            "{}: target-memory writes forbidden",
            path.display()
        );
        assert!(
            !text.contains("PTRACE_PEEK") && !text.contains("pidfd_getfd"),
            "{}: exotic target-memory reads forbidden",
            path.display()
        );
        if text.contains("process_vm_readv(") {
            readers.push(path.clone());
        }
    }
    assert_eq!(
        readers.len(),
        1,
        "exactly one userspace target-memory read site, found {readers:?}"
    );
    // T06 moved the single `pretouch_mappings` site from
    // `harvest.rs` to `session.rs` with the live environment; the
    // count stays exactly one and the documented behavior (fault
    // pages in, sink the bytes) is unchanged.
    assert!(
        readers[0].ends_with("src/discovery/session.rs"),
        "unexpected read site: {}",
        readers[0].display()
    );
}
