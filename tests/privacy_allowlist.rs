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

/// (harvest, count) sections from the doc's inventory block. The
/// sections are compared PER OBJECT: a union would let a new map
/// hide behind a same-named map in the other object (H1's harvest
/// `GEN` hid behind count's `GEN` — union count stayed 17 by
/// coincidence).
fn inventory_from_doc() -> (BTreeSet<String>, BTreeSet<String>) {
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut in_block = false;
    let mut harvest = BTreeSet::new();
    let mut count = BTreeSet::new();
    let mut section: Option<&mut BTreeSet<String>> = None;
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
        if t.is_empty() {
            continue;
        }
        if let Some(name) = t.strip_prefix("# ") {
            section = Some(match name {
                "harvest" => &mut harvest,
                "count" => &mut count,
                other => panic!("unknown inventory section: {other:?}"),
            });
            continue;
        }
        assert!(
            t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
            "inventory names are BPF map idents, found {t:?}"
        );
        section
            .as_mut()
            .expect("inventory entry before any section")
            .insert(t.to_string());
    }
    assert!(!harvest.is_empty(), "harvest inventory missing/empty");
    assert!(!count.is_empty(), "count inventory missing/empty");
    (harvest, count)
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
    let (doc_harvest, doc_count) = inventory_from_doc();
    let src_harvest = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/harvest.rs"));
    let src_count = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/count.rs"));
    assert_eq!(src_harvest.len(), 13, "unexpected harvest map count: {src_harvest:?}");
    assert_eq!(src_count.len(), 5, "unexpected count map count: {src_count:?}");
    assert_eq!(
        doc_harvest, src_harvest,
        "allowlist harvest inventory drifted from eBPF maps"
    );
    assert_eq!(
        doc_count, src_count,
        "allowlist count inventory drifted from eBPF maps"
    );
}

#[test]
fn no_raw_runtime_addresses_in_diagnostics() {
    // Allowlist §2 rule, source-pinned: no diagnostic may print a
    // raw runtime address, in any base. Named `arr`/`addr` format
    // args trip this, as does positional hex with an `arr`/`addr`
    // argument. Deliberately NOT flagged: file offsets
    // (`off`/`offset`, incl. ELF `vaddr`/symbol values and BPF
    // section offsets — static locators, not ASLR-slid addresses)
    // and `#[cfg(test)]` modules (which assert redaction).
    // (M3: H1's generation diagnostics printed `{arr:#x}` — the
    // first raw vaddrs on stderr. They now identify tables by op.)
    fn is_addr_print(line: &str) -> bool {
        // Named form, any base: `{arr}`, `{addr:#x}`, `{arr:?}`,
        // `{addr.len}`... The continuation check keeps `{array…}`
        // idents from tripping it.
        for name in ["{arr", "{addr"] {
            let mut rest = line;
            while let Some(i) = rest.find(name) {
                let after = rest[i + name.len()..].chars().next();
                if matches!(after, Some('}') | Some(':') | Some('?') | Some('.')) {
                    return true;
                }
                rest = &rest[i + name.len()..];
            }
        }
        // Positional form: `... {:x} ...", arr)`. Token-boundary
        // match so `address_taken`-style idents do not trip it.
        if !line.contains(":x}") {
            return false;
        }
        line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|t| t == "arr" || t == "addr")
    }
    fn visit(path: &std::path::Path, hits: &mut Vec<String>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), hits);
            }
            return;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            return;
        }
        let text = fs::read_to_string(path).unwrap();
        let mut depth: i32 = 0;
        let mut cfg_test_armed = false;
        let mut test_mod_depth: Option<i32> = None;
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t == "#[cfg(test)]" {
                cfg_test_armed = true;
            } else if cfg_test_armed && t.starts_with("mod ") {
                test_mod_depth = Some(depth);
                cfg_test_armed = false;
            }
            depth += line.bytes().filter(|b| *b == b'{').count() as i32;
            depth -= line.bytes().filter(|b| *b == b'}').count() as i32;
            if let Some(d) = test_mod_depth {
                if depth <= d {
                    test_mod_depth = None;
                } else {
                    continue;
                }
            }
            if t.starts_with("//") {
                continue;
            }
            if is_addr_print(t) {
                hits.push(format!("{}:{}: {t}", path.display(), n + 1));
            }
        }
    }
    let mut hits = Vec::new();
    visit(&manifest_dir().join("src"), &mut hits);
    assert!(
        hits.is_empty(),
        "raw runtime address in diagnostics (allowlist §2): {hits:?}"
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
    assert_eq!(total, 11, "expected 11 probe-read sites, found {total}");
    assert_eq!(str_reads, 2, "expected 2 string reads, found {str_reads}");
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
