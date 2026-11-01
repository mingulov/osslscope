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
fn inventory_from_doc() -> [BTreeSet<String>; 5] {
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut in_block = false;
    let mut harvest = BTreeSet::new();
    let mut count = BTreeSet::new();
    let mut members = BTreeSet::new();
    let mut observation = BTreeSet::new();
    let mut focused = BTreeSet::new();
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
                "members" => &mut members,
                "provider_observation" => &mut observation,
                "focused_count" => &mut focused,
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
    assert!(!members.is_empty(), "members inventory missing/empty");
    [harvest, count, members, observation, focused]
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
    let [
        doc_harvest,
        doc_count,
        doc_members,
        doc_observation,
        doc_focused,
    ] = inventory_from_doc();
    assert_eq!(
        doc_observation,
        maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/provider_observation.rs"))
    );
    assert_eq!(
        doc_focused,
        maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/focused_count.rs"))
    );
    let src_harvest = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/harvest.rs"));
    let src_count = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/count.rs"));
    let src_members = maps_from_source(&manifest_dir().join("crates/ebpf/src/bin/members.rs"));
    assert_eq!(
        src_harvest.len(),
        14,
        "unexpected harvest map count: {src_harvest:?}"
    );
    // Task 5 adds LATC (c8 log2-ns callback-latency histogram) — end
    // state 7.
    assert_eq!(
        src_count.len(),
        7,
        "unexpected count map count: {src_count:?}"
    );
    // Stage D dropped PENDING (members read SCAN — R18 §6.1);
    // item 5 re-added BUCKET (tier-1 per-tid rate state), and
    // round 3 adds per-op TRUNC_SEQ (flag-event generation for
    // repeat re-report) — end state 15.
    assert_eq!(
        src_members.len(),
        15,
        "unexpected members map count: {src_members:?}"
    );
    assert!(
        !src_members.contains("PENDING_QUERY"),
        "PENDING dropped in D: {src_members:?}"
    );
    assert_eq!(
        doc_harvest, src_harvest,
        "allowlist harvest inventory drifted from eBPF maps"
    );
    assert_eq!(
        doc_count, src_count,
        "allowlist count inventory drifted from eBPF maps"
    );
    assert_eq!(
        doc_members, src_members,
        "allowlist members inventory drifted from eBPF maps"
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
    let members =
        fs::read_to_string(manifest_dir().join("crates/ebpf/src/bin/members.rs")).unwrap();
    assert!(
        !count.contains("bpf_probe_read_user"),
        "count program must read no target memory"
    );
    let focused =
        fs::read_to_string(manifest_dir().join("crates/ebpf/src/bin/focused_count.rs")).unwrap();
    assert!(
        !focused.contains("bpf_probe_read_user"),
        "static candidates must remain entry-only"
    );
    let observation =
        fs::read_to_string(manifest_dir().join("crates/ebpf/src/bin/provider_observation.rs"))
            .unwrap();
    assert_eq!(observation.match_indices("bpf_probe_read_user").count(), 10);
    assert_eq!(
        observation
            .match_indices("bpf_probe_read_user_str_bytes")
            .count(),
        2
    );
    let total = harvest.match_indices("bpf_probe_read_user").count();
    let str_reads = harvest
        .match_indices("bpf_probe_read_user_str_bytes")
        .count();
    assert_eq!(total, 21, "expected 21 probe-read sites, found {total}");
    assert_eq!(str_reads, 4, "expected 4 string reads, found {str_reads}");
    assert!(harvest.contains("[0u8; 32]"), "trip string bound missing");
    assert!(
        harvest.contains("[0u8; 128]"),
        "alg-name string bound missing"
    );
    // Members (stage D + round-2): 9 source sites (walk_dispatch
    // 2 + member slot tuple 2 + member-0 no_store pointee 1 +
    // would-skip no_store pointee 1 + T+1 boundary names 1 +
    // guard tail 1 + name string 1), 1 string read. The D
    // additions are the T-gate's local eligibility read
    // (would-skip path — a u32 verdict, never retained past the
    // branch) and the guard's single positional slot-512 read
    // (names-present verdict → GUARD event only). The round-2
    // addition is the T+1 boundary proof (u64 names read — zero
    // proves the terminator via an explicit ALG_EMPTY, anything
    // else cold-walks; the value is never retained past the
    // branch). The ENTRY plane (entry + skip-path helpers through
    // `def_member`) reads NO target memory — args and map cells
    // only (R18 §3: the entry cannot see rv).
    let m_total = members.match_indices("bpf_probe_read_user").count();
    let m_str = members
        .match_indices("bpf_probe_read_user_str_bytes")
        .count();
    assert_eq!(m_total, 9, "expected 9 member read sites, found {m_total}");
    assert_eq!(m_str, 1, "expected 1 member string read, found {m_str}");
    // Entry plane = `bump_attempt` (first entry helper) through
    // the member macro (exclusive): entry + skip-path helpers, all
    // of which must read no target memory (walk_dispatch lives
    // BEFORE this slice and keeps its 2 reads).
    let plane_start = members.find("fn bump_attempt").expect("entry plane start");
    let member_start = members
        .find("macro_rules! def_member")
        .expect("def_member present");
    assert!(
        members[plane_start..].contains("pub fn member_entry"),
        "entry inside the plane slice"
    );
    assert!(
        !members[plane_start..member_start].contains("bpf_probe_read_user"),
        "entry plane must read no target memory"
    );
    assert!(
        members.contains("[0u8; 128]"),
        "member alg-name string bound missing"
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

// These source pins are review boundaries, not a general static analyzer. Every
// new read, alias or changed owner/caller requires a fresh privacy review.
// Literals are atomic tokens: comments and raw strings cannot impersonate code.
fn privacy_tokens(source: &str) -> Result<Vec<String>, String> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while i < b.len() && depth > 0 {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth != 0 {
                return Err("unclosed comment".into());
            }
            continue;
        }
        let start = i;
        // Raw strings, including byte/C prefixes. Preserve the literal as one
        // token, including hashes and its contents; never extract code from it.
        let raw = if b[i..].starts_with(b"br") || b[i..].starts_with(b"cr") {
            Some(i + 2)
        } else if b[i] == b'r' {
            Some(i + 1)
        } else {
            None
        };
        if let Some(mut quote) = raw {
            let hashes_start = quote;
            while quote < b.len() && b[quote] == b'#' {
                quote += 1;
            }
            if quote < b.len() && b[quote] == b'"' {
                let hashes = quote - hashes_start;
                i = quote + 1;
                loop {
                    if i >= b.len() {
                        return Err("unclosed raw string".into());
                    }
                    if b[i] == b'"'
                        && b.get(i + 1..i + 1 + hashes)
                            .is_some_and(|s| s.iter().all(|x| *x == b'#'))
                    {
                        i += 1 + hashes;
                        break;
                    }
                    i += 1;
                }
                out.push(source[start..i].to_string());
                continue;
            }
        }
        // Raw identifiers denote the same capability/method as ordinary
        // identifiers. Raw strings have already been consumed above.
        if b[i..].starts_with(b"r#")
            && b.get(i + 2)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        {
            i += 2;
            let identifier = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(source[identifier..i].to_string());
            continue;
        }
        if b[i] == b'"' {
            i += 1;
            loop {
                if i >= b.len() {
                    return Err("unclosed string".into());
                }
                if b[i] == b'"' {
                    i += 1;
                    break;
                }
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
        } else if b[i] == b'\'' && b.get(i + 1) == Some(&b'\\') {
            i += 2;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            if i == b.len() {
                return Err("unclosed character".into());
            }
            i += 1;
        } else if b[i] == b'\''
            && source[i + 1..]
                .chars()
                .next()
                .is_some_and(|c| b.get(i + 1 + c.len_utf8()) == Some(&b'\''))
        {
            i += 2 + source[i + 1..].chars().next().unwrap().len_utf8();
        } else if b[i].is_ascii_alphanumeric() || b[i] == b'_' {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
        } else {
            i += source[i..].chars().next().unwrap().len_utf8();
        }
        out.push(source[start..i].to_string());
    }
    Ok(out)
}

fn reviewed_region_range(
    tokens: &[String],
    marker: &str,
) -> Result<std::ops::Range<usize>, String> {
    let needle = privacy_tokens(marker)?;
    let starts: Vec<_> = tokens
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, w)| (w == needle).then_some(i))
        .collect();
    if starts.len() != 1 {
        return Err(format!("ambiguous/missing owner: {marker}"));
    }
    let start = starts[0];
    if marker.starts_with("const ") || marker.contains("mod source_anchor") {
        let end = (start..tokens.len())
            .find(|i| tokens[*i] == ";")
            .ok_or_else(|| format!("unterminated constant: {marker}"))?;
        return Ok(start..end + 1);
    }
    let open = (start..tokens.len())
        .find(|i| tokens[*i] == "{")
        .ok_or_else(|| format!("missing body: {marker}"))?;
    let mut depth = 0;
    for i in open..tokens.len() {
        if tokens[i] == "{" {
            depth += 1;
        }
        if tokens[i] == "}" {
            depth -= 1;
        }
        if depth == 0 {
            return Ok(start..i + 1);
        }
    }
    Err(format!("unclosed body: {marker}"))
}

fn reviewed_region(tokens: &[String], marker: &str) -> Result<Vec<String>, String> {
    Ok(tokens[reviewed_region_range(tokens, marker)?].to_vec())
}

// Frozen SHA256 of token sequences reviewed with their caller provenance.
// Deliberately literal, never derived from the source being checked at runtime.
// Backing fault has a caller-derived within-page index, not a local bounds
// guard. Its two one-byte copies are finite but not separately read-charged.
const SELF_READ_PINS: &[(&str, &str, &str)] = &[
    (
        "src/inventory/backing.rs",
        "struct SelfMap",
        "67d0184be0bb4266a25b5f84a963cc51eb4038671202a3ae7e5795b8d717e47e",
    ),
    (
        "src/inventory/backing.rs",
        "impl SelfMap",
        "0232b59cbdb68ac025c565559890e42ecca0125a94b93eb098ad5d4ea78c1691",
    ),
    (
        "src/inventory/backing.rs",
        "impl Drop for SelfMap",
        "cd691481f1c3696f92eb7f9fa0f39c731e12e6b838d61771bd001045c3797e11",
    ),
    (
        "src/inventory/backing.rs",
        "fn page_size",
        "f2aac211ff7ae948c50aa39714b9e762cd7809e2a7bf2546691d9f636d19bf1e",
    ),
    (
        "src/inventory/backing.rs",
        "fn candidate_identity",
        "b09c2d188e4eaa927868effe342ee960cecc9cd93e0ac1c7c4beb24b784efe53",
    ),
    (
        "src/inventory/backing.rs",
        "fn verify_witness",
        "e4b4015aa4af6ee0f1153875c98f14552d3ba0edca83bc481f08b4c87ec25a71",
    ),
    (
        "src/inventory/backing.rs",
        "fn verify_with_process_charged",
        "eb47758cbfe8813705bc88585c6116231adea71abd1c940ab9516e5b5eb2dd67",
    ),
    (
        "src/inventory/backing.rs",
        "fn revalidate_charged",
        "a300636e003120b1c78cac817eb06c330396dcbd6b9c61fab1109e4f4a330c34",
    ),
    (
        "src/inventory/backing.rs",
        "fn open_at",
        "db9ab11c9f88b7eb0af15d66feaed3cc16413d9827e97fd019223b72635096e2",
    ),
    (
        "src/inventory/backing.rs",
        "fn open_layer_candidate",
        "442d07747272a31fb88c6b6f939c27e3c6d70afd21e990e84645bcd1c2348c91",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "const HASH_CHUNK",
        "d5851480744c8b8ccb43555d7b90ad1bdc9ac1c9b470c57df7b18e8bba990b98",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "struct SourceAnchor",
        "24bbedb6c43ff9de54fc0a2cba0d2f5672b21bb439af499878bfc60d9e239384",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "impl SourceAnchor",
        "27b0353d8345d13ea8db8bffd18075a647149b2ad4a0f6ff7c4d4d04d7bfdcd2",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "impl Drop for SourceAnchor",
        "1feba8863aa1365fec54e010bac1af4fc1409d31c34f814a7ed705dc532f32eb",
    ),
    (
        "src/provider_observation/objects.rs",
        "const MAX_OBJECT",
        "eda1bf857f603f80c7c7616414be9fe6baae93f5fceb58e9af8a04e6171d708f",
    ),
    (
        "src/provider_observation/objects.rs",
        "fn anchor ( & self , budget",
        "fba73afbb672c74948d45d119b3a7a2cccb380175dd76856178f0b29fe8b613d",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "fn anchor_source",
        "1adf2a02cde1be073ac627ef78b9ef10d9a7562694bb6f66223e228b8529d652",
    ),
];

// Additional existing reference locations, including the import that grants
// capture authority and test callers. These do not grant whole-file permission:
// every protected reference must occur inside a uniquely extracted pinned region.
const SELF_REFERENCE_PINS: &[(&str, &str, &str)] = &[
    (
        "src/inventory/backing.rs",
        "unsafe impl Send for SelfMap",
        "820c0a9fc79f208d1494c8894de0486cb9a5a311b64130b8cc5e0a46b424336c",
    ),
    (
        "src/inventory/backing.rs",
        "fn check_self_map",
        "45485a41f0dcb642b700afee152c0ffa7e3c821861cc8232668d099ba027d40f",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "fn mapped_anchor_hashes_its_own_backing_and_faults_return_errors",
        "df1adb92429ac640791774cebce37dfebd47dd8e8d583e0f35d0933f2d512286",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "fn anchor_reuse_proof_requires_same_backing_stamp_and_hash",
        "a6e63a14ce9ff9dcc66e20e77393947f92688ef1b90fdbf69a0a863411f83fbf",
    ),
    (
        "src/provider_observation/source_anchor.rs",
        "fn anchor_refuses_wrong_artifact_and_capacity_before_mapping",
        "fb0d974989bfb8205f0b097a54ca3d815bc6fe4f6f7decab42848171639417c7",
    ),
    (
        "src/provider_observation/objects.rs",
        "#[path = \"source_anchor.rs\"] pub(super) mod source_anchor",
        "e42882bdf5b0a88b507f7c9c0b7232c7a7db08f1011b788b94ed0d5d8c1bb802",
    ),
    (
        "src/provider_observation/objects.rs",
        "struct Object {",
        "5afc37bf403c2599aaee85f36dbe884a182e503e93edfedfadf379ad9071de33",
    ),
    (
        "src/provider_observation/objects.rs",
        "struct TypedPublicSite",
        "4e1a822fee9a3667da9c42dc8235557d19ca900049d1276746dc612bf999ed43",
    ),
    (
        "src/provider_observation/objects.rs",
        "fn anchor ( & self )",
        "f0cd0a6576bd7eb510ab6757f758ea480a9b26fd9ddc0613e1f9cfa97f7bd2c5",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "use super :: {",
        "bb4bd45bc90a92a9f89e181792e5886585ffdcc54feb6c14a2c9ae24096397c9",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "struct SourceOwner",
        "e92ea7f40fd68ad1ef12782f4264da2c4aea681ef9e6c567a92d8b691bdc8cc6",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "fn anchor_rc_test",
        "dd1a874db1971d4a8d0e21828dff4bcbfd73ff503307b3ce8986c856ae487788",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "fn anchor_source_reuses_verified_candidate_without_recapture",
        "fb5e32f9bb5ed74792a709e21344ae2a043b55d938f29a3ae6123c6dca5ea836",
    ),
    (
        "src/provider_observation/source_owner.rs",
        "fn anchor_source_recaptures_when_candidate_mismatches",
        "5c26c7fa21d91ee051f84a72cd09b2c7b914f3848a84f593729e311bfa5bdb8f",
    ),
];

fn self_read_policy(files: &[(String, String)]) -> Result<(), String> {
    use sha2::Digest;
    let mut census = Vec::new();
    for (path, source) in files {
        for forbidden in ["process_vm_writev", "PTRACE_PEEK", "pidfd_getfd"] {
            if source.contains(forbidden) {
                return Err(format!("{path}: forbidden {forbidden}"));
            }
        }
        let tokens = privacy_tokens(source)?;
        let regions: Vec<_> = SELF_READ_PINS
            .iter()
            .chain(SELF_REFERENCE_PINS)
            .filter(|(owner, _, _)| *owner == path)
            .map(|(_, marker, _)| reviewed_region_range(&tokens, marker))
            .collect::<Result<_, _>>()?;
        for (i, token) in tokens.iter().enumerate() {
            let protected = matches!(token.as_str(), "SelfMap" | "SourceAnchor" | "source_anchor")
                || match path.as_str() {
                    "src/inventory/backing.rs" => {
                        matches!(token.as_str(), "fault" | "verify_witness")
                    }
                    "src/provider_observation/source_anchor.rs" => {
                        matches!(token.as_str(), "capture" | "digest")
                    }
                    "src/provider_observation/objects.rs"
                    | "src/provider_observation/source_owner.rs" => token == "capture",
                    _ => false,
                };
            // This covers imports, aliases, type mentions and function items;
            // no following '(' is required. Aggregate counts cannot authorize
            // moving a reference into a new caller or adding an aliased import.
            if protected && !regions.iter().any(|range| range.contains(&i)) {
                return Err(format!(
                    "{path}: {token} outside reviewed reference locations"
                ));
            }
        }
        for (i, token) in tokens.iter().enumerate() {
            // All identifier uses count, including alias/import declarations.
            if token == "process_vm_readv" {
                let direct = i >= 3
                    && tokens[i - 3..i] == ["libc", ":", ":"]
                    && tokens.get(i + 1).is_some_and(|s| s == "(");
                if !direct {
                    return Err(format!("{path}: unreviewed read alias"));
                }
                census.push(path.as_str());
            }
        }
    }
    census.sort_unstable();
    if census
        != [
            "src/inventory/backing.rs",
            "src/provider_observation/source_anchor.rs",
        ]
    {
        return Err(format!(
            "exactly two reviewed self-read occurrences required: {census:?}"
        ));
    }
    for &(path, marker, expected) in SELF_READ_PINS.iter().chain(SELF_REFERENCE_PINS) {
        let sources: Vec<_> = files.iter().filter(|(p, _)| p == path).collect();
        if sources.len() != 1 {
            return Err(format!("ambiguous/missing source: {path}"));
        }
        let region = reviewed_region(&privacy_tokens(&sources[0].1)?, marker)?;
        let actual = sha2::Sha256::digest(region.join("\n"))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if actual != expected {
            return Err(format!("{path}: reviewed boundary changed: {marker}"));
        }
    }
    Ok(())
}

fn privacy_sources() -> Vec<(String, String)> {
    let root = manifest_dir();
    let mut paths = Vec::new();
    rust_sources(&root.join("src"), &mut paths);
    for member in [
        "ossl-discover",
        "manifest",
        "ebpf-common",
        "bpf-sys",
        "ebpf",
    ] {
        let dir = root.join("crates").join(member).join("src");
        if dir.is_dir() {
            rust_sources(&dir, &mut paths);
        }
    }
    paths
        .into_iter()
        .map(|p| {
            (
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                fs::read_to_string(p).unwrap(),
            )
        })
        .collect()
}

#[test]
fn userspace_target_memory_reads_are_pinned() {
    self_read_policy(&privacy_sources()).unwrap();
}

#[test]
fn discovery_never_reads_target_environment_or_requests_pretouch() {
    let text = fs::read_to_string(manifest_dir().join("src/discovery/session.rs")).unwrap();
    let tokens = privacy_tokens(&text).unwrap();
    assert!(
        !tokens.iter().any(|s| s.contains("/environ")),
        "target environ discovery is forbidden"
    );
    assert!(
        !tokens
            .iter()
            .any(|s| s == "pretouch" || s == "pretouch_mappings"),
        "foreign pretouch capability must be removed"
    );
    let helper = reviewed_region(&tokens, "fn legacy_candidates").unwrap();
    // Independently authored permitted dependency set: no target PID, ambient
    // environment lookup, alternate helper or directory traversal can enter.
    let expected = privacy_tokens(
        r#"
        fn legacy_candidates(libcrypto: &str) -> Vec<PathBuf> {
            let mut out: Vec<PathBuf> = Vec::new();
            let mut consider = |p: PathBuf| {
                if p.is_file() && !out.contains(&p) { out.push(p); }
            };
            if let Some(dir) = Path::new(libcrypto).parent() {
                consider(dir.join("ossl-modules").join("legacy.so"));
            }
            out
        }
    "#,
    )
    .unwrap();
    assert_eq!(
        helper, expected,
        "candidate helper has unreviewed dependencies"
    );
    assert!(
        !helper
            .iter()
            .any(|s| s == "env" || s == "var" || s == "var_os" || s.contains("OPENSSL_MODULES")),
        "candidate discovery must not consult process environment"
    );
}

fn reviewed_self_sources() -> Vec<(String, String)> {
    [
        "src/inventory/backing.rs",
        "src/provider_observation/source_anchor.rs",
        "src/provider_observation/objects.rs",
        "src/provider_observation/source_owner.rs",
    ]
    .into_iter()
    .map(|p| {
        (
            p.into(),
            fs::read_to_string(manifest_dir().join(p)).unwrap(),
        )
    })
    .collect()
}

#[test]
fn self_read_policy_rejects_provenance_bounds_lifetime_and_output_mutations() {
    let clean = reviewed_self_sources();
    self_read_policy(&clean).expect("independently pinned reviewed owners");
    // Each stimulus changes one approved boundary; expected refusal is authored
    // here, never computed by a second copy of the production read operation.
    let cases = [
        (0, "foreign PID", "libc::getpid()", "12345"),
        (
            0,
            "foreign pointer",
            "(self.address as *mut u8).add(index)",
            "(target_address as *mut u8).add(index)",
        ),
        (
            0,
            "arbitrary self pointer",
            "(self.address as *mut u8).add(index)",
            "local_buffer.as_mut_ptr()",
        ),
        (0, "shared map", "libc::MAP_PRIVATE", "libc::MAP_SHARED"),
        (0, "writable map", "libc::PROT_READ", "libc::PROT_WRITE"),
        (0, "executable map", "libc::PROT_READ", "libc::PROT_EXEC"),
        (
            0,
            "missing regular file check",
            "if !metadata.is_file()",
            "if false",
        ),
        (
            0,
            "unretained mapping source",
            "candidate.as_raw_fd(),\n                offset",
            "foreign_fd,\n                offset",
        ),
        (
            0,
            "offset bound",
            "file_offset >= candidate_fp.size",
            "false",
        ),
        (
            0,
            "within-page bound",
            "file_offset - aligned",
            "file_offset",
        ),
        (0, "larger fault", "iov_len: 1,", "iov_len: 2,"),
        (0, "short copy accepted", "if copied == 1", "if copied >= 0"),
        (
            0,
            "capacity reduced",
            "page_bytes.checked_mul(2)",
            "page_bytes.checked_mul(0)",
        ),
        (
            0,
            "checkpoint removed",
            "budget.checkpoint()?;\n        let page = page_size()?;",
            "let page = page_size()?;",
        ),
        (
            0,
            "fault byte output",
            "if copied == 1",
            "eprintln!(\"{}\", byte); if copied == 1",
        ),
        (
            0,
            "mapping cleanup removed",
            "libc::munmap(self.address, self.length);",
            "",
        ),
        (1, "anchor foreign PID", "libc::getpid()", "12345"),
        (
            1,
            "anchor pointer",
            "self.address.as_ptr() as usize",
            "target_address as usize",
        ),
        (
            1,
            "anchor shared map",
            "libc::MAP_PRIVATE",
            "libc::MAP_SHARED",
        ),
        (
            1,
            "anchor writable map",
            "libc::PROT_READ",
            "libc::PROT_WRITE",
        ),
        (
            1,
            "anchor executable map",
            "libc::PROT_READ",
            "libc::PROT_EXEC",
        ),
        (1, "anchor regular file", "!metadata.is_file()", "false"),
        (
            1,
            "anchor remaining bound",
            "HASH_CHUNK.min(self.length - offset)",
            "HASH_CHUNK",
        ),
        (
            1,
            "anchor overflow bound",
            ".checked_add(offset)",
            ".checked_add(0)",
        ),
        (1, "anchor chunk enlarged", "16 << 10", "32 << 10"),
        (
            1,
            "anchor state reservation",
            "budget.reserve_state(capacity)?",
            "budget.reserve_state(0)?",
        ),
        (
            1,
            "anchor scratch reservation",
            "budget.reserve_state(HASH_CHUNK)?",
            "budget.reserve_state(0)?",
        ),
        (
            1,
            "anchor read charge",
            "budget.read(self.length as u64)?;",
            "",
        ),
        (
            1,
            "anchor checkpoint",
            "while offset < self.length {\n            budget.checkpoint()?;",
            "while offset < self.length {",
        ),
        (
            1,
            "anchor short read",
            "if copied != length as isize",
            "if copied < 0",
        ),
        (
            1,
            "anchor bytes output",
            "hash.update(&bytes[..length]);",
            "eprintln!(\"{:?}\", bytes); hash.update(&bytes[..length]);",
        ),
        (
            1,
            "anchor hash acceptance",
            "if &anchor.digest(budget, &scratch)? != expected",
            "if false",
        ),
        (
            1,
            "anchor retained fd",
            "_file: owned,",
            "_file: other_file,",
        ),
        (
            1,
            "anchor cleanup",
            "libc::munmap(self.address.as_ptr(), self.length);",
            "",
        ),
        (
            1,
            "anchor reuse stamp",
            "Stamp::of(&current) == self.stamp",
            "true",
        ),
        (2, "object length cap", "134_217_728", "268_435_456"),
        (2, "admission unchanged check", "self.unchanged()?;", ""),
        (
            3,
            "reuse proof",
            "shared.verifies_against(&scope.target, &scope.expected_artifact)",
            "true",
        ),
        (
            3,
            "admitted artifact",
            "&scope.expected_artifact,\n                budget",
            "&other_artifact,\n                budget",
        ),
    ];
    for (index, label, from, to) in cases {
        let mut changed = clean.clone();
        assert!(changed[index].1.contains(from), "fixture missing {label}");
        changed[index].1 = changed[index].1.replacen(from, to, 1);
        assert!(self_read_policy(&changed).is_err(), "accepted {label}");
    }
    assert_eq!(cases.len(), 39);
}

#[test]
fn self_read_census_rejects_duplicates_aliases_and_literal_camouflage() {
    let clean = reviewed_self_sources();
    self_read_policy(&clean).unwrap();
    for extra in [
        "fn extra() { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0); }",
        "use libc::process_vm_readv as read_memory; fn extra() { read_memory(42, p); }",
        "fn extra() { libc :: process_vm_readv \n (42, p); }",
    ] {
        for index in [0, 1] {
            let mut changed = clean.clone();
            changed[index].1.push_str(extra);
            assert!(
                self_read_policy(&changed).is_err(),
                "extra call/alias in allowed owner"
            );
        }
        let mut changed = clean.clone();
        changed.push(("src/extra.rs".into(), extra.into()));
        assert!(self_read_policy(&changed).is_err(), "extra file");
    }
    // Literal/comment mentions neither add calls nor impersonate reviewed
    // definitions. The clean owners are still required for this positive.
    let mut mentions = clean.clone();
    mentions[0].1.push_str("\n/* outer /* libc::process_vm_readv() */ comment */\nconst TEXT: &str = r###\"libc::process_vm_readv() { impl SelfMap {} }\"###;\n");
    self_read_policy(&mentions).unwrap();
    for wrap in [0, 1] {
        let mut changed = clean.clone();
        changed[0].1 = if wrap == 0 {
            format!("/* {} */", changed[0].1)
        } else {
            format!("const TEXT: &str = r########\"{}\"########;", changed[0].1)
        };
        assert!(
            self_read_policy(&changed).is_err(),
            "comment/raw string grants no permission"
        );
    }
    for alias in ["read_memory", "process_vm_ readv"] {
        let mut changed = clean.clone();
        changed[0].1 = changed[0].1.replace("process_vm_readv", alias);
        assert!(
            self_read_policy(&changed).is_err(),
            "renamed/split read must fail closed"
        );
    }
    for (index, extra) in [
        (0, "fn extra(mapping: &SelfMap) { mapping.fault(4096); }"),
        (0, "fn extra(mapping: &impl Trait) { mapping.fault(4096); }"),
        (
            1,
            "fn extra(anchor: &impl Trait) { anchor.digest(budget, scratch); }",
        ),
        (
            3,
            "fn extra() { SourceAnchor::capture(file, expected, budget); }",
        ),
    ] {
        let mut changed = clean.clone();
        changed[index].1.push_str(extra);
        assert!(self_read_policy(&changed).is_err(), "unreviewed caller");
    }
    // Whitespace around punctuation is harmless when provenance is unchanged.
    let mut spaced = clean.clone();
    spaced[0].1 = spaced[0]
        .1
        .replace("libc::process_vm_readv(", "libc :: process_vm_readv \n (");
    self_read_policy(&spaced).unwrap();
}

#[test]
fn self_read_policy_rejects_aliased_capture_authority() {
    let clean = reviewed_self_sources();
    self_read_policy(&clean).unwrap();
    let import = "objects::source_anchor::SourceAnchor,";
    assert_eq!(clean[3].1.matches(import).count(), 1);
    let mut accepted = Vec::new();
    for (label, function) in [
        (
            "raw identifier call",
            "fn extra_read(file: &File, expected: &ObjectHash, budget: &ObservationBudget) { let _ = Alias::r#capture(file, expected, budget); }",
        ),
        (
            "function item",
            "fn extra_read(file: &File, expected: &ObjectHash, budget: &ObservationBudget) { let read = Alias::capture; let _ = read(file, expected, budget); }",
        ),
    ] {
        let mut changed = clean.clone();
        changed[3].1 = changed[3].1.replacen(
            import,
            "objects::source_anchor::{SourceAnchor as Alias, *},",
            1,
        );
        changed[3].1.push_str(function);
        let rejected = self_read_policy(&changed).is_err();
        eprintln!("aliased capture mutation {label}: rejected={rejected}");
        if !rejected {
            accepted.push(label);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted unreviewed capture authority: {accepted:?}"
    );
}

#[test]
fn self_read_references_are_location_bound_and_raw_identifiers_are_normalized() {
    let clean = reviewed_self_sources();
    // Equivalent raw spelling in existing reviewed callers remains valid. This
    // also proves r#capture is treated as a method identifier, not a raw string.
    let mut raw = clean.clone();
    raw[3].1 = raw[3]
        .1
        .replace("SourceAnchor::capture", "r#SourceAnchor::r#capture");
    self_read_policy(&raw).unwrap();
    assert_eq!(
        privacy_tokens("Alias::r#capture").unwrap(),
        privacy_tokens("Alias::capture").unwrap()
    );

    for (index, extra) in [
        (3, "fn extra() { let read = SourceAnchor::capture; }"),
        (3, "fn extra() { let read = SourceAnchor::r#capture; }"),
        (
            3,
            "use super::objects::source_anchor::*; fn extra() { let read = SourceAnchor::capture; }",
        ),
        (
            3,
            "use super::objects::r#source_anchor as renamed; fn extra() { let read = renamed::SourceAnchor::r#capture; }",
        ),
        (0, "fn extra() { let read = SelfMap::r#fault; }"),
    ] {
        let mut changed = clean.clone();
        changed[index].1.push_str(extra);
        let error = self_read_policy(&changed).unwrap_err();
        assert!(
            error.contains("outside reviewed reference locations"),
            "location guard did not reject {extra}: {error}"
        );
    }
    // Pin the actual import's entire syntax, not just a SourceAnchor token
    // count. An unrelated alias name must not receive permission either.
    let mut changed = clean.clone();
    changed[3].1 = changed[3].1.replacen(
        "objects::source_anchor::SourceAnchor,",
        "objects::source_anchor::{SourceAnchor as DifferentName, *},",
        1,
    );
    changed[3]
        .1
        .push_str("fn extra() { let read = DifferentName::r#capture; }");
    assert!(self_read_policy(&changed).is_err());
}

#[test]
fn traversal_inventory_is_approved() {
    // T2-2 (doc side): the allowlist's Optional `traversal`
    // bullet must enumerate exactly the approved emitted-field
    // inventory — the ten section keys. Emission-side agreement
    // (rendered keys ⊆ bullet idents) is pinned by
    // output_contract::traversal_emission_matches_allowlist_inventory;
    // this pins the doc baseline so neither side can silently
    // shrink or grow. Round 2, residual N: the check is exact
    // (an inclusion check lets extra backtick names pass both
    // agreement tests silently).
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut bullet = String::new();
    let mut in_bullet = false;
    for line in text.lines() {
        if line.starts_with("- Optional `traversal`") {
            in_bullet = true;
        } else if in_bullet && !line.starts_with(' ') && !line.is_empty() {
            break;
        }
        if in_bullet {
            bullet.push_str(line);
            bullet.push('\n');
        }
    }
    assert!(
        !bullet.is_empty(),
        "allowlist lacks the Optional `traversal` bullet"
    );
    let listed: BTreeSet<&str> = bullet
        .split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s)
        .collect();
    // The bullet's subject (`traversal`), the `objects`
    // cross-reference, plus exactly the ten section keys —
    // nothing else backticked.
    let approved: BTreeSet<&str> = [
        "traversal",
        "objects",
        "harvest",
        "count",
        "members",
        "records",
        "findings",
        "polls",
        "admitted",
        "admitted_unknown",
        "census_loss",
        "entries",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        listed, approved,
        "allowlist traversal bullet drifted from the approved inventory"
    );
}

/// Diagnostic-text trigger spellings (round 3, residual F):
/// every `AttachEvent.failed` construction — `failed: Some(..)`
/// literals, `failed: replan.then(..)` conditional
/// re-establishment, shorthand `failed` (value from a
/// `x.then(..)` binding, whose own line triggers too), and
/// `record_attach_failure` — opens a scanned window.
fn is_diagnostic_trigger(t: &str) -> bool {
    t.contains("failed: Some")
        || t.contains("record_attach_failure(&mut delta")
        || (t.contains("failed") && t.contains(".then("))
        || t.starts_with("failed,")
}

/// Round 3, residuals F+R (publication half of the composed
/// chain): the allowlist bullet carries the exact producer
/// literals for the two re-established-anchor texts (the
/// session suite pins the producers emit them; the
/// rendered-doc test pins they publish pathname-free).
#[test]
fn reestablished_anchor_texts_are_allowlisted() {
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut bullet = String::new();
    let mut in_bullet = false;
    for line in text.lines() {
        if line.starts_with("- Optional `attach_diagnostics`") {
            in_bullet = true;
        } else if in_bullet && !line.starts_with(' ') && !line.is_empty() {
            break;
        }
        if in_bullet {
            bullet.push_str(line);
            bullet.push('\n');
        }
    }
    assert!(
        !bullet.is_empty(),
        "allowlist lacks the Optional `attach_diagnostics` bullet"
    );
    let spans: Vec<String> = bullet
        .split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    for want in [
        "tripwire anchors re-established after replacement (identical mapping)",
        "dispatch anchors re-established after replacement; continuity unproven",
    ] {
        assert!(
            spans.iter().any(|s| s == want),
            "allowlist bullet must carry the producer literal {want:?}"
        );
    }
}

/// Round 3, residual F: the scanner covers every diagnostic
/// construction spelling — the `replan.then(..)` conditional
/// and the shorthand `failed` field included (both missed in
/// round 2, hiding two production texts from the inventory).
#[test]
fn diagnostic_scanner_covers_all_constructions() {
    assert!(is_diagnostic_trigger("failed: Some("));
    assert!(
        is_diagnostic_trigger("failed: replan.then(|| {"),
        "replan.then(..) conditional must open a window"
    );
    assert!(
        is_diagnostic_trigger("let failed = prior_mapped.then(|| {"),
        ".then(..) binding must open a window"
    );
    assert!(
        is_diagnostic_trigger("failed,"),
        "shorthand failed field must open a window"
    );
}

/// Round 2, residual F (source-pinned): no diagnostic-text
/// construction interpolates a path, cookie, or target string.
/// Every `AttachEvent.failed` / `record_attach_failure` text
/// window is scanned: literals stay literal, and the only
/// allowed interpolation is `{e:#}` of an already-approved error
/// (resolve/install/reinstall producers emit approved texts by
/// construction — pinned exactly in the session/harvest unit
/// suites). A pathname sneaking back into any producer fails
/// here. `#[cfg(test)]` modules are exempt (they assert the
/// vocabulary itself).
#[test]
fn no_paths_in_diagnostic_text_windows() {
    fn check(path: &Path) {
        let text = fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut in_test_mod = false;
        let mut depth: i32 = 0;
        let mut test_depth: Option<i32> = None;
        let mut cfg_test_armed = false;
        for (n, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t == "#[cfg(test)]" {
                cfg_test_armed = true;
            } else if cfg_test_armed && t.starts_with("mod ") {
                test_depth = Some(depth);
                cfg_test_armed = false;
            }
            depth += line.bytes().filter(|b| *b == b'{').count() as i32;
            depth -= line.bytes().filter(|b| *b == b'}').count() as i32;
            if let Some(d) = test_depth {
                in_test_mod = depth > d;
                if !in_test_mod {
                    test_depth = None;
                }
            }
            if in_test_mod {
                continue;
            }
            if !is_diagnostic_trigger(t) {
                continue;
            }
            // Code part only (`//` comments are not emitted text —
            // split before scanning so comment slashes cannot trip
            // the pathname check; no window line holds `//` inside
            // a string literal).
            let window: String = lines[n..lines.len().min(n + 7)]
                .iter()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            for banned in [
                ".display()",
                "{cookie",
                "{path",
                "{prov",
                "{lc_",
                "cookie {",
                "{e}",
                "path.display",
                // A literal pathname reads as `/...` in the text
                // (the approved vocabulary's only `/`-free
                // exception is none — even the pin-dup pair
                // separator is `+`).
                "/",
            ] {
                assert!(
                    !window.contains(banned),
                    "diagnostic text interpolates {banned:?} ({}:{}):\n{window}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
    fn check_harvest(path: &Path) {
        // Resolve-error literals (the texts the sink test pins
        // behaviorally): exact-match, so any interpolation or
        // pathname fails here too.
        let text = fs::read_to_string(path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.contains("has no file mapping") {
                assert!(
                    t.contains("\"legacy stage-2 attach has no file mapping\""),
                    "resolve literal drifted ({}:{}): {t:?}",
                    path.display(),
                    n + 1
                );
            }
            if t.contains("has no provider mapping") {
                assert!(
                    t.contains("\"stage-2 attach has no provider mapping\""),
                    "resolve literal drifted ({}:{}): {t:?}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
    check(&manifest_dir().join("src/discovery/session.rs"));
    check_harvest(&manifest_dir().join("src/discovery/harvest.rs"));
}

/// Round 2, residual F (rendered-doc property): the full
/// representative diagnostic vocabulary renders with no pathname
/// in any text, and every text is a member of the approved set
/// (literals verbatim; kind-token templates with an alphanumeric
/// kind token and hex file offsets only). The producers' exact
/// texts are pinned in the session/harvest unit suites; this pins
/// the shipped property over what they emit.
#[test]
fn attach_diagnostics_vocabulary_has_no_pathnames() {
    use osslscope::evidence::{
        CaptureWindow, FinalizeInput, LegacyCallPartition, OpensslVersion, TargetRecord, finalize,
    };
    // One of each producer shape (literals verbatim from the
    // allowlist bullet; templates instantiated with
    // representative kinds — NotFound/PermissionDenied/InvalidData
    // plus the collapse token).
    let diags = [
        "stage-2 target unmapped; link detached",
        "libcrypto unmapped after replacement; tripwire anchors blind",
        "tripwire mapping changed across replacement; anchors blind (cookie meanings shifted)",
        "stage-2 target superseded by replacement; old link detached",
        "stage-2 retry superseded by replacement; awaiting fresh init",
        "legacy stage-2 attach has no file mapping",
        "stage-2 attach has no provider mapping",
        "stage-2 pin open failed (kind=NotFound; cookie retries next poll)",
        "stage-2 pin open failed (kind=PermissionDenied; cookie retries next poll)",
        "stage-2 pin misses the resolve-time identity (cookie retries next poll)",
        "attach query_entry@0x1234 failed (kind=PermissionDenied)",
        "attach query_entry+query_return pin dup failed (kind=NotFound)",
        "tripwire anchors re-established after replacement (identical mapping)",
        "dispatch anchors re-established after replacement; continuity unproven",
        "attach path contains NUL",
        "dispatch reinstall failed: reinstall init anchor unresolved",
        "dispatch reinstall failed: no dispatch anchor to reinstall",
        "dispatch maps read failed (kind=InvalidData)",
        "dispatch provider read failed (kind=error)",
        "reinstall init anchor unresolved",
        "reinstall builtin anchor unresolved",
        "no dispatch anchor to reinstall",
        "missing program query_entry",
    ];
    let mut doc = finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
            count_admission: None,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    });
    doc.attach_diagnostics = diags.iter().map(|s| s.to_string()).collect();
    let bytes = osslscope::report::render_json(&doc).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rendered: Vec<&str> = v["attach_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert_eq!(rendered.len(), diags.len());
    fn is_kind_token(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
    }
    fn is_hex_offset(s: &str) -> bool {
        s.strip_prefix("0x")
            .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
    }
    fn approved(text: &str) -> bool {
        const LITERALS: &[&str] = &[
            "stage-2 target unmapped; link detached",
            "libcrypto unmapped after replacement; tripwire anchors blind",
            "tripwire mapping changed across replacement; anchors blind (cookie meanings shifted)",
            "stage-2 target superseded by replacement; old link detached",
            "stage-2 retry superseded by replacement; awaiting fresh init",
            "legacy stage-2 attach has no file mapping",
            "stage-2 attach has no provider mapping",
            "stage-2 pin misses the resolve-time identity (cookie retries next poll)",
            "tripwire anchors re-established after replacement (identical mapping)",
            "dispatch anchors re-established after replacement; continuity unproven",
            "attach path contains NUL",
            "reinstall init anchor unresolved",
            "reinstall builtin anchor unresolved",
            "no dispatch anchor to reinstall",
        ];
        if LITERALS.contains(&text) {
            return true;
        }
        if let Some(rest) = text.strip_prefix("stage-2 pin open failed (kind=") {
            return rest
                .strip_suffix("; cookie retries next poll)")
                .is_some_and(is_kind_token);
        }
        if let Some(rest) = text.strip_prefix("attach ") {
            // Link form `<name>@<hex-offset>` or pin-dup form
            // `<name>+<name> pin dup` — static names only.
            fn is_prog_name(s: &str) -> bool {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }
            if let Some((head, kind)) = rest.rsplit_once(" failed (kind=") {
                let kind_ok = kind.strip_suffix(')').is_some_and(is_kind_token);
                let link_ok = head
                    .split_once('@')
                    .is_some_and(|(name, off)| is_prog_name(name) && is_hex_offset(off));
                let dup_ok = head
                    .strip_suffix(" pin dup")
                    .and_then(|pair| pair.split_once('+'))
                    .is_some_and(|(a, b)| is_prog_name(a) && is_prog_name(b));
                return kind_ok && (link_ok || dup_ok);
            }
            return false;
        }
        if let Some(rest) = text.strip_prefix("dispatch reinstall failed: ") {
            return approved(rest);
        }
        if let Some(rest) = text.strip_prefix("dispatch maps read failed (kind=") {
            return rest.strip_suffix(')').is_some_and(is_kind_token);
        }
        if let Some(rest) = text.strip_prefix("dispatch provider read failed (kind=") {
            return rest.strip_suffix(')').is_some_and(is_kind_token);
        }
        if let Some(name) = text.strip_prefix("missing program ") {
            return !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        }
        false
    }
    for d in &rendered {
        assert!(!d.contains('/'), "diagnostic carries a pathname: {d}");
        assert!(
            approved(d),
            "diagnostic outside the approved vocabulary: {d}"
        );
    }
}

/// R14 minor: every rendered refusal entry matches the numeric
/// grammar `dev=<n> ino=<n> kind=<a-z_> bytes=<n>
/// allowance=<n>` — identities and sizes only, never paths. One
/// of each producer kind (no regex crate in dev-deps, so the
/// grammar is checked by hand).
#[test]
fn refusal_diagnostics_shape_is_numeric_only() {
    use osslscope::evidence::{
        CaptureWindow, FinalizeInput, LegacyCallPartition, OpensslVersion, TargetRecord, finalize,
    };
    let diags = [
        "dev=8 ino=100 kind=file_too_large bytes=2048 allowance=1024",
        "dev=8 ino=200 kind=over_allowance bytes=1536 allowance=1024",
    ];
    let mut doc = finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
            count_admission: None,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    });
    doc.refusal_diagnostics = diags.iter().map(|s| s.to_string()).collect();
    let bytes = osslscope::report::render_json(&doc).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rendered: Vec<&str> = v["refusal_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert_eq!(rendered.len(), diags.len());
    fn num(v: &str) -> bool {
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
    }
    fn kind(v: &str) -> bool {
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    }
    for d in &rendered {
        assert!(!d.contains('/'), "refusal carries a pathname: {d}");
        let parts: Vec<&str> = d.split(' ').collect();
        assert_eq!(parts.len(), 5, "five space-separated fields: {d}");
        assert!(parts[0].strip_prefix("dev=").is_some_and(num));
        assert!(parts[1].strip_prefix("ino=").is_some_and(num));
        assert!(parts[2].strip_prefix("kind=").is_some_and(kind));
        assert!(parts[3].strip_prefix("bytes=").is_some_and(num));
        assert!(parts[4].strip_prefix("allowance=").is_some_and(num));
    }
}
