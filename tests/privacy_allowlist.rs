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
fn inventory_from_doc() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let text = fs::read_to_string(manifest_dir().join("docs/privacy/allowlist-v1.md")).unwrap();
    let mut in_block = false;
    let mut harvest = BTreeSet::new();
    let mut count = BTreeSet::new();
    let mut members = BTreeSet::new();
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
    (harvest, count, members)
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
    let (doc_harvest, doc_count, doc_members) = inventory_from_doc();
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
