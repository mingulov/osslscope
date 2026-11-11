// SPDX-License-Identifier: GPL-3.0-or-later

//! H5-T3: identity-domain audit — every device-identity site in
//! `src/` is pinned with the ONE domain it operates in. Any new,
//! removed, or reworded site fails LOUDLY: the author reviews the
//! diff, verifies single-domain operation, and re-pins with a
//! domain tag (reviewed, not silent).
//!
//! Scope (greppable device-identity sites across `src/`, including
//! the `startup_controls`, `budget_tests` and `session_tests` test
//! modules — only column-0 `mod tests` bodies are skipped):
//!
//! - `device_id_of_dev_str` / `parse_dev_str` (domain-free
//!   decoders — the CALLER's domain governs the join)
//! - `render_stat_dev` / `render_device` / `encode_device`
//!   (domain production / domain-agnostic shaping)
//! - `bound_bytes(` (full-identity binds)
//! - `backing_dev(` / `stat_dev_of(` (stat-or-fallback producers)
//! - `.dev` field access (maps-text fields, encoded-word fields,
//!   raw `dev_t` calls — compares and plumbing)
//!
//! Deliberately OUT of scope (reviewed by construction, not by
//! grep): bare-identifier string compares (`cur == dev` in
//! `bindings_alive`, the dual-facet filter in `relevant_paths`)
//! and ino-only compares (ino is domain-agnostic). If in doubt,
//! the pin diff is the review prompt — not proof.
//!
//! Domain tags (closed vocabulary — the test rejects unknown
//! tags): `stat` (stat-vs-stat), `maps` (maps-vs-maps),
//! `raw` (raw dev_t), `agnostic` (domain-free shape/decoder),
//! `fallback` (dual-facet unstatable arm), `display`
//! (display-only, never compared), `local` (run-local consistent
//! keys, never cross-domain joined).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_site(trimmed: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "device_id_of_dev_str",
        "parse_dev_str",
        "render_stat_dev",
        "render_device",
        "encode_device",
        "bound_bytes(",
        "backing_dev(",
        "stat_dev_of(",
        ".dev",
    ];
    PATTERNS.iter().any(|p| trimmed.contains(p))
}

fn normalize(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Line spans (1-based, inclusive) of column-0 `mod tests {` bodies.
/// Brace-matched with a small lexer so braces inside comments, strings,
/// raw strings and char literals cannot end a module early: a C fixture
/// in a raw string once terminated the naive skip at its own column-0
/// `}` and leaked session.rs test sites into the production set.
fn test_module_spans(text: &str) -> Vec<(usize, usize)> {
    #[derive(Clone, Copy, PartialEq)]
    enum Lex {
        Code,
        LineComment,
        BlockComment(u32),
        Str,
        RawStr(usize),
    }
    // String start at chars[i]: `"` or `[b|c][r][#]*"`. Returns the lexer
    // state to enter and the prefix length consumed (quote included).
    fn string_start(chars: &[char], i: usize) -> Option<(Lex, usize)> {
        if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
            return None;
        }
        if chars[i] == '"' {
            return Some((Lex::Str, 1));
        }
        let mut j = i;
        if matches!(chars[j], 'b' | 'c') && matches!(chars.get(j + 1), Some('"') | Some('r')) {
            j += 1;
        }
        let mut is_raw = false;
        if chars.get(j) == Some(&'r') && matches!(chars.get(j + 1), Some('"') | Some('#')) {
            is_raw = true;
            j += 1;
        }
        let mut hashes = 0;
        if is_raw {
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
        }
        if chars.get(j) != Some(&'"') {
            return None;
        }
        if is_raw {
            Some((Lex::RawStr(hashes), j - i + 1))
        } else if j > i {
            Some((Lex::Str, j - i + 1))
        } else {
            None
        }
    }
    // Char literal length at chars[i] == '\'', or None for a lifetime.
    fn char_literal_len(chars: &[char], i: usize) -> Option<usize> {
        match chars.get(i + 1) {
            Some('\\') => {
                let mut j = i + 2;
                while j < chars.len() && j - i <= 16 {
                    if chars[j] == '\\' {
                        j += 2;
                    } else if chars[j] == '\'' {
                        return Some(j - i + 1);
                    } else {
                        j += 1;
                    }
                }
                None
            }
            Some(c) if *c != '\'' && chars.get(i + 2) == Some(&'\'') => Some(3),
            _ => None,
        }
    }
    let mut spans = Vec::new();
    let mut state = Lex::Code;
    let mut span_start: Option<usize> = None;
    let mut depth: i64 = 0;
    let mut last_line = 0;
    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        last_line = lineno;
        if span_start.is_none() && state == Lex::Code && line.starts_with("mod tests {") {
            span_start = Some(lineno);
            depth = 0;
        }
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            match state {
                Lex::Code => {
                    if c == '/' && next == Some('/') {
                        state = Lex::LineComment;
                        i += 2;
                    } else if c == '/' && next == Some('*') {
                        state = Lex::BlockComment(1);
                        i += 2;
                    } else if let Some((entered, consumed)) = string_start(&chars, i) {
                        state = entered;
                        i += consumed;
                    } else if c == '\'' {
                        match char_literal_len(&chars, i) {
                            Some(consumed) => i += consumed,
                            None => i += 1,
                        }
                    } else {
                        if span_start.is_some() {
                            if c == '{' {
                                depth += 1;
                            } else if c == '}' {
                                depth -= 1;
                            }
                        }
                        i += 1;
                    }
                }
                Lex::LineComment => i = chars.len(),
                Lex::BlockComment(n) => {
                    if c == '/' && next == Some('*') {
                        state = Lex::BlockComment(n + 1);
                        i += 2;
                    } else if c == '*' && next == Some('/') {
                        state = if n == 1 {
                            Lex::Code
                        } else {
                            Lex::BlockComment(n - 1)
                        };
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                Lex::Str => {
                    if c == '\\' {
                        i += 2;
                    } else if c == '"' {
                        state = Lex::Code;
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
                Lex::RawStr(hashes) => {
                    if c == '"' && (0..hashes).all(|k| chars.get(i + 1 + k) == Some(&'#')) {
                        state = Lex::Code;
                        i += 1 + hashes;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        if state == Lex::LineComment {
            state = Lex::Code;
        }
        if let Some(start) = span_start {
            if depth <= 0 {
                spans.push((start, lineno));
                span_start = None;
            }
        }
    }
    if let Some(start) = span_start {
        spans.push((start, last_line));
    }
    spans
}

fn collect(dir: &Path, out: &mut BTreeMap<(String, String), u32>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(manifest_dir())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        // Skip `mod tests` bodies: brace-matched line spans (see
        // test_module_spans).
        let spans = test_module_spans(&text);
        let mut span = spans.iter().peekable();
        for (idx, line) in text.lines().enumerate() {
            let lineno = idx + 1;
            while span.peek().is_some_and(|(_, end)| lineno > *end) {
                span.next();
            }
            if span
                .peek()
                .is_some_and(|(start, end)| *start <= lineno && lineno <= *end)
            {
                continue;
            }
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if is_site(t) {
                *out.entry((rel.clone(), normalize(t))).or_insert(0) += 1;
            }
        }
    }
}

#[test]
fn h5_t3_every_device_site_names_one_domain() {
    let mut found: BTreeMap<(String, String), u32> = BTreeMap::new();
    collect(&manifest_dir().join("src"), &mut found);
    // Pinned sites: (file, domain tag, normalized line) →
    // occurrences. Domain vocabulary is closed (see module
    // docs) — an unknown tag fails the test.
    const DOMAINS: &[&str] = &[
        "stat", "maps", "raw", "agnostic", "fallback", "display", "local",
    ];
    let pinned: &[(&str, &str, &str, u32)] = &[
        // Public provenance repeats the physical row's already-encoded device
        // within the same document/count generation. No native/stat/maps join.
        (
            "src/schema.rs",
            "local",
            "&& site[\"device\"].as_u64() == Some(row.site.device)",
            1,
        ),
        // Startup dependency dedup compares native fstat dev_t/inode from
        // opened regular candidate FDs only. It suppresses repeated parsing;
        // it grants no mapped/site authority and never joins encoded evidence
        // devices or maps text. Retained Object stamps remain in this domain.
        (
            "src/startup_objects.rs",
            "raw",
            "if !seen.insert((before.dev(), before.ino())) {",
            1,
        ),
        // Native retained observer namespace st_dev is used solely by the
        // public namespace helper, never joined to maps text device values.
        ("src/focused_count.rs", "raw", "device: meta.dev(),", 1),
        // Explicit one-way conversion from native fstat dev_t to evidence's
        // major/minor encoding. The roundtrip is covered by focused_count.
        (
            "src/focused_count.rs",
            "stat",
            "crate::plan::encode_device(libc::major(native), libc::minor(native))",
            1,
        ),
        // Companion snapshots and executable reopen checks compare native
        // fstat identities only; no maps or encoded device-domain join.
        ("src/provider_observation/artifact.rs", "raw", "m.dev(),", 1),
        // T5 `--resolve-paths` (external F4): crypto Object-row
        // fragment joins the sidecar by the row's native
        // ModuleInfo identity (fstat-derived, same snapshot) —
        // exact equality, never maps text or display values.
        (
            "src/crypto_watch.rs",
            "raw",
            "writer.fragment(m.identity_status, (m.info.device, m.info.inode))",
            1,
        ),
        // Static table discovery compares before/after fstat stamps from the
        // same retained FD: native dev_t only, with no maps/encoded-domain join.
        (
            "src/provider_observation/static_tables.rs",
            "raw",
            "m.dev(),",
            1,
        ),
        // Native st_dev of the observer PID namespace FD, consumed only by
        // bpf_get_ns_current_pid_tgid; never joined with maps text devices.
        (
            "src/provider_observation/session.rs",
            "raw",
            "device: ns.dev(),",
            1,
        ),
        // Provider observations retain native fstat identities throughout:
        // only the retained FD's native device/inode is used for
        // deduplication and expected hashes. Record comparisons use the
        // backing association's approved native identity, not a re-read.
        // (The former map_files/Btrfs-exception pin moved to
        // inventory/backing check_target_keys.)
        (
            "src/provider_observation/objects.rs",
            "raw",
            "native: m.dev(),",
            1,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            "device: m.dev(),",
            1,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            "&& m.info.device == approved_native",
            2,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            "e.device != before.dev() || e.inode != before.ino() || e.size_bytes != before.len()",
            1,
        ),
        // Refused inventory hints compare ModuleInfo native st_dev/inode only;
        // they request fresh acquisition and never confer attachment authority.
        (
            "src/provider_observation/objects.rs",
            "raw",
            ".contains(&(module.info.device, module.info.inode))",
            1,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            ".map(|m| (m.info.device, m.info.inode)),",
            1,
        ),
        // Discovery cache, verified-record dedup and ELF identity use native
        // fstat dev_t, never
        // encoded callback/stat words. Cache keys and stability checks compare
        // descriptors in the same raw domain; ModuleInfo preserves it.
        ("src/inventory/cli.rs", "raw", "metadata.dev(),", 1),
        ("src/inventory/elf.rs", "raw", "device: before.dev(),", 1),
        (
            "src/inventory/elf.rs",
            "raw",
            "if before.dev() != after.dev()",
            1,
        ),
        // Coalesced gap display groups one snapshot's gaps by
        // their recorded (reason, device, pid) as opaque
        // run-local keys; comparisons never leave the snapshot
        // or join another identity domain (stat/maps/native).
        (
            "src/inventory/mod.rs",
            "local",
            ".entry((gap.reason, gap.device, gap.pid))",
            1,
        ),
        ("src/inventory/procfs.rs", "raw", "dev: m.dev(),", 1),
        // Watch compares native ModuleInfo identities, previously obtained
        // from fstat; no join to encoded map text or display-domain values.
        (
            "src/inventory/watch.rs",
            "raw",
            "(a.info.device, a.info.inode, &a.info.sha256) == (b.info.device, b.info.inode, &b.info.sha256)",
            1,
        ),
        // T5 `--resolve-paths`: sidecar join keys and render-time
        // identity checks. Every device value is native fstat dev_t
        // (opened FDs) or ModuleInfo preserving it; joins are exact
        // equality within one snapshot, never against maps text or
        // display values.
        (
            "src/inventory/cli.rs",
            "raw",
            "(info.device, info.inode),",
            1,
        ),
        (
            "src/inventory/procfs.rs",
            "raw",
            "let identity = (metadata.dev(), metadata.ino());",
            1,
        ),
        (
            "src/inventory/procfs.rs",
            "raw",
            ".push((key.clone(), (module.info.device, module.info.inode)));",
            1,
        ),
        // v0.6.0 D1/D3 machine publish: the row's native ModuleInfo
        // identity is passed as the expected pair and re-proven by
        // exact fstat equality (`identity_matches`) — same raw
        // domain, never maps text or an encoded device word.
        (
            "src/inventory/procfs.rs",
            "raw",
            "(module.info.device, module.info.inode),",
            1,
        ),
        (
            "src/inventory/resolve.rs",
            "raw",
            "(metadata.dev(), metadata.ino()) == retained",
            1,
        ),
        (
            "src/inventory/resolve.rs",
            "raw",
            "if (metadata.dev(), metadata.ino()) != expect {",
            1,
        ),
        (
            "src/inventory/resolve.rs",
            "raw",
            "(module.info.device, module.info.inode),",
            1,
        ),
        (
            "src/inventory/resolve.rs",
            "raw",
            ".fragment_module((module.device, module.inode))",
            1,
        ),
        // Namespace and cgroup descriptor IDs retain native dev_t; selector
        // fingerprints compare fstat metadata only, never encoded map IDs.
        ("src/inventory/procfs.rs", "raw", "device: m.dev(),", 1),
        // v0.6.0 D3 incarnation bracket: fstat st_dev of the opened
        // ns/mnt FD into NamespaceId, compared only against a second
        // same-domain incarnation read (before != after fails closed).
        (
            "src/inventory/procfs.rs",
            "raw",
            "device: metadata.dev(),",
            1,
        ),
        ("src/inventory/scope.rs", "raw", "device: m.dev(),", 1),
        ("src/inventory/scope.rs", "raw", "m.dev(),", 1),
        // Mapping text major/minor is converted with libc::makedev before
        // all joins. The explicit Btrfs branch permits its known distinct
        // subvolume st_dev; it does not convert device domains or establish
        // a path lookup as verified association.
        (
            "src/inventory/procfs.rs",
            "raw",
            "&& (metadata.dev() == mapping.device || filesystem(&file) == Some(0x9123683e))",
            1,
        ),
        (
            "src/inventory/procfs.rs",
            "raw",
            "|| (metadata.dev() != mapping.device && filesystem(&file) != Some(0x9123683e))",
            1,
        ),
        // Finite gap identities preserve native mapping or backing dev_t;
        // sorting uses that same raw identity without re-encoding it.
        (
            "src/inventory/procfs.rs",
            "raw",
            "device: mapping.map(|m| m.device),",
            1,
        ),
        (
            "src/inventory/procfs.rs",
            "raw",
            "device: Some(module.info.device),",
            1,
        ),
        (
            "src/inventory/procfs.rs",
            "raw",
            ".sort_by(|a, b| (a.0.info.device, a.0.info.inode).cmp(&(b.0.info.device, b.0.info.inode)));",
            1,
        ),
        // Preview: raw Metadata dev_t is encoded once, then joins use stat words.
        (
            "src/capture/profiled.rs",
            "stat",
            ".cookie_for(s.site.device, s.site.inode, s.site.offset)",
            1,
        ),
        (
            "src/capture/profiled.rs",
            "local",
            "|| cfg.dev_bundle.is_some()",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            ".cookie_for(site.site.device, site.site.inode, site.site.offset)",
            1,
        ),
        (
            "src/count_session.rs",
            "raw",
            "device: plan::encode_device(libc::major(m.dev()), libc::minor(m.dev())),",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "let dev = plan::render_device(site.site.device);",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "s.site.device != first.site.device",
            1,
        ),
        ("src/profile.rs", "raw", "dev: m.dev(),", 1),
        (
            "src/profile.rs",
            "stat",
            "let device = crate::plan::encode_device(",
            1,
        ),
        (
            "src/profile.rs",
            "raw",
            "libc::major(identity.dev as libc::dev_t),",
            1,
        ),
        (
            "src/profile.rs",
            "raw",
            "libc::minor(identity.dev as libc::dev_t),",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            ".map(|file| (file.bytes, (file.dev, file.ino)))",
            1,
        ),
        (
            "src/capture_setup.rs",
            "stat",
            ".map(|file| (file.bytes, (file.dev, file.ino)));",
            1,
        ),
        ("src/capture_setup.rs", "stat", "device: file.dev,", 1),
        (
            "src/capture_setup.rs",
            "stat",
            "let device = crate::plan::encode_device(",
            1,
        ),
        (
            "src/capture_setup.rs",
            "stat",
            "let dev = crate::plan::render_device(device);",
            1,
        ),
        (
            "src/capture_setup.rs",
            "raw",
            "libc::major(metadata.dev()),",
            1,
        ),
        (
            "src/capture_setup.rs",
            "raw",
            "libc::minor(metadata.dev()),",
            1,
        ),
        // capture.rs: file-cache identity validation (R20: both
        // fstat-sourced encoded words — cached read identity vs
        // current FileStat).
        ("src/capture.rs", "stat", "if cached.file.dev == cur.dev", 1),
        // capture.rs: torn-read guard (R20: read-identity (dev, ino)
        // from the bound read's fstat vs the pre-stat FileStat —
        // both fstat-encoded).
        (
            "src/capture.rs",
            "stat",
            "if (dev, ino) == (cur.dev, cur.ino)",
            1,
        ),
        // capture.rs: stable cookies keyed by the stat triple.
        (
            "src/capture.rs",
            "stat",
            ".cookie_for(site.site.device, site.site.inode, site.site.offset)",
            1,
        ),
        // capture.rs (H8): legacy-file join — stat triple both
        // sides (site backing vs advertised object identity).
        (
            "src/capture.rs",
            "stat",
            "&& legacy_files.contains(&(site.site.device, site.site.inode))",
            1,
        ),
        ("src/capture.rs", "stat", ".map(|o| (o.device, o.inode))", 1),
        // (R19 traversal-anchor pin removed round 3 with the
        // SiteKey adaptation — no stat site remains there.)
        // capture.rs: object-id bind against the full identity
        // (P6: carries the path for the build-id cache key; the
        // bind itself is still stat (dev, ino)).
        (
            "src/capture.rs",
            "stat",
            "plan::bound_bytes(files, &m.path, want, ino).map(|b| (m.path.clone(), b))",
            1,
        ),
        // capture.rs: B-5 registry key (dev, ino, id).
        (
            "src/capture.rs",
            "stat",
            ".insert((object.dev.clone(), object.ino, id.0.clone()))",
            1,
        ),
        // capture.rs: fence snapshot planned ident (maps-vs-maps).
        (
            "src/capture.rs",
            "maps",
            ".map(|m| (m.dev.clone(), m.ino))",
            1,
        ),
        // capture.rs: fence mapset (maps-vs-maps across polls).
        (
            "src/capture.rs",
            "maps",
            ".map(|m| (m.path.clone(), m.dev.clone(), m.ino, m.offset, m.x))",
            1,
        ),
        // capture.rs: bound read plumbing (fstat-produced).
        (
            "src/capture.rs",
            "stat",
            "plan::read_file_bounded(path, max_bytes).map(|f| (f.bytes, (f.dev, f.ino)))",
            1,
        ),
        // capture.rs: group device string (BackingRef, stat).
        ("src/capture.rs", "stat", "backing.dev.clone(),", 1),
        // capture.rs: stat-or-fallback production (×3).
        (
            "src/capture.rs",
            "stat",
            ".insert((crate::discovery::session::backing_dev(m), m.ino));",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "idents.insert((crate::discovery::session::backing_dev(m), m.ino));",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "let ident = (crate::discovery::session::backing_dev(m), m.ino);",
            1,
        ),
        // capture.rs: stat-facet pass.
        (
            "src/capture.rs",
            "stat",
            "crate::discovery::session::stat_dev_of(&m.path),",
            1,
        ),
        // capture.rs: B-5 advertising record (stat, 0 when ownerless).
        (
            "src/capture.rs",
            "stat",
            "device: plan::device_id_of_dev_str(&candidate.advertising_dev).unwrap_or(0),",
            1,
        ),
        // capture.rs: relevance idents (BackingRef, stat).
        (
            "src/capture.rs",
            "stat",
            "idents.insert((b.dev.clone(), b.ino));",
            1,
        ),
        // capture.rs: relevance idents (D2 objects, stat).
        (
            "src/capture.rs",
            "stat",
            "idents.insert((o.dev.clone(), o.ino));",
            1,
        ),
        // capture.rs: advertising turnover (stat-vs-stat).
        (
            "src/capture.rs",
            "stat",
            "if crate::discovery::session::backing_dev(m) != candidate.advertising_dev",
            1,
        ),
        // capture.rs: triple device decodes (stat strings, ×3
        // variants). Honest guarantee (sol round 2): BackingRef.dev
        // is stat-normally but maps-on-fallback (`backing_dev`
        // falls back to maps text when unstatable), so one file
        // may group under two triples across an unlink — a known
        // H5 tension (bindings use dual-facet path+ino and never
        // compare maps dev; triple grouping does not). The close
        // reconcile sidesteps it by matching (ino, offset) only.
        (
            "src/capture.rs",
            "stat",
            "let Some(device) = plan::device_id_of_dev_str(&backing.dev) else {",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "let Some(device) = plan::device_id_of_dev_str(&object.dev) else {",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "let Some(want) = plan::device_id_of_dev_str(&candidate.advertising_dev) else {",
            1,
        ),
        // capture.rs (R05 fix): per-module pin device decode +
        // object join — stat words both sides (fstat-rendered pin
        // strings decoded vs fingerprinted object registry). Each
        // probe's own module, never libcrypto.
        (
            "src/capture.rs",
            "stat",
            "if let Some(device) = plan::device_id_of_dev_str(&p.dev) {",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            ".filter(|o| o.device == *device && o.inode == *ino)",
            1,
        ),
        // capture.rs: advertising bind against the full identity
        // (P6: match-restructured to route bytes through the
        // build-id cache; the bind is still stat (dev, ino)).
        (
            "src/capture.rs",
            "stat",
            "let bid = match plan::bound_bytes(files, &m.path, want, candidate.advertising_ino) {",
            1,
        ),
        // capture.rs: object-id row decode (stat string).
        (
            "src/capture.rs",
            "stat",
            "let bid = plan::device_id_of_dev_str(dev).and_then(|want| {",
            1,
        ),
        // capture.rs: D2 record id from the stat triple (P6:
        // added the call-local build-id cache param; the id still
        // derives from the stat (dev, ino) bind, never the cache).
        (
            "src/capture.rs",
            "stat",
            "object_id_for_mapping(&object.dev, object.ino, ctx.live, ctx.files, &mut build_ids);",
            1,
        ),
        // capture.rs: maps facet carried for the unstatable arm.
        ("src/capture.rs", "fallback", "m.dev.as_str(),", 1),
        // capture.rs: stat_file encodes fstat (raw dev_t) into the
        // FileStat dev word (R20 struct-literal form).
        (
            "src/capture.rs",
            "raw",
            "dev: plan::encode_device(libc::major(m.dev()), libc::minor(m.dev())),",
            1,
        ),
        // capture.rs (R14): refusal-tag identity — raw dev_t from
        // fs metadata, rendered into the numeric diagnostic string
        // only, never joined/compared.
        ("src/capture.rs", "raw", ".map(|m| (m.dev(), m.ino()))", 1),
        // capture.rs (R14): cached-over-allowance refusal —
        // fstat-encoded word rendered only, never joined/compared.
        ("src/capture.rs", "display", "cached.file.dev,", 1),
        // target.rs: staging self-delete guard (R06: raw lstat
        // dev_t vs the raw dev_t recorded at staging creation —
        // both raw, never encoded; re-pinned during R20 while the
        // audit was already red at BASE for this line).
        ("src/target.rs", "raw", "&& st.st_dev == staging.dev", 1),
        // check.rs: evidence ref carries the stat word (plumbing).
        ("src/check.rs", "stat", "device: h.site.device,", 1),
        // check.rs (R05): engine-plane ref + violation entry carry
        // the stat word (same plumbing, tripwire key).
        ("src/check.rs", "stat", "device: h.key.device,", 1),
        ("src/check.rs", "stat", "\"device\": h.key.device,", 1),
        // Count owner: borrowed-fstat raw dev_t is encoded into the planned
        // stat identity. The two real host fixtures use that same conversion.
        (
            "src/count_owner/io.rs",
            "raw",
            "device: crate::plan::encode_device(libc::major(stat.st_dev), libc::minor(stat.st_dev)),",
            1,
        ),
        (
            "src/count_owner/tests.rs",
            "raw",
            "device: crate::plan::encode_device(libc::major(old.dev()), libc::minor(old.dev())),",
            1,
        ),
        (
            "src/count_owner/tests.rs",
            "raw",
            "device: crate::plan::encode_device(libc::major(current.dev()), libc::minor(current.dev())),",
            1,
        ),
        // Count owner session fixtures: PipeDriver's normalized stat backing
        // (1,2) is rendered into the mapping and retained verbatim in SiteKey.
        (
            "src/count_owner/tests.rs",
            "stat",
            "assert_eq!((current.site.device, current.site.inode), (1, 2));",
            1,
        ),
        (
            "src/count_owner/tests.rs",
            "stat",
            "assert_eq!(site.site.device, 1);",
            1,
        ),
        (
            "src/count_owner/tests.rs",
            "stat",
            "dev: crate::plan::render_device(1),",
            1,
        ),
        // count_session.rs: triple keys (stat words, ×3).
        (
            "src/count_session.rs",
            "stat",
            ".insert((prov.site.device, prov.site.inode, offset));",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            ".contains(&(prov.site.device, prov.site.inode, *offset))",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "let key = (site.site.device, site.site.inode, site.site.offset);",
            1,
        ),
        // count_session.rs: plan rows and owner refusals render stat words;
        // both lookups consume the same encoded stat-domain identities.
        (
            "src/count_session.rs",
            "stat",
            ".lookup(&plan::render_device(device), inode, offset)",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "dev: plan::render_device(backing.device),",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "dev: plan::render_device(s.site.device),",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "let Some(cookie) = self.stable.lookup(&row.dev, row.ino, row.offset) else {",
            1,
        ),
        // count_session.rs: the owner request copies the immutable planned
        // stat word; terminal survivor binding compares it with that provenance.
        (
            "src/count_session.rs",
            "stat",
            "device: prov.site.device,",
            1,
        ),
        (
            "src/count_session.rs",
            "stat",
            "if prov.site.device != pending.backing.device",
            1,
        ),
        // count_session.rs: the HostModel backend verifies an actual fstat pin
        // against the request's planned stat word, like the live owner port.
        (
            "src/count_session.rs",
            "stat",
            "if p.device != request.expected_backing.device",
            1,
        ),
        // harvest.rs: legacy target dev (stat render + maps fallback + raw expected).
        (
            "src/discovery/harvest.rs",
            "stat",
            ".map(|meta| crate::plan::render_stat_dev(meta.dev()))",
            1,
        ),
        (
            "src/discovery/harvest.rs",
            "fallback",
            ".unwrap_or_else(|| m.dev.clone());",
            1,
        ),
        (
            "src/discovery/harvest.rs",
            "stat",
            "dev: crate::plan::render_stat_dev(raw.0),",
            1,
        ),
        (
            "src/discovery/harvest.rs",
            "raw",
            "let expected = meta.as_ref().map(|meta| (meta.dev(), m.ino));",
            1,
        ),
        // harvest.rs: H6 presence check (stat-vs-stat, never pathname).
        (
            "src/discovery/harvest.rs",
            "stat",
            ".any(|m| m.ino == *ino && session::stat_dev_of(&m.path).as_deref() == Some(dev.as_str()))",
            1,
        ),
        // maps.rs: provider binding in the descriptor domain (raw dev_t).
        (
            "src/discovery/maps.rs",
            "raw",
            "Some((m, (meta.dev(), ino)))",
            1,
        ),
        (
            "src/discovery/maps.rs",
            "raw",
            "if map_meta.dev() != meta.dev() || map_meta.ino() != ino {",
            1,
        ),
        // onboard.rs: libcrypto dedup within one snapshot (maps-vs-maps).
        (
            "src/discovery/onboard.rs",
            "maps",
            ".entry((m.dev.clone(), m.ino))",
            1,
        ),
        // onboard.rs: file_id in raw dev_t.
        (
            "src/discovery/onboard.rs",
            "raw",
            ".map(|m| (m.dev(), m.ino()))",
            1,
        ),
        // schema.rs: row backings (provider stat tuple + foreign stat-or-fallback).
        (
            "src/discovery/schema.rs",
            "stat",
            "(ok, crate::plan::render_stat_dev(raw.0), m.ino, o)",
            1,
        ),
        (
            "src/discovery/schema.rs",
            "stat",
            "(ok, crate::discovery::session::backing_dev(m), m.ino, o)",
            1,
        ),
        // session.rs: D2 dedup on BackingRef strings (stat, ×2).
        (
            "src/discovery/session.rs",
            "stat",
            "&& self.seen_objects.insert((b.dev.clone(), b.ino))",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "if self.seen_objects.insert((b.dev.clone(), b.ino)) {",
            1,
        ),
        // session.rs: D2 records from BackingRef strings (stat, ×2).
        ("src/discovery/session.rs", "stat", "dev: b.dev.clone(),", 2),
        // session.rs (H10): pending re-resolve stats the provider
        // path (stat-vs-stat against the bound triple). R06
        // re-pin (justified — the item-13 domain fix): the raw
        // dev_t renders through render_stat_dev (major/minor
        // split), not render_device (encoded-word domain).
        (
            "src/discovery/session.rs",
            "stat",
            "Some((crate::plan::render_stat_dev(md.dev()), md.ino()))",
            1,
        ),
        // session.rs (R05 fix): tripwire module pins — fstat word
        // rendered to a stat string at attach, plumbed stat
        // end-to-end into the binding map (×2 sites).
        (
            "src/discovery/session.rs",
            "stat",
            "let identity = (crate::plan::render_device(pin.device), pin.ino);",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            ".map(|p| ((p.module, p.program), (p.dev, p.ino)))",
            2,
        ),
        // session.rs: plan ident / bindings from bound reads + pins (stat, ×4).
        (
            "src/discovery/session.rs",
            "stat",
            "(crate::plan::render_device(bound.dev), bound.ino),",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "binding: (prov_path, crate::plan::render_device(bound.dev), bound.ino),",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "crate::plan::render_device(prov_pin.device),",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "let bound_ident = (crate::plan::render_device(bound.dev), bound.ino);",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "let pdev = crate::plan::render_device(prov_pin.device);",
            1,
        ),
        // session.rs: fresh fstat in plan_trips (stat).
        (
            "src/discovery/session.rs",
            "stat",
            "(crate::plan::render_stat_dev(m.dev()), m.ino())",
            1,
        ),
        // session.rs: stat_dev_of body (stat).
        (
            "src/discovery/session.rs",
            "stat",
            "crate::plan::render_stat_dev(meta.dev())",
            1,
        ),
        // session.rs: suspect scope + incarnation + latch prints (maps, ×4).
        (
            "src/discovery/session.rs",
            "maps",
            ".map(|m| (m.dev.clone(), m.ino));",
            1,
        ),
        (
            "src/discovery/session.rs",
            "maps",
            ".map(|m| (m.dev.clone(), m.ino, m.start, m.end, m.offset))",
            1,
        ),
        // session.rs: M1 first-sighting fingerprint (maps, ×1 —
        // same tuple shape as incarnation_of, compared only
        // against incarnation_of output — single-domain).
        (
            "src/discovery/session.rs",
            "maps",
            "Some((m.dev.clone(), m.ino, m.start, m.end, m.offset))",
            1,
        ),
        (
            "src/discovery/session.rs",
            "maps",
            ".map(|m| (m.path.clone(), m.dev.clone(), m.ino))",
            1,
        ),
        (
            "src/discovery/session.rs",
            "maps",
            "libcrypto_entry(maps).map(|m| (m.path.clone(), m.dev.clone(), m.ino))",
            1,
        ),
        // session.rs: array owner to stat-or-fallback.
        (
            "src/discovery/session.rs",
            "stat",
            ".map(|m| (m.path.clone(), backing_dev(m), m.ino))",
            1,
        ),
        // session.rs: mapping-flap memory triple (R20-fix F4;
        // offset added round 4): STAT dev via backing_dev,
        // maps ino + maps offset — compared only against the
        // same-domain remembered triple (dev STAT-vs-STAT, ino
        // and offset maps-vs-maps) — single-domain.
        (
            "src/discovery/session.rs",
            "stat",
            "let triple = (backing_dev(m), m.ino, m.offset);",
            1,
        ),
        // session.rs: backing-freshness path resolve (R20-fix
        // F5): per-mapping STAT dev (`backing_dev`) vs the
        // candidate's STAT backing dev; ino==ino is
        // domain-agnostic — single-domain (stat-vs-stat).
        (
            "src/discovery/session.rs",
            "stat",
            ".find(|(m, d)| m.ino == backing.ino && *d == &backing.dev)",
            1,
        ),
        // session.rs: install decodes the stat plan ident.
        (
            "src/discovery/session.rs",
            "stat",
            "crate::plan::device_id_of_dev_str(dev).map(|enc| (path, (enc, *ino)))",
            1,
        ),
        // session.rs: attribute_impl arms (stat, ×2).
        (
            "src/discovery/session.rs",
            "stat",
            "dev: backing_dev(m),",
            2,
        ),
        // session.rs: pin-vs-plan / pin-vs-expected (fstat vs stat, ×3).
        (
            "src/discovery/session.rs",
            "stat",
            "if pin.device != enc || pin.ino != ino {",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "pin.device == enc && pin.ino == ino",
            1,
        ),
        (
            "src/discovery/session.rs",
            "raw",
            "let enc = crate::plan::encode_device(",
            1,
        ),
        // session.rs: retry ident from the stat target.
        (
            "src/discovery/session.rs",
            "stat",
            "let fresh_ident = (t.dev.clone(), t.ino);",
            1,
        ),
        // session.rs: reconcile stat-facet pass.
        (
            "src/discovery/session.rs",
            "stat",
            "let stat_devs: Vec<Option<String>> = maps.iter().map(|m| stat_dev_of(&m.path)).collect();",
            1,
        ),
        // session.rs: reinstall stat-facet pass (R03 seeds the
        // replacement binding's mapped history from install-poll
        // evidence; stat strings feed bindings_alive against the
        // stat-domain fresh binding — same single-domain shape as
        // the reconcile pass above, maps text never compared).
        (
            "src/discovery/session.rs",
            "stat",
            "maps.iter().map(|m| stat_dev_of(&m.path)).collect();",
            1,
        ),
        // session.rs: install targets from stat resolves (×2).
        (
            "src/discovery/session.rs",
            "stat",
            "let target = (t.off, t.path.to_string_lossy().into_owned(), t.dev, t.ino);",
            2,
        ),
        // session.rs: object order is domain-free (sort only).
        (
            "src/discovery/session.rs",
            "agnostic",
            "objects.sort_by(|a, b| (&a.dev, a.ino).cmp(&(&b.dev, b.ino)));",
            1,
        ),
        // session.rs: stat-or-fallback producer decls.
        (
            "src/discovery/session.rs",
            "stat",
            "pub(crate) fn backing_dev(m: &maps::Mapping) -> String {",
            1,
        ),
        (
            "src/discovery/session.rs",
            "stat",
            "pub(crate) fn stat_dev_of(path: &str) -> Option<String> {",
            1,
        ),
        // session.rs: backing_dev fallback arm.
        (
            "src/discovery/session.rs",
            "fallback",
            "stat_dev_of(&m.path).unwrap_or_else(|| m.dev.clone())",
            1,
        ),
        // plan.rs: row bind against the full identity.
        (
            "src/plan.rs",
            "stat",
            ".find_map(|p| bound_bytes(files, p, row_dev, ino).map(|b| (*p, b)));",
            1,
        ),
        // plan.rs: bound/pinned reads encode fstat (raw, ×2).
        // R14: the bound-read encode moved into
        // `ReadBoundedSource::bound_identity` (same raw dev_t in,
        // same encoded word out); the tear check now compares
        // those encoded words (encode is injective, so equality
        // is exact) and is no longer a greppable site.
        (
            "src/plan.rs",
            "raw",
            "encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),",
            1,
        ),
        (
            "src/plan.rs",
            "raw",
            "device: encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),",
            1,
        ),
        // plan.rs: bound_bytes core (fstat word vs stat-decoded word).
        (
            "src/plan.rs",
            "stat",
            "if fb.dev != dev || fb.ino != ino {",
            1,
        ),
        // plan.rs: row decode (rows are stat).
        (
            "src/plan.rs",
            "stat",
            "let Some(row_dev) = device_id_of_dev_str(&dev) else {",
            1,
        ),
        // plan.rs: row string plumbing (stat-rendered).
        ("src/plan.rs", "stat", "let dev = r.dev.clone();", 1),
        // plan.rs: domain-free decoder/shaper decls + body.
        (
            "src/plan.rs",
            "agnostic",
            "parse_dev_str(dev).map(|(major, minor)| encode_device(major, minor))",
            1,
        ),
        (
            "src/plan.rs",
            "agnostic",
            "pub fn device_id_of_dev_str(dev: &str) -> Option<u64> {",
            1,
        ),
        (
            "src/plan.rs",
            "agnostic",
            "pub fn encode_device(major: u32, minor: u32) -> u64 {",
            1,
        ),
        (
            "src/plan.rs",
            "agnostic",
            "pub fn parse_dev_str(dev: &str) -> Option<(u32, u32)> {",
            1,
        ),
        (
            "src/plan.rs",
            "agnostic",
            "pub fn render_device(id: u64) -> String {",
            1,
        ),
        // plan.rs: stat producer decl + body.
        (
            "src/plan.rs",
            "stat",
            "pub fn render_stat_dev(dev_t: u64) -> String {",
            1,
        ),
        ("src/plan.rs", "stat", "render_device(encode_device(", 1),
        // report.rs: device words rendered (display-only, ×5;
        // R05 adds the engine-observation and engine-evidence rows;
        // 5C adds the v2.5 attribution render rows, ×2).
        ("src/report.rs", "display", "\"device\": e.device,", 2),
        ("src/report.rs", "display", "\"device\": o.device,", 1),
        ("src/report.rs", "display", "\"device\": o.key.device,", 1),
        (
            "src/report.rs",
            "display",
            "\"device\": site.site.device,",
            1,
        ),
        ("src/report.rs", "display", "site.site.device,", 1),
        // 5C: admitted site-key devices rendered into the v2.5
        // attribution JSON and the partition bom-ref —
        // display-only, same domain as the site rows above.
        ("src/report.rs", "display", "\"device\": r.site.device,", 1),
        ("src/report.rs", "display", "row.site.device,", 1),
        // target.rs: staging-cleanup unlink guard (R06: lstat dev_t
        // vs the fstat-recorded dev_t — a raw-vs-raw same-file check
        // so a stale worker unlinks only the inode it created; no
        // maps text or rendered dev strings in this file).
        ("src/target.rs", "raw", "&& st.st_dev == staging.dev", 1),
        // target.rs: canonical registry key (v0.2 R19: raw dev_t
        // from `metadata` embedded in `canon:<dev>:<ino>/<name>`
        // keys, compared only against same-constructed keys —
        // raw-vs-raw, run-local, never cross-domain joined).
        ("src/target.rs", "raw", "md.dev(),", 1),
        // Development-bundle selectors carry directory paths, with no device
        // comparison or conversion. Their .dev substring is pathname plumbing.
        (
            "src/capture.rs",
            "agnostic",
            "dev_bundle: cfg.dev_bundle.clone(),",
            1,
        ),
        (
            "src/package/commands.rs",
            "agnostic",
            "if let Some(dir) = &overrides.dev_bundle {",
            1,
        ),
        // Development snapshots compare raw fstat dev_t only before/after
        // reads of that same opened FD, as the other package snapshots do.
        ("src/package/dev.rs", "raw", "dev: m.dev(),", 1),
        // Package snapshots retain raw dev_t from opened-FD metadata for
        // same-FD before/after identity checks; no encoded/maps-domain join.
        ("src/package/commands.rs", "raw", "dev: m.dev(),", 1),
        // Retained artifacts compare raw fstat metadata before/after reads;
        // their identity never joins encoded or maps device domains.
        // Focused Count already encoded this SiteKey's device as a stat word;
        // projection copies it into ObjectRecord dedup keys in that same domain.
        (
            "src/focused_capture.rs",
            "stat",
            "objects.insert((site.site.object.clone(), site.site.device, site.site.inode));",
            1,
        ),
        // Scanner-owned native PID namespace FD; never maps-text metadata.
        (
            "src/focused_capture.rs",
            "raw",
            "device: metadata.dev(),",
            1,
        ),
        ("src/package/build.rs", "raw", "dev: m.dev(),", 1),
        // Task 2 trusted file identities use the same raw FD metadata domain.
        ("src/package/trusted.rs", "raw", "dev: m.dev(),", 1),
        // Executing-FD and trusted path-rebound FD devices are compared raw.
        (
            "src/package/trusted.rs",
            "raw",
            "if proc_id.dev != rebound_id.dev || proc_id.ino != rebound_id.ino {",
            1,
        ),
        // Source reads compare before/after raw metadata from the same retained FD.
        ("src/package/source.rs", "raw", "a.dev(),", 1),
        ("src/package/source.rs", "raw", "b.dev(),", 1),
        // Artifact aliases compare two raw stat identities, never maps or
        // encoded callback devices, before a second output can overwrite one.
        (
            "src/report.rs",
            "raw",
            "(Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),",
            1,
        ),
        // The actual-source HOST driver makes capture's test module visible.
        // These fixtures keep normalized stat words in SiteKey/ObjectRecord;
        // rendering or decoding the fixture does not change its caller domain.
        (
            "src/capture.rs",
            "stat",
            "&crate::plan::render_device(dev),",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "assert_eq!(o.key.device, device);",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "assert_eq!(site.site.device, device);",
            1,
        ),
        // SeedFile metadata starts as raw dev_t, then major/minor encode it
        // into the same stat word used by the seeded file and mapping.
        (
            "src/capture.rs",
            "raw",
            "crate::plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),",
            1,
        ),
        (
            "src/capture.rs",
            "stat",
            "let device = plan::device_id_of_dev_str(\"08:01\").unwrap();",
            7,
        ),
        // Namespace FD identities compare raw MetadataExt dev_t/inode tuples
        // only with other namespace FD identities, never maps/encoded devices.
        (
            "src/lifecycle_producer.rs",
            "raw",
            "namespaces.push((m.dev(), m.ino()));",
            1,
        ),
        // Inventory backing: Fingerprint is the native fstat identity
        // (MetadataExt dev_t/ino) of a retained FD. Continuity and
        // association compare native fingerprints only; the one
        // maps-facing check compares the native fingerprint device
        // against the makedev-decoded maps dev_t under the same
        // reviewed Btrfs exception (0x9123683e) as the former
        // objects.rs map_files pin. NamespaceId pairs come from
        // namespace-file fstat and join only namespace identities.
        ("src/inventory/backing.rs", "raw", "dev: m.dev(),", 1),
        (
            "src/inventory/backing.rs",
            "raw",
            "device: metadata.dev(),",
            1,
        ),
        (
            "src/inventory/backing.rs",
            "raw",
            "before.dev == after.dev",
            1,
        ),
        (
            "src/inventory/backing.rs",
            "raw",
            "(self.candidate_fp.dev, self.candidate_fp.ino)",
            1,
        ),
        (
            "src/inventory/backing.rs",
            "raw",
            "if fingerprint.dev != vma.dev && fstype != Some(BTRFS_SUPER_MAGIC) {",
            1,
        ),
        // Test-hook observation of the verified candidate's native
        // fstat identity (cfg(test) only); production returns the same
        // Metadata unjoined with any other domain.
        (
            "src/inventory/procfs.rs",
            "raw",
            "let _ = hook.observed.send((verified.dev(), verified.ino()));",
            1,
        ),
        // Multi-attachment admission: claims and the single-backing
        // consistency check compare fresh stat/native site devices
        // (attachment.site.native_device()) only.
        (
            "src/provider_observation/session.rs",
            "raw",
            "|| claimed.dev() != attachment.site.native_device()",
            1,
        ),
        (
            "src/provider_observation/session.rs",
            "raw",
            "let (device, inode) = (admitted[0].device, admitted[0].inode);",
            1,
        ),
        (
            "src/provider_observation/session.rs",
            "raw",
            ".any(|a| (a.device, a.inode) != (device, inode))",
            1,
        ),
        (
            "src/provider_observation/session.rs",
            "raw",
            "admitted.iter().map(|a| (a.device, a.inode)).collect();",
            1,
        ),
        (
            "src/provider_observation/session.rs",
            "raw",
            "let (device, inode) = (metadata.dev(), metadata.ino());",
            1,
        ),
        // Source-observer enrollment records the observer PID
        // namespace's native st_dev for kernel-side comparison.
        (
            "src/provider_observation/source_owner.rs",
            "raw",
            "namespace_device: ns.dev(),",
            2,
        ),
        // Typed-site attribution: record devices are evidence-encoded
        // once at admission (focused_count::evidence_device); SiteKey
        // keys, the counter pin map and the admitted/sample join all
        // compare those stat words only.
        ("src/attribution.rs", "stat", "device: site.device,", 1),
        (
            "src/focused_capture.rs",
            "stat",
            "device: record.device,",
            1,
        ),
        (
            "src/focused_count.rs",
            "stat",
            ".and_then(|pins| pins.get(&(key.device, key.inode, key.offset)).copied())",
            1,
        ),
        // 6B service stream tap: the OPEN tap file's native
        // (dev, ino) is retained at open; rotation/reconcile paths
        // re-stat the PATH and compare native-to-native (same-file
        // proof, §6.1). No encoded evidence device joins this
        // comparison anywhere; both sides are observer-side fstat.
        (
            "src/service/coordinator.rs",
            "raw",
            ".map(|m| (m.dev(), m.ino()) == (dev, ino))",
            1,
        ),
        // 6B rotation stat snapshot: native (len, dev, ino) of the
        // active/rotated tap file for size + identity decisions.
        // Observer-side fstat only.
        (
            "src/service/coordinator.rs",
            "raw",
            ".map(|m| (m.len(), m.dev(), m.ino()))",
            1,
        ),
        // 6B rotation record: repeats the retained native tap
        // identity into the rotation row. No re-read, no join.
        (
            "src/service/coordinator.rs",
            "raw",
            "dest_dev: tap.ident.dev,",
            1,
        ),
        // 6B rotation unpack: repeats the retained native
        // (path, dev, ino) triple. No re-read, no join.
        (
            "src/service/coordinator.rs",
            "raw",
            "let (path, dev, ino) = (rot.rotated.clone(), rot.dev, rot.ino);",
            1,
        ),
        // 6B tap re-stat: fresh native fstat of a tap path for
        // the same-file proof. Observer-side fstat only.
        (
            "src/service/coordinator.rs",
            "raw",
            "std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))",
            1,
        ),
        // 6B snapshot rows: evidence-encoded site devices
        // (admission-encoded once) propagated into merged rows —
        // the attribution.rs precedent. No native/stat join.
        ("src/service/snapshot.rs", "stat", "device: site.device,", 1),
        (
            "src/service/snapshot.rs",
            "stat",
            "push(row.site.object.clone(), row.site.device, row.site.inode);",
            1,
        ),
        // 6B dev_ino helper: native fstat of an open tap FD into
        // a (dev, ino) tuple. Observer-side fstat only.
        ("src/service/stream.rs", "raw", "Ok((m.dev(), m.ino()))", 1),
        // Native test harness (cfg(test) module): the observer
        // namespace's native st_dev/inode written as map bytes.
        (
            "src/writer_gate_native.rs",
            "raw",
            "let ns = [ns.device.to_ne_bytes(), ns.inode.to_ne_bytes()].concat();",
            3,
        ),
        // 1D-D3 (engine identity domain): the focused ENGINE path
        // admits libcrypto/caller devices as evidence-encoded stat
        // words (evidence_device), matching FileBytes.dev and the
        // document's SiteKey.device — raw dev_t never meets an
        // encoded word. The admission check itself stays raw-vs-raw
        // (ModuleInfo native dev_t vs fresh fstat); everything
        // stored or compared past it is encoded.
        (
            "src/focused_capture.rs",
            "raw",
            ".any(|m| m.info.device == fresh.dev() && m.info.inode == fresh.ino())",
            1,
        ),
        (
            "src/focused_capture.rs",
            "stat",
            "device: evidence_device(fresh.dev()),",
            2,
        ),
        (
            "src/focused_capture.rs",
            "stat",
            "if lib.device != device || lib.inode != inode {",
            1,
        ),
        // Caller-set watch baseline/current: fresh native fstat
        // tuples on both sides of the diff (raw-vs-raw).
        (
            "src/focused_capture.rs",
            "raw",
            "let identity = std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));",
            2,
        ),
        // Identity-bound reads: FileBytes.dev (encoded) against
        // encoded admitted/fresh identities (stat-vs-stat).
        (
            "src/focused_capture.rs",
            "stat",
            "Ok(fb) if fb.dev == lib.device && fb.ino == lib.inode => fb,",
            1,
        ),
        (
            "src/focused_capture.rs",
            "stat",
            "Ok(fb) if fb.dev == evidence_device(fresh.dev()) && fb.ino == fresh.ino() => fb,",
            1,
        ),
        // Probe-plan identity: encoded libcrypto word shaped for
        // the planner; encoded caller identities keyed, stored,
        // and rendered (render_device over encoded words).
        (
            "src/focused_capture.rs",
            "stat",
            "(crate::plan::render_device(lc.dev), lc.ino),",
            1,
        ),
        (
            "src/focused_capture.rs",
            "stat",
            ".map(|m| (m.path.clone(), (m.device, m.inode)))",
            1,
        ),
        (
            "src/focused_capture.rs",
            "stat",
            "(found.device, found.inode, String::new()),",
            1,
        ),
        ("src/focused_capture.rs", "stat", "device: found.device,", 1),
        (
            "src/focused_capture.rs",
            "stat",
            "dev: crate::plan::render_device(plan.device),",
            1,
        ),
        ("src/focused_capture.rs", "stat", "device: lib.device,", 1),
        (
            "src/focused_capture.rs",
            "stat",
            "crate::plan::render_device(*device)",
            1,
        ),
        // session_tests ModuleInfo fixture: ModuleInfo.device is
        // native dev_t by type (raw, consumed raw at admission).
        ("src/focused_capture.rs", "raw", "device: meta.dev(),", 1),
        // Admission stores the evidence encoding (holds on every
        // filesystem, not just major-0 low-minor where raw==encoded).
        (
            "src/focused_capture.rs",
            "stat",
            "assert_eq!(admitted.device, evidence_device(meta.dev()));",
            1,
        ),
        // Engine-plan alias dedupe keys plan-vs-plan triples
        // (same encoded field both sides).
        (
            "src/focused_count.rs",
            "stat",
            "if let Some(&u) = seen.get(&(p.device, p.inode, p.offset)) {",
            1,
        ),
        (
            "src/focused_count.rs",
            "stat",
            "seen.insert((p.device, p.inode, p.offset), unique.len());",
            1,
        ),
        // Attach-time TOCTOU check: the fresh stat side is encoded
        // before meeting the encoded plan devices (stat-vs-stat).
        (
            "src/focused_count.rs",
            "stat",
            "let stat_dev = evidence_device(stat.dev());",
            1,
        ),
        (
            "src/focused_count.rs",
            "stat",
            ".all(|&i| stat_dev == probes[i].device && stat.ino() == probes[i].inode);",
            1,
        ),
        // startup_controls fixtures over read_file_bound bytes:
        // FileBytes.dev is encoded (render over encoded words).
        (
            "src/focused_count.rs",
            "stat",
            "(crate::plan::render_device(lc.dev), lc.ino),",
            4,
        ),
        // EngineProbePlan fixtures carry encoded devices (the
        // struct's domain; the attach check encodes its side).
        (
            "src/focused_count.rs",
            "stat",
            "device: evidence_device(meta.dev()),",
            6,
        ),
        // 6A exe identity: fresh fstat tuples compared across
        // samples for exec detection (raw-vs-raw).
        (
            "src/crypto_watch.rs",
            "raw",
            ".map(|m| (m.dev(), m.ino()))",
            1,
        ),
        // Gap display triples: run-local grouping keys for the
        // human gap block (same local precedent as
        // inventory/mod.rs) — rendered, never cross-domain joined.
        (
            "src/crypto_watch.rs",
            "local",
            "self.pending_gaps.push((gap.reason, gap.device, gap.pid));",
            1,
        ),
        (
            "src/inventory/watch.rs",
            "local",
            "let triples = gaps.iter().map(|g| (g.reason.word(), g.device, g.pid));",
            1,
        ),
        (
            "src/provider_observation/cli.rs",
            "local",
            "gaps.iter().map(|g| (g.reason.word(), g.device, g.pid)),",
            1,
        ),
        // 6B tap identity proof: fresh native fstat vs fresh
        // native fstat of reserved sinks (raw-vs-raw).
        (
            "src/service/stream.rs",
            "raw",
            "let id = (meta.dev(), meta.ino());",
            1,
        ),
        (
            "src/service/stream.rs",
            "raw",
            ".map(|m| (m.dev(), m.ino()) == id)",
            1,
        ),
    ];
    for (file, domain, _, _) in pinned {
        assert!(
            DOMAINS.contains(domain),
            "unknown domain tag {domain:?} for {file} (closed vocabulary)"
        );
    }
    let mut expected: BTreeMap<(String, String), u32> = BTreeMap::new();
    for (file, _domain, snippet, count) in pinned {
        expected.insert((file.to_string(), snippet.to_string()), *count);
    }
    if found != expected {
        let mut only_found = BTreeMap::new();
        let mut only_pinned = BTreeMap::new();
        for (k, v) in &found {
            if expected.get(k) != Some(v) {
                only_found.insert(k, v);
            }
        }
        for (k, v) in &expected {
            if found.get(k) != Some(v) {
                only_pinned.insert(k, v);
            }
        }
        panic!(
            "identity-domain pin mismatch (review each site, verify \
             single-domain operation, re-pin with a domain tag):\n\
             --- discovered but not pinned ({}):\n{}\n\
             --- pinned but not discovered ({}):\n{}",
            only_found.len(),
            only_found
                .iter()
                .map(|((f, s), c)| format!("  {f} x{c}: {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
            only_pinned.len(),
            only_pinned
                .iter()
                .map(|((f, s), c)| format!("  {f} x{c}: {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

#[test]
fn spans_skip_whole_tests_module() {
    let src = [
        "fn prod() {}",
        "mod tests {",
        "    fn t() { let _ = x.dev(); }",
        "}",
        "fn after() {}",
    ]
    .join("\n");
    assert_eq!(test_module_spans(&src), vec![(2, 4)]);
}

#[test]
fn spans_survive_raw_string_fixture_braces() {
    // Regression: a C fixture in a raw string used to end the skip at
    // its own column-0 `}` (session.rs); unbalanced `{{` in a raw JSON
    // fixture (builtin.rs) must not corrupt the depth either.
    let src = [
        "mod tests {",
        "    const C: &str = r#\"int main() {",
        "}",
        "\"#;",
        "    const J: &str = r#\"{{\"a\":1}\"#;",
        "    fn t() {}",
        "}",
        "fn after() {}",
    ]
    .join("\n");
    assert_eq!(test_module_spans(&src), vec![(1, 7)]);
}

#[test]
fn spans_ignore_comment_and_char_braces() {
    let src = [
        "mod tests {",
        "    // } in a line comment",
        "    /* { /* } */ still } */",
        "    const CLOSE: char = '}';",
        "    const OPEN: char = '{';",
        "    fn t<'a>(x: &'a str) {}",
        "}",
    ]
    .join("\n");
    assert_eq!(test_module_spans(&src), vec![(1, 7)]);
}

#[test]
fn spans_not_started_inside_string() {
    let src = ["const S: &str = \"mod tests {\";", "fn prod() {}"].join("\n");
    assert_eq!(test_module_spans(&src), Vec::<(usize, usize)>::new());
}
