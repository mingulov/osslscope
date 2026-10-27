// SPDX-License-Identifier: GPL-3.0-or-later

//! H5-T3: identity-domain audit — every device-identity site in
//! `src/` is pinned with the ONE domain it operates in. Any new,
//! removed, or reworded site fails LOUDLY: the author reviews the
//! diff, verifies single-domain operation, and re-pins with a
//! domain tag (reviewed, not silent).
//!
//! Scope (greppable device-identity sites, production code only —
//! `mod tests` bodies are skipped):
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
        // Skip `mod tests` bodies: rustfmt keeps test modules
        // top-level, so a column-0 `mod tests {` ... column-0
        // `}` pair delimits them.
        let mut in_tests = false;
        for line in text.lines() {
            if !in_tests && line.starts_with("mod tests {") {
                in_tests = true;
                continue;
            }
            if in_tests {
                if line.starts_with('}') {
                    in_tests = false;
                }
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
        // Native st_dev of the observer PID namespace FD, consumed only by
        // bpf_get_ns_current_pid_tgid; never joined with maps text devices.
        (
            "src/provider_observation/session.rs",
            "raw",
            "device: ns.dev(),",
            1,
        ),
        // Provider observations retain native fstat identities throughout.
        // The map_files association uses makedev-decoded maps dev_t and the
        // same reviewed Btrfs exception as inventory; only the retained FD's
        // native device/inode is used for deduplication and expected hashes.
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
            "&& m.info.device == stamp.native",
            2,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            "&& (metadata.dev() == map.native || filesystem == 0x9123683e)",
            1,
        ),
        (
            "src/provider_observation/objects.rs",
            "raw",
            "e.device != before.dev() || e.inode != before.ino() || e.size_bytes != before.len()",
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
        ("src/inventory/procfs.rs", "raw", "dev: m.dev(),", 1),
        // Watch compares native ModuleInfo identities, previously obtained
        // from fstat; no join to encoded map text or display-domain values.
        (
            "src/inventory/watch.rs",
            "raw",
            "(a.info.device, a.info.inode, &a.info.sha256) == (b.info.device, b.info.inode, &b.info.sha256)",
            1,
        ),
        // Namespace and cgroup descriptor IDs retain native dev_t; selector
        // fingerprints compare fstat metadata only, never encoded map IDs.
        ("src/inventory/procfs.rs", "raw", "device: m.dev(),", 1),
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
        // R05 adds the engine-observation and engine-evidence rows).
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
