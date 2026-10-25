//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture planner (P2): harvest doc + live maps → multi-link plan.
//!
//! Plans are ASLR-immune: doc rows carry the stable
//! backing{dev,ino,offset} triple, and entries resolve (path, offset)
//! through live mappings matched on dev:ino — runtime addresses are
//! never consulted. Userspace-first validation (offset < file size,
//! in X LOAD) keeps kernel EINVALs rare; survivors are isolated by
//! `bisect_attach` (bounded log n) into `unresolved_offsets`.
//! Plan-time rejects (unmapped / unreadable / past-eof /
//! not-executable) surface as `missed_attaches` — planned offsets
//! with no active probe at window end.
use crate::discovery::{elf, maps};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{OwnedFd, RawFd};

/// Cookie identity: what a plan index MEANS (drain attribution).
/// File offset (not addr) — stable across runs (ASLR-immune).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub provider: String,
    pub op: u32,
    pub funcid: u32,
    pub alg_class: String,
    pub offset: u64,
}

/// One planned probe: multi-link site + cookie + identity. Shared
/// implementations (same backing+offset under several rows) attach
/// ONCE under the first identity; the rest ride as `aliases` (their
/// calls ARE counted — under the canonical cookie — so this is plan
/// metadata, not a gap counter).
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub offset: u64,
    pub cookie: u32,
    pub id: Identity,
    pub aliases: Vec<Identity>,
}

/// Plan-time reject → `missed_attaches` at window end. Reasons:
/// `unmapped` (no live X mapping of the backing file),
/// `unreadable` (no file bytes / stat failure), `past-eof`,
/// `not-executable`, `replaced` (the link path no longer backs the
/// planned file identity — open-file check around attachment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub dev: String,
    pub ino: u64,
    pub offset: u64,
    pub reason: &'static str,
}

/// Attach plan at one generation epoch.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub entries: Vec<Entry>,
    pub missed: Vec<Missed>,
    pub generation: u32,
}

/// One multi link's payload: parallel offsets + cookies for `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub path: String,
    pub offsets: Vec<u64>,
    pub cookies: Vec<u64>,
}

fn str_at(r: &serde_json::Value, k: &str) -> anyhow::Result<String> {
    r.get(k)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks string {k:?}"))
}

fn u32_at(r: &serde_json::Value, k: &str) -> anyhow::Result<u32> {
    let v = r
        .get(k)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks numeric {k:?}"))?;
    u32::try_from(v).map_err(|_| anyhow::anyhow!("harvest row {k:?} overflows u32"))
}

fn u64_at(r: &serde_json::Value, k: &str) -> anyhow::Result<u64> {
    r.get(k)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks numeric {k:?}"))
}

/// Stable cookie allocator across fence re-plans. Cookies identify
/// verified physical backing (device, inode, file offset) for the
/// whole run — never the link path. The same inode through another
/// path reuses its cookie; a replacement inode at the same path
/// mints a new one while the old cookie keeps its old meaning. Old
/// links keep firing with correct cookies under new generations
/// (the gen half of the key separates pre/post-fence counts), so
/// re-plans never detach. Single-shot `plan` is the fresh-allocator
/// case (cookies 0..n).
#[derive(Debug, Default)]
pub struct StableCookies {
    next: u32,
    ids: HashMap<(String, u64, u64), u32>,
}

impl StableCookies {
    fn cookie_for(&mut self, dev: &str, ino: u64, offset: u64) -> anyhow::Result<u32> {
        if let Some(&c) = self.ids.get(&(dev.to_string(), ino, offset)) {
            return Ok(c);
        }
        if self.next == u32::MAX {
            anyhow::bail!("cookie space exhausted");
        }
        let c = self.next;
        self.next += 1;
        self.ids.insert((dev.to_string(), ino, offset), c);
        Ok(c)
    }

    /// Reverse lookup: the cookie minted for a backing triple, if any.
    pub fn lookup(&self, dev: &str, ino: u64, offset: u64) -> Option<u32> {
        self.ids.get(&(dev.to_string(), ino, offset)).copied()
    }

    /// Cookies minted so far.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether any cookie has been minted.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// Parse an `MM:mm` device string (both hex — the kernel prints
/// `%02x:%02x`, so e.g. device-mapper `253:0` reads `fd:00`;
/// stat-rendered strings share the shape exactly). Domain-free
/// decoder: stat and maps strings parse identically — the
/// CALLER's domain governs what the word may join against (H5).
/// `None` on any malformed input; callers treat that as an
/// unplannable row, never a guess.
pub fn parse_dev_str(dev: &str) -> Option<(u32, u32)> {
    let (major, minor) = dev.split_once(':')?;
    if major.is_empty() || minor.is_empty() {
        return None;
    }
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some((major, minor))
}

/// Encode a (major, minor) device pair as the `SiteKey.device`
/// identity word. This is a stable identity encoding, not the kernel
/// `dev_t` bit layout; [`decode_device`] inverts it exactly.
pub fn encode_device(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | (minor as u64)
}

/// Split an [`encode_device`] word back into (major, minor).
pub fn decode_device(id: u64) -> (u32, u32) {
    ((id >> 32) as u32, id as u32)
}

/// Render an encoded device word as `MM:mm` (domain-agnostic
/// shape — the word's domain comes from its producer: stat
/// fstat or maps text; callers document which).
pub fn render_device(id: u64) -> String {
    let (major, minor) = decode_device(id);
    format!("{major:02x}:{minor:02x}")
}

/// Render a RAW stat dev_t (`Metadata::dev`) as `MM:mm` (H5):
/// the stat-domain device string for rows, bindings, and retry
/// idents — same format as maps dev-strings, deliberately
/// indistinguishable in shape (callers document the domain).
pub fn render_stat_dev(dev_t: u64) -> String {
    render_device(encode_device(
        libc::major(dev_t as libc::dev_t),
        libc::minor(dev_t as libc::dev_t),
    ))
}

/// `MM:mm` device string → encoded identity word (H5: parses
/// EITHER domain — stat-rendered and maps text share the shape).
/// `None` when the field is malformed.
pub fn device_id_of_dev_str(dev: &str) -> Option<u64> {
    parse_dev_str(dev).map(|(major, minor)| encode_device(major, minor))
}

// H4 removed `sample_backing` (before/after path sampling for
// attach binding): the fd pin subsumes it — no path sample can
// race an open file description. Design:
// docs/2026-10-11-h4-descriptor-custody-design.md §2.

/// An open file retained as an attach pin (H4): the fd was opened
/// FIRST and fstat'd ITSELF, so `(device, ino)` names the exact
/// inode the subsequent fd-path attach binds — no path sample can
/// race it. The kernel resolves [`PinnedFile::link_path`] to the
/// open file description, not the pathname (H4 §4 spike: pin
/// proven across A→B→A, pending arms on exec of the pinned
/// inode). Retain until the link detaches.
#[derive(Debug)]
pub struct PinnedFile {
    /// The pin itself. Keep alive while the link lives.
    pub fd: std::os::fd::OwnedFd,
    /// Encoded device of the OPEN file (fstat, not path stat).
    pub device: u64,
    /// Inode of the OPEN file (fstat, not path stat).
    pub ino: u64,
}

impl PinnedFile {
    /// Attach-path form for this pin: the kernel binds the open
    /// file description behind the fd, whatever the pathname
    /// says now (or whether it still exists).
    pub fn link_path(&self) -> String {
        use std::os::fd::AsRawFd as _;
        format!("/proc/self/fd/{}", self.fd.as_raw_fd())
    }
}

/// Open `path` and pin the open file's identity (H4): open FIRST,
/// then fstat THE FD. What the pathname says afterwards —
/// swapped, replaced, deleted — cannot move the pin. Compare
/// [`PinnedFile::device`]/[`PinnedFile::ino`] against the planned
/// identity; on mismatch drop the plan (loud `replaced`) having
/// bound nothing.
pub fn resolve_pinned(path: &str) -> std::io::Result<PinnedFile> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    Ok(pinned_from_metadata(file, meta))
}

fn pinned_from_metadata(file: std::fs::File, meta: std::fs::Metadata) -> PinnedFile {
    use std::os::unix::fs::MetadataExt as _;
    PinnedFile {
        fd: file.into(),
        device: encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
        ino: meta.ino(),
    }
}

pub(crate) fn resolve_pinned_controlled(
    path: &str,
    links: &crate::capture_setup::SetupLinks,
) -> std::io::Result<PinnedFile> {
    resolve_pinned_controlled_with(path, links, std::fs::File::metadata)
}
fn resolve_pinned_controlled_with(
    path: &str,
    links: &crate::capture_setup::SetupLinks,
    mut metadata: impl FnMut(&std::fs::File) -> std::io::Result<std::fs::Metadata>,
) -> std::io::Result<PinnedFile> {
    use crate::capture::BoundaryStage;
    use crate::capture_setup::{SetupFailure, SetupResource};
    let stage = BoundaryStage::Discovery;
    // The caller reserves the successful pin's one slot. Retain at most two
    // failed candidates plus the current attempt within the same four-slot cap.
    let control = links.control_for_effect();
    let _extra = match &control {
        Some(control) => Some(
            links
                .temporary(control, stage, (PIN_OPEN_ATTEMPTS - 1) as usize)
                .map_err(std::io::Error::other)?,
        ),
        None => None,
    };
    let mut retained = Vec::with_capacity(PIN_OPEN_ATTEMPTS as usize);
    let mut last = None;
    for _ in 0..PIN_OPEN_ATTEMPTS {
        links.check_owned(stage).map_err(std::io::Error::other)?;
        match std::fs::File::open(path) {
            Err(error) => last = Some(error),
            Ok(file) => {
                #[cfg(test)]
                links.test_retained_fd(std::os::fd::AsRawFd::as_raw_fd(&file));
                let file = SetupResource::guarded(file, links, stage);
                match metadata(&file) {
                    Ok(meta) => {
                        links.check_owned(stage).map_err(std::io::Error::other)?;
                        return Ok(pinned_from_metadata(file.into_inner(), meta));
                    }
                    Err(error) => {
                        last = Some(error);
                        retained.push(file);
                    }
                }
            }
        }
    }
    let error = last.expect("PIN_OPEN_ATTEMPTS >= 1");
    links.seal(SetupFailure::io(
        stage,
        &error,
        "setup pin metadata/open failed",
    ));
    links.before_dispose(stage);
    Err(error)
}
#[cfg(test)]
pub(crate) fn resolve_pinned_controlled_fault(
    path: &str,
    links: &crate::capture_setup::SetupLinks,
) -> std::io::Result<PinnedFile> {
    resolve_pinned_controlled_with(path, links, |_| {
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    })
}

/// Pin-open attempts (H4-T2): the initial open plus bounded
/// retries over transient absence (a rename swap landing
/// mid-open resolves in microseconds; the poll loop is the
/// slow retry). Mismatches are NOT retried here — open is
/// atomic, so a pin-vs-plan mismatch is deterministic, and
/// F-D/Am1 forbids installer maps re-reads; the fresh-maps
/// retry happens at the next-poll boundary instead.
pub const PIN_OPEN_ATTEMPTS: u32 = 3;

/// Open a pin with bounded retries over transient failure
/// (H4-T2). Returns the first success, else the LAST error
/// after exactly [`PIN_OPEN_ATTEMPTS`] attempts. The opener
/// is injected so tests script absence-then-presence;
/// production passes `|| resolve_pinned(path)`.
pub fn resolve_pinned_retry(
    mut open: impl FnMut() -> std::io::Result<PinnedFile>,
) -> std::io::Result<PinnedFile> {
    let mut err = None;
    for _ in 0..PIN_OPEN_ATTEMPTS {
        match open() {
            ok @ Ok(_) => return ok,
            Err(e) => err = Some(e),
        }
    }
    Err(err.expect("PIN_OPEN_ATTEMPTS >= 1"))
}

// H4 removed `verify_backing` and `binding_holds` (F-A/A1
// open-then-verify plus pre/post-sample attach binding): the fd
// pin subsumes both — the open file description IS the binding,
// so there is nothing to re-sample or compare after attach, and
// the old comment's "no userspace flow can pin the resolution"
// is superseded by fd-path attaches (proven in the H4 §4 spike).
// Design: docs/2026-10-11-h4-descriptor-custody-design.md §2.

/// One round's read of a mapped file: bytes plus the read-time
/// identity (F-A/A3). The identity binds the bytes to the mapping
/// they are looked up for — a same-path replacement between the
/// maps read and the files read must not lend the new file's bytes
/// (or fingerprint) to the old mapping. `dev` is the encoded
/// device (same domain as [`PinnedFile::device`]).
/// The payload has one shared immutable owner (R14 fix): the
/// verified-identity cache and every round output clone the `Arc`,
/// never the bytes — a cache→output handoff is a refcount bump,
/// not a per-poll full-payload copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBytes {
    pub bytes: std::sync::Arc<[u8]>,
    pub dev: u64,
    pub ino: u64,
}

/// Identity-bound byte lookup (F-A/A3): maps and files are round-consistent
/// sampled artifacts; lookup performs no fresh path stat. A replacement
/// between samples surfaces as an identity mismatch, while a replacement
/// after both leaves the round consistently old. Cross-mount-namespace
/// observation is out of model (operator co-locates; see attach-failures.md
/// pidns).
/// Identity-bound bytes lookup (F-A/A3, H5): serve `files[path]`
/// only when the entry's FULL identity matches the claim —
/// encoded stat-dev AND ino, both stat-domain. Ino-only used to
/// lend x-fs same-ino twins' bytes (B-4); the dev check closes
/// it. Callers pass the row's stat-dev (BackingRef-sourced) or a
/// fresh path fstat for path-exact lookups.
pub fn bound_bytes<'a>(
    files: &'a HashMap<String, FileBytes>,
    path: &str,
    dev: u64,
    ino: u64,
) -> Option<&'a [u8]> {
    let fb = files.get(path)?;
    if fb.dev != dev || fb.ino != ino {
        return None;
    }
    Some(&fb.bytes[..])
}

/// Per-object read bound (R14): no single relevant-file read may
/// hold more than this. Sized at the existing per-poll
/// cache-budget ceiling (capture's `MAX_CACHED_BYTES`) so one
/// object can never exceed the whole round's allowance on its own.
/// This value is a proposed resource policy for R14, not a
/// preexisting PRD maximum: an unusual legitimate object past this
/// bound is refused with `ErrorKind::FileTooLarge`, its rows miss
/// loud, and the run degrades to PARTIAL — never a completeness
/// claim.
pub const MAX_OBJECT_BYTES: usize = 128 * 1024 * 1024;

/// A readable object with a stable identity (R14): the production
/// source is an open `File` (fstat identity on the open file
/// description — same pin semantics as the pre-R14 reader); tests
/// inject scripted sources (mid-read growth, replacement) that no
/// filesystem timing can produce deterministically.
pub trait ReadBoundedSource: std::io::Read {
    /// (encoded stat-domain device, inode, advertised length) of
    /// the CURRENT object behind this source.
    fn bound_identity(&self) -> std::io::Result<(u64, u64, u64)>;
}

impl ReadBoundedSource for std::fs::File {
    fn bound_identity(&self) -> std::io::Result<(u64, u64, u64)> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = self.metadata()?;
        Ok((
            encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
            meta.ino(),
            meta.len(),
        ))
    }
}

fn too_large(max_bytes: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::FileTooLarge,
        format!("file exceeds {max_bytes}-byte read bound"),
    )
}

/// Bounded identity-bound read over an injected source (R14):
/// fstat the source, refuse a huge advertised length BEFORE
/// allocating, read at most `max_bytes + 1` (one
/// overflow-detection byte, so a mid-read grower cannot slip
/// past), then fstat identity/length again. Oversize (before or
/// during) is `ErrorKind::FileTooLarge`; a mid-read
/// identity/length change is `ErrorKind::InvalidData` (the
/// pre-R14 tear refusal, unchanged). Never allocates from the
/// advertised length.
pub fn read_bounded_from<S: ReadBoundedSource>(
    mut src: S,
    max_bytes: usize,
) -> std::io::Result<FileBytes> {
    read_bounded_source(&mut src, max_bytes)
}
fn read_bounded_source<S: ReadBoundedSource>(
    src: &mut S,
    max_bytes: usize,
) -> std::io::Result<FileBytes> {
    use std::io::Read as _;
    let (dev, ino, advertised) = src.bound_identity()?;
    // BEFORE: a huge advertised length refuses without reading a
    // byte (a sparse multi-gigabyte file costs one fstat, not a
    // multi-gigabyte Vec).
    if advertised > max_bytes as u64 {
        return Err(too_large(max_bytes));
    }
    // DURING: one overflow-detection byte past the cap; checked
    // arithmetic (an unrepresentable bound refuses, never wraps).
    let limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|m| m.checked_add(1))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unrepresentable read bound {max_bytes}"),
            )
        })?;
    let mut bytes = Vec::new();
    // Borrowed take: the source stays owned for the after-fstat.
    (&mut *src).take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(too_large(max_bytes));
    }
    // AFTER: same pin semantics as the pre-R14 reader — the object
    // behind the source must be unchanged in identity and length,
    // else the bytes may have torn across a replacement.
    let (dev_after, ino_after, len_after) = src.bound_identity()?;
    if dev != dev_after || ino != ino_after || advertised != len_after {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file changed mid-read",
        ));
    }
    Ok(FileBytes {
        bytes: bytes.into(),
        dev,
        ino,
    })
}

/// Identity-bound file read (F-A/A3), bounded (R14): open once,
/// fstat/read/fstat on the open description — the bytes cannot tear
/// across a replacement; a mid-read change (or unreadable path)
/// fails instead of returning mixed bytes. Reads past `max_bytes`
/// refuse with `ErrorKind::FileTooLarge` before and during the
/// read; callers skip the path and count loud loss.
pub fn read_file_bounded(path: &str, max_bytes: usize) -> std::io::Result<FileBytes> {
    let file = std::fs::File::open(path)?;
    read_bounded_from(file, max_bytes)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{path}: {e}")))
}

pub(crate) fn read_file_bounded_controlled(
    path: &str,
    max_bytes: usize,
    links: &crate::capture_setup::SetupLinks,
    stage: crate::capture::BoundaryStage,
    fatal: bool,
) -> std::io::Result<FileBytes> {
    let file = std::fs::File::open(path).map_err(|error| {
        if fatal {
            links.seal(crate::capture_setup::SetupFailure::io(
                stage,
                &error,
                "setup identity-bound file open failed",
            ));
        }
        error
    })?;
    let mut file = crate::capture_setup::SetupResource::guarded(file, links, stage);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_bounded_source(&mut *file, max_bytes)
    }));
    match result {
        Ok(result) => {
            if let Err(error) = &result
                && fatal
            {
                links.seal(crate::capture_setup::SetupFailure::io(
                    stage,
                    error,
                    "setup identity-bound file read failed",
                ));
            }
            links.before_dispose(stage);
            result.map_err(|e| std::io::Error::new(e.kind(), format!("{path}: {e}")))
        }
        Err(panic) => {
            links.seal(crate::capture_setup::SetupFailure::Boundary(
                crate::capture::BoundaryFailure::new(
                    stage,
                    crate::capture::BoundaryFailureClass::Panic,
                    None,
                    "setup identity-bound file read unwound",
                ),
            ));
            links.before_dispose(stage);
            std::panic::resume_unwind(panic)
        }
    }
}

/// Identity-bound file read (F-A/A3): open once, fstat/read/fstat —
/// the bytes cannot tear across a replacement; a mid-read change
/// (or unreadable path) fails instead of returning mixed bytes.
/// Capped at [`MAX_OBJECT_BYTES`] per object (R14); callers with a
/// tighter remaining round budget prefer [`read_file_bounded`].
pub fn read_file_bound(path: &str) -> std::io::Result<FileBytes> {
    read_file_bounded(path, MAX_OBJECT_BYTES)
}

/// Plan every doc row against live mappings. `files` maps link-path
/// → identity-bound bytes (caller pre-reads each distinct mapped
/// path once). Fail-closed: malformed rows are an error, never a
/// skip.
pub fn plan(
    doc: &serde_json::Value,
    live: &[maps::Mapping],
    files: &HashMap<String, FileBytes>,
    generation: u32,
) -> anyhow::Result<Plan> {
    plan_stable(doc, live, files, generation, &mut StableCookies::default())
}

/// `plan` with caller-held cookie stability (fence re-plans reuse
/// cookies for surviving sites; fresh sites mint new ones).
pub fn plan_stable(
    doc: &serde_json::Value,
    live: &[maps::Mapping],
    files: &HashMap<String, FileBytes>,
    generation: u32,
    stable: &mut StableCookies,
) -> anyhow::Result<Plan> {
    let rows = doc
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("harvest doc has no rows array"))?;
    let mut typed = Vec::with_capacity(rows.len());
    for r in rows {
        let backing = r
            .get("backing")
            .ok_or_else(|| anyhow::anyhow!("harvest row lacks backing"))?;
        typed.push(PlanRow {
            dev: str_at(backing, "dev")?,
            ino: u64_at(backing, "ino")?,
            offset: u64_at(backing, "offset")?,
            id: Identity {
                provider: str_at(r, "provider")?,
                op: u32_at(r, "op")?,
                funcid: u32_at(r, "funcid")?,
                alg_class: str_at(r, "alg_class")?,
                offset: u64_at(backing, "offset")?,
            },
        });
    }
    plan_rows(&typed, live, files, generation, stable)
}

/// One typed plan row: physical backing + the candidate identity
/// riding it. The JSON harvest-doc path ([`plan_stable`]) and the
/// typed discovery-delta path (count session) both funnel through
/// [`plan_rows`], so validation and cookie identity cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRow {
    pub dev: String,
    pub ino: u64,
    pub offset: u64,
    pub id: Identity,
}

/// Memoized ELF parses (P6): one parse per bound file per
/// plan_rows call. The parse closure runs at most once per (path,
/// dev, ino) identity (unparseable files cache None); a same-path
/// replacement carries a new inode, so it re-parses. Call-local:
/// never outlives the `files` bytes of its own call.
type ElfCache<'b> = HashMap<(String, u64, u64), Option<goblin::elf::Elf<'b>>>;

fn cached_elf_parse<'m, 'b>(
    cache: &'m mut ElfCache<'b>,
    path: &str,
    dev: u64,
    ino: u64,
    parse: impl FnOnce() -> Option<goblin::elf::Elf<'b>>,
) -> Option<&'m goblin::elf::Elf<'b>> {
    cache
        .entry((path.to_owned(), dev, ino))
        .or_insert_with(parse)
        .as_ref()
}

/// Plan typed rows against live mappings. `files` maps link-path →
/// identity-bound bytes (caller pre-reads each distinct mapped path
/// once). Fail-closed: malformed rows are an error, never a skip.
/// Dedup and cookie identity key on verified physical backing
/// (dev, ino, offset) — the same inode through another path aliases
/// under one cookie, while a replacement inode mints a new one.
pub fn plan_rows(
    rows: &[PlanRow],
    live: &[maps::Mapping],
    files: &HashMap<String, FileBytes>,
    generation: u32,
    stable: &mut StableCookies,
) -> anyhow::Result<Plan> {
    let mut out = Plan {
        entries: Vec::new(),
        missed: Vec::new(),
        generation,
    };
    let mut seen: HashMap<(String, u64, u64), usize> = HashMap::new();
    let mut elfs: ElfCache<'_> = HashMap::new();
    for r in rows {
        let dev = r.dev.clone();
        let ino = r.ino;
        let id = r.id.clone();
        // Row device (H5/B-4): the stat-domain `MM:mm` binding
        // (BackingRef via H5-T1) — parsed to the encoded
        // identity; an unparsable row binds nothing (loud miss,
        // never device zero).
        let Some(row_dev) = device_id_of_dev_str(&dev) else {
            out.missed.push(Missed {
                dev,
                ino,
                offset: r.offset,
                reason: "unmapped",
            });
            continue;
        };
        // Candidate link paths: X mappings sharing the row's
        // inode (H5: ino is the domain-agnostic prefilter; the
        // device binds at the byte read, never via maps text —
        // x-subvol/x-mount twins share maps-dev + ino).
        let mut cands: Vec<&str> = live
            .iter()
            .filter(|m| m.x && m.ino != 0 && m.ino == ino)
            .map(|m| m.path.as_str())
            .collect();
        cands.sort_unstable();
        cands.dedup();
        // First candidate whose bytes bind to the ROW's full
        // (dev, ino) identity (H5/B-4): an x-fs same-ino twin
        // lends nothing even when the path matches, and a
        // same-path replacement between the maps read and the
        // files read lends nothing to the old row.
        let bound = cands
            .iter()
            .find_map(|p| bound_bytes(files, p, row_dev, ino).map(|b| (*p, b)));
        let Some((path, bytes)) = bound else {
            out.missed.push(Missed {
                dev,
                ino,
                offset: r.offset,
                reason: if cands.is_empty() {
                    "unmapped"
                } else {
                    "unreadable"
                },
            });
            continue;
        };
        if r.offset >= bytes.len() as u64 {
            out.missed.push(Missed {
                dev,
                ino,
                offset: r.offset,
                reason: "past-eof",
            });
            continue;
        }
        let parsed = cached_elf_parse(&mut elfs, path, row_dev, ino, || elf::parse_elf(bytes).ok());
        let reason = match parsed {
            Some(e) if elf::offset_in_x_segment(e, r.offset) => None,
            Some(_) => Some("not-executable"),
            None => Some("unreadable"),
        };
        if let Some(reason) = reason {
            out.missed.push(Missed {
                dev,
                ino,
                offset: r.offset,
                reason,
            });
            continue;
        }
        // Shared implementation: alias under the canonical cookie.
        // Keyed by physical backing, not by the chosen link path, so
        // the same file reached through another alias cannot mint a
        // second cookie for the same site.
        let key = (dev.clone(), ino, r.offset);
        if let Some(&i) = seen.get(&key) {
            out.entries[i].aliases.push(id);
            continue;
        }
        let cookie = stable.cookie_for(&dev, ino, r.offset)?;
        seen.insert(key, out.entries.len());
        out.entries.push(Entry {
            path: path.to_string(),
            offset: r.offset,
            cookie,
            id,
            aliases: Vec::new(),
        });
    }
    Ok(out)
}

/// Group entries by link path (sorted by path, offsets ascending —
/// deterministic link order for stable behavior + diffable logs).
pub fn groups(plan: &Plan) -> Vec<Group> {
    let mut by_path: HashMap<&str, Vec<&Entry>> = HashMap::new();
    for e in &plan.entries {
        by_path.entry(e.path.as_str()).or_default().push(e);
    }
    let mut paths: Vec<&str> = by_path.keys().copied().collect();
    paths.sort_unstable();
    paths
        .into_iter()
        .map(|p| {
            let mut es = by_path.remove(p).unwrap();
            es.sort_by_key(|e| e.offset);
            Group {
                path: p.to_string(),
                offsets: es.iter().map(|e| e.offset).collect(),
                cookies: es.iter().map(|e| e.cookie as u64).collect(),
            }
        })
        .collect()
}

/// One multi link over `path` (production `bisect_attach` leaf).
pub fn attach_group(
    prog_fd: RawFd,
    pid: u32,
    path: &str,
    offsets: &[u64],
    cookies: &[u64],
) -> std::io::Result<OwnedFd> {
    let cpath = CString::new(path)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in link path"))?;
    ossl_bpf_sys::link_create_uprobe_multi(prog_fd, &cpath, offsets, cookies, pid)
}

/// Permission-class failures are systemic (caps/LSM), never
/// per-offset: fail the whole slice without a retry storm.
fn is_permission_err(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
}

/// Attach one group's sites, bisecting attach errors to isolate
/// kernel-rejected offsets (bounded: ≤ 2n−1 attempts, log n depth).
/// `attach` tries a slice as ONE multi link. Only permission-class
/// errors fail the whole slice; anything else (EINVAL, unknown
/// kernel errnos — RHEL returns 524 for un-attachable offsets)
/// bisects, so one poison offset cannot sink good siblings.
/// Returns live links + refused site indices (→ `unresolved_offsets`).
/// Generic over the link handle so the isolation logic unit-tests
/// without caps or fds; production passes `attach_group`.
pub type TryAttach<'a, T> = dyn Fn(&[(u64, u64)]) -> std::io::Result<T> + 'a;

pub fn bisect_attach<T>(attach: &TryAttach<'_, T>, sites: &[(u64, u64)]) -> (Vec<T>, Vec<usize>) {
    let mut links = Vec::new();
    let mut bad = Vec::new();
    let mut stack: Vec<Vec<usize>> = vec![(0..sites.len()).collect()];
    while let Some(idxs) = stack.pop() {
        if idxs.is_empty() {
            continue;
        }
        let slice: Vec<(u64, u64)> = idxs.iter().map(|&i| sites[i]).collect();
        match attach(&slice) {
            Ok(l) => links.push(l),
            Err(e) if !is_permission_err(&e) && idxs.len() > 1 => {
                let mid = idxs.len() / 2;
                stack.push(idxs[mid..].to_vec());
                stack.push(idxs[..mid].to_vec());
            }
            Err(_) => bad.extend(idxs),
        }
    }
    bad.sort_unstable();
    (links, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real executable bytes (self): offsets derived from its own
    /// program headers (same precedent as elf::tests::self_bytes).
    fn self_bytes() -> Vec<u8> {
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    }

    /// (in-X-LOAD offset, in-file-but-not-X offset) from real phdrs.
    fn probe_offsets(bytes: &[u8]) -> (u64, u64) {
        use goblin::elf::program_header::{PF_X, PT_LOAD};
        let e = elf::parse_elf(bytes).unwrap();
        let x = e
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
            .unwrap();
        let r = e
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X == 0)
            .unwrap();
        (x.p_offset + 8, r.p_offset + 8)
    }

    fn row(op: u32, funcid: u32, dev: &str, ino: u64, off: u64) -> serde_json::Value {
        serde_json::json!({
            "provider": "spike", "op": op, "alg_class": "digest", "funcid": funcid,
            "backing": {"dev": dev, "ino": ino, "offset": off},
        })
    }

    fn mapping(dev: &str, ino: u64, path: &str) -> maps::Mapping {
        maps::Mapping {
            start: 0x7f00_0000_0000,
            end: 0x7f00_0000_1000,
            x: true,
            offset: 0,
            dev: dev.to_string(),
            ino,
            path: path.to_string(),
        }
    }

    fn doc(rows: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"provider": "spike", "rows": rows})
    }

    fn file_bytes(bytes: Vec<u8>, ino: u64) -> FileBytes {
        FileBytes {
            bytes: bytes.into(),
            dev: device_id_of_dev_str("08:01").unwrap(),
            ino,
        }
    }

    #[test]
    fn plan_entries_aliases_groups() {
        let bytes = self_bytes();
        let (x_off, _) = probe_offsets(&bytes);
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), file_bytes(bytes, 99))]);
        let d = doc(vec![
            row(1, 7, "08:01", 99, x_off),
            row(1, 9, "08:01", 99, x_off + 0x40),
            row(2, 7, "08:01", 99, x_off), // alias: same impl
        ]);
        let p = plan(&d, &live, &files, 3).unwrap();
        assert_eq!(p.generation, 3);
        assert!(p.missed.is_empty(), "{:?}", p.missed);
        assert_eq!(p.entries.len(), 2);
        assert_eq!((p.entries[0].cookie, p.entries[1].cookie), (0, 1));
        assert_eq!(p.entries[0].aliases.len(), 1);
        assert_eq!(p.entries[0].aliases[0].op, 2);
        let g = groups(&p);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].offsets, vec![x_off, x_off + 0x40]);
        assert_eq!(g[0].cookies, vec![0, 1]);
    }

    #[test]
    fn elf_cache_parses_once_per_identity() {
        // P6: plan_rows memoized per-file ELF parses — the per-row
        // parse stalled count attach ~2.5s (414 rows × full goblin
        // parse). The parse closure runs once per (path, dev, ino);
        // unparseable files cache None; distinct identities
        // re-parse.
        use std::cell::Cell;
        let bytes = self_bytes();
        let garbage = vec![0u8; 64];
        let calls = Cell::new(0u32);
        let mut cache: ElfCache<'_> = HashMap::new();
        let e1 = cached_elf_parse(&mut cache, "/lib/a.so", 8, 100, || {
            calls.set(calls.get() + 1);
            elf::parse_elf(&bytes).ok()
        });
        assert!(e1.is_some());
        let e2 = cached_elf_parse(&mut cache, "/lib/a.so", 8, 100, || {
            calls.set(calls.get() + 1);
            elf::parse_elf(&bytes).ok()
        });
        assert!(e2.is_some());
        assert_eq!(calls.get(), 1, "same identity parses once");
        let e3 = cached_elf_parse(&mut cache, "/lib/b.so", 8, 101, || {
            calls.set(calls.get() + 1);
            elf::parse_elf(&bytes).ok()
        });
        assert!(e3.is_some());
        assert_eq!(calls.get(), 2, "distinct identity re-parses");
        let n1 = cached_elf_parse(&mut cache, "/lib/z.so", 8, 102, || {
            calls.set(calls.get() + 1);
            elf::parse_elf(&garbage).ok()
        });
        assert!(n1.is_none());
        let n2 = cached_elf_parse(&mut cache, "/lib/z.so", 8, 102, || {
            calls.set(calls.get() + 1);
            elf::parse_elf(&bytes).ok()
        });
        assert!(n2.is_none(), "absence caches too");
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn plan_missed_matrix() {
        let bytes = self_bytes();
        let (x_off, r_off) = probe_offsets(&bytes);
        let eof_off = bytes.len() as u64 + 8;
        let live = vec![
            mapping("08:01", 99, "/lib/spike.so"),
            mapping("08:01", 100, "/lib/gone.so"), // no bytes
        ];
        let files = HashMap::from([("/lib/spike.so".to_string(), file_bytes(bytes, 99))]);
        let d = doc(vec![
            row(1, 1, "08:01", 4242, x_off), // unmapped
            row(1, 2, "08:01", 100, x_off),  // unreadable
            row(1, 3, "08:01", 99, eof_off), // past-eof
            row(1, 4, "08:01", 99, r_off),   // not-executable
        ]);
        let p = plan(&d, &live, &files, 0).unwrap();
        assert!(p.entries.is_empty());
        let reasons: Vec<&str> = p.missed.iter().map(|m| m.reason).collect();
        assert_eq!(
            reasons,
            vec!["unmapped", "unreadable", "past-eof", "not-executable"]
        );
    }

    #[test]
    fn plan_rejects_malformed_rows() {
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), file_bytes(self_bytes(), 99))]);
        assert!(plan(&serde_json::json!({}), &live, &files, 0).is_err());
        assert!(plan(&doc(vec![serde_json::json!({"op": 1})]), &live, &files, 0).is_err());
        let mut bad = row(1, 1, "08:01", 99, 0x1010);
        bad["op"] = serde_json::json!(u64::from(u32::MAX) + 1);
        assert!(plan(&doc(vec![bad]), &live, &files, 0).is_err());
    }

    /// Stub multi attach: `errno` iff the slice holds a poison offset.
    fn poisoned_with(
        poison: Vec<u64>,
        errno: i32,
    ) -> impl Fn(&[(u64, u64)]) -> std::io::Result<()> {
        move |slice: &[(u64, u64)]| {
            if slice.iter().any(|(o, _)| poison.contains(o)) {
                Err(std::io::Error::from_raw_os_error(errno))
            } else {
                Ok(())
            }
        }
    }

    /// Stub multi attach: EINVAL iff the slice holds a poison offset.
    fn poisoned(poison: Vec<u64>) -> impl Fn(&[(u64, u64)]) -> std::io::Result<()> {
        poisoned_with(poison, libc::EINVAL)
    }

    #[test]
    fn bisect_isolates_poison() {
        let sites: Vec<(u64, u64)> = (0..8u64).map(|i| (0x1000 + i * 8, i)).collect();
        let (links, bad) = bisect_attach(&poisoned(vec![0x1018, 0x1030]), &sites);
        assert_eq!(links.len(), 4);
        assert_eq!(bad, vec![3, 6]);
        let (links, bad) = bisect_attach(&poisoned(vec![]), &sites);
        assert_eq!(links.len(), 1);
        assert!(bad.is_empty());
    }

    #[test]
    fn bisect_isolates_nonstandard_errno() {
        // RHEL returns 524 (no libc string) for un-attachable
        // offsets; it must bisect like EINVAL, not sink the batch.
        let sites: Vec<(u64, u64)> = (0..8u64).map(|i| (0x1000 + i * 8, i)).collect();
        let (links, bad) = bisect_attach(&poisoned_with(vec![0x1018, 0x1030], 524), &sites);
        assert_eq!(links.len(), 4);
        assert_eq!(bad, vec![3, 6]);
    }

    #[test]
    fn bisect_fails_fast_on_permission_err() {
        // Systemic EPERM: one attempt, whole slice condemned, no storm.
        use std::cell::Cell;
        let sites: Vec<(u64, u64)> = (0..8u64).map(|i| (0x1000 + i * 8, i)).collect();
        let calls = Cell::new(0u32);
        let stub = |_slice: &[(u64, u64)]| -> std::io::Result<()> {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        };
        let (links, bad) = bisect_attach(&stub, &sites);
        assert!(links.is_empty());
        assert_eq!(bad, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn stable_cookies_survive_replan() {
        let bytes = self_bytes();
        let (x_off, _) = probe_offsets(&bytes);
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), file_bytes(bytes, 99))]);
        let mut stable = StableCookies::default();
        let p0 = plan_stable(
            &doc(vec![
                row(1, 7, "08:01", 99, x_off),
                row(1, 9, "08:01", 99, x_off + 0x40),
            ]),
            &live,
            &files,
            0,
            &mut stable,
        )
        .unwrap();
        assert_eq!((p0.entries[0].cookie, p0.entries[1].cookie), (0, 1));
        // Re-plan: one survivor (reordered), one fresh site.
        let p1 = plan_stable(
            &doc(vec![
                row(1, 9, "08:01", 99, x_off + 0x40),
                row(3, 1, "08:01", 99, x_off + 0x80),
            ]),
            &live,
            &files,
            1,
            &mut stable,
        )
        .unwrap();
        assert_eq!(p1.entries[0].cookie, 1); // survivor keeps 1
        assert_eq!(p1.entries[1].cookie, 2); // fresh mints 2
    }

    #[test]
    fn bisect_non_einval_fails_slice() {
        let sites: Vec<(u64, u64)> = (0..4u64).map(|i| (0x1000 + i * 8, i)).collect();
        let (links, bad) = bisect_attach::<()>(
            &|_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            &sites,
        );
        assert!(links.is_empty());
        assert_eq!(bad, vec![0, 1, 2, 3]);
    }

    #[test]
    fn maps_dev_codec_roundtrips() {
        // Hex major:minor, including a device-mapper-shaped major.
        assert_eq!(parse_dev_str("08:01"), Some((8, 1)));
        assert_eq!(parse_dev_str("fd:00"), Some((253, 0)));
        assert_eq!(parse_dev_str("0:0"), Some((0, 0)));
        assert_eq!(parse_dev_str(""), None);
        assert_eq!(parse_dev_str("08"), None);
        assert_eq!(parse_dev_str("08:"), None);
        assert_eq!(parse_dev_str(":01"), None);
        assert_eq!(parse_dev_str("zz:01"), None);
        assert_eq!(parse_dev_str("08:01:02"), None);
        for (major, minor) in [(8u32, 1u32), (253, 0), (0, 0), (259, 3)] {
            let id = encode_device(major, minor);
            assert_eq!(decode_device(id), (major, minor));
            assert_eq!(device_id_of_dev_str(&render_device(id)), Some(id));
        }
        assert_eq!(device_id_of_dev_str("bogus"), None);
    }

    // H4 removed `verify_backing_checks_open_file` with
    // `verify_backing`: the pin fstats the open fd itself (no
    // path-vs-plan comparison exists to test at this layer —
    // callers compare, pinned by the count-session H4 tests).

    #[test]
    fn h4_t2_pin_open_retries_bounded_then_fails() {
        // H4: the pin open retries transient absence (a swap
        // landing mid-open) — bounded, then the last error
        // surfaces. Mismatches are NOT retried here (open is
        // atomic: a mismatch is deterministic, and F-D/Am1
        // forbids installer maps re-reads — fresh-maps retry
        // happens at the next-poll boundary, not here).
        use std::cell::Cell;
        use std::os::fd::AsRawFd as _;
        // First-try success: one attempt.
        let attempts = Cell::new(0u32);
        let exe = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let pin = resolve_pinned_retry(|| {
            attempts.set(attempts.get() + 1);
            resolve_pinned(&exe)
        })
        .expect("first-try open succeeds");
        assert_eq!(attempts.get(), 1);
        assert_eq!(
            pin.link_path(),
            format!("/proc/self/fd/{}", pin.fd.as_raw_fd()),
            "link_path form"
        );
        // Absent-then-present: the retry lands it.
        let attempts2 = Cell::new(0u32);
        let pin2 = resolve_pinned_retry(|| {
            attempts2.set(attempts2.get() + 1);
            if attempts2.get() < 2 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "swap in flight",
                ))
            } else {
                resolve_pinned(&exe)
            }
        })
        .expect("retry succeeds");
        assert_eq!(attempts2.get(), 2);
        assert_eq!(pin2.ino, pin.ino, "same file pinned");
        // Persistent failure: EXACTLY the bound, last error kept.
        let attempts3 = Cell::new(0u32);
        let err = resolve_pinned_retry(|| {
            attempts3.set(attempts3.get() + 1);
            Err::<PinnedFile, _>(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"))
        })
        .expect_err("persistent absence must fail");
        assert_eq!(attempts3.get(), PIN_OPEN_ATTEMPTS);
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    // H4 removed `attach_binding_needs_expected_identity` with
    // `binding_holds`: no post-attach binding decision exists
    // anymore — the fd IS the pin (the A→B→A race is
    // unrepresentable, pinned by H4-T1 at the caller).

    #[test]
    fn bound_bytes_requires_identity_match() {
        // A3/H5(B-4): bytes bind to the full (dev, ino) identity
        // — a same-path replacement between the maps read and
        // the files read must not lend the new file's bytes to
        // the old mapping.
        let files: HashMap<String, FileBytes> = HashMap::from([
            (
                "old.so".to_string(),
                FileBytes {
                    bytes: b"v1".to_vec().into(),
                    dev: 1,
                    ino: 100,
                },
            ),
            (
                "new.so".to_string(),
                FileBytes {
                    bytes: b"v2".to_vec().into(),
                    dev: 1,
                    ino: 200,
                },
            ),
        ]);
        assert_eq!(
            bound_bytes(&files, "old.so", 1, 100),
            Some(b"v1".as_slice())
        );
        // Same path, replaced bytes: the old mapping binds nothing.
        assert_eq!(bound_bytes(&files, "old.so", 1, 200), None);
        assert_eq!(bound_bytes(&files, "new.so", 1, 100), None);
        assert_eq!(bound_bytes(&files, "missing.so", 1, 100), None);
    }

    #[test]
    fn h5_t2_bound_bytes_refuses_xfs_same_ino() {
        // H5 (B-4): bytes bind to the FULL (dev, ino) identity —
        // an x-fs same-ino twin (same ino, different device) lends
        // nothing, even when the path matches. Both sides are
        // stat-domain (encoded dev_t); the row's stat-dev arrives
        // via BackingRef (H5-T1). RED pre-H5 (ino-only).
        let files: HashMap<String, FileBytes> = HashMap::from([(
            "twin.so".to_string(),
            FileBytes {
                bytes: b"v1".to_vec().into(),
                dev: 0x1111,
                ino: 100,
            },
        )]);
        assert_eq!(
            bound_bytes(&files, "twin.so", 0x1111, 100),
            Some(b"v1".as_slice()),
            "exact identity binds"
        );
        assert_eq!(
            bound_bytes(&files, "twin.so", 0x2222, 100),
            None,
            "x-fs twin (same ino, other dev) must not lend"
        );
        assert_eq!(
            bound_bytes(&files, "twin.so", 0x1111, 200),
            None,
            "replaced ino must not lend"
        );
    }

    #[test]
    fn resolve_pinned_stats_the_open_file() {
        // H4 successor to sample_backing_matches_stat: the pin
        // carries the OPEN file's fstat identity (not a path
        // sample), and a missing path fails (open error, not a
        // silent pass).
        use std::os::unix::fs::MetadataExt as _;
        let exe = std::env::current_exe().unwrap();
        let meta = std::fs::metadata(&exe).unwrap();
        let pin = resolve_pinned(exe.to_str().unwrap()).unwrap();
        assert_eq!(
            (pin.device, pin.ino),
            (
                encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
                meta.ino()
            )
        );
        assert!(resolve_pinned("/nonexistent-osslscope-probe-path").is_err());
    }

    #[test]
    fn typed_rows_alias_by_backing_not_path() {
        // Same (dev, ino, offset) reached through two alias link
        // paths plans ONE entry under ONE cookie.
        let bytes = self_bytes();
        let (x_off, _) = probe_offsets(&bytes);
        let live = vec![
            mapping("08:01", 99, "/lib/spike.so"),
            mapping("08:01", 99, "/mnt/alias/spike.so"),
        ];
        let files = HashMap::from([
            ("/lib/spike.so".to_string(), file_bytes(bytes.clone(), 99)),
            ("/mnt/alias/spike.so".to_string(), file_bytes(bytes, 99)),
        ]);
        let mk = |provider: &str| PlanRow {
            dev: "08:01".to_string(),
            ino: 99,
            offset: x_off,
            id: Identity {
                provider: provider.to_string(),
                op: 1,
                funcid: 7,
                alg_class: "digest".to_string(),
                offset: x_off,
            },
        };
        let mut stable = StableCookies::default();
        let p = plan_rows(&[mk("a"), mk("b")], &live, &files, 0, &mut stable).unwrap();
        assert!(p.missed.is_empty(), "{:?}", p.missed);
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].aliases.len(), 1);
        assert_eq!(stable.len(), 1);
        assert_eq!(stable.lookup("08:01", 99, x_off), Some(0));
        // A replacement inode at the same offset mints a new cookie.
        let mk2 = PlanRow {
            dev: "08:01".to_string(),
            ino: 100,
            offset: x_off,
            id: Identity {
                provider: "a".to_string(),
                op: 1,
                funcid: 7,
                alg_class: "digest".to_string(),
                offset: x_off,
            },
        };
        let live2 = vec![mapping("08:01", 100, "/lib/spike.so")];
        // A3: the replacement inode's bytes arrive under their own
        // binding — the old ino-99 read no longer lends to ino 100.
        let files2 = HashMap::from([("/lib/spike.so".to_string(), file_bytes(self_bytes(), 100))]);
        let p2 = plan_rows(std::slice::from_ref(&mk2), &live2, &files2, 1, &mut stable).unwrap();
        assert_eq!(p2.entries.len(), 1);
        assert_eq!(p2.entries[0].cookie, 1);
        assert_eq!(stable.lookup("08:01", 99, x_off), Some(0));
    }
}

#[cfg(test)]
mod fix1_pin_retry_tests {
    use super::*;
    #[test]
    fn w079_fix1_real_file_retry_then_success() {
        use std::os::fd::AsRawFd as _;
        let links = crate::capture_setup::SetupLinks::new();
        let mut calls = 0;
        let pinned = resolve_pinned_controlled_with("/dev/null", &links, |file| {
            calls += 1;
            if calls < PIN_OPEN_ATTEMPTS {
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            } else {
                file.metadata()
            }
        })
        .unwrap();
        let fds = links.test_fds();
        let successes = fds
            .iter()
            .flatten()
            .filter(|fd| **fd == pinned.fd.as_raw_fd())
            .count();
        assert_eq!(calls, PIN_OPEN_ATTEMPTS);
        assert_eq!(successes, 1);
        assert!(
            fds.iter()
                .flatten()
                .filter(|fd| **fd != pinned.fd.as_raw_fd())
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) == -1 })
        );
        drop(pinned);
        assert!(
            fds.iter()
                .flatten()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) == -1 })
        );
    }
}
