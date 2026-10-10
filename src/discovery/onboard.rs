//! SPDX-License-Identifier: GPL-3.0-or-later
//! Normal-application onboarding (T12/R09): automatic discovery of
//! installed BPF objects and supported target anchors, plus the
//! explicit override/local-enrollment behavior. `report`/`check`
//! resolve through this module and `doctor` vets through the same
//! functions, so diagnostics agree with the backend by construction.
//!
//! Contracts:
//! - BPF objects resolve from compiled trusted system locations,
//!   in fixed order, skipping untrusted (group/other-writable)
//!   directories and files. No cwd, no environment, no per-user
//!   paths are ever searched implicitly. Explicit `--object` /
//!   `--count-object` paths are operator-trusted but still checked
//!   for existence and loader-shape compatibility.
//! - Target anchors resolve from the object itself: a verified
//!   build-id table hit (anchor-checked, T09 rule) or the object's
//!   own symtab. The version-keyed anchor+delta rung needs an
//!   explicitly selected `--table` (or `--force-offset`); automatic
//!   discovery never guesses offsets for the wrong object.
//! - Qualification is three-way: Supported (attachable now),
//!   Unsupported (never supportable: wrong arch, non-OpenSSL
//!   flavor), Unknown (unenrolled stripped build: needs explicit
//!   local enrollment). Unsupported/Unknown are distinct from an
//!   actual inability to attach (caps, kernel, unreadable target).
//! - Provider class comes only from pinned enrollment or the
//!   operator builtin assertion (T09 [`resolve_provider_class`]);
//!   filenames are never class authority.
use crate::discovery::builtin::{self, Resolution};
use crate::discovery::flavor::{self, Flavor};
use crate::discovery::maps::Mapping;
use crate::discovery::provider::{self, ProviderClass, ProviderTable};
use crate::discovery::{elf, maps};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Actionable onboarding failure: what happened plus the operator's
/// fix. Callers render [`OnboardError::full`] (usage/exit-4 paths) or
/// map the fields into diagnostic rows (doctor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardError {
    pub message: String,
    pub remediation: String,
}

impl OnboardError {
    pub fn new(message: String, remediation: String) -> Self {
        OnboardError {
            message,
            remediation,
        }
    }

    /// Single-line rendering for stderr/exit paths.
    pub fn full(&self) -> String {
        format!("{}; fix: {}", self.message, self.remediation)
    }
}

impl fmt::Display for OnboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full())
    }
}

impl std::error::Error for OnboardError {}

// ---------------------------------------------------------------------------
// Installed BPF objects.
// ---------------------------------------------------------------------------

/// Installed harvest-object file name (matches the build artifact
/// name from `scripts/build-dev.sh`, no extension).
pub const HARVEST_OBJECT_NAME: &str = "osslscope-harvest";
/// Installed count-object file name (same naming rule).
pub const COUNT_OBJECT_NAME: &str = "osslscope-count";

/// Which BPF object a path/bytes claim to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRole {
    Harvest,
    Count,
}

impl ObjectRole {
    pub fn file_name(&self) -> &'static str {
        match self {
            ObjectRole::Harvest => HARVEST_OBJECT_NAME,
            ObjectRole::Count => COUNT_OBJECT_NAME,
        }
    }

    fn flag(&self) -> &'static str {
        match self {
            ObjectRole::Harvest => "--object",
            ObjectRole::Count => "--count-object",
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            ObjectRole::Harvest => "harvest",
            ObjectRole::Count => "count",
        }
    }
}

/// Trusted implicit search set, in order: operator-local prefix
/// first (a local install shadows the distro package), then the
/// distro tree. This list is the documented contract of which paths
/// a privileged invocation accepts implicitly (R09).
pub fn default_object_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/local/lib/osslscope"),
        PathBuf::from("/usr/local/lib64/osslscope"),
        PathBuf::from("/usr/lib/osslscope"),
        PathBuf::from("/usr/lib64/osslscope"),
    ]
}

/// Resolved BPF-object pair (mixed explicit/implicit provenance is
/// the operator's stated choice; see [`resolve_objects`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPaths {
    pub harvest: PathBuf,
    pub count: PathBuf,
}

/// Where implicit resolution looked (diagnostics/doctor only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectSearch {
    /// Trusted directories examined, in order.
    pub searched: Vec<PathBuf>,
    /// Directories skipped for trust (missing, not a dir, or
    /// group/other-writable), in order.
    pub skipped_untrusted: Vec<PathBuf>,
}

/// Who may own implicitly trusted objects. Production trusts
/// root-owned paths only, with ancestry checked: a trusted file in
/// a trusted dir under a writable ancestor is still swappable (via
/// rename), so every level must be trusted-owner-owned with no
/// group/other write bit. Mode bits alone are NOT enough (an
/// unprivileged owner of a 0755 dir can swap its files under a
/// privileged invocation).
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub trusted_uids: Vec<u32>,
    pub check_ancestry: bool,
}

impl TrustPolicy {
    /// Production trust: root-owned, ancestry-checked.
    pub fn production() -> Self {
        TrustPolicy {
            trusted_uids: vec![0],
            check_ancestry: true,
        }
    }
}

/// One metadata probe for the trust walk (injectable for tests).
struct LevelMeta {
    uid: u32,
    mode: u32,
    is_dir: bool,
}

fn real_meta(p: &Path) -> Option<LevelMeta> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    std::fs::metadata(p).ok().map(|m| LevelMeta {
        uid: m.uid(),
        mode: m.permissions().mode(),
        is_dir: m.is_dir(),
    })
}

/// One trusted directory level: a directory, owned by a trusted
/// uid, with no group/other write bit.
fn level_ok(m: &LevelMeta, trust: &TrustPolicy) -> bool {
    m.is_dir && trust.trusted_uids.contains(&m.uid) && m.mode & 0o022 == 0
}

/// Walk `dir` upward: every level (including `dir` itself, up
/// through `/`) must satisfy [`level_ok`]. Metadata comes from an
/// injected probe so the walk is unit-testable without root.
fn ancestry_ok_with(
    dir: &Path,
    trust: &TrustPolicy,
    meta: &dyn Fn(&Path) -> Option<LevelMeta>,
) -> bool {
    let mut cur = dir;
    loop {
        match meta(cur) {
            Some(m) if level_ok(&m, trust) => {}
            _ => return false,
        }
        match cur.parent() {
            Some(p) if p != cur => cur = p,
            _ => return true,
        }
    }
}

/// Trusted for implicit search under `trust`: the canonicalized
/// path is a trusted directory level, plus (when the policy asks)
/// a trusted ancestry above it.
pub fn is_trusted_dir_with(path: &Path, trust: &TrustPolicy) -> bool {
    let canon = match std::fs::canonicalize(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match real_meta(&canon) {
        Some(m) if level_ok(&m, trust) => {}
        _ => return false,
    }
    if trust.check_ancestry {
        if let Some(parent) = canon.parent() {
            return ancestry_ok_with(parent, trust, &real_meta);
        }
    }
    true
}

/// Trusted for implicit search (production policy).
pub fn is_trusted_dir(path: &Path) -> bool {
    is_trusted_dir_with(path, &TrustPolicy::production())
}

/// Trusted object file under `trust`: a regular file owned by a
/// trusted uid with no group/other write bit, in a trusted
/// ancestry (defense in depth alongside the directory check).
pub fn is_trusted_file_with(path: &Path, trust: &TrustPolicy) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let canon = match std::fs::canonicalize(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match std::fs::metadata(&canon) {
        Ok(m) => {
            if !(m.is_file() && trust.trusted_uids.contains(&m.uid())) {
                return false;
            }
            if m.permissions().mode() & 0o022 != 0 {
                return false;
            }
        }
        Err(_) => return false,
    }
    if trust.check_ancestry {
        if let Some(parent) = canon.parent() {
            return ancestry_ok_with(parent, trust, &real_meta);
        }
    }
    true
}

/// Trusted object file (production policy).
pub fn is_trusted_file(path: &Path) -> bool {
    is_trusted_file_with(path, &TrustPolicy::production())
}

/// Single-file read bound for qualification scans (libcrypto, exe,
/// BPF objects): real files are megabytes; anything past the bound
/// is refused rather than read into memory.
pub const MAX_OBJECT_SCAN_BYTES: u64 = 512 << 20;

/// Bounded file read: `Ok(bytes)` when the file fits, `Err` on I/O
/// or oversize. Reads at most `max + 1` bytes (no metadata-length
/// dependence, which races with writers anyway).
#[derive(Debug)]
pub enum ReadBoundedError {
    Io(std::io::Error),
    TooLarge(u64),
}

impl std::fmt::Display for ReadBoundedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadBoundedError::Io(e) => write!(f, "{e}"),
            ReadBoundedError::TooLarge(max) => {
                write!(f, "file exceeds {} MiB scan bound", max >> 20)
            }
        }
    }
}

pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, ReadBoundedError> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(ReadBoundedError::Io)?;
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(ReadBoundedError::Io)?;
    if buf.len() as u64 > max {
        return Err(ReadBoundedError::TooLarge(max));
    }
    Ok(buf)
}

/// Loader-shape compatibility: the same frozen `prepare` check the
/// backend runs at attach (same specs), so an object accepted here
/// cannot fail shape validation later, and an object rejected here
/// fails early with an actionable error instead of a late attach
/// failure. Pure over bytes (no caps needed).
pub fn check_object_compatible(role: ObjectRole, bytes: &[u8]) -> Result<(), String> {
    let r = match role {
        ObjectRole::Harvest => crate::loader::prepare(
            bytes,
            &crate::loader::HARVEST_MAPS,
            &crate::loader::HARVEST_PROGS,
        ),
        ObjectRole::Count => crate::loader::prepare(
            bytes,
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
        ),
    };
    r.map(|_| ()).map_err(|e| format!("{e:#}"))
}

/// Resolve the BPF-object pair: explicit paths win per role
/// (operator-trusted; existence + compatibility still checked); a
/// fully automatic pair comes from the first trusted directory
/// holding a complete compatible pair (matched builds stay
/// together — never one role from each of two installs). A broken
/// trusted directory (incompatible or writable objects) fails
/// closed instead of silently falling through.
pub fn resolve_objects(
    harvest: Option<&Path>,
    count: Option<&Path>,
    dirs: &[PathBuf],
    trust: &TrustPolicy,
) -> Result<(ObjectPaths, ObjectSearch), OnboardError> {
    let mut search = ObjectSearch::default();
    let h = match harvest {
        Some(p) => Some(resolve_explicit(ObjectRole::Harvest, p)?),
        None => None,
    };
    let c = match count {
        Some(p) => Some(resolve_explicit(ObjectRole::Count, p)?),
        None => None,
    };
    match (h, c) {
        (Some(h), Some(c)) => Ok((
            ObjectPaths {
                harvest: h,
                count: c,
            },
            search,
        )),
        (Some(h), None) => {
            let c = resolve_implicit_role(ObjectRole::Count, dirs, trust, &mut search)?;
            Ok((
                ObjectPaths {
                    harvest: h,
                    count: c,
                },
                search,
            ))
        }
        (None, Some(c)) => {
            let h = resolve_implicit_role(ObjectRole::Harvest, dirs, trust, &mut search)?;
            Ok((
                ObjectPaths {
                    harvest: h,
                    count: c,
                },
                search,
            ))
        }
        (None, None) => {
            let pair = resolve_implicit_pair(dirs, trust, &mut search)?;
            Ok((pair, search))
        }
    }
}

/// Validate one explicit object path (operator-trusted for trust,
/// still checked for existence + loader-shape compatibility).
pub fn resolve_explicit(role: ObjectRole, path: &Path) -> Result<PathBuf, OnboardError> {
    let bytes = read_bounded(path, MAX_OBJECT_SCAN_BYTES).map_err(|e| {
        OnboardError::new(
            format!(
                "explicit {} object {} missing or unreadable: {e}",
                role.describe(),
                path.display()
            ),
            format!(
                "pass a readable {} BPF object (built via scripts/build-dev.sh)",
                role.describe()
            ),
        )
    })?;
    check_object_compatible(role, &bytes).map_err(|reason| {
        OnboardError::new(
            format!(
                "explicit {} object {} incompatible: {reason}",
                role.describe(),
                path.display()
            ),
            format!(
                "rebuild matched objects with scripts/build-dev.sh, or omit {} to use the installed defaults",
                role.flag()
            ),
        )
    })?;
    Ok(path.to_path_buf())
}

/// Check one implicit candidate file: trust + readability +
/// loader-shape compatibility (shared by role and pair search).
/// Check-then-read TOCTOU is accepted: swapping the file between
/// the trust check and the read needs directory write access the
/// trust check itself excludes.
fn check_candidate(role: ObjectRole, cand: &Path, trust: &TrustPolicy) -> Result<(), OnboardError> {
    if !is_trusted_file_with(cand, trust) {
        return Err(OnboardError::new(
            format!(
                "{} object {} is untrusted (writable or wrong owner): refused",
                role.describe(),
                cand.display()
            ),
            "reinstall with safe ownership/permissions (root-owned, 0644)".to_string(),
        ));
    }
    let bytes = read_bounded(cand, MAX_OBJECT_SCAN_BYTES).map_err(|e| {
        OnboardError::new(
            format!(
                "{} object {} unreadable: {e}",
                role.describe(),
                cand.display()
            ),
            "check permissions on the installed objects".to_string(),
        )
    })?;
    check_object_compatible(role, &bytes).map_err(|reason| {
        OnboardError::new(
            format!(
                "{} object {} incompatible: {reason}",
                role.describe(),
                cand.display()
            ),
            "reinstall matched objects (host and BPF from one build); \
             a stale object after an upgrade is the usual cause"
                .to_string(),
        )
    })
}

fn note_dir(dir: &PathBuf, trust: &TrustPolicy, search: &mut ObjectSearch) {
    if is_trusted_dir_with(dir, trust) {
        if !search.searched.contains(dir) {
            search.searched.push(dir.clone());
        }
    } else if !search.skipped_untrusted.contains(dir) {
        search.skipped_untrusted.push(dir.clone());
    }
}

/// Resolve one role implicitly (the other role was explicit, so the
/// operator chose the mix): first trusted directory containing that
/// role's compatible object.
pub fn resolve_implicit_role(
    role: ObjectRole,
    dirs: &[PathBuf],
    trust: &TrustPolicy,
    search: &mut ObjectSearch,
) -> Result<PathBuf, OnboardError> {
    for dir in dirs {
        note_dir(dir, trust, search);
        if !is_trusted_dir_with(dir, trust) {
            continue;
        }
        let cand = dir.join(role.file_name());
        if !cand.exists() {
            continue;
        }
        check_candidate(role, &cand, trust)?;
        return Ok(cand);
    }
    let mut message = format!(
        "no BPF objects found for the {} role (searched {} trusted dirs)",
        role.describe(),
        search.searched.len()
    );
    if !search.skipped_untrusted.is_empty() {
        message.push_str(&format!(
            "; skipped {} untrusted dirs (missing, wrong owner, or writable)",
            search.skipped_untrusted.len()
        ));
    }
    Err(OnboardError::new(
        message,
        format!(
            "install objects to a trusted dir ({}) or pass {} explicitly",
            default_object_dirs()
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            role.flag()
        ),
    ))
}

/// Resolve the fully automatic pair: first trusted directory
/// holding a complete compatible pair. Incomplete directories are
/// skipped (partial installs never donate one role); a complete
/// but broken directory fails closed.
pub fn resolve_implicit_pair(
    dirs: &[PathBuf],
    trust: &TrustPolicy,
    search: &mut ObjectSearch,
) -> Result<ObjectPaths, OnboardError> {
    for dir in dirs {
        note_dir(dir, trust, search);
        if !is_trusted_dir_with(dir, trust) {
            continue;
        }
        let h = dir.join(ObjectRole::Harvest.file_name());
        let c = dir.join(ObjectRole::Count.file_name());
        if !h.exists() || !c.exists() {
            continue;
        }
        check_candidate(ObjectRole::Harvest, &h, trust)?;
        check_candidate(ObjectRole::Count, &c, trust)?;
        return Ok(ObjectPaths {
            harvest: h,
            count: c,
        });
    }
    let mut message = format!(
        "no BPF objects found (no trusted dir holds the harvest+count pair; searched {} trusted dirs)",
        search.searched.len()
    );
    if !search.skipped_untrusted.is_empty() {
        message.push_str(&format!(
            "; skipped {} untrusted dirs (missing, wrong owner, or writable)",
            search.skipped_untrusted.len()
        ));
    }
    Err(OnboardError::new(
        message,
        format!(
            "install objects to a trusted dir ({}) or pass --object/--count-object explicitly",
            default_object_dirs()
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ))
}

/// Read + validate an explicit offset-table file (`--table`): usage
/// shaped errors (the CLI maps these to exit 2 before any
/// target/BPF side effect).
/// Explicit table-file bound (tables are kilobytes; anything past
/// the bound is refused rather than parsed).
pub const MAX_TABLE_FILE_BYTES: u64 = 1 << 20;

fn read_table_text(flag: &str, path: &Path) -> Result<String, OnboardError> {
    let bytes = read_bounded(path, MAX_TABLE_FILE_BYTES).map_err(|e| {
        OnboardError::new(
            format!("{flag} {} unreadable: {e}", path.display()),
            "pass a readable JSON file".to_string(),
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        OnboardError::new(
            format!("{flag} {} is not UTF-8", path.display()),
            "pass a UTF-8 JSON file".to_string(),
        )
    })
}

pub fn load_offset_table_file(path: &Path) -> Result<builtin::Table, OnboardError> {
    let text = read_table_text("--table", path)?;
    builtin::load_table_str(&text).map_err(|e| {
        OnboardError::new(
            format!("--table {} invalid: {e:#}", path.display()),
            "fix the JSON (table_version 1; entries need build_id, \
             query_offset, anchor, anchor_offset)"
                .to_string(),
        )
    })
}

/// Read + validate an explicit provider-enrollment file
/// (`--provider-table`): same early usage-error shape.
pub fn load_enrollment_file(path: &Path) -> Result<ProviderTable, OnboardError> {
    let text = read_table_text("--provider-table", path)?;
    provider::load_table_str(&text).map_err(|e| {
        OnboardError::new(
            format!("--provider-table {} invalid: {e:#}", path.display()),
            "fix the JSON (table_version 1; entries need build_id and \
             provider_class default|legacy|fips|third-party)"
                .to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Target discovery + qualification.
// ---------------------------------------------------------------------------

/// libcrypto mapping outcome over a target's maps (deduped by backing
/// file; name match only — content qualification is separate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibcryptoMaps {
    One { path: String },
    None,
    Deleted,
    Multi { paths: Vec<String> },
}

/// Libcrypto file/name rule (single home): the dev symlink name
/// or a versioned soname. Maps discovery and `DT_NEEDED` matching
/// share it.
fn is_libcrypto_name(n: &str) -> bool {
    n == "libcrypto.so" || n.starts_with("libcrypto.so.")
}

/// Find mapped libcrypto by file basename (`libcrypto.so` or
/// `libcrypto.so.<version>`). Deleted mappings, non-file-backed
/// entries, and same-file duplicates are handled; two distinct files
/// are `Multi` (dual-load: refused fail-closed downstream).
pub fn libcrypto_from_maps(maps: &[Mapping]) -> LibcryptoMaps {
    let mut by_file: BTreeMap<(String, u64), String> = BTreeMap::new();
    let mut deleted_only = false;
    for m in maps {
        let deleted = m.path.ends_with("(deleted)");
        let clean = m.path.strip_suffix(" (deleted)").unwrap_or(m.path.as_str());
        let base = clean.rsplit('/').next().unwrap_or("");
        if !is_libcrypto_name(base) {
            continue;
        }
        if deleted {
            deleted_only = true;
            continue;
        }
        if m.ino == 0 {
            continue;
        }
        by_file
            .entry((m.dev.clone(), m.ino))
            .or_insert_with(|| m.path.clone());
    }
    let mut paths: Vec<String> = by_file.into_values().collect();
    match paths.len() {
        0 if deleted_only => LibcryptoMaps::Deleted,
        0 => LibcryptoMaps::None,
        1 => LibcryptoMaps::One {
            path: paths.pop().unwrap(),
        },
        _ => {
            paths.sort();
            LibcryptoMaps::Multi { paths }
        }
    }
}

/// Inputs for target qualification. The offset table is the shipped
/// frozen table by default or an explicitly selected local file;
/// `offset_table_explicit` records which (only explicit selection
/// unlocks the version-keyed anchor+delta rung). Enrollment is
/// explicit-only (empty = none enrolled).
pub struct QualifyOpts<'a> {
    pub offset_table: &'a builtin::Table,
    pub offset_table_explicit: bool,
    pub force_offset: Option<u64>,
    pub enrollment: &'a ProviderTable,
    pub builtin_asserted: bool,
}

/// A target the backend can attach to now.
#[derive(Debug, Clone)]
pub struct SupportedTarget {
    /// Provider file to attach to (libcrypto in builtin mode).
    pub provider_path: PathBuf,
    /// Observation mode: in-libcrypto default provider (true) vs a
    /// file provider's init pair (false).
    pub builtin: bool,
    /// Builtin-mode dispatch anchor (None in file-provider mode,
    /// where the init anchor is used instead).
    pub query_offset: Option<u64>,
    /// Which ladder rung resolved the anchor (None in file mode).
    pub resolution: Option<Resolution>,
    /// Verified GNU build-id, when the object carries one.
    pub build_id: Option<String>,
    /// OpenSSL line for display ("3.5"; "?" for file providers).
    pub openssl_display: String,
    /// T09 provider class (pinned enrollment, else builtin
    /// assertion, else unknown — never from a filename).
    pub provider_class: Option<ProviderClass>,
    /// Resolved from a static exe (no libcrypto mapped).
    pub static_exe: bool,
}

/// Three-way qualification: Supported (attach now), Unsupported
/// (never supportable), Unknown (needs explicit local enrollment).
/// Unsupported/Unknown carry the operator's reason + fix and are
/// distinct from an inability to attach (caps, kernel, access).
#[derive(Debug, Clone)]
pub enum TargetQualification {
    Supported(SupportedTarget),
    Unsupported { reason: String, remediation: String },
    Unknown { reason: String, remediation: String },
}

/// ELF machine names (single home; doctor renders the same strings).
pub fn arch_name(machine: u16) -> String {
    match machine {
        3 => "i386".into(),
        20 => "PowerPC".into(),
        21 => "PowerPC64".into(),
        22 => "s390x".into(),
        40 => "ARM".into(),
        62 => "x86-64".into(),
        183 => "AArch64".into(),
        243 => "RISC-V".into(),
        n => format!("EM_{n}"),
    }
}

/// Raw-header architecture gate (no parser dependence): x86-64 only.
/// Shared by qualification and doctor's arch row.
pub fn check_arch(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 20 {
        return Err(format!("file too small ({}B, truncated?)", bytes.len()));
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err("not an ELF binary (script or data?)".to_string());
    }
    match bytes[4] {
        2 => {}
        1 => return Err("32-bit target (ELFCLASS32)".to_string()),
        n => return Err(format!("unknown EI_CLASS {n}")),
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 62 {
        return Err(format!("arch {} (not x86-64)", arch_name(machine)));
    }
    Ok(())
}

const ENROLL_REMEDIATION: &str = "enroll this build with --table (measure the query offset \
     from an unstripped twin; see docs/builtin-runbook.md), or pass \
     --force-offset for a one-shot run";

/// Qualify libcrypto (or static-exe) bytes for builtin-mode dispatch
/// observation: arch → flavor → provider class → supported anchor.
/// The anchor ladder here is table-hit (anchor-verified) or symtab;
/// the anchor+delta rung runs only with an explicitly selected table
/// (`offset_table_explicit`), and `--force-offset` only when the
/// operator passed one. Never guesses.
pub fn qualify_libcrypto_bytes(
    bytes: &[u8],
    path: &Path,
    static_exe: bool,
    opts: &QualifyOpts,
) -> TargetQualification {
    let unsupported = |reason: String, remediation: &str| TargetQualification::Unsupported {
        reason,
        remediation: remediation.to_string(),
    };
    if let Err(e) = check_arch(bytes) {
        return unsupported(
            format!("{}: {e}", path.display()),
            "run against a 64-bit x86-64 OpenSSL build",
        );
    }
    let what = if static_exe {
        "static exe"
    } else {
        "libcrypto"
    };
    // Static candidates classify with symtab names unioned in (a
    // non-rdynamic static exe keeps anchors only in `.symtab`).
    let classified = if static_exe {
        flavor::classify_elf_with_symtab(bytes)
    } else {
        flavor::classify_elf(bytes)
    };
    let openssl_display = match classified {
        Ok((flavor, _)) => match flavor {
            Flavor::OpenSSL { major, minor } => match minor {
                Some(m) => format!("{major}.{m}"),
                None => format!("{major}.?"),
            },
            Flavor::BoringSSL => {
                return unsupported(
                    format!(
                        "{} is BoringSSL, not OpenSSL (provider model absent)",
                        path.display()
                    ),
                    "osslscope supports genuine OpenSSL 3.x/4.x only",
                );
            }
            Flavor::AwsLc => {
                return unsupported(
                    format!(
                        "{} is AWS-LC, not OpenSSL (provider model absent)",
                        path.display()
                    ),
                    "osslscope supports genuine OpenSSL 3.x/4.x only",
                );
            }
            Flavor::UnknownLookalike => {
                return unsupported(
                    format!(
                        "{} is an unrecognized crypto library (no OpenSSL anchors)",
                        path.display()
                    ),
                    "osslscope supports genuine OpenSSL 3.x/4.x only",
                );
            }
            Flavor::NotCrypto => {
                // Static candidates may still load OpenSSL at
                // runtime (dlopen): say so in the fix.
                let remediation = if static_exe {
                    "observe a process linked against OpenSSL 3.x/4.x (or pass its libcrypto with --provider if it loads OpenSSL at runtime)"
                } else {
                    "observe a process linked against OpenSSL 3.x/4.x"
                };
                return unsupported(
                    format!("{} is not OpenSSL (not a crypto library)", path.display()),
                    remediation,
                );
            }
        },
        Err(e) => {
            return unsupported(
                format!("{} bytes are not ELF ({e:#})", path.display()),
                "check which file the target maps",
            );
        }
    };
    let build_id = elf::read_build_id(bytes);
    let provider_class = provider::resolve_provider_class(&provider::ResolutionInputs {
        build_id: build_id.as_deref(),
        table: opts.enrollment,
        builtin_asserted: opts.builtin_asserted,
    });
    if let Some(force) = opts.force_offset {
        return TargetQualification::Supported(SupportedTarget {
            provider_path: path.to_path_buf(),
            builtin: true,
            query_offset: Some(force),
            resolution: Some(Resolution::Forced),
            build_id,
            openssl_display,
            provider_class,
            static_exe,
        });
    }
    // Table-hit identity is decided by the ladder: a table hit either
    // resolves (anchor verified) or bails (mismatch) — it never falls
    // through. So a ladder error with a table hit present IS the
    // mismatch case (bytes already parsed as ELF above, so the error
    // cannot be a parse failure).
    let table_hit = build_id
        .as_deref()
        .and_then(|id| opts.offset_table.by_build_id(id))
        .is_some();
    let resolved = if opts.offset_table_explicit {
        builtin::resolve_query_offset(bytes, opts.offset_table, None)
    } else {
        builtin::resolve_supported_offset(bytes, opts.offset_table)
    };
    match resolved {
        Ok((off, r)) => TargetQualification::Supported(SupportedTarget {
            provider_path: path.to_path_buf(),
            builtin: true,
            query_offset: Some(off),
            resolution: Some(r),
            build_id,
            openssl_display,
            provider_class,
            static_exe,
        }),
        Err(_) if table_hit => TargetQualification::Unknown {
            reason: format!(
                "local table identity mismatch for build {}: the enrolled anchor does not \
                 match this {what} (stale table or mislabeled build); no offset was used",
                build_id.as_deref().unwrap_or("?")
            ),
            remediation: "re-enroll this exact build (measure anchor + query offsets from \
                 an unstripped twin with a matching build-id)"
                .to_string(),
        },
        Err(_) => TargetQualification::Unknown {
            reason: match &build_id {
                Some(id) => {
                    format!("stripped build {id}: not enrolled and no symtab (no supported anchor)")
                }
                None => "no GNU build-id and no symtab (no supported anchor)".to_string(),
            },
            remediation: ENROLL_REMEDIATION.to_string(),
        },
    }
}

/// Qualify an explicit file-provider `.so`: arch → ELF → load-mandated
/// init anchor. No flavor ladder (a provider module is not
/// libcrypto); no guessed offsets (the init anchor is object-derived
/// or the file is refused).
pub fn qualify_file_provider_bytes(
    bytes: &[u8],
    path: &Path,
    opts: &QualifyOpts,
) -> TargetQualification {
    if let Err(e) = check_arch(bytes) {
        return TargetQualification::Unsupported {
            reason: format!("{}: {e}", path.display()),
            remediation: "run against a 64-bit x86-64 provider build".to_string(),
        };
    }
    if elf::parse_elf(bytes).is_err() {
        return TargetQualification::Unsupported {
            reason: format!("{} bytes are not ELF", path.display()),
            remediation: "pass the provider .so file".to_string(),
        };
    }
    let anchor = crate::discovery::session::INIT_ANCHOR;
    let has_init = elf::dynsym_file_offset(bytes, anchor).is_ok()
        || elf::symtab_file_offset(bytes, anchor).is_ok();
    if !has_init {
        return TargetQualification::Unsupported {
            reason: format!(
                "{} exports no {anchor} (not a loadable provider module)",
                path.display()
            ),
            remediation: "pass the provider .so (or libcrypto with --builtin)".to_string(),
        };
    }
    let build_id = elf::read_build_id(bytes);
    let provider_class = provider::resolve_provider_class(&provider::ResolutionInputs {
        build_id: build_id.as_deref(),
        table: opts.enrollment,
        builtin_asserted: opts.builtin_asserted,
    });
    TargetQualification::Supported(SupportedTarget {
        provider_path: path.to_path_buf(),
        builtin: false,
        query_offset: None,
        resolution: None,
        build_id,
        openssl_display: "?".to_string(),
        provider_class,
        static_exe: false,
    })
}

/// Discover + qualify a live pid's crypto target: mapped dynamic
/// libcrypto, else the static exe. IO failures (unreadable maps) are
/// `Err` (inability to attach, with its fix); discovered-but-bad
/// targets are `Ok(Unsupported/Unknown)` (qualification).
pub fn discover_pid(pid: u32, opts: &QualifyOpts) -> Result<TargetQualification, OnboardError> {
    let unsupported = |reason: String, remediation: &str| TargetQualification::Unsupported {
        reason,
        remediation: remediation.to_string(),
    };
    let maps = maps::read_maps(pid).map_err(|e| {
        // anyhow wraps the io error; downcast for the stable kind().
        let kind = e
            .downcast_ref::<std::io::Error>()
            .map(|io| io.kind().to_string())
            .unwrap_or_else(|| e.to_string());
        OnboardError::new(
            format!("cannot read target maps ({kind})"),
            "run as the target uid, or grant cap_sys_ptrace and re-run".to_string(),
        )
    })?;
    match libcrypto_from_maps(&maps) {
        LibcryptoMaps::One { path } => {
            let bytes = read_bounded(Path::new(&path), MAX_OBJECT_SCAN_BYTES).map_err(|e| {
                OnboardError::new(
                    format!("libcrypto file unreadable ({path}): {e}"),
                    "check the path/permissions (deleted underfoot?)".to_string(),
                )
            })?;
            Ok(qualify_libcrypto_bytes(
                &bytes,
                Path::new(&path),
                false,
                opts,
            ))
        }
        LibcryptoMaps::None => {
            // Static candidate: the exe itself may link OpenSSL.
            let exe_link = format!("/proc/{pid}/exe");
            let bytes = match read_bounded(Path::new(&exe_link), MAX_OBJECT_SCAN_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(unsupported(
                        format!("no libcrypto mapped and target exe unreadable: {e}"),
                        "run as the target uid, or grant cap_sys_ptrace and re-run",
                    ));
                }
            };
            Ok(qualify_libcrypto_bytes(
                &bytes,
                Path::new(&exe_link),
                true,
                opts,
            ))
        }
        LibcryptoMaps::Deleted => Ok(unsupported(
            "libcrypto mapping is (deleted) (upgraded underfoot?)".to_string(),
            "restart the target",
        )),
        LibcryptoMaps::Multi { paths } => Ok(unsupported(
            format!(
                "multiple libcrypto builds mapped (dual-load, ambiguous): {}",
                paths.join(", ")
            ),
            "run with a single libcrypto (dual-load refused fail-closed)",
        )),
    }
}

// ---------------------------------------------------------------------------
// Spawn prediction (pre-exec `run --` discovery).
// ---------------------------------------------------------------------------

/// Spawn environment for exe/loader prediction: explicit inputs so
/// prediction is deterministic and testable. Capture fills them
/// from the current process environment (the child inherits it).
pub struct SpawnEnv<'a> {
    pub path: &'a str,
    pub ld_library_path: Option<&'a str>,
}

/// Resolve a spawn argv[0] to a file (execvp rules): a slash means
/// the path itself, otherwise `PATH` order (empty components mean
/// cwd, like the loader). Best effort — discovery reads the file
/// next, so a missing file fails there with its own error.
pub fn resolve_spawn_exe(argv0: &str, env: &SpawnEnv) -> PathBuf {
    if argv0.contains('/') {
        return PathBuf::from(argv0);
    }
    for dir in env.path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let cand = Path::new(dir).join(argv0);
        if is_executable_file(&cand) {
            return cand;
        }
    }
    PathBuf::from(argv0)
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn is_regular_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

/// Fixed loader fallback directories (x86-64 system defaults,
/// multiarch first). `ld.so.cache` is deliberately NOT consulted:
/// it duplicates these defaults for system libraries, and a
/// cache-only custom prefix resolves via rpath/`LD_LIBRARY_PATH`
/// or explicit `--provider` instead.
pub fn default_loader_dirs() -> Vec<PathBuf> {
    [
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// `$ORIGIN` directory of an exe path (canonicalized: the loader
/// resolves through symlinks — `/proc/self/exe` — so `$ORIGIN`
/// anchors at the real exe dir even when argv[0] is a symlink).
fn origin_dir(exe: &Path) -> PathBuf {
    exe.canonicalize()
        .ok()
        .and_then(|c| c.parent().map(Path::to_path_buf))
        .or_else(|| {
            exe.parent()
                .map(Path::to_path_buf)
                .filter(|p| !p.as_os_str().is_empty())
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Expand `$ORIGIN`/`${ORIGIN}` (exe directory) in one search
/// component; other `$` variables stay unexpanded (no match).
fn expand_origin(component: &str, exe_dir: &Path) -> String {
    let dir = exe_dir.to_string_lossy();
    component
        .replace("${ORIGIN}", &dir)
        .replace("$ORIGIN", &dir)
}

/// Own-dirs phase of loader search (rpath/runpath/`LD_LIBRARY_PATH`
/// only — no fixed defaults). glibc order, empirically pinned:
/// RPATH wins over `LD_LIBRARY_PATH` when RUNPATH is absent; when
/// RUNPATH is present RPATH is ignored and `LD_LIBRARY_PATH` wins.
/// Empty components mean cwd (loader rule). `$ORIGIN` expands
/// against the MAIN exe (always the caller's `exe_path`, never the
/// needing dep). First regular file wins.
fn search_loader_own_dirs(
    filename: &str,
    exe_path: &Path,
    rpath: Option<&str>,
    runpath: Option<&str>,
    env: &SpawnEnv,
) -> Option<PathBuf> {
    let mut dirs: Vec<String> = Vec::new();
    match (rpath, runpath) {
        (_, Some(rp)) => {
            // RUNPATH present: LD wins, RPATH ignored.
            if let Some(ld) = env.ld_library_path {
                dirs.extend(ld.split(':').map(str::to_string));
            }
            dirs.extend(rp.split(':').map(str::to_string));
        }
        (Some(rp), None) => {
            // RPATH only: RPATH wins over LD_LIBRARY_PATH.
            dirs.extend(rp.split(':').map(str::to_string));
            if let Some(ld) = env.ld_library_path {
                dirs.extend(ld.split(':').map(str::to_string));
            }
        }
        (None, None) => {
            if let Some(ld) = env.ld_library_path {
                dirs.extend(ld.split(':').map(str::to_string));
            }
        }
    }
    let exe_dir = origin_dir(exe_path);
    for d in dirs {
        let d = if d.is_empty() {
            ".".to_string()
        } else {
            expand_origin(&d, &exe_dir)
        };
        let cand = Path::new(&d).join(filename);
        if is_regular_file(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Fixed-defaults phase of loader search (system dirs only, no
/// `$ORIGIN`: [`default_loader_dirs`]).
fn search_loader_defaults(filename: &str) -> Option<PathBuf> {
    for d in default_loader_dirs() {
        let cand = d.join(filename);
        if is_regular_file(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Predict which file the loader maps for `filename`: own dirs,
/// then fixed defaults. (`ld.so.cache` sits between RUNPATH and
/// defaults in the real loader and is deliberately skipped — see
/// [`default_loader_dirs`].) `None` when nothing matches (the
/// caller fails closed with explicit-`--provider` remediation).
///
/// Prediction mirrors the loader on purpose: the target resolves
/// the same way, so a hit predicts the actual file. The predicted
/// file is content-qualified before use, and a wrong prediction
/// degrades to zero-rows PARTIAL (probes attach to a file the
/// target never maps) — never wrong attribution.
///
/// NOTE: the closure walk does not call this directly — the exe's
/// transitive RPATH must be consulted BEFORE fixed defaults for
/// deeper levels (glibc rule), so the walk composes the phases
/// itself (own dirs → transitive RPATH → defaults).
pub fn search_loader_file(
    filename: &str,
    exe_path: &Path,
    rpath: Option<&str>,
    runpath: Option<&str>,
    env: &SpawnEnv,
) -> Option<PathBuf> {
    search_loader_own_dirs(filename, exe_path, rpath, runpath, env)
        .or_else(|| search_loader_defaults(filename))
}

/// Scan one colon-separated dir list for `filename` (`$ORIGIN`
/// expands against the main exe). Used for the transitive-RPATH
/// fallback below.
fn search_in_dirs(filename: &str, main_exe: &Path, dirs: &str) -> Option<PathBuf> {
    let exe_dir = origin_dir(main_exe);
    for d in dirs.split(':') {
        let d = if d.is_empty() {
            ".".to_string()
        } else {
            expand_origin(d, &exe_dir)
        };
        let cand = Path::new(&d).join(filename);
        if is_regular_file(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Maximum files visited while walking a spawn target's NEEDED
/// closure (real closures are dozens).
const MAX_LOADER_FILES: usize = 128;
/// Maximum total bytes read while walking the closure.
const MAX_CLOSURE_BYTES: u64 = 256 << 20;
/// Maximum NEEDED names honored per file (corrupt counts fail
/// closed via `incomplete`, never a slow scan).
const MAX_NEEDED_PER_FILE: usize = 256;

/// One closure-walk queue entry: file, already-read bytes (the exe
/// only — deps are read on visit), the needing file's own rpath,
/// its own runpath.
type LoaderQueueEntry = (PathBuf, Option<Vec<u8>>, Option<String>, Option<String>);

/// Identity for dual-load dedup: same file via two paths (symlink,
/// hardlink) is one lib, not two. Metadata failure falls back to
/// a path hash (distinct strings stay distinct — the fail-closed
/// direction).
fn file_id(p: &Path) -> (u64, u64) {
    use std::hash::{Hash as _, Hasher as _};
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(p)
        .map(|m| (m.dev(), m.ino()))
        .unwrap_or_else(|_| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            p.hash(&mut h);
            (u64::MAX, h.finish())
        })
}

/// Pre-exec spawn prediction: the resolved exe plus every distinct
/// libcrypto file in its dependency closure (direct and
/// transitive). Empty `libs` with empty `unresolved` and no
/// `incomplete` means no libcrypto dependency — static candidate.
pub struct SpawnPrediction {
    pub exe: PathBuf,
    pub exe_bytes: Vec<u8>,
    pub libs: Vec<PathBuf>,
    pub unresolved: Vec<String>,
    pub incomplete: bool,
}

/// Predict a spawn target's libcrypto files (no execution):
/// resolve argv[0], then walk the NEEDED closure breadth-first
/// (direct and transitive deps — `curl → libcurl → libcrypto`
/// included), resolving each name with that file's own
/// rpath/runpath plus the exe's transitive RPATH (old dtags:
/// RPATH applies to deeper levels, RUNPATH does not) plus fixed
/// defaults. Cycles are visited once; bounds fail closed via
/// `incomplete`. Content verdicts (ELF shape, flavor, anchors)
/// belong to qualification — prediction only fails on I/O.
pub fn predict_spawn_lib(argv: &[String], env: &SpawnEnv) -> Result<SpawnPrediction, OnboardError> {
    use std::collections::{HashSet, VecDeque};
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    if argv0.is_empty() {
        return Err(OnboardError::new(
            "cannot resolve spawn target: empty argv".to_string(),
            "pass a command after `run --`".to_string(),
        ));
    }
    let exe = resolve_spawn_exe(argv0, env);
    let exe_bytes = read_bounded(&exe, MAX_OBJECT_SCAN_BYTES).map_err(|e| {
        OnboardError::new(
            format!("cannot read spawn executable {}: {e}", exe.display()),
            "check the command exists and is readable".to_string(),
        )
    })?;
    let mut pred = SpawnPrediction {
        exe: exe.clone(),
        exe_bytes: Vec::new(),
        libs: Vec::new(),
        unresolved: Vec::new(),
        incomplete: false,
    };
    // Non-ELF (scripts, data) predicts nothing; discovery
    // qualifies the outcome below (fail-closed).
    if elf::needed_libraries(&exe_bytes).is_err() {
        pred.exe_bytes = exe_bytes;
        return Ok(pred);
    }
    let (exe_rpath, exe_runpath) = elf::rpath_runpath(&exe_bytes).unwrap_or((None, None));
    // Transitive RPATH (glibc old-dtags rule): the exe's RPATH
    // applies to deeper levels when the exe has RPATH and no
    // RUNPATH. Intermediate objects' own RPATHs are NOT chained
    // (only the exe's): that under-resolves to Unknown, never a
    // wrong file.
    let transitive_rpath: Option<String> = match (&exe_rpath, &exe_runpath) {
        (Some(rp), None) => Some(rp.clone()),
        _ => None,
    };
    // Queue entries carry their own rpath/runpath (known up front
    // for the exe, read on visit for deps).
    let mut queue: VecDeque<LoaderQueueEntry> = VecDeque::new();
    queue.push_back((exe.clone(), Some(exe_bytes.clone()), exe_rpath, exe_runpath));
    let mut visited: HashSet<PathBuf> = HashSet::new();
    visited.insert(std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone()));
    let mut lib_ids: HashSet<(u64, u64)> = HashSet::new();
    let mut files_visited: usize = 0;
    let mut bytes_read: u64 = exe_bytes.len() as u64;
    while let Some((file, bytes_opt, rpath, runpath)) = queue.pop_front() {
        if files_visited >= MAX_LOADER_FILES || bytes_read >= MAX_CLOSURE_BYTES {
            pred.incomplete = true;
            break;
        }
        files_visited += 1;
        let (bytes, rpath, runpath) = match bytes_opt {
            Some(b) => (b, rpath, runpath),
            None => match read_bounded(&file, MAX_OBJECT_SCAN_BYTES) {
                Ok(b) => {
                    bytes_read += b.len() as u64;
                    let (rp, run) = elf::rpath_runpath(&b).unwrap_or((None, None));
                    (b, rp, run)
                }
                Err(_) => {
                    // Unreadable dep: its subtree is unknown.
                    pred.incomplete = true;
                    continue;
                }
            },
        };
        let needed = elf::needed_libraries(&bytes).unwrap_or_default();
        if needed.len() > MAX_NEEDED_PER_FILE {
            pred.incomplete = true;
        }
        for name in needed.into_iter().take(MAX_NEEDED_PER_FILE) {
            // Each name resolves with the needing file's own
            // rpath/runpath, then the exe's transitive RPATH, then
            // fixed defaults (glibc order — transitive RPATH beats
            // defaults for deeper levels). `$ORIGIN` always means
            // the MAIN exe's dir.
            let hit =
                search_loader_own_dirs(&name, &exe, rpath.as_deref(), runpath.as_deref(), env)
                    // Approximation: the transitive fallback is tried even
                    // when the needing file has its own RUNPATH (real
                    // glibc skips the chain RPATH then). The deviation only
                    // over-resolves, which fails closed (dual-load refusal
                    // / Unknown) or degrades to zero-rows PARTIAL — never
                    // wrong attribution.
                    .or_else(|| {
                        transitive_rpath
                            .as_deref()
                            .and_then(|trp| search_in_dirs(&name, &exe, trp))
                    })
                    .or_else(|| search_loader_defaults(&name));
            if is_libcrypto_name(&name) {
                match hit {
                    Some(p) => {
                        if lib_ids.insert(file_id(&p)) {
                            pred.libs.push(p);
                        }
                    }
                    None => {
                        if !pred.unresolved.contains(&name) {
                            pred.unresolved.push(name);
                        }
                    }
                }
                continue;
            }
            // Non-crypto dep: traverse (an unresolvable one fails
            // the loader too — exec reports that downstream).
            if let Some(p) = hit {
                let canon = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
                if visited.insert(canon) {
                    queue.push_back((p, None, None, None));
                }
            }
        }
    }
    pred.exe_bytes = exe_bytes;
    Ok(pred)
}

/// Discover + qualify a spawn target BEFORE it executes (the child
/// is still the pre-exec image: its maps predict nothing). The
/// NEEDED closure (direct and transitive) predicts the dynamic lib
/// file(s); otherwise the exe itself is the static candidate.
/// Scripts (non-ELF) cannot be predicted: Unknown with explicit
/// `--provider` remediation, never a guess. Multiple distinct
/// libcryptos in the closure are dual-load: refused like `--pid`.
pub fn discover_spawn(
    argv: &[String],
    opts: &QualifyOpts,
    env: &SpawnEnv,
) -> Result<TargetQualification, OnboardError> {
    let pred = predict_spawn_lib(argv, env)?;
    if !pred.exe_bytes.starts_with(b"\x7fELF") {
        return Ok(TargetQualification::Unknown {
            reason: format!(
                "spawn target {} is not an ELF binary (script or data?)",
                pred.exe.display()
            ),
            remediation: "run the interpreter binary directly, or pass the target libcrypto with --provider explicitly".to_string(),
        });
    }
    if let Err(e) = check_arch(&pred.exe_bytes) {
        return Ok(TargetQualification::Unsupported {
            reason: format!("{}: {e}", pred.exe.display()),
            remediation: "run a 64-bit x86-64 binary".to_string(),
        });
    }
    // An unresolvable libcrypto NEEDED fails the loader itself —
    // the target cannot run until the search path is fixed.
    if let Some(wanted) = pred.unresolved.first() {
        return Ok(TargetQualification::Unknown {
            reason: format!(
                "cannot resolve NEEDED {wanted} for {} (loader search exhausted)",
                pred.exe.display()
            ),
            remediation: "pass the libcrypto file with --provider explicitly, or fix \
                 LD_LIBRARY_PATH/rpath so the loader finds it"
                .to_string(),
        });
    }
    if pred.libs.len() >= 2 {
        return Ok(TargetQualification::Unsupported {
            reason: format!(
                "multiple libcrypto builds in dependency closure (dual-load, ambiguous): {}",
                pred.libs
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            remediation: "run with a single libcrypto (dual-load refused fail-closed)".to_string(),
        });
    }
    if pred.libs.len() == 1 {
        if pred.incomplete {
            return Ok(TargetQualification::Unknown {
                reason: format!(
                    "dependency closure of {} unscanned past bounds (cannot exclude a second libcrypto)",
                    pred.exe.display()
                ),
                remediation: "pass the libcrypto file with --provider explicitly".to_string(),
            });
        }
        let path = &pred.libs[0];
        let bytes = read_bounded(path, MAX_OBJECT_SCAN_BYTES).map_err(|e| {
            OnboardError::new(
                format!("predicted libcrypto {} unreadable: {e}", path.display()),
                "check permissions on the library file".to_string(),
            )
        })?;
        return Ok(qualify_libcrypto_bytes(&bytes, path, false, opts));
    }
    if pred.incomplete {
        return Ok(TargetQualification::Unknown {
            reason: format!(
                "dependency closure of {} unscanned past bounds (cannot prove no libcrypto)",
                pred.exe.display()
            ),
            remediation: "pass the libcrypto file with --provider explicitly".to_string(),
        });
    }
    Ok(qualify_libcrypto_bytes(
        &pred.exe_bytes,
        &pred.exe,
        true,
        opts,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_enrollment_parses() {
        // The shipped example must stay valid (doc-rot guard); it
        // is never auto-loaded (explicit --provider-table only).
        let t = provider::load_table_str(include_str!("../../etc/provider-table.example.json"))
            .unwrap();
        assert_eq!(t.entry_count(), 1);
        assert_eq!(
            t.by_build_id(&"a".repeat(40)).unwrap().class,
            ProviderClass::ThirdParty
        );
    }

    #[test]
    fn error_full_renders_both_fields() {
        let e = OnboardError::new("m".to_string(), "r".to_string());
        assert_eq!(e.full(), "m; fix: r");
        assert_eq!(format!("{e}"), "m; fix: r");
    }

    #[test]
    fn ancestry_walk_pins() {
        use std::collections::HashMap;
        // Synthetic tree /t/a/b over mock metadata (no root needed):
        // the walk climbs through / — every level needs an entry.
        let trust = TrustPolicy {
            trusted_uids: vec![0],
            check_ancestry: true,
        };
        let probe = |entries: &[(&str, u32, u32, bool)]| {
            let map: HashMap<PathBuf, (u32, u32, bool)> = entries
                .iter()
                .map(|(p, uid, mode, dir)| (PathBuf::from(p), (*uid, *mode, *dir)))
                .collect();
            move |p: &Path| {
                map.get(p).map(|(uid, mode, dir)| LevelMeta {
                    uid: *uid,
                    mode: *mode,
                    is_dir: *dir,
                })
            }
        };
        let good = probe(&[
            ("/", 0, 0o755, true),
            ("/t", 0, 0o755, true),
            ("/t/a", 0, 0o755, true),
            ("/t/a/b", 0, 0o755, true),
        ]);
        assert!(ancestry_ok_with(Path::new("/t/a/b"), &trust, &good));
        // Writable middle (rename attack) → refused.
        let writable = probe(&[
            ("/", 0, 0o755, true),
            ("/t", 0, 0o755, true),
            ("/t/a", 0, 0o777, true),
            ("/t/a/b", 0, 0o755, true),
        ]);
        assert!(!ancestry_ok_with(Path::new("/t/a/b"), &trust, &writable));
        // Wrong owner in the middle → refused.
        let owned = probe(&[
            ("/", 0, 0o755, true),
            ("/t", 1000, 0o755, true),
            ("/t/a", 0, 0o755, true),
            ("/t/a/b", 0, 0o755, true),
        ]);
        assert!(!ancestry_ok_with(Path::new("/t/a/b"), &trust, &owned));
        // Leaf must be a directory.
        let file = probe(&[
            ("/", 0, 0o755, true),
            ("/t", 0, 0o755, true),
            ("/t/a", 0, 0o755, true),
            ("/t/a/b", 0, 0o755, false),
        ]);
        assert!(!ancestry_ok_with(Path::new("/t/a/b"), &trust, &file));
        // Missing level → refused.
        let missing = probe(&[("/", 0, 0o755, true), ("/t", 0, 0o755, true)]);
        assert!(!ancestry_ok_with(Path::new("/t/a/b"), &trust, &missing));
    }

    #[test]
    fn arch_gate_pins() {
        let mut good = vec![0u8; 64];
        good[0..4].copy_from_slice(b"\x7fELF");
        good[4] = 2;
        good[18] = 62;
        assert!(check_arch(&good).is_ok());
        assert!(check_arch(&[]).is_err());
        assert!(check_arch(&good[..10]).is_err());
        let mut i386 = good.clone();
        i386[4] = 1;
        i386[18] = 3;
        assert!(check_arch(&i386).unwrap_err().contains("32-bit"));
    }

    #[test]
    fn compat_rejects_non_bpf_elf() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(check_object_compatible(ObjectRole::Harvest, &exe).is_err());
        assert!(check_object_compatible(ObjectRole::Count, &exe).is_err());
        assert!(check_object_compatible(ObjectRole::Harvest, b"junk").is_err());
    }

    fn mapping(dev: &str, ino: u64, path: &str) -> Mapping {
        Mapping {
            start: 0,
            end: 0x1000,
            x: true,
            offset: 0,
            dev: dev.into(),
            ino,
            path: path.into(),
        }
    }

    #[test]
    fn libcrypto_basename_matching() {
        // Same file twice (r-x + r--) dedupes to One.
        let maps = vec![
            mapping("08:01", 2, "/opt/lib/libcrypto.so.3"),
            mapping("08:01", 2, "/opt/lib/libcrypto.so.3"),
            mapping("08:01", 1, "/lib/libc.so.6"),
        ];
        assert!(matches!(
            libcrypto_from_maps(&maps),
            LibcryptoMaps::One { .. }
        ));
        // Bare dev-symlink name matches; lookalike dirs do not.
        let maps = vec![mapping("08:01", 3, "/x/libcrypto.so")];
        assert!(matches!(
            libcrypto_from_maps(&maps),
            LibcryptoMaps::One { .. }
        ));
        let maps = vec![mapping("08:01", 3, "/x/libcrypto.so.3-backup/y.so")];
        assert_eq!(libcrypto_from_maps(&maps), LibcryptoMaps::None);
        // Non-file-backed entries are skipped.
        let maps = vec![mapping("00:00", 0, "/mem/libcrypto.so.3")];
        assert_eq!(libcrypto_from_maps(&maps), LibcryptoMaps::None);
    }
}
