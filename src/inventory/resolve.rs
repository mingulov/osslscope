// SPDX-License-Identifier: GPL-3.0-or-later
//! Constrained resolved host paths (T5 privacy D-record,
//! `--resolve-paths`, v0.6.0 D1): the terminal writer renders
//! verified object locators on TTY-attached human rows, and the D1
//! machine publisher re-resolves the same retained locators into
//! JSON path evidence — through the same constrained machinery,
//! never maps text.
//!
//! Design (D-record rules 2–7 + implementation caveat):
//! - The ONLY resolution primitive is [`open_constrained`]: one
//!   `openat2` with `RESOLVE_NO_MAGICLINKS`. Every magic-link
//!   encounter fails `ELOOP`, at any component including the
//!   final. There is no fallback: unsupported enforcement
//!   (`ENOSYS`/`EPERM`/`EINVAL` on a valid probe) fails closed to
//!   `(unavailable)` — unrestricted `canonicalize` before or after
//!   the constrained open would violate the design.
//! - Display strings are derived by a constrained userspace chase
//!   ([`chase_canonical`]) and then VERIFIED: the string must
//!   re-open (constrained) to the same file the atomic open
//!   pinned. Chase races fail closed to suppression, never to a
//!   mislabeled path.
//! - Every opened candidate is identity-checked against the
//!   retained backing identity with the project's
//!   filesystem-aware rule (ino must match; dev must match unless
//!   the opened side is btrfs — the [`BackingProcess`] carve-out).
//! - Errors carry errnos/words only, never paths (rule 2: no
//!   path-bearing text in error contexts, debug output, or
//!   diagnostics). [`ResolveSidecar`] debug output redacts.
//! - `/proc/self/fd` is never probed.

use super::{IdentityStatus, ModuleInfo, ProcessRecord, backing};
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Placeholder vocabulary (D-record rules 2–6): the ONLY non-path
/// strings the terminal writer emits.
pub(crate) const NOT_A_TERMINAL: &str = "(not-a-terminal)";
pub(crate) const UNAVAILABLE: &str = "(unavailable)";
pub(crate) const UNVERIFIED: &str = "(unverified)";
pub(crate) const MISSING: &str = "(missing)";
pub(crate) const CHANGED: &str = "(changed)";

/// `RESOLVE_NO_MAGICLINKS` (uapi `linux/openat2.h`): reject
/// `/proc` magic-link traversal by link type, at any procfs mount.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

/// `RESOLVE_NO_SYMLINKS` (uapi `linux/openat2.h`, same
/// kernel baseline as above): resolve no symlink at any
/// component — a swapped-in link fails `ELOOP` instead of
/// traversing. The rooted descent's confinement primitive.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// Chase expansion bound: the chase gives up past this many
/// readlink splices (suppression, never unbounded pursuit).
/// Defense in depth — the kernel's own MAXSYMLINKS (same value)
/// fires first at the atomic open and at every following
/// classify, so this bound is unreachable in practice; it pins
/// render time if kernel behavior ever drifts.
const MAX_SYMLINK_EXPANSIONS: usize = 40;

/// Total chase-step bound (component descents + expansions):
/// same defense-in-depth story as above (ENAMETOOLONG fires
/// first on absurd depths); render time stays finite at any
/// input size regardless.
const MAX_CHASE_STEPS: usize = 1024;

/// Display bound (rule 7): at most 200 chars, truncation marks `…`.
const DISPLAY_BOUND: usize = 200;

/// Human maps-hint bound (v0.6.0 P0-3): the whole
/// `(unverified maps hint: …)` fragment fits 80 chars, truncation
/// marks `…`.
const HUMAN_MAPS_HINT_CHARS: usize = 80;

/// Dedicated resolve-staging byte budget per acquisition
/// (external F3): retained locator bytes + row overhead charge
/// here, never the shared record pools — the flag cannot change
/// machine records or exit status under resource pressure.
pub(crate) const RESOLVE_BUDGET_BYTES: usize = 1 << 20;

/// Resolution failure. Carries errnos/words ONLY — never the path
/// under resolution (rule 2). `Debug` is path-free by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolveError {
    /// Nothing at the retained locator (`ENOENT` during the walk).
    Missing,
    /// Opened candidate mismatches the retained backing identity
    /// (replacement/retarget race caught), or the verified chase
    /// string re-opens to a different file.
    Changed,
    /// Any other failure: permission, overlong, magic-link
    /// encounter, unsupported enforcement, bound exhaustion.
    Unavailable,
}

impl ResolveError {
    fn placeholder(self) -> &'static str {
        match self {
            ResolveError::Missing => MISSING,
            ResolveError::Changed => CHANGED,
            ResolveError::Unavailable => UNAVAILABLE,
        }
    }
}

// Per-thread resolver invocation count: incremented on every
// resolve_for_display, establish_locator, establish_container_locator,
// and publish_root_anchored entry. Hostile cells
// assert zero deltas (rules 1/4/5: the resolver never runs for
// candidates, without the flag, or off-terminal). Thread-local,
// so parallel suites stay isolated; production overhead is one
// cell increment per render-time resolution.
thread_local! {
    static RESOLVE_INVOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Current thread's resolver invocation count (cell support).
#[cfg(test)]
pub(crate) fn resolve_invocations() -> u64 {
    RESOLVE_INVOCATIONS.with(|c| c.get())
}

fn count_invocation() {
    RESOLVE_INVOCATIONS.with(|c| c.set(c.get().saturating_add(1)));
}

/// Test hook events: deterministic mutation points inside
/// resolution (cell 4 symlink-swap races) and the D2
/// exe-continuity sample (procfs). Always compiled; `None` in
/// production (no behavior delta).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HookEvent {
    /// After the atomic constrained open pinned its FD, before
    /// the display chase starts.
    AfterAtomicOpen,
    /// Before descending into chase component `index` (0-based
    /// over walked components, symlink expansions included).
    BeforeChaseStep { index: usize },
    /// After a rooted-walk component classified as a non-symlink,
    /// before the descent open (`index` 0-based over popped
    /// components). Fires inside the former fstatat→open window —
    /// the descent itself can no longer follow a swapped-in link.
    BeforeRootedStep { index: usize },
    /// After the rooted walk, backing-identity match, and
    /// incarnation bracket all passed, before the fresh-root
    /// re-proof walk.
    BeforeRootedReproof,
    /// After the D2 exe spelling sample, before the continuity
    /// re-sample (fired by procfs, same per-thread slot).
    AfterExeSample,
}

type HookFn = Box<dyn FnMut(HookEvent) + Send>;

// Thread-local hook storage: install, fire, and clear are all
// per-thread, so parallel suites cannot steal or clear each
// other's hooks (a global install with a thread-gated fire still
// races at clear time).
thread_local! {
    static HOOK: std::cell::RefCell<Option<HookFn>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the calling thread's resolution test hook (cells only;
/// production never sets it). Replaces any previous hook.
#[cfg(test)]
pub(crate) fn set_hook(hook: Option<HookFn>) {
    HOOK.with(|slot| *slot.borrow_mut() = hook);
}

pub(crate) fn fire_hook(event: HookEvent) {
    // try_borrow: a (never-written) reentrant resolve inside a
    // hook skips the nested fire instead of panicking.
    HOOK.with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut()
            && let Some(hook) = guard.as_mut()
        {
            hook(event);
        }
    });
}

/// Row rendering capability (rule 3): retained backing custody
/// plus proven host locator, joined to exact object identity.
/// Threaded from the acquisition site; never recovered from maps
/// text or serialized records.
/// DELIBERATELY NONSERIALIZABLE: `File` implements no `Serialize`,
/// so this struct can never derive it (cell 2 whole-output
/// comparison would catch a manual impl).
pub(crate) struct RowCapability {
    /// Verified (device, inode) from acquisition.
    identity: (u64, u64),
    /// Retained verifying descriptor: pins the inode against
    /// recycling between acquisition and render. Never read by
    /// design — retention IS the custody (open FD pins the inode).
    #[allow(dead_code)]
    file: File,
    /// Host locator PROVEN at acquisition (constrained direct
    /// open + identity match) or operator-supplied (`--module`).
    /// `None` when no permissible pathname exists (rule 9 allows
    /// `(unavailable)` — custody never mints a pathname).
    locator: Option<PathBuf>,
}

impl RowCapability {
    pub(crate) fn new(identity: (u64, u64), file: File, locator: Option<PathBuf>) -> Self {
        Self {
            identity,
            file,
            locator,
        }
    }
}

/// Per-snapshot sidecar: capabilities for verified rows, joined by
/// (device, inode) at render. Lives beside the serializable
/// snapshot under `#[serde(skip)]` (never emitted); `Debug` and
/// `PartialEq` never touch pathnames or FDs.
#[derive(Clone, Default)]
pub(crate) struct ResolveSidecar {
    rows: Vec<std::sync::Arc<RowCapability>>,
}

impl std::fmt::Debug for ResolveSidecar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rule 2: no path-bearing debug output — row count only.
        f.debug_struct("ResolveSidecar")
            .field("rows", &self.rows.len())
            .finish()
    }
}

impl PartialEq for ResolveSidecar {
    fn eq(&self, other: &Self) -> bool {
        // FDs excluded (dup identity is not row identity).
        if self.rows.len() != other.rows.len() {
            return false;
        }
        self.rows
            .iter()
            .zip(other.rows.iter())
            .all(|(a, b)| a.identity == b.identity && a.locator == b.locator)
    }
}

impl Eq for ResolveSidecar {}

impl ResolveSidecar {
    pub(crate) fn push(&mut self, capability: RowCapability) {
        self.rows.push(std::sync::Arc::new(capability));
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Capability for one rendered row, joined by exact object
    /// identity. First match wins (one acquisition enrolls one
    /// capability per identity).
    pub(crate) fn lookup(&self, identity: (u64, u64)) -> Option<&RowCapability> {
        self.rows
            .iter()
            .find(|row| row.identity == identity)
            .map(AsRef::as_ref)
    }
}

/// `open_how` for [`libc::SYS_openat2`] (mirrors
/// `package::trusted`: flags + mode + resolve).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Raw `openat2(dirfd, name, O_PATH|O_CLOEXEC, resolve)`
/// core. Returns the raw errno on failure.
fn openat2_with(dirfd: i32, name: &std::ffi::CStr, resolve: u64) -> Result<File, i32> {
    let flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    let how = OpenHow {
        flags,
        mode: 0,
        resolve,
    };
    // SAFETY: `how` and the component name are valid for the
    // syscall duration; dirfd is borrowed, ownership of the
    // returned FD transfers exactly once below.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        // SAFETY: errno is valid immediately after the failed call.
        return Err(unsafe { *libc::__errno_location() });
    }
    // SAFETY: fd was returned by openat2; ownership transfers once.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

/// Following open with `RESOLVE_NO_MAGICLINKS`: the kernel
/// resolves plain symlinks but rejects every magic link.
/// Always follows: the classifier relies on follow-vs-ELOOP to
/// tell plain links from magic ones (O_NOFOLLOW would open the
/// link itself either way — useless as a discriminator).
fn openat2_no_magic(dirfd: i32, name: &std::ffi::CStr) -> Result<File, i32> {
    openat2_with(dirfd, name, RESOLVE_NO_MAGICLINKS)
}

/// Non-following descent open for [`walk_rooted`]: the mask adds
/// `RESOLVE_NO_SYMLINKS`, so a component swapped for a (plain
/// or absolute) symlink between the `fstatat` classification and
/// this open fails `ELOOP` instead of escaping the root fd (F1:
/// confinement is kernel-enforced at open time, never dependent
/// on the check→open window).
fn openat2_no_follow(dirfd: i32, name: &std::ffi::CStr) -> Result<File, i32> {
    openat2_with(dirfd, name, RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)
}

/// Enforcement support probe (cached per process): `openat2` on
/// `/` distinguishes "syscall unavailable" from path errors.
/// `ENOSYS`/`EPERM` (seccomp)/`EINVAL` (broken ABI) on a valid
/// probe mean enforcement is unavailable → every resolution
/// suppresses to `(unavailable)` (implementation caveat: no
/// `canonicalize` fallback, ever).
fn enforcement_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let root = std::ffi::CString::new("/").unwrap();
        match openat2_no_magic(libc::AT_FDCWD, &root) {
            Ok(_) => true,
            Err(errno) => !matches!(errno, libc::ENOSYS | libc::EPERM | libc::EINVAL),
        }
    })
}

/// Constrained open of one absolute host path: single `openat2`
/// with `RESOLVE_NO_MAGICLINKS` — the kernel resolves symlinks
/// but rejects every magic link atomically (no userspace precheck
/// to race). Returns the pinned FD; the caller identity-checks it.
fn open_constrained(path: &Path) -> Result<File, ResolveError> {
    if !enforcement_supported() {
        return Err(ResolveError::Unavailable);
    }
    let bytes = path.as_os_str().as_bytes();
    let name = std::ffi::CString::new(bytes).map_err(|_| ResolveError::Unavailable)?;
    match openat2_no_magic(libc::AT_FDCWD, &name) {
        Ok(file) => Ok(file),
        Err(errno) if errno == libc::ENOENT => Err(ResolveError::Missing),
        Err(_) => Err(ResolveError::Unavailable),
    }
}

/// Render-time identity check: EXACT (device, inode) equality.
/// Both sides are opened-FD fstat in the same domain, so the btrfs
/// device carve-out does NOT apply here — it exists only for
/// cross-domain (maps-text-device vs fstat) comparisons at
/// acquisition. Distinct files on different btrfs subvolumes
/// routinely share inode numbers; accepting a device mismatch here
/// would mislabel one file with another's path (external F1).
fn identity_matches(opened: &File, retained: (u64, u64)) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(metadata) = opened.metadata() else {
        return false;
    };
    (metadata.dev(), metadata.ino()) == retained
}

/// Verified canonical chase: derive the display string for `path`
/// (already atomically opened — route proven magic-free at open
/// time) by a constrained component walk, then VERIFY the string
/// re-opens (constrained) to `expect`. Any divergence — swap
/// races, chase bugs, magic re-entry — suppresses instead of
/// mislabeling.
///
/// Walk rules: every descent is a constrained `openat2`; every
/// symlink is classified by a FOLLOWING constrained open (plain
/// links follow, magic links `ELOOP` — kernel magic detection,
/// never name spelling); `..` pops lexically only over
/// a proven link-free prefix (after any expansion it suppresses —
/// physical parents are unnameable without `/proc/self/fd`,
/// which is never probed).
fn chase_canonical(path: &Path, expect: (u64, u64)) -> Result<PathBuf, ResolveError> {
    use std::os::unix::fs::MetadataExt as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || !bytes.starts_with(b"/") {
        return Err(ResolveError::Unavailable);
    }
    let root_name = std::ffi::CString::new("/").unwrap();
    let mut dir =
        openat2_no_magic(libc::AT_FDCWD, &root_name).map_err(|_| ResolveError::Unavailable)?;
    // Pending components (reversed stack, owned: symlink targets
    // splice in across iterations).
    let mut pending: Vec<Vec<u8>> = bytes
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(|c| c.to_vec())
        .collect();
    pending.reverse();
    let mut built: Vec<Vec<u8>> = Vec::new();
    let mut expanded_symlink = false;
    let mut expansions = 0usize;
    let mut step = 0usize;
    while let Some(component) = pending.pop() {
        if step >= MAX_CHASE_STEPS {
            return Err(ResolveError::Unavailable);
        }
        fire_hook(HookEvent::BeforeChaseStep { index: step });
        step += 1;
        if component == b".." {
            // Lexical pop is exact only over proven non-link
            // prefixes (at root it stays root).
            if expanded_symlink {
                return Err(ResolveError::Unavailable);
            }
            built.pop();
            // Re-anchor dirfd to the popped prefix (the walk
            // restarts from root — bounded by MAX_CHASE_STEPS).
            dir = openat2_no_magic(libc::AT_FDCWD, &root_name)
                .map_err(|_| ResolveError::Unavailable)?;
            for prefix in &built {
                let name = std::ffi::CString::new(prefix.as_slice())
                    .map_err(|_| ResolveError::Unavailable)?;
                // SAFETY: dirfd borrowed; stat valid for the call.
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                let ok = unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        &mut stat,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if ok != 0 {
                    // SAFETY: errno valid immediately after the call.
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::ENOENT {
                        return Err(ResolveError::Missing);
                    }
                    return Err(ResolveError::Unavailable);
                }
                dir = openat2_no_magic(dir.as_raw_fd(), &name).map_err(|errno| {
                    if errno == libc::ENOENT {
                        ResolveError::Missing
                    } else {
                        ResolveError::Unavailable
                    }
                })?;
            }
            continue;
        }
        let name =
            std::ffi::CString::new(component.as_slice()).map_err(|_| ResolveError::Unavailable)?;
        // SAFETY: dirfd borrowed; stat valid for the call.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ok != 0 {
            // SAFETY: errno valid immediately after the failed call.
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ENOENT {
                return Err(ResolveError::Missing);
            }
            return Err(ResolveError::Unavailable);
        }
        if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            // Classify by kernel magic detection: a FOLLOWING
            // constrained open follows plain links (success) and
            // ELOOPs on magic links. (O_NOFOLLOW would open the
            // link itself either way — useless as a discriminator.
            // The FD is classification-only; readlink below drives
            // the string chase.)
            match openat2_no_magic(dir.as_raw_fd(), &name) {
                Ok(_) => {}
                Err(errno) if errno == libc::ENOENT => return Err(ResolveError::Missing),
                Err(_) => return Err(ResolveError::Unavailable),
            }
            expansions += 1;
            if expansions > MAX_SYMLINK_EXPANSIONS {
                return Err(ResolveError::Unavailable);
            }
            let mut target = vec![0u8; libc::PATH_MAX as usize];
            // SAFETY: dirfd + name borrowed; target outlives the call.
            let len = unsafe {
                libc::readlinkat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if len <= 0 {
                return Err(ResolveError::Unavailable);
            }
            target.truncate(len as usize);
            expanded_symlink = true;
            if target.starts_with(b"/") {
                // Absolute target: restart from root.
                dir = openat2_no_magic(libc::AT_FDCWD, &root_name)
                    .map_err(|_| ResolveError::Unavailable)?;
                built.clear();
            }
            let mut parts: Vec<Vec<u8>> = target
                .split(|b| *b == b'/')
                .filter(|c| !c.is_empty() && *c != b".")
                .map(|c| c.to_vec())
                .collect();
            parts.reverse();
            pending.extend(parts);
            continue;
        }
        dir = openat2_no_magic(dir.as_raw_fd(), &name).map_err(|errno| {
            if errno == libc::ENOENT {
                ResolveError::Missing
            } else {
                ResolveError::Unavailable
            }
        })?;
        built.push(component);
    }
    // Rebuild the canonical string from descended components.
    let mut canonical = vec![b'/'];
    canonical.extend(built.join(&b'/'));
    let canonical = PathBuf::from(std::ffi::OsStr::from_bytes(&canonical));
    // VERIFY: the string must re-open (constrained) to the same
    // file the atomic open pinned. Chase races fail closed here.
    let verify = open_constrained(&canonical)?;
    let metadata = verify.metadata().map_err(|_| ResolveError::Unavailable)?;
    if (metadata.dev(), metadata.ino()) != expect {
        return Err(ResolveError::Changed);
    }
    Ok(canonical)
}

/// Establish a host locator at acquisition (rule 3, pid routes):
/// constrained direct open of the maps-claimed candidate pathname
/// plus identity match against the verified backing. Returns the
/// PROVEN locator, or `None` (maps text alone never suffices;
/// target-namespaced spellings fail the magic-free open).
/// Relative candidates resolve against the process CWD at
/// acquisition time; the retained locator is always absolute.
pub(crate) fn establish_locator(candidate: &Path, verified: (u64, u64)) -> Option<PathBuf> {
    count_invocation();
    if !enforcement_supported() {
        return None;
    }
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(candidate)
    };
    let opened = open_constrained(&absolute).ok()?;
    if !identity_matches(&opened, verified) {
        return None;
    }
    Some(absolute)
}

/// Transient establishment budget (v0.6.0 D3): `establish_container_locator`
/// carries no caller `Work` (fixed signature), so layer discovery charges
/// here instead: reads capped across a single derivation, state
/// reservations capped, no deadline (one acquisition op — the caller
/// enforces its own deadline at the next `Work` checkpoint). Any refusal
/// fails the arm closed.
struct EstablishmentBudget {
    read_left: usize,
    state_left: usize,
}

impl EstablishmentBudget {
    /// One derivation: a mountinfo-sized read allowance plus a scratch
    /// allowance covering the extraction formula (both transient —
    /// dropped with the candidates after establishment).
    fn one_derivation() -> Self {
        Self {
            read_left: 2 << 20,
            state_left: 8 << 20,
        }
    }
}

impl backing::BackingBudget for EstablishmentBudget {
    fn checkpoint(&mut self) -> Result<(), backing::BackingError> {
        Ok(())
    }
    fn allow_read(&mut self, want: usize) -> Result<usize, backing::BackingError> {
        if self.read_left == 0 {
            return Err(backing::BackingError::Unavailable);
        }
        Ok(want.max(1).min(self.read_left))
    }
    fn commit_read(&mut self, bytes: u64) -> Result<(), backing::BackingError> {
        self.read_left = self
            .read_left
            .saturating_sub(usize::try_from(bytes).unwrap_or(usize::MAX));
        Ok(())
    }
    fn reserve_state(
        &mut self,
        bytes: usize,
    ) -> Result<backing::BackingLease, backing::BackingError> {
        if bytes > self.state_left {
            return Err(backing::BackingError::Unavailable);
        }
        self.state_left -= bytes;
        Ok(backing::BackingLease::Uncharged)
    }
}

/// Layer-candidate bound for the container arm: mirrors the backing
/// call site (`procfs::backing` passes the same value).
const CONTAINER_LAYER_MAX: usize = 16;

/// Establish a container locator at acquisition (v0.6.0 D3): runs ONLY
/// after the host arm (`establish_locator`) returns `None` for a
/// verified module. Two sub-arms, first full pass wins:
///
/// - Layer arm: each `direct_layer_candidate_paths_charged` spelling is
///   a CANDIDATE only — constrained-reopened, identity-matched against
///   the retained verified identity, layer-membership re-proven by a
///   fresh derivation from the retained proc dir, and chase-verified.
/// - Root-fd arm: the maps-relative spelling is resolved inside a root
///   fd acquired from the RETAINED proc dir, with magic-link/escape
///   protection, then revalidated (process, root, namespace, backing,
///   pathname — see `verify_root_anchored`).
///
/// Returns the proven locator plus its kind; `None` fails closed (the
/// caller keeps the host-arm reason and publishes `null`).
pub(crate) fn establish_container_locator(
    process_dir: &File,
    candidate: &Path,
    verified: (u64, u64),
) -> Option<(PathBuf, super::LocatorKind)> {
    count_invocation();
    if !enforcement_supported() {
        return None;
    }
    if let Some(hit) = establish_layer_locator(process_dir, candidate, verified) {
        return Some(hit);
    }
    let anchored = verify_root_anchored(process_dir, candidate, verified)?;
    Some((anchored, super::LocatorKind::ProcRootAnchored))
}

/// Layer sub-arm: host-absolute overlay spellings from the TARGET's
/// mount table. Proof per candidate is a constrained open, exact
/// identity, still-a-member re-derivation, and a verified chase.
/// First full pass wins; anything short fails through to the
/// root-fd arm.
fn establish_layer_locator(
    process_dir: &File,
    candidate: &Path,
    verified: (u64, u64),
) -> Option<(PathBuf, super::LocatorKind)> {
    let maps_bytes = candidate.as_os_str().as_bytes();
    let entries = backing::direct_layer_candidate_paths_charged(
        process_dir,
        maps_bytes,
        CONTAINER_LAYER_MAX,
        &mut EstablishmentBudget::one_derivation(),
    );
    for spelling in entries {
        if !spelling.is_absolute() {
            continue;
        }
        let Ok(opened) = open_constrained(&spelling) else {
            continue;
        };
        if !identity_matches(&opened, verified) {
            continue;
        }
        // Membership re-proof: the layer must STILL be listed in the
        // target's mount table now (a stale derivation from a
        // since-unmounted layer never publishes).
        let fresh = backing::direct_layer_candidate_paths_charged(
            process_dir,
            maps_bytes,
            CONTAINER_LAYER_MAX,
            &mut EstablishmentBudget::one_derivation(),
        );
        if !fresh.contains(&spelling) {
            continue;
        }
        let Ok(canonical) = chase_canonical(&spelling, verified) else {
            continue;
        };
        return Some((canonical, super::LocatorKind::ContainerLayer));
    }
    None
}

/// Root-fd walk: resolve `absolute` (target-namespace spelling, leading
/// `/`) inside `root`, returning the canonical spelling plus the pinned
/// final descriptor. Every descent is a single-component
/// non-following `openat2` (`RESOLVE_NO_SYMLINKS`): a component
/// swapped for a symlink between the `fstatat` NOFOLLOW
/// classification and the descent open fails `ELOOP` instead of
/// escaping the root fd — confinement is kernel-enforced at open
/// time, never dependent on the check→open window. Symlinks chase
/// TEXTUALLY (readlink + splice, absolute targets restart at the
/// root fd) so the kernel never interprets a link — magic links
/// can only contribute text, never traversal, and absolute
/// restarts land on the target root, never the host root. `..`
/// pops lexically over the proven link-free prefix (after any
/// expansion, or above the root fd, it fails closed). Bounded by
/// `MAX_CHASE_STEPS`/`MAX_SYMLINK_EXPANSIONS`; anything else fails
/// closed to `None`.
fn walk_rooted(root: &File, absolute: &[u8]) -> Option<(Vec<u8>, File)> {
    use std::os::unix::io::AsRawFd as _;
    if absolute.is_empty() || !absolute.starts_with(b"/") {
        return None;
    }
    let Ok(root_anchor) = root.try_clone() else {
        return None;
    };
    let mut dir = root.try_clone().ok()?;
    let mut pending: Vec<Vec<u8>> = absolute
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(|c| c.to_vec())
        .collect();
    pending.reverse();
    let mut built: Vec<Vec<u8>> = Vec::new();
    let mut expanded_symlink = false;
    let mut expansions = 0usize;
    let mut step = 0usize;
    while let Some(component) = pending.pop() {
        if step >= MAX_CHASE_STEPS {
            return None;
        }
        let index = step;
        step += 1;
        if component == b".." {
            // Lexical pop is exact only over a proven non-link
            // prefix; above the root fd it is an escape attempt.
            if expanded_symlink || built.pop().is_none() {
                return None;
            }
            // Re-anchor by restarting the walk over the popped
            // prefix plus the untouched remainder (re-classifies
            // every component; steps stay bounded above).
            let Ok(fresh) = root_anchor.try_clone() else {
                return None;
            };
            dir = fresh;
            let mut rest: Vec<Vec<u8>> = pending.drain(..).rev().collect();
            let mut combined = built.clone();
            combined.append(&mut rest);
            combined.reverse();
            pending = combined;
            built = Vec::new();
            continue;
        }
        let name = std::ffi::CString::new(component.as_slice()).ok()?;
        // SAFETY: dirfd borrowed; stat valid for the call.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ok != 0 {
            return None;
        }
        if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            expansions += 1;
            if expansions > MAX_SYMLINK_EXPANSIONS {
                return None;
            }
            let mut target = vec![0u8; libc::PATH_MAX as usize];
            // SAFETY: dirfd + name borrowed; target outlives the call.
            let len = unsafe {
                libc::readlinkat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if len <= 0 {
                return None;
            }
            target.truncate(len as usize);
            expanded_symlink = true;
            if target.starts_with(b"/") {
                let Ok(fresh) = root_anchor.try_clone() else {
                    return None;
                };
                dir = fresh;
                built.clear();
            }
            let mut parts: Vec<Vec<u8>> = target
                .split(|b| *b == b'/')
                .filter(|c| !c.is_empty() && *c != b".")
                .map(|c| c.to_vec())
                .collect();
            parts.reverse();
            pending.extend(parts);
            continue;
        }
        // Deterministic race-test seam: fires after the non-link
        // classification, before the descent open.
        fire_hook(HookEvent::BeforeRootedStep { index });
        let child = openat2_no_follow(dir.as_raw_fd(), &name).ok()?;
        dir = child;
        built.push(component);
    }
    let mut canonical = vec![b'/'];
    canonical.extend(built.join(&b'/'));
    Some((canonical, dir))
}

/// Root-fd sub-arm, shared by establishment and publish: prove the
/// maps-relative spelling inside a root fd acquired from the RETAINED
/// proc dir (the single audited magic-link traversal on this path —
/// `open_at` follows `root` deliberately to enter the target mount
/// namespace; every later step is magic-free by construction, see
/// `walk_rooted`), then revalidate process + root + namespace +
/// backing + pathname:
///
/// - process/root/namespace: the incarnation bracket
///   (`incarnation_direct` before vs after — starttime plus mount-ns
///   identity must be stable, and both reads must succeed, so a raced
///   exit/reuse fails closed);
/// - backing: the pinned final descriptor must fstat-match the retained
///   verified identity EXACTLY (same-domain comparison — no btrfs
///   carve-out, mirroring `identity_matches`);
/// - pathname: the canonical string must re-walk from a FRESH root fd
///   to the same identity (walk races fail closed here, never to a
///   mislabeled spelling).
fn verify_root_anchored(
    process_dir: &File,
    candidate: &Path,
    verified: (u64, u64),
) -> Option<PathBuf> {
    let bytes = candidate.as_os_str().as_bytes();
    let before = super::procfs::incarnation_direct(process_dir)?;
    let root = super::procfs::open_at(process_dir, b"root").ok()?;
    let (canonical, pinned) = walk_rooted(&root, bytes)?;
    if !identity_matches(&pinned, verified) {
        return None;
    }
    drop(pinned);
    let after = super::procfs::incarnation_direct(process_dir)?;
    if before != after {
        return None;
    }
    // Deterministic re-proof-test seam: the first walk, backing
    // match, and incarnation bracket all passed at this point.
    fire_hook(HookEvent::BeforeRootedReproof);
    // Pathname re-proof from a fresh root fd (also re-proves target
    // liveness: a raced exit fails the fresh `root` open).
    let fresh = super::procfs::open_at(process_dir, b"root").ok()?;
    let (rebuilt, confirm) = walk_rooted(&fresh, &canonical)?;
    if rebuilt != canonical || !identity_matches(&confirm, verified) {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&canonical)))
}

/// Machine publish for one root-anchored row (D3): re-prove the
/// retained target-relative spelling through a FRESH root fd (same
/// core as establishment — process/root/namespace/backing/pathname),
/// then encode losslessly with `LocatorKind::ProcRootAnchored`.
/// Anything short publishes `null` + `ResolveFailed` (never a weaker
/// reason — only a positive revalidation closes).
pub(crate) fn publish_root_anchored(
    process_dir: &File,
    locator: &Path,
    identity: (u64, u64),
) -> (
    Option<super::VerifiedPath>,
    Option<super::PathUnavailableReason>,
) {
    count_invocation();
    let Some(canonical) = verify_root_anchored(process_dir, locator, identity) else {
        return (None, Some(super::PathUnavailableReason::ResolveFailed));
    };
    let (path, path_encoding) = encode_machine_path(canonical.as_os_str().as_bytes());
    (
        Some(super::VerifiedPath {
            path,
            path_encoding,
            locator_kind: super::LocatorKind::ProcRootAnchored,
            capture_unix_ms: crate::inventory::wall_ms_pub(),
        }),
        None,
    )
}

/// Render-time resolution for one capability (rules 5–6): atomic
/// constrained open → identity match vs retained → verified chase.
/// Returns the canonical display path or the suppression.
/// Never fails the render: every error maps to a placeholder.
pub(crate) fn resolve_for_display(capability: &RowCapability) -> Result<PathBuf, ResolveError> {
    count_invocation();
    let locator = capability
        .locator
        .as_ref()
        .ok_or(ResolveError::Unavailable)?;
    // Atomic open first: the kernel proves the route magic-free
    // (no userspace precheck to race). Then the identity match.
    let pinned = open_constrained(locator)?;
    if !identity_matches(&pinned, capability.identity) {
        return Err(ResolveError::Changed);
    }
    fire_hook(HookEvent::AfterAtomicOpen);
    // Anchor the chase expectation to the RETAINED identity, not
    // the fresh open: the verify must prove the string names the
    // acquired file, even if the match above ever weakens
    // (external F1 defense in depth).
    chase_canonical(locator, capability.identity)
}

/// Machine publish for one verified row (D1): re-resolve the
/// retained locator through the SAME constrained machinery as the
/// terminal writer, then encode losslessly. `None` path always
/// pairs with a finite reason; locator candidates never reach here
/// (callers gate on `IdentityStatus::Verified`).
pub(crate) fn publish_verified_path(
    capability: &RowCapability,
) -> (
    Option<super::VerifiedPath>,
    Option<super::PathUnavailableReason>,
) {
    use super::{PathUnavailableReason, VerifiedPath};
    let Some(locator) = capability.locator.as_ref() else {
        return (None, Some(PathUnavailableReason::NoLocator));
    };
    let _ = locator;
    match resolve_for_display(capability) {
        Ok(canonical) => {
            let (path, path_encoding) = encode_machine_path(canonical.as_os_str().as_bytes());
            (
                Some(VerifiedPath {
                    path,
                    path_encoding,
                    locator_kind: super::LocatorKind::HostDirect,
                    capture_unix_ms: crate::inventory::wall_ms_pub(),
                }),
                None,
            )
        }
        Err(ResolveError::Missing) => (None, Some(PathUnavailableReason::Missing)),
        Err(ResolveError::Changed) => (None, Some(PathUnavailableReason::Changed)),
        Err(ResolveError::Unavailable) => (None, Some(PathUnavailableReason::ResolveFailed)),
    }
}

/// Machine path bound (D1): valid UTF-8 publishes verbatim to
/// 4096 chars; longer strings truncate to 4095 chars + `…`.
pub(crate) const MACHINE_PATH_CHARS: usize = 4096;

/// Escaped machine path bound (D1): 3× the verbatim bound, so a
/// fully-escaped PATH_MAX spelling still fits; truncation marks
/// `…` and never splits a `%XX` escape.
pub(crate) const MACHINE_PATH_ESCAPED_CHARS: usize = 12288;

/// Lossless machine encoding for proven path bytes (D1): valid
/// UTF-8 publishes verbatim ([`MACHINE_PATH_CHARS`]); otherwise
/// valid runs publish verbatim with each invalid byte `%XX`
/// percent-escaped (uppercase hex, [`MACHINE_PATH_ESCAPED_CHARS`]).
/// No sanitization (unlike [`display_path`): control bytes in
/// valid UTF-8 stay verbatim — JSON string escaping, not lossy
/// display folding, carries machine evidence.
pub(crate) fn encode_machine_path(bytes: &[u8]) -> (String, super::PathEncoding) {
    use super::PathEncoding;
    if let Ok(valid) = std::str::from_utf8(bytes) {
        if valid.chars().count() <= MACHINE_PATH_CHARS {
            return (valid.to_string(), PathEncoding::Utf8);
        }
        let truncated: String = valid.chars().take(MACHINE_PATH_CHARS - 1).collect();
        return (format!("{truncated}…"), PathEncoding::Utf8);
    }
    let mut escaped = String::new();
    for chunk in bytes.utf8_chunks() {
        escaped.push_str(chunk.valid());
        for byte in chunk.invalid() {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    if escaped.chars().count() <= MACHINE_PATH_ESCAPED_CHARS {
        return (escaped, PathEncoding::Utf8PercentEscaped);
    }
    let mut cut: String = escaped
        .chars()
        .take(MACHINE_PATH_ESCAPED_CHARS - 1)
        .collect();
    // Never split a `%XX` escape: back off over a trailing
    // partial escape (`%` or `%X`; a trailing literal `%`/`%X`
    // costs at most two chars — still within bound, still marked).
    if cut.ends_with('%') {
        cut.pop();
    } else {
        let tail: Vec<char> = cut.chars().rev().take(2).collect();
        if tail.len() == 2 && tail[0].is_ascii_hexdigit() && tail[1] == '%' {
            cut.truncate(cut.len() - 2);
        }
    }
    cut.push('…');
    (cut, PathEncoding::Utf8PercentEscaped)
}

/// Display pipeline (rule 7 + defense in depth): lossy decode,
/// target-pid normalization, control sanitization, 200-char bound
/// with `…`. Applied to EVERY emitted path; placeholders bypass.
pub(crate) fn display_path(canonical: &Path) -> String {
    let lossy = canonical.as_os_str().to_string_lossy();
    // Defense in depth (rule 6 already enforced structurally):
    // any literal `/proc/<digits>` spellings normalize.
    let normalized = crate::report::normalize_proc_pid(&lossy);
    let safe = crate::report::safe_display(&normalized);
    if safe.chars().count() <= DISPLAY_BOUND {
        return safe;
    }
    format!(
        "{}…",
        safe.chars().take(DISPLAY_BOUND - 1).collect::<String>()
    )
}

/// Render one row's `path=` value: placeholder or resolved display
/// string. Infallible by design (exits/diagnostics unaffected).
pub(crate) fn path_value(capability: Option<&RowCapability>) -> String {
    let Some(capability) = capability else {
        return UNAVAILABLE.to_string();
    };
    match resolve_for_display(capability) {
        Ok(canonical) => display_path(&canonical),
        Err(error) => error.placeholder().to_string(),
    }
}

/// Dedicated terminal writer (rules 2-4): the ONLY home that turns
/// row capabilities into display strings. Flag-off callers OMIT
/// the fragment (`None` — byte-identical output, zero resolver
/// I/O); flag-on callers render exactly one `path=...` value per
/// object row.
pub(crate) struct TerminalPathWriter<'a> {
    flag: bool,
    terminal: bool,
    sidecar: &'a ResolveSidecar,
}

impl<'a> TerminalPathWriter<'a> {
    pub(crate) fn new(flag: bool, terminal: bool, sidecar: &'a ResolveSidecar) -> Self {
        Self {
            flag,
            terminal,
            sidecar,
        }
    }

    /// One pid-route row's `path=` value (`None` = omit the
    /// fragment). Candidates render `(unverified)` WITHOUT
    /// resolver I/O (rule 4); off-terminal renders
    /// `(not-a-terminal)` without I/O (rule 2).
    pub(crate) fn fragment(&self, status: IdentityStatus, identity: (u64, u64)) -> Option<String> {
        if !self.flag {
            return None;
        }
        if !self.terminal {
            return Some(NOT_A_TERMINAL.to_string());
        }
        if status != IdentityStatus::Verified {
            return Some(UNVERIFIED.to_string());
        }
        Some(self.resolve_or_unavailable(identity))
    }

    /// One `--module`-route row's `path=` value: operator-observed
    /// rows carry no status word (eligibility documented at the
    /// acquisition site); terminal + flag gates still apply.
    pub(crate) fn fragment_module(&self, identity: (u64, u64)) -> Option<String> {
        // Operator-observed rows: eligibility was established at
        // the acquisition site, so the join is status-blind here;
        // flag + terminal gates still apply.
        if !self.flag {
            return None;
        }
        if !self.terminal {
            return Some(NOT_A_TERMINAL.to_string());
        }
        Some(self.resolve_or_unavailable(identity))
    }

    /// Sidecar join + constrained resolve for one identity; join
    /// misses and resolve failures both render `(unavailable)`.
    fn resolve_or_unavailable(&self, identity: (u64, u64)) -> String {
        path_value(self.sidecar.lookup(identity))
    }

    /// Short identity key for human rows: first 12 sha256 hex
    /// chars. A label, never a map key (full sha256 is
    /// machine-only).
    pub(crate) fn short_sha(sha256: &str) -> &str {
        sha256.get(..12).unwrap_or(sha256)
    }

    /// Human `path=` value for one discovery row (v0.6.0 P0-3):
    /// TTY + flag rows keep the live [`TerminalPathWriter::fragment`]
    /// rules (constrained re-resolution, `(unverified)` for
    /// candidates); every other row shows D1 machine evidence —
    /// `verified_path.path` (sanitized for display), else the
    /// explicitly-unverified maps hint (80 chars), else
    /// `(unavailable)`. Piped rows never render `(not-a-terminal)`.
    fn human_path(&self, module: &super::ModuleRecord) -> String {
        if self.flag && self.terminal {
            return self
                .fragment(
                    module.identity_status,
                    (module.info.device, module.info.inode),
                )
                .unwrap_or_else(|| UNAVAILABLE.to_string());
        }
        if let Some(verified) = module.verified_path.as_ref() {
            return crate::report::safe_display(&verified.path);
        }
        if let Some(hint) = module.maps_spelling.as_ref() {
            let spelling = crate::report::safe_display(&hint.spelling);
            let full = format!("(unverified maps hint: {spelling})");
            if full.chars().count() <= HUMAN_MAPS_HINT_CHARS {
                return full;
            }
            let mut cut: String = full.chars().take(HUMAN_MAPS_HINT_CHARS - 1).collect();
            cut.push('…');
            return cut;
        }
        UNAVAILABLE.to_string()
    }

    /// Human `version=` value for one row: validated file version
    /// evidence first, SONAME second, `none` when neither exists.
    /// Both inputs are ELF-derived bytes, so both sanitize at this
    /// human boundary. File evidence only, never a runtime claim.
    fn human_version(info: &ModuleInfo) -> String {
        info.file_openssl_version
            .as_deref()
            .or(info.file_soname.as_deref())
            .map(crate::report::safe_display)
            .unwrap_or_else(|| "none".to_string())
    }

    /// Human identity word for one discovery row. Deliberately
    /// hyphenated (`locator-candidate`); the serde machine spelling
    /// keeps its underscore (`locator_candidate`).
    fn human_identity(status: IdentityStatus) -> &'static str {
        match status {
            IdentityStatus::Verified => "verified",
            IdentityStatus::LocatorCandidate => "locator-candidate",
        }
    }

    /// Discovery human module rows (v0.6.0 P0-3, one per module,
    /// deterministic snapshot order). Rows ALWAYS render — the flag
    /// gates only live TTY re-resolution inside `path=`, never the
    /// row itself.
    pub(crate) fn object_rows(&self, processes: &[ProcessRecord]) -> Vec<String> {
        let mut rows = Vec::new();
        for process in processes {
            for module in &process.modules {
                rows.push(format!(
                    "  {} sha256={} identity={} size={} path={} version={}",
                    module.info.kind.word(),
                    Self::short_sha(&module.info.sha256),
                    Self::human_identity(module.identity_status),
                    module.info.size_bytes,
                    self.human_path(module),
                    Self::human_version(&module.info),
                ));
            }
        }
        rows
    }

    /// `--module`-route human rows (v0.6.0 P0-3). Operator-observed
    /// rows carry no identity word (eligibility was established at
    /// the acquisition site) and no machine path evidence exists on
    /// this route, so `path=` renders only under the flag
    /// ([`TerminalPathWriter::fragment_module`] rules, including the
    /// piped `(not-a-terminal)` placeholder) and is omitted without
    /// it — flag-absent output carries no `path=` anywhere.
    pub(crate) fn module_rows(&self, modules: &[ModuleInfo]) -> Vec<String> {
        modules
            .iter()
            .map(|module| {
                let mut row = format!(
                    "  {} sha256={} size={}",
                    module.kind.word(),
                    Self::short_sha(&module.sha256),
                    module.size_bytes,
                );
                if let Some(path) = self.fragment_module((module.device, module.inode)) {
                    row.push_str(&format!(" path={path}"));
                }
                row.push_str(&format!(" version={}", Self::human_version(module)));
                row
            })
            .collect()
    }

    /// Watch change-row fragment from the serialized module value
    /// (watch.rs renders from JSON values — the resolved string
    /// never enters that carrier; the sidecar join happens here).
    /// Unknown status words fail closed to `(unverified)`;
    /// unjoinable identities to `(unavailable)`.
    pub(crate) fn change_fragment(&self, module: &serde_json::Value) -> Option<String> {
        if !self.flag {
            return None;
        }
        if !self.terminal {
            return Some(NOT_A_TERMINAL.to_string());
        }
        let verified = module
            .get("identity_status")
            .and_then(serde_json::Value::as_str)
            == Some("verified");
        if !verified {
            return Some(UNVERIFIED.to_string());
        }
        let identity = (|| {
            let info = module.get("info")?;
            let device = info.get("device")?.as_u64()?;
            let inode = info.get("inode")?.as_u64()?;
            Some((device, inode))
        })();
        let Some(identity) = identity else {
            return Some(UNAVAILABLE.to_string());
        };
        Some(self.resolve_or_unavailable(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-resolve-{}-{}-{}",
            std::process::id(),
            test,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn identity_of(path: &Path) -> (u64, u64) {
        let metadata = std::fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    fn capability_for(path: &Path) -> RowCapability {
        RowCapability::new(
            identity_of(path),
            File::open(path).unwrap(),
            Some(path.to_path_buf()),
        )
    }

    fn symlink(original: &Path, link: &Path) {
        std::os::unix::fs::symlink(original, link).unwrap();
    }

    #[test]
    fn chain_resolves_to_canonical_target() {
        // Cell 2 leg: a.so → b.so → real.so displays real.so.
        let dir = scratch("chain");
        let real = dir.join("real.so");
        std::fs::write(&real, b"elf?").unwrap();
        let b = dir.join("b.so");
        symlink(&real, &b);
        let a = dir.join("a.so");
        symlink(&b, &a);
        let capability = capability_for(&a);
        assert_eq!(resolve_for_display(&capability).unwrap(), real);
        assert_eq!(path_value(Some(&capability)), real.to_string_lossy());
    }

    #[test]
    fn dot_components_and_plain_files_resolve() {
        let dir = scratch("dots");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let dotted = dir.join("./sub/../real.so");
        std::fs::create_dir(dir.join("sub")).unwrap();
        // Note: `..` over the proven link-free prefix pops lexically.
        let capability =
            RowCapability::new(identity_of(&real), File::open(&real).unwrap(), Some(dotted));
        assert_eq!(resolve_for_display(&capability).unwrap(), real);
    }

    #[test]
    fn dotdot_after_expansion_suppresses() {
        // Physical `..` past a symlink is unnameable without
        // /proc/self/fd (never probed) → suppress, never guess.
        let dir = scratch("dotdot");
        let target_dir = dir.join("target");
        std::fs::create_dir(&target_dir).unwrap();
        let real = target_dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.join("link");
        symlink(&target_dir, &link);
        let via = link.join("../target/real.so");
        let capability =
            RowCapability::new(identity_of(&real), File::open(&real).unwrap(), Some(via));
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Unavailable
        );
    }

    #[test]
    fn symlink_loop_suppresses() {
        let dir = scratch("loop");
        let a = dir.join("a");
        let b = dir.join("b");
        symlink(&b, &a);
        symlink(&a, &b);
        // Identity is unprovable (nothing opens); any identity the
        // chase cannot reach must suppress.
        let probe = dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        let capability =
            RowCapability::new(identity_of(&probe), File::open(&probe).unwrap(), Some(a));
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Unavailable
        );
    }

    #[test]
    fn proc_magic_links_suppress_by_link_type() {
        // Cell 4 legs: every magic-link shape suppresses —
        // numeric pid dirs, self/thread-self aliases, exe/cwd/
        // root/map_files/fd/ns — never published in any form.
        let pid = std::process::id();
        let probe = scratch("magic");
        let anchor = probe.join("anchor");
        std::fs::write(&anchor, b"x").unwrap();
        let identity = identity_of(&anchor);
        let file = || File::open(&anchor).unwrap();
        // A fd that is provably open in this process (fd 0 may be
        // closed under some runners — never assume it).
        use std::os::unix::io::AsRawFd as _;
        let held = file();
        let held_fd = held.as_raw_fd();
        let mut cases = vec![
            format!("/proc/{pid}/exe"),
            format!("/proc/{pid}/cwd"),
            format!("/proc/{pid}/root"),
            format!("/proc/{pid}/fd/{held_fd}"),
            format!("/proc/{pid}/ns/mnt"),
            "/proc/self/exe".to_string(),
            "/proc/self/cwd".to_string(),
            "/proc/self/root".to_string(),
            format!("/proc/self/fd/{held_fd}"),
            "/proc/thread-self/exe".to_string(),
            "/proc/thread-self/cwd".to_string(),
            format!("/proc/self/task/{pid}/exe"),
        ];
        // Pipe fds are magic links of another object type (F5d).
        let mut pipe = [0; 2];
        // SAFETY: pipe writes exactly two fds into the live array.
        let piped = unsafe { libc::pipe(pipe.as_mut_ptr()) } == 0;
        if piped {
            cases.push(format!("/proc/self/fd/{}", pipe[0]));
            cases.push(format!("/proc/{pid}/fd/{}", pipe[1]));
        }
        // Alternate-procfs-mount note (F5d): enforcement is by
        // kernel link TYPE (openat2 ELOOP), never by path spelling
        // or mount point — no spelling of a magic link, at any
        // mount, can pass the constrained open. Untestable without
        // mount privilege; covered by construction (no `/proc`
        // prefix check exists on the enforcement path).
        // First FILE-BACKED VMA (a leading vsyscall/vdso line has
        // no map_files entry — that would be Missing, not magic).
        if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            && let Some(line) = maps.lines().find(|line| line.contains('/'))
            && let Some(range) = line.split_whitespace().next()
        {
            cases.push(format!("/proc/{pid}/map_files/{range}"));
        }
        assert!(!cases.is_empty());
        for case in &cases {
            let capability = RowCapability::new(identity, file(), Some(PathBuf::from(case)));
            let error = resolve_for_display(&capability).unwrap_err();
            assert_eq!(error, ResolveError::Unavailable, "{case}");
            assert_eq!(path_value(Some(&capability)), UNAVAILABLE, "{case}");
        }
        if piped {
            // SAFETY: both fds came from the successful pipe above.
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
        }
    }

    #[test]
    fn symlink_into_proc_suppresses_and_erased_prefix_too() {
        // Cell 4: a plain link whose target re-enters procfs —
        // including targets that erase the prefix — suppresses.
        let dir = scratch("proc-link");
        let pid = std::process::id();
        let anchor = dir.join("anchor");
        std::fs::write(&anchor, b"x").unwrap();
        let identity = identity_of(&anchor);
        for (name, target) in [
            ("direct", format!("/proc/{pid}/exe")),
            ("root", format!("/proc/{pid}/root/etc/hostname")),
            ("self", "/proc/self/cwd".to_string()),
        ] {
            let link = dir.join(name);
            symlink(Path::new(&target), &link);
            let capability =
                RowCapability::new(identity, File::open(&anchor).unwrap(), Some(link.clone()));
            assert_eq!(
                resolve_for_display(&capability).unwrap_err(),
                ResolveError::Unavailable,
                "{name} → {target}"
            );
        }
    }

    #[test]
    fn plain_directory_named_proc_resolves() {
        // Cell 4 contrast: magic is a link TYPE, never a spelling —
        // an ordinary directory literally named `proc` resolves.
        let dir = scratch("plain-proc");
        let proc = dir.join("proc");
        std::fs::create_dir(&proc).unwrap();
        let real = proc.join("12345");
        std::fs::write(&real, b"x").unwrap();
        let capability = capability_for(&real);
        assert_eq!(resolve_for_display(&capability).unwrap(), real);
    }

    #[test]
    fn swap_safe_to_magic_mid_walk_suppresses() {
        // Cell 4: deterministic symlink swap between the atomic
        // open and the chase (safe link → re-entrant magic link)
        // still suppresses — the walk enforces, not a preflight.
        let dir = scratch("swap");
        let safe = dir.join("safe.so");
        std::fs::write(&safe, b"x").unwrap();
        let link = dir.join("link.so");
        symlink(&safe, &link);
        let capability = capability_for(&link);
        let swap_to = format!("/proc/{}/exe", std::process::id());
        let link_clone = link.clone();
        set_hook(Some(Box::new(move |event| {
            if event == HookEvent::AfterAtomicOpen {
                std::fs::remove_file(&link_clone).unwrap();
                symlink(Path::new(&swap_to), &link_clone);
            }
        })));
        let error = resolve_for_display(&capability).unwrap_err();
        set_hook(None);
        assert_eq!(error, ResolveError::Unavailable);
        assert_eq!(path_value(Some(&capability)), UNAVAILABLE);
    }

    #[test]
    fn swap_mid_chase_step_suppresses() {
        // Same fence one level deeper: swap `mid` after the chase
        // classified `outer` but before it classifies `mid` (step
        // index = component count of the locator: `outer` is the
        // last pending component, `mid` splices in next).
        let dir = scratch("swap-step");
        let safe = dir.join("safe.so");
        std::fs::write(&safe, b"x").unwrap();
        let mid = dir.join("mid");
        symlink(&safe, &mid);
        let outer = dir.join("outer");
        symlink(&mid, &outer);
        let capability = capability_for(&outer);
        let mid_step = outer.components().count() - 1;
        let swap_to = format!("/proc/{}/exe", std::process::id());
        let mid_clone = mid.clone();
        set_hook(Some(Box::new(move |event| {
            if event == (HookEvent::BeforeChaseStep { index: mid_step }) {
                std::fs::remove_file(&mid_clone).unwrap();
                symlink(Path::new(&swap_to), &mid_clone);
            }
        })));
        let error = resolve_for_display(&capability).unwrap_err();
        set_hook(None);
        assert_eq!(error, ResolveError::Unavailable);
    }

    #[test]
    fn swap_to_loop_suppresses() {
        // Third swap shape: safe link → symlink loop AFTER the
        // atomic open. The chase classify hits kernel ELOOP on
        // the swapped link and suppresses (the chase's own
        // expansion bound is defense-in-depth behind it).
        let dir = scratch("swap-loop");
        let safe = dir.join("safe.so");
        std::fs::write(&safe, b"x").unwrap();
        let link = dir.join("link.so");
        symlink(&safe, &link);
        let loop_a = dir.join("loop-a");
        let loop_b = dir.join("loop-b");
        symlink(&loop_b, &loop_a);
        symlink(&loop_a, &loop_b);
        let capability = capability_for(&link);
        let link_clone = link.clone();
        let loop_clone = loop_a.clone();
        set_hook(Some(Box::new(move |event| {
            if event == HookEvent::AfterAtomicOpen {
                std::fs::remove_file(&link_clone).unwrap();
                symlink(&loop_clone, &link_clone);
            }
        })));
        let error = resolve_for_display(&capability).unwrap_err();
        set_hook(None);
        assert_eq!(error, ResolveError::Unavailable);
    }

    #[test]
    fn cross_device_same_inode_never_matches() {
        // External F1 (cell 3 cross-subvolume leg): render-time
        // identity is EXACT (dev, ino) — the btrfs device carve-out
        // applies only to cross-domain (maps-vs-stat) comparisons
        // at acquisition. Here both sides are opened-FD fstat
        // (same domain): distinct files on different btrfs
        // subvolumes routinely share inode numbers, so a dev
        // mismatch must refuse even when the opened side is btrfs
        // and the inode matches. On btrfs hosts this test
        // discriminates (old code accepted); elsewhere it pins.
        let dir = scratch("xdev");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let (device, inode) = identity_of(&real);
        let impostor = (device.wrapping_add(1), inode);
        // Establishment refuses the cross-device identity.
        assert_eq!(establish_locator(&real, impostor), None);
        // Render refuses it too (Changed, never a resolved path).
        let capability =
            RowCapability::new(impostor, File::open(&real).unwrap(), Some(real.clone()));
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Changed
        );
        assert_eq!(path_value(Some(&capability)), CHANGED);
    }

    #[test]
    fn replacement_retarget_and_removal_classify() {
        // Cell 3 legs: replacement + retarget → (changed);
        // removal → (missing).
        let dir = scratch("races");
        let a = dir.join("a.so");
        let b = dir.join("b.so");
        std::fs::write(&a, b"A").unwrap();
        std::fs::write(&b, b"B").unwrap();
        // Replacement: same path, new file.
        let victim = dir.join("victim.so");
        std::fs::write(&victim, b"A").unwrap();
        let capability = capability_for(&victim);
        std::fs::remove_file(&victim).unwrap();
        std::fs::write(&victim, b"B").unwrap();
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Changed
        );
        assert_eq!(path_value(Some(&capability)), CHANGED);
        // Retarget: same link, new target.
        let link = dir.join("link.so");
        symlink(&a, &link);
        let capability = capability_for(&link);
        std::fs::remove_file(&link).unwrap();
        symlink(&b, &link);
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Changed
        );
        // Removal: path gone (the retained FD still pins the
        // inode — the PATH is what's missing).
        let doomed = dir.join("doomed.so");
        std::fs::write(&doomed, b"x").unwrap();
        let capability = capability_for(&doomed);
        std::fs::remove_file(&doomed).unwrap();
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Missing
        );
        assert_eq!(path_value(Some(&capability)), MISSING);
    }

    #[test]
    fn replacement_between_open_and_chase_suppresses() {
        // Cell 3 race leg (external round-2 note 1): replace the
        // target AFTER the atomic open pinned it but BEFORE the
        // chase verify runs. The retained-identity anchor must
        // catch it (Changed), never name the replacement.
        let dir = scratch("race-open-chase");
        let victim = dir.join("victim.so");
        std::fs::write(&victim, b"A").unwrap();
        let capability = capability_for(&victim);
        let victim_clone = victim.clone();
        set_hook(Some(Box::new(move |event| {
            if event == HookEvent::AfterAtomicOpen {
                std::fs::remove_file(&victim_clone).unwrap();
                std::fs::write(&victim_clone, b"B").unwrap();
            }
        })));
        let error = resolve_for_display(&capability).unwrap_err();
        set_hook(None);
        assert_eq!(error, ResolveError::Changed);
        assert_eq!(path_value(Some(&capability)), CHANGED);
    }

    #[test]
    fn establish_proves_or_refuses() {
        // Cell 9 leg: establishment proves the locator against
        // the verified identity — mismatches, magic spellings,
        // and unknown paths yield no locator.
        let dir = scratch("establish");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let identity = identity_of(&real);
        assert_eq!(establish_locator(&real, identity), Some(real.clone()));
        // Wrong identity → refused.
        let other = dir.join("other.so");
        std::fs::write(&other, b"y").unwrap();
        assert_eq!(establish_locator(&other, identity), None);
        // Magic spelling → refused even with the TRUE identity
        // of the process executable.
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let exe_identity = identity_of(&exe);
        let magic = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        assert_eq!(establish_locator(&magic, exe_identity), None);
        // Missing path → refused.
        assert_eq!(establish_locator(&dir.join("absent.so"), identity), None);
    }

    #[test]
    fn establish_absolutizes_relative_candidates() {
        let cwd = std::env::current_dir().unwrap();
        let name = format!(
            "ossl-resolve-rel-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let relative = PathBuf::from(&name).join("f.so");
        let absolute = cwd.join(&relative);
        std::fs::create_dir(cwd.join(&name)).unwrap();
        std::fs::write(&absolute, b"x").unwrap();
        let identity = identity_of(&absolute);
        assert_eq!(
            establish_locator(&relative, identity),
            Some(absolute.clone())
        );
        std::fs::remove_file(&absolute).unwrap();
        std::fs::remove_dir(cwd.join(&name)).unwrap();
    }

    #[test]
    fn display_sanitizes_and_bounds_verified_paths() {
        // Cell 8: the actual control surface — OSC + DCS + CR/LF
        // + bidi + overlength on a VERIFIED path.
        let hostile = "a\x1b]0;title\x07b\x1bPqDCS\x1bc\rd\n\
             e\u{202e}f\u{200b}g";
        let shown = display_path(Path::new(hostile));
        assert!(!shown.contains('\x1b'), "{shown:?}");
        assert!(!shown.contains('\x07'), "{shown:?}");
        assert!(!shown.contains('\r'), "{shown:?}");
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(!shown.contains('\u{202e}'), "{shown:?}");
        assert!(!shown.contains('\u{200b}'), "{shown:?}");
        assert!(shown.contains('?'), "{shown:?}");
        // 300 chars → 200 with `…`.
        let long = format!("/{}", "x".repeat(300));
        let shown = display_path(Path::new(&long));
        assert_eq!(shown.chars().count(), 200);
        assert!(shown.ends_with('…'), "{shown:?}");
        // Exactly 200 passes through unmarked.
        let exact = format!("/{}", "y".repeat(199));
        assert_eq!(exact.chars().count(), 200);
        assert!(!display_path(Path::new(&exact)).ends_with('…'));
        // Ordinary paths pass through byte-identical.
        assert_eq!(display_path(Path::new("/usr/lib/x.so")), "/usr/lib/x.so");
        // Defense in depth: literal /proc/<digits> normalizes.
        assert_eq!(
            display_path(Path::new("/tmp/proc/1234/x")),
            "/tmp/proc/<pid>/x"
        );
    }

    #[test]
    fn errors_and_debug_carry_no_paths() {
        // Cell 10 leg: resolver error contexts and debug output
        // never bear path text.
        for error in [
            ResolveError::Missing,
            ResolveError::Changed,
            ResolveError::Unavailable,
        ] {
            let rendered = format!("{error:?}");
            assert!(!rendered.contains('/'), "{rendered:?}");
        }
        let dir = scratch("redact");
        let real = dir.join("SENTINEL-PATH-SEGMENT.so");
        std::fs::write(&real, b"x").unwrap();
        let mut sidecar = ResolveSidecar::default();
        sidecar.push(capability_for(&real));
        let rendered = format!("{sidecar:?}");
        assert!(!rendered.contains("SENTINEL"), "{rendered:?}");
        assert!(rendered.contains('1'), "{rendered:?}");
    }

    #[test]
    fn permission_and_length_failures_suppress() {
        // Cell 10: EACCES / ENAMETOOLONG → (unavailable).
        let dir = scratch("denied");
        let gated = dir.join("gated");
        std::fs::create_dir(&gated).unwrap();
        let real = gated.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let capability = capability_for(&real);
        // SAFETY: geteuid takes no arguments and always succeeds.
        if unsafe { libc::geteuid() } == 0 {
            // Root bypasses permission checks — the EACCES leg is
            // vacuous for privileged observers (loud skip; the
            // length leg below still runs, so the dir stays).
            eprintln!("SKIP permission leg: running as root");
        } else {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gated, std::fs::Permissions::from_mode(0o0)).unwrap();
            let error = resolve_for_display(&capability).unwrap_err();
            std::fs::set_permissions(&gated, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(error, ResolveError::Unavailable);
        }
        let toolong = dir.join("x".repeat(300));
        let probe = dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        let capability = RowCapability::new(
            identity_of(&probe),
            File::open(&probe).unwrap(),
            Some(toolong),
        );
        assert_eq!(
            resolve_for_display(&capability).unwrap_err(),
            ResolveError::Unavailable
        );
    }

    #[test]
    fn non_utf8_names_display_lossy() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = scratch("nonutf8");
        let name = std::ffi::OsStr::from_bytes(b"evil-\xff.so");
        let real = dir.join(name);
        std::fs::write(&real, b"x").unwrap();
        let capability = capability_for(&real);
        let shown = path_value(Some(&capability));
        assert!(shown.contains('\u{fffd}'), "{shown:?}");
        assert!(!shown.contains("(unavailable)"), "{shown:?}");
    }

    #[test]
    fn invocation_counter_tracks_resolver_entries() {
        let dir = scratch("counter");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let before = resolve_invocations();
        let _ = establish_locator(&real, identity_of(&real));
        let capability = capability_for(&real);
        let _ = resolve_for_display(&capability);
        assert_eq!(resolve_invocations() - before, 2);
    }

    #[test]
    fn writer_gates_flag_terminal_and_status_without_io() {
        // Rules 1/2/4 + cells 1/5 legs: flag-off omits (None);
        // off-terminal and candidate rows render placeholders —
        // all three WITHOUT resolver invocation.
        let dir = scratch("writer-gates");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let identity = identity_of(&real);
        let mut sidecar = ResolveSidecar::default();
        sidecar.push(capability_for(&real));
        // Flag off: fragments omitted on every row shape.
        let writer = TerminalPathWriter::new(false, true, &sidecar);
        let before = resolve_invocations();
        assert_eq!(writer.fragment(IdentityStatus::Verified, identity), None);
        assert_eq!(
            writer.fragment(IdentityStatus::LocatorCandidate, identity),
            None
        );
        assert_eq!(writer.fragment_module(identity), None);
        assert!(writer.object_rows(&[]).is_empty());
        assert!(writer.module_rows(&[]).is_empty());
        assert_eq!(resolve_invocations() - before, 0);
        // Flag on, off-terminal: placeholder, no I/O.
        let writer = TerminalPathWriter::new(true, false, &sidecar);
        let before = resolve_invocations();
        assert_eq!(
            writer.fragment(IdentityStatus::Verified, identity),
            Some(NOT_A_TERMINAL.to_string())
        );
        assert_eq!(
            writer.fragment_module(identity),
            Some(NOT_A_TERMINAL.to_string())
        );
        assert_eq!(resolve_invocations() - before, 0);
        // Flag on, terminal, candidate: unverified, no I/O.
        let writer = TerminalPathWriter::new(true, true, &sidecar);
        let before = resolve_invocations();
        assert_eq!(
            writer.fragment(IdentityStatus::LocatorCandidate, identity),
            Some(UNVERIFIED.to_string())
        );
        assert_eq!(resolve_invocations() - before, 0);
    }

    #[test]
    fn writer_resolves_verified_and_reports_join_misses() {
        let dir = scratch("writer-resolve");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let identity = identity_of(&real);
        let mut sidecar = ResolveSidecar::default();
        sidecar.push(capability_for(&real));
        let writer = TerminalPathWriter::new(true, true, &sidecar);
        assert_eq!(
            writer.fragment(IdentityStatus::Verified, identity),
            Some(real.to_string_lossy().into_owned())
        );
        assert_eq!(
            writer.fragment(IdentityStatus::Verified, (u64::MAX, u64::MAX)),
            Some(UNAVAILABLE.to_string())
        );
        assert_eq!(
            writer.fragment_module(identity),
            Some(real.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn writer_change_fragment_reads_values_fail_closed() {
        // watch.rs renders from JSON values: status words map
        // strictly; unknown words and unjoinable identities fail
        // closed; the resolved string never enters the carrier.
        let dir = scratch("writer-change");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let (device, inode) = identity_of(&real);
        let mut sidecar = ResolveSidecar::default();
        sidecar.push(capability_for(&real));
        let writer = TerminalPathWriter::new(true, true, &sidecar);
        let module = serde_json::json!({
            "identity_status": "verified",
            "info": {"device": device, "inode": inode, "sha256": "ab"},
        });
        assert_eq!(
            writer.change_fragment(&module),
            Some(real.to_string_lossy().into_owned())
        );
        // The carrier gained no path: re-serialize and confirm.
        assert!(!serde_json::to_string(&module).unwrap().contains("real.so"));
        for (status, want) in [
            ("locator_candidate", UNVERIFIED),
            ("bogus_future_word", UNVERIFIED),
        ] {
            let module = serde_json::json!({
                "identity_status": status,
                "info": {"device": device, "inode": inode},
            });
            assert_eq!(writer.change_fragment(&module).as_deref(), Some(want));
        }
        for module in [
            serde_json::json!({"identity_status": "verified"}),
            serde_json::json!({"identity_status": "verified", "info": {}}),
            serde_json::json!({
                "identity_status": "verified",
                "info": {"device": "x", "inode": inode},
            }),
            serde_json::json!({
                "identity_status": "verified",
                "info": {"device": u64::MAX, "inode": u64::MAX},
            }),
        ] {
            assert_eq!(
                writer.change_fragment(&module).as_deref(),
                Some(UNAVAILABLE)
            );
        }
        // Flag-off omits even well-formed values.
        let writer = TerminalPathWriter::new(false, true, &sidecar);
        assert_eq!(
            writer.change_fragment(&serde_json::json!({
                "identity_status": "verified",
                "info": {"device": device, "inode": inode},
            })),
            None
        );
    }

    fn writer_module_record(
        sha256: &str,
        identity: (u64, u64),
        status: IdentityStatus,
    ) -> crate::inventory::ModuleRecord {
        crate::inventory::ModuleRecord {
            info: crate::inventory::ModuleInfo {
                sha256: sha256.to_string(),
                device: identity.0,
                inode: identity.1,
                size_bytes: 0,
                architecture: crate::inventory::Architecture::X86_64,
                kind: crate::inventory::ObjectKind::Other,
                exports: Vec::new(),
                depends_on_libcrypto: false,
                depends_on_libssl: false,
                file_soname: None,
                file_openssl_version: None,
                file_version_status: crate::inventory::FileVersionStatus::Absent,
            },
            identity_status: status,
            verified_path: None,
            verified_path_unavailable: None,
            maps_spelling: None,
        }
    }

    #[test]
    fn writer_object_rows_shape() {
        use crate::inventory::{IdentityAvailability, IdentityStatus, ProcessRecord};
        let dir = scratch("writer-rows");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let identity = identity_of(&real);
        let mut sidecar = ResolveSidecar::default();
        sidecar.push(capability_for(&real));
        let writer = TerminalPathWriter::new(true, true, &sidecar);
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let processes = vec![ProcessRecord {
            interval: crate::inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            namespaces: crate::inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
            pid: 4242,
            starttime: 7,
            comm: None,
            comm_status: IdentityAvailability::Unreadable,
            exe: None,
            exe_status: IdentityAvailability::Unreadable,
            modules: vec![
                writer_module_record(sha, identity, IdentityStatus::Verified),
                writer_module_record(sha, (1, 2), IdentityStatus::LocatorCandidate),
            ],
            provider_activation: crate::inventory::ObservationState::Unknown,
            provider_interfaces: crate::inventory::ObservationState::Unknown,
            execution: crate::inventory::ObservationState::NotObserved,
        }];
        let rows = writer.object_rows(&processes);
        assert_eq!(rows.len(), 2);
        // v0.6.0 P0-3 shape: kind word, 12-hex label, hyphenated
        // identity, size, path, file version evidence.
        assert!(
            rows[0].starts_with("  other sha256=0123456789ab identity=verified size=0 path="),
            "{}",
            rows[0]
        );
        assert!(rows[0].contains("real.so"), "{}", rows[0]);
        assert!(rows[0].ends_with("version=none"), "{}", rows[0]);
        assert_eq!(
            rows[1],
            "  other sha256=0123456789ab identity=locator-candidate size=0 path=(unverified) version=none"
        );
        // Flag-off: rows still render (the flag gates only live TTY
        // re-resolution); with no machine evidence the path is
        // honestly unavailable.
        let writer = TerminalPathWriter::new(false, true, &sidecar);
        let rows = writer.object_rows(&processes);
        assert_eq!(rows.len(), 2);
        assert!(
            rows[0].ends_with("path=(unavailable) version=none"),
            "{}",
            rows[0]
        );
    }

    #[test]
    fn writer_rows_show_machine_evidence_off_terminal() {
        use crate::inventory::{
            IdentityAvailability, IdentityStatus, LocatorKind, MapsSource, MapsSpelling,
            MapsVerification, PathEncoding, ProcessRecord, VerifiedPath,
        };
        let sidecar = ResolveSidecar::default();
        // Piped even with the flag: machine verified_path wins over
        // the old (not-a-terminal) placeholder (v0.6.0 D1).
        let mut verified = writer_module_record(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            (8, 100),
            IdentityStatus::Verified,
        );
        verified.verified_path = Some(VerifiedPath {
            path: "/usr/lib/libcrypto.so.3".to_string(),
            path_encoding: PathEncoding::Utf8,
            locator_kind: LocatorKind::HostDirect,
            capture_unix_ms: None,
        });
        verified.maps_spelling = Some(MapsSpelling {
            spelling: "/usr/lib/libcrypto.so.3".to_string(),
            source: MapsSource::ProcMaps,
            verification: MapsVerification::Unverified,
        });
        verified.info.file_openssl_version = Some("OpenSSL 3.5.1".to_string());
        let mut candidate = writer_module_record("ab", (8, 200), IdentityStatus::LocatorCandidate);
        candidate.maps_spelling = Some(MapsSpelling {
            spelling: "/memfd:jit (deleted)".to_string(),
            source: MapsSource::ProcMaps,
            verification: MapsVerification::Unverified,
        });
        candidate.info.file_soname = Some("libfoo.so.1".to_string());
        let mut bare = writer_module_record("cd", (8, 300), IdentityStatus::LocatorCandidate);
        bare.info.file_soname = Some("lib\x07bar.so".to_string());
        let processes = vec![ProcessRecord {
            interval: crate::inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            namespaces: crate::inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
            pid: 4242,
            starttime: 7,
            comm: None,
            comm_status: IdentityAvailability::Unreadable,
            exe: None,
            exe_status: IdentityAvailability::Unreadable,
            modules: vec![verified, candidate, bare],
            provider_activation: crate::inventory::ObservationState::Unknown,
            provider_interfaces: crate::inventory::ObservationState::Unknown,
            execution: crate::inventory::ObservationState::NotObserved,
        }];
        for (flag, terminal) in [(true, false), (false, false), (false, true)] {
            let writer = TerminalPathWriter::new(flag, terminal, &sidecar);
            let rows = writer.object_rows(&processes);
            assert_eq!(rows.len(), 3, "flag={flag} terminal={terminal}");
            assert_eq!(
                rows[0],
                "  other sha256=0123456789ab identity=verified size=0 path=/usr/lib/libcrypto.so.3 version=OpenSSL 3.5.1",
                "flag={flag} terminal={terminal}"
            );
            assert_eq!(
                rows[1],
                "  other sha256=ab identity=locator-candidate size=0 path=(unverified maps hint: /memfd:jit (deleted)) version=libfoo.so.1",
                "flag={flag} terminal={terminal}"
            );
            // No evidence at all: unavailable path, sanitized SONAME.
            assert_eq!(
                rows[2],
                "  other sha256=cd identity=locator-candidate size=0 path=(unavailable) version=lib?bar.so",
                "flag={flag} terminal={terminal}"
            );
        }
        // Overlong maps hints truncate to 80 chars, marked.
        let mut long = writer_module_record("ef", (8, 400), IdentityStatus::LocatorCandidate);
        long.maps_spelling = Some(MapsSpelling {
            spelling: format!("/{}", "s".repeat(200)),
            source: MapsSource::ProcMaps,
            verification: MapsVerification::Unverified,
        });
        let mut one = processes.clone();
        one[0].modules = vec![long];
        let writer = TerminalPathWriter::new(false, false, &sidecar);
        let rows = writer.object_rows(&one);
        let path = rows[0]
            .split_once("path=")
            .unwrap()
            .1
            .strip_suffix(" version=none")
            .unwrap();
        assert_eq!(path.chars().count(), 80, "{path}");
        assert!(path.ends_with('…'), "{path}");
        assert!(path.starts_with("(unverified maps hint: /sss"), "{path}");
    }

    #[test]
    fn writer_module_rows_omit_path_without_flag() {
        use crate::inventory::{Architecture, FileVersionStatus, ModuleInfo, ObjectKind};
        let sidecar = ResolveSidecar::default();
        let module = ModuleInfo {
            sha256: "0123456789abcdef".to_string(),
            device: 8,
            inode: 100,
            size_bytes: 4096,
            architecture: Architecture::X86_64,
            kind: ObjectKind::Other,
            exports: Vec::new(),
            depends_on_libcrypto: false,
            depends_on_libssl: false,
            file_soname: Some("libfoo.so.1".to_string()),
            file_openssl_version: None,
            file_version_status: FileVersionStatus::Absent,
        };
        // Flag-absent: rows render with no path= anywhere (cell 5).
        let writer = TerminalPathWriter::new(false, true, &sidecar);
        assert_eq!(
            writer.module_rows(std::slice::from_ref(&module)),
            vec!["  other sha256=0123456789ab size=4096 version=libfoo.so.1".to_string()]
        );
        // Piped with the flag: the module route has no machine path
        // evidence, so the historical placeholder stands.
        let writer = TerminalPathWriter::new(true, false, &sidecar);
        assert_eq!(
            writer.module_rows(std::slice::from_ref(&module)),
            vec![
                "  other sha256=0123456789ab size=4096 path=(not-a-terminal) version=libfoo.so.1"
                    .to_string()
            ]
        );
    }

    #[test]
    fn sidecar_joins_by_exact_identity() {
        let dir = scratch("sidecar");
        let a = dir.join("a.so");
        let b = dir.join("b.so");
        std::fs::write(&a, b"A").unwrap();
        std::fs::write(&b, b"B").unwrap();
        let mut sidecar = ResolveSidecar::default();
        assert!(sidecar.is_empty());
        sidecar.push(capability_for(&a));
        sidecar.push(capability_for(&b));
        assert_eq!(sidecar.len(), 2);
        assert!(sidecar.lookup(identity_of(&a)).is_some());
        assert!(sidecar.lookup(identity_of(&b)).is_some());
        assert!(sidecar.lookup((u64::MAX, u64::MAX)).is_none());
        // Clones share custody (same rows, dup'd FDs pin on).
        let dupe = sidecar.clone();
        assert_eq!(sidecar, dupe);
    }

    #[test]
    fn v060_encode_machine_path_verbatim_escapes_and_bounds() {
        use crate::inventory::PathEncoding;
        // Valid UTF-8 publishes verbatim — controls included
        // (machine evidence is lossless, unlike display).
        let (text, encoding) = encode_machine_path(b"/usr/lib/x.so");
        assert_eq!(text, "/usr/lib/x.so");
        assert_eq!(encoding, PathEncoding::Utf8);
        let hostile = "a\x1b]0;b\x07c\r\nd";
        let (text, encoding) = encode_machine_path(hostile.as_bytes());
        assert_eq!(text, hostile);
        assert_eq!(encoding, PathEncoding::Utf8);
        // Exactly 4096 chars passes unmarked; 4097 truncates marked.
        let exact = "x".repeat(MACHINE_PATH_CHARS);
        let (text, _) = encode_machine_path(exact.as_bytes());
        assert_eq!(text, exact);
        let over = "y".repeat(MACHINE_PATH_CHARS + 1);
        let (text, encoding) = encode_machine_path(over.as_bytes());
        assert_eq!(text.chars().count(), MACHINE_PATH_CHARS);
        assert!(text.ends_with('…'), "{text:?}");
        assert_eq!(encoding, PathEncoding::Utf8);
        // Invalid bytes escape `%XX` (uppercase hex), valid runs verbatim.
        let (text, encoding) = encode_machine_path(b"/lib/\xff\xfe.so");
        assert_eq!(text, "/lib/%FF%FE.so");
        assert_eq!(encoding, PathEncoding::Utf8PercentEscaped);
        // Escaped truncation never splits an escape: a cut landing on
        // `%F` backs off to the escape boundary (12285 + `…`).
        let raw = vec![0xff; MACHINE_PATH_ESCAPED_CHARS];
        let (text, encoding) = encode_machine_path(&raw);
        assert_eq!(encoding, PathEncoding::Utf8PercentEscaped);
        assert_eq!(text.chars().count(), MACHINE_PATH_ESCAPED_CHARS - 2);
        assert!(text.ends_with("…"), "{text:?}");
        assert!(text[..text.len() - '…'.len_utf8()].ends_with("%FF"));
        // A cut landing on a bare `%` backs off one char instead.
        let mut raw = vec![b'a'];
        raw.extend(std::iter::repeat_n(0xff, MACHINE_PATH_ESCAPED_CHARS));
        let (text, _) = encode_machine_path(&raw);
        assert!(text.ends_with('…'));
        assert!(text.chars().count() <= MACHINE_PATH_ESCAPED_CHARS);
        let body = text.trim_end_matches('…');
        assert!(!body.ends_with('%'), "{body:?}");
        // Every retained `%` still opens a complete escape.
        let chars: Vec<char> = body.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c == '%' {
                assert!(chars.get(i + 1).is_some_and(|c| c.is_ascii_hexdigit()));
                assert!(chars.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    #[test]
    fn v060_publish_verified_path_pairs_path_or_reason() {
        use crate::inventory::{LocatorKind, PathEncoding, PathUnavailableReason};
        // Proven locator publishes the CANONICAL path (chain links
        // resolve away — custody, not maps text).
        let dir = scratch("publish");
        let real = dir.join("real.so");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.join("link.so");
        symlink(&real, &link);
        let capability = capability_for(&link);
        let (path, reason) = publish_verified_path(&capability);
        let path = path.expect("proven locator publishes");
        assert_eq!(path.path, real.to_string_lossy());
        assert_eq!(path.path_encoding, PathEncoding::Utf8);
        assert_eq!(path.locator_kind, LocatorKind::HostDirect);
        assert!(path.capture_unix_ms.is_some());
        assert_eq!(reason, None);
        // No locator: finite reason, never a path.
        let bare = RowCapability::new(identity_of(&real), File::open(&real).unwrap(), None);
        assert_eq!(
            publish_verified_path(&bare),
            (None, Some(PathUnavailableReason::NoLocator))
        );
        // Removal after custody: Missing (the retained FD still pins
        // the inode — the PATH is what's missing).
        let doomed = dir.join("doomed.so");
        std::fs::write(&doomed, b"x").unwrap();
        let capability = capability_for(&doomed);
        std::fs::remove_file(&doomed).unwrap();
        assert_eq!(
            publish_verified_path(&capability),
            (None, Some(PathUnavailableReason::Missing))
        );
        // Magic spelling: ResolveFailed, never the spelling.
        let magic = RowCapability::new(
            identity_of(&real),
            File::open(&real).unwrap(),
            Some(PathBuf::from(format!("/proc/{}/exe", std::process::id()))),
        );
        let (path, reason) = publish_verified_path(&magic);
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
    }

    #[test]
    fn v060_container_locator_rejects_escape_and_recycle() {
        let dir = std::fs::File::open("/proc/self").unwrap();
        // `..` escaping above the target root fd must fail closed.
        let escape = std::path::Path::new("/../../../../etc/hostname");
        assert!(super::establish_container_locator(&dir, escape, (0, 0)).is_none());
        // Wrong retained identity (stand-in for PID-reuse/starttime
        // mismatch) must fail closed, never publish the candidate.
        let real = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libcrypto.so.3");
        assert!(super::establish_container_locator(&dir, real, (1, 1)).is_none());
    }

    // v0.6.0 D3 agent-runnable positive: `/proc/self` is its own
    // target, so the root-fd arm proves a real file with no backing
    // verification. Kind-agnostic at this level — on overlay hosts
    // the layer arm legitimately wins first; the KIND→publish
    // mapping is pinned by the procfs publish test and the bwrap
    // integration instead.
    #[test]
    fn v060_container_locator_proves_self_rooted_file() {
        use crate::inventory::LocatorKind;
        let lib = [
            "/usr/lib64/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/lib64/libcrypto.so.3",
        ]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists());
        let Some(lib) = lib else {
            eprintln!("SKIP: no system libcrypto for the container-locator positive test");
            return;
        };
        let dir = std::fs::File::open("/proc/self").unwrap();
        let identity = identity_of(Path::new(lib));
        // Root-arm core directly: canonical spelling, pinned identity.
        let anchored = super::verify_root_anchored(&dir, Path::new(lib), identity)
            .expect("self-rooted walk proves the file");
        let expected = std::fs::canonicalize(lib).unwrap();
        assert_eq!(anchored, expected);
        // Full establish: a proven kind naming the same file.
        let (path, kind) = super::establish_container_locator(&dir, Path::new(lib), identity)
            .expect("container arm proves the self-rooted file");
        assert!(
            kind == LocatorKind::ProcRootAnchored || kind == LocatorKind::ContainerLayer,
            "{kind:?}"
        );
        assert_eq!(identity_of(&path), identity);
        if kind == LocatorKind::ProcRootAnchored {
            assert_eq!(path, expected);
        }
    }

    #[test]
    fn v060f1_rooted_walk_component_swap_cannot_escape() {
        // F1: deterministic dir→symlink swap inside the
        // fstatat→open window must fail the walk closed — the
        // swapped absolute symlink is never followed out of the
        // root fd, even when the escape landing carries the
        // retained identity (shared-file stand-in: only
        // confinement fails this closed, never identity).
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = scratch("f1-race");
        let root = dir.join("root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("sub").join("keep"), b"k").unwrap();
        std::fs::write(outside.join("file"), b"host").unwrap();
        // Positive control (no hook): the unattacked walk proves.
        let root_fd = File::open(&root).unwrap();
        assert!(super::walk_rooted(&root_fd, b"/sub/keep").is_some());
        // The attack: `root/sub` (a proven dir) becomes an
        // absolute symlink to `outside` after classification,
        // before the descent open.
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        let sub = root.join("sub");
        let sub_clone = sub.clone();
        let outside_clone = outside.clone();
        set_hook(Some(Box::new(move |event| {
            if event == (HookEvent::BeforeRootedStep { index: 0 })
                && !fired_clone.swap(true, Ordering::SeqCst)
            {
                std::fs::remove_dir_all(&sub_clone).unwrap();
                symlink(&outside_clone, &sub_clone);
            }
        })));
        let walked = super::walk_rooted(&root_fd, b"/sub/file");
        set_hook(None);
        assert!(
            fired.load(Ordering::SeqCst),
            "hook must fire (anti-vacuity)"
        );
        assert!(
            walked.is_none(),
            "swapped symlink must not be followed out of the root"
        );
    }

    #[test]
    fn v060f1_rooted_escape_publishes_null_with_finite_reason() {
        // F1 at the publish layer: an in-window swap at BOTH the
        // first walk and the re-proof walk must surface as null +
        // `ResolveFailed`, never a locator. Root-cause note: a
        // single persistent swap does NOT escape publish even
        // pre-fix — the re-proof re-classifies it textually and
        // `rebuilt != canonical` fails closed. The end-to-end
        // exploit is a flicker (dir at each classification, link
        // at each descent open), choreographed here by swapping
        // at the `sub` step and restoring at the `file` step in
        // each walk. Pre-fix both walks follow the flicker, pin
        // the shared identity, and agree on the spelling (Some);
        // post-fix the first descent ELOOPs (None + reason).
        use crate::inventory::PathUnavailableReason;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = scratch("f1-publish");
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let retained = elsewhere.join("file");
        std::fs::write(&retained, b"host").unwrap();
        let identity = identity_of(&retained);
        let candidate = sub.join("file");
        // Walk steps are 0-based over popped components, so `sub`
        // (second-to-last normal component) fires at count - 3
        // (`components` counts the leading root as well), and the
        // link-free candidate keeps `file` immediately after.
        let sub_step = candidate.components().count() - 3;
        let file_step = sub_step + 1;
        let swaps = std::sync::Arc::new(AtomicUsize::new(0));
        let swaps_clone = swaps.clone();
        let sub_clone = sub.clone();
        let elsewhere_clone = elsewhere.clone();
        set_hook(Some(Box::new(move |event| {
            if event == (HookEvent::BeforeRootedStep { index: sub_step }) {
                swaps_clone.fetch_add(1, Ordering::SeqCst);
                std::fs::remove_dir(&sub_clone).unwrap();
                symlink(&elsewhere_clone, &sub_clone);
            } else if event == (HookEvent::BeforeRootedStep { index: file_step }) {
                std::fs::remove_file(&sub_clone).unwrap();
                std::fs::create_dir(&sub_clone).unwrap();
            }
        })));
        let proc_dir = File::open("/proc/self").unwrap();
        let (path, reason) = super::publish_root_anchored(&proc_dir, &candidate, identity);
        set_hook(None);
        assert!(
            swaps.load(Ordering::SeqCst) >= 1,
            "hook must swap in-window (anti-vacuity)"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
    }

    /// Owned test child: SIGKILL + reap on drop, so no stray or
    /// zombie child survives any path (including assertion
    /// panics). Best-effort and exact-pid only.
    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn v060f3_replacement_between_walk_and_reproof_fails_closed() {
        // F3 root-walk replacement: the target is replaced (new
        // inode, different bytes) after the first walk passed, so
        // the fresh-root re-proof's identity leg must fire — null
        // + `ResolveFailed`, never the retained spelling. The
        // fired flag proves the hook (hence the first walk, the
        // backing match, and the incarnation bracket) completed.
        use crate::inventory::PathUnavailableReason;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = scratch("f3-replace");
        let target = dir.join("lib.so");
        std::fs::write(&target, b"v1").unwrap();
        let identity = identity_of(&target);
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        let target_clone = target.clone();
        set_hook(Some(Box::new(move |event| {
            if event == HookEvent::BeforeRootedReproof && !fired_clone.swap(true, Ordering::SeqCst)
            {
                let fresh = target_clone.with_extension("new");
                std::fs::write(&fresh, b"v2-different").unwrap();
                std::fs::rename(&fresh, &target_clone).unwrap();
            }
        })));
        let proc_dir = File::open("/proc/self").unwrap();
        let (path, reason) = super::publish_root_anchored(&proc_dir, &target, identity);
        set_hook(None);
        assert!(
            fired.load(Ordering::SeqCst),
            "hook must fire (anti-vacuity)"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
    }

    #[test]
    fn v060f3_copyup_identical_bytes_fails_closed() {
        // F3 copy-up: the target is replaced by a content-IDENTICAL
        // copy (fresh inode, same bytes — what an overlay copy-up
        // looks like at the verify layer) after the first walk
        // passed. Verification is identity, not content, so the
        // re-proof identity leg must fire all the same.
        use crate::inventory::PathUnavailableReason;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = scratch("f3-copyup");
        let target = dir.join("lib.so");
        std::fs::write(&target, b"same-bytes").unwrap();
        let identity = identity_of(&target);
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        let target_clone = target.clone();
        set_hook(Some(Box::new(move |event| {
            if event == HookEvent::BeforeRootedReproof && !fired_clone.swap(true, Ordering::SeqCst)
            {
                let fresh = target_clone.with_extension("up");
                std::fs::write(&fresh, b"same-bytes").unwrap();
                std::fs::rename(&fresh, &target_clone).unwrap();
            }
        })));
        let proc_dir = File::open("/proc/self").unwrap();
        let (path, reason) = super::publish_root_anchored(&proc_dir, &target, identity);
        set_hook(None);
        assert!(
            fired.load(Ordering::SeqCst),
            "hook must fire (anti-vacuity)"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
    }

    #[test]
    fn v060f3_namespace_change_mid_verify_fails_closed() {
        // F3 namespace change: a live child enters a new user+mount
        // namespace (one `unshare` call) between the incarnation
        // bracket's two reads, synchronized by hook→stdin→ack (no
        // sleeps, no timing). Both reads succeed with equal
        // starttime and different mount-ns identity, so the
        // `before != after` mismatch leg fires — null +
        // `ResolveFailed`. Post-assertions prove the mismatch
        // (not a read failure): the child is alive throughout and
        // the namespace pair straddles the change.
        use crate::inventory::PathUnavailableReason;
        use std::io::{Read as _, Write as _};
        use std::process::Stdio;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = scratch("f3-ns");
        let target = dir.join("lib.so");
        std::fs::write(&target, b"x").unwrap();
        let identity = identity_of(&target);
        let mut child = ChildGuard(
            std::process::Command::new("python3")
                .arg("-c")
                .arg(
                    "import ctypes, sys, time; \
                     sys.stdin.buffer.read(1); \
                     rc = ctypes.CDLL(None).unshare(0x10000000 | 0x00020000); \
                     sys.stdout.buffer.write(b'1' if rc == 0 else b'0'); \
                     sys.stdout.buffer.flush(); \
                     time.sleep(60)",
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let mut stdin = child.0.stdin.take().unwrap();
        let mut stdout = child.0.stdout.take().unwrap();
        let proc_dir = File::open(format!("/proc/{pid}")).unwrap();
        let (start_before, ns_before) =
            super::super::procfs::incarnation_direct(&proc_dir).expect("live target pre-read");
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        set_hook(Some(Box::new(move |event| {
            if event == (HookEvent::BeforeRootedStep { index: 0 })
                && !fired_clone.swap(true, Ordering::SeqCst)
            {
                stdin.write_all(b"x").unwrap();
                let mut ack = [0u8; 1];
                stdout.read_exact(&mut ack).unwrap();
                assert_eq!(ack, [b'1'], "child must enter the new namespaces");
            }
        })));
        let (path, reason) = super::publish_root_anchored(&proc_dir, &target, identity);
        set_hook(None);
        assert!(
            fired.load(Ordering::SeqCst),
            "hook must fire (anti-vacuity)"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
        // The mismatch leg (not a read failure): the child never
        // died, starttime is stable, the mount ns moved.
        assert!(child.0.try_wait().unwrap().is_none(), "target stays alive");
        let (start_after, ns_after) =
            super::super::procfs::incarnation_direct(&proc_dir).expect("live target post-read");
        assert_eq!(start_before, start_after);
        assert_ne!(ns_before, ns_after);
    }

    #[test]
    fn v060f3_exit_mid_verify_fails_closed() {
        // F3 real PID lifecycle (mid-verify exit): the target is
        // SIGKILLed and reaped between the bracket's two reads, so
        // the post-walk incarnation read fails and the bracket's
        // liveness clause fails closed — null + `ResolveFailed`.
        // The pre/post incarnation pair proves which leg fired:
        // `Some` before (the first read passed), `None` after.
        use crate::inventory::PathUnavailableReason;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = scratch("f3-exit");
        let target = dir.join("lib.so");
        std::fs::write(&target, b"x").unwrap();
        let identity = identity_of(&target);
        // The guard owns the child until the hook takes it: no
        // stray or zombie on any path, including pre-hook panics.
        let mut slot = Some(ChildGuard(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let proc_dir = File::open(format!("/proc/{}", slot.as_ref().unwrap().0.id())).unwrap();
        assert!(
            super::super::procfs::incarnation_direct(&proc_dir).is_some(),
            "target alive at the first read"
        );
        let fired = std::sync::Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        set_hook(Some(Box::new(move |event| {
            if event == (HookEvent::BeforeRootedStep { index: 0 })
                && !fired_clone.swap(true, Ordering::SeqCst)
            {
                let mut owned = slot.take().unwrap();
                owned.0.kill().unwrap();
                owned.0.wait().unwrap();
            }
        })));
        let (path, reason) = super::publish_root_anchored(&proc_dir, &target, identity);
        set_hook(None);
        assert!(
            fired.load(Ordering::SeqCst),
            "hook must fire (anti-vacuity)"
        );
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
        assert!(
            super::super::procfs::incarnation_direct(&proc_dir).is_none(),
            "reaped target reads fail"
        );
    }

    #[test]
    fn v060f3_exit_between_establish_and_publish_fails_closed() {
        // F3 real PID lifecycle (establish→publish reuse boundary):
        // the root arm PROVES a live target, the target is then
        // reaped, and publishing through the stale held dir must
        // fail closed — null + `ResolveFailed`. A literal
        // same-number reuse is unforceable (the kernel assigns
        // PIDs), but the held dir fd pins the OLD proc entry, so a
        // reused number reads through the stale entry exactly as
        // this dead one does: the re-proof, not the number, is the
        // boundary.
        use crate::inventory::PathUnavailableReason;
        let dir = scratch("f3-reuse");
        let target = dir.join("lib.so");
        std::fs::write(&target, b"x").unwrap();
        let identity = identity_of(&target);
        let mut child = ChildGuard(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let proc_dir = File::open(format!("/proc/{}", child.0.id())).unwrap();
        let locator =
            super::verify_root_anchored(&proc_dir, &target, identity).expect("live target proves");
        assert_eq!(locator, target);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let (path, reason) = super::publish_root_anchored(&proc_dir, &locator, identity);
        assert_eq!(path, None);
        assert_eq!(reason, Some(PathUnavailableReason::ResolveFailed));
    }
}
