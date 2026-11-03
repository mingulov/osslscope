// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapped-backing association: one retained-descriptor verification shared by
//! passive inventory and active observation.
//!
//! A mapping association proves that a caller-held candidate descriptor is the
//! actual backing of a target virtual-memory range at this instant, and the
//! returned [`BackingAssociation`] privately owns the identity/lifetime
//! witness needed to re-prove it later. The SAME candidate descriptor flows
//! through verification, parsing, attachment and revalidation; pathnames are
//! hints only and never authority.
//!
//! Two proof paths, selected by filesystem semantics (feature detection via
//! `fstatfs`, never distro or kernel-build enrollment):
//!
//! * Direct path: when both the candidate and the range-bound `map_files`
//!   descriptor live on filesystems with POSIX-stable `(st_dev, st_ino)`
//!   identity, full-fingerprint equality plus the range-bound open proves
//!   backing. No `pagemap` access is needed, so this path works
//!   unprivileged wherever `map_files` itself is readable.
//! * Witness path: any other filesystem (notably overlayfs, where the
//!   rendered identity is stable across copy-up while the backing changes)
//!   requires the page witness: a private nonexecuted one-page self-mapping
//!   of the candidate whose page-frame number (via `pagemap`) must equal the
//!   target range's page-frame number, plus a re-resolution check proving the
//!   registration path (`/proc/self/fd/N`, the same path a later uprobe
//!   attach resolves) still serves the same page. Equal bytes, equal
//!   rendered identities, or equal maps keys alone never verify.
//!
//! The page witness is sound because the observer's self-mapping is never
//! marked mergeable, so kernel same-page merging cannot merge it with any
//! other page: an equal frame number proves the target shares our page-cache
//! page, hence the same backing data. Both sides must be present file pages;
//! anything else (swapped, unmapped, withheld frame numbers) fails closed.
//!
//! No success on unreadable evidence, ever: denied, changed, unavailable and
//! unsupported outcomes are distinct [`BackingError`] variants and none of
//! them yields an association.

use super::NamespaceId;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;

/// Internal-only virtual-memory range under verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MappedRange {
    pub start: u64,
    pub end: u64,
}

/// Finite verification outcome. No variant carries paths, addresses or bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackingError {
    /// Evidence exists but the observer may not read it.
    Denied,
    /// Positive evidence of mismatch or change (wrong backing, copy-up,
    /// remap, exec, namespace change, content change).
    Changed,
    /// Evidence is transiently absent (unmapped page, raced exit, short read).
    Unavailable,
    /// The request or evidence type cannot carry backing proof (bad range,
    /// anonymous mapping, non-regular file, multi-mapping span).
    Unsupported,
}

pub(crate) fn classify_errno(errno: i32) -> BackingError {
    match errno {
        x if x == libc::EACCES || x == libc::EPERM => BackingError::Denied,
        _ => BackingError::Unavailable,
    }
}

fn last_error() -> BackingError {
    classify_errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

fn io_error(error: std::io::Error) -> BackingError {
    match error.raw_os_error() {
        Some(errno) => classify_errno(errno),
        None => BackingError::Unavailable,
    }
}

/// Caller-owned budget for backing IO and buffers (ER-5E-I2). Both production
/// callers implement this — inventory `Work` and the acquisition budget
/// adapter — so every backing allocation is reserved before it happens,
/// every read is accounted to the shared ceilings, and deadlines are
/// enforced between reads. Refusal surfaces as [`BackingError`]; the caller
/// maps it to its own precise limit gap.
pub(crate) trait BackingBudget {
    /// Enforce the caller deadline. Called before allocation and between reads.
    fn checkpoint(&mut self) -> Result<(), BackingError>;
    /// Clamp a planned read to the remaining read allowance; refuse when
    /// exhausted. Never returns 0 on success.
    fn allow_read(&mut self, want: usize) -> Result<usize, BackingError>;
    /// Account bytes just read. Called only for amounts `allow_read` admitted.
    fn commit_read(&mut self, bytes: u64) -> Result<(), BackingError>;
    /// Reserve buffer/state capacity before allocation. The returned lease is
    /// held by the buffer owner: retained buffers keep it for their lifetime
    /// while transient buffers drop it after use, releasing shared capacity.
    fn reserve_state(&mut self, bytes: usize) -> Result<BackingLease, BackingError>;
}

/// Shared-capacity lease held by backing buffers. Dropping a lease releases
/// its reservation; read charges are cumulative and never released. Payloads
/// are intentionally write-only RAII holders, never read.
#[allow(dead_code)]
pub(crate) enum BackingLease {
    Pool(crate::observation_memory::MemoryLease),
    Held(Box<dyn HeldCapacity>),
    /// No state budget exists on this path (reads are still charged).
    Uncharged,
}

impl BackingLease {
    pub(crate) fn held(capacity: impl HeldCapacity + 'static) -> Self {
        Self::Held(Box::new(capacity))
    }
}

/// Marker for caller-owned capacity reservations backing can retain without
/// naming the caller's budget types. Implemented by the acquisition side for
/// its state reservations.
pub(crate) trait HeldCapacity {}

/// Unbounded budget for the plan-pinned one-shot entry point and unit tests.
/// Production callers use the charged variants with real caller budgets.
struct UnboundedBudget;
impl BackingBudget for UnboundedBudget {
    fn checkpoint(&mut self) -> Result<(), BackingError> {
        Ok(())
    }
    fn allow_read(&mut self, want: usize) -> Result<usize, BackingError> {
        Ok(want.max(1))
    }
    fn commit_read(&mut self, _bytes: u64) -> Result<(), BackingError> {
        Ok(())
    }
    fn reserve_state(&mut self, _bytes: usize) -> Result<BackingLease, BackingError> {
        Ok(BackingLease::Uncharged)
    }
}

const MAX_MAPS_READ: usize = 4_194_304;
const MAX_MOUNTINFO_READ: usize = 1_048_576;
const MAX_STAT_READ: usize = 65_536;
const MAX_LAYER_CANDIDATES: usize = 16;

const PAGEMAP_PRESENT: u64 = 1 << 63;
const PAGEMAP_FILE: u64 = 1 << 61;
const PAGEMAP_PFN_MASK: u64 = (1 << 55) - 1;

fn filesystem_type(file: &File) -> Option<libc::c_long> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes stat on success and borrows an open FD.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0 {
        Some(unsafe { stat.assume_init() }.f_type)
    } else {
        None
    }
}

/// Filesystems where `(st_dev, st_ino)` plus ctime fingerprinting identifies
/// the backing stably: no view aliasing, no copy-up rebinding under a stable
/// rendered identity. Everything else requires the page witness.
fn direct_semantics(f_type: libc::c_long) -> bool {
    matches!(
        f_type,
        0xef53 | // ext family
        0x58465342 | // XFS
        0x9123683e | // Btrfs (anonymous st_dev per subvolume keeps identity unique)
        0x01021994 | // tmpfs
        0x858458f6 | // ramfs
        0x958458f6 | // hugetlbfs
        0x73717368 | // squashfs
        0xf2f52010 | // f2fs
        0x3153464a | // jfs
        0x2fc12fc1 // zfs
    )
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl From<&Metadata> for Fingerprint {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mode: m.mode(),
            nlink: m.nlink(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}

fn open_at(directory: &File, name: &[u8]) -> Result<File, BackingError> {
    let name = CString::new(name).map_err(|_| BackingError::Unsupported)?;
    // SAFETY: directory/name remain live; the returned FD is owned exactly
    // once. Nonblocking prevents FIFO open from waiting for a writer.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
    };
    if raw < 0 {
        return Err(last_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

const READ_CHUNK: usize = 8192;

/// Budget-charged procfs read: the buffer reservation precedes allocation,
/// each chunk is deadline-checked, clamped to the remaining read allowance
/// and committed after the syscall, and the per-file cap keeps its probe
/// byte. The caller holds the lease for as long as it keeps the bytes.
fn read_at_charged<B: BackingBudget>(
    directory: &File,
    name: &[u8],
    max: usize,
    budget: &mut B,
) -> Result<(Vec<u8>, BackingLease), BackingError> {
    budget.checkpoint()?;
    let mut file = open_at(directory, name)?;
    let lease = budget.reserve_state(max)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        budget.checkpoint()?;
        // Probe one byte beyond the per-file cap, without over-allocation.
        let allowed = max.saturating_sub(bytes.len()).saturating_add(1);
        let count = budget.allow_read(allowed.min(chunk.len()))?;
        let read = file.read(&mut chunk[..count]).map_err(io_error)?;
        budget.commit_read(read as u64)?;
        if read == 0 {
            return Ok((bytes, lease));
        }
        if read > max.saturating_sub(bytes.len()) {
            return Err(BackingError::Unavailable);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn number(bytes: &[u8], radix: u32) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(|b| (*b as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(bytes).ok()?, radix).ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VmaRecord {
    start: u64,
    end: u64,
    pgoff: u64,
    dev: u64,
    ino: u64,
    executable: bool,
}

fn parse_vma(line: &[u8]) -> Option<VmaRecord> {
    if line.contains(&0) {
        return None;
    }
    let mut fields = line.split(u8::is_ascii_whitespace);
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let device = fields.next()?;
    let inode = fields.next()?;
    let dash = range.iter().position(|b| *b == b'-')?;
    let start = number(&range[..dash], 16)?;
    let end = number(&range[dash + 1..], 16)?;
    if start >= end || perms.len() != 4 {
        return None;
    }
    let colon = device.iter().position(|b| *b == b':')?;
    let major = u32::try_from(number(&device[..colon], 16)?).ok()?;
    let minor = u32::try_from(number(&device[colon + 1..], 16)?).ok()?;
    Some(VmaRecord {
        start,
        end,
        pgoff: number(offset, 16)?,
        dev: libc::makedev(major, minor),
        ino: number(inode, 10)?,
        executable: perms.get(2) == Some(&b'x'),
    })
}

/// Malformed lines are skipped for lookup; continuity compares the matched
/// record, so any later mutation of our row still fails closed.
fn find_vma(maps: &[u8], range: &MappedRange) -> Option<VmaRecord> {
    maps.split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(parse_vma)
        .find(|vma| vma.start <= range.start && range.end <= vma.end)
}

fn starttime_charged<B: BackingBudget>(
    directory: &File,
    budget: &mut B,
) -> Result<u64, BackingError> {
    let bytes = read_at_charged(directory, b"stat", MAX_STAT_READ, budget)?.0;
    let end = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or(BackingError::Unavailable)?;
    bytes[end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|b| !b.is_empty())
        .nth(19)
        .and_then(|value| number(value, 10))
        .ok_or(BackingError::Unavailable)
}

fn namespace_id(directory: &File, name: &[u8]) -> Result<NamespaceId, BackingError> {
    let file = open_at(directory, name)?;
    let metadata = file.metadata().map_err(io_error)?;
    Ok(NamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn page_size() -> Result<u64, BackingError> {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        return Err(BackingError::Unavailable);
    }
    Ok(size as u64)
}

/// Test-only fault injection for ER-5E-I1: a writable handle of the candidate
/// plus the witness fault site (1 = candidate page, 2 = re-resolution page)
/// where the witness truncates the candidate to zero length. The truncation
/// lands deterministically between the size check and the page touch,
/// simulating a concurrent truncation. Production builds contain no hook.
#[cfg(test)]
static FAULT_TRUNCATE: std::sync::Mutex<Option<(File, u8)>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn fire_fault_hook(site: u8) {
    let guard = FAULT_TRUNCATE.lock().unwrap();
    if let Some((file, want)) = guard.as_ref() {
        if *want == site {
            let _ = file.set_len(0);
        }
    }
}

/// One guarded read-only private mapping of exactly one candidate page.
/// Never executable, never mergeable, never retained past verification.
struct SelfMap {
    address: *mut libc::c_void,
    length: usize,
}
// SAFETY: the mapping is private to this thread's verification call.
unsafe impl Send for SelfMap {}
impl SelfMap {
    fn map(candidate: &File, offset: u64, page: u64) -> Result<Self, BackingError> {
        let length = usize::try_from(page).map_err(|_| BackingError::Unavailable)?;
        let offset = libc::off_t::try_from(offset).map_err(|_| BackingError::Unavailable)?;
        // SAFETY: length is one runtime page, offset is page-aligned and
        // within the file; PROT_READ/MAP_PRIVATE on a borrowed O_RDONLY FD.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                candidate.as_raw_fd(),
                offset,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(last_error());
        }
        Ok(Self { address, length })
    }
    /// Touch one mapped byte through a fault-safe observer-self read: the
    /// kernel resolves the fault and reports a truncation (or unmapping)
    /// that lands after the size check as a failed or short read instead
    /// of delivering SIGBUS to a direct load. Same primitive the source
    /// anchor uses for its retained mapping.
    fn fault(&self, index: usize) -> Result<(), BackingError> {
        let mut byte = 0u8;
        let local = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(byte).cast(),
            iov_len: 1,
        };
        let remote = libc::iovec {
            // SAFETY: pointer arithmetic only; the address is consumed by
            // the checked read below, never dereferenced by us.
            iov_base: unsafe { (self.address as *mut u8).add(index) }.cast(),
            iov_len: 1,
        };
        // SAFETY: the destination is a live one-byte stack slot and the
        // source is one byte inside this owner's own fresh mapping. An
        // out-of-range or truncated source fails the call; no Rust
        // reference to mapping bytes is ever formed.
        let copied = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        if copied == 1 {
            Ok(())
        } else {
            Err(BackingError::Unavailable)
        }
    }
    fn start(&self) -> u64 {
        self.address as u64
    }
}
impl Drop for SelfMap {
    fn drop(&mut self) {
        // SAFETY: the exact range returned by the successful mmap above.
        unsafe {
            libc::munmap(self.address, self.length);
        }
    }
}

fn pread_exact(file: &File, offset: u64) -> Result<[u8; 8], BackingError> {
    let mut tries = 0;
    loop {
        let mut bytes = [0u8; 8];
        // SAFETY: borrowed FD, stack buffer, single 8-byte read.
        let read = unsafe {
            libc::pread(
                file.as_raw_fd(),
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                offset as libc::off_t,
            )
        };
        if read == 8 {
            return Ok(bytes);
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR && tries < 3 {
            tries += 1;
            continue;
        }
        if read < 0 {
            return Err(classify_errno(errno));
        }
        return Err(BackingError::Unavailable);
    }
}

/// Read one pagemap frame number. A present page with a zero frame means the
/// kernel withheld the number (privilege), which is denial, not absence.
fn pagemap_frame<B: BackingBudget>(
    pagemap: &File,
    address: u64,
    page: u64,
    budget: &mut B,
) -> Result<u64, BackingError> {
    let index = address / page;
    let offset = index.checked_mul(8).ok_or(BackingError::Unavailable)?;
    budget.allow_read(8)?;
    let entry = u64::from_le_bytes(pread_exact(pagemap, offset)?);
    budget.commit_read(8)?;
    if entry & PAGEMAP_PRESENT == 0 {
        return Err(BackingError::Unavailable);
    }
    let frame = entry & PAGEMAP_PFN_MASK;
    if frame == 0 {
        return Err(BackingError::Denied);
    }
    if entry & PAGEMAP_FILE == 0 {
        return Err(BackingError::Unavailable);
    }
    Ok(frame)
}

/// Captured process view: all verification inputs read once from the target
/// directory descriptor, so one capture serves every mapping of a process.
/// The directory descriptor itself is the process identity; no PID is kept.
pub(crate) struct BackingProcess {
    directory: File,
    starttime: u64,
    pid_namespace: NamespaceId,
    mount_namespace: NamespaceId,
    executable: Fingerprint,
    maps: Vec<u8>,
    /// Caller-budget leases for the retained maps buffer: the reservation
    /// lives exactly as long as the buffer it accounts for.
    _leases: Vec<BackingLease>,
}

impl BackingProcess {
    pub(crate) fn capture(target: &File) -> Result<Self, BackingError> {
        Self::capture_charged(target, &mut UnboundedBudget)
    }

    pub(crate) fn capture_charged<B: BackingBudget>(
        target: &File,
        budget: &mut B,
    ) -> Result<Self, BackingError> {
        budget.checkpoint()?;
        let directory = target.try_clone().map_err(io_error)?;
        let starttime = starttime_charged(&directory, budget)?;
        let pid_namespace = namespace_id(&directory, b"ns/pid")?;
        let mount_namespace = namespace_id(&directory, b"ns/mnt")?;
        let executable =
            Fingerprint::from(&open_at(&directory, b"exe")?.metadata().map_err(io_error)?);
        let (maps, lease) = read_at_charged(&directory, b"maps", MAX_MAPS_READ, budget)?;
        Ok(Self {
            directory,
            starttime,
            pid_namespace,
            mount_namespace,
            executable,
            maps,
            _leases: vec![lease],
        })
    }

    fn candidate_identity(
        candidate: &File,
    ) -> Result<(Fingerprint, Option<libc::c_long>), BackingError> {
        let metadata = candidate.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(BackingError::Unsupported);
        }
        Ok((Fingerprint::from(&metadata), filesystem_type(candidate)))
    }

    /// Open the range-bound `map_files` entry for a matched VMA. A missing
    /// entry means the mapping changed between the maps read and this open.
    fn target_file(&self, vma: &VmaRecord) -> Result<File, BackingError> {
        let name = format!("map_files/{:x}-{:x}", vma.start, vma.end);
        match open_at(&self.directory, name.as_bytes()) {
            Ok(file) => Ok(file),
            Err(error) => {
                if error == BackingError::Unavailable {
                    // By-range opens fail only when the VMA is gone.
                    return Err(BackingError::Changed);
                }
                Err(error)
            }
        }
    }

    /// Race tripwire: the range-bound open must still show the mapped inode.
    /// The Btrfs device carve-out stays tripwire-only (maps carries the
    /// superblock device there); identity itself always compares full native
    /// fingerprints including the device.
    fn check_target_keys(
        &self,
        target: &File,
        fingerprint: &Fingerprint,
        vma: &VmaRecord,
    ) -> Result<Option<libc::c_long>, BackingError> {
        if !fingerprint_matches_file(target, fingerprint) {
            return Err(BackingError::Changed);
        }
        if fingerprint.ino != vma.ino {
            return Err(BackingError::Changed);
        }
        let fstype = filesystem_type(target);
        if fingerprint.dev != vma.dev && fstype != Some(0x9123683e) {
            return Err(BackingError::Changed);
        }
        Ok(fstype)
    }

    fn verify_fast(
        &self,
        candidate: &Fingerprint,
        target: &Fingerprint,
    ) -> Result<Option<u64>, BackingError> {
        if candidate != target {
            return Err(BackingError::Changed);
        }
        Ok(None)
    }

    /// Page witness for stackable or unknown filesystems: the candidate's
    /// page must be the target range's page, and a fresh re-resolution of
    /// the candidate (the same `/proc/self/fd/N` path a later attach
    /// resolves) must serve the same page. Returns the witnessed frame.
    /// Both witness pages are reserved against the caller budget before
    /// either mapping is created; pagemap reads are charged as they happen.
    fn verify_witness<B: BackingBudget>(
        &self,
        range: &MappedRange,
        candidate: &File,
        candidate_fp: &Fingerprint,
        vma: &VmaRecord,
        budget: &mut B,
    ) -> Result<u64, BackingError> {
        budget.checkpoint()?;
        let page = page_size()?;
        let file_offset = vma
            .pgoff
            .checked_add(range.start - vma.start)
            .ok_or(BackingError::Unsupported)?;
        if file_offset >= candidate_fp.size {
            return Err(BackingError::Unavailable);
        }
        let aligned = file_offset & !(page - 1);
        let index =
            usize::try_from(file_offset - aligned).map_err(|_| BackingError::Unavailable)?;
        let page_bytes = usize::try_from(page).map_err(|_| BackingError::Unavailable)?;
        let _witness_pages =
            budget.reserve_state(page_bytes.checked_mul(2).ok_or(BackingError::Unavailable)?)?;
        let mapping = SelfMap::map(candidate, aligned, page)?;
        #[cfg(test)]
        fire_fault_hook(1);
        mapping.fault(index)?;
        self.check_self_map(&mapping, candidate_fp)?;
        let target_pagemap = open_at(&self.directory, b"pagemap")?;
        let self_pagemap = File::open("/proc/self/pagemap").map_err(io_error)?;
        let target_frame = pagemap_frame(&target_pagemap, range.start, page, budget)?;
        let own_frame = pagemap_frame(&self_pagemap, mapping.start() + index as u64, page, budget)?;
        let target_frame = if target_frame == own_frame {
            target_frame
        } else {
            // One confirmation pass: a page migration between the two reads
            // must not become a permanent change verdict.
            let retry_target = pagemap_frame(&target_pagemap, range.start, page, budget)?;
            let retry_own =
                pagemap_frame(&self_pagemap, mapping.start() + index as u64, page, budget)?;
            if retry_target != retry_own {
                return Err(BackingError::Changed);
            }
            retry_target
        };
        budget.checkpoint()?;
        let fresh =
            File::open(format!("/proc/self/fd/{}", candidate.as_raw_fd())).map_err(io_error)?;
        let fresh_metadata = fresh.metadata().map_err(io_error)?;
        if !fresh_metadata.is_file() {
            return Err(BackingError::Changed);
        }
        let fresh_map = SelfMap::map(&fresh, aligned, page)?;
        #[cfg(test)]
        fire_fault_hook(2);
        fresh_map.fault(index)?;
        let fresh_frame = pagemap_frame(
            &self_pagemap,
            fresh_map.start() + index as u64,
            page,
            budget,
        )?;
        if fresh_frame != own_frame {
            return Err(BackingError::Changed);
        }
        Ok(target_frame)
    }

    /// Prove the self-mapping is backed by the candidate descriptor, through
    /// the observer's own `map_files`. A denied self leg fails closed.
    fn check_self_map(
        &self,
        mapping: &SelfMap,
        candidate: &Fingerprint,
    ) -> Result<(), BackingError> {
        let start = mapping.start();
        let end = start
            .checked_add(mapping.length as u64)
            .ok_or(BackingError::Unavailable)?;
        let file =
            File::open(format!("/proc/self/map_files/{start:x}-{end:x}")).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if Fingerprint::from(&metadata) != *candidate {
            return Err(BackingError::Changed);
        }
        Ok(())
    }

    pub(crate) fn verify_with_process(
        &self,
        range: &MappedRange,
        candidate: &File,
    ) -> Result<BackingAssociation, BackingError> {
        self.verify_with_process_charged(range, candidate, &mut UnboundedBudget)
    }

    pub(crate) fn verify_with_process_charged<B: BackingBudget>(
        &self,
        range: &MappedRange,
        candidate: &File,
        budget: &mut B,
    ) -> Result<BackingAssociation, BackingError> {
        budget.checkpoint()?;
        if range.start >= range.end {
            return Err(BackingError::Unsupported);
        }
        let (candidate_fp, candidate_fs) = Self::candidate_identity(candidate)?;
        let vma = find_vma(&self.maps, range).ok_or(BackingError::Unsupported)?;
        if vma.ino == 0 {
            return Err(BackingError::Unsupported);
        }
        let target = self.target_file(&vma)?;
        let target_fp = Fingerprint::from(&target.metadata().map_err(io_error)?);
        let target_fs = self.check_target_keys(&target, &target_fp, &vma)?;
        let page = match (candidate_fs, target_fs) {
            (Some(left), Some(right)) if direct_semantics(left) && direct_semantics(right) => {
                self.verify_fast(&candidate_fp, &target_fp)?
            }
            _ => Some(self.verify_witness(range, candidate, &candidate_fp, &vma, budget)?),
        };
        Ok(BackingAssociation {
            directory: self.directory.try_clone().map_err(io_error)?,
            candidate: candidate.try_clone().map_err(io_error)?,
            range: *range,
            vma,
            candidate_fp,
            target_fp,
            page,
            starttime: self.starttime,
            pid_namespace: self.pid_namespace,
            mount_namespace: self.mount_namespace,
            executable: self.executable.clone(),
        })
    }
}

fn fingerprint_matches_file(file: &File, fingerprint: &Fingerprint) -> bool {
    file.metadata()
        .map(|m| Fingerprint::from(&m) == *fingerprint)
        .unwrap_or(false)
}

/// Revalidation continuity for one retained inode across time. Identity,
/// size and mtime must match exactly; a ctime drift is tolerated only when
/// confined to a link-count change with unchanged mode (unlink or link of
/// the same inode — the backing and its bytes are intact). In particular a
/// write followed by an mtime restore still fails: the link count did not
/// move, so the ctime drift is unexplained.
fn unchanged_for_backing(before: &Fingerprint, after: &Fingerprint) -> bool {
    before.dev == after.dev
        && before.ino == after.ino
        && before.size == after.size
        && before.mtime == after.mtime
        && before.mtime_nsec == after.mtime_nsec
        && ((before.ctime == after.ctime && before.ctime_nsec == after.ctime_nsec)
            || (before.nlink != after.nlink && before.mode == after.mode))
}

/// One-shot verification: capture the process view, then verify.
/// Canonical entry point; production hot paths share one capture per
/// process via [`BackingProcess::capture`] instead. Exercised by unit tests.
#[allow(dead_code)]
pub(crate) fn verify_mapped_backing(
    target: &File,
    range: &MappedRange,
    candidate: &File,
) -> Result<BackingAssociation, BackingError> {
    BackingProcess::capture(target)?.verify_with_process(range, candidate)
}

/// Validated mapping association. Privately owns the identity/lifetime
/// witness (retained descriptors plus the verified fingerprints and VMA
/// record); public projections expose only capability, status and the
/// approved object identity. Deliberately not Clone: custody is linear.
pub(crate) struct BackingAssociation {
    directory: File,
    candidate: File,
    range: MappedRange,
    vma: VmaRecord,
    candidate_fp: Fingerprint,
    target_fp: Fingerprint,
    page: Option<u64>,
    starttime: u64,
    pid_namespace: NamespaceId,
    mount_namespace: NamespaceId,
    executable: Fingerprint,
}

impl BackingAssociation {
    /// Approved object identity: the verifying candidate's native device and
    /// inode. The only identity this association ever discloses.
    pub(crate) fn object_identity(&self) -> (u64, u64) {
        (self.candidate_fp.dev, self.candidate_fp.ino)
    }

    /// Capability/status signal: the witnessed page frame on the witness
    /// path, `None` on the direct path. Callers use it as a cache and
    /// deduplication dimension so two layers sharing one rendered identity
    /// never share one record.
    pub(crate) fn witness_page(&self) -> Option<u64> {
        self.page
    }

    /// Verified echo of the matched mapping: start, end, file offset, maps
    /// inode. Lets owners bind custody to the verified record instead of
    /// their own possibly stale parse. The rendered device is deliberately
    /// not echoed: backing identity comes from the approved descriptor.
    pub(crate) fn mapping_keys(&self) -> (u64, u64, u64, u64) {
        (self.vma.start, self.vma.end, self.vma.pgoff, self.vma.ino)
    }

    /// Re-prove the association against live state. The witness path re-runs
    /// the full page witness (a copy-up after verification changes the
    /// re-resolution leg); the direct path re-checks fingerprints and keys.
    /// Uncharged entry point for unit tests; production uses the charged
    /// variant with real caller budgets.
    #[allow(dead_code)]
    pub(crate) fn revalidate(&self) -> Result<(), BackingError> {
        self.revalidate_charged(&mut UnboundedBudget)
    }

    /// Budget-charged revalidation: the deadline is enforced before any IO,
    /// the maps re-read is reserved and charged, and the witness re-run is
    /// charged like verification.
    pub(crate) fn revalidate_charged<B: BackingBudget>(
        &self,
        budget: &mut B,
    ) -> Result<(), BackingError> {
        budget.checkpoint()?;
        if starttime_charged(&self.directory, budget)? != self.starttime {
            return Err(BackingError::Changed);
        }
        if namespace_id(&self.directory, b"ns/pid")? != self.pid_namespace
            || namespace_id(&self.directory, b"ns/mnt")? != self.mount_namespace
        {
            return Err(BackingError::Changed);
        }
        let executable = Fingerprint::from(
            &open_at(&self.directory, b"exe")?
                .metadata()
                .map_err(io_error)?,
        );
        if !unchanged_for_backing(&self.executable, &executable) {
            return Err(BackingError::Changed);
        }
        let (maps, maps_lease) = read_at_charged(&self.directory, b"maps", MAX_MAPS_READ, budget)?;
        let current = find_vma(&maps, &self.range).ok_or(BackingError::Changed)?;
        if current != self.vma {
            return Err(BackingError::Changed);
        }
        // Path text is intentionally not compared: an unlinked-but-retained
        // backing keeps its keys while gaining a " (deleted)" suffix, and
        // pathnames are never authority.
        let candidate_fp = Fingerprint::from(&self.candidate.metadata().map_err(io_error)?);
        if !unchanged_for_backing(&self.candidate_fp, &candidate_fp) {
            return Err(BackingError::Changed);
        }
        let name = format!("map_files/{:x}-{:x}", self.vma.start, self.vma.end);
        let target = match open_at(&self.directory, name.as_bytes()) {
            Ok(file) => file,
            Err(BackingError::Unavailable) => return Err(BackingError::Changed),
            Err(error) => return Err(error),
        };
        let target_fp = Fingerprint::from(&target.metadata().map_err(io_error)?);
        if target_fp.ino != self.vma.ino || !unchanged_for_backing(&self.target_fp, &target_fp) {
            return Err(BackingError::Changed);
        }
        if self.page.is_some() {
            let view = BackingProcess {
                directory: self.directory.try_clone().map_err(io_error)?,
                starttime: self.starttime,
                pid_namespace: self.pid_namespace,
                mount_namespace: self.mount_namespace,
                executable: self.executable.clone(),
                maps,
                _leases: vec![maps_lease],
            };
            let frame = view.verify_witness(
                &self.range,
                &self.candidate,
                &self.candidate_fp,
                &self.vma,
                budget,
            )?;
            if Some(frame) != self.page {
                // The page binding moved (migration settled elsewhere or the
                // backing changed); the stored witness no longer describes
                // this mapping.
                return Err(BackingError::Changed);
            }
        }
        Ok(())
    }
}

/// Fixed-container slack for one bounded layer-discovery extraction: the
/// admitted candidates vector (at most [`MAX_LAYER_CANDIDATES`] open files)
/// plus iterator and table state. Declared bytes only — allocator slack is
/// out of model, per `observation_memory`.
const LAYER_SCRATCH_SLOP: usize = 1024;

/// Borrowed best-match overlay mount: the unescaped mountpoint length the
/// relative-path cut applies (exactly as the match compared it) plus the raw
/// superoptions slice the admitted layer dirs stream from. Borrowed so
/// selection retains nothing per line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BestOverlayMount<'a> {
    point_len: usize,
    super_options: &'a [u8],
}

/// Streaming best-match overlay selection over raw mountinfo: per-line field
/// navigation borrows (no field vectors) and only the winning line's
/// superoptions slice is retained. Match semantics are exactly the replaced
/// full parse's — skip empty, NUL-bearing, short, dashless and non-overlay
/// lines; unescape the mountpoint for the prefix test; longest match wins
/// with ties keeping mountinfo order. The working buffer is reused across
/// lines and never exceeds the longest mountpoint (at most the input
/// length); the caller reserves that scratch before calling.
fn select_overlay_mount<'a>(
    mountinfo: &'a [u8],
    maps_path: &[u8],
    scratch: &mut Vec<u8>,
) -> Option<BestOverlayMount<'a>> {
    // Fields: id parent major:minor root mountpoint options ... " - " fstype source superoptions.
    let mut best: Option<BestOverlayMount<'a>> = None;
    for line in mountinfo.split(|b| *b == b'\n') {
        if line.is_empty() || line.contains(&0) {
            continue;
        }
        let mut parts = line.split(|b| *b == b' ');
        let mut mountpoint = None;
        let mut count = 0;
        for field in parts.by_ref().take(6) {
            if count == 4 {
                mountpoint = Some(field);
            }
            count += 1;
        }
        if count < 6 {
            continue;
        }
        let Some(mountpoint) = mountpoint else {
            continue;
        };
        let mut dash = false;
        for field in parts.by_ref() {
            if field == b"-" {
                dash = true;
                break;
            }
        }
        if !dash {
            continue;
        }
        let (Some(fstype), Some(_source), Some(super_options)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if fstype != b"overlay" {
            continue;
        }
        unescape_octal_into(mountpoint, scratch);
        let point = scratch.as_slice();
        let matches = maps_path == point
            || (maps_path.starts_with(point)
                && (point == b"/" || maps_path.get(point.len()) == Some(&b'/')));
        if matches && best.is_none_or(|won| point.len() > won.point_len) {
            best = Some(BestOverlayMount {
                point_len: point.len(),
                super_options,
            });
        }
    }
    best
}

/// Admitted layer dirs for the winning mount, streaming: the LAST `upperdir=`
/// value first (repeated options overwrite, as the replaced full parse did),
/// then every `lowerdir=` value's non-empty segments in order across repeated
/// options. Borrowed slices, no allocation; the caller stops after the
/// candidate bound (early cutoff) and unescapes only the admitted dirs.
fn overlay_layer_dirs(super_options: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    let mut upper = None;
    for option in super_options.split(|b| *b == b',') {
        if let Some(dir) = option.strip_prefix(b"upperdir=") {
            upper = Some(dir);
        }
    }
    upper.into_iter().chain(
        super_options
            .split(|b| *b == b',')
            .filter_map(|option| option.strip_prefix(b"lowerdir="))
            .flat_map(LowerSplit::new),
    )
}

/// Borrowed `lowerdir=` segments: a backslash quotes the next byte and only
/// an unquoted ':' separates; empty segments are skipped. The same split the
/// replaced full parse performed, without allocating.
struct LowerSplit<'a> {
    rest: &'a [u8],
}
impl<'a> LowerSplit<'a> {
    fn new(dirs: &'a [u8]) -> Self {
        Self { rest: dirs }
    }
}
impl<'a> Iterator for LowerSplit<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            if self.rest.is_empty() {
                return None;
            }
            let bytes = self.rest;
            let mut end = 0;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 1;
                    if end < bytes.len() {
                        end += 1;
                    }
                    continue;
                }
                if bytes[end] == b':' {
                    break;
                }
                end += 1;
            }
            let segment = &bytes[..end];
            self.rest = bytes.get(end + 1..).unwrap_or(b"");
            if segment.is_empty() {
                continue;
            }
            return Some(segment);
        }
    }
}

/// Unescape mountinfo octal (`\040` and friends) into a reused buffer:
/// space, tab, newline and backslash arrive octal-escaped; anything else
/// passes through. Malformed escapes fail the whole entry later, at
/// validation. Clears first; never grows past the input it unescapes.
fn unescape_octal_into(bytes: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() + 1 {
            let end = (i + 4).min(bytes.len());
            let digits = &bytes[i + 1..end];
            if digits.len() == 3 && digits.iter().all(|b| (b'0'..=b'7').contains(b)) {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(digits).unwrap_or(""), 8)
                        .unwrap_or(b'\\'),
                );
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
}

/// Join a layer dir with the caller-relative path into the single charged
/// NUL-terminated buffer that also serves the open: `open_layer_candidate`
/// passes its pointer straight to `libc::open`, so std never heap-copies
/// long paths outside the reservation (Rust 1.88 `small_c_string`
/// heap-copies paths of `len >= 384` while the joined buffer stays live).
/// Exact capacity plus the terminator: the caller reserves one joined path
/// before building it, so construction must not grow past the declared
/// bound. Rejects the same shapes as before; the terminator is the only
/// new byte.
fn join_layer(layer: &[u8], relative: &[u8]) -> Option<Vec<u8>> {
    if layer.is_empty() || !layer.starts_with(b"/") || relative.is_empty() {
        return None;
    }
    if relative
        .split(|b| *b == b'/')
        .any(|c| c == b".." || c.contains(&0))
    {
        return None;
    }
    if layer.contains(&0) {
        return None;
    }
    let mut joined = Vec::with_capacity(layer.len() + 1 + relative.len() + 1);
    joined.extend_from_slice(layer);
    if !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(relative);
    joined.push(0);
    Some(joined)
}

/// Open one joined layer path for verification. Symlinked layer members are
/// skipped (the range-bound map_files route still verifies them when they are
/// unambiguous); no link chasing, no path authority. Opens from a BORROWED
/// C string over the caller-charged NUL-terminated buffer — no conversion
/// copy at any path length — with the exact flags the previous `OpenOptions`
/// shape produced (read-only + CLOEXEC + NOFOLLOW + NONBLOCK + NOCTTY).
fn open_layer_candidate(path: &[u8]) -> Option<File> {
    let cstr = std::ffi::CStr::from_bytes_with_nul(path).ok()?;
    // SAFETY: the pointer borrows the live caller-owned buffer for the
    // syscall; no O_CREAT, so no mode argument is needed.
    let raw = unsafe {
        libc::open(
            cstr.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a fresh owned FD from the successful open above.
    let file = unsafe { File::from_raw_fd(raw) };
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some(file)
}

/// Direct layer candidates for a mapped path: host-absolute upper/lower
/// resolutions from the target's `mountinfo`, bounded. These are hints only;
/// every candidate still requires independent verification. Empty for
/// non-absolute paths, deleted mappings, and unresolvable layers.
/// Uncharged entry point for unit tests; production uses the charged
/// variant with real caller budgets.
#[allow(dead_code)]
pub(crate) fn direct_layer_candidates(
    process_dir: &File,
    maps_path: &[u8],
    max: usize,
) -> Vec<File> {
    direct_layer_candidates_charged(process_dir, maps_path, max, &mut UnboundedBudget)
}

/// Budget-charged layer discovery (ER-5E-I2 remainder): the mountinfo buffer
/// reservation is held for the whole extraction (released only with the
/// buffer), parser/path/candidate scratch is reserved BEFORE any of it is
/// allocated, and the candidate bound cuts the layer stream BEFORE paths are
/// joined — at most [`MAX_LAYER_CANDIDATES`] joins, one at a time, each
/// opened (or dropped) before the next is built. A budget refusal yields no
/// candidates and the caller re-derives the precise gap downstream, exactly
/// as a mountinfo read refusal does.
pub(crate) fn direct_layer_candidates_charged<B: BackingBudget>(
    process_dir: &File,
    maps_path: &[u8],
    max: usize,
    budget: &mut B,
) -> Vec<File> {
    let limit = max.min(MAX_LAYER_CANDIDATES);
    let mut candidates = Vec::new();
    if maps_path.is_empty() || !maps_path.starts_with(b"/") || maps_path.ends_with(b" (deleted)") {
        return candidates;
    }
    // The raw reservation lives in this scope with the buffer: both release
    // together at the end, never the lease first while bytes are live.
    let (mountinfo, _mountinfo_lease) =
        match read_at_charged(process_dir, b"mountinfo", MAX_MOUNTINFO_READ, budget) {
            Ok(pair) => pair,
            Err(_) => return candidates,
        };
    // Worst-case owned extraction scratch, reserved BEFORE any of it is
    // allocated: the reused working buffer (exact capacity, at most one
    // input length of content) plus the single joined path under
    // construction (one layer dir plus '/' plus the caller path plus the NUL
    // terminator, exact capacity) plus fixed containers. Mountinfo is
    // scanned streaming — field navigation borrows, only the winning line's
    // superoptions slice is retained — layer dirs stream with early cutoff
    // at the bound, and the open borrows the charged buffer directly, so
    // nothing else is allocated at any input size up to the cap, at any
    // path length. Declared bytes only (allocator slack out of model, per
    // `observation_memory`).
    let Some(scratch_bytes) = mountinfo
        .len()
        .checked_add(mountinfo.len())
        .and_then(|n| n.checked_add(maps_path.len()))
        .and_then(|n| n.checked_add(2 + LAYER_SCRATCH_SLOP))
    else {
        return candidates;
    };
    let Ok(_layer_scratch) = budget.reserve_state(scratch_bytes) else {
        return candidates;
    };
    candidates.reserve_exact(limit);
    let mut scratch = Vec::with_capacity(mountinfo.len());
    let Some(best) = select_overlay_mount(&mountinfo, maps_path, &mut scratch) else {
        return candidates;
    };
    let mut relative = maps_path.get(best.point_len..).unwrap_or(b"");
    if relative.starts_with(b"/") {
        relative = &relative[1..];
    }
    if relative.is_empty() {
        return candidates;
    }
    // The bound cuts the stream: join (and open) only until `limit` paths
    // are joined — open failures still consume slots, as before.
    let mut joined = 0;
    for dir in overlay_layer_dirs(best.super_options) {
        if joined >= limit {
            break;
        }
        unescape_octal_into(dir, &mut scratch);
        let Some(path) = join_layer(&scratch, relative) else {
            continue;
        };
        joined += 1;
        if let Some(file) = open_layer_candidate(&path) {
            candidates.push(file);
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn err_of(result: Result<BackingAssociation, BackingError>) -> BackingError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected verification failure"),
        }
    }

    fn scratch(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-backing-{prefix}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn self_range(executable: bool) -> MappedRange {
        let maps = std::fs::read("/proc/self/maps").unwrap();
        for line in maps.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            if let Some(vma) = parse_vma(line)
                && vma.ino != 0
                && vma.executable == executable
            {
                return MappedRange {
                    start: vma.start,
                    end: vma.start + 1,
                };
            }
        }
        panic!("no self mapping found");
    }

    fn stack_range() -> MappedRange {
        let maps = std::fs::read("/proc/self/maps").unwrap();
        for line in maps.split(|b| *b == b'\n') {
            if line.windows(7).any(|w| w == b"[stack]") {
                let vma = parse_vma(line).unwrap();
                assert_eq!(vma.ino, 0);
                return MappedRange {
                    start: vma.start,
                    end: vma.start + 1,
                };
            }
        }
        panic!("no [stack] mapping found");
    }

    /// Child mapping the given paths read-only (whole files), kept alive on
    /// stdin. Mappings need no executable bit: association is general.
    struct MapChild {
        child: Child,
        pid: u32,
    }
    impl MapChild {
        fn spawn(paths: &[std::path::PathBuf]) -> Self {
            Self::spawn_via("python3", &[], paths)
        }
        fn spawn_in_new_mountns(paths: &[std::path::PathBuf]) -> Self {
            Self::spawn_via("unshare", &["-m", "python3"], paths)
        }
        fn spawn_in_new_userns(paths: &[std::path::PathBuf]) -> Self {
            Self::spawn_via("unshare", &["-U", "python3"], paths)
        }
        fn spawn_via(program: &str, prefix: &[&str], paths: &[std::path::PathBuf]) -> Self {
            let mut child = Command::new(program)
                .args(prefix)
                .arg("-c")
                .arg(
                    "import mmap,sys\nfiles=[open(p,'rb') for p in sys.argv[1:]]\nmaps=[mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) for f in files]\n[t.__getitem__(0) for t in maps]\nprint('ready',flush=True)\nsys.stdin.read()\n",
                )
                .args(paths)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line, "ready\n");
            let pid = child.id();
            Self { child, pid }
        }
        fn pid(&self) -> u32 {
            self.pid
        }
        fn maps(&self) -> Vec<u8> {
            std::fs::read(format!("/proc/{}/maps", self.pid)).unwrap()
        }
        fn range_of(&self, path: &std::path::Path) -> MappedRange {
            let maps = self.maps();
            let needle = path.to_string_lossy().into_owned();
            for line in maps.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                if String::from_utf8_lossy(line).contains(&needle) {
                    let vma = parse_vma(line).unwrap();
                    return MappedRange {
                        start: vma.start,
                        end: vma.start + 1,
                    };
                }
            }
            panic!("child never mapped {needle}");
        }
        fn dir(&self) -> File {
            File::open(format!("/proc/{}", self.pid)).unwrap()
        }
    }
    impl Drop for MapChild {
        fn drop(&mut self) {
            drop(self.child.stdin.take());
            let _ = self.child.wait();
        }
    }

    #[test]
    fn reversed_or_empty_range_is_unsupported() {
        let dir = File::open("/proc/self").unwrap();
        let exe = File::open(std::env::current_exe().unwrap()).unwrap();
        for range in [
            MappedRange { start: 5, end: 5 },
            MappedRange { start: 9, end: 4 },
        ] {
            assert_eq!(
                err_of(verify_mapped_backing(&dir, &range, &exe)),
                BackingError::Unsupported
            );
        }
    }

    #[test]
    fn anonymous_range_is_unsupported() {
        let dir = File::open("/proc/self").unwrap();
        let exe = File::open(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&dir, &stack_range(), &exe)),
            BackingError::Unsupported
        );
    }

    #[test]
    fn nonregular_candidate_is_unsupported() {
        let dir = File::open("/proc/self").unwrap();
        let candidate = File::open(std::env::temp_dir()).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&dir, &self_range(true), &candidate)),
            BackingError::Unsupported
        );
    }

    #[test]
    fn unmapped_range_is_unsupported() {
        let dir = File::open("/proc/self").unwrap();
        let exe = File::open(std::env::current_exe().unwrap()).unwrap();
        let first = self_range(true);
        let range = MappedRange {
            start: first.start,
            end: u64::MAX,
        };
        assert_eq!(
            err_of(verify_mapped_backing(&dir, &range, &exe)),
            BackingError::Unsupported
        );
    }

    #[test]
    fn errno_classifier_maps_denied_and_unavailable() {
        assert_eq!(classify_errno(libc::EACCES), BackingError::Denied);
        assert_eq!(classify_errno(libc::EPERM), BackingError::Denied);
        assert_eq!(classify_errno(libc::ENOENT), BackingError::Unavailable);
        assert_eq!(classify_errno(libc::ESRCH), BackingError::Unavailable);
        assert_eq!(classify_errno(libc::EIO), BackingError::Unavailable);
        assert_eq!(classify_errno(0), BackingError::Unavailable);
    }

    #[test]
    fn denied_target_map_files_maps_denied() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: denial requires an unprivileged observer");
            return;
        }
        // MapChild reports readiness only after exec and mmap complete;
        // reading a freshly spawned process's maps once races exec setup.
        let dir = scratch("denied-map-files");
        let path = dir.join("mapped");
        std::fs::write(&path, vec![0x5au8; 4096]).unwrap();
        let child = MapChild::spawn(&[path.clone()]);
        let range = child.range_of(&path);
        let target = child.dir();
        let candidate = File::open(&path).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &candidate)),
            BackingError::Denied
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overlay_mount_selection_prefers_longest_prefix() {
        let info =
            b"27 1 0:24 / / rw - overlay overlay rw,lowerdir=/l1:/l2,upperdir=/u,workdir=/w\n\
            28 1 0:25 / /mnt rw - ext4 /dev/x rw\n\
            bad line\n\
            29 1 0:26 / /mnt/sub rw - overlay overlay rw,lowerdir=/l3\n\
            30 0 0:27 / /sp\\040ace rw - overlay overlay rw,lowerdir=/l\\0404\n";
        let mut scratch = Vec::new();
        // Longest match wins: /mnt/sub beats / for a path under it; the
        // non-overlay and malformed lines never select.
        let best = select_overlay_mount(info, b"/mnt/sub/file", &mut scratch).unwrap();
        assert_eq!(best.point_len, 8);
        assert_eq!(best.super_options, b"rw,lowerdir=/l3");
        // The root mount matches anything absolute.
        let best = select_overlay_mount(info, b"/other/file", &mut scratch).unwrap();
        assert_eq!(best.point_len, 1);
        assert_eq!(
            best.super_options,
            b"rw,lowerdir=/l1:/l2,upperdir=/u,workdir=/w"
        );
        // Escaped mountpoints unescape for the match (length 7 proves the
        // octal escape collapsed).
        let best = select_overlay_mount(info, b"/sp ace/x", &mut scratch).unwrap();
        assert_eq!(best.point_len, 7);
        // A mountpoint boundary still falls back to the root mount.
        let best = select_overlay_mount(info, b"/mnt-sub/x", &mut scratch).unwrap();
        assert_eq!(best.point_len, 1);
        // Ties keep mountinfo order.
        let tied = b"1 1 0:1 / /a rw - overlay overlay rw,lowerdir=/x\n\
            2 1 0:2 / /a rw - overlay overlay rw,lowerdir=/y\n";
        let best = select_overlay_mount(tied, b"/a/f", &mut scratch).unwrap();
        assert_eq!(best.super_options, b"rw,lowerdir=/x");
        // No overlay line at all: nothing selects.
        assert!(
            select_overlay_mount(
                b"28 1 0:25 / /mnt rw - ext4 /dev/x rw\n",
                b"/mnt/x",
                &mut scratch
            )
            .is_none()
        );
    }

    #[test]
    fn layer_dir_streaming_preserves_order_and_cutoff() {
        // Upper (last wins) first, then lowers in order across repeated
        // options; empty segments are skipped.
        let dirs: Vec<&[u8]> =
            overlay_layer_dirs(b"rw,upperdir=/u1,lowerdir=/a::/b,upperdir=/u2,lowerdir=/c")
                .collect();
        assert_eq!(
            dirs,
            vec![
                b"/u2".as_slice(),
                b"/a".as_slice(),
                b"/b".as_slice(),
                b"/c".as_slice()
            ]
        );
        // An escaped colon stays data.
        let dirs: Vec<&[u8]> = overlay_layer_dirs(b"lowerdir=/x\\:y:/z").collect();
        assert_eq!(dirs, vec![b"/x\\:y".as_slice(), b"/z".as_slice()]);
        // Early cutoff: the caller stops after the bound; the rest of the
        // stream is never touched.
        let mut stream = overlay_layer_dirs(b"lowerdir=/1:/2:/3:/4");
        assert_eq!(stream.next(), Some(b"/1".as_slice()));
        assert_eq!(stream.next(), Some(b"/2".as_slice()));
        // No layer options: empty stream.
        assert_eq!(overlay_layer_dirs(b"rw,workdir=/w").count(), 0);
    }

    #[test]
    fn layer_join_rejects_escape_and_relative() {
        assert_eq!(join_layer(b"/l", b"a/b"), Some(b"/l/a/b\0".to_vec()));
        assert_eq!(join_layer(b"/l/", b"a"), Some(b"/l/a\0".to_vec()));
        assert_eq!(join_layer(b"/l", b"../x"), None);
        assert_eq!(join_layer(b"/l", b"a/../../x"), None);
        assert_eq!(join_layer(b"relative", b"a"), None);
        assert_eq!(join_layer(b"/l", b""), None);
        assert_eq!(join_layer(b"/l\0", b"a"), None);
    }

    #[test]
    #[ignore = "requires privileged map_files (5E)"]
    fn direct_self_mapping_verifies_and_revalidates() {
        let dir = File::open("/proc/self").unwrap();
        let exe_path = std::env::current_exe().unwrap();
        let exe = File::open(&exe_path).unwrap();
        let meta = exe.metadata().unwrap();
        let assoc = verify_mapped_backing(&dir, &self_range(true), &exe).unwrap();
        assert_eq!(assoc.object_identity(), (meta.dev(), meta.ino()));
        assert_eq!(assoc.witness_page(), None);
        assoc.revalidate().unwrap();
    }

    #[test]
    #[ignore = "requires privileged map_files (5E)"]
    fn same_content_different_inode_refuses() {
        let dir = scratch("sibling");
        let bytes = vec![0x51u8; 4096];
        std::fs::write(dir.join("a"), &bytes).unwrap();
        std::fs::write(dir.join("b"), &bytes).unwrap();
        let child = MapChild::spawn(&[dir.join("a")]);
        let range = child.range_of(&dir.join("a"));
        let target = child.dir();
        let other = File::open(dir.join("b")).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &other)),
            BackingError::Changed
        );
        let same = File::open(dir.join("a")).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &same).unwrap();
        let meta = same.metadata().unwrap();
        assert_eq!(assoc.object_identity(), (meta.dev(), meta.ino()));
        assoc.revalidate().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires root + btrfs subvolume control (T4; OSSL_INVENTORY_BTRFS_FIRST/SECOND override)"]
    fn btrfs_subvolume_cross_candidate_refuses() {
        // Self-provisioned unless the operator pins paths explicitly.
        let mut _held = None;
        let paths = match (
            std::env::var_os("OSSL_INVENTORY_BTRFS_FIRST"),
            std::env::var_os("OSSL_INVENTORY_BTRFS_SECOND"),
        ) {
            (Some(a), Some(b)) => [std::path::PathBuf::from(a), std::path::PathBuf::from(b)],
            _ => {
                let fx = match BtrfsFixture::create(&["a", "b"]) {
                    Some(fx) => fx,
                    None => return,
                };
                let (p0, p1) = fx.colliding_pair("a", "b");
                _held = Some(fx);
                [p0, p1]
            }
        };
        let metas = paths.each_ref().map(|p| std::fs::metadata(p).unwrap());
        assert_eq!(metas[0].ino(), metas[1].ino(), "fixture collision required");
        assert_ne!(metas[0].dev(), metas[1].dev(), "distinct natives required");
        let child = MapChild::spawn(&paths);
        // Precondition: maps keys collide across the subvolumes.
        let maps = String::from_utf8(child.maps()).unwrap();
        let keys: Vec<(String, String)> = paths
            .iter()
            .map(|p| {
                let line = maps
                    .lines()
                    .find(|l| l.contains(p.to_str().unwrap()))
                    .unwrap();
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields[3].to_owned(), fields[4].to_owned())
            })
            .collect();
        assert_eq!(keys[0], keys[1], "maps key collision required");
        let range = child.range_of(&paths[0]);
        let target = child.dir();
        let cross = File::open(&paths[1]).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &cross)),
            BackingError::Changed
        );
        let own = File::open(&paths[0]).unwrap();
        verify_mapped_backing(&target, &range, &own).unwrap();
    }

    #[test]
    #[ignore = "requires root + btrfs subvolume control (T4)"]
    fn btrfs_snapshot_twin_cross_refuses_self_provisioned() {
        let Some(mut fx) = BtrfsFixture::create(&["sv1"]) else {
            return;
        };
        let bytes = vec![0x53u8; 4096];
        let original = fx.write("sv1", "lib.so", &bytes);
        let snap = fx.snapshot("sv1", "sv1snap");
        let twin = snap.join("lib.so");
        let meta_o = original.metadata().unwrap();
        let meta_t = twin.metadata().unwrap();
        assert_eq!(meta_o.ino(), meta_t.ino(), "snapshot twin shares ino");
        assert_ne!(
            meta_o.dev(),
            meta_t.dev(),
            "twin lives on a distinct native dev"
        );
        let child = MapChild::spawn(std::slice::from_ref(&original));
        let range = child.range_of(&original);
        let target = child.dir();
        let cross = File::open(&twin).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &cross)),
            BackingError::Changed
        );
        let own = File::open(&original).unwrap();
        verify_mapped_backing(&target, &range, &own).unwrap();
    }

    #[test]
    #[ignore = "requires root map_files (T4)"]
    fn deleted_mapped_library_verifies_by_retained_proof() {
        let dir = scratch("deleted");
        let path = dir.join("lib.so");
        std::fs::write(&path, vec![0x44u8; 4096]).unwrap();
        let meta_before = path.metadata().unwrap();
        let child = MapChild::spawn(std::slice::from_ref(&path));
        std::fs::remove_file(&path).unwrap();
        let maps = String::from_utf8(child.maps()).unwrap();
        assert!(
            maps.contains(" (deleted)"),
            "precondition: maps shows deletion"
        );
        let range = child.range_of(&path);
        let target = child.dir();
        // The range-bound entry needs the full VMA span (not the 1-byte
        // probe range) and still binds the unlinked file.
        let maps = child.maps();
        let needle = path.to_string_lossy().into_owned();
        let line = maps
            .split(|b| *b == b'\n')
            .find(|l| String::from_utf8_lossy(l).contains(&needle))
            .unwrap();
        let vma = parse_vma(line).unwrap();
        let entry = format!(
            "/proc/{}/map_files/{:x}-{:x}",
            child.pid(),
            vma.start,
            vma.end
        );
        let candidate = File::open(&entry).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &candidate).unwrap();
        assert_eq!(
            assoc.object_identity(),
            (meta_before.dev(), meta_before.ino())
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires root map_files (T4)"]
    fn symlink_swap_candidate_before_verifies_after_refuses() {
        let dir = scratch("symlink");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, vec![0x41u8; 4096]).unwrap();
        std::fs::write(&b, vec![0x41u8; 4096]).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        // The mapping resolves through the link: maps names the target.
        let child = MapChild::spawn(std::slice::from_ref(&link));
        let range = child.range_of(&a);
        let target = child.dir();
        let before = File::open(&link).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &before).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        // H5a Verified column: the retained association binds file A
        // through file descriptors, so a pathname swap cannot disturb it.
        assoc.revalidate().unwrap();
        // But a candidate opened through the swapped link is file B — a
        // different file from the mapping — and must refuse.
        let after = File::open(&link).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &after)),
            BackingError::Changed
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires root map_files + mountns control (T4)"]
    fn cross_mountns_target_verifies_by_proof() {
        let dir = scratch("mntns");
        let path = dir.join("lib.so");
        std::fs::write(&path, vec![0x4du8; 4096]).unwrap();
        let meta = path.metadata().unwrap();
        let child = MapChild::spawn_in_new_mountns(std::slice::from_ref(&path));
        // Precondition: the child really is in another mount namespace.
        let mine = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        let theirs = std::fs::read_link(format!("/proc/{}/ns/mnt", child.pid())).unwrap();
        assert_ne!(mine, theirs, "precondition: distinct mount namespaces");
        let range = child.range_of(&path);
        let target = child.dir();
        let candidate = File::open(&path).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &candidate).unwrap();
        assert_eq!(assoc.object_identity(), (meta.dev(), meta.ino()));
        assoc.revalidate().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires root map_files (T4)"]
    fn restarted_process_invalidates_retained_association() {
        let dir = scratch("restart");
        let path = dir.join("lib.so");
        std::fs::write(&path, vec![0x52u8; 4096]).unwrap();
        let child = MapChild::spawn(std::slice::from_ref(&path));
        let range = child.range_of(&path);
        let target = child.dir();
        let candidate = File::open(&path).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &candidate).unwrap();
        // Restart: the old incarnation is gone; a same-path successor must
        // not validate the retained association.
        drop(child);
        let _successor = MapChild::spawn(std::slice::from_ref(&path));
        assert!(
            assoc.revalidate().is_err(),
            "revalidate after restart must fail"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn userns_target_map_files_denied_to_outside_observer() {
        // Portable denied shape (no privilege needed): a target in a child
        // userns keeps world-readable maps, but the outside observer's
        // map_files opens fail (EPERM/EACCES) — verify must say Denied,
        // never Ok and never silent. The MapChild ready handshake proves
        // post-exec stability, so no extra settle gate is needed.
        if Command::new("unshare").arg("--help").output().is_err() {
            eprintln!("skip: unshare absent");
            return;
        }
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip: root observer bypasses the denial under test");
            return;
        }
        // The binary existing does not prove userns creation works
        // (hardened kernels may forbid it): probe before spawning, or the
        // ready-handshake assert would panic instead of skipping.
        let probe = Command::new("unshare")
            .args(["-U", "true"])
            .status()
            .is_ok_and(|s| s.success());
        if !probe {
            eprintln!("skip: unprivileged userns creation unavailable");
            return;
        }
        let dir = scratch("userns");
        let path = dir.join("lib.so");
        std::fs::write(&path, vec![0x55u8; 4096]).unwrap();
        let child = MapChild::spawn_in_new_userns(std::slice::from_ref(&path));
        if std::fs::read(format!("/proc/{}/maps", child.pid())).is_err() {
            eprintln!("skip: environment hides userns target maps");
            return;
        }
        let range = child.range_of(&path);
        let target = child.dir();
        let candidate = File::open(&path).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &candidate)),
            BackingError::Denied
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires root + loop + ext4 (T4)"]
    fn ext4_loop_backed_mapping_verifies() {
        let mkfs = ["/sbin/mke2fs", "/sbin/mkfs.ext4"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(mkfs) = mkfs else {
            eprintln!("skip: mke2fs absent");
            return;
        };
        let dir = scratch("ext4");
        let img = dir.join("fs.img");
        assert!(
            Command::new("truncate")
                .args(["-s", "512M"])
                .arg(&img)
                .status()
                .is_ok_and(|s| s.success())
        );
        let formatted = Command::new(mkfs)
            .args(["-t", "ext4", "-q", "-F"])
            .arg(&img)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        assert!(formatted.is_ok_and(|s| s.success()), "mke2fs failed");
        // MountGuard owns the mount: isolated-mntns + private-propagation
        // asserts, mountinfo verification, retention policy, and unwind
        // cleanup if any later assert fails.
        let mnt = dir.join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        let mut guard = MountGuard::new(dir);
        guard
            .mount(mnt.clone(), &["-o", "loop", img.to_str().unwrap()])
            .unwrap();
        // The child mapping must be gone before cleanup: an open mapping
        // pins the mount and normal umount refuses (by design).
        {
            let path = mnt.join("lib.so");
            std::fs::write(&path, vec![0x45u8; 4096]).unwrap();
            let candidate = File::open(&path).unwrap();
            // Precondition: the file really is on ext4 (0xef53), so this
            // cell cannot silently pass on the wrong filesystem.
            assert_eq!(filesystem_type(&candidate), Some(0xef53));
            let meta = path.metadata().unwrap();
            let child = MapChild::spawn(std::slice::from_ref(&path));
            let range = child.range_of(&path);
            let target = child.dir();
            let assoc = verify_mapped_backing(&target, &range, &candidate).unwrap();
            assert_eq!(assoc.object_identity(), (meta.dev(), meta.ino()));
            assoc.revalidate().unwrap();
        }
        guard.cleanup().unwrap();
    }

    #[derive(Debug)]
    struct FixtureMount {
        point: std::path::PathBuf,
        // None means acquisition outcome is unknown: never delete its backing.
        mountinfo: Option<String>,
        unique_id: Option<u64>,
    }

    struct MountGuard {
        base: std::path::PathBuf,
        base_identity: (u64, u64),
        namespace: std::path::PathBuf,
        origin_namespace_path: std::path::PathBuf,
        mounts: Vec<FixtureMount>,
        cleaned: bool,
        // Pins prevent namespace/base inode reuse while the guard is live.
        namespace_pin: File,
        _base_pin: File,
    }

    fn fixture_unique_mount_id(point: &std::path::Path) -> Result<u64, String> {
        use std::os::unix::ffi::OsStrExt as _;
        // Linux statx ABI (include/uapi/linux/stat.h), available since 6.8.
        // Ordinary mountinfo IDs can be immediately recycled after umount.
        const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
        let path = CString::new(point.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let mut stat = std::mem::MaybeUninit::<libc::statx>::uninit();
        // SAFETY: NUL-terminated path and correctly sized writable result.
        let result = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                STATX_MNT_ID_UNIQUE,
                stat.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: successful statx initializes the result.
        let stat = unsafe { stat.assume_init() };
        if stat.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
            return Err("kernel did not supply unique mount ID; retain fixture".into());
        }
        Ok(stat.stx_mnt_id)
    }

    fn fixture_mounts() -> Result<Vec<(std::path::PathBuf, String)>, String> {
        use std::os::unix::ffi::OsStringExt as _;
        let text =
            std::fs::read_to_string("/proc/thread-self/mountinfo").map_err(|e| e.to_string())?;
        text.lines()
            .map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 10 || !fields.contains(&"-") {
                    return Err("unrecognized mountinfo; retain fixture".into());
                }
                let mut decoded = Vec::new();
                unescape_octal_into(fields[4].as_bytes(), &mut decoded);
                Ok((
                    std::ffi::OsString::from_vec(decoded).into(),
                    line.to_owned(),
                ))
            })
            .collect()
    }

    impl MountGuard {
        fn new(base: std::path::PathBuf) -> Self {
            let meta = std::fs::symlink_metadata(&base).unwrap();
            let guard = Self {
                base: base.clone(),
                base_identity: (meta.dev(), meta.ino()),
                namespace: std::fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
                origin_namespace_path: std::path::PathBuf::from("/proc")
                    .join(std::fs::read_link("/proc/thread-self").unwrap())
                    .join("ns/mnt"),
                mounts: Vec::new(),
                cleaned: false,
                namespace_pin: File::open("/proc/thread-self/ns/mnt").unwrap(),
                _base_pin: File::open(&base).unwrap(),
            };
            // Require the caller's isolated private namespace before acquiring
            // anything. Shared/slave propagation is unsuitable for fixtures.
            assert_ne!(
                guard.namespace,
                std::fs::read_link("/proc/1/ns/mnt").unwrap(),
                "mount fixtures require an isolated mount namespace"
            );
            // Fail before mounting when unique identity is unavailable.
            fixture_unique_mount_id(&guard.base).unwrap();
            let mounts = fixture_mounts().unwrap();
            assert!(
                mounts.iter().all(|(_, row)| row
                    .split(" - ")
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .all(|f| !f.starts_with("shared:") && !f.starts_with("master:"))),
                "mount fixtures require unshare --mount --propagation private"
            );
            assert!(mounts.iter().all(|(p, _)| !p.starts_with(&guard.base)));
            guard
        }

        fn mount(&mut self, point: std::path::PathBuf, args: &[&str]) -> Result<(), String> {
            if self.cleaned || !point.starts_with(&self.base) || point == self.base {
                return Err("mountpoint outside live owned fixture".into());
            }
            if std::fs::read_link("/proc/thread-self/ns/mnt").map_err(|e| e.to_string())?
                != self.namespace
            {
                return Err("mount namespace changed before acquisition".into());
            }
            if !std::fs::symlink_metadata(&point)
                .map_err(|e| e.to_string())?
                .is_dir()
                || fixture_mounts()?.iter().any(|(p, _)| p == &point)
            {
                return Err("mountpoint is not an unmounted owned directory".into());
            }
            // Register before invoking mount: even a failed/unknown subprocess
            // outcome must keep this tree out of recursive deletion.
            self.mounts.push(FixtureMount {
                point: point.clone(),
                mountinfo: None,
                unique_id: None,
            });
            let status = Command::new("mount")
                .args(args)
                .arg(&point)
                .status()
                .map_err(|e| e.to_string())?;
            let mounts = fixture_mounts()?;
            let rows: Vec<_> = mounts.iter().filter(|(p, _)| p == &point).collect();
            if !status.success() {
                if rows.is_empty() {
                    self.mounts.pop();
                }
                return Err(format!("mount failed: {status}, point={point:?}"));
            }
            if rows.len() != 1 {
                return Err(format!("ambiguous mount identity: {point:?}"));
            }
            let unique_id = fixture_unique_mount_id(&point)?;
            self.mounts.last_mut().unwrap().mountinfo = Some(rows[0].1.clone());
            self.mounts.last_mut().unwrap().unique_id = Some(unique_id);
            eprintln!(
                "fixture acquired pid={} namespace={:?} base={:?} base_identity={:?} mount={:?}",
                std::process::id(),
                self.namespace,
                self.base,
                self.base_identity,
                self.mounts.last().unwrap()
            );
            Ok(())
        }

        fn refusal(&self, reason: impl std::fmt::Display) -> String {
            let reclaim: Vec<_> = self
                .mounts
                .iter()
                .rev()
                .map(|m| {
                    vec![
                        "nsenter".to_owned(),
                        format!("--mount={}", self.origin_namespace_path.display()),
                        "--".to_owned(),
                        "umount".to_owned(),
                        "--".to_owned(),
                        m.point.to_string_lossy().into_owned(),
                    ]
                })
                .collect();
            format!(
                "fixture cleanup REFUSED: {reason}; retained base={:?} base_identity={:?}; owner pid={} namespace={:?}; mounts={:?}. Origin PID/TID namespace path={:?}; retained namespace FD=/proc/{}/fd/{} (FD locator valid only while guard lives). Before reclaim, verify the origin path still names the recorded namespace, then recheck base dev/inode, full mountinfo rows and statx unique mount IDs; release blockers and use normal-unmount argv (reverse order)={reclaim:?}. If the origin path/namespace is gone or ownership cannot be re-established, leave backing retained: independently establish recorded mount absence in every remaining holder namespace before removing the exact owned base. Recheck /proc/thread-self/mountinfo for all descendant mounts before deletion. Never force/lazy unmount.",
                self.base,
                self.base_identity,
                std::process::id(),
                self.namespace,
                self.mounts,
                self.origin_namespace_path,
                std::process::id(),
                self.namespace_pin.as_raw_fd()
            )
        }

        fn cleanup(&mut self) -> Result<(), String> {
            if self.cleaned {
                return Ok(());
            }
            self.cleanup_checked().map_err(|e| self.refusal(e))
        }

        fn cleanup_checked(&mut self) -> Result<(), String> {
            if std::fs::read_link("/proc/thread-self/ns/mnt").map_err(|e| e.to_string())?
                != self.namespace
            {
                return Err("mount namespace changed".into());
            }
            let meta = std::fs::symlink_metadata(&self.base).map_err(|e| e.to_string())?;
            if !meta.is_dir() || (meta.dev(), meta.ino()) != self.base_identity {
                return Err("base directory identity changed".into());
            }
            while let Some(owned) = self.mounts.last() {
                let mounts = fixture_mounts()?;
                let rows: Vec<_> = mounts.iter().filter(|(p, _)| p == &owned.point).collect();
                if rows.len() != 1
                    || owned.mountinfo.as_ref() != Some(&rows[0].1)
                    || owned.unique_id != Some(fixture_unique_mount_id(&owned.point)?)
                {
                    return Err(format!("mount identity changed/unknown: {owned:?}"));
                }
                // No -l/-f: refusal must preserve every backing directory.
                let status = Command::new("umount")
                    .arg("--")
                    .arg(&owned.point)
                    .status()
                    .map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err(format!("normal umount refused: {status}; {owned:?}"));
                }
                if fixture_mounts()?.iter().any(|(p, _)| p == &owned.point) {
                    return Err(format!("mount remains after umount: {owned:?}"));
                }
                self.mounts.pop();
            }
            if fixture_mounts()?
                .iter()
                .any(|(p, _)| p.starts_with(&self.base))
            {
                return Err("unowned mount beneath fixture".into());
            }
            std::fs::remove_dir_all(&self.base).map_err(|e| e.to_string())?;
            self.cleaned = true;
            Ok(())
        }
    }

    impl Drop for MountGuard {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                eprintln!("{error}");
                // A normal test must fail on refusal. During unwind retain the
                // original panic and report refusal without double-panicking.
                if !std::thread::panicking() {
                    panic!("{error}");
                }
            }
        }
    }

    /// Self-provisioning Btrfs fixture (T4): subvolumes under a leased-TMPDIR
    /// base, snapshots, and reverse-order reclamation. Root + `btrfs` CLI +
    /// TMPDIR-on-btrfs required; anything else prints a skip and yields None.
    /// Snapshots here are always siblings (never nested), so reverse
    /// creation order is a valid deletion order.
    struct BtrfsFixture {
        base: std::path::PathBuf,
        subvols: Vec<std::path::PathBuf>,
    }
    impl BtrfsFixture {
        fn create(names: &[&str]) -> Option<Self> {
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("skip: btrfs subvolume control requires root");
                return None;
            }
            if Command::new("btrfs").arg("--version").output().is_err() {
                eprintln!("skip: btrfs CLI absent");
                return None;
            }
            let probe = File::open(std::env::temp_dir()).ok()?;
            // BTRFS_SUPER_MAGIC, cf. direct_semantics().
            if filesystem_type(&probe) != Some(0x9123683e) {
                eprintln!("skip: TMPDIR is not on btrfs");
                return None;
            }
            let base = scratch("t4btrfs");
            let mut subvols = Vec::with_capacity(names.len());
            for name in names {
                let path = base.join(name);
                let created = Command::new("btrfs")
                    .args(["subvolume", "create"])
                    .arg(&path)
                    .output();
                match created {
                    Ok(out) if out.status.success() => subvols.push(path),
                    _ => {
                        // Prerequisites passed, so this is an acquisition
                        // failure (ENOSPC, unexpected fs error) — fail the
                        // cell, never green-skip. Reclaim first, in reverse.
                        for done in subvols.iter().rev() {
                            let _ = Command::new("btrfs")
                                .args(["subvolume", "delete"])
                                .arg(done)
                                .status();
                        }
                        let _ = std::fs::remove_dir_all(&base);
                        let detail = created
                            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                            .unwrap_or_else(|e| e.to_string());
                        panic!(
                            "btrfs subvolume create failed for {}: {detail}",
                            path.display()
                        );
                    }
                }
            }
            Some(Self { base, subvols })
        }
        fn write(&self, subvol: &str, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = self.base.join(subvol).join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
        fn snapshot(&mut self, src: &str, dst: &str) -> std::path::PathBuf {
            let from = self.base.join(src);
            let to = self.base.join(dst);
            let status = Command::new("btrfs")
                .args(["subvolume", "snapshot"])
                .arg(&from)
                .arg(&to)
                .status()
                .unwrap();
            assert!(status.success(), "btrfs snapshot failed");
            self.subvols.push(to.clone());
            to
        }
        /// Same-ino pair across two subvolumes: fresh subvolumes allocate
        /// from the same start, so a bounded scan finds a collision fast.
        /// Loud failure (not skip) when the filesystem disagrees.
        fn colliding_pair(&self, a: &str, b: &str) -> (std::path::PathBuf, std::path::PathBuf) {
            use std::os::unix::fs::MetadataExt as _;
            let mut seen: Vec<(u64, std::path::PathBuf)> = Vec::new();
            for i in 0..16 {
                let pa = self.write(a, &format!("f{i}"), &[0x41u8; 64]);
                let ino = pa.metadata().unwrap().ino();
                if let Some((_, pb)) = seen.iter().find(|(n, _)| *n == ino) {
                    if pb.starts_with(self.base.join(b)) {
                        return (pb.clone(), pa);
                    }
                }
                seen.push((ino, pa));
                let pb = self.write(b, &format!("g{i}"), &[0x42u8; 64]);
                let ino = pb.metadata().unwrap().ino();
                if let Some((_, pa)) = seen.iter().find(|(n, _)| *n == ino) {
                    if pa.starts_with(self.base.join(a)) {
                        return (pa.clone(), pb);
                    }
                }
                seen.push((ino, pb));
            }
            panic!("no same-ino pair across fresh subvolumes after 16 files each");
        }
    }
    impl BtrfsFixture {
        /// Couple to a retained mount: when unmount refuses and the mount
        /// is kept by policy, the backing subvolumes must survive with it
        /// (leak by design, loudly) instead of being deleted from under it.
        fn retain(self, reason: &str) {
            eprintln!(
                "BtrfsFixture: retaining {} subvolumes under {}: {reason}",
                self.subvols.len(),
                self.base.display()
            );
            std::mem::forget(self);
        }
    }
    impl Drop for BtrfsFixture {
        fn drop(&mut self) {
            for subvol in self.subvols.iter().rev() {
                // Loud, never panicking: a failed delete leaks a subvolume
                // and must show in logs, not vanish. Both spawn errors and
                // unsuccessful exit statuses count as failures.
                match Command::new("btrfs")
                    .args(["subvolume", "delete"])
                    .arg(subvol)
                    .status()
                {
                    Ok(status) if status.success() => {}
                    other => eprintln!(
                        "BtrfsFixture: subvolume delete failed for {}: {other:?}",
                        subvol.display()
                    ),
                }
            }
            if let Err(error) = std::fs::remove_dir_all(&self.base) {
                eprintln!("BtrfsFixture: base removal failed: {error}");
            }
        }
    }

    fn mount_overlay() -> (MountGuard, std::path::PathBuf) {
        let base = scratch("overlay");
        let mut guard = MountGuard::new(base.clone());
        for name in ["lower", "upper", "work", "merged"] {
            std::fs::create_dir(base.join(name)).unwrap();
        }
        guard
            .mount(
                base.join("merged"),
                &[
                    "-t",
                    "overlay",
                    "overlay",
                    "-o",
                    &format!(
                        "lowerdir={},upperdir={},workdir={}",
                        base.join("lower").display(),
                        base.join("upper").display(),
                        base.join("work").display()
                    ),
                ],
            )
            .unwrap();
        (guard, base)
    }

    #[test]
    #[ignore = "requires root + btrfs + overlay mount (T4)"]
    fn overlay_on_btrfs_subvolumes_lower_verifies_and_copyup_downgrades() {
        let Some(fx) = BtrfsFixture::create(&["lower-sv", "upper-sv"]) else {
            return;
        };
        let lower_file = fx.write("lower-sv", "lib.so", &[0x4fu8; 4096]);
        let upper = fx.base.join("upper-sv");
        std::fs::create_dir(upper.join("u")).unwrap();
        std::fs::create_dir(upper.join("w")).unwrap();
        // Preconditions: layers on btrfs, on distinct subvolumes.
        let lower_meta = lower_file.metadata().unwrap();
        let upper_meta = upper.metadata().unwrap();
        assert_ne!(
            lower_meta.dev(),
            upper_meta.dev(),
            "precondition: lower/upper on distinct subvolumes"
        );
        let mbase = scratch("overlay-btrfs");
        std::fs::create_dir(mbase.join("merged")).unwrap();
        let mut guard = MountGuard::new(mbase.clone());
        guard
            .mount(
                mbase.join("merged"),
                &[
                    "-t",
                    "overlay",
                    "overlay",
                    "-o",
                    &format!(
                        "lowerdir={},upperdir={},workdir={}",
                        fx.base.join("lower-sv").display(),
                        upper.join("u").display(),
                        upper.join("w").display()
                    ),
                ],
            )
            .unwrap();
        let merged = mbase.join("merged/lib.so");
        // The child mapping must be gone before cleanup: an open merged
        // mapping pins the mount and normal umount refuses (by design).
        {
            let child = MapChild::spawn(std::slice::from_ref(&merged));
            let range = child.range_of(&merged);
            let target = child.dir();
            // Lower-only mapping verifies via the page witness (overlay target
            // is never fast-pathed): the association carries a frame.
            let lower = File::open(&lower_file).unwrap();
            let assoc = verify_mapped_backing(&target, &range, &lower).unwrap();
            assert!(
                assoc.witness_page().is_some(),
                "overlay must witness, not fast-path"
            );
            assert_eq!(
                assoc.object_identity(),
                (lower_meta.dev(), lower_meta.ino())
            );
            // Copy-up: the merged path now serves upper bytes, so the VMA's
            // reported identity moves with it — the pre-copy-up association no
            // longer describes live state and revalidation must fail closed.
            std::fs::write(&merged, vec![0x55u8; 4096]).unwrap();
            assert_eq!(assoc.revalidate(), Err(BackingError::Changed));
            // And the merged path as a fresh candidate is a different file
            // from the lower-bound mapping, so it must refuse too.
            let upper_view = File::open(&merged).unwrap();
            assert_eq!(
                err_of(verify_mapped_backing(&target, &range, &upper_view)),
                BackingError::Changed
            );
        }
        // Couple the backing to the mount's fate: if cleanup refuses, the
        // mount is retained by policy and the subvolumes must survive with
        // it — deleting them from under a retained mount would corrupt the
        // evidence MountGuard kept.
        if let Err(error) = guard.cleanup() {
            fx.retain(&error);
            panic!("{error}");
        }
    }

    fn mount_tmpfs_siblings(base: std::path::PathBuf, points: &[std::path::PathBuf]) -> MountGuard {
        let mut guard = MountGuard::new(base);
        for point in points {
            guard
                .mount(point.clone(), &["-t", "tmpfs", "tmpfs"])
                .unwrap();
        }
        guard
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_busy_unmount_preserves_backing() {
        let (mut guard, base) = mount_overlay();
        let point = base.join("merged");
        let sentinel = base.join("upper/owned-sentinel");
        std::fs::write(&sentinel, b"preserve on refusal").unwrap();
        let blocker = File::open(&point).unwrap();
        eprintln!(
            "G1F busy pid={} namespace={:?} base={base:?}",
            std::process::id(),
            std::fs::read_link("/proc/thread-self/ns/mnt").unwrap()
        );
        // An open directory pins this real mount, so normal umount refuses.
        let refusal = guard.cleanup().unwrap_err();
        eprintln!("{refusal}");
        let preserved = std::fs::read(&sentinel).ok() == Some(b"preserve on refusal".to_vec());
        let mounted = Command::new("findmnt")
            .args([
                "--mountpoint",
                point.to_str().unwrap(),
                "-n",
                "-o",
                "ID,TARGET,FSTYPE",
            ])
            .output()
            .unwrap();
        eprintln!(
            "G1F busy after cleanup mounted={} preserved={} identity={}",
            mounted.status.success(),
            preserved,
            String::from_utf8_lossy(&mounted.stdout)
        );
        drop(blocker);
        guard.cleanup().unwrap();
        assert!(
            !Command::new("findmnt")
                .arg("--mountpoint")
                .arg(&point)
                .status()
                .unwrap()
                .success()
        );
        assert!(!base.exists());
        assert!(
            preserved,
            "cleanup deleted backing after normal umount refused"
        );
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_first_sibling_setup_failure_cleans_mount() {
        let base = scratch("partial-siblings");
        let first = base.join("m1");
        let absent_second = base.join("missing-m2");
        std::fs::create_dir(&first).unwrap();
        let setup = std::panic::catch_unwind(|| {
            mount_tmpfs_siblings(base.clone(), &[first.clone(), absent_second])
        });
        assert!(setup.is_err(), "second sibling setup must fail");
        let mounted = Command::new("findmnt")
            .args([
                "--mountpoint",
                first.to_str().unwrap(),
                "-n",
                "-o",
                "ID,TARGET,FSTYPE",
            ])
            .output()
            .unwrap();
        eprintln!(
            "G1F partial pid={} namespace={:?} base={base:?} leaked={} identity={}",
            std::process::id(),
            std::fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
            mounted.status.success(),
            String::from_utf8_lossy(&mounted.stdout)
        );
        if mounted.status.success() {
            assert!(
                Command::new("umount")
                    .arg("--")
                    .arg(&first)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(
            !Command::new("findmnt")
                .arg("--mountpoint")
                .arg(&first)
                .status()
                .unwrap()
                .success()
        );
        if base.exists() {
            std::fs::remove_dir_all(&base).unwrap();
        }
        assert!(
            !mounted.status.success(),
            "first sibling mount leaked on second-mount setup failure"
        );
    }

    fn independently_mounted(point: &std::path::Path) -> bool {
        let output = Command::new("findmnt")
            .arg("--mountpoint")
            .arg(point)
            .args(["-n", "-o", "ID,TARGET,FSTYPE"])
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(0 | 1)));
        eprintln!(
            "independent mount observation: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        output.status.success()
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_normal_exit_cleans_overlay_and_siblings() {
        let (guard, base) = mount_overlay();
        let merged = base.join("merged");
        assert!(independently_mounted(&merged));
        drop(guard);
        assert!(!independently_mounted(&merged));
        assert!(!base.exists());
        let base = scratch("normal-siblings");
        let points = [base.join("m1"), base.join("m2")];
        for point in &points {
            std::fs::create_dir(point).unwrap();
        }
        let guard = mount_tmpfs_siblings(base.clone(), &points);
        assert!(points.iter().all(|p| independently_mounted(p)));
        drop(guard);
        assert!(points.iter().all(|p| !independently_mounted(p)));
        assert!(!base.exists());
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_unwind_cleans_acquired_mounts() {
        let base = scratch("unwind-siblings");
        let points = [base.join("m1"), base.join("m2")];
        for point in &points {
            std::fs::create_dir(point).unwrap();
        }
        let unwind = std::panic::catch_unwind(|| {
            let _guard = mount_tmpfs_siblings(base.clone(), &points);
            assert!(points.iter().all(|p| independently_mounted(p)));
            panic!("intentional owned fixture unwind");
        });
        assert!(unwind.is_err());
        assert!(points.iter().all(|p| !independently_mounted(p)));
        assert!(!base.exists());
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_cooperative_cancellation_cleans_mount() {
        let (guard, base) = mount_overlay();
        let point = base.join("merged");
        let cancelled: Result<(), &str> = (move || {
            let _guard = guard;
            assert!(independently_mounted(&point));
            Err("intentional fixture cancellation")
        })();
        assert_eq!(cancelled, Err("intentional fixture cancellation"));
        assert!(!independently_mounted(&base.join("merged")));
        assert!(!base.exists());
    }

    #[test]
    #[ignore = "requires owned private mount namespace + privilege (G1F)"]
    fn fixture_replaced_mount_refuses_unmount_and_deletion() {
        let base = scratch("replaced-mount");
        let point = base.join("m1");
        std::fs::create_dir(&point).unwrap();
        let mut guard = mount_tmpfs_siblings(base.clone(), std::slice::from_ref(&point));
        assert!(
            Command::new("umount")
                .arg("--")
                .arg(&point)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(&point)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(point.join("replacement-sentinel"), b"replacement").unwrap();
        let refusal = guard.cleanup();
        eprintln!("replacement cleanup outcome: {refusal:?}");
        let preserved =
            std::fs::read(point.join("replacement-sentinel")).ok() == Some(b"replacement".to_vec());
        let mounted = independently_mounted(&point);
        // A normal Drop must fail visibly and preserve the replacement too.
        let drop_refused = std::panic::catch_unwind(move || drop(guard)).is_err();
        if mounted {
            assert!(
                Command::new("umount")
                    .arg("--")
                    .arg(&point)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(!independently_mounted(&point));
        if base.exists() {
            std::fs::remove_dir_all(&base).unwrap();
        }
        assert!(refusal.is_err());
        assert!(
            preserved && mounted && drop_refused,
            "changed mount must remain intact and refusal visible"
        );
    }

    fn copy_up_same_bytes(path: &std::path::Path) {
        use std::os::unix::fs::FileExt as _;
        let bytes = std::fs::read(path).unwrap();
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        writer.write_all_at(&bytes, 0).unwrap();
        writer.sync_all().unwrap();
    }

    #[test]
    #[ignore = "requires privileged overlay mount + map_files/pagemap (5E)"]
    fn overlay_copyup_matrix() {
        let (_guard, base) = mount_overlay();
        let mut bytes = vec![0x41u8; 4096];
        bytes.extend_from_slice(&vec![0x42u8; 4096]);
        std::fs::write(base.join("lower/file"), &bytes).unwrap();
        let merged = base.join("merged/file");
        // Retained before copy-up: its mmap keeps serving the lower backing.
        let retained = File::open(&merged).unwrap();
        let child = MapChild::spawn(&[merged.clone()]);
        let range = child.range_of(&merged);
        let target = child.dir();
        // Lower-only: the overlay descriptor verifies through the witness.
        let fresh = File::open(&merged).unwrap();
        let before = verify_mapped_backing(&target, &range, &fresh).unwrap();
        assert!(before.witness_page().is_some());
        before.revalidate().unwrap();
        copy_up_same_bytes(&merged);
        assert!(
            base.join("upper/file").metadata().is_ok(),
            "copy-up proof: upper file must exist"
        );
        // The pre-copy-up association no longer describes live state.
        assert_eq!(before.revalidate(), Err(BackingError::Changed));
        // Reopened overlay descriptor serves the upper copy now.
        let reopened = File::open(&merged).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &reopened)),
            BackingError::Changed
        );
        // Retained overlay descriptor: mmap still lower, registration path
        // re-resolves upper, so the re-resolution leg refuses.
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &retained)),
            BackingError::Changed
        );
        // Direct lower descriptor still traces the old mapping.
        let lower = File::open(base.join("lower/file")).unwrap();
        let assoc = verify_mapped_backing(&target, &range, &lower).unwrap();
        let meta = lower.metadata().unwrap();
        assert_eq!(assoc.object_identity(), (meta.dev(), meta.ino()));
        assoc.revalidate().unwrap();
        // Direct upper descriptor is not the old mapping's backing.
        let upper = File::open(base.join("upper/file")).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &upper)),
            BackingError::Changed
        );
        // Layer discovery finds both direct backings as hints.
        let found = direct_layer_candidates(
            &target,
            merged.to_string_lossy().as_bytes(),
            MAX_LAYER_CANDIDATES,
        );
        let identities: Vec<(u64, u64)> = found
            .iter()
            .map(|f| {
                let m = f.metadata().unwrap();
                (m.dev(), m.ino())
            })
            .collect();
        let upper_meta = upper.metadata().unwrap();
        assert!(
            identities.contains(&(meta.dev(), meta.ino())),
            "lower hint missing"
        );
        assert!(
            identities.contains(&(upper_meta.dev(), upper_meta.ino())),
            "upper hint missing"
        );
    }

    #[test]
    #[ignore = "requires privileged mounts + map_files (5E)"]
    fn sibling_tmpfs_mounts_same_content_refuses() {
        let base = scratch("siblings");
        let m1 = base.join("m1");
        let m2 = base.join("m2");
        std::fs::create_dir(&m1).unwrap();
        std::fs::create_dir(&m2).unwrap();
        let _cleanup = mount_tmpfs_siblings(base.clone(), &[m1.clone(), m2.clone()]);
        let bytes = vec![0x5au8; 4096];
        std::fs::write(m1.join("x"), &bytes).unwrap();
        std::fs::write(m2.join("x"), &bytes).unwrap();
        let child = MapChild::spawn(&[m1.join("x")]);
        let range = child.range_of(&m1.join("x"));
        let target = child.dir();
        let sibling = File::open(m2.join("x")).unwrap();
        assert_eq!(
            err_of(verify_mapped_backing(&target, &range, &sibling)),
            BackingError::Changed
        );
        let own = File::open(m1.join("x")).unwrap();
        verify_mapped_backing(&target, &range, &own).unwrap();
    }

    #[test]
    #[ignore = "requires privileged map_files (5E)"]
    fn content_change_detected_on_revalidate() {
        use std::os::unix::fs::FileExt as _;
        let dir = scratch("content");
        std::fs::write(dir.join("a"), vec![0x30u8; 4096]).unwrap();
        let child = MapChild::spawn(&[dir.join("a")]);
        let range = child.range_of(&dir.join("a"));
        let assoc =
            verify_mapped_backing(&child.dir(), &range, &File::open(dir.join("a")).unwrap())
                .unwrap();
        // Same-size in-place change: size legs pass, timestamp legs fire.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("a"))
            .unwrap();
        writer.write_all_at(&[0x31u8], 0).unwrap();
        writer.sync_all().unwrap();
        assert_eq!(writer.metadata().unwrap().len(), 4096);
        assert_eq!(assoc.revalidate(), Err(BackingError::Changed));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires privileged map_files (5E)"]
    fn unlink_keeps_retained_association() {
        let dir = scratch("unlink");
        std::fs::write(dir.join("a"), vec![0x33u8; 4096]).unwrap();
        let before = std::fs::metadata(dir.join("a")).unwrap();
        let child = MapChild::spawn(&[dir.join("a")]);
        let range = child.range_of(&dir.join("a"));
        let assoc =
            verify_mapped_backing(&child.dir(), &range, &File::open(dir.join("a")).unwrap())
                .unwrap();
        std::fs::remove_file(dir.join("a")).unwrap();
        let maps = String::from_utf8(child.maps()).unwrap();
        assert!(
            maps.lines().any(|l| l.contains("(deleted)")),
            "precondition: maps must show the deletion"
        );
        assoc.revalidate().unwrap();
        assert_eq!(assoc.object_identity(), (before.dev(), before.ino()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires privileged map_files (5E)"]
    fn path_replace_keeps_retained_association() {
        let dir = scratch("replace");
        std::fs::write(dir.join("a"), vec![0x40u8; 4096]).unwrap();
        std::fs::write(dir.join("b"), vec![0x41u8; 4096]).unwrap();
        let before = std::fs::metadata(dir.join("a")).unwrap();
        let child = MapChild::spawn(&[dir.join("a")]);
        let range = child.range_of(&dir.join("a"));
        let assoc =
            verify_mapped_backing(&child.dir(), &range, &File::open(dir.join("a")).unwrap())
                .unwrap();
        std::fs::rename(dir.join("b"), dir.join("a")).unwrap();
        // The pathname now serves different bytes; the retained association
        // still describes the mapped backing, not the path.
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), vec![0x41u8; 4096]);
        assoc.revalidate().unwrap();
        assert_eq!(assoc.object_identity(), (before.dev(), before.ino()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "requires privileged map_files + setns (5E)"]
    fn namespace_change_detected_on_revalidate() {
        let dir = scratch("nschange");
        std::fs::write(dir.join("a"), vec![0x44u8; 4096]).unwrap();
        // Donor mount namespace, distinct from the test's own.
        let mut donor = Command::new("unshare")
            .args(["-m", "sleep", "60"])
            .spawn()
            .unwrap();
        // Child maps our file, then moves itself into the donor mount
        // namespace on command; mappings stay intact across setns.
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(
                "import ctypes,mmap,os,sys\nf=open(sys.argv[1],'rb')\nm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)\nprint('ready',flush=True)\nsys.stdin.read(1)\nlibc=ctypes.CDLL(None)\nns=os.open(sys.argv[2],os.O_RDONLY)\nassert libc.setns(ns,0x00020000)==0\nprint('moved',flush=True)\nsys.stdin.read()\n",
            )
            .arg(dir.join("a"))
            .arg(format!("/proc/{}/ns/mnt", donor.id()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let pid = child.id();
        let target = File::open(format!("/proc/{pid}")).unwrap();
        let maps = std::fs::read(format!("/proc/{pid}/maps")).unwrap();
        let needle = dir.join("a").to_string_lossy().into_owned();
        let vma = maps
            .split(|b| *b == b'\n')
            .filter(|l| String::from_utf8_lossy(l).contains(&needle))
            .filter_map(parse_vma)
            .next()
            .unwrap();
        let range = MappedRange {
            start: vma.start,
            end: vma.start + 1,
        };
        let assoc =
            verify_mapped_backing(&target, &range, &File::open(dir.join("a")).unwrap()).unwrap();
        child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        child.stdin.as_mut().unwrap().flush().unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "moved\n");
        // The mapping itself is untouched; only the namespace moved.
        let after = std::fs::read(format!("/proc/{pid}/maps")).unwrap();
        let still = after
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .filter_map(parse_vma)
            .any(|v| v.start == vma.start && v.end == vma.end && v.ino == vma.ino);
        assert!(still, "mapping must survive setns");
        assert_eq!(assoc.revalidate(), Err(BackingError::Changed));
        drop(child.stdin.take());
        child.wait().unwrap();
        donor.kill().unwrap();
        donor.wait().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Minimal caller budget for GREEN-only supplement controls (the
    /// path-level I2 controls carry RED; these pin the refusal mechanics of
    /// the new charged entry points directly).
    struct TinyBudget {
        max_state: usize,
        max_reads: u64,
        reads: u64,
        expired: bool,
    }
    impl BackingBudget for TinyBudget {
        fn checkpoint(&mut self) -> Result<(), BackingError> {
            if self.expired {
                Err(BackingError::Unavailable)
            } else {
                Ok(())
            }
        }
        fn allow_read(&mut self, want: usize) -> Result<usize, BackingError> {
            let remaining = self.max_reads.saturating_sub(self.reads);
            if remaining == 0 {
                return Err(BackingError::Unavailable);
            }
            Ok(want
                .max(1)
                .min(usize::try_from(remaining).unwrap_or(usize::MAX)))
        }
        fn commit_read(&mut self, bytes: u64) -> Result<(), BackingError> {
            self.reads += bytes;
            if self.reads > self.max_reads {
                return Err(BackingError::Unavailable);
            }
            Ok(())
        }
        fn reserve_state(&mut self, bytes: usize) -> Result<BackingLease, BackingError> {
            if bytes > self.max_state {
                return Err(BackingError::Unavailable);
            }
            Ok(BackingLease::Uncharged)
        }
    }

    #[test]
    fn charged_capture_refuses_before_allocating_on_exhausted_budget() {
        let dir = File::open("/proc/self").unwrap();
        // The stat reservation does not fit: refuse before any read.
        let mut budget = TinyBudget {
            max_state: MAX_STAT_READ - 1,
            max_reads: u64::MAX,
            reads: 0,
            expired: false,
        };
        assert_eq!(
            BackingProcess::capture_charged(&dir, &mut budget).map(|_| ()),
            Err(BackingError::Unavailable)
        );
        assert_eq!(budget.reads, 0);
        // The stat read fits but the maps reservation does not: refuse
        // after the stat read, before allocating the maps buffer.
        let mut budget = TinyBudget {
            max_state: MAX_STAT_READ,
            max_reads: u64::MAX,
            reads: 0,
            expired: false,
        };
        assert_eq!(
            BackingProcess::capture_charged(&dir, &mut budget).map(|_| ()),
            Err(BackingError::Unavailable)
        );
        assert!(budget.reads > 0 && budget.reads <= MAX_STAT_READ as u64);
    }

    #[test]
    fn charged_revalidate_enforces_deadline_before_any_io() {
        let dir = File::open("/proc/self").unwrap();
        // Synthetic association: never valid, never reached — the expired
        // deadline must refuse before any field is consulted or any IO happens.
        let zero = Fingerprint {
            dev: 0,
            ino: 0,
            size: 0,
            mode: 0,
            nlink: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
        };
        let assoc = BackingAssociation {
            directory: dir.try_clone().unwrap(),
            candidate: dir.try_clone().unwrap(),
            range: MappedRange { start: 0, end: 1 },
            vma: VmaRecord {
                start: 0,
                end: 1,
                pgoff: 0,
                dev: 0,
                ino: 0,
                executable: false,
            },
            candidate_fp: zero.clone(),
            target_fp: zero.clone(),
            page: None,
            starttime: 0,
            pid_namespace: NamespaceId {
                device: 0,
                inode: 0,
            },
            mount_namespace: NamespaceId {
                device: 0,
                inode: 0,
            },
            executable: zero,
        };
        let mut budget = TinyBudget {
            max_state: usize::MAX,
            max_reads: u64::MAX,
            reads: 0,
            expired: true,
        };
        assert_eq!(
            assoc.revalidate_charged(&mut budget).map(|_| ()),
            Err(BackingError::Unavailable)
        );
        assert_eq!(budget.reads, 0);
    }

    /// I1 child entry: runs the truncation scenario through the actual
    /// production caller pair (`BackingProcess::capture` +
    /// `verify_with_process`) when spawned by
    /// `truncation_during_verification_refuses_safely` with
    /// `OSSLSCOPE_BACKING_I1_CHILD=first|second`. No-op otherwise, so
    /// default suite runs stay fast.
    #[test]
    fn i1_truncation_child_entry() {
        let mode = std::env::var("OSSLSCOPE_BACKING_I1_CHILD").unwrap_or_default();
        if mode.is_empty() {
            return;
        }
        let site: u8 = match mode.as_str() {
            "first" => 1,
            "second" => 2,
            _ => panic!("unknown I1 child mode"),
        };
        // The witness path needs a non-direct pair: overlay mount.
        let (_guard, base) = mount_overlay();
        let mut bytes = vec![0x41u8; 4096];
        bytes.extend_from_slice(&vec![0x42u8; 4096]);
        std::fs::write(base.join("lower/file"), &bytes).unwrap();
        let merged = base.join("merged/file");
        let child = MapChild::spawn(&[merged.clone()]);
        let range = child.range_of(&merged);
        let target = child.dir();
        let candidate = File::open(&merged).unwrap();
        // Truncate the LOWER file, not the merged path: a merged-path
        // truncate copies up and leaves the mmap'd lower pages intact
        // (harmless Changed refusal), while truncating the actual backing
        // invalidates the mapped pages (the SIGBUS hazard).
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .open(base.join("lower/file"))
            .unwrap();
        *FAULT_TRUNCATE.lock().unwrap() = Some((writable, site));
        let process = BackingProcess::capture(&target).unwrap();
        match process.verify_with_process(&range, &candidate) {
            Err(error) => println!("I1-REFUSED:{error:?}"),
            Ok(_) => panic!("I1 child: verification unexpectedly succeeded after truncation"),
        }
    }

    /// I1 RED control (ER-5E-I1): a truncation landing between the witness
    /// size check and the page touch must yield a typed refusal with
    /// observer survival, never SIGBUS. Each truncating half runs in a
    /// spawned child (this same test binary, filtered to
    /// `i1_truncation_child_entry`) so the RED hazard — the child killed
    /// by SIGBUS — cannot crash this harness.
    #[test]
    #[ignore = "requires privileged overlay mount + map_files/pagemap (5E-I1)"]
    fn truncation_during_verification_refuses_safely() {
        for mode in ["first", "second"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("inventory::backing::tests::i1_truncation_child_entry")
                .arg("--nocapture")
                .env("OSSLSCOPE_BACKING_I1_CHILD", mode)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.status.success() {
                use std::os::unix::process::ExitStatusExt as _;
                panic!(
                    "I1 RED (mode={mode}): child did not survive truncation: status={} signal={:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                    output.status,
                    output.status.signal(),
                );
            }
            assert!(
                stdout.contains("I1-REFUSED:Unavailable"),
                "I1 (mode={mode}): expected typed Unavailable refusal, got:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
        }
    }

    /// Shared outstanding-state cell for the peak-charge control below.
    struct PeakShared {
        current: std::cell::Cell<usize>,
        peak: std::cell::Cell<usize>,
    }

    /// Caller-budget capacity whose drop releases its outstanding charge, so
    /// the control observes live (peak) charges, not just admissions.
    struct PeakCapacity {
        shared: std::rc::Rc<PeakShared>,
        bytes: usize,
    }
    impl HeldCapacity for PeakCapacity {}
    impl Drop for PeakCapacity {
        fn drop(&mut self) {
            self.shared
                .current
                .set(self.shared.current.get() - self.bytes);
        }
    }

    /// Outstanding-based caller budget for the peak-charge control: state
    /// reservations accumulate while their leases live (pool-shaped, like
    /// both production callers) and refusals are recorded with the denied
    /// amount, so the control can tell "raw admitted, copies refused".
    struct PeakBudget {
        shared: std::rc::Rc<PeakShared>,
        max_state: usize,
        max_reads: u64,
        reads: u64,
        denials: Vec<usize>,
    }
    impl PeakBudget {
        fn new(max_state: usize) -> Self {
            Self {
                shared: std::rc::Rc::new(PeakShared {
                    current: std::cell::Cell::new(0),
                    peak: std::cell::Cell::new(0),
                }),
                max_state,
                max_reads: u64::MAX,
                reads: 0,
                denials: Vec::new(),
            }
        }
    }
    impl BackingBudget for PeakBudget {
        fn checkpoint(&mut self) -> Result<(), BackingError> {
            Ok(())
        }
        fn allow_read(&mut self, want: usize) -> Result<usize, BackingError> {
            let remaining = self.max_reads.saturating_sub(self.reads);
            if remaining == 0 {
                return Err(BackingError::Unavailable);
            }
            Ok(want
                .max(1)
                .min(usize::try_from(remaining).unwrap_or(usize::MAX)))
        }
        fn commit_read(&mut self, bytes: u64) -> Result<(), BackingError> {
            self.reads += bytes;
            Ok(())
        }
        fn reserve_state(&mut self, bytes: usize) -> Result<BackingLease, BackingError> {
            let next = self.shared.current.get().saturating_add(bytes);
            if next > self.max_state {
                self.denials.push(bytes);
                return Err(BackingError::Unavailable);
            }
            self.shared.current.set(next);
            self.shared.peak.set(self.shared.peak.get().max(next));
            Ok(BackingLease::held(PeakCapacity {
                shared: self.shared.clone(),
                bytes,
            }))
        }
    }

    /// I2-remainder control (ER-5E-I2): successful layer discovery near the
    /// mountinfo input cap must hold BOTH the raw-buffer reservation and the
    /// parser/path scratch reservation while the bytes are live, and a caller
    /// budget that admits the raw read but not the copies must refuse (fail
    /// closed with no candidates). Drives the real
    /// `direct_layer_candidates_charged` shared by both production callers
    /// against a synthetic near-cap mountinfo in a scratch dir — the charged
    /// entry point reads `mountinfo` relative to any directory File, so no
    /// privilege is needed.
    #[test]
    fn layer_discovery_holds_raw_and_scratch_charges_at_peak() {
        let base = scratch("layer-peak");
        for name in ["upper", "lower1", "lower2"] {
            let dir = base.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("libtest.so"), b"layer-bytes").unwrap();
        }
        let dir = |name: &str| base.join(name).to_string_lossy().into_owned();
        let mut mountinfo = format!(
            "100 1 0:100 / /target/mount rw - overlay overlay rw,lowerdir={}:{},upperdir={}\n",
            dir("lower1"),
            dir("lower2"),
            dir("upper")
        )
        .into_bytes();
        // Filler overlay mounts with short non-matching mountpoints pad the
        // input to just under the cap; the target mount wins longest-match.
        let mut filler = 0u32;
        while mountinfo.len() + 256 < MAX_MOUNTINFO_READ {
            filler += 1;
            mountinfo.extend_from_slice(
                format!(
                    "{filler} 1 0:200 / /f{filler:06} rw - overlay overlay rw,lowerdir=/nonexistent/filler-{filler:06}\n"
                )
                .as_bytes(),
            );
        }
        let size = mountinfo.len();
        assert!(
            size > MAX_MOUNTINFO_READ - 8192 && size <= MAX_MOUNTINFO_READ,
            "near-cap input required, got {size} vs cap {MAX_MOUNTINFO_READ}"
        );
        std::fs::write(base.join("mountinfo"), &mountinfo).unwrap();
        let process_dir = File::open(&base).unwrap();
        let maps_path = b"/target/mount/libtest.so";
        let expected: Vec<(u64, u64)> = ["upper", "lower1", "lower2"]
            .iter()
            .map(|name| {
                let meta = std::fs::metadata(base.join(name).join("libtest.so")).unwrap();
                (meta.dev(), meta.ino())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();

        // Success half: a generous outstanding-based budget. Discovery must
        // succeed AND the peak live charge must cover the raw reservation
        // plus input-sized scratch at the same instant.
        {
            let mut budget = PeakBudget::new(usize::MAX);
            let found = direct_layer_candidates_charged(
                &process_dir,
                maps_path,
                MAX_LAYER_CANDIDATES,
                &mut budget,
            );
            let identities: Vec<(u64, u64)> = found
                .iter()
                .map(|f| {
                    let meta = f.metadata().unwrap();
                    (meta.dev(), meta.ino())
                })
                .collect();
            if identities != expected {
                failures.push(format!(
                    "success half: expected upper+lowers in order {expected:?}, got {identities:?}"
                ));
            }
            let peak = budget.shared.peak.get();
            if peak < MAX_MOUNTINFO_READ + size {
                failures.push(format!(
                    "success half: peak live charge {peak} does not cover raw {MAX_MOUNTINFO_READ} + scratch {size} (lease dropped early or scratch unreserved)"
                ));
            }
            if budget.reads != size as u64 {
                failures.push(format!(
                    "success half: raw read must charge exactly {size} bytes, got {}",
                    budget.reads
                ));
            }
            if budget.shared.current.get() != 0 {
                failures.push(format!(
                    "success half: outstanding charge must release, still {}",
                    budget.shared.current.get()
                ));
            }
        }

        // Tight half: admits the raw read plus one input of scratch, but not
        // the raw-plus-copies peak — must refuse fail-closed, no candidates.
        {
            let mut budget = PeakBudget::new(MAX_MOUNTINFO_READ + size);
            let found = direct_layer_candidates_charged(
                &process_dir,
                maps_path,
                MAX_LAYER_CANDIDATES,
                &mut budget,
            );
            if !found.is_empty() {
                failures.push(format!(
                    "tight half: budget admitting raw but not copies must refuse, got {} candidates",
                    found.len()
                ));
            }
            if budget.denials.is_empty() {
                failures.push(
                    "tight half: expected a scratch reservation denial, got none".to_string(),
                );
            } else {
                let denied_max = budget.denials.iter().max().copied().unwrap_or(0);
                if denied_max <= size {
                    failures.push(format!(
                        "tight half: denial must exceed the post-raw remainder {size}, got {:?}",
                        budget.denials
                    ));
                }
            }
            if budget.reads != size as u64 {
                failures.push(format!(
                    "tight half: raw read must be admitted ({size} bytes), got {}",
                    budget.reads
                ));
            }
            if budget.shared.current.get() != 0 {
                failures.push(format!(
                    "tight half: outstanding charge must release on refusal, still {}",
                    budget.shared.current.get()
                ));
            }
        }

        std::fs::remove_dir_all(&base).unwrap();
        assert!(
            failures.is_empty(),
            "layer-discovery peak control RED:\n{}",
            failures.join("\n")
        );
    }

    /// Rust 1.88 path-to-C-string conversion behavior, verified first-hand
    /// from the pinned sources (`library/std/src/sys/pal/common/
    /// small_c_string.rs`, reached from `File::open` via `run_path_with_cstr`
    /// in `library/std/src/sys/fs/unix.rs`): paths with `len >=
    /// MAX_STACK_ALLOCATION` (384 on non-espidf) are heap-copied with
    /// `CString::new` while the caller's buffer stays live; shorter paths
    /// convert in a stack buffer with no heap allocation.
    const STD_PATH_STACK_COPY_LIMIT: usize = 384;

    /// Long relative path of exactly `total` bytes (`total >= 13`), every
    /// component below NAME_MAX and ending in a real filename, so the
    /// control sizes joined paths from the measured layer length whatever
    /// TMPDIR contributes.
    fn long_relative(total: usize) -> Vec<u8> {
        let tail = b"/libtest.so";
        let full = total.saturating_sub(tail.len() + 1) / 201;
        let mut out = Vec::with_capacity(total);
        for _ in 0..full {
            out.extend_from_slice(&[b'd'; 200]);
            out.push(b'/');
        }
        let rest = total - tail.len() - full * 201;
        out.resize(out.len() + rest, b'z');
        out.extend_from_slice(tail);
        assert_eq!(out.len(), total);
        out
    }

    /// I2-remainder long-path control (ER-5E-I2): layer discovery over a LONG
    /// mapped path — joined length at/above the std conversion threshold —
    /// must perform no heap allocation beyond the charged reservation (in
    /// particular no path-conversion copy), and a budget admitting the raw
    /// read but not the scratch must refuse before any joined-path
    /// allocation. Drives the real `direct_layer_candidates_charged` shared
    /// by both production callers; heap allocations are COUNTED through the
    /// shared test allocator, not inferred from requested charges, so an
    /// uncovered copy fails the control even though discovery succeeds.
    #[test]
    fn layer_discovery_opens_long_paths_without_conversion_copy() {
        use crate::provider_observation::source_acquire::heap_measure::{
            LARGE_ALLOC_THRESHOLD, count_large_of,
        };
        let base = scratch("lp");
        let layer_len = base.join("upper").to_string_lossy().len();
        // Joined capacity (layer + '/' + relative + NUL) must clear the
        // counting threshold with margin; the conversion-copy trigger (384)
        // then follows. Sized from the measured layer length, not TMPDIR.
        let relative_len = (LARGE_ALLOC_THRESHOLD + 64).saturating_sub(layer_len + 2);
        assert!(
            relative_len >= STD_PATH_STACK_COPY_LIMIT,
            "TMPDIR too long to size a separating relative path"
        );
        let relative = long_relative(relative_len);
        assert!(
            layer_len + 1 + relative.len() >= STD_PATH_STACK_COPY_LIMIT + 64
                && layer_len + 1 + relative.len() + 1 >= LARGE_ALLOC_THRESHOLD + 64,
            "joined path must trigger the std copy and clear the counter"
        );
        for name in ["upper", "lower1"] {
            let file = base
                .join(name)
                .join(std::str::from_utf8(&relative).unwrap());
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, b"layer-bytes").unwrap();
        }
        let dir = |name: &str| base.join(name).to_string_lossy().into_owned();
        let mountinfo = format!(
            "100 1 0:100 / /t rw - overlay overlay rw,lowerdir={},upperdir={}\n",
            dir("lower1"),
            dir("upper")
        )
        .into_bytes();
        let size = mountinfo.len();
        assert!(
            size < LARGE_ALLOC_THRESHOLD / 2,
            "raw/working buffers must stay below the counting threshold, got {size}"
        );
        std::fs::write(base.join("mountinfo"), &mountinfo).unwrap();
        let process_dir = File::open(&base).unwrap();
        let mut maps_path = b"/t/".to_vec();
        maps_path.extend_from_slice(&relative);
        let expected: Vec<(u64, u64)> = ["upper", "lower1"]
            .iter()
            .map(|name| {
                let file = base
                    .join(name)
                    .join(std::str::from_utf8(&relative).unwrap());
                let meta = std::fs::metadata(&file).unwrap();
                (meta.dev(), meta.ino())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();

        // Warmup absorbs any one-time lazy allocation before measuring.
        {
            let mut budget = PeakBudget::new(usize::MAX);
            let warm = direct_layer_candidates_charged(
                &process_dir,
                &maps_path,
                MAX_LAYER_CANDIDATES,
                &mut budget,
            );
            if warm.len() != expected.len() {
                failures.push(format!(
                    "warmup: expected {} candidates, got {}",
                    expected.len(),
                    warm.len()
                ));
            }
        }

        // Success half: long-path discovery succeeds with exactly the two
        // joined buffers allocated — no conversion copy — while the peak
        // live charge covers the raw reservation plus the scratch
        // reservation (including the NUL terminator byte).
        {
            let mut budget = PeakBudget::new(usize::MAX);
            let mut found = Vec::new();
            let large = count_large_of(|| {
                found = direct_layer_candidates_charged(
                    &process_dir,
                    &maps_path,
                    MAX_LAYER_CANDIDATES,
                    &mut budget,
                );
            });
            let identities: Vec<(u64, u64)> = found
                .iter()
                .map(|f| {
                    let meta = f.metadata().unwrap();
                    (meta.dev(), meta.ino())
                })
                .collect();
            if identities != expected {
                failures.push(format!(
                    "success half: expected upper+lower in order {expected:?}, got {identities:?}"
                ));
            }
            if large != expected.len() {
                failures.push(format!(
                    "success half: {large} large heap allocations during long-path discovery, expected exactly {} joined buffers (an extra copy per open is the uncovered path-conversion allocation)",
                    expected.len()
                ));
            }
            let scratch = size + size + maps_path.len() + 2 + LAYER_SCRATCH_SLOP;
            let peak = budget.shared.peak.get();
            if peak != MAX_MOUNTINFO_READ + scratch {
                failures.push(format!(
                    "success half: peak live charge {peak} must equal raw {} + scratch {scratch} (lease dropped early, scratch unreserved, or terminator unaccounted)",
                    MAX_MOUNTINFO_READ
                ));
            }
            if budget.reads != size as u64 {
                failures.push(format!(
                    "success half: raw read must charge exactly {size} bytes, got {}",
                    budget.reads
                ));
            }
            if budget.shared.current.get() != 0 {
                failures.push(format!(
                    "success half: outstanding charge must release, still {}",
                    budget.shared.current.get()
                ));
            }
        }

        // Tight half: admits the raw read plus one input of scratch, but not
        // the raw-plus-scratch peak — must refuse fail-closed with no
        // candidates and no joined-path allocation at all.
        {
            let mut budget = PeakBudget::new(MAX_MOUNTINFO_READ + size);
            let mut found = Vec::new();
            let large = count_large_of(|| {
                found = direct_layer_candidates_charged(
                    &process_dir,
                    &maps_path,
                    MAX_LAYER_CANDIDATES,
                    &mut budget,
                );
            });
            if !found.is_empty() {
                failures.push(format!(
                    "tight half: budget admitting raw but not scratch must refuse, got {} candidates",
                    found.len()
                ));
            }
            if large != 0 {
                failures.push(format!(
                    "tight half: refusal must precede any joined-path allocation, got {large} large allocations"
                ));
            }
            if budget.denials.is_empty() {
                failures.push(
                    "tight half: expected a scratch reservation denial, got none".to_string(),
                );
            } else {
                let denied_max = budget.denials.iter().max().copied().unwrap_or(0);
                if denied_max <= size {
                    failures.push(format!(
                        "tight half: denial must exceed the post-raw remainder {size}, got {:?}",
                        budget.denials
                    ));
                }
            }
            if budget.reads != size as u64 {
                failures.push(format!(
                    "tight half: raw read must be admitted ({size} bytes), got {}",
                    budget.reads
                ));
            }
            if budget.shared.current.get() != 0 {
                failures.push(format!(
                    "tight half: outstanding charge must release on refusal, still {}",
                    budget.shared.current.get()
                ));
            }
        }

        std::fs::remove_dir_all(&base).unwrap();
        assert!(
            failures.is_empty(),
            "long-path control RED:\n{}",
            failures.join("\n")
        );
    }
}
