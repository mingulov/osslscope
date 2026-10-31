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
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

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
/// its reservation; read charges are cumulative and never released.
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
    leases: Vec<BackingLease>,
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
            leases: vec![lease],
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
                leases: vec![maps_lease],
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

/// One overlay mount's layer directories as host-absolute paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OverlayLayers {
    pub mountpoint: Vec<u8>,
    pub upper: Option<Vec<u8>>,
    pub lower: Vec<Vec<u8>>,
}

fn unescape_octal(bytes: &[u8]) -> Vec<u8> {
    // mountinfo escapes space/tab/newline/backslash as octal; anything else
    // passes through. Malformed escapes fail the whole entry later.
    let mut out = Vec::with_capacity(bytes.len());
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
    out
}

/// Pure `mountinfo` parser: overlay mounts with their layer directories.
/// Unparseable lines are skipped; resolution failures are the caller's.
pub(crate) fn parse_overlay_layers(mountinfo: &[u8]) -> Vec<OverlayLayers> {
    let mut mounts = Vec::new();
    for line in mountinfo.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        if line.contains(&0) {
            continue;
        }
        // Fields: id parent major:minor root mountpoint options ... " - " fstype source superoptions.
        let mut parts = line.split(|b| *b == b' ');
        let mut fields = Vec::new();
        for _ in 0..6 {
            match parts.next() {
                Some(field) => fields.push(field),
                None => break,
            }
        }
        if fields.len() < 6 {
            continue;
        }
        let rest: Vec<&[u8]> = parts.collect();
        let dash = rest.iter().position(|f| *f == b"-");
        let Some(dash) = dash else { continue };
        if rest.len() < dash + 4 {
            continue;
        }
        if rest[dash + 1] != b"overlay" {
            continue;
        }
        let superoptions = rest[dash + 3];
        let mut upper = None;
        let mut lower = Vec::new();
        for option in superoptions.split(|b| *b == b',') {
            if let Some(dir) = option.strip_prefix(b"upperdir=") {
                upper = Some(unescape_octal(dir));
            } else if let Some(dirs) = option.strip_prefix(b"lowerdir=") {
                // Lowerdirs separate with ':'; an escaped colon stays data.
                // Split on unescaped ':' only.
                let mut current = Vec::new();
                let mut bytes = dirs.iter();
                while let Some(b) = bytes.next() {
                    if *b == b'\\' {
                        current.push(*b);
                        if let Some(next) = bytes.next() {
                            current.push(*next);
                        }
                        continue;
                    }
                    if *b == b':' {
                        if !current.is_empty() {
                            lower.push(unescape_octal(&current));
                            current.clear();
                        }
                        continue;
                    }
                    current.push(*b);
                }
                if !current.is_empty() {
                    lower.push(unescape_octal(&current));
                }
            }
        }
        mounts.push(OverlayLayers {
            mountpoint: unescape_octal(fields[4]),
            upper,
            lower,
        });
    }
    mounts
}

fn join_layer(layer: &[u8], relative: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;
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
    let mut joined = layer.to_vec();
    if !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(relative);
    let _ = std::ffi::OsStr::from_bytes(&joined);
    Some(joined)
}

/// Direct layer candidates for a mapped path: host-absolute upper/lower
/// resolutions from the target's `mountinfo`, bounded. These are hints only;
/// every candidate still requires independent verification. Empty for
/// non-absolute paths, deleted mappings, and unresolvable layers.
pub(crate) fn direct_layer_candidates(
    process_dir: &File,
    maps_path: &[u8],
    max: usize,
) -> Vec<File> {
    direct_layer_candidates_charged(process_dir, maps_path, max, &mut UnboundedBudget)
}

pub(crate) fn direct_layer_candidates_charged<B: BackingBudget>(
    process_dir: &File,
    maps_path: &[u8],
    max: usize,
    budget: &mut B,
) -> Vec<File> {
    let mut candidates = Vec::new();
    if maps_path.is_empty() || !maps_path.starts_with(b"/") || maps_path.ends_with(b" (deleted)") {
        return candidates;
    }
    // The mountinfo buffer is transient: reserved before the read, released
    // once the layer hints are extracted.
    let mountinfo = match read_at_charged(process_dir, b"mountinfo", MAX_MOUNTINFO_READ, budget) {
        Ok((bytes, _lease)) => bytes,
        Err(_) => return candidates,
    };
    let layers = parse_overlay_layers(&mountinfo);
    // Longest mountpoint prefix wins; ties keep mountinfo order.
    let mut best: Option<&OverlayLayers> = None;
    for mount in &layers {
        let point = &mount.mountpoint;
        let matches = maps_path == point.as_slice()
            || (maps_path.starts_with(point.as_slice())
                && (point == b"/" || maps_path.get(point.len()) == Some(&b'/')));
        if matches && best.is_none_or(|b: &OverlayLayers| point.len() > b.mountpoint.len()) {
            best = Some(mount);
        }
    }
    let Some(best) = best else {
        return candidates;
    };
    let mut relative = maps_path.get(best.mountpoint.len()..).unwrap_or(b"");
    if relative.starts_with(b"/") {
        relative = &relative[1..];
    }
    if relative.is_empty() {
        return candidates;
    }
    let mut paths: Vec<Vec<u8>> = Vec::new();
    if let Some(upper) = &best.upper
        && let Some(joined) = join_layer(upper, relative)
    {
        paths.push(joined);
    }
    for dir in &best.lower {
        if let Some(joined) = join_layer(dir, relative) {
            paths.push(joined);
        }
    }
    let limit = max.min(MAX_LAYER_CANDIDATES);
    for path in paths.into_iter().take(limit) {
        use std::os::unix::ffi::OsStrExt as _;
        // Symlinked layer members are skipped (the range-bound map_files
        // route still verifies them when they are unambiguous); no link
        // chasing, no path authority.
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(std::ffi::OsStr::from_bytes(&path))
        else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        candidates.push(file);
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
            let mut child = Command::new("python3")
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
        let mut sleep = Command::new("sleep").arg("30").spawn().unwrap();
        let dir = File::open(format!("/proc/{}", sleep.id())).unwrap();
        let maps = std::fs::read(format!("/proc/{}/maps", sleep.id())).unwrap();
        let vma = maps
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .filter_map(parse_vma)
            .find(|v| v.ino != 0 && v.executable)
            .unwrap();
        let candidate = File::open("/bin/true").unwrap();
        let range = MappedRange {
            start: vma.start,
            end: vma.start + 1,
        };
        assert_eq!(
            err_of(verify_mapped_backing(&dir, &range, &candidate)),
            BackingError::Denied
        );
        sleep.kill().unwrap();
        sleep.wait().unwrap();
    }

    #[test]
    fn mountinfo_parser_reads_overlay_layers() {
        let info =
            b"27 1 0:24 / / rw - overlay overlay rw,lowerdir=/l1:/l2,upperdir=/u,workdir=/w\n\
            28 1 0:25 / /mnt rw - ext4 /dev/x rw\n\
            bad line\n\
            29 1 0:26 / /mnt/sub rw - overlay overlay rw,lowerdir=/l3\n\
            30 0 0:27 / /sp\\040ace rw - overlay overlay rw,lowerdir=/l\\0404\n";
        let mounts = parse_overlay_layers(info);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[0].mountpoint, b"/");
        assert_eq!(mounts[0].upper, Some(b"/u".to_vec()));
        assert_eq!(mounts[0].lower, vec![b"/l1".to_vec(), b"/l2".to_vec()]);
        assert_eq!(mounts[1].mountpoint, b"/mnt/sub");
        assert_eq!(mounts[1].upper, None);
        assert_eq!(mounts[1].lower, vec![b"/l3".to_vec()]);
        assert_eq!(mounts[2].mountpoint, b"/sp ace");
        assert_eq!(mounts[2].lower, vec![b"/l 4".to_vec()]);
    }

    #[test]
    fn layer_join_rejects_escape_and_relative() {
        assert_eq!(join_layer(b"/l", b"a/b"), Some(b"/l/a/b".to_vec()));
        assert_eq!(join_layer(b"/l/", b"a"), Some(b"/l/a".to_vec()));
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
    #[ignore = "requires externally prepared Btrfs collision paths in OSSL_INVENTORY_BTRFS_FIRST/SECOND + privilege (5E)"]
    fn btrfs_subvolume_cross_candidate_refuses() {
        let paths = ["OSSL_INVENTORY_BTRFS_FIRST", "OSSL_INVENTORY_BTRFS_SECOND"].map(|name| {
            std::path::PathBuf::from(std::env::var_os(name).expect("Btrfs input path required"))
        });
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

    struct MountGuard {
        point: std::path::PathBuf,
        base: std::path::PathBuf,
    }
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg(&self.point).status();
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn mount_overlay() -> (MountGuard, std::path::PathBuf) {
        let base = scratch("overlay");
        for name in ["lower", "upper", "work", "merged"] {
            std::fs::create_dir(base.join(name)).unwrap();
        }
        let status = Command::new("mount")
            .args([
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
            ])
            .arg(base.join("merged"))
            .status()
            .unwrap();
        assert!(status.success(), "overlay mount requires privilege");
        let guard = MountGuard {
            point: base.join("merged"),
            base: base.clone(),
        };
        (guard, base)
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
        for point in [&m1, &m2] {
            let status = Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(point)
                .status()
                .unwrap();
            assert!(status.success(), "tmpfs mount requires privilege");
        }
        struct Cleanup(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("umount").arg(&self.1).status();
                let _ = Command::new("umount").arg(&self.2).status();
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone(), m1.clone(), m2.clone());
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
}
