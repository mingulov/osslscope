// SPDX-License-Identifier: GPL-3.0-or-later
//! Procfs discovery keeps raw mapping text private and never follows a locator
//! as execution evidence. No producer bootstrap or target-memory dependency.

use super::{
    Capabilities, CaptureClock, Gap, GapReason, IdentityStatus, InventoryState, ModuleInfo,
    ModuleRecord, NamespaceId, NamespaceIds, ObjectKind, ObservationState, ProcessRecord, Scope,
    ScopeRecord, Snapshot, SnapshotMode, SnapshotOptions, WorkTotals, backing, elf,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
struct Mapping<'a> {
    start: u64,
    end: u64,
    device: u64,
    inode: u64,
    executable: bool,
    path: &'a [u8],
}
impl Mapping<'_> {
    fn map_name(&self) -> String {
        // Kernel map_files entries use unpadded lowercase hexadecimal.
        format!("{:x}-{:x}", self.start, self.end)
    }
}

fn parse_line(line: &[u8]) -> Result<Mapping<'_>, GapReason> {
    let bad = GapReason::MalformedMaps;
    if line.contains(&0) {
        return Err(bad);
    }
    let mut rest = line;
    let mut token = || {
        rest = rest.trim_ascii_start();
        let end = rest
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(rest.len());
        let value = &rest[..end];
        rest = &rest[end..];
        value
    };
    let range = token();
    let permissions = token();
    let offset = token();
    let device = token();
    let inode = token();
    let path = rest.trim_ascii_start();
    let (start, end) = split_once(range, b'-').ok_or(bad)?;
    let start = number(start, 16).ok_or(bad)?;
    let end = number(end, 16).ok_or(bad)?;
    if start >= end
        || permissions.len() != 4
        || !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
        || number(offset, 16).is_none()
    {
        return Err(bad);
    }
    let (major, minor) = split_once(device, b':').ok_or(bad)?;
    let major = u32::try_from(number(major, 16).ok_or(bad)?).map_err(|_| bad)?;
    let minor = u32::try_from(number(minor, 16).ok_or(bad)?).map_err(|_| bad)?;
    Ok(Mapping {
        start,
        end,
        device: libc::makedev(major, minor),
        inode: number(inode, 10).ok_or(bad)?,
        executable: permissions[2] == b'x',
        path,
    })
}
fn split_once(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let at = bytes.iter().position(|b| *b == separator)?;
    Some((&bytes[..at], &bytes[at + 1..]))
}
fn number(bytes: &[u8], radix: u32) -> Option<u64> {
    // No sign, whitespace, prefix or empty numeric fields.
    if bytes.is_empty() || !bytes.iter().all(|b| (*b as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(bytes).ok()?, radix).ok()
}

struct Process {
    directory: File,
    pidfd: File,
    starttime: u64,
}
impl Process {
    fn open(pid: u32, work: &mut Work<'_>) -> Result<Self, GapReason> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(GapReason::ProcessUnavailable);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(format!("/proc/{pid}"))
            .map_err(|_| GapReason::ProcessUnavailable)?;
        let starttime = starttime(&directory, work)?;
        // SAFETY: pidfd_open receives a positive PID and flags zero. A
        // successful descriptor transfers ownership once to File.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            return Err(GapReason::ProcessUnavailable);
        }
        let process = Self {
            directory,
            pidfd: unsafe { File::from_raw_fd(raw as i32) },
            starttime,
        };
        process.validate(work)?;
        Ok(process)
    }
    fn validate(&self, work: &mut Work<'_>) -> Result<(), GapReason> {
        work.deadline()?;
        self.live()?;
        if starttime(&self.directory, work)? != self.starttime {
            return Err(GapReason::Changed);
        }
        // The stat read itself may race exit. Poll the actual held pidfd again.
        self.live()
    }
    fn live(&self) -> Result<(), GapReason> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, zero timeout; this never signals.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result != 0 || poll.revents != 0 {
            return Err(GapReason::ProcessUnavailable);
        }
        Ok(())
    }
}
pub(super) fn open_at(directory: &File, name: &[u8]) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
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
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn starttime(directory: &File, work: &mut Work<'_>) -> Result<u64, GapReason> {
    let file = open_at(directory, b"stat").map_err(|_| GapReason::ProcessUnavailable)?;
    let bytes = work.read(file, 65_536)?;
    // comm can contain spaces and ')': only the last ')' delimits it.
    let end = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or(GapReason::ProcessUnavailable)?;
    let start = bytes[end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|b| !b.is_empty())
        .nth(19)
        .and_then(|value| number(value, 10))
        .ok_or(GapReason::ProcessUnavailable)?;
    Ok(start)
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
struct Cached {
    _memory: Option<crate::observation_memory::MemoryLease>,
    // Keep the inode alive across reuse; an inode number cannot be recycled
    // underneath this cache simply because a mapped pathname was unlinked.
    file: File,
    info: Result<ModuleInfo, GapReason>,
    seen: bool,
}

/// Cache identity: native fingerprint plus the association's witnessed page
/// (`None` on the direct path). Two layers sharing one rendered identity
/// never share one cache entry.
type CacheKey = (Fingerprint, Option<u64>);

/// Metadata and retained descriptors only; no mapped bytes or history.
#[derive(Default)]
pub(super) struct ScanState {
    pub(super) memory: Option<crate::observation_memory::MemoryPool>,
    pub(super) records_memory: Vec<crate::observation_memory::MemoryLease>,
    cache: BTreeMap<CacheKey, Cached>,
    cursor: Option<u32>,
}
struct Work<'a> {
    records_memory: Vec<crate::observation_memory::MemoryLease>,
    memory: Option<crate::observation_memory::MemoryPool>,
    options: &'a SnapshotOptions,
    include_other: bool,
    started: Instant,
    totals: WorkTotals,
    gaps: BTreeSet<Gap>,
    cache: BTreeMap<CacheKey, Cached>,
    /// Precise limit cause of the most recent backing-budget refusal, if any.
    /// Lets the backing caller report Deadline/ReadLimit instead of a generic
    /// evidence gap. Taken (cleared) by the caller after each backing call.
    backing_limit: Option<GapReason>,
}

/// Inventory half of ER-5E-I2: backing IO and buffers charge the same read
/// totals, shared pool and deadline the procfs reads use.
impl backing::BackingBudget for Work<'_> {
    fn checkpoint(&mut self) -> Result<(), backing::BackingError> {
        self.deadline().map_err(|_| {
            self.backing_limit = Some(GapReason::Deadline);
            backing::BackingError::Unavailable
        })
    }
    fn allow_read(&mut self, want: usize) -> Result<usize, backing::BackingError> {
        let remaining = self.remaining();
        if remaining == 0 {
            self.backing_limit = Some(GapReason::ReadLimit);
            return Err(backing::BackingError::Unavailable);
        }
        Ok(want
            .max(1)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX)))
    }
    fn commit_read(&mut self, bytes: u64) -> Result<(), backing::BackingError> {
        self.totals.read_bytes += bytes;
        Ok(())
    }
    fn reserve_state(
        &mut self,
        bytes: usize,
    ) -> Result<backing::BackingLease, backing::BackingError> {
        match &self.memory {
            Some(pool) => pool
                .reserve(bytes)
                .map(backing::BackingLease::Pool)
                .ok_or_else(|| {
                    self.backing_limit = Some(GapReason::ReadLimit);
                    backing::BackingError::Unavailable
                }),
            None => Ok(backing::BackingLease::Uncharged),
        }
    }
}
struct ReadBuffer {
    bytes: Vec<u8>,
    _memory: Vec<crate::observation_memory::MemoryLease>,
}
impl std::ops::Deref for ReadBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl PartialEq for ReadBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Work<'_> {
    fn reserve_record(&mut self, bytes: usize) -> Result<(), GapReason> {
        if let Some(pool) = &self.memory {
            self.records_memory
                .push(pool.reserve(bytes + 64).ok_or(GapReason::ReadLimit)?);
        }
        Ok(())
    }
    fn deadline(&self) -> Result<(), GapReason> {
        if self.started.elapsed() >= self.options.limits.timeout {
            Err(GapReason::Deadline)
        } else {
            Ok(())
        }
    }
    fn gap(&mut self, pid: Option<u32>, mapping: Option<&Mapping<'_>>, reason: GapReason) {
        if self.reserve_record(256).is_err() {
            self.gaps.insert(Gap {
                pid: None,
                device: None,
                inode: None,
                reason: GapReason::ReadLimit,
            });
            return;
        }
        self.gaps.insert(Gap {
            pid,
            device: mapping.map(|m| m.device),
            inode: mapping.map(|m| m.inode),
            reason,
        });
    }
    fn remaining(&self) -> u64 {
        self.options
            .limits
            .max_read_bytes
            .saturating_sub(self.totals.read_bytes)
    }
    fn read(&mut self, mut file: File, maximum: usize) -> Result<ReadBuffer, GapReason> {
        let mut bytes = Vec::new();
        let mut leases = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            self.deadline()?;
            let remaining = self.remaining();
            if remaining == 0 {
                return Err(GapReason::ReadLimit);
            }
            // Probe one byte beyond the per-file cap, without over-allocation.
            let allowed = maximum.saturating_sub(bytes.len()).saturating_add(1);
            let count = allowed
                .min(chunk.len())
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let read = file
                .read(&mut chunk[..count])
                .map_err(|_| GapReason::Unavailable)?;
            self.totals.read_bytes += read as u64;
            if read == 0 {
                return Ok(ReadBuffer {
                    bytes,
                    _memory: leases,
                });
            }
            if read > maximum.saturating_sub(bytes.len()) {
                return Err(GapReason::ReadLimit);
            }
            if let Some(pool) = &self.memory {
                leases.push(pool.reserve(read * 2 + 64).ok_or(GapReason::ReadLimit)?);
            }
            bytes
                .try_reserve_exact(read)
                .map_err(|_| GapReason::ReadLimit)?;
            bytes.extend_from_slice(&chunk[..read]);
        }
    }
    fn inspect(
        &mut self,
        mut file: File,
        metadata: &Metadata,
        page: Option<u64>,
    ) -> Result<ModuleInfo, GapReason> {
        let fingerprint = Fingerprint::from(metadata);
        if file.metadata().map(|m| Fingerprint::from(&m)).ok().as_ref() != Some(&fingerprint) {
            return Err(GapReason::Changed);
        }
        let key = (fingerprint.clone(), page);
        if let Some(cached) = self.cache.get_mut(&key) {
            cached.seen = true;
            return cached.info.clone();
        }
        self.deadline()?;
        if !metadata.is_file() {
            return Err(GapReason::NonRegular);
        }
        if metadata.len() > self.options.limits.max_module_bytes {
            return Err(GapReason::TooLarge);
        }
        let charge = metadata.len().checked_add(1).ok_or(GapReason::ReadLimit)?;
        if charge > self.remaining() {
            return Err(GapReason::ReadLimit);
        }
        let lease = self
            .memory
            .as_ref()
            .map(|pool| pool.reserve(2048).ok_or(GapReason::ReadLimit))
            .transpose()?;
        // Shared capacity is transient, not a property of this fingerprint.
        // Refuse before charging IO or memoizing a parser result. Keep this
        // lease through parsing; only structural parser errors reach the cache.
        let _scratch = self
            .memory
            .as_ref()
            .map(|pool| {
                pool.reserve(elf::parser_scratch_bytes(metadata.len())?)
                    .ok_or(GapReason::ReadLimit)
            })
            .transpose()?;
        self.totals.read_bytes += charge;
        self.totals.objects_inspected += 1;
        // The external lease covers this parser; metadata.len() still bounds
        // growth between admission and its independent descriptor checks.
        let result = elf::inspect_file(&mut file, metadata.len());
        self.deadline()?;
        if file.metadata().map(|m| Fingerprint::from(&m)).ok().as_ref() != Some(&fingerprint) {
            return Err(GapReason::Changed);
        }
        // Current-snapshot attempts are capped by max_objects. Prefer dropping
        // an unseen retained entry before admitting a newly observed object.
        if self.cache.len() >= self.options.limits.max_objects {
            let victim = self
                .cache
                .iter()
                .find(|(_, value)| !value.seen)
                .map(|(key, _)| key.clone());
            if let Some(victim) = victim {
                self.cache.remove(&victim);
            }
        }
        self.cache.insert(
            key,
            Cached {
                _memory: lease,
                file,
                info: result.clone(),
                seen: true,
            },
        );
        result
    }
}

pub(super) fn filesystem(file: &File) -> Option<libc::c_long> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes stat on success and borrows an open FD.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0 {
        Some(unsafe { stat.assume_init() }.f_type)
    } else {
        None
    }
}
fn direct_filesystem(file: &File) -> bool {
    // A map_files open binds ordinary VMA backing, but stackable resolution
    // can yield an upper inode instead of the mapped lower. Unknown filesystem
    // semantics remain conservative candidates; this is not an attach gate.
    matches!(
        filesystem(file),
        Some(
            0xef53 | // ext family
        0x58465342 | // XFS
        0x9123683e | // Btrfs (st_dev may differ from the maps superblock device)
        0x01021994 | // tmpfs
        0x858458f6 | // ramfs
        0x958458f6 | // hugetlbfs
        0x73717368 | // squashfs
        0xf2f52010 | // f2fs
        0x3153464a | // jfs
        0x2fc12fc1 // zfs
        )
    )
}
/// Test-only rendezvous for ER-5E-I3 (no production behavior): after a
/// candidate verifies and before its metadata is re-read, the witness
/// reports the verified descriptor's identity and waits for release. The
/// barrier test uses this to land a copy-up deterministically inside the
/// verify→parse window. A dropped test side releases the wait; failures are
/// ignored so a broken rendezvous fails the test's window assertions loudly
/// instead of hanging the snapshot.
#[cfg(test)]
struct VerifyParseRendezvous {
    observed: std::sync::mpsc::Sender<(u64, u64)>,
    proceed: std::sync::mpsc::Receiver<()>,
}
#[cfg(test)]
static VERIFY_PARSE_HOOK: std::sync::Mutex<Option<VerifyParseRendezvous>> =
    std::sync::Mutex::new(None);

fn backing(
    view: Option<&backing::BackingProcess>,
    process: &Process,
    mapping: &Mapping<'_>,
    work: &mut Work<'_>,
) -> Result<
    (
        File,
        Metadata,
        IdentityStatus,
        Option<u64>,
        Option<backing::BackingAssociation>,
    ),
    GapReason,
> {
    // Acquisition failures must remain distinct from a successfully acquired
    // LocatorCandidate: failure leaves mapping visibility unresolved and can
    // never support a sampled absence claim in watch.
    let name = format!("map_files/{}", mapping.map_name());
    let mut ordered: Vec<File> = Vec::new();
    let mut have_direct = false;
    if let Ok(file) = open_at(&process.directory, name.as_bytes()) {
        ordered.push(file);
        have_direct = true;
    }
    // Common verification first: the range-bound descriptor, then direct
    // layer resolutions. The first verified candidate wins and its
    // descriptor is retained through parsing. Layer discovery and
    // verification charge the inventory budget; a budget refusal reports
    // its precise limit gap instead of falling through to weaker proof.
    if let Some(view) = view {
        let range = backing::MappedRange {
            start: mapping.start,
            end: mapping.end,
        };
        ordered.extend(backing::direct_layer_candidates_charged(
            &process.directory,
            mapping.path,
            16,
            work,
        ));
        for index in 0..ordered.len() {
            match view.verify_with_process_charged(&range, &ordered[index], work) {
                Ok(association) => {
                    #[cfg(test)]
                    if let Ok(guard) = VERIFY_PARSE_HOOK.lock()
                        && let Some(hook) = guard.as_ref()
                        && let Ok(verified) = ordered[index].metadata()
                    {
                        let _ = hook.observed.send((verified.dev(), verified.ino()));
                        let _ = hook.proceed.recv();
                    }
                    let page = association.witness_page();
                    let file = ordered.remove(index);
                    let metadata = file.metadata().map_err(|_| GapReason::BackingUnavailable)?;
                    return Ok((
                        file,
                        metadata,
                        IdentityStatus::Verified,
                        page,
                        Some(association),
                    ));
                }
                Err(_) => {
                    if let Some(limit) = work.backing_limit.take() {
                        return Err(limit);
                    }
                }
            }
        }
    }
    // Legacy fallback: no verified candidate. A mapping-bound descriptor on
    // a nonstackable filesystem keeps its previous status (reachable only
    // without a process view, or when verification itself was unavailable).
    if have_direct {
        let file = ordered.remove(0);
        let metadata = file.metadata().map_err(|_| GapReason::BackingUnavailable)?;
        if direct_filesystem(&file)
            && metadata.ino() == mapping.inode
            && (metadata.dev() == mapping.device || filesystem(&file) == Some(0x9123683e))
        {
            return Ok((file, metadata, IdentityStatus::Verified, None, None));
        }
        // A locator may still be useful on overlay, but not after obvious
        // replacement by an inode different from the mapping's inode.
        if metadata.ino() == mapping.inode {
            return Ok((file, metadata, IdentityStatus::LocatorCandidate, None, None));
        }
        return Err(GapReason::BackingUnavailable);
    }
    // Namespace-relative locator fallback never establishes mapping identity.
    // Do not strip the kernel's deleted suffix into a replacement pathname.
    if !mapping.path.starts_with(b"/") || mapping.path.ends_with(b" (deleted)") {
        return Err(GapReason::BackingUnavailable);
    }
    let mut name = b"root".to_vec();
    name.extend_from_slice(mapping.path);
    let file = open_at(&process.directory, &name).map_err(|_| GapReason::BackingUnavailable)?;
    let metadata = file.metadata().map_err(|_| GapReason::BackingUnavailable)?;
    if metadata.ino() != mapping.inode
        || (metadata.dev() != mapping.device && filesystem(&file) != Some(0x9123683e))
    {
        return Err(GapReason::BackingUnavailable);
    }
    Ok((file, metadata, IdentityStatus::LocatorCandidate, None, None))
}

fn process(pid: u32, work: &mut Work<'_>) -> Result<ProcessRecord, GapReason> {
    let clock = CaptureClock::start();
    work.reserve_record(1024)?;
    let process = Process::open(pid, work)?;
    let namespace = |name: &[u8]| {
        open_at(&process.directory, name).ok().and_then(|f| {
            f.metadata().ok().map(|m| {
                (
                    f,
                    NamespaceId {
                        device: m.dev(),
                        inode: m.ino(),
                    },
                )
            })
        })
    };
    let pid_ns = namespace(b"ns/pid");
    let mount_ns = namespace(b"ns/mnt");
    if pid_ns.is_none() || mount_ns.is_none() {
        work.gap(Some(pid), None, GapReason::NamespaceUnavailable);
    }
    let maps_file =
        open_at(&process.directory, b"maps").map_err(|_| GapReason::ProcessUnavailable)?;
    let maps = work.read(maps_file, work.options.limits.max_maps_bytes)?;
    // One backing view per process; without it every mapping keeps its
    // previous legacy status (never a new failure). A budget refusal here
    // degrades the same approved way an unreadable view does; the charges
    // below re-derive the precise limit gap honestly.
    let view = backing::BackingProcess::capture_charged(&process.directory, work).ok();
    work.backing_limit.take();
    let mut modules = Vec::new();
    let mut verified = BTreeSet::new();
    let mut attempts = 0;
    for line in maps.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        if let Err(reason) = work.deadline() {
            work.gap(Some(pid), None, reason);
            break;
        }
        let mapping = match parse_line(line) {
            Ok(mapping) => mapping,
            Err(reason) => {
                work.gap(Some(pid), None, reason);
                continue;
            }
        };
        if mapping.inode == 0 || !mapping.executable {
            continue;
        }
        if attempts >= work.options.limits.max_objects_per_process
            || work.totals.objects_attempted >= work.options.limits.max_objects
        {
            work.gap(Some(pid), None, GapReason::ObjectLimit);
            break;
        }
        // Bound mapping/open attempts even when locators collide or fail.
        attempts += 1;
        work.totals.objects_attempted += 1;
        let (file, metadata, identity_status, page, association) =
            match backing(view.as_ref(), &process, &mapping, work) {
                Ok(bound) => bound,
                Err(reason) => {
                    work.gap(Some(pid), Some(&mapping), reason);
                    continue;
                }
            };
        if identity_status == IdentityStatus::LocatorCandidate {
            work.gap(Some(pid), Some(&mapping), GapReason::IdentityUnverified);
        }
        let fingerprint = Fingerprint::from(&metadata);
        let key = (fingerprint.clone(), page);
        // A maps superblock device/inode pair is not unique across Btrfs
        // subvolumes, and one rendered overlay identity can hide two layers.
        // Only verified associations may share a retained cache key.
        // Uncertain locators remain separate records.
        if identity_status == IdentityStatus::Verified && verified.contains(&key) {
            continue;
        }
        // Charge metadata, vector growth and temporary fingerprint/set copies
        // before cloning cached or newly inspected module metadata.
        work.reserve_record(2048)?;
        let mut status = identity_status;
        match work.inspect(file, &metadata, page) {
            Ok(info) => {
                if work.include_other || info.kind != ObjectKind::Other {
                    // ER-5E-I3: the association is retained through parsing
                    // and re-proven before publication — for fresh parses
                    // and cache hits alike, since both return here. The
                    // parsed bytes come from the retained verifying
                    // descriptor, and this revalidation brackets the parse:
                    // a copy-up (or any backing change) inside the
                    // verify→parse window downgrades to a locator
                    // candidate instead of publishing post-window bytes
                    // as Verified.
                    if status == IdentityStatus::Verified {
                        if let Some(association) = &association {
                            if association.revalidate_charged(work).is_err() {
                                status = IdentityStatus::LocatorCandidate;
                                let cause = work
                                    .backing_limit
                                    .take()
                                    .unwrap_or(GapReason::IdentityUnverified);
                                work.gap(Some(pid), Some(&mapping), cause);
                            }
                        }
                    }
                    modules.push((
                        ModuleRecord {
                            info,
                            identity_status: status,
                        },
                        key.clone(),
                    ));
                }
            }
            Err(GapReason::NotElf) => {}
            Err(reason) => work.gap(Some(pid), Some(&mapping), reason),
        }
        // The cache holds the descriptor alive; failed admission alone is
        // not retained identity evidence and must not suppress another VMA.
        if status == IdentityStatus::Verified && work.cache.contains_key(&key) {
            verified.insert(key);
        }
    }
    // Recheck maps, the held proc directory's incarnation, and the actual
    // pidfd before accepting any process. IO churn cannot become completeness.
    let again = open_at(&process.directory, b"maps")
        .map_err(|_| GapReason::ProcessUnavailable)
        .and_then(|file| work.read(file, work.options.limits.max_maps_bytes));
    match again {
        Ok(again) if again == maps => {}
        Ok(_) => {
            work.gap(Some(pid), None, GapReason::Changed);
            for (module, _) in &mut modules {
                module.identity_status = IdentityStatus::LocatorCandidate;
            }
        }
        Err(reason) => {
            work.gap(Some(pid), None, reason);
            for (module, _) in &mut modules {
                module.identity_status = IdentityStatus::LocatorCandidate;
            }
        }
    }
    modules.retain(|(module, key)| {
        let unchanged = work
            .cache
            .get(key)
            .and_then(|cached| cached.file.metadata().ok())
            .is_some_and(|metadata| Fingerprint::from(&metadata) == key.0);
        if !unchanged {
            work.gaps.insert(Gap {
                pid: Some(pid),
                device: Some(module.info.device),
                inode: Some(module.info.inode),
                reason: GapReason::Changed,
            });
        }
        unchanged
    });
    process.validate(work)?;
    modules
        .sort_by(|a, b| (a.0.info.device, a.0.info.inode).cmp(&(b.0.info.device, b.0.info.inode)));
    let mut namespaces = NamespaceIds {
        pid: pid_ns.as_ref().map(|(_, id)| *id),
        mount: mount_ns.as_ref().map(|(_, id)| *id),
    };
    for (name, identity) in [
        (b"ns/pid".as_slice(), &mut namespaces.pid),
        (b"ns/mnt".as_slice(), &mut namespaces.mount),
    ] {
        if namespace(name).map(|(_, id)| id) != *identity {
            *identity = None;
            work.gap(Some(pid), None, GapReason::NamespaceUnavailable);
        }
    }
    Ok(ProcessRecord {
        interval: clock.finish(),
        namespaces,
        pid,
        starttime: process.starttime,
        modules: modules.into_iter().map(|(module, _)| module).collect(),
        provider_activation: ObservationState::Unknown,
        provider_interfaces: ObservationState::Unknown,
        execution: ObservationState::NotObserved,
    })
}

pub(super) fn snapshot(options: &SnapshotOptions) -> Snapshot {
    snapshot_selected(options, options.pids.is_empty())
}
/// The explicit mode preserves an empty resolved selection as empty.
pub(super) fn snapshot_selected(options: &SnapshotOptions, system: bool) -> Snapshot {
    snapshot_scoped(options, system, false)
}
pub(super) fn snapshot_scoped(
    options: &SnapshotOptions,
    system: bool,
    include_other: bool,
) -> Snapshot {
    snapshot_reused(options, system, include_other, &mut ScanState::default())
}

pub(super) fn snapshot_reused(
    options: &SnapshotOptions,
    system: bool,
    include_other: bool,
    state: &mut ScanState,
) -> Snapshot {
    state.records_memory.clear();
    let clock = CaptureClock::start();
    let started = Instant::now();
    let mut cache = std::mem::take(&mut state.cache);
    cache.retain(|key, value| {
        value.seen = false;
        started.elapsed() < options.limits.timeout
            && value
                .file
                .metadata()
                .is_ok_and(|m| Fingerprint::from(&m) == key.0)
    });
    while cache.len() > options.limits.max_objects {
        cache.pop_first();
    }
    let mut work = Work {
        records_memory: Vec::new(),
        memory: state.memory.clone(),
        include_other,
        options,
        started,
        totals: WorkTotals::default(),
        gaps: BTreeSet::new(),
        cache,
        backing_limit: None,
    };
    // Keep at most two bounded prefixes while enumerating: the next PIDs
    // above the previous cursor, then wrap. Enumerating itself is deadline
    // bounded, so reaching an admission cap never permanently hides high PIDs.
    let pid_memory = work.reserve_record(options.limits.max_pids.saturating_mul(160));
    let mut above = BTreeSet::new();
    let mut wrapped = BTreeSet::new();
    let mut overflow = false;
    let mut admit = |pid, work: &mut Work<'_>| {
        if let Err(reason) = pid_memory {
            work.gap(None, None, reason);
            return false;
        }
        if let Err(reason) = work.deadline() {
            work.gap(None, None, reason);
            return false;
        }
        let set = if state.cursor.is_none_or(|cursor| pid > cursor) {
            &mut above
        } else {
            &mut wrapped
        };
        set.insert(pid);
        if set.len() > options.limits.max_pids {
            set.pop_last();
            overflow = true;
        }
        true
    };
    if system {
        match fs::read_dir("/proc") {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(_) => {
                            work.gap(None, None, GapReason::ProcessUnavailable);
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    let Some(pid) = number(OsStr::new(&name).as_bytes(), 10)
                        .and_then(|n| u32::try_from(n).ok())
                    else {
                        continue;
                    };
                    if !admit(pid, &mut work) {
                        break;
                    }
                }
            }
            Err(_) => work.gap(None, None, GapReason::ProcessUnavailable),
        }
    } else {
        for &pid in &options.pids {
            if !admit(pid, &mut work) {
                break;
            }
        }
    }
    if overflow || above.len().saturating_add(wrapped.len()) > options.limits.max_pids {
        work.gap(None, None, GapReason::ProcessLimit);
    }
    let order: Vec<_> = above
        .into_iter()
        .chain(wrapped)
        .take(options.limits.max_pids)
        .collect();
    let mut selected_pids = order.clone();
    selected_pids.sort_unstable();
    let processes = sample_order(&order, &mut work, state);
    work.cache.retain(|key, value| {
        value.seen
            && value
                .file
                .metadata()
                .is_ok_and(|m| Fingerprint::from(&m) == key.0)
    });
    state.cache = std::mem::take(&mut work.cache);
    state.records_memory = std::mem::take(&mut work.records_memory);
    let inventory = if work.gaps.is_empty() {
        InventoryState::Complete
    } else if processes.is_empty() {
        InventoryState::Unavailable
    } else {
        InventoryState::Partial
    };
    Snapshot {
        interval: clock.finish(),
        scope_record: ScopeRecord::default(),
        schema_version: "osslscope.discovery.v1".to_owned(),
        mode: SnapshotMode::Snapshot,
        scope: if system { Scope::System } else { Scope::Pids },
        selected_pids,
        processes,
        gaps: work.gaps.into_iter().collect(),
        totals: work.totals,
        limits: options.limits.clone(),
        capabilities: Capabilities {
            inventory,
            provider_activation: ObservationState::Unknown,
            provider_interfaces: ObservationState::Unknown,
            execution: ObservationState::NotObserved,
        },
    }
}

fn sample_order(order: &[u32], work: &mut Work<'_>, state: &mut ScanState) -> Vec<ProcessRecord> {
    let mut processes = Vec::new();
    for &pid in order {
        if let Err(reason) = work.deadline() {
            // Every remaining admitted PID is unsampled. A PID-specific gap
            // would let watch mistake the others for successful absences.
            work.gap(None, None, reason);
            break;
        }
        state.cursor = Some(pid);
        work.totals.processes_attempted += 1;
        match process(pid, work) {
            Ok(process) => processes.push(process),
            Err(reason) => work.gap(Some(pid), None, reason),
        }
        if work.totals.objects_attempted >= work.options.limits.max_objects || work.remaining() == 0
        {
            // The next poll resumes at a different process, even when this
            // process consumed the entire snapshot allowance.
            if order.last() != Some(&pid) {
                work.gap(
                    None,
                    None,
                    if work.remaining() == 0 {
                        GapReason::ReadLimit
                    } else {
                        GapReason::ObjectLimit
                    },
                );
            }
            break;
        }
    }
    processes.sort_by_key(|p| p.pid);
    processes
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches deadline uncertainty applying only to the first skipped PID.
    #[test]
    fn expired_admitted_population_has_uncertainty_for_every_skipped_pid() {
        let options = SnapshotOptions {
            pids: vec![7, 11, 13],
            limits: super::super::Limits {
                timeout: std::time::Duration::ZERO,
                ..Default::default()
            },
        };
        let mut work = Work {
            records_memory: Vec::new(),
            memory: None,
            options: &options,
            include_other: false,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
            backing_limit: None,
        };
        let mut state = ScanState::default();
        assert!(sample_order(&options.pids, &mut work, &mut state).is_empty());
        assert_eq!(work.totals.processes_attempted, 0);
        assert_eq!(state.cursor, None);
        for &pid in &options.pids {
            assert!(
                work.gaps.iter().any(|gap| {
                    gap.reason == GapReason::Deadline && (gap.pid.is_none() || gap.pid == Some(pid))
                }),
                "skipped PID {pid} has no applicable deadline uncertainty: {:?}",
                work.gaps
            );
        }
    }

    // Catches accepting truncated/overflowing/non-file mappings as identities.
    #[test]
    fn malformed_maps_are_finite_errors() {
        for line in [
            b"garbage".as_slice(),
            b"1-2 r--p 0 00:01 nope /secret",
            b"2-1 r--p 0 00:01 1 /secret",
            b"1-2 r--p 0 00:100000000 1 /secret",
            b"1-2 r--p 0 00:01 1\0 /secret",
            b"10000000000000000-2 r--p 0 00:01 1 /secret",
        ] {
            assert_eq!(parse_line(line), Err(GapReason::MalformedMaps));
        }
        let parsed = parse_line(b"0000000a-000000bc r--p 0 00:01 42 /secret name").unwrap();
        assert_eq!(parsed.map_name(), "a-bc");
        assert_eq!(parsed.inode, 42);
    }

    #[test]
    fn pooled_refusal_does_not_count_unperformed_inspections() {
        let options = SnapshotOptions::default();
        let pool = crate::observation_memory::MemoryPool::new(64 << 20);
        let metadata = std::fs::metadata("/bin/true").unwrap();
        let free = elf::parser_scratch_bytes(metadata.len()).unwrap() + 2048 - 1;
        let busy = pool.reserve((64 << 20) - free).unwrap();
        let mut work = Work {
            records_memory: Vec::new(),
            memory: Some(pool),
            options: &options,
            include_other: false,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
            backing_limit: None,
        };
        for _ in 0..3 {
            assert_eq!(
                work.inspect(File::open("/bin/true").unwrap(), &metadata, None),
                Err(GapReason::ReadLimit)
            );
            assert_eq!(work.totals.read_bytes, 0);
            assert_eq!(work.totals.objects_inspected, 0);
            assert!(work.cache.is_empty());
        }
        drop(busy);
        work.inspect(File::open("/bin/true").unwrap(), &metadata, None)
            .unwrap();
        assert_eq!(work.totals.read_bytes, metadata.len() + 1);
        assert_eq!(work.totals.objects_inspected, 1);
        work.inspect(File::open("/bin/true").unwrap(), &metadata, None)
            .unwrap();
        assert_eq!(work.totals.read_bytes, metadata.len() + 1);
    }

    // Catches reading or reusing cached bytes after stale metadata admission.
    #[test]
    fn changed_descriptor_is_rejected_before_read_admission_or_cache_reuse() {
        use std::io::Write as _;
        let path = std::env::temp_dir().join(format!("osslscope-admission-{}", std::process::id()));
        let mut writer = File::create(&path).unwrap();
        writer.write_all(b"not ELF").unwrap();
        let metadata = writer.metadata().unwrap();
        let options = SnapshotOptions::default();
        let mut work = Work {
            records_memory: Vec::new(),
            memory: None,
            options: &options,
            include_other: false,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
            backing_limit: None,
        };
        assert_eq!(
            work.inspect(File::open(&path).unwrap(), &metadata, None),
            Err(GapReason::NotElf)
        );
        writer.write_all(b"grown").unwrap();
        assert_eq!(
            work.inspect(File::open(&path).unwrap(), &metadata, None),
            Err(GapReason::Changed)
        );
        let mut fresh = Work {
            records_memory: Vec::new(),
            memory: None,
            options: &options,
            include_other: false,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
            backing_limit: None,
        };
        assert_eq!(
            fresh.inspect(File::open(&path).unwrap(), &metadata, None),
            Err(GapReason::Changed)
        );
        assert_eq!(fresh.totals.read_bytes, 0);
        assert_eq!(fresh.totals.objects_inspected, 0);
        fs::remove_file(path).unwrap();
    }

    struct I3Overlay {
        base: std::path::PathBuf,
        merged: std::path::PathBuf,
    }
    impl I3Overlay {
        fn mount(scratch: &std::path::Path) -> Self {
            let base = scratch.join("overlay");
            for name in ["lower", "upper", "work", "merged"] {
                fs::create_dir_all(base.join(name)).unwrap();
            }
            let status = std::process::Command::new("mount")
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
            Self {
                merged: base.join("merged"),
                base,
            }
        }
    }
    impl Drop for I3Overlay {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount")
                .arg(&self.merged)
                .status();
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    fn i3_build_so(dir: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
        let src = dir.join(format!("{name}.c"));
        let out = dir.join(name);
        fs::write(&src, source).unwrap();
        let result = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-Wl,--build-id=none", "-o"])
            .arg(&out)
            .arg(src)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        out
    }
    struct I3Child(std::process::Child);
    impl I3Child {
        fn spawn(scratch: &std::path::Path, paths: &[std::path::PathBuf]) -> Self {
            use std::io::BufRead as _;
            let executable = scratch.join("mmap-child");
            if !executable.exists() {
                let src = scratch.join("mmap-child.c");
                fs::write(
                    &src,
                    r#"
                    #include <sys/mman.h>
                    #include <sys/stat.h>
                    #include <fcntl.h>
                    #include <stdio.h>
                    #include <unistd.h>
                    int main(int argc, char **argv) {
                        for (int i = 1; i < argc; ++i) {
                            int fd = open(argv[i], O_RDONLY); struct stat st;
                            if (fd < 0 || fstat(fd, &st)) return 2;
                            void *at = mmap(0, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
                            if (at == MAP_FAILED) return 3;
                            { volatile char touch = ((char *)at)[0]; (void)touch; }
                            close(fd);
                        }
                        puts("ready"); fflush(stdout);
                        while (getchar() != EOF) {}
                        return 0;
                    }
                "#,
                )
                .unwrap();
                let result = std::process::Command::new("cc")
                    .args(["-o"])
                    .arg(&executable)
                    .arg(src)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            let mut child = std::process::Command::new(&executable)
                .args(paths)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line, "ready\n");
            Self(child)
        }
        fn pid(&self) -> u32 {
            self.0.id()
        }
    }
    impl Drop for I3Child {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            assert!(self.0.wait().unwrap().success());
        }
    }
    struct I3HookGuard;
    impl Drop for I3HookGuard {
        fn drop(&mut self) {
            *VERIFY_PARSE_HOOK.lock().unwrap() = None;
        }
    }

    // Catches publishing post-copy-up bytes as Verified for a pre-copy-up
    // mapping (ER-5E-I3). A rendezvous lands a different-bytes copy-up
    // deterministically inside the verify→parse window — no sleeps: the
    // snapshot reports each verification and waits; this thread copies up
    // exactly when the overlay mapping verifies, then releases. RED
    // publishes the upper hash as Verified; GREEN revalidates before
    // publication and downgrades to a locator candidate.
    #[test]
    #[ignore = "requires privileged overlay mount + map_files/pagemap (5E-I3)"]
    fn copyup_between_verify_and_parse_downgrades_to_candidate() {
        use sha2::Digest as _;
        use std::os::unix::fs::{FileExt as _, MetadataExt as _};
        let scratch = std::env::temp_dir().join(format!(
            "osslscope-i3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&scratch).unwrap();
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _scratch = Scratch(scratch.clone());
        let overlay = I3Overlay::mount(&scratch);
        let lower = i3_build_so(
            &overlay.base.join("lower"),
            "PRIVATE_CANARY_i3",
            "int OSSL_provider_init(void) { return 11; }",
        );
        let upper_src = i3_build_so(
            &scratch,
            "PRIVATE_CANARY_i3_upper",
            "int OSSL_provider_init(void) { return 99; } int EVP_MD_fetch(void) { return 42; }",
        );
        let upper_bytes = fs::read(&upper_src).unwrap();
        let merged = overlay.merged.join("PRIVATE_CANARY_i3");
        let child = I3Child::spawn(&scratch, &[merged.clone()]);
        let merged_meta = fs::metadata(&merged).unwrap();
        let merged_id = (merged_meta.dev(), merged_meta.ino());
        let lower_hash: String = sha2::Sha256::digest(fs::read(&lower).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let upper_hash: String = sha2::Sha256::digest(&upper_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(lower_hash, upper_hash, "copy-up must change bytes");
        let (observed_tx, observed) = std::sync::mpsc::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        *VERIFY_PARSE_HOOK.lock().unwrap() = Some(VerifyParseRendezvous {
            observed: observed_tx,
            proceed: proceed_rx,
        });
        let _hook_guard = I3HookGuard;
        let pid = child.pid();
        let mut copied_up = false;
        let result = std::thread::scope(|scope| {
            let snapshot = scope.spawn(|| {
                let result = snapshot(&SnapshotOptions {
                    pids: vec![pid],
                    ..Default::default()
                });
                // Release the rendezvous consumer: no more events can arrive.
                *VERIFY_PARSE_HOOK.lock().unwrap() = None;
                result
            });
            for (dev, ino) in &observed {
                if (dev, ino) == merged_id && !copied_up {
                    let writer = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&merged)
                        .unwrap();
                    writer.write_all_at(&upper_bytes, 0).unwrap();
                    writer.sync_all().unwrap();
                    assert!(
                        overlay
                            .base
                            .join("upper/PRIVATE_CANARY_i3")
                            .metadata()
                            .is_ok(),
                        "copy-up proof: upper file must exist"
                    );
                    copied_up = true;
                }
                if proceed_tx.send(()).is_err() {
                    break;
                }
            }
            snapshot.join().unwrap()
        });
        assert!(copied_up, "the copy-up never landed in the window");
        let process = result
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .expect("child must be inventoried");
        // The parse read post-copy-up bytes through the retained FD; those
        // bytes must never publish as Verified for the old lower mapping.
        assert!(
            process.modules.iter().all(|m| {
                m.info.sha256 != upper_hash || m.identity_status != IdentityStatus::Verified
            }),
            "upper bytes published as Verified: {result:?}"
        );
        let upper = process
            .modules
            .iter()
            .find(|m| m.info.sha256 == upper_hash)
            .expect("parse must have read post-copy-up bytes");
        assert_eq!(
            upper.identity_status,
            IdentityStatus::LocatorCandidate,
            "post-window bytes must downgrade: {result:?}"
        );
        assert!(
            result
                .gaps
                .iter()
                .any(|gap| gap.reason == GapReason::IdentityUnverified),
            "downgrade must record unverified identity: {result:?}"
        );
    }
}
