// SPDX-License-Identifier: GPL-3.0-or-later
//! Procfs discovery keeps raw mapping text private and never follows a locator
//! as execution evidence. No producer bootstrap or target-memory dependency.

use super::{
    Capabilities, Gap, GapReason, IdentityStatus, InventoryState, ModuleInfo, ModuleRecord,
    ObjectKind, ObservationState, ProcessRecord, Scope, Snapshot, SnapshotMode, SnapshotOptions,
    WorkTotals, elf,
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
fn open_at(directory: &File, name: &[u8]) -> io::Result<File> {
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
    // Keep the inode alive across reuse; an inode number cannot be recycled
    // underneath this cache simply because a mapped pathname was unlinked.
    file: File,
    info: Result<ModuleInfo, GapReason>,
}
struct Work<'a> {
    options: &'a SnapshotOptions,
    started: Instant,
    totals: WorkTotals,
    gaps: BTreeSet<Gap>,
    cache: BTreeMap<Fingerprint, Cached>,
}
impl Work<'_> {
    fn deadline(&self) -> Result<(), GapReason> {
        if self.started.elapsed() >= self.options.limits.timeout {
            Err(GapReason::Deadline)
        } else {
            Ok(())
        }
    }
    fn gap(&mut self, pid: Option<u32>, mapping: Option<&Mapping<'_>>, reason: GapReason) {
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
    fn read(&mut self, mut file: File, maximum: usize) -> Result<Vec<u8>, GapReason> {
        let mut bytes = Vec::new();
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
                return Ok(bytes);
            }
            if read > maximum.saturating_sub(bytes.len()) {
                return Err(GapReason::ReadLimit);
            }
            bytes.try_reserve(read).map_err(|_| GapReason::ReadLimit)?;
            bytes.extend_from_slice(&chunk[..read]);
        }
    }
    fn inspect(&mut self, mut file: File, metadata: &Metadata) -> Result<ModuleInfo, GapReason> {
        let fingerprint = Fingerprint::from(metadata);
        if file.metadata().map(|m| Fingerprint::from(&m)).ok().as_ref() != Some(&fingerprint) {
            return Err(GapReason::Changed);
        }
        if let Some(cached) = self.cache.get(&fingerprint) {
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
        self.totals.read_bytes += charge;
        self.totals.objects_inspected += 1;
        // An object growing between our admission and the ELF inspector's
        // fstat must never read beyond the aggregate work already charged.
        let result = elf::inspect_file(&mut file, metadata.len());
        self.deadline()?;
        if file.metadata().map(|m| Fingerprint::from(&m)).ok().as_ref() != Some(&fingerprint) {
            return Err(GapReason::Changed);
        }
        self.cache.insert(
            fingerprint,
            Cached {
                file,
                info: result.clone(),
            },
        );
        result
    }
}

fn filesystem(file: &File) -> Option<libc::c_long> {
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
fn backing(
    process: &Process,
    mapping: &Mapping<'_>,
) -> Result<(File, Metadata, IdentityStatus), GapReason> {
    let name = format!("map_files/{}", mapping.map_name());
    if let Ok(file) = open_at(&process.directory, name.as_bytes()) {
        let metadata = file.metadata().map_err(|_| GapReason::Unavailable)?;
        // A mapping-bound descriptor on a nonstackable filesystem is the
        // association proof, including Btrfs' distinct anonymous st_dev.
        if direct_filesystem(&file)
            && metadata.ino() == mapping.inode
            && (metadata.dev() == mapping.device || filesystem(&file) == Some(0x9123683e))
        {
            return Ok((file, metadata, IdentityStatus::Verified));
        }
        // A locator may still be useful on overlay, but not after obvious
        // replacement by an inode different from the mapping's inode.
        if metadata.ino() == mapping.inode {
            return Ok((file, metadata, IdentityStatus::LocatorCandidate));
        }
        return Err(GapReason::IdentityUnverified);
    }
    // Namespace-relative locator fallback never establishes mapping identity.
    // Do not strip the kernel's deleted suffix into a replacement pathname.
    if !mapping.path.starts_with(b"/") || mapping.path.ends_with(b" (deleted)") {
        return Err(GapReason::IdentityUnverified);
    }
    let mut name = b"root".to_vec();
    name.extend_from_slice(mapping.path);
    let file = open_at(&process.directory, &name).map_err(|_| GapReason::IdentityUnverified)?;
    let metadata = file.metadata().map_err(|_| GapReason::IdentityUnverified)?;
    if metadata.ino() != mapping.inode
        || (metadata.dev() != mapping.device && filesystem(&file) != Some(0x9123683e))
    {
        return Err(GapReason::IdentityUnverified);
    }
    Ok((file, metadata, IdentityStatus::LocatorCandidate))
}

fn process(pid: u32, work: &mut Work<'_>) -> Result<ProcessRecord, GapReason> {
    let process = Process::open(pid, work)?;
    let maps_file =
        open_at(&process.directory, b"maps").map_err(|_| GapReason::ProcessUnavailable)?;
    let maps = work.read(maps_file, work.options.limits.max_maps_bytes)?;
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
        let (file, metadata, identity_status) = match backing(&process, &mapping) {
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
        // A maps superblock device/inode pair is not unique across Btrfs
        // subvolumes. Only verified associations may share a retained native
        // backing fingerprint. Uncertain locators remain separate records.
        if identity_status == IdentityStatus::Verified && verified.contains(&fingerprint) {
            continue;
        }
        match work.inspect(file, &metadata) {
            Ok(info) if info.kind != ObjectKind::Other => modules.push((
                ModuleRecord {
                    info,
                    identity_status,
                },
                fingerprint.clone(),
            )),
            Ok(_) | Err(GapReason::NotElf) => {}
            Err(reason) => work.gap(Some(pid), Some(&mapping), reason),
        }
        // The cache holds the descriptor alive; failed admission alone is
        // not retained identity evidence and must not suppress another VMA.
        if identity_status == IdentityStatus::Verified && work.cache.contains_key(&fingerprint) {
            verified.insert(fingerprint);
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
    modules.retain(|(module, fingerprint)| {
        let unchanged = work
            .cache
            .get(fingerprint)
            .and_then(|cached| cached.file.metadata().ok())
            .is_some_and(|metadata| Fingerprint::from(&metadata) == *fingerprint);
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
    Ok(ProcessRecord {
        pid,
        starttime: process.starttime,
        modules: modules.into_iter().map(|(module, _)| module).collect(),
        provider_activation: ObservationState::Unknown,
        provider_interfaces: ObservationState::Unknown,
        execution: ObservationState::NotObserved,
    })
}

pub(super) fn snapshot(options: &SnapshotOptions) -> Snapshot {
    let mut work = Work {
        options,
        started: Instant::now(),
        totals: WorkTotals::default(),
        gaps: BTreeSet::new(),
        cache: BTreeMap::new(),
    };
    let system = options.pids.is_empty();
    let mut pids = BTreeSet::new();
    let mut admit = |pid, work: &mut Work<'_>| {
        if let Err(reason) = work.deadline() {
            work.gap(None, None, reason);
            return false;
        }
        if pids.contains(&pid) {
            return true;
        }
        if pids.len() >= options.limits.max_pids {
            work.gap(None, None, GapReason::ProcessLimit);
            return false;
        }
        pids.insert(pid);
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
    let selected_pids: Vec<_> = pids.into_iter().collect();
    let mut processes = Vec::new();
    for &pid in &selected_pids {
        if let Err(reason) = work.deadline() {
            work.gap(Some(pid), None, reason);
            break;
        }
        work.totals.processes_attempted += 1;
        match process(pid, &mut work) {
            Ok(process) => processes.push(process),
            Err(reason) => work.gap(Some(pid), None, reason),
        }
    }
    let inventory = if work.gaps.is_empty() {
        InventoryState::Complete
    } else if processes.is_empty() {
        InventoryState::Unavailable
    } else {
        InventoryState::Partial
    };
    Snapshot {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            options: &options,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
        };
        assert_eq!(
            work.inspect(File::open(&path).unwrap(), &metadata),
            Err(GapReason::NotElf)
        );
        writer.write_all(b"grown").unwrap();
        assert_eq!(
            work.inspect(File::open(&path).unwrap(), &metadata),
            Err(GapReason::Changed)
        );
        let mut fresh = Work {
            options: &options,
            started: Instant::now(),
            totals: WorkTotals::default(),
            gaps: BTreeSet::new(),
            cache: BTreeMap::new(),
        };
        assert_eq!(
            fresh.inspect(File::open(&path).unwrap(), &metadata),
            Err(GapReason::Changed)
        );
        assert_eq!(fresh.totals.read_bytes, 0);
        assert_eq!(fresh.totals.objects_inspected, 0);
        fs::remove_file(path).unwrap();
    }
}
