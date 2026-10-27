// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned, bounded selectors. Paths are private locators, never report fields.
use super::{
    CaptureClock, Gap, GapReason, InventoryState, Limits, NamespaceId, Scope, ScopeRecord,
    Snapshot, SnapshotOptions, elf, procfs,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug, Default)]
pub struct Selection {
    pub pids: Vec<u32>,
    pub cgroup: Option<PathBuf>,
    pub modules: Vec<PathBuf>,
}

type Fingerprint = (u64, u64, u64, i64, i64, i64, i64);
fn fingerprint(m: &Metadata) -> Fingerprint {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn native(file: &File) -> Result<NamespaceId, GapReason> {
    file.metadata()
        .map(|m| NamespaceId {
            device: m.dev(),
            inode: m.ino(),
        })
        .map_err(|_| GapReason::CgroupUnavailable)
}
struct ModuleSelector {
    file: File,
    fingerprint: Fingerprint,
    sha256: String,
}
/// Resources are bounded by the supplied limits; no target code is loaded.
pub struct ScopedScanner {
    pids: Vec<u32>,
    cgroup: Option<File>,
    modules: Vec<ModuleSelector>,
    limits: Limits,
    scope: Scope,
    record: ScopeRecord,
}
impl ScopedScanner {
    pub fn new(selection: Selection, limits: Limits) -> Result<Self, GapReason> {
        let count = usize::from(!selection.pids.is_empty())
            + usize::from(selection.cgroup.is_some())
            + usize::from(!selection.modules.is_empty());
        let scope = match count {
            0 => Scope::System,
            2.. => Scope::Intersection,
            _ if selection.cgroup.is_some() => Scope::Cgroup,
            _ if !selection.modules.is_empty() => Scope::Modules,
            _ => Scope::Pids,
        };
        if selection.modules.len() > limits.max_objects {
            return Err(GapReason::ObjectLimit);
        }
        let mut budget = Budget::new(&limits);
        let cgroup = selection
            .cgroup
            .map(|path| {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|_| GapReason::CgroupUnavailable)?;
                validate_cgroup(&file, &mut budget)?;
                Ok(file)
            })
            .transpose()?;
        if cgroup.is_some() {
            validate_pid_view(&mut budget)?;
        }
        let mut modules = Vec::new();
        for path in selection.modules {
            budget.deadline()?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(path)
                .map_err(|_| GapReason::Unavailable)?;
            let metadata = file.metadata().map_err(|_| GapReason::Unavailable)?;
            if !metadata.is_file() {
                return Err(GapReason::NonRegular);
            }
            if metadata.len() > limits.max_module_bytes {
                return Err(GapReason::TooLarge);
            }
            let key = fingerprint(&metadata);
            if modules
                .iter()
                .any(|m: &ModuleSelector| m.fingerprint == key)
            {
                continue;
            }
            budget.charge(metadata.len().checked_add(1).ok_or(GapReason::ReadLimit)?)?;
            let info = elf::inspect_file(&mut file, metadata.len())?;
            budget.deadline()?;
            if file.metadata().map(|m| fingerprint(&m)).ok() != Some(key) {
                return Err(GapReason::Changed);
            }
            modules.push(ModuleSelector {
                file,
                fingerprint: key,
                sha256: info.sha256,
            });
        }
        let record = ScopeRecord {
            cgroup: cgroup.as_ref().map(native).transpose()?,
            modules: modules
                .iter()
                .map(|m| m.sha256.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        Ok(Self {
            pids: selection.pids,
            cgroup,
            modules,
            limits,
            scope,
            record,
        })
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let clock = CaptureClock::start();
        let mut budget = Budget::new(&self.limits);
        let valid = self
            .modules
            .iter()
            .all(|m| m.file.metadata().map(|v| fingerprint(&v)).ok() == Some(m.fingerprint));
        if !valid {
            return self.failed(GapReason::Changed, &clock, budget.bytes);
        }
        if self.cgroup.is_some() {
            if let Err(reason) = validate_pid_view(&mut budget) {
                return self.failed(reason, &clock, budget.bytes);
            }
        }
        let before = match self
            .cgroup
            .as_ref()
            .map(|file| members(file, &mut budget))
            .transpose()
        {
            Ok(value) => value,
            Err(reason) => return self.failed(reason, &clock, budget.bytes),
        };
        let pids = match &before {
            Some(membership) => {
                let selected: BTreeSet<_> = self.pids.iter().copied().collect();
                membership
                    .records
                    .values()
                    .flatten()
                    .copied()
                    .filter(|pid| selected.is_empty() || selected.contains(pid))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            }
            None => self.pids.clone(),
        };
        let mut limits = self.limits.clone();
        limits.max_read_bytes = limits.max_read_bytes.saturating_sub(budget.bytes);
        limits.timeout = limits.timeout.saturating_sub(budget.started.elapsed());
        let mut result = procfs::snapshot_scoped(
            &SnapshotOptions { pids, limits },
            self.pids.is_empty() && self.cgroup.is_none(),
            !self.modules.is_empty(),
        );
        budget.bytes = budget.bytes.saturating_add(result.totals.read_bytes);
        if let Some(before) = &before {
            for reason in &before.gaps {
                add_gap(&mut result, *reason);
            }
        }
        if let Some(file) = &self.cgroup {
            match members(file, &mut budget) {
                Ok(after) => {
                    for reason in &after.gaps {
                        add_gap(&mut result, *reason);
                    }
                    let before = &before.as_ref().expect("cgroup membership").records;
                    let stable = stable_members(before, &after.records);
                    // Even equal passes may contain an ambiguous PID observed
                    // in multiple directories during each traversal.
                    let ambiguous = |records: &BTreeMap<NamespaceId, BTreeSet<u32>>| {
                        records.values().map(BTreeSet::len).sum::<usize>()
                            != records
                                .values()
                                .flatten()
                                .copied()
                                .collect::<BTreeSet<_>>()
                                .len()
                    };
                    result.processes.retain(|p| stable.contains(&p.pid));
                    result.selected_pids.retain(|pid| stable.contains(pid));
                    if before != &after.records {
                        add_gap(&mut result, GapReason::Changed);
                    }
                    if ambiguous(before) || ambiguous(&after.records) {
                        add_gap(&mut result, GapReason::MembershipUnknown);
                    }
                }
                Err(reason) => {
                    result.processes.clear();
                    result.selected_pids.clear();
                    add_gap(&mut result, reason);
                }
            }
        }
        if !self.modules.is_empty() {
            let hashes: BTreeSet<_> = self.record.modules.iter().collect();
            for process in &mut result.processes {
                process.modules.retain(|m| hashes.contains(&m.info.sha256));
            }
            result.processes.retain(|p| !p.modules.is_empty());
            let matched: BTreeSet<_> = result.processes.iter().map(|p| p.pid).collect();
            result.selected_pids.retain(|pid| matched.contains(pid));
        }
        // Revalidate selector descriptors after the sampled read as well.
        if self
            .modules
            .iter()
            .any(|m| m.file.metadata().map(|v| fingerprint(&v)).ok() != Some(m.fingerprint))
        {
            result.processes.clear();
            result.selected_pids.clear();
            add_gap(&mut result, GapReason::Changed);
        }
        result.interval = clock.finish();
        result.scope = self.scope;
        result.scope_record = self.record.clone();
        result.limits = self.limits.clone();
        result.totals.read_bytes = budget.bytes;
        result.capabilities.inventory = if result.gaps.is_empty() {
            InventoryState::Complete
        } else if result.processes.is_empty() {
            InventoryState::Unavailable
        } else {
            InventoryState::Partial
        };
        result
    }
    fn failed(&self, reason: GapReason, clock: &CaptureClock, bytes: u64) -> Snapshot {
        let mut result = procfs::snapshot_selected(
            &SnapshotOptions {
                pids: vec![],
                limits: self.limits.clone(),
            },
            false,
        );
        result.interval = clock.finish();
        result.scope = self.scope;
        result.scope_record = self.record.clone();
        result.totals.read_bytes = bytes;
        add_gap(&mut result, reason);
        result.capabilities.inventory = InventoryState::Unavailable;
        result
    }
}
fn add_gap(result: &mut Snapshot, reason: GapReason) {
    result.gaps.push(Gap {
        pid: None,
        device: None,
        inode: None,
        reason,
    });
    result.gaps.sort();
    result.gaps.dedup();
}
struct Budget<'a> {
    limits: &'a Limits,
    started: Instant,
    bytes: u64,
    membership_bytes: usize,
    directory_visits: usize,
}
impl<'a> Budget<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            bytes: 0,
            membership_bytes: 0,
            directory_visits: 0,
        }
    }
    fn admit_directory(&mut self) -> Result<(), GapReason> {
        self.deadline()?;
        if self.directory_visits >= 4096 {
            return Err(GapReason::CgroupLimit);
        }
        self.directory_visits += 1;
        Ok(())
    }
    fn deadline(&self) -> Result<(), GapReason> {
        if self.started.elapsed() >= self.limits.timeout {
            Err(GapReason::Deadline)
        } else {
            Ok(())
        }
    }
    fn charge(&mut self, count: u64) -> Result<(), GapReason> {
        if count > self.limits.max_read_bytes.saturating_sub(self.bytes) {
            return Err(GapReason::ReadLimit);
        }
        self.bytes += count;
        Ok(())
    }
    fn read(
        &mut self,
        mut file: File,
        maximum: usize,
        membership: bool,
    ) -> Result<Vec<u8>, GapReason> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            self.deadline()?;
            let remaining = self.limits.max_read_bytes.saturating_sub(self.bytes);
            if remaining == 0 {
                return Err(GapReason::ReadLimit);
            }
            let membership_remaining = if membership {
                4_194_304usize.saturating_sub(self.membership_bytes)
            } else {
                usize::MAX
            };
            if membership_remaining == 0 {
                return Err(GapReason::CgroupLimit);
            }
            let count = chunk
                .len()
                .min(membership_remaining)
                .min(maximum.saturating_sub(bytes.len()).saturating_add(1))
                .min(remaining.try_into().unwrap_or(usize::MAX));
            let n = file
                .read(&mut chunk[..count])
                .map_err(|_| GapReason::MembershipUnknown)?;
            self.charge(n as u64)?;
            if membership {
                self.membership_bytes = self.membership_bytes.saturating_add(n);
                if self.membership_bytes > 4_194_304 {
                    return Err(GapReason::CgroupLimit);
                }
            }
            if n == 0 {
                return Ok(bytes);
            }
            if n > maximum.saturating_sub(bytes.len()) {
                return Err(GapReason::CgroupLimit);
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
    }
}
fn validate_cgroup(file: &File, budget: &mut Budget<'_>) -> Result<(), GapReason> {
    budget.deadline()?;
    if procfs::filesystem(file) != Some(libc::CGROUP2_SUPER_MAGIC) {
        return Err(GapReason::UnsupportedCgroup);
    }
    match procfs::open_at(file, b"cgroup.type") {
        Ok(kind) => domain_type(&budget.read(kind, 64, false)?),
        // cgroup2's actual hierarchy root omits cgroup.type. A parent on
        // another filesystem proves this special case, never a fake tree.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && procfs::open_at(file, b"..").ok().is_some_and(|parent| {
                    procfs::filesystem(&parent)
                        .is_some_and(|kind| kind != libc::CGROUP2_SUPER_MAGIC)
                }) =>
        {
            Ok(())
        }
        Err(_) => Err(GapReason::MembershipUnknown),
    }
}
// cgroup.procs reports caller-namespace PIDs, while a procfs mount may
// expose an ancestor namespace. Never join these independent coordinates.
fn validate_pid_view(budget: &mut Budget<'_>) -> Result<(), GapReason> {
    let file = File::open("/proc/self/status").map_err(|_| GapReason::MembershipUnknown)?;
    if procfs::filesystem(&file) != Some(libc::PROC_SUPER_MAGIC) {
        return Err(GapReason::MembershipUnknown);
    }
    pid_view(&budget.read(file, 65_536, false)?, std::process::id())
}
fn pid_view(bytes: &[u8], observer_pid: u32) -> Result<(), GapReason> {
    let values = bytes
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"NSpid:"))
        .ok_or(GapReason::MembershipUnknown)?;
    let mut values = values
        .split(u8::is_ascii_whitespace)
        .filter(|value| !value.is_empty());
    let pid = values
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u32>().ok());
    if pid == Some(observer_pid) && values.next().is_none() {
        Ok(())
    } else {
        Err(GapReason::MembershipUnknown)
    }
}
fn domain_type(bytes: &[u8]) -> Result<(), GapReason> {
    if bytes == b"domain\n" {
        Ok(())
    } else {
        Err(GapReason::UnsupportedCgroup)
    }
}
fn parse_members(bytes: &[u8]) -> Result<BTreeSet<u32>, GapReason> {
    let mut result = BTreeSet::new();
    if bytes.is_empty() {
        return Ok(result);
    }
    let bytes = bytes
        .strip_suffix(b"\n")
        .ok_or(GapReason::MembershipUnknown)?;
    for line in bytes.split(|b| *b == b'\n') {
        if !line.iter().all(u8::is_ascii_digit) {
            return Err(GapReason::MembershipUnknown);
        }
        let pid = std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|p| *p > 0 && *p <= i32::MAX as u32)
            .ok_or(GapReason::MembershipUnknown)?;
        result.insert(pid);
    }
    Ok(result)
}
// Retain every sampled directory through membership reconciliation so its
// native inode identity cannot be recycled during the process scan.
struct Membership {
    records: BTreeMap<NamespaceId, BTreeSet<u32>>,
    _pins: Vec<File>,
    gaps: BTreeSet<GapReason>,
}
fn mount_id(file: &File) -> Result<u64, GapReason> {
    let mut stat = std::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: valid FD, empty C string and correctly sized writable result.
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(GapReason::MembershipUnknown);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(GapReason::MembershipUnknown);
    }
    Ok(stat.stx_mnt_id)
}
fn same_mount(file: &File, expected: u64) -> Result<(), GapReason> {
    if mount_id(file)? == expected {
        Ok(())
    } else {
        Err(GapReason::MembershipUnknown)
    }
}
fn members(root: &File, budget: &mut Budget<'_>) -> Result<Membership, GapReason> {
    budget.admit_directory()?;
    let selected_mount = mount_id(root)?;
    let mut pending = vec![root.try_clone().map_err(|_| GapReason::CgroupUnavailable)?];
    let mut result = BTreeMap::new();
    let mut pins = Vec::new();
    let mut gaps = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        if let Err(reason) = same_mount(&directory, selected_mount) {
            gaps.insert(reason);
            continue;
        }
        validate_cgroup(&directory, budget)?;
        let identity = native(&directory)?;
        if directory
            .metadata()
            .map_err(|_| GapReason::CgroupUnavailable)?
            .nlink()
            == 0
        {
            return Err(GapReason::Changed);
        }
        let procs = procfs::open_at(&directory, b"cgroup.procs")
            .map_err(|_| GapReason::MembershipUnknown)?;
        let bytes = budget.read(procs, 4_194_304, true)?;
        result.insert(identity, parse_members(&bytes)?);
        // Resolve entries relative to the held directory, never a target
        // pathname. O_NOFOLLOW prevents substitution by a symlink.
        let entries = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| GapReason::MembershipUnknown)?;
        for entry in entries {
            budget.deadline()?;
            let entry = entry.map_err(|_| GapReason::MembershipUnknown)?;
            if !entry
                .file_type()
                .map_err(|_| GapReason::MembershipUnknown)?
                .is_dir()
            {
                continue;
            }
            budget.admit_directory()?;
            let name = std::ffi::CString::new(entry.file_name().as_bytes())
                .map_err(|_| GapReason::MembershipUnknown)?;
            // SAFETY: live parent FD and C string; successful FD owned once.
            let raw = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK,
                )
            };
            if raw < 0 {
                return Err(GapReason::MembershipUnknown);
            }
            use std::os::fd::FromRawFd as _;
            pending.push(unsafe { File::from_raw_fd(raw) });
        }
        pins.push(directory);
    }
    Ok(Membership {
        records: result,
        _pins: pins,
        gaps,
    })
}

fn stable_members(
    before: &BTreeMap<NamespaceId, BTreeSet<u32>>,
    after: &BTreeMap<NamespaceId, BTreeSet<u32>>,
) -> BTreeSet<u32> {
    let locations = |membership: &BTreeMap<NamespaceId, BTreeSet<u32>>| {
        let mut locations: BTreeMap<u32, BTreeSet<NamespaceId>> = BTreeMap::new();
        for (id, pids) in membership {
            for pid in pids {
                locations.entry(*pid).or_default().insert(*id);
            }
        }
        locations
    };
    let previous = locations(before);
    let current = locations(after);
    previous
        .into_iter()
        .filter_map(|(pid, ids)| (ids.len() == 1 && current.get(&pid) == Some(&ids)).then_some(pid))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_boundary_revalidation_accepts_same_mount_and_refuses_other_mount() {
        let first = File::open("/proc/self").unwrap();
        let second = File::open("/proc").unwrap();
        let different = File::open("/dev").unwrap();
        let id = mount_id(&first).unwrap();
        assert_eq!(same_mount(&second, id), Ok(()));
        assert_eq!(
            same_mount(&different, id),
            Err(GapReason::MembershipUnknown)
        );
    }

    #[test]
    fn pid_view_must_share_cgroup_procs_numeric_coordinates() {
        assert_eq!(pid_view(b"Name:	private\nNSpid:	123\n", 123), Ok(()));
        for bytes in [
            b"NSpid:	1000 123\n".as_slice(),
            b"NSpid:	124\n",
            b"NSpid:	0\n",
            b"Name:	only\n",
            b"NSpid:	unknown\n",
        ] {
            assert_eq!(pid_view(bytes, 123), Err(GapReason::MembershipUnknown));
        }
    }

    // Source behavior only: numeric bytes are not a fake cgroup filesystem.
    #[test]
    fn membership_parser_refuses_invisible_and_malformed_ids() {
        assert_eq!(
            parse_members(b"19\n3\n19\n").unwrap(),
            BTreeSet::from([3, 19])
        );
        for bytes in [
            b"0\n".as_slice(),
            b"-1\n",
            b"4294967296\n",
            b"2147483648\n",
            b"19 garbage\n",
            b"\n",
            b"12",
        ] {
            assert_eq!(
                parse_members(bytes),
                Err(GapReason::MembershipUnknown),
                "{bytes:?}"
            );
        }
        assert!(parse_members(b"").unwrap().is_empty());
    }

    // Per-snapshot cumulative bound, including both membership passes.
    #[test]
    fn membership_read_budget_is_shared_across_passes() {
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        budget.membership_bytes = 4_194_304;
        let file = File::open("/dev/zero").unwrap();
        assert_eq!(budget.read(file, 8192, true), Err(GapReason::CgroupLimit));
        assert!(budget.bytes <= 8192);
    }

    #[test]
    fn traversal_directory_budget_is_shared_across_passes() {
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        for _ in 0..4096 {
            budget.admit_directory().unwrap();
        }
        assert_eq!(budget.admit_directory(), Err(GapReason::CgroupLimit));
    }

    #[test]
    fn domain_only_refuses_threaded_or_unrecognized_membership_models() {
        for bytes in [
            b"threaded\n".as_slice(),
            b"domain threaded\n",
            b"domain invalid\n",
            b"unknown\n",
        ] {
            assert_eq!(domain_type(bytes), Err(GapReason::UnsupportedCgroup));
        }
        assert_eq!(domain_type(b"domain\n"), Ok(()));
    }

    #[test]
    fn membership_revalidation_excludes_moves_and_ambiguous_pid_locations() {
        let first = NamespaceId {
            device: 1,
            inode: 2,
        };
        let second = NamespaceId {
            device: 1,
            inode: 3,
        };
        let before = BTreeMap::from([
            (first, BTreeSet::from([3, 4, 5, 6])),
            (second, BTreeSet::from([6])),
        ]);
        let after = BTreeMap::from([
            (first, BTreeSet::from([3, 6, 7])),
            (second, BTreeSet::from([4, 6])),
        ]);
        assert_eq!(stable_members(&before, &after), BTreeSet::from([3]));
    }
}
