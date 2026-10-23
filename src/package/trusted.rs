// SPDX-License-Identifier: GPL-3.0-or-later
//! FD-anchored installed package trust boundary.

use super::{
    PackageError,
    records::{Digest, RelativePath, sha256},
};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

fn identity(file: &File, path: &Path) -> Result<FileIdentity, PackageError> {
    let m = file.metadata().map_err(|e| io_error(path, e))?;
    Ok(FileIdentity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.size(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}

fn label(path: &Path) -> String {
    path.display().to_string().chars().take(120).collect()
}
fn untrusted(path: &Path, reason: &str) -> PackageError {
    PackageError::Untrusted {
        context: format!("{}: {reason}", label(path))
            .chars()
            .take(160)
            .collect(),
    }
}
fn mutated(path: &Path, reason: &str) -> PackageError {
    PackageError::Mutated {
        context: format!("{}: {reason}", label(path))
            .chars()
            .take(160)
            .collect(),
    }
}
fn io_error(path: &Path, e: io::Error) -> PackageError {
    match e.raw_os_error() {
        Some(libc::ENOENT) => PackageError::unavailable(format!("missing {}", label(path))),
        Some(libc::ELOOP | libc::ENOTDIR) => untrusted(path, "symlink or non-directory component"),
        _ => PackageError::unreadable(format!("{}: {e}", label(path))),
    }
}

#[derive(Clone, Debug)]
struct TrustPolicy {
    uids: Vec<u32>,
    #[cfg(test)]
    exempt_ancestors_through: Option<PathBuf>,
}
impl TrustPolicy {
    fn production() -> Self {
        Self {
            uids: vec![0],
            #[cfg(test)]
            exempt_ancestors_through: None,
        }
    }
}

#[derive(Clone, Copy)]
enum OpenStrategy {
    Auto,
    #[cfg(test)]
    Walk,
    #[cfg(test)]
    Openat2,
}

pub struct OpenedFile {
    file: File,
    pub locator: PathBuf,
    pub identity: FileIdentity,
}

pub struct FileSnapshot {
    pub before: FileIdentity,
    pub after: FileIdentity,
    pub bytes: Arc<[u8]>,
    pub sha256: Digest,
}

pub struct TrustedDir {
    fd: File,
    path: PathBuf,
    policy: TrustPolicy,
    strategy: OpenStrategy,
}

impl TrustedDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every component is opened relative to an already checked directory FD.
    pub fn open_relative(&self, relative: &RelativePath) -> Result<OpenedFile, PackageError> {
        let (parent, name, locator) = self.parent_and_leaf(relative)?;
        let file = open_child(&parent, name, false, self.strategy, &locator)?;
        let id = identity(&file, &locator)?;
        check_file(&file, &id, &locator, &self.policy, false)?;
        Ok(OpenedFile {
            file,
            locator,
            identity: id,
        })
    }

    pub(crate) fn open_dir_relative(&self, relative: &RelativePath) -> Result<Self, PackageError> {
        let mut fd = self.fd.try_clone().map_err(|e| io_error(&self.path, e))?;
        let mut path = self.path.clone();
        for part in relative.as_str().split('/') {
            path.push(part);
            fd = open_child(&fd, part, true, self.strategy, &path)?;
            check_dir(&identity(&fd, &path)?, &path, &self.policy)?;
        }
        Ok(Self {
            fd,
            path,
            policy: self.policy.clone(),
            strategy: self.strategy,
        })
    }

    fn parent_and_leaf<'a>(
        &self,
        relative: &'a RelativePath,
    ) -> Result<(File, &'a str, PathBuf), PackageError> {
        let mut parts = relative.as_str().split('/').peekable();
        let mut fd = self.fd.try_clone().map_err(|e| io_error(&self.path, e))?;
        let mut path = self.path.clone();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                path.push(part);
                return Ok((fd, part, path));
            }
            path.push(part);
            fd = open_child(&fd, part, true, self.strategy, &path)?;
            check_dir(&identity(&fd, &path)?, &path, &self.policy)?;
        }
        Err(PackageError::invalid("empty relative path"))
    }
}

fn check_dir(id: &FileIdentity, path: &Path, policy: &TrustPolicy) -> Result<(), PackageError> {
    #[cfg(test)]
    let mode_exempt = policy
        .exempt_ancestors_through
        .as_ref()
        .is_some_and(|p| p.starts_with(path));
    #[cfg(not(test))]
    let mode_exempt = false;
    if id.mode & libc::S_IFMT != libc::S_IFDIR
        || !policy.uids.contains(&id.uid)
        || (id.mode & 0o022 != 0 && !mode_exempt)
    {
        return Err(untrusted(path, "directory owner, mode or type"));
    }
    Ok(())
}

fn check_file(
    file: &File,
    id: &FileIdentity,
    path: &Path,
    policy: &TrustPolicy,
    executable: bool,
) -> Result<(), PackageError> {
    check_file_metadata(id, path, policy, executable, false)?;
    if !executable {
        let name = CString::new("security.capability").unwrap();
        // SAFETY: name is NUL terminated, null value with zero size asks for xattr length.
        let rc =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if rc >= 0 {
            return check_file_metadata(id, path, policy, executable, true);
        }
        let e = io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
            return Err(io_error(path, e));
        }
    }
    Ok(())
}

fn check_file_metadata(
    id: &FileIdentity,
    path: &Path,
    policy: &TrustPolicy,
    executable: bool,
    has_capability: bool,
) -> Result<(), PackageError> {
    if id.mode & libc::S_IFMT != libc::S_IFREG
        || !policy.uids.contains(&id.uid)
        || id.mode & 0o022 != 0
        || (!executable && id.nlink != 1)
    {
        return Err(untrusted(path, "file owner, mode, link count or type"));
    }
    if executable {
        if id.mode & 0o111 == 0 || id.mode & 0o6000 != 0 {
            return Err(untrusted(path, "unsafe executable mode"));
        }
    } else {
        if id.mode & 0o6000 != 0 {
            return Err(untrusted(path, "set-id file"));
        }
        if id.mode & 0o444 == 0 {
            return Err(PackageError::unreadable(format!(
                "{}: no read mode",
                label(path)
            )));
        }
        if has_capability {
            return Err(untrusted(path, "file capabilities present"));
        }
    }
    Ok(())
}

fn open_child(
    parent: &File,
    name: &str,
    directory: bool,
    strategy: OpenStrategy,
    path: &Path,
) -> Result<File, PackageError> {
    let name = CString::new(name).map_err(|_| PackageError::invalid("NUL path component"))?;
    // O_NONBLOCK prevents an attacker-controlled FIFO leaf from stalling admission.
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let open_walk = || {
        // SAFETY: parent is live, name is NUL terminated, flags have no mode argument.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    };
    let open_at2 = || {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: 0x02 | 0x04 | 0x08,
        };
        // SAFETY: open_how and component name are valid for the syscall duration.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd as i32)
        }
    };
    let fd = match strategy {
        #[cfg(test)]
        OpenStrategy::Walk => open_walk(),
        #[cfg(test)]
        OpenStrategy::Openat2 => open_at2(),
        OpenStrategy::Auto => match open_at2() {
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
                ) =>
            {
                open_walk()
            }
            other => other,
        },
    }
    .map_err(|e| io_error(path, e))?;
    // SAFETY: fd was returned by openat/openat2 and ownership transfers exactly once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn trusted_dir_with(
    path: &Path,
    policy: TrustPolicy,
    strategy: OpenStrategy,
) -> Result<TrustedDir, PackageError> {
    trusted_dir_with_ops(path, policy, strategy, identity)
}

fn trusted_dir_with_ops<M>(
    path: &Path,
    policy: TrustPolicy,
    strategy: OpenStrategy,
    mut metadata: M,
) -> Result<TrustedDir, PackageError>
where
    M: FnMut(&File, &Path) -> Result<FileIdentity, PackageError>,
{
    if !path.is_absolute() {
        return Err(PackageError::invalid("non-absolute trust root"));
    }
    let mut fd = File::open("/").map_err(|e| io_error(Path::new("/"), e))?;
    check_dir(&metadata(&fd, Path::new("/"))?, Path::new("/"), &policy)?;
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                current.push(part);
                let text = part
                    .to_str()
                    .ok_or_else(|| PackageError::invalid("non-UTF8 trust path"))?;
                fd = open_child(&fd, text, true, strategy, &current)?;
                check_dir(&metadata(&fd, &current)?, &current, &policy)?;
            }
            _ => return Err(PackageError::invalid("unsafe absolute trust path")),
        }
    }
    Ok(TrustedDir {
        fd,
        path: current,
        policy,
        strategy,
    })
}

pub struct HostIdentity {
    pub executable: OpenedFile,
    pub prefix: TrustedDir,
}

fn executing_host_with(
    file: File,
    path: PathBuf,
    policy: TrustPolicy,
    strategy: OpenStrategy,
) -> Result<HostIdentity, PackageError> {
    let proc_id = identity(&file, &path)?;
    if proc_id.nlink == 0 {
        return Err(mutated(&path, "executable was deleted"));
    }
    check_file(&file, &proc_id, &path, &policy, true)?;
    let parent = path
        .parent()
        .ok_or_else(|| PackageError::invalid("executable has no parent"))?;
    let anchored_parent = trusted_dir_with(parent, policy, strategy)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| PackageError::invalid("invalid executable filename"))?;
    let rebound =
        open_child(&anchored_parent.fd, name, false, strategy, &path).map_err(|e| match e {
            PackageError::Unavailable { .. } => mutated(&path, "executable path no longer exists"),
            other => other,
        })?;
    let rebound_id = identity(&rebound, &path)?;
    check_file(&rebound, &rebound_id, &path, &anchored_parent.policy, true)?;
    if proc_id.dev != rebound_id.dev || proc_id.ino != rebound_id.ino {
        return Err(mutated(&path, "executable path rebound to another inode"));
    }
    let prefix_path = installed_prefix_path(&path)?;
    let prefix = trusted_dir_with(&prefix_path, anchored_parent.policy, strategy)?;
    Ok(HostIdentity {
        executable: OpenedFile {
            file,
            locator: path,
            identity: proc_id,
        },
        prefix,
    })
}

fn installed_prefix_path(path: &Path) -> Result<PathBuf, PackageError> {
    let parent = path
        .parent()
        .ok_or_else(|| PackageError::invalid("executable has no parent"))?;
    if path.file_name().and_then(|n| n.to_str()) != Some("osslscope")
        || parent.file_name().and_then(|n| n.to_str()) != Some("bin")
    {
        return Err(PackageError::invalid(format!(
            "{}: unsupported installed executable layout",
            label(path)
        )));
    }
    let prefix_path = parent
        .parent()
        .ok_or_else(|| PackageError::invalid("missing executable prefix"))?;
    if prefix_path == Path::new("/") {
        return Err(PackageError::invalid("root is not an installed prefix"));
    }
    Ok(prefix_path.to_path_buf())
}

/// The only intentional magic-link traversal is this executable FD acquisition.
pub fn executing_host() -> Result<HostIdentity, PackageError> {
    executing_host_at(
        Path::new("/proc/self/exe"),
        TrustPolicy::production(),
        OpenStrategy::Auto,
    )
}

fn executing_host_at(
    executable_link: &Path,
    policy: TrustPolicy,
    strategy: OpenStrategy,
) -> Result<HostIdentity, PackageError> {
    let file = File::open(executable_link).map_err(|e| io_error(executable_link, e))?;
    let path = std::fs::read_link(executable_link).map_err(|e| io_error(executable_link, e))?;
    executing_host_with(file, path, policy, strategy)
}

/// Bound reads to limit+1 and compare the opened FD before and after.
pub fn snapshot(opened: &OpenedFile, limit: u64) -> Result<FileSnapshot, PackageError> {
    snapshot_with(
        opened,
        limit,
        |file, buf, offset| file.read_at(buf, offset),
        |file| identity(file, &opened.locator),
    )
}

fn snapshot_with<R, M>(
    opened: &OpenedFile,
    limit: u64,
    mut read: R,
    mut metadata: M,
) -> Result<FileSnapshot, PackageError>
where
    R: FnMut(&File, &mut [u8], u64) -> io::Result<usize>,
    M: FnMut(&File) -> Result<FileIdentity, PackageError>,
{
    let before = metadata(&opened.file)?;
    if before != opened.identity {
        return Err(mutated(&opened.locator, "metadata changed before read"));
    }
    let mut buf = Vec::new();
    let mut offset = 0u64;
    let bound = limit.saturating_add(1);
    while offset < bound {
        let chunk = (bound - offset).min(64 * 1024) as usize;
        let mut part = vec![0u8; chunk];
        let n = read(&opened.file, &mut part, offset).map_err(|e| io_error(&opened.locator, e))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&part[..n]);
        offset += n as u64;
    }
    let after = metadata(&opened.file)?;
    if before != after {
        return Err(mutated(&opened.locator, "metadata changed during read"));
    }
    if offset > limit {
        return Err(PackageError::invalid(format!(
            "{}: exceeds read bound {limit}",
            label(&opened.locator)
        )));
    }
    if offset != after.size {
        return Err(PackageError::unreadable(format!(
            "{}: short read from opened file",
            label(&opened.locator)
        )));
    }
    let bytes: Arc<[u8]> = Arc::from(buf);
    let digest = sha256(&bytes);
    Ok(FileSnapshot {
        before,
        after,
        bytes,
        sha256: digest,
    })
}

#[cfg(test)]
fn test_policy() -> TrustPolicy {
    let mut uids = vec![0, unsafe { libc::geteuid() }];
    let mut p = std::env::temp_dir();
    loop {
        if let Ok(m) = std::fs::metadata(&p) {
            uids.push(m.uid());
        }
        if !p.pop() {
            break;
        }
    }
    uids.sort_unstable();
    uids.dedup();
    TrustPolicy {
        uids,
        exempt_ancestors_through: Some(std::env::temp_dir()),
    }
}

#[cfg(test)]
pub(super) fn test_dir(path: &Path) -> Result<TrustedDir, PackageError> {
    trusted_dir_with(path, test_policy(), OpenStrategy::Walk)
}

#[cfg(test)]
pub(super) fn test_host_from_link(path: &Path) -> Result<HostIdentity, PackageError> {
    executing_host_at(path, test_policy(), OpenStrategy::Walk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::records::RelativePath;
    use std::fs;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir()
                .join(format!("osslscope-package-fd-{}-{n}", std::process::id()));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            Self(p)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn prefix_selection_is_executable_bound() {
        let f = Fixture::new();
        let bin = f.0.join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = bin.join("osslscope");
        fs::write(&executable, b"host").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let other = f.0.join("other-prefix");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
        let link = other.join("other-invocation");
        symlink(&executable, &link).unwrap();
        let host = test_host_from_link(&link).unwrap();
        assert_eq!(host.prefix.path(), f.0.as_path());
        assert_eq!(
            host.executable.identity.dev,
            fs::metadata(&executable).unwrap().dev()
        );
        assert_ne!(host.executable.locator, link);
    }

    #[test]
    fn executing_host_rebind_races() {
        let f = Fixture::new();
        let bin = f.0.join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = bin.join("osslscope");
        fs::write(&executable, b"old").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let old = fs::File::open(&executable).unwrap();
        fs::rename(&executable, bin.join("old")).unwrap();
        fs::write(&executable, b"new").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            executing_host_with(old, executable.clone(), test_policy(), OpenStrategy::Walk),
            Err(crate::package::PackageError::Mutated { .. })
        ));
        let deleted = fs::File::open(&executable).unwrap();
        fs::remove_file(&executable).unwrap();
        assert!(matches!(
            executing_host_with(deleted, executable, test_policy(), OpenStrategy::Walk),
            Err(crate::package::PackageError::Mutated { .. })
        ));
    }

    #[test]
    fn nofollow_and_ownership_on_both_fd_walks() {
        let f = Fixture::new();
        fs::create_dir(f.0.join("bundle")).unwrap();
        fs::set_permissions(f.0.join("bundle"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(f.0.join("bundle/file"), b"stable").unwrap();
        fs::set_permissions(f.0.join("bundle/file"), fs::Permissions::from_mode(0o644)).unwrap();
        symlink("file", f.0.join("bundle/link")).unwrap();
        for strategy in [OpenStrategy::Walk, OpenStrategy::Openat2] {
            let dir = trusted_dir_with(&f.0, test_policy(), strategy).unwrap();
            let good = dir
                .open_relative(&RelativePath::new("bundle/file").unwrap())
                .unwrap();
            assert_eq!(&*snapshot(&good, 6).unwrap().bytes, b"stable");
            assert!(matches!(
                dir.open_relative(&RelativePath::new("bundle/link").unwrap()),
                Err(crate::package::PackageError::Untrusted { .. })
            ));
            assert!(matches!(
                snapshot(&good, 5),
                Err(crate::package::PackageError::Invalid { .. })
            ));
        }
        fs::set_permissions(f.0.join("bundle"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            trusted_dir_with(&f.0.join("bundle"), test_policy(), OpenStrategy::Walk),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
    }

    #[test]
    fn file_and_ancestor_trust_matrix() {
        let f = Fixture::new();
        let dir = trusted_dir_with(&f.0, test_policy(), OpenStrategy::Walk).unwrap();
        let original = f.0.join("regular");
        fs::write(&original, b"x").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
        let rel = RelativePath::new("regular").unwrap();
        assert!(dir.open_relative(&rel).is_ok());
        for mode in [0o646, 0o664, 0o4644, 0o2644, 0o000] {
            fs::set_permissions(&original, fs::Permissions::from_mode(mode)).unwrap();
            assert!(dir.open_relative(&rel).is_err(), "mode {mode:o}");
        }
        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&original, f.0.join("hardlink")).unwrap();
        assert!(matches!(
            dir.open_relative(&rel),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
        fs::remove_file(f.0.join("hardlink")).unwrap();
        let fifo = f.0.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL terminated owned fixture path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert!(
            dir.open_relative(&RelativePath::new("fifo").unwrap())
                .is_err()
        );
        let writable = f.0.join("writable");
        fs::create_dir(&writable).unwrap();
        for mode in [0o757, 0o775, 0o1777] {
            fs::set_permissions(&writable, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    dir.open_dir_relative(&RelativePath::new("writable").unwrap()),
                    Err(crate::package::PackageError::Untrusted { .. })
                ),
                "mode {mode:o}"
            );
        }
        symlink("writable", f.0.join("linked")).unwrap();
        assert!(matches!(
            dir.open_dir_relative(&RelativePath::new("linked").unwrap()),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
    }

    #[test]
    fn snapshot_fault_adapter_bounds_and_mutation() {
        let f = Fixture::new();
        let file = f.0.join("record");
        fs::write(&file, b"abcdef").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let dir = trusted_dir_with(&f.0, test_policy(), OpenStrategy::Walk).unwrap();
        let opened = dir
            .open_relative(&RelativePath::new("record").unwrap())
            .unwrap();
        let read_total = std::cell::Cell::new(0usize);
        let result = snapshot_with(
            &opened,
            5,
            |fd, buf, off| {
                read_total.set(read_total.get() + buf.len());
                fd.read_at(buf, off)
            },
            |fd| identity(fd, &opened.locator),
        );
        assert!(matches!(
            result,
            Err(crate::package::PackageError::Invalid { .. })
        ));
        assert_eq!(read_total.get(), 6);
        let calls = std::cell::Cell::new(0usize);
        let result = snapshot_with(
            &opened,
            6,
            |fd, buf, off| fd.read_at(buf, off),
            |fd| {
                calls.set(calls.get() + 1);
                let mut id = identity(fd, &opened.locator)?;
                if calls.get() == 2 {
                    id.mtime.0 += 1;
                }
                Ok(id)
            },
        );
        assert!(matches!(
            result,
            Err(crate::package::PackageError::Mutated { .. })
        ));
        let short = snapshot_with(
            &opened,
            6,
            |_fd, _buf, _off| Ok(0),
            |fd| identity(fd, &opened.locator),
        );
        assert!(matches!(
            short,
            Err(crate::package::PackageError::Unreadable { .. })
        ));
    }

    #[test]
    fn every_ancestor_and_leaf_owner_is_checked_on_opened_fds() {
        let f = Fixture::new();
        let mut levels: Vec<_> = f.0.ancestors().collect();
        levels.reverse();
        for bad in levels {
            let result =
                trusted_dir_with_ops(&f.0, test_policy(), OpenStrategy::Walk, |fd, path| {
                    let mut id = identity(fd, path)?;
                    if path == bad {
                        id.uid = u32::MAX;
                    }
                    Ok(id)
                });
            assert!(
                matches!(result, Err(crate::package::PackageError::Untrusted { .. })),
                "{}",
                bad.display()
            );
        }
        let path = f.0.join("leaf");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let dir = trusted_dir_with(&f.0, test_policy(), OpenStrategy::Walk).unwrap();
        let opened = dir
            .open_relative(&RelativePath::new("leaf").unwrap())
            .unwrap();
        let mut bad = opened.identity.clone();
        bad.uid = u32::MAX;
        assert!(matches!(
            check_file(&opened.file, &bad, &path, &test_policy(), false),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
    }

    #[test]
    fn capability_and_device_metadata_are_rejected_before_snapshot() {
        let f = Fixture::new();
        let path = f.0.join("ordinary");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let dir = trusted_dir_with(&f.0, test_policy(), OpenStrategy::Walk).unwrap();
        let opened = dir
            .open_relative(&RelativePath::new("ordinary").unwrap())
            .unwrap();
        assert!(matches!(
            check_file_metadata(&opened.identity, &path, &test_policy(), false, true),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
        let mut device = opened.identity.clone();
        device.mode = (device.mode & !libc::S_IFMT) | libc::S_IFCHR;
        assert!(matches!(
            check_file_metadata(&device, &path, &test_policy(), false, false),
            Err(crate::package::PackageError::Untrusted { .. })
        ));
    }

    #[test]
    fn retained_walk_allows_distinct_device_at_usr_component() {
        let f = Fixture::new();
        let usr = f.0.join("usr");
        fs::create_dir(&usr).unwrap();
        fs::set_permissions(&usr, fs::Permissions::from_mode(0o755)).unwrap();
        let mut checked = false;
        let walk = trusted_dir_with_ops(&usr, test_policy(), OpenStrategy::Walk, |fd, path| {
            let mut id = identity(fd, path)?;
            if path == usr {
                id.dev = id.dev.wrapping_add(1);
                checked = true;
            }
            Ok(id)
        });
        assert!(checked);
        assert!(walk.is_ok());
    }

    #[test]
    fn symlinked_manifest_leaf_and_nested_component_fail_closed() {
        let f = Fixture::new();
        fs::create_dir(f.0.join("bundle")).unwrap();
        fs::set_permissions(f.0.join("bundle"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(f.0.join("bundle/real.json"), b"{}\n").unwrap();
        symlink("real.json", f.0.join("bundle/payload-manifest.json")).unwrap();
        symlink("bundle", f.0.join("linked-bundle")).unwrap();
        let dir = trusted_dir_with(&f.0, test_policy(), OpenStrategy::Walk).unwrap();
        for relative in ["bundle/payload-manifest.json", "linked-bundle/real.json"] {
            assert!(
                matches!(
                    dir.open_relative(&RelativePath::new(relative).unwrap()),
                    Err(crate::package::PackageError::Untrusted { .. })
                ),
                "{relative}"
            );
        }
    }

    #[test]
    fn root_prefix_layout_is_refused() {
        assert!(matches!(
            installed_prefix_path(Path::new("/bin/osslscope")),
            Err(crate::package::PackageError::Invalid { .. })
        ));
        assert_eq!(
            installed_prefix_path(Path::new("/usr/bin/osslscope")).unwrap(),
            Path::new("/usr")
        );
    }
}
