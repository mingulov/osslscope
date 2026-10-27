// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed executable-relative companion. Locator and IO errors stay private.
use super::ObservationGap;
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::Read as _,
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::{Component, Path},
};
const NAME: &str = "osslscope-provider-observation";
const MAX_BYTES: u64 = 16 << 20;
type Identity = (u64, u64, u64, i64, i64, i64, i64);
fn identity(m: &Metadata) -> Identity {
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
fn trusted(m: &Metadata, privileged: bool) -> bool {
    !privileged || (m.uid() == 0 && m.mode() & 0o022 == 0)
}
fn open_at(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, ObservationGap> {
    let name = CString::new(name.as_bytes()).map_err(|_| ObservationGap::BpfUnavailable)?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_NOCTTY
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: live directory FD, terminated pathname; successful FD owned once.
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        Err(ObservationGap::BpfUnavailable)
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}
fn directory(path: &Path, privileged: bool) -> Result<File, ObservationGap> {
    if !path.is_absolute() {
        return Err(ObservationGap::BpfUnavailable);
    }
    let mut file = File::open("/").map_err(|_| ObservationGap::BpfUnavailable)?;
    if !trusted(
        &file
            .metadata()
            .map_err(|_| ObservationGap::BpfUnavailable)?,
        privileged,
    ) {
        return Err(ObservationGap::BpfUnavailable);
    }
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                file = open_at(&file, name, true)?;
                if !trusted(
                    &file
                        .metadata()
                        .map_err(|_| ObservationGap::BpfUnavailable)?,
                    privileged,
                ) {
                    return Err(ObservationGap::BpfUnavailable);
                }
            }
            _ => return Err(ObservationGap::BpfUnavailable),
        }
    }
    Ok(file)
}
fn read_at(parent: &File, privileged: bool) -> Result<Vec<u8>, ObservationGap> {
    let mut file = open_at(parent, std::ffi::OsStr::new(NAME), false)?;
    let before = file
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    if !before.is_file()
        || !trusted(&before, privileged)
        || before.len() == 0
        || before.len() > MAX_BYTES
    {
        return Err(ObservationGap::BpfUnavailable);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    if bytes.len() as u64 != before.len() || identity(&before) != identity(&after) {
        return Err(ObservationGap::BpfUnavailable);
    }
    Ok(bytes)
}
/// File caps (including capabilities other than BPF) and set-ID/root invocations
/// require a root-owned, non-writable file and every ancestor directory.
fn privileged() -> bool {
    // SAFETY: identity queries have no memory operands or side effects.
    if unsafe {
        libc::geteuid() == 0
            || libc::geteuid() != libc::getuid()
            || libc::getegid() != libc::getgid()
    } {
        return true;
    }
    let status = match File::open("/proc/self/status") {
        Ok(file) => file,
        Err(_) => return true,
    };
    let mut bytes = String::new();
    if status.take(65537).read_to_string(&mut bytes).is_err() || bytes.len() > 65536 {
        return true;
    }
    // SAFETY: AT_SECURE is a scalar entry in this observer's auxiliary vector.
    privilege_status(&bytes, unsafe { libc::getauxval(libc::AT_SECURE) } != 0)
}
fn privilege_status(bytes: &str, secure: bool) -> bool {
    secure
        || ["CapEff:", "CapPrm:"].iter().any(|field| {
            bytes
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .is_none_or(|caps| caps != 0)
        })
}

/// Resolve only the sibling or prefix/lib/osslscope fixed basename. Open and
/// verify the host executable before consulting its directory. No CWD/env path.
pub fn load() -> Result<Vec<u8>, ObservationGap> {
    let executable = File::open("/proc/self/exe").map_err(|_| ObservationGap::BpfUnavailable)?;
    let path = std::fs::read_link("/proc/self/exe").map_err(|_| ObservationGap::BpfUnavailable)?;
    load_for(&executable, &path, privileged())
}
fn load_for(executable: &File, path: &Path, privileged: bool) -> Result<Vec<u8>, ObservationGap> {
    let parent_path = path.parent().ok_or(ObservationGap::BpfUnavailable)?;
    let parent = directory(parent_path, privileged)?;
    let reopened = open_at(
        &parent,
        path.file_name().ok_or(ObservationGap::BpfUnavailable)?,
        false,
    )?;
    let expected = executable
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    let actual = reopened
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    if !actual.is_file()
        || !trusted(&actual, privileged)
        || identity(&expected) != identity(&actual)
    {
        return Err(ObservationGap::BpfUnavailable);
    }
    if let Ok(bytes) = read_at(&parent, privileged) {
        return Ok(bytes);
    }
    if parent_path.file_name() != Some(std::ffi::OsStr::new("bin")) {
        return Err(ObservationGap::BpfUnavailable);
    }
    let prefix = parent_path.parent().ok_or(ObservationGap::BpfUnavailable)?;
    read_at(
        &directory(&prefix.join("lib/osslscope"), privileged)?,
        privileged,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    static SEQ: AtomicU64 = AtomicU64::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "osslscope-companion-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            fs::write(p.join("osslscope"), b"host").unwrap();
            Self(p)
        }
        fn load(&self) -> Result<Vec<u8>, ObservationGap> {
            load_for(
                &File::open(self.0.join("osslscope")).unwrap(),
                &self.0.join("osslscope"),
                false,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn all_effective_permitted_and_secure_invocations_require_trusted_companions() {
        assert!(!privilege_status(
            "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n",
            false
        ));
        for (status, secure) in [
            (
                "CapEff:\t000000c000000000\nCapPrm:\t000000c000000000\n",
                false,
            ),
            (
                "CapEff:\t0000000000000000\nCapPrm:\t000000c000000000\n",
                false,
            ),
            (
                "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n",
                true,
            ),
            ("CapEff:\tmalformed\nCapPrm:\t0000000000000000\n", false),
            ("CapEff:\t0000000000000000\n", false),
            ("", false),
        ] {
            assert!(privilege_status(status, secure));
        }
    }
    #[test]
    fn sibling_is_read_from_opened_executable_and_replacement_is_refused() {
        let f = Fixture::new();
        fs::write(f.0.join(NAME), b"companion").unwrap();
        assert_eq!(f.load().unwrap(), b"companion");
        let pinned = File::open(f.0.join("osslscope")).unwrap();
        fs::rename(f.0.join("osslscope"), f.0.join("old")).unwrap();
        fs::write(f.0.join("osslscope"), b"replacement").unwrap();
        assert_eq!(
            load_for(&pinned, &f.0.join("osslscope"), false),
            Err(ObservationGap::BpfUnavailable)
        );
    }
    #[test]
    fn symlink_nonregular_empty_and_oversized_companions_are_refused() {
        let f = Fixture::new();
        let p = f.0.join(NAME);
        fs::write(f.0.join("data"), b"object").unwrap();
        symlink("data", &p).unwrap();
        assert!(f.load().is_err());
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        assert!(f.load().is_err());
        fs::remove_dir(&p).unwrap();
        let file = File::create(&p).unwrap();
        assert!(f.load().is_err());
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(f.load().is_err());
    }
    #[test]
    fn installed_layout_and_symlinked_ancestor_are_handled_without_cwd_lookup() {
        let f = Fixture::new();
        fs::create_dir(f.0.join("bin")).unwrap();
        fs::create_dir_all(f.0.join("lib/osslscope")).unwrap();
        fs::rename(f.0.join("osslscope"), f.0.join("bin/osslscope")).unwrap();
        fs::write(f.0.join("lib/osslscope").join(NAME), b"installed").unwrap();
        let exe = File::open(f.0.join("bin/osslscope")).unwrap();
        assert_eq!(
            load_for(&exe, &f.0.join("bin/osslscope"), false).unwrap(),
            b"installed"
        );
        symlink("bin", f.0.join("linked")).unwrap();
        assert!(load_for(&exe, &f.0.join("linked/osslscope"), false).is_err());
    }
    #[test]
    fn privilege_policy_rejects_user_ownership_and_writable_ancestors() {
        let f = Fixture::new();
        fs::write(f.0.join(NAME), b"object").unwrap();
        assert!(
            load_for(
                &File::open(f.0.join("osslscope")).unwrap(),
                &f.0.join("osslscope"),
                true
            )
            .is_err()
        );
        let metadata = fs::metadata(&f.0).unwrap();
        if metadata.uid() != 0 {
            assert!(!trusted(&metadata, true));
        }
        fs::set_permissions(f.0.join(NAME), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!trusted(&fs::metadata(f.0.join(NAME)).unwrap(), true));
        assert!(directory(Path::new("/usr"), true).is_ok());
    }
}
