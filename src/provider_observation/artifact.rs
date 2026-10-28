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
#[derive(Clone, Copy)]
pub(crate) enum Companion {
    Observation,
    FocusedCount,
}
impl Companion {
    fn name(self) -> &'static str {
        match self {
            Self::Observation => NAME,
            Self::FocusedCount => "osslscope-focused-count",
        }
    }
}
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
fn read_at(parent: &File, privileged: bool, name: &str) -> Result<Vec<u8>, ObservationGap> {
    read_at_limit(parent, privileged, name, MAX_BYTES)
}
fn read_at_limit(
    parent: &File,
    privileged: bool,
    name: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, ObservationGap> {
    let mut file = open_at(parent, std::ffi::OsStr::new(name), false)?;
    let before = file
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    if !before.is_file()
        || !trusted(&before, privileged)
        || before.len() == 0
        || before.len() > max_bytes
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
    load_companion(Companion::Observation)
}
pub(crate) fn load_companion(role: Companion) -> Result<Vec<u8>, ObservationGap> {
    let executable = File::open("/proc/self/exe").map_err(|_| ObservationGap::BpfUnavailable)?;
    let path = std::fs::read_link("/proc/self/exe").map_err(|_| ObservationGap::BpfUnavailable)?;
    load_role_for(&executable, &path, privileged(), role)
}
#[cfg(test)]
fn load_for(executable: &File, path: &Path, privileged: bool) -> Result<Vec<u8>, ObservationGap> {
    load_role_for(executable, path, privileged, Companion::Observation)
}
fn load_role_for(
    executable: &File,
    path: &Path,
    privileged: bool,
    role: Companion,
) -> Result<Vec<u8>, ObservationGap> {
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
    if parent_path.file_name() != Some(std::ffi::OsStr::new("bin")) {
        // Explicit development layout. Installed prefixes always use the
        // protected current receipt below, even if a sibling object exists.
        return read_at(&parent, privileged, role.name());
    }
    let prefix = parent_path.parent().ok_or(ObservationGap::BpfUnavailable)?;
    let receipts = directory(&prefix.join("share/osslscope"), privileged)?;
    let receipt_bytes = read_at_limit(&receipts, privileged, "install-manifest.json", 1 << 20)?;
    let receipt = crate::package::installed::InstalledReceipt::parse(&receipt_bytes, prefix)
        .ok_or(ObservationGap::BpfUnavailable)?;
    let (host_bytes, host_digest) = executable_digest(&reopened)?;
    if !receipt.matches("osslscope", host_bytes, &host_digest) {
        return Err(ObservationGap::BpfUnavailable);
    }
    let objects = directory(&prefix.join("lib/osslscope"), privileged)?;
    let mut selected = None;
    for name in crate::package::installed::CURRENT_NAMES.into_iter().skip(1) {
        let bytes = read_at(&objects, privileged, name)?;
        if !receipt.matches(name, bytes.len() as u64, &digest(&bytes)) {
            return Err(ObservationGap::BpfUnavailable);
        }
        if name == role.name() {
            selected = Some(bytes);
        }
    }
    selected.ok_or(ObservationGap::BpfUnavailable)
}
fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn executable_digest(file: &File) -> Result<(u64, String), ObservationGap> {
    use sha2::Digest as _;
    use std::os::unix::fs::FileExt as _;
    let before = file
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    // Debug development binaries can exceed the BPF object bound. Stream a
    // separate host bound; no allocation proportional to the executable.
    if before.len() == 0 || before.len() > 256 << 20 {
        return Err(ObservationGap::BpfUnavailable);
    }
    let mut hash = sha2::Sha256::new();
    let mut offset = 0;
    let mut buffer = [0; 65536];
    loop {
        let count = file
            .read_at(&mut buffer, offset)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        if count == 0 {
            break;
        }
        offset += count as u64;
        if offset > before.len() {
            return Err(ObservationGap::BpfUnavailable);
        }
        hash.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| ObservationGap::BpfUnavailable)?;
    if offset != before.len() || identity(&before) != identity(&after) {
        return Err(ObservationGap::BpfUnavailable);
    }
    Ok((
        offset,
        hash.finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
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
    fn install_fixture() -> Fixture {
        let f = Fixture::new();
        fs::create_dir(f.0.join("bin")).unwrap();
        fs::create_dir_all(f.0.join("lib/osslscope")).unwrap();
        fs::create_dir_all(f.0.join("share/osslscope")).unwrap();
        fs::rename(f.0.join("osslscope"), f.0.join("bin/osslscope")).unwrap();
        let mut arts = Vec::new();
        for name in [
            "osslscope",
            "osslscope-harvest",
            "osslscope-count",
            "osslscope-members",
            NAME,
            "osslscope-focused-count",
        ] {
            let dest = if name == "osslscope" {
                f.0.join("bin/osslscope")
            } else {
                f.0.join("lib/osslscope").join(name)
            };
            if name != "osslscope" {
                fs::write(&dest, name.as_bytes()).unwrap();
            }
            let bytes = fs::read(&dest).unwrap();
            use sha2::Digest as _;
            let hash = sha2::Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let mut entry = serde_json::json!({"role": if name == "osslscope" { "host-binary" } else { "bpf-object" }, "dest": dest, "bytes": bytes.len(), "sha256": hash, "product_ref": "a".repeat(40)});
            if name != "osslscope" {
                entry["bin"] = name.into();
            }
            arts.push(entry);
        }
        fs::write(f.0.join("share/osslscope/install-manifest.json"), serde_json::to_vec(&serde_json::json!({"schema": "osslscope-install-manifest-v2", "prefix": f.0, "product_ref": "a".repeat(40), "product_dirty": false, "artifacts": arts})).unwrap()).unwrap();
        f
    }
    fn installed_load(f: &Fixture, role: Companion) -> Result<Vec<u8>, ObservationGap> {
        load_role_for(
            &File::open(f.0.join("bin/osslscope")).unwrap(),
            &f.0.join("bin/osslscope"),
            false,
            role,
        )
    }
    #[test]
    fn installed_five_roles_bind_both_companions_and_running_host() {
        let f = install_fixture();
        for role in [Companion::Observation, Companion::FocusedCount] {
            assert_eq!(installed_load(&f, role).unwrap(), role.name().as_bytes());
        }
        fs::write(f.0.join("bin/osslscope"), b"different host").unwrap();
        assert!(installed_load(&f, Companion::Observation).is_err());
    }
    #[test]
    fn installed_set_rejects_each_missing_mutated_or_symlinked_role() {
        for name in [
            "osslscope-harvest",
            "osslscope-count",
            "osslscope-members",
            NAME,
            "osslscope-focused-count",
        ] {
            for mutation in 0..3 {
                let f = install_fixture();
                let path = f.0.join("lib/osslscope").join(name);
                if mutation == 0 {
                    fs::remove_file(&path).unwrap();
                }
                if mutation == 1 {
                    fs::write(&path, b"mutated bytes").unwrap();
                }
                if mutation == 2 {
                    fs::remove_file(&path).unwrap();
                    symlink("../elsewhere", &path).unwrap();
                }
                for role in [Companion::Observation, Companion::FocusedCount] {
                    assert!(
                        installed_load(&f, role).is_err(),
                        "{name} mutation {mutation}"
                    );
                }
            }
        }
    }
    #[test]
    fn installed_set_rejects_missing_legacy_mixed_duplicate_receipts_and_sibling_bypass() {
        for mutation in 0..7 {
            let f = install_fixture();
            let path = f.0.join("share/osslscope/install-manifest.json");
            let mut receipt: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match mutation {
                0 => {
                    fs::remove_file(&path).unwrap();
                }
                1 => {
                    receipt["schema"] = "osslscope-install-manifest-v1".into();
                }
                2 => {
                    receipt["artifacts"].as_array_mut().unwrap().truncate(4);
                }
                3 => {
                    receipt["artifacts"][4]["product_ref"] = "b".repeat(40).into();
                }
                4 => {
                    let dupe = receipt["artifacts"][3].clone();
                    receipt["artifacts"][4] = dupe;
                }
                5 => {
                    receipt["artifacts"][4]["dest"] =
                        "/elsewhere/osslscope-provider-observation".into();
                }
                _ => {
                    receipt["artifacts"][0]["sha256"] = "0".repeat(64).into();
                }
            }
            if mutation != 0 {
                fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
            }
            fs::write(f.0.join("bin").join(NAME), b"unreceipted sibling").unwrap();
            assert!(
                installed_load(&f, Companion::Observation).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn focused_pair_uses_the_same_nofollow_and_retained_executable_policy() {
        for role in [Companion::Observation, Companion::FocusedCount] {
            let f = Fixture::new();
            let name = role.name();
            fs::write(f.0.join(name), b"companion").unwrap();
            let exe = File::open(f.0.join("osslscope")).unwrap();
            assert_eq!(
                load_role_for(&exe, &f.0.join("osslscope"), false, role).unwrap(),
                b"companion"
            );
            fs::remove_file(f.0.join(name)).unwrap();
            fs::write(f.0.join("data"), b"replacement").unwrap();
            symlink("data", f.0.join(name)).unwrap();
            assert!(load_role_for(&exe, &f.0.join("osslscope"), false, role).is_err());
            fs::remove_file(f.0.join(name)).unwrap();
            fs::write(f.0.join(name), b"companion").unwrap();
            fs::set_permissions(f.0.join(name), fs::Permissions::from_mode(0o666)).unwrap();
            assert!(load_role_for(&exe, &f.0.join("osslscope"), true, role).is_err());
            fs::rename(f.0.join("osslscope"), f.0.join("old")).unwrap();
            fs::write(f.0.join("osslscope"), b"new host").unwrap();
            assert!(load_role_for(&exe, &f.0.join("osslscope"), false, role).is_err());
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
        let f = install_fixture();
        let exe = File::open(f.0.join("bin/osslscope")).unwrap();
        assert_eq!(
            load_for(&exe, &f.0.join("bin/osslscope"), false).unwrap(),
            NAME.as_bytes()
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
