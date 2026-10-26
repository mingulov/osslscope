// SPDX-License-Identifier: GPL-3.0-or-later
//! Admission for the finite, file-backed foreground preview.

use anyhow::{Context as _, bail};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::package::trusted::FileIdentity;

#[derive(Debug)]
pub(crate) struct AdmittedProfile {
    backing: File,
    identity: FileIdentity,
    pub profile_id: String,
    pub object: crate::evidence::ObjectRecord,
    pub sites: Vec<crate::count_session::DiscoveredSite>,
    /// The owner may run in a different process. Refer to the observer's
    /// retained descriptor, never its caller-supplied pathname or owner's fd.
    pub locator: PathBuf,
}

impl AdmittedProfile {
    pub(crate) fn verify_backing(&self) -> anyhow::Result<()> {
        if library_identity(&self.backing)? != self.identity {
            bail!("stock library changed after admission");
        }
        Ok(())
    }
}

pub(crate) fn admit(libcrypto: &Path) -> anyhow::Result<AdmittedProfile> {
    if std::env::consts::ARCH != "x86_64" {
        bail!("preview profile requires x86-64");
    }
    let catalogue = parse_catalogue(include_bytes!("../profiles/stock-openssl3-v1.json"))?;
    let (release, build_id) = kernel_identity()?;
    catalogue.check_host(&release, &build_id)?;
    let (backing, identity, bytes) = snapshot_library(libcrypto, catalogue.libcrypto_size)?;
    validate_library(&catalogue, &bytes, identity.uid, identity.mode)?;
    let locator = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        backing.as_raw_fd()
    ));
    let device = crate::plan::encode_device(
        libc::major(identity.dev as libc::dev_t),
        libc::minor(identity.dev as libc::dev_t),
    );
    let sites = catalogue.discovered_sites(device, identity.ino);
    let object = crate::evidence::ObjectRecord {
        id: crate::evidence::ObjectId(catalogue.libcrypto_sha256),
        device,
        inode: identity.ino,
        display_locator: "stock-libcrypto".into(),
    };
    Ok(AdmittedProfile {
        backing,
        identity,
        profile_id: catalogue.id,
        object,
        sites,
        locator,
    })
}

fn library_identity(file: &File) -> anyhow::Result<FileIdentity> {
    let m = file
        .metadata()
        .context("stock library metadata unavailable")?;
    validate_stock_permissions(m.uid(), m.mode())?;
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

fn snapshot_library(path: &Path, size: u64) -> anyhow::Result<(File, FileIdentity, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .context("stock library unreadable")?;
    let before = library_identity(&file)?;
    if before.size != size || size == 0 || size > 64 * 1024 * 1024 {
        bail!("library size is outside the enrolled preview profile");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(size + 1)
        .read_to_end(&mut bytes)
        .context("stock library read failed")?;
    if library_identity(&file)? != before || bytes.len() as u64 != size {
        bail!("stock library changed during admission");
    }
    Ok((file, before, bytes))
}

fn validate_library(
    catalogue: &Catalogue,
    bytes: &[u8],
    uid: u32,
    mode: u32,
) -> anyhow::Result<()> {
    use goblin::elf::{header, program_header};
    validate_stock_permissions(uid, mode)?;
    if bytes.len() as u64 != catalogue.libcrypto_size
        || crate::package::records::sha256(bytes).to_string() != catalogue.libcrypto_sha256
        || crate::discovery::elf::read_build_id(bytes).as_deref()
            != Some(catalogue.libcrypto_build_id.as_str())
    {
        bail!("library identity is outside the enrolled preview profile");
    }
    let elf = crate::discovery::elf::parse_elf(bytes)?;
    if !elf.is_64
        || !elf.little_endian
        || elf.header.e_machine != header::EM_X86_64
        || elf.header.e_type != header::ET_DYN
    {
        bail!("preview library must be an x86-64 little-endian shared ELF object");
    }
    for ph in &elf.program_headers {
        if ph.p_type == program_header::PT_LOAD
            && ph
                .p_offset
                .checked_add(ph.p_filesz)
                .is_none_or(|end| end > bytes.len() as u64)
        {
            bail!("library segment exceeds its file backing");
        }
    }
    for site in &catalogue.sites {
        if !elf.program_headers.iter().any(|ph| {
            ph.p_type == program_header::PT_LOAD
                && ph.p_flags & program_header::PF_X != 0
                && site.offset >= ph.p_offset
                && ph
                    .p_offset
                    .checked_add(ph.p_filesz)
                    .is_some_and(|end| site.offset < end)
        }) {
            bail!("catalogue entry is outside executable file backing");
        }
    }
    Ok(())
}

fn kernel_identity() -> anyhow::Result<(String, String)> {
    // SAFETY: uname initializes this exclusively borrowed, correctly sized struct.
    let mut u = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return Err(std::io::Error::last_os_error()).context("kernel identity unavailable");
    }
    // SAFETY: a successful uname provides a NUL-terminated release field.
    let release = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }
        .to_str()
        .context("kernel release is not UTF-8")?
        .to_owned();
    let mut notes = Vec::new();
    File::open("/sys/kernel/notes")
        .context("kernel build notes unavailable")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut notes)
        .context("kernel build notes unreadable")?;
    if notes.len() > 1024 * 1024 {
        bail!("kernel build notes exceed admission bound");
    }
    let build_id = crate::discovery::elf::parse_build_id_notes(&notes)
        .context("kernel GNU build identity unavailable")?;
    Ok((release, build_id))
}

fn validate_procfs_link(link: &Path, pid: u32) -> anyhow::Result<()> {
    if link != Path::new(&pid.to_string()) {
        bail!("procfs does not refer to the observer's PID namespace");
    }
    Ok(())
}

pub(crate) fn admit_initial_pid_namespaces() -> anyhow::Result<()> {
    validate_procfs_link(
        &std::fs::read_link("/proc/self").context("observer procfs identity unavailable")?,
        std::process::id(),
    )?;
    admit_namespace_paths(Path::new("/proc/self"))
}

pub(crate) fn admit_child_pid_namespace(pid: u32) -> anyhow::Result<()> {
    if pid == 0 {
        bail!("preview requires a nonzero owned PID");
    }
    admit_namespace_paths(&PathBuf::from(format!("/proc/{pid}")))
}

fn admit_namespace_paths(proc: &Path) -> anyhow::Result<()> {
    let current = File::open(proc.join("ns/pid")).context("PID namespace handle unavailable")?;
    let child = File::open(proc.join("ns/pid_for_children"))
        .context("PID-for-children namespace handle unavailable")?;
    let (kind, id) = read_namespace_identity(&current)?;
    let (child_kind, child_id) = read_namespace_identity(&child)?;
    validate_namespace_pair(kind, id, child_kind, child_id)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalogue {
    format_version: u32,
    id: String,
    kernel_release: String,
    kernel_build_id: String,
    libcrypto_sha256: String,
    libcrypto_build_id: String,
    libcrypto_size: u64,
    sites: Vec<CatalogueSite>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogueSite {
    offset: u64,
    complete: bool,
    candidates: Vec<CatalogueCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogueCandidate {
    op: u32,
    funcid: u32,
    algorithm_classes: Vec<String>,
    weak_alias: bool,
}

fn lower_hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn parse_catalogue(bytes: &[u8]) -> anyhow::Result<Catalogue> {
    let mut catalogue: Catalogue =
        serde_json::from_slice(bytes).context("invalid built-in catalogue")?;
    if catalogue.format_version != 1
        || catalogue.id.is_empty()
        || catalogue.id.len() > 128
        || !catalogue
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || catalogue.kernel_release.is_empty()
        || !lower_hex(&catalogue.kernel_build_id, 20)
        || !lower_hex(&catalogue.libcrypto_build_id, 20)
        || !lower_hex(&catalogue.libcrypto_sha256, 32)
        || catalogue.libcrypto_size == 0
        || catalogue.libcrypto_size > 64 * 1024 * 1024
        || catalogue.sites.is_empty()
        || catalogue.sites.len() > 64
    {
        bail!("unsupported built-in catalogue identity or bounds");
    }
    let mut offsets = BTreeSet::new();
    for site in &catalogue.sites {
        if site.offset >= catalogue.libcrypto_size
            || !offsets.insert(site.offset)
            || site.candidates.is_empty()
            || site.candidates.len() > 128
        {
            bail!("invalid physical catalogue entry");
        }
        for candidate in &site.candidates {
            if !matches!(candidate.op, 1 | 2)
                || candidate.funcid == 0
                || candidate.algorithm_classes.is_empty()
                || candidate.algorithm_classes.len() > 32
                || candidate
                    .algorithm_classes
                    .iter()
                    .any(|name| !crate::kinds::is_known_alg(name))
            {
                bail!("invalid finite catalogue candidate");
            }
            let meanings: BTreeSet<_> = candidate
                .algorithm_classes
                .iter()
                .map(|name| crate::kinds::algorithm_semantic_id(name))
                .collect();
            if meanings.len() != 1 || meanings.contains(&None) {
                bail!("catalogue candidate combines different algorithm meanings");
            }
        }
    }
    catalogue.sites.sort_by_key(|site| site.offset);
    Ok(catalogue)
}

impl Catalogue {
    fn check_host(&self, release: &str, build_id: &str) -> anyhow::Result<()> {
        if release != self.kernel_release || build_id != self.kernel_build_id {
            bail!("kernel build is outside the enrolled preview profile");
        }
        Ok(())
    }

    fn discovered_sites(
        &self,
        device: u64,
        inode: u64,
    ) -> Vec<crate::count_session::DiscoveredSite> {
        use crate::evidence::{CandidateCoverage, CandidateIdentity, ObjectId, SiteKey};
        let object = ObjectId(self.libcrypto_sha256.clone());
        self.sites
            .iter()
            .map(|entry| crate::count_session::DiscoveredSite {
                site: SiteKey {
                    object: object.clone(),
                    device,
                    inode,
                    offset: entry.offset,
                },
                candidates: entry
                    .candidates
                    .iter()
                    .map(|c| {
                        CandidateIdentity::new(
                            object.clone(),
                            "default".into(),
                            c.op,
                            c.funcid,
                            c.algorithm_classes.clone(),
                            c.weak_alias,
                        )
                    })
                    .collect(),
                candidates_coverage: if entry.complete {
                    CandidateCoverage::Complete
                } else {
                    CandidateCoverage::Unknown
                },
            })
            .collect()
    }
}

const INITIAL_PID_NAMESPACE_ID: u64 = 4;
// Linux v7.0 uapi/linux/nsfs.h, for the supported x86-64 profile.
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NS_GET_ID: libc::c_ulong = 0x8008_b70d;

fn validate_namespace_pair(
    kind: i32,
    id: u64,
    child_kind: i32,
    child_id: u64,
) -> anyhow::Result<()> {
    if kind != libc::CLONE_NEWPID
        || child_kind != libc::CLONE_NEWPID
        || id != INITIAL_PID_NAMESPACE_ID
        || child_id != INITIAL_PID_NAMESPACE_ID
    {
        bail!("preview requires the initial PID namespace for observer and children");
    }
    Ok(())
}

fn validate_stock_permissions(uid: u32, mode: u32) -> anyhow::Result<()> {
    if uid != 0 || mode & libc::S_IFMT != libc::S_IFREG || mode & 0o022 != 0 {
        bail!("preview requires root-owned regular stock code without group/other write access");
    }
    Ok(())
}

fn read_namespace_identity(file: &File) -> anyhow::Result<(i32, u64)> {
    // SAFETY: the first ioctl has no output argument. The second writes one
    // aligned u64 owned by this call; the fd remains live throughout both calls.
    let kind = unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE) };
    if kind < 0 {
        return Err(std::io::Error::last_os_error()).context("PID namespace type unavailable");
    }
    let mut id = 0u64;
    if unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_ID, &mut id) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("PID namespace identifier unavailable");
    }
    Ok((kind, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal ELF shared object with one executable segment and a GNU note.
    // This exercises admission, never stands in for live callback qualification.
    fn library_fixture() -> (Catalogue, Vec<u8>) {
        let mut bytes = vec![0u8; 512];
        bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // program headers
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        bytes[96..104].copy_from_slice(&512u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&512u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&4u32.to_le_bytes()); // PT_NOTE
        bytes[128..136].copy_from_slice(&256u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&36u64.to_le_bytes());
        bytes[160..168].copy_from_slice(&36u64.to_le_bytes());
        bytes[256..260].copy_from_slice(&4u32.to_le_bytes());
        bytes[260..264].copy_from_slice(&20u32.to_le_bytes());
        bytes[264..268].copy_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        bytes[268..272].copy_from_slice(b"GNU\0");
        bytes[272..292].fill(0x51);
        bytes[400] = 0xc3;
        let mut catalogue =
            parse_catalogue(include_bytes!("../profiles/stock-openssl3-v1.json")).unwrap();
        catalogue.libcrypto_sha256 = crate::package::records::sha256(&bytes).to_string();
        catalogue.libcrypto_build_id = "51".repeat(20);
        catalogue.libcrypto_size = bytes.len() as u64;
        catalogue.sites.truncate(1);
        catalogue.sites[0].offset = 400;
        (catalogue, bytes)
    }

    #[test]
    fn unknown_or_replaced_library_refuses() {
        let (mut catalogue, mut bytes) = library_fixture();
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_ok());
        bytes[400] ^= 1;
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_err());
        bytes[400] ^= 1;
        catalogue.libcrypto_build_id = "52".repeat(20);
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_err());
        catalogue.libcrypto_build_id = "51".repeat(20);
        assert!(validate_library(&catalogue, &bytes[..511], 0, libc::S_IFREG | 0o644).is_err());
    }

    #[test]
    fn writable_or_nonexec_site_refuses() {
        let (mut catalogue, mut bytes) = library_fixture();
        assert!(validate_library(&catalogue, &bytes, 1000, libc::S_IFREG | 0o644).is_err());
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o666).is_err());
        bytes[68..72].copy_from_slice(&4u32.to_le_bytes()); // remove PF_X
        catalogue.libcrypto_sha256 = crate::package::records::sha256(&bytes).to_string();
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_err());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[96..104].copy_from_slice(&u64::MAX.to_le_bytes());
        catalogue.libcrypto_sha256 = crate::package::records::sha256(&bytes).to_string();
        assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_err());
    }

    #[test]
    fn library_must_be_a_native_shared_object() {
        for (offset, value) in [(16, 2u16), (18, 183u16)] {
            let (mut catalogue, mut bytes) = library_fixture();
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            catalogue.libcrypto_sha256 = crate::package::records::sha256(&bytes).to_string();
            assert!(validate_library(&catalogue, &bytes, 0, libc::S_IFREG | 0o644).is_err());
        }
    }

    #[test]
    fn procfs_must_name_the_observer_pid() {
        assert!(validate_procfs_link(std::path::Path::new("42"), 42).is_ok());
        assert!(validate_procfs_link(std::path::Path::new("41"), 42).is_err());
        assert!(validate_procfs_link(std::path::Path::new("42/task/42"), 42).is_err());
    }

    #[test]
    fn library_snapshot_refuses_special_files() {
        assert!(snapshot_library(std::path::Path::new("/dev/null"), 512).is_err());
    }

    #[test]
    #[ignore = "requires the enrolled host and stock libcrypto; metadata admission only"]
    fn enrolled_host_metadata_admission() {
        admit_initial_pid_namespaces().unwrap();
        admit_child_pid_namespace(std::process::id()).unwrap();
        let profile = admit(Path::new("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")).unwrap();
        profile.verify_backing().unwrap();
        assert_eq!(profile.profile_id, "ubuntu2604-openssl355-v1");
        assert_eq!(profile.sites.len(), 3);
        assert!(
            profile
                .sites
                .iter()
                .all(|s| s.site.device == profile.object.device
                    && s.site.inode == profile.object.inode
                    && s.site.object == profile.object.id)
        );
        let pinned = crate::plan::resolve_pinned(profile.locator.to_str().unwrap()).unwrap();
        assert_eq!(pinned.device, profile.object.device);
        assert_eq!(pinned.ino, profile.object.inode);
    }

    #[test]
    fn namespace_requires_pid_type_initial_id_and_child_match() {
        assert!(validate_namespace_pair(libc::CLONE_NEWPID, 4, libc::CLONE_NEWPID, 4).is_ok());
        for (kind, id, child_kind, child_id) in [
            (libc::CLONE_NEWUSER, 4, libc::CLONE_NEWPID, 4),
            (libc::CLONE_NEWPID, 10, libc::CLONE_NEWPID, 4),
            (libc::CLONE_NEWPID, 4, libc::CLONE_NEWUSER, 4),
            (libc::CLONE_NEWPID, 4, libc::CLONE_NEWPID, 11),
        ] {
            assert!(validate_namespace_pair(kind, id, child_kind, child_id).is_err());
        }
    }

    #[test]
    fn stock_backing_rejects_target_owned_or_writable_files() {
        assert!(validate_stock_permissions(0, libc::S_IFREG | 0o644).is_ok());
        assert!(validate_stock_permissions(1000, libc::S_IFREG | 0o444).is_err());
        assert!(validate_stock_permissions(0, libc::S_IFREG | 0o664).is_err());
        assert!(validate_stock_permissions(0, libc::S_IFREG | 0o646).is_err());
        assert!(validate_stock_permissions(0, libc::S_IFDIR | 0o755).is_err());
    }

    #[test]
    fn namespace_reader_rejects_non_namespace_fds() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(read_namespace_identity(&file).is_err());
    }

    #[test]
    fn builtin_catalogue_keeps_shared_candidates_at_one_physical_site() {
        let catalogue =
            parse_catalogue(include_bytes!("../profiles/stock-openssl3-v1.json")).unwrap();
        let sites = catalogue.discovered_sites(37, 99);
        assert_eq!(sites.len(), 3);
        let shared = sites.iter().find(|s| s.site.offset == 0x472bc0).unwrap();
        assert_eq!(shared.candidates.len(), 7);
        assert_eq!(
            shared.candidates_coverage,
            crate::evidence::CandidateCoverage::Complete
        );
        assert!(
            sites
                .iter()
                .all(|s| s.site.device == 37 && s.site.inode == 99)
        );
        assert_eq!(
            shared
                .candidates
                .iter()
                .map(|c| &c.algorithm_classes[0])
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            7
        );
    }

    #[test]
    fn catalogue_rejects_unknown_classes_and_duplicate_physical_entries() {
        let original: serde_json::Value =
            serde_json::from_slice(include_bytes!("../profiles/stock-openssl3-v1.json")).unwrap();
        let mut unknown = original.clone();
        unknown["sites"][0]["candidates"][0]["algorithm_classes"][0] =
            serde_json::json!("unrecognized-target-bytes");
        assert!(parse_catalogue(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut duplicate = original;
        let first = duplicate["sites"][0].clone();
        duplicate["sites"].as_array_mut().unwrap().push(first);
        assert!(parse_catalogue(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }

    #[test]
    fn unknown_catalogue_union_does_not_become_complete() {
        let mut value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../profiles/stock-openssl3-v1.json")).unwrap();
        value["sites"][0]["complete"] = serde_json::json!(false);
        let catalogue = parse_catalogue(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            catalogue.discovered_sites(1, 2)[0].candidates_coverage,
            crate::evidence::CandidateCoverage::Unknown
        );
    }

    #[test]
    fn kernel_release_and_build_identity_are_both_required() {
        let catalogue =
            parse_catalogue(include_bytes!("../profiles/stock-openssl3-v1.json")).unwrap();
        assert!(
            catalogue
                .check_host(
                    "7.0.0-38-generic",
                    "338e542e384c46228f7a378babc0f9bb2b6a5997"
                )
                .is_ok()
        );
        assert!(
            catalogue
                .check_host(
                    "7.0.0-39-generic",
                    "338e542e384c46228f7a378babc0f9bb2b6a5997"
                )
                .is_err()
        );
        assert!(
            catalogue
                .check_host(
                    "7.0.0-38-generic",
                    "0000000000000000000000000000000000000000"
                )
                .is_err()
        );
    }
}
