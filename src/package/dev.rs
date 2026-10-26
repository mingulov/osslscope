// SPDX-License-Identifier: GPL-3.0-or-later
//! Operator-selected v2 snapshots and the descriptor-free development producer.
use super::{PackageError, records::*, resolve::RoleSnapshot, trusted::FileIdentity};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
const RECORD_LIMIT: u64 = 1_048_576;
const ELF_LIMIT: u64 = 536_870_912;

pub struct CustodyArtifactSnapshot {
    pub(crate) locator: PathBuf,
    pub(crate) identity: FileIdentity,
    pub(crate) sha256: Digest,
    pub(crate) length: u64,
}
#[non_exhaustive]
pub struct AdmittedIdentity {
    pub(crate) object_bytes: Arc<[u8]>,
    pub(crate) object_sha256: Digest,
    pub(crate) profile_sha256: Digest,
    pub(crate) custody: CustodyArtifactSnapshot,
    pub(crate) custody_protocol: u32,
}
impl CustodyArtifactSnapshot {
    pub fn locator(&self) -> &Path {
        &self.locator
    }
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }
    pub fn sha256(&self) -> Digest {
        self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}
impl AdmittedIdentity {
    pub fn object_bytes(&self) -> &Arc<[u8]> {
        &self.object_bytes
    }
    pub fn object_sha256(&self) -> Digest {
        self.object_sha256
    }
    pub fn profile_sha256(&self) -> Digest {
        self.profile_sha256
    }
    pub fn custody(&self) -> &CustodyArtifactSnapshot {
        &self.custody
    }
    pub fn custody_protocol(&self) -> u32 {
        self.custody_protocol
    }
    /// Data admission is not proof of the current identity/service/adapter gates.
    pub fn require_activation(&self) -> Result<(), PackageError> {
        Err(PackageError::unavailable(
            "identity v2 activation unavailable: accepted profile, custody and reader authority required",
        ))
    }
}
pub struct VerifiedDevelopment {
    pub(crate) contract: Box<BundleContractV2>,
    pub(crate) identity: Box<AdmittedIdentity>,
    pub(crate) roles: BTreeMap<Role, RoleSnapshot>,
}
impl VerifiedDevelopment {
    pub fn contract(&self) -> &BundleContractV2 {
        &self.contract
    }
}
struct Snapshot {
    locator: PathBuf,
    identity: FileIdentity,
    bytes: Arc<[u8]>,
    digest: Digest,
}
struct Root {
    fd: File,
    path: PathBuf,
}
fn io_error(error: std::io::Error) -> PackageError {
    PackageError::unreadable(format!("development artifact: {error}"))
}
fn file_identity(file: &File) -> Result<FileIdentity, PackageError> {
    let m = file.metadata().map_err(io_error)?;
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
fn snapshot_file(mut file: File, locator: PathBuf, limit: u64) -> Result<Snapshot, PackageError> {
    let before = file_identity(&file)?;
    if before.mode & libc::S_IFMT != libc::S_IFREG || before.size == 0 || before.size > limit {
        return Err(PackageError::invalid(
            "development artifact type/size bound",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = file_identity(&file)?;
    if before != after || bytes.len() as u64 != after.size {
        return Err(PackageError::Mutated {
            context: "development artifact changed during snapshot".into(),
        });
    }
    let digest = sha256(&bytes);
    Ok(Snapshot {
        locator,
        identity: after,
        bytes: bytes.into(),
        digest,
    })
}
impl Root {
    fn open(path: &Path) -> Result<Self, PackageError> {
        use std::path::Component;
        if path.as_os_str().is_empty() {
            return Err(PackageError::invalid("empty development directory"));
        }
        let mut fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            })
            .map_err(io_error)?;
        for part in path.components() {
            let name = match part {
                Component::RootDir | Component::CurDir => continue,
                Component::ParentDir => CString::new("..").unwrap(),
                Component::Normal(name) => CString::new(name.as_encoded_bytes())
                    .map_err(|_| PackageError::invalid("development directory component"))?,
                _ => {
                    return Err(PackageError::invalid(
                        "development directory prefix component",
                    ));
                }
            };
            let raw = unsafe {
                libc::openat(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            fd = unsafe { File::from_raw_fd(raw) };
        }
        Ok(Self {
            fd,
            path: path.to_owned(),
        })
    }
    fn read(&self, name: &str, limit: u64) -> Result<Snapshot, PackageError> {
        // All companions have fixed single-component names, anchored to this FD.
        if name.contains('/') {
            return Err(PackageError::invalid(
                "development companion must be a fixed filename",
            ));
        }
        let c = CString::new(name).map_err(|_| PackageError::invalid("development filename"))?;
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(raw) };
        snapshot_file(file, self.path.join(name), limit)
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), PackageError> {
        let temporary = format!(".{name}.{}.tmp", std::process::id());
        let c = CString::new(temporary.clone()).unwrap();
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        let result = (|| {
            let mut file = unsafe { File::from_raw_fd(raw) };
            file.write_all(bytes).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            drop(file);
            let dest = CString::new(name).unwrap();
            if unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    self.fd.as_raw_fd(),
                    dest.as_ptr(),
                )
            } < 0
            {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            self.fd.sync_all().map_err(io_error)
        })();
        if result.is_err() {
            unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) };
        }
        result
    }
}
fn content(s: &Snapshot, name: &str) -> ContentEntry {
    ContentEntry {
        path: RelativePath::new(name).unwrap(),
        sha256: s.digest,
        bytes: s.bytes.len() as u64,
    }
}
fn check_content(s: &Snapshot, e: &ContentEntry) -> Result<(), PackageError> {
    if s.digest != e.sha256 || s.bytes.len() as u64 != e.bytes {
        return Err(PackageError::invalid(
            "development content hash/length mismatch",
        ));
    }
    Ok(())
}
fn host_entry(s: &Snapshot, name: &str) -> Result<HostEntry, PackageError> {
    let elf = goblin::elf::Elf::parse(&s.bytes)
        .map_err(|_| PackageError::invalid("development host is not ELF"))?;
    if elf.header.e_machine != 62 || !elf.little_endian || !elf.is_64 {
        return Err(PackageError::invalid("development host ELF identity"));
    }
    Ok(HostEntry {
        path: RelativePath::new(name)?,
        sha256: s.digest,
        bytes: s.bytes.len() as u64,
        elf_machine: elf.header.e_machine,
        elf_build_id: crate::discovery::elf::read_build_id(&s.bytes),
    })
}
fn check_host(s: &Snapshot, entry: &HostEntry, name: &str) -> Result<(), PackageError> {
    if host_entry(s, name)? != *entry {
        return Err(PackageError::invalid("development host ELF/hash mismatch"));
    }
    Ok(())
}
fn verify_policy(c: &BundleContractV2) -> Result<(), PackageError> {
    let (wire, digest) = super::resolve::compiled_loader_identity(RecordVersion::V2)?;
    if c.wire_abi != wire || c.loader_contract_sha256 != digest {
        return Err(PackageError::invalid(
            "compiled v2 wire/loader policy mismatch",
        ));
    }
    Ok(())
}
fn read_roles(
    root: &Root,
    entries: Option<&[RoleEntry]>,
) -> Result<BTreeMap<Role, RoleSnapshot>, PackageError> {
    let mut remaining = ELF_LIMIT;
    let mut roles = BTreeMap::new();
    for role in [Role::Harvest, Role::Count, Role::Members, Role::Identity] {
        let s = root.read(role.file_name(), remaining)?;
        if let Some(entries) = entries {
            let e = entries
                .iter()
                .find(|e| e.role == role)
                .ok_or_else(|| PackageError::invalid("missing v2 role"))?;
            if e.sha256 != s.digest || e.bytes != s.bytes.len() as u64 {
                return Err(PackageError::invalid("v2 role hash/length mismatch"));
            }
        }
        crate::discovery::onboard::check_v2_role_compatible(role, &s.bytes)?;
        remaining -= s.bytes.len() as u64;
        roles.insert(
            role,
            RoleSnapshot {
                locator: s.locator,
                identity: s.identity,
                sha256: s.digest,
                length: s.bytes.len() as u64,
                bytes: s.bytes,
                loader_validated: true,
            },
        );
    }
    Ok(roles)
}
fn role_entries(roles: &BTreeMap<Role, RoleSnapshot>) -> Vec<RoleEntry> {
    [Role::Harvest, Role::Count, Role::Members, Role::Identity]
        .into_iter()
        .map(|role| {
            let s = &roles[&role];
            RoleEntry {
                role,
                file: RelativePath::new(role.file_name()).unwrap(),
                sha256: s.sha256,
                bytes: s.length,
            }
        })
        .collect()
}
fn admit(
    root: &Root,
    embedded: Option<&[u8]>,
) -> Result<(VerifiedDevelopment, Snapshot), PackageError> {
    let record = root.read("dev-admission.json", RECORD_LIMIT)?;
    let dev: DevAdmissionV2 = parse_canonical(&record.bytes)?;
    let input = root.read("build-inputs.json", RECORD_LIMIT)?;
    check_content(&input, &dev.build_inputs)?;
    let inputs: BuildInputsV2 = parse_canonical(&input.bytes)?;
    let contract = root.read("bundle-contract.json", RECORD_LIMIT)?;
    check_content(&contract, &dev.contract)?;
    let c: BundleContractV2 = parse_canonical(&contract.bytes)?;
    verify_contract_v2(&c, &inputs, &input.bytes)?;
    verify_policy(&c)?;
    if dev.custody_host != c.custody_host || dev.roles != c.roles {
        return Err(PackageError::invalid("dev/contract binding mismatch"));
    }
    if embedded.is_some_and(|bytes| bytes != contract.bytes.as_ref()) {
        return Err(PackageError::invalid(
            "selected dev/embedded contract mismatch",
        ));
    }
    if inputs.product_version != env!("CARGO_PKG_VERSION")
        || inputs.host_profile.target != env!("OSSL_PACKAGE_HOST_TARGET")
    {
        return Err(PackageError::invalid(
            "development executing profile mismatch",
        ));
    }
    let host = root.read("osslscope", ELF_LIMIT)?;
    check_host(&host, &dev.host, "osslscope")?;
    if super::build::extract_host_contract(&host.bytes)? != AdmittedContract::V2(c.clone()) {
        return Err(PackageError::invalid(
            "development observer embedded contract mismatch",
        ));
    }
    let custody = root.read("osslscope-identity-custodian", ELF_LIMIT)?;
    check_host(&custody, &c.custody_host, "osslscope-identity-custodian")?;
    if has_contract_section(&custody.bytes)? {
        return Err(PackageError::invalid(
            "custody host must be descriptor-free",
        ));
    }
    let artifact = CustodyArtifactSnapshot {
        locator: custody.locator,
        identity: custody.identity,
        sha256: custody.digest,
        length: custody.bytes.len() as u64,
    };
    drop(custody.bytes);
    let custody = artifact;
    let roles = read_roles(root, Some(&c.roles))?;
    let object = &roles[&Role::Identity];
    let identity = AdmittedIdentity {
        object_bytes: Arc::clone(&object.bytes),
        object_sha256: object.sha256,
        profile_sha256: c.identity_profile_sha256,
        custody,
        custody_protocol: c.custody_protocol,
    };
    Ok((
        VerifiedDevelopment {
            contract: Box::new(c),
            identity: Box::new(identity),
            roles,
        },
        host,
    ))
}
pub fn resolve_dev_bundle(
    dir: &Path,
    embedded: Option<&[u8]>,
) -> Result<super::commands::AdmittedSet, PackageError> {
    let root = Root::open(dir)?;
    let (admitted, host) = admit(&root, embedded)?;
    let current = snapshot_file(
        File::open("/proc/self/exe").map_err(io_error)?,
        PathBuf::from("/proc/self/exe"),
        ELF_LIMIT,
    )?;
    if current.digest != host.digest || current.bytes.as_ref() != host.bytes.as_ref() {
        return Err(PackageError::invalid(
            "development observer differs from executing host",
        ));
    }

    Ok(super::commands::AdmittedSet::Development(admitted))
}
/// Freeze the actual descriptor-free outputs before embedding only the observer.
pub fn produce_contract(inputs_path: &Path, dir: &Path) -> Result<(), PackageError> {
    let root = Root::open(dir)?;
    let input = snapshot_file(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(inputs_path)
            .map_err(io_error)?,
        inputs_path.to_owned(),
        RECORD_LIMIT,
    )?;
    let inputs: BuildInputsV2 = parse_canonical(&input.bytes)?;
    if inputs.product_version != env!("CARGO_PKG_VERSION") {
        return Err(PackageError::invalid(
            "development product version mismatch",
        ));
    }
    let custody = root.read("osslscope-identity-custodian", ELF_LIMIT)?;
    let custody_host = host_entry(&custody, "osslscope-identity-custodian")?;
    if has_contract_section(&custody.bytes)? {
        return Err(PackageError::invalid(
            "custody must be built descriptor-free",
        ));
    }
    drop(custody);
    let roles = read_roles(&root, None)?;
    let (wire_abi, loader_contract_sha256) =
        super::resolve::compiled_loader_identity(RecordVersion::V2)?;
    let contract = BundleContractV2 {
        schema: "osslscope-bundle-contract-v2".into(),
        input_id: input.digest,
        source: inputs.source.clone(),
        product_version: inputs.product_version.clone(),
        host_profile: inputs.host_profile.clone(),
        wire_abi,
        loader_contract_sha256,
        roles: role_entries(&roles),
        identity_abi: inputs.identity_abi,
        custody_protocol: inputs.custody_protocol,
        identity_profile_sha256: inputs.identity_profile_sha256,
        custody_host,
    };
    verify_contract_v2(&contract, &inputs, &input.bytes)?;
    root.write_atomic("build-inputs.json", &input.bytes)?;
    root.write_atomic("bundle-contract.json", &canonical_bytes(&contract))
}
pub fn finalize(dir: &Path) -> Result<(), PackageError> {
    let root = Root::open(dir)?;
    let input = root.read("build-inputs.json", RECORD_LIMIT)?;
    let inputs: BuildInputsV2 = parse_canonical(&input.bytes)?;
    let contract = root.read("bundle-contract.json", RECORD_LIMIT)?;
    let c: BundleContractV2 = parse_canonical(&contract.bytes)?;
    verify_contract_v2(&c, &inputs, &input.bytes)?;
    verify_policy(&c)?;
    let custody = root.read("osslscope-identity-custodian", ELF_LIMIT)?;
    check_host(&custody, &c.custody_host, "osslscope-identity-custodian")?;
    if has_contract_section(&custody.bytes)? {
        return Err(PackageError::invalid("custody must be descriptor-free"));
    }
    let roles = read_roles(&root, Some(&c.roles))?;
    let host = root.read("osslscope", ELF_LIMIT)?;
    if super::build::extract_host_contract(&host.bytes)? != AdmittedContract::V2(c.clone()) {
        return Err(PackageError::invalid(
            "observer contract differs from frozen contract",
        ));
    }
    let record = DevAdmissionV2 {
        schema: "osslscope-dev-admission-v2".into(),
        build_inputs: content(&input, "build-inputs.json"),
        contract: content(&contract, "bundle-contract.json"),
        host: host_entry(&host, "osslscope")?,
        custody_host: c.custody_host,
        roles: role_entries(&roles),
    };
    record.validate()?;
    root.write_atomic("dev-admission.json", &canonical_bytes(&record))
}

fn has_contract_section(bytes: &[u8]) -> Result<bool, PackageError> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|_| PackageError::invalid("custody ELF"))?;
    Ok(elf
        .section_headers
        .iter()
        .any(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".osslscope.bundle_contract")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    mod fixtures {
        use crate as osslscope;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/package_fixtures.rs"
        ));
    }
    fn compile_host(root: &Path) -> PathBuf {
        let source = root.join("custody.rs");
        fs::write(&source, "fn main() {}\n").unwrap();
        let output = root.join("osslscope-identity-custodian");
        let result = Command::new("rustc")
            .args([
                "+1.88.0",
                "--edition=2024",
                "--crate-name",
                "custody_host_fixture",
            ])
            .arg(source)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        output
    }
    fn cli(host: &Path, verb: &str, root: &Path, marker: &Path) -> std::process::Output {
        let mut command = Command::new("setsid");
        command
            .args(["timeout", "--kill-after=3s", "20s"])
            .arg(host)
            .args([verb, "--dev-bundle"])
            .arg(root);
        if verb == "check" {
            command.arg("--deny-weak");
        }
        command
            .args(["run", "--", "/bin/sh", "-c"])
            .arg(format!("touch '{}'", marker.display()))
            .output()
            .unwrap()
    }
    #[test]
    fn identity_v2_real_producer_selected_retained_and_embedded() {
        let base = PathBuf::from(
            std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").expect("owned fixture root"),
        );
        let root = base.join(format!("v2-graph-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let inputs = fixtures::identity_v2_inputs();
        let bytes = canonical_bytes(&inputs);
        let input = root.join("seed.json");
        fs::write(&input, &bytes).unwrap();
        // The real producer refuses missing actual artifacts; fixtures do not
        // make a future source/runtime identity or custody producer available.
        assert!(produce_contract(&input, &root).is_err());
        compile_host(&root);
        for role in [Role::Harvest, Role::Count, Role::Members, Role::Identity] {
            fs::write(root.join(role.file_name()), fixtures::identity_v2_bpf(role)).unwrap();
        }
        produce_contract(&input, &root).unwrap();
        let cb = fs::read(root.join("bundle-contract.json")).unwrap();
        let c: BundleContractV2 = parse_canonical(&cb).unwrap();
        fixtures::check_complete_schema(
            include_str!("../../schemas/package-bundle-contract-v2.json"),
            &cb,
            true,
        );
        assert_eq!(c.roles.len(), 4);
        assert_eq!(c.input_id, sha256(&bytes));
        for name in ["host", "observer_sha256", "payload_id", "contract_id"] {
            assert!(serde_json::to_value(&c).unwrap().get(name).is_none());
            assert!(serde_json::to_value(&inputs).unwrap().get(name).is_none());
        }
        assert_ne!(
            super::super::resolve::compiled_loader_identity(RecordVersion::V1)
                .unwrap()
                .1,
            c.loader_contract_sha256
        );
        assert!(finalize(&root).is_err());
        let target = root.join("observer-target");
        // Compilation is outside every runtime watchdog. Its target directory
        // belongs only to this embedding fixture, never the shared Cargo cache.
        let result = Command::new("cargo")
            .args([
                "+1.88.0",
                "build",
                "--locked",
                "--offline",
                "--bin",
                "osslscope",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("CARGO_BUILD_JOBS", "2")
            .env("CARGO_TARGET_DIR", &target)
            .env("OSSL_PACKAGE_RECORD_DIR", &root)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "real observer compilation: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::copy(target.join("debug/osslscope"), root.join("osslscope")).unwrap();
        let observer = fs::read(root.join("osslscope")).unwrap();
        assert_eq!(
            super::super::build::extract_host_contract(&observer).unwrap(),
            AdmittedContract::V2(c.clone())
        );
        let elf = goblin::elf::Elf::parse(&observer).unwrap();
        let symbol = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("osslscope_bundle_contract_v2"))
            .expect("actual v2 link root");
        assert_eq!(symbol.st_size, cb.len() as u64);
        assert_eq!(
            elf.shdr_strtab
                .get_at(elf.section_headers[symbol.st_shndx].sh_name),
            Some(".osslscope.bundle_contract")
        );
        finalize(&root).unwrap();
        let record = fs::read(root.join("dev-admission.json")).unwrap();
        let d: DevAdmissionV2 = parse_canonical(&record).unwrap();
        fixtures::check_complete_schema(
            include_str!("../../schemas/dev-admission-v2.json"),
            &record,
            true,
        );
        assert_eq!(d.contract.sha256, sha256(&cb));
        assert_eq!(d.host.sha256, sha256(&observer));
        let directory = Root::open(&root).unwrap();
        let (admitted, _) = admit(&directory, Some(&cb)).unwrap();
        assert_eq!(admitted.roles.len(), 4);
        assert!(matches!(
            admitted.identity.require_activation(),
            Err(PackageError::Unavailable { .. })
        ));
        assert!(
            resolve_dev_bundle(&root, Some(&cb)).is_err(),
            "this test executable is not the selected observer"
        );
        assert!(admit(&directory, Some(b"v1-or-mismatched")).is_err());
        let original = Arc::clone(&admitted.roles[&Role::Identity].bytes);
        let path = root.join("osslscope-identity");
        let saved = fs::read(&path).unwrap();
        fs::write(root.join("replacement"), b"changed").unwrap();
        fs::rename(root.join("replacement"), &path).unwrap();
        assert_eq!(original.as_ref(), saved);
        assert!(admit(&directory, None).is_err());
        fs::write(&path, &saved).unwrap();
        let effects = std::cell::Cell::new(0);
        for kind in [
            super::super::commands::CommandKind::Report,
            super::super::commands::CommandKind::Check,
        ] {
            let (set, _) = admit(&directory, Some(&cb)).unwrap();
            let set = super::super::commands::AdmittedSet::Development(set);
            let provenance = set.provenance();
            assert!(provenance.installed_base.is_none());
            assert!(provenance.roles.harvest.build_input_id.is_none());
            let resolver = |_, _: &super::super::commands::ObjectOverrides| Ok(set);
            let effect = |_| effects.set(effects.get() + 1);
            let result = if kind == super::super::commands::CommandKind::Report {
                crate::report::with_report_objects(&Default::default(), resolver, effect)
            } else {
                crate::check::with_check_objects(&Default::default(), resolver, effect)
            };
            assert!(matches!(result, Err(PackageError::Unavailable { .. })));
        }
        assert_eq!(effects.get(), 0);
        let marker = root.join("target-effect");
        for verb in ["report", "check"] {
            let output = cli(&root.join("osslscope"), verb, &root, &marker);
            assert_eq!(output.status.code(), Some(4));
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                text.contains("identity v2 activation unavailable"),
                "selected real {verb}: {text}"
            );
            assert!(!marker.exists());
            let mut command = Command::new("setsid");
            command
                .args(["timeout", "--kill-after=3s", "20s"])
                .arg(root.join("osslscope"))
                .args([verb, "--dev-bundle"])
                .arg(&root)
                .args(["--object", "missing", "--pid", "1"]);
            if verb == "check" {
                command.arg("--deny-weak");
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(4));
            assert!(
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
                .contains("without role overrides")
            );
        }
        // Negative records reach real admission and refuse before activation.
        for case in [
            "profile",
            "target",
            "host",
            "missing",
            "mixed",
            "policy",
            "identity-abi",
            "custody",
        ] {
            let mut contract = c.clone();
            let mut dev = d.clone();
            match case {
                "profile" => contract.identity_profile_sha256 = Digest([0x33; 32]),
                "target" => {
                    contract.host_profile.target = "x86_64-unknown-linux-musl".into();
                    contract.host_profile.abi_profile = "linux-x86_64-musl".into();
                }
                "host" => dev.host.sha256 = Digest([0x33; 32]),
                "missing" => {
                    fs::rename(&path, root.join("identity-held")).unwrap();
                }
                "mixed" => {
                    let mut v = serde_json::to_value(&contract).unwrap();
                    v["schema"] = serde_json::json!("osslscope-bundle-contract-v1");
                    fs::write(
                        root.join("bundle-contract.json"),
                        super::super::source::json_bytes(&v).unwrap(),
                    )
                    .unwrap();
                }
                "policy" => contract.loader_contract_sha256 = Digest([0x33; 32]),
                "identity-abi" => contract.identity_abi = 3,
                "custody" => dev.custody_host.sha256 = Digest([0x33; 32]),
                _ => unreachable!(),
            }
            if case != "mixed" {
                let changed = canonical_bytes(&contract);
                dev.contract.sha256 = sha256(&changed);
                dev.contract.bytes = changed.len() as u64;
                fs::write(root.join("bundle-contract.json"), changed).unwrap();
            }
            fs::write(root.join("dev-admission.json"), canonical_bytes(&dev)).unwrap();
            assert!(admit(&directory, None).is_err(), "{case}");
            if case == "missing" {
                fs::rename(root.join("identity-held"), &path).unwrap();
            }
            fs::write(root.join("bundle-contract.json"), &cb).unwrap();
            fs::write(root.join("dev-admission.json"), &record).unwrap();
        }
        // Existing test-only trust policy admits an owned HOST prefix. This
        // exercises production installed validation, not installed qualification.
        let prefix = root.join("prefix");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::copy(root.join("osslscope"), prefix.join("bin/osslscope")).unwrap();
        for path in [&prefix, &prefix.join("bin"), &prefix.join("bin/osslscope")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let alias = root.join("executing-link");
        symlink(prefix.join("bin/osslscope"), &alias).unwrap();
        let host = super::super::trusted::test_host_from_link(&alias).unwrap();
        let bundle = prefix.join(format!("lib/osslscope/bundles/{}", sha256(&cb)));
        fs::create_dir_all(&bundle).unwrap();
        let mut level = prefix.clone();
        for name in ["lib", "osslscope", "bundles", &sha256(&cb).to_string()] {
            level.push(name);
            fs::set_permissions(&level, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut payload = serde_json::to_value(fixtures::records_fixture().payload).unwrap();
        payload["schema"] = serde_json::json!("osslscope-payload-manifest-v2");
        payload["identity_abi"] = serde_json::json!(4);
        payload["custody_protocol"] = serde_json::json!(1);
        payload["identity_profile_sha256"] = serde_json::json!(c.identity_profile_sha256);
        payload["custody_host"] = serde_json::to_value(&c.custody_host).unwrap();
        payload["roles"] = serde_json::to_value(&c.roles).unwrap();
        payload["input_id"] = serde_json::json!(c.input_id);
        payload["bundle_id"] = serde_json::json!(sha256(&cb));
        payload["contract"] = serde_json::to_value(&d.contract).unwrap();
        payload["build_inputs"] = serde_json::to_value(&d.build_inputs).unwrap();
        let mut host_entry = d.host.clone();
        host_entry.path = RelativePath::new("bin/osslscope").unwrap();
        payload["host"] = serde_json::to_value(host_entry).unwrap();
        let payload: PayloadManifestV2 = serde_json::from_value(payload).unwrap();
        fixtures::check_complete_schema(
            include_str!("../../schemas/package-payload-manifest-v2.json"),
            &canonical_bytes(&payload),
            true,
        );
        fs::write(
            bundle.join("payload-manifest.json"),
            canonical_bytes(&payload),
        )
        .unwrap();
        fs::set_permissions(
            bundle.join("payload-manifest.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        for name in [
            "build-inputs.json",
            "bundle-contract.json",
            "osslscope-identity-custodian",
            "osslscope-harvest",
            "osslscope-count",
            "osslscope-members",
            "osslscope-identity",
        ] {
            fs::copy(root.join(name), bundle.join(name)).unwrap();
            fs::set_permissions(bundle.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        for kind in [
            super::super::commands::CommandKind::Report,
            super::super::commands::CommandKind::Check,
        ] {
            let installed =
                super::super::resolve::resolve_installed_identity_bundle(&host, &cb).unwrap();
            assert_eq!(installed.data.roles.len(), 4);
            let resolve = |_, _: &super::super::commands::ObjectOverrides| {
                Ok(super::super::commands::AdmittedSet::InstalledV2(Box::new(
                    installed,
                )))
            };
            let effect = |_| effects.set(effects.get() + 1);
            let result = if kind == super::super::commands::CommandKind::Report {
                crate::report::with_report_objects(&Default::default(), resolve, effect)
            } else {
                crate::check::with_check_objects(&Default::default(), resolve, effect)
            };
            assert!(matches!(result, Err(PackageError::Unavailable { .. })));
            assert_eq!(effects.get(), 0);
        }
        drop(directory);
        drop(admitted);
        drop(host);
        fs::remove_dir_all(&root).unwrap();
    }
}
