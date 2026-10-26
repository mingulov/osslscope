// SPDX-License-Identifier: GPL-3.0-or-later
//! One admitted, immutable object selection for ordinary commands.
use super::{
    PackageError,
    records::{
        AdmittedMetadata, Digest, HostProfile, LockIdentity, RecipeIdentity, Role, SourceIdentity,
        sha256,
    },
    resolve::{RoleSnapshot, VerifiedBundle},
    trusted::FileIdentity,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) const ROLE_BUFFER_LIMIT: u64 = 536_870_912;
#[derive(Clone, Debug, Default)]
pub struct ObjectOverrides {
    pub harvest: Option<PathBuf>,
    pub count: Option<PathBuf>,
    pub members: Option<PathBuf>,
    pub dev_bundle: Option<PathBuf>,
}
impl ObjectOverrides {
    fn path(&self, role: Role) -> Option<&Path> {
        match role {
            Role::Harvest => self.harvest.as_deref(),
            Role::Count => self.count.as_deref(),
            Role::Members => self.members.as_deref(),
            Role::Identity => None,
        }
    }
    fn any(&self) -> bool {
        self.harvest.is_some() || self.count.is_some() || self.members.is_some()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandKind {
    Doctor,
    Inspect,
    Report,
    Check,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageSelection {
    InstalledMatched,
    OperatorOverride,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleSelection {
    InstalledMatched,
    OperatorExplicit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageToolIdentity {
    pub host_sha256: Digest,
    pub bpf_sha256: Digest,
    pub linker_sha256: Digest,
    pub llvm_sha256: Digest,
    pub builder_sha256: Digest,
    pub components_sha256: Vec<Digest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBuildIdentity {
    pub bundle_id: Digest,
    pub payload_id: Digest,
    pub input_id: Digest,
    pub source: SourceIdentity,
    pub product_version: String,
    pub host_profile: HostProfile,
    pub locks: LockIdentity,
    pub recipe: RecipeIdentity,
    pub tools: PackageToolIdentity,
}
impl PackageBuildIdentity {
    fn from_admitted(metadata: &AdmittedMetadata) -> Self {
        let i = &metadata.inputs;
        Self {
            bundle_id: metadata.contract_id,
            payload_id: metadata.payload_id,
            input_id: metadata.input_id,
            source: i.source.clone(),
            product_version: i.product_version.clone(),
            host_profile: i.host_profile.clone(),
            locks: i.locks.clone(),
            recipe: i.recipe.clone(),
            tools: PackageToolIdentity {
                host_sha256: i.tools.host.sha256,
                bpf_sha256: i.tools.bpf.sha256,
                linker_sha256: i.tools.linker.sha256,
                llvm_sha256: i.tools.llvm.sha256,
                builder_sha256: i.tools.builder.sha256,
                components_sha256: i.tools.components.iter().map(|t| t.sha256).collect(),
            },
        }
    }
}
fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRoleProvenance {
    pub selection: RoleSelection,
    pub sha256: Digest,
    pub bytes: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub build_input_id: Option<Digest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRoleProvenanceSet {
    pub harvest: PackageRoleProvenance,
    #[serde(deserialize_with = "required_nullable")]
    pub count: Option<PackageRoleProvenance>,
    #[serde(deserialize_with = "required_nullable")]
    pub members: Option<PackageRoleProvenance>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProvenance {
    pub selection: PackageSelection,
    #[serde(deserialize_with = "required_nullable")]
    pub installed_base: Option<PackageBuildIdentity>,
    pub roles: PackageRoleProvenanceSet,
}

pub struct OperatorSet {
    roles: BTreeMap<Role, (RoleSnapshot, RoleSelection)>,
    base: Option<Box<AdmittedMetadata>>,
}
pub enum AdmittedSet {
    Installed(Box<VerifiedBundle>),
    Operator(OperatorSet),
    Development(super::dev::VerifiedDevelopment),
    InstalledV2(Box<super::resolve::VerifiedIdentityBundle>),
}
impl AdmittedSet {
    pub fn identity(&self) -> Option<&super::dev::AdmittedIdentity> {
        match self {
            Self::Development(d) => Some(&d.identity),
            Self::InstalledV2(b) => Some(&b.data.identity),
            _ => None,
        }
    }
    pub fn role(&self, role: Role) -> Option<&RoleSnapshot> {
        match self {
            Self::Installed(b) => b.roles().get(&role),
            Self::Operator(o) => o.roles.get(&role).map(|(s, _)| s),
            Self::Development(d) => d.roles.get(&role),
            Self::InstalledV2(b) => b.data.roles.get(&role),
        }
    }
    pub fn provenance(&self) -> PackageProvenance {
        let metadata = match self {
            Self::Installed(b) => Some(&b.metadata),
            Self::Operator(o) => o.base.as_deref(),
            Self::Development(_) => None,
            Self::InstalledV2(b) => Some(&b.metadata),
        };
        let one = |role| {
            self.role(role).map(|s| {
                let selection = match self {
                    Self::Installed(_) => RoleSelection::InstalledMatched,
                    Self::Operator(o) => o.roles[&role].1,
                    Self::Development(_) => RoleSelection::OperatorExplicit,
                    Self::InstalledV2(_) => RoleSelection::InstalledMatched,
                };
                PackageRoleProvenance {
                    selection,
                    sha256: s.sha256,
                    bytes: s.length,
                    build_input_id: if selection == RoleSelection::InstalledMatched {
                        metadata.map(|m| m.input_id)
                    } else {
                        None
                    },
                }
            })
        };
        PackageProvenance {
            selection: if [Role::Harvest, Role::Count, Role::Members]
                .into_iter()
                .any(|r| one(r).is_some_and(|p| p.selection == RoleSelection::OperatorExplicit))
            {
                PackageSelection::OperatorOverride
            } else {
                PackageSelection::InstalledMatched
            },
            installed_base: metadata.map(PackageBuildIdentity::from_admitted),
            roles: PackageRoleProvenanceSet {
                harvest: one(Role::Harvest).expect("admission requires harvest"),
                count: one(Role::Count),
                members: one(Role::Members),
            },
        }
    }
}

/// Count-only preview selection. Explicit objects retain the existing
/// operator-trust boundary; compatibility and a digest do not authenticate code.
pub(crate) struct ProfiledCount {
    pub object_bytes: Arc<[u8]>,
    pub object_sha256: [u8; 32],
    pub selection: RoleSelection,
}

pub(crate) fn resolve_profiled_count(
    override_path: Option<&Path>,
) -> Result<ProfiledCount, PackageError> {
    resolve_profiled_count_with(override_path, installed_profiled_count, snapshot_explicit)
}

fn resolve_profiled_count_with(
    override_path: Option<&Path>,
    installed: impl FnOnce() -> Result<RoleSnapshot, PackageError>,
    explicit: impl FnOnce(Role, &Path, u64) -> Result<RoleSnapshot, PackageError>,
) -> Result<ProfiledCount, PackageError> {
    let (snapshot, selection) = match override_path {
        Some(path) => (
            explicit(Role::Count, path, ROLE_BUFFER_LIMIT)?,
            RoleSelection::OperatorExplicit,
        ),
        None => (installed()?, RoleSelection::InstalledMatched),
    };
    Ok(ProfiledCount {
        object_bytes: snapshot.bytes,
        object_sha256: snapshot.sha256.0,
        selection,
    })
}

fn installed_profiled_count() -> Result<RoleSnapshot, PackageError> {
    use crate::discovery::onboard;
    for dir in onboard::default_object_dirs() {
        if !onboard::is_trusted_dir(&dir) {
            continue;
        }
        let path = dir.join(onboard::COUNT_OBJECT_NAME);
        if !path.exists() {
            continue;
        }
        if !onboard::is_trusted_file(&path) {
            return Err(PackageError::Untrusted {
                context: "installed Count object owner, mode or ancestry".into(),
            });
        }
        let snapshot = snapshot_explicit(Role::Count, &path, ROLE_BUFFER_LIMIT)?;
        if snapshot.identity.uid != 0 || snapshot.identity.mode & 0o022 != 0 {
            return Err(PackageError::Untrusted {
                context: "installed Count object owner or mode changed".into(),
            });
        }
        let receipt_bytes = onboard::verify_role_receipt_bytes(onboard::ObjectRole::Count, &path)
            .map_err(|_| {
            PackageError::invalid("installed Count receipt verification failed")
        })?;
        if receipt_bytes.as_slice() != snapshot.bytes.as_ref() {
            return Err(PackageError::Mutated {
                context: "installed Count changed during receipt verification".into(),
            });
        }
        return Ok(snapshot);
    }
    Err(PackageError::unavailable(
        "no trusted installed Count object; pass --count-object for a local build",
    ))
}

pub fn resolve_command_objects(
    kind: CommandKind,
    overrides: &ObjectOverrides,
) -> Result<AdmittedSet, PackageError> {
    #[cfg(test)]
    RESOLVER_CALLS.with(|calls| calls.set(calls.get() + 1));
    let embedded = super::embedded::contract_bytes();
    if let Some(dir) = &overrides.dev_bundle {
        if !matches!(kind, CommandKind::Report | CommandKind::Check) || overrides.any() {
            return Err(PackageError::invalid(
                "dev v2 requires Report/Check without role overrides",
            ));
        }
        return super::resolve::resolve_dev_bundle(dir, embedded);
    }
    if let Some(bytes) = embedded {
        if let super::records::AdmittedContract::V2(_) = super::records::parse_canonical(bytes)? {
            if overrides.any() {
                return Err(PackageError::invalid("embedded v2 forbids role overrides"));
            }
            let host = super::trusted::executing_host()?;
            return super::resolve::resolve_installed_identity_bundle(&host, bytes)
                .map(|b| AdmittedSet::InstalledV2(Box::new(b)));
        }
    }
    resolve_with(
        kind,
        overrides,
        embedded,
        |contract| {
            let host = super::trusted::executing_host()?;
            super::resolve::resolve_installed_bundle(&host, contract)
                .map(|bundle| AdmittedSet::Installed(Box::new(bundle)))
        },
        snapshot_explicit,
    )
}
fn resolve_with(
    kind: CommandKind,
    overrides: &ObjectOverrides,
    descriptor: Option<&[u8]>,
    installed: impl FnOnce(&[u8]) -> Result<AdmittedSet, PackageError>,
    explicit: impl FnMut(Role, &Path, u64) -> Result<RoleSnapshot, PackageError>,
) -> Result<AdmittedSet, PackageError> {
    let base = descriptor.map(installed).transpose()?;
    if !overrides.any() {
        return base.ok_or_else(|| {
            PackageError::unavailable("complete installed package or explicit objects required")
        });
    }
    let operator = base
        .map(|b| retained_base(b, overrides))
        .unwrap_or_else(|| OperatorSet {
            roles: BTreeMap::new(),
            base: None,
        });
    // The full temporary base and every superseded Arc have been dropped here.
    select_operator(kind, overrides, operator, explicit)
}
fn retained_base(bundle: AdmittedSet, overrides: &ObjectOverrides) -> OperatorSet {
    let roles = [Role::Harvest, Role::Count, Role::Members]
        .into_iter()
        .filter(|r| overrides.path(*r).is_none())
        .filter_map(|r| bundle.role(r).map(|s| (r, s)))
        .map(|(r, s)| {
            (
                r,
                (
                    RoleSnapshot {
                        locator: s.locator.clone(),
                        identity: s.identity.clone(),
                        sha256: s.sha256,
                        length: s.length,
                        bytes: Arc::clone(&s.bytes),
                        loader_validated: s.loader_validated,
                    },
                    RoleSelection::InstalledMatched,
                ),
            )
        })
        .collect();
    OperatorSet {
        roles,
        base: match bundle {
            AdmittedSet::Installed(b) => Some(Box::new(b.metadata)),
            AdmittedSet::Operator(o) => o.base,
            AdmittedSet::Development(_) | AdmittedSet::InstalledV2(_) => {
                unreachable!("v2 overrides refused before retention")
            }
        },
    }
}
fn charge(remaining: &mut u64, bytes: u64) -> Result<(), PackageError> {
    if bytes == 0 || bytes > ROLE_BUFFER_LIMIT {
        return Err(PackageError::invalid("invalid role length"));
    }
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or_else(|| PackageError::invalid("selected role buffers exceed 512 MiB"))?;
    Ok(())
}
fn select_operator(
    kind: CommandKind,
    overrides: &ObjectOverrides,
    mut operator: OperatorSet,
    mut explicit: impl FnMut(Role, &Path, u64) -> Result<RoleSnapshot, PackageError>,
) -> Result<AdmittedSet, PackageError> {
    for role in [Role::Harvest, Role::Count] {
        if (role == Role::Harvest || kind != CommandKind::Inspect)
            && !operator.roles.contains_key(&role)
            && overrides.path(role).is_none()
        {
            return Err(PackageError::unavailable(
                "complete explicit harvest/count selection required",
            ));
        }
    }
    let mut remaining = ROLE_BUFFER_LIMIT;
    for (s, _) in operator.roles.values() {
        charge(&mut remaining, s.length)?;
    }
    for role in [Role::Harvest, Role::Count, Role::Members] {
        if let Some(path) = overrides.path(role) {
            let snapshot = explicit(role, path, remaining)?;
            charge(&mut remaining, snapshot.length)?;
            operator
                .roles
                .insert(role, (snapshot, RoleSelection::OperatorExplicit));
        }
    }
    Ok(AdmittedSet::Operator(operator))
}
fn file_identity(file: &File) -> Result<FileIdentity, PackageError> {
    let m = file
        .metadata()
        .map_err(|_| PackageError::unreadable("explicit object metadata"))?;
    if !m.is_file() {
        return Err(PackageError::invalid(
            "explicit object must be a regular file",
        ));
    }
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
fn snapshot_explicit(
    role: Role,
    path: &Path,
    remaining: u64,
) -> Result<RoleSnapshot, PackageError> {
    snapshot_explicit_with(
        role,
        path,
        remaining,
        crate::discovery::onboard::check_installed_role_compatible,
    )
}
fn snapshot_explicit_with(
    role: Role,
    path: &Path,
    remaining: u64,
    validate: impl FnOnce(Role, &[u8]) -> Result<(), PackageError>,
) -> Result<RoleSnapshot, PackageError> {
    // Special files must reach the regular-file check without waiting for a
    // peer. O_NONBLOCK does not change reads from admitted regular objects.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| {
            PackageError::unavailable(format!("explicit {} object unreadable", role.file_name()))
        })?;
    let before = file_identity(&file)?;
    if before.size == 0 || before.size > remaining {
        return Err(PackageError::invalid(
            "explicit object exceeds remaining role budget or is empty",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(remaining.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PackageError::unreadable("explicit object read"))?;
    let after = file_identity(&file)?;
    if before != after || bytes.len() as u64 != after.size {
        return Err(PackageError::Mutated {
            context: "explicit object changed during admission".into(),
        });
    }
    if bytes.len() as u64 > remaining {
        return Err(PackageError::invalid(
            "explicit object exceeds remaining role budget",
        ));
    }
    validate(role, &bytes)?;
    let sha256 = sha256(&bytes);
    Ok(RoleSnapshot {
        locator: path.to_path_buf(),
        identity: after,
        sha256,
        length: bytes.len() as u64,
        bytes: Arc::from(bytes),
        loader_validated: true,
    })
}
/// The only resolution/effect boundary used by command adapters. Effects never
/// receive a locator without the retained admitted bytes alongside it.
pub(crate) fn with_admitted<R>(
    kind: CommandKind,
    overrides: &ObjectOverrides,
    resolve: impl FnOnce(CommandKind, &ObjectOverrides) -> Result<AdmittedSet, PackageError>,
    effect: impl FnOnce(AdmittedSet) -> R,
) -> Result<R, PackageError> {
    let admitted = resolve(kind, overrides)?;
    if matches!(kind, CommandKind::Report | CommandKind::Check) {
        if let Some(identity) = admitted.identity() {
            identity.require_activation()?;
        }
    }
    Ok(effect(admitted))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub(crate) fn digest(text: &str) -> Digest {
        serde_json::from_value(serde_json::json!(text)).unwrap()
    }
    pub(crate) fn snapshot(role: Role) -> RoleSnapshot {
        let bytes: &[u8] = match role {
            Role::Harvest => b"harvest-fixture",
            Role::Count => b"count-fixture",
            Role::Members => b"members-fixture",
            Role::Identity => b"identity-fixture",
        };
        RoleSnapshot {
            locator: std::env::temp_dir().join(role.file_name()),
            identity: FileIdentity {
                dev: 1,
                ino: role as u64,
                uid: 0,
                mode: 0o100644,
                nlink: 1,
                size: bytes.len() as u64,
                mtime: (0, 0),
                ctime: (0, 0),
            },
            sha256: sha256(bytes),
            length: bytes.len() as u64,
            bytes: Arc::from(bytes),
            loader_validated: true,
        }
    }
    pub(crate) fn metadata() -> AdmittedMetadata {
        let inputs: super::super::records::BuildInputs = serde_json::from_str(INPUT).unwrap();
        AdmittedMetadata {
            input_bytes: Arc::from(INPUT.as_bytes()),
            inputs,
            input_id: digest("164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"),
            contract_id: Digest([0x11; 32]),
            payload_id: Digest([0x22; 32]),
        }
    }
    pub(crate) fn selection_in(triple: bool, dir: &Path) -> AdmittedSet {
        let AdmittedSet::Operator(mut set) = selection(triple) else {
            unreachable!()
        };
        for (role, (snapshot, _)) in &mut set.roles {
            snapshot.locator = dir.join(role.file_name());
        }
        AdmittedSet::Operator(set)
    }
    pub(crate) fn selection(triple: bool) -> AdmittedSet {
        let mut roles = BTreeMap::new();
        for role in [Role::Harvest, Role::Count, Role::Members] {
            if triple || role != Role::Members {
                roles.insert(
                    role,
                    (
                        snapshot(role),
                        if role == Role::Count {
                            RoleSelection::OperatorExplicit
                        } else {
                            RoleSelection::InstalledMatched
                        },
                    ),
                );
            }
        }
        AdmittedSet::Operator(OperatorSet {
            roles,
            base: Some(Box::new(metadata())),
        })
    }
    const INPUT: &str = r#"{"argv":["cargo","build","--locked"],"environment":[{"name":"CARGO_NET_OFFLINE","value":"true"}],"host_profile":{"abi_floor":"fixture-abi-floor","abi_profile":"linux-x86_64-gnu","target":"x86_64-unknown-linux-gnu"},"jobs":2,"locks":{"bpf_sha256":"5555555555555555555555555555555555555555555555555555555555555555","host_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},"offline_inventory_sha256":"8888888888888888888888888888888888888888888888888888888888888888","package_epoch":0,"package_revision":1,"product_version":"0.1.0","recipe":{"config_sha256":"7777777777777777777777777777777777777777777777777777777777777777","recipe_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},"schema":"osslscope-build-inputs-v1","source":{"inventory_sha256":"3333333333333333333333333333333333333333333333333333333333333333","revision":"9d2dfbc906f0e861eab37249ce59daf31271a31c"},"source_epoch":1,"tools":{"bpf":{"name":"clang","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"builder":{"name":"builder","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"components":[{"name":"cargo","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},{"name":"rust-std","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}],"host":{"name":"rust","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"linker":{"name":"ld","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"},"llvm":{"name":"llvm","sha256":"2222222222222222222222222222222222222222222222222222222222222222","version":"fixture-1"}}}
"#;
}
#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::cell::Cell;

    #[test]
    fn profile_count_never_resolves_reader_roles() {
        let old_calls = RESOLVER_CALLS.with(Cell::get);
        let calls = Cell::new(0);
        let selected = resolve_profiled_count_with(
            Some(Path::new("count-only")),
            || panic!("explicit Count must not resolve an installed bundle"),
            |role, path, limit| {
                calls.set(calls.get() + 1);
                assert_eq!(role, Role::Count);
                assert_eq!(path, Path::new("count-only"));
                assert_eq!(limit, ROLE_BUFFER_LIMIT);
                Ok(snapshot(role))
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(&*selected.object_bytes, b"count-fixture");
        assert_eq!(selected.object_sha256, sha256(b"count-fixture").0);
        assert_eq!(selected.selection, RoleSelection::OperatorExplicit);
        assert_eq!(RESOLVER_CALLS.with(Cell::get), old_calls);

        let installed = resolve_profiled_count_with(
            None,
            || Ok(snapshot(Role::Count)),
            |_, _, _| panic!("implicit Count must not use explicit selection"),
        )
        .unwrap();
        assert_eq!(installed.selection, RoleSelection::InstalledMatched);
        assert_eq!(&*installed.object_bytes, b"count-fixture");
        assert_eq!(RESOLVER_CALLS.with(Cell::get), old_calls);
    }

    #[test]
    fn profile_count_bad_abi_stops_before_any_command_effect() {
        let old_calls = RESOLVER_CALLS.with(Cell::get);
        assert!(resolve_profiled_count(Some(&std::env::current_exe().unwrap())).is_err());
        assert_eq!(RESOLVER_CALLS.with(Cell::get), old_calls);
    }
    #[test]
    fn package_command_adapters_share_admitted_snapshots() {
        let effects = Cell::new(0);
        for expected in [
            CommandKind::Doctor,
            CommandKind::Inspect,
            CommandKind::Report,
            CommandKind::Check,
        ] {
            let admitted = selection(true);
            let originals: [Arc<[u8]>; 3] = [Role::Harvest, Role::Count, Role::Members]
                .map(|r| Arc::clone(&admitted.role(r).unwrap().bytes));
            let resolver = |kind, _: &ObjectOverrides| {
                assert_eq!(kind, expected);
                Ok(admitted)
            };
            let effect = |set: AdmittedSet| {
                effects.set(effects.get() + 1);
                let p = set.provenance();
                assert_eq!(
                    p.installed_base.as_ref().unwrap().input_id.to_string(),
                    "164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"
                );
                assert_eq!(
                    p.installed_base.as_ref().unwrap().bundle_id,
                    Digest([0x11; 32])
                );
                assert_eq!(
                    p.installed_base.as_ref().unwrap().payload_id,
                    Digest([0x22; 32])
                );
                for (r, original) in [Role::Harvest, Role::Count, Role::Members]
                    .into_iter()
                    .zip(&originals)
                {
                    assert!(Arc::ptr_eq(&set.role(r).unwrap().bytes, original));
                }
                if expected == CommandKind::Inspect {
                    let args = crate::inspect::parse(
                        &["--pid", "42", "--provider", "/observer/provider"].map(String::from),
                    )
                    .unwrap();
                    let cfg = args.harvest_config(set.role(Role::Harvest).unwrap());
                    let mut loaded = Vec::new();
                    crate::discovery::session::with_harvest_snapshot(
                        cfg.object_bytes.as_ref().unwrap(),
                        |bytes| {
                            assert_eq!(bytes.as_ptr(), originals[0].as_ptr());
                            assert_eq!(bytes, b"harvest-fixture");
                            loaded.push(Role::Harvest);
                        },
                    );
                    assert_eq!(loaded, vec![Role::Harvest]);
                }
                assert_eq!(
                    p.roles.harvest.sha256.to_string(),
                    "ccbc7d8e3a9cdb133d089ee7d7f7b9bfeb7c432520b9ae158c6044e8c09d920d"
                );
            };
            match expected {
                CommandKind::Doctor => crate::doctor::with_doctor_objects(
                    &ObjectOverrides::default(),
                    resolver,
                    effect,
                ),
                CommandKind::Inspect => crate::inspect::with_inspect_objects(
                    &ObjectOverrides::default(),
                    resolver,
                    effect,
                ),
                CommandKind::Report => crate::report::with_report_objects(
                    &ObjectOverrides::default(),
                    resolver,
                    effect,
                ),
                CommandKind::Check => {
                    crate::check::with_check_objects(&ObjectOverrides::default(), resolver, effect)
                }
            }
            .unwrap();
        }
        assert_eq!(effects.get(), 4);
    }
    #[test]
    fn package_admission_failure_precedes_effects() {
        for kind in [
            CommandKind::Doctor,
            CommandKind::Inspect,
            CommandKind::Report,
            CommandKind::Check,
        ] {
            for error in [
                PackageError::invalid("F1"),
                PackageError::invalid("shape"),
                PackageError::Untrusted {
                    context: "trust".into(),
                },
            ] {
                let effects = Cell::new(0);
                let resolver = |actual, _: &ObjectOverrides| {
                    assert_eq!(actual, kind);
                    Err(error)
                };
                let effect = |_: AdmittedSet| {
                    effects.set(effects.get() + 1);
                };
                let result = match kind {
                    CommandKind::Doctor => crate::doctor::with_doctor_objects(
                        &ObjectOverrides::default(),
                        resolver,
                        effect,
                    ),
                    CommandKind::Inspect => crate::inspect::with_inspect_objects(
                        &ObjectOverrides::default(),
                        resolver,
                        effect,
                    ),
                    CommandKind::Report => crate::report::with_report_objects(
                        &ObjectOverrides::default(),
                        resolver,
                        effect,
                    ),
                    CommandKind::Check => crate::check::with_check_objects(
                        &ObjectOverrides::default(),
                        resolver,
                        effect,
                    ),
                };
                assert!(result.is_err());
                assert_eq!(effects.get(), 0);
            }
        }
    }
    #[test]
    fn explicit_operator_selection_keeps_unknown_provenance() {
        let explicit = |role, path: &Path, remaining| {
            let mut s = snapshot(role);
            s.locator = path.to_path_buf();
            assert!(s.length <= remaining);
            Ok(s)
        };
        let empty = || OperatorSet {
            roles: BTreeMap::new(),
            base: None,
        };
        let pair = ObjectOverrides {
            harvest: Some("h".into()),
            count: Some("c".into()),
            members: None,
            dev_bundle: None,
        };
        for kind in [CommandKind::Doctor, CommandKind::Report, CommandKind::Check] {
            let set = select_operator(kind, &pair, empty(), explicit).unwrap();
            let p = set.provenance();
            assert!(p.installed_base.is_none());
            assert!(p.roles.harvest.build_input_id.is_none());
            assert!(p.roles.count.unwrap().build_input_id.is_none());
            assert!(p.roles.members.is_none());
        }
        let harvest = ObjectOverrides {
            harvest: Some("h".into()),
            ..Default::default()
        };
        let p = select_operator(CommandKind::Inspect, &harvest, empty(), explicit)
            .unwrap()
            .provenance();
        assert!(p.roles.count.is_none());
        assert!(select_operator(CommandKind::Report, &harvest, empty(), explicit).is_err());
        let triple = ObjectOverrides {
            members: Some("m".into()),
            ..pair.clone()
        };
        assert!(
            select_operator(CommandKind::Check, &triple, empty(), explicit)
                .unwrap()
                .role(Role::Members)
                .is_some()
        );
        // Descriptor-bearing explicit triples cannot repair even one base failure.
        let reads = Cell::new(0);
        assert!(
            resolve_with(
                CommandKind::Report,
                &triple,
                Some(b"descriptor"),
                |_| Err(PackageError::invalid("broken base")),
                |_, _, _| {
                    reads.set(reads.get() + 1);
                    unreachable!()
                }
            )
            .is_err()
        );
        assert_eq!(reads.get(), 0);
        // The same selection function retains exactly one admitted base for partial overrides.
        let AdmittedSet::Operator(mut base) = selection(true) else {
            unreachable!()
        };
        base.roles.remove(&Role::Count);
        let override_count = ObjectOverrides {
            count: Some("inside/the/bundle/count".into()),
            ..Default::default()
        };
        let p = select_operator(CommandKind::Report, &override_count, base, explicit)
            .unwrap()
            .provenance();
        assert_eq!(
            p.roles.harvest.build_input_id.unwrap().to_string(),
            "164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"
        );
        assert!(p.roles.count.unwrap().build_input_id.is_none());
        // A descriptor-bearing all-explicit selection still admits exactly one
        // complete base first; every selected replacement remains unknown.
        let admissions = Cell::new(0);
        let set = resolve_with(
            CommandKind::Report,
            &triple,
            Some(b"descriptor"),
            |_| {
                admissions.set(admissions.get() + 1);
                Ok(selection(true))
            },
            explicit,
        )
        .unwrap();
        let p = set.provenance();
        assert_eq!(admissions.get(), 1);
        assert!(p.installed_base.is_some());
        assert!(p.roles.harvest.build_input_id.is_none());
        assert!(p.roles.count.unwrap().build_input_id.is_none());
        assert!(p.roles.members.unwrap().build_input_id.is_none());
        assert!(
            resolve_with(
                CommandKind::Report,
                &ObjectOverrides::default(),
                None,
                |_| unreachable!(),
                explicit
            )
            .is_err()
        );
    }
    #[test]
    fn package_provenance_projects_only_admitted_inputs() {
        // One input-record field at a time. Expected output slots and values
        // are literal facts, independent of the projection under test.
        for (input_path, output_path, value) in [
            (
                "/source/revision",
                "/source/revision",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "/source/inventory_sha256",
                "/source/inventory_sha256",
                "abababababababababababababababababababababababababababababababab",
            ),
            (
                "/product_version",
                "/product_version",
                "independent-version",
            ),
            (
                "/host_profile/abi_floor",
                "/host_profile/abi_floor",
                "independent-floor",
            ),
            (
                "/locks/host_sha256",
                "/locks/host_sha256",
                "0101010101010101010101010101010101010101010101010101010101010101",
            ),
            (
                "/locks/bpf_sha256",
                "/locks/bpf_sha256",
                "0202020202020202020202020202020202020202020202020202020202020202",
            ),
            (
                "/recipe/recipe_sha256",
                "/recipe/recipe_sha256",
                "0303030303030303030303030303030303030303030303030303030303030303",
            ),
            (
                "/recipe/config_sha256",
                "/recipe/config_sha256",
                "0404040404040404040404040404040404040404040404040404040404040404",
            ),
            (
                "/tools/host/sha256",
                "/tools/host_sha256",
                "0505050505050505050505050505050505050505050505050505050505050505",
            ),
            (
                "/tools/bpf/sha256",
                "/tools/bpf_sha256",
                "0606060606060606060606060606060606060606060606060606060606060606",
            ),
            (
                "/tools/linker/sha256",
                "/tools/linker_sha256",
                "0707070707070707070707070707070707070707070707070707070707070707",
            ),
            (
                "/tools/llvm/sha256",
                "/tools/llvm_sha256",
                "0808080808080808080808080808080808080808080808080808080808080808",
            ),
            (
                "/tools/builder/sha256",
                "/tools/builder_sha256",
                "0909090909090909090909090909090909090909090909090909090909090909",
            ),
            (
                "/tools/components/0/sha256",
                "/tools/components_sha256/0",
                "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            ),
        ] {
            let mut metadata = metadata();
            let mut input = serde_json::to_value(&metadata.inputs).unwrap();
            *input.pointer_mut(input_path).unwrap() = serde_json::json!(value);
            metadata.inputs = serde_json::from_value(input).unwrap();
            let output =
                serde_json::to_value(PackageBuildIdentity::from_admitted(&metadata)).unwrap();
            assert_eq!(
                output.pointer(output_path).unwrap(),
                &serde_json::json!(value),
                "{input_path}"
            );
        }
        let AdmittedSet::Operator(mut set) = selection(true) else {
            unreachable!()
        };
        let m = set.base.as_mut().unwrap();
        m.inputs.argv = vec!["PRIVATE-ARGV-SENTINEL".into()];
        m.inputs.environment[0].value = "PRIVATE-ENV-SENTINEL".into();
        m.inputs.tools.host.name = "PRIVATE-TOOL-SENTINEL".into();
        m.inputs.tools.host.version = "PRIVATE-VERSION-SENTINEL".into();
        m.inputs.source.revision = "b".repeat(40);
        m.inputs.source.inventory_sha256 = Digest([0xab; 32]);
        m.inputs.product_version = "reviewed-version".into();
        m.inputs.host_profile.abi_floor = "reviewed-floor".into();
        m.inputs.locks.host_sha256 = Digest([1; 32]);
        m.inputs.recipe.config_sha256 = Digest([2; 32]);
        m.inputs.tools.host.sha256 = Digest([3; 32]);
        m.inputs.tools.bpf.sha256 = Digest([4; 32]);
        m.inputs.tools.linker.sha256 = Digest([5; 32]);
        m.inputs.tools.llvm.sha256 = Digest([6; 32]);
        m.inputs.tools.builder.sha256 = Digest([7; 32]);
        m.inputs.tools.components[0].sha256 = Digest([8; 32]);
        m.inputs.tools.components[1].sha256 = Digest([9; 32]);
        m.input_bytes = Arc::from(serde_json::to_vec(&m.inputs).unwrap());
        assert!(
            std::str::from_utf8(&m.input_bytes)
                .unwrap()
                .contains("PRIVATE-ARGV-SENTINEL")
        );
        let p = AdmittedSet::Operator(set).provenance();
        let b = p.installed_base.as_ref().unwrap();
        assert_eq!(
            b.source.revision,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(b.source.inventory_sha256, Digest([0xab; 32]));
        assert_eq!(b.product_version, "reviewed-version");
        assert_eq!(b.host_profile.abi_floor, "reviewed-floor");
        assert_eq!(b.locks.host_sha256, Digest([1; 32]));
        assert_eq!(b.recipe.config_sha256, Digest([2; 32]));
        assert_eq!(
            [
                b.tools.host_sha256,
                b.tools.bpf_sha256,
                b.tools.linker_sha256,
                b.tools.llvm_sha256,
                b.tools.builder_sha256
            ],
            [
                Digest([3; 32]),
                Digest([4; 32]),
                Digest([5; 32]),
                Digest([6; 32]),
                Digest([7; 32])
            ]
        );
        assert_eq!(
            b.tools.components_sha256,
            vec![Digest([8; 32]), Digest([9; 32])]
        );
        let text = serde_json::to_string(&p).unwrap();
        assert!(!text.contains("SENTINEL"));
        assert!(!text.contains("argv"));
        assert!(!text.contains("environment"));
    }
    #[test]
    fn package_override_unique_buffer_budget() {
        let mut remaining = ROLE_BUFFER_LIMIT;
        charge(&mut remaining, ROLE_BUFFER_LIMIT - 1).unwrap();
        charge(&mut remaining, 1).unwrap();
        assert_eq!(remaining, 0);
        assert!(charge(&mut remaining, 1).is_err());
        // Virtual lengths exercise the allocation bound without 512 MiB allocations.
        let AdmittedSet::Operator(mut base) = selection(true) else {
            unreachable!()
        };
        let keep = Arc::clone(&base.roles[&Role::Harvest].0.bytes);
        base.roles.get_mut(&Role::Harvest).unwrap().0.length = ROLE_BUFFER_LIMIT - 30;
        base.roles.get_mut(&Role::Count).unwrap().0.length = 15;
        let weak = Arc::downgrade(&base.roles[&Role::Count].0.bytes);
        let weak_members = Arc::downgrade(&base.roles[&Role::Members].0.bytes);
        let overrides = ObjectOverrides {
            count: Some("count".into()),
            members: Some("members".into()),
            ..Default::default()
        };
        let reads = Cell::new(0);
        let result = resolve_with(
            CommandKind::Report,
            &overrides,
            Some(b"descriptor"),
            |_| Ok(AdmittedSet::Operator(base)),
            |role, _, remaining| {
                reads.set(reads.get() + 1);
                assert!(weak.upgrade().is_none());
                assert!(weak_members.upgrade().is_none());
                let mut s = snapshot(role);
                assert_eq!(remaining, if role == Role::Count { 30 } else { 1 });
                s.length = if role == Role::Count { 29 } else { 2 };
                Ok(s)
            },
        );
        assert!(result.is_err());
        assert_eq!(reads.get(), 2);
        assert_eq!(&*keep, b"harvest-fixture");
        // Exact-boundary positive uses the same production selection/charge path.
        let empty = OperatorSet {
            roles: BTreeMap::new(),
            base: None,
        };
        let pair = ObjectOverrides {
            harvest: Some("h".into()),
            count: Some("c".into()),
            members: None,
            dev_bundle: None,
        };
        let set = select_operator(CommandKind::Report, &pair, empty, |r, _, _| {
            let mut s = snapshot(r);
            s.length = if r == Role::Harvest {
                ROLE_BUFFER_LIMIT - 1
            } else {
                1
            };
            Ok(s)
        })
        .unwrap();
        assert_eq!(set.provenance().roles.harvest.bytes, 536_870_911);
    }
    #[test]
    fn package_explicit_snapshot_rejects_fifo_without_writer() {
        use std::ffi::CString;
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::mpsc;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "osslscope-profile-fifo-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("count");
        let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let (send, receive) = mpsc::channel();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            let rejected = snapshot_explicit_with(Role::Count, &reader_path, 1024, |_, _| {
                panic!("non-regular input reached object validation")
            })
            .is_err();
            let _ = send.send(rejected);
        });
        let observed = receive.recv_timeout(Duration::from_millis(300));
        // Unblock the old blocking-open behavior before failing the assertion;
        // even the RED run must not leave a thread or FIFO behind.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut unblocked = false;
        if observed.is_err() {
            while !reader.is_finished() && Instant::now() < deadline {
                if let Ok(writer) = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path)
                {
                    drop(writer);
                    unblocked = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if observed.is_ok() || unblocked || reader.is_finished() {
            reader.join().unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            matches!(observed, Ok(true)),
            "explicit object admission waited for a FIFO writer: {observed:?}"
        );
    }

    #[test]
    fn package_explicit_snapshot_retains_read_buffer_and_identity() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let dir =
            std::env::temp_dir().join(format!("package-explicit-snapshot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("object");
        let link = dir.join("operator-link");
        std::fs::write(&path, b"count-fixture").unwrap();
        symlink(&path, &link).unwrap();
        let identity = std::fs::metadata(&path).unwrap();
        let snapshot = snapshot_explicit_with(Role::Count, &link, 13, |r, bytes| {
            assert_eq!(r, Role::Count);
            assert_eq!(bytes, b"count-fixture");
            let replacement = dir.join("replacement");
            std::fs::write(&replacement, b"changed-count").unwrap();
            std::fs::rename(replacement, &path).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(snapshot.identity.dev, identity.dev());
        assert_eq!(snapshot.identity.ino, identity.ino());
        assert_eq!(&*snapshot.bytes, b"count-fixture");
        assert_eq!(
            snapshot.sha256.to_string(),
            "727d5430ed3ae804ffaf8d1fe1679d95d50d266f219ebed4177fc6812dc7bfc6"
        );
        let changed = snapshot_explicit_with(Role::Count, &link, 13, |_, _| Ok(())).unwrap();
        assert_eq!(
            changed.sha256.to_string(),
            "243e5127d3042906c416d2b8beeaf9d51208c1aa151ada4b574e4d22548ab154"
        );
        assert_ne!(changed.identity.ino, snapshot.identity.ino);
        assert!(snapshot_explicit_with(Role::Count, &link, 12, |_, _| unreachable!()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
thread_local! {static RESOLVER_CALLS:std::cell::Cell<usize>=const {std::cell::Cell::new(0)};}

#[cfg(test)]
#[test]
fn package_offline_render_resolver_probe_stays_zero() {
    // Calibrate at the actual public resolver even when a descriptor-free host
    // can fail without issuing IO. A read-only syscall probe alone misses that.
    RESOLVER_CALLS.with(|c| c.set(0));
    let _ = resolve_command_objects(CommandKind::Report, &ObjectOverrides::default());
    RESOLVER_CALLS.with(|c| assert_eq!(c.get(), 1));
    RESOLVER_CALLS.with(|c| c.set(0));
    let mut doc = crate::report::setup_failure_document(crate::evidence::FatalKind::Recycled);
    doc.schema = "observed-crypto-v2.2".into();
    let original = test_support::selection(false).provenance();
    let mut current_fixture = test_support::metadata();
    current_fixture.input_id = Digest([0xff; 32]);
    current_fixture.inputs.product_version = "DIFFERENT-CURRENT-INSTALLATION".into();
    assert_eq!(
        current_fixture.input_id.to_string(),
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    for recorded in [false, true] {
        doc.package_build = recorded.then(|| original.clone());
        let v: serde_json::Value =
            serde_json::from_slice(&crate::report::render_json(&doc).unwrap()).unwrap();
        let human = crate::report::render_human(&doc);
        let cbom = crate::report::render_cbom(&doc).unwrap();
        assert_eq!(v["schema_version"], "observed-crypto-v2.2");
        assert!(human.contains("observed-crypto-v2.2"));
        assert!(
            std::str::from_utf8(&cbom)
                .unwrap()
                .contains("observed-crypto-v2.2")
        );
        if recorded {
            assert_eq!(
                v["package_build"]["installed_base"]["input_id"],
                "164714d5150c22be89e5523af0e578782f57c5cd93f7adb991f790042f360c9d"
            );
        } else {
            assert!(v.get("package_build").is_none());
        }
        assert!(!human.contains("DIFFERENT-CURRENT-INSTALLATION"));
        RESOLVER_CALLS.with(|c| assert_eq!(c.get(), 0));
    }
}
