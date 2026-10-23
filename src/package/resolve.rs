// SPDX-License-Identifier: GPL-3.0-or-later
//! Complete, retained installed bundle admission.

use super::{
    PackageError,
    records::{
        AdmittedMetadata, BundleContract, Digest, PayloadManifest, RelativePath, Role, RoleEntry,
        parse_canonical, sha256, verify_metadata,
    },
    trusted::{FileIdentity, HostIdentity, OpenedFile, TrustedDir, snapshot},
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

const RECORD_LIMIT: u64 = 1_048_576;
const ROLE_TOTAL_LIMIT: u64 = 536_870_912;
const HOST_LIMIT: u64 = 536_870_912;

pub struct RoleSnapshot {
    pub locator: PathBuf,
    pub identity: FileIdentity,
    pub sha256: Digest,
    pub length: u64,
    pub bytes: Arc<[u8]>,
    pub loader_validated: bool,
}

pub struct HostSnapshot {
    pub locator: PathBuf,
    pub identity: FileIdentity,
    pub sha256: Digest,
    pub bytes: u64,
}

pub struct VerifiedBundle {
    pub metadata: AdmittedMetadata,
    pub contract: BundleContract,
    pub payload: PayloadManifest,
    pub host: HostSnapshot,
    roles: BTreeMap<Role, RoleSnapshot>,
}

impl VerifiedBundle {
    pub fn role(&self, role: Role) -> &RoleSnapshot {
        self.roles
            .get(&role)
            .expect("verified bundle always owns all three roles")
    }
    pub fn roles(&self) -> &BTreeMap<Role, RoleSnapshot> {
        &self.roles
    }
}

fn admit_roles<O, V>(
    entries: &[RoleEntry],
    mut open: O,
    mut validate: V,
) -> Result<BTreeMap<Role, RoleSnapshot>, PackageError>
where
    O: FnMut(&RelativePath) -> Result<OpenedFile, PackageError>,
    V: FnMut(Role, &[u8]) -> Result<(), PackageError>,
{
    if entries.len() != 3 {
        return Err(PackageError::invalid("v1 requires exactly three roles"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut declared_total = 0u64;
    for entry in entries {
        if !seen.insert(entry.role)
            || entry.file.as_str() != entry.role.file_name()
            || entry.bytes == 0
            || entry.bytes > ROLE_TOTAL_LIMIT
        {
            return Err(PackageError::invalid(format!(
                "{}: invalid role record",
                entry.role.file_name()
            )));
        }
        declared_total = declared_total
            .checked_add(entry.bytes)
            .ok_or_else(|| PackageError::invalid("role total overflow"))?;
    }
    if declared_total > ROLE_TOTAL_LIMIT
        || ![Role::Harvest, Role::Count, Role::Members]
            .into_iter()
            .all(|r| seen.contains(&r))
    {
        return Err(PackageError::invalid("incomplete or oversized role set"));
    }
    let mut remaining = ROLE_TOTAL_LIMIT;
    let mut roles = BTreeMap::new();
    for entry in entries {
        let opened = open(&entry.file)?;
        let bound = remaining.min(entry.bytes);
        let snap = snapshot(&opened, bound)?;
        if snap.bytes.len() as u64 != entry.bytes || snap.sha256 != entry.sha256 {
            return Err(PackageError::invalid(format!(
                "{}: length or SHA-256 mismatch",
                entry.role.file_name()
            )));
        }
        remaining -= snap.bytes.len() as u64;
        validate(entry.role, &snap.bytes)?;
        roles.insert(
            entry.role,
            RoleSnapshot {
                locator: opened.locator,
                identity: snap.after,
                sha256: snap.sha256,
                length: entry.bytes,
                bytes: snap.bytes,
                loader_validated: true,
            },
        );
    }
    Ok(roles)
}

/// Resolve one exact bundle under the executing inode's trusted prefix.
/// No path outside this prefix or role absent from the contract is searched.
pub fn resolve_installed_bundle(
    host: &HostIdentity,
    embedded_contract: &[u8],
) -> Result<VerifiedBundle, PackageError> {
    resolve_installed_bundle_with(
        host,
        embedded_contract,
        |dir, relative| dir.open_relative(relative),
        crate::discovery::onboard::check_installed_role_compatible,
    )
}

fn resolve_installed_bundle_with<O, V>(
    host: &HostIdentity,
    embedded_contract: &[u8],
    mut open: O,
    validate: V,
) -> Result<VerifiedBundle, PackageError>
where
    O: FnMut(&TrustedDir, &RelativePath) -> Result<OpenedFile, PackageError>,
    V: FnMut(Role, &[u8]) -> Result<(), PackageError>,
{
    parse_canonical::<BundleContract>(embedded_contract)?;
    let bundle_id = sha256(embedded_contract);
    let bundle_path = RelativePath::new(format!("lib/osslscope/bundles/{bundle_id}"))?;
    let bundle = host.prefix.open_dir_relative(&bundle_path)?;

    let contract_file = open(&bundle, &RelativePath::new("bundle-contract.json")?)?;
    let contract_snapshot = snapshot(&contract_file, RECORD_LIMIT)?;
    if contract_snapshot.bytes.as_ref() != embedded_contract {
        return Err(PackageError::invalid(
            "bundle contract differs from embedded contract",
        ));
    }
    let contract: BundleContract = parse_canonical(&contract_snapshot.bytes)?;
    let payload_file = open(&bundle, &RelativePath::new("payload-manifest.json")?)?;
    let payload_snapshot = snapshot(&payload_file, RECORD_LIMIT)?;
    let payload: PayloadManifest = parse_canonical(&payload_snapshot.bytes)?;
    if payload.bundle_id != bundle_id || payload.host.path.as_str() != "bin/osslscope" {
        return Err(PackageError::invalid("bundle ID or host path mismatch"));
    }
    let input_file = open(&bundle, &payload.build_inputs.path)?;
    let input_snapshot = snapshot(&input_file, RECORD_LIMIT)?;
    if input_snapshot.bytes.len() as u64 != payload.build_inputs.bytes
        || input_snapshot.sha256 != payload.build_inputs.sha256
    {
        return Err(PackageError::invalid(
            "build-inputs.json length or SHA-256 mismatch",
        ));
    }
    let metadata = verify_metadata(&contract, &payload, input_snapshot.bytes)?;
    if metadata.contract_id != bundle_id {
        return Err(PackageError::invalid("embedded bundle ID mismatch"));
    }

    if payload.host.bytes > HOST_LIMIT {
        return Err(PackageError::invalid("host exceeds scan bound"));
    }
    let host_snapshot = snapshot(&host.executable, payload.host.bytes)?;
    if host_snapshot.bytes.len() as u64 != payload.host.bytes
        || host_snapshot.sha256 != payload.host.sha256
    {
        return Err(PackageError::invalid(
            "executing host length or SHA-256 mismatch",
        ));
    }
    let parsed_host = goblin::Object::parse(&host_snapshot.bytes)
        .map_err(|_| PackageError::invalid("executing host is not ELF"))?;
    let goblin::Object::Elf(elf) = parsed_host else {
        return Err(PackageError::invalid("executing host is not ELF"));
    };
    if elf.header.e_machine != goblin::elf::header::EM_X86_64
        || elf.header.e_machine != payload.host.elf_machine
        || crate::discovery::elf::read_build_id(&host_snapshot.bytes) != payload.host.elf_build_id
    {
        return Err(PackageError::invalid(
            "executing host ELF identity mismatch",
        ));
    }

    let (wire_abi, policy_digest) = compiled_loader_identity()?;
    if contract.wire_abi != wire_abi || contract.loader_contract_sha256 != policy_digest {
        return Err(PackageError::invalid(
            "compiled wire/loader policy identity mismatch",
        ));
    }
    let roles = admit_roles(
        &contract.roles,
        |relative| open(&bundle, relative),
        validate,
    )?;
    Ok(VerifiedBundle {
        metadata,
        contract,
        payload,
        host: HostSnapshot {
            locator: host.executable.locator.clone(),
            identity: host_snapshot.after,
            sha256: host_snapshot.sha256,
            bytes: host_snapshot.bytes.len() as u64,
        },
        roles,
    })
}

pub(crate) fn compiled_loader_identity() -> Result<(u32, Digest), PackageError> {
    let count = osslscope_ebpf_common::COUNT_ABI_VERSION;
    let discovery = osslscope_ebpf_common::DISCOVERY_ABI_VERSION;
    if count == 0 || count != discovery {
        return Err(PackageError::invalid(
            "compiled Count/Discovery wire ABI disagreement",
        ));
    }
    let bytes = canonical_inventory_bytes()?;
    Ok((count, sha256(&bytes)))
}

fn canonical_inventory_bytes() -> Result<Vec<u8>, PackageError> {
    canonical_json_bytes(&inventory_value()?)
}

fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, PackageError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| PackageError::invalid("loader inventory serialization failed"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn role_inventory(
    role: Role,
    maps: &[crate::loader::MapSpec],
    programs: &[crate::loader::ProgSpec],
    extra: serde_json::Value,
) -> Result<serde_json::Value, PackageError> {
    use serde_json::json;
    let maps: Vec<_> = maps
        .iter()
        .map(|m| {
            json!({
                "name": m.name, "map_type": m.map_type, "key_size": m.key_size,
                "value_size": m.value_size, "max_entries": m.max_entries, "flags": m.flags,
            })
        })
        .collect();
    let mut progs = Vec::with_capacity(programs.len());
    for p in programs {
        if !matches!(p.section, "uprobe" | "uretprobe") {
            return Err(PackageError::invalid(format!(
                "{}: unsupported compiled program section",
                role.file_name()
            )));
        }
        progs.push(json!({"name": p.name, "section": p.section}));
    }
    let role_name = match role {
        Role::Harvest => "harvest",
        Role::Count => "count",
        Role::Members => "members",
    };
    Ok(json!({
        "role": role_name, "file": role.file_name(),
        "program_type": ossl_bpf_sys::BPF_PROG_TYPE_KPROBE,
        "maps": maps, "programs": progs, "extra": extra,
    }))
}

fn inventory_value() -> Result<serde_json::Value, PackageError> {
    use serde_json::json;
    let count_extra = json!({
        "executable_sections": [".text", "uprobe"],
        "root": {"name": "count_entry", "section": "uprobe", "nonempty": true, "exact_count": 1},
        "map_count": 7,
        "program_count": 1,
        "is_return": false,
        "first_subprogram": {"name": "count_entry", "insn_off": 0},
        "callback_subprograms": "FORBIDDEN",
        "helper12_tail_calls": "FORBIDDEN",
        "pseudo_func": "FORBIDDEN",
        "map_fixups": "EXACT_LD_IMM64_SITE_AND_COUNT_MAP_MEMBER",
    });
    let roles = vec![
        role_inventory(
            Role::Harvest,
            &crate::loader::HARVEST_MAPS,
            &crate::loader::HARVEST_PROGS,
            json!({}),
        )?,
        role_inventory(
            Role::Count,
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
            count_extra,
        )?,
        role_inventory(
            Role::Members,
            &crate::loader::MEMBER_MAPS,
            &crate::loader::MEMBER_PROGS,
            json!({}),
        )?,
    ];
    Ok(json!({
        "schema": "osslscope-loader-policy-v1",
        "wire_abi": osslscope_ebpf_common::COUNT_ABI_VERSION,
        "wire_components": {
            "count": osslscope_ebpf_common::COUNT_ABI_VERSION,
            "discovery": osslscope_ebpf_common::DISCOVERY_ABI_VERSION,
        },
        "generic": {
            "elf": {
                "machine": goblin::elf::header::EM_BPF,
                "endianness": "little",
                "forbidden_sections": [".BTF", ".BTF.ext"],
            },
            "license": {
                "section": ".license",
                "absent_default": "GPL",
                "accepted": ["GPL", "GPL v2", "GPL and additional rights", "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL"],
                "encoding": "UTF8",
                "trim_trailing_NUL": true,
            },
            "maps": {
                "section": "maps",
                "symbol_kind": "OBJECT",
                "definition_bytes": 28,
                "checked_fields": ["map_type", "key_size", "value_size", "max_entries", "flags"],
                "required_dimensions": "EXACT_TABLE",
                "unknown_map_symbols": "REJECT",
            },
            "programs": {
                "selected_sections": ["uprobe", "uretprobe"],
                "selection": "REQUIRED_TABLE_SYMBOLS",
                "body_min_bytes": 8,
                "alignment_bytes": 8,
                "output": "SELECTED_ROOT_PLUS_REACHABLE_TEXT",
            },
            "relocations": {
                "section_prefix": ".rel",
                "entry_bytes": 16,
                "selected_types": [1, 10],
                "site_bytes": [16, 8],
                "rules": [
                    "OWNED_OR_REJECT",
                    "FULL_SITE_WITHIN_OWNER",
                    "MAP_TARGET_KNOWN_OBJECT_AND_LD_IMM64",
                    "CALL_TARGET_TEXT_ENTRY",
                    "FUNCTION_POINTER_FUNC_TEXT_ENTRY_NAME_VALUE_MATCH",
                    "ALL_PSEUDO_CALL_AND_FUNCTION_POINTER_REWRITES_ACCOUNTED",
                ],
            },
            "text": {
                "section": ".text",
                "functions": "NONEMPTY_ALIGNED_UNIQUE_NAMES",
                "closure": "TRANSITIVE_CALL_AND_FUNCTION_POINTER_ROOTS",
                "layout": "ROOT_THEN_REACHABLE_TEXT_ELF_ORDER",
                "callbacks": "REFERENCED_FUNCTION_POINTER_TARGETS_MARKED",
            },
        },
        "roles": roles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(dead_code)]
    mod package_fixtures {
        use crate as osslscope;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/package_fixtures.rs"
        ));
    }
    use crate::package::{
        PackageError,
        records::{RelativePath, Role, RoleEntry, sha256},
        trusted::test_dir,
    };
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "osslscope-package-resolve-{}-{n}",
                std::process::id()
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            Self(p)
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn entries() -> Vec<RoleEntry> {
        [Role::Harvest, Role::Count, Role::Members]
            .into_iter()
            .map(|role| {
                let bytes = role.file_name().as_bytes();
                RoleEntry {
                    role,
                    file: RelativePath::new(role.file_name()).unwrap(),
                    sha256: sha256(bytes),
                    bytes: bytes.len() as u64,
                }
            })
            .collect()
    }

    fn minimal_host_elf() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b
    }

    #[test]
    fn complete_metadata_is_opened_once_before_any_role_validation() {
        let f = Fixture::new();
        let executing_prefix = f.0.join("executing-prefix");
        fs::create_dir(&executing_prefix).unwrap();
        fs::set_permissions(&executing_prefix, fs::Permissions::from_mode(0o755)).unwrap();
        let host_path = executing_prefix.join("bin/osslscope");
        fs::create_dir(executing_prefix.join("bin")).unwrap();
        fs::set_permissions(
            executing_prefix.join("bin"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let host_bytes = minimal_host_elf();
        fs::write(&host_path, &host_bytes).unwrap();
        fs::set_permissions(&host_path, fs::Permissions::from_mode(0o755)).unwrap();
        let other_prefix = f.0.join("other-prefix");
        fs::create_dir(&other_prefix).unwrap();
        fs::set_permissions(&other_prefix, fs::Permissions::from_mode(0o755)).unwrap();
        let other_bin = other_prefix.join("bin");
        fs::create_dir(&other_bin).unwrap();
        fs::set_permissions(&other_bin, fs::Permissions::from_mode(0o755)).unwrap();
        let invocation_alias = other_bin.join("osslscope");
        symlink(&host_path, &invocation_alias).unwrap();
        let host = crate::package::trusted::test_host_from_link(&invocation_alias).unwrap();
        assert_eq!(host.prefix.path(), executing_prefix.as_path());
        assert_eq!(host.executable.locator, host_path);
        let mut fixture = package_fixtures::records_fixture();
        let (wire, policy) = compiled_loader_identity().unwrap();
        fixture.contract.wire_abi = wire;
        fixture.contract.loader_contract_sha256 = policy;
        for role in &mut fixture.contract.roles {
            role.bytes = role.role.file_name().len() as u64;
            role.sha256 = sha256(role.role.file_name().as_bytes());
        }
        fixture.payload.roles = fixture.contract.roles.clone();
        fixture.payload.host.sha256 = sha256(&host_bytes);
        fixture.payload.host.bytes = host_bytes.len() as u64;
        let embedded = crate::package::records::canonical_bytes(&fixture.contract);
        let bundle_id = sha256(&embedded);
        fixture.payload.bundle_id = bundle_id;
        fixture.payload.contract.sha256 = bundle_id;
        fixture.payload.contract.bytes = embedded.len() as u64;
        let bundle_dir = executing_prefix.join(format!("lib/osslscope/bundles/{bundle_id}"));
        let mut level = executing_prefix.clone();
        for part in ["lib", "osslscope", "bundles", &bundle_id.to_string()] {
            level.push(part);
            fs::create_dir(&level).unwrap();
            fs::set_permissions(&level, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let write = |name: &str, bytes: &[u8]| {
            let path = bundle_dir.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        };
        write("bundle-contract.json", &embedded);
        write(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&fixture.payload),
        );
        write("build-inputs.json", &fixture.expected_input_bytes);
        for role in [Role::Harvest, Role::Count, Role::Members] {
            write(role.file_name(), role.file_name().as_bytes());
        }
        let mut opens = std::collections::BTreeMap::<String, usize>::new();
        let admitted = resolve_installed_bundle_with(
            &host,
            &embedded,
            |dir, relative| {
                *opens.entry(relative.as_str().to_owned()).or_default() += 1;
                dir.open_relative(relative)
            },
            |_role, _bytes| Ok(()),
        )
        .unwrap();
        assert_eq!(admitted.roles().len(), 3);
        assert_eq!(opens.get("build-inputs.json"), Some(&1));
        assert_eq!(opens.get("payload-manifest.json"), Some(&1));
        assert_eq!(opens.get("bundle-contract.json"), Some(&1));
        fs::rename(
            bundle_dir.join(Role::Count.file_name()),
            bundle_dir.join("old-count"),
        )
        .unwrap();
        write(Role::Count.file_name(), b"replacement");
        assert_eq!(
            &*admitted.role(Role::Count).bytes,
            Role::Count.file_name().as_bytes()
        );
        assert_eq!(
            admitted.metadata.input_bytes.as_ref(),
            fixture.expected_input_bytes
        );
        let before = opens.clone();
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                b"invalid embedded contract\n",
                |dir, relative| {
                    *opens.entry(relative.as_str().to_owned()).or_default() += 1;
                    dir.open_relative(relative)
                },
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Invalid { .. })
        ));
        assert_eq!(opens, before);
        write("payload-manifest.json", b"{ }\n");
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                &embedded,
                |dir, relative| dir.open_relative(relative),
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Invalid { .. })
        ));
        write(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&fixture.payload),
        );
        write("build-inputs.json", b"different input\n");
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                &embedded,
                |dir, relative| dir.open_relative(relative),
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Invalid { .. })
        ));
        write("build-inputs.json", &fixture.expected_input_bytes);
        let mut wrong_host = fixture.payload.clone();
        wrong_host.host.sha256 = sha256(b"another host");
        write(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&wrong_host),
        );
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                &embedded,
                |dir, relative| dir.open_relative(relative),
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Invalid { .. })
        ));
        write(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&fixture.payload),
        );
        fs::remove_file(bundle_dir.join("payload-manifest.json")).unwrap();
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                &embedded,
                |dir, relative| dir.open_relative(relative),
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Unavailable { .. })
        ));
        write(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&fixture.payload),
        );
        fs::remove_file(bundle_dir.join(Role::Count.file_name())).unwrap();
        let mut alt = executing_prefix.clone();
        for part in ["lib64", "osslscope", "bundles", &bundle_id.to_string()] {
            alt.push(part);
            fs::create_dir(&alt).unwrap();
            fs::set_permissions(&alt, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(alt.join(Role::Count.file_name()), Role::Count.file_name()).unwrap();
        fs::set_permissions(
            alt.join(Role::Count.file_name()),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        // A second, complete bundle sits beneath the invocation alias's
        // prefix. The executing prefix still lacks Count.
        let mut competitor = other_prefix.clone();
        for part in ["lib", "osslscope", "bundles", &bundle_id.to_string()] {
            competitor.push(part);
            fs::create_dir(&competitor).unwrap();
            fs::set_permissions(&competitor, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let write_competitor = |name: &str, bytes: &[u8]| {
            let path = competitor.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        };
        write_competitor("bundle-contract.json", &embedded);
        write_competitor(
            "payload-manifest.json",
            &crate::package::records::canonical_bytes(&fixture.payload),
        );
        write_competitor("build-inputs.json", &fixture.expected_input_bytes);
        for role in [Role::Harvest, Role::Count, Role::Members] {
            write_competitor(role.file_name(), role.file_name().as_bytes());
        }
        assert_eq!(
            fs::read(competitor.join(Role::Count.file_name())).unwrap(),
            Role::Count.file_name().as_bytes()
        );
        assert!(matches!(
            resolve_installed_bundle_with(
                &host,
                &embedded,
                |dir, relative| {
                    assert_eq!(dir.path(), bundle_dir.as_path());
                    dir.open_relative(relative)
                },
                |_role, _bytes| Ok(())
            ),
            Err(PackageError::Unavailable { .. })
        ));
    }

    #[test]
    fn retained_complete_roles_open_once_and_survive_path_replacement() {
        let f = Fixture::new();
        for role in [Role::Harvest, Role::Count, Role::Members] {
            f.write(role.file_name(), role.file_name().as_bytes());
        }
        let dir = test_dir(&f.0).unwrap();
        let opens = Cell::new(0);
        let roles = admit_roles(
            &entries(),
            |path| {
                opens.set(opens.get() + 1);
                dir.open_relative(path)
            },
            |_role, _bytes| Ok(()),
        )
        .unwrap();
        assert_eq!(roles.len(), 3);
        assert_eq!(opens.get(), 3);
        let count = roles.get(&Role::Count).unwrap();
        fs::rename(f.0.join(Role::Count.file_name()), f.0.join("old-count")).unwrap();
        f.write(Role::Count.file_name(), b"replacement");
        assert_eq!(&*count.bytes, Role::Count.file_name().as_bytes());
        assert_eq!(count.sha256, sha256(Role::Count.file_name().as_bytes()));
    }

    #[test]
    fn incomplete_or_changed_role_set_never_returns_a_partial_bundle() {
        let f = Fixture::new();
        for role in [Role::Harvest, Role::Count, Role::Members] {
            f.write(role.file_name(), role.file_name().as_bytes());
        }
        let dir = test_dir(&f.0).unwrap();
        let mut missing = entries();
        missing.pop();
        assert!(matches!(
            admit_roles(&missing, |p| dir.open_relative(p), |_, _| Ok(())),
            Err(PackageError::Invalid { .. })
        ));
        fs::remove_file(f.0.join(Role::Members.file_name())).unwrap();
        assert!(matches!(
            admit_roles(&entries(), |p| dir.open_relative(p), |_, _| Ok(())),
            Err(PackageError::Unavailable { .. })
        ));
        f.write(Role::Members.file_name(), b"changed");
        assert!(matches!(
            admit_roles(&entries(), |p| dir.open_relative(p), |_, _| Ok(())),
            Err(PackageError::Invalid { .. })
        ));
        let mut oversized = entries();
        oversized[0].bytes = 536_870_913;
        assert!(matches!(
            admit_roles(&oversized, |p| dir.open_relative(p), |_, _| Ok(())),
            Err(PackageError::Invalid { .. })
        ));
    }

    #[test]
    fn aggregate_role_budget_is_checked_before_any_open_or_validation() {
        let mut over = entries();
        over[0].bytes = ROLE_TOTAL_LIMIT / 3;
        over[1].bytes = ROLE_TOTAL_LIMIT / 3;
        over[2].bytes = ROLE_TOTAL_LIMIT - over[0].bytes - over[1].bytes + 1;
        assert!(over.iter().all(|entry| entry.bytes <= ROLE_TOTAL_LIMIT));
        assert_eq!(
            over.iter().map(|entry| entry.bytes).sum::<u64>(),
            ROLE_TOTAL_LIMIT + 1
        );
        let opens = Cell::new(0);
        let validations = Cell::new(0);
        assert!(matches!(
            admit_roles(
                &over,
                |_| {
                    opens.set(opens.get() + 1);
                    Err(PackageError::unavailable("test opener sentinel"))
                },
                |_, _| {
                    validations.set(validations.get() + 1);
                    Ok(())
                }
            ),
            Err(PackageError::Invalid { .. })
        ));
        assert_eq!(opens.get(), 0);
        assert_eq!(validations.get(), 0);

        over[2].bytes -= 1;
        assert_eq!(
            over.iter().map(|entry| entry.bytes).sum::<u64>(),
            ROLE_TOTAL_LIMIT
        );
        assert!(matches!(
            admit_roles(
                &over,
                |_| {
                    opens.set(opens.get() + 1);
                    Err(PackageError::unavailable("test opener sentinel"))
                },
                |_, _| {
                    validations.set(validations.get() + 1);
                    Ok(())
                }
            ),
            Err(PackageError::Unavailable { .. })
        ));
        assert_eq!(opens.get(), 1);
        assert_eq!(validations.get(), 0);
    }

    #[test]
    fn compiled_identity_covers_all_current_role_tables_and_wire() {
        let (wire, digest) = compiled_loader_identity().unwrap();
        assert_eq!(wire, 2);
        let bytes = canonical_inventory_bytes().unwrap();
        assert_eq!(sha256(&bytes), digest);
        assert_eq!(bytes.len(), 28_356);
        assert_eq!(
            digest.to_string(),
            "62d35545bf9b93389f9690c52c7fbfce5307acf832e0612ae126279aceb1e029"
        );
        let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data["schema"], "osslscope-loader-policy-v1");
        assert_eq!(data["wire_components"]["count"], 2);
        assert_eq!(data["wire_components"]["discovery"], 2);
        let roles = data["roles"].as_array().unwrap();
        assert_eq!(
            roles
                .iter()
                .map(|r| r["role"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["harvest", "count", "members"]
        );
        assert_eq!(
            roles
                .iter()
                .map(|r| r["maps"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            vec![14, 7, 15]
        );
        assert_eq!(
            roles
                .iter()
                .map(|r| r["programs"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            vec![15, 1, 513]
        );
        assert_eq!(roles[1]["extra"]["root"]["name"], "count_entry");
        assert_eq!(
            roles[1]["extra"]["map_fixups"],
            "EXACT_LD_IMM64_SITE_AND_COUNT_MAP_MEMBER"
        );
    }

    #[test]
    fn compiled_inventory_tracks_every_source_table_entry() {
        let data = inventory_value().unwrap();
        let roles = data["roles"].as_array().unwrap();
        let tables = [
            (
                &crate::loader::HARVEST_MAPS[..],
                &crate::loader::HARVEST_PROGS[..],
            ),
            (
                &crate::loader::COUNT_MAPS[..],
                &crate::loader::COUNT_PROGS[..],
            ),
            (
                &crate::loader::MEMBER_MAPS[..],
                &crate::loader::MEMBER_PROGS[..],
            ),
        ];
        for (row, (maps, progs)) in roles.iter().zip(tables) {
            let observed_maps = row["maps"].as_array().unwrap();
            let observed_progs = row["programs"].as_array().unwrap();
            assert_eq!(observed_maps.len(), maps.len());
            assert_eq!(observed_progs.len(), progs.len());
            for (observed, expected) in observed_maps.iter().zip(maps) {
                assert_eq!(observed["name"], expected.name);
                assert_eq!(observed["map_type"], expected.map_type);
                assert_eq!(observed["key_size"], expected.key_size);
                assert_eq!(observed["value_size"], expected.value_size);
                assert_eq!(observed["max_entries"], expected.max_entries);
                assert_eq!(observed["flags"], expected.flags);
            }
            for (observed, expected) in observed_progs.iter().zip(progs) {
                assert_eq!(observed["name"], expected.name);
                assert_eq!(observed["section"], expected.section);
            }
        }
    }

    #[test]
    fn compiled_identity_changes_with_table_order_dimensions_and_clauses() {
        let base = inventory_value().unwrap();
        let base_hash = sha256(&canonical_json_bytes(&base).unwrap());
        let mut mutations = Vec::new();
        let mut dim = base.clone();
        dim["roles"][0]["maps"][0]["max_entries"] = serde_json::json!(1);
        mutations.push(dim);
        let mut maps = base.clone();
        maps["roles"][0]["maps"].as_array_mut().unwrap().swap(0, 1);
        mutations.push(maps);
        let mut progs = base.clone();
        progs["roles"][0]["programs"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        mutations.push(progs);
        let mut count = base.clone();
        count["roles"][1]["extra"]["callback_subprograms"] = serde_json::json!("ALLOWED");
        mutations.push(count);
        let mut generic = base.clone();
        generic["generic"]["relocations"]["rules"][4] = serde_json::json!("UNREVIEWED");
        mutations.push(generic);
        for changed in mutations {
            assert_ne!(sha256(&canonical_json_bytes(&changed).unwrap()), base_hash);
        }
    }

    #[test]
    fn installed_count_policy_rejects_unparseable_retained_bytes() {
        assert!(matches!(
            crate::discovery::onboard::check_installed_role_compatible(
                Role::Count,
                b"not an ELF object"
            ),
            Err(PackageError::Invalid { .. })
        ));
    }

    // Exact seven-map, one-root synthetic relocatable object. All offsets are
    // assembled here; no BPF load or generated/ignored artifact is consumed.
    fn synthetic_count_elf(
        root_name: &str,
        empty_root: bool,
        extra_root: Option<&str>,
        other_exec: bool,
    ) -> Vec<u8> {
        fn w16(b: &mut [u8], at: usize, n: u16) {
            b[at..at + 2].copy_from_slice(&n.to_le_bytes());
        }
        fn w32(b: &mut [u8], at: usize, n: u32) {
            b[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        fn w64(b: &mut [u8], at: usize, n: u64) {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        let mut section_names = Vec::new();
        let mut shstr = Vec::new();
        for name in [
            "",
            ".shstrtab",
            ".strtab",
            ".symtab",
            "maps",
            "uprobe",
            ".reluprobe",
        ] {
            section_names.push(shstr.len());
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
        }
        let mut strings = vec![0];
        let root_name_offset = strings.len();
        strings.extend_from_slice(root_name.as_bytes());
        strings.push(0);
        let mut map_name_offsets = Vec::new();
        let mut maps = Vec::new();
        for map in crate::loader::COUNT_MAPS {
            map_name_offsets.push(strings.len());
            strings.extend_from_slice(map.name.as_bytes());
            strings.push(0);
            for dimension in [
                map.map_type,
                map.key_size,
                map.value_size,
                map.max_entries,
                map.flags,
                0,
                0,
            ] {
                maps.extend_from_slice(&dimension.to_le_bytes());
            }
        }
        let extra_name_offset = extra_root.map(|name| {
            if name == root_name {
                root_name_offset
            } else {
                let at = strings.len();
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
                at
            }
        });
        let mut instructions = vec![0u8; 7 * 16];
        for index in 0..7 {
            instructions[index * 16] = 0x18;
            instructions[index * 16 + 1] = 1;
        }
        // A non-relocated LD_IMM64 and exit follow the seven map sites.
        instructions.extend_from_slice(&[0x18, 0, 0, 0, 0, 0, 0, 0]);
        instructions.extend_from_slice(&[0; 8]);
        instructions.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        let mut symbols = vec![0u8; (9 + usize::from(extra_root.is_some())) * 24];
        w32(&mut symbols, 24, root_name_offset as u32);
        symbols[28] = 0x12;
        w16(&mut symbols, 30, 5);
        w64(
            &mut symbols,
            40,
            if empty_root {
                0
            } else {
                instructions.len() as u64
            },
        );
        let mut relocations = vec![0u8; 7 * 16];
        for (index, name_offset) in map_name_offsets.into_iter().enumerate() {
            let at = (index + 2) * 24;
            w32(&mut symbols, at, name_offset as u32);
            symbols[at + 4] = 0x11;
            w16(&mut symbols, at + 6, 4);
            w64(&mut symbols, at + 8, (index * 28) as u64);
            w64(&mut symbols, at + 16, 28);
            w64(&mut relocations, index * 16, (index * 16) as u64);
            w64(
                &mut relocations,
                index * 16 + 8,
                ((index as u64 + 2) << 32) | 1,
            );
        }
        if let Some(name_offset) = extra_name_offset {
            let at = 9 * 24;
            w32(&mut symbols, at, name_offset as u32);
            symbols[at + 4] = 0x12;
            w16(&mut symbols, at + 6, 5);
            w64(&mut symbols, at + 16, 8);
        }
        let sections = [
            Vec::new(),
            shstr,
            strings,
            symbols,
            maps,
            instructions,
            relocations,
        ];
        let mut elf = vec![0u8; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        w16(&mut elf, 16, 1);
        w16(&mut elf, 18, 247);
        w32(&mut elf, 20, 1);
        w16(&mut elf, 52, 64);
        w16(&mut elf, 58, 64);
        w16(&mut elf, 60, 7);
        w16(&mut elf, 62, 1);
        let mut offsets = Vec::new();
        for section in &sections {
            while elf.len() % 8 != 0 {
                elf.push(0);
            }
            offsets.push(elf.len());
            elf.extend_from_slice(section);
        }
        while elf.len() % 8 != 0 {
            elf.push(0);
        }
        let shoff = elf.len();
        w64(&mut elf, 40, shoff as u64);
        elf.resize(shoff + 7 * 64, 0);
        for index in 1..7 {
            let at = shoff + index * 64;
            w32(&mut elf, at, section_names[index] as u32);
            w32(
                &mut elf,
                at + 4,
                match index {
                    1 | 2 => 3,
                    3 => 2,
                    6 => 9,
                    _ => 1,
                },
            );
            w64(
                &mut elf,
                at + 8,
                if index == 5 || (other_exec && index == 6) {
                    6
                } else {
                    0
                },
            );
            w64(&mut elf, at + 24, offsets[index] as u64);
            w64(&mut elf, at + 32, sections[index].len() as u64);
            w64(&mut elf, at + 48, 8);
            if index == 3 {
                w32(&mut elf, at + 40, 2);
                w32(&mut elf, at + 44, 1);
                w64(&mut elf, at + 56, 24);
            }
            if index == 6 {
                w32(&mut elf, at + 40, 3);
                w32(&mut elf, at + 44, 5);
                w64(&mut elf, at + 56, 16);
            }
        }
        elf
    }

    fn prepared_count() -> crate::loader::Prepared {
        let bytes = synthetic_count_elf("count_entry", false, None, false);
        assert!(
            crate::discovery::onboard::check_installed_role_compatible(Role::Count, &bytes).is_ok()
        );
        crate::loader::prepare(
            &bytes,
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
        )
        .unwrap()
    }

    #[test]
    fn package_count_incompatible_root_rejected_before_setup() {
        let valid = synthetic_count_elf("count_entry", false, None, false);
        assert!(crate::loader::validate_count_object(&valid).is_ok());
        assert!(
            crate::discovery::onboard::check_installed_role_compatible(Role::Count, &valid).is_ok()
        );
        for bad in [
            synthetic_count_elf("count_entry", false, Some("other_entry"), false),
            synthetic_count_elf("other_entry", false, None, false),
            synthetic_count_elf("count_entry", false, Some("count_entry"), false),
            synthetic_count_elf("count_entry", true, None, false),
            synthetic_count_elf("count_entry", false, None, true),
        ] {
            assert!(crate::loader::validate_count_object(&bad).is_err());
            assert!(matches!(
                crate::discovery::onboard::check_installed_role_compatible(Role::Count, &bad),
                Err(PackageError::Invalid { .. })
            ));
        }
    }

    #[test]
    fn package_count_prepared_callback_rejected_before_setup() {
        let mut prepared = prepared_count();
        assert!(crate::discovery::onboard::validate_installed_count_prepared(&prepared).is_ok());
        prepared.progs[0].subprogs[0].is_callback = true;
        assert!(matches!(
            crate::discovery::onboard::validate_installed_count_prepared(&prepared),
            Err(PackageError::Invalid { .. })
        ));
    }

    #[test]
    fn package_count_tail_call_rejected_before_setup() {
        let mut prepared = prepared_count();
        assert!(
            prepared.progs[0]
                .map_fixups
                .iter()
                .all(|fixup| fixup.insn_off < 112)
        );
        // At a non-fixup site, an ordinary helper call is accepted. Only the
        // helper ID changes in the rejected neighbor.
        prepared.progs[0].insns[112..120].copy_from_slice(&[0x85, 0, 0, 0, 1, 0, 0, 0]);
        prepared.progs[0].insns[120..128].copy_from_slice(&[0xb7, 0, 0, 0, 0, 0, 0, 0]);
        assert!(crate::discovery::onboard::validate_installed_count_prepared(&prepared).is_ok());
        prepared.progs[0].insns[116] = 12;
        assert!(matches!(
            crate::discovery::onboard::validate_installed_count_prepared(&prepared),
            Err(PackageError::Invalid { .. })
        ));
    }

    #[test]
    fn package_count_pseudofunction_rejected_before_setup() {
        let mut prepared = prepared_count();
        assert!(
            prepared.progs[0]
                .map_fixups
                .iter()
                .all(|fixup| fixup.insn_off < 112)
        );
        assert_eq!(prepared.progs[0].insns[112], 0x18);
        assert_eq!(prepared.progs[0].insns[113], 0);
        assert!(crate::discovery::onboard::validate_installed_count_prepared(&prepared).is_ok());
        prepared.progs[0].insns[113] = 0x40;
        assert!(matches!(
            crate::discovery::onboard::validate_installed_count_prepared(&prepared),
            Err(PackageError::Invalid { .. })
        ));
    }

    #[test]
    fn package_count_fixup_rejected_before_setup() {
        let valid = prepared_count();
        assert!(!valid.progs[0].map_fixups.is_empty());
        let mut unknown_map = prepared_count();
        unknown_map.progs[0].map_fixups[0].map = "NOT_A_COUNT_MAP".into();
        assert!(matches!(
            crate::discovery::onboard::validate_installed_count_prepared(&unknown_map),
            Err(PackageError::Invalid { .. })
        ));
        let mut malformed_site = prepared_count();
        malformed_site.progs[0].insns[0] = 0x95;
        assert!(matches!(
            crate::discovery::onboard::validate_installed_count_prepared(&malformed_site),
            Err(PackageError::Invalid { .. })
        ));
        assert!(crate::discovery::onboard::validate_installed_count_prepared(&valid).is_ok());
    }
}
