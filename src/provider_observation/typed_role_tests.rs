// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct PublicExports(std::path::PathBuf);
impl PublicExports {
    fn new(conflicting: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "osslscope-typed-export-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut code = String::from(
            "void *EVP_MAC_fetch(void *c,const char *n,const char *p){return c;}\nvoid EVP_MAC_free(void *m){}\nvoid *OSSL_PROVIDER_get0_provider_ctx(const void *p){return (void *)p;}\nvoid OPENSSL_cleanup(void){}\nvoid EVP_MAC_fetch_extra(void){}\n",
        );
        if conflicting {
            code.push_str("void EVP_KDF_free(void *m) __attribute__((alias(\"EVP_MAC_free\")));\n");
        }
        std::fs::write(path.join("public.c"), code).unwrap();
        let output = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(path.join("public.so"))
            .arg(path.join("public.c"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(path)
    }
    fn parsed(&self) -> ElfObject {
        parse_object(
            &mut File::open(self.0.join("public.so")).unwrap(),
            None,
            &ObservationBudget::default(),
        )
        .unwrap()
    }
}
impl Drop for PublicExports {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn exact_typed_public_exports_are_independent_from_legacy_event_roles() {
    let object = PublicExports::new(false).parsed();
    let roles: Vec<_> = object
        .typed_exports
        .iter()
        .map(|(role, _)| role.id())
        .collect();
    assert_eq!(roles, vec![130, 136, 146, 155]);
    assert!(!object.typed_partial);
    assert_eq!(object.exports.len(), 1);
    assert_eq!(object.exports[0].0.export_name(), Some("EVP_MAC_fetch"));
}
#[test]
fn typed_public_roles_stage_first_slice_exports_only() {
    // P3-I2 permanent-negative premise: the host stages exactly the 17
    // first-slice public roles and nothing at or above the copied-role
    // boundary (256+), so constructor/operational callbacks are
    // unreachable before phase-2 U1 staging lands. H2/H3 pin the
    // resulting definite=0 from the fail-closed side; this pins the
    // table those pins stand on.
    assert_eq!(
        TYPED_PUBLIC_ROLES,
        [
            5, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155
        ]
    );
    assert_eq!(TYPED_PUBLIC_ROLES.len(), TYPED_PUBLIC_ROLE_COUNT);
    assert!(TYPED_PUBLIC_ROLES.iter().all(|role| *role < 256));
}
#[test]
fn shared_code_conflicting_typed_roles_refuses_both_and_retains_other_facts() {
    let object = PublicExports::new(true).parsed();
    let roles: Vec<_> = object
        .typed_exports
        .iter()
        .map(|(role, _)| role.id())
        .collect();
    assert_eq!(roles, vec![130, 146, 155]);
    assert!(object.typed_partial);
    assert_eq!(object.exports.len(), 1);
}

#[test]
fn typed_capability_memory_is_charged_before_it_can_escape() {
    use std::os::fd::AsRawFd;
    let fixture = PublicExports::new(false);
    let file = File::open(fixture.0.join("public.so")).unwrap();
    let length = file.metadata().unwrap().len() as usize;
    // This source test maps its own public ELF fixture. It loads no BPF and
    // invokes none of its functions; descriptor/mapping validation is real.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(address, libc::MAP_FAILED);
    struct Mapped(*mut libc::c_void, usize);
    impl Drop for Mapped {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.0, self.1) }, 0);
        }
    }
    let _mapped = Mapped(address, length);
    let mut options = inventory::SnapshotOptions::default();
    options.pids = vec![std::process::id()];
    options.limits.max_objects_per_process = 0;
    let record = inventory::snapshot(&options)
        .processes
        .into_iter()
        .next()
        .unwrap();
    let budget = ObservationBudget::new(super::super::ObservationLimits {
        max_state_bytes: PARSER_STATE_BYTES + 255,
        ..Default::default()
    });
    let process = fixture_support::mapped_process(&record, file.try_clone().unwrap(), &budget);
    assert!(
        process
            .resolve_typed_api(TypedRoleId::from_u32(130).unwrap())
            .is_empty()
    );
    assert!(process.gaps().contains(&ObservationGap::StateLimit));
    let available = ObservationBudget::default();
    let process = fixture_support::mapped_process(&record, file.try_clone().unwrap(), &available);
    let sites = process.resolve_typed_api(TypedRoleId::from_u32(130).unwrap());
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].role().id(), 130);
    assert_eq!(sites[0].site().inode(), file.metadata().unwrap().ino());
    sites[0].site().revalidate_object().unwrap();
    let reads = available.elf_read_bytes();
    let free = process.resolve_typed_api(TypedRoleId::from_u32(136).unwrap());
    assert_eq!(free.len(), 1);
    assert!(Rc::ptr_eq(&sites[0]._anchor, &free[0]._anchor));
    assert_eq!(
        available.elf_read_bytes(),
        reads,
        "one backing anchor per retained object"
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        fixture.0.join("public.so"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(sites[0].site().revalidate_object().is_err());
    assert!(
        process
            .resolve_typed_api(TypedRoleId::from_u32(130).unwrap())
            .is_empty()
    );
}

#[test]
fn ambiguous_typed_symbol_definition_retains_discovery_but_grants_no_reader() {
    let fixture = PublicExports::new(false);
    let path = fixture.0.join("public.so");
    let mut image = std::fs::read(&path).unwrap();
    let (rewrite, name) = {
        let elf = goblin::elf::Elf::parse(&image).unwrap();
        let header = elf
            .section_headers
            .iter()
            .find(|h| h.sh_type == goblin::elf::section_header::SHT_DYNSYM)
            .unwrap();
        let free = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some("EVP_MAC_free"))
            .unwrap();
        let extra = elf
            .dynsyms
            .iter()
            .position(|s| elf.dynstrtab.get_at(s.st_name) == Some("EVP_MAC_fetch_extra"))
            .unwrap();
        (header.sh_offset as usize + extra * 24, free.st_name as u32)
    };
    image[rewrite..rewrite + 4].copy_from_slice(&name.to_le_bytes());
    std::fs::write(path, image).unwrap();
    let object = fixture.parsed();
    assert!(object.typed_partial);
    assert!(object.typed_exports.is_empty());
    assert_eq!(object.exports.len(), 1);
}

#[test]
fn held_startup_exports_prepare_typed_sources_without_legacy_fetch_promotion() {
    let fixture = PublicExports::new(false);
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let budget = ObservationBudget::default();
    let discovered = startup_candidates(
        StartupProcess::held(&child).unwrap(),
        File::open(fixture.0.join("public.so")).unwrap(),
        &budget,
        None,
    )
    .unwrap();
    assert!(
        discovered.apis.is_empty(),
        "legacy mapped-only fetch stays separate"
    );
    assert_eq!(
        discovered
            .typed
            .iter()
            .map(|site| site.role.id())
            .collect::<Vec<_>>(),
        vec![130, 136, 146, 155]
    );
    let mut prepared = Vec::new();
    for candidate in discovered.typed {
        let site = candidate.prepare(&budget).unwrap();
        assert!(site.site.is_startup());
        assert_eq!(site.site.pid(), child.pid());
        site.site.revalidate_object().unwrap();
        prepared.push(site);
    }
    assert!(
        prepared[1..]
            .iter()
            .all(|site| Rc::ptr_eq(&site._anchor, &prepared[0]._anchor))
    );
}

#[test]
fn refused_startup_source_preparation_keeps_legacy_owned_exports() {
    use std::io::Write;
    let fixture = PublicExports::new(false);
    let mut code = std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.0.join("public.c"))
        .unwrap();
    code.write_all(b"void OSSL_PROVIDER_unquery_operation(void *p,int op,void *a){}\n")
        .unwrap();
    drop(code);
    assert!(
        std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(fixture.0.join("public.so"))
            .arg(fixture.0.join("public.c"))
            .status()
            .unwrap()
            .success()
    );
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let mut discovered = startup_candidates(
        StartupProcess::held(&child).unwrap(),
        File::open(fixture.0.join("public.so")).unwrap(),
        &ObservationBudget::default(),
        None,
    )
    .unwrap();
    assert_eq!(discovered.apis.len(), 1);
    let refused = ObservationBudget::new(super::super::ObservationLimits {
        max_state_bytes: 0,
        ..Default::default()
    });
    assert!(matches!(
        discovered.typed.remove(0).prepare(&refused),
        Err(ObservationGap::StateLimit)
    ));
    let (api, site) = discovered.apis.remove(0).into_parts();
    assert_eq!(api, ObservationApi::OsslProviderUnqueryOperation);
    site.revalidate_object().unwrap();
}
