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

#[test]
fn startup_discovery_releases_table_scratch_between_files() {
    // U3 frugality: the startup path drops its table discovery after
    // extracting the separately-charged outputs, so the 4 MiB table
    // ceiling must not accumulate per file. Two discoveries of the
    // same file under an 8 MiB budget prove it: retaining code holds
    // ~4.4 MiB after the first file and refuses the second file's
    // ~4.3 MiB peak (~8.7 MiB > 8 MiB); releasing code peaks near
    // ~4.5 MiB both times. Both discoveries return Ok, which proves
    // the tables parse succeeded (a failed parse returns Err, which
    // would make this control vacuous).
    let fixture = PublicExports::new(false);
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let custody = StartupProcess::held(&child).unwrap();
    let budget = ObservationBudget::new(super::super::ObservationLimits {
        max_state_bytes: 8 << 20,
        ..Default::default()
    });
    for round in 0..2 {
        let discovered = startup_candidates(
            custody.clone(),
            File::open(fixture.0.join("public.so")).unwrap(),
            &budget,
            None,
        )
        .unwrap_or_else(|gap| panic!("round {round} must fit without retained scratch: {gap:?}"));
        assert_eq!(discovered.plan_gap, None, "round {round} keeps its plan");
        assert_eq!(
            discovered.typed_gap, None,
            "round {round} keeps its typed sites"
        );
    }
}

#[test]
fn startup_plan_charge_withholds_only_plan_inputs_when_tight() {
    // U3 accounting: the pass-2 plan inputs carry their own retention
    // charge (the released table scratch no longer covers them). A
    // budget sized exactly one byte below the full charge refuses only
    // the plan inputs — the charged sites are kept and pass 2 stages
    // nothing from this file — while the exact budget keeps everything.
    use super::super::copied_plan::plan_arrays_charge;
    let fixture = PublicExports::new(false);
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let custody = StartupProcess::held(&child).unwrap();
    let generous = startup_candidates(
        custody.clone(),
        File::open(fixture.0.join("public.so")).unwrap(),
        &ObservationBudget::default(),
        None,
    )
    .unwrap();
    assert_eq!(generous.plan_gap, None);
    let files = generous.plan_arrays;
    let held_peak = TableLimits::default().max_metadata_bytes;
    let exact = PARSER_STATE_BYTES
        + held_peak
        + generous.apis.len() * 256
        + generous.candidates.len() * (std::mem::size_of::<VerifiedStaticCandidate>() * 2)
        + generous.typed.len() * 256
        + plan_arrays_charge(&files).unwrap();
    // One byte short: the plan charge (the last charge, still under
    // the held table ceiling) refuses; sites are kept, plan withheld.
    let tight = ObservationBudget::new(super::super::ObservationLimits {
        max_state_bytes: exact - 1,
        ..Default::default()
    });
    let refused = startup_candidates(
        custody.clone(),
        File::open(fixture.0.join("public.so")).unwrap(),
        &tight,
        None,
    )
    .unwrap();
    assert_eq!(refused.plan_gap, Some(ObservationGap::StateLimit));
    assert_eq!(refused.apis.len(), generous.apis.len());
    assert_eq!(refused.typed.len(), generous.typed.len());
    assert_eq!(refused.candidates.len(), generous.candidates.len());
    assert!(refused.plan_arrays.inputs.is_empty());
    assert_eq!(refused.plan_arrays.hash, files.hash);
    // The exact byte keeps everything.
    let roomy = ObservationBudget::new(super::super::ObservationLimits {
        max_state_bytes: exact,
        ..Default::default()
    });
    let kept = startup_candidates(
        custody.clone(),
        File::open(fixture.0.join("public.so")).unwrap(),
        &roomy,
        None,
    )
    .unwrap();
    assert_eq!(kept.plan_gap, None);
    assert_eq!(kept.plan_arrays, files);
}
