// SPDX-License-Identifier: GPL-3.0-or-later
use goblin::elf::Elf;
use osslscope::provider_observation::static_tables::{TableGap, TableLimits, discover_tables};
use std::{
    fs::{self, File},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new(extra: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-static-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("fixture.so");
        let out = Command::new("cc")
            .args([
                "-shared",
                "-fPIC",
                "-O2",
                "-Wl,-z,relro",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(&path)
            .arg("tests/fixtures/static_tables.c")
            .args(extra)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            Command::new("strip")
                .arg("--strip-all")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        Self { dir, path }
    }
    fn mutate(&self, edit: impl FnOnce(&mut Vec<u8>)) {
        let mut b = fs::read(&self.path).unwrap();
        edit(&mut b);
        fs::write(&self.path, b).unwrap();
    }
    fn discover(&self) -> osslscope::provider_observation::static_tables::TableDiscovery {
        discover_tables(&File::open(&self.path).unwrap(), TableLimits::default()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn sym(b: &[u8], name: &str) -> u64 {
    let e = Elf::parse(b).unwrap();
    e.dynsyms
        .iter()
        .find(|s| e.dynstrtab.get_at(s.st_name) == Some(name))
        .unwrap()
        .st_value
}
fn offset(b: &[u8], va: u64) -> usize {
    let e = Elf::parse(b).unwrap();
    let p = e
        .program_headers
        .iter()
        .find(|p| p.p_type == 1 && va >= p.p_vaddr && va < p.p_vaddr + p.p_filesz)
        .unwrap();
    (p.p_offset + va - p.p_vaddr) as usize
}
fn rela(b: &[u8], va: u64) -> usize {
    let e = Elf::parse(b).unwrap();
    let section = e
        .section_headers
        .iter()
        .find(|s| {
            s.sh_type == 4
                && (s.sh_offset as usize..(s.sh_offset + s.sh_size) as usize)
                    .step_by(24)
                    .any(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) == va)
        })
        .unwrap();
    (section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize)
        .step_by(24)
        .find(|&i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) == va)
        .unwrap()
}
#[test]
fn stripped_layouts_retain_unknown_ids_distinct_algorithms_and_shared_implementation() {
    for flags in [
        &[][..],
        &["-DLAYOUT_TWO", "-Wl,-z,pack-relative-relocs"][..],
    ] {
        let f = Fixture::new(flags);
        // Remove section headers entirely: no private/debug symbols are available.
        f.mutate(|b| {
            b[40..48].fill(0);
            b[58..64].fill(0);
        });
        let d = f.discover();
        assert_eq!(d.algorithm_count(), 2);
        assert_eq!(
            d.dispatch_table_count(),
            1,
            "suffixes are not independent tables"
        );
        assert_eq!(d.function_ids().collect::<Vec<_>>(), vec![70001, 70002]);
        let ids = d.algorithm_ids().collect::<Vec<_>>();
        assert_ne!(ids[0], ids[1]);
    }
}
#[test]
fn out_of_file_and_mid_instruction_targets_never_become_candidates() {
    for invalid in [u64::MAX, 1] {
        let f = Fixture::new(&[]);
        f.mutate(|b| {
            let va = sym(b, "test_dispatch");
            for slot in [va + 8, va + 24] {
                let r = rela(b, slot);
                let old = u64::from_le_bytes(b[r + 16..r + 24].try_into().unwrap());
                let value = if invalid == 1 { old + 1 } else { invalid };
                b[r + 16..r + 24].copy_from_slice(&value.to_le_bytes());
            }
        });
        let d = f.discover();
        assert_eq!(d.candidate_count(), 0);
        assert!(d.gaps().contains(&if invalid == 1 {
            TableGap::MissingFunctionStart
        } else {
            TableGap::Bounds
        }));
    }
}
#[test]
fn unsupported_relocations_and_ifunc_fail_closed() {
    for kind in [42u64, 37] {
        let f = Fixture::new(&[]);
        f.mutate(|b| {
            let va = sym(b, "test_dispatch");
            for slot in [va + 8, va + 24] {
                let r = rela(b, slot);
                b[r + 8..r + 16].copy_from_slice(&kind.to_le_bytes());
            }
        });
        let d = f.discover();
        assert_eq!(d.candidate_count(), 0);
        assert!(d.gaps().contains(&TableGap::UnsupportedRelocation));
    }
}
#[test]
fn absent_function_start_records_fail_closed() {
    let f = Fixture::new(&["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"]);
    let d = f.discover();
    assert_eq!(d.candidate_count(), 0);
    assert!(d.gaps().contains(&TableGap::MissingFunctionStart));
}
#[test]
fn unterminated_and_malformed_dispatches_are_rejected() {
    for id in [1u64, u64::MAX] {
        let f = Fixture::new(&[]);
        f.mutate(|b| {
            let va = sym(b, "test_dispatch");
            let at = offset(b, va + 32);
            b[at..at + 8].copy_from_slice(&id.to_le_bytes());
        });
        assert_eq!(f.discover().candidate_count(), 0);
    }
}
#[test]
fn resource_and_overflow_limits_are_finite() {
    let f = Fixture::new(&[]);
    for limits in [
        TableLimits {
            max_object_bytes: 1,
            ..TableLimits::default()
        },
        TableLimits {
            max_metadata_bytes: 1,
            ..TableLimits::default()
        },
        TableLimits {
            max_entries: 1,
            ..TableLimits::default()
        },
        TableLimits {
            max_tables: 0,
            ..TableLimits::default()
        },
    ] {
        assert!(matches!(
            discover_tables(&File::open(&f.path).unwrap(), limits),
            Err(TableGap::Resource)
        ));
    }
    f.mutate(|b| b[32..40].copy_from_slice(&u64::MAX.to_le_bytes()));
    assert!(matches!(
        discover_tables(&File::open(&f.path).unwrap(), TableLimits::default()),
        Err(TableGap::Bounds)
    ));
}
#[test]
#[ignore = "opt-in local ELF inspection; set OSSLSCOPE_STATIC_ELF"]
fn inspect_local_stock_object() {
    let path = std::env::var_os("OSSLSCOPE_STATIC_ELF").expect("OSSLSCOPE_STATIC_ELF");
    let begin = std::time::Instant::now();
    let d = discover_tables(&File::open(path).unwrap(), TableLimits::default()).unwrap();
    println!(
        "elapsed_us={} read_bytes={} metadata_bytes={}",
        begin.elapsed().as_micros(),
        d.read_bytes(),
        d.metadata_bytes()
    );
    println!(
        "algorithms={} dispatch_tables={} candidates={} partial_tables={} gaps={:?}",
        d.algorithm_count(),
        d.dispatch_table_count(),
        d.candidate_count(),
        d.partial_table_count(),
        d.gaps()
    );
    assert!(d.algorithm_count() > 0);
    assert!(d.candidate_count() > 0);
}

#[test]
fn unwind_index_cannot_invent_a_mid_instruction_function_start() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let va = sym(b, "test_dispatch");
        let r = rela(b, va + 8);
        let target = u64::from_le_bytes(b[r + 16..r + 24].try_into().unwrap());
        for slot in [va + 8, va + 24] {
            let r = rela(b, slot);
            b[r + 16..r + 24].copy_from_slice(&(target + 1).to_le_bytes());
        }
        let e = Elf::parse(b).unwrap();
        let ph = e
            .program_headers
            .iter()
            .find(|p| p.p_type == 0x6474e550)
            .unwrap();
        let off = ph.p_offset as usize;
        let base = ph.p_vaddr;
        assert_eq!(&b[off..off + 4], &[1, 0x1b, 3, 0x3b]);
        let count = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap());
        let row = (0..count as usize)
            .map(|i| off + 12 + i * 8)
            .find(|&i| {
                base.checked_add_signed(i32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as i64)
                    == Some(target)
            })
            .unwrap();
        let value = i32::from_le_bytes(b[row..row + 4].try_into().unwrap());
        b[row..row + 4].copy_from_slice(&(value + 1).to_le_bytes());
    });
    match discover_tables(&File::open(&f.path).unwrap(), TableLimits::default()) {
        Ok(d) => assert_eq!(d.candidate_count(), 0),
        Err(gap) => assert!(matches!(
            gap,
            TableGap::Malformed | TableGap::MissingFunctionStart
        )),
    }
}

#[test]
fn mutable_non_relro_tables_are_not_static_candidates() {
    let f = Fixture::new(&["-Wl,-z,norelro"]);
    assert_eq!(f.discover().candidate_count(), 0);
}

#[test]
fn one_entry_future_id_table_is_admitted() {
    let f = Fixture::new(&["-DONE_ENTRY"]);
    let d = f.discover();
    assert_eq!(d.function_ids().collect::<Vec<_>>(), vec![70001]);
    assert_eq!(d.algorithm_count(), 2);
}

#[test]
fn symbol_start_requires_a_valid_executable_section_when_sections_exist() {
    let f = Fixture::new(&[
        "-DEXPORTED_IMPL",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
    ]);
    assert_eq!(
        f.discover().candidate_count(),
        2,
        "exported function start corroborates the table"
    );
    f.mutate(|b| {
        let e = Elf::parse(b).unwrap();
        let index = e
            .dynsyms
            .iter()
            .position(|s| e.dynstrtab.get_at(s.st_name) == Some("implementation"))
            .unwrap();
        let section = e.section_headers.iter().find(|s| s.sh_type == 11).unwrap();
        let at = section.sh_offset as usize + index * 24;
        b[at + 6..at + 8].copy_from_slice(&1234u16.to_le_bytes());
    });
    assert_eq!(f.discover().candidate_count(), 0);
}

#[test]
fn candidate_table_limit_includes_algorithm_record_shapes() {
    let f = Fixture::new(&[]);
    let limits = TableLimits {
        max_tables: 1,
        ..TableLimits::default()
    };
    assert!(matches!(
        discover_tables(&File::open(&f.path).unwrap(), limits),
        Err(TableGap::Resource)
    ));
}

#[test]
fn retained_descriptor_survives_path_replacement() {
    let f = Fixture::new(&[]);
    let file = File::open(&f.path).unwrap();
    fs::rename(&f.path, f.dir.join("retained.so")).unwrap();
    fs::write(&f.path, b"unrelated replacement").unwrap();
    assert_eq!(
        discover_tables(&file, TableLimits::default())
            .unwrap()
            .algorithm_count(),
        2
    );
}

#[test]
fn public_records_in_opaque_containers_are_only_shape_candidates() {
    let f = Fixture::new(&["-DOPAQUE_RECORDS"]);
    let d = f.discover();
    assert_eq!(d.algorithm_count(), 2);
    assert_eq!(d.dispatch_table_count(), 1);
    f.mutate(|b| {
        let at = offset(b, sym(b, "test_dispatch") + 32);
        b[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
    });
    assert_eq!(
        f.discover().candidate_count(),
        0,
        "a public record does not excuse an unterminated dispatch"
    );
}

#[test]
fn empty_properties_and_opaque_control_bytes_remain_private_metadata() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let r = rela(b, sym(b, "test_algorithms") + 8);
        let address = u64::from_le_bytes(b[r + 16..r + 24].try_into().unwrap());
        let at = offset(b, address);
        b[at] = 0;
    });
    assert_eq!(f.discover().algorithm_count(), 2);
    f.mutate(|b| {
        let r = rela(b, sym(b, "test_algorithms"));
        let address = u64::from_le_bytes(b[r + 16..r + 24].try_into().unwrap());
        let at = offset(b, address);
        b[at] = b'\n';
    });
    let d = f.discover();
    assert_eq!(d.algorithm_count(), 2);
    let ids = d.algorithm_ids().collect::<Vec<_>>();
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn symbol_typed_ifunc_is_not_an_ordinary_function_start() {
    let f = Fixture::new(&["-DEXPORTED_IMPL"]);
    f.mutate(|b| {
        let e = Elf::parse(b).unwrap();
        let index = e
            .dynsyms
            .iter()
            .position(|s| e.dynstrtab.get_at(s.st_name) == Some("implementation"))
            .unwrap();
        let section = e.section_headers.iter().find(|s| s.sh_type == 11).unwrap();
        let at = section.sh_offset as usize + index * 24;
        b[at + 4] = (b[at + 4] & 0xf0) | 10;
    });
    let d = f.discover();
    assert_eq!(d.candidate_count(), 0);
    assert!(d.gaps().contains(&TableGap::UnsupportedRelocation));
}

#[test]
fn relr_bitmap_requires_a_preceding_base() {
    let f = Fixture::new(&["-Wl,-z,pack-relative-relocs"]);
    f.mutate(|b| {
        let e = Elf::parse(b).unwrap();
        let at = e
            .section_headers
            .iter()
            .find(|s| s.sh_type == 19)
            .unwrap()
            .sh_offset as usize;
        b[at..at + 8].copy_from_slice(&3u64.to_le_bytes());
    });
    assert!(matches!(
        discover_tables(&File::open(&f.path).unwrap(), TableLimits::default()),
        Err(TableGap::Malformed)
    ));
}

#[test]
fn unresolved_ordinary_linkage_preserves_only_independently_valid_local_rows() {
    let f = Fixture::new(&["-DEXTERNAL_ROW"]);
    let d = f.discover();
    assert_eq!(d.function_ids().collect::<Vec<_>>(), vec![70001]);
    assert_eq!(d.algorithm_count(), 2);
    assert_eq!(d.partial_table_count(), 1);
    assert!(d.gaps().contains(&TableGap::UnsupportedRelocation));
    f.mutate(|b| {
        let r = rela(b, sym(b, "test_dispatch") + 24);
        b[r + 8..r + 16].copy_from_slice(&37u64.to_le_bytes());
    });
    assert_eq!(
        f.discover().candidate_count(),
        0,
        "IFUNC is not an ordinary unresolved linkage"
    );
}

#[test]
fn partial_linkage_never_excuses_a_mid_instruction_local_row() {
    let f = Fixture::new(&["-DEXTERNAL_ROW"]);
    f.mutate(|b| {
        let r = rela(b, sym(b, "test_dispatch") + 8);
        let address = u64::from_le_bytes(b[r + 16..r + 24].try_into().unwrap());
        b[r + 16..r + 24].copy_from_slice(&(address + 1).to_le_bytes());
    });
    let d = f.discover();
    assert_eq!(d.candidate_count(), 0);
    assert!(d.gaps().contains(&TableGap::MissingFunctionStart));
}

#[test]
fn alias_association_expansion_is_bounded_separately_from_source_entries() {
    let f = Fixture::new(&["-DEXTRA_SHARED"]);
    assert_eq!(f.discover().algorithm_count(), 3);
    // Two dispatch entries plus three public records fit the source-entry
    // budget, but produce six algorithm/function associations.
    let limits = TableLimits {
        max_entries: 5,
        ..TableLimits::default()
    };
    assert!(matches!(
        discover_tables(&File::open(&f.path).unwrap(), limits),
        Err(TableGap::Resource)
    ));
}

#[test]
fn repeated_public_ids_preserve_all_validated_static_row_candidates() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let at = offset(b, sym(b, "test_dispatch") + 16);
        b[at..at + 8].copy_from_slice(&70001u64.to_le_bytes());
    });
    let d = f.discover();
    assert_eq!(d.algorithm_count(), 2);
    assert_eq!(d.function_ids().collect::<Vec<_>>(), vec![70001, 70001]);
    assert_eq!(d.candidate_count(), 2);
}

#[test]
fn dispatch_ids_do_not_interpret_unspecified_abi_padding() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let address = sym(b, "test_dispatch");
        for row in [0, 16, 32] {
            let at = offset(b, address + row + 4);
            b[at..at + 4].copy_from_slice(&0xaabbccddu32.to_le_bytes());
        }
    });
    let d = f.discover();
    assert_eq!(d.function_ids().collect::<Vec<_>>(), vec![70001, 70002]);
    assert_eq!(d.algorithm_count(), 2);
}

#[test]
fn zero_id_terminates_without_interpreting_the_ignored_function_field() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let address = sym(b, "test_dispatch");
        let at = offset(b, address + 40);
        b[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    });
    let d = f.discover();
    assert_eq!(d.candidate_count(), 2);
    assert_eq!(d.algorithm_count(), 2);
}

#[test]
fn unfamiliar_utf8_and_non_utf8_records_keep_distinct_opaque_identities() {
    let mut prior = None;
    for flags in [["-DUTF8_NAMES"], ["-DBINARY_NAMES"]] {
        let f = Fixture::new(&flags);
        let d = f.discover();
        assert_eq!(d.algorithm_count(), 2);
        let ids = d.algorithm_ids().collect::<Vec<_>>();
        assert_ne!(ids[0], ids[1]);
        for id in &ids {
            let token = format!("{id:?}");
            assert!(token.is_ascii());
            assert!(!token.contains("unrecognized"));
        }
        if let Some(before) = prior {
            assert_ne!(before, ids[0]);
        }
        prior = Some(ids[0]);
    }
}

#[test]
fn unterminated_alias_at_a_load_boundary_is_rejected() {
    let f = Fixture::new(&[]);
    f.mutate(|b| {
        let e = Elf::parse(b).unwrap();
        let segment = e
            .program_headers
            .iter()
            .filter(|p| p.p_type == 1 && p.p_flags == 4)
            .max_by_key(|p| p.p_vaddr)
            .unwrap();
        let address = segment.p_vaddr + segment.p_filesz - 1;
        let at = (segment.p_offset + segment.p_filesz - 1) as usize;
        b[at] = 0xff;
        let r = rela(b, sym(b, "test_algorithms"));
        b[r + 16..r + 24].copy_from_slice(&address.to_le_bytes());
    });
    let d = f.discover();
    assert_eq!(d.algorithm_count(), 1);
    assert!(d.gaps().contains(&TableGap::Bounds));
}

#[test]
fn null_names_are_not_confused_with_bytes_at_elf_virtual_zero() {
    let f = Fixture::new(&["-DNULL_NAME"]);
    let d = f.discover();
    assert_eq!(d.algorithm_count(), 1);
    assert!(d.gaps().contains(&TableGap::Malformed));
}
