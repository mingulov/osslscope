//! Disk-ELF helpers: `.dynsym` lookup + vaddr↔offset translation.
//! No symbols are used past the `OSSL_provider_init` anchor, which is
//! load-mandated and present even in stripped modules. The built-in
//! ladder (P1 exit 2) adds `.symtab` + build-id + version-name helpers.
use crate::kinds::Version;
use anyhow::{Context as _, bail};
use goblin::elf::program_header::{PF_X, PT_LOAD, PT_NOTE};
use std::collections::HashMap;

/// Note type `NT_GNU_BUILD_ID` (3); owner name is `GNU\0`.
const NT_GNU_BUILD_ID: u32 = 3;

/// File offset of a defined `.dynsym` symbol via PT_LOAD vaddr→offset.
pub fn dynsym_file_offset(elf_bytes: &[u8], want: &str) -> anyhow::Result<u64> {
    let obj = goblin::Object::parse(elf_bytes)?;
    let goblin::Object::Elf(elf) = obj else {
        bail!("provider is not an ELF object")
    };
    let mut vaddr = None;
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx != 0 && elf.dynstrtab.get_at(sym.st_name) == Some(want) {
            vaddr = Some(sym.st_value);
            break;
        }
    }
    let vaddr = vaddr.ok_or_else(|| anyhow::anyhow!("{want} not exported"))?;
    vaddr_to_offset(&elf, vaddr)
        .ok_or_else(|| anyhow::anyhow!("{want} vaddr {vaddr:#x} outside PT_LOAD"))
}

/// Defined dynamic FUNC symbols as (name, file offset), sorted and
/// deduped. Tripwire building block: prefix matching needs the full
/// set, and uprobes only fire on code (OBJECT/NOTYPE matches would
/// attach to data that can never execute).
pub fn dynsym_func_entries(elf_bytes: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    let obj = goblin::Object::parse(elf_bytes)?;
    let goblin::Object::Elf(elf) = obj else {
        bail!("object is not an ELF object")
    };
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == 0 || sym.st_type() != goblin::elf::sym::STT_FUNC {
            continue;
        }
        let (Some(name), Some(off)) = (
            elf.dynstrtab.get_at(sym.st_name),
            vaddr_to_offset(&elf, sym.st_value),
        ) else {
            continue;
        };
        out.push((name.to_string(), off));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Undefined (imported) FUNC/NOTYPE names from `.dynsym`: the
/// module's external calls. NOTYPE included (a missed import is a
/// silent tripwire gap; data imports never match the call-only
/// taxonomy anyway).
pub fn und_imports(elf_bytes: &[u8]) -> anyhow::Result<Vec<String>> {
    use goblin::elf::sym::{STT_FUNC, STT_NOTYPE};
    let elf = parse_elf(elf_bytes)?;
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx != 0 {
            continue;
        }
        if sym.st_type() != STT_FUNC && sym.st_type() != STT_NOTYPE {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            out.push(name.to_string());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// PLT stub file offsets for x86-64 imports, by name. JMPREL order
/// selects the stub: 16B PLT0 + 16B entries in `.plt.sec` (old-style
/// `.plt` fallback). Empty (not an error) when the object has no PLT
/// machinery — static, section-less, or non-x86-64 — so the caller
/// counts those imports as uninstrumented instead of failing.
pub fn plt_stub_offsets(elf_bytes: &[u8]) -> anyhow::Result<HashMap<String, u64>> {
    use goblin::elf::header::EM_X86_64;
    use goblin::elf::reloc::R_X86_64_JUMP_SLOT;
    let elf = parse_elf(elf_bytes)?;
    let mut out = HashMap::new();
    if elf.header.e_machine != EM_X86_64 {
        return Ok(out);
    }
    let mut plt_addr = None;
    for sh in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".plt.sec" {
                plt_addr = Some(sh.sh_addr);
                break;
            }
            if name == ".plt" {
                plt_addr = Some(sh.sh_addr);
            }
        }
    }
    let Some(plt_addr) = plt_addr else {
        return Ok(out);
    };
    let mut idx = 0u64;
    for reloc in elf.pltrelocs.iter() {
        if reloc.r_type != R_X86_64_JUMP_SLOT {
            continue;
        }
        let name = elf
            .dynsyms
            .get(reloc.r_sym)
            .and_then(|s| elf.dynstrtab.get_at(s.st_name));
        // Slot consumed even when the name is unresolvable.
        let stub = plt_addr + 16 + idx * 16;
        idx += 1;
        let (Some(name), Some(off)) = (name, vaddr_to_offset(&elf, stub)) else {
            continue;
        };
        if offset_in_x_segment(&elf, off) {
            out.insert(name.to_string(), off);
        }
    }
    Ok(out)
}

/// Translate a link-time vaddr to a file offset via the LOAD map.
pub fn vaddr_to_offset(elf: &goblin::elf::Elf, vaddr: u64) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .find(|ph| vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_memsz)
        .map(|ph| vaddr - ph.p_vaddr + ph.p_offset)
}

/// True iff the file offset sits in an executable LOAD segment.
pub fn offset_in_x_segment(elf: &goblin::elf::Elf, offset: u64) -> bool {
    elf.program_headers.iter().any(|ph| {
        ph.p_type == PT_LOAD
            && ph.p_flags & PF_X != 0
            && offset >= ph.p_offset
            && offset < ph.p_offset + ph.p_filesz
    })
}

/// File offset of a defined `.symtab` symbol (debug builds only;
/// stripped modules have no `.symtab` — the ladder's second rung).
pub fn symtab_file_offset(elf_bytes: &[u8], want: &str) -> anyhow::Result<u64> {
    let obj = goblin::Object::parse(elf_bytes)?;
    let goblin::Object::Elf(elf) = obj else {
        bail!("provider is not an ELF object")
    };
    let mut vaddr = None;
    for sym in elf.syms.iter() {
        if sym.st_shndx != 0 && elf.strtab.get_at(sym.st_name) == Some(want) {
            vaddr = Some(sym.st_value);
            break;
        }
    }
    let vaddr = vaddr.ok_or_else(|| anyhow::anyhow!("{want} not in symtab"))?;
    vaddr_to_offset(&elf, vaddr)
        .ok_or_else(|| anyhow::anyhow!("{want} vaddr {vaddr:#x} outside PT_LOAD"))
}

/// GNU build-id of the object (hex), or None when no
/// `.note.gnu.build-id` note is present. Survives stripping by design.
pub fn read_build_id(elf_bytes: &[u8]) -> Option<String> {
    let elf = parse_elf(elf_bytes).ok()?;
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_NOTE)
        .filter_map(|ph| {
            let off = ph.p_offset as usize;
            let len = ph.p_filesz as usize;
            elf_bytes.get(off..off.checked_add(len)?)
        })
        .find_map(parse_build_id_notes)
}

/// Pure `.note.gnu.build-id` parser over one note segment's bytes:
/// namesz/descsz/type + owner + descriptor (4-padded fields).
pub fn parse_build_id_notes(note_bytes: &[u8]) -> Option<String> {
    let mut cur = note_bytes;
    while cur.len() >= 12 {
        let namesz = u32::from_le_bytes(cur[0..4].try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(cur[4..8].try_into().ok()?) as usize;
        let ntype = u32::from_le_bytes(cur[8..12].try_into().ok()?);
        let name_off = 12usize;
        let name_end = name_off.checked_add(namesz.next_multiple_of(4))?;
        let desc_end = name_end.checked_add(descsz.next_multiple_of(4))?;
        if desc_end > cur.len() {
            return None;
        }
        if ntype == NT_GNU_BUILD_ID
            && cur.get(name_off..name_off + namesz) == Some(b"GNU\0".as_slice())
        {
            return Some(
                cur[name_end..name_end + descsz]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            );
        }
        cur = &cur[desc_end..];
    }
    None
}

/// Max `OPENSSL_<major>.<minor>` version name (patch ignored);
/// version nodes live in `.dynstr` even on stripped modules.
pub fn max_openssl_version<'a>(names: impl Iterator<Item = &'a str>) -> Option<Version> {
    names
        .filter_map(|s| {
            let rest = s.strip_prefix("OPENSSL_")?;
            let (maj, rest) = rest.split_once('.')?;
            let min = rest.split('.').next()?;
            Some((maj.parse::<u32>().ok()?, min.parse::<u32>().ok()?))
        })
        .max()
}

/// Parse disk bytes as ELF or fail closed (non-ELF input is never probed).
pub fn parse_elf(elf_bytes: &[u8]) -> anyhow::Result<goblin::elf::Elf<'_>> {
    match goblin::Object::parse(elf_bytes).context("ELF parse")? {
        goblin::Object::Elf(e) => Ok(e),
        _ => bail!("not an ELF object"),
    }
}

#[cfg(test)]
#[unsafe(no_mangle)]
#[allow(clippy::missing_const_for_fn)]
pub extern "C" fn osslscope_test_symtab_anchor() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_bytes() -> Vec<u8> {
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    }

    fn libc_bytes() -> Vec<u8> {
        for p in ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libc.so.6"] {
            if let Ok(b) = std::fs::read(p) {
                return b;
            }
        }
        panic!("no libc at standard paths — broken test env");
    }

    #[test]
    fn self_is_elf() {
        parse_elf(&self_bytes()).unwrap();
    }

    #[test]
    fn dynsym_anchor_roundtrip_on_libc() {
        let b = libc_bytes();
        let elf = parse_elf(&b).unwrap();
        // Known anchor translates (printf is exported by every libc).
        let off = dynsym_file_offset(&b, "printf").unwrap();
        assert!(off < b.len() as u64 && offset_in_x_segment(&elf, off));
        // Every defined export must translate; FUNC symbols (the only
        // ones harvest ever anchors on) must land file-backed in X.
        // (BSS data legitimately translates past EOF: memsz > filesz.)
        let mut n = 0;
        for sym in elf.dynsyms.iter() {
            if sym.st_shndx == 0 || sym.st_value == 0 {
                continue;
            }
            let off = vaddr_to_offset(&elf, sym.st_value);
            assert!(off.is_some(), "export {:#x} outside LOAD", sym.st_value);
            if sym.st_type() == goblin::elf::sym::STT_FUNC {
                assert!(
                    off.unwrap() < b.len() as u64,
                    "func {:#x} past EOF",
                    sym.st_value
                );
                assert!(offset_in_x_segment(&elf, off.unwrap()));
                n += 1;
            }
        }
        assert!(n > 0, "libc exports no functions?");
    }

    #[test]
    fn missing_symbol_fails_loud() {
        let b = self_bytes();
        let r = dynsym_file_offset(&b, "OSSLscope_NoSuchSymbol_Xyz");
        assert!(r.is_err());
    }

    #[test]
    fn non_elf_fails_closed() {
        assert!(parse_elf(b"definitely not an ELF file").is_err());
    }

    #[test]
    fn symtab_anchor_roundtrip_on_self() {
        // Anchor defined below; the call pins the symbol against DCE and
        // test binaries keep .symtab (no strip).
        super::osslscope_test_symtab_anchor();
        let b = self_bytes();
        let off = symtab_file_offset(&b, "osslscope_test_symtab_anchor").unwrap();
        let elf = parse_elf(&b).unwrap();
        assert!(off < b.len() as u64 && offset_in_x_segment(&elf, off));
        assert!(symtab_file_offset(&b, "OSSLscope_NoSuchSymbol_Xyz").is_err());
    }

    #[test]
    fn build_id_note_parses() {
        // namesz=4 descsz=20 type=3 "GNU\0" + 20 desc bytes.
        let mut note = vec![4u8, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0];
        note.extend_from_slice(b"GNU\0");
        note.extend((0..20u8).collect::<Vec<_>>());
        assert_eq!(
            parse_build_id_notes(&note).as_deref(),
            Some("000102030405060708090a0b0c0d0e0f10111213")
        );
        // Wrong type / wrong name / truncated → None.
        let mut bad = note.clone();
        bad[8] = 1;
        assert_eq!(parse_build_id_notes(&bad), None);
        let mut bad = note.clone();
        bad[12] = b'X';
        assert_eq!(parse_build_id_notes(&bad), None);
        assert_eq!(parse_build_id_notes(&note[..note.len() - 1]), None);
        assert_eq!(parse_build_id_notes(b""), None);
    }

    #[test]
    fn libc_has_build_id() {
        // Distro invariant (debuginfod needs it); same posture as the
        // existing libc tests (broken env fails loudly).
        let id = read_build_id(&libc_bytes());
        assert!(id.is_some(), "libc without .note.gnu.build-id?");
        assert!(id.unwrap().len() >= 16);
    }

    #[test]
    fn openssl_version_scan_picks_max() {
        use super::max_openssl_version;
        let s = [
            "libcrypto.so.3",
            "OPENSSL_3.0.0",
            "OPENSSL_3.5.0",
            "OPENSSL_3.0.8",
        ];
        assert_eq!(max_openssl_version(s.iter().copied()), Some((3, 5)));
        let s = ["OPENSSL_4.0.0", "OPENSSL_3.0.0"];
        assert_eq!(max_openssl_version(s.iter().copied()), Some((4, 0)));
        let s = ["GLIBC_2.2.5", "OPENSSL_nope", "OPENSSL_3", "OPENSSL_3.x"];
        assert_eq!(max_openssl_version(s.iter().copied()), None);
        let s: [&str; 0] = [];
        assert_eq!(max_openssl_version(s.iter().copied()), None);
    }

    #[test]
    fn plt_resolves_self_imports_in_x() {
        // Dynamic test binary: every PLT stub is file-backed in X.
        // (PLT names are NOT all UND: self-interposition stubs like
        // libc's realloc resolve locally-defined symbols.)
        let b = self_bytes();
        let elf = parse_elf(&b).unwrap();
        let plt = super::plt_stub_offsets(&b).unwrap();
        assert!(!plt.is_empty(), "dynamic binary without PLT?");
        let und = super::und_imports(&b).unwrap();
        assert!(
            plt.keys().any(|k| und.contains(k)),
            "no PLT stub serves an actual import?"
        );
        for (name, off) in &plt {
            assert!(*off < b.len() as u64, "{name} stub past EOF");
            assert!(offset_in_x_segment(&elf, *off), "{name} stub not in X");
        }
    }

    #[test]
    fn plt_stubs_valid_on_libc() {
        let b = libc_bytes();
        let elf = parse_elf(&b).unwrap();
        let plt = super::plt_stub_offsets(&b).unwrap();
        for (name, off) in &plt {
            assert!(*off < b.len() as u64, "{name} stub past EOF");
            assert!(offset_in_x_segment(&elf, *off), "{name} stub not in X");
        }
    }

    #[test]
    fn header_only_elf_has_no_imports() {
        // No program headers → no dynamic section → no imports, and
        // crucially no error (statically linked shape).
        let mut hdr = vec![0u8; 64];
        hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        hdr[4] = 2; // 64-bit
        hdr[5] = 1; // little-endian
        hdr[6] = 1; // version
        assert_eq!(super::und_imports(&hdr).unwrap(), Vec::<String>::new());
        assert!(super::plt_stub_offsets(&hdr).unwrap().is_empty());
    }

    #[test]
    fn import_scan_fails_closed_on_non_elf() {
        assert!(super::und_imports(b"definitely not an ELF file").is_err());
        assert!(super::plt_stub_offsets(b"definitely not an ELF file").is_err());
    }

    #[test]
    fn dynsym_func_entries_sorted_unique_bounded() {
        let b = libc_bytes();
        let entries = super::dynsym_func_entries(&b).unwrap();
        assert!(!entries.is_empty());
        assert!(entries.windows(2).all(|w| w[0] <= w[1]));
        assert!(entries.iter().all(|(_, o)| *o < b.len() as u64));
        assert!(entries.iter().any(|(n, _)| n == "printf"));
    }
}
