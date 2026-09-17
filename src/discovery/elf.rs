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

/// Decode one 16B x86-64 PLT chunk's GOT target (endbr64 + jmp
/// *GOTPCREL, or bare jmp *GOTPCREL). None for PLT0 and unrecognized
/// shapes (fail-closed per chunk — an unrecognized stub is a gap,
/// never a misattributed probe).
fn plt_chunk_got(chunk: &[u8], chunk_vaddr: u64) -> Option<u64> {
    if chunk.len() < 16 {
        return None;
    }
    let jmp_at = if chunk[0..4] == [0xf3, 0x0f, 0x1e, 0xfa] {
        4
    } else {
        0
    };
    if chunk[jmp_at..jmp_at + 2] != [0xff, 0x25] {
        return None;
    }
    let disp = i32::from_le_bytes(chunk[jmp_at + 2..jmp_at + 6].try_into().ok()?);
    Some(chunk_vaddr + jmp_at as u64 + 6 + disp as i64 as u64)
}

/// PLT stub file offsets for x86-64 imports, by name. Entries are
/// derived from stub bytes (chunk jmp → GOT slot → JUMP_SLOT name),
/// never positional math: split `.plt.sec` holds entries only (no
/// PLT0) while old combined `.plt` holds PLT0 first, and only the
/// bytes distinguish the layouts. Empty (not an error) when the
/// object has no PLT machinery — static, section-less, or non-x86-64
/// — so the caller counts those imports as uninstrumented instead.
pub fn plt_stub_offsets(elf_bytes: &[u8]) -> anyhow::Result<HashMap<String, u64>> {
    use goblin::elf::header::EM_X86_64;
    use goblin::elf::reloc::R_X86_64_JUMP_SLOT;
    let elf = parse_elf(elf_bytes)?;
    let mut out = HashMap::new();
    if elf.header.e_machine != EM_X86_64 {
        return Ok(out);
    }
    // GOT slot → imported name (jump slots only: data relocs are
    // never PLT-jmp targets).
    let mut got_name: HashMap<u64, &str> = HashMap::new();
    for r in elf.pltrelocs.iter() {
        if r.r_type != R_X86_64_JUMP_SLOT {
            continue;
        }
        if let Some(s) = elf.dynsyms.get(r.r_sym) {
            if let Some(n) = elf.dynstrtab.get_at(s.st_name) {
                got_name.insert(r.r_offset, n);
            }
        }
    }
    if got_name.is_empty() {
        return Ok(out);
    }
    let mut plt_sec = None;
    for sh in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".plt.sec" {
                plt_sec = Some(sh);
                break;
            }
            if name == ".plt" {
                plt_sec = Some(sh);
            }
        }
    }
    let Some(sh) = plt_sec else {
        return Ok(out);
    };
    for k in 0..sh.sh_size / 16 {
        let vaddr = sh.sh_addr + k * 16;
        let off = sh.sh_offset + k * 16;
        let Some(bytes) = elf_bytes.get(off as usize..(off + 16) as usize) else {
            break;
        };
        let Some(got) = plt_chunk_got(bytes, vaddr) else {
            continue;
        };
        let (Some(name), Some(file_off)) = (got_name.get(&got), vaddr_to_offset(&elf, vaddr))
        else {
            continue;
        };
        if offset_in_x_segment(&elf, file_off) {
            out.insert(name.to_string(), file_off);
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

    /// Independent oracle: decode one 16B PLT stub's GOT target
    /// (endbr64 + jmp *GOTPCREL, or bare jmp *GOTPCREL). Returns the
    /// GOT address the stub jumps through, or None when the bytes
    /// are not a recognized stub shape. Deliberately NOT shared with
    /// production `plt_chunk_got`: the oracle must not verify
    /// production against itself.
    fn stub_got_target(stub: &[u8], stub_vaddr: u64) -> Option<u64> {
        if stub.len() < 16 {
            return None;
        }
        let jmp_at = if stub[0..4] == [0xf3, 0x0f, 0x1e, 0xfa] {
            4
        } else {
            0
        };
        if stub[jmp_at..jmp_at + 2] != [0xff, 0x25] {
            return None;
        }
        let disp = i32::from_le_bytes(stub[jmp_at + 2..jmp_at + 6].try_into().ok()?);
        Some(stub_vaddr + jmp_at as u64 + 6 + disp as i64 as u64)
    }

    /// Test-only file-offset → link-time-vaddr (inverse of
    /// `vaddr_to_offset`) for stub-byte decoding.
    fn off_to_vaddr(elf: &goblin::elf::Elf, off: u64) -> u64 {
        use goblin::elf::program_header::PT_LOAD;
        elf.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .find(|ph| off >= ph.p_offset && off < ph.p_offset + ph.p_filesz)
            .map(|ph| off - ph.p_offset + ph.p_vaddr)
            .unwrap()
    }

    /// Closed-loop oracle: every resolved stub's bytes must jump to
    /// the GOT slot whose JUMP_SLOT reloc names it (an off-by-one
    /// still lands in-X on a neighbor stub, so validity alone never
    /// proves the slot math).
    fn assert_closed_loop(b: &[u8], elf: &goblin::elf::Elf, plt: &HashMap<String, u64>) {
        let mut got_name: HashMap<u64, &str> = HashMap::new();
        for r in elf.pltrelocs.iter() {
            if let Some(s) = elf.dynsyms.get(r.r_sym) {
                if let Some(n) = elf.dynstrtab.get_at(s.st_name) {
                    got_name.insert(r.r_offset, n);
                }
            }
        }
        for (name, off) in plt {
            let stub_vaddr = off_to_vaddr(elf, *off);
            let bytes = &b[*off as usize..*off as usize + 16];
            let got = stub_got_target(bytes, stub_vaddr)
                .unwrap_or_else(|| panic!("{name} stub bytes unrecognized"));
            assert_eq!(
                got_name.get(&got).copied(),
                Some(name.as_str()),
                "{name} stub jumps to GOT {got:#x} of another symbol"
            );
        }
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
        assert_closed_loop(&b, &elf, &plt);
    }

    #[test]
    fn plt_chunk_decode_shapes() {
        // CET entry: endbr64 + jmp *[rip+disp]; rip = vaddr+10.
        let cet = [
            0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0xf6, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            super::plt_chunk_got(&cet, 0x1210),
            Some(0x1210 + 10 + 0x2cf6)
        );
        // Bare entry: jmp *[rip+disp]; rip = vaddr+6.
        let bare = [
            0xff, 0x25, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(super::plt_chunk_got(&bare, 0x1000), Some(0x1000 + 6 + 0x10));
        // PLT0 shapes (push+jmp): not entries.
        let plt0 = [
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(super::plt_chunk_got(&plt0, 0x1000), None);
        let cet0 = [
            0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x35, 0x00, 0x00, 0x00, 0x00, 0xff, 0x25, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(super::plt_chunk_got(&cet0, 0x1000), None);
        // Short buffer / NOP sled: unrecognized.
        assert_eq!(super::plt_chunk_got(&[0xff], 0x1000), None);
        assert_eq!(super::plt_chunk_got(&[0x90; 16], 0x1000), None);
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
        // libc uses split .plt.sec (no PLT0 at base): the layout the
        // positional math gets wrong.
        assert_closed_loop(&b, &elf, &plt);
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
