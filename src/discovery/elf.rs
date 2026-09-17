//! Disk-ELF helpers: `.dynsym` lookup + vaddr↔offset translation.
//! No symbols are used past the `OSSL_provider_init` anchor, which is
//! load-mandated and present even in stripped modules.
use anyhow::{Context as _, bail};
use goblin::elf::program_header::{PF_X, PT_LOAD};

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

/// Parse disk bytes as ELF or fail closed (non-ELF input is never probed).
pub fn parse_elf(elf_bytes: &[u8]) -> anyhow::Result<goblin::elf::Elf<'_>> {
    match goblin::Object::parse(elf_bytes).context("ELF parse")? {
        goblin::Object::Elf(e) => Ok(e),
        _ => bail!("not an ELF object"),
    }
}

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
}
