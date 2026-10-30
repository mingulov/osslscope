// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(dead_code)]
//! Independently assembled ELF fixtures; Goblin/section headers provide the test oracle.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub const QUERY: &str = "OSSL_PROVIDER_query_operation";
pub const UNQUERY: &str = "OSSL_PROVIDER_unquery_operation";
pub const OTHER: &str = "EVP_MD_fetch";
pub const GETCTX: &str = "OSSL_PROVIDER_get0_provider_ctx";
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct ForwarderFixture {
    directory: PathBuf,
    pub image: Vec<u8>,
    pub offsets: BTreeMap<String, u64>,
    pub addresses: BTreeMap<String, u64>,
    pub symbols: BTreeMap<String, usize>,
}
impl ForwarderFixture {
    pub fn new(query: &str, unquery: &str) -> Self {
        Self::assemble(query, unquery, "")
    }
    /// Variant that additionally exports the role-146 provider-context
    /// getter behind a caller-chosen wrapper plus its local
    /// implementation, for own-derivation regression tests.
    pub fn new_with_getctx(query: &str, unquery: &str, getctx: &str) -> Self {
        let extra = format!(
            r#"
.globl OSSL_PROVIDER_get0_provider_ctx
.type OSSL_PROVIDER_get0_provider_ctx,@function
OSSL_PROVIDER_get0_provider_ctx:
{getctx}
.size OSSL_PROVIDER_get0_provider_ctx,.-OSSL_PROVIDER_get0_provider_ctx
.space 16,0x90
.type getctx_impl,@function
getctx_impl: .byte 0xb8,0x0d,0,0,0,0xc3
.size getctx_impl,.-getctx_impl
.space 16,0x90
"#
        );
        Self::assemble(query, unquery, &extra)
    }
    fn assemble(query: &str, unquery: &str, extra: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "osslscope-forwarder-{}-{}-{}",
            std::process::id(),
            module_path!(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let source = format!(
            r#"
.text
.type unquery_impl,@function
unquery_impl: .byte 0xb8,0x07,0,0,0,0xc3
.size unquery_impl,.-unquery_impl
.space 16,0x90
.globl OSSL_PROVIDER_query_operation
.type OSSL_PROVIDER_query_operation,@function
OSSL_PROVIDER_query_operation:
{query}
.size OSSL_PROVIDER_query_operation,.-OSSL_PROVIDER_query_operation
.space 16,0x90
.type query_impl,@function
query_impl: .byte 0xb8,0x09,0,0,0,0xc3
.size query_impl,.-query_impl
.space 16,0x90
.globl OSSL_PROVIDER_unquery_operation
.type OSSL_PROVIDER_unquery_operation,@function
OSSL_PROVIDER_unquery_operation:
{unquery}
.size OSSL_PROVIDER_unquery_operation,.-OSSL_PROVIDER_unquery_operation
.space 16,0x90
{extra}.globl EVP_MD_fetch
.type EVP_MD_fetch,@function
EVP_MD_fetch: .byte 0xe9
.long query_impl-.-4
.size EVP_MD_fetch,.-EVP_MD_fetch
.globl other_function
.type other_function,@function
other_function: .byte 0xb8,0x0b,0,0,0,0xc3
.size other_function,.-other_function
.globl resolver
.type resolver,@gnu_indirect_function
resolver: .byte 0xc3
.size resolver,.-resolver
.section .plt,"ax",@progbits
.type linkage_stub,@function
linkage_stub: .byte 0xff,0x25,0,0,0,0
.size linkage_stub,.-linkage_stub
.data
data_target: .quad 0
.section .note.GNU-stack,"",@progbits
"#
        );
        fs::write(directory.join("fixture.S"), source).unwrap();
        assert!(
            Command::new("cc")
                .args([
                    "-shared",
                    "-nostdlib",
                    "-Wl,--build-id=none,-Bsymbolic",
                    "-o"
                ])
                .arg(directory.join("fixture.so"))
                .arg(directory.join("fixture.S"))
                .status()
                .unwrap()
                .success()
        );
        let image = fs::read(directory.join("fixture.so")).unwrap();
        let elf = goblin::elf::Elf::parse(&image).unwrap();
        let mut offsets = BTreeMap::new();
        let mut addresses = BTreeMap::new();
        for symbol in elf
            .syms
            .iter()
            .filter(|s| s.st_shndx > 0 && s.st_shndx < elf.section_headers.len())
        {
            let name = elf.strtab.get_at(symbol.st_name).unwrap().to_owned();
            let section = &elf.section_headers[symbol.st_shndx];
            offsets.insert(
                name.clone(),
                section.sh_offset + symbol.st_value - section.sh_addr,
            );
            addresses.insert(name, symbol.st_value);
        }
        // Production must never need local/private symbols, even for exact targets.
        assert!(
            Command::new("strip")
                .arg("--strip-all")
                .arg(directory.join("fixture.so"))
                .status()
                .unwrap()
                .success()
        );
        let image = fs::read(directory.join("fixture.so")).unwrap();
        let elf = goblin::elf::Elf::parse(&image).unwrap();
        assert!(elf.syms.is_empty());
        let dynsym = elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 11)
            .unwrap()
            .sh_offset as usize;
        let symbols = elf
            .dynsyms
            .iter()
            .enumerate()
            .map(|(i, s)| {
                (
                    elf.dynstrtab.get_at(s.st_name).unwrap().to_owned(),
                    dynsym + i * 24,
                )
            })
            .collect();
        Self {
            directory,
            image,
            offsets,
            addresses,
            symbols,
        }
    }
    pub fn file(&self) -> File {
        fs::write(self.directory.join("input.so"), &self.image).unwrap();
        File::open(self.directory.join("input.so")).unwrap()
    }
    pub fn size(&mut self, name: &str, size: u64) {
        let at = self.symbols[name] + 16;
        self.image[at..at + 8].copy_from_slice(&size.to_le_bytes());
    }
    pub fn sectionless(&mut self) {
        self.image[40..48].fill(0);
        self.image[60..64].fill(0);
    }
    pub fn rebase(&mut self, bias: u64) {
        let elf = goblin::elf::Elf::parse(&self.image).unwrap();
        let mut addresses = Vec::new();
        for (i, p) in elf.program_headers.iter().enumerate() {
            addresses.push((elf.header.e_phoff as usize + i * 56 + 16, p.p_vaddr));
            addresses.push((elf.header.e_phoff as usize + i * 56 + 24, p.p_paddr));
        }
        for (i, s) in elf.section_headers.iter().enumerate() {
            if s.sh_flags & 2 != 0 {
                addresses.push((elf.header.e_shoff as usize + i * 64 + 16, s.sh_addr));
            }
            if s.sh_type == 6 {
                for at in (s.sh_offset as usize..(s.sh_offset + s.sh_size) as usize).step_by(16) {
                    let tag = u64::from_le_bytes(self.image[at..at + 8].try_into().unwrap());
                    if matches!(tag, 4 | 5 | 6 | 0x6ffffef5) {
                        addresses.push((
                            at + 8,
                            u64::from_le_bytes(self.image[at + 8..at + 16].try_into().unwrap()),
                        ));
                    }
                }
            }
        }
        for (_, at) in &self.symbols {
            let value = u64::from_le_bytes(self.image[at + 8..at + 16].try_into().unwrap());
            if value != 0 {
                addresses.push((at + 8, value));
            }
        }
        for (at, value) in addresses {
            self.image[at..at + 8].copy_from_slice(&value.checked_add(bias).unwrap().to_le_bytes());
        }
        for value in self.addresses.values_mut() {
            *value += bias;
        }
    }
    pub fn query_target(&mut self, target: u64) {
        let at = self.offsets[QUERY] as usize;
        let delta =
            i32::try_from(i128::from(target) - i128::from(self.addresses[QUERY] + 5)).unwrap();
        self.image[at..at + 5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
        self.image[at + 1..at + 5].copy_from_slice(&delta.to_le_bytes());
        self.size(QUERY, 5);
    }
}
impl Drop for ForwarderFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
