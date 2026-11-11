// SPDX-License-Identifier: GPL-3.0-or-later
//! Data parsing only: no loader calls, symbol execution or target inspection.

use super::{Api, Architecture, FileVersionStatus, GapReason, ModuleInfo, ObjectKind};
use goblin::container::{Container, Ctx, Endian};
use goblin::elf::{Elf, dynamic, header, program_header, section_header, sym};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

/// Open once, nonblocking for FIFOs, then inspect only a regular descriptor.
/// Nonblocking flags do not bound filesystem latency on regular files.
pub fn inspect_module(path: &Path, max_bytes: u64) -> Result<ModuleInfo, GapReason> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|_| GapReason::Unavailable)?;
    inspect_file(&mut file, max_bytes)
}

/// Inspect the caller's bound descriptor, from offset zero, without reopening
/// a path or changing the descriptor's cursor. Foreign ELF machines are
/// descriptive inventory; tracing support is a separate decision.
pub fn inspect_file(file: &mut File, max_bytes: u64) -> Result<ModuleInfo, GapReason> {
    inspect_file_budgeted(file, max_bytes, None)
}
pub(crate) fn inspect_file_budgeted(
    file: &mut File,
    max_bytes: u64,
    memory: Option<&crate::observation_memory::MemoryPool>,
) -> Result<ModuleInfo, GapReason> {
    let before = file.metadata().map_err(|_| GapReason::Unavailable)?;
    if !before.is_file() {
        return Err(GapReason::NonRegular);
    }
    // Procfs pseudofiles can claim to be regular, including memory,
    // environment and argv views. Inspect the opened descriptor's actual
    // filesystem before any read; /proc links to ordinary backing remain
    // valid because fstatfs follows the descriptor, not its locator path.
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the live FD and properly sized output storage are valid. Only
    // a successful fstatfs result is subsequently initialized/read.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(GapReason::Unavailable);
    }
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type == libc::PROC_SUPER_MAGIC {
        return Err(GapReason::Unavailable);
    }
    if before.len() > max_bytes {
        return Err(GapReason::TooLarge);
    }
    // A file shorter than ELF magic cannot be a module. Avoid even an EOF
    // probe on empty or short inputs.
    if before.len() < 4 {
        return Err(GapReason::NotElf);
    }
    let _scratch = match memory {
        Some(pool) => Some(
            pool.reserve(parser_scratch_bytes(before.len())?)
                .ok_or(GapReason::ReadLimit)?,
        ),
        None => None,
    };
    let bytes = read_bounded(file, before.len());
    verify_unchanged(file, &before)?;
    let bytes = bytes?;
    if bytes.len() as u64 != before.len() {
        return Err(GapReason::Changed);
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err(GapReason::NotElf);
    }
    admit_parser_metadata(&bytes)?;
    let elf = Elf::parse(&bytes).map_err(|_| GapReason::MalformedElf)?;
    if elf.dynsyms.len() > MAX_SYMBOLS {
        return Err(GapReason::ReadLimit);
    }
    let architecture = match elf.header.e_machine {
        header::EM_X86_64 => Architecture::X86_64,
        header::EM_AARCH64 => Architecture::Aarch64,
        _ => Architecture::Other,
    };
    let mut exports = BTreeSet::new();
    let mut imports_api = false;
    for symbol in elf.dynsyms.iter() {
        let Some(api) = elf
            .dynstrtab
            .get_at(symbol.st_name)
            .and_then(recognized_api)
        else {
            continue;
        };
        if symbol.st_shndx == section_header::SHN_UNDEF as usize {
            if matches!(symbol.st_type(), sym::STT_FUNC | sym::STT_NOTYPE) {
                imports_api = true;
            }
        } else if code_export(&elf, &symbol, bytes.len() as u64) {
            exports.insert(api);
        }
    }
    // Only known SONAME forms count. Substrings and arbitrary suffixes do
    // not establish a libcrypto/libssl dependency; names are never retained.
    let depends_on_libcrypto = elf.libraries.iter().any(|name| {
        matches!(
            *name,
            "libcrypto.so"
                | "libcrypto.so.1.0.0"
                | "libcrypto.so.1.0.2"
                | "libcrypto.so.1.1"
                | "libcrypto.so.3"
                | "libcrypto.so.4"
        )
    });
    let depends_on_libssl = elf.libraries.iter().any(|name| {
        matches!(
            *name,
            "libssl.so"
                | "libssl.so.1.0.0"
                | "libssl.so.1.0.2"
                | "libssl.so.1.1"
                | "libssl.so.3"
                | "libssl.so.4"
        )
    });
    let kind = if exports.contains(&Api::OsslProviderInit) {
        ObjectKind::ProviderModule
    } else if !exports.is_empty() {
        ObjectKind::OpenSslCompatible
    } else if depends_on_libcrypto || depends_on_libssl || imports_api {
        ObjectKind::OpenSslConsumer
    } else {
        ObjectKind::Other
    };
    // File version evidence (v0.6.0 D4): the object's OWN SONAME plus a
    // singular validated rodata version id, or null with a finite reason.
    // Strings never change `kind` and never cross object boundaries.
    let (file_soname, file_openssl_version, file_version_status) =
        extract_file_version(&bytes, &elf);
    let result = ModuleInfo {
        sha256: Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        device: before.dev(),
        inode: before.ino(),
        size_bytes: before.len(),
        architecture,
        kind,
        exports: exports.into_iter().collect(),
        depends_on_libcrypto,
        depends_on_libssl,
        file_soname,
        file_openssl_version,
        file_version_status,
    };
    verify_unchanged(file, &before)?;
    Ok(result)
}

// These are aggregate metadata limits, independent of the caller's file-byte
// limit (including 128 MiB objects). Goblin 0.10 eagerly allocates headers,
// dynamic records, string indexes, dependency/path vectors and relocation
// descriptors; symbols, relocation contents and version sections are borrowed.
pub(crate) fn parser_scratch_bytes(file_bytes: u64) -> Result<usize, GapReason> {
    usize::try_from(file_bytes)
        .ok()
        .and_then(|n| n.checked_add(MAX_METADATA_BYTES + 65_537))
        .ok_or(GapReason::ReadLimit)
}
const MAX_HEADERS: usize = 4_096;
const MAX_DYNAMIC_ENTRIES: usize = 16_384;
const MAX_STRING_ROWS: usize = 65_536;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_SYMBOLS: usize = 262_144;
const MAX_HASH_STEPS: usize = 262_144;

#[derive(Default)]
struct ParserBudget {
    bytes: usize,
    strings: usize,
}

impl ParserBudget {
    fn charge(&mut self, size: usize) -> Result<(), GapReason> {
        self.bytes = self.bytes.checked_add(size).ok_or(GapReason::ReadLimit)?;
        if self.bytes > MAX_METADATA_BYTES {
            return Err(GapReason::ReadLimit);
        }
        Ok(())
    }

    fn strings(&mut self, bytes: &[u8], offset: u64, size: u64) -> Result<(), GapReason> {
        let size = usize::try_from(size).map_err(|_| GapReason::ReadLimit)?;
        self.charge(size)?;
        let table = file_slice(bytes, offset, size)?;
        // Each delimiter is one eager row, including empty strings. Charge a
        // final unterminated entry too; the parser will reject invalid data.
        let rows = table.iter().filter(|&&byte| byte == 0).count()
            + usize::from(table.last().is_some_and(|&byte| byte != 0));
        self.strings = self.strings.checked_add(rows).ok_or(GapReason::ReadLimit)?;
        if self.strings > MAX_STRING_ROWS {
            return Err(GapReason::ReadLimit);
        }
        Ok(())
    }
}

/// Admit every eager allocation class before invoking Elf::parse. Repeated
/// references count repeatedly: Goblin builds separate indexes even when
/// section-name, ordinary symbol-name and dynamic string tables alias.
pub(crate) fn admit_parser_metadata(bytes: &[u8]) -> Result<(), GapReason> {
    let h = Elf::parse_header(bytes).map_err(|_| GapReason::MalformedElf)?;
    let container = match h.e_ident[header::EI_CLASS] {
        header::ELFCLASS64 => Container::Big,
        header::ELFCLASS32 => Container::Little,
        _ => return Err(GapReason::MalformedElf),
    };
    let endian = match h.e_ident[header::EI_DATA] {
        header::ELFDATA2LSB => Endian::Little,
        header::ELFDATA2MSB => Endian::Big,
        _ => return Err(GapReason::MalformedElf),
    };
    let ctx = Ctx::new(container, endian);
    let mut budget = ParserBudget::default();
    let mut section_count = usize::from(h.e_shnum);
    if h.e_shoff == 0 {
        section_count = 0;
    } else if section_count == 0 {
        // A count of zero invokes ELF's extended section count. Decode only
        // the first fixed-size header before admitting the resulting vector.
        let first = section_header::SectionHeader::parse(bytes, h.e_shoff as usize, 1, ctx)
            .map_err(|_| GapReason::MalformedElf)?;
        section_count = usize::try_from(first[0].sh_size).map_err(|_| GapReason::ReadLimit)?;
        // Goblin still pushes the null header for an extended zero count.
        section_count = section_count.max(1);
    }
    let program_count = usize::from(h.e_phnum);
    if section_count > MAX_HEADERS || program_count > MAX_HEADERS - section_count {
        return Err(GapReason::ReadLimit);
    }
    budget.charge(section_count * section_header::SectionHeader::size(ctx))?;
    budget.charge(program_count * program_header::ProgramHeader::size(ctx))?;
    let sections =
        section_header::SectionHeader::parse(bytes, h.e_shoff as usize, section_count, ctx)
            .map_err(|_| GapReason::MalformedElf)?;
    let programs =
        program_header::ProgramHeader::parse(bytes, h.e_phoff as usize, program_count, ctx)
            .map_err(|_| GapReason::MalformedElf)?;

    let mut string_index = usize::from(h.e_shstrndx);
    if string_index == section_header::SHN_XINDEX as usize {
        string_index = sections.first().map_or(0, |s| s.sh_link as usize);
    }
    if let Some(s) = sections.get(string_index) {
        budget.strings(bytes, s.sh_offset, s.sh_size)?;
    }
    if let Some(s) = sections
        .iter()
        .rfind(|s| s.sh_type == section_header::SHT_SYMTAB)
    {
        let count = if s.sh_entsize == 0 {
            0
        } else {
            s.sh_size / s.sh_entsize
        };
        if count > MAX_SYMBOLS as u64 {
            return Err(GapReason::ReadLimit);
        }
        budget.charge(count as usize * sym::Sym::size(container))?;
        // get_strtab treats SHN_XINDEX specially even for an ordinary link.
        let link = if s.sh_link == section_header::SHN_XINDEX {
            sections.first().map_or(0, |s| s.sh_link as usize)
        } else {
            s.sh_link as usize
        };
        if let Some(s) = sections.get(link) {
            budget.strings(bytes, s.sh_offset, s.sh_size)?;
        }
    }
    for s in &sections {
        if matches!(
            s.sh_type,
            section_header::SHT_REL | section_header::SHT_RELA
        ) {
            budget.charge(usize::try_from(s.sh_size).map_err(|_| GapReason::ReadLimit)?)?;
        }
    }
    for p in &programs {
        if p.p_type == program_header::PT_INTERP {
            budget.charge(usize::try_from(p.p_filesz).map_err(|_| GapReason::ReadLimit)?)?;
        }
    }
    if let Some(p) = programs
        .iter()
        .find(|p| p.p_type == program_header::PT_DYNAMIC)
    {
        let size = usize::try_from(p.p_filesz).map_err(|_| GapReason::ReadLimit)?;
        if size / dynamic::Dyn::size(container) > MAX_DYNAMIC_ENTRIES {
            return Err(GapReason::ReadLimit);
        }
        budget.charge(size)?;
    }
    // Dynamic::parse is safe to invoke now: its sole vector capacity is
    // admitted above, including records after an early DT_NULL terminator.
    if let Some(d) =
        dynamic::Dynamic::parse(bytes, &programs, ctx).map_err(|_| GapReason::MalformedElf)?
    {
        let info = &d.info;
        budget.strings(bytes, info.strtab as u64, info.strsz as u64)?;
        for size in [info.relasz, info.relsz, info.pltrelsz] {
            budget.charge(size)?;
        }
        admit_hash_work(bytes, info, ctx, &mut budget)?;
    }
    Ok(())
}

fn file_slice(bytes: &[u8], offset: u64, size: usize) -> Result<&[u8], GapReason> {
    let start = usize::try_from(offset).map_err(|_| GapReason::MalformedElf)?;
    let end = start.checked_add(size).ok_or(GapReason::MalformedElf)?;
    bytes.get(start..end).ok_or(GapReason::MalformedElf)
}

fn read_word(bytes: &[u8], offset: usize, ctx: Ctx) -> Result<u32, GapReason> {
    let word: [u8; 4] = file_slice(bytes, offset as u64, 4)?.try_into().unwrap();
    Ok(if ctx.is_little_endian() {
        u32::from_le_bytes(word)
    } else {
        u32::from_be_bytes(word)
    })
}

// Mirror only Goblin's bounded GNU hash extent walk, not its parser. SYSV hash
// and relocation-derived symbol counts are borrowed and checked after parsing.
fn admit_hash_work(
    bytes: &[u8],
    info: &dynamic::DynamicInfo,
    ctx: Ctx,
    budget: &mut ParserBudget,
) -> Result<(), GapReason> {
    let Some(offset) = info.gnu_hash else {
        return Ok(());
    };
    let offset = usize::try_from(offset).map_err(|_| GapReason::MalformedElf)?;
    let buckets = read_word(bytes, offset, ctx)? as usize;
    let minimum = read_word(
        bytes,
        offset.checked_add(4).ok_or(GapReason::MalformedElf)?,
        ctx,
    )? as usize;
    let bloom = read_word(
        bytes,
        offset.checked_add(8).ok_or(GapReason::MalformedElf)?,
        ctx,
    )? as usize;
    if buckets == 0 || minimum == 0 || bloom == 0 {
        return Err(GapReason::MalformedElf);
    }
    if buckets > MAX_HASH_STEPS || minimum > MAX_SYMBOLS {
        return Err(GapReason::ReadLimit);
    }
    let bloom_bytes = bloom.checked_mul(ctx.size()).ok_or(GapReason::ReadLimit)?;
    budget.charge(bloom_bytes)?;
    budget.charge(buckets * 4)?;
    let bucket_offset = offset
        .checked_add(16)
        .and_then(|n| n.checked_add(bloom_bytes))
        .ok_or(GapReason::MalformedElf)?;
    let bucket_bytes = file_slice(bytes, bucket_offset as u64, buckets * 4)?;
    let mut maximum = 0;
    for offset in (0..bucket_bytes.len()).step_by(4) {
        maximum = maximum.max(read_word(bucket_bytes, offset, ctx)? as usize);
    }
    if maximum < minimum {
        return Ok(());
    }
    if maximum >= MAX_SYMBOLS {
        return Err(GapReason::ReadLimit);
    }
    let mut chain_offset = bucket_offset
        .checked_add(buckets * 4)
        .and_then(|n| n.checked_add((maximum - minimum) * 4))
        .ok_or(GapReason::MalformedElf)?;
    for _ in 0..MAX_HASH_STEPS - buckets {
        let word = read_word(bytes, chain_offset, ctx)?;
        budget.charge(4)?;
        maximum += 1;
        if maximum > MAX_SYMBOLS {
            return Err(GapReason::ReadLimit);
        }
        if word & 1 != 0 {
            return Ok(());
        }
        chain_offset = chain_offset.checked_add(4).ok_or(GapReason::MalformedElf)?;
    }
    Err(GapReason::ReadLimit)
}

fn read_bounded(file: &File, size: u64) -> Result<Vec<u8>, GapReason> {
    // Read at most the admitted size plus one, so growth cannot turn into
    // an unbounded read. The extra byte detects growth before fstat too.
    let limit = usize::try_from(size)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(GapReason::ReadLimit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit)
        .map_err(|_| GapReason::ReadLimit)?;
    let mut buffer = [0; 65_536];
    while bytes.len() < limit {
        let count = buffer.len().min(limit - bytes.len());
        match file.read_at(&mut buffer[..count], bytes.len() as u64) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(GapReason::Unavailable),
        }
    }
    Ok(bytes)
}

fn verify_unchanged(file: &File, before: &Metadata) -> Result<(), GapReason> {
    let after = file.metadata().map_err(|_| GapReason::Unavailable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(GapReason::Changed);
    }
    Ok(())
}

fn code_export(elf: &Elf<'_>, symbol: &sym::Sym, file_size: u64) -> bool {
    if symbol.st_type() != sym::STT_FUNC
        || symbol.st_shndx >= section_header::SHN_LORESERVE as usize
        || !matches!(symbol.st_bind(), sym::STB_GLOBAL | sym::STB_WEAK)
        || !matches!(
            symbol.st_visibility(),
            sym::STV_DEFAULT | sym::STV_PROTECTED
        )
    {
        return false;
    }
    // When a section table is present, the claimed definition must also
    // identify executable, file-backed code in that section. A synthetic
    // nonreserved section index alone is not a definition.
    if !elf.section_headers.is_empty() {
        let Some(section) = elf.section_headers.get(symbol.st_shndx) else {
            return false;
        };
        let Some(relative) = symbol.st_value.checked_sub(section.sh_addr) else {
            return false;
        };
        if section.sh_type != section_header::SHT_PROGBITS
            || section.sh_flags & u64::from(section_header::SHF_EXECINSTR) == 0
            || relative >= section.sh_size
            || relative
                .checked_add(symbol.st_size)
                .is_none_or(|end| end > section.sh_size)
            || section
                .sh_offset
                .checked_add(section.sh_size)
                .is_none_or(|end| end > file_size)
        {
            return false;
        }
    }
    elf.program_headers.iter().any(|segment| {
        if segment.p_type != program_header::PT_LOAD || segment.p_flags & program_header::PF_X == 0
        {
            return false;
        }
        let Some(relative) = symbol.st_value.checked_sub(segment.p_vaddr) else {
            return false;
        };
        relative < segment.p_filesz
            && relative
                .checked_add(symbol.st_size)
                .is_some_and(|end| end <= segment.p_filesz)
            && segment
                .p_offset
                .checked_add(segment.p_filesz)
                .is_some_and(|end| end <= file_size)
    })
}

fn recognized_api(name: &str) -> Option<Api> {
    Some(match name {
        "OSSL_provider_init" => Api::OsslProviderInit,
        "OSSL_PROVIDER_load" => Api::OsslProviderLoad,
        "OSSL_PROVIDER_try_load" => Api::OsslProviderTryLoad,
        "OSSL_PROVIDER_unload" => Api::OsslProviderUnload,
        "OSSL_PROVIDER_load_ex" => Api::OsslProviderLoadEx,
        "OSSL_PROVIDER_try_load_ex" => Api::OsslProviderTryLoadEx,
        "OSSL_PROVIDER_add_builtin" => Api::OsslProviderAddBuiltin,
        "OSSL_PROVIDER_get0_dispatch" => Api::OsslProviderGet0Dispatch,
        "OSSL_PROVIDER_query_operation" => Api::OsslProviderQueryOperation,
        "OPENSSL_init_crypto" => Api::OpenSslInitCrypto,
        "OPENSSL_version_major" => Api::OpenSslVersionMajor,
        "EVP_MD_fetch" => Api::EvpMdFetch,
        "EVP_CIPHER_fetch" => Api::EvpCipherFetch,
        "EVP_MAC_fetch" => Api::EvpMacFetch,
        "EVP_KDF_fetch" => Api::EvpKdfFetch,
        "EVP_SIGNATURE_fetch" => Api::EvpSignatureFetch,
        "EVP_KEM_fetch" => Api::EvpKemFetch,
        "EVP_DigestInit_ex" => Api::EvpDigestInitEx,
        "EVP_DigestInit_ex2" => Api::EvpDigestInitEx2,
        "EVP_DigestUpdate" => Api::EvpDigestUpdate,
        "EVP_DigestFinal_ex" => Api::EvpDigestFinalEx,
        "EVP_EncryptInit_ex" => Api::EvpEncryptInitEx,
        "EVP_EncryptInit_ex2" => Api::EvpEncryptInitEx2,
        "EVP_EncryptUpdate" => Api::EvpEncryptUpdate,
        "EVP_EncryptFinal_ex" => Api::EvpEncryptFinalEx,
        "EVP_DecryptInit_ex" => Api::EvpDecryptInitEx,
        "EVP_DecryptInit_ex2" => Api::EvpDecryptInitEx2,
        "EVP_DecryptUpdate" => Api::EvpDecryptUpdate,
        "EVP_DecryptFinal_ex" => Api::EvpDecryptFinalEx,
        "EVP_CipherInit_ex" => Api::EvpCipherInitEx,
        "EVP_CipherUpdate" => Api::EvpCipherUpdate,
        "EVP_CipherFinal_ex" => Api::EvpCipherFinalEx,
        "EVP_MAC_init" => Api::EvpMacInit,
        "EVP_MAC_update" => Api::EvpMacUpdate,
        "EVP_MAC_final" => Api::EvpMacFinal,
        "EVP_KDF_derive" => Api::EvpKdfDerive,
        "EVP_PKEY_sign" => Api::EvpPkeySign,
        "EVP_PKEY_verify" => Api::EvpPkeyVerify,
        "EVP_PKEY_encrypt" => Api::EvpPkeyEncrypt,
        "EVP_PKEY_decrypt" => Api::EvpPkeyDecrypt,
        "EVP_PKEY_derive" => Api::EvpPkeyDerive,
        "EVP_DigestSignFinal" => Api::EvpDigestSignFinal,
        "EVP_DigestVerifyFinal" => Api::EvpDigestVerifyFinal,
        "EVP_DigestSign" => Api::EvpDigestSign,
        "EVP_DigestVerify" => Api::EvpDigestVerify,
        "EVP_RAND_generate" => Api::EvpRandGenerate,
        "EVP_PKEY_encapsulate" => Api::EvpPkeyEncapsulate,
        "EVP_PKEY_decapsulate" => Api::EvpPkeyDecapsulate,
        "EVP_PKEY_keygen_init" => Api::EvpPkeyKeygenInit,
        "EVP_PKEY_keygen" => Api::EvpPkeyKeygen,
        "EVP_PKEY_paramgen_init" => Api::EvpPkeyParamgenInit,
        "EVP_PKEY_paramgen" => Api::EvpPkeyParamgen,
        "EVP_PKEY_derive_init" => Api::EvpPkeyDeriveInit,
        "EVP_PKEY_check" => Api::EvpPkeyCheck,
        "EVP_PKEY_public_check" => Api::EvpPkeyPublicCheck,
        "EVP_PKEY_param_check" => Api::EvpPkeyParamCheck,
        "EVP_PKEY_copy_parameters" => Api::EvpPkeyCopyParameters,
        "EVP_DigestSignInit" => Api::EvpDigestSignInit,
        "EVP_DigestSignUpdate" => Api::EvpDigestSignUpdate,
        "EVP_DigestVerifyInit" => Api::EvpDigestVerifyInit,
        "EVP_DigestVerifyUpdate" => Api::EvpDigestVerifyUpdate,
        "EVP_Q_digest" => Api::EvpQDigest,
        "EVP_Q_mac" => Api::EvpQMac,
        "EVP_RAND_nonce" => Api::EvpRandNonce,
        "EVP_RAND_CTX_new" => Api::EvpRandCtxNew,
        "EVP_RAND_CTX_free" => Api::EvpRandCtxFree,
        "EVP_MD_CTX_new" => Api::EvpMdCtxNew,
        "EVP_MD_CTX_free" => Api::EvpMdCtxFree,
        "EVP_CIPHER_CTX_new" => Api::EvpCipherCtxNew,
        "EVP_CIPHER_CTX_free" => Api::EvpCipherCtxFree,

        _ => return None,
    })
}

/// Maximum total `.rodata*` bytes scanned for version evidence in one file.
/// Past this the version is honestly `NotFullyScanned`, never a partial read.
const MAX_VERSION_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// The object's OWN `DT_SONAME` plus the singular recognized rodata version
/// id (optional validated date), or `None` with a finite reason. Each
/// `SHT_PROGBITS` section named `.rodata*` is scanned independently with
/// checked extents; sections are never concatenated. Strings found here
/// never change `kind` and are never attributed to another object.
pub(crate) fn extract_file_version(
    bytes: &[u8],
    elf: &Elf,
) -> (Option<String>, Option<String>, FileVersionStatus) {
    let soname = elf.soname.map(str::to_string);
    let mut candidates = Vec::new();
    let mut scanned: usize = 0;
    for section in &elf.section_headers {
        if section.sh_type != section_header::SHT_PROGBITS {
            continue;
        }
        let is_rodata = elf
            .shdr_strtab
            .get_at(section.sh_name)
            .is_some_and(|name| name.starts_with(".rodata"));
        if !is_rodata {
            continue;
        }
        let (Some(offset), Some(size)) = (
            usize::try_from(section.sh_offset).ok(),
            usize::try_from(section.sh_size).ok(),
        ) else {
            return (soname, None, FileVersionStatus::NotFullyScanned);
        };
        let Some(end) = offset.checked_add(size) else {
            return (soname, None, FileVersionStatus::NotFullyScanned);
        };
        let Some(region) = bytes.get(offset..end) else {
            return (soname, None, FileVersionStatus::NotFullyScanned);
        };
        let Some(total) = scanned.checked_add(region.len()) else {
            return (soname, None, FileVersionStatus::NotFullyScanned);
        };
        if total > MAX_VERSION_SCAN_BYTES {
            return (soname, None, FileVersionStatus::NotFullyScanned);
        }
        scanned = total;
        candidates.extend(scan_rodata_region(region));
    }
    let (version, status) = select_file_version(&candidates);
    (soname, version, status)
}

/// Singular-or-null selection (D4): dedupe; exactly one distinct candidate
/// yields `Present`, two or more yield `None` + `Ambiguous` (never
/// first-match-wins), zero yields `None` + `Absent`.
pub(crate) fn select_file_version(candidates: &[String]) -> (Option<String>, FileVersionStatus) {
    let distinct: BTreeSet<&str> = candidates.iter().map(String::as_str).collect();
    if distinct.len() > 1 {
        return (None, FileVersionStatus::Ambiguous);
    }
    match distinct.into_iter().next() {
        Some(one) => (Some(one.to_string()), FileVersionStatus::Present),
        None => (None, FileVersionStatus::Absent),
    }
}

/// Closed-grammar matches in one region: `OpenSSL <major>.<minor>.<patch>[a-z]?`
/// with 1-2 digits per component, optionally followed by a validated
/// `<day> <Mon> <year>` date. Near-misses never match; a match carries the
/// date only when fully valid, else the bare recognized id.
pub(crate) fn scan_rodata_region(region: &[u8]) -> Vec<String> {
    const PREFIX: &[u8] = b"OpenSSL ";
    let mut found = Vec::new();
    let mut i = 0;
    while i + PREFIX.len() <= region.len() {
        // No match inside a larger token (`FooOpenSSL 1.2.3` is not evidence).
        let start_boundary = i == 0 || !region[i - 1].is_ascii_alphanumeric();
        if start_boundary && region[i..].starts_with(PREFIX) {
            if let Some(matched) = parse_version_at(&region[i..]) {
                found.push(matched);
            }
        }
        i += 1;
    }
    found
}

/// Recognized id at `input` (which starts with `OpenSSL `), or `None` for a
/// near-miss. Every consumed byte is validated ASCII, so UTF-8 holds.
fn parse_version_at(input: &[u8]) -> Option<String> {
    let mut pos = "OpenSSL ".len();
    for step in 0..3 {
        if step > 0 {
            if input.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
        let digits = digit_run(input, pos, 2);
        if digits.is_empty() {
            return None;
        }
        pos += digits.len();
    }
    if input.get(pos).is_some_and(|b| b.is_ascii_lowercase()) {
        pos += 1;
    }
    if input.get(pos) == Some(&b' ') {
        // Optional validated date; any failure keeps the bare core id.
        if let Some(date_end) = parse_version_date(input, pos) {
            pos = date_end;
        }
    } else if continues_token(input.get(pos)) {
        return None;
    }
    String::from_utf8(input[..pos].to_vec()).ok()
}

/// End offset of a fully validated ` <day> <Mon> <year>` date at `pos`
/// (which holds the separating space): day 1-31, one of the twelve month
/// words, four-digit year at a token boundary. Else `None`.
fn parse_version_date(input: &[u8], pos: usize) -> Option<usize> {
    const MONTHS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let day = digit_run(input, pos + 1, 2);
    if day.is_empty() {
        return None;
    }
    let day_value = day.iter().fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
    if !(1..=31).contains(&day_value) {
        return None;
    }
    let mut p = pos + 1 + day.len();
    if input.get(p) != Some(&b' ') {
        return None;
    }
    p += 1;
    let month_end = p.checked_add(3)?;
    if !MONTHS.contains(&input.get(p..month_end)?) {
        return None;
    }
    p = month_end;
    if input.get(p) != Some(&b' ') {
        return None;
    }
    p += 1;
    let year = digit_run(input, p, 4);
    if year.len() != 4 {
        return None;
    }
    p += year.len();
    if continues_token(input.get(p)) {
        return None;
    }
    Some(p)
}

/// Up to `max` ASCII digits at `pos` (possibly empty; callers decide).
fn digit_run(input: &[u8], pos: usize, max: usize) -> &[u8] {
    let mut end = pos;
    while end < input.len() && end - pos < max && input[end].is_ascii_digit() {
        end += 1;
    }
    &input[pos..end]
}

/// The token continues past the match (`3.0.0.1`, `3.0.0X`, `2021a`): the
/// full token is outside the closed grammar, so the prefix is not evidence.
fn continues_token(next: Option<&u8>) -> bool {
    next.is_some_and(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
}

#[cfg(test)]
mod tests {
    #[test]
    fn v060_version_extraction_is_singular_or_null_with_reason() {
        let path = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libcrypto.so.3");
        if !path.exists() {
            panic!("system libcrypto fixture missing; run on a lane with OpenSSL installed");
        }
        let info = super::inspect_module(path, 134_217_728).unwrap();
        assert_eq!(info.file_soname.as_deref(), Some("libcrypto.so.3"));
        match info.file_version_status {
            super::FileVersionStatus::Present => {
                let v = info.file_openssl_version.as_deref().unwrap();
                assert!(v.starts_with("OpenSSL 3."), "unexpected {v}");
            }
            super::FileVersionStatus::Absent
            | super::FileVersionStatus::Ambiguous
            | super::FileVersionStatus::NotFullyScanned => {
                assert!(info.file_openssl_version.is_none());
            }
        }
        // NSS libssl3.so fixture (or any non-OpenSSL ELF): no OpenSSL version, kind untouched.
        let nss = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libssl3.so");
        if nss.exists() {
            let nss_info = super::inspect_module(nss, 134_217_728).unwrap();
            assert!(nss_info.file_openssl_version.is_none());
            assert_ne!(
                nss_info.file_version_status,
                super::FileVersionStatus::Present
            );
        }
        // Pure selection rule: dedupe + singular-or-null, no first-match-wins.
        let two = vec![
            "OpenSSL 3.0.0 7 Sep 2021".to_string(),
            "OpenSSL 3.1.0 14 Mar 2023".to_string(),
        ];
        let (version, status) = super::select_file_version(&two);
        assert_eq!(status, super::FileVersionStatus::Ambiguous);
        assert!(version.is_none());
        let dup = vec![
            "OpenSSL 3.0.0 7 Sep 2021".to_string(),
            "OpenSSL 3.0.0 7 Sep 2021".to_string(),
        ];
        let (version, status) = super::select_file_version(&dup);
        assert_eq!(status, super::FileVersionStatus::Present);
        assert_eq!(version.as_deref(), Some("OpenSSL 3.0.0 7 Sep 2021"));
        let (version, status) = super::select_file_version(&[]);
        assert_eq!(status, super::FileVersionStatus::Absent);
        assert!(version.is_none());
        // Region scan: closed grammar only; near-misses never match.
        let region = b"\0OpenSSL 3.0.0 7 Sep 2021\0OpenSSL X\0 LibreSSL 3.0\0";
        let found = super::scan_rodata_region(region);
        assert_eq!(found, vec!["OpenSSL 3.0.0 7 Sep 2021".to_string()]);
    }
}
