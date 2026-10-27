// SPDX-License-Identifier: GPL-3.0-or-later
//! Data parsing only: no loader calls, symbol execution or target inspection.

use super::{Api, Architecture, GapReason, ModuleInfo, ObjectKind};
use goblin::elf::{Elf, header, program_header, section_header, sym};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
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
    let before = file.metadata().map_err(|_| GapReason::Unavailable)?;
    if !before.is_file() {
        return Err(GapReason::NonRegular);
    }
    if before.len() > max_bytes {
        return Err(GapReason::TooLarge);
    }
    let bytes = read_bounded(file, before.len());
    verify_unchanged(file, &before)?;
    let bytes = bytes?;
    if bytes.len() as u64 != before.len() {
        return Err(GapReason::Changed);
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err(GapReason::NotElf);
    }
    let elf = Elf::parse(&bytes).map_err(|_| GapReason::MalformedElf)?;
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
        )
    });
    let depends_on_libssl = elf.libraries.iter().any(|name| {
        matches!(
            *name,
            "libssl.so" | "libssl.so.1.0.0" | "libssl.so.1.0.2" | "libssl.so.1.1" | "libssl.so.3"
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
    };
    verify_unchanged(file, &before)?;
    Ok(result)
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
        _ => return None,
    })
}
