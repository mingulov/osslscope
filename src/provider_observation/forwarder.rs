// SPDX-License-Identifier: GPL-3.0-or-later
//! One-hop public query ABI derivation from the retained ELF, never target memory.
use super::{
    ObservationApi, ObservationBudget, ObservationGap, Segment, bytes, export_api_at, word,
};
use std::fs::File;

pub(super) const APIS: [ObservationApi; 2] = [
    ObservationApi::Inventoried(crate::inventory::Api::OsslProviderQueryOperation),
    ObservationApi::OsslProviderUnqueryOperation,
];

pub(super) struct Context<'a> {
    pub file: &'a File,
    pub len: u64,
    pub budget: &'a ObservationBudget,
    pub segments: &'a [Segment],
    pub symbols: &'a [u8],
    pub names: &'a [u8],
    pub sections: &'a [u8],
    pub header: &'a [u8],
}
impl Context<'_> {
    fn executable(&self, address: u64, size: u64) -> Option<(&Segment, u64)> {
        let end = address.checked_add(size)?;
        let mut matches = self
            .segments
            .iter()
            .filter(|s| address >= s.address && end <= s.address.checked_add(s.size).unwrap_or(0));
        let segment = matches.next()?;
        if matches.next().is_some() || segment.writable {
            return None;
        }
        let offset = segment
            .offset
            .checked_add(address.checked_sub(segment.address)?)?;
        (offset.checked_add(size)? <= self.len).then_some((segment, offset))
    }

    pub(super) fn resolve(
        &self,
        api: ObservationApi,
        entry: u64,
        exports: &[(ObservationApi, u64)],
    ) -> Result<Option<u64>, ObservationGap> {
        if exports
            .iter()
            .any(|(other, at)| *other != api && *at == entry)
        {
            return Ok(None);
        }
        let mut source = None;
        for symbol in self.symbols.chunks_exact(24) {
            if symbol[4] & 15 != 2 || word(symbol, 6, 2)? == 0 {
                continue;
            }
            let name = word(symbol, 0, 4)? as usize;
            if export_api_at(|i| self.names.get(name.checked_add(i)?).copied()) != Some(api) {
                continue;
            }
            let address = word(symbol, 8, 8)?;
            let size = word(symbol, 16, 8)?;
            if self
                .executable(address, size.max(1))
                .map(|(_, offset)| offset)
                != Some(entry)
            {
                continue;
            }
            if source.is_some_and(|old| old != (address, size)) {
                return Ok(None);
            }
            source = Some((address, size));
        }
        let Some((address, size @ (2 | 5 | 6 | 9))) = source else {
            return Ok(None);
        };
        let code = bytes(self.file, entry, size as usize, self.len, self.budget)?;
        let instruction = code
            .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa])
            .unwrap_or(&code);
        let delta = match instruction {
            [0xe9, a, b, c, d] => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
            [0xeb, a] => i64::from(*a as i8),
            _ => return Ok(None),
        };
        let Some(target) = address
            .checked_add(size)
            .and_then(|end| end.checked_add_signed(delta))
        else {
            return Ok(None);
        };
        if (address..address + size).contains(&target) {
            return Ok(None);
        }
        let Some((segment, offset)) = self.executable(target, 1) else {
            return Ok(None);
        };
        if exports
            .iter()
            .any(|(other, at)| *other != api && *at == offset)
        {
            return Ok(None);
        }
        // Exact entries of ordinary dynamic functions are permitted. Interior
        // entries and IFUNC resolvers cannot inherit this public signature.
        for symbol in self.symbols.chunks_exact(24) {
            if word(symbol, 6, 2)? == 0 || !matches!(symbol[4] & 15, 2 | 10) {
                continue;
            }
            let start = word(symbol, 8, 8)?;
            let size = word(symbol, 16, 8)?.max(1);
            if self.executable(start, 1).is_none() {
                continue;
            }
            let Some(end) = start.checked_add(size) else {
                return Ok(None);
            };
            if target >= start && target < end && (target != start || symbol[4] & 15 == 10) {
                return Ok(None);
            }
        }
        if self.linkage_section(target)? {
            return Ok(None);
        }
        // This is a bounded refusal check, not another hop or an ABI inference.
        // It catches sectionless x86 PLT/GOT transfer stubs too.
        let available = (segment.address + segment.size - target).min(7) as usize;
        let prefix = bytes(self.file, offset, available, self.len, self.budget)?;
        let prefix = prefix
            .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa])
            .unwrap_or(&prefix);
        let prefix = prefix.strip_prefix(&[0xf2]).unwrap_or(prefix);
        if prefix.first() == Some(&0xff) {
            return Ok(None);
        }
        Ok(Some(offset))
    }

    fn linkage_section(&self, target: u64) -> Result<bool, ObservationGap> {
        if self.sections.is_empty() {
            return Ok(false);
        }
        let mut index = word(self.header, 62, 2)? as usize;
        if index == 0xffff {
            index = word(self.sections, 40, 4)? as usize;
        }
        let Some(names) = self.sections.get(index * 64..index * 64 + 64) else {
            return Ok(true);
        };
        let names_offset = word(names, 24, 8)?;
        let names_size = word(names, 32, 8)?;
        for section in self.sections.chunks_exact(64) {
            let start = word(section, 16, 8)?;
            let Some(end) = start.checked_add(word(section, 32, 8)?) else {
                return Ok(true);
            };
            if target < start || target >= end {
                continue;
            }
            let name = word(section, 0, 4)?;
            if name >= names_size {
                return Ok(true);
            }
            let Some(at) = names_offset.checked_add(name) else {
                return Ok(true);
            };
            let prefix = bytes(
                self.file,
                at,
                (names_size - name).min(9) as usize,
                self.len,
                self.budget,
            )?;
            if [b".plt".as_slice(), b".got".as_slice()].iter().any(|stem| {
                prefix.starts_with(stem) && matches!(prefix.get(stem.len()), Some(0 | b'.'))
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
