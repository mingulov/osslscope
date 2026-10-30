// SPDX-License-Identifier: GPL-3.0-or-later
//! One-hop public ABI derivation from the retained ELF, never target memory.
use super::{
    ObservationApi, ObservationBudget, ObservationGap, Segment, TypedRoleId, bytes, export_api_at,
    word,
};
use std::fs::File;

// Test-only work observations inject expiry after an independently selected row.
// They do not implement cancellation; production must still check its budget.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum ScanKind {
    Source = 0,
    Conflict = 1,
    Segment = 2,
}
#[cfg(test)]
#[derive(Clone, Copy, Default)]
pub(super) struct ScanProbe {
    pub rows: [usize; 3],
    pub expire_at: Option<(ScanKind, usize)>,
    pub expired: bool,
    pub after_expiry: usize,
}
#[cfg(test)]
thread_local! {
    pub(super) static SCAN_PROBE: std::cell::Cell<ScanProbe> = const { std::cell::Cell::new(ScanProbe {
        rows: [0; 3], expire_at: None, expired: false, after_expiry: 0,
    }) };
}
#[cfg(test)]
fn observe_scan(budget: &ObservationBudget, kind: ScanKind) {
    SCAN_PROBE.with(|probe| {
        let mut value = probe.get();
        if value.expired {
            value.after_expiry += 1;
        }
        value.rows[kind as usize] += 1;
        if !value.expired
            && value.expire_at.is_some_and(|(at, row)| {
                at as usize == kind as usize && row == value.rows[kind as usize]
            })
        {
            budget.set_deadline(std::time::Instant::now());
            value.expired = true;
        }
        probe.set(value);
    });
}

pub(super) const APIS: [ObservationApi; 2] = [
    ObservationApi::Inventoried(crate::inventory::Api::OsslProviderQueryOperation),
    ObservationApi::OsslProviderUnqueryOperation,
];

/// What a derivation resolves: a legacy public API (matched through the
/// finite legacy spelling table) or a typed role's own public export name
/// (matched byte-exact, claiming no legacy identity).
#[derive(Clone, Copy)]
enum ResolutionSubject<'a> {
    Legacy(ObservationApi),
    Typed(&'a str),
}

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
    fn checkpoint(&self, row: usize) -> Result<(), ObservationGap> {
        if row % 256 == 0 {
            self.budget.checkpoint()?;
        }
        Ok(())
    }

    fn executable(
        &self,
        address: u64,
        size: u64,
    ) -> Result<Option<(&Segment, u64)>, ObservationGap> {
        let Some(end) = address.checked_add(size) else {
            return Ok(None);
        };
        let mut found = None;
        for (index, segment) in self.segments.iter().enumerate() {
            #[cfg(test)]
            observe_scan(self.budget, ScanKind::Segment);
            self.checkpoint(index)?;
            if address >= segment.address
                && end <= segment.address.checked_add(segment.size).unwrap_or(0)
                && found.replace(segment).is_some()
            {
                return Ok(None);
            }
        }
        let Some(segment) = found.filter(|segment| !segment.writable) else {
            return Ok(None);
        };
        let Some(offset) = segment.offset.checked_add(address - segment.address) else {
            return Ok(None);
        };
        Ok(
            (offset.checked_add(size).is_some_and(|end| end <= self.len))
                .then_some((segment, offset)),
        )
    }

    pub(super) fn resolve(
        &self,
        api: ObservationApi,
        entry: u64,
        exports: &[(ObservationApi, u64)],
    ) -> Result<Option<u64>, ObservationGap> {
        self.resolve_inner(ResolutionSubject::Legacy(api), entry, exports)
    }

    /// Typed-role derivation: the same one-hop stub analysis keyed by the
    /// role's own public export name instead of a legacy API identity, with
    /// its own full scans and budget charges. A role without a public
    /// export, or any legacy export at the entry or the target, refuses
    /// (fail closed).
    pub(super) fn resolve_typed(
        &self,
        role: TypedRoleId,
        entry: u64,
        exports: &[(ObservationApi, u64)],
    ) -> Result<Option<u64>, ObservationGap> {
        let Some(name) = role.public_export() else {
            return Ok(None);
        };
        self.resolve_inner(ResolutionSubject::Typed(name), entry, exports)
    }

    fn resolve_inner(
        &self,
        subject: ResolutionSubject<'_>,
        entry: u64,
        exports: &[(ObservationApi, u64)],
    ) -> Result<Option<u64>, ObservationGap> {
        // A typed derivation claims no legacy identity, so any legacy
        // export at the entry refuses; the legacy self-exclusion is
        // unchanged.
        let legacy = match subject {
            ResolutionSubject::Legacy(api) => Some(api),
            ResolutionSubject::Typed(_) => None,
        };
        if exports
            .iter()
            .any(|(other, at)| Some(*other) != legacy && *at == entry)
        {
            return Ok(None);
        }
        let mut source = None;
        for (index, symbol) in self.symbols.chunks_exact(24).enumerate() {
            #[cfg(test)]
            observe_scan(self.budget, ScanKind::Source);
            self.checkpoint(index)?;
            if symbol[4] & 15 != 2 || word(symbol, 6, 2)? == 0 {
                continue;
            }
            let name = word(symbol, 0, 4)? as usize;
            let matched = match subject {
                ResolutionSubject::Legacy(api) => {
                    export_api_at(|i| self.names.get(name.checked_add(i)?).copied()) == Some(api)
                }
                ResolutionSubject::Typed(want) => want
                    .bytes()
                    .chain(std::iter::once(0))
                    .enumerate()
                    .all(|(index, byte)| {
                        name.checked_add(index)
                            .is_some_and(|at| self.names.get(at).copied() == Some(byte))
                    }),
            };
            if !matched {
                continue;
            }
            let address = word(symbol, 8, 8)?;
            let size = word(symbol, 16, 8)?;
            if self
                .executable(address, size.max(1))?
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
        let Some((segment, offset)) = self.executable(target, 1)? else {
            return Ok(None);
        };
        if exports
            .iter()
            .any(|(other, at)| Some(*other) != legacy && *at == offset)
        {
            return Ok(None);
        }
        // Exact entries of ordinary dynamic functions are permitted. Interior
        // entries and IFUNC resolvers cannot inherit this public signature.
        for (index, symbol) in self.symbols.chunks_exact(24).enumerate() {
            #[cfg(test)]
            observe_scan(self.budget, ScanKind::Conflict);
            self.checkpoint(index)?;
            if word(symbol, 6, 2)? == 0 || !matches!(symbol[4] & 15, 2 | 10) {
                continue;
            }
            let start = word(symbol, 8, 8)?;
            if target < start {
                continue;
            }
            let size = word(symbol, 16, 8)?.max(1);
            let end = start.checked_add(size);
            // Discard unrelated intervals and allowed ordinary exact entries
            // before any segment lookup. Overflowing potential conflicts still
            // refuse forwarding when their start has executable backing.
            if end.is_some_and(|end| target >= end)
                || end.is_some() && target == start && symbol[4] & 15 == 2
            {
                continue;
            }
            if self.executable(start, 1)?.is_some() {
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
        for (index, section) in self.sections.chunks_exact(64).enumerate() {
            self.checkpoint(index)?;
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
