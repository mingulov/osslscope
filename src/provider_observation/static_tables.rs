// SPDX-License-Identifier: GPL-3.0-or-later
//! File-only public-table shape discovery. Candidates do not grant public ABI
//! authority, permit target-memory reads, or establish crypto execution.
//! Public algorithm records may be embedded in opaque containers. Only their
//! public 32-byte prefix is examined; no surrounding array or container layout
//! is inferred. Dispatch arrays must terminate. An unresolved ordinary function
//! linkage can leave a partial table, but never produces a candidate for that
//! row. Malformed, IFUNC and uncorroborated code pointers reject the table.
use super::schema::ObservationBudget;
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs::{File, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TableGap {
    Io,
    UnsupportedElf,
    UnsupportedRelocation,
    MissingFunctionStart,
    Bounds,
    Malformed,
    Resource,
    Changed,
}
#[derive(Clone, Copy)]
/// Work ceilings, independent of versions, names and public function-ID lists.
/// Each validated dispatch or standalone public-record shape consumes a table
/// slot; alias/function association expansion also consumes the entry ceiling.
pub struct TableLimits {
    /// Caps file length and cumulative non-executable load bytes scanned per
    /// pass, including separate virtual loads backed by the same file bytes.
    pub max_object_bytes: u64,
    pub max_tables: usize,
    pub max_entries: usize,
    pub max_metadata_bytes: usize,
}
impl Default for TableLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 128 * 1024 * 1024,
            max_tables: 4096,
            max_entries: 65536,
            max_metadata_bytes: 4 * 1024 * 1024,
        }
    }
}
/// Opaque, object-bound identity. Names and addresses never enter formatting.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DynamicAlgorithmId([u8; 32]);
impl DynamicAlgorithmId {
    /// Observer-generated identity of one public algorithm observation. Only
    /// observer IDs, object fingerprint and bounded ordinal enter this digest.
    pub(crate) fn observed(object: &super::ObjectHash, identity: [u64; 7]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"osslscope-public-algorithm-v1");
        hash.update(String::from(object.clone()).as_bytes());
        for value in identity {
            hash.update(value.to_le_bytes());
        }
        Self(hash.finalize().into())
    }
}
impl std::fmt::Display for DynamicAlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("algorithm-")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
impl std::fmt::Debug for DynamicAlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
struct Row {
    id: u32,
    offset: u64,
}
/// Storage evidence only: neither variant establishes an OpenSSL ABI role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableStorage {
    ReadOnly,
    Relro,
}
struct Dispatch {
    address: u64,
    rows: Vec<Row>,
    storage: TableStorage,
    algorithms: std::ops::Range<usize>,
    partial: bool,
}
struct Algorithm {
    id: DynamicAlgorithmId,
    dispatch: usize,
    _aliases: Vec<u8>,
}
/// Private locators and aliases intentionally have no Debug or serialization.
pub struct TableDiscovery {
    tables: Vec<Dispatch>,
    algorithms: Vec<Algorithm>,
    gaps: Vec<TableGap>,
    read_bytes: u64,
    metadata_bytes: usize,
}
/// A shape is not an advertised ABI, even when its storage and function starts
/// are corroborated. Embedded public records do not imply a surrounding array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticTableProvenance {
    DispatchTableShape,
    AlgorithmRecordShape,
}
/// An entry-count-only site; its shape supplies no callable signature.
pub(crate) struct StaticCandidate {
    pub file_offset: u64,
    pub function_id: u32,
    pub algorithm: Option<DynamicAlgorithmId>,
    pub storage: TableStorage,
    pub provenance: StaticTableProvenance,
    /// Other rows in this table have unresolved ordinary function linkage.
    pub partial: bool,
}
impl TableDiscovery {
    pub fn algorithm_count(&self) -> usize {
        self.algorithms.len()
    }
    pub fn dispatch_table_count(&self) -> usize {
        self.tables.len()
    }
    pub fn partial_table_count(&self) -> usize {
        self.tables.iter().filter(|table| table.partial).count()
    }
    /// Validated dispatch rows, before algorithm associations or physical-site
    /// deduplication by the process-bound observer.
    pub fn candidate_count(&self) -> usize {
        self.tables.iter().map(|t| t.rows.len()).sum()
    }
    pub fn algorithm_ids(&self) -> impl Iterator<Item = DynamicAlgorithmId> + '_ {
        self.algorithms.iter().map(|a| a.id)
    }
    pub fn function_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.tables.iter().flat_map(|t| t.rows.iter().map(|r| r.id))
    }
    /// Actual descriptor bytes read, including bounded cache reloads.
    pub fn read_bytes(&self) -> u64 {
        self.read_bytes
    }
    /// Conservative cumulative metadata allocations, including growth copies.
    pub fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }
    pub fn gaps(&self) -> &[TableGap] {
        &self.gaps
    }
    pub(crate) fn candidates(&self) -> impl Iterator<Item = StaticCandidate> + '_ {
        self.tables.iter().flat_map(move |table| {
            let algorithms = &self.algorithms[table.algorithms.clone()];
            table.rows.iter().flat_map(move |row| {
                algorithms
                    .iter()
                    .map(move |algorithm| StaticCandidate {
                        file_offset: row.offset,
                        function_id: row.id,
                        algorithm: Some(algorithm.id),
                        storage: table.storage,
                        provenance: StaticTableProvenance::AlgorithmRecordShape,
                        partial: table.partial,
                    })
                    .chain(algorithms.is_empty().then_some(StaticCandidate {
                        file_offset: row.offset,
                        function_id: row.id,
                        algorithm: None,
                        storage: table.storage,
                        provenance: StaticTableProvenance::DispatchTableShape,
                        partial: table.partial,
                    }))
            })
        })
    }
}
const PAGE: usize = 16384;
const CACHE_PAGES: usize = 4;
struct Memory {
    used: usize,
    limit: usize,
}
impl Memory {
    fn charge(&mut self, n: usize) -> Result<(), TableGap> {
        self.used = self.used.checked_add(n).ok_or(TableGap::Resource)?;
        if self.used > self.limit {
            Err(TableGap::Resource)
        } else {
            Ok(())
        }
    }
    fn push<T>(&mut self, v: &mut Vec<T>, value: T) -> Result<(), TableGap> {
        if v.len() == v.capacity() {
            let more = v.capacity().max(8);
            self.charge(
                v.capacity()
                    .checked_add(more)
                    .and_then(|capacity| capacity.checked_mul(std::mem::size_of::<T>()))
                    .ok_or(TableGap::Resource)?,
            )?;
            v.try_reserve_exact(more).map_err(|_| TableGap::Resource)?;
        }
        v.push(value);
        Ok(())
    }
}
struct Cache {
    base: u64,
    valid: usize,
    data: [u8; PAGE],
}
struct Reader<'a> {
    file: &'a File,
    len: u64,
    budget: Option<&'a ObservationBudget>,
    cache: RefCell<[Cache; CACHE_PAGES]>,
    victim: Cell<usize>,
    read: Cell<u64>,
    max_read: u64,
}
impl Reader<'_> {
    fn bytes<const N: usize>(&self, offset: u64) -> Result<[u8; N], TableGap> {
        if offset
            .checked_add(N as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(TableGap::Bounds);
        }
        let mut out = [0; N];
        let mut done = 0;
        while done < N {
            let at = offset + done as u64;
            let mut cache = self.cache.borrow_mut();
            let hit = cache
                .iter()
                .position(|c| c.valid > 0 && at >= c.base && at < c.base + c.valid as u64);
            let index = hit.unwrap_or_else(|| {
                let index = self.victim.get();
                self.victim.set((index + 1) % CACHE_PAGES);
                index
            });
            let c = &mut cache[index];
            if hit.is_none() {
                let base = at / PAGE as u64 * PAGE as u64;
                let valid = (self.len - base).min(PAGE as u64) as usize;
                // A refused or failed refill must never expose old bytes as
                // a valid cache hit at the requested new file offset.
                c.valid = 0;
                let next = self
                    .read
                    .get()
                    .checked_add(valid as u64)
                    .ok_or(TableGap::Resource)?;
                if next > self.max_read {
                    return Err(TableGap::Resource);
                }
                if let Some(b) = self.budget {
                    b.read(valid as u64).map_err(|_| TableGap::Resource)?;
                }
                self.read.set(next);
                self.file
                    .read_exact_at(&mut c.data[..valid], base)
                    .map_err(|_| TableGap::Io)?;
                c.base = base;
                c.valid = valid;
            }
            let local = (at - c.base) as usize;
            let n = (N - done).min(c.valid - local);
            out[done..done + n].copy_from_slice(&c.data[local..local + n]);
            done += n;
        }
        Ok(out)
    }
    fn u64(&self, offset: u64) -> Result<u64, TableGap> {
        Ok(u64::from_le_bytes(self.bytes(offset)?))
    }
}
#[derive(Clone, Copy)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
}
enum RelocationTarget {
    Address(u64),
    UnresolvedFunction,
    Rejected(TableGap),
}
struct Relocation {
    slot: u64,
    target: RelocationTarget,
}
struct Elf<'a> {
    reader: Reader<'a>,
    // Sorted, disjoint file-backed loads only. Irrelevant headers never enter
    // address/storage lookup state.
    segments: Vec<Segment>,
    relro: Vec<Segment>,
    dynamic_header: Option<Segment>,
    unwind_header: Option<Segment>,
    relocations: Vec<Relocation>,
    starts: Vec<u64>,
    ifuncs: Vec<u64>,
    tags: Vec<(u64, u64)>,
    kind: u16,
    section_offset: u64,
    section_count: u64,
}
fn add(a: u64, b: u64) -> Result<u64, TableGap> {
    a.checked_add(b).ok_or(TableGap::Bounds)
}
fn stamp(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn w(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn d(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn h(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn index_ranges(ranges: &mut [Segment]) -> Result<(), TableGap> {
    ranges.sort_unstable_by_key(|range| range.address);
    for pair in ranges.windows(2) {
        if add(pair[0].address, pair[0].size)? > pair[1].address {
            return Err(TableGap::Malformed);
        }
    }
    Ok(())
}
fn range_at(ranges: &[Segment], address: u64, size: u64) -> Result<&Segment, TableGap> {
    let end = add(address, size)?;
    let index = ranges
        .partition_point(|range| range.address <= address)
        .checked_sub(1)
        .ok_or(TableGap::Bounds)?;
    let range = &ranges[index];
    if end > add(range.address, range.size)? {
        return Err(TableGap::Bounds);
    }
    Ok(range)
}
impl Elf<'_> {
    fn offset(&self, address: u64, size: u64) -> Result<u64, TableGap> {
        let range = range_at(&self.segments, address, size)?;
        add(range.offset, address - range.address)
    }
    fn word(&self, address: u64) -> Result<u64, TableGap> {
        self.reader.u64(self.offset(address, 8)?)
    }
    fn pointer(&self, address: u64) -> Result<u64, TableGap> {
        if let Ok(i) = self.relocations.binary_search_by_key(&address, |r| r.slot) {
            return match self.relocations[i].target {
                RelocationTarget::Address(address) => Ok(address),
                RelocationTarget::UnresolvedFunction => Err(TableGap::UnsupportedRelocation),
                RelocationTarget::Rejected(gap) => Err(gap),
            };
        }
        let raw = self.word(address)?;
        if raw == 0 || self.kind == 2 {
            Ok(raw)
        } else {
            Err(TableGap::UnsupportedRelocation)
        }
    }
    fn code(&self, address: u64) -> Result<u64, TableGap> {
        let offset = self.offset(address, 1)?;
        if range_at(&self.segments, address, 1)?.flags & 1 == 0 {
            return Err(TableGap::Bounds);
        }
        if self.ifuncs.binary_search(&address).is_ok() {
            return Err(TableGap::UnsupportedRelocation);
        }
        if self.starts.binary_search(&address).is_err() {
            return Err(TableGap::MissingFunctionStart);
        }
        Ok(offset)
    }
    fn tag(&self, t: u64) -> Option<u64> {
        self.tags.iter().find_map(|&(k, v)| (k == t).then_some(v))
    }
    fn symbol_section(&self, address: u64, section: u16) -> Result<bool, TableGap> {
        if section == 0 || section >= 0xff00 {
            return Ok(false);
        }
        if self.section_offset == 0 {
            return Ok(true);
        }
        if section as u64 >= self.section_count {
            return Ok(false);
        }
        let h = self
            .reader
            .bytes::<64>(add(self.section_offset, section as u64 * 64)?)?;
        Ok(d(&h, 4) != 8
            && w(&h, 8) & 6 == 6
            && address >= w(&h, 16)
            && address - w(&h, 16) < w(&h, 32))
    }
    fn symbol(&self, index: u64, count: u64) -> Result<(u64, u8, u8, u16), TableGap> {
        if index >= count {
            return Err(TableGap::Bounds);
        }
        let address = add(
            self.tag(6).ok_or(TableGap::Malformed)?,
            index.checked_mul(24).ok_or(TableGap::Bounds)?,
        )?;
        let row = self.reader.bytes::<24>(self.offset(address, 24)?)?;
        Ok((w(&row, 8), row[4], row[5], h(&row, 6)))
    }
    fn symbol_count(&self) -> Result<u64, TableGap> {
        if self.tag(6).is_none() {
            return Ok(0);
        }
        if self.tag(11) != Some(24) {
            return Err(TableGap::Malformed);
        }
        if let Some(addr) = self.tag(4) {
            let b = self.reader.bytes::<8>(self.offset(addr, 8)?)?;
            return Ok(d(&b, 4) as u64);
        }
        if let Some(addr) = self.tag(0x6ffffef5) {
            let b = self.reader.bytes::<16>(self.offset(addr, 16)?)?;
            let n = d(&b, 0) as u64;
            let first = d(&b, 4) as u64;
            let bloom = d(&b, 8) as u64;
            let buckets = add(
                addr,
                add(16, bloom.checked_mul(8).ok_or(TableGap::Bounds)?)?,
            )?;
            self.offset(buckets, n.checked_mul(4).ok_or(TableGap::Bounds)?)?;
            let mut largest = 0;
            for i in 0..n {
                let x = u32::from_le_bytes(
                    self.reader
                        .bytes::<4>(self.offset(add(buckets, i * 4)?, 4)?)?,
                ) as u64;
                if x != 0 && x < first {
                    return Err(TableGap::Malformed);
                }
                largest = largest.max(x);
            }
            if largest == 0 {
                return Ok(first);
            }
            let chains = add(buckets, n * 4)?;
            let mut index = largest;
            loop {
                let at = add(
                    chains,
                    (index - first).checked_mul(4).ok_or(TableGap::Bounds)?,
                )?;
                let value = u32::from_le_bytes(self.reader.bytes::<4>(self.offset(at, 4)?)?);
                index = add(index, 1)?;
                if value & 1 != 0 {
                    return Ok(index);
                }
            }
        }
        Err(TableGap::UnsupportedElf)
    }
    fn dynamic(&mut self, m: &mut Memory) -> Result<(), TableGap> {
        let Some(s) = self.dynamic_header else {
            return Ok(());
        };
        if s.size % 16 != 0 {
            return Err(TableGap::Malformed);
        }
        let mut terminated = false;
        for at in (0..s.size).step_by(16) {
            let b = self.reader.bytes::<16>(add(s.offset, at)?)?;
            let tag = w(&b, 0);
            if tag == 0 {
                terminated = true;
                break;
            }
            if matches!(
                tag,
                2 | 4 | 6 | 7 | 8 | 9 | 11 | 17 | 18 | 19 | 20 | 23 | 35 | 36 | 37 | 0x6ffffef5
            ) {
                if self.tag(tag).is_some() {
                    return Err(TableGap::Malformed);
                }
                m.push(&mut self.tags, (tag, w(&b, 8)))?;
            }
        }
        if !terminated {
            return Err(TableGap::Malformed);
        }
        if self.tag(17).is_some() || self.tag(18).is_some() {
            return Err(TableGap::UnsupportedRelocation);
        }
        let count = self.symbol_count()?;
        // Bounds precede symbol iteration, independently of an optional section table.
        if count > 0 {
            self.offset(
                self.tag(6).ok_or(TableGap::Malformed)?,
                count.checked_mul(24).ok_or(TableGap::Bounds)?,
            )?;
        }
        for i in 0..count {
            let (address, info, _, section) = self.symbol(i, count)?;
            if section != 0 && section < 0xff00 {
                if info & 15 == 2 && self.symbol_section(address, section)? {
                    m.push(&mut self.starts, address)?;
                } else if info & 15 == 10 {
                    m.push(&mut self.ifuncs, address)?;
                }
            }
        }
        for (tag, size_tag, ent_tag) in [(7, 8, Some(9)), (23, 2, None)] {
            if let Some(address) = self.tag(tag) {
                let size = self.tag(size_tag).ok_or(TableGap::Malformed)?;
                if size % 24 != 0
                    || ent_tag.is_some_and(|t| self.tag(t) != Some(24))
                    || tag == 23 && self.tag(20) != Some(7)
                {
                    return Err(TableGap::UnsupportedRelocation);
                }
                self.offset(address, size)?;
                for delta in (0..size).step_by(24) {
                    let b = self
                        .reader
                        .bytes::<24>(self.offset(add(address, delta)?, 24)?)?;
                    let slot = w(&b, 0);
                    let info = w(&b, 8);
                    let addend = w(&b, 16);
                    self.offset(slot, 8)?;
                    let mut unresolved = false;
                    let target = match (info as u32, info >> 32) {
                        (8, 0) => Ok(addend),
                        (1, index) => self.symbol(index, count).and_then(
                            |(value, info, visibility, section)| {
                                // An ordinary unresolved linkage may be skipped,
                                // but is never guessed to refer to this file.
                                if info & 15 == 2
                                    && matches!(info >> 4, 1 | 2)
                                    && visibility & 3 == 0
                                    && addend == 0
                                {
                                    if section == 0 {
                                        if value != 0 {
                                            return Err(TableGap::Malformed);
                                        }
                                    } else {
                                        if !self.symbol_section(value, section)? {
                                            return Err(TableGap::Malformed);
                                        }
                                        if range_at(&self.segments, value, 1)?.flags & 1 == 0 {
                                            return Err(TableGap::Bounds);
                                        }
                                    }
                                    unresolved = true;
                                    return Err(TableGap::UnsupportedRelocation);
                                }
                                if info & 15 == 10
                                    || section == 0
                                    || section >= 0xff00
                                    || info >> 4 != 0 && visibility & 3 == 0
                                {
                                    return Err(TableGap::UnsupportedRelocation);
                                }
                                value
                                    .checked_add_signed(addend as i64)
                                    .ok_or(TableGap::Bounds)
                            },
                        ),
                        _ => Err(TableGap::UnsupportedRelocation),
                    };
                    let target = match target {
                        Ok(address) => RelocationTarget::Address(address),
                        Err(TableGap::UnsupportedRelocation) if unresolved => {
                            RelocationTarget::UnresolvedFunction
                        }
                        Err(gap) => RelocationTarget::Rejected(gap),
                    };
                    m.push(&mut self.relocations, Relocation { slot, target })?;
                }
            } else if self.tag(size_tag).is_some_and(|s| s != 0) {
                return Err(TableGap::Malformed);
            }
        }
        if let Some(address) = self.tag(36) {
            let size = self.tag(35).ok_or(TableGap::Malformed)?;
            if size % 8 != 0 || self.tag(37) != Some(8) {
                return Err(TableGap::UnsupportedRelocation);
            }
            self.offset(address, size)?;
            let mut next = None;
            for delta in (0..size).step_by(8) {
                let entry = self.word(add(address, delta)?)?;
                if entry & 1 == 0 {
                    self.offset(entry, 8)?;
                    let target = RelocationTarget::Address(self.word(entry)?);
                    m.push(
                        &mut self.relocations,
                        Relocation {
                            slot: entry,
                            target,
                        },
                    )?;
                    next = Some(add(entry, 8)?);
                } else {
                    let base = next.ok_or(TableGap::Malformed)?;
                    for bit in 1..64 {
                        if entry & (1u64 << bit) != 0 {
                            let slot = add(base, (bit - 1) * 8)?;
                            let target = RelocationTarget::Address(self.word(slot)?);
                            m.push(&mut self.relocations, Relocation { slot, target })?;
                        }
                    }
                    next = Some(add(base, 63 * 8)?);
                }
            }
        } else if self.tag(35).is_some_and(|s| s != 0) {
            return Err(TableGap::Malformed);
        }
        self.relocations.sort_unstable_by_key(|r| r.slot);
        if self.relocations.windows(2).any(|r| r[0].slot == r[1].slot) {
            return Err(TableGap::Malformed);
        }
        Ok(())
    }
    fn encoded(
        &self,
        cursor: &mut u64,
        end: u64,
        encoding: u8,
        base: u64,
    ) -> Result<u64, TableGap> {
        let at = *cursor;
        let (size, signed) = match encoding & 15 {
            3 => (4, false),
            4 => (8, false),
            0xb => (4, true),
            0xc => (8, true),
            _ => return Err(TableGap::UnsupportedElf),
        };
        *cursor = add(at, size)?;
        if *cursor > end {
            return Err(TableGap::Bounds);
        }
        let raw = if size == 4 {
            let v = u32::from_le_bytes(self.reader.bytes::<4>(self.offset(at, 4)?)?);
            if signed {
                (v as i32 as i64) as u64
            } else {
                v as u64
            }
        } else {
            self.word(at)?
        };
        let relative = match encoding & 0xf0 {
            0 => return Ok(raw),
            0x10 => at,
            0x30 => base,
            _ => return Err(TableGap::UnsupportedElf),
        };
        if signed {
            relative
                .checked_add_signed(raw as i64)
                .ok_or(TableGap::Bounds)
        } else {
            add(relative, raw)
        }
    }
    fn unwind(&mut self, m: &mut Memory) -> Result<(), TableGap> {
        let Some(s) = self.unwind_header else {
            return Ok(());
        };
        let b = self.reader.bytes::<4>(s.offset)?;
        if b[0] != 1 {
            return Err(TableGap::UnsupportedElf);
        }
        let mut cursor = add(s.address, 4)?;
        let end = add(s.address, s.size)?;
        let eh = self.encoded(&mut cursor, end, b[1], s.address)?;
        self.offset(eh, 4)?;
        let count = self.encoded(&mut cursor, end, b[2], s.address)?;
        let mut previous = None;
        for _ in 0..count {
            let start = self.encoded(&mut cursor, end, b[3], s.address)?;
            let fde = self.encoded(&mut cursor, end, b[3], s.address)?;
            self.offset(fde, 8)?;
            if self.fde_start(fde)? != start {
                return Err(TableGap::Malformed);
            }
            if previous.is_some_and(|p| p >= start) {
                return Err(TableGap::Malformed);
            }
            previous = Some(start);
            m.push(&mut self.starts, start)?;
        }
        Ok(())
    }
    fn leb(&self, cursor: &mut u64, end: u64) -> Result<u64, TableGap> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            if *cursor >= end {
                return Err(TableGap::Bounds);
            }
            let byte = self.reader.bytes::<1>(self.offset(*cursor, 1)?)?[0];
            *cursor = add(*cursor, 1)?;
            if shift == 63 && byte & 0x7e != 0 {
                return Err(TableGap::Malformed);
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(TableGap::Malformed)
    }
    fn fde_start(&self, fde: u64) -> Result<u64, TableGap> {
        let head = self.reader.bytes::<8>(self.offset(fde, 8)?)?;
        let length = d(&head, 0) as u64;
        if length < 8 || length == u32::MAX as u64 {
            return Err(TableGap::UnsupportedElf);
        }
        let end = add(fde, add(4, length)?)?;
        self.offset(fde, 4 + length)?;
        let cie = add(fde, 4)?
            .checked_sub(d(&head, 4) as u64)
            .ok_or(TableGap::Bounds)?;
        let head = self.reader.bytes::<9>(self.offset(cie, 9)?)?;
        let length = d(&head, 0) as u64;
        if length < 5 || length == u32::MAX as u64 || d(&head, 4) != 0 || !matches!(head[8], 1 | 3)
        {
            return Err(TableGap::UnsupportedElf);
        }
        let cie_end = add(cie, add(4, length)?)?;
        self.offset(cie, 4 + length)?;
        let mut cursor = add(cie, 9)?;
        let mut augmentation = [0; 32];
        let mut used = 0;
        loop {
            if cursor >= cie_end || used >= augmentation.len() {
                return Err(TableGap::Malformed);
            }
            let b = self.reader.bytes::<1>(self.offset(cursor, 1)?)?[0];
            cursor = add(cursor, 1)?;
            if b == 0 {
                break;
            }
            augmentation[used] = b;
            used += 1;
        }
        self.leb(&mut cursor, cie_end)?; // code alignment
        // Signed data alignment has the same termination; its value is irrelevant.
        let mut terminated = false;
        for _ in 0..10 {
            if cursor >= cie_end {
                return Err(TableGap::Bounds);
            }
            let b = self.reader.bytes::<1>(self.offset(cursor, 1)?)?[0];
            cursor = add(cursor, 1)?;
            if b & 0x80 == 0 {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(TableGap::Malformed);
        }
        if head[8] == 1 {
            cursor = add(cursor, 1)?;
            if cursor > cie_end {
                return Err(TableGap::Bounds);
            }
        } else {
            self.leb(&mut cursor, cie_end)?;
        }
        let mut encoding = 4;
        if used > 0 {
            if augmentation[0] != b'z' {
                return Err(TableGap::UnsupportedElf);
            }
            let aug_len = self.leb(&mut cursor, cie_end)?;
            let aug_end = add(cursor, aug_len)?;
            if aug_end > cie_end {
                return Err(TableGap::Bounds);
            }
            for &kind in &augmentation[1..used] {
                if kind == b'S' {
                    continue;
                }
                if cursor >= aug_end {
                    return Err(TableGap::Bounds);
                }
                let value = self.reader.bytes::<1>(self.offset(cursor, 1)?)?[0];
                cursor = add(cursor, 1)?;
                match kind {
                    b'R' => encoding = value,
                    b'L' => {}
                    b'P' => {
                        self.encoded(&mut cursor, aug_end, value & 0x7f, 0)?;
                    }
                    _ => return Err(TableGap::UnsupportedElf),
                }
            }
        }
        let mut cursor = add(fde, 8)?;
        let start = self.encoded(&mut cursor, end, encoding, 0)?;
        let size = self.encoded(&mut cursor, end, encoding & 15, 0)?;
        if range_at(&self.segments, start, size.max(1))?.flags & 1 == 0 {
            return Err(TableGap::Bounds);
        }
        Ok(start)
    }
    fn storage(&self, address: u64, size: u64) -> Option<TableStorage> {
        let load = range_at(&self.segments, address, size).ok()?;
        if load.flags & 3 == 0 {
            return Some(TableStorage::ReadOnly);
        }
        range_at(&self.relro, address, size)
            .ok()
            .map(|_| TableStorage::Relro)
    }
    fn function_id(&self, address: u64) -> Result<u32, TableGap> {
        // OSSL_DISPATCH has an int32 ID, then unspecified alignment padding.
        Ok(u32::from_le_bytes(
            self.reader.bytes::<4>(self.offset(address, 4)?)?,
        ))
    }
    fn structural_row(&self, address: u64) -> Result<bool, TableGap> {
        if self
            .relocations
            .binary_search_by_key(&address, |relocation| relocation.slot)
            .is_ok()
        {
            return Ok(false);
        }
        let id = self.function_id(address)?;
        if id == 0 || id > i32::MAX as u32 {
            return Ok(false);
        }
        let slot = add(address, 8)?;
        if self
            .relocations
            .binary_search_by_key(&slot, |relocation| relocation.slot)
            .is_ok()
        {
            return Ok(true);
        }
        Ok(self.kind == 2 && self.word(slot)? != 0)
    }
    fn algorithm_implementation(&self, address: u64) -> Result<Option<u64>, TableGap> {
        match self.pointer(address) {
            Ok(pointer) => Ok(Some(pointer)),
            Err(gap @ (TableGap::Resource | TableGap::Io | TableGap::Changed)) => Err(gap),
            Err(_) => Ok(None),
        }
    }
    fn dispatch(
        &self,
        address: u64,
        m: &mut Memory,
        entries: &mut usize,
        limits: TableLimits,
    ) -> Result<Dispatch, TableGap> {
        let mut rows: Vec<Row> = Vec::new();
        let first_entry = *entries;
        let mut partial = false;
        let mut at = address;
        let storage = self.storage(address, 16).ok_or(TableGap::Malformed)?;
        loop {
            if self.storage(at, 16) != Some(storage) {
                return Err(TableGap::Bounds);
            }
            if self
                .relocations
                .binary_search_by_key(&at, |relocation| relocation.slot)
                .is_ok()
            {
                return Err(TableGap::Malformed);
            }
            let id = self.function_id(at)?;
            if id == 0 {
                if *entries == first_entry {
                    return Err(TableGap::Malformed);
                }
                // Repeated public IDs occur in real tables. They do not
                // choose an ABI role or multiply physical execution counts.
                rows.sort_unstable_by_key(|row| row.id);
                return Ok(Dispatch {
                    address,
                    rows,
                    storage,
                    algorithms: 0..0,
                    partial,
                });
            }
            let slot = add(at, 8)?;
            let unresolved = self
                .relocations
                .binary_search_by_key(&slot, |relocation| relocation.slot)
                .is_ok_and(|index| {
                    matches!(
                        self.relocations[index].target,
                        RelocationTarget::UnresolvedFunction
                    )
                });
            let target = if unresolved {
                partial = true;
                None
            } else {
                Some(self.pointer(slot)?)
            };
            if id > i32::MAX as u32 || target == Some(0) {
                return Err(TableGap::Malformed);
            }
            *entries = entries.checked_add(1).ok_or(TableGap::Resource)?;
            if *entries > limits.max_entries {
                return Err(TableGap::Resource);
            }
            if let Some(target) = target {
                m.push(
                    &mut rows,
                    Row {
                        id,
                        offset: self.code(target)?,
                    },
                )?;
            }
            at = add(at, 16)?;
        }
    }

    fn string(&self, address: u64, m: &mut Memory, allow_empty: bool) -> Result<Vec<u8>, TableGap> {
        if address == 0 {
            return Err(TableGap::Malformed);
        }
        let mut value = Vec::new();
        // Public const char* fields are bounded NUL-terminated byte strings,
        // not an ASCII/UTF-8 admission list. Bytes stay private and opaque.
        for i in 0..4096 {
            let c = self.reader.bytes::<1>(self.offset(add(address, i)?, 1)?)?[0];
            if c == 0 {
                return if value.is_empty() && !allow_empty {
                    Err(TableGap::Malformed)
                } else {
                    Ok(value)
                };
            }
            m.push(&mut value, c)?;
        }
        Err(TableGap::Resource)
    }
}
/// Inspect a retained descriptor; no pathname is reopened or trusted.
pub fn discover_tables(file: &File, limits: TableLimits) -> Result<TableDiscovery, TableGap> {
    discover(file, limits, None)
}
/// Production integration uses the same parser and cumulative session admission.
#[allow(dead_code)]
pub(crate) fn discover_tables_budgeted(
    file: &File,
    limits: TableLimits,
    budget: &ObservationBudget,
) -> Result<TableDiscovery, TableGap> {
    discover(file, limits, Some(budget))
}
fn discover(
    file: &File,
    limits: TableLimits,
    budget: Option<&ObservationBudget>,
) -> Result<TableDiscovery, TableGap> {
    let before = file.metadata().map_err(|_| TableGap::Io)?;
    if !before.is_file() {
        return Err(TableGap::UnsupportedElf);
    }
    if before.len() > limits.max_object_bytes {
        return Err(TableGap::Resource);
    }
    // Reserve the entire metadata ceiling before any parser allocation; live
    // callers share this cumulative charge with other retained-object work.
    if let Some(b) = budget {
        b.state(limits.max_metadata_bytes)
            .map_err(|_| TableGap::Resource)?;
    }
    let mut m = Memory {
        used: 0,
        limit: limits.max_metadata_bytes,
    };
    m.charge(std::mem::size_of::<Elf<'_>>() + std::mem::size_of::<TableDiscovery>() + PAGE + 4096)?;
    let reader = Reader {
        file,
        len: before.len(),
        budget,
        cache: RefCell::new(std::array::from_fn(|_| Cache {
            base: 0,
            valid: 0,
            data: [0; PAGE],
        })),
        victim: Cell::new(0),
        read: Cell::new(0),
        max_read: limits.max_object_bytes.saturating_mul(16),
    };
    let header = reader.bytes::<64>(0)?;
    if &header[..6] != b"\x7fELF\x02\x01"
        || h(&header, 18) != 62
        || !matches!(h(&header, 16), 2 | 3)
    {
        return Err(TableGap::UnsupportedElf);
    }
    if d(&header, 20) != 1 || h(&header, 52) != 64 || h(&header, 54) != 56 {
        return Err(TableGap::Malformed);
    }
    let phoff = w(&header, 32);
    let phnum = h(&header, 56) as u64;
    if phnum == 0 || phnum == 0xffff {
        return Err(TableGap::UnsupportedElf);
    }
    if add(phoff, phnum * 56)? > before.len() {
        return Err(TableGap::Bounds);
    }
    let mut elf = Elf {
        reader,
        segments: Vec::new(),
        relro: Vec::new(),
        dynamic_header: None,
        unwind_header: None,
        relocations: Vec::new(),
        starts: Vec::new(),
        ifuncs: Vec::new(),
        tags: Vec::new(),
        kind: h(&header, 16),
        section_offset: 0,
        section_count: 0,
    };
    let mut scan_bytes = 0u64;
    for i in 0..phnum {
        let b = elf.reader.bytes::<56>(add(phoff, i * 56)?)?;
        if !matches!(d(&b, 0), 1 | 2 | 0x6474e550 | 0x6474e552) {
            continue;
        }
        let s = Segment {
            kind: d(&b, 0),
            flags: d(&b, 4),
            offset: w(&b, 8),
            address: w(&b, 16),
            size: w(&b, 32),
        };
        if add(s.offset, s.size)? > before.len() || s.size > w(&b, 40) {
            return Err(TableGap::Bounds);
        }
        add(s.address, w(&b, 40))?;
        match s.kind {
            1 if s.size > 0 => {
                if s.flags & 1 == 0 {
                    // Distinct virtual loads may alias the same file bytes.
                    // Bound both scans by admitted bytes, not file length alone.
                    scan_bytes = scan_bytes.checked_add(s.size).ok_or(TableGap::Resource)?;
                    if scan_bytes > limits.max_object_bytes {
                        return Err(TableGap::Resource);
                    }
                }
                m.push(&mut elf.segments, s)?;
            }
            2 => {
                if elf.dynamic_header.replace(s).is_some() {
                    return Err(TableGap::Malformed);
                }
            }
            0x6474e550 => {
                if elf.unwind_header.replace(s).is_some() {
                    return Err(TableGap::Malformed);
                }
            }
            0x6474e552 if s.size > 0 => m.push(&mut elf.relro, s)?,
            _ => {}
        }
    }
    index_ranges(&mut elf.segments)?;
    index_ranges(&mut elf.relro)?;
    // Section metadata is optional, but malformed present headers fail closed.
    let shoff = w(&header, 40);
    if shoff != 0 {
        if h(&header, 58) != 64 {
            return Err(TableGap::Malformed);
        }
        let count = if h(&header, 60) == 0 {
            w(&elf.reader.bytes::<64>(shoff)?, 32)
        } else {
            h(&header, 60) as u64
        };
        if add(shoff, count.checked_mul(64).ok_or(TableGap::Bounds)?)? > before.len() {
            return Err(TableGap::Bounds);
        }
        elf.section_offset = shoff;
        elf.section_count = count;
        for i in 0..count {
            let b = elf.reader.bytes::<64>(add(shoff, i * 64)?)?;
            if d(&b, 4) != 8 && add(w(&b, 24), w(&b, 32))? > before.len() {
                return Err(TableGap::Bounds);
            }
            if matches!(d(&b, 4), 2 | 11) {
                if w(&b, 56) != 24 || w(&b, 32) % 24 != 0 {
                    return Err(TableGap::Malformed);
                }
                for delta in (0..w(&b, 32)).step_by(24) {
                    let symbol = elf.reader.bytes::<24>(add(w(&b, 24), delta)?)?;
                    if h(&symbol, 6) != 0 && h(&symbol, 6) < 0xff00 {
                        match symbol[4] & 15 {
                            2 if elf.symbol_section(w(&symbol, 8), h(&symbol, 6))? => {
                                m.push(&mut elf.starts, w(&symbol, 8))?
                            }
                            10 => m.push(&mut elf.ifuncs, w(&symbol, 8))?,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    elf.dynamic(&mut m)?;
    elf.unwind(&mut m)?;
    elf.starts.sort_unstable();
    elf.starts.dedup();
    elf.ifuncs.sort_unstable();
    elf.ifuncs.dedup();
    let mut hash = Sha256::new();
    let mut at = 0;
    while at + PAGE as u64 <= before.len() {
        hash.update(elf.reader.bytes::<PAGE>(at)?);
        at += PAGE as u64;
    }
    while at < before.len() {
        hash.update(elf.reader.bytes::<1>(at)?);
        at += 1;
    }
    let object_hash: [u8; 32] = hash.finalize().into();
    let mut result = TableDiscovery {
        tables: Vec::new(),
        algorithms: Vec::new(),
        gaps: Vec::new(),
        read_bytes: 0,
        metadata_bytes: 0,
    };
    let mut entries = 0;
    for s in &elf.segments {
        if s.kind != 1 || s.flags & 1 != 0 {
            continue;
        }
        let mut at = add(s.address, 7)? & !7;
        let end = add(s.address, s.size)?;
        while add(at, 16)? <= end {
            if elf.storage(at, 16).is_some()
                && elf.structural_row(at)?
                // Defer anonymous interior-looking rows. A public record's
                // explicit start is validated independently below, even if
                // the apparent predecessor was rejected.
                && !(at >= s.address + 16 && elf.structural_row(at - 16)?)
            {
                match elf.dispatch(at, &mut m, &mut entries, limits) {
                    Ok(table) => {
                        if table.partial && !result.gaps.contains(&TableGap::UnsupportedRelocation)
                        {
                            m.push(&mut result.gaps, TableGap::UnsupportedRelocation)?;
                        }
                        if result.tables.len() >= limits.max_tables {
                            return Err(TableGap::Resource);
                        }
                        m.push(&mut result.tables, table)?;
                    }
                    Err(TableGap::Resource) => return Err(TableGap::Resource),
                    Err(gap) => {
                        if !result.gaps.contains(&gap) {
                            m.push(&mut result.gaps, gap)?;
                        }
                    }
                }
            }
            at = add(at, 8)?;
        }
    }
    result.tables.sort_unstable_by_key(|table| table.address);
    // Stable table indices plus a small sorted address index permit independent
    // public-record starts without repeatedly searching every discovered table.
    let mut table_index = Vec::new();
    for (index, table) in result.tables.iter().enumerate() {
        m.push(&mut table_index, (table.address, index))?;
    }
    for s in &elf.segments {
        if s.kind != 1 || s.flags & 1 != 0 {
            continue;
        }
        let mut at = add(s.address, 7)? & !7;
        let end = add(s.address, s.size)?;
        while add(at, 32)? <= end {
            if let Some(implementation) = elf.algorithm_implementation(add(at, 16)?)? {
                if elf.storage(at, 32).is_some() {
                    let lookup =
                        table_index.binary_search_by_key(&implementation, |&(address, _)| address);
                    let possible = lookup.is_ok()
                        || elf.storage(implementation, 16).is_some()
                            && elf.structural_row(implementation)?;
                    if possible {
                        // Validate exactly the public record before accepting a
                        // previously deferred start. No private container fields
                        // or arbitrary anonymous tails establish this reference.
                        let record = (|| -> Result<Algorithm, TableGap> {
                            let aliases = elf.string(elf.pointer(at)?, &mut m, false)?;
                            for slot in [add(at, 8)?, add(at, 24)?] {
                                let pointer = elf.pointer(slot)?;
                                if pointer != 0 {
                                    let _ = elf.string(pointer, &mut m, true)?;
                                }
                            }
                            let dispatch = match lookup {
                                Ok(index) => table_index[index].1,
                                Err(position) => {
                                    let table =
                                        elf.dispatch(implementation, &mut m, &mut entries, limits)?;
                                    if result
                                        .tables
                                        .len()
                                        .checked_add(result.algorithms.len())
                                        .is_none_or(|count| count >= limits.max_tables)
                                    {
                                        return Err(TableGap::Resource);
                                    }
                                    if table.partial
                                        && !result.gaps.contains(&TableGap::UnsupportedRelocation)
                                    {
                                        m.push(&mut result.gaps, TableGap::UnsupportedRelocation)?;
                                    }
                                    let index = result.tables.len();
                                    m.push(&mut result.tables, table)?;
                                    m.push(&mut table_index, (implementation, index))?;
                                    table_index[position..].rotate_right(1);
                                    index
                                }
                            };
                            let mut id = Sha256::new();
                            id.update(b"osslscope-static-algorithm-v1\0");
                            id.update(object_hash);
                            id.update(at.to_le_bytes());
                            id.update(implementation.to_le_bytes());
                            Ok(Algorithm {
                                id: DynamicAlgorithmId(id.finalize().into()),
                                dispatch,
                                _aliases: aliases,
                            })
                        })();
                        match record {
                            Ok(algorithm) => {
                                entries = entries.checked_add(1).ok_or(TableGap::Resource)?;
                                if entries > limits.max_entries
                                    || result
                                        .tables
                                        .len()
                                        .checked_add(result.algorithms.len())
                                        .is_none_or(|count| count >= limits.max_tables)
                                {
                                    return Err(TableGap::Resource);
                                }
                                m.push(&mut result.algorithms, algorithm)?;
                            }
                            Err(TableGap::Resource) => return Err(TableGap::Resource),
                            Err(gap) => {
                                if !result.gaps.contains(&gap) {
                                    m.push(&mut result.gaps, gap)?;
                                }
                            }
                        }
                    }
                }
            }
            at = add(at, 8)?;
        }
    }
    // Bound association expansion as well as parsed records. Many aliases may
    // share an implementation; iteration must not create an unbounded product.
    result
        .algorithms
        .sort_unstable_by_key(|algorithm| (algorithm.dispatch, algorithm.id));
    let mut expanded = 0usize;
    for (index, table) in result.tables.iter_mut().enumerate() {
        let start = result
            .algorithms
            .partition_point(|algorithm| algorithm.dispatch < index);
        let end = result
            .algorithms
            .partition_point(|algorithm| algorithm.dispatch <= index);
        table.algorithms = start..end;
        expanded = expanded
            .checked_add(
                table
                    .rows
                    .len()
                    .checked_mul((end - start).max(1))
                    .ok_or(TableGap::Resource)?,
            )
            .ok_or(TableGap::Resource)?;
        if expanded > limits.max_entries {
            return Err(TableGap::Resource);
        }
    }
    result.read_bytes = elf.reader.read.get();
    result.metadata_bytes = m.used;
    result.gaps.sort_unstable();
    if stamp(&before) != stamp(&file.metadata().map_err(|_| TableGap::Changed)?) {
        return Err(TableGap::Changed);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_observation::schema::{ObservationBudget, ObservationLimits};

    #[test]
    fn cumulative_budget_refuses_state_and_reads_before_file_access() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let limits = TableLimits {
            max_object_bytes: u64::MAX,
            ..TableLimits::default()
        };
        let state = ObservationBudget::new(ObservationLimits {
            max_state_bytes: 0,
            ..ObservationLimits::default()
        });
        assert!(matches!(
            discover_tables_budgeted(&file, limits, &state),
            Err(TableGap::Resource)
        ));
        assert_eq!(state.elf_read_bytes(), 0);
        let reads = ObservationBudget::new(ObservationLimits {
            max_elf_read_bytes: 1,
            ..ObservationLimits::default()
        });
        assert!(matches!(
            discover_tables_budgeted(&file, limits, &reads),
            Err(TableGap::Resource)
        ));
        assert_eq!(reads.elf_read_bytes(), 0);
    }

    #[test]
    fn refused_cache_refill_never_becomes_a_successful_stale_hit() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let len = file.metadata().unwrap().len();
        assert!(len > 2 * PAGE as u64);
        let budget = ObservationBudget::new(ObservationLimits {
            max_elf_read_bytes: PAGE as u64,
            ..ObservationLimits::default()
        });
        let reader = Reader {
            file: &file,
            len,
            budget: Some(&budget),
            cache: RefCell::new(std::array::from_fn(|_| Cache {
                base: 0,
                valid: 0,
                data: [0; PAGE],
            })),
            victim: Cell::new(0),
            read: Cell::new(0),
            max_read: u64::MAX,
        };
        assert!(reader.bytes::<1>(0).is_ok());
        assert_eq!(reader.bytes::<1>(PAGE as u64), Err(TableGap::Resource));
        assert_eq!(reader.bytes::<1>(PAGE as u64), Err(TableGap::Resource));
        assert_eq!(budget.elf_read_bytes(), PAGE as u64);
    }

    #[test]
    fn scan_predicates_propagate_resource_refusal() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let len = file.metadata().unwrap().len();
        let budget = ObservationBudget::new(ObservationLimits {
            max_elf_read_bytes: 0,
            ..ObservationLimits::default()
        });
        let elf = Elf {
            reader: Reader {
                file: &file,
                len,
                budget: Some(&budget),
                cache: RefCell::new(std::array::from_fn(|_| Cache {
                    base: 0,
                    valid: 0,
                    data: [0; PAGE],
                })),
                victim: Cell::new(0),
                read: Cell::new(0),
                max_read: u64::MAX,
            },
            segments: vec![Segment {
                kind: 1,
                flags: 4,
                offset: 0,
                address: 0,
                size: len,
            }],
            relro: Vec::new(),
            dynamic_header: None,
            unwind_header: None,
            relocations: Vec::new(),
            starts: Vec::new(),
            ifuncs: Vec::new(),
            tags: Vec::new(),
            kind: 3,
            section_offset: 0,
            section_count: 0,
        };
        assert_eq!(elf.structural_row(0), Err(TableGap::Resource));
        assert_eq!(elf.algorithm_implementation(0), Err(TableGap::Resource));
        assert_eq!(budget.elf_read_bytes(), 0);
    }

    #[test]
    #[ignore = "opt-in independent normal OpenSSL listing comparison"]
    fn compare_stock_alias_set_with_normal_listing() {
        let file = File::open(std::env::var_os("OSSLSCOPE_STATIC_ELF").unwrap()).unwrap();
        let discovery = discover_tables(&file, TableLimits::default()).unwrap();
        let listing =
            std::fs::read_to_string(std::env::var_os("OSSLSCOPE_STATIC_ALIASES").unwrap()).unwrap();
        let expected: std::collections::BTreeSet<_> = listing
            .lines()
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let actual: std::collections::BTreeSet<_> = discovery
            .algorithms
            .iter()
            .flat_map(|a| a._aliases.split(|&c| c == b':'))
            .filter_map(|alias| String::from_utf8(alias.to_ascii_lowercase()).ok())
            .collect();
        let intersection = actual.intersection(&expected).count();
        println!(
            "static_aliases={} listed_aliases={} intersection={} static_only={} listed_only={}",
            actual.len(),
            expected.len(),
            intersection,
            actual.difference(&expected).count(),
            expected.difference(&actual).count()
        );
        for alias in expected.difference(&actual) {
            let token: String = Sha256::digest(alias.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            println!("listed_only_token={token}");
        }
        assert!(!expected.is_empty());
        // Listings prove advertisement, not execution, and static candidates
        // may include unavailable providers or alternate implementations.
        // This is a comparison, not a coverage-equality gate: static-only
        // records may contain disabled alternatives, while listings may add
        // registry aliases or use imported/interposable implementations.
        assert!(
            intersection > 0,
            "listing and file have no overlapping aliases"
        );
    }
}
