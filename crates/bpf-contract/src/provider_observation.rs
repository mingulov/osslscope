// SPDX-License-Identifier: GPL-2.0-or-later
//! Finite observation ABI. No opaque target handle is a transport field.
pub const VERSION: u32 = 2;
pub const EVENT_SIZE: usize = 96;
pub const MAX_DEPTH: u32 = 8;
pub const MAX_PENDING: u32 = 4096;
pub const MAX_RANGES: u32 = 128;
pub const OTHER: u32 = 65535;
pub const ATTEMPT: u32 = 1;
pub const RESULT: u32 = 2;
pub const INIT: u32 = 3;
pub const QUERY: u32 = 4;
pub const ALGORITHM: u32 = 5;
pub const IMPLEMENTATION: u32 = 6;
pub const INVALIDATION: u32 = 7;
pub const GAP: u32 = 8;
/// Internal finite alias: algorithm=class, function=canon, outcome=weak, status=index.
pub const ALIAS: u32 = 9;
/// Internal terminator: function=segment count, status=0/2/3/4, algorithm=OTHER.
pub const ALIAS_END: u32 = 10;
pub const LOAD: u32 = 1;
pub const TRY_LOAD: u32 = 2;
pub const LOAD_EX: u32 = 3;
pub const TRY_LOAD_EX: u32 = 4;
pub const UNLOAD: u32 = 5;
pub const ADD_BUILTIN: u32 = 6;
pub const PROVIDER_INIT: u32 = 7;
pub const PUBLIC_QUERY: u32 = 8;
pub const PUBLIC_UNQUERY: u32 = 9;
pub const QUERY_CALLBACK: u32 = 17;
pub const TEARDOWN: u32 = 18;
pub const UNQUERY_CALLBACK: u32 = 19;
pub const LOSS_RING: u32 = 0;
pub const LOSS_MAP: u32 = 1;
pub const LOSS_DEPTH: u32 = 2;
pub const LOSS_PAIR: u32 = 3;
pub const LOSS_READ: u32 = 4;
pub const LOSS_RANGE: u32 = 5;
pub const LOSS_TRUNC: u32 = 6;
pub const LOSS_NAMESPACE: u32 = 7;
pub const LOSS_MAX: u32 = 8;
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Record {
    pub version: u32,
    pub kind: u32,
    pub size: u32,
    pub api: u32,
    pub pid: u32,
    pub tid: u32,
    pub cookie: u64,
    pub generation: u64,
    pub monotonic_ns: u64,
    pub invocation: u64,
    pub outcome: u32,
    pub operation: u32,
    pub algorithm: u32,
    pub function: u32,
    pub cacheability: u32,
    pub status: u32,
    /// Only INIT and cacheable IMPLEMENTATION may contain a verified-range code operand.
    pub code: u64,
    pub reserved: [u32; 2],
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Config {
    pub generation: u64,
    pub object: u64,
    pub pid: u32,
    pub api: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Member {
    pub generation: u64,
    pub epoch: u64,
    pub range_count: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Namespace {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct RangeKey {
    pub pid: u32,
    pub index: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ThreadKey {
    pub pid: u32,
    pub tid: u32,
    pub generation: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Thread {
    pub next: u64,
    pub depth: u32,
    pub overflow: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PendingKey {
    pub thread: ThreadKey,
    pub depth: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Pending {
    pub cookie: u64,
    pub invocation: u64,
    pub object: u64,
    pub arg0: u64,
    pub arg2: u64,
    pub operation: u32,
    pub api: u32,
    pub name: u32,
    pub suppressed: u32,
}
/// Kernel-only: not a wire record, and the host never enumerates this map.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct CursorKey {
    pub generation: u64,
    pub epoch: u64,
    pub cookie: u64,
    pub context: u64,
    pub table: u64,
    pub pid: u32,
    pub operation: u32,
}
pub const fn known_operation(op: u32) -> u32 {
    match op {
        1..=5 | 10..=14 | 20..=22 => op,
        _ => 0,
    }
}
pub const fn load_api(api: u32) -> bool {
    api >= LOAD && api <= TRY_LOAD_EX
}
pub const fn query_api(api: u32) -> bool {
    api == PUBLIC_QUERY || api == QUERY_CALLBACK
}

/// Wrapper variants collapse only within one object/library-context stack;
/// a same-API recursive call is always a distinct invocation.
pub fn suppress_wrapper(parent: &Pending, child: &Pending) -> bool {
    load_api(parent.api)
        && load_api(child.api)
        && parent.api != child.api
        && parent.object == child.object
        && parent.arg0 == child.arg0
}
/// Sample policy is shared with the consumer tests; no table pointer participates.
pub const fn sample_index(cacheability: u32, stored: u32) -> Option<u32> {
    let index = if cacheability == 1 { stored } else { 0 };
    match index {
        0..=511 => Some(index),
        _ => None,
    }
}
impl Thread {
    pub fn enter(&mut self) -> Option<u64> {
        if self.depth >= MAX_DEPTH || self.overflow != 0 {
            self.overflow = self.overflow.saturating_add(1);
            return None;
        }
        if self.next == u64::MAX {
            self.overflow = self.overflow.saturating_add(1);
            return None;
        }
        self.next += 1;
        self.depth += 1;
        Some(self.next)
    }
    pub fn failed_entry(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        self.overflow = self.overflow.saturating_add(1);
    }
    pub fn skip_return(&mut self) -> bool {
        if self.overflow != 0 {
            self.overflow -= 1;
            true
        } else {
            false
        }
    }
}

/// Exact finite load taxonomy, unrolled to avoid a compiler-local memcmp
/// subprogram that the strict reachable-subset loader cannot relocate.
#[inline(always)]
pub fn provider_name_class(b: &[u8; 32], len: usize) -> u32 {
    if len == 31 {
        return 5;
    }
    if len == 7
        && b[7] == 0
        && b[0] == b'd'
        && b[1] == b'e'
        && b[2] == b'f'
        && b[3] == b'a'
        && b[4] == b'u'
        && b[5] == b'l'
        && b[6] == b't'
    {
        2
    } else if len == 6
        && b[6] == 0
        && b[0] == b'l'
        && b[1] == b'e'
        && b[2] == b'g'
        && b[3] == b'a'
        && b[4] == b'c'
        && b[5] == b'y'
    {
        1
    } else if len == 4 && b[4] == 0 && b[0] == b'f' && b[1] == b'i' && b[2] == b'p' && b[3] == b's'
    {
        3
    } else {
        0
    }
}

/// Documented int APIs return exactly one for success, zero for failure.
/// Other int values remain unknown and never authorize an output-table walk.
pub const fn int_outcome(rv: u64) -> u32 {
    match rv as u32 {
        1 => 1,
        0 => 2,
        _ => 0,
    }
}

/// Executable-range membership, with no target-memory reads.
#[inline(always)]
pub fn code_in_ranges(
    address: u64,
    count: u32,
    mut lookup: impl FnMut(u32) -> Option<Range>,
) -> bool {
    if !(4096..=0x0000_ffff_ffff_ffff).contains(&address) || count == 0 || count > MAX_RANGES {
        return false;
    }
    // Upper-bound search for the last start <= address. Host admission proves
    // sorted, nonempty, disjoint intervals. Eight steps cover all 128 slots.
    let mut low = 0u32;
    let mut high = count;
    let mut end = 0u64;
    for _ in 0..8 {
        if low >= high {
            break;
        }
        let mid = (low + high) / 2;
        let Some(range) = lookup(mid) else {
            return false;
        };
        if address < range.start {
            high = mid
        } else {
            low = mid + 1;
            end = range.end
        }
    }
    address < end
}

/// Aggregate already classified finite alias identities; never raw target bytes.
#[derive(Clone, Copy)]
pub struct FiniteEvidence {
    minimum: u16,
    weak: bool,
    canon: Option<u16>,
    mixed: bool,
}
impl Default for FiniteEvidence {
    fn default() -> Self {
        Self::new()
    }
}
impl FiniteEvidence {
    pub const fn new() -> Self {
        Self {
            minimum: u16::MAX,
            weak: false,
            canon: None,
            mixed: false,
        }
    }
    pub fn include(&mut self, class: u16, weak: u8, canon: u16) {
        if weak > 1 {
            return;
        }
        if class == u16::MAX {
            if canon == u16::MAX && weak == 1 {
                self.weak = true;
            }
            return;
        }
        if canon == u16::MAX {
            return;
        }
        self.minimum = self.minimum.min(class);
        self.weak |= weak == 1;
        if let Some(previous) = self.canon {
            self.mixed |= previous != canon;
        } else {
            self.canon = Some(canon);
        }
    }
    pub fn finish(self, truncated: bool) -> (u16, bool, u8) {
        (
            self.minimum,
            self.weak || truncated,
            if truncated {
                3
            } else if self.canon.is_none() {
                1
            } else if self.mixed {
                5
            } else {
                0
            },
        )
    }
}
