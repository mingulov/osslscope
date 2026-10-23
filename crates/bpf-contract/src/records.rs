// SPDX-License-Identifier: GPL-2.0-or-later

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CountValue {
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PendQuery {
    pub op: u64,
    pub ns_ptr: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanRec {
    pub op: u64,
    pub ns_ptr: u64,
    pub seq: u64,
    pub expected: u32,
    pub _pad: u32,
    pub epoch: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TCacheValue {
    pub t: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtrlValue {
    pub expected: u32,
    pub skip_all: u8,
    pub _pad: [u8; 3],
    pub epoch: u64,
    pub governor: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AlgEvent {
    pub kind: u32,
    pub op: u32,
    pub class: u16,
    pub status: u8,
    pub weak: u8,
    pub _pad: u32,
    pub arr: u64,
    pub idx: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TripEvent {
    pub kind: u32,
    pub cookie: u32,
    pub class: u16,
    pub status: u8,
    pub _pad: u8,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RowEvent {
    pub kind: u32,
    pub op: u32,
    pub funcid: u32,
    pub _pad: u32,
    pub addr: u64,
    pub aux: u64,
    pub idx: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct InitRetEvent {
    pub kind: u32,
    pub op: u32,
    pub funcid: u32,
    pub _pad: u32,
    pub addr: u64,
    pub aux: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanCallEvent {
    pub kind: u32,
    pub op: u32,
    pub tid: u32,
    pub flags: u32,
    pub seq: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanRetEvent {
    pub kind: u32,
    pub op: u32,
    pub flags: u32,
    pub tid: u32,
    pub seq: u64,
    pub arr: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GuardEvent {
    pub kind: u32,
    pub op: u32,
    pub verdict: u32,
    pub tid: u32,
    pub seq: u64,
    pub arr: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanAlgEvent {
    pub kind: u32,
    pub op: u32,
    pub class: u16,
    pub status: u8,
    pub weak: u8,
    pub _pad: u32,
    pub arr: u64,
    pub idx: u64,
    pub generation: u64,
    pub tid: u32,
    pub _pad2: u32,
    pub seq: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScanRowEvent {
    pub kind: u32,
    pub op: u32,
    pub funcid: u32,
    pub _pad: u32,
    pub addr: u64,
    pub aux: u64,
    pub idx: u64,
    pub generation: u64,
    pub tid: u32,
    pub _pad2: u32,
    pub seq: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AlgClassValue {
    pub class: u16,
    pub weak: u8,
    pub len: u8,
    pub canon: u16,
    pub name: [u8; 36],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TripClassValue {
    pub engine: u16,
    pub load: u16,
    pub len: u16,
    pub name: [u8; 16],
}

// These assertions also run when the library is compiled for the BPF target.
macro_rules! layout {
    ($record:ty, $size:expr, $align:expr; $($field:ident = $offset:expr),+ $(,)?) => {
        const _: () = {
            assert!(core::mem::size_of::<$record>() == $size);
            assert!(core::mem::align_of::<$record>() == $align);
            $(assert!(core::mem::offset_of!($record, $field) == $offset);)+
        };
    };
}

layout!(CountValue, 24, 8; count = 0, first_ns = 8, last_ns = 16);
layout!(PendQuery, 16, 8; op = 0, ns_ptr = 8);
layout!(ScanRec, 40, 8; op = 0, ns_ptr = 8, seq = 16, expected = 24, _pad = 28, epoch = 32);
layout!(TCacheValue, 16, 8; t = 0, generation = 8);
layout!(CtrlValue, 24, 8; expected = 0, skip_all = 4, _pad = 5, epoch = 8, governor = 16);
layout!(AlgEvent, 40, 8; kind = 0, op = 4, class = 8, status = 10, weak = 11,
    _pad = 12, arr = 16, idx = 24, generation = 32);
layout!(TripEvent, 16, 4; kind = 0, cookie = 4, class = 8, status = 10, _pad = 11, _pad2 = 12);
layout!(RowEvent, 48, 8; kind = 0, op = 4, funcid = 8, _pad = 12,
    addr = 16, aux = 24, idx = 32, generation = 40);
layout!(InitRetEvent, 32, 8; kind = 0, op = 4, funcid = 8, _pad = 12, addr = 16, aux = 24);
layout!(ScanCallEvent, 24, 8; kind = 0, op = 4, tid = 8, flags = 12, seq = 16);
layout!(ScanRetEvent, 40, 8; kind = 0, op = 4, flags = 8, tid = 12, seq = 16, arr = 24, generation = 32);
layout!(GuardEvent, 40, 8; kind = 0, op = 4, verdict = 8, tid = 12, seq = 16, arr = 24, generation = 32);
layout!(ScanAlgEvent, 56, 8; kind = 0, op = 4, class = 8, status = 10, weak = 11,
    _pad = 12, arr = 16, idx = 24, generation = 32, tid = 40, _pad2 = 44, seq = 48);
layout!(ScanRowEvent, 64, 8; kind = 0, op = 4, funcid = 8, _pad = 12,
    addr = 16, aux = 24, idx = 32, generation = 40, tid = 48, _pad2 = 52, seq = 56);
layout!(AlgClassValue, 42, 2; class = 0, weak = 2, len = 3, canon = 4, name = 6);
layout!(TripClassValue, 22, 2; engine = 0, load = 2, len = 4, name = 6);
