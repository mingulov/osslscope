// SPDX-License-Identifier: GPL-2.0-or-later

pub const ALG_WINDOW: usize = 128;
pub const TRIP_WINDOW: usize = 32;
pub const ALG_EMPTY: u8 = 6;
pub const ALG_NOIMP: u8 = 7;
pub const ALG_UNREADABLE: u8 = 4;
pub const TRIP_UNREADABLE: u8 = 1;
pub const BIRTH_FROZEN: u16 = 65535;
pub const OTHER_CLASS: u16 = 65535;
pub const TRIP_OTHER: u16 = 0;
pub const BUCKET_BURST: u64 = 4;
pub const BUCKET_PERIOD_SHIFTED: u64 = 97656;
pub const MEMBER_ENTRY_COOKIE: u64 = 512;
pub const RINGBUF_AVAIL_DATA: u64 = 0;
pub const SEQ_CTR_MAX: u64 = 281474976710655;
pub const GUARD_EMPTY: u32 = 0;
pub const GUARD_ERROR: u32 = 2;
pub const GUARD_VALID: u32 = 1;
pub const RCOUNT_STATE_ACTIVE: u32 = 1;
pub const RCOUNT_STATE_IDLE: u32 = 0;
pub const RET_FLAG_EMPTY: u32 = 1;
pub const KIND_ALG: u32 = 4;
pub const KIND_GUARD: u32 = 9;
pub const KIND_INIT_RET: u32 = 1;
pub const KIND_QUERY_RET: u32 = 2;
pub const KIND_ROW: u32 = 3;
pub const KIND_SCAN_ALG: u32 = 10;
pub const KIND_SCAN_CALL: u32 = 7;
pub const KIND_SCAN_RET: u32 = 8;
pub const KIND_SCAN_ROW: u32 = 11;
pub const KIND_TRIP: u32 = 5;
pub const LOSS_GUARD_READ_ABORT: u32 = 22;
pub const LOSS_INIT_SCAN: u32 = 15;
pub const LOSS_MAP_CALLS: u32 = 7;
pub const LOSS_MAP_LGCALLS: u32 = 9;
pub const LOSS_MAP_QUERY_NEXT: u32 = 5;
pub const LOSS_MAP_TERMD: u32 = 10;
pub const LOSS_MAP_TRIP: u32 = 8;
pub const LOSS_MAP_TRUNC: u32 = 6;
pub const LOSS_MEMBER_COOKIE: u32 = 16;
pub const LOSS_PENDING_INIT_FULL: u32 = 11;
pub const LOSS_PENDING_INIT_MISS: u32 = 13;
pub const LOSS_PENDING_QUERY_FULL: u32 = 12;
pub const LOSS_PENDING_QUERY_MISS: u32 = 14;
pub const LOSS_RETIRE_FAIL: u32 = 21;
pub const LOSS_RING_ALG: u32 = 1;
pub const LOSS_RING_CALL: u32 = 27;
pub const LOSS_RING_GUARD: u32 = 29;
pub const LOSS_RING_INIT: u32 = 4;
pub const LOSS_RING_RET: u32 = 28;
pub const LOSS_RING_ROW: u32 = 2;
pub const LOSS_RING_TRIP: u32 = 3;
pub const LOSS_SCAN_CHURNED: u32 = 25;
pub const LOSS_SCAN_EVICTED: u32 = 20;
pub const LOSS_STALE_REPAIRED: u32 = 31;
pub const SKIP_ADMITTED: u8 = 0;
pub const SKIP_ADMIT_STORE_FAIL: u8 = 8;
pub const SKIP_ALL: u8 = 5;
pub const SKIP_BIRTH_PENDING: u8 = 1;
pub const SKIP_BIRTH_WRAP: u8 = 3;
pub const SKIP_BUCKET_EMPTY: u8 = 10;
pub const SKIP_CTRL_UNPROGRAMMED: u8 = 7;
pub const SKIP_ENTRY_COOKIE: u8 = 6;
pub const SKIP_RING_PRESSURE: u8 = 4;
pub const SKIP_SEQ_FULL: u8 = 2;
pub const SKIP_SEQ_SATURATED: u8 = 9;
pub const TRUNC_ALGS: u64 = 1;
pub const TRUNC_DISPATCH: u64 = 2;
pub const TRUNC_NO_STORE: u64 = 64;
pub const TRUNC_WALK_EMPTY: u64 = 8;
pub const TRUNC_WALK_NAME: u64 = 32;
pub const TRUNC_WALK_NOIMP: u64 = 16;
pub const TRUNC_WALK_READ: u64 = 4;
pub const WINDOW_CELLS: u32 = 2;
pub const WINDOW_DEADLINE: u32 = 1;
pub const WINDOW_START: u32 = 0;

pub const fn make_key(cookie: u32, generation: u32) -> u64 {
    ((cookie as u64) << 32) | generation as u64
}

pub const fn lat_bucket(delta_ns: u64) -> usize {
    let mut remaining = delta_ns;
    let mut bucket = 0;
    while remaining >= 2 && bucket < 15 {
        remaining /= 2;
        bucket += 1;
    }
    bucket
}

pub const fn make_termd(op: u32, len: u32) -> u64 {
    ((len as u64) << 32) | op as u64
}

pub const fn make_seq(birth: u16, ctr: u64) -> u64 {
    ((birth as u64) << 48) | (ctr & 0x0000_ffff_ffff_ffff)
}

pub const fn split_seq(seq: u64) -> (u16, u64) {
    ((seq >> 48) as u16, seq & 0x0000_ffff_ffff_ffff)
}

pub const fn make_bucket(tokens: u8, last_shifted: u64) -> u64 {
    ((last_shifted & 0x00ff_ffff_ffff_ffff) << 8) | tokens as u64
}

pub const fn split_bucket(v: u64) -> (u8, u64) {
    ((v & 0xff) as u8, v >> 8)
}

pub const fn make_rcount(count: u32, state: u32) -> u64 {
    ((state as u64) << 32) | count as u64
}

pub const fn split_rcount(v: u64) -> (u32, u32) {
    ((v & 0xffff_ffff) as u32, (v >> 32) as u32)
}

pub const fn make_call_flags(hint: bool, cause: u8) -> u32 {
    ((cause as u32) << 8) | hint as u32
}

pub const fn loss_for_skip_cause(cause: u8) -> u32 {
    match cause {
        1 => 17,
        2 => 18,
        3 => 19,
        4 => 23,
        5 => 26,
        6 => 24,
        7 => 30,
        8 => 32,
        9 => 33,
        10 => 34,
        _ => 0,
    }
}
