// SPDX-License-Identifier: GPL-2.0-or-later
use osslscope_bpf_contract::*;

mod scalars {
    use super::*;

    #[test]
    fn constant_types_and_protocol_values() {
        macro_rules! values {
            ($ty:ty; $($name:ident = $value:expr),+ $(,)?) => {$({
                let actual: $ty = $name;
                assert_eq!(actual, $value, stringify!($name));
            })+};
        }
        values!(usize; ALG_WINDOW = 128, TRIP_WINDOW = 32);
        values!(u8; ALG_EMPTY = 6, ALG_NOIMP = 7, ALG_UNREADABLE = 4, TRIP_UNREADABLE = 1);
        values!(u16; BIRTH_FROZEN = 65535, OTHER_CLASS = 65535, TRIP_OTHER = 0);
        values!(u64; BUCKET_BURST = 4, BUCKET_PERIOD_SHIFTED = 97656,
            MEMBER_ENTRY_COOKIE = 512, RINGBUF_AVAIL_DATA = 0, SEQ_CTR_MAX = 281474976710655);
        values!(u32; GUARD_EMPTY = 0, GUARD_ERROR = 2, GUARD_VALID = 1,
            RCOUNT_STATE_ACTIVE = 1, RCOUNT_STATE_IDLE = 0, RET_FLAG_EMPTY = 1);
        values!(u32; KIND_ALG = 4, KIND_GUARD = 9, KIND_INIT_RET = 1, KIND_QUERY_RET = 2,
            KIND_ROW = 3, KIND_SCAN_ALG = 10, KIND_SCAN_CALL = 7, KIND_SCAN_RET = 8,
            KIND_SCAN_ROW = 11, KIND_TRIP = 5);
        values!(u32; LOSS_GUARD_READ_ABORT = 22, LOSS_INIT_SCAN = 15, LOSS_MAP_CALLS = 7,
            LOSS_MAP_LGCALLS = 9, LOSS_MAP_QUERY_NEXT = 5, LOSS_MAP_TERMD = 10,
            LOSS_MAP_TRIP = 8, LOSS_MAP_TRUNC = 6);
        values!(u32; LOSS_MEMBER_COOKIE = 16, LOSS_PENDING_INIT_FULL = 11,
            LOSS_PENDING_INIT_MISS = 13, LOSS_PENDING_QUERY_FULL = 12,
            LOSS_PENDING_QUERY_MISS = 14, LOSS_RETIRE_FAIL = 21);
        values!(u32; LOSS_RING_ALG = 1, LOSS_RING_CALL = 27, LOSS_RING_GUARD = 29,
            LOSS_RING_INIT = 4, LOSS_RING_RET = 28, LOSS_RING_ROW = 2, LOSS_RING_TRIP = 3,
            LOSS_SCAN_CHURNED = 25, LOSS_SCAN_EVICTED = 20, LOSS_STALE_REPAIRED = 31);
        values!(u8; SKIP_ADMITTED = 0, SKIP_ADMIT_STORE_FAIL = 8, SKIP_ALL = 5,
            SKIP_BIRTH_PENDING = 1, SKIP_BIRTH_WRAP = 3, SKIP_BUCKET_EMPTY = 10,
            SKIP_CTRL_UNPROGRAMMED = 7, SKIP_ENTRY_COOKIE = 6, SKIP_RING_PRESSURE = 4,
            SKIP_SEQ_FULL = 2, SKIP_SEQ_SATURATED = 9);
        values!(u64; TRUNC_ALGS = 1, TRUNC_DISPATCH = 2, TRUNC_NO_STORE = 64,
            TRUNC_WALK_EMPTY = 8, TRUNC_WALK_NAME = 32, TRUNC_WALK_NOIMP = 16, TRUNC_WALK_READ = 4);
        values!(u32; WINDOW_CELLS = 2, WINDOW_DEADLINE = 1, WINDOW_START = 0);
    }

    #[test]
    fn public_signatures_and_const_evaluation() {
        let _: fn(u32, u32) -> u64 = make_key;
        let _: fn(u64) -> usize = lat_bucket;
        let _: fn(u32, u32) -> u64 = make_termd;
        let _: fn(u16, u64) -> u64 = make_seq;
        let _: fn(u64) -> (u16, u64) = split_seq;
        let _: fn(u8, u64) -> u64 = make_bucket;
        let _: fn(u64) -> (u8, u64) = split_bucket;
        let _: fn(u32, u32) -> u64 = make_rcount;
        let _: fn(u64) -> (u32, u32) = split_rcount;
        let _: fn(bool, u8) -> u32 = make_call_flags;
        let _: fn(u8) -> u32 = loss_for_skip_cause;
        const {
            assert!(make_key(3, 5) == 0x0000_0003_0000_0005);
            assert!(lat_bucket(65) == 6);
            assert!(make_termd(3, 5) == 0x0000_0005_0000_0003);
            assert!(make_seq(3, 5) == 0x0003_0000_0000_0005);
            assert!(split_seq(0x0003_0000_0000_0005).0 == 3);
            assert!(split_seq(0x0003_0000_0000_0005).1 == 5);
            assert!(make_bucket(3, 5) == 0x503);
            assert!(split_bucket(0x503).0 == 3);
            assert!(split_bucket(0x503).1 == 5);
            assert!(make_rcount(3, 5) == 0x0000_0005_0000_0003);
            assert!(split_rcount(0x0000_0005_0000_0003).0 == 3);
            assert!(split_rcount(0x0000_0005_0000_0003).1 == 5);
            assert!(make_call_flags(true, 3) == 0x301);
            assert!(loss_for_skip_cause(8) == 32);
        }
    }

    #[test]
    fn full_width_halves_keep_their_order() {
        for (left, right, key, termd) in [
            (0, 0, 0, 0),
            (u32::MAX, 1, 0xffff_ffff_0000_0001, 0x0000_0001_ffff_ffff),
            (0, u32::MAX, 0x0000_0000_ffff_ffff, 0xffff_ffff_0000_0000),
            (
                0x1234_5678,
                0x9abc_def0,
                0x1234_5678_9abc_def0,
                0x9abc_def0_1234_5678,
            ),
            (u32::MAX, u32::MAX, u64::MAX, u64::MAX),
        ] {
            assert_eq!(make_key(left, right), key);
            assert_eq!(make_termd(left, right), termd);
            assert_eq!(make_rcount(left, right), termd);
            assert_eq!(split_rcount(termd), (left, right));
        }
        assert_eq!(split_rcount(make_rcount(7, u32::MAX)), (7, u32::MAX));
    }

    #[test]
    fn sequence_discards_only_counter_bits_above_47() {
        for (birth, counter, packed, decoded) in [
            (0, 0, 0, 0),
            (1, 0, 0x0001_0000_0000_0000, 0),
            (0xffff, 0, 0xffff_0000_0000_0000, 0),
            (0xfffe, u64::MAX, 0xfffe_ffff_ffff_ffff, 281474976710655),
            (
                0x1357,
                0xabcd_2468_1357_9876,
                0x1357_2468_1357_9876,
                0x2468_1357_9876,
            ),
        ] {
            assert_eq!(make_seq(birth, counter), packed);
            assert_eq!(split_seq(packed), (birth, decoded));
        }
        for bit in 48..64 {
            assert_eq!(make_seq(0x8421, (1_u64 << bit) + 9), 0x8421_0000_0000_0009);
        }
        assert_eq!(
            split_seq(make_seq(0xfffe, u64::MAX)),
            (0xfffe, 281474976710655)
        );
    }

    #[test]
    fn bucket_discards_only_timestamp_bits_above_55() {
        for (tokens, timestamp, packed, decoded) in [
            (0, 0, 0, 0),
            (255, 0, 255, 0),
            (0, 1, 256, 1),
            (255, u64::MAX, u64::MAX, 72057594037927935),
            (
                0x5a,
                0xff12_3456_789a_bcde,
                0x1234_5678_9abc_de5a,
                0x0012_3456_789a_bcde,
            ),
        ] {
            assert_eq!(make_bucket(tokens, timestamp), packed);
            assert_eq!(split_bucket(packed), (tokens, decoded));
        }
        for bit in 56..64 {
            assert_eq!(make_bucket(0xc3, (1_u64 << bit) + 17), 0x11c3);
        }
        assert_eq!(
            split_bucket(make_bucket(255, u64::MAX)),
            (255, 72057594037927935)
        );
    }

    #[test]
    fn latency_power_boundaries_and_saturation() {
        let boundaries = [
            (2, 1),
            (4, 2),
            (8, 3),
            (16, 4),
            (32, 5),
            (64, 6),
            (128, 7),
            (256, 8),
            (512, 9),
            (1024, 10),
            (2048, 11),
            (4096, 12),
            (8192, 13),
            (16384, 14),
            (32768, 15),
        ];
        for (edge, bucket) in boundaries {
            assert_eq!(lat_bucket(edge - 1), bucket - 1);
            assert_eq!(lat_bucket(edge), bucket);
            assert_eq!(lat_bucket(edge + 1), bucket);
        }
        for bit in 16..64 {
            assert_eq!(lat_bucket((1_u64 << bit) - 1), 15);
            assert_eq!(lat_bucket(1_u64 << bit), 15);
            assert_eq!(lat_bucket((1_u64 << bit) + 1), 15);
        }
        assert_eq!(
            [
                lat_bucket(0),
                lat_bucket(1),
                lat_bucket(2),
                lat_bucket(32767),
                lat_bucket(32768),
                lat_bucket(u64::MAX)
            ],
            [0, 0, 1, 14, 15, 15]
        );
    }

    #[test]
    fn flags_and_loss_cover_every_cause_and_both_hints() {
        let losses = [0, 17, 18, 19, 23, 26, 24, 30, 32, 33, 34];
        for cause in 0..=u8::MAX {
            for hint in [false, true] {
                let expected = u32::from(cause) * 256 + u32::from(hint);
                assert_eq!(make_call_flags(hint, cause), expected);
            }
            let expected = losses.get(usize::from(cause)).copied().unwrap_or(0);
            assert_eq!(loss_for_skip_cause(cause), expected);
        }
        assert_eq!(make_call_flags(true, 255), 0x0000_ff01);
    }
}

mod layouts {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn every_field_type_offset_size_and_alignment() {
        fn copy_clone<T: Copy + Clone>() {}
        macro_rules! record {
            ($name:ident, $size:expr, $align:expr; $($field:ident: $ty:ty = $offset:expr),+ $(,)?) => {{
                copy_clone::<$name>();
                assert_eq!(size_of::<$name>(), $size, stringify!($name));
                assert_eq!(align_of::<$name>(), $align, stringify!($name));
                $(assert_eq!(offset_of!($name, $field), $offset, concat!(stringify!($name), ".", stringify!($field)));
                let _: fn(&$name) -> &$ty = |record| &record.$field;)+
                assert_eq!(0 $(+ size_of::<$ty>())+, $size);
            }};
        }
        record!(CountValue, 24, 8; count: u64 = 0, first_ns: u64 = 8, last_ns: u64 = 16);
        record!(PendQuery, 16, 8; op: u64 = 0, ns_ptr: u64 = 8);
        record!(ScanRec, 40, 8; op: u64 = 0, ns_ptr: u64 = 8, seq: u64 = 16,
            expected: u32 = 24, _pad: u32 = 28, epoch: u64 = 32);
        record!(TCacheValue, 16, 8; t: u64 = 0, generation: u64 = 8);
        record!(CtrlValue, 24, 8; expected: u32 = 0, skip_all: u8 = 4, _pad: [u8; 3] = 5,
            epoch: u64 = 8, governor: u64 = 16);
        record!(AlgEvent, 40, 8; kind: u32 = 0, op: u32 = 4, class: u16 = 8,
            status: u8 = 10, weak: u8 = 11, _pad: u32 = 12, arr: u64 = 16,
            idx: u64 = 24, generation: u64 = 32);
        record!(TripEvent, 16, 4; kind: u32 = 0, cookie: u32 = 4, class: u16 = 8,
            status: u8 = 10, _pad: u8 = 11, _pad2: u32 = 12);
        record!(RowEvent, 48, 8; kind: u32 = 0, op: u32 = 4, funcid: u32 = 8,
            _pad: u32 = 12, addr: u64 = 16, aux: u64 = 24, idx: u64 = 32, generation: u64 = 40);
        record!(InitRetEvent, 32, 8; kind: u32 = 0, op: u32 = 4, funcid: u32 = 8,
            _pad: u32 = 12, addr: u64 = 16, aux: u64 = 24);
        record!(ScanCallEvent, 24, 8; kind: u32 = 0, op: u32 = 4, tid: u32 = 8,
            flags: u32 = 12, seq: u64 = 16);
        record!(ScanRetEvent, 40, 8; kind: u32 = 0, op: u32 = 4, flags: u32 = 8,
            tid: u32 = 12, seq: u64 = 16, arr: u64 = 24, generation: u64 = 32);
        record!(GuardEvent, 40, 8; kind: u32 = 0, op: u32 = 4, verdict: u32 = 8,
            tid: u32 = 12, seq: u64 = 16, arr: u64 = 24, generation: u64 = 32);
        record!(ScanAlgEvent, 56, 8; kind: u32 = 0, op: u32 = 4, class: u16 = 8,
            status: u8 = 10, weak: u8 = 11, _pad: u32 = 12, arr: u64 = 16,
            idx: u64 = 24, generation: u64 = 32, tid: u32 = 40, _pad2: u32 = 44, seq: u64 = 48);
        record!(ScanRowEvent, 64, 8; kind: u32 = 0, op: u32 = 4, funcid: u32 = 8,
            _pad: u32 = 12, addr: u64 = 16, aux: u64 = 24, idx: u64 = 32,
            generation: u64 = 40, tid: u32 = 48, _pad2: u32 = 52, seq: u64 = 56);
        record!(AlgClassValue, 42, 2; class: u16 = 0, weak: u8 = 2, len: u8 = 3,
            canon: u16 = 4, name: [u8; 36] = 6);
        record!(TripClassValue, 22, 2; engine: u16 = 0, load: u16 = 2, len: u16 = 4, name: [u8; 16] = 6);
    }

    #[test]
    fn explicit_padding_stays_zero_in_wire_fixtures() {
        let scan = ScanRec {
            op: 1,
            ns_ptr: 2,
            seq: 3,
            expected: 4,
            _pad: 0,
            epoch: 5,
        };
        let ctrl = CtrlValue {
            expected: 1,
            skip_all: 1,
            _pad: [0; 3],
            epoch: 2,
            governor: 3,
        };
        let alg = AlgEvent {
            kind: 4,
            op: 1,
            class: 2,
            status: 3,
            weak: 1,
            _pad: 0,
            arr: 5,
            idx: 6,
            generation: 7,
        };
        let trip = TripEvent {
            kind: 5,
            cookie: 1,
            class: 2,
            status: 3,
            _pad: 0,
            _pad2: 0,
        };
        let row = RowEvent {
            kind: 3,
            op: 1,
            funcid: 2,
            _pad: 0,
            addr: 3,
            aux: 4,
            idx: 5,
            generation: 6,
        };
        let init = InitRetEvent {
            kind: 1,
            op: 2,
            funcid: 3,
            _pad: 0,
            addr: 4,
            aux: 5,
        };
        let scan_alg = ScanAlgEvent {
            kind: 10,
            op: 1,
            class: 2,
            status: 3,
            weak: 1,
            _pad: 0,
            arr: 4,
            idx: 5,
            generation: 6,
            tid: 7,
            _pad2: 0,
            seq: 8,
        };
        let scan_row = ScanRowEvent {
            kind: 11,
            op: 1,
            funcid: 2,
            _pad: 0,
            addr: 3,
            aux: 4,
            idx: 5,
            generation: 6,
            tid: 7,
            _pad2: 0,
            seq: 8,
        };
        assert_eq!(
            [
                scan._pad,
                alg._pad,
                trip._pad2,
                row._pad,
                init._pad,
                scan_alg._pad,
                scan_alg._pad2,
                scan_row._pad,
                scan_row._pad2
            ],
            [0; 9]
        );
        assert_eq!(ctrl._pad, [0; 3]);
        assert_eq!(trip._pad, 0);
    }
}
