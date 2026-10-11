//! SPDX-License-Identifier: GPL-3.0-or-later
//! T02 discovery-protocol gates: classify-before-emission.
//!
//! The discovery wire ABI (v2) carries only finite numeric class IDs
//! plus internal structural join addresses. Raw target name/argument
//! bytes must never cross the ring, and raw runtime addresses must
//! never reach public artifacts. These tests pin the wire layout,
//! the strict decoder, kernel/userspace classifier agreement (both
//! sides call the same shared logic; only the table backend differs),
//! and the no-raw-address output rule.

use osslscope::discovery::harvest::{build_alg_entries, build_trip_entries};
use osslscope::discovery::legacy::{self, SectionInputs, TripHit};
use osslscope::discovery::schema::{self, Row, Stats};
use osslscope::kinds;
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};

/// Host table backend mirroring the BPF map lookups: hash -> value.
fn host_alg_table() -> HashMap<u64, wire::AlgClassValue> {
    build_alg_entries().unwrap().into_iter().collect()
}

fn host_trip_table() -> HashMap<u64, wire::TripClassValue> {
    build_trip_entries().unwrap().into_iter().collect()
}

fn classify_host(name: &[u8], saturated: bool) -> wire::AlgVerdict {
    let t = host_alg_table();
    // Zero-padded 128-byte window, like the BPF stack array (the
    // classifier scans the full window; overlong `len` returns
    // before any read).
    let mut buf = [0u8; wire::ALG_WINDOW];
    let n = name.len().min(wire::ALG_WINDOW);
    buf[..n].copy_from_slice(&name[..n]);
    wire::classify_alg_with(&buf, name.len(), saturated, |h| t.get(&h).copied())
}

fn classify_trip_host(arg: &[u8], saturated: bool, tax: wire::TripTaxonomy) -> wire::TripVerdict {
    let t = host_trip_table();
    wire::classify_trip_with(arg, saturated, tax, |h| t.get(&h).copied())
}

#[test]
fn wire_layout_leaves_no_room_for_raw_buffers() {
    use std::mem::{align_of, size_of};
    // Classified events are small numerics-only structs: the old
    // 128-byte name / 32-byte arg payloads cannot physically fit.
    assert_eq!(size_of::<wire::AlgEvent>(), 40);
    assert_eq!(align_of::<wire::AlgEvent>(), 8);
    assert_eq!(size_of::<wire::TripEvent>(), 16);
    assert_eq!(align_of::<wire::TripEvent>(), 4);
    assert_eq!(size_of::<wire::RowEvent>(), 48);
    assert_eq!(size_of::<wire::InitRetEvent>(), 32);
    assert!(size_of::<wire::AlgEvent>() < 128, "must not fit a raw name");
    assert!(size_of::<wire::TripEvent>() < 32, "must not fit a raw arg");
    // Field offsets are pinned: BPF and userspace share one definition.
    let e = wire::AlgEvent {
        kind: 0,
        op: 0,
        class: 0,
        status: 0,
        weak: 0,
        _pad: 0,
        arr: 0,
        idx: 0,
        generation: 0,
    };
    let base = &e as *const _ as usize;
    assert_eq!(&e.op as *const _ as usize - base, 4);
    assert_eq!(&e.class as *const _ as usize - base, 8);
    assert_eq!(&e.status as *const _ as usize - base, 10);
    assert_eq!(&e.weak as *const _ as usize - base, 11);
    assert_eq!(&e.arr as *const _ as usize - base, 16);
    assert_eq!(&e.idx as *const _ as usize - base, 24);
    assert_eq!(&e.generation as *const _ as usize - base, 32);
    let t = wire::TripEvent {
        kind: 0,
        cookie: 0,
        class: 0,
        status: 0,
        _pad: 0,
        _pad2: 0,
    };
    let base = &t as *const _ as usize;
    assert_eq!(&t.cookie as *const _ as usize - base, 4);
    assert_eq!(&t.class as *const _ as usize - base, 8);
    assert_eq!(&t.status as *const _ as usize - base, 10);
    // Map-value layouts (population writes explicit LE bytes against
    // these offsets; BPF reads the same structs typed).
    assert_eq!(size_of::<wire::AlgClassValue>(), 40);
    assert_eq!(size_of::<wire::TripClassValue>(), 22);
    let v = wire::AlgClassValue {
        class: 0x0201,
        weak: 1,
        len: 3,
        name: [0u8; wire::MAX_ALG_NAME],
    };
    let b = wire::alg_value_bytes(&v);
    assert_eq!(&b[0..2], &[0x01, 0x02]);
    assert_eq!(&b[2..4], &[1, 3]);
    let w = wire::TripClassValue {
        engine: 1,
        load: 2,
        len: 7,
        name: [0u8; wire::MAX_TRIP_NAME],
    };
    let b = wire::trip_value_bytes(&w);
    assert_eq!(&b[0..6], &[1, 0, 2, 0, 7, 0]);
    // Same-host little-endian is embodied by the target pair
    // (bpfel-unknown-none + x86-64); the decoder relies on it.
    assert_eq!(u16::from_ne_bytes(u16::to_ne_bytes(1)), 1);
    assert_eq!(u16::from_le_bytes([1, 0]), 1);
}

#[test]
fn parse_accepts_golden_vectors() {
    // AlgEvent: kind=4 op=1 class=7 status=OK weak=1 arr/idx join keys.
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&4u32.to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[8..10].copy_from_slice(&7u16.to_le_bytes());
    b[10] = wire::ALG_OK;
    b[11] = 1;
    b[16..24].copy_from_slice(&0x7f00_1000u64.to_le_bytes());
    b[24..32].copy_from_slice(&3u64.to_le_bytes());
    b[32..40].copy_from_slice(&9u64.to_le_bytes());
    let e = wire::parse_alg_event(&b, kinds::ALG_NAMES.len() as u16).unwrap();
    assert_eq!((e.op, e.class, e.status, e.weak), (1, 7, wire::ALG_OK, 1));
    assert_eq!((e.arr, e.idx), (0x7f00_1000, 3));
    assert_eq!(e.generation, 9);
    // OTHER class decodes (unknown-but-explicit), out-of-range does not.
    b[8..10].copy_from_slice(&wire::OTHER_CLASS.to_le_bytes());
    b[10] = wire::ALG_UNKNOWN;
    b[11] = 0;
    let e = wire::parse_alg_event(&b, kinds::ALG_NAMES.len() as u16).unwrap();
    assert_eq!(e.class, wire::OTHER_CLASS);
    // TripEvent: kind=5 cookie/class/status.
    let mut t = vec![0u8; 16];
    t[0..4].copy_from_slice(&5u32.to_le_bytes());
    t[4..8].copy_from_slice(&9u32.to_le_bytes());
    t[8..10].copy_from_slice(&wire::LOAD_LEGACY.to_le_bytes());
    t[10] = wire::TRIP_OK;
    let te = wire::parse_trip_event(&t).unwrap();
    assert_eq!((te.cookie, te.class, te.status), (9, wire::LOAD_LEGACY, 0));
    // RowEvent + InitRetEvent shapes.
    let mut r = vec![0u8; 48];
    r[0..4].copy_from_slice(&3u32.to_le_bytes());
    r[40..48].copy_from_slice(&5u64.to_le_bytes());
    let re = wire::parse_row_event(&r).unwrap();
    assert_eq!(re.generation, 5);
    r[0..4].copy_from_slice(&2u32.to_le_bytes());
    wire::parse_row_event(&r).unwrap();
    let mut i = vec![0u8; 32];
    i[0..4].copy_from_slice(&1u32.to_le_bytes());
    wire::parse_init_ret_event(&i).unwrap();
}

#[test]
fn parse_rejects_short_unknown_and_out_of_range() {
    let n = kinds::ALG_NAMES.len() as u16;
    // Wire items are fixed-size reservations: short OR oversized
    // payloads are corruption, never longer variants.
    assert_eq!(
        wire::parse_alg_event(&[4u8; 39], n),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_alg_event(&[4u8; 41], n),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_trip_event(&[5u8; 15]),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_trip_event(&[5u8; 17]),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_row_event(&[3u8; 47]),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_row_event(&[3u8; 49]),
        Err(wire::WireErr::Length)
    );
    assert_eq!(
        wire::parse_init_ret_event(&[1u8; 31]),
        Err(wire::WireErr::Length)
    );
    // Wrong kind (incl. retired WALKDBG=6 and zero).
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&6u32.to_le_bytes());
    assert_eq!(wire::parse_alg_event(&b, n), Err(wire::WireErr::Kind));
    b[0..4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(wire::parse_trip_event(&b[..16]), Err(wire::WireErr::Kind));
    // Class id past the registry (and not OTHER) is rejected, never
    // labeled: a corrupt id must not become a false class.
    b[0..4].copy_from_slice(&4u32.to_le_bytes());
    for bad in [n, n + 1, wire::OTHER_CLASS - 1] {
        b[8..10].copy_from_slice(&bad.to_le_bytes());
        assert_eq!(
            wire::parse_alg_event(&b, n),
            Err(wire::WireErr::ClassRange),
            "class {bad} must be rejected"
        );
    }
    // Status/weak bytes outside their vocabularies are rejected.
    // (Status 4 is the BPF-only unreadable verdict: parseable here,
    // never produced by the pure classifier.)
    b[8..10].copy_from_slice(&wire::OTHER_CLASS.to_le_bytes());
    b[10] = wire::ALG_UNREADABLE;
    b[11] = 0;
    wire::parse_alg_event(&b, n).unwrap();
    b[8..10].copy_from_slice(&0u16.to_le_bytes());
    b[10] = 9;
    assert_eq!(
        wire::parse_alg_event(&b, n),
        Err(wire::WireErr::StatusRange)
    );
    b[10] = wire::ALG_OK;
    b[11] = 2;
    assert_eq!(wire::parse_alg_event(&b, n), Err(wire::WireErr::WeakRange));
    let mut t = vec![0u8; 16];
    t[0..4].copy_from_slice(&5u32.to_le_bytes());
    t[10] = 7;
    assert_eq!(wire::parse_trip_event(&t), Err(wire::WireErr::StatusRange));
}

#[test]
fn parse_rejects_contradictory_combinations() {
    let n = kinds::ALG_NAMES.len() as u16;
    // Each status admits only the classes/weak values the kernel
    // actually emits with it; anything else is corruption, never a
    // labeled row.
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&4u32.to_le_bytes());
    let mut verdict = |class: u16, status: u8, weak: u8| {
        b[8..10].copy_from_slice(&class.to_le_bytes());
        b[10] = status;
        b[11] = weak;
        wire::parse_alg_event(&b, n)
    };
    // Valid combinations (all five statuses).
    verdict(7, wire::ALG_OK, 0).unwrap();
    verdict(7, wire::ALG_OK, 1).unwrap();
    verdict(wire::OTHER_CLASS, wire::ALG_UNKNOWN, 0).unwrap();
    verdict(wire::OTHER_CLASS, wire::ALG_UNKNOWN, 1).unwrap();
    verdict(wire::OTHER_CLASS, wire::ALG_OVERLONG, 0).unwrap();
    verdict(7, wire::ALG_TRUNCATED, 1).unwrap();
    verdict(wire::OTHER_CLASS, wire::ALG_TRUNCATED, 1).unwrap();
    verdict(wire::OTHER_CLASS, wire::ALG_UNREADABLE, 0).unwrap();
    // Contradictions.
    for (class, status, weak) in [
        (wire::OTHER_CLASS, wire::ALG_OK, 0), // ok requires a registry class
        (7, wire::ALG_UNKNOWN, 0),            // unknown requires OTHER
        (7, wire::ALG_OVERLONG, 0),           // overlong requires OTHER
        (wire::OTHER_CLASS, wire::ALG_OVERLONG, 1), // overlong keeps no weak
        (7, wire::ALG_UNREADABLE, 0),         // unreadable requires OTHER
        (wire::OTHER_CLASS, wire::ALG_UNREADABLE, 1),
        (7, wire::ALG_TRUNCATED, 0), // truncated always fails weak closed
        (wire::OTHER_CLASS, wire::ALG_TRUNCATED, 0),
    ] {
        assert_eq!(
            verdict(class, status, weak),
            Err(wire::WireErr::Contradiction),
            "class={class} status={status} weak={weak} must be rejected"
        );
    }
    // Trip: non-OK statuses pair only with OTHER.
    let mut t = vec![0u8; 16];
    t[0..4].copy_from_slice(&5u32.to_le_bytes());
    t[8..10].copy_from_slice(&wire::LOAD_LEGACY.to_le_bytes());
    t[10] = wire::TRIP_UNREADABLE;
    assert_eq!(
        wire::parse_trip_event(&t),
        Err(wire::WireErr::Contradiction)
    );
    t[10] = wire::TRIP_OVERLONG;
    assert_eq!(
        wire::parse_trip_event(&t),
        Err(wire::WireErr::Contradiction)
    );
    t[8..10].copy_from_slice(&wire::TRIP_OTHER.to_le_bytes());
    t[10] = wire::TRIP_UNREADABLE;
    wire::parse_trip_event(&t).unwrap();
    // Status labels decode totally over the strict vocabulary.
    assert_eq!(wire::alg_status_name(wire::ALG_OK), Some("ok"));
    assert_eq!(wire::alg_status_name(wire::ALG_UNKNOWN), Some("unknown"));
    assert_eq!(wire::alg_status_name(wire::ALG_OVERLONG), Some("overlong"));
    assert_eq!(
        wire::alg_status_name(wire::ALG_TRUNCATED),
        Some("truncated")
    );
    assert_eq!(
        wire::alg_status_name(wire::ALG_UNREADABLE),
        Some("unreadable")
    );
    assert_eq!(wire::alg_status_name(9), None);
}

#[test]
fn soaked_wire_bytes_yield_numerics_only() {
    // Sentinel-soaked ring bytes (0x41 fill): the decoder either
    // rejects them or yields table-derived labels — never an echo.
    let n = kinds::ALG_NAMES.len() as u16;
    let soaked40 = vec![0x41u8; 40];
    assert_eq!(
        wire::parse_alg_event(&soaked40, n),
        Err(wire::WireErr::Kind)
    );
    let mut b = vec![0x41u8; 40];
    b[0..4].copy_from_slice(&4u32.to_le_bytes());
    // class bytes 0x4141 = 16705: out of range (692 valid + OTHER).
    assert_eq!(wire::parse_alg_event(&b, n), Err(wire::WireErr::ClassRange));
    let soaked16 = vec![0x41u8; 16];
    assert_eq!(wire::parse_trip_event(&soaked16), Err(wire::WireErr::Kind));
    // Classifier soak: 64 sentinel bytes (no NUL, unsaturated window)
    // classify to OTHER with no retained prefix.
    let v = classify_host(&[0x41u8; 64], false);
    assert_eq!(
        (v.class, v.weak, v.status),
        (wire::OTHER_CLASS, false, wire::ALG_UNKNOWN)
    );
    assert_eq!(kinds::alg_class_label(v.class), Some("other"));
    let tv = classify_trip_host(&[0x41u8; 20], false, wire::TripTaxonomy::Load);
    assert_eq!((tv.class, tv.status), (wire::TRIP_OTHER, wire::TRIP_OK));
    assert_eq!(wire::load_class_name(tv.class), Some("other"));
}

#[test]
fn fnv1a64_matches_reference_vectors() {
    // IETF FNV test vectors (offset basis + "foobar").
    assert_eq!(wire::fnv1a64(b""), 14695981039346656037);
    assert_eq!(wire::fnv1a64(b"foobar"), 9625390261332436968);
    assert_eq!(wire::fnv1a64(b"a"), 12638187200555641996);
}

#[test]
fn registry_hashes_are_collision_free_and_bounded() {
    // The populated kernel tables key on FNV-1a-64: within-table
    // collisions would be unrepresentable (population fails closed).
    let mut hashes = HashSet::new();
    let mut longest = 0usize;
    for a in kinds::ALG_NAMES {
        assert!(hashes.insert(wire::fnv1a64(a.name.as_bytes())), "dup {a:?}");
        longest = longest.max(a.name.len());
    }
    for w in kinds::WEAK_ALGS {
        if !kinds::is_known_alg(w) {
            assert!(hashes.insert(wire::fnv1a64(w.as_bytes())), "dup weak {w}");
            longest = longest.max(w.len());
        }
    }
    // 692 registry + 4 weak-only extras (SHA0/3DES/Blowfish/CAST5;
    // RC4 registered since T09).
    assert_eq!(hashes.len(), 692 + 4);
    assert!(longest <= wire::MAX_ALG_NAME, "longest {longest}");
    assert!(kinds::ALG_NAMES.len() < wire::OTHER_CLASS as usize);
    let trips = [
        "dynamic",
        "padlock",
        "capi",
        "dasync",
        "afalg",
        "loader_attic",
        "ossltest",
        "legacy",
        "default",
        "fips",
    ];
    let th: HashSet<u64> = trips.iter().map(|s| wire::fnv1a64(s.as_bytes())).collect();
    assert_eq!(th.len(), trips.len());
    assert!(trips.iter().map(|s| s.len()).max().unwrap() <= wire::MAX_TRIP_NAME);
}

#[test]
fn classifier_agrees_with_reference_over_corpus() {
    // Every registry name plus alias/weak/edge shapes: the shared
    // kernel logic (host table backend) must equal the reference
    // userspace classifier on (class label, weak).
    let mut corpus: Vec<String> = kinds::ALG_NAMES
        .iter()
        .map(|a| a.name.to_string())
        .collect();
    corpus.extend(
        [
            "SHA2-256:SHA256",
            "SHA1:SHA-1",
            "MD5",
            "AES-256-GCM:MD5",
            "canary-DOOM-7QZ",
            "SPIKE-SHA",
            "",
            ":",
            "::",
            "a:",
            ":a",
            "a::b",
            "SHA2-256:",
            ":SHA2-256",
            "MD5:SHA2-256",
            "nope:MD5",
            "MD5:nope",
            "nope1:nope2:nope3",
            "SHA0",
            "3DES",
            "RC4",
            "Blowfish",
            "CAST5",
            "RC4:SHA2-256",
            "SHA2-256:RC4",
            "DESX",
            "MDC2:AES-128-CBC",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    // 8-segment boundary (kept) and 9-segment truncation.
    corpus.push(
        [
            "SHA2-256", "SHA384", "SHA512", "MD5", "SHA1", "DES", "RC2", "SEED",
        ]
        .join(":"),
    );
    for input in &corpus {
        let v = classify_host(input.as_bytes(), false);
        let (class, weak) = kinds::classify_alg(input);
        let label = kinds::alg_class_label(v.class).unwrap();
        assert_eq!(label, class, "class mismatch for {input:?}");
        assert_eq!(v.weak, weak, "weak mismatch for {input:?}");
        // Status is OK iff ANY segment is registered (F-A/A5: no
        // corpus entry exceeds the segment bound or saturates).
        let any_known = input.split(':').any(kinds::is_known_alg);
        let want = if any_known {
            wire::ALG_OK
        } else {
            wire::ALG_UNKNOWN
        };
        assert_eq!(v.status, want, "status for {input:?}");
    }
    // Lists no segment of which is registered (incl. empty/edge
    // splits) are explicit UNKNOWN. (RC4 registered since T09;
    // SHA0 keeps the weak-only exemplar: its table extra folds
    // weak but never wins the label.)
    for input in ["", ":", "nope", "SHA0"] {
        let v = classify_host(input.as_bytes(), false);
        assert_eq!(v.status, wire::ALG_UNKNOWN, "status for {input:?}");
        assert_eq!(kinds::alg_class_label(v.class), Some("other"));
    }
    let v = classify_host(b"SHA0", false);
    assert!(v.weak, "weak-only extra must still count weak");
    // Non-UTF8 bytes can never confirm against UTF-8 registry
    // names — but the MD5 segment still identifies the list.
    let v = classify_host(&[0xff, 0xfe, b':', b'M', b'D', b'5'], false);
    assert_eq!(v.status, wire::ALG_OK);
    assert_eq!(kinds::alg_class_label(v.class), Some("MD5"));
    assert!(v.weak, "MD5 segment must still count weak");
}

#[test]
fn classifier_label_is_order_free() {
    // F-A/A5: alias order never changes the verdict — the label
    // is the canonical minimum over recognized segments.
    for (a, b) in [
        ("SHA2-256", "SHA256"),
        ("RC4", "SHA2-256"),
        ("MDC2", "AES-128-CBC"),
        ("SHA1", "MD5"),
        ("nope", "MD5"),
        ("", "SHA2-256"),
    ] {
        let fwd = classify_host(format!("{a}:{b}").as_bytes(), false);
        let rev = classify_host(format!("{b}:{a}").as_bytes(), false);
        assert_eq!(
            (fwd.class, fwd.weak, fwd.status),
            (rev.class, rev.weak, rev.status),
            "order swap {a}:{b}"
        );
    }
    // The canonical label is the minimum registry index.
    let v = classify_host(b"SHA256:SHA2-256", false);
    assert_eq!(kinds::alg_class_label(v.class), Some("SHA2-256"));
    let v = classify_host(b"MDC2:AES-128-CBC", false);
    assert_eq!(kinds::alg_class_label(v.class), Some("AES-128-CBC"));
    let v = classify_host(b"RC4:SHA2-256", false);
    assert_eq!(kinds::alg_class_label(v.class), Some("SHA2-256"));
}

#[test]
fn classifier_recognizes_non_primary_alias() {
    // F-A/A5: a recognized non-primary alias identifies the
    // algorithm — no longer UNKNOWN.
    for (input, want) in [
        ("nope:MD5", "MD5"),
        (":SHA2-256", "SHA2-256"),
        ("SHA0:SHA1", "SHA1"),
    ] {
        let v = classify_host(input.as_bytes(), false);
        assert_eq!(v.status, wire::ALG_OK, "status for {input:?}");
        assert_eq!(
            kinds::alg_class_label(v.class),
            Some(want),
            "label for {input:?}"
        );
    }
}

#[test]
fn classifier_statuses_are_explicit() {
    // Saturated window: OVERLONG with no retained prefix, even when
    // the visible bytes start with a recognized primary.
    let mut over = b"SHA2-256:".to_vec();
    over.resize(127, b'X');
    let v = classify_host(&over, true);
    assert_eq!(v.status, wire::ALG_OVERLONG);
    assert_eq!(v.class, wire::OTHER_CLASS);
    assert!(!v.weak, "overlong input keeps no weak evidence");
    // Unsaturated short input with a recognized primary is OK.
    let v = classify_host(b"SHA2-256", false);
    assert_eq!(v.status, wire::ALG_OK);
    assert_eq!(kinds::alg_class_label(v.class), Some("SHA2-256"));
    // Nine segments: TRUNCATED keeps the observed primary but fails
    // weak closed (unseen segments may be weak).
    let nine = ["SHA2-256", "a", "b", "c", "d", "e", "f", "g", "h"].join(":");
    let v = classify_host(nine.as_bytes(), false);
    assert_eq!(v.status, wire::ALG_TRUNCATED);
    assert_eq!(kinds::alg_class_label(v.class), Some("SHA2-256"));
    assert!(v.weak, "truncated alias fails weak closed");
    // Exactly eight segments are fully observed (no truncation).
    let eight = ["SHA2-256", "a", "b", "c", "d", "e", "f", "g"].join(":");
    let v = classify_host(eight.as_bytes(), false);
    assert_eq!(v.status, wire::ALG_OK);
    assert!(!v.weak);
}

#[test]
fn trip_taxonomy_pins_classes() {
    use wire::TripTaxonomy::{Engine, Load};
    // Engine ids: dynamic/builtin/other.
    for (id, want) in [
        ("dynamic", wire::ENGINE_DYNAMIC),
        ("padlock", wire::ENGINE_BUILTIN),
        ("capi", wire::ENGINE_BUILTIN),
        ("ossltest", wire::ENGINE_BUILTIN),
        ("wat", wire::TRIP_OTHER),
        ("", wire::TRIP_OTHER),
        ("CNRY7QN-ENGINE-ID-20", wire::TRIP_OTHER),
        ("DYNAMIC", wire::TRIP_OTHER),
    ] {
        let v = classify_trip_host(id.as_bytes(), false, Engine);
        assert_eq!((v.class, v.status), (want, wire::TRIP_OK), "engine {id:?}");
    }
    assert_eq!(
        wire::engine_class_name(wire::ENGINE_DYNAMIC),
        Some("dynamic")
    );
    assert_eq!(
        wire::engine_class_name(wire::ENGINE_BUILTIN),
        Some("builtin")
    );
    assert_eq!(wire::engine_class_name(wire::TRIP_OTHER), Some("other"));
    assert_eq!(wire::engine_class_name(99), None);
    // Load names: legacy/default/fips/other.
    for (name, want) in [
        ("legacy", wire::LOAD_LEGACY),
        ("default", wire::LOAD_DEFAULT),
        ("fips", wire::LOAD_FIPS),
        ("spike", wire::TRIP_OTHER),
        ("", wire::TRIP_OTHER),
        ("CNRY7QN-LOAD-NAME-19", wire::TRIP_OTHER),
        ("LEGACY", wire::TRIP_OTHER),
    ] {
        let v = classify_trip_host(name.as_bytes(), false, Load);
        assert_eq!((v.class, v.status), (want, wire::TRIP_OK), "load {name:?}");
    }
    assert_eq!(wire::load_class_name(wire::LOAD_LEGACY), Some("legacy"));
    assert_eq!(wire::load_class_name(wire::LOAD_DEFAULT), Some("default"));
    assert_eq!(wire::load_class_name(wire::LOAD_FIPS), Some("fips"));
    assert_eq!(wire::load_class_name(wire::TRIP_OTHER), Some("other"));
    assert_eq!(wire::load_class_name(99), None);
    // Saturated window: OVERLONG with no retained class.
    let mut over = b"legacy".to_vec();
    over.resize(31, b'X');
    let v = classify_trip_host(&over, true, Load);
    assert_eq!((v.class, v.status), (wire::TRIP_OTHER, wire::TRIP_OVERLONG));
    // Non-UTF8: readable but unconfirmable -> other.
    let v = classify_trip_host(&[0xff, 0xfe], false, Engine);
    assert_eq!((v.class, v.status), (wire::TRIP_OTHER, wire::TRIP_OK));
}

#[test]
fn population_builders_cover_registry() {
    let alg = build_alg_entries().unwrap();
    assert_eq!(alg.len(), 692 + 4);
    let by_hash: HashMap<u64, &wire::AlgClassValue> = alg.iter().map(|(h, v)| (*h, v)).collect();
    assert_eq!(by_hash.len(), 692 + 4, "population hashes must be unique");
    // Spot checks: recognized class index, weak flag, weak-only names.
    let sha = &by_hash[&wire::fnv1a64(b"SHA2-256")];
    assert_eq!(kinds::alg_class_label(sha.class), Some("SHA2-256"));
    assert_eq!(sha.weak, 0);
    let md5 = &by_hash[&wire::fnv1a64(b"MD5")];
    assert_eq!(md5.weak, 1);
    // RC4 registered since T09: own class id, still weak-flagged.
    let rc4 = &by_hash[&wire::fnv1a64(b"RC4")];
    assert_eq!(kinds::alg_class_label(rc4.class), Some("RC4"));
    assert_eq!(rc4.weak, 1);
    for w in ["SHA0", "3DES", "Blowfish", "CAST5"] {
        let v = &by_hash[&wire::fnv1a64(w.as_bytes())];
        assert_eq!((v.class, v.weak), (wire::OTHER_CLASS, 1), "weak-only {w}");
    }
    assert!(!by_hash.contains_key(&wire::fnv1a64(b"canary-DOOM-7QZ")));
    let trip = build_trip_entries().unwrap();
    assert_eq!(trip.len(), 10);
    let th: HashMap<u64, &wire::TripClassValue> = trip.iter().map(|(h, v)| (*h, v)).collect();
    assert_eq!(th.len(), 10);
    assert_eq!(th[&wire::fnv1a64(b"dynamic")].engine, wire::ENGINE_DYNAMIC);
    assert_eq!(th[&wire::fnv1a64(b"legacy")].load, wire::LOAD_LEGACY);
    assert_eq!(th[&wire::fnv1a64(b"padlock")].engine, wire::ENGINE_BUILTIN);
}

/// Recursively assert no serialized key named exactly `addr`.
fn assert_no_addr_key(v: &serde_json::Value, path: &str) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, vv) in m {
                assert_ne!(k, "addr", "raw address key at {path}.{k}");
                assert_no_addr_key(vv, &format!("{path}.{k}"));
            }
        }
        serde_json::Value::Array(a) => {
            for (i, vv) in a.iter().enumerate() {
                assert_no_addr_key(vv, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn inspect_rows_carry_no_raw_addresses() {
    // Backed rows emit class/backing/hash — never the runtime address.
    // Stat-or-None resolution stats the provider arg: stage the test
    // exe's own identity.
    use std::os::unix::fs::MetadataExt;
    let exe_path = std::env::current_exe().unwrap();
    let exe = std::fs::read(&exe_path).unwrap();
    let want_ino = std::fs::metadata(&exe_path).unwrap().ino();
    let base = exe_path.file_name().unwrap().to_string_lossy().into_owned();
    let mut dev = String::from("08:01");
    for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6
            && f[5].rsplit('/').next() == Some(base.as_str())
            && f[4].parse::<u64>().ok() == Some(want_ino)
        {
            dev = f[3].to_string();
            break;
        }
    }
    let elf = osslscope::discovery::elf::parse_elf(&exe).unwrap();
    let ph = elf
        .program_headers
        .iter()
        .find(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD
                && ph.p_flags & goblin::elf::program_header::PF_X != 0
        })
        .unwrap();
    let maps = vec![osslscope::discovery::maps::Mapping {
        start: 0x1000,
        end: 0x1000 + ph.p_filesz,
        x: true,
        offset: ph.p_offset,
        dev,
        ino: want_ino,
        path: exe_path.to_string_lossy().into_owned(),
    }];
    let rows = vec![
        Row {
            op: 1,
            alg_class: "SHA2-256".into(),
            weak: false,
            status: "ok".into(),
            funcid: 7,
            impl_addr: 0x1000,
            arr: 0,
        },
        Row {
            op: 1,
            alg_class: "other".into(),
            weak: false,
            status: "unknown".into(),
            funcid: 1,
            impl_addr: 0x1010,
            arr: 0,
        },
        Row {
            op: 1,
            alg_class: "MD5".into(),
            weak: true,
            status: "ok".into(),
            funcid: 2,
            impl_addr: 0x1020,
            arr: 0,
        },
    ];
    let doc = schema::emit(
        "t",
        &exe_path,
        "",
        &exe,
        &maps,
        &rows,
        true,
        &Stats::trivial(),
    )
    .unwrap();
    assert_no_addr_key(&doc, "$");
    let jrows = doc["rows"].as_array().unwrap();
    assert_eq!(jrows.len(), 3);
    let classes: Vec<&str> = jrows
        .iter()
        .map(|r| r["alg_class"].as_str().unwrap())
        .collect();
    assert_eq!(classes, vec!["MD5", "SHA2-256", "other"]);
    for r in jrows {
        assert!(r.get("backing").is_some());
        assert!(r.get("addr_hash").is_some());
        assert_eq!(r["addr_backed"], true);
    }
    let statuses: Vec<&str> = jrows
        .iter()
        .map(|r| r["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, vec!["ok", "ok", "unknown"]);
    // The raw impl address is unrecoverable from the document.
    let text = serde_json::to_string(&doc).unwrap();
    assert!(!text.contains("4096"), "raw addr leaked: {text}");
}

#[test]
fn legacy_section_counts_classes_without_raw_strings() {
    use std::collections::HashSet;
    // Sentinel-derived trip hits: readable-unknown -> other classes,
    // unreadable/overlong -> explicit unreadable counts. Zero sentinel
    // bytes may survive in the emitted JSON.
    let set = legacy::ProbeSet {
        probes: vec![
            legacy::Probe {
                cookie: 9,
                symbol: "OSSL_PROVIDER_load".into(),
                offset: 1,
                module: "lc".into(),
                family: None,
                str_arg: Some(1),
                program: "trip_str1",
            },
            legacy::Probe {
                cookie: 10,
                symbol: "ENGINE_by_id".into(),
                offset: 2,
                module: "/app".into(),
                family: None,
                str_arg: Some(0),
                program: "trip_str0",
            },
        ],
        load_cookies: HashSet::from([9]),
        by_id_cookies: HashSet::from([10]),
        ..Default::default()
    };
    // NOTE: the verdicts below are what the kernel classifier emits
    // for CNRY7QN-LOAD-NAME-19 / CNRY7QN-ENGINE-ID-20 (readable,
    // unregistered -> TRIP_OK/TRIP_OTHER) plus one NULL load arg
    // (TRIP_UNREADABLE); the raw sentinels never cross the ring.
    let hits = vec![
        TripHit {
            cookie: 9,
            class: wire::TRIP_OTHER,
            status: wire::TRIP_OK,
        },
        TripHit {
            cookie: 9,
            class: wire::TRIP_OTHER,
            status: wire::TRIP_UNREADABLE,
        },
        TripHit {
            cookie: 10,
            class: wire::TRIP_OTHER,
            status: wire::TRIP_OK,
        },
    ];
    let trip = HashMap::from([(9u64, 2u64), (10u64, 1u64)]);
    let doc = legacy::section(&SectionInputs {
        set: &set,
        trip: &trip,
        trip_hits: &hits,
        legacy_queries: 0,
        legacy_classes: vec!["other".into()],
        extra_findings: &[],
    });
    assert_eq!(doc["legacy_provider"]["loads"]["other"], 1);
    assert_eq!(doc["engine"]["engine_id_class"]["other"], 1);
    assert_eq!(doc["unreadable"]["load_names"], 1);
    assert_eq!(doc["unreadable"]["engine_ids"], 0);
    let text = serde_json::to_string(&doc).unwrap();
    assert!(!text.contains("CNRY7QN"), "sentinel leaked: {text}");
    assert_no_addr_key(&doc, "$");
}

#[test]
fn bpf_uses_shared_wire_types_exclusively() {
    // The BPF program must not define its own wire structs (drift
    // vector for smuggled string fields): all event shapes come from
    // the shared crate, and both classifier maps exist.
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/src/bin/harvest.rs"),
    )
    .unwrap();
    assert!(
        !src.contains("struct Event"),
        "BPF must not define its own Event"
    );
    assert!(
        !src.contains("struct TripEvent"),
        "BPF must not define its own TripEvent"
    );
    assert!(
        !src.contains("struct RowEvent"),
        "BPF must not define its own RowEvent"
    );
    assert!(
        src.contains("osslscope_ebpf_common"),
        "BPF must use shared wire types"
    );
    for map in ["ALG_CLASS", "TRIP_CLASS"] {
        assert!(src.contains(map), "BPF must define {map}");
    }
    assert!(
        !src.contains("KIND_WALKDBG"),
        "retired debug kind must be gone"
    );
}
