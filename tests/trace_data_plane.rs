// SPDX-License-Identifier: GPL-3.0-or-later
//! 6D trace data plane integration pins (T8.2a): decoder delta, mode map,
//! demux/public surface. Live pairing smoke lives in
//! `tests/trace_live_smoke.rs`.
use osslscope::provider_observation::{self as po, trace, wire};

fn edge(kind: u32, api: u32, outcome: u32) -> Vec<u8> {
    let mut b = vec![0; 96];
    for (at, v) in [
        (0, wire::contract::VERSION),
        (4, kind),
        (8, 96),
        (12, api),
        (16, 42),
        (20, 43),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    for at in [24, 32, 40, 48] {
        b[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
    }
    b[56..60].copy_from_slice(&outcome.to_le_bytes());
    b
}

#[test]
fn decoder_accepts_operational_attempt() {
    for api in [20, 21, 39, 40, 45, 47, 56, 64, 65, 68, 69, 70, 71, 72] {
        let event = wire::decode(&edge(1, api, 0))
            .unwrap_or_else(|g| panic!("operational ATTEMPT api={api}: {g:?}"));
        assert!(
            matches!(event.payload(), po::ObservationPayload::ApiAttempt { .. }),
            "api {api}"
        );
    }
}

#[test]
fn decoder_accepts_operational_result_classes() {
    for (raw, folded) in [
        (0u32, po::ApiOutcome::Unknown),
        (1, po::ApiOutcome::Success),
        (2, po::ApiOutcome::Failure),
        (3, po::ApiOutcome::Failure),
        (4, po::ApiOutcome::Failure),
    ] {
        let event = wire::decode(&edge(2, 45, raw))
            .unwrap_or_else(|g| panic!("operational RESULT outcome={raw}: {g:?}"));
        assert!(
            matches!(event.payload(), po::ObservationPayload::ApiResult { outcome: got, .. } if *got == folded),
            "raw {raw}"
        );
    }
}

#[test]
fn decoder_gates_unchanged_for_operational() {
    assert!(wire::decode(&edge(1, 20, 1)).is_err());
    let mut nonzero_op = edge(1, 20, 0);
    nonzero_op[60..64].copy_from_slice(&1u32.to_le_bytes());
    assert!(wire::decode(&nonzero_op).is_err());
    let mut nonzero_status = edge(1, 20, 0);
    nonzero_status[76..80].copy_from_slice(&9u32.to_le_bytes());
    assert!(wire::decode(&nonzero_status).is_err());
    assert!(wire::decode(&edge(1, 0, 0)).is_err());
    assert!(wire::decode(&edge(1, 73, 0)).is_err());
    assert!(wire::decode(&edge(1, 7, 0)).is_err());
    assert!(wire::decode(&edge(2, 20, 5)).is_err());
}

#[test]
fn decoder_still_accepts_fetch_lifecycle_edges() {
    for api in [1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15] {
        assert!(wire::decode(&edge(1, api, 0)).is_ok(), "attempt api {api}");
        assert!(wire::decode(&edge(2, api, 1)).is_ok(), "result api {api}");
    }
}

#[test]
fn trace_mode_words_are_frozen() {
    assert_eq!(
        (
            trace::TRACE_MODE_OFF,
            trace::TRACE_MODE_METADATA,
            trace::TRACE_MODE_LATENCY,
            trace::TRACE_MODE_STATUS,
            trace::TRACE_MODE_ALL
        ),
        (0, 1, 2, 3, 4)
    );
}

#[test]
fn fresh_object_carries_trace_mode_map() {
    let path = match std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF") {
        Some(p) => p,
        None => {
            eprintln!("SKIP trace_mode map: set OSSL_PROVIDER_OBSERVATION_TEST_BPF");
            return;
        }
    };
    let bytes = std::fs::read(path).unwrap();
    let object = goblin::Object::parse(&bytes).unwrap();
    let goblin::Object::Elf(elf) = object else {
        panic!("not an ELF object");
    };
    let maps_idx = elf
        .section_headers
        .iter()
        .position(|s| &elf.shdr_strtab[s.sh_name] == "maps")
        .expect("maps section");
    let found = elf
        .syms
        .iter()
        .any(|s| s.st_shndx == maps_idx && elf.strtab.get_at(s.st_name) == Some("TRACE_MODE"));
    assert!(
        found,
        "TRACE_MODE map missing from provider-observation object"
    );
}
