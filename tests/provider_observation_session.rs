// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::provider_observation::{self as po, wire};

fn record(kind: u32) -> Vec<u8> {
    let mut b = vec![0; 96];
    for (at, v) in [
        (0, wire::contract::VERSION),
        (4, kind),
        (8, 96),
        (12, 1),
        (16, 42),
        (20, 43),
    ] {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    for at in [24, 32, 40, 48] {
        b[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
    }
    b
}
#[test]
fn entry_return_success_failure() {
    let a = wire::decode(&record(1)).unwrap();
    assert!(matches!(
        a.payload(),
        po::ObservationPayload::ApiAttempt { .. }
    ));
    for (n, outcome) in [
        (1u32, po::ApiOutcome::Success),
        (2, po::ApiOutcome::Failure),
    ] {
        let mut b = record(2);
        b[56..60].copy_from_slice(&n.to_le_bytes());
        assert!(
            matches!(wire::decode(&b).unwrap().payload(), po::ObservationPayload::ApiResult { outcome: got, .. } if *got == outcome)
        );
    }
}
#[test]
fn private_handles_never_enter_host_transport() {
    let mut b = record(1);
    b[80..88].copy_from_slice(&0x12345678u64.to_le_bytes());
    assert!(wire::decode(&b).is_err());
    for at in [8, 88, 92] {
        let mut b = record(1);
        b[at] = 255;
        assert!(wire::decode(&b).is_err());
    }
    assert!(wire::decode(&record(1)[..95]).is_err());
}
#[test]
fn fact_payload_distinguishes_attempt_result_and_advertisement() {
    let a = serde_json::to_value(wire::decode(&record(1)).unwrap().payload()).unwrap();
    let mut b = record(2);
    b[56..60].copy_from_slice(&1u32.to_le_bytes());
    let r = serde_json::to_value(wire::decode(&b).unwrap().payload()).unwrap();
    assert_ne!(a, r);
    assert_eq!(a["kind"], "api_attempt");
    assert_eq!(r["kind"], "api_result");
    assert!(!r.to_string().contains("activation"));
}
#[test]
fn finite_registry_ids_reject_unregistered_values() {
    assert!(po::AlgorithmId::try_from(65534).is_err());
    assert_eq!(
        po::AlgorithmId::try_from(u16::MAX).unwrap().label(),
        "other"
    );
    assert!(po::FunctionIdentity::new(po::Operation::Digest, 99999).is_ok());
    assert!(po::FunctionIdentity::new(po::Operation::Digest, u32::MAX).is_err());
    assert!(po::FunctionIdentity::new(po::Operation::Digest, 1).is_ok());
}
#[test]
fn no_store_not_retained() {
    let mut b = record(6);
    b[12..16].copy_from_slice(&17u32.to_le_bytes());
    b[60..64].copy_from_slice(&1u32.to_le_bytes());
    b[64..68].copy_from_slice(&65535u32.to_le_bytes());
    b[68..72].copy_from_slice(&1u32.to_le_bytes());
    b[72..76].copy_from_slice(&2u32.to_le_bytes());
    b[80..88].copy_from_slice(&0x12345678u64.to_le_bytes());
    assert!(
        wire::decode(&b).is_err(),
        "volatile record must carry no relocation"
    );
}
#[test]
fn init_success_unreadable_dispatch() {
    let mut b = record(3);
    b[12..16].copy_from_slice(&7u32.to_le_bytes());
    b[56..60].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        wire::decode(&b).unwrap().payload(),
        po::ObservationPayload::InitResult {
            outcome: po::ApiOutcome::Success
        }
    ));
}
#[test]
fn corehandle_libctx_provctx_not_equated() {
    let b = record(1);
    let json = serde_json::to_string(wire::decode(&b).unwrap().payload()).unwrap();
    assert!(!json.contains("context"));
}

fn fixture_ack(line: &str, command: char, expected: [u32; 5]) -> Result<(), &'static str> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 8
        || fields.first() != Some(&"ack")
        || fields.get(1) != Some(&command.to_string().as_str())
        || fields.get(2) != Some(&"1")
    {
        return Err("bad_ack");
    }
    for (field, expected) in fields[3..].iter().zip(expected) {
        if field.parse::<u32>() != Ok(expected) {
            return Err("counter_mismatch");
        }
    }
    Ok(())
}
fn query_phase_complete(
    batch: &po::ObservationBatch,
    volatile: bool,
    other: bool,
) -> Result<(), &'static str> {
    let cache = if volatile {
        po::Cacheability::Volatile
    } else {
        po::Cacheability::Cacheable
    };
    let callback = |f: &po::ObservationFact| {
        f.api == po::ObservationApi::ProviderQueryCallback && f.operation == po::Operation::Digest
    };
    if !batch.facts.iter().any(|f|callback(f) && matches!(f.payload,po::ObservationPayload::QueryResult{outcome:po::ApiOutcome::Success,cacheability} if cacheability==cache)){return Err("callback_query_missing")}
    if !batch.facts.iter().any(|f|callback(f) && matches!(f.payload,po::ObservationPayload::Algorithm{algorithm,cacheability,..} if cacheability==cache && (algorithm.label()=="other")==other)){return Err("callback_algorithm_missing")}
    let implementation=batch.facts.iter().find(|f|callback(f) && matches!(&f.payload,po::ObservationPayload::Implementation{algorithm,function,cacheability,advertiser_candidates,backing_sha256,..} if *cacheability==cache && (algorithm.label()=="other")==other && function.id()!=0 && !advertiser_candidates.is_empty() && backing_sha256.is_some()!=volatile));
    let Some(fact) = implementation else {
        return Err("callback_implementation_missing");
    };
    if volatile {
        if !batch.learned_sites.is_empty() {
            return Err("volatile_site_retained");
        }
        if batch.facts.iter().any(|f| {
            matches!(
                &f.payload,
                po::ObservationPayload::Implementation {
                    backing_sha256: Some(_),
                    ..
                }
            )
        }) {
            return Err("volatile_backing_retained");
        }
    } else if let po::ObservationPayload::Implementation {
        algorithm,
        alias_quality,
        function,
        backing_sha256: Some(backing),
        advertiser_candidates,
        ..
    } = &fact.payload
    {
        if !batch.learned_sites.iter().any(|site| {
            site.pid() == fact.pid
                && site.generation() == fact.generation
                && site.algorithm() == *algorithm
                && site.alias_quality() == *alias_quality
                && site.function() == *function
                && site.site().object_hash() == backing
                && !site.advertiser_candidates().is_empty()
                && site.advertiser_candidates() == advertiser_candidates
        }) {
            return Err("verified_site_missing");
        }
    }
    Ok(())
}
#[test]
fn native_ack_checks_each_independent_counter() {
    let expected = [1, 1, 4, 1, 1];
    assert_eq!(fixture_ack("ack X 1 1 1 4 1 1\n", 'X', expected), Ok(()));
    for index in 0..5 {
        let mut changed = expected;
        changed[index] += 1;
        assert_eq!(
            fixture_ack(
                &format!(
                    "ack X 1 {} {} {} {} {}",
                    changed[0], changed[1], changed[2], changed[3], changed[4]
                ),
                'X',
                expected
            ),
            Err("counter_mismatch")
        );
    }
}
#[test]
fn native_query_oracle_refuses_public_only_evidence() {
    let fact = |payload| po::ObservationFact {
        pid: 42,
        starttime: 1,
        object_sha256: "a".repeat(64).try_into().unwrap(),
        generation: 1,
        context: po::ContextIdentity::Unknown {},
        source: po::ObservationSource::ProviderQuery,
        api: po::ObservationApi::Inventoried(osslscope::inventory::Api::OsslProviderQueryOperation),
        operation: po::Operation::Digest,
        class: po::AlgorithmClass::Digest,
        monotonic_ns: 1,
        confidence: po::ScopeConfidence::Observed,
        payload,
    };
    let batch = po::ObservationBatch {
        facts: vec![
            fact(po::ObservationPayload::QueryResult {
                outcome: po::ApiOutcome::Success,
                cacheability: po::Cacheability::Cacheable,
            }),
            fact(po::ObservationPayload::Algorithm {
                algorithm: po::AlgorithmId::try_from(u16::MAX).unwrap(),
                alias_quality: po::AliasQuality::default(),
                cacheability: po::Cacheability::Cacheable,
            }),
        ],
        ..Default::default()
    };
    assert_eq!(
        query_phase_complete(&batch, false, true),
        Err("callback_query_missing")
    );
}
#[test]
#[ignore = "Root review gate: requires actual map_files and BPF privileges"]
fn native_provider_observation() {
    use osslscope::inventory::{
        self,
        scope::{ScopedScanner, Selection},
    };
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    let dir =
        std::env::temp_dir().join(format!("osslscope-public-provider-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let provider = dir.join("fixture.so");
    let app = dir.join("fixture");
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-O1", "-o"])
            .arg(&provider)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/provider_observation_provider.c"
            ))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/provider_observation.c"
            ))
            .args(["-lcrypto", "-ldl"])
            .status()
            .unwrap()
            .success()
    );
    let mut child = Owned(
        Command::new(&app)
            .arg(&provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.0.id()],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let object_path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
        .expect("exact reviewed BPF object required");
    let file = fs::File::open(object_path).unwrap();
    let len = file.metadata().unwrap().len();
    assert!(len <= 16 << 20);
    let mut object = Vec::with_capacity(len as usize + 1);
    file.take(len + 1).read_to_end(&mut object).unwrap();
    assert_eq!(object.len(), len as usize);
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), &object)
        .unwrap_or_else(|g| panic!("session open: {g:?}"));
    let setup = session.reconcile(&scanner.snapshot());
    assert!(
        !setup.gaps.iter().any(|g| matches!(
            g,
            po::ObservationGap::AttachFailed
                | po::ObservationGap::BpfUnavailable
                | po::ObservationGap::SymbolUnavailable
        )),
        "setup: {:?}",
        setup.gaps
    );
    let mut facts = Vec::new();
    let mut gaps = Vec::new();
    let mut volatile = false;
    for (command, counters) in [
        ('I', [1, 0, 0, 1, 0]),
        ('F', [1, 1, 0, 1, 0]),
        ('Q', [1, 1, 1, 1, 0]),
        ('Q', [1, 1, 2, 1, 0]),
        ('U', [1, 1, 2, 1, 0]),
        ('Q', [1, 1, 3, 1, 0]),
        ('V', [1, 1, 3, 1, 0]),
        ('Q', [1, 1, 4, 1, 0]),
        ('S', [1, 1, 4, 1, 0]),
        ('H', [1, 1, 4, 1, 0]),
        ('X', [1, 1, 4, 1, 1]),
    ] {
        writeln!(child.0.stdin.as_mut().unwrap(), "{command}").unwrap();
        child.0.stdin.as_mut().unwrap().flush().unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(
            fixture_ack(&line, command, counters),
            Ok(()),
            "fixture counters in phase {command}"
        );
        // ACK establishes return completion; no timing-based producer assumption.
        let b = session.drain(Instant::now() + Duration::from_millis(100));
        if command == 'V' {
            volatile = true
        } else if command == 'S' {
            volatile = false
        }
        if command == 'Q' {
            // Every single returned table must now contain both algorithms;
            // no second application query is needed to reach the next slot.
            assert_eq!(
                query_phase_complete(&b, volatile, false),
                Ok(()),
                "query phase {}: gaps={:?}",
                counters[2],
                b.gaps
            );
        }
        if command == 'Q' {
            assert_eq!(
                query_phase_complete(&b, volatile, true),
                Ok(()),
                "same-return unknown row: {:?}",
                b.gaps
            );
        }
        if matches!(command, 'I' | 'F') {
            let wanted = if command == 'I' {
                po::ApiOutcome::Success
            } else {
                po::ApiOutcome::Failure
            };
            assert!(b.facts.iter().any(|f|f.api==po::ObservationApi::Inventoried(inventory::Api::OsslProviderLoad) && matches!(f.payload,po::ObservationPayload::ApiResult{outcome,name:po::ProviderNameClass::Other} if outcome==wanted)),"load phase {command}: gaps={:?}",b.gaps);
        }
        if command == 'I' {
            assert!(
                b.facts.iter().any(|f| f.api
                    == po::ObservationApi::Inventoried(inventory::Api::OsslProviderInit)
                    && matches!(
                        f.payload,
                        po::ObservationPayload::InitResult {
                            outcome: po::ApiOutcome::Success
                        }
                    )),
                "init success missing: gaps={:?}",
                b.gaps
            );
        }
        if command == 'U' {
            assert!(
                b.facts
                    .iter()
                    .any(|f| f.api == po::ObservationApi::ProviderUnqueryCallback
                        && matches!(
                            f.payload,
                            po::ObservationPayload::Invalidation {
                                cause: po::InvalidationCause::Unquery
                            }
                        )),
                "learned unquery callback missing: gaps={:?}",
                b.gaps
            );
        }
        facts.extend(b.facts);
        gaps.extend(b.gaps);
        // Public APIs may naturally change maps (provider DSO load); reconcile anew.
        let b = session.reconcile(&scanner.snapshot());
        facts.extend(b.facts);
        gaps.extend(b.gaps);
    }
    let mut departed = scanner.snapshot();
    departed.processes.clear();
    departed.selected_pids.clear();
    let departure = session.reconcile(&departed);
    assert!(
        departure
            .gaps
            .contains(&po::ObservationGap::IntervalUnknown)
    );
    writeln!(child.0.stdin.as_mut().unwrap(), "H").unwrap();
    child.0.stdin.as_mut().unwrap().flush().unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    assert_eq!(fixture_ack(&line, 'H', [1, 1, 4, 1, 1]), Ok(()));
    assert!(
        session
            .drain(Instant::now() + Duration::from_millis(100))
            .facts
            .is_empty(),
        "scope departure left active links"
    );
    // A second actual session proves the output cap and child-exit retirement.
    let limited = po::ObservationLimits {
        max_facts: 1,
        ..Default::default()
    };
    let mut capped = po::ProviderSession::open(limited, &object)
        .unwrap_or_else(|g| panic!("capped session: {g:?}"));
    capped.reconcile(&scanner.snapshot());
    for _ in 0..2 {
        writeln!(child.0.stdin.as_mut().unwrap(), "H").unwrap();
        child.0.stdin.as_mut().unwrap().flush().unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(fixture_ack(&line, 'H', [1, 1, 4, 1, 1]), Ok(()));
    }
    let bounded = capped.drain(Instant::now() + Duration::from_millis(100));
    assert_eq!(bounded.facts.len(), 1);
    assert!(bounded.gaps.contains(&po::ObservationGap::FactLimit));
    writeln!(child.0.stdin.as_mut().unwrap(), "E").unwrap();
    child.0.stdin.take();
    assert!(child.0.wait().unwrap().success());
    let retired = capped.close();
    assert!(
        retired
            .gaps
            .contains(&po::ObservationGap::ProcessUnavailable)
    );
    let b = session.close();
    facts.extend(b.facts);
    gaps.extend(b.gaps);
    assert!(
        facts
            .iter()
            .filter(|f| f.api == po::ObservationApi::Inventoried(inventory::Api::OsslProviderLoad))
            .any(|f| matches!(
                f.payload,
                po::ObservationPayload::ApiResult {
                    outcome: po::ApiOutcome::Success,
                    ..
                }
            )),
        "no success; gaps={gaps:?}"
    );
    assert!(
        facts
            .iter()
            .filter(|f| f.api == po::ObservationApi::Inventoried(inventory::Api::OsslProviderLoad))
            .any(|f| matches!(
                f.payload,
                po::ObservationPayload::ApiResult {
                    outcome: po::ApiOutcome::Failure,
                    ..
                }
            )),
        "no failure; gaps={gaps:?}"
    );
    assert!(
        facts.iter().any(|f| matches!(
            f.payload,
            po::ObservationPayload::InitResult {
                outcome: po::ApiOutcome::Success
            }
        )),
        "no init; gaps={gaps:?}"
    );
    assert!(
        facts.iter().any(|f| matches!(
            f.payload,
            po::ObservationPayload::QueryResult {
                outcome: po::ApiOutcome::Success,
                ..
            }
        )),
        "no query; gaps={gaps:?}"
    );
    assert!(
        facts
            .iter()
            .any(|f| matches!(f.payload, po::ObservationPayload::Algorithm { .. })),
        "no advertised algorithm; gaps={gaps:?}"
    );
    assert!(
        facts.iter().any(|f| matches!(
            f.payload,
            po::ObservationPayload::InitResult {
                outcome: po::ApiOutcome::Failure
            }
        )),
        "failed init not observed; gaps={gaps:?}"
    );
    assert!(
        facts
            .iter()
            .all(|f| matches!(f.context, po::ContextIdentity::Unknown {}))
    );
    let public = serde_json::to_string(&facts).unwrap();
    assert!(!public.contains("PRIVATE-FIXTURE"));
    assert!(!public.contains("private-fixture"));
    println!(
        "native public ABI fixture: {} finite facts; gaps={gaps:?}",
        facts.len()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn nested_wrapper_one_attempt() {
    use wire::contract::*;
    let outer = Pending {
        api: LOAD,
        object: 7,
        arg0: 0xabc,
        ..Default::default()
    };
    let mut inner = Pending {
        api: LOAD_EX,
        ..outer
    };
    assert!(suppress_wrapper(&outer, &inner));
    inner.api = LOAD;
    assert!(!suppress_wrapper(&outer, &inner), "genuine recursion");
    inner.api = LOAD_EX;
    inner.arg0 += 1;
    assert!(!suppress_wrapper(&outer, &inner));
    inner.arg0 = outer.arg0;
    inner.object += 1;
    assert!(!suppress_wrapper(&outer, &inner));
}
#[test]
fn recursion_overflow_is_gap() {
    use wire::contract::*;
    let mut thread = Thread::default();
    for invocation in 1..=8 {
        assert_eq!(thread.enter(), Some(invocation));
    }
    assert_eq!(thread.enter(), None);
    assert_eq!(thread.depth, 8);
    assert_eq!(thread.overflow, 1);
    assert!(thread.skip_return());
    assert_eq!(thread.depth, 8);
    assert!(!thread.skip_return());
    // Failed insertion reserves a skipped return, so recursion cannot consume its parent.
    let mut t = Thread::default();
    assert_eq!(t.enter(), Some(1));
    t.failed_entry();
    assert_eq!(t.depth, 0);
    assert!(t.skip_return());
}
#[test]
fn future_public_operations_preserve_numeric_identity() {
    assert_eq!(wire::contract::known_operation(50001), 50001);
    assert_eq!(wire::contract::known_operation(50002), 50002);
    assert_eq!(wire::contract::known_operation(u32::MAX), 0);
}
#[test]
fn unknown_and_alias_bytes_discarded() {
    // Actual canonical classifier and registry; no mock target-name dictionary.
    use osslscope_ebpf_common::{ALG_WINDOW, OTHER_CLASS, classify_alg_with};
    let mut bytes = [0u8; ALG_WINDOW];
    let unknown = b"PRIVATE-NAME:OTHER-PRIVATE-NAME";
    bytes[..unknown.len()].copy_from_slice(unknown);
    let v = classify_alg_with(&bytes, unknown.len(), false, |_| None);
    assert_eq!(v.class, OTHER_CLASS);
    let mut r = record(6);
    r[12..16].copy_from_slice(&17u32.to_le_bytes());
    r[64..68].copy_from_slice(&(OTHER_CLASS as u32).to_le_bytes());
    let json = serde_json::to_string(wire::decode(&r).unwrap().payload()).unwrap();
    assert!(!json.contains("PRIVATE"));
}

#[test]
fn provider_name_taxonomy_is_exact_and_finite() {
    use wire::contract::provider_name_class;
    for (name, class) in [
        ("default", osslscope_ebpf_common::LOAD_DEFAULT),
        ("legacy", osslscope_ebpf_common::LOAD_LEGACY),
        ("fips", osslscope_ebpf_common::LOAD_FIPS),
    ] {
        let mut b = [0; 32];
        b[..name.len()].copy_from_slice(name.as_bytes());
        assert_eq!(provider_name_class(&b, name.len()), class as u32);
        b[name.len()] = b'x';
        assert_eq!(
            provider_name_class(&b, name.len()),
            0,
            "exact terminating NUL"
        );
        assert_eq!(provider_name_class(&b, name.len() + 1), 0);
    }
    assert_eq!(provider_name_class(&[b'x'; 32], 31), 5);
}
#[test]
fn query_return_before_entry_is_gap() {
    // Return-without-entry is the explicit producer loss category. Unknown kind
    // or API-kind pair cannot be interpreted as a successful advertisement.
    assert_eq!(wire::contract::LOSS_PAIR, 3);
    let mut r = record(4);
    assert!(wire::decode(&r).is_err());
    r[12..16].copy_from_slice(&17u32.to_le_bytes());
    assert!(wire::decode(&r).is_ok());
}
#[test]
fn failed_init_never_authorizes_relocation() {
    let mut r = record(3);
    r[12..16].copy_from_slice(&7u32.to_le_bytes());
    r[56..60].copy_from_slice(&2u32.to_le_bytes());
    assert!(wire::decode(&r).is_ok());
    r[68..72].copy_from_slice(&1027u32.to_le_bytes());
    r[80..88].copy_from_slice(&0x12345000u64.to_le_bytes());
    assert!(wire::decode(&r).is_err());
}
#[test]
fn invalid_object_is_refused_before_bpf_load() {
    assert!(matches!(
        po::ProviderSession::open(po::ObservationLimits::default(), b"not ELF"),
        Err(po::ObservationGap::InvalidObject)
    ));
}

#[test]
fn public_abi_future_numeric_ids_remain_distinct_countable_inputs() {
    for (operation, function) in [(50001u32, 70001u32), (50002, 70001), (50001, 70002)] {
        let mut r = record(6);
        for (at, value) in [
            (12, 17),
            (60, operation),
            (64, 65535),
            (68, function),
            (72, 1),
        ] {
            r[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        r[80..88].copy_from_slice(&4096u64.to_le_bytes());
        assert!(
            wire::decode(&r).is_ok(),
            "future public ABI operation/function is not a registry admission gate"
        );
    }
}
#[test]
fn public_dispatch_getter_return_is_a_correlated_dispatch_source() {
    let mut r = record(3);
    for (at, value) in [(12, 16u32), (56, 1), (68, 1027)] {
        r[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    r[80..88].copy_from_slice(&4096u64.to_le_bytes());
    assert!(wire::decode(&r).is_ok());
    r[56..60].copy_from_slice(&0u32.to_le_bytes());
    assert!(
        wire::decode(&r).is_err(),
        "unsuccessful getter cannot authorize code relocation"
    );
}

#[test]
#[ignore = "requires explicitly supplied fresh observation/count objects and native BPF privileges"]
fn native_static_lookalike_getter_and_shared_site() {
    use osslscope::{
        capture::{ClockPort, LiveClock},
        focused_count::{CountCandidate, CountLimits, FocusedCounter, MetadataOrigin},
        inventory::{
            self,
            scope::{ScopedScanner, Selection},
        },
    };
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::fs::MetadataExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    let dir = std::env::temp_dir().join(format!("osslscope-v2-count-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let provider = dir.join("fixture.so");
    let app = dir.join("fixture");
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-O1", "-Wl,-Bsymbolic", "-o"])
            .arg(&provider)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/provider_observation_provider.c"
            ))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("cc")
            .args(["-O1", "-o"])
            .arg(&app)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/provider_observation.c"
            ))
            .args(["-lcrypto", "-ldl"])
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(&provider).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let offset = |name: &str| {
        let symbol = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some(name))
            .unwrap();
        let segment = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == 1
                    && symbol.st_value >= p.p_vaddr
                    && symbol.st_value < p.p_vaddr + p.p_filesz
            })
            .unwrap();
        segment.p_offset + symbol.st_value - segment.p_vaddr
    };
    let shared = offset("fixture_count_entry");
    let lookalike = offset("fixture_lookalike");
    let mut child = Owned(
        Command::new(&app)
            .arg(&provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    let mut send = |child: &mut Owned, command: &str| -> Vec<String> {
        writeln!(child.0.stdin.as_mut().unwrap(), "{command}").unwrap();
        child.0.stdin.as_mut().unwrap().flush().unwrap();
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0);
            let ack = line.starts_with("ack ");
            lines.push(line);
            if ack {
                break;
            }
        }
        assert_eq!(lines.last().unwrap().split_whitespace().nth(2), Some("1"));
        lines
    };
    // Initialize/query before the observer: only the later public getter can
    // corroborate the callback ABI. Static discovery must work without it.
    send(&mut child, "I");
    send(&mut child, "P");
    send(&mut child, "Q");
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![child.0.id()],
            ..Default::default()
        },
        inventory::Limits::default(),
    )
    .unwrap();
    let snapshot = scanner.snapshot();
    let mut budget = po::ObservationBudget::default();
    let process = po::acquire(&snapshot.processes[0], &mut budget).unwrap();
    let first = process.static_candidates(&budget).unwrap();
    let read_bytes = budget.elf_read_bytes();
    let second = process.static_candidates(&budget).unwrap();
    assert_eq!(first.len(), second.len());
    assert_eq!(
        budget.elf_read_bytes(),
        read_bytes,
        "cached retained files were reparsed"
    );
    assert!(read_bytes > 0 && read_bytes <= 268435456);
    println!(
        "retained-file static discovery: {} associations, {} shared-budget read bytes; second scan adds zero reads",
        first.len(),
        read_bytes
    );
    drop((first, second, process));
    let object = fs::read(
        std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").expect("fresh observation object"),
    )
    .unwrap();
    let count =
        fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").expect("fresh count object"))
            .unwrap();
    let mut session = po::ProviderSession::open(po::ObservationLimits::default(), &object).unwrap();
    let setup = session.reconcile(&scanner.snapshot());
    let metadata = fs::metadata(&provider).unwrap();
    let candidates: Vec<_> = setup
        .static_candidates
        .into_iter()
        .filter(|c| {
            c.site().inode() == metadata.ino() && c.site().native_device() == metadata.dev()
        })
        .collect();
    assert!(
        candidates
            .iter()
            .any(|c| c.site().file_offset() == lookalike && c.function_id() == 1027)
    );
    assert!(
        candidates
            .iter()
            .any(|c| c.site().file_offset() == shared && c.function_id() == 70001)
    );
    let ns = fs::metadata("/proc/self/ns/pid").unwrap();
    let namespace = inventory::NamespaceId {
        device: ns.dev(),
        inode: ns.ino(),
    };
    let now = || LiveClock.checked_monotonic_ns().unwrap();
    let limits = CountLimits {
        max_links: 1,
        window: osslscope::evidence::CountAdmissionWindow {
            start_ns: now(),
            deadline_ns: now() + 30_000_000_000,
        },
        ..Default::default()
    };
    let mut negative = FocusedCounter::open(&count, child.0.id(), namespace, limits).unwrap();
    negative
        .attach_candidates(
            candidates
                .iter()
                .filter(|c| c.site().file_offset() == lookalike || c.site().file_offset() == shared)
                .cloned()
                .map(CountCandidate::Static)
                .collect(),
            now(),
        )
        .unwrap();
    assert_eq!(
        (negative.active_site_count(), negative.active_link_count()),
        (2, 1)
    );
    send(&mut child, "L7");
    let b = session.drain(Instant::now() + Duration::from_millis(100));
    assert!(
        b.facts.is_empty(),
        "static lookalike emitted an advertisement"
    );
    assert!(
        b.learned_sites.is_empty(),
        "static lookalike installed a query reader"
    );
    assert!(!b.gaps.contains(&po::ObservationGap::TargetReadFailed));
    let n = negative.close(Instant::now() + Duration::from_secs(1));
    assert_eq!(n.fenced.iter().map(|s| s.calls).sum::<u64>(), 7);
    let mut counter = FocusedCounter::open(&count, child.0.id(), namespace, limits).unwrap();
    counter
        .attach_candidates(
            candidates
                .into_iter()
                .filter(|c| c.site().file_offset() == shared)
                .map(CountCandidate::Static)
                .collect(),
            now(),
        )
        .unwrap();
    assert_eq!(
        (counter.active_site_count(), counter.active_link_count()),
        (1, 1)
    );
    send(&mut child, "G");
    let getter = session.drain(Instant::now() + Duration::from_millis(100));
    assert!(getter.facts.iter().any(|f| f.api
        == po::ObservationApi::Inventoried(inventory::Api::OsslProviderGet0Dispatch)
        && matches!(
            f.payload,
            po::ObservationPayload::InitResult {
                outcome: po::ApiOutcome::Success
            }
        )));
    let mut algorithms = std::collections::BTreeSet::new();
    for (command, operation) in [("Q", 1), ("Y", 2), ("J", 50001)] {
        send(&mut child, command);
        let b = session.drain(Instant::now() + Duration::from_millis(100));
        assert!(
            !b.gaps.iter().any(|g| matches!(
                g,
                po::ObservationGap::InvalidWire
                    | po::ObservationGap::TargetReadFailed
                    | po::ObservationGap::QueueLoss
            )),
            "{:?}",
            b.gaps
        );
        let learned: Vec<_> = b
            .learned_sites
            .into_iter()
            .filter(|c| c.site().inode() == metadata.ino() && c.site().file_offset() == shared)
            .collect();
        assert!(
            learned
                .iter()
                .any(|c| c.numeric_operation() == operation && c.function().id() == 70001)
        );
        assert!(learned.iter().any(|c| c.algorithm().label() == "other"));
        assert!(learned.iter().any(|c| c.algorithm().label() != "other"));
        let unknown_ids: std::collections::BTreeSet<_> = learned
            .iter()
            .filter(|c| c.algorithm().label() == "other")
            .map(|c| c.dynamic_algorithm())
            .collect();
        // Two unknown rows in each of the public wrapper and correlated
        // callback observations must remain four distinct observation IDs.
        assert_eq!(
            unknown_ids.len(),
            4,
            "unknown rows collapsed within one returned table"
        );
        for c in &learned {
            algorithms.insert(c.dynamic_algorithm());
        }
        counter
            .attach_candidates(
                learned.into_iter().map(CountCandidate::Learned).collect(),
                now(),
            )
            .unwrap();
        assert_eq!(
            (counter.active_site_count(), counter.active_link_count()),
            (1, 1)
        );
        assert_eq!(
            counter
                .sample(Instant::now() + Duration::from_secs(1))
                .sites[0]
                .calls,
            0,
            "advertisement is not execution"
        );
    }
    assert!(
        algorithms.len() == 18,
        "unknown observations must not collapse into Other"
    );
    let lines = send(&mut child, "C37");
    assert!(lines.iter().any(|s| s.trim() == "calls C 37 37"));
    let sample = counter.sample(Instant::now() + Duration::from_secs(1));
    assert_eq!(sample.sites.len(), 1);
    assert_eq!(sample.sites[0].calls, 37);
    assert_eq!(sample.admitted, 37);
    assert!(
        sample.sites[0].candidates.is_empty(),
        "late metadata relabeled earlier attribution"
    );
    assert_eq!(
        sample.sites[0].candidates_coverage,
        osslscope::evidence::CandidateCoverage::Unknown
    );
    assert_eq!(sample.associations.len(), 1);
    for origin in [
        MetadataOrigin::StaticPublicTableCandidate,
        MetadataOrigin::ObservedPublicAbi,
    ] {
        assert!(
            sample.associations[0]
                .associations
                .iter()
                .any(|a| a.origin == origin)
        );
    }
    assert!(
        sample.associations[0]
            .associations
            .iter()
            .filter(|a| a.origin == MetadataOrigin::StaticPublicTableCandidate)
            .all(|a| a.advertisers.is_empty())
    );
    // Volatile advertisement invalidates its lease, not the file-backed entry
    // counter; no volatile callback pointer enters learned attachment inputs.
    send(&mut child, "V");
    send(&mut child, "Q");
    let volatile = session.drain(Instant::now() + Duration::from_millis(100));
    assert!(volatile.learned_sites.is_empty());
    assert!(!osslscope::focused_capture::batch_requires_retirement(
        &volatile,
        child.0.id()
    ));
    send(&mut child, "M");
    send(&mut child, "Q");
    let unreadable = session.drain(Instant::now() + Duration::from_secs(2));
    assert!(
        unreadable
            .gaps
            .contains(&po::ObservationGap::TargetReadFailed)
    );
    assert!(!osslscope::focused_capture::batch_requires_retirement(
        &unreadable,
        child.0.id()
    ));
    send(&mut child, "T");
    send(&mut child, "Q");
    let truncated = session.drain(Instant::now() + Duration::from_secs(5));
    assert!(
        truncated
            .gaps
            .contains(&po::ObservationGap::DispatchPartial),
        "bounded table overflow was not explicit: {:?}",
        truncated.gaps
    );
    for _ in 0..3 {
        send(&mut child, "Q");
    }
    let overflow = session.drain(Instant::now() + Duration::from_secs(5));
    assert!(
        overflow.gaps.contains(&po::ObservationGap::QueueLoss),
        "full ring not disclosed: {:?}",
        overflow.gaps
    );
    assert!(!osslscope::focused_capture::batch_requires_retirement(
        &overflow,
        child.0.id()
    ));
    let sample = counter.close(Instant::now() + Duration::from_secs(1));
    assert_eq!(sample.fenced.iter().map(|s| s.calls).sum::<u64>(), 37);
    assert_eq!(
        sample.associations[0].count_generation,
        sample.fenced[0].generation
    );
    println!(
        "native static lookalike=7, shared static+live N=37, advertise-only=0, physical sites=1, links=1, algorithms={}",
        algorithms.len()
    );
    writeln!(child.0.stdin.as_mut().unwrap(), "E").unwrap();
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
    drop(session);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn operational_calls_cannot_enter_the_cold_fact_ring() {
    for api in 20u32..=48 {
        for kind in [1, 2, 3, 4, 5, 6] {
            let mut bytes = record(kind);
            bytes[12..16].copy_from_slice(&api.to_le_bytes());
            assert!(wire::decode(&bytes).is_err());
        }
    }
}

#[test]
fn scalar_aggregate_transport_is_exact_and_conserved() {
    let mut bytes = vec![0; 72];
    for (at, n) in [(0, 5u64), (8, 2), (16, 1), (24, 1), (40, 1), (64, 3)] {
        bytes[at..at + 8].copy_from_slice(&n.to_ne_bytes());
    }
    let row = wire::decode_activity(40, &bytes).unwrap();
    assert_eq!(
        (
            row.entries,
            row.observed_success,
            row.observed_failure,
            row.gaps.tail,
            row.gaps.unpaired
        ),
        (5, 2, 1, 1, 3)
    );
    assert!(
        wire::decode_activity(20, &bytes).is_err(),
        "digest cannot have mismatch returns"
    );
    assert!(wire::decode_activity(99, &bytes).is_err());
    assert!(wire::decode_activity(40, &bytes[..71]).is_err());
    bytes.extend_from_slice(b"secret-runtime-alias");
    assert!(wire::decode_activity(40, &bytes).is_err());
    bytes.truncate(72);
    bytes[8..16].copy_from_slice(&6u64.to_ne_bytes());
    assert!(wire::decode_activity(40, &bytes).is_err());
}

#[test]
#[ignore = "requires fresh BPF object and native tracing privileges"]
fn native_scalar_unpaired_depth_and_tail_have_no_hot_ring_records() {
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    let dir = std::env::temp_dir().join(format!("osslscope-scalar-pair-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let source = dir.join("pair.c");
    let app = dir.join("pair");
    fs::write(&source, r#"
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <pthread.h>
int EVP_DigestUpdate(void*, const void*, size_t);
static void *worker(void *unused) { EVP_DigestUpdate((void*)1,(void*)2,0); return unused; }
__attribute__((noinline)) int EVP_DigestUpdate(void *ctx, const void *data, size_t n) {
 if (n == 97) return 2;
 if (n == 96) return 0;
 if (n == 99) { char byte; puts("inside"); fflush(stdout); if(read(0,&byte,1) != 1) return 0; }
 else if (n == 98) { pthread_t thread; if(pthread_create(&thread,0,worker,0)) return 0; pthread_join(thread,0); }
 else if (n) { volatile int result = EVP_DigestUpdate(ctx, data, n-1); if (result != 1) return 0; }
 return 1;
}
int main(void) { if(EVP_DigestUpdate((void*)1,(void*)2,99) != 1) return 0;
 if(EVP_DigestUpdate((void*)1,(void*)2,12) != 1) return 1;
 if(EVP_DigestUpdate((void*)1,(void*)2,98) != 1) return 1;
 if(EVP_DigestUpdate((void*)1,(void*)2,97) != 2 || EVP_DigestUpdate((void*)1,(void*)2,96) != 0) return 1;
 return EVP_DigestUpdate((void*)1,(void*)2,99) == 1 ? 0 : 0; }
"#).unwrap();
    assert!(
        Command::new("cc")
            .args(["-O0", "-rdynamic", "-pthread", "-o"])
            .arg(&app)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Owned(
        Command::new(&app)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert_eq!(line, "inside\n");
    let object =
        fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").expect("fresh BPF object"))
            .unwrap();
    let mut session = po::ProviderSession::open(
        po::ObservationLimits {
            max_pending_calls: 1,
            ..Default::default()
        },
        &object,
    )
    .unwrap();
    let snapshot = osslscope::inventory::snapshot(&osslscope::inventory::SnapshotOptions {
        pids: vec![child.0.id()],
        ..Default::default()
    });
    let setup = session.reconcile(&snapshot);
    assert!(
        !setup.gaps.contains(&po::ObservationGap::AttachFailed),
        "{:?}",
        setup.gaps
    );
    child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    line.clear();
    out.read_line(&mut line).unwrap();
    assert_eq!(line, "inside\n");
    for _ in 0..3 {
        let batch = session.drain(Instant::now() + Duration::from_millis(100));
        assert!(
            batch.facts.is_empty(),
            "operational hot calls entered cold ring"
        );
        assert!(
            batch.api_activity.is_empty(),
            "interim snapshot must not be accumulated"
        );
    }
    let batch = session.close();
    let rows: Vec<_> = batch
        .api_activity
        .iter()
        .filter(|a| u32::from(a.row.api) == 22)
        .collect();
    assert_eq!(rows.len(), 1, "{:?}", batch.gaps);
    let row = &rows[0].row;
    assert_eq!(
        (
            row.entries,
            row.observed_success,
            row.observed_failure,
            row.gaps.depth,
            row.gaps.unpaired,
            row.gaps.tail
        ),
        (18, 9, 1, 5, 1, 7)
    );
    assert_eq!(row.gaps.map, 1);
    assert_eq!(row.gaps.unsupported_return, 1);
    println!("scalar pairing: {}", serde_json::to_string(row).unwrap());
    drop(child);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn scalar_failure_subsets_are_disjoint_and_cannot_overflow() {
    for (failures, mismatch, unsupported) in [(1u64, 1u64, 1u64), (u64::MAX, u64::MAX, 1)] {
        let mut bytes = vec![0; 72];
        for (at, n) in [
            (0, failures),
            (16, failures),
            (24, mismatch),
            (32, unsupported),
        ] {
            bytes[at..at + 8].copy_from_slice(&n.to_ne_bytes());
        }
        assert!(
            wire::decode_activity(40, &bytes).is_err(),
            "overlapping failure subsets accepted"
        );
    }
}
