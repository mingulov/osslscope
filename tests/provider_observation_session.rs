// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::provider_observation::{self as po, wire};

fn record(kind: u32) -> Vec<u8> {
    let mut b = vec![0; 96];
    for (at, v) in [(0, 1u32), (4, kind), (8, 96), (12, 1), (16, 42), (20, 43)] {
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
    assert!(po::FunctionIdentity::new(po::Operation::Digest, 99999).is_err());
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
    if !batch.facts.iter().any(|f|callback(f) && matches!(f.payload,po::ObservationPayload::Algorithm{algorithm,cacheability} if cacheability==cache && (algorithm.label()=="other")==other)){return Err("callback_algorithm_missing")}
    let implementation=batch.facts.iter().find(|f|callback(f) && matches!(&f.payload,po::ObservationPayload::Implementation{algorithm,function,cacheability,advertiser_candidates,backing_sha256} if *cacheability==cache && (algorithm.label()=="other")==other && function.id()!=0 && !advertiser_candidates.is_empty() && backing_sha256.is_some()!=volatile));
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
            // The third Q follows acknowledged unquery and must restart at the
            // known first entry. The second Q must independently reach Other.
            assert_eq!(
                query_phase_complete(&b, volatile, counters[2] == 2),
                Ok(()),
                "query phase {}: gaps={:?}",
                counters[2],
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
fn unquery_restarts_sampling_without_census_claim() {
    use wire::contract::*;
    assert_eq!(sample_index(1, 511), Some(511));
    assert_eq!(sample_index(1, 512), None);
    assert_eq!(sample_index(2, 511), Some(0));
    assert_eq!(sample_index(0, 511), Some(0));
    assert_eq!(sample_index(1, 0), Some(0));
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
    let mut r = record(5);
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
