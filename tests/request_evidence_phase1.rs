// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 1 request/fetch/load/query evidence: honesty contract tests.
//!
//! Fix1 (NEW-P5): every control here drives the PRODUCTION path —
//! facts fold through `RequestEvidence::fold`, and operational planes
//! derive from real `ApiActivityRow`s (successful terminal-read shape)
//! through the production `operational_plane` mapping with an explicit
//! scope receipt. No test injects an outcome (`Some(n)` totals,
//! caller-supplied counts, or a twice-repeated synthetic identity):
//! same-name providers carry two independently identified loads, and
//! every assertion covers BOTH renderers (JSON + human) plus the
//! independent physical/operational evidence. Fetch, load, and query
//! facts NEVER mean "used implementation".
use osslscope::api_activity::{ApiActivityGaps, ApiActivityRow, ApiId};
use osslscope::inventory::Api as InvApi;
use osslscope::provider_observation::request_evidence::{
    ActivationState, CandidateTier, FETCH_SURFACES, FetchCapability, RequestEvidence, RequestScope,
    Unattributed,
};
use osslscope::provider_observation::{
    AlgorithmClass, ApiOutcome, Cacheability, ContextIdentity, ObservationApi, ObservationFact,
    ObservationPayload, ObservationSource, Operation, ProviderNameClass, ScopeConfidence,
};
use std::collections::BTreeSet;

/// Production target incarnation shared by facts, rows, and receipts.
const PID: u32 = 4242;
const STARTTIME: u64 = 777;

fn fact(
    api: ObservationApi,
    payload: ObservationPayload,
    operation: Operation,
    identity: (&str, u64),
    monotonic_ns: u64,
) -> ObservationFact {
    ObservationFact {
        pid: PID,
        starttime: STARTTIME,
        object_sha256: identity.0.repeat(64).try_into().unwrap(),
        generation: identity.1,
        context: ContextIdentity::Unknown {},
        source: ObservationSource::PublicApi,
        api,
        operation,
        class: AlgorithmClass::Other,
        monotonic_ns,
        confidence: ScopeConfidence::Observed,
        payload,
    }
}

fn fetch_attempt(api: InvApi, monotonic_ns: u64) -> ObservationFact {
    fact(
        ObservationApi::Inventoried(api),
        ObservationPayload::ApiAttempt {
            name: ProviderNameClass::Other,
        },
        Operation::Other,
        ("a", 1),
        monotonic_ns,
    )
}

fn fetch_result(api: InvApi, outcome: ApiOutcome, monotonic_ns: u64) -> ObservationFact {
    fact(
        ObservationApi::Inventoried(api),
        ObservationPayload::ApiResult {
            name: ProviderNameClass::Other,
            outcome,
        },
        Operation::Other,
        ("a", 1),
        monotonic_ns,
    )
}

fn load_edge(
    name: ProviderNameClass,
    success: bool,
    identity: (&str, u64),
    monotonic_ns: u64,
) -> Vec<ObservationFact> {
    vec![
        fact(
            ObservationApi::Inventoried(InvApi::OsslProviderLoad),
            ObservationPayload::ApiAttempt { name },
            Operation::Other,
            identity,
            monotonic_ns,
        ),
        fact(
            ObservationApi::Inventoried(InvApi::OsslProviderLoad),
            ObservationPayload::ApiResult {
                name,
                outcome: if success {
                    ApiOutcome::Success
                } else {
                    ApiOutcome::Failure
                },
            },
            Operation::Other,
            identity,
            monotonic_ns + 1,
        ),
    ]
}

fn query_result(
    api: ObservationApi,
    outcome: ApiOutcome,
    cacheability: Cacheability,
    operation: Operation,
    monotonic_ns: u64,
) -> ObservationFact {
    let mut fact = fact(
        api,
        ObservationPayload::QueryResult {
            outcome,
            cacheability,
        },
        operation,
        ("a", 1),
        monotonic_ns,
    );
    fact.source = ObservationSource::ProviderQuery;
    fact
}

fn algorithm_row(operation: Operation, monotonic_ns: u64) -> ObservationFact {
    use osslscope::provider_observation::{AlgorithmId, AliasQuality};
    let mut fact = fact(
        ObservationApi::ProviderQueryCallback,
        ObservationPayload::Algorithm {
            algorithm: AlgorithmId::try_from(u16::MAX).unwrap(),
            alias_quality: AliasQuality::default(),
            cacheability: Cacheability::Cacheable,
        },
        operation,
        ("a", 1),
        monotonic_ns,
    );
    fact.source = ObservationSource::ProviderQuery;
    fact
}

/// One successful terminal-read row (the production shape: real
/// entries, `not_attached: false`, the `read_receipt`,
/// prefix/finality caveats set — exactly what `wire::activity`
/// emits for a successful read).
fn successful_row(api: u32, entries: u64) -> ApiActivityRow {
    ApiActivityRow {
        api: ApiId::try_from(api).unwrap(),
        entries,
        observed_success: entries,
        observed_failure: 0,
        verification_mismatch: 0,
        unsupported: 0,
        gaps: ApiActivityGaps {
            read_receipt: true,
            attachment: true,
            finality: true,
            ..Default::default()
        },
    }
}

fn all_armed() -> BTreeSet<u32> {
    FETCH_SURFACES.iter().map(|s| s.id).collect()
}

fn scope_receipt() -> BTreeSet<(u32, u64)> {
    BTreeSet::from([(PID, STARTTIME)])
}

/// Production scope: the entry sum over real rows (merge-neutral —
/// padded unavailable rows contribute zero) through the production
/// `operational_plane` mapping with an explicit scope receipt. The
/// plane is DERIVED, never injected.
fn production_scope(
    rows: &[ApiActivityRow],
    scopes: &BTreeSet<(u32, u64)>,
    armed: BTreeSet<u32>,
) -> RequestScope {
    let entries: u64 = rows.iter().map(|row| row.entries).sum();
    RequestScope {
        operational_entries: RequestEvidence::operational_plane(
            entries,
            scopes.contains(&(PID, STARTTIME)),
        ),
        fetch_armed: armed,
        window: None,
        silence_start: None,
        silence_end: None,
        fence_cuts: Vec::new(),
    }
}

/// Windowed production scope (GATE-OPEN + NEW-16 fix5): zero claims
/// ride a published interval — the armed-idle zero test seals its
/// zeros over a window containing its edges.
fn production_scope_windowed(
    rows: &[ApiActivityRow],
    scopes: &BTreeSet<(u32, u64)>,
    armed: BTreeSet<u32>,
) -> RequestScope {
    let entries: u64 = rows.iter().map(|row| row.entries).sum();
    RequestScope {
        operational_entries: RequestEvidence::operational_plane(
            entries,
            scopes.contains(&(PID, STARTTIME)),
        ),
        fetch_armed: armed,
        window: Some((0, 100)),
        silence_start: Some(0),
        silence_end: None,
        fence_cuts: Vec::new(),
    }
}

fn collect_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                keys.insert(k.clone());
                collect_keys(v, keys);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_keys(item, keys);
            }
        }
        _ => {}
    }
}

/// No execution-claim key may ever appear in request evidence JSON.
fn assert_no_execution_keys(evidence: &RequestEvidence) {
    let json = serde_json::to_value(evidence).unwrap();
    let mut keys = BTreeSet::new();
    collect_keys(&json, &mut keys);
    // NOTE: `properties` alone is the legitimate gap marker
    // (`not_captured`) — only content-carrying keys are banned.
    for banned in [
        "serving_provider",
        "serving",
        "used_implementation",
        "used",
        "executed",
        "execution",
        "winner",
        "selected_provider",
        "property_query",
        "property_string",
    ] {
        assert!(
            !keys.contains(banned),
            "request evidence must not carry `{banned}`: {keys:?}"
        );
    }
}

/// No execution-claim wording may ever appear in the human block
/// (beyond the honesty banner's own "never mean ... was used").
fn assert_no_execution_words(human: &str) {
    for banned in [
        "serving provider",
        "winner",
        "selected provider",
        "used implementation",
    ] {
        assert!(
            !human.contains(banned),
            "human block must not claim `{banned}`:\n{human}"
        );
    }
    assert!(
        human.contains("fetch/load/query facts never mean the fetched object was used"),
        "honesty banner required:\n{human}"
    );
}

#[test]
fn all_14_fetch_surfaces_have_stable_ids() {
    assert_eq!(FETCH_SURFACES.len(), 14);
    let ids: Vec<u32> = FETCH_SURFACES.iter().map(|s| s.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "fetch IDs must be unique");
    // The six v0.6.0 IDs are pinned; the eight Phase 1 IDs extend 73..=80.
    for id in [10, 11, 12, 13, 14, 15, 73, 74, 75, 76, 77, 78, 79, 80] {
        assert!(ids.contains(&id), "missing stable fetch ID {id}");
    }
    let exports: Vec<&str> = FETCH_SURFACES.iter().map(|s| s.export).collect();
    for name in [
        "EVP_MD_fetch",
        "EVP_CIPHER_fetch",
        "EVP_MAC_fetch",
        "EVP_KDF_fetch",
        "EVP_SIGNATURE_fetch",
        "EVP_KEM_fetch",
        "EVP_ASYM_CIPHER_fetch",
        "EVP_KEYEXCH_fetch",
        "EVP_KEYMGMT_fetch",
        "EVP_RAND_fetch",
        "EVP_SKEYMGMT_fetch",
        "OSSL_DECODER_fetch",
        "OSSL_ENCODER_fetch",
        "OSSL_STORE_LOADER_fetch",
    ] {
        assert!(
            exports.contains(&name),
            "missing fetch surface {name}: {exports:?}"
        );
    }
}

#[test]
fn failed_fetch_counts_failure_not_success() {
    // Production path: real fetch edges (attempt + NULL-return
    // failure) plus real operational rows (the digest calls that ran
    // anyway) — the plane derives from the rows, never injected.
    let facts = vec![
        fetch_attempt(InvApi::EvpRandFetch, 10),
        fetch_result(InvApi::EvpRandFetch, ApiOutcome::Failure, 11),
    ];
    let rows = vec![successful_row(64, 4)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    let row = evidence
        .fetches
        .iter()
        .find(|r| r.surface_id == 76)
        .expect("EVP_RAND_fetch row");
    assert_eq!(row.attempts, 1);
    assert_eq!(row.success, 0);
    assert_eq!(row.failure, 1);
    assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 4 });
    // Both renderers + the independent operational evidence agree.
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["fetches"][0]["failure"], 1);
    assert_eq!(json["unattributed"]["observed"]["ops"], 4);
    let human = evidence.human_section();
    assert!(human.contains("EVP_RAND_fetch"), ":\n{human}");
    assert!(human.contains("failure=1"), ":\n{human}");
    assert!(
        human.contains("unattributed operational entries: 4"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn unused_fetch_never_reads_as_used() {
    // Fetched successfully but nothing ever executed: the fetch count
    // stands, the operational plane is an armed-idle observed zero
    // (windowed — GATE-OPEN + NEW-16 fix5: the zero rides its
    // published interval), and nothing in either renderer reads as
    // "used".
    let facts = vec![
        fetch_attempt(InvApi::EvpMacFetch, 10),
        fetch_result(InvApi::EvpMacFetch, ApiOutcome::Success, 11),
    ];
    let rows = vec![successful_row(35, 0)];
    let scope = production_scope_windowed(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    let row = evidence
        .fetches
        .iter()
        .find(|r| r.surface_id == 12)
        .expect("EVP_MAC_fetch row");
    assert_eq!((row.attempts, row.success, row.failure), (1, 1, 0));
    assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 0 });
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["fetches"][0]["success"], 1);
    assert_eq!(json["unattributed"]["observed"]["ops"], 0);
    let human = evidence.human_section();
    assert!(human.contains("success=1"), ":\n{human}");
    assert!(
        human.contains("unattributed operational entries: 0"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn fresh_automatic_default_activation_is_unknown() {
    // Fresh process: a real query traversal observed at BOTH layers
    // (wrapper + provider callback), no explicit load call. The
    // default provider may have auto-loaded silently — Unknown, never
    // "not loaded" and never "loaded", in both renderers.
    let facts = vec![
        query_result(
            ObservationApi::Inventoried(InvApi::OsslProviderQueryOperation),
            ApiOutcome::Success,
            Cacheability::Cacheable,
            Operation::Digest,
            10,
        ),
        query_result(
            ObservationApi::ProviderQueryCallback,
            ApiOutcome::Success,
            Cacheability::Cacheable,
            Operation::Digest,
            11,
        ),
    ];
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    assert_eq!(evidence.default_activation, ActivationState::Unknown);
    assert!(evidence.loads.is_empty());
    assert_eq!(evidence.queries.len(), 1);
    assert_eq!(evidence.queries[0].wrapper.success, 1);
    assert_eq!(evidence.queries[0].callback.success, 1);
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["default_activation"], "unknown");
    assert_eq!(json["queries"][0]["wrapper"]["success"], 1);
    assert_eq!(json["queries"][0]["callback"]["success"], 1);
    let human = evidence.human_section();
    assert!(human.contains("activation: unknown"), ":\n{human}");
    assert!(human.contains("wrapper success=1"), ":\n{human}");
    assert!(human.contains("callback success=1"), ":\n{human}");
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn warm_preattach_activation_is_unknown() {
    // Warm attach: real operational entries observed, no in-window
    // load call. Loads before attach are invisible — Unknown (never
    // "not loaded"), with the observed remainder derived from the
    // real rows in both renderers.
    let rows = vec![successful_row(20, 11)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&[], scope);
    assert_eq!(evidence.default_activation, ActivationState::Unknown);
    assert!(evidence.loads.is_empty());
    assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 11 });
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["unattributed"]["observed"]["ops"], 11);
    let human = evidence.human_section();
    assert!(human.contains("pre-attach"), ":\n{human}");
    assert!(
        human.contains("unattributed operational entries: 11"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn implicit_digest_pkey_paths_are_unattributed() {
    // Operational entries with zero fetch attempts (one-shot
    // EVP_Q_digest / direct-init PKEY paths, as real rows): every
    // entry lands in the remainder — never force-joined to a fetch.
    // No fetch→execution continuity is proved in Phase 1, so observed
    // fetches never shrink the remainder either. Both renderers.
    let rows = vec![successful_row(64, 40), successful_row(39, 20)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&[], scope);
    assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 60 });
    let facts = vec![
        fetch_attempt(InvApi::EvpMdFetch, 10),
        fetch_result(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
    ];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 60 });
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["unattributed"]["observed"]["ops"], 60);
    assert_eq!(json["fetches"][0]["success"], 1);
    let human = evidence.human_section();
    assert!(
        human.contains("unattributed operational entries: 60"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn unattributed_unknown_when_planes_unobserved() {
    // Per-batch folds carry no operational plane and no scope
    // receipt: the remainder is Unknown (never a zero over an
    // unobserved population), and uncovered absent surfaces are
    // unknown — in both renderers.
    let facts = vec![fetch_attempt(InvApi::EvpMdFetch, 9)];
    let evidence = RequestEvidence::fold(&facts, RequestScope::batch());
    assert_eq!(evidence.unattributed, Unattributed::Unknown);
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["unattributed"], "unknown");
    let human = evidence.human_section();
    assert!(
        human.contains("unattributed operational entries: unknown (operational plane unobserved)"),
        ":\n{human}"
    );
    assert!(
        human.contains("absent rows are unknown, not zeros"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn same_name_providers_are_candidates_never_winner() {
    // TWO independently identified same-name providers: distinct
    // code-object identities (hash + generation) under one name
    // class. Two candidates, no winner — name classes cannot count
    // providers — in both renderers.
    let mut facts = load_edge(ProviderNameClass::Default, true, ("d", 1), 10);
    facts.extend(load_edge(ProviderNameClass::Default, true, ("e", 2), 20));
    assert_ne!(facts[0].object_sha256, facts[2].object_sha256);
    assert_ne!(facts[0].generation, facts[2].generation);
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    let row = evidence
        .loads
        .iter()
        .find(|r| r.name == ProviderNameClass::Default)
        .expect("default load row");
    assert_eq!(row.candidates, 2);
    assert_eq!(row.tier, CandidateTier::Candidate);
    assert_eq!(evidence.default_activation, ActivationState::LoadObserved);
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["loads"][0]["tier"], "candidate");
    assert_eq!(json["loads"][0]["candidates"], 2);
    assert_eq!(json["default_activation"], "load_observed");
    let human = evidence.human_section();
    assert!(human.contains("tier=candidate"), ":\n{human}");
    assert!(human.contains("observed default-class load"), ":\n{human}");
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn unknown_spelling_stays_eligible_by_vacuity() {
    // An unrecognized algorithm spelling: the surface row still folds
    // (no admission whitelist is consulted — rows are keyed by fetch
    // surface only), the exact export spelling renders in both
    // formats, and nothing reads as used.
    let facts = vec![
        fetch_attempt(InvApi::EvpMdFetch, 10),
        fetch_result(InvApi::EvpMdFetch, ApiOutcome::Unknown, 11),
    ];
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    let row = evidence
        .fetches
        .iter()
        .find(|r| r.surface_id == 10)
        .expect("EVP_MD_fetch row");
    assert_eq!((row.attempts, row.success, row.unknown), (1, 0, 1));
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["fetches"][0]["export"], "EVP_MD_fetch");
    assert_eq!(json["fetches"][0]["unknown"], 1);
    let human = evidence.human_section();
    assert!(human.contains("EVP_MD_fetch"), ":\n{human}");
    assert!(human.contains("unknown=1"), ":\n{human}");
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn sole_advertiser_with_provider_request_stays_candidate() {
    // A sole algorithm advertiser plus a `provider=`-style request
    // (an explicit genuine load under the requested class): the
    // advert is one candidate algorithm row, the load is a candidate,
    // and neither proves execution — in both renderers.
    let mut facts = vec![algorithm_row(Operation::Digest, 10)];
    facts.extend(load_edge(ProviderNameClass::Default, true, ("d", 1), 20));
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    assert_eq!(evidence.advertisements.len(), 1);
    assert_eq!(evidence.advertisements[0].count, 1);
    assert_eq!(evidence.advertisements[0].tier, CandidateTier::Candidate);
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["advertisements"][0]["count"], 1);
    assert_eq!(json["advertisements"][0]["tier"], "candidate");
    let human = evidence.human_section();
    assert!(human.contains("algorithm_rows=1"), ":\n{human}");
    assert!(
        human.contains("a sole advertiser never proves execution"),
        ":\n{human}"
    );
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}

#[test]
fn store_takes_scheme_encoder_decoder_selection_claims() {
    let by_id = |id: u32| FETCH_SURFACES.iter().find(|s| s.id == id).unwrap();
    assert_eq!(
        by_id(80).capability,
        FetchCapability::StoreLoader,
        "STORE_LOADER takes a scheme, not an algorithm"
    );
    assert_eq!(by_id(79).capability, FetchCapability::Encoder);
    assert_eq!(by_id(78).capability, FetchCapability::Decoder);
    assert!(matches!(by_id(76).capability, FetchCapability::Evp { .. }));
    // Selection is not an execution claim: exercised surfaces still
    // carry no execution keys in either renderer.
    let facts = vec![
        fetch_attempt(InvApi::OsslEncoderFetch, 10),
        fetch_result(InvApi::OsslEncoderFetch, ApiOutcome::Success, 11),
        fetch_attempt(InvApi::OsslStoreLoaderFetch, 12),
        fetch_result(InvApi::OsslStoreLoaderFetch, ApiOutcome::Success, 13),
    ];
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    assert_eq!(evidence.fetches.len(), 2);
    assert_no_execution_keys(&evidence);
    let human = evidence.human_section();
    assert!(human.contains("scheme"), ":\n{human}");
    assert_no_execution_words(&human);
}

#[test]
fn propquery_raw_strings_are_forbidden() {
    // The fold captures no property content: rows carry the explicit
    // gap in BOTH renderers, and no free-string field exists to
    // smuggle one.
    let facts = vec![
        fetch_attempt(InvApi::EvpCipherFetch, 10),
        fetch_result(InvApi::EvpCipherFetch, ApiOutcome::Success, 11),
    ];
    let rows = vec![successful_row(20, 0)];
    let scope = production_scope(&rows, &scope_receipt(), all_armed());
    let evidence = RequestEvidence::fold(&facts, scope);
    let json = serde_json::to_value(&evidence).unwrap();
    let row = &json["fetches"][0];
    assert_eq!(row["properties"], "not_captured");
    let mut keys = BTreeSet::new();
    collect_keys(row, &mut keys);
    assert!(
        keys.iter()
            .all(|k| !k.contains("propert") || *k == "properties"),
        "no property-content field allowed: {keys:?}"
    );
    let human = evidence.human_section();
    assert!(human.contains("properties=not_captured"), ":\n{human}");
    assert_no_execution_keys(&evidence);
    assert_no_execution_words(&human);
}
