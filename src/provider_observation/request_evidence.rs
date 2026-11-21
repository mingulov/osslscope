// SPDX-License-Identifier: GPL-3.0-or-later
//! Request/fetch/load/query evidence (Phase 1): counts of observed
//! provider requests, kept structurally separate from the physical
//! execution ledger.
//!
//! Honesty contract (binding):
//! - Fetch, load, and query facts NEVER mean "used implementation".
//!   This section has no serving-provider, winner, or used-execution
//!   field — by construction, not by discipline.
//! - `provider=` requests and sole advertisers never prove execution:
//!   loads and advertisements carry the `candidate` tier only.
//! - Raw property-query strings are FORBIDDEN in records. Phase 1
//!   captures no property content at all: every fetch row carries the
//!   explicit [`FetchProperties::NotCaptured`] gap instead of a string.
//! - Unattributed remainders range only over observed populations:
//!   without an observed operational plane the remainder is
//!   [`Unattributed::Unknown`], never a zero. The plane is observed
//!   only when a successful scoped count read vouches for it (or
//!   positive entries exist); refused attaches and failed terminal
//!   reads observe nothing — a `Some(0)` over those is a false
//!   zero, so the producer maps them to `None`. Reads vouch SCOPE
//!   only for admitted owners (NEW-1: allocation without a
//!   successful arm admits nothing — a readable zero map over a
//!   never-armed plane certifies nothing; verified-positive
//!   unadmitted rows project with the ROW read receipt but earn
//!   no scope receipt — fix7 NEW-28).
//! - Per-surface zeros are coverage-gated: [`FetchCoverageRow`]
//!   records, for every surface, whether probes EFFECTIVELY covered
//!   it during the window. An absent row under coverage is an
//!   armed-idle in-window zero; an absent row WITHOUT coverage
//!   (refused, missing, late-armed, fence-voided, or
//!   loss-uncertain) is unknown, never a zero. Surfaces with
//!   edges are observed by evidence. Attach refusals ride as gaps
//!   in the same document/batch.
//!
//! Opaque-identity decision (signed off here, Phase 1): rows are keyed
//! by fetch surface only — no algorithm names are captured, so there
//! is nothing to normalize and no admission whitelist to consult.
//! Arbitrary/unknown algorithm names stay eligible by vacuity. When a
//! later phase captures request spellings, the contract is fixed now:
//! records carry a stable hash (never the raw string); the human
//! rendering may echo the exact spelling.
use super::schema::{
    ApiOutcome, Cacheability, ObservationApi, ObservationFact, ObservationPayload, Operation,
    ProviderNameClass,
};
use crate::inventory::Api as InvApi;
use serde::{Deserialize, Serialize};

/// Section version (Phase 1 ships 1).
pub const REQUEST_EVIDENCE_VERSION: u32 = 1;

/// Capability class of one fetch surface. Meanings differ by
/// capability: STORE takes a scheme (not an algorithm), and
/// encoder/decoder selection is not an execution claim.
/// Struct variants deny unknown fields (GATE: no discarded extras).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FetchCapability {
    /// `EVP_*_fetch`: requests an object of the peer operation.
    Evp { operation: Operation },
    /// `OSSL_ENCODER_fetch`: selection is not an execution claim.
    Encoder,
    /// `OSSL_DECODER_fetch`: selection is not an execution claim.
    Decoder,
    /// `OSSL_STORE_LOADER_fetch`: takes a scheme, not an algorithm.
    StoreLoader,
}

/// One of the 14 fetch surfaces (P1-A1 stable IDs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchSurface {
    /// Stable wire ID (10..=15, 73..=80).
    pub id: u32,
    /// Exact export spelling.
    pub export: &'static str,
    /// Inventory identity for fact folding.
    pub api: InvApi,
    /// Capability class (meaning of a request here).
    pub capability: FetchCapability,
}

/// All 14 fetch surfaces: 11 `EVP_*_fetch` (incl. `EVP_SKEYMGMT_fetch`
/// @ OPENSSL_3.5.0) plus `OSSL_ENCODER/DECODER/STORE_LOADER_fetch`.
/// Order is ID order: the six v0.6.0 IDs, then the P1-A1 extension.
pub const FETCH_SURFACES: [FetchSurface; 14] = [
    FetchSurface {
        id: 10,
        export: "EVP_MD_fetch",
        api: InvApi::EvpMdFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Digest,
        },
    },
    FetchSurface {
        id: 11,
        export: "EVP_CIPHER_fetch",
        api: InvApi::EvpCipherFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Cipher,
        },
    },
    FetchSurface {
        id: 12,
        export: "EVP_MAC_fetch",
        api: InvApi::EvpMacFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Mac,
        },
    },
    FetchSurface {
        id: 13,
        export: "EVP_KDF_fetch",
        api: InvApi::EvpKdfFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Kdf,
        },
    },
    FetchSurface {
        id: 14,
        export: "EVP_SIGNATURE_fetch",
        api: InvApi::EvpSignatureFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Signature,
        },
    },
    FetchSurface {
        id: 15,
        export: "EVP_KEM_fetch",
        api: InvApi::EvpKemFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Kem,
        },
    },
    FetchSurface {
        id: 73,
        export: "EVP_ASYM_CIPHER_fetch",
        api: InvApi::EvpAsymCipherFetch,
        capability: FetchCapability::Evp {
            operation: Operation::AsymCipher,
        },
    },
    FetchSurface {
        id: 74,
        export: "EVP_KEYEXCH_fetch",
        api: InvApi::EvpKeyexchFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Keyexch,
        },
    },
    FetchSurface {
        id: 75,
        export: "EVP_KEYMGMT_fetch",
        api: InvApi::EvpKeymgmtFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Keymgmt,
        },
    },
    FetchSurface {
        id: 76,
        export: "EVP_RAND_fetch",
        api: InvApi::EvpRandFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Rand,
        },
    },
    FetchSurface {
        id: 77,
        export: "EVP_SKEYMGMT_fetch",
        api: InvApi::EvpSkeymgmtFetch,
        capability: FetchCapability::Evp {
            operation: Operation::Skeymgmt,
        },
    },
    FetchSurface {
        id: 78,
        export: "OSSL_DECODER_fetch",
        api: InvApi::OsslDecoderFetch,
        capability: FetchCapability::Decoder,
    },
    FetchSurface {
        id: 79,
        export: "OSSL_ENCODER_fetch",
        api: InvApi::OsslEncoderFetch,
        capability: FetchCapability::Encoder,
    },
    FetchSurface {
        id: 80,
        export: "OSSL_STORE_LOADER_fetch",
        api: InvApi::OsslStoreLoaderFetch,
        capability: FetchCapability::StoreLoader,
    },
];

/// Surface lookup by inventory identity.
pub fn surface_for(api: InvApi) -> Option<&'static FetchSurface> {
    FETCH_SURFACES.iter().find(|s| s.api == api)
}

/// Property-query capture state. Raw strings are forbidden in
/// records; Phase 1 captures no property content at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchProperties {
    /// No property content captured (explicit gap, never a string).
    NotCaptured,
}

/// Admission tier for loads and advertisements: candidate-only, never
/// a forced winner. The single variant is the whole point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateTier {
    Candidate,
}

/// Default-provider activation state. The ONLY positive state is an
/// explicitly observed in-window load success; silence (automatic
/// default loading) and pre-attach loads are both `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationState {
    /// An in-window genuine `OSSL_PROVIDER_load*` success for the
    /// default name class was observed (registration via
    /// `add_builtin` never qualifies — NEW-P3).
    LoadObserved,
    /// No explicit in-window load observed: silent auto-load and
    /// pre-attach loads are both possible. Never "not loaded".
    Unknown,
}

/// Operational entries unattributed to any fetch. Phase 1 proves no
/// fetch→execution continuity, so every observed operational entry is
/// unattributed — including when fetches were also observed (implicit
/// one-shot/direct-init paths and pre-window fetches are possible).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Unattributed {
    /// Operational plane unobserved: no remainder over an
    /// unobserved population (never a zero).
    Unknown,
    /// Observed remainder over the observed operational plane.
    Observed {
        /// Operational entries with no proven fetch.
        ops: u64,
    },
}

/// Fetch counts for one surface (ID order in the section).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FetchRow {
    pub surface_id: u32,
    pub export: &'static str,
    pub capability: FetchCapability,
    pub attempts: u64,
    pub success: u64,
    pub failure: u64,
    pub unknown: u64,
    pub properties: FetchProperties,
}

impl<'de> Deserialize<'de> for FetchRow {
    /// Fail-closed read binding: the ID must name a known surface
    /// and the carried export/capability must agree with it — a
    /// hand-edited row with a mismatched spelling or capability is
    /// rejected, never normalized.
    fn deserialize<D: serde::Deserializer<'de>>(read: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            surface_id: u32,
            export: String,
            capability: FetchCapability,
            attempts: u64,
            success: u64,
            failure: u64,
            unknown: u64,
            properties: FetchProperties,
        }
        let wire = Wire::deserialize(read)?;
        let surface = FETCH_SURFACES
            .iter()
            .find(|s| s.id == wire.surface_id)
            .ok_or_else(|| D::Error::custom("unknown fetch surface_id"))?;
        if surface.export != wire.export {
            return Err(D::Error::custom("fetch export disagrees with surface_id"));
        }
        if surface.capability != wire.capability {
            return Err(D::Error::custom(
                "fetch capability disagrees with surface_id",
            ));
        }
        Ok(FetchRow {
            surface_id: surface.id,
            export: surface.export,
            capability: surface.capability,
            attempts: wire.attempts,
            success: wire.success,
            failure: wire.failure,
            unknown: wire.unknown,
            properties: wire.properties,
        })
    }
}

/// Load counts for one provider name class (candidate tier only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadRow {
    pub name: ProviderNameClass,
    pub attempts: u64,
    pub success: u64,
    pub failure: u64,
    pub unknown: u64,
    /// Successful loads under this class. Name classes cannot count
    /// distinct providers: same-name providers stay candidates here,
    /// never a forced winner.
    pub candidates: u64,
    pub tier: CandidateTier,
}

/// Query counts for one observation side (NEW-P4): the public
/// wrapper (`OSSL_PROVIDER_query_operation`) and the provider query
/// callback observe the same traversal at two layers — their results
/// are distinguished, never collapsed into one count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySideCounts {
    pub success: u64,
    pub failure: u64,
    pub unknown: u64,
    pub cacheable: u64,
    pub volatile: u64,
    pub cache_unknown: u64,
}

/// Query counts for one operation, split by observation side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRow {
    pub operation: Operation,
    /// Public `OSSL_PROVIDER_query_operation` results.
    pub wrapper: QuerySideCounts,
    /// Provider query-callback results.
    pub callback: QuerySideCounts,
}

/// Returned-table advertisement counts for one operation
/// (candidate-only: a sole advertiser never proves execution).
/// The counted unit is the ALGORITHM ROW (NEW-P4): per-dispatch-function
/// facts describe one row's table entries, never additional entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertRow {
    pub operation: Operation,
    pub count: u64,
    pub tier: CandidateTier,
}

/// Plain outcome counts (init results).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeCounts {
    pub success: u64,
    pub failure: u64,
    pub unknown: u64,
}

/// Per-surface EFFECTIVE probe coverage (NEW-P1-OPEN, NEW-P1 fix3
/// claimed-interval form): whether the window's probes covered this
/// fetch surface continuously from effective admission (armed at or
/// before the claimed-interval start) with no mid-window disarm
/// and no observed loss. Read WITH [`RequestEvidence::fetches`]:
/// an absent row under `observed: true` is an armed-idle
/// in-window zero; an absent row under `observed: false` (refused,
/// missing, post-claim-armed, fence-voided, or loss-uncertain) is
/// unknown, never a zero. Always all 14 surfaces in ID order; a
/// present fetch row implies `observed: true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchCoverageRow {
    pub surface_id: u32,
    pub observed: bool,
}

/// Projection scope: which populations the producer actually observed
/// (NEW-P1). The fold never invents observation: `None` planes stay
/// [`Unattributed::Unknown`] and uncovered surfaces stay unknown.
#[derive(Clone, Debug, Default)]
pub struct RequestScope {
    /// Observed operational entries, or `None` when the operational
    /// plane was unobserved (no successful scoped count read and no
    /// positive entries — see [`RequestEvidence::operational_plane`]).
    pub operational_entries: Option<u64>,
    /// Fetch surface IDs with EFFECTIVE probe coverage during the
    /// window (NEW-P1-OPEN + NEW-P1 fix3: armed at or before the
    /// claimed-interval start, no mid-window disarm, no observed
    /// loss — the session seal rule). Surfaces with folded edges
    /// count as observed regardless (evidence overrides).
    pub fetch_armed: std::collections::BTreeSet<u32>,
    /// Focused window `[start, end)` in monotonic ns (NEW-P2,
    /// NEW-9 fix4): the PUBLISHED capture window — genuine edges
    /// anywhere inside it project (including the setup prefix
    /// before effective admission). Edges outside it never
    /// project. The upper cut is EXCLUSIVE like the producer's
    /// (`now >= window.end` is closed) — an edge exactly at the
    /// deadline is out. `None` = unwindowed (per-batch scope
    /// counts every fed edge).
    pub window: Option<(u64, u64)>,
    /// Silence-interval start in monotonic ns (NEW-9 fix4): the
    /// effective-admission instant the window's zeros are claimed
    /// from (`Some` from the focused seal iff the claim
    /// established; NEW-16-OPEN + NEW-20 fix6: `None` claims NO
    /// silence — the projection publishes no interval and
    /// certifies no zeros, never a setup-time fallback). The
    /// projection publishes `[silence_start, silence_end)` as the
    /// section's [`SilenceWindow`] — the narrower interval BOTH
    /// formats expose beside the capture-window rows.
    pub silence_start: Option<u64>,
    /// Silence-interval end in monotonic ns (NEW-26 fix7): the
    /// instant the window's zeros are claimed through (`Some`
    /// from the focused seal when the writer cut succeeded — the
    /// cut's conservative `close_before_ns`, never past the
    /// end sample the seal takes after closing the writers).
    /// `None` claims through the window end (batch scope and
    /// gateless seals — no cut exists, so the capture end
    /// stands). Always clamped inside the window; rows still
    /// project over the whole capture window (verified
    /// capture-window positives are retained).
    pub silence_end: Option<u64>,
    /// Sealed incarnation-fence cuts (NEW-2): excluded intervals
    /// `(edge, resume)` in monotonic ns, retained through seal
    /// across recovery drains. An open interval `(edge, None)`
    /// excludes `[edge, ∞)`; a closed one excludes `[edge,
    /// resume)`. Edges inside any interval are wrong-incarnation
    /// and excluded even when fed before the fence arrived (the
    /// fold journals timestamped edges and replays at projection,
    /// so arrival order never matters). Cuts match the live
    /// consumer (`>= edge` excluded; `>= resume` re-admitted).
    pub fence_cuts: Vec<(u64, Option<u64>)>,
}

impl RequestScope {
    /// Per-batch scope: no operational plane, no arm records, every
    /// edge counts (coverage comes from edges alone).
    pub fn batch() -> Self {
        Self::default()
    }
}

/// The silence interval (NEW-9 fix4): the monotonic-ns `[start,
/// end)` over which the section's ZEROS are claimed (absent
/// fetch rows under coverage, the unattributed observed zero).
/// NARROWER than the published capture window: request ROWS
/// (positives) cover the whole capture window — genuine
/// setup-prefix edges are preserved — while silence is claimed
/// only from effective admission. Rendered in both formats; the
/// semantic gate binds it inside the document's effective window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SilenceWindow {
    pub start_ns: u64,
    pub end_ns: u64,
}

/// Request/fetch/load/query evidence for one window (or batch).
/// Structurally separate from the physical execution ledger: no
/// field here names a serving provider or a used implementation.
/// Deserialization is strict (GATE): the section parses only when
/// [`RequestEvidence::validate_strict`] accepts it, so typed readers
/// and the JSON semantic gate share one validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestEvidence {
    pub version: u32,
    /// The silence interval (NEW-9): `Some` for window scope
    /// (sealed with the fold), `None` for per-batch scope (no
    /// window, no silence claim). Omitted from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silence_window: Option<SilenceWindow>,
    /// Surfaces with in-window edges, in ID order. Absent surfaces
    /// are interpreted through [`RequestEvidence::fetch_coverage`]:
    /// armed-idle zeros when covered, unknown when not.
    pub fetches: Vec<FetchRow>,
    /// Probe coverage for all 14 surfaces, in ID order (NEW-P1).
    pub fetch_coverage: Vec<FetchCoverageRow>,
    /// Name classes with in-window load edges.
    pub loads: Vec<LoadRow>,
    /// Init-callback outcomes (all init APIs; detail stays per-fact).
    pub inits: OutcomeCounts,
    /// Per-operation query outcomes.
    pub queries: Vec<QueryRow>,
    /// Per-operation returned-table advertisement counts.
    pub advertisements: Vec<AdvertRow>,
    /// Default-provider activation (Unknown unless an explicit
    /// in-window load success was observed).
    pub default_activation: ActivationState,
    /// Operational entries unattributed to any fetch.
    pub unattributed: Unattributed,
}

/// Incremental fold over fact batches. `feed` journals one small
/// timestamped edge per request edge (NEW-P2: the journal replays at
/// projection, so the window and a LATE incarnation fence still
/// exclude already-fed facts — arrival order never matters);
/// `finish`/`project` filter, reduce, and bind the scope; `fold` is
/// the single-batch form. The journal is capped at the production
/// fact cap (NEW-5: past-cap edges drop with a visible count, so
/// replay is bounded close work and the reservation covers the
/// worst case for the session lifetime).
#[derive(Clone, Debug, Default)]
pub struct RequestEvidenceFold {
    journal: Vec<JournalEdge>,
    journal_dropped: u64,
}

/// One journaled edge's retained bytes (NEW-5 reservation unit).
pub(crate) const JOURNAL_EDGE_BYTES: usize = std::mem::size_of::<JournalEdge>();

/// One journaled request edge (NEW-P2).
#[derive(Clone, Copy, Debug)]
struct JournalEdge {
    /// Fact monotonic timestamp (window/fence filter key).
    ts: u64,
    kind: EdgeKind,
}

/// Classified request edge (see `classify_edge`).
#[derive(Clone, Copy, Debug)]
enum EdgeKind {
    FetchAttempt(u8),
    FetchResult(u8, ApiOutcome),
    LoadAttempt(u8),
    LoadResult(u8, ApiOutcome),
    Init(ApiOutcome),
    Query {
        operation: Operation,
        callback: bool,
        outcome: ApiOutcome,
        cacheability: Cacheability,
    },
    Advert(Operation),
}

/// Which layer observed a query result (NEW-P4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum QuerySide {
    Wrapper,
    Callback,
}

fn name_slot(name: ProviderNameClass) -> usize {
    match name {
        ProviderNameClass::Default => 0,
        ProviderNameClass::Legacy => 1,
        ProviderNameClass::Fips => 2,
        ProviderNameClass::Other => 3,
        ProviderNameClass::Unreadable => 4,
        ProviderNameClass::Overlong => 5,
    }
}

fn name_at(slot: usize) -> ProviderNameClass {
    match slot {
        0 => ProviderNameClass::Default,
        1 => ProviderNameClass::Legacy,
        2 => ProviderNameClass::Fips,
        3 => ProviderNameClass::Other,
        4 => ProviderNameClass::Unreadable,
        _ => ProviderNameClass::Overlong,
    }
}

/// Load-family exports folded into [`LoadRow`]s: the four genuine
/// load calls ONLY (NEW-P3). `OSSL_PROVIDER_add_builtin` registers
/// an initializer (a static availability grant, provider.c) — it is
/// registration, not a load, so its edges never feed loads or
/// activation. Unload results accompany invalidation facts and are
/// not load requests either.
fn is_load_api(api: InvApi) -> bool {
    use InvApi::*;
    matches!(
        api,
        OsslProviderLoad | OsslProviderTryLoad | OsslProviderLoadEx | OsslProviderTryLoadEx
    )
}

/// True only for actual provider-init callbacks (NEW-P3): the
/// `get0_dispatch` table getter and the `add_builtin` registration
/// INIT records are not init executions, so they never feed inits.
fn is_init_api(api: InvApi) -> bool {
    matches!(api, InvApi::OsslProviderInit)
}

/// Classify one fact into a journal edge (NEW-P2: classification
/// without reduction — counts happen at projection, after the window
/// and fence filters). `None` = not a request edge:
/// - fetch surfaces → fetch edges (attempts + outcomes);
/// - genuine load calls → load edges joining their classified
///   name-class row (the BPF status word); `add_builtin` registration
///   is not a load (NEW-P3);
/// - actual init callbacks → init edges (getter + registration INIT
///   records excluded, NEW-P3);
/// - query results → wrapper/callback-side edges (NEW-P4);
/// - algorithm rows → advert edges (`Implementation` dispatch-function
///   facts are not additional entries, NEW-P4).
fn classify_edge(fact: &ObservationFact) -> Option<EdgeKind> {
    let slot_for = |api: InvApi| {
        FETCH_SURFACES
            .iter()
            .position(|s| s.api == api)
            .map(|slot| slot as u8)
    };
    match &fact.payload {
        ObservationPayload::ApiAttempt { name } => {
            let ObservationApi::Inventoried(api) = fact.api else {
                return None;
            };
            if let Some(slot) = slot_for(api) {
                Some(EdgeKind::FetchAttempt(slot))
            } else if is_load_api(api) {
                Some(EdgeKind::LoadAttempt(name_slot(*name) as u8))
            } else {
                None
            }
        }
        ObservationPayload::ApiResult { name, outcome } => {
            let ObservationApi::Inventoried(api) = fact.api else {
                return None;
            };
            if let Some(slot) = slot_for(api) {
                Some(EdgeKind::FetchResult(slot, *outcome))
            } else if is_load_api(api) {
                // Edges counted as observed (pairing is the trace
                // plane's job): results split by outcome.
                Some(EdgeKind::LoadResult(name_slot(*name) as u8, *outcome))
            } else {
                None
            }
        }
        ObservationPayload::InitResult { outcome } => {
            let ObservationApi::Inventoried(api) = fact.api else {
                return None;
            };
            if !is_init_api(api) {
                return None;
            }
            Some(EdgeKind::Init(*outcome))
        }
        ObservationPayload::QueryResult {
            outcome,
            cacheability,
        } => {
            // The wire emits QUERY records for exactly the wrapper
            // and callback APIs; anything else rides the public
            // wrapper side, never silently dropped.
            let callback = matches!(fact.api, ObservationApi::ProviderQueryCallback);
            Some(EdgeKind::Query {
                operation: fact.operation,
                callback,
                outcome: *outcome,
                cacheability: *cacheability,
            })
        }
        ObservationPayload::Algorithm { .. } => Some(EdgeKind::Advert(fact.operation)),
        ObservationPayload::Implementation { .. } | ObservationPayload::Invalidation { .. } => None,
    }
}

/// Reduced journal counts (projection-local).
#[derive(Default)]
struct Reduced {
    fetch_attempts: [u64; 14],
    fetch_success: [u64; 14],
    fetch_failure: [u64; 14],
    fetch_unknown: [u64; 14],
    load_attempts: [u64; 6],
    load_success: [u64; 6],
    load_failure: [u64; 6],
    load_unknown: [u64; 6],
    inits: OutcomeCounts,
    query_outcome: std::collections::BTreeMap<(Operation, QuerySide), [u64; 3]>,
    query_cache: std::collections::BTreeMap<(Operation, QuerySide), [u64; 3]>,
    adverts: std::collections::BTreeMap<Operation, u64>,
}

impl Reduced {
    fn add_outcome(counts: &mut [u64; 3], outcome: ApiOutcome) {
        match outcome {
            ApiOutcome::Success => counts[0] = counts[0].saturating_add(1),
            ApiOutcome::Failure => counts[1] = counts[1].saturating_add(1),
            ApiOutcome::Unknown => counts[2] = counts[2].saturating_add(1),
        }
    }

    fn add(&mut self, kind: EdgeKind) {
        match kind {
            EdgeKind::FetchAttempt(slot) => {
                let cell = &mut self.fetch_attempts[slot as usize];
                *cell = cell.saturating_add(1);
            }
            EdgeKind::FetchResult(slot, outcome) => {
                let index = slot as usize;
                let mut counts = [
                    self.fetch_success[index],
                    self.fetch_failure[index],
                    self.fetch_unknown[index],
                ];
                Self::add_outcome(&mut counts, outcome);
                [
                    self.fetch_success[index],
                    self.fetch_failure[index],
                    self.fetch_unknown[index],
                ] = counts;
            }
            EdgeKind::LoadAttempt(slot) => {
                let cell = &mut self.load_attempts[slot as usize];
                *cell = cell.saturating_add(1);
            }
            EdgeKind::LoadResult(slot, outcome) => {
                let index = slot as usize;
                let mut counts = [
                    self.load_success[index],
                    self.load_failure[index],
                    self.load_unknown[index],
                ];
                Self::add_outcome(&mut counts, outcome);
                [
                    self.load_success[index],
                    self.load_failure[index],
                    self.load_unknown[index],
                ] = counts;
            }
            EdgeKind::Init(outcome) => {
                let mut counts = [self.inits.success, self.inits.failure, self.inits.unknown];
                Self::add_outcome(&mut counts, outcome);
                [self.inits.success, self.inits.failure, self.inits.unknown] = counts;
            }
            EdgeKind::Query {
                operation,
                callback,
                outcome,
                cacheability,
            } => {
                let side = if callback {
                    QuerySide::Callback
                } else {
                    QuerySide::Wrapper
                };
                Self::add_outcome(
                    self.query_outcome
                        .entry((operation, side))
                        .or_insert([0; 3]),
                    outcome,
                );
                let cache = self.query_cache.entry((operation, side)).or_insert([0; 3]);
                match cacheability {
                    Cacheability::Cacheable => cache[0] = cache[0].saturating_add(1),
                    Cacheability::Volatile => cache[1] = cache[1].saturating_add(1),
                    Cacheability::Unknown => cache[2] = cache[2].saturating_add(1),
                }
            }
            EdgeKind::Advert(operation) => {
                let entry = self.adverts.entry(operation).or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
    }
}

impl RequestEvidenceFold {
    /// Journal capacity (NEW-5): the production fact cap — every
    /// producer-fed edge passed the session emit gate, so producer
    /// journals never reach it; it bounds hostile/test inputs and
    /// sizes the reservation + replay bound.
    pub(crate) fn journal_cap() -> usize {
        super::schema::ObservationLimits::default().max_facts
    }

    /// Retained-memory reservation for a worst-case journal
    /// (NEW-5): full-cap edges plus `Vec` header slack, held by
    /// the focused session lease for the session lifetime.
    pub(crate) fn journal_reserve_bytes() -> usize {
        Self::journal_cap()
            .saturating_mul(JOURNAL_EDGE_BYTES)
            .saturating_add(32)
    }

    /// Journaled edges (test seam).
    #[cfg(test)]
    pub(crate) fn journal_len(&self) -> usize {
        self.journal.len()
    }

    /// Past-cap edges dropped so far (NEW-5: callers surface a
    /// visible gap; never silent).
    pub(crate) fn journal_dropped(&self) -> u64 {
        self.journal_dropped
    }

    /// Take (drain) the dropped count (window-fold callers drain
    /// after every feed so each overflow gaps its own batch).
    pub(crate) fn take_journal_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.journal_dropped)
    }

    /// Feed one batch of facts: classify + journal (no reduction —
    /// the window and fence apply at projection, so late fences
    /// still retract already-fed facts). The journal caps at
    /// [`Self::journal_cap`]: past-cap edges drop with a visible
    /// [`Self::take_journal_dropped`] count (callers gap it —
    /// never silent), so close replay is bounded work.
    pub fn feed(&mut self, facts: &[ObservationFact]) {
        for fact in facts {
            let Some(kind) = classify_edge(fact) else {
                continue;
            };
            if self.journal.len() >= Self::journal_cap() {
                self.journal_dropped = self.journal_dropped.saturating_add(1);
                continue;
            }
            self.journal.push(JournalEdge {
                ts: fact.monotonic_ns,
                kind,
            });
        }
    }

    /// Bind the scope and seal the section: `None` planes stay
    /// [`Unattributed::Unknown`] (never a zero over an unobserved
    /// population) and coverage marks every surface (NEW-P1).
    pub fn finish(self, scope: RequestScope) -> RequestEvidence {
        self.project(&scope)
    }

    /// Seal without consuming (test seam + shared projection).
    pub fn project(&self, scope: &RequestScope) -> RequestEvidence {
        // NEW-P2: replay the journal through the window + fence —
        // out-of-window edges (pre-window strays, post-deadline
        // closing-drain edges) and post-fence edges
        // (wrong-incarnation) never project.
        let mut reduced = Reduced::default();
        for edge in &self.journal {
            // NEW-P2-OPEN: the SAME exclusive upper cut as the
            // producer (`now >= window.end` is closed) and the live
            // consumer (`monotonic_ns >= edge` withholds) — an edge
            // exactly at the deadline or the fence is OUT.
            if let Some((start, end)) = scope.window {
                if edge.ts < start || edge.ts >= end {
                    continue;
                }
            }
            // NEW-2: sealed cuts exclude their union — a recovery
            // drain must not resurrect journaled uncertain facts.
            let fenced = scope.fence_cuts.iter().any(|(edge_cut, resume)| {
                edge.ts >= *edge_cut && resume.is_none_or(|cut| edge.ts < cut)
            });
            if fenced {
                continue;
            }
            reduced.add(edge.kind);
        }
        let mut fetches = Vec::new();
        let mut edged = [false; 14];
        for (index, surface) in FETCH_SURFACES.iter().enumerate() {
            let (attempts, success, failure, unknown) = (
                reduced.fetch_attempts[index],
                reduced.fetch_success[index],
                reduced.fetch_failure[index],
                reduced.fetch_unknown[index],
            );
            if attempts == 0 && success == 0 && failure == 0 && unknown == 0 {
                continue;
            }
            edged[index] = true;
            fetches.push(FetchRow {
                surface_id: surface.id,
                export: surface.export,
                capability: surface.capability,
                attempts,
                success,
                failure,
                unknown,
                properties: FetchProperties::NotCaptured,
            });
        }
        // NEW-9-OPEN + NEW-16 fix5: the window above is the capture
        // window (prefix edges project); the section publishes the
        // NARROWER silence interval beside the rows (batch scope
        // claims none) — and zeros certify ONLY under a NONEMPTY
        // published interval. NEW-16-OPEN + NEW-20 fix6: silence is
        // claimed ONLY from an established start (`silence_start:
        // None` — the seal's unestablished shape — publishes NO
        // interval, exactly like a late claim clamped empty):
        // armed-but-edgeless surfaces read unknown and an idle
        // plane reads Unknown (fail closed). Positives are
        // unaffected (rows project, remainders observe, edges prove
        // observation).
        let silence_window = scope.window.and_then(|(start, end)| {
            scope.silence_start.and_then(|claimed| {
                // NEW-26 fix7: the claimed end is the writer cut
                // when the seal supplies one (clamped inside the
                // window — a cut past the end sample or before the
                // start clamps or empties, never widens).
                let end = scope.silence_end.unwrap_or(end).min(end);
                let silence = SilenceWindow {
                    start_ns: claimed.max(start).min(end),
                    end_ns: end,
                };
                (silence.start_ns < silence.end_ns).then_some(silence)
            })
        });
        let certifies_zeros = silence_window.is_some();
        // Coverage (NEW-P1): all 14 surfaces, in ID order. Edged
        // means observed (evidence overrides); armed means observed
        // only under a certifying interval — absent + unarmed (or
        // interval-less) is unknown.
        let mut fetch_coverage = Vec::with_capacity(14);
        for (index, surface) in FETCH_SURFACES.iter().enumerate() {
            fetch_coverage.push(FetchCoverageRow {
                surface_id: surface.id,
                observed: edged[index]
                    || (certifies_zeros && scope.fetch_armed.contains(&surface.id)),
            });
        }
        let mut loads = Vec::new();
        for slot in 0..6 {
            let (attempts, success, failure, unknown) = (
                reduced.load_attempts[slot],
                reduced.load_success[slot],
                reduced.load_failure[slot],
                reduced.load_unknown[slot],
            );
            if attempts == 0 && success == 0 && failure == 0 && unknown == 0 {
                continue;
            }
            loads.push(LoadRow {
                name: name_at(slot),
                attempts,
                success,
                failure,
                unknown,
                candidates: success,
                tier: CandidateTier::Candidate,
            });
        }
        let mut queries = Vec::new();
        let mut operations: Vec<Operation> = reduced
            .query_outcome
            .keys()
            .map(|(operation, _)| *operation)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        operations.sort();
        for operation in operations {
            let side_counts = |side: QuerySide| {
                let counts = reduced
                    .query_outcome
                    .get(&(operation, side))
                    .copied()
                    .unwrap_or([0; 3]);
                let cache = reduced
                    .query_cache
                    .get(&(operation, side))
                    .copied()
                    .unwrap_or([0; 3]);
                QuerySideCounts {
                    success: counts[0],
                    failure: counts[1],
                    unknown: counts[2],
                    cacheable: cache[0],
                    volatile: cache[1],
                    cache_unknown: cache[2],
                }
            };
            queries.push(QueryRow {
                operation,
                wrapper: side_counts(QuerySide::Wrapper),
                callback: side_counts(QuerySide::Callback),
            });
        }
        let mut advertisements = Vec::new();
        for (operation, count) in &reduced.adverts {
            advertisements.push(AdvertRow {
                operation: *operation,
                count: *count,
                tier: CandidateTier::Candidate,
            });
        }
        RequestEvidence {
            version: REQUEST_EVIDENCE_VERSION,
            silence_window,
            fetches,
            fetch_coverage,
            loads,
            inits: reduced.inits,
            queries,
            advertisements,
            default_activation: if reduced.load_success[name_slot(ProviderNameClass::Default)] > 0 {
                ActivationState::LoadObserved
            } else {
                ActivationState::Unknown
            },
            unattributed: match scope.operational_entries {
                None => Unattributed::Unknown,
                // NEW-9-OPEN + NEW-16 fix5: an idle plane certifies
                // an observed zero only under a published nonempty
                // interval — interval-less idleness is Unknown.
                Some(0) if !certifies_zeros => Unattributed::Unknown,
                // No fetch→execution continuity is proved in Phase 1:
                // every observed operational entry is unattributed.
                Some(ops) => Unattributed::Observed { ops },
            },
        }
    }
}

/// NEW-27 fix7: the published schema requires an OBJECT when
/// `silence_window` is present — reject explicit `null` (it is
/// not omission) and every non-object shape (notably the
/// positional `[start, end]` array the derived reader used to
/// accept). Missing fields never reach here (`#[serde(default)]`
/// supplies `None`), so `None` below is always an explicit null.
fn de_optional_silence_window<'de, D: serde::Deserializer<'de>>(
    read: D,
) -> Result<Option<SilenceWindow>, D::Error> {
    use serde::de::{Error as _, MapAccess, Visitor};
    // NEW-33 fix8: decode the wire object DIRECTLY — never through
    // a `Value` round-trip (`Value::Object` is a map, so it
    // last-wins duplicate members that direct typed decoding
    // rejects). The map visitor preserves duplicate-field errors
    // alongside the NEW-27 shape rules (explicit null and every
    // non-object rejected; missing still omits via
    // `#[serde(default)]`, which never reaches here).
    struct OptVisitor;
    impl<'de> Visitor<'de> for OptVisitor {
        type Value = Option<SilenceWindow>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object with start_ns and end_ns")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Err(E::custom(
                "request_evidence.silence_window: explicit null is not omission — omit the field",
            ))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            self.visit_none()
        }
        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            inner: D2,
        ) -> Result<Self::Value, D2::Error> {
            inner.deserialize_map(SilenceVisitor).map(Some)
        }
    }
    struct SilenceVisitor;
    impl<'de> Visitor<'de> for SilenceVisitor {
        type Value = SilenceWindow;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object with start_ns and end_ns")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut start_ns: Option<u64> = None;
            let mut end_ns: Option<u64> = None;
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "start_ns" => {
                        if start_ns.is_some() {
                            return Err(A::Error::duplicate_field("start_ns"));
                        }
                        start_ns = Some(map.next_value()?);
                    }
                    "end_ns" => {
                        if end_ns.is_some() {
                            return Err(A::Error::duplicate_field("end_ns"));
                        }
                        end_ns = Some(map.next_value()?);
                    }
                    other => {
                        return Err(A::Error::unknown_field(other, &["start_ns", "end_ns"]));
                    }
                }
            }
            Ok(SilenceWindow {
                start_ns: start_ns.ok_or_else(|| A::Error::missing_field("start_ns"))?,
                end_ns: end_ns.ok_or_else(|| A::Error::missing_field("end_ns"))?,
            })
        }
    }
    read.deserialize_option(OptVisitor)
}

impl<'de> Deserialize<'de> for RequestEvidence {
    /// Strict shared read (GATE): unknown fields rejected, then
    /// [`RequestEvidence::validate_strict`] — the same validation
    /// the JSON semantic gate applies, so both read paths agree.
    fn deserialize<D: serde::Deserializer<'de>>(read: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: u32,
            #[serde(default, deserialize_with = "de_optional_silence_window")]
            silence_window: Option<SilenceWindow>,
            fetches: Vec<FetchRow>,
            fetch_coverage: Vec<FetchCoverageRow>,
            loads: Vec<LoadRow>,
            inits: OutcomeCounts,
            queries: Vec<QueryRow>,
            advertisements: Vec<AdvertRow>,
            default_activation: ActivationState,
            unattributed: Unattributed,
        }
        let wire = Wire::deserialize(read)?;
        let section = RequestEvidence {
            version: wire.version,
            silence_window: wire.silence_window,
            fetches: wire.fetches,
            fetch_coverage: wire.fetch_coverage,
            loads: wire.loads,
            inits: wire.inits,
            queries: wire.queries,
            advertisements: wire.advertisements,
            default_activation: wire.default_activation,
            unattributed: wire.unattributed,
        };
        section.validate_strict().map_err(D::Error::custom)?;
        Ok(section)
    }
}

impl RequestEvidence {
    /// True when the section claims a zero: an observed zero
    /// remainder or any covered-but-absent fetch surface
    /// (GATE-OPEN + NEW-16 fix5 — both need the published
    /// nonempty interval, in typed validation and the document
    /// gate alike).
    pub fn claims_zero(&self) -> bool {
        if matches!(self.unattributed, Unattributed::Observed { ops: 0 }) {
            return true;
        }
        let edged: std::collections::BTreeSet<u32> =
            self.fetches.iter().map(|row| row.surface_id).collect();
        self.fetch_coverage
            .iter()
            .any(|c| c.observed && !edged.contains(&c.surface_id))
    }

    /// Strict section validation (GATE, shared by the typed reader
    /// and the JSON semantic gate):
    /// - `version` is the Phase 1 section version (1);
    /// - fetch rows carry strictly increasing surface IDs (canonical
    ///   ID order, duplicates rejected; the export/capability binding
    ///   is enforced by [`FetchRow`]'s own deserialization, shape and
    ///   all — surface 78 is `decoder`, never an `evp` object) and no
    ///   row is all-zero (GATE-OPEN + NEW-22 fix6: the producer
    ///   never emits an edgeless row, so a present one is
    ///   fabricated — row presence never counts as an edge);
    /// - coverage holds exactly the 14 surfaces in ID order, and every
    ///   present fetch row is covered (rows imply observation);
    /// - load rows carry `candidates == success`, unique names in
    ///   canonical slot order, and `default_activation` agrees with
    ///   default success (manufactured activation rejected);
    /// - query/advert rows carry unique operations in canonical
    ///   (`Ord`) order, and every query side's outcome and
    ///   cacheability counts partition the same results (checked
    ///   arithmetic — overflow fails closed);
    /// - a published silence interval is nonempty (`start < end`
    ///   — NEW-9-OPEN + NEW-16 fix5, no silent empty intervals
    ///   anywhere; the document gate binds it inside the capture
    ///   window), and every zero claim rides one: an observed zero
    ///   remainder or any covered-but-absent surface without the
    ///   interval is rejected (fail closed). Batch + positive-only
    ///   evidence (no zeros) stays valid without one.
    ///
    /// Deliberately NOT checked: attempts vs results (unmatched
    /// attempt/result edges are legitimate — pairing is the trace
    /// plane's job, and forcing equality would reject honest windows).
    pub fn validate_strict(&self) -> Result<(), String> {
        if self.version != REQUEST_EVIDENCE_VERSION {
            return Err(format!(
                "request_evidence.version: expected {}, got {}",
                REQUEST_EVIDENCE_VERSION, self.version
            ));
        }
        // NEW-9-OPEN + NEW-16 fix5: a published silence interval is
        // nonempty (never inverted, never empty) — the document
        // gate additionally binds it inside the capture window.
        if let Some(silence) = self.silence_window {
            if silence.start_ns >= silence.end_ns {
                return Err(format!(
                    "request_evidence.silence_window: empty interval {}..{} certifies nothing",
                    silence.start_ns, silence.end_ns
                ));
            }
        }
        let mut previous: Option<u32> = None;
        for row in &self.fetches {
            if previous.is_some_and(|prev| row.surface_id <= prev) {
                return Err(format!(
                    "request_evidence.fetches: surface IDs must be strictly increasing ({} repeats or backtracks)",
                    row.surface_id
                ));
            }
            previous = Some(row.surface_id);
            // GATE-OPEN + NEW-22 fix6: an explicit all-zero fetch
            // row is fabricated (the producer never emits one —
            // projection skips edgeless surfaces), so row presence
            // must never count as an edge — reject it outright
            // (shared by both readers). Any single nonzero count
            // (a legitimate unmatched attempt OR result) still
            // passes — only the all-zero shape is refused.
            if row.attempts == 0 && row.success == 0 && row.failure == 0 && row.unknown == 0 {
                return Err(format!(
                    "request_evidence.fetches: surface {} carries an explicit all-zero row (fabricated — not positive evidence)",
                    row.surface_id
                ));
            }
        }
        if self.fetch_coverage.len() != FETCH_SURFACES.len() {
            return Err(format!(
                "request_evidence.fetch_coverage: expected {} rows, got {}",
                FETCH_SURFACES.len(),
                self.fetch_coverage.len()
            ));
        }
        for (coverage, surface) in self.fetch_coverage.iter().zip(FETCH_SURFACES.iter()) {
            if coverage.surface_id != surface.id {
                return Err(format!(
                    "request_evidence.fetch_coverage: expected surface {} in order, got {}",
                    surface.id, coverage.surface_id
                ));
            }
        }
        for row in &self.fetches {
            let covered = self
                .fetch_coverage
                .iter()
                .any(|c| c.surface_id == row.surface_id && c.observed);
            if !covered {
                return Err(format!(
                    "request_evidence.fetches: surface {} has a row but no coverage (rows imply observation)",
                    row.surface_id
                ));
            }
        }
        // GATE-OPEN + NEW-16 fix5: every zero claim rides a
        // published interval — without one it is rejected (fail
        // closed). (Presence here ⟹ nonempty by the check above.)
        if self.claims_zero() && self.silence_window.is_none() {
            return Err(
                "request_evidence: a zero claim (observed zero remainder or covered-but-absent surface) needs its published silence interval"
                    .to_string(),
            );
        }
        let mut previous_slot: Option<usize> = None;
        let mut default_success = 0u64;
        for row in &self.loads {
            if row.candidates != row.success {
                return Err(format!(
                    "request_evidence.loads: {:?} candidates {} != success {}",
                    row.name, row.candidates, row.success
                ));
            }
            let slot = name_slot(row.name);
            if previous_slot.is_some_and(|prev| slot <= prev) {
                return Err(format!(
                    "request_evidence.loads: names must be unique in canonical order ({:?} repeats or backtracks)",
                    row.name
                ));
            }
            previous_slot = Some(slot);
            if row.name == ProviderNameClass::Default {
                default_success = default_success.saturating_add(row.success);
            }
        }
        match (&self.default_activation, default_success) {
            (ActivationState::LoadObserved, 1..) | (ActivationState::Unknown, 0) => {}
            _ => {
                return Err(format!(
                    "request_evidence.default_activation: {:?} disagrees with default success {default_success}",
                    self.default_activation
                ));
            }
        }
        let mut previous_operation: Option<Operation> = None;
        for row in &self.queries {
            if previous_operation.is_some_and(|prev| row.operation <= prev) {
                return Err(format!(
                    "request_evidence.queries: operations must be unique in canonical order ({:?} repeats or backtracks)",
                    row.operation
                ));
            }
            previous_operation = Some(row.operation);
            for (label, side) in [("wrapper", &row.wrapper), ("callback", &row.callback)] {
                let outcomes = side
                    .success
                    .checked_add(side.failure)
                    .and_then(|n| n.checked_add(side.unknown))
                    .ok_or_else(|| {
                        format!(
                            "request_evidence.queries: {:?} {label} outcome overflow",
                            row.operation
                        )
                    })?;
                let cached = side
                    .cacheable
                    .checked_add(side.volatile)
                    .and_then(|n| n.checked_add(side.cache_unknown))
                    .ok_or_else(|| {
                        format!(
                            "request_evidence.queries: {:?} {label} cacheability overflow",
                            row.operation
                        )
                    })?;
                if outcomes != cached {
                    return Err(format!(
                        "request_evidence.queries: {:?} {label} outcomes {outcomes} != cacheability {cached} (unequal partitions of the same results)",
                        row.operation
                    ));
                }
            }
        }
        let mut previous_advert: Option<Operation> = None;
        for row in &self.advertisements {
            if previous_advert.is_some_and(|prev| row.operation <= prev) {
                return Err(format!(
                    "request_evidence.advertisements: operations must be unique in canonical order ({:?} repeats or backtracks)",
                    row.operation
                ));
            }
            previous_advert = Some(row.operation);
        }
        Ok(())
    }

    /// Single-batch fold (window folds use [`RequestEvidenceFold`]).
    /// The [`RequestScope`] carries what the producer observed (NEW-P1):
    /// per-batch folds pass [`RequestScope::batch`]. The single
    /// batch is emit-gated (a subset of the session-cumulative cap),
    /// so the journal cap cannot drop here — the debug assert
    /// tripwires that premise in test builds.
    pub fn fold(facts: &[ObservationFact], scope: RequestScope) -> Self {
        let mut fold = RequestEvidenceFold::default();
        fold.feed(facts);
        debug_assert_eq!(
            fold.journal_dropped(),
            0,
            "single emit-gated batches never reach the journal cap"
        );
        fold.finish(scope)
    }

    /// Production plane mapping (NEW-P1, single-sourced): the merged
    /// operational entry sum becomes an observed plane only when a
    /// successful scoped count read vouches for it (`scope_observed`)
    /// or positive entries exist (positives with gaps are preserved,
    /// never demoted). Refused attaches and failed terminal reads map
    /// to `None` (Unknown) — never a false observed zero.
    pub fn operational_plane(entries: u64, scope_observed: bool) -> Option<u64> {
        if scope_observed || entries > 0 {
            Some(entries)
        } else {
            None
        }
    }

    /// Focused-seal plane mapping (NEW-15 fix5): a mid-window fence
    /// voids the operational zero when it intersects the claimed
    /// interval (terminal readability is not observability across
    /// a counting cut — the fence stopped counting mid-window, so
    /// a terminal zero proves nothing about the cut span). Verified
    /// positives are retained (they prove themselves across the
    /// cut). Cuts are half-open `[edge, resume)` against the
    /// half-open claim — touching its edges excludes nothing.
    pub fn operational_plane_sealed(
        entries: u64,
        scope_observed: bool,
        fence_cuts: &[(u64, Option<u64>)],
        claim_start: u64,
        claim_end: u64,
    ) -> Option<u64> {
        let cut = fence_cuts.iter().any(|(edge, resume)| {
            *edge < claim_end && resume.is_none_or(|stop| stop > claim_start)
        });
        Self::operational_plane(entries, scope_observed && !cut)
    }

    /// True when the section carries no request rows and no observed
    /// remainder (per-batch renderers skip such sections).
    pub fn is_empty(&self) -> bool {
        self.fetches.is_empty()
            && self.loads.is_empty()
            && self.inits == OutcomeCounts::default()
            && self.queries.is_empty()
            && self.advertisements.is_empty()
            && matches!(self.unattributed, Unattributed::Unknown)
    }

    /// Stable human rendering (report/check/scan share this text).
    pub fn human_section(&self) -> String {
        let mut s = String::from(
            "request evidence (fetch/load/query are requests; fetch/load/query facts never mean the fetched object was used):\n",
        );
        // NEW-9: the narrower silence interval rides the human
        // block (window scope only) beside the capture-window
        // rows — zeros are claimed over this interval alone.
        if let Some(silence) = self.silence_window {
            s.push_str(&format!(
                "  silence window: {}..{}ns (zeros claimed over this interval only; request rows cover the published capture window)\n",
                silence.start_ns, silence.end_ns,
            ));
        }
        for row in &self.fetches {
            let capability = match row.capability {
                FetchCapability::Evp { operation } => format!("evp/{}", op_word(operation)),
                FetchCapability::Encoder => "encoder (selection is not an execution claim)".into(),
                FetchCapability::Decoder => "decoder (selection is not an execution claim)".into(),
                FetchCapability::StoreLoader => {
                    "store-loader (takes a scheme, not an algorithm)".into()
                }
            };
            s.push_str(&format!(
                "  fetch {} (id={}, {}): attempts={} success={} failure={} unknown={} properties=not_captured\n",
                row.export,
                row.surface_id,
                capability,
                row.attempts,
                row.success,
                row.failure,
                row.unknown,
            ));
        }
        // Coverage (NEW-P1): name the unobserved surfaces so an
        // absent row is never misread as an in-window zero.
        let unobserved: Vec<&str> = self
            .fetch_coverage
            .iter()
            .filter(|r| !r.observed)
            .filter_map(|r| FETCH_SURFACES.iter().find(|s| s.id == r.surface_id))
            .map(|s| s.export)
            .collect();
        if unobserved.is_empty() {
            s.push_str("  fetch coverage: all 14 surfaces observed\n");
        } else {
            s.push_str(&format!(
                "  fetch coverage: unobserved surfaces (absent rows are unknown, not zeros): {}\n",
                unobserved.join(", ")
            ));
        }
        for row in &self.loads {
            s.push_str(&format!(
                "  load {}: attempts={} success={} failure={} unknown={} candidates={} tier=candidate\n",
                name_word(row.name),
                row.attempts,
                row.success,
                row.failure,
                row.unknown,
                row.candidates,
            ));
        }
        if self.inits != OutcomeCounts::default() {
            s.push_str(&format!(
                "  init results: success={} failure={} unknown={}\n",
                self.inits.success, self.inits.failure, self.inits.unknown,
            ));
        }
        for row in &self.queries {
            // NEW-P4: wrapper and provider-callback results render
            // side by side, never collapsed.
            let side = |label: &str, counts: &QuerySideCounts| {
                format!(
                    "{label} success={} failure={} unknown={} cacheable={} volatile={} cache_unknown={}",
                    counts.success,
                    counts.failure,
                    counts.unknown,
                    counts.cacheable,
                    counts.volatile,
                    counts.cache_unknown,
                )
            };
            s.push_str(&format!(
                "  query {}: {}; {}\n",
                op_word(row.operation),
                side("wrapper", &row.wrapper),
                side("callback", &row.callback),
            ));
        }
        for row in &self.advertisements {
            s.push_str(&format!(
                "  advertised {}: algorithm_rows={} tier=candidate (a sole advertiser never proves execution)\n",
                op_word(row.operation),
                row.count,
            ));
        }
        match self.default_activation {
            ActivationState::LoadObserved => {
                s.push_str("  default provider activation: observed default-class load (explicit in-window genuine load success; candidate tier)\n");
            }
            ActivationState::Unknown => {
                s.push_str("  default provider activation: unknown (no explicit load observed in-window; silent auto-load or pre-attach load possible)\n");
            }
        }
        match self.unattributed {
            Unattributed::Unknown => {
                s.push_str(
                    "  unattributed operational entries: unknown (operational plane unobserved)\n",
                );
            }
            Unattributed::Observed { ops } => {
                s.push_str(&format!(
                    "  unattributed operational entries: {ops} (no fetch-to-execution continuity is proved in Phase 1; implicit one-shot/direct-init paths or pre-window fetches possible)\n",
                ));
            }
        }
        s
    }
}

/// Human word for an operation (mirrors the serde snake_case label).
fn op_word(operation: Operation) -> &'static str {
    match operation {
        Operation::Digest => "digest",
        Operation::Cipher => "cipher",
        Operation::Mac => "mac",
        Operation::Kdf => "kdf",
        Operation::Rand => "rand",
        Operation::Keymgmt => "keymgmt",
        Operation::Keyexch => "keyexch",
        Operation::Signature => "signature",
        Operation::AsymCipher => "asym_cipher",
        Operation::Kem => "kem",
        Operation::Skeymgmt => "skeymgmt",
        Operation::Encoder => "encoder",
        Operation::Decoder => "decoder",
        Operation::Store => "store",
        Operation::Other => "other",
    }
}

/// Human word for a provider name class (mirrors serde).
fn name_word(name: ProviderNameClass) -> &'static str {
    match name {
        ProviderNameClass::Default => "default",
        ProviderNameClass::Legacy => "legacy",
        ProviderNameClass::Fips => "fips",
        ProviderNameClass::Other => "other",
        ProviderNameClass::Unreadable => "unreadable",
        ProviderNameClass::Overlong => "overlong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn attempt_fact(api: InvApi, monotonic_ns: u64) -> ObservationFact {
        ObservationFact {
            pid: 1,
            starttime: 1,
            object_sha256: "b".repeat(64).try_into().unwrap(),
            generation: 1,
            context: super::super::schema::ContextIdentity::Unknown {},
            source: super::super::schema::ObservationSource::PublicApi,
            api: ObservationApi::Inventoried(api),
            operation: Operation::Other,
            class: super::super::schema::AlgorithmClass::Other,
            monotonic_ns,
            confidence: super::super::schema::ScopeConfidence::Observed,
            payload: ObservationPayload::ApiAttempt {
                name: ProviderNameClass::Other,
            },
        }
    }

    fn result_fact(api: InvApi, outcome: ApiOutcome, monotonic_ns: u64) -> ObservationFact {
        let mut fact = attempt_fact(api, monotonic_ns);
        fact.payload = ObservationPayload::ApiResult {
            name: ProviderNameClass::Other,
            outcome,
        };
        fact
    }

    fn all_surface_ids() -> BTreeSet<u32> {
        FETCH_SURFACES.iter().map(|s| s.id).collect()
    }

    fn init_fact(api: InvApi, outcome: ApiOutcome, monotonic_ns: u64) -> ObservationFact {
        let mut fact = attempt_fact(api, monotonic_ns);
        fact.source = super::super::schema::ObservationSource::ProviderInit;
        fact.payload = ObservationPayload::InitResult { outcome };
        fact
    }

    fn observed_scope() -> RequestScope {
        RequestScope {
            operational_entries: Some(0),
            fetch_armed: all_surface_ids(),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        }
    }

    fn section_json(evidence: &RequestEvidence) -> serde_json::Value {
        serde_json::to_value(evidence).unwrap()
    }

    // GATE RED: the typed reader shares strict validation — a
    // hand-edited section with inconsistent counts is rejected,
    // never parsed (candidates != success).
    #[test]
    fn typed_reader_rejects_inconsistent_load_counts() {
        let mut load_attempt = attempt_fact(InvApi::OsslProviderLoad, 10);
        load_attempt.payload = ObservationPayload::ApiAttempt {
            name: ProviderNameClass::Default,
        };
        let mut load_result = result_fact(InvApi::OsslProviderLoad, ApiOutcome::Success, 11);
        load_result.payload = ObservationPayload::ApiResult {
            name: ProviderNameClass::Default,
            outcome: ApiOutcome::Success,
        };
        let evidence = RequestEvidence::fold(&[load_attempt, load_result], observed_scope());
        let mut json = section_json(&evidence);
        json["loads"][0]["candidates"] = serde_json::json!(2);
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "candidates != success must not parse"
        );
    }

    // GATE RED: manufactured activation is rejected by the typed reader.
    #[test]
    fn typed_reader_rejects_manufactured_activation() {
        let evidence = RequestEvidence::fold(&[], observed_scope());
        let mut json = section_json(&evidence);
        json["default_activation"] = serde_json::json!("load_observed");
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "activation without default success must not parse"
        );
    }

    // GATE RED: unequal query partitions are rejected (per side,
    // outcomes and cacheability partition the same results).
    #[test]
    fn typed_reader_rejects_unequal_query_partitions() {
        let facts = vec![query_fact(
            ObservationApi::Inventoried(InvApi::OsslProviderQueryOperation),
            ApiOutcome::Success,
            super::super::schema::Cacheability::Cacheable,
            Operation::Digest,
            10,
        )];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        let mut json = section_json(&evidence);
        json["queries"][0]["wrapper"]["cacheable"] = serde_json::json!(2);
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "outcome/cache partition mismatch must not parse"
        );
    }

    // GATE RED: duplicate fetch IDs are rejected by the typed reader.
    #[test]
    fn typed_reader_rejects_duplicate_fetch_ids() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        let mut json = section_json(&evidence);
        let row = json["fetches"][0].clone();
        json["fetches"].as_array_mut().unwrap().push(row);
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "duplicate fetch IDs must not parse"
        );
    }

    // GATE RED: the wrong capability SHAPE is rejected even when the
    // operation word matches (surface 78 is `decoder`, never an
    // `evp` object — the current producer trigger for this shape).
    #[test]
    fn typed_reader_rejects_wrong_capability_shape() {
        let facts = vec![
            attempt_fact(InvApi::OsslDecoderFetch, 10),
            result_fact(InvApi::OsslDecoderFetch, ApiOutcome::Success, 11),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        let mut json = section_json(&evidence);
        json["fetches"][0]["capability"] = serde_json::json!({"evp": {"operation": "decoder"}});
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "surface 78 with an evp object must not parse"
        );
    }

    // GATE-OPEN RED: extra fields inside the `Observed` variant are
    // rejected (deny-unknown-fields throughout the section — the
    // remainder must not discard smuggled fields either).
    #[test]
    fn typed_reader_rejects_unattributed_extra_fields() {
        // GATE-OPEN + NEW-16 fix5: the Observed-zero base needs its
        // windowed interval (interval-less zeros no longer certify).
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(100);
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 0 });
        let mut json = section_json(&evidence);
        json["unattributed"] = serde_json::json!({"observed": {"ops": 0, "smuggled": 1}});
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "unattributed extra fields must not parse"
        );
    }

    // GATE RED: extra fields inside the capability object are rejected
    // (struct variants must not discard unknown fields).
    #[test]
    fn typed_reader_rejects_capability_extra_fields() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        let mut json = section_json(&evidence);
        json["fetches"][0]["capability"] =
            serde_json::json!({"evp": {"operation": "digest", "smuggled": 1}});
        assert!(
            serde_json::from_value::<RequestEvidence>(json).is_err(),
            "capability extra fields must not parse"
        );
    }

    // GATE guard: legitimate unmatched attempt/result edges still parse
    // (attempts == results is NEVER forced).
    #[test]
    fn typed_reader_accepts_unmatched_attempt_result_edges() {
        let facts = vec![attempt_fact(InvApi::EvpMdFetch, 10)];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        let json = section_json(&evidence);
        let back: RequestEvidence = serde_json::from_value(json).expect("unmatched edges parse");
        assert_eq!(back.fetches[0].attempts, 1);
        assert_eq!(back.fetches[0].success, 0);
    }

    // GATE-OPEN + NEW-22 fix6 RED: an explicit all-zero fetch row
    // (attempts/success/failure/unknown all 0, observed coverage)
    // is NOT positive evidence — the producer never emits one (its
    // projection skips edgeless surfaces), so a present one is
    // fabricated and both readers reject it (shared strict
    // validation). The boundary is exact: any single nonzero count
    // (a legitimate unmatched attempt OR result) still parses.
    #[test]
    fn typed_reader_rejects_all_zero_fetch_rows() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert_eq!(evidence.fetches.len(), 1);
        // Fabricated twin: every count zeroed, coverage still observed.
        let mut zero = section_json(&evidence);
        zero["fetches"][0]["attempts"] = serde_json::json!(0);
        zero["fetches"][0]["success"] = serde_json::json!(0);
        zero["fetches"][0]["failure"] = serde_json::json!(0);
        zero["fetches"][0]["unknown"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<RequestEvidence>(zero).is_err(),
            "an explicit all-zero fetch row must not parse"
        );
        // The shared validator convicts the same shape directly.
        let mut direct = evidence.clone();
        direct.fetches[0].attempts = 0;
        direct.fetches[0].success = 0;
        direct.fetches[0].failure = 0;
        direct.fetches[0].unknown = 0;
        assert!(
            direct.validate_strict().is_err(),
            "validate_strict must reject an explicit all-zero fetch row"
        );
        // Boundary: one nonzero count (unmatched result) still parses.
        let mut survivor = section_json(&evidence);
        survivor["fetches"][0]["attempts"] = serde_json::json!(0);
        survivor["fetches"][0]["failure"] = serde_json::json!(0);
        survivor["fetches"][0]["unknown"] = serde_json::json!(0);
        assert_eq!(survivor["fetches"][0]["success"], serde_json::json!(1));
        let back: RequestEvidence =
            serde_json::from_value(survivor).expect("an unmatched result still parses");
        assert_eq!(back.fetches[0].success, 1);
    }

    // NEW-27 fix7 RED: the published schema requires an OBJECT when
    // `silence_window` is present — a positional `[start, end]`
    // array and an explicit `null` (where omission is legal) are
    // both rejected, while omission and the object shape parse.
    // (The JSON semantic gate shares this read, so one pin here
    // plus the document-gate twin covers both readers.)
    #[test]
    fn typed_reader_enforces_object_silence_window() {
        // Non-zero batch scope: omission is legal here, so the
        // rejections below convict the SHAPE, never a missing
        // interval.
        let evidence = RequestEvidence::fold(&[], RequestScope::batch());
        assert_eq!(evidence.silence_window, None);
        // Omission parses (the producer's per-batch shape).
        let omitted = section_json(&evidence);
        assert!(
            omitted.get("silence_window").is_none(),
            "premise: batch scope omits the interval"
        );
        let back: RequestEvidence = serde_json::from_value(omitted).expect("omission parses");
        assert_eq!(back.silence_window, None);
        // Explicit null is rejected (it is not omission).
        let mut nulled = section_json(&evidence);
        nulled["silence_window"] = serde_json::json!(null);
        assert!(
            serde_json::from_value::<RequestEvidence>(nulled).is_err(),
            "an explicit null silence_window must not parse"
        );
        // A positional array is rejected (the schema needs an object).
        let mut arrayed = section_json(&evidence);
        arrayed["silence_window"] = serde_json::json!([100, 200]);
        assert!(
            serde_json::from_value::<RequestEvidence>(arrayed).is_err(),
            "a positional silence_window array must not parse"
        );
        // The object shape parses (the producer's windowed shape).
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(100);
        let windowed = RequestEvidence::fold(&[], scope);
        let shape = windowed.silence_window.expect("windowed seal publishes");
        assert_eq!((shape.start_ns, shape.end_ns), (100, 200));
        let back: RequestEvidence =
            serde_json::from_value(section_json(&windowed)).expect("the object shape parses");
        assert_eq!(back.silence_window, Some(shape));
        // NEW-33 fix8: raw-text duplicate members are rejected —
        // the decode must see the wire object (with its
        // duplicates), never a collapsed `Value` round-trip (which
        // last-wins them away). Splice the duplicate into the
        // serialized silence object (flat `{start,end}` — the
        // first `}` after its start closes it). NEW-33-OPEN fix9:
        // the replacements are otherwise-valid (the same start/end
        // the section already carries — a collapsed read stays
        // valid), and BOTH rejections must be duplicate-field
        // errors — a start-after-end value with a generic error
        // assertion would pass without duplicate detection (the
        // empty-interval rule convicts it instead).
        let raw = serde_json::to_string(&section_json(&windowed)).expect("section serializes");
        let key = "\"silence_window\":{";
        let at = raw
            .find(key)
            .expect("premise: the windowed section carries its silence object")
            + key.len();
        let rel = raw[at..]
            .find('}')
            .expect("premise: the flat silence object closes");
        let mut dup_start = raw.clone();
        dup_start.insert_str(at + rel, ",\"start_ns\":100");
        let err = serde_json::from_str::<RequestEvidence>(&dup_start)
            .expect_err("a duplicated start_ns must not parse");
        assert!(
            err.to_string().contains("duplicate field `start_ns`"),
            "the start rejection is a duplicate-field error: {err}"
        );
        let mut dup_end = raw.clone();
        dup_end.insert_str(at + rel, ",\"end_ns\":200");
        let err = serde_json::from_str::<RequestEvidence>(&dup_end)
            .expect_err("a duplicated end_ns must not parse");
        assert!(
            err.to_string().contains("duplicate field `end_ns`"),
            "the end rejection is a duplicate-field error: {err}"
        );
    }

    // NEW-16 + NEW-20 fix6 RED: a windowed scope WITHOUT an
    // established silence claim (`silence_start: None` — the seal's
    // unestablished shape) publishes NO silence interval and
    // certifies no zeros — armed-but-edgeless surfaces read
    // unknown and an idle plane reads Unknown — while genuine
    // positives still project (rows + observed remainder, never
    // demoted).
    #[test]
    fn windowed_scope_without_silence_claims_no_interval() {
        let scope = RequestScope {
            operational_entries: Some(0),
            fetch_armed: all_surface_ids(),
            window: Some((100, 200)),
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(
            evidence.silence_window, None,
            "an unestablished window publishes no silence interval"
        );
        assert_eq!(
            evidence.unattributed,
            Unattributed::Unknown,
            "an unestablished idle plane is Unknown"
        );
        for row in &evidence.fetch_coverage {
            assert!(
                !row.observed,
                "unestablished armed surface {} reads unknown",
                row.surface_id
            );
        }
        evidence
            .validate_strict()
            .expect("interval-less zero-free evidence validates");
        // Positives are preserved: rows project, remainders observe.
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 110),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 111),
        ];
        let scope = RequestScope {
            operational_entries: Some(3),
            fetch_armed: all_surface_ids(),
            window: Some((100, 200)),
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&facts, scope);
        assert_eq!(evidence.silence_window, None);
        assert_eq!(evidence.fetches.len(), 1, "the positive row projects");
        assert_eq!(evidence.fetches[0].attempts, 1);
        assert_eq!(
            evidence.unattributed,
            Unattributed::Observed { ops: 3 },
            "the positive remainder is observed"
        );
    }

    // NEW-P2 RED: the focused window bounds projection — edges
    // outside [start, end] (pre-window strays, post-deadline edges
    // from the closing drain) never enter the section.
    #[test]
    fn window_bounds_projection_both_directions() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 5),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 6),
            attempt_fact(InvApi::EvpMdFetch, 50),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 51),
            attempt_fact(InvApi::EvpMdFetch, 500),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 501),
        ];
        let mut scope = observed_scope();
        scope.window = Some((10, 100));
        let evidence = RequestEvidence::fold(&facts, scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (1, 1),
            "only the in-window pair projects"
        );
    }

    // NEW-P2 RED: a late incarnation fence retracts already-fed facts
    // (the fold journals timestamped edges and replays at projection,
    // so fence arrival order never matters).
    #[test]
    fn late_fence_retracts_already_fed_facts() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 20),
            attempt_fact(InvApi::EvpMdFetch, 30),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 40),
        ];
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(25, None)];
        let evidence = fold.finish(scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (1, 1),
            "post-fence edges are wrong-incarnation"
        );
    }

    // NEW-P2-OPEN RED: replay uses the SAME exclusive upper cut as
    // the producer (`now >= window.end` is closed) and the live
    // consumer (`monotonic_ns >= edge` withholds) at BOTH the
    // deadline and the fence. The lower bound stays inclusive
    // (`now < window.start` is closed — an edge exactly at start
    // is in-window).
    #[test]
    fn replay_uses_exclusive_upper_cuts_at_deadline_and_fence() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 99),
            attempt_fact(InvApi::EvpMdFetch, 100),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 101),
        ];
        let mut scope = observed_scope();
        scope.window = Some((10, 100));
        let evidence = RequestEvidence::fold(&facts, scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (1, 1),
            "start admitted, deadline excluded (exclusive upper cut)"
        );
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 24),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 25),
            attempt_fact(InvApi::EvpMdFetch, 26),
        ];
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(25, None)];
        let evidence = fold.finish(scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (1, 0),
            "fence edge excluded like the live consumer (ts >= edge)"
        );
    }

    // NEW-5 RED: the journal caps at the production fact cap —
    // past-cap edges drop with a visible count (never silent), so
    // close replay is bounded work over at most `journal_cap()`
    // edges and the reservation covers the worst case.
    #[test]
    fn journal_caps_at_production_fact_cap_and_counts_dropped() {
        let cap = RequestEvidenceFold::journal_cap();
        assert_eq!(
            cap,
            super::super::schema::ObservationLimits::default().max_facts,
            "the journal cap IS the production fact cap (single-sourced)"
        );
        let facts: Vec<ObservationFact> = (0..(cap + 10) as u64)
            .map(|ts| attempt_fact(InvApi::EvpMdFetch, ts))
            .collect();
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        assert_eq!(fold.journal_len(), cap, "journal stops at the cap");
        assert_eq!(fold.journal_dropped(), 10, "past-cap drops stay visible");
        assert_eq!(fold.take_journal_dropped(), 10, "drained once");
        assert_eq!(fold.journal_dropped(), 0, "drain resets the count");
        // Bounded replay: projection completes over exactly the
        // capped journal with exact counts.
        let evidence = fold.finish(observed_scope());
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(row.attempts, cap as u64);
    }

    // NEW-5 RED: the reservation covers a worst-case (full-cap)
    // journal — the focused session lease holds it for the session
    // lifetime (idle reclamation cannot release what it never
    // charged because the lease, not the budget, carries it).
    #[test]
    fn journal_reserve_covers_full_cap_journal() {
        let cap = RequestEvidenceFold::journal_cap();
        assert_eq!(
            RequestEvidenceFold::journal_reserve_bytes(),
            cap.saturating_mul(JOURNAL_EDGE_BYTES).saturating_add(32),
            "reserve == full-cap edges + Vec slack (exact)"
        );
        assert!(
            cap.saturating_mul(JOURNAL_EDGE_BYTES) <= RequestEvidenceFold::journal_reserve_bytes(),
            "a full-cap journal fits its reserve"
        );
    }

    // NEW-2 pin: suspension + recovery with valid facts on BOTH
    // sides — the sealed cut `(edge, resume)` excludes exactly the
    // uncertain interval `[edge, resume)`. Pre-edge facts project,
    // uncertain-interval facts (fed before the fence arrived) stay
    // excluded after the recovery drain, and post-recovery facts
    // (`>= resume`) project again. The resume bound is exclusive
    // like every other upper cut (an edge exactly at resume is IN).
    #[test]
    fn sealed_cut_excludes_uncertain_interval_across_recovery() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 20),
            attempt_fact(InvApi::EvpMdFetch, 30),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 40),
            attempt_fact(InvApi::EvpMdFetch, 50),
            attempt_fact(InvApi::EvpMdFetch, 60),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 70),
        ];
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(25, Some(60))];
        let evidence = fold.project(&scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (2, 2),
            "pre-edge pair + resume-edge pair project; the uncertain triple stays excluded"
        );
        // A second fence cycle appends (union): neither cycle's
        // uncertain facts resurrect.
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(25, Some(60)), (65, None)];
        let evidence = fold.project(&scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (2, 1),
            "the open second cycle retracts the post-70 tail (70 excluded, 60 kept)"
        );
    }

    // NEW-11 fix4: replay excludes the cuts' UNION whatever their
    // recorded order — a backdated cut (later recorded, earlier
    // start) and overlapping cuts exclude exactly their spans.
    // Regression guard beside the compaction pin: replay matches
    // cuts by containment (order-free), so the merged span and the
    // raw cuts exclude the same edges.
    #[test]
    fn replay_excludes_backdated_and_overlapping_cuts() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 5),
            attempt_fact(InvApi::EvpMdFetch, 15),
            attempt_fact(InvApi::EvpMdFetch, 25),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 35),
            attempt_fact(InvApi::EvpMdFetch, 45),
        ];
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        // Backdated: `[20,30)` recorded BEFORE `[10,40)`.
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(20, Some(30)), (10, Some(40))];
        let evidence = fold.project(&scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (2, 0),
            "only the pre/post edges project; the backdated union [10,40) stays excluded"
        );
        // Overlapping: `[(10,20),(15,25)]` excludes `[10,25)`.
        let mut scope = observed_scope();
        scope.fence_cuts = vec![(10, Some(20)), (15, Some(25))];
        let evidence = fold.project(&scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (3, 1),
            "5/25/35/45 project; 15 stays excluded by the overlap"
        );
    }

    // NEW-9 fix4: the window is the PUBLISHED capture window —
    // genuine setup-prefix edges (before effective admission)
    // project as rows (positives), while the narrower silence
    // interval (from effective admission) is published in BOTH
    // formats beside them. The scope below is the seal's shape:
    // `window` = capture, `silence_start` = effective admission.
    #[test]
    fn capture_window_preserves_prefix_edges_and_publishes_silence() {
        let facts = vec![
            // Setup-prefix pair (genuine, pre-admission): PRESERVED.
            attempt_fact(InvApi::EvpMdFetch, 110),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 120),
            // Silence-interval pair: projects.
            attempt_fact(InvApi::EvpMdFetch, 160),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 170),
            // Post-deadline edge: excluded (exclusive upper cut).
            attempt_fact(InvApi::EvpMdFetch, 200),
        ];
        let mut fold = RequestEvidenceFold::default();
        fold.feed(&facts);
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(150);
        let evidence = fold.project(&scope);
        let row = evidence
            .fetches
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md row");
        assert_eq!(
            (row.attempts, row.success),
            (2, 2),
            "prefix + silence pairs project; only the post-deadline edge is cut"
        );
        assert_eq!(
            evidence.silence_window,
            Some(SilenceWindow {
                start_ns: 150,
                end_ns: 200
            }),
            "the narrower silence interval rides the section"
        );
        // JSON format carries it.
        let json = section_json(&evidence);
        assert_eq!(json["silence_window"]["start_ns"], 150);
        assert_eq!(json["silence_window"]["end_ns"], 200);
        // Human format carries it (exact line, beside the rows).
        let human = evidence.human_section();
        assert!(
            human.contains(
                "silence window: 150..200ns (zeros claimed over this interval only; request rows cover the published capture window)"
            ),
            "human exposes the silence interval:\n{human}"
        );
        // Batch scope (no window) claims no silence in either format.
        let batch = RequestEvidence::fold(&facts, RequestScope::batch());
        assert_eq!(batch.silence_window, None);
        assert!(
            section_json(&batch).get("silence_window").is_none(),
            "batch JSON omits the silence key"
        );
        assert!(
            !batch.human_section().contains("silence window:"),
            "batch human omits the silence line"
        );
    }

    // NEW-P3 RED: `OSSL_PROVIDER_add_builtin` registers an initializer
    // (provider.c) — registration is not a load. Its ATTEMPT/RESULT
    // edges must not feed loads/activation, and its registration INIT
    // record is not an init callback either.
    #[test]
    fn registration_only_feeds_no_loads_or_inits() {
        let facts = vec![
            attempt_fact(InvApi::OsslProviderAddBuiltin, 10),
            result_fact(InvApi::OsslProviderAddBuiltin, ApiOutcome::Success, 11),
            init_fact(InvApi::OsslProviderAddBuiltin, ApiOutcome::Success, 12),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert!(evidence.loads.is_empty(), "registration is not a load");
        assert_eq!(evidence.default_activation, ActivationState::Unknown);
        assert_eq!(
            evidence.inits,
            OutcomeCounts::default(),
            "registration is not an init callback"
        );
    }

    // NEW-P3 RED: `OSSL_provider_get0_dispatch` is a table getter —
    // its INIT record must not feed init counts.
    #[test]
    fn getter_only_feeds_no_inits() {
        let facts = vec![init_fact(
            InvApi::OsslProviderGet0Dispatch,
            ApiOutcome::Success,
            10,
        )];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert_eq!(evidence.inits, OutcomeCounts::default());
    }

    fn query_fact(
        api: ObservationApi,
        outcome: ApiOutcome,
        cacheability: super::super::schema::Cacheability,
        operation: Operation,
        monotonic_ns: u64,
    ) -> ObservationFact {
        let mut fact = attempt_fact(InvApi::EvpMdFetch, monotonic_ns);
        fact.api = api;
        fact.operation = operation;
        fact.source = super::super::schema::ObservationSource::ProviderQuery;
        fact.payload = ObservationPayload::QueryResult {
            outcome,
            cacheability,
        };
        fact
    }

    fn algorithm_fact(operation: Operation, monotonic_ns: u64) -> ObservationFact {
        let mut fact = attempt_fact(InvApi::EvpMdFetch, monotonic_ns);
        fact.api = ObservationApi::ProviderQueryCallback;
        fact.operation = operation;
        fact.source = super::super::schema::ObservationSource::ProviderQuery;
        fact.payload = ObservationPayload::Algorithm {
            algorithm: super::super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
            alias_quality: super::super::schema::AliasQuality::default(),
            cacheability: super::super::schema::Cacheability::Cacheable,
        };
        fact
    }

    fn implementation_fact(
        operation: Operation,
        function: u32,
        monotonic_ns: u64,
    ) -> ObservationFact {
        let mut fact = attempt_fact(InvApi::EvpMdFetch, monotonic_ns);
        fact.api = ObservationApi::ProviderQueryCallback;
        fact.operation = operation;
        fact.source = super::super::schema::ObservationSource::ProviderDispatch;
        fact.payload = ObservationPayload::Implementation {
            algorithm: super::super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
            alias_quality: super::super::schema::AliasQuality::default(),
            function: super::super::schema::FunctionIdentity::new(operation, function).unwrap(),
            cacheability: super::super::schema::Cacheability::Cacheable,
            advertiser_candidates: Vec::new(),
            backing_sha256: None,
        };
        fact
    }

    // NEW-P4 RED: the advertisement unit is the algorithm row — a
    // table with one algorithm and three emitted dispatch functions
    // reports ONE entry, not four.
    #[test]
    fn adverts_count_algorithm_rows_not_dispatch_facts() {
        let facts = vec![
            algorithm_fact(Operation::Digest, 10),
            implementation_fact(Operation::Digest, 1, 11),
            implementation_fact(Operation::Digest, 2, 12),
            implementation_fact(Operation::Digest, 3, 13),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert_eq!(evidence.advertisements.len(), 1);
        assert_eq!(evidence.advertisements[0].operation, Operation::Digest);
        assert_eq!(
            evidence.advertisements[0].count, 1,
            "one algorithm row, not 1+3 dispatch facts"
        );
    }

    // NEW-P4 RED: wrapper and provider-callback query results are
    // distinguished in BOTH formats (one traversal observed at two
    // layers must not collapse into one count).
    #[test]
    fn queries_split_wrapper_and_callback_in_both_formats() {
        let facts = vec![
            query_fact(
                ObservationApi::Inventoried(InvApi::OsslProviderQueryOperation),
                ApiOutcome::Success,
                super::super::schema::Cacheability::Cacheable,
                Operation::Digest,
                10,
            ),
            query_fact(
                ObservationApi::ProviderQueryCallback,
                ApiOutcome::Success,
                super::super::schema::Cacheability::Cacheable,
                Operation::Digest,
                11,
            ),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert_eq!(evidence.queries.len(), 1);
        let row = &evidence.queries[0];
        assert_eq!(row.operation, Operation::Digest);
        assert_eq!(row.wrapper.success, 1, "public wrapper result");
        assert_eq!(row.callback.success, 1, "provider callback result");
        assert_eq!(row.wrapper.cacheable, 1);
        assert_eq!(row.callback.cacheable, 1);
        let json = serde_json::to_value(&evidence).unwrap();
        let qrow = &json["queries"][0];
        assert_eq!(qrow["wrapper"]["success"], 1);
        assert_eq!(qrow["callback"]["success"], 1);
        let human = evidence.human_section();
        assert!(human.contains("wrapper"), ":\n{human}");
        assert!(human.contains("callback"), ":\n{human}");
    }

    // NEW-P3 RED: genuine loads feed loads + activation, and actual
    // init callbacks feed inits. The human positive state is an
    // observed default-class load.
    #[test]
    fn genuine_load_and_init_feed_loads_activation_and_inits() {
        let mut load_attempt = attempt_fact(InvApi::OsslProviderLoad, 10);
        load_attempt.payload = ObservationPayload::ApiAttempt {
            name: ProviderNameClass::Default,
        };
        let mut load_result = result_fact(InvApi::OsslProviderLoad, ApiOutcome::Success, 11);
        load_result.payload = ObservationPayload::ApiResult {
            name: ProviderNameClass::Default,
            outcome: ApiOutcome::Success,
        };
        let facts = vec![
            load_attempt,
            load_result,
            init_fact(InvApi::OsslProviderInit, ApiOutcome::Success, 12),
        ];
        let evidence = RequestEvidence::fold(&facts, observed_scope());
        assert_eq!(evidence.loads.len(), 1);
        assert_eq!(evidence.loads[0].success, 1);
        assert_eq!(evidence.loads[0].candidates, 1);
        assert_eq!(evidence.default_activation, ActivationState::LoadObserved);
        assert_eq!(evidence.inits.success, 1);
        let human = evidence.human_section();
        assert!(
            human.contains("observed default-class load"),
            "human positive state renamed:\n{human}"
        );
    }

    // NEW-P1 RED: a refused attach observes no population — the
    // remainder is Unknown (never an observed zero) and every
    // surface is uncovered (absent rows are unknown, not zeros).
    #[test]
    fn refused_attach_yields_unknown_plane_and_coverage() {
        let scope = RequestScope {
            operational_entries: None,
            fetch_armed: BTreeSet::new(),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(evidence.unattributed, Unattributed::Unknown);
        assert!(evidence.fetches.is_empty());
        assert_eq!(evidence.fetch_coverage.len(), 14);
        for row in &evidence.fetch_coverage {
            assert!(!row.observed, "surface {} uncovered", row.surface_id);
        }
    }

    // NEW-P1 RED: failed terminal reads observe no population either
    // (the production plane maps no-successful-read to None).
    #[test]
    fn failed_terminal_reads_yield_unknown_plane() {
        assert_eq!(RequestEvidence::operational_plane(0, false), None);
        let scope = RequestScope {
            operational_entries: RequestEvidence::operational_plane(0, false),
            fetch_armed: BTreeSet::new(),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(evidence.unattributed, Unattributed::Unknown);
    }

    // NEW-P1 RED: armed idle is a genuine observed zero — plane
    // Some(0) with full coverage — and stays that way (positives
    // with gaps are preserved, never demoted).
    #[test]
    fn armed_idle_yields_observed_zero_plane_and_coverage() {
        assert_eq!(
            RequestEvidence::operational_plane(0, true),
            Some(0),
            "armed idle is an observed zero"
        );
        assert_eq!(
            RequestEvidence::operational_plane(5, false),
            Some(5),
            "positives survive without a scope receipt"
        );
        assert_eq!(RequestEvidence::operational_plane(5, true), Some(5));
        // GATE-OPEN + NEW-16 fix5: armed idle certifies its zeros
        // only under a published nonempty interval.
        let scope = RequestScope {
            operational_entries: RequestEvidence::operational_plane(0, true),
            fetch_armed: all_surface_ids(),
            window: Some((100, 200)),
            silence_start: Some(100),
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(
            evidence.silence_window,
            Some(SilenceWindow {
                start_ns: 100,
                end_ns: 200
            }),
            "armed idle publishes its interval"
        );
        assert_eq!(evidence.unattributed, Unattributed::Observed { ops: 0 });
        assert!(evidence.fetches.is_empty());
        for row in &evidence.fetch_coverage {
            assert!(row.observed, "surface {} armed", row.surface_id);
        }
        assert_eq!(evidence.default_activation, ActivationState::Unknown);
    }

    // NEW-P1 RED: mixed coverage — the armed surface with edges is
    // observed; absent unarmed surfaces are unknown (covered=false),
    // never in-window zeros.
    #[test]
    fn mixed_coverage_marks_absent_unarmed_unknown() {
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
        ];
        let scope = RequestScope {
            operational_entries: Some(0),
            fetch_armed: BTreeSet::from([10]),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&facts, scope);
        assert_eq!(evidence.fetches.len(), 1);
        assert_eq!(evidence.fetches[0].surface_id, 10);
        assert_eq!(evidence.fetch_coverage.len(), 14);
        for row in &evidence.fetch_coverage {
            assert_eq!(
                row.observed,
                row.surface_id == 10,
                "only surface 10 covered: {}",
                row.surface_id
            );
        }
    }

    // NEW-P1 RED: edges are observation evidence — a surface with
    // edges is covered even when the arm set missed it (late arm).
    #[test]
    fn edges_observe_surface_by_evidence() {
        let facts = vec![
            attempt_fact(InvApi::EvpRandFetch, 10),
            result_fact(InvApi::EvpRandFetch, ApiOutcome::Success, 11),
        ];
        let scope = RequestScope {
            operational_entries: Some(0),
            fetch_armed: BTreeSet::new(),
            window: None,
            silence_start: None,
            silence_end: None,
            fence_cuts: Vec::new(),
        };
        let evidence = RequestEvidence::fold(&facts, scope);
        let row = evidence
            .fetch_coverage
            .iter()
            .find(|r| r.surface_id == 76)
            .expect("rand coverage row");
        assert!(row.observed, "edges prove observation");
        assert_eq!(evidence.fetches.len(), 1);
    }

    #[test]
    fn surfaces_match_wire_ids_and_spellings() {
        // P1-A1: the fold table agrees with the wire decode table —
        // every surface ID decodes to its inventory identity.
        for surface in FETCH_SURFACES {
            let decoded = super::super::wire::api(surface.id).expect("wire id");
            assert_eq!(decoded, ObservationApi::Inventoried(surface.api));
            assert_eq!(decoded.export_name(), Some(surface.export));
        }
        // ... and the wire fetch range holds nothing else.
        for id in [9, 16, 19, 20, 72] {
            let decoded = super::super::wire::api(id).expect("wire id");
            assert!(
                !matches!(decoded, ObservationApi::Inventoried(api) if surface_for(api).is_some()),
                "id {id}"
            );
        }
        assert_eq!(
            super::super::wire::api(81),
            Err(super::super::schema::ObservationGap::InvalidWire)
        );
    }

    #[test]
    fn load_attempts_join_their_named_row() {
        // Load ATTEMPT edges carry the classified provider name
        // (the BPF status word): attempts join name-class rows.
        let attempt = ObservationFact {
            pid: 1,
            starttime: 1,
            object_sha256: "b".repeat(64).try_into().unwrap(),
            generation: 1,
            context: super::super::schema::ContextIdentity::Unknown {},
            source: super::super::schema::ObservationSource::PublicApi,
            api: ObservationApi::Inventoried(InvApi::OsslProviderLoad),
            operation: Operation::Other,
            class: super::super::schema::AlgorithmClass::Other,
            monotonic_ns: 1,
            confidence: super::super::schema::ScopeConfidence::Observed,
            payload: ObservationPayload::ApiAttempt {
                name: ProviderNameClass::Fips,
            },
        };
        let evidence = RequestEvidence::fold(
            std::slice::from_ref(&attempt),
            RequestScope {
                operational_entries: Some(0),
                fetch_armed: BTreeSet::new(),
                window: None,
                silence_start: None,
                silence_end: None,
                fence_cuts: Vec::new(),
            },
        );
        assert_eq!(evidence.loads.len(), 1);
        assert_eq!(evidence.loads[0].name, ProviderNameClass::Fips);
        assert_eq!(evidence.loads[0].attempts, 1);
        assert_eq!(evidence.loads[0].candidates, 0);
    }

    // NEW-9-OPEN + NEW-16 fix5 RED: a late claim clamped to an EMPTY
    // interval certifies NO zeros — the section publishes no silence
    // interval, armed-but-edgeless surfaces read unknown, and an
    // idle plane reads Unknown — while genuine positives still
    // project (rows + observed remainder, never demoted).
    #[test]
    fn empty_silence_interval_voids_zero_certification_keeps_positives() {
        // Idle: late claim (silence start AT the deadline) + full
        // arms + idle plane.
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(200);
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(
            evidence.silence_window, None,
            "no empty interval is published"
        );
        assert_eq!(
            evidence.unattributed,
            Unattributed::Unknown,
            "an idle plane without an interval is Unknown, never an observed zero"
        );
        assert!(
            evidence.fetch_coverage.iter().all(|r| !r.observed),
            "armed-but-edgeless surfaces are unknown without an interval"
        );
        // Inverted clamp (silence start PAST the deadline): same.
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(250);
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(evidence.silence_window, None);
        assert_eq!(evidence.unattributed, Unattributed::Unknown);
        assert!(evidence.fetch_coverage.iter().all(|r| !r.observed));
        // Positives under the same empty interval still project
        // (positive-only evidence stays valid).
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 110),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 120),
        ];
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(200);
        scope.operational_entries = Some(3);
        let evidence = RequestEvidence::fold(&facts, scope);
        assert_eq!(evidence.silence_window, None);
        assert_eq!(evidence.fetches.len(), 1, "the genuine row projects");
        assert_eq!(
            evidence.unattributed,
            Unattributed::Observed { ops: 3 },
            "the positive remainder is never demoted"
        );
        let md = evidence
            .fetch_coverage
            .iter()
            .find(|r| r.surface_id == 10)
            .expect("md coverage row");
        assert!(md.observed, "edges prove observation");
        assert!(
            evidence
                .fetch_coverage
                .iter()
                .filter(|r| r.surface_id != 10)
                .all(|r| !r.observed),
            "edgeless surfaces stay unknown"
        );
        evidence
            .validate_strict()
            .expect("positive-only evidence without an interval stays valid");
    }

    // GATE-OPEN + NEW-16 fix5 RED: zero claims require a nonempty
    // published silence interval — in the typed validation as in
    // the document gate. Batch + positive-only evidence (no zeros)
    // stays valid without one.
    #[test]
    fn zero_claims_require_nonempty_silence_interval() {
        // Control: windowed armed-idle zeros with a nonempty
        // interval validate.
        let mut scope = observed_scope();
        scope.window = Some((100, 200));
        scope.silence_start = Some(150);
        let evidence = RequestEvidence::fold(&[], scope);
        assert_eq!(
            evidence.silence_window,
            Some(SilenceWindow {
                start_ns: 150,
                end_ns: 200
            }),
            "premise: the control publishes its interval"
        );
        assert_eq!(
            evidence.unattributed,
            Unattributed::Observed { ops: 0 },
            "premise: the control claims zeros"
        );
        evidence
            .validate_strict()
            .expect("interval-backed zeros validate");
        // Interval-free observed zero: rejected.
        let no_interval = RequestEvidence {
            silence_window: None,
            ..evidence.clone()
        };
        assert!(
            no_interval.validate_strict().is_err(),
            "an observed zero without a silence interval must not validate"
        );
        // Covered-but-absent surface without an interval: rejected
        // (per-surface zeros need the interval too).
        let mut edged = observed_scope();
        edged.window = Some((100, 200));
        edged.silence_start = Some(150);
        edged.operational_entries = Some(4);
        let positive = RequestEvidence::fold(&[], edged);
        assert_eq!(
            positive.unattributed,
            Unattributed::Observed { ops: 4 },
            "premise: positive remainder, no zero there"
        );
        let positive_no_interval = RequestEvidence {
            silence_window: None,
            ..positive.clone()
        };
        assert!(
            positive_no_interval.validate_strict().is_err(),
            "covered-but-absent surfaces without an interval must not validate"
        );
        // Empty interval with zeros: rejected.
        let empty = RequestEvidence {
            silence_window: Some(SilenceWindow {
                start_ns: 150,
                end_ns: 150,
            }),
            ..evidence.clone()
        };
        assert!(
            empty.validate_strict().is_err(),
            "an empty silence interval must not validate"
        );
        // Empty interval even with positives only: rejected (no
        // silent empty intervals anywhere).
        let positive_empty = RequestEvidence {
            silence_window: Some(SilenceWindow {
                start_ns: 150,
                end_ns: 150,
            }),
            ..positive.clone()
        };
        assert!(
            positive_empty.validate_strict().is_err(),
            "an empty silence interval must not validate even for positive-only evidence"
        );
        // Batch positive-only without an interval: valid.
        let facts = vec![
            attempt_fact(InvApi::EvpMdFetch, 10),
            result_fact(InvApi::EvpMdFetch, ApiOutcome::Success, 11),
        ];
        let batch = RequestEvidence::fold(
            &facts,
            RequestScope {
                operational_entries: Some(2),
                fetch_armed: BTreeSet::new(),
                window: None,
                silence_start: None,
                silence_end: None,
                fence_cuts: Vec::new(),
            },
        );
        assert_eq!(batch.silence_window, None);
        batch
            .validate_strict()
            .expect("positive-only batch evidence stays valid");
    }

    // NEW-15 fix5 RED: a mid-window fence voids the operational
    // zero when it intersects the claimed interval (terminal
    // readability is not observability across a counting cut) —
    // while verified positives are retained and non-intersecting
    // cuts (fully before the claim, touching its edges) leave the
    // zero standing.
    #[test]
    fn mid_window_fence_voids_operational_zero_keeps_positives() {
        // Unfenced idle: the observed zero stands (control).
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[], 100, 200),
            Some(0),
            "unfenced idle is an observed zero"
        );
        // Fenced idle, open cut inside the claim: Unknown.
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(150, None)], 100, 200),
            None,
            "a mid-window fence voids the operational zero"
        );
        // Fenced idle, closed cut inside the claim: Unknown.
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(150, Some(160))], 100, 200),
            None,
            "a recovered mid-window cut still voids the zero"
        );
        // Fenced positive: the remainder is retained (positives
        // prove themselves across the cut).
        assert_eq!(
            RequestEvidence::operational_plane_sealed(5, true, &[(150, None)], 100, 200),
            Some(5),
            "verified positives survive the cut"
        );
        assert_eq!(
            RequestEvidence::operational_plane_sealed(5, false, &[(150, Some(160))], 100, 200),
            Some(5),
            "positives need no scope receipt even when fenced"
        );
        // Fully before the claim (recovered pre-establishment):
        // the zero stands.
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(50, Some(80))], 100, 200),
            Some(0),
            "a pre-claim cut leaves the zero standing"
        );
        // Touching the claim edges excludes nothing (half-open).
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(50, Some(100))], 100, 200),
            Some(0),
            "a cut ending at the claim start does not intersect"
        );
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(200, None)], 100, 200),
            Some(0),
            "a cut starting at the claim end does not intersect"
        );
        // Spanning the claim start: voids.
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, true, &[(50, Some(150))], 100, 200),
            None,
            "a cut spanning the claim start voids"
        );
        // Unobserved planes stay Unknown regardless.
        assert_eq!(
            RequestEvidence::operational_plane_sealed(0, false, &[], 100, 200),
            None,
            "no scope receipt is still Unknown"
        );
    }
}
