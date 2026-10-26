//! SPDX-License-Identifier: GPL-3.0-or-later
//! T01 conserved evidence model (spec R01/R02/R06).
//!
//! The counted unit is entry into a provider-dispatch callback at one
//! physical site, not an algorithm execution. Each [`SiteExecution`]
//! carries its physical call count once plus a sorted, deduplicated set
//! of [`CandidateIdentity`] metadata describing which identities could
//! explain that entry. Candidate identity is not definite executed
//! algorithm identity: a complete candidate set permits a definite
//! statement only for predicates true of every candidate, and an
//! incomplete ([`CandidateCoverage::Unknown`]) set makes the possible
//! upper bound unknown while preventing any lower-bound assertion.
//!
//! [`finalize`] is the sole completeness finalizer: it canonicalizes
//! input order, collects typed [`GapReason`]s, and assigns
//! [`Completeness`]. Nothing else in the tree may mint a COMPLETE
//! status.

use crate::scan::oracle::{Outcome, TrueT};
use serde::{Deserialize, Serialize};

/// Schema identity carried by every finalized capture document.
pub const CAPTURE_SCHEMA_V2: &str = "observed-crypto-v2.3";

/// Verified object fingerprint. A pathname may locate a file for display,
/// but it never defines identity (R02).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub String);

/// Physical callback backing site: the executable backing object plus the
/// `(device, inode, file offset)` triple. Replacing the file at a path
/// yields a new inode and therefore a new site, never a relabeled one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SiteKey {
    pub object: ObjectId,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
}

/// One candidate identity that could explain entry at a site: the
/// advertising provider object, its finite class (or third-party opaque
/// id), the operation/function ids, the sorted recognized algorithm
/// classes from that alias, and whether the alias is weak. The first
/// class is not a canonical semantic authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CandidateIdentity {
    pub provider: ObjectId,
    pub provider_class: String,
    pub op: u32,
    pub funcid: u32,
    pub algorithm_classes: Vec<String>,
    pub weak_alias: bool,
}

impl CandidateIdentity {
    /// Build a candidate, sorting and deduplicating its algorithm classes.
    pub fn new(
        provider: ObjectId,
        provider_class: String,
        op: u32,
        funcid: u32,
        mut algorithm_classes: Vec<String>,
        weak_alias: bool,
    ) -> Self {
        algorithm_classes.sort();
        algorithm_classes.dedup();
        Self {
            provider,
            provider_class,
            op,
            funcid,
            algorithm_classes,
            weak_alias,
        }
    }
}

/// Whether the candidate set for a site is itself complete. `Unknown`
/// means candidates may be missing; it is not the same as a candidate
/// carrying an `other`/unreadable algorithm class.
/// `AmbiguousComplete` (R01) means the set is complete — terminated
/// tables prove no rows are missing — but every row mixed two or more
/// semantic identities, so each retained class is only the row's
/// minimum and the discarded alternatives are unlisted. Candidate
/// count and identities prove nothing on such a site: every
/// predicate reads `(0, Some(calls))`, never definite, never
/// proved-absent, and no definite asset is minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CandidateCoverage {
    Complete,
    AmbiguousComplete,
    Unknown,
}

/// Physical execution record for one site in one generation: the site
/// key, its candidate metadata, and the conserved call count with its
/// first/last in-window timestamps. `installed_at` is the cookie's
/// probe-attachment wall (monotonic ns, `None` = never recorded —
/// installed is not counted: compare against `first_ns`). Field
/// order defines the total document order: `(site, generation)`
/// first, full record after (`installed_at` trails, so it only
/// breaks ties between records otherwise fully equal).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SiteExecution {
    pub site: SiteKey,
    pub generation: u32,
    pub candidates: Vec<CandidateIdentity>,
    pub candidates_coverage: CandidateCoverage,
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub installed_at: Option<u64>,
}

impl SiteExecution {
    /// Conserved total: each site's calls counted once, never once per
    /// candidate. Saturates rather than wrapping on hostile input.
    pub fn sum_calls(sites: &[SiteExecution]) -> u64 {
        sites.iter().map(|s| s.calls).fold(0, u64::saturating_add)
    }

    /// Canonicalize candidate metadata in place: sort classes, sort and
    /// dedupe candidates. Full-struct equality keeps a weak alias
    /// distinct from an otherwise identical strong one.
    fn normalize(&mut self) {
        for c in &mut self.candidates {
            c.algorithm_classes.sort();
            c.algorithm_classes.dedup();
        }
        self.candidates.sort();
        self.candidates.dedup();
    }
}

/// Three-valued predicate outcome over one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PredicateMatch {
    Yes,
    No,
    Unknown,
}

/// Conserved match bounds for one predicate over a set of sites:
/// `definite` calls are proved to match; `possible` bounds the calls
/// that could match, or is `None` when candidate loss makes the upper
/// bound unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchBounds {
    pub definite: u64,
    pub possible: Option<u64>,
}

/// Per-site bound outcomes. A site contributes its calls to `definite`
/// only when every candidate matches and the set is complete; it
/// contributes to `possible` whenever any candidate matches or is
/// unknown. An empty candidate set proves nothing either way: absence
/// of attribution is not absence of use.
fn site_bound(
    site: &SiteExecution,
    predicate: &dyn Fn(&CandidateIdentity) -> PredicateMatch,
) -> (u64, Option<u64>) {
    if site.calls == 0 {
        // No activity to attribute: known-zero on both bounds however
        // incomplete the candidate set is.
        return (0, Some(0));
    }
    if site.candidates_coverage == CandidateCoverage::Unknown {
        // Incomplete set: no lower-bound assertion, unbounded upper.
        return (0, None);
    }
    if site.candidates_coverage == CandidateCoverage::AmbiguousComplete {
        // Complete set, ambiguous rows: the wire retains only the
        // minimum class per row, so candidate identities prove
        // nothing — no definite attribution from any count, and no
        // proved absence either (the unlisted alternatives could be
        // anything in their rows). Finite upper over known calls.
        return (0, Some(site.calls));
    }
    if site.candidates.is_empty() {
        return (0, Some(site.calls));
    }
    let mut all_yes = true;
    let mut any_yes_or_unknown = false;
    for c in &site.candidates {
        match predicate(c) {
            PredicateMatch::Yes => {
                any_yes_or_unknown = true;
            }
            PredicateMatch::No => {
                all_yes = false;
            }
            PredicateMatch::Unknown => {
                all_yes = false;
                any_yes_or_unknown = true;
            }
        }
    }
    if all_yes {
        (site.calls, Some(site.calls))
    } else if any_yes_or_unknown {
        // Mixed or unknown between candidates: possible but unproven.
        (0, Some(site.calls))
    } else {
        // Every candidate says no: proved absence at this site.
        (0, Some(0))
    }
}

/// Compute conserved definite/possible bounds without duplicating any
/// site. Ambiguity between candidates shapes both bounds; ambiguity
/// inside one alias list is the predicate's job
/// (see `crate::policy::Predicate`).
pub fn match_bounds(
    sites: &[SiteExecution],
    predicate: &dyn Fn(&CandidateIdentity) -> PredicateMatch,
) -> MatchBounds {
    let mut definite = 0u64;
    let mut possible = Some(0u64);
    for site in sites {
        let (d, p) = site_bound(site, predicate);
        definite = definite.saturating_add(d);
        possible = match (possible, p) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
    }
    MatchBounds { definite, possible }
}

/// Policy verdict for one rule (R06). `Inconclusive` is fail-closed.
/// Derived order is a total canonical order for sorting rendered
/// rule outcomes, not a severity ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RuleVerdict {
    Pass,
    Violation,
    Inconclusive,
}

/// What the observer expected to instrument for one scope unit (one
/// provider/operation area). `NotApplicable` (nothing expected) differs
/// from `Unknown` (denominator unknowable, never complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExpectedScope {
    Applicable { sites: u64 },
    NotApplicable,
    Unknown,
}

/// Readiness for one scope: what was expected, discovered and attached.
/// Coverage is about instrumentation, not about which operations fired:
/// quiet but fully attached sites are covered, not gaps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopeCoverage {
    pub scope: String,
    pub expected: ExpectedScope,
    pub discovered: u64,
    pub attached: u64,
}

impl ScopeCoverage {
    pub fn is_complete(&self) -> bool {
        match self.expected {
            ExpectedScope::NotApplicable => true,
            ExpectedScope::Unknown => false,
            ExpectedScope::Applicable { sites } => {
                self.discovered >= sites && self.attached >= sites
            }
        }
    }

    /// Typed gaps for this scope; empty exactly when complete.
    pub fn gaps(&self) -> Vec<GapReason> {
        match self.expected {
            ExpectedScope::NotApplicable => Vec::new(),
            ExpectedScope::Unknown => vec![GapReason::UnknownDenominator {
                scope: self.scope.clone(),
            }],
            ExpectedScope::Applicable { sites } => {
                let mut out = Vec::new();
                if self.discovered < sites {
                    out.push(GapReason::UndiscoveredSites {
                        scope: self.scope.clone(),
                        missing: sites - self.discovered,
                    });
                }
                if self.attached < sites {
                    out.push(GapReason::UnattachedSites {
                        scope: self.scope.clone(),
                        missing: sites - self.attached,
                    });
                }
                out
            }
        }
    }
}

/// Whether a counter records integrity/coverage loss (forces PARTIAL
/// when positive) or ordinary non-gap activity (never forces PARTIAL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CounterKind {
    Loss,
    Activity,
}

/// Units of a gap/activity counter, published with every counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CounterUnits {
    Calls,
    Sites,
    TableRows,
    Events,
    Probes,
}

/// Source that produced a counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CounterSource {
    KernelRing,
    KernelMap,
    Discovery,
    Attach,
    Drain,
    Lifecycle,
    Setup,
}

/// One source-tagged counter with its units and loss/activity kind.
/// Field order defines the total document order: `name` first so the
/// primary key stays human-stable, full record after for ties.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GapCounter {
    pub name: String,
    pub kind: CounterKind,
    pub units: CounterUnits,
    pub source: CounterSource,
    pub value: u64,
}

impl GapCounter {
    /// Only positive loss forces PARTIAL. Activity counters — including
    /// "unseen op" tallies that are mere observations — never do.
    pub fn forces_partial(&self) -> bool {
        matches!(self.kind, CounterKind::Loss) && self.value > 0
    }
}

/// Typed reason a window is not COMPLETE.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GapReason {
    UnknownDenominator {
        scope: String,
    },
    UndiscoveredSites {
        scope: String,
        missing: u64,
    },
    UnattachedSites {
        scope: String,
        missing: u64,
    },
    Loss {
        counter: String,
        source: CounterSource,
        value: u64,
    },
    UnattributedCalls {
        sites: u64,
        calls: u64,
    },
    StartupGap {
        missing_ns: u64,
    },
    TailGap {
        missing_ns: u64,
    },
    SignalCut,
}

/// Requested versus effective coverage boundaries. Any unobserved
/// interval inside the requested window is a gap; starting the visible
/// clock late cannot erase setup activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountAdmissionWindow {
    pub start_ns: u64,
    pub deadline_ns: u64,
}

/// Requested time and conservative coverage; admission is a distinct bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureWindow {
    pub requested_start_ns: u64,
    pub requested_end_ns: u64,
    pub effective_start_ns: u64,
    pub effective_end_ns: u64,
    pub signal_cut: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count_admission: Option<CountAdmissionWindow>,
}

impl CaptureWindow {
    pub fn startup_gap_ns(&self) -> u64 {
        self.effective_start_ns
            .saturating_sub(self.requested_start_ns)
    }

    pub fn tail_gap_ns(&self) -> u64 {
        self.requested_end_ns.saturating_sub(self.effective_end_ns)
    }
}

/// Execution context retained in the finalized document (R12/G08):
/// the host kernel release plus the wall-clock window edges in unix
/// nanoseconds. Context only — the monotonic [`CaptureWindow`] fields
/// stay authoritative for durations and deadlines; wall edges may run
/// backward across a clock adjustment without affecting verdicts, and
/// missing/unrepresentable wall times are explicit `None` (rendered
/// JSON `null`, human `unknown`), never a fabricated zero. Carries no
/// argv, pointers or payloads: kernel release plus two timestamps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CaptureContext {
    /// Host kernel release (`uname -r`); empty means unknown.
    pub kernel_release: String,
    /// Wall-clock window start in unix nanoseconds (`None` = unknown).
    pub wall_start_unix_ns: Option<u64>,
    /// Wall-clock window end in unix nanoseconds (`None` = unknown).
    pub wall_end_unix_ns: Option<u64>,
}

/// Observed code object: verified identity plus a display locator. The
/// locator is provenance for operators, never identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub id: ObjectId,
    pub device: u64,
    pub inode: u64,
    pub display_locator: String,
}

/// Conserved counts of one fenced generation: same [`SiteExecution`]
/// shape as current sites so fence crossings preserve candidates.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FencedGeneration {
    pub generation: u32,
    pub sites: Vec<SiteExecution>,
}

/// Fatal observation failure. Every kind discards the window's
/// observations except [`FatalKind::Runtime`], which salvages them
/// (see [`CaptureDocument::has_usable_evidence`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FatalKind {
    Recycled,
    AttachZero,
    Environment(String),
    /// Post-observation tool failure (H7): the close flow broke
    /// mid-run (drain, discovery finish, or target disposition).
    /// The doc is salvaged — every collected observation survives —
    /// with the failure folded in as fatal loss + `close-failure`
    /// reason. Unlike other fatal kinds, salvaged docs evaluate
    /// policy (a proved violation still exits 10) and exit 1.
    Runtime(String),
}

/// Window completeness. COMPLETE means no relevant
/// integrity/coverage/startup/drain/lifecycle gaps for the stated
/// scope; positive non-gap activity counters are allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completeness {
    Complete,
    Partial {
        reasons: Vec<GapReason>,
    },
    Fatal {
        kind: FatalKind,
        reasons: Vec<GapReason>,
    },
}

/// Observed target identity for safe actionability (R07): pid,
/// comm and container/image provenance where available. Raw argv is
/// never carried anywhere in the document: renders state
/// `argv_redacted = true` unconditionally, and the public schema
/// rejects any argv/cmdline field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TargetRecord {
    pub pid: u32,
    pub comm: String,
    pub container_id: String,
    pub image_digest: String,
}

impl TargetRecord {
    pub fn new(pid: u32, comm: String, container_id: String, image_digest: String) -> Self {
        Self {
            pid,
            comm,
            container_id,
            image_digest,
        }
    }

    /// Placeholder when a producer never observed a target (fixture
    /// shorthand; live captures always carry the real target).
    pub fn unknown() -> Self {
        Self {
            pid: 0,
            comm: "(unknown)".to_string(),
            container_id: String::new(),
            image_digest: String::new(),
        }
    }
}

/// Whether the OpenSSL version came from verified object metadata.
/// A version string is emitted only when verified, never guessed
/// (R08); `Unknown` carries no version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpensslVersionState {
    Verified,
    Unknown,
}

/// Observed OpenSSL version: verified metadata or explicitly
/// unknown. The constructors maintain the invariant (Verified ⟺
/// version present and non-empty); the output validator rejects
/// inconsistent documents rather than silently repairing them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpensslVersion {
    pub state: OpensslVersionState,
    pub version: Option<String>,
}

impl OpensslVersion {
    pub fn verified(version: String) -> Self {
        Self {
            state: OpensslVersionState::Verified,
            version: Some(version),
        }
    }

    pub fn unknown() -> Self {
        Self {
            state: OpensslVersionState::Unknown,
            version: None,
        }
    }

    pub fn is_consistent(&self) -> bool {
        match self.state {
            OpensslVersionState::Verified => self.version.as_ref().is_some_and(|v| !v.is_empty()),
            OpensslVersionState::Unknown => self.version.is_none(),
        }
    }
}

/// End-of-observation custody outcome. `Exited` preserves the reaped
/// status; `DetachedRunning` is an owned child left running under
/// explicit ownership transfer; `ForeignObserved` is a `--pid`
/// target left running and never signaled (documented, not
/// custody). A document with no recorded disposition carries `None`
/// instead of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DispositionOutcome {
    Exited,
    DetachedRunning,
    ForeignObserved,
}

/// End-of-observation custody disposition value. `Exited` carries a
/// code, the running outcomes carry a pid; the constructors maintain
/// that shape and the output validator rejects anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DispositionRecord {
    pub outcome: DispositionOutcome,
    pub code: Option<i32>,
    pub pid: Option<u32>,
}

impl DispositionRecord {
    pub fn exited(code: i32) -> Self {
        Self {
            outcome: DispositionOutcome::Exited,
            code: Some(code),
            pid: None,
        }
    }

    pub fn detached_running(pid: u32) -> Self {
        Self {
            outcome: DispositionOutcome::DetachedRunning,
            code: None,
            pid: Some(pid),
        }
    }

    pub fn foreign_observed(pid: u32) -> Self {
        Self {
            outcome: DispositionOutcome::ForeignObserved,
            code: None,
            pid: Some(pid),
        }
    }

    pub fn is_consistent(&self) -> bool {
        match self.outcome {
            DispositionOutcome::Exited => self.code.is_some() && self.pid.is_none(),
            DispositionOutcome::DetachedRunning | DispositionOutcome::ForeignObserved => {
                self.code.is_none() && self.pid.is_some()
            }
        }
    }
}

/// Site evidence backing one policy rule outcome (R02): the exact
/// site key plus generation and the definite calls attributed there.
/// Every ref resolves to a site listed in the same document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyEvidenceRef {
    pub object: ObjectId,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
    pub generation: u32,
    pub calls: u64,
}

/// Window provenance of one [`EngineObservation`]: whether the trip
/// count is definite requested-window evidence (`InWindow`),
/// retained pre-window context excluded from verdicts (`PreWindow`),
/// or window-unbound (`Untimed`, never definite, poisons the upper
/// bound — fail closed). The live path emits `InWindow` only:
/// baselined at the window boundary, accumulated from in-window
/// polls; straddling polls are already explicit loss, never
/// observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineWindow {
    InWindow,
    PreWindow,
    Untimed,
}

/// One typed ENGINE tripwire observation (R05/F06): the pinned
/// tripwire attach identity ([`SiteKey`] of the probe stub in its
/// own module — caller-attributed PLT stubs attach through each
/// module's own pin, never through libcrypto), the tripwire binding
/// `generation` (0 = first bind; +1 per install — provenance, never
/// fabricated), the `entrypoint` index into the frozen
/// [`crate::kinds::ENGINE`] registry, and the observed `calls` with
/// their [`EngineWindow`].
/// Trip counters are untimed by construction (hits carry no
/// timestamps), so there are no first/last fields: the window
/// binding is the certainty. Field order defines the total document
/// order: `(key, generation, entrypoint)` first, count/window after.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EngineObservation {
    pub key: SiteKey,
    pub generation: u64,
    pub entrypoint: u16,
    pub calls: u64,
    pub window: EngineWindow,
}

/// Index of an `ENGINE_*` symbol in the frozen
/// [`crate::kinds::ENGINE`] registry: the authoritative join key for
/// [`EngineObservation::entrypoint`]. `None` for meth/low-level/load
/// symbols, which live on other planes and never become ENGINE
/// observations.
pub fn engine_index(name: &str) -> Option<u16> {
    u16::try_from(crate::kinds::ENGINE.iter().position(|e| e.name == name)?).ok()
}

/// Name of the indexed [`crate::kinds::ENGINE`] entrypoint, for
/// display rendering (the index stays the authoritative key).
pub fn engine_name(entrypoint: u16) -> Option<&'static str> {
    crate::kinds::ENGINE
        .get(entrypoint as usize)
        .map(|e| e.name)
}

/// Engine-plane evidence backing one policy rule outcome (R05): the
/// exact observation key plus generation, entrypoint and the
/// definite calls attributed there. Every ref resolves to an
/// observation listed in the same document; per-rule refs never
/// claim more calls than the observation executed (checked like
/// [`PolicyEvidenceRef`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EngineEvidenceRef {
    pub object: ObjectId,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
    pub generation: u64,
    pub entrypoint: u16,
    pub calls: u64,
}

/// One policy rule outcome over conserved bounds (R06): the rule and
/// predicate, the three-valued result, definite/possible call
/// bounds (`possible == None` means the upper bound is unknown),
/// site evidence for definite provider-plane matches, and
/// engine-plane evidence for definite tripwire observations (R05).
/// Field order defines the total document order: `(rule, predicate)`
/// first, full record after.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRuleResult {
    pub rule: String,
    pub predicate: String,
    pub result: RuleVerdict,
    pub definite: u64,
    pub possible: Option<u64>,
    pub evidence: Vec<PolicyEvidenceRef>,
    #[serde(default)]
    pub engine_evidence: Vec<EngineEvidenceRef>,
}

/// Overall policy verdict (R06): rules are ANDed by the evaluator.
/// `NoVerdict` rides fatal/evidence-free documents only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Pass,
    Violation,
    Inconclusive,
    NoVerdict,
}

/// Evaluated policy section (T10 fills this; T11 renders it):
/// overall verdict plus per-rule outcomes. `None` on the document
/// means unevaluated (the `report` path); renders omit the section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub verdict: PolicyVerdict,
    pub rules: Vec<PolicyRuleResult>,
}

/// Unfinalized capture input. Producers fill this; only [`finalize`]
/// turns it into a [`CaptureDocument`].
#[derive(Debug, Clone)]
pub struct FinalizeInput {
    pub window: CaptureWindow,
    pub sites: Vec<SiteExecution>,
    pub fenced: Vec<FencedGeneration>,
    pub objects: Vec<ObjectRecord>,
    pub coverage: Vec<ScopeCoverage>,
    pub counters: Vec<GapCounter>,
    pub fatal: Option<FatalKind>,
    pub target: TargetRecord,
    pub openssl: OpensslVersion,
    pub disposition: Option<DispositionRecord>,
    pub policy: Option<PolicyRecord>,
    pub legacy_partition: LegacyCallPartition,
    pub engine_observations: Vec<EngineObservation>,
    pub traversal: Option<TraversalRecord>,
}

/// Legacy call partition (H8): per-site callback executions split
/// by candidate class and backing identity. Conserves exactly:
/// [`total`](LegacyCallPartition::total) equals the window's
/// counted calls over current plus fenced sites. Computed once by
/// the producer over the same sites the document claims.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyCallPartition {
    /// Calls on sites whose every candidate is legacy-class and
    /// whose backing (device, inode) is the legacy provider file.
    pub legacy_exclusive: u64,
    /// Calls on sites with no legacy-class candidate.
    pub non_legacy_exclusive: u64,
    /// Calls on sites mixing legacy with non-legacy candidates, or
    /// all-legacy candidates backed by a foreign file.
    pub shared_ambiguous: u64,
    /// Calls on sites carrying no candidates (no partition key).
    pub unfenced_tails: u64,
}

impl LegacyCallPartition {
    /// Conserved total: must equal
    /// [`total_calls`](CaptureDocument::total_calls).
    pub fn total(&self) -> u64 {
        self.legacy_exclusive
            .saturating_add(self.non_legacy_exclusive)
            .saturating_add(self.shared_ambiguous)
            .saturating_add(self.unfenced_tails)
    }
}

/// Finalized capture document. All report/check/CBOM formats derive
/// from this one document for the same window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDocument {
    pub schema: String,
    /// Observer package identity derived only from admitted retained inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_build: Option<crate::package::commands::PackageProvenance>,
    /// Retained Count bytes for the foreground preview, which resolves no
    /// harvest/members set. Reuses the existing per-role provenance record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count_object: Option<crate::package::commands::PackageRoleProvenance>,
    pub status: Completeness,
    pub window: CaptureWindow,
    pub sites: Vec<SiteExecution>,
    pub fenced: Vec<FencedGeneration>,
    pub objects: Vec<ObjectRecord>,
    pub coverage: Vec<ScopeCoverage>,
    pub counters: Vec<GapCounter>,
    pub target: TargetRecord,
    pub openssl: OpensslVersion,
    pub disposition: Option<DispositionRecord>,
    pub policy: Option<PolicyRecord>,
    pub legacy_partition: LegacyCallPartition,
    /// Typed ENGINE tripwire observations (R05/F06): the replayable
    /// engine plane. Additive and old-reader-safe: missing in old
    /// documents means none observed. Never joins [`Self::total_calls`]
    /// or the legacy partition (conserved provider-dispatch units).
    #[serde(default)]
    pub engine_observations: Vec<EngineObservation>,
    /// Execution context (R12): kernel release plus wall-clock window
    /// edges. Additive and old-reader-safe: missing in old documents
    /// means unrecorded. Set post-finalization by the producer from
    /// already-captured context; [`finalize`] leaves it `None` so
    /// every existing producer keeps its exact shape.
    #[serde(default)]
    pub context: Option<CaptureContext>,
    /// Traversal outcome (v2.1, optional — present iff the window
    /// ran the members backend): the exact selected triple
    /// (paths + sha256, so doctor/report/check agree) plus
    /// record/findings/poll counts. Absent on harvest-only runs.
    pub traversal: Option<TraversalRecord>,
    /// Run-set selection provenance (v0.2): the exact objects the
    /// run resolved — recorded on every production run's document
    /// (`None` on stubbed `observe` captures, which resolve no
    /// objects; pair-only runs carry `members: None`), so
    /// doctor/report/check agree on the selection. Additive and
    /// old-reader-safe.
    #[serde(default)]
    pub selected_objects: Option<RunSetProvenance>,
    /// Failed-attach diagnostic texts (R06): sorted, deduped,
    /// capped producer literals (no paths/pointers) — the failed
    /// attach identifies itself, not just counts. Additive and
    /// old-reader-safe: missing in old documents means none
    /// recorded. Set post-finalization by the producer;
    /// [`finalize`] leaves it empty so every existing producer
    /// keeps its exact shape.
    #[serde(default)]
    pub attach_diagnostics: Vec<String>,
    /// Budget-refusal diagnostic entries (R14 minor): sorted,
    /// deduped, capped numeric entries — each names the refused
    /// object by (dev, ino) plus kind/bytes/allowance, so the
    /// refusal identifies itself, not just counts. Additive and
    /// old-reader-safe: missing in old documents means none
    /// recorded. Set post-finalization by the producer;
    /// [`finalize`] leaves it empty so every existing producer
    /// keeps its exact shape.
    #[serde(default)]
    pub refusal_diagnostics: Vec<String>,
}

/// One BPF object selected for the window (path locates for
/// display; sha256 defines identity).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraversalObject {
    pub path: String,
    pub sha256: String,
}

/// Run-set selection provenance (v0.2): the exact objects the
/// run resolved — recorded on EVERY document (pair-only runs
/// carry `members: None`), so doctor/report/check agree on the
/// selection. Additive and old-reader-safe.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RunSetProvenance {
    pub harvest: TraversalObject,
    pub count: TraversalObject,
    pub members: Option<TraversalObject>,
}

/// One traversal record's native facts (per-record summary —
/// full slot arrays stay in-capture like raw ring events; the
/// document carries the verdict-relevant facts per record).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraversalRecordEntry {
    pub tid: u32,
    pub seq: u64,
    pub op: u32,
    pub outcome: Outcome,
    pub true_t: TrueT,
    pub alg_count: usize,
    pub row_count: usize,
    /// Agreed array incarnation (None when mixed or slotless).
    pub generation: Option<u64>,
}

/// Traversal outcome summary (see [`CaptureDocument::traversal`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TraversalRecord {
    pub harvest: TraversalObject,
    pub count: TraversalObject,
    pub members: TraversalObject,
    pub records: u64,
    pub findings: u64,
    pub polls: u64,
    /// Admitted queries per op (loss-independent observation
    /// census — record count is not a census; additive round-4
    /// field, old readers ignore it).
    #[serde(default)]
    pub admitted: std::collections::BTreeMap<u32, u64>,
    /// Per-record native facts, close order (additive round-4
    /// field, old readers ignore it).
    #[serde(default)]
    pub entries: Vec<TraversalRecordEntry>,
    /// Ops observed (records retained) but missing from the
    /// census while increments were lost (additive round-5
    /// field, old readers ignore it): UNKNOWN counts, never
    /// zero. Sorted (BTreeSet order at the producer).
    #[serde(default)]
    pub admitted_unknown: Vec<u32>,
    /// Cumulative admitted-increment loss (additive round-5
    /// field, old readers ignore it): nonzero means the
    /// census snapshot is incomplete.
    #[serde(default)]
    pub census_loss: u64,
}

/// Fatal-kind usability classes for the shared usability rule
/// (v0.2 R22: the single decision behind
/// [`CaptureDocument::has_usable_evidence`] and the schema
/// validator's policy check — both sides map onto this, so the
/// rule can never drift on one side again).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalUsabilityKind {
    Runtime,
    AttachZero,
    Other,
}

impl FatalUsabilityKind {
    pub fn of(kind: &FatalKind) -> Self {
        match kind {
            FatalKind::Runtime(_) => Self::Runtime,
            FatalKind::AttachZero => Self::AttachZero,
            _ => Self::Other,
        }
    }

    pub fn of_token(token: &str) -> Self {
        match token {
            "runtime" => Self::Runtime,
            "attach-zero" => Self::AttachZero,
            _ => Self::Other,
        }
    }
}

/// Shared fatal-usability rule: runtime-salvageable kinds are
/// usable; attach-zero is usable only with proved ENGINE
/// evidence; everything else is unusable (fail-closed).
///
/// ```rust
/// use osslscope::evidence::{fatal_kind_usable, FatalUsabilityKind};
/// assert!(fatal_kind_usable(FatalUsabilityKind::Runtime, false));
/// assert!(fatal_kind_usable(FatalUsabilityKind::Runtime, true));
/// assert!(fatal_kind_usable(FatalUsabilityKind::AttachZero, true));
/// assert!(!fatal_kind_usable(FatalUsabilityKind::AttachZero, false));
/// assert!(!fatal_kind_usable(FatalUsabilityKind::Other, true));
/// assert!(!fatal_kind_usable(FatalUsabilityKind::Other, false));
/// ```
pub fn fatal_kind_usable(kind: FatalUsabilityKind, proved_engine: bool) -> bool {
    matches!(kind, FatalUsabilityKind::Runtime)
        || (matches!(kind, FatalUsabilityKind::AttachZero) && proved_engine)
}

impl CaptureDocument {
    /// Conserved total across current and fenced sites.
    pub fn total_calls(&self) -> u64 {
        let current = SiteExecution::sum_calls(&self.sites);
        self.fenced.iter().fold(current, |acc, g| {
            acc.saturating_add(SiteExecution::sum_calls(&g.sites))
        })
    }

    /// Proved in-window ENGINE executions (P2): typed tripwire
    /// observations the attach-zero/fetch planes cannot suppress —
    /// an AttachZero-classified document carrying these still
    /// proves a violation (the classification describes provider
    /// attachment, not the independent ENGINE evidence plane).
    pub fn has_proved_engine_evidence(&self) -> bool {
        self.engine_observations
            .iter()
            .any(|o| o.calls > 0 && o.window == EngineWindow::InWindow)
    }

    /// Fatal-kind usability: salvaged Runtime-fatal documents retain
    /// their observed sites for policy evaluation, semantic validation
    /// and CBOM export; AttachZero documents carrying proved ENGINE
    /// evidence retain that independent plane (P2 — the attach-zero
    /// classification describes provider attachment, never the
    /// tripwire plane). Recycled and Environment fatals are never
    /// usable (recycled observations are wrong-process-tainted and
    /// discarded by construction; setup observed nothing), even if
    /// observations are carried — the kind disclaims them.
    /// Non-fatal documents are usable. This gates eligibility only —
    /// per-site certainty/coverage tests still decide definite vs
    /// possible use, so a usable Runtime site is not automatically
    /// definite. The kind rule itself lives in the shared
    /// [`fatal_kind_usable`] decision (this method and the schema
    /// validator's policy check both consume it — no restated rule
    /// remains to drift); this method is its typed-side consumer
    /// for the policy no-verdict gate and the report/CBOM wording.
    pub fn has_usable_evidence(&self) -> bool {
        match &self.status {
            Completeness::Complete | Completeness::Partial { .. } => true,
            Completeness::Fatal { kind, .. } => fatal_kind_usable(
                FatalUsabilityKind::of(kind),
                self.has_proved_engine_evidence(),
            ),
        }
    }

    /// Gap reasons; empty for COMPLETE and (by construction) for fatal
    /// inputs that carried no other gaps.
    pub fn reasons(&self) -> &[GapReason] {
        match &self.status {
            Completeness::Complete => &[],
            Completeness::Partial { reasons } | Completeness::Fatal { reasons, .. } => reasons,
        }
    }
}

/// Sole completeness finalizer: canonicalize every list into a total
/// order independent of arrival order, collect typed gap reasons, and
/// assign the status. Every sort is a full-record derived order, so
/// even records sharing a primary key (two same-name counters, two
/// same-scope coverage rows) serialize deterministically. COMPLETE
/// requires no fatal failure, no coverage gaps, no positive loss, no
/// unattributed executed calls, and an effective window covering the
/// requested window.
pub fn finalize(mut input: FinalizeInput) -> CaptureDocument {
    for site in &mut input.sites {
        site.normalize();
    }
    input.sites.sort();
    for bucket in &mut input.fenced {
        for site in &mut bucket.sites {
            site.normalize();
        }
        bucket.sites.sort();
    }
    input.fenced.sort();
    input.objects.sort();
    input.coverage.sort();
    input.counters.sort();
    input.engine_observations.sort();
    if let Some(policy) = input.policy.as_mut() {
        for rule in &mut policy.rules {
            rule.evidence.sort();
            rule.engine_evidence.sort();
        }
        policy.rules.sort();
    }

    let mut reasons: Vec<GapReason> = Vec::new();
    for scope in &input.coverage {
        reasons.extend(scope.gaps());
    }
    for counter in &input.counters {
        if counter.forces_partial() {
            reasons.push(GapReason::Loss {
                counter: counter.name.clone(),
                source: counter.source,
                value: counter.value,
            });
        }
    }
    let mut unattributed_sites = 0u64;
    let mut unattributed_calls = 0u64;
    for site in input
        .sites
        .iter()
        .chain(input.fenced.iter().flat_map(|g| g.sites.iter()))
    {
        if site.calls > 0 && site.candidates_coverage == CandidateCoverage::Unknown {
            unattributed_sites += 1;
            unattributed_calls = unattributed_calls.saturating_add(site.calls);
        }
    }
    if unattributed_sites > 0 {
        reasons.push(GapReason::UnattributedCalls {
            sites: unattributed_sites,
            calls: unattributed_calls,
        });
    }
    let startup = input.window.startup_gap_ns();
    if startup > 0 {
        reasons.push(GapReason::StartupGap {
            missing_ns: startup,
        });
    }
    let tail = input.window.tail_gap_ns();
    if tail > 0 {
        reasons.push(GapReason::TailGap { missing_ns: tail });
    }
    if input.window.signal_cut {
        reasons.push(GapReason::SignalCut);
    }
    reasons.sort();
    reasons.dedup();

    let status = match input.fatal {
        Some(kind) => Completeness::Fatal { kind, reasons },
        None if reasons.is_empty() => Completeness::Complete,
        None => Completeness::Partial { reasons },
    };
    CaptureDocument {
        schema: CAPTURE_SCHEMA_V2.to_string(),
        package_build: None,
        count_object: None,
        status,
        window: input.window,
        sites: input.sites,
        fenced: input.fenced,
        objects: input.objects,
        coverage: input.coverage,
        counters: input.counters,
        target: input.target,
        openssl: input.openssl,
        disposition: input.disposition,
        policy: input.policy,
        legacy_partition: input.legacy_partition,
        engine_observations: input.engine_observations,
        context: None,
        traversal: input.traversal,
        selected_objects: None,
        attach_diagnostics: Vec::new(),
        refusal_diagnostics: Vec::new(),
    }
}
