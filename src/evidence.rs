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
pub const CAPTURE_SCHEMA_V2: &str = "observed-crypto-v2.4";

/// Schema identity for finalized documents carrying certified
/// execution attribution (v2.5): the producer upgrades to this
/// identity exactly when it projects a certified closed
/// attribution result (definite partitions and/or the certified
/// unresolved bound). [`finalize`] keeps emitting
/// [`CAPTURE_SCHEMA_V2`].
pub const CAPTURE_SCHEMA_V2_5: &str = "observed-crypto-v2.5";

/// Schema identity for finalized documents carrying a sampled
/// sysctl context (v2.6, T5 schema D-record): the producer upgrades
/// to this identity exactly when `context.sysctls` is present (see
/// [`stamp_context`]). The coarse `openssl.version` domain is
/// enforced by `check_v2_semantics` gated numerically on minor ≥ 6;
/// the schema keeps the historical free `string|null` domain so
/// 2.4/2.5 documents stay valid.
pub const CAPTURE_SCHEMA_V2_6: &str = "observed-crypto-v2.6";

/// Scope token for a certified execution attribution: an observed
/// successful fetch of an exact spelling returned a method, and
/// the consuming API used that method under the public-reference
/// guard at the callback object. Kebab-case (the `EngineWindow`
/// precedent); the only scope the v2.5 producer emits.
pub const ATTRIBUTION_SCOPE_V1: &str =
    "observed-successful-request-for-consumed-method-at-callback-object-v1";

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

/// 6A §1.3 owned-corpse wait span (N13): the monotonic-nanosecond
/// interval the controller waited for an owned maps-empty target
/// before retiring it. Endpoints, not a scalar: the span joins the
/// evidence as an interval with cause `corpse_wait`, never an
/// invented zero-count window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpseWaitSpan {
    pub start_ns: u64,
    pub end_ns: u64,
}

/// 6A §1.3 retirement membership leg (N13): the end-of-observation
/// membership state of the captured target. `None` (absent) on
/// every non-retired capture. Reason + window ride the typed
/// [`GapReason::VisibilityLost`]; this record carries only the
/// membership state (never double-reported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRecord {
    pub state: MembershipState,
}

/// Membership states a capture can retire into. Only corpse-expiry
/// retirement exists today; the enum holds the vocabulary slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipState {
    Retired,
}

/// Typed reason a window is not COMPLETE.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GapReason {
    VisibilityLost {
        cause: String,
        start_ns: u64,
        end_ns: u64,
    },
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
    /// Sampled sysctl context (v2.6, T5 schema D-record): one
    /// admission-event sample, retained never reread. `None` means
    /// never sampled (pre-2.6 documents); per-key `None` means
    /// sampled-but-failed (rendered JSON omits the key, human
    /// shows `unknown`). Forensics only — no verdict, exit,
    /// admission, or policy input may read these fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sysctls: Option<SysctlContext>,
}

/// One admission-event sysctl sample (observer's `/proc/sys` view).
/// Bounded signed integers as read; `-1` is legitimate data
/// (`perf_event_paranoid`), never a sentinel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SysctlContext {
    pub perf_event_paranoid: Option<i64>,
    pub kptr_restrict: Option<i64>,
    pub unprivileged_bpf_disabled: Option<i64>,
    pub ptrace_scope: Option<i64>,
}

/// Sample the four forensic sysctls from a `/proc/sys` root (T5
/// schema D-record rule 7): one admission-event sample, retained
/// never reread. Per-key failure (unreadable, empty, malformed,
/// overflowing) yields `None` for that key; the sample as a whole
/// never fails. Production passes `/proc/sys`; tests inject a
/// scratch root.
pub fn sample_sysctls_from(proc_sys: &std::path::Path) -> SysctlContext {
    let read = |relative: &str| {
        std::fs::read_to_string(proc_sys.join(relative))
            .ok()
            .and_then(|text| parse_sysctl_value(&text))
    };
    SysctlContext {
        perf_event_paranoid: read("kernel/perf_event_paranoid"),
        kptr_restrict: read("kernel/kptr_restrict"),
        unprivileged_bpf_disabled: read("kernel/unprivileged_bpf_disabled"),
        ptrace_scope: read("kernel/yama/ptrace_scope"),
    }
}

/// Parse one sysctl file's text: trimmed ASCII integer, else `None`.
/// Empty, malformed, and overflowing inputs yield `None` (absent
/// key), never a sentinel or a string passthrough.
pub fn parse_sysctl_value(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .strip_prefix('-')
        .unwrap_or(trimmed)
        .bytes()
        .all(|b| b.is_ascii_digit())
        || trimmed.strip_prefix('-').unwrap_or(trimmed).is_empty()
    {
        return None;
    }
    trimmed.parse::<i64>().ok()
}

/// Attach execution context to a finalized document (T5 schema
/// D-record): stamps `context` and upgrades the schema identity to
/// v2.6 exactly when `sysctls` is present. All context attach sites
/// go through here so the schema rule has one home.
pub fn stamp_context(doc: &mut CaptureDocument, context: CaptureContext) {
    if context.sysctls.is_some() {
        doc.schema = CAPTURE_SCHEMA_V2_6.to_string();
    }
    doc.context = Some(context);
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

/// Coarse OpenSSL family (T5 schema D-record rule 1): the ONLY
/// values the v2.6 producer emits. Major.minor, never patch strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpensslFamily {
    V3_0,
    V3_5,
    V3_6,
    V4_0,
}

impl OpensslFamily {
    pub fn label(self) -> &'static str {
        match self {
            OpensslFamily::V3_0 => "3.0",
            OpensslFamily::V3_5 => "3.5",
            OpensslFamily::V3_6 => "3.6",
            OpensslFamily::V4_0 => "4.0",
        }
    }

    /// Strict coarsen of a shipped-table `openssl` string: dotted
    /// numerics only (`3.0.22` → `V3_0`); anything else — including
    /// family-prefixed poison (`3.5.8-EVIL`) — yields `None`
    /// (→ `Unknown`, never passthrough).
    pub fn coarsen(table_string: &str) -> Option<OpensslFamily> {
        let parts: Vec<&str> = table_string.split('.').collect();
        if parts.len() < 2
            || !parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        match (parts[0], parts[1]) {
            ("3", "0") => Some(OpensslFamily::V3_0),
            ("3", "5") => Some(OpensslFamily::V3_5),
            ("3", "6") => Some(OpensslFamily::V3_6),
            ("4", "0") => Some(OpensslFamily::V4_0),
            _ => None,
        }
    }
}

/// One ELIGIBLE version observation (T5 schema D-record rule 3):
/// the caller (capture) establishes eligibility — backing-verified
/// AND core-anchor role on the same bytes — before constructing
/// this. `table_openssl` is the shipped-table `openssl` string for
/// the object's build-id hit, or `None` when the eligible object
/// has no hit (which poisons the claim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionObservation {
    pub table_openssl: Option<String>,
}

/// Capture-wide accumulation (T5 schema D-record rule 3): the
/// unique KNOWN TABLE-HIT FAMILY, else `Unknown`. Zero observations,
/// any unmatched/malformed entry, or ≥2 distinct families all yield
/// `Unknown`; multi-patch same-family entries are compatible.
pub fn accumulate_openssl_family(observations: &[VersionObservation]) -> OpensslVersion {
    use std::collections::BTreeSet;
    let mut families = BTreeSet::new();
    for observation in observations {
        let Some(table_string) = &observation.table_openssl else {
            return OpensslVersion::unknown();
        };
        let Some(family) = OpensslFamily::coarsen(table_string) else {
            return OpensslVersion::unknown();
        };
        families.insert(family);
    }
    if families.len() == 1 {
        OpensslVersion::verified(families.into_iter().next().unwrap().label().to_string())
    } else {
        OpensslVersion::unknown()
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

/// One certified definite execution partition (v2.5): a proved
/// slice of one physical site's calls. Projected only from the
/// certifying fold's definite rows — producers never hand-build
/// these. `segment` is the nonzero fold-issued identity, unique
/// per document; `start_ns`/`end_ns` are inclusive actual-hit
/// extrema; `provider_definition` is `None` (Unknown origin)
/// unless independent evidence bound a defining artifact (it is
/// never filled from the executing code object); `selector`
/// indexes the same document's [`AlgorithmSelectorEntry`] list.
/// Field order defines the total document order: `(site,
/// generation, segment)` first, full record after.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExecutionAttribution {
    pub site: SiteKey,
    pub generation: u32,
    pub segment: u64,
    pub start_ns: u64,
    pub end_ns: u64,
    pub calls: u64,
    pub provider_definition: Option<ObjectId>,
    pub provider_instance: u64,
    pub operation: u32,
    pub function: u32,
    pub selector: u32,
    pub scope: String,
}

/// One doc-scoped algorithm selector (v2.5): the opaque
/// object-bound request identity behind one or more
/// [`ExecutionAttribution`] records. `object` is the
/// independently retained artifact containing the actual firing
/// operational callback (never the provider definition); `id`
/// is the encoding-2 digest as 64 lowercase hex; `operation`
/// is the public operation the digest binds. `canonical_name`
/// is a frozen-registry spelling the host proved equal to the
/// requested spelling by re-hashing its own registry strings —
/// never a read-back target string — or `None` when the
/// requested spelling is unregistered (opaque but still
/// observable and matchable by object-bound policy; a present
/// but unregistered name is malformed, never emitted).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AlgorithmSelectorEntry {
    pub object: ObjectId,
    pub operation: u32,
    pub id: String,
    pub canonical_name: Option<String>,
}

/// Certified unresolved attribution bounds (v2.5): calls the
/// closed collect could not attribute to any certified
/// partition, plus segments withheld for unproved optional
/// identity (whose calls stay inside `unresolved_calls`).
/// Bounds from the same closed result as the definite rows —
/// never an arithmetic projection over unrelated counters.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct AttributionBounds {
    pub unresolved_calls: u64,
    pub withheld_uncertain: u64,
}

/// Unfinalized capture input. Producers fill this; only [`finalize`]
/// turns it into a [`CaptureDocument`].
#[derive(Debug, Clone)]
pub struct FinalizeInput {
    /// 6A §1.3 owned-corpse retirement (N13): `Some` span retires
    /// the capture with `VisibilityLost` + membership `Retired`.
    pub corpse_wait: Option<CorpseWaitSpan>,
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
    /// Calls on sites with a complete candidate set and no legacy-class candidate.
    pub non_legacy_exclusive: u64,
    /// Calls on sites mixing legacy with non-legacy candidates, or
    /// all-legacy candidates backed by a foreign file. Also includes nonempty
    /// candidate sets with unknown coverage: omitted legacy candidates remain
    /// possible even when every advertised candidate has another class.
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub algorithm_identities: Vec<AlgorithmIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub site_provenance: Vec<SiteProvenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_activity: Vec<crate::api_activity::ApiActivityRow>,
    /// Internal bounded metadata handoff; public projection is separately versioned.
    #[serde(skip)]
    pub candidate_associations: Vec<crate::focused_count::SiteAssociations>,
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
    /// 6A §1.3 retirement membership leg (N13): `Some(Retired)`
    /// iff the controller retired the target (corpse-wait
    /// expiry). Additive and old-reader-safe: missing in old
    /// documents means non-retired. Set by [`finalize`] from
    /// the corpse span; every existing producer keeps its exact
    /// shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<MembershipRecord>,
    /// Certified definite execution partitions (v2.5, optional —
    /// present iff the window ran the closed attribution collect
    /// and certified partitions). Projected post-finalization
    /// from the certifying fold only; [`finalize`] leaves it
    /// empty so every existing producer keeps its exact shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_attributions: Vec<ExecutionAttribution>,
    /// Doc-scoped algorithm selector dictionary (v2.5, optional —
    /// referenced by [`Self::execution_attributions`]).
    /// Projected post-finalization with the partitions;
    /// [`finalize`] leaves it empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub algorithm_selectors: Vec<AlgorithmSelectorEntry>,
    /// Certified unresolved attribution bounds (v2.5, optional —
    /// present iff the closed collect certified a result, even
    /// when the definite set is empty). Projected
    /// post-finalization; [`finalize`] leaves it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_bounds: Option<AttributionBounds>,
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
    // N13: owned-corpse retirement — the frozen §1.3 evidence
    // (typed reason + interval window; the membership leg rides
    // the document below). Never a bare counter.
    if let Some(span) = input.corpse_wait {
        reasons.push(GapReason::VisibilityLost {
            cause: "corpse_wait".to_string(),
            start_ns: span.start_ns,
            end_ns: span.end_ns,
        });
    }
    reasons.sort();
    reasons.dedup();

    let status = match input.fatal {
        Some(kind) => Completeness::Fatal { kind, reasons },
        None if reasons.is_empty() => Completeness::Complete,
        None => Completeness::Partial { reasons },
    };
    CaptureDocument {
        candidate_associations: Vec::new(),
        algorithm_identities: Vec::new(),
        site_provenance: Vec::new(),
        api_activity: Vec::new(),
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
        membership: input.corpse_wait.map(|_| MembershipRecord {
            state: MembershipState::Retired,
        }),
        execution_attributions: Vec::new(),
        algorithm_selectors: Vec::new(),
        attribution_bounds: None,
    }
}

/// Observer-generated identities and finite hints. No runtime alias spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmIdentity {
    pub id: String,
    pub known_algorithm: Option<u16>,
}
/// Metadata is associated with an exact count generation, never a second count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteProvenance {
    pub site: SiteKey,
    pub count_generation: u32,
    pub associations: Vec<CandidateProvenance>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProvenance {
    pub algorithm_id: Option<String>,
    pub origin: crate::provider_observation::MetadataOrigin,
    pub operation: Option<u32>,
    pub function_id: u32,
    pub advertisers: Vec<crate::provider_observation::ObjectHash>,
    pub static_provenance:
        Option<crate::provider_observation::static_tables::StaticTableProvenance>,
    pub storage: Option<crate::provider_observation::static_tables::TableStorage>,
    pub partial: bool,
    pub alias_quality: crate::provider_observation::AliasQuality,
    pub observed_ns: u64,
    pub observation_generation: u64,
}
/// Frozen metadata-projection budget in bytes (5D): projection runs
/// after native session/counter destruction and reuses the released
/// 64 MiB observation-host allowance. Account growth/temporary IDs,
/// tree nodes, vector cells, advertiser strings, JSON Value/key copies
/// and pretty-printed output growth before cloning output. The
/// allowance includes both retained metadata and rendering; it is not
/// just Rust struct sizes. Never raised as a fix for over-budget
/// metadata — over-budget rows are omitted with explicit counts.
pub const METADATA_PROJECTION_BUDGET_BYTES: usize = 64 << 20;

/// Why a bounded metadata projection omitted rows (or omitted none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataProjectionReason {
    /// Every candidate row fit the budget; omitted counts are zero.
    Complete,
    /// One or more rows exceeded the remaining budget; the omitted
    /// counts name exactly what was left out. Physical evidence is
    /// never dropped by projection.
    OverBudget,
}

/// Bounded candidate-metadata projection (5D): the retained public
/// sections plus explicit omitted row counts. Retained rows keep
/// stable input order; selection prefers executed (positive) sites
/// first, then remaining rows in input order. Identity interning is
/// deterministic (sorted by identity string); every retained
/// association reference resolves to a retained identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataProjection {
    pub algorithm_identities: Vec<AlgorithmIdentity>,
    pub site_provenance: Vec<SiteProvenance>,
    /// Candidate site rows left out of the projection.
    pub omitted_sites: usize,
    /// Association rows inside omitted site rows.
    pub omitted_associations: usize,
    pub reason: MetadataProjectionReason,
}

/// Charged cost of one candidate site row under the frozen byte
/// model: 2048 bytes plus the object identity length per row, 4096
/// bytes plus 1024 per advertiser per association. Saturates; a
/// saturated cost never fits any finite budget.
pub(crate) fn metadata_row_cost_bytes(row: &crate::focused_count::SiteAssociations) -> usize {
    let mut bytes = 2048usize.saturating_add(row.site.object.0.len());
    for association in &row.associations {
        bytes = bytes.saturating_add(
            association
                .advertisers
                .len()
                .saturating_mul(1024)
                .saturating_add(4096),
        );
    }
    bytes
}

/// Executed (positive) site generations: `(site, generation)` pairs
/// carrying at least one physical call. Projection prefers these
/// rows; zero-call and unmatched rows fill the remaining budget.
pub(crate) fn used_site_generations<'a>(
    sites: impl Iterator<Item = &'a SiteExecution>,
) -> std::collections::BTreeSet<(SiteKey, u32)> {
    sites
        .filter(|site| site.calls > 0)
        .map(|site| (site.site.clone(), site.generation))
        .collect()
}

/// Row-granularity selection: whole site rows are retained or
/// omitted, so every retained site's metadata is complete. Greedy in
/// priority order (used rows in input order, then remaining rows in
/// input order); a row that does not fit is omitted but selection
/// continues, so a later small row can still be retained. Fully
/// deterministic for a given input order.
pub(crate) struct MetadataRowSelection {
    pub retained: Vec<bool>,
    pub omitted_sites: usize,
    pub omitted_associations: usize,
}

pub(crate) fn select_metadata_rows(
    rows: &[crate::focused_count::SiteAssociations],
    used: &std::collections::BTreeSet<(SiteKey, u32)>,
    budget: usize,
) -> MetadataRowSelection {
    let is_used: Vec<bool> = rows
        .iter()
        .map(|row| used.contains(&(row.site.clone(), row.count_generation)))
        .collect();
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&index| (!is_used[index], index));
    let mut retained = vec![false; rows.len()];
    let mut bytes = 0usize;
    let mut omitted_sites = 0usize;
    let mut omitted_associations = 0usize;
    for index in order {
        let cost = metadata_row_cost_bytes(&rows[index]);
        match bytes.checked_add(cost) {
            Some(next) if next <= budget => {
                bytes = next;
                retained[index] = true;
            }
            _ => {
                omitted_sites += 1;
                omitted_associations += rows[index].associations.len();
            }
        }
    }
    MetadataRowSelection {
        retained,
        omitted_sites,
        omitted_associations,
    }
}

fn build_metadata_projection(
    rows: &[crate::focused_count::SiteAssociations],
    selection: &MetadataRowSelection,
) -> MetadataProjection {
    let mut identities = std::collections::BTreeMap::new();
    let mut site_provenance = Vec::new();
    for (row, keep) in rows.iter().zip(selection.retained.iter()) {
        if !keep {
            continue;
        }
        site_provenance.push(SiteProvenance {
            site: row.site.clone(),
            count_generation: row.count_generation,
            associations: row
                .associations
                .iter()
                .map(|a| {
                    let algorithm_id = a.algorithm.map(|id| id.to_string());
                    if let Some(id) = &algorithm_id {
                        identities
                            .entry(id.clone())
                            .or_insert(a.known_algorithm.filter(|n| *n != u16::MAX));
                    }
                    CandidateProvenance {
                        algorithm_id,
                        origin: a.origin,
                        operation: a.operation,
                        function_id: a.function_id,
                        advertisers: a.advertisers.clone(),
                        static_provenance: a.static_provenance,
                        storage: a.storage,
                        partial: a.partial,
                        alias_quality: a.alias_quality,
                        observed_ns: a.observed_ns,
                        observation_generation: a.observation_generation,
                    }
                })
                .collect(),
        });
    }
    let reason = if selection.omitted_sites == 0 && selection.omitted_associations == 0 {
        MetadataProjectionReason::Complete
    } else {
        MetadataProjectionReason::OverBudget
    };
    MetadataProjection {
        algorithm_identities: identities
            .into_iter()
            .map(|(id, known_algorithm)| AlgorithmIdentity {
                id,
                known_algorithm,
            })
            .collect(),
        site_provenance,
        omitted_sites: selection.omitted_sites,
        omitted_associations: selection.omitted_associations,
        reason,
    }
}

/// Project bounded candidate metadata from a finalized document's
/// internal association handoff. Used (executed) site rows are
/// preferred; remaining rows fill the budget in stable input order;
/// omitted rows are counted explicitly with the reason. Physical
/// sites, counts, attribution and policy inputs are never modified —
/// the caller applies the retained sections. When every row fits,
/// the retained sections equal the unbounded projection exactly.
pub fn project_metadata_bounded(doc: &CaptureDocument, budget: usize) -> MetadataProjection {
    let used = used_site_generations(
        doc.sites
            .iter()
            .chain(doc.fenced.iter().flat_map(|bucket| bucket.sites.iter())),
    );
    let selection = select_metadata_rows(&doc.candidate_associations, &used, budget);
    build_metadata_projection(&doc.candidate_associations, &selection)
}

#[cfg(test)]
mod t5_schema_d_record_tests {
    use super::*;

    #[test]
    fn hostile_cell_1_poisoned_table_strings_yield_unknown() {
        for poison in [
            "9.9.9-EVIL",
            "3.5.8-EVIL",
            "3",
            "",
            "3.5.8 ",
            "v3.5.8",
            "03.05.01",
        ] {
            // "03.05.01" is numeric-dot but not a known family.
            assert_eq!(OpensslFamily::coarsen(poison), None, "{poison:?}");
            let version = accumulate_openssl_family(&[VersionObservation {
                table_openssl: Some(poison.to_string()),
            }]);
            assert_eq!(version, OpensslVersion::unknown(), "{poison:?}");
        }
        // Controls: genuine table strings coarsen; extra numeric parts
        // and bare major.minor are unambiguous, so they coarsen too.
        for (raw, family) in [
            ("3.0.22", OpensslFamily::V3_0),
            ("4.0.2", OpensslFamily::V4_0),
            ("3.5", OpensslFamily::V3_5),
            ("3.5.8.1.2", OpensslFamily::V3_5),
        ] {
            assert_eq!(OpensslFamily::coarsen(raw), Some(family), "{raw:?}");
        }
    }

    #[test]
    fn hostile_cell_2_family_matrix() {
        let obs = |strings: &[Option<&str>]| {
            strings
                .iter()
                .map(|s| VersionObservation {
                    table_openssl: s.map(str::to_string),
                })
                .collect::<Vec<_>>()
        };
        let label = |version: &OpensslVersion| version.version.clone();
        // Zero observations → unknown.
        assert_eq!(accumulate_openssl_family(&[]), OpensslVersion::unknown());
        // One hit → its family.
        assert_eq!(
            label(&accumulate_openssl_family(&obs(&[Some("3.5.8")]))),
            Some("3.5".to_string())
        );
        // Duplicate same-family hits → family.
        assert_eq!(
            label(&accumulate_openssl_family(&obs(&[
                Some("3.5.8"),
                Some("3.5.8")
            ]))),
            Some("3.5".to_string())
        );
        // Multi-patch same-family → family (compatible, not unknown).
        assert_eq!(
            label(&accumulate_openssl_family(&obs(&[
                Some("3.0.22"),
                Some("3.0.25")
            ]))),
            Some("3.0".to_string())
        );
        // Two families → unknown.
        assert_eq!(
            accumulate_openssl_family(&obs(&[Some("3.0.22"), Some("3.5.8")])),
            OpensslVersion::unknown()
        );
        // Eligible-but-unmatched poisons a known hit.
        assert_eq!(
            accumulate_openssl_family(&obs(&[Some("3.0.22"), None])),
            OpensslVersion::unknown()
        );
        // Malformed poisons a known hit.
        assert_eq!(
            accumulate_openssl_family(&obs(&[Some("3.0.22"), Some("9.9.9-EVIL")])),
            OpensslVersion::unknown()
        );
    }

    #[test]
    fn parse_sysctl_value_matrix() {
        // Valid: plain, trimmed, negative (data, never sentinel).
        assert_eq!(parse_sysctl_value("4\n"), Some(4));
        assert_eq!(parse_sysctl_value("  0  "), Some(0));
        assert_eq!(parse_sysctl_value("-1\n"), Some(-1));
        assert_eq!(parse_sysctl_value("9223372036854775807"), Some(i64::MAX));
        // Invalid: empty, malformed, overflowing, bare sign.
        assert_eq!(parse_sysctl_value(""), None);
        assert_eq!(parse_sysctl_value("   \n"), None);
        assert_eq!(parse_sysctl_value("unreadable"), None);
        assert_eq!(parse_sysctl_value("4x"), None);
        assert_eq!(parse_sysctl_value("0x4"), None);
        assert_eq!(parse_sysctl_value("-"), None);
        assert_eq!(parse_sysctl_value("9223372036854775808"), None);
        assert_eq!(parse_sysctl_value("4.0"), None);
    }

    #[test]
    fn stamp_context_upgrades_schema_only_with_sysctls() {
        let mut doc = finalize(FinalizeInput {
            corpse_wait: None,
            window: CaptureWindow {
                requested_start_ns: 0,
                requested_end_ns: 0,
                effective_start_ns: 0,
                effective_end_ns: 0,
                signal_cut: false,
                count_admission: None,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        assert_eq!(doc.schema, CAPTURE_SCHEMA_V2);
        stamp_context(
            &mut doc,
            CaptureContext {
                kernel_release: "6.9.0-test".to_string(),
                wall_start_unix_ns: None,
                wall_end_unix_ns: None,
                sysctls: None,
            },
        );
        assert_eq!(doc.schema, CAPTURE_SCHEMA_V2);
        stamp_context(
            &mut doc,
            CaptureContext {
                kernel_release: "6.9.0-test".to_string(),
                wall_start_unix_ns: None,
                wall_end_unix_ns: None,
                sysctls: Some(SysctlContext {
                    perf_event_paranoid: Some(4),
                    kptr_restrict: None,
                    unprivileged_bpf_disabled: Some(2),
                    ptrace_scope: Some(1),
                }),
            },
        );
        assert_eq!(doc.schema, CAPTURE_SCHEMA_V2_6);
        assert!(doc.context.unwrap().sysctls.is_some());
    }

    static SYSCTL_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn sysctl_scratch(test: &str) -> std::path::PathBuf {
        let n = SYSCTL_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "osslscope-sysctl-{}-{}-{}",
            std::process::id(),
            test,
            n
        ));
        std::fs::create_dir_all(dir.join("kernel/yama")).unwrap();
        dir
    }

    fn write_sysctl(root: &std::path::Path, relative: &str, text: &str) {
        std::fs::write(root.join(relative), text).unwrap();
    }

    #[test]
    fn hostile_cell_5_sample_matrix() {
        // All valid, including legitimate `-1` data and nested
        // yama path.
        let root = sysctl_scratch("valid");
        write_sysctl(&root, "kernel/perf_event_paranoid", "-1\n");
        write_sysctl(&root, "kernel/kptr_restrict", "1\n");
        write_sysctl(&root, "kernel/unprivileged_bpf_disabled", "2\n");
        write_sysctl(&root, "kernel/yama/ptrace_scope", "0\n");
        assert_eq!(
            sample_sysctls_from(&root),
            SysctlContext {
                perf_event_paranoid: Some(-1),
                kptr_restrict: Some(1),
                unprivileged_bpf_disabled: Some(2),
                ptrace_scope: Some(0),
            }
        );
        // Partial + full read failures: keys absent, the sample as
        // a whole never fails (capture continues).
        let root = sysctl_scratch("missing");
        assert_eq!(
            sample_sysctls_from(&root),
            SysctlContext {
                perf_event_paranoid: None,
                kptr_restrict: None,
                unprivileged_bpf_disabled: None,
                ptrace_scope: None,
            }
        );
        write_sysctl(&root, "kernel/perf_event_paranoid", "4\n");
        let sample = sample_sysctls_from(&root);
        assert_eq!(sample.perf_event_paranoid, Some(4));
        assert_eq!(sample.kptr_restrict, None);
        // Malformed, empty, and overflowing inputs yield absent
        // keys, never sentinels or passthrough.
        let root = sysctl_scratch("malformed");
        write_sysctl(&root, "kernel/perf_event_paranoid", "unreadable");
        write_sysctl(&root, "kernel/kptr_restrict", "");
        write_sysctl(&root, "kernel/unprivileged_bpf_disabled", "4x");
        write_sysctl(&root, "kernel/yama/ptrace_scope", "9223372036854775808");
        assert_eq!(
            sample_sysctls_from(&root),
            SysctlContext {
                perf_event_paranoid: None,
                kptr_restrict: None,
                unprivileged_bpf_disabled: None,
                ptrace_scope: None,
            }
        );
    }

    #[test]
    fn hostile_cell_5_sample_frozen_no_reread() {
        // Rule 7: one admission-event sample, retained through
        // finalization, never reread. Mutating the source after
        // sampling cannot move the retained value or the stamp.
        let root = sysctl_scratch("frozen");
        write_sysctl(&root, "kernel/perf_event_paranoid", "4\n");
        let retained = sample_sysctls_from(&root);
        assert_eq!(retained.perf_event_paranoid, Some(4));
        write_sysctl(&root, "kernel/perf_event_paranoid", "0\n");
        std::fs::remove_file(root.join("kernel/perf_event_paranoid")).unwrap();
        assert_eq!(retained.perf_event_paranoid, Some(4));
        let mut doc = finalize(FinalizeInput {
            corpse_wait: None,
            window: CaptureWindow {
                requested_start_ns: 0,
                requested_end_ns: 0,
                effective_start_ns: 0,
                effective_end_ns: 0,
                signal_cut: false,
                count_admission: None,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: TargetRecord::unknown(),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        stamp_context(
            &mut doc,
            CaptureContext {
                kernel_release: "6.9.0-test".to_string(),
                wall_start_unix_ns: None,
                wall_end_unix_ns: None,
                sysctls: Some(retained),
            },
        );
        assert_eq!(
            doc.context.unwrap().sysctls.unwrap().perf_event_paranoid,
            Some(4)
        );
    }
}

#[cfg(test)]
mod bounded_projection_tests {
    use super::*;
    use crate::focused_count::{CandidateAssociation, SiteAssociations};
    use crate::provider_observation::static_tables::{
        DynamicAlgorithmId, StaticTableProvenance, TableStorage,
    };
    use crate::provider_observation::wire::contract::Record;
    use crate::provider_observation::{AliasQuality, MetadataOrigin, ObjectHash};

    fn alg_id(invocation: u64) -> DynamicAlgorithmId {
        let object = ObjectHash::try_from("c".repeat(64)).unwrap();
        let record = Record {
            invocation,
            ..Default::default()
        };
        DynamicAlgorithmId::observed(&object, 99, &record)
    }

    fn assoc(algorithm: Option<DynamicAlgorithmId>, known: Option<u16>) -> CandidateAssociation {
        CandidateAssociation {
            origin: MetadataOrigin::StaticPublicTableCandidate,
            algorithm,
            known_algorithm: known,
            alias_quality: AliasQuality::default(),
            operation: None,
            function_id: 7,
            advertisers: Vec::new(),
            static_provenance: Some(StaticTableProvenance::DispatchTableShape),
            storage: Some(TableStorage::ReadOnly),
            partial: false,
            observed_ns: 20,
            observation_generation: 9,
        }
    }

    fn exec_site(calls: u64, offset: u64) -> SiteExecution {
        SiteExecution {
            site: SiteKey {
                object: ObjectId("a".repeat(64)),
                device: 1,
                inode: 2,
                offset,
            },
            generation: 1,
            candidates: Vec::new(),
            candidates_coverage: CandidateCoverage::Unknown,
            calls,
            first_ns: if calls == 0 { 0 } else { 30 },
            last_ns: if calls == 0 { 0 } else { 40 },
            installed_at: Some(20),
        }
    }

    fn row(offset: u64, associations: Vec<CandidateAssociation>) -> SiteAssociations {
        SiteAssociations {
            site: SiteKey {
                object: ObjectId("a".repeat(64)),
                device: 1,
                inode: 2,
                offset,
            },
            count_generation: 1,
            associations,
        }
    }

    fn doc_with(sites: Vec<SiteExecution>, rows: Vec<SiteAssociations>) -> CaptureDocument {
        let mut doc = finalize(FinalizeInput {
            corpse_wait: None,
            window: CaptureWindow {
                requested_start_ns: 10,
                requested_end_ns: 100,
                effective_start_ns: 10,
                effective_end_ns: 100,
                signal_cut: false,
                count_admission: None,
            },
            sites,
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: TargetRecord::new(42, "unknown".into(), String::new(), String::new()),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        doc.candidate_associations = rows;
        doc
    }

    #[test]
    fn zero_budget_omits_everything_without_touching_physical() {
        let sites = vec![exec_site(37, 5), exec_site(0, 6)];
        let rows = vec![
            row(5, vec![assoc(None, None)]),
            row(6, vec![assoc(None, None), assoc(None, None)]),
        ];
        let doc = doc_with(sites, rows);
        let before = doc.clone();
        let projection = project_metadata_bounded(&doc, 0);
        assert!(projection.algorithm_identities.is_empty());
        assert!(projection.site_provenance.is_empty());
        assert_eq!(projection.omitted_sites, 2);
        assert_eq!(projection.omitted_associations, 3);
        assert_eq!(projection.reason, MetadataProjectionReason::OverBudget);
        assert_eq!(doc, before);
        assert_eq!(doc.total_calls(), 37);
    }

    #[test]
    fn one_over_budget_omits_exactly_one_row_in_stable_order() {
        let single = row(7, vec![assoc(None, None)]);
        let cost = metadata_row_cost_bytes(&single);
        let sites = vec![exec_site(0, 7), exec_site(0, 8)];
        let rows = vec![single, row(8, vec![assoc(None, None)])];
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, 2 * cost - 1);
        assert_eq!(projection.site_provenance.len(), 1);
        assert_eq!(projection.site_provenance[0].site.offset, 7);
        assert_eq!(projection.omitted_sites, 1);
        assert_eq!(projection.omitted_associations, 1);
        assert_eq!(projection.reason, MetadataProjectionReason::OverBudget);
        let exact = project_metadata_bounded(&doc, 2 * cost);
        assert_eq!(exact.site_provenance.len(), 2);
        assert_eq!(exact.reason, MetadataProjectionReason::Complete);
    }

    #[test]
    fn used_rows_win_over_earlier_unused_rows() {
        let used = row(9, vec![assoc(None, None)]);
        let cost = metadata_row_cost_bytes(&used);
        let sites = vec![exec_site(11, 9), exec_site(0, 10)];
        // Unused row first in input order; the used row must still win
        // the single-row budget, and output keeps input order.
        let rows = vec![row(10, vec![assoc(None, None)]), used];
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, cost);
        assert_eq!(projection.site_provenance.len(), 1);
        assert_eq!(projection.site_provenance[0].site.offset, 9);
        assert_eq!(projection.omitted_sites, 1);
        assert_eq!(projection.reason, MetadataProjectionReason::OverBudget);
    }

    #[test]
    fn unmatched_rows_are_lowest_priority() {
        let used = row(12, vec![assoc(None, None)]);
        let cost = metadata_row_cost_bytes(&used);
        let sites = vec![exec_site(5, 12)];
        let rows = vec![row(13, vec![assoc(None, None)]), used];
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, cost);
        assert_eq!(projection.site_provenance.len(), 1);
        assert_eq!(projection.site_provenance[0].site.offset, 12);
        assert_eq!(projection.omitted_sites, 1);
    }

    #[test]
    fn small_rows_after_an_over_budget_row_are_still_retained() {
        let huge = row(14, vec![assoc(None, None); 10_000]);
        let small = row(15, vec![assoc(None, None)]);
        let small_cost = metadata_row_cost_bytes(&small);
        assert!(metadata_row_cost_bytes(&huge) > small_cost);
        let sites = vec![exec_site(0, 14), exec_site(0, 15)];
        let doc = doc_with(sites, vec![huge, small]);
        let projection = project_metadata_bounded(&doc, small_cost);
        assert_eq!(projection.site_provenance.len(), 1);
        assert_eq!(projection.site_provenance[0].site.offset, 15);
        assert_eq!(projection.omitted_sites, 1);
        assert_eq!(projection.omitted_associations, 10_000);
    }

    #[test]
    fn interning_is_deterministic_across_input_orders() {
        let first = alg_id(1);
        let second = alg_id(2);
        assert_ne!(first.to_string(), second.to_string());
        let sites = vec![exec_site(3, 16), exec_site(4, 17)];
        let forward = doc_with(
            sites.clone(),
            vec![
                row(16, vec![assoc(Some(first), Some(9))]),
                row(17, vec![assoc(Some(second), None)]),
            ],
        );
        let backward = doc_with(
            sites,
            vec![
                row(17, vec![assoc(Some(second), None)]),
                row(16, vec![assoc(Some(first), Some(9))]),
            ],
        );
        let budget = METADATA_PROJECTION_BUDGET_BYTES;
        let a = project_metadata_bounded(&forward, budget);
        let b = project_metadata_bounded(&backward, budget);
        assert_eq!(a.algorithm_identities, b.algorithm_identities);
        assert_eq!(a.algorithm_identities.len(), 2);
        let mut sorted = a.algorithm_identities.clone();
        sorted.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(a.algorithm_identities, sorted);
        // Same input projects identically on repeat (provenance keeps
        // input order, so only the identities are order-independent).
        assert_eq!(a, project_metadata_bounded(&forward, budget));
    }

    #[test]
    fn retained_references_resolve_and_max_is_filtered() {
        let id = alg_id(3);
        let sites = vec![exec_site(2, 18)];
        let rows = vec![row(
            18,
            vec![
                assoc(Some(id), Some(u16::MAX)),
                assoc(Some(id), Some(9)),
                assoc(None, None),
            ],
        )];
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, METADATA_PROJECTION_BUDGET_BYTES);
        assert_eq!(projection.reason, MetadataProjectionReason::Complete);
        assert_eq!(projection.algorithm_identities.len(), 1);
        // u16::MAX is filtered at first sight; the first-seen entry wins.
        assert_eq!(projection.algorithm_identities[0].known_algorithm, None);
        let ids: std::collections::BTreeSet<&str> = projection
            .algorithm_identities
            .iter()
            .map(|identity| identity.id.as_str())
            .collect();
        for row in &projection.site_provenance {
            for association in &row.associations {
                if let Some(name) = &association.algorithm_id {
                    assert!(ids.contains(name.as_str()), "dangling {name}");
                }
            }
        }
    }

    #[test]
    fn fits_case_retains_everything_complete_in_input_order() {
        let sites = vec![exec_site(1, 21), exec_site(0, 19), exec_site(7, 20)];
        let rows = vec![
            row(21, vec![assoc(None, None)]),
            row(19, vec![assoc(None, None)]),
            row(20, vec![assoc(None, None), assoc(None, None)]),
        ];
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, METADATA_PROJECTION_BUDGET_BYTES);
        assert_eq!(projection.reason, MetadataProjectionReason::Complete);
        assert_eq!(projection.omitted_sites, 0);
        assert_eq!(projection.omitted_associations, 0);
        let offsets: Vec<u64> = projection
            .site_provenance
            .iter()
            .map(|row| row.site.offset)
            .collect();
        assert_eq!(offsets, vec![21, 19, 20]);
    }

    #[test]
    fn huge_unknown_sets_stay_bounded_and_counted() {
        let mut sites = Vec::new();
        let mut rows = Vec::new();
        for offset in 0..50_000u64 {
            sites.push(exec_site(0, offset));
            rows.push(row(offset, vec![assoc(None, None)]));
        }
        let doc = doc_with(sites, rows);
        let projection = project_metadata_bounded(&doc, METADATA_PROJECTION_BUDGET_BYTES);
        assert_eq!(projection.reason, MetadataProjectionReason::OverBudget);
        assert_eq!(
            projection.site_provenance.len() + projection.omitted_sites,
            50_000
        );
        assert_eq!(
            projection.omitted_associations, projection.omitted_sites,
            "one association per row"
        );
        assert!(
            projection.site_provenance.len() > 1_000,
            "bounded output must retain a useful prefix"
        );
    }
}
