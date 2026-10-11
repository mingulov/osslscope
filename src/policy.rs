//! SPDX-License-Identifier: GPL-3.0-or-later
//! T01 pure policy predicate primitives (spec R06).
//!
//! No CLI wiring: these are total functions over
//! [`crate::evidence`] types. CLI parsing, exit mapping and artifact
//! delivery belong to T10/T11. Ambiguity inside one alias list (mixed
//! or unresolved algorithm classes) and ambiguity between candidates
//! (mixed per-candidate outcomes in `match_bounds`) both shape
//! definite/possible bounds; there is no boolean-first-alias shortcut.

use crate::evidence::{
    CandidateCoverage, CandidateIdentity, CaptureDocument, Completeness, GapReason, MatchBounds,
    PredicateMatch, RuleVerdict, SiteExecution, SiteKey, match_bounds,
};

/// Classification bucket for unknown, aliased, overlong or unreadable
/// algorithm input. A candidate carrying this class can prove neither
/// an algorithm match nor an algorithm absence.
pub const UNRESOLVED_ALGORITHM_CLASS: &str = "other";

/// Classification bucket for unattributed provider identity
/// (capture synthesizes this until T09 pinned classification lands).
/// A candidate carrying this class can prove neither a provider match
/// nor a provider absence.
pub const UNRESOLVED_PROVIDER_CLASS: &str = "unknown";

/// Pure predicate over one candidate identity. Algorithm predicates
/// are three-valued over the candidate's whole class list; provider,
/// operation and weak-alias predicates are certain even when the
/// algorithm alone is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Algorithm(String),
    /// Algorithm match with parameter-blind-op awareness (T10/R06):
    /// like [`Predicate::Algorithm`], except a non-matching class list
    /// at a MAC/KDF/SIGNATURE/ASYM_CIPHER site is `Unknown` instead of
    /// `No` — a parameter-selected digest/cipher component (never
    /// captured) could be the wanted name. A definite all-class match
    /// still yields `Yes`.
    AlgorithmParamAware(String),
    ProviderClass(String),
    ProviderObject(String),
    Op(u32),
    FuncId(u32),
    WeakAlias,
    /// Weak-or-possibly-weak (T10/R06): `Yes` iff the alias is weak,
    /// `Unknown` iff the class list is empty or carries an unresolved
    /// class (an unknown class could be weak), or the site is a
    /// parameter-blind op whose unseen digest/cipher could be weak
    /// (F-E/B6); else `No`.
    WeakOrUnresolved,
    Not(Box<Predicate>),
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
}

impl Predicate {
    /// Evaluate against one candidate. `Algorithm` is `Yes` only when
    /// every recognized class equals the target, `No` only when none
    /// does and none is unresolved; mixed lists, empty lists and lists
    /// containing [`UNRESOLVED_ALGORITHM_CLASS`] are `Unknown`.
    /// Class-list algorithm match shared by [`Predicate::Algorithm`]
    /// and [`Predicate::AlgorithmParamAware`]: `Yes` only when every
    /// recognized class equals the target, `No` only when none does and
    /// none is unresolved; mixed lists, empty lists and lists containing
    /// [`UNRESOLVED_ALGORITHM_CLASS`] are `Unknown`.
    fn eval_algorithm(want: &str, c: &CandidateIdentity) -> PredicateMatch {
        if c.algorithm_classes.is_empty() {
            return PredicateMatch::Unknown;
        }
        if c.algorithm_classes
            .iter()
            .any(|a| a == UNRESOLVED_ALGORITHM_CLASS)
        {
            return PredicateMatch::Unknown;
        }
        let matching = c.algorithm_classes.iter().filter(|a| *a == want).count();
        if matching == c.algorithm_classes.len() {
            PredicateMatch::Yes
        } else if matching == 0 {
            PredicateMatch::No
        } else {
            PredicateMatch::Unknown
        }
    }

    pub fn eval(&self, c: &CandidateIdentity) -> PredicateMatch {
        match self {
            Predicate::Algorithm(want) => Self::eval_algorithm(want, c),
            Predicate::AlgorithmParamAware(want) => match Self::eval_algorithm(want, c) {
                PredicateMatch::No if param_blind_op(c.op) => PredicateMatch::Unknown,
                other => other,
            },
            Predicate::ProviderClass(want) => {
                if c.provider_class == UNRESOLVED_PROVIDER_CLASS {
                    PredicateMatch::Unknown
                } else if &c.provider_class == want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::ProviderObject(want) => {
                if &c.provider.0 == want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::Op(want) => {
                if c.op == *want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::FuncId(want) => {
                if c.funcid == *want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::WeakAlias => {
                if c.weak_alias {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::WeakOrUnresolved => {
                if c.weak_alias {
                    PredicateMatch::Yes
                } else if c.algorithm_classes.is_empty()
                    || c.algorithm_classes
                        .iter()
                        .any(|a| a == UNRESOLVED_ALGORITHM_CLASS)
                {
                    PredicateMatch::Unknown
                } else if param_blind_op(c.op) {
                    // F-E/B6: a resolved non-weak class list at a
                    // parameter-blind op (MAC/KDF/SIGNATURE/
                    // ASYM_CIPHER) does not rule out a weak
                    // parameter-selected digest/cipher, which is
                    // never captured — same upgrade as
                    // AlgorithmParamAware.
                    PredicateMatch::Unknown
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::Not(inner) => match inner.eval(c) {
                PredicateMatch::Yes => PredicateMatch::No,
                PredicateMatch::No => PredicateMatch::Yes,
                PredicateMatch::Unknown => PredicateMatch::Unknown,
            },
            Predicate::All(parts) => {
                let mut out = PredicateMatch::Yes;
                for p in parts {
                    match p.eval(c) {
                        PredicateMatch::No => return PredicateMatch::No,
                        PredicateMatch::Unknown => out = PredicateMatch::Unknown,
                        PredicateMatch::Yes => {}
                    }
                }
                out
            }
            Predicate::Any(parts) => {
                let mut out = PredicateMatch::No;
                for p in parts {
                    match p.eval(c) {
                        PredicateMatch::Yes => return PredicateMatch::Yes,
                        PredicateMatch::Unknown => out = PredicateMatch::Unknown,
                        PredicateMatch::No => {}
                    }
                }
                out
            }
        }
    }

    /// Adapter for `crate::evidence::match_bounds`.
    pub fn as_fn(&self) -> impl Fn(&CandidateIdentity) -> PredicateMatch + '_ {
        |c| self.eval(c)
    }
}

/// One policy rule. Rules are ANDed by the caller; `--require-provider`
/// stays existential (at least one definite execution of that class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Require(Predicate),
    Deny(Predicate),
}

/// Require-X over conserved bounds with explicit relevant completeness
/// (complete relevant coverage and candidates, as decided by the
/// caller): definite use passes; clean absence in a complete window
/// violates; possible or unknown use, or incomplete relevance, is
/// inconclusive — the requirement is unproven, never fabricated.
pub fn evaluate_require(bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    if bounds.definite > 0 {
        RuleVerdict::Pass
    } else if relevant_complete && bounds.possible == Some(0) {
        RuleVerdict::Violation
    } else {
        RuleVerdict::Inconclusive
    }
}

/// Deny-X over conserved bounds: definite use violates; clean absence
/// in a complete window passes; possible or unknown use, or incomplete
/// relevance, is inconclusive — never a definite violation from an
/// ambiguous candidate.
pub fn evaluate_deny(bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    if bounds.definite > 0 {
        RuleVerdict::Violation
    } else if relevant_complete && bounds.possible == Some(0) {
        RuleVerdict::Pass
    } else {
        RuleVerdict::Inconclusive
    }
}

/// Evaluate one rule over conserved bounds.
pub fn evaluate_rule(rule: &Rule, bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    match rule {
        Rule::Require(_) => evaluate_require(bounds, relevant_complete),
        Rule::Deny(_) => evaluate_deny(bounds, relevant_complete),
    }
}

// ---------------------------------------------------------------- T10
// Document-level policy integration (spec R06): CLI-shaped rules over a
// finalized [`CaptureDocument`], per-rule relevance scoping, and definite
// violation evidence. Pure over the document; CLI parsing, exit mapping
// and artifact delivery live in `crate::check`.

/// Provider class identifying legacy ENGINE tripwire executions. T08
/// convention, consumed here: ENGINE calls surface as sites carrying
/// this class (backing object stays the executing object).
pub const ENGINE_PROVIDER_CLASS: &str = "engine";

/// Provider class whose executions may include unlabeled FIPS
/// self-test (KAT) calls. KATs are never excluded; their calls count
/// like any other execution (fail closed) and are tallied separately.
pub const FIPS_PROVIDER_CLASS: &str = "fips";

/// True for operations whose executed algorithm identity has a
/// parameter-selected component (digest/cipher parameter, never
/// captured): MAC, KDF, SIGNATURE, and ASYM_CIPHER (OAEP digest).
/// Resolved through the frozen registry so drift fails the op-set test
/// loudly instead of silently narrowing this list.
fn param_blind_op(op: u32) -> bool {
    const NAMES: [&str; 4] = [
        "OSSL_OP_MAC",
        "OSSL_OP_KDF",
        "OSSL_OP_SIGNATURE",
        "OSSL_OP_ASYM_CIPHER",
    ];
    NAMES
        .iter()
        .filter_map(|n| crate::kinds::op_id(n))
        .any(|id| id == op)
}

/// Area a rule reasons about. Engine-area rules (matching only the
/// [`ENGINE_PROVIDER_CLASS`]) trust no blind spot: any gap fails their
/// absence proofs closed, because coverage scope names are
/// producer-defined and no name proves a gap cannot hide ENGINE use.
/// Provider-area rules are blind only to explicitly engine-area gaps,
/// which cannot hide provider-dispatch execution (a different
/// mechanism with separate counters). Every other gap is relevant to
/// both areas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleArea {
    Provider,
    Engine,
}

/// Scope/counter naming convention consumed from T06/T08 producers: the
/// `legacy.`/`engine.` (`:` accepted) prefixes — or the bare names —
/// denote legacy-engine instrumentation. Anything else is provider-area
/// or generic. Unknown names fail closed: generic losses and time gaps
/// stay relevant to every rule; only explicitly engine-area items are
/// ever treated as unrelated, and only by provider-area rules.
fn is_engine_area(name: &str) -> bool {
    name == "engine"
        || name == "legacy"
        || name.starts_with("engine.")
        || name.starts_with("engine:")
        || name.starts_with("legacy.")
        || name.starts_with("legacy:")
}

/// Area of a predicate rule: engine iff it matches exactly the engine
/// provider class. Compound predicates stay provider-area (fail closed).
pub fn rule_area(rule: &Rule) -> RuleArea {
    match rule {
        Rule::Require(Predicate::ProviderClass(s)) | Rule::Deny(Predicate::ProviderClass(s))
            if s == ENGINE_PROVIDER_CLASS =>
        {
            RuleArea::Engine
        }
        _ => RuleArea::Provider,
    }
}

fn gap_relevant_to(area: RuleArea, reason: &GapReason) -> bool {
    match reason {
        // Unobserved time and unattributed calls could hide any use.
        GapReason::StartupGap { .. }
        | GapReason::TailGap { .. }
        | GapReason::SignalCut
        | GapReason::UnattributedCalls { .. } => true,
        // Any loss could drop tripwire data, so engine rules trust no
        // loss; engine-internal loss cannot hide provider execution.
        GapReason::Loss { counter, .. } => match area {
            RuleArea::Engine => true,
            RuleArea::Provider => !is_engine_area(counter),
        },
        // Coverage scope names are producer-defined: engine rules
        // fail closed on every coverage blind spot, since no name
        // proves the gap is disjoint from ENGINE use. Provider rules
        // ignore explicitly engine-area scopes only.
        GapReason::UnknownDenominator { scope }
        | GapReason::UndiscoveredSites { scope, .. }
        | GapReason::UnattachedSites { scope, .. } => match area {
            RuleArea::Engine => true,
            RuleArea::Provider => !is_engine_area(scope),
        },
    }
}

/// Relevant completeness for one rule over a finalized document:
/// COMPLETE is complete for every rule; PARTIAL is complete for a rule
/// iff no gap relevant to its area remains. (Fatal documents never
/// reach per-rule evaluation — see [`evaluate_document`].) Activity
/// counters never appear here: only typed loss/coverage/time gaps do,
/// so query/load/activity tallies cannot shape verdicts.
pub fn relevant_complete(area: RuleArea, doc: &CaptureDocument) -> bool {
    match &doc.status {
        Completeness::Complete => true,
        Completeness::Fatal { .. } => false,
        Completeness::Partial { reasons } => !reasons.iter().any(|r| gap_relevant_to(area, r)),
    }
}

/// One CLI-shaped policy rule: the flag name, its matcher text (empty
/// for `--deny-engine`/`--deny-weak`), and the predicate rule. The
/// constructors below are the single CLI→predicate mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub name: &'static str,
    pub matcher: String,
    pub rule: Rule,
}

impl PolicyRule {
    /// Existential: at least one definite execution of the class.
    pub fn require_provider(class: &str) -> Self {
        Self {
            name: "require-provider",
            matcher: class.to_string(),
            rule: Rule::Require(Predicate::ProviderClass(class.to_string())),
        }
    }

    pub fn deny_provider(class: &str) -> Self {
        Self {
            name: "deny-provider",
            matcher: class.to_string(),
            rule: Rule::Deny(Predicate::ProviderClass(class.to_string())),
        }
    }

    pub fn deny_engine() -> Self {
        Self {
            name: "deny-engine",
            // F-E/B1: the matcher doubles as the v2 "predicate"
            // (minLength 1) and the human display; an argument-less
            // rule still needs a canonical nonempty token.
            matcher: ENGINE_PROVIDER_CLASS.to_string(),
            rule: Rule::Deny(Predicate::ProviderClass(ENGINE_PROVIDER_CLASS.to_string())),
        }
    }

    pub fn deny_algorithm(algorithm: &str) -> Self {
        Self {
            name: "deny-algorithm",
            matcher: algorithm.to_string(),
            rule: Rule::Deny(Predicate::AlgorithmParamAware(algorithm.to_string())),
        }
    }

    pub fn deny_weak() -> Self {
        Self {
            name: "deny-weak",
            // F-E/B1: canonical token, see deny_engine.
            matcher: "weak".to_string(),
            rule: Rule::Deny(Predicate::WeakOrUnresolved),
        }
    }

    pub fn require_executed(algorithm: &str) -> Self {
        Self {
            name: "require-executed",
            matcher: algorithm.to_string(),
            rule: Rule::Require(Predicate::AlgorithmParamAware(algorithm.to_string())),
        }
    }

    fn predicate(&self) -> &Predicate {
        match &self.rule {
            Rule::Require(p) | Rule::Deny(p) => p,
        }
    }
}

/// One definitely matching executed site (R02 provenance): the physical
/// site key, its generation, and conserved call evidence. Only sites
/// whose every candidate matches (complete attribution, nonzero calls)
/// appear here — possible use is never listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefiniteHit {
    pub site: SiteKey,
    pub generation: u32,
    pub fenced: bool,
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub candidates: Vec<CandidateIdentity>,
}

/// One evaluated rule: conserved bounds, relevance, verdict, and — for
/// deny rules with definite matches — the hit sites behind the
/// violation. Require violations carry no hits (nothing matched).
/// `legacy_engine_calls` is nonzero only when the pre-T08 legacy
/// tripwire fallback (see [`apply_legacy_engine_fallback`]) supplied
/// the violation: untimed ENGINE evidence with no document site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedRule {
    pub name: &'static str,
    pub matcher: String,
    pub bounds: MatchBounds,
    pub relevant_complete: bool,
    pub verdict: RuleVerdict,
    pub hits: Vec<DefiniteHit>,
    pub legacy_engine_calls: u64,
}

/// Overall policy outcome: rules are ANDed (violation dominates
/// inconclusive dominates pass); fatal evidence yields no verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOutcome {
    Pass,
    Violation,
    Inconclusive,
    NoVerdict,
}

/// Evaluated policy over one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub no_verdict: bool,
    pub rules: Vec<EvaluatedRule>,
}

impl PolicyVerdict {
    pub fn overall(&self) -> PolicyOutcome {
        if self.no_verdict {
            return PolicyOutcome::NoVerdict;
        }
        let mut outcome = PolicyOutcome::Pass;
        for r in &self.rules {
            match r.verdict {
                RuleVerdict::Violation => return PolicyOutcome::Violation,
                RuleVerdict::Inconclusive => outcome = PolicyOutcome::Inconclusive,
                RuleVerdict::Pass => {}
            }
        }
        outcome
    }
}

fn site_is_definite(predicate: &Predicate, site: &SiteExecution) -> bool {
    if site.calls == 0
        || site.candidates_coverage != CandidateCoverage::Complete
        || site.candidates.is_empty()
    {
        return false;
    }
    site.candidates
        .iter()
        .all(|c| predicate.eval(c) == PredicateMatch::Yes)
}

/// Evaluate every rule over a finalized document (current plus fenced
/// sites, conserved — no site counted twice). Fatal documents yield no
/// verdict and no per-rule results: never a violation without evidence.
pub fn evaluate_document(rules: &[PolicyRule], doc: &CaptureDocument) -> PolicyVerdict {
    if matches!(doc.status, Completeness::Fatal { .. }) {
        return PolicyVerdict {
            no_verdict: true,
            rules: Vec::new(),
        };
    }
    let all: Vec<SiteExecution> = doc
        .sites
        .iter()
        .chain(doc.fenced.iter().flat_map(|g| g.sites.iter()))
        .cloned()
        .collect();
    let evaluated = rules
        .iter()
        .map(|r| {
            let predicate = r.predicate();
            let mut bounds = match_bounds(&all, &predicate.as_fn());
            let area = rule_area(&r.rule);
            let complete = relevant_complete(area, doc);
            // F-E/B5: relevant coverage/loss shapes the published
            // bound, not just the verdict. Definite evidence is
            // preserved, but over a relevant blind spot the upper
            // count is unknown (None renders as null), never a
            // finite number over an unknown denominator.
            if !complete {
                bounds.possible = None;
            }
            let verdict = evaluate_rule(&r.rule, &bounds, complete);
            let hits = match (&r.rule, verdict) {
                (Rule::Deny(_), RuleVerdict::Violation) => {
                    let mut hits: Vec<DefiniteHit> = doc
                        .sites
                        .iter()
                        .filter(|s| site_is_definite(predicate, s))
                        .map(|s| DefiniteHit {
                            site: s.site.clone(),
                            generation: s.generation,
                            fenced: false,
                            calls: s.calls,
                            first_ns: s.first_ns,
                            last_ns: s.last_ns,
                            candidates: s.candidates.clone(),
                        })
                        .collect();
                    for bucket in &doc.fenced {
                        hits.extend(
                            bucket
                                .sites
                                .iter()
                                .filter(|s| site_is_definite(predicate, s))
                                .map(|s| DefiniteHit {
                                    site: s.site.clone(),
                                    generation: bucket.generation,
                                    fenced: true,
                                    calls: s.calls,
                                    first_ns: s.first_ns,
                                    last_ns: s.last_ns,
                                    candidates: s.candidates.clone(),
                                }),
                        );
                    }
                    hits
                }
                _ => Vec::new(),
            };
            EvaluatedRule {
                name: r.name,
                matcher: r.matcher.clone(),
                bounds,
                relevant_complete: complete,
                verdict,
                hits,
                legacy_engine_calls: 0,
            }
        })
        .collect();
    PolicyVerdict {
        no_verdict: false,
        rules: evaluated,
    }
}

/// Fold pre-T08 legacy ENGINE tripwire evidence into an evaluated
/// verdict (fail-closed transition aid). The legacy tripwire counted
/// real in-window ENGINE executions that the document does not yet
/// model as sites; when a deny-engine rule found no definite document
/// hit but the tripwire counted `engine_calls`, upgrade that rule to a
/// definite violation. Never downgrades, never double-counts (document
/// hits win; the tripwire fires only when the document is silent), and
/// never manufactures a pass. No-op for zero calls, no-verdict
/// verdicts, and verdicts without a deny-engine rule. T08 retires this
/// once ENGINE executions surface as document sites.
pub fn apply_legacy_engine_fallback(verdict: &mut PolicyVerdict, engine_calls: u64) {
    if engine_calls == 0 || verdict.no_verdict {
        return;
    }
    for r in &mut verdict.rules {
        if r.name != "deny-engine" || r.verdict == RuleVerdict::Violation {
            continue;
        }
        r.verdict = RuleVerdict::Violation;
        // The tripwire proves at least this many executions; the upper
        // bound is unknown (a contradicting document zero is refuted
        // positive evidence, not a bound).
        r.bounds = MatchBounds {
            definite: engine_calls,
            possible: None,
        };
        r.legacy_engine_calls = engine_calls;
    }
}

/// True when any executed site (current or fenced) carries a
/// candidate on a parameter-blind operation: feeds the `param_blind`
/// caveat. Empty candidate lists prove no param-blind execution.
pub fn executed_param_blind_ops(doc: &CaptureDocument) -> bool {
    doc.sites
        .iter()
        .chain(doc.fenced.iter().flat_map(|g| g.sites.iter()))
        .any(|s| s.calls > 0 && s.candidates.iter().any(|c| param_blind_op(c.op)))
}

/// Executed calls touching the FIPS provider class (any candidate):
/// the unlabeled-KAT exposure count. KATs are never excluded.
pub fn fips_unlabeled_calls(doc: &CaptureDocument) -> u64 {
    doc.sites
        .iter()
        .chain(doc.fenced.iter().flat_map(|g| g.sites.iter()))
        .filter(|s| {
            s.calls > 0
                && s.candidates
                    .iter()
                    .any(|c| c.provider_class == FIPS_PROVIDER_CLASS)
        })
        .map(|s| s.calls)
        .fold(0, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_blind_op_set_is_pinned() {
        // Frozen-registry cross-check: fail loudly on drift.
        assert_eq!(crate::kinds::op_id("OSSL_OP_MAC"), Some(3));
        assert_eq!(crate::kinds::op_id("OSSL_OP_KDF"), Some(4));
        assert_eq!(crate::kinds::op_id("OSSL_OP_SIGNATURE"), Some(12));
        assert_eq!(crate::kinds::op_id("OSSL_OP_ASYM_CIPHER"), Some(13));
        for op in [3, 4, 12, 13] {
            assert!(param_blind_op(op), "op {op} must be parameter-blind");
        }
        for op in [0, 1, 2, 5, 10, 11, 14, 15, 20, 21, 22, 99] {
            assert!(!param_blind_op(op), "op {op} must stay exact");
        }
    }

    #[test]
    fn engine_area_names() {
        for name in [
            "engine",
            "legacy",
            "engine.tripwire",
            "engine:tripwire",
            "legacy.engine_uninstrumented",
            "legacy:meth",
        ] {
            assert!(is_engine_area(name), "{name}");
        }
        for name in [
            "",
            "default",
            "discovery.table_aborted",
            "engineered",
            "legacyx",
            "myengine.stuff",
        ] {
            assert!(!is_engine_area(name), "{name}");
        }
    }

    #[test]
    fn unknown_provider_class_is_unknown() {
        let known = CandidateIdentity::new(
            crate::evidence::ObjectId("p".to_string()),
            "default".to_string(),
            1,
            7,
            vec!["SHA2-256".to_string()],
            false,
        );
        let unknown = CandidateIdentity::new(
            crate::evidence::ObjectId("p".to_string()),
            UNRESOLVED_PROVIDER_CLASS.to_string(),
            1,
            7,
            vec!["SHA2-256".to_string()],
            false,
        );
        let pred = Predicate::ProviderClass("default".to_string());
        assert_eq!(pred.eval(&known), PredicateMatch::Yes);
        assert_eq!(pred.eval(&unknown), PredicateMatch::Unknown);
        let pred = Predicate::ProviderClass("fips".to_string());
        assert_eq!(pred.eval(&known), PredicateMatch::No);
        assert_eq!(pred.eval(&unknown), PredicateMatch::Unknown);
    }

    #[test]
    fn rule_area_mapping() {
        assert_eq!(rule_area(&PolicyRule::deny_engine().rule), RuleArea::Engine);
        assert_eq!(
            rule_area(&PolicyRule::require_provider("engine").rule),
            RuleArea::Engine
        );
        assert_eq!(
            rule_area(&PolicyRule::deny_provider("engine").rule),
            RuleArea::Engine
        );
        for rule in [
            PolicyRule::require_provider("default"),
            PolicyRule::deny_provider("fips"),
            PolicyRule::deny_algorithm("SHA2-256"),
            PolicyRule::deny_weak(),
            PolicyRule::require_executed("SHA2-256"),
        ] {
            assert_eq!(rule_area(&rule.rule), RuleArea::Provider, "{}", rule.name);
        }
    }
}
