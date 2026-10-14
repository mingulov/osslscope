//! SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent discovery session (T06, spec R03/R04).
//!
//! [`DiscoverySession`] is the single discovery engine: it owns the
//! loaded BPF programs/maps, the attach links, the ring consumer,
//! the target pin, and all discovery state until the session drops.
//! Callers poll it in bounded batches and consume typed
//! [`DiscoveryDelta`]s — there is no blocking full harvest and no
//! JSON reparse in the (future T08) count loop. `inspect` and the
//! capture harvest path are thin run-policies over this session
//! (see `harvest::run_detailed`).
//!
//! The engine splits into two layers:
//!
//! * [`SessionCore`], the host-testable state machine: ring decode,
//!   table-epoch binding, monotonic map joins, retry state, and
//!   delta/snapshot accounting. It touches no BPF types directly;
//!   every privileged/file operation goes through [`SessionEnv`].
//! * [`LiveEnv`], the privileged environment behind
//!   [`DiscoverySession`]: the real ring, maps, links, pin, and
//!   `/proc` reads.
//!
//! Wire enums/records stay in `ebpf-common`; the frozen
//! `DiscoverySession`/`DiscoveryConfig`/`DiscoveryDelta`/
//! `DiscoverySnapshot`/`PollBudget`/`CoverageState`/`DiscoveryLoss`
//! surface below is the spec's task boundary (T08 consumes deltas).
//!
//! Epoch binding (T03 follow-up): every observed (op, array) table
//! is bound to its array mapping's incarnation fingerprint
//! `(device, inode, range, file offset)`, reconciled from `/proc`
//! maps on every poll. When the incarnation changes or vanishes,
//! the table retires: its walked set and termination proof drop,
//! the kernel's per-array walker state (`TERMD` proof and
//! `QUERY_NEXT` cursors) is evicted so stale state cannot satisfy
//! the next incarnation, its gap reasons are retained forever, and
//! its rows stay. This closes growth-ABA (a stale proof plus a
//! longer walk is still a prefix, per T03 exact coverage),
//! shrinkage-OOB (an old proof can never terminate a new
//! incarnation), and cursor staleness on reload (the next walk
//! restarts at slot 0). Two more closings (F-A/A4): the ring drains
//! BEFORE reconcile, so stragglers join their own (old) epoch
//! instead of the rebirth (reconcile-first stamped A's evidence
//! with B's epoch); and a repeat init retires its provider file's
//! tables plus every anonymous table — a same-fingerprint rebirth
//! is polling-invisible, so suspicion replaces proof (multi-libctx
//! pays a spurious retire; re-walks re-prove). Residuals remain
//! explicit: content change with no init and no maps delta (token
//! swap behind a static array) is invisible to polling; cross-CPU
//! ring misorder can invert an init and its first re-query
//! (microscopic — the maps reconcile still catches print changes);
//! and a turnover that lands between the kernel's genuine re-proof
//! and the next poll evicts a fresh proof too — fail-safe to
//! prefix, never to false COMPLETE. Eviction failure is explicit
//! loss (`evict_failed`), and loss forces PARTIAL, which contains
//! any surviving stale proof.
//!
//! `no_store` lifetimes stay intact: uncacheable arrays are sampled,
//! never walked to proof, and no array pointer is ever retained
//! beyond its poll — candidates keep classified metadata plus
//! integer join keys only, exactly as before.
//!
//! Teardown is quiesce-then-PROCESS: [`SessionCore::close`] drops
//! the attach links first (quiesce: no new events can arrive),
//! then ingests the ring tail (bounded; only the residual past
//! the bound counts as drain shortfall), joins the maps once more,
//! and verifies the pin — so no post-stop arrival escapes
//! accounting. Prefer `close()` over `drop()`: the `Drop` impl
//! only releases file descriptors and cannot report the tail.
//!
//! The session performs no ELF reads in the poll path: backing
//! triples come from `/proc` maps alone, and foreign-object ELF
//! checks stay at the (cached, per-emit) document-render layer, so
//! only relevant objects are ever read.

use crate::discovery::{builtin, coverage, elf, harvest, legacy, maps};
use crate::loader::Loaded;
use anyhow::{Context as _, anyhow, bail};
use aya::maps::{Map, MapData, RingBuf};
use osslscope_ebpf_common as wire;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Frozen task-boundary types.
// ---------------------------------------------------------------------------

/// Discovery session configuration: what to attach, not how long to
/// run (durations are caller run-policy, e.g. `harvest::Config`).
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Provider `.so` (or libcrypto with `builtin`).
    pub provider: PathBuf,
    /// Harvest BPF object.
    pub object: PathBuf,
    /// Verified harvest byte snapshot (triple runs): when present
    /// the attach loads these bytes instead of re-reading the
    /// path (no reread drift between identity and loading). The
    /// path stays for identity/diags regardless.
    pub object_bytes: Option<Vec<u8>>,
    /// Builtin mode: the in-libcrypto default provider.
    pub builtin: bool,
    /// Legacy tripwires (ENGINE/meth/load/low-level + legacy query).
    pub legacy: bool,
    /// Override build-id table (forensics/redacted-table gates).
    pub table: Option<PathBuf>,
    /// Forced query-fn file offset (forensics escape hatch).
    pub force_offset: Option<u64>,
    /// Operator explicitly selected offsets (`--table` or
    /// `--force-offset`): unlocks the version-keyed anchor+delta
    /// rung. False (automatic discovery) uses the supported-only
    /// ladder — table hit or symtab — and never guesses.
    pub explicit_offsets: bool,
    /// Required cmdline marker (fixture guard), or None for any target.
    pub cmdline_marker: Option<String>,
}

/// Per-poll resource bounds (spec R04: every poll/attachment batch
/// is bounded). The default drains a full 2 MiB ring of smallest
/// events per poll, matching the old full-drain rounds; tighter
/// budgets yield partial polls flagged via
/// [`DiscoveryDelta::budget_exhausted`].
#[derive(Clone, Debug)]
pub struct PollBudget {
    /// Ring items decoded per poll at most.
    pub max_events: u64,
    /// Stage-2/tripwire attaches per poll at most.
    pub max_attaches: u32,
}

impl PollBudget {
    pub fn new(max_events: u64, max_attaches: u32) -> Self {
        Self {
            max_events,
            max_attaches,
        }
    }
}

impl Default for PollBudget {
    fn default() -> Self {
        Self {
            max_events: 131072,
            max_attaches: 64,
        }
    }
}

/// One source-tagged discovery loss: `source` is a wire `LOSS_*` id
/// or a `coverage::HOST_*` id (see
/// [`coverage::loss_source_name`]); `count` is this delta's
/// increment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryLoss {
    pub source: u32,
    pub count: u64,
    /// Op the missing evidence localizes to (orphan ROWs carry
    /// their table's op); `None` when the loss cannot be localized
    /// (undecodable records, drain tails, snapshot failures,
    /// kernel-side counters) and conservatively taints every op
    /// (F-B/A7).
    pub op: Option<u32>,
}

/// Traversal state of one table incarnation. R03's aborted/truncated
/// shapes travel alongside as sticky `TRUNC` bits (frozen
/// vocabulary in `ebpf-common`) plus ranked gap reasons — see
/// [`TableCoverage`] — rather than as a second precedence order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageState {
    Unseen,
    InProgress { walked: u32 },
    Terminated { len: u32 },
}

/// One observed (op, array-epoch) table and its current state.
/// `epoch` is the mapping-incarnation generation (see the module
/// docs); `trunc_bits` carries the op's sticky walk-shape bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableCoverage {
    pub op: u32,
    pub epoch: u64,
    pub state: CoverageState,
    pub trunc_bits: u64,
}

/// Verified backing triple for one callback implementation: the
/// `(device, inode, file offset)` the address relocated to. The
/// mapping executable bit and ELF segment checks stay at the
/// document-render layer; this triple is the claimed relocation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackingRef {
    pub dev: String,
    pub ino: u64,
    pub offset: u64,
}

/// One observed backing object (code provenance for operators).
/// Verified fingerprints are T07 work; this carries the
/// `(device, inode)` identity plus a display locator, never an
/// authority claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredObject {
    pub dev: String,
    pub ino: u64,
    pub display_locator: String,
}

/// One classified dispatch candidate, retained across polls. The
/// advertising identity (which provider's array offered it) and the
/// backing identity (which object's code implements it) are
/// separate fields and are never conflated: `backing` is `None`
/// exactly when the implementation sits in no file mapping (fenced,
/// count-only at render). `impl_addr`/`arr` are internal integer
/// join keys, never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredCandidate {
    /// Array owner's mapped locator (`""` for anonymous/unmapped
    /// arrays).
    pub advertising: String,
    /// Array owner's discovery-time identity (F-A/A3): capture
    /// verifies the array's CURRENT owner against this instead of
    /// re-resolving the bare locator (empty/zero for anonymous).
    pub advertising_dev: String,
    pub advertising_ino: u64,
    pub backing: Option<BackingRef>,
    pub op: u32,
    pub funcid: u32,
    /// Registry class label or `"other"` — never target bytes.
    pub class: String,
    pub weak: bool,
    /// Kernel read verdict (`ok`/`unknown`/`overlong`/`truncated`).
    pub status: String,
    /// Table-epoch this candidate was ingested under.
    pub epoch: u64,
    /// INTERNAL relocation input, never serialized.
    pub impl_addr: u64,
    /// INTERNAL array join key, never serialized.
    pub arr: u64,
}

/// This poll's tripwire news. Query/load counters and tripwire
/// counters stay separate: `executed_legacy_queries_delta` moves
/// only on the executed-query ledger, never on load hits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TripwireDelta {
    /// Newly classified hits this poll.
    pub hits: Vec<legacy::TripHit>,
    /// Per-cookie counter increments (joined `TRIP` map).
    pub counter_deltas: Vec<(u64, u64)>,
    /// Executed-query ledger increment (joined `LGCALLS` map).
    pub executed_legacy_queries_delta: u64,
}

/// One link-installation outcome this poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachEvent {
    pub kind: AttachKind,
    /// Set on failure (retryable: the next trigger re-attempts).
    pub failed: Option<String>,
}

/// What was (or failed to be) installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachKind {
    /// Stage-2 query pair for one init cookie.
    Stage2 { cookie: u64 },
    /// Legacy tripwire batch.
    Tripwires { count: usize },
    /// Dispatch anchor pair (init or builtin query) reinstalled
    /// after replacement (F-D/A11).
    DispatchAnchors { count: usize },
}

/// One table-incarnation retirement this poll: the epoch that
/// turned over plus the gap it carried (retained forever in the
/// snapshot; rows survive separately). Consumers must drop the
/// retired epoch's completion — only the new epoch's proof counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableRetirement {
    pub op: u32,
    pub epoch: u64,
    pub gap: coverage::CoverageDelta,
}

/// One poll's worth of discovery news: new/changed classified
/// candidates + newly observed objects + touched table states +
/// retirements + tripwire deltas + source-tagged losses.
/// Cumulative state lives in [`DiscoverySnapshot`]; this delta
/// never requires JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryDelta {
    /// Ring items consumed this poll.
    pub events_consumed: u64,
    /// Candidates first seen (or identity-refreshed after a
    /// same-address remap) this poll.
    pub candidates: Vec<DiscoveredCandidate>,
    /// Backing objects first seen this poll.
    pub objects: Vec<DiscoveredObject>,
    /// Tables touched this poll (ring events, map-join
    /// transitions, or rebirth), with current state.
    pub tables: Vec<TableCoverage>,
    /// Incarnations retired this poll, with their gaps.
    pub retirements: Vec<TableRetirement>,
    pub tripwire: TripwireDelta,
    /// Losses incurred this poll (host + kernel increments).
    pub losses: Vec<DiscoveryLoss>,
    /// Query/load counter increment — arrivals, NOT execution.
    pub queries_delta: u64,
    pub attaches: Vec<AttachEvent>,
    /// True when the budget stopped work with more pending (more
    /// events queued or attaches deferred): resume with another
    /// poll. This is backpressure, not loss.
    pub budget_exhausted: bool,
    /// Cumulative dispatch-trigger flag (loop-convenience copy;
    /// authoritative state lives in the snapshot).
    pub trigger_observed: bool,
}

/// Unresolved stage-2 attach failure (retryable state, not a
/// terminal verdict): the next init for `cookie` re-attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachFailure {
    pub cookie: u64,
    pub error: String,
}

/// Cumulative dispatch-plane state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatchSnapshot {
    /// A dispatch anchor is attached (init pair, builtin pair, or
    /// any stage-2 pair).
    pub attached: bool,
    /// Blind-dispatch PARTIAL reason (`anchor-unresolved`), if the
    /// anchor ladder failed.
    pub preset_reason: Option<String>,
    /// Non-default resolution label (`symtab`, `anchor+delta`, `force`).
    pub resolution: Option<String>,
    /// Currently unresolved stage-2 failures, by cookie.
    pub attach_failures: Vec<AttachFailure>,
    /// Repeat inits per cookie (reload witness; the content-swap
    /// backstop is exact coverage, see the module docs).
    pub reloads: Vec<(u64, u64)>,
    /// The target provider's init fired post-attach.
    pub primary_init_observed: bool,
    /// Any dispatch trigger (query/alg/row) was observed.
    pub trigger_observed: bool,
    /// Bootstrap-original provider binding (H6): (path,
    /// stat-dev, ino) pinned at attach. The file-provider
    /// mapped check reads this.
    pub bootstrap_binding: Option<(String, String, u64)>,
}

/// Cumulative legacy-plane state. Query counters
/// (`executed_queries`) and tripwire counters (`trip`/`hits`) are
/// separate fields; only the executed-query ledger feeds
/// `executed_queries` at render (F-C/A9: queries, not
/// executions).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacySnapshot {
    /// A tripwire probe set is planned and installed.
    pub planned: bool,
    pub set: Option<legacy::ProbeSet>,
    /// Last-joined `TRIP` contents: cookie → hit count.
    pub trip: HashMap<u64, u64>,
    /// Retained classified hits.
    pub hits: Vec<legacy::TripHit>,
    /// Executed legacy queries (joined `LGCALLS` ledger only).
    pub executed_queries: u64,
    /// Extra findings (e.g. legacy attach notes).
    pub extra_findings: Vec<String>,
}

/// Live attach-link counts (resource-liveness witness for T08
/// lifecycle accounting).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkLiveness {
    pub dispatch: u64,
    pub tripwire: u64,
}

/// Cumulative discovery state: all retained candidates/objects,
/// live-epoch table states, retained ∪ live gap reasons, and
/// accumulated counters. Reasons only ever grow within a session.
///
/// `retained_reasons` carries the retired-epoch gaps alone (the
/// `reasons` union minus live state): renderers must honor them —
/// a retired prefix stays PARTIAL even when every live table
/// terminates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    pub candidates: Vec<DiscoveredCandidate>,
    /// Candidates first joined (or identity-refreshed) by
    /// close's tail ingest: they never rode a poll delta, so a
    /// delta-fed consumer (capture's adapter) never saw them.
    /// Reported for the finish-time reconcile (P6 §6ii) — taint,
    /// never silent census. Empty until close runs.
    pub close_candidates: Vec<DiscoveredCandidate>,
    /// M4-remembered (ino, offset) backings for close-joined impl
    /// addrs that differ from the joined backing (sol round 3 —
    /// first-cell adoption may have outrun an impl remap). Sorted
    /// + deduped; empty until close runs.
    pub close_remembered: Vec<(u64, u64)>,
    pub objects: Vec<DiscoveredObject>,
    /// Live-epoch tables only; retired epochs survive in
    /// `candidates` (rows) and `reasons` (gaps).
    pub tables: Vec<TableCoverage>,
    /// Retained ∪ live gap reasons, in the frozen rank order.
    pub reasons: Vec<String>,
    /// Retired-epoch gaps alone (subset of `reasons`).
    pub retained_reasons: Vec<String>,
    /// Accumulated source-tagged losses, sorted by source.
    pub losses: Vec<(u32, u64)>,
    /// Sticky per-op walk-shape bits (never retired).
    pub truncated_ops: Vec<(u32, u64)>,
    /// Walked slots whose identity was lost.
    pub lossy_slots: u64,
    /// Query/load arrivals (CALLS-joined total, event-count
    /// fallback) — never execution.
    pub queries_observed: u64,
    /// Per-op query arrivals, sorted by op, from the same source
    /// as the published total (CALLS-joined per-op high-water, or
    /// event counts when the map is absent; see the core fields).
    pub queries_by_op: Vec<(u32, u64)>,
    /// Ops with at least one query hit.
    pub ops_hit: Vec<u32>,
    pub dispatch: DispatchSnapshot,
    pub legacy: LegacySnapshot,
    pub links_live: LinkLiveness,
    pub pid_recycled: u64,
}

// ---------------------------------------------------------------------------
// Environment: the seam between the state machine and the privileged world.
// ---------------------------------------------------------------------------

/// One round of BPF map reads. Kernel counters (`losses`, `calls`,
/// `trip`, `lgcalls`) are cumulative; the core joins them
/// monotonically and reports only increments. `TERMD`/`TRUNC` join
/// idempotently. A `*_failed` flag means that map's contents are
/// unknown and becomes explicit snapshot loss, never a silent
/// empty.
#[derive(Clone, Debug, Default)]
pub struct MapSnapshots {
    pub trunc: Vec<(u32, u64)>,
    pub trunc_failed: bool,
    pub termd: Vec<(u64, u64)>,
    pub termd_failed: bool,
    pub losses: Vec<(u32, u64)>,
    pub losses_failed: bool,
    /// `CALLS` sum (`None` when the map is absent).
    pub calls: Option<u64>,
    /// `CALLS` per-op rows (empty when the map is absent; partial
    /// rows ride with `calls_failed` and the max-join ignores dips).
    pub calls_by_op: Vec<(u32, u64)>,
    pub calls_failed: bool,
    /// `TRIP` contents.
    pub trip: Vec<(u64, u64)>,
    pub trip_failed: bool,
    /// `LGCALLS` sum.
    pub lgcalls: u64,
    pub lgcalls_failed: bool,
}

/// Fresh dispatch anchor binding after a reinstall (F-D/A11):
/// the (path, dev, ino) the new links pin, plus the resolution
/// label when the non-default ladder rung applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchReinstall {
    pub binding: (String, String, u64),
    pub resolution: Option<String>,
}

/// One queued stage-2 retry (F-D/A12): the failed address, the
/// resolve identity when one was established (`None` for
/// resolve failures — unmapped, nothing to compare), and the
/// poll that queued it (due from the next poll on).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stage2Retry {
    addr: u64,
    ident: Option<(String, u64)>,
    queued_seq: u64,
}

/// Privileged/file operations the [`SessionCore`] needs. The live
/// implementation ([`LiveEnv`]) performs real BPF and `/proc` work;
/// host tests stage synthetic rings, maps, snapshots, links, and
/// pins behind the same contract.
pub trait SessionEnv {
    /// Pop one raw ring item, or `None` when the ring is empty now.
    fn next_event(&mut self) -> Option<Vec<u8>>;
    /// Current target mappings (epoch reconcile + attribution).
    /// `None` when the read itself failed (F-D/Am1) — NOT empty
    /// maps: the core reconciles against its last-good snapshot
    /// and records the failure explicitly instead of reading it
    /// as a vanished target.
    fn current_maps(&mut self) -> Option<Vec<maps::Mapping>>;
    /// One round of BPF map reads.
    fn join_maps(&mut self) -> MapSnapshots;
    /// Install one stage-2 query pair; the live impl reports the
    /// harness-gated `INSPECT stage=query` line itself. `expected`
    /// is the resolve-time raw (dev, ino) the install binds
    /// against (F-A/A1); `None` (unstatable at resolve) fails
    /// closed.
    fn install_stage2(
        &mut self,
        cookie: u64,
        offset: u64,
        path: &Path,
        pid: u32,
        expected: Option<(u64, u64)>,
    ) -> anyhow::Result<()>;
    /// Install one tripwire batch; returns an optional attach note
    /// (e.g. legacy-query attach failure, loud but non-fatal).
    /// `maps` is the caller's explicit snapshot (F-D/Am1) — the
    /// installer never re-reads /proc itself (a second read would
    /// be a second failure-conflation site).
    fn install_trips(
        &mut self,
        set: &legacy::ProbeSet,
        pid: u32,
        maps: &[maps::Mapping],
    ) -> anyhow::Result<Option<String>>;
    /// Plan legacy tripwires against `maps`: `None` when
    /// libcrypto is not mapped (blind — the core retries on later
    /// polls as mappings appear).
    fn plan_trips(&mut self, maps: &[maps::Mapping]) -> anyhow::Result<Option<legacy::ProbeSet>>;
    /// Best-effort page fault-in after a repeat init (cold reload
    /// pages make nofault BPF reads abort the walk).
    fn pretouch(&mut self, cookie: u64, addr: u64);
    /// Evict one array's kernel walker state (`TERMD` proof and
    /// `QUERY_NEXT` cursors) after its incarnation retired, so stale
    /// proofs and mid-array cursors cannot satisfy the next
    /// incarnation. Evicting an absent entry succeeds; other
    /// failures are explicit loss (the stale state may survive).
    fn evict_array_state(&mut self, arr: u64) -> anyhow::Result<()>;
    /// Install one array's incarnation generation into `GEN[arr]`
    /// (F-H/H1): BPF stamps every ROW/ALG/QUERY_RET record with the
    /// installed value, and the core drops records carrying a
    /// retired one. Called when an epoch is born (bootstrap) or
    /// reborn (turnover bump); the core forgets the array on
    /// failure (the next record re-bootstraps) and records
    /// explicit loss.
    fn install_generation(&mut self, arr: u64, generation: u64) -> anyhow::Result<()>;
    /// Re-verify the target pin; `Err` means the pid recycled and
    /// all retained evidence is tainted.
    fn verify_pin(&self) -> anyhow::Result<()>;
    /// Drop every attach link (quiesce: no new events can arrive).
    fn quiesce(&mut self);
    /// Live link counts as `(dispatch, tripwire)`.
    fn link_counts(&self) -> (u64, u64);
    /// Detach the legacy tripwire batch, including the legacy-init
    /// pairs installed with it (F-D/A11: replacement invalidated
    /// the plan's offsets).
    fn detach_trips(&mut self);
    /// Detach the dispatch anchor pairs (init or builtin query),
    /// excluding stage-2 links (F-D/A11).
    fn detach_dispatch_anchors(&mut self);
    /// Detach one cookie's stage-2 links (F-D/A11: the cookie's
    /// target was superseded or unmapped).
    fn detach_stage2(&mut self, cookie: u64);
    /// Re-resolve the dispatch anchor against the current provider
    /// file and install a fresh pair, returning its binding
    /// (F-D/A11). Fails when the provider is unmapped or the
    /// anchor is unresolvable (the core latches blind and retries
    /// on fingerprint change); an `InvalidData` error is a
    /// transient file race (retry next poll, no latch).
    /// H10: unmapped-but-present installs kernel-pending on the
    /// current file (no maps entry to compare); only a missing
    /// file stays a retry.
    fn reinstall_dispatch(&mut self) -> anyhow::Result<DispatchReinstall>;
    /// Current (rendered dev, ino) of the provider-path file
    /// (H10): the pending re-resolve compares stat-vs-stat
    /// against the bound identity (H5 single-domain — the maps
    /// dev-string is never compared). `None` when the file is
    /// unstatable (retained quietly — absence of evidence).
    fn provider_stat(&self) -> Option<(String, u64)>;
}

/// Pid recycle mid-observation: carries the discarded-state
/// snapshot (zero rows; blind legacy at most — trip data is
/// pid-scoped, hence tainted too). Callers render their
/// `PARTIAL(pid-recycled)` discard from it.
///
/// `final_snapshot` is `Some` only from [`SessionCore::close`]: the
/// pre-wipe cumulative state (all polls' joins plus the close-time
/// tail count), for custody-holding callers whose pin failure is a
/// reaped OWNED child (exit, not recycle). Foreign callers must
/// never touch it (tainted pid scope); the wiped `snapshot` stays
/// the discard contract.
#[derive(Debug)]
pub struct Recycled {
    pub snapshot: DiscoverySnapshot,
    pub final_snapshot: Option<DiscoverySnapshot>,
}

impl std::fmt::Display for Recycled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "target recycled mid-run (evidence discarded; see PARTIAL snapshot)"
        )
    }
}

impl std::error::Error for Recycled {}

fn debug_session() -> bool {
    std::env::var("OSSL_DEBUG_HARVEST").is_ok()
}

/// Debug-only alg line over an already-classified record (logs are
/// artifacts: table labels, ids, and counters only — never target
/// strings, string lengths, or runtime addresses, even under the
/// debug flag).
fn debug_alg_line(op: u32, idx: u64, class: &str, weak: bool, status: u8) -> String {
    format!(
        "HARVESTDBG alg op={op} idx={idx} class={class} weak={} status={status}",
        u8::from(weak)
    )
}

// ---------------------------------------------------------------------------
// SessionCore: the host-testable discovery state machine.
// ---------------------------------------------------------------------------

/// Mapping-incarnation fingerprint: `(device text, inode, range
/// start, range end, file offset)`. File mappings only.
type Fingerprint = (String, u64, u64, u64, u64);

/// One table incarnation: the epoch id plus the mapping
/// fingerprint the array was bound to (`None` for anonymous or
/// unmapped arrays, which carry no verifiable identity).
#[derive(Clone, Debug)]
struct TableEpoch {
    epoch: u64,
    fingerprint: Option<Fingerprint>,
}

/// One mapping's first sighting (M1): the range end, its
/// fingerprint then (`None` for anonymous mappings), and a session
/// sequence so the earliest sighting wins even when a later split
/// reuses a higher start address inside the same range.
#[derive(Clone, Debug)]
struct SightedMapping {
    end: u64,
    fingerprint: Option<Fingerprint>,
    seq: u64,
}

/// Candidate identity: `(op, class, weak, status, funcid,
/// impl_addr, array)`. Scaled tables cycle funcids, alias verdicts
/// must not collapse, and two providers sharing one implementation
/// stay distinct per offering array (R02 advertising identity).
/// Epoch is deliberately excluded: re-walked rows in a new epoch
/// refresh, never duplicate.
type CandidateKey = (u32, String, bool, String, u32, u64, u64);

/// One reconcile round: retirements (for the delta) and reborn
/// keys (fresh unproven epochs, always delta-visible).
#[derive(Default)]
struct ReconcileOutcome {
    retired: Vec<TableRetirement>,
    reborn: Vec<(u32, u64)>,
}

/// Fingerprint the mapping covering `arr`: `(dev, ino, start, end,
/// file offset)`. File mappings only — anonymous mappings have no
/// identity to bind.
fn incarnation_of(maps: &[maps::Mapping], arr: u64) -> Option<Fingerprint> {
    maps.iter()
        .find(|m| m.start <= arr && arr < m.end && m.ino != 0)
        .map(|m| (m.dev.clone(), m.ino, m.start, m.end, m.offset))
}

/// Cookie-meaning equality for tripwire re-plans (F-D/A11): the
/// same (cookie, symbol, module, family, string-arg, program) pairs
/// as sets (offsets excluded — they legitimately move across
/// replacement; order excluded — the TRIP map keys by cookie).
/// Equal mappings re-attach soundly (accumulation continues under
/// unchanged meanings); anything else must stay blind (fresh
/// cookies would collide with old meanings).
/// Cookie-meaning key for one tripwire probe (everything but the
/// file offset, which legitimately moves across replacement).
type TripProbeKey<'a> = (
    u64,
    &'a str,
    &'a str,
    Option<&'static str>,
    Option<usize>,
    &'static str,
);

fn trip_mapping_equal(a: &legacy::ProbeSet, b: &legacy::ProbeSet) -> bool {
    use std::collections::HashSet;
    fn pairs(set: &legacy::ProbeSet) -> HashSet<TripProbeKey<'_>> {
        set.probes
            .iter()
            .map(|p| {
                (
                    p.cookie,
                    p.symbol.as_str(),
                    p.module.as_str(),
                    p.family,
                    p.str_arg,
                    p.program,
                )
            })
            .collect()
    }
    pairs(a) == pairs(b)
}

/// The mapped libcrypto entry a plan would resolve against, if any
/// (shared by planning and blind-latch fingerprints so the two
/// cannot select different entries).
fn libcrypto_entry(maps: &[maps::Mapping]) -> Option<&maps::Mapping> {
    legacy::find_libcrypto(maps).and_then(|path| maps.iter().find(|m| m.path == path))
}

/// Current libcrypto fingerprint: (path, dev, ino) or `None` when
/// unmapped (F-D/A11 blind-latch print).
fn libcrypto_print(maps: &[maps::Mapping]) -> Option<(String, String, u64)> {
    libcrypto_entry(maps).map(|m| (m.path.clone(), m.dev.clone(), m.ino))
}

/// Current provider fingerprint: (path, dev, ino) or `None` when
/// unmapped (F-D/A11 blind-latch print).
fn provider_print(
    provider: &Path,
    canon: &str,
    maps: &[maps::Mapping],
) -> Option<(String, String, u64)> {
    let prov = provider.to_string_lossy();
    maps.iter()
        .find(|m| m.path == prov || m.path == canon)
        .map(|m| (m.path.clone(), m.dev.clone(), m.ino))
}

/// Transient file-race errors (F-D/A11): the target file changed
/// mid-operation — retry next poll without latching blind and
/// without failing the poll. Only the A3 bound-read mid-read
/// signal and the plan/reinstall identity-mismatch errors use
/// `InvalidData`, so the match is precise.
fn is_transient_race(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::InvalidData)
}

/// The discovery state machine: ring decode, epoch binding,
/// monotonic joins, event-driven retry, and delta/snapshot
/// accounting, with no direct BPF dependency. Drive it with
/// [`SessionCore::poll`] through a [`SessionEnv`]; the live
/// [`DiscoverySession`] pairs it with [`LiveEnv`], host tests with
/// a staged fake.
///
/// There are no permanent harvested bits here: quiet tables wait,
/// failed attaches retry on the next trigger, and incarnation
/// turnover retires table state while retaining rows and reasons.
pub struct SessionCore {
    pid: u32,
    provider: PathBuf,
    canon: String,
    legacy_enabled: bool,
    class_count: u16,
    tracker: coverage::CoverageTracker,
    retained: coverage::CoverageDelta,
    table_epochs: HashMap<(u32, u64), TableEpoch>,
    next_epoch: u64,
    /// Expected producer generation per array base (F-H/H1):
    /// installed into `GEN[arr]` when the array's epoch is born
    /// (bootstrap) or reborn (turnover bump). Keyed by array,
    /// not (op, array): BPF stamps from the same key, and two
    /// ops sharing one array degrade to explicit in-flight loss
    /// on a bump, never to silence or a permanently bricked
    /// array. Removed on forget (failed bump / unload, with the
    /// kernel entry evicted); a re-mapped array re-bootstraps
    /// above the high-water mark, never from 1 (M2).
    array_gen: HashMap<u64, u64>,
    /// Highest generation ever installed per array base (M2):
    /// survives forget (failed bump / unload remove the live
    /// binding above, never this mark), so a re-bootstrap
    /// cannot reuse a value whose stragglers may still be
    /// queued. Entries persist for the session (bounded by
    /// distinct arrays ever observed — dispatch tables, few
    /// per target); cleared only on recycle with all lineage.
    gen_high_water: HashMap<u64, u64>,
    /// Bootstrap-install drain grace (M2): arrays whose
    /// generation installed during the CURRENT poll's drain.
    /// Records sharing the bootstrap install's drain predate
    /// it — genuine install-gap evidence, like the fresh
    /// `GEN == 1` case — so a tracked table accepts stamp 0
    /// from them. Cleared every poll: deep-queue gap-0s in
    /// later drains, and ancient gap-0s, still drop loud.
    /// Bootstrap installs only (rebirth bumps land back-to-back
    /// with their eviction — a 0 after a bump is stale).
    bootstrap_grace: HashSet<u64>,
    /// First-sighting fingerprints per mapping start (M1): every
    /// maps snapshot's never-before-seen ranges land here,
    /// first-wins, so an array's baseline predates its first
    /// event even when the mapping appeared after attach. Bounded
    /// by distinct mapping starts sighted (mmap churn per run).
    /// Cleared on recycle with all lineage (a recycled pid owns a
    /// new address space — old sightings are meaningless).
    sightings: BTreeMap<u64, SightedMapping>,
    /// Sighting sequence: monotonic per session, reset on recycle.
    sight_seq: u64,
    /// Resolved first-observation baselines per array (M1):
    /// earliest-sighting fingerprint, else the current one at
    /// first ingest; re-seated to current on mismatch. Bounded by
    /// distinct arrays (same bound as the M2 high-water mark).
    baselines: HashMap<u64, Option<Fingerprint>>,
    /// Arrays whose baseline mismatched during the CURRENT poll's
    /// drain (M1): same-drain siblings of the mismatch drop
    /// silently (one loss per array per poll), and re-baselined
    /// arrays bootstrap cleanly from the next poll. Cleared every
    /// poll, like `bootstrap_grace`.
    m1_poison: HashSet<u64>,
    /// Remembered impl-backing triple per (array, slot, impl)
    /// (M4): populated on the first validated row per cell,
    /// compared before join/refresh, re-seated on mismatch. The
    /// impl vaddr is in the key because one (array, slot) carries
    /// many dispatch entries (the walker emits one ROW per entry
    /// sharing the alg index) — and because a new vaddr is a new
    /// candidate key, hence a fresh cell (sound-silent, never a
    /// false stale). Cleared for `arr` on array retire (memories
    /// belong to the array epoch) and wholly on recycle. Bounded
    /// by distinct (slot, impl) rows ever walked.
    slot_backing: HashMap<(u64, u64, u64), BackingRef>,
    /// Last successfully read mappings (F-D/Am1): a failed
    /// `current_maps` reconciles against this instead of reading
    /// the failure as empty. Starts empty (a first-poll failure
    /// reconciles against nothing, WITH an explicit loss — links
    /// cannot spuriously detach before any attach).
    last_good_maps: Vec<maps::Mapping>,
    candidates: Vec<DiscoveredCandidate>,
    /// Close-time tail-joined candidates (P6 §6ii): stashed by
    /// [`SessionCore::close`] from its otherwise-discarded delta so
    /// the closing snapshot reports them. Always empty before close
    /// (close runs once); cleared on recycle with all lineage.
    close_candidates: Vec<DiscoveredCandidate>,
    /// M4-remembered (ino, offset) backings for close-joined impl
    /// addrs that DIFFER from the joined backing (P6 §6ii sol
    /// round 3): a first-cell adoption may have outrun an impl
    /// remap, so the old sites' sets may miss the alias — capture
    /// revises them too. Sorted + deduped; empty until close.
    close_remembered: Vec<(u64, u64)>,
    /// Dedupe index by [`CandidateKey`]. Value is the candidate index.
    seen: HashMap<CandidateKey, usize>,
    objects: Vec<DiscoveredObject>,
    seen_objects: HashSet<(String, u64)>,
    /// (Array, alg index) → kernel verdict: ROW events join here.
    alg_records: HashMap<(u64, u64), (String, bool, String)>,
    ops_hit: HashSet<u32>,
    queries_events: u64,
    /// Per-op query-event arrivals (fallback source, used only when
    /// the CALLS map is absent — always sums to `queries_events`).
    queries_by_op: HashMap<u32, u64>,
    /// Per-op CALLS-joined high-water (primary source, mirrors the
    /// total's max-join per key; sums to the published total when
    /// every map read is good — a failed (partial) read inflates
    /// the sum past the total while its failure flag records
    /// snapshot loss; a silent dip on a good read is ignored by
    /// the max-join without record).
    calls_by_op: HashMap<u32, u64>,
    /// Joined CALLS total (`None` until the map is first seen; the
    /// query source pins on first join — see `calls_pinned`).
    calls_joined: Option<u64>,
    calls_pinned: bool,
    emitted_queries: u64,
    emitted_losses: HashMap<u32, u64>,
    emitted_orphan_ops: HashMap<u32, u64>,
    emitted_straggler_ops: HashMap<u32, u64>,
    loss_seen: HashMap<u32, u64>,
    trip_joined: HashMap<u64, u64>,
    lgcalls_joined: u64,
    trip_hits: Vec<legacy::TripHit>,
    probe_set: Option<legacy::ProbeSet>,
    staged_trips: Option<legacy::ProbeSet>,
    /// Tripwire anchors live (F-D/A11): links installed against
    /// the bound libcrypto. `probe_set` retains the last-good plan
    /// for rendering history while blind.
    trip_live: bool,
    /// Libcrypto (path, dev, ino) the live tripwire links pin.
    trip_bound: Option<(String, String, u64)>,
    /// Blind latch (F-D/A11): a changed-mapping replacement
    /// declined re-attach; planning resumes when the libcrypto
    /// fingerprint differs from the latch print (bounded reads).
    trip_blind: bool,
    trip_blind_print: Option<(String, String, u64)>,
    legacy_note: Option<String>,
    attached_queries: HashSet<u64>,
    /// Installed stage-2 target per cookie: (file offset, attach
    /// path). A repeat init resolving elsewhere re-attaches instead
    /// of trusting a stale offset.
    attached_targets: HashMap<u64, (u64, String, String, u64)>,
    /// Bootstrap builtin-query anchor (attach path, file offset)
    /// for the traversal backend: written ONLY by
    /// [`SessionCore::mark_query_attached`] (whose sole caller is
    /// the builtin bootstrap path), never by poll-time stage-2
    /// installs — so an init-mode stage-2 cookie-0 install cannot
    /// collide with it. `None` in init mode and when dispatch-blind.
    bootstrap_query_anchor: Option<(String, u64)>,
    attach_failures: HashMap<u64, String>,
    reloads: HashMap<u64, u64>,
    pending_stage2: std::collections::VecDeque<(u64, u64)>,
    /// Retryable unattached set (F-D/A12): cookies whose stage-2
    /// attach failed, keyed by cookie (latest address wins) with
    /// the resolve identity when one was established. Retried every
    /// poll from the NEXT poll on (`queued_seq` excludes same-poll
    /// retries, so a failure still records before any re-attempt);
    /// dropped when the bytes change under the queued address.
    retry_stage2: BTreeMap<u64, Stage2Retry>,
    /// Poll sequence clock for retry due-ness (F-D/A12).
    poll_seq: u64,
    primary_init_observed: bool,
    trigger_observed: bool,
    /// Dispatch anchors live (F-D/A11): init/query links installed
    /// against the bound provider file. Cleared when replacement
    /// invalidates the binding, restored by reinstall.
    dispatch_live: bool,
    /// Provider (path, dev, ino) the live dispatch links pin.
    dispatch_bound: Option<(String, String, u64)>,
    /// Whether the bound provider file was ever observed mapped
    /// (H10): distinguishes PENDING (never mapped → retain the
    /// kernel-pending links across unmapped polls) from GONE (was
    /// mapped, now unmapped → detach). Set on the first poll whose
    /// maps carry the bound triple; cleared only by pid recycle (a
    /// new process restarts the distinction).
    dispatch_ever_mapped: bool,
    /// Bootstrap-original provider binding (H6): the identity
    /// pinned at attach, NEVER refreshed by reinstall (which
    /// updates `dispatch_bound` only). The file-provider
    /// mapped check reads this — the doc is about P, the
    /// expected file.
    bootstrap_binding: Option<(String, String, u64)>,
    /// Blind latch (F-D/A11): a failed reinstall retries only when
    /// the provider fingerprint differs from the latch print.
    dispatch_blind: bool,
    dispatch_blind_print: Option<(String, String, u64)>,
    preset_reason: Option<String>,
    resolution: Option<String>,
    trunc_seen: HashMap<u32, u64>,
    stashed: Option<Vec<u8>>,
    last_links: (u64, u64),
    pid_recycled: u64,
    closed: bool,
    recycled: bool,
}

impl SessionCore {
    /// Bare core for staged/test driving: dispatch bootstrap state
    /// starts empty (waiting, retryable). The live session builds
    /// the same core through [`DiscoverySession::attach`], which
    /// then records its bootstrap outcome.
    pub fn new(provider: PathBuf, canon: String, legacy: bool, pid: u32) -> Self {
        Self {
            pid,
            provider,
            canon,
            legacy_enabled: legacy,
            class_count: crate::kinds::ALG_NAMES.len() as u16,
            tracker: coverage::CoverageTracker::new(),
            retained: coverage::CoverageDelta::default(),
            table_epochs: HashMap::new(),
            next_epoch: 0,
            array_gen: HashMap::new(),
            gen_high_water: HashMap::new(),
            bootstrap_grace: HashSet::new(),
            sightings: BTreeMap::new(),
            sight_seq: 0,
            baselines: HashMap::new(),
            m1_poison: HashSet::new(),
            slot_backing: HashMap::new(),
            last_good_maps: Vec::new(),
            candidates: Vec::new(),
            close_candidates: Vec::new(),
            close_remembered: Vec::new(),
            seen: HashMap::new(),
            objects: Vec::new(),
            seen_objects: HashSet::new(),
            alg_records: HashMap::new(),
            ops_hit: HashSet::new(),
            queries_events: 0,
            queries_by_op: HashMap::new(),
            calls_by_op: HashMap::new(),
            calls_joined: None,
            calls_pinned: false,
            emitted_queries: 0,
            emitted_losses: HashMap::new(),
            emitted_orphan_ops: HashMap::new(),
            emitted_straggler_ops: HashMap::new(),
            loss_seen: HashMap::new(),
            trip_joined: HashMap::new(),
            lgcalls_joined: 0,
            trip_hits: Vec::new(),
            probe_set: None,
            staged_trips: None,
            trip_live: false,
            trip_bound: None,
            trip_blind: false,
            trip_blind_print: None,
            legacy_note: None,
            attached_queries: HashSet::new(),
            attached_targets: HashMap::new(),
            bootstrap_query_anchor: None,
            attach_failures: HashMap::new(),
            reloads: HashMap::new(),
            pending_stage2: std::collections::VecDeque::new(),
            retry_stage2: BTreeMap::new(),
            poll_seq: 0,
            primary_init_observed: false,
            trigger_observed: false,
            dispatch_live: false,
            dispatch_bound: None,
            dispatch_ever_mapped: false,
            bootstrap_binding: None,
            dispatch_blind: false,
            dispatch_blind_print: None,
            preset_reason: None,
            resolution: None,
            trunc_seen: HashMap::new(),
            stashed: None,
            last_links: (0, 0),
            pid_recycled: 0,
            closed: false,
            recycled: false,
        }
    }

    /// Record the live bootstrap outcome (init/builtin anchor
    /// installed, or blind with a preset reason) plus the provider
    /// identity the installed links pin (F-D/A11 anchor binding;
    /// `None` when the file was unstatable — validation then trusts
    /// the links as before).
    pub(crate) fn set_bootstrap(
        &mut self,
        attached: bool,
        preset_reason: Option<String>,
        resolution: Option<String>,
        binding: Option<(String, String, u64)>,
    ) {
        self.dispatch_live = attached;
        self.dispatch_bound = binding.clone();
        // H6: bootstrap-original binding (set once — reinstall
        // refreshes `dispatch_bound` but never this).
        self.bootstrap_binding = binding;
        self.preset_reason = preset_reason;
        self.resolution = resolution;
    }

    /// Record an attach-time stage-2 install (builtin mode
    /// pre-attaches its query pair): later inits for the cookie
    /// re-resolve against this target and re-attach when the
    /// callback moved OR its backing identity changed (a same-path
    /// replacement keeps offset+path but must not reuse the stale
    /// install — T14r4-2b).
    pub(crate) fn mark_query_attached(
        &mut self,
        cookie: u64,
        offset: u64,
        path: String,
        dev: String,
        ino: u64,
    ) {
        self.attached_queries.insert(cookie);
        self.attached_targets
            .insert(cookie, (offset, path.clone(), dev, ino));
        // Bootstrap-only caller: the builtin query anchor the
        // traversal backend attaches to (poll-time stage-2
        // installs write `attached_targets` directly, never this).
        self.bootstrap_query_anchor = Some((path, offset));
    }

    /// Bootstrap builtin-query anchor (attach path, file offset)
    /// for the traversal backend. `None` in init mode and when
    /// dispatch-blind — traversal refuses, it never guesses an
    /// offset. Cleared on recycle with all lineage.
    pub(crate) fn builtin_anchor(&self) -> Option<(PathBuf, u64)> {
        self.bootstrap_query_anchor
            .as_ref()
            .map(|(path, off)| (PathBuf::from(path), *off))
    }

    /// Adopt an attach-time legacy plan (first poll planning goes
    /// through [`SessionCore::poll`] instead).
    pub(crate) fn adopt_legacy_plan(&mut self, set: legacy::ProbeSet, note: Option<String>) {
        if self.legacy_note.is_none() {
            self.legacy_note = note;
        }
        // Freshly installed at attach: live against the plan's own
        // libcrypto binding (validated from the first poll).
        self.trip_bound = set.libcrypto.clone();
        self.trip_live = true;
        self.probe_set = Some(set);
    }

    /// Next installable generation for an array (M2 high-water):
    /// above both the live binding and every generation this
    /// session ever installed for the array. `None` at u64
    /// exhaustion (F10 — callers fail closed like an install
    /// failure; operationally unreachable).
    fn next_generation(&self, arr: u64) -> Option<u64> {
        self.array_gen
            .get(&arr)
            .copied()
            .unwrap_or(0)
            .max(self.gen_high_water.get(&arr).copied().unwrap_or(0))
            .checked_add(1)
    }

    /// Record a successful install in both the live binding and
    /// the high-water mark (every install is a new maximum by
    /// construction of [`Self::next_generation`]).
    fn record_generation_install(&mut self, arr: u64, generation: u64) {
        self.array_gen.insert(arr, generation);
        self.gen_high_water.insert(arr, generation);
    }

    /// Record first sightings from one maps snapshot (M1):
    /// never-before-seen range starts land here with their
    /// fingerprint, first-wins (a same-start replacement keeps
    /// the OLDEST fingerprint — that is the point: the baseline
    /// must predate any turnover). Called from [`Self::poll_maps`],
    /// the single maps funnel, so poll-start, mid-poll refresh,
    /// and close-time reads all sight.
    fn sight_mappings(&mut self, maps: &[maps::Mapping]) {
        for m in maps {
            if self.sightings.contains_key(&m.start) {
                continue;
            }
            let fingerprint = if m.ino != 0 {
                Some((m.dev.clone(), m.ino, m.start, m.end, m.offset))
            } else {
                None
            };
            self.sightings.insert(
                m.start,
                SightedMapping {
                    end: m.end,
                    fingerprint,
                    seq: self.sight_seq,
                },
            );
            self.sight_seq += 1;
        }
    }

    /// Resolve (and cache) an array's first-observation baseline
    /// (M1): the earliest sighting covering the address, else the
    /// current fingerprint (genuinely first sighting — the R1
    /// shape: appear+replace inside one poll interval is
    /// polling-invisible and stays silent by design).
    fn baseline_for(&mut self, arr: u64, maps: &[maps::Mapping]) -> Option<Fingerprint> {
        if let Some(fp) = self.baselines.get(&arr) {
            return fp.clone();
        }
        let base = self
            .sightings
            .iter()
            .filter(|(start, s)| **start <= arr && s.end > arr)
            .min_by_key(|(_, s)| s.seq)
            .map(|(_, s)| s.fingerprint.clone())
            .unwrap_or_else(|| incarnation_of(maps, arr));
        self.baselines.insert(arr, base.clone());
        base
    }

    /// First-observation gate (M1): the array's baseline
    /// fingerprint must agree with the current one, or the array
    /// turned over inside its first-observation window and this
    /// batch drops with an op-None mismatch loss (the stale
    /// records are indistinguishable from the replacement's
    /// fresh stamp-0s — fail closed). On mismatch the baseline
    /// re-seats to current and the array poisons for the rest of
    /// the drain (same-drain siblings drop silently — one loss
    /// per array per poll); the next poll bootstraps cleanly.
    /// Idempotent across the row pre-gate and the
    /// [`Self::ensure_epoch`] funnel: the first call per drain
    /// does the loud work, the rest observe poison. Arrays with
    /// an M2 high-water mark skip (post-unload remaps are M2's
    /// territory — stragglers drop by the generation gap and the
    /// re-bootstrap is clean).
    fn check_first_sighting(&mut self, maps: &[maps::Mapping], op: u32, arr: u64) -> bool {
        if self.gen_high_water.contains_key(&arr) {
            return true;
        }
        if self.m1_poison.contains(&arr) {
            return false;
        }
        let base = self.baseline_for(arr, maps);
        let current = incarnation_of(maps, arr);
        if base == current {
            return true;
        }
        eprintln!("first-sighting mismatch: op={op}");
        self.tracker.note_baseline_mismatch();
        self.baselines.insert(arr, current);
        self.m1_poison.insert(arr);
        false
    }

    /// Slot-backing gate (M4): the row's impl backing must match
    /// the triple remembered for its (array, slot, impl) — a
    /// backing-only replacement at the same vaddr is
    /// indistinguishable from a stale queued row (same address,
    /// same stamp, array never bumped), so the first
    /// post-replacement row per cell drops loudly with
    /// op-localized loss (the row names its op — same channel as
    /// stragglers) and re-seats the memory; subsequent rows match
    /// and flow. First sighting records silently; a missing
    /// backing now (transient unmap) neither records nor compares
    /// (like the refresh arm, it never overwrites attested
    /// state). Callers run this after the orphan check (only
    /// validated rows participate) and before join/refresh.
    fn check_slot_backing(
        &mut self,
        op: u32,
        arr: u64,
        idx: u64,
        imp: u64,
        backing: &Option<BackingRef>,
    ) -> bool {
        let Some(current) = backing else {
            return true;
        };
        match self.slot_backing.get(&(arr, idx, imp)) {
            None => {
                self.slot_backing.insert((arr, idx, imp), current.clone());
                true
            }
            Some(remembered) if remembered == current => true,
            Some(_) => {
                eprintln!("stale slot backing: op={op} idx={idx}");
                self.tracker.note_straggler(op);
                self.slot_backing.insert((arr, idx, imp), current.clone());
                false
            }
        }
    }

    /// Register (op, arr) under its current incarnation when first
    /// observed; every fresh key mints a new epoch id.
    /// Fetch an array's epoch, minting one for a novel table.
    /// Minting bootstraps the incarnation generation (F-H/H1):
    /// `GEN[arr]` installs at previous+1 (1 for a
    /// never-before-seen array — never 0, the pre-install
    /// stamp; above the high-water mark after forget — never a
    /// reuse, M2), so records the new incarnation produces
    /// validate while the retired one's queued records drop. A
    /// novel table on an already-tracked array whose record
    /// carries the installed value adopts it (shared array
    /// across ops — no install, no bump). `None` when the
    /// install fails: nothing is inserted, existing bindings are
    /// untouched (a failed `map_update` leaves the old value), and
    /// the next record retries — with explicit loss, so a stuck
    /// install can never pass silent.
    fn ensure_epoch<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
        op: u32,
        arr: u64,
        stamp: u64,
    ) -> Option<u64> {
        if let Some(t) = self.table_epochs.get(&(op, arr)) {
            return Some(t.epoch);
        }
        if let Some(cur) = self.array_gen.get(&arr).copied()
            && cur == stamp
        {
            // Shared-array adoption (see `check_gen`): the array
            // is already bound, this op just joins it.
            let epoch = self.next_epoch;
            self.next_epoch += 1;
            self.table_epochs.insert(
                (op, arr),
                TableEpoch {
                    epoch,
                    fingerprint: incarnation_of(maps, arr),
                },
            );
            return Some(epoch);
        }
        // First-observation gate (M1): a pre-ingest replacement
        // drops the batch loud instead of bootstrapping stale
        // records against the replacement's mappings. Shared-array
        // adoption above already returned (bound arrays are
        // reconcile-guarded); only true bootstraps gate here.
        if !self.check_first_sighting(maps, op, arr) {
            return None;
        }
        let Some(generation) = self.next_generation(arr) else {
            // u64 exhaustion: fail closed like an install failure
            // (F10 — operationally unreachable).
            eprintln!("generation space exhausted for op {op}");
            self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
            return None;
        };
        if let Err(e) = env.install_generation(arr, generation) {
            eprintln!("generation bootstrap failed for op {op}: {e:#}");
            self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
            return None;
        }
        self.record_generation_install(arr, generation);
        // The bootstrap install's own drain shares the install
        // gap: same-drain stamp-0 records predate it (M2 grace).
        self.bootstrap_grace.insert(arr);
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.table_epochs.insert(
            (op, arr),
            TableEpoch {
                epoch,
                fingerprint: incarnation_of(maps, arr),
            },
        );
        Some(epoch)
    }

    /// Per-arrival generation check (F-H/H1): the record's
    /// producer stamp must agree with the array's incarnation, or
    /// the record drops with op-localized loss — never attributed
    /// against mappings it predates. Rules:
    /// - novel table, untracked array: accept only the pre-install
    ///   stamp 0 (BPF misses before the bootstrap install lands; a
    ///   nonzero stamp here is a pre-unload straggler);
    /// - novel table, tracked array: accept only the installed
    ///   value (shared-array adoption — a 0 here cannot be genuine
    ///   because BPF has a value installed, so it is ancient
    ///   garbage);
    /// - tracked table: accept the installed value, plus 0 while
    ///   the incarnation was never reborn (`GEN[arr] == 1` — the
    ///   first drain's records all predate the bootstrap install)
    ///   or the bootstrap install landed during this drain (M2
    ///   grace — same-drain records predate it). A 0 after any
    ///   rebirth, outside the install drain, is ancient garbage
    ///   (the install landed long ago), and anything else is a
    ///   retired incarnation's queued record. Fail-closed
    ///   throughout: no rule matches, no attribution.
    fn check_gen(&mut self, op: u32, arr: u64, generation: u64) -> bool {
        if !self.table_epochs.contains_key(&(op, arr)) {
            let ok = match self.array_gen.get(&arr).copied() {
                None => generation == 0,
                Some(cur) => generation == cur,
            };
            if !ok {
                self.tracker.note_straggler(op);
            }
            return ok;
        }
        if generation == 0 {
            if self.array_gen.get(&arr).copied() == Some(1) {
                return true;
            }
            if self.bootstrap_grace.contains(&arr) {
                return true;
            }
            self.tracker.note_straggler(op);
            return false;
        }
        if self.array_gen.get(&arr).copied() == Some(generation) {
            return true;
        }
        self.tracker.note_straggler(op);
        false
    }

    /// Retire one table epoch: proof and walked set drop, gap
    /// retained, join records pruned, kernel walker state evicted.
    /// `now` is the array's current fingerprint: `Some` rebirths a
    /// fresh unproven epoch, `None` (unload) removes the key.
    /// Shared by maps-turnover reconcile and repeat-init suspect
    /// (F-A/A4). Returns the retirement plus whether the array
    /// rebirthed (delta-visible rebirth).
    ///
    /// Rebirth bumps the incarnation generation (F-H/H1):
    /// `GEN[arr]` installs at previous+1 AFTER the eviction above
    /// deletes the retired entry, so the new incarnation's records
    /// validate while the retired one's queued records drop. A
    /// failed bump forgets the array's live binding (no epoch, no
    /// expected generation — the retired kernel entry is already
    /// evicted) with explicit loss, and reports no rebirth; the
    /// high-water mark survives, so the next record
    /// re-bootstraps ABOVE it instead of reusing 1 (M2) — never
    /// half-bound, never reused. Unload removes the live binding
    /// with the key (the kernel entry is evicted with it); a
    /// re-mapped array re-bootstraps above high-water, and its
    /// pre-unload stragglers drop by the generation gap whatever
    /// key they carry (same-key mmap reuse included).
    fn retire_table_epoch<E: SessionEnv>(
        &mut self,
        env: &mut E,
        op: u32,
        arr: u64,
        epoch: u64,
        now: Option<Fingerprint>,
    ) -> (TableRetirement, bool) {
        // M4: slot memories belong to the array epoch — every
        // retire path (rebirth, unload, failed bump) clears the
        // array's, so the next epoch's first rows record fresh
        // instead of going falsely stale.
        self.slot_backing.retain(|(a, _, _), _| *a != arr);
        let gap = self.tracker.retire_table(op, arr);
        self.retained.accumulate(&gap);
        self.alg_records.retain(|(a, _), _| *a != arr);
        // Generation-bind the kernel walker: without eviction a
        // sticky proof (or a mid-array cursor) from the retired
        // incarnation could satisfy the next one. Eviction
        // failure is explicit loss — and loss forces PARTIAL,
        // which contains any surviving stale proof.
        if let Err(e) = env.evict_array_state(arr) {
            eprintln!("array evict failed: {e:#}");
            self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
        }
        let rebirth = now.is_some();
        match now {
            Some(fp) => {
                let Some(generation) = self.next_generation(arr) else {
                    // u64 exhaustion: fail closed like a failed
                    // bump (F10 — operationally unreachable).
                    eprintln!("generation space exhausted for op {op}");
                    self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
                    self.table_epochs.remove(&(op, arr));
                    self.array_gen.remove(&arr);
                    return (TableRetirement { op, epoch, gap }, false);
                };
                if let Err(e) = env.install_generation(arr, generation) {
                    eprintln!("generation bump failed for op {op}: {e:#}");
                    self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
                    self.table_epochs.remove(&(op, arr));
                    self.array_gen.remove(&arr);
                    return (TableRetirement { op, epoch, gap }, false);
                }
                self.record_generation_install(arr, generation);
                // Retirement invalidates bootstrap grace (P6 §6ii):
                // the previous drain's M2 stamp-0 tolerance belongs
                // to the retired incarnation, never the replacement
                // — without this, close-time rebirth (which runs
                // before the tail join, outside any poll's
                // drain-scoped clear) would attribute queued stamp-0
                // records to the new generation. Grace is
                // array-scoped, so a rebirth conservatively retires
                // it for every table sharing the array.
                self.bootstrap_grace.remove(&arr);
                let epoch = self.next_epoch;
                self.next_epoch += 1;
                self.table_epochs.insert(
                    (op, arr),
                    TableEpoch {
                        epoch,
                        fingerprint: Some(fp),
                    },
                );
            }
            None => {
                self.table_epochs.remove(&(op, arr));
                self.array_gen.remove(&arr);
            }
        };
        (TableRetirement { op, epoch, gap }, rebirth)
    }

    /// Reconcile tracked tables against current mappings: an
    /// incarnation change or unload retires the table (proof and
    /// walked set drop, gap retained, join records pruned, kernel
    /// walker state evicted) and a reborn array starts a fresh
    /// unproven epoch. Rows are never retired — only completion
    /// state is. Returns the retirements (for the delta) and the
    /// reborn keys (fresh unproven epochs, always delta-visible).
    fn reconcile_epochs<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
    ) -> ReconcileOutcome {
        // Empty maps mean the target is gone (reaped) or the read
        // failed: there is nothing to reconcile against, and every
        // incarnation would read None != live fingerprint,
        // retiring ALL tables. The last-good epochs stand instead
        // (T14r4 w1: close-time retire-all wiped live tables and
        // the doc collapsed to 0 sites despite 581 late sites).
        if maps.is_empty() {
            return ReconcileOutcome::default();
        }
        let mut outcome = ReconcileOutcome::default();
        let keys: Vec<(u32, u64)> = self.table_epochs.keys().copied().collect();
        for (op, arr) in keys {
            let now = incarnation_of(maps, arr);
            let Some((epoch, fp)) = self
                .table_epochs
                .get(&(op, arr))
                .map(|t| (t.epoch, t.fingerprint.clone()))
            else {
                continue;
            };
            if fp == now {
                continue;
            }
            let (retirement, rebirth) = self.retire_table_epoch(env, op, arr, epoch, now);
            if rebirth {
                outcome.reborn.push((op, arr));
            }
            outcome.retired.push(retirement);
        }
        outcome
            .retired
            .sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        outcome
    }

    /// Suspect a provider file's tables on repeat init (F-A/A4): a
    /// re-initialized provider may have reborn its arrays at
    /// identical fingerprints (same file, same range — polling
    /// cannot prove absence of ABA), so every table bound to the
    /// init address's `(device, inode)` retires, plus every
    /// anonymous/unmapped table (no verifiable identity — globally
    /// suspect). An unresolvable init address scopes to anonymous
    /// only: a mapped file's tables cannot be the reborn ones.
    /// Mid-drain ring order keeps this exact: pre-init events
    /// already joined the old epoch; post-init events join the
    /// rebirth. Retires through the shared epoch path, so gaps,
    /// prunes, eviction, and rebirth links match maps turnover.
    /// Post-init records stamped with the retired generation drop
    /// as stragglers (F-H/H1) instead of joining: same-file ABA
    /// means records produced before the suspect point may attest
    /// the old incarnation, so only records the rebirth produces
    /// (new stamp) join it.
    fn suspect_provider_tables<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
        addr: u64,
        delta: &mut DiscoveryDelta,
        touched: &mut HashSet<(u32, u64)>,
    ) {
        let scope = maps
            .iter()
            .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
            .map(|m| (m.dev.clone(), m.ino));
        let mut keys: Vec<(u32, u64, u64, Option<Fingerprint>)> = self
            .table_epochs
            .iter()
            .map(|((op, arr), t)| (*op, *arr, t.epoch, t.fingerprint.clone()))
            .collect();
        keys.sort();
        for (op, arr, epoch, fp) in keys {
            let suspect = match (&scope, &fp) {
                (Some((dev, ino)), Some((fdev, fino, _, _, _))) => dev == fdev && ino == fino,
                (Some(_), None) => true,
                (None, None) => true,
                (None, Some(_)) => false,
            };
            if !suspect {
                continue;
            }
            // A second matching init in this drain retires the
            // rebirth again (chained links): each repeat init is
            // its own suspected rebirth — multi-libctx and fast
            // double-cycles are indistinguishable by polling.
            let now = incarnation_of(maps, arr);
            let (retirement, rebirth) = self.retire_table_epoch(env, op, arr, epoch, now);
            if rebirth {
                touched.insert((op, arr));
            }
            delta.retirements.push(retirement);
        }
    }

    /// Discard all observation state after a pin failure: rows and
    /// trip data are pid-scoped, hence tainted.
    fn mark_recycled(&mut self) {
        self.tracker = coverage::CoverageTracker::new();
        self.retained = coverage::CoverageDelta::default();
        self.table_epochs.clear();
        self.array_gen.clear();
        self.gen_high_water.clear();
        self.bootstrap_grace.clear();
        self.sightings.clear();
        self.sight_seq = 0;
        self.baselines.clear();
        self.m1_poison.clear();
        self.slot_backing.clear();
        self.candidates.clear();
        self.close_candidates.clear();
        self.close_remembered.clear();
        self.seen.clear();
        self.objects.clear();
        self.seen_objects.clear();
        self.alg_records.clear();
        self.ops_hit.clear();
        self.queries_events = 0;
        self.queries_by_op.clear();
        self.calls_by_op.clear();
        self.calls_joined = None;
        self.emitted_queries = 0;
        self.emitted_losses.clear();
        self.emitted_orphan_ops.clear();
        self.emitted_straggler_ops.clear();
        self.loss_seen.clear();
        self.trip_joined.clear();
        self.lgcalls_joined = 0;
        self.trip_hits.clear();
        self.probe_set = None;
        self.staged_trips = None;
        self.trip_live = false;
        self.trip_bound = None;
        self.trip_blind = false;
        self.trip_blind_print = None;
        self.legacy_note = None;
        self.attached_queries.clear();
        self.attached_targets.clear();
        self.bootstrap_query_anchor = None;
        self.attach_failures.clear();
        self.reloads.clear();
        self.pending_stage2.clear();
        self.retry_stage2.clear();
        self.dispatch_live = false;
        self.dispatch_bound = None;
        self.dispatch_ever_mapped = false;
        self.dispatch_blind = false;
        self.dispatch_blind_print = None;
        self.stashed = None;
        self.primary_init_observed = false;
        self.trigger_observed = false;
        self.trunc_seen.clear();
        self.pid_recycled = 1;
        self.recycled = true;
    }

    fn recycled_err(&self) -> anyhow::Error {
        anyhow::Error::new(Recycled {
            snapshot: self.snapshot(),
            final_snapshot: None,
        })
    }

    /// Recycle error carrying a pre-wipe final snapshot (close-time
    /// only; see [`Recycled::final_snapshot`]).
    fn recycled_err_with_final(&self, final_snapshot: DiscoverySnapshot) -> anyhow::Error {
        anyhow::Error::new(Recycled {
            snapshot: self.snapshot(),
            final_snapshot: Some(final_snapshot),
        })
    }

    fn pop_event<E: SessionEnv>(&mut self, env: &mut E) -> Option<Vec<u8>> {
        if let Some(ev) = self.stashed.take() {
            return Some(ev);
        }
        env.next_event()
    }

    fn queries_total(&self) -> u64 {
        self.calls_joined.unwrap_or(self.queries_events)
    }

    /// Current (state, sticky TRUNC bits) for one live table.
    fn live_table_state(&self, op: u32, arr: u64) -> (CoverageState, u64) {
        let state = match self.tracker.table_state(op, arr) {
            coverage::TableState::Unseen => CoverageState::Unseen,
            coverage::TableState::InProgress { walked } => CoverageState::InProgress { walked },
            coverage::TableState::Terminated { len } => CoverageState::Terminated { len },
        };
        (state, self.trunc_seen.get(&op).copied().unwrap_or(0))
    }

    /// Validate anchor bindings against current mappings (F-D/A11).
    /// Links pin the bytes they resolved at attach, so a bound
    /// (dev, ino) that is no longer mapped means dead links (exec,
    /// dlclose, replacement): detach them and clear readiness. The
    /// planning gates below re-establish what is soundly
    /// re-establishable; invalidation itself is silent (the outcome
    /// — replan, reinstall, or blind latch — carries the loss
    /// signal, exactly once per replacement).
    fn reconcile_anchors<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
        delta: &mut DiscoveryDelta,
    ) {
        // H5: one stat-facet pass per poll feeds every plane
        // (single-domain aliveness — never maps text).
        let stat_devs: Vec<Option<String>> = maps.iter().map(|m| stat_dev_of(&m.path)).collect();
        // P6 §6ii: empty maps are "no information", never an unmap —
        // but ONLY the purely maps-driven detaches below are gated
        // on that. The dispatch arm stays ungated: its stat-driven
        // paths (H10 pending re-resolve) must run against filesystem
        // truth even when the address space is unreadable (h10_t3),
        // and its maps-driven GONE branch is unreachable here anyway
        // (blind ⟹ never mapped ⟹ !ever_mapped).
        let maps_blind = maps.is_empty();
        if self.trip_live
            && let Some((path, dev, ino)) = &self.trip_bound
            && !maps_blind
            && !bindings_alive(maps, &stat_devs, path, dev, *ino)
        {
            env.detach_trips();
            // A staged plan resolved against the old maps: stale
            // offsets, never installable.
            self.staged_trips = None;
            self.trip_live = false;
        }
        if self.dispatch_live
            && let Some((path, dev, ino)) = &self.dispatch_bound
        {
            if bindings_alive(maps, &stat_devs, path, dev, *ino) {
                // ARMED (or still armed): the bound file is mapped.
                self.dispatch_ever_mapped = true;
            } else if self.dispatch_ever_mapped {
                // GONE: was mapped, now unmapped (dlclose) — detach
                // (A11 behavior preserved).
                env.detach_dispatch_anchors();
                self.dispatch_live = false;
            } else {
                // H10 PENDING: never observed mapped — retain the
                // kernel-pending links (they arm on first map).
                // Re-resolve the path per poll: a replace-before-map
                // must not leave links on A while the path serves B
                // (stat-vs-stat, H5 single-domain). Unstatable →
                // retained quietly (absence of evidence).
                match env.provider_stat() {
                    Some((cur_dev, cur_ino)) if cur_dev == *dev && cur_ino == *ino => {}
                    Some(_) => {
                        env.detach_dispatch_anchors();
                        self.dispatch_live = false;
                    }
                    None => {}
                }
            }
        }
        // Stage-2 targets whose backing vanished: detach and forget
        // (dead links never count as live coverage). Unlike the
        // planes above there is no follow-up outcome — removal is
        // terminal, so it signals here. Blind polls (empty maps: no
        // successful read yet — the death-during-first-poll race)
        // detach nothing: a zombie-phase address space is not an
        // unmap, and death is the drain's business (should_stop).
        let dead: Vec<u64> = if maps_blind {
            Vec::new()
        } else {
            self.attached_targets
                .iter()
                .filter(|(_, (_, path, dev, ino))| {
                    !bindings_alive(maps, &stat_devs, path, dev, *ino)
                })
                .map(|(cookie, _)| *cookie)
                .collect()
        };
        for cookie in dead {
            env.detach_stage2(cookie);
            self.attached_queries.remove(&cookie);
            self.attached_targets.remove(&cookie);
            delta.attaches.push(AttachEvent {
                kind: AttachKind::Stage2 { cookie },
                failed: Some("stage-2 target unmapped; link detached".to_string()),
            });
        }
    }

    /// A tripwire replan is due when not latched blind, or when the
    /// libcrypto fingerprint moved under the latch (F-D/A11).
    fn trip_replan_due(&self, maps: &[maps::Mapping]) -> bool {
        !self.trip_blind || libcrypto_print(maps) != self.trip_blind_print
    }

    /// A dispatch reinstall is due when not latched blind, or when
    /// the provider fingerprint moved under the latch (F-D/A11).
    fn dispatch_reinstall_due(&self, maps: &[maps::Mapping]) -> bool {
        !self.dispatch_blind
            || provider_print(&self.provider, &self.canon, maps) != self.dispatch_blind_print
    }

    /// Mappings for one reconcile/attribution step (F-D/Am1): a
    /// successful non-empty read refreshes the last-good snapshot;
    /// a failed read — or an EMPTY snapshot — keeps the last-good
    /// snapshot and records explicit loss instead of reading the
    /// absence as empty maps. Empty is information-free, never an
    /// unmap: a zombie (dead, not yet reaped) reads 0 bytes
    /// successfully, while a live address space always carries
    /// mappings — clobbering last-good with it terminally
    /// detached every plane in the death-during-poll race.
    fn poll_maps<E: SessionEnv>(&mut self, env: &mut E) -> Vec<maps::Mapping> {
        match env.current_maps() {
            Some(maps) if !maps.is_empty() => {
                // M1: every fresh snapshot sights its new ranges
                // (first-wins baselines for late-seen arrays).
                self.sight_mappings(&maps);
                self.last_good_maps = maps.clone();
                maps
            }
            _ => {
                self.tracker.note_maps_read();
                self.last_good_maps.clone()
            }
        }
    }

    /// One bounded poll: verify the pin, reconcile epochs, plan
    /// deferred tripwires, decode up to `budget.max_events` ring
    /// items, install up to `budget.max_attaches` pending links,
    /// and join one round of maps. Returns this poll's typed delta;
    /// cumulative state is available via [`SessionCore::snapshot`].
    pub fn poll<E: SessionEnv>(
        &mut self,
        env: &mut E,
        budget: PollBudget,
    ) -> anyhow::Result<DiscoveryDelta> {
        if self.closed {
            bail!("discovery session is closed");
        }
        if self.recycled {
            return Err(self.recycled_err());
        }
        // Every poll advances the retry clock (F-D/A12).
        self.poll_seq += 1;
        // Bootstrap-install grace is drain-scoped (M2): last
        // poll's installs confer no stamp-0 tolerance now.
        self.bootstrap_grace.clear();
        // M1 poison is drain-scoped too: re-baselined arrays
        // bootstrap cleanly from this poll on.
        self.m1_poison.clear();
        // Pin FIRST: tainted events must not drive attaches.
        if env.verify_pin().is_err() {
            self.mark_recycled();
            return Err(self.recycled_err());
        }
        let mut maps = self.poll_maps(env);
        let mut delta = DiscoveryDelta::default();
        let mut touched: HashSet<(u32, u64)> = HashSet::new();

        // F-D/A11: validate anchor bindings before planning or
        // installing anything — replacement invalidates pins, and
        // stale links must detach before fresh ones attach.
        self.reconcile_anchors(env, &maps, &mut delta);

        // Turnover reconcile BEFORE the drain (F-H/H1): a replaced
        // array retires and rebirths here — bumping `GEN[arr]` —
        // before any record is ingested, so the drain's per-arrival
        // generation check drops the retired incarnation's queued
        // records instead of attributing them against the new
        // mappings. F-A/A4 ordered drain-before-reconcile because a
        // reconcile-first order STAMPED stragglers with the new
        // epoch (A's evidence attributed to B); the generation
        // check removes the stamp path — stragglers drop with
        // explicit loss and never join any epoch — so the order is
        // safe to invert. (The bounded drain is NOT exhaustive
        // despite the old comment here: budget cap + one stash
        // slot. Stash-first ordering is preserved; cross-poll
        // stragglers are now caught by cookie, not by order.)
        let rec = self.reconcile_epochs(env, &maps);
        delta.retirements.extend(rec.retired);
        touched.extend(rec.reborn);

        let mut attaches_done = 0u32;
        // Deferred legacy planning: pre-exec images have no
        // libcrypto; plan at the first poll where it appears, and
        // install under the same attach budget as stage-2 pairs (a
        // zero budget stages the plan without installing).
        // F-D/A11: the same gate re-establishes superseded anchors
        // (reconcile cleared `trip_live` above): a fresh plan with
        // an identical cookie mapping re-attaches soundly, anything
        // else latches blind (fresh cookies would collide with old
        // meanings), and unmapped libcrypto latches silently on
        // first plan, loudly on replacement.
        if self.legacy_enabled && !self.trip_live && self.trip_replan_due(&maps) {
            if self.staged_trips.is_none() && legacy::find_libcrypto(&maps).is_some() {
                match env.plan_trips(&maps) {
                    Err(e) if is_transient_race(&e) => {
                        // File swapped mid-plan: retry next poll
                        // (no latch — the maps fingerprint is
                        // unchanged, so a latch would stick blind
                        // past a transient race).
                    }
                    Err(e) => return Err(e),
                    Ok(None) => {
                        self.trip_blind = true;
                        self.trip_blind_print = libcrypto_print(&maps);
                        if self.probe_set.is_some() {
                            delta.attaches.push(AttachEvent {
                                kind: AttachKind::Tripwires { count: 0 },
                                failed: Some(
                                    "libcrypto unmapped after replacement; \
                                     tripwire anchors blind"
                                        .to_string(),
                                ),
                            });
                        }
                    }
                    Ok(Some(fresh)) => {
                        let sound = match &self.probe_set {
                            Some(stale) => trip_mapping_equal(stale, &fresh),
                            // First plan: no old meanings to collide.
                            None => true,
                        };
                        if sound {
                            self.staged_trips = Some(fresh);
                        } else {
                            self.trip_blind = true;
                            self.trip_blind_print = libcrypto_print(&maps);
                            delta.attaches.push(AttachEvent {
                                kind: AttachKind::Tripwires {
                                    count: fresh.probes.len(),
                                },
                                failed: Some(
                                    "tripwire mapping changed across replacement; \
                                     anchors blind (cookie meanings shifted)"
                                        .to_string(),
                                ),
                            });
                        }
                    }
                }
            }
            if let Some(set) = self.staged_trips.clone()
                && attaches_done < budget.max_attaches
            {
                attaches_done += 1;
                let count = set.probes.len();
                let replan = self.probe_set.is_some();
                match env.install_trips(&set, self.pid, &maps) {
                    Err(e) if is_transient_race(&e) => {
                        // Swap spanned the install (rolled back by
                        // the env): drop the staged plan and retry
                        // next poll without latching blind.
                        self.staged_trips = None;
                    }
                    Err(e) => return Err(e),
                    Ok(note) => {
                        if self.legacy_note.is_none() {
                            self.legacy_note = note;
                        }
                        // Freshly installed: live against the
                        // plan's own libcrypto binding (validated
                        // from the next poll).
                        self.trip_bound = set.libcrypto.clone();
                        self.trip_live = true;
                        self.trip_blind = false;
                        self.probe_set = Some(set);
                        self.staged_trips = None;
                        delta.attaches.push(AttachEvent {
                            kind: AttachKind::Tripwires { count },
                            failed: replan.then(|| {
                                "tripwire anchors re-established after replacement \
                                 (identical mapping)"
                                    .to_string()
                            }),
                        });
                    }
                }
            }
        }

        let mut consumed = 0u64;
        while consumed < budget.max_events {
            let Some(item) = self.pop_event(env) else {
                break;
            };
            consumed += 1;
            self.ingest_one(env, &maps, &item, &mut delta, &mut touched);
        }
        delta.events_consumed = consumed;
        // Exact exhaustion signal: probe one past the budget and
        // stash it for the next poll (backpressure, not loss).
        if consumed == budget.max_events
            && let Some(extra) = env.next_event()
        {
            self.stashed = Some(extra);
            delta.budget_exhausted = true;
        }

        // Deterministic retirement order across the pre-drain
        // turnover batch and the mid-drain suspect batch (ring
        // order). The turnover reconcile ran before the drain
        // (F-H/H1, above); suspect retirements appended during the
        // drain join the same sorted set.
        delta
            .retirements
            .sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));

        // Resolve against fresh mappings: a provider that loaded
        // after the poll-start snapshot (file reads sit between the
        // snapshot and this drain) must still resolve.
        if !self.pending_stage2.is_empty() {
            maps = self.poll_maps(env);
        }
        // Bounded pending stage-2 installs (FIFO across polls),
        // sharing the budget with the tripwire batch above.
        while attaches_done < budget.max_attaches {
            let Some((cookie, addr)) = self.pending_stage2.pop_front() else {
                break;
            };
            attaches_done += 1;
            // A pending entry is the freshest instruction for its
            // cookie: it supersedes any queued retry (F-D/A12 —
            // recovery runs on the fresh address, never the stale
            // queued one).
            self.retry_stage2.remove(&cookie);
            // Tainted events must not drive stage-2 attaches.
            if env.verify_pin().is_err() {
                self.mark_recycled();
                return Err(self.recycled_err());
            }
            match harvest::resolve_query_target(&maps, &self.provider, &self.canon, addr, cookie) {
                Err(e) => {
                    self.record_attach_failure(
                        &mut delta,
                        cookie,
                        format!("resolve stage-2 for cookie {cookie}: {e:#}"),
                    );
                    // Unmapped (no identity to compare): retry from
                    // the next poll until it maps.
                    self.retry_stage2.insert(
                        cookie,
                        Stage2Retry {
                            addr,
                            ident: None,
                            queued_seq: self.poll_seq,
                        },
                    );
                }
                Ok(t) => {
                    let target = (t.off, t.path.to_string_lossy().into_owned(), t.dev, t.ino);
                    if self.attached_queries.contains(&cookie)
                        && self.attached_targets.get(&cookie) == Some(&target)
                    {
                        // Same callback on the same bytes: the
                        // install stands; fault the cold pages back
                        // in (best-effort).
                        env.pretouch(cookie, addr);
                        continue;
                    }
                    // F-D/A11: superseding install — the same
                    // cookie re-resolved to a different target
                    // (replacement). Detach the old link first: it
                    // pins the old bytes and would attribute to the
                    // new meaning.
                    let supersede = self.attached_queries.contains(&cookie);
                    if supersede {
                        env.detach_stage2(cookie);
                    }
                    match env.install_stage2(cookie, t.off, &t.path, self.pid, t.expected) {
                        Err(e) => {
                            self.record_attach_failure(&mut delta, cookie, format!("{e:#}"));
                            // Resolved but not installed: retry from
                            // the next poll against the same bytes
                            // (a changed identity drops the entry).
                            self.retry_stage2.insert(
                                cookie,
                                Stage2Retry {
                                    addr,
                                    ident: Some((target.2.clone(), target.3)),
                                    queued_seq: self.poll_seq,
                                },
                            );
                        }
                        Ok(()) => {
                            self.attached_queries.insert(cookie);
                            self.attached_targets.insert(cookie, target);
                            self.attach_failures.remove(&cookie);
                            env.pretouch(cookie, addr);
                            delta.attaches.push(AttachEvent {
                                kind: AttachKind::Stage2 { cookie },
                                failed: None,
                            });
                            if supersede {
                                delta.attaches.push(AttachEvent {
                                    kind: AttachKind::Stage2 { cookie },
                                    failed: Some(
                                        "stage-2 target superseded by replacement; \
                                         old link detached"
                                            .to_string(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        // F-D/A12: time-driven retry of the unattached set, in
        // cookie order (deterministic), on the remaining budget
        // (fresh pending ran first, above). Quiet systems recover
        // without fresh inits; retries stay silent while failing
        // (the first record stands — no event spam) and report
        // only transitions (install, supersede-drop).
        let due: Vec<(u64, Stage2Retry)> = self
            .retry_stage2
            .iter()
            .filter(|(_, r)| r.queued_seq < self.poll_seq)
            .map(|(c, r)| (*c, r.clone()))
            .collect();
        let mut retry_idx = 0usize;
        while retry_idx < due.len() && attaches_done < budget.max_attaches {
            let (cookie, queued) = due[retry_idx].clone();
            retry_idx += 1;
            attaches_done += 1;
            if env.verify_pin().is_err() {
                self.mark_recycled();
                return Err(self.recycled_err());
            }
            match harvest::resolve_query_target(
                &maps,
                &self.provider,
                &self.canon,
                queued.addr,
                cookie,
            ) {
                Err(_) => {
                    // Still unresolvable: keep queued, silently.
                }
                Ok(t) => {
                    let fresh_ident = (t.dev.clone(), t.ino);
                    if queued.ident.as_ref().is_some_and(|r| *r != fresh_ident) {
                        // Bytes changed under the queued address:
                        // drop (a fresh init drives recovery, if
                        // any) — never attach to the wrong bytes.
                        self.retry_stage2.remove(&cookie);
                        delta.attaches.push(AttachEvent {
                            kind: AttachKind::Stage2 { cookie },
                            failed: Some(
                                "stage-2 retry superseded by replacement; \
                                 awaiting fresh init"
                                    .to_string(),
                            ),
                        });
                        continue;
                    }
                    let target = (t.off, t.path.to_string_lossy().into_owned(), t.dev, t.ino);
                    match env.install_stage2(cookie, t.off, &t.path, self.pid, t.expected) {
                        Err(_) => {
                            // Still failing: keep queued with the
                            // fresh identity (learned), silently.
                            self.retry_stage2.insert(
                                cookie,
                                Stage2Retry {
                                    addr: queued.addr,
                                    ident: Some(fresh_ident),
                                    queued_seq: queued.queued_seq,
                                },
                            );
                        }
                        Ok(()) => {
                            self.retry_stage2.remove(&cookie);
                            self.attached_queries.insert(cookie);
                            self.attached_targets.insert(cookie, target);
                            self.attach_failures.remove(&cookie);
                            env.pretouch(cookie, queued.addr);
                            delta.attaches.push(AttachEvent {
                                kind: AttachKind::Stage2 { cookie },
                                failed: None,
                            });
                        }
                    }
                }
            }
        }
        if self.staged_trips.is_some() || !self.pending_stage2.is_empty() || retry_idx < due.len() {
            delta.budget_exhausted = true;
        }

        // F-D/A11: re-establish superseded dispatch anchors under
        // the same attach budget (bounded batches). Success restores
        // readiness with a continuity caveat (the replacement gap is
        // unproven); failure latches blind until the provider
        // fingerprint moves; a transient file race retries next
        // poll without latching.
        if !self.dispatch_live
            && self.dispatch_bound.is_some()
            && self.dispatch_reinstall_due(&maps)
            && attaches_done < budget.max_attaches
        {
            // Gated on the remaining budget (bounded batches);
            // no counter increment — nothing observes attach
            // counts past this point.
            match env.reinstall_dispatch() {
                Err(e) if is_transient_race(&e) => {}
                Err(e) => {
                    self.dispatch_blind = true;
                    self.dispatch_blind_print = provider_print(&self.provider, &self.canon, &maps);
                    self.preset_reason = Some("anchor-unresolved".to_string());
                    delta.attaches.push(AttachEvent {
                        kind: AttachKind::DispatchAnchors { count: 0 },
                        failed: Some(format!("dispatch reinstall failed: {e:#}")),
                    });
                }
                Ok(fresh) => {
                    self.dispatch_bound = Some(fresh.binding);
                    self.dispatch_live = true;
                    self.dispatch_blind = false;
                    self.resolution = fresh.resolution;
                    self.preset_reason = None;
                    // H10: a pending re-resolve (never mapped in
                    // this pid) is provably lossless — no events
                    // could have fired on either inode — so it
                    // carries no continuity caveat. Only a
                    // post-map replacement keeps the caveat.
                    let failed = self.dispatch_ever_mapped.then(|| {
                        "dispatch anchors re-established after replacement; \
                         continuity unproven"
                            .to_string()
                    });
                    delta.attaches.push(AttachEvent {
                        kind: AttachKind::DispatchAnchors { count: 2 },
                        failed,
                    });
                }
            }
        }

        // Map-only transitions (a late proof, a fresh TRUNC bit)
        // are delta-visible too: compare every tracked table
        // across the join.
        let pre_join: HashMap<(u32, u64), (CoverageState, u64)> = self
            .table_epochs
            .keys()
            .map(|(op, arr)| ((*op, *arr), self.live_table_state(*op, *arr)))
            .collect();
        let snap = env.join_maps();
        self.join_snapshots(&snap, &mut delta);
        for (op, arr) in self.table_epochs.keys() {
            let cur = self.live_table_state(*op, *arr);
            if pre_join.get(&(*op, *arr)) != Some(&cur) {
                touched.insert((*op, *arr));
            }
        }

        let mut tables: Vec<TableCoverage> = Vec::with_capacity(touched.len());
        for (op, arr) in &touched {
            let Some(t) = self.table_epochs.get(&(*op, *arr)) else {
                continue;
            };
            let (state, trunc_bits) = self.live_table_state(*op, *arr);
            tables.push(TableCoverage {
                op: *op,
                epoch: t.epoch,
                state,
                trunc_bits,
            });
        }
        tables.sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        delta.tables = tables;

        // Fresh losses: positive diffs of the cumulative tracker
        // against what earlier deltas already reported. Orphan ROWs
        // and straggler records localize to their op (per-op diffs
        // below); everything else is unlocalizable (op: None) and
        // taints every op (F-B/A7).
        for (src, n) in self.tracker.losses() {
            let last = self.emitted_losses.get(&src).copied().unwrap_or(0);
            if n > last && src != coverage::HOST_ORPHAN_ROW && src != coverage::HOST_STRAGGLER {
                delta.losses.push(DiscoveryLoss {
                    source: src,
                    count: n - last,
                    op: None,
                });
            }
            self.emitted_losses.insert(src, n);
        }
        for (op, n) in self.tracker.orphan_ops() {
            let last = self.emitted_orphan_ops.get(&op).copied().unwrap_or(0);
            if n > last {
                delta.losses.push(DiscoveryLoss {
                    source: coverage::HOST_ORPHAN_ROW,
                    count: n - last,
                    op: Some(op),
                });
            }
            self.emitted_orphan_ops.insert(op, n);
        }
        for (op, n) in self.tracker.straggler_ops() {
            let last = self.emitted_straggler_ops.get(&op).copied().unwrap_or(0);
            if n > last {
                delta.losses.push(DiscoveryLoss {
                    source: coverage::HOST_STRAGGLER,
                    count: n - last,
                    op: Some(op),
                });
            }
            self.emitted_straggler_ops.insert(op, n);
        }
        let total = self.queries_total();
        delta.queries_delta = total.saturating_sub(self.emitted_queries);
        self.emitted_queries = total;
        delta.trigger_observed = self.trigger_observed;

        self.last_links = env.link_counts();
        Ok(delta)
    }

    fn record_attach_failure(&mut self, delta: &mut DiscoveryDelta, cookie: u64, msg: String) {
        // Retryable state, not a terminal verdict: the next init
        // for this cookie re-attempts the install.
        self.attach_failures.insert(cookie, msg.clone());
        delta.attaches.push(AttachEvent {
            kind: AttachKind::Stage2 { cookie },
            failed: Some(msg),
        });
    }

    /// Join one round of map snapshots: `TERMD`/`TRUNC`
    /// idempotently, cumulative counters monotonically (only
    /// increments reach the tracker and the delta). Every baseline
    /// is a high-water mark: a dipped or partial read (failed
    /// iteration, reset map) never moves a baseline backward, so
    /// `5→0→5` reports five once, not twice. Kernel counters are
    /// `u64` monotonic (a wrap needs 2⁶⁴ events); a dip always
    /// means a bad read, and bad reads are flagged below.
    fn join_snapshots(&mut self, snap: &MapSnapshots, delta: &mut DiscoveryDelta) {
        self.tracker.ingest_termd(&snap.termd);
        self.tracker.ingest_trunc(&snap.trunc);
        for (op, bits) in &snap.trunc {
            *self.trunc_seen.entry(*op).or_default() |= *bits;
        }
        for (src, n) in &snap.losses {
            let last = self.loss_seen.get(src).copied().unwrap_or(0);
            if *n > last {
                self.loss_seen.insert(*src, *n);
                self.tracker.ingest_losses(&[(*src, *n - last)]);
            }
        }
        for failed in [
            snap.trunc_failed,
            snap.termd_failed,
            snap.losses_failed,
            snap.trip_failed,
            snap.calls_failed,
            snap.lgcalls_failed,
        ] {
            if failed {
                self.tracker.note_map_snapshot();
            }
        }
        // The query source pins on first join: CALLS-joined when
        // the map exists (always, live), event-count otherwise. A
        // later missing read keeps the last total rather than
        // flapping sources mid-stream.
        if !self.calls_pinned {
            self.calls_pinned = true;
            self.calls_joined = snap.calls;
        } else if let (Some(cur), Some(c)) = (self.calls_joined, snap.calls) {
            self.calls_joined = Some(cur.max(c));
        }
        // Per-op CALLS high-water (same max-join per key; partial
        // rows from a failed iteration can only undershoot, so the
        // max ignores the dip exactly like the total's).
        if snap.calls.is_some() {
            for (op, n) in &snap.calls_by_op {
                let last = self.calls_by_op.get(op).copied().unwrap_or(0);
                if *n > last {
                    self.calls_by_op.insert(*op, *n);
                }
            }
        }
        let joined: HashMap<u64, u64> = snap.trip.iter().copied().collect();
        for (cookie, n) in &joined {
            let last = self.trip_joined.get(cookie).copied().unwrap_or(0);
            if *n > last {
                delta.tripwire.counter_deltas.push((*cookie, *n - last));
                self.trip_joined.insert(*cookie, *n);
            }
        }
        delta.tripwire.counter_deltas.sort_unstable();
        if snap.lgcalls > self.lgcalls_joined {
            delta.tripwire.executed_legacy_queries_delta = snap.lgcalls - self.lgcalls_joined;
            self.lgcalls_joined = snap.lgcalls;
        }
    }

    /// Decode one raw ring item into core state. Payloads are small
    /// numerics-only structs (shared wire ABI v2): unknown kinds
    /// cannot be sized, so they are dropped before any field is
    /// read. Every drop path counts its loss at the drop site.
    #[allow(clippy::too_many_lines, reason = "one decode dispatch per wire kind")]
    fn ingest_one<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
        b: &[u8],
        delta: &mut DiscoveryDelta,
        touched: &mut HashSet<(u32, u64)>,
    ) {
        if b.len() < 4 {
            eprintln!("short event: {} bytes", b.len());
            self.tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
            return;
        }
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let want = match kind {
            wire::KIND_INIT_RET => size_of::<wire::InitRetEvent>(),
            wire::KIND_QUERY_RET | wire::KIND_ROW => size_of::<wire::RowEvent>(),
            wire::KIND_ALG => size_of::<wire::AlgEvent>(),
            wire::KIND_TRIP => size_of::<wire::TripEvent>(),
            k => {
                eprintln!("unknown event kind {k}");
                self.tracker.note_bad_event(coverage::HOST_UNKNOWN_KIND);
                return;
            }
        };
        if b.len() < want {
            eprintln!("short event: {} bytes", b.len());
            self.tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
            return;
        }
        match kind {
            wire::KIND_INIT_RET => {
                let Ok(ev) = wire::parse_init_ret_event(b) else {
                    eprintln!("bad init-ret event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                // aux carries the attach cookie: 0 = target
                // provider, 1 = legacy.
                let cookie = ev.aux;
                if self.attached_queries.contains(&cookie) {
                    // Repeat init (unload/reload cycles,
                    // multi-libctx): witness the reload, suspect
                    // the provider's tables (F-A/A4 — a
                    // same-fingerprint rebirth is
                    // polling-invisible), and queue for
                    // the bounded drain, which re-resolves and
                    // re-attaches when the callback moved, else
                    // faults the cold pages back in.
                    *self.reloads.entry(cookie).or_default() += 1;
                    self.suspect_provider_tables(env, maps, ev.addr, delta, touched);
                    self.pending_stage2.push_back((cookie, ev.addr));
                    return;
                }
                if cookie == 0 {
                    self.primary_init_observed = true;
                }
                // Resolution + install happen in the bounded
                // pending drain below; failures are recorded for
                // event-driven retry on the next init.
                self.pending_stage2.push_back((cookie, ev.addr));
            }
            wire::KIND_QUERY_RET => {
                let Ok(ev) = wire::parse_row_event(b) else {
                    eprintln!("bad query-ret event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if ev.kind != wire::KIND_QUERY_RET || ev.funcid != 0 {
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                if !self.check_gen(ev.op, ev.addr, ev.generation) {
                    return;
                }
                self.trigger_observed = true;
                self.queries_events += 1;
                self.ops_hit.insert(ev.op);
                *self.queries_by_op.entry(ev.op).or_default() += 1;
                // Unbound (bootstrap install failed — loss already
                // recorded): liveness above is genuine, but nothing
                // epoch-scoped may join until the array binds.
                if self
                    .ensure_epoch(env, maps, ev.op, ev.addr, ev.generation)
                    .is_none()
                {
                    return;
                }
                self.tracker.note_query_ret(ev.op, ev.addr);
                touched.insert((ev.op, ev.addr));
                if debug_session() {
                    eprintln!("HARVESTDBG query_ret op={} slot={}", ev.op, ev.aux);
                }
            }
            wire::KIND_ALG => {
                let Ok(ev) = wire::parse_alg_event(b, self.class_count) else {
                    eprintln!("bad alg event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if !self.check_gen(ev.op, ev.arr, ev.generation) {
                    return;
                }
                self.trigger_observed = true;
                let Some(label) = crate::kinds::alg_class_label(ev.class) else {
                    eprintln!("alg event with out-of-range class {}", ev.class);
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                let Some(status) = wire::alg_status_name(ev.status) else {
                    eprintln!("alg event with out-of-range status {}", ev.status);
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if debug_session() {
                    eprintln!(
                        "{}",
                        debug_alg_line(ev.op, ev.idx, label, ev.weak != 0, ev.status)
                    );
                }
                // Unreadable/overlong names lose the slot's
                // identity (no retained prefix); unknown names
                // are explicit `other` evidence, not loss.
                let lossy = ev.status == wire::ALG_UNREADABLE || ev.status == wire::ALG_OVERLONG;
                // Unbound (bootstrap install failed — loss already
                // recorded): the verdict must not join `alg_records`
                // where a later row could meet pre-epoch data.
                if self
                    .ensure_epoch(env, maps, ev.op, ev.arr, ev.generation)
                    .is_none()
                {
                    return;
                }
                self.tracker.note_alg(ev.op, ev.arr, ev.idx, lossy);
                self.alg_records.insert(
                    (ev.arr, ev.idx),
                    (label.to_string(), ev.weak != 0, status.to_string()),
                );
                touched.insert((ev.op, ev.arr));
            }
            wire::KIND_ROW => {
                let Ok(ev) = wire::parse_row_event(b) else {
                    eprintln!("bad row event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if ev.kind != wire::KIND_ROW {
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                // Incarnation before slot: a retired generation's
                // record is a straggler even when its slot also
                // lost its ALG (orphan would mislocalize the cause).
                if !self.check_gen(ev.op, ev.aux, ev.generation) {
                    return;
                }
                // Same for first observation (M1): a poisoned
                // array's row drops here, not as an orphan — the
                // mismatch loss already names the cause.
                if !self.check_first_sighting(maps, ev.op, ev.aux) {
                    return;
                }
                self.trigger_observed = true;
                touched.insert((ev.op, ev.aux));
                let Some((label, weak, status)) = self.alg_records.get(&(ev.aux, ev.idx)).cloned()
                else {
                    eprintln!("orphan row: op={} idx={}", ev.op, ev.idx);
                    self.tracker.note_orphan_row(ev.op);
                    return;
                };
                let key = (
                    ev.op,
                    label.clone(),
                    weak,
                    status.clone(),
                    ev.funcid,
                    ev.addr,
                    ev.aux,
                );
                let (advertising, advertising_dev, advertising_ino) = array_owner(maps, ev.aux);
                let (backing, locator) = attribute_impl(maps, &self.provider, &self.canon, ev.addr);
                // Slot-backing gate (M4): compares BEFORE the
                // refresh arm below can adopt a changed backing —
                // a mismatched duplicate drops here instead.
                if !self.check_slot_backing(ev.op, ev.aux, ev.idx, ev.addr, &backing) {
                    return;
                }
                if let Some(&i) = self.seen.get(&key) {
                    // Duplicate key (multi-libctx re-query): refresh
                    // identities when the current mappings attest a
                    // new owner or backing (same-address remap),
                    // else skip. A missing backing now (transient
                    // unmap) never overwrites an attested triple —
                    // the render re-derives from live maps.
                    // The epoch heals too (F-A/A4): a re-walked row
                    // is live evidence in the CURRENT epoch, so it
                    // re-points (and re-emits) instead of sticking
                    // to a retired one. Sound because every ingest
                    // arm gates on `check_gen` before ANY
                    // attribution or heal (QUERY_RET/ALG/ROW arms
                    // above): a retired generation's straggler
                    // drops with loss before reaching this refresh,
                    // so only live-generation rows re-point, and
                    // same-epoch re-queries compare equal and stay
                    // silent. No minting here: an unloaded array
                    // (key removed) keeps its retired stamp — only
                    // a live table re-points.
                    let mut changed = false;
                    if let Some(t) = self.table_epochs.get(&(ev.op, ev.aux)) {
                        let live_epoch = t.epoch;
                        if self.candidates[i].epoch != live_epoch {
                            self.candidates[i].epoch = live_epoch;
                            changed = true;
                        }
                    }
                    if self.candidates[i].advertising != advertising
                        || self.candidates[i].advertising_dev != advertising_dev
                        || self.candidates[i].advertising_ino != advertising_ino
                    {
                        self.candidates[i].advertising = advertising;
                        self.candidates[i].advertising_dev = advertising_dev;
                        self.candidates[i].advertising_ino = advertising_ino;
                        changed = true;
                    }
                    if let Some(b) = &backing
                        && self.candidates[i].backing.as_ref() != Some(b)
                    {
                        if self.seen_objects.insert((b.dev.clone(), b.ino)) {
                            let obj = DiscoveredObject {
                                dev: b.dev.clone(),
                                ino: b.ino,
                                display_locator: locator,
                            };
                            self.objects.push(obj.clone());
                            delta.objects.push(obj);
                        }
                        self.candidates[i].backing = Some(b.clone());
                        changed = true;
                    }
                    if changed {
                        delta.candidates.push(self.candidates[i].clone());
                    }
                } else {
                    // Unbound (bootstrap install failed — loss
                    // already recorded): no epoch exists to stamp,
                    // so the row cannot become a candidate.
                    let Some(epoch) = self.ensure_epoch(env, maps, ev.op, ev.aux, ev.generation)
                    else {
                        return;
                    };
                    if let Some(b) = &backing
                        && self.seen_objects.insert((b.dev.clone(), b.ino))
                    {
                        let obj = DiscoveredObject {
                            dev: b.dev.clone(),
                            ino: b.ino,
                            display_locator: locator,
                        };
                        self.objects.push(obj.clone());
                        delta.objects.push(obj);
                    }
                    let candidate = DiscoveredCandidate {
                        advertising,
                        advertising_dev,
                        advertising_ino,
                        backing,
                        op: ev.op,
                        funcid: ev.funcid,
                        class: label,
                        weak,
                        status,
                        epoch,
                        impl_addr: ev.addr,
                        arr: ev.aux,
                    };
                    self.seen.insert(key, self.candidates.len());
                    self.candidates.push(candidate.clone());
                    delta.candidates.push(candidate);
                }
            }
            wire::KIND_TRIP => {
                // Deliberately NOT a dispatch trigger (doctrine:
                // tripwires observe independently of the dispatch
                // harvest).
                let Ok(ev) = wire::parse_trip_event(b) else {
                    eprintln!("bad trip event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                // Trip events imply attached tripwires, which imply
                // a planned probe set; without one the cookie
                // cannot be validated, so the hit is dropped.
                if self.probe_set.is_none() {
                    eprintln!("trip hit before probe plan");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                let hit = {
                    let set = self.probe_set.as_ref().expect("checked above");
                    harvest::decode_trip_hit(ev.cookie as u64, ev.class, ev.status, set)
                };
                match hit {
                    Some(hit) => {
                        self.trip_hits.push(hit);
                        delta.tripwire.hits.push(hit);
                    }
                    None => {
                        eprintln!(
                            "trip hit outside taxonomy: cookie={} class={}",
                            ev.cookie, ev.class
                        );
                        self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    }
                }
            }
            // Unreachable: unknown kinds are dropped at the sizing
            // match above, before any field is read.
            _ => {}
        }
    }

    /// Cumulative discovery state. Candidates, objects, tables, and
    /// reasons all serialize deterministically (total orders,
    /// never arrival order).
    pub fn snapshot(&self) -> DiscoverySnapshot {
        let mut candidates = self.candidates.clone();
        candidates.sort_by(|a, b| {
            (
                a.op,
                &a.class,
                &a.status,
                a.funcid,
                a.epoch,
                a.backing.as_ref(),
            )
                .cmp(&(
                    b.op,
                    &b.class,
                    &b.status,
                    b.funcid,
                    b.epoch,
                    b.backing.as_ref(),
                ))
        });
        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| (&a.dev, a.ino).cmp(&(&b.dev, b.ino)));
        let mut tables: Vec<TableCoverage> = self
            .table_epochs
            .iter()
            .map(|((op, arr), t)| {
                let (state, trunc_bits) = self.live_table_state(*op, *arr);
                TableCoverage {
                    op: *op,
                    epoch: t.epoch,
                    state,
                    trunc_bits,
                }
            })
            .collect();
        tables.sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        let mut truncated_ops: Vec<(u32, u64)> =
            self.trunc_seen.iter().map(|(op, b)| (*op, *b)).collect();
        truncated_ops.sort_unstable();
        let mut ops_hit: Vec<u32> = self.ops_hit.iter().copied().collect();
        ops_hit.sort_unstable();
        // Same source as the published total: CALLS-joined per-op
        // when the map exists, event counts otherwise.
        let mut queries_by_op: Vec<(u32, u64)> = if self.calls_joined.is_some() {
            self.calls_by_op.iter().map(|(op, n)| (*op, *n)).collect()
        } else {
            self.queries_by_op.iter().map(|(op, n)| (*op, *n)).collect()
        };
        queries_by_op.sort_unstable();
        let mut attach_failures: Vec<AttachFailure> = self
            .attach_failures
            .iter()
            .map(|(cookie, error)| AttachFailure {
                cookie: *cookie,
                error: error.clone(),
            })
            .collect();
        attach_failures.sort_by(|a, b| a.cookie.cmp(&b.cookie));
        let mut reloads: Vec<(u64, u64)> = self.reloads.iter().map(|(c, n)| (*c, *n)).collect();
        reloads.sort_unstable();
        DiscoverySnapshot {
            candidates,
            close_candidates: self.close_candidates.clone(),
            close_remembered: self.close_remembered.clone(),
            objects,
            tables,
            reasons: union_reasons(&self.retained.reasons, &self.tracker.reasons()),
            retained_reasons: self.retained.reasons.clone(),
            losses: self.tracker.losses(),
            truncated_ops,
            lossy_slots: self.tracker.lossy_slots(),
            queries_observed: self.queries_total(),
            queries_by_op,
            ops_hit,
            dispatch: DispatchSnapshot {
                attached: self.dispatch_live || !self.attached_queries.is_empty(),
                preset_reason: self.preset_reason.clone(),
                resolution: self.resolution.clone(),
                attach_failures,
                reloads,
                primary_init_observed: self.primary_init_observed,
                trigger_observed: self.trigger_observed,
                bootstrap_binding: self.bootstrap_binding.clone(),
            },
            legacy: LegacySnapshot {
                planned: self.trip_live,
                set: self.probe_set.clone(),
                trip: self.trip_joined.clone(),
                hits: self.trip_hits.clone(),
                executed_queries: self.lgcalls_joined,
                extra_findings: self.legacy_note.clone().into_iter().collect(),
            },
            links_live: LinkLiveness {
                dispatch: self.last_links.0,
                tripwire: self.last_links.1,
            },
            pid_recycled: self.pid_recycled,
        }
    }

    /// Quiesce-then-PROCESS teardown: drop the attach links first
    /// (no new events can arrive past this point), ingest the
    /// quiesced ring tail through the same path as poll (bounded
    /// by one default budget — P6 §6ii), count only the residual
    /// past the bound as drain shortfall, join the maps once more,
    /// and verify the pin — so no post-stop arrival escapes
    /// accounting. Consumes nothing: the closed session keeps its
    /// final snapshot but rejects further polls.
    pub fn close<E: SessionEnv>(&mut self, env: &mut E) -> anyhow::Result<DiscoverySnapshot> {
        if self.closed {
            bail!("discovery session is already closed");
        }
        self.closed = true;
        // Freeze M4 cell memory at entry (sol round 4): the final
        // reconcile below RETIRES tables — wiping their cells —
        // and a terminated retirement is SILENT (no retained
        // reason — it carried no gap). The remap-evidence scan
        // must therefore read pre-reconciliation memory, else a
        // queued first-cross-op ROW joining a remapped impl loses
        // its old backing silently. Triples only (imp, ino, off)
        // — all the scan needs; one-time close cost.
        let frozen_backings: Vec<(u64, u64, u64)> = self
            .slot_backing
            .iter()
            .map(|((_, _, imp), b)| (*imp, b.ino, b.offset))
            .collect();
        // Final reconcile so the closing snapshot never carries a
        // stale-epoch table (retirements feed the retained gaps).
        // A failed read reconciles against last-good (F-D/Am1),
        // not empty — with explicit loss.
        let maps = self.poll_maps(env);
        self.reconcile_epochs(env, &maps);
        env.quiesce();
        // Tail join (P6 §6ii): a fast-dying target's in-ring wave
        // joins the snapshot instead of becoming shortfall. Same
        // ingest_one path as poll (no attaches can issue — the
        // pending drains live in poll(), and quiesce already
        // dropped the links); the close-time delta is discarded
        // like the join below, the snapshot carries the state.
        let mut delta = DiscoveryDelta::default();
        let mut touched: HashSet<(u32, u64)> = HashSet::new();
        let mut joined = 0u64;
        while joined < PollBudget::default().max_events {
            let Some(item) = self.pop_event(env) else {
                break;
            };
            joined += 1;
            self.ingest_one(env, &maps, &item, &mut delta, &mut touched);
        }
        delta.events_consumed = joined;
        let mut shortfall: u64 = 0;
        while self.pop_event(env).is_some() {
            shortfall += 1;
        }
        if shortfall > 0 {
            eprintln!("drain shortfall: {shortfall} unprocessed ring items at stop");
        }
        self.tracker.note_drain_shortfall(shortfall);
        // Final join feeds cumulative state only (the close-time
        // delta is discarded — the snapshot below carries it).
        let snap = env.join_maps();
        self.join_snapshots(&snap, &mut delta);
        // ...except its candidates (P6 §6ii sol blocker 2): they
        // never rode a poll delta, so a delta-fed consumer
        // (capture's adapter) never saw them — stash them for the
        // snapshot so the finish-time reconcile taints their
        // ops/sites instead of claiming a poll-time census.
        self.close_candidates = std::mem::take(&mut delta.candidates);
        // Remap-evidence scan (sol round 3, frozen round 4): for
        // each close-joined impl, collect M4-remembered (ino,
        // offset) backings that DIFFER from the joined one. A
        // first-cell adoption is silent, so it may have outrun an
        // impl remap (stale record, misattributed) — the old
        // sites' sets may miss the alias and must revise too.
        // Reads the ENTRY-FROZEN memory plus the live map (union,
        // deduped): the final reconcile above may have retired
        // tables — wiping their cells — and a terminated
        // retirement is SILENT, so post-reconcile memory alone
        // would forget the old backing without any taint. There
        // is deliberately no reliance on "retirement's own global
        // taint" (that claim was false for the silent shape).
        // Per-candidate filter + global union, sorted + deduped
        // for determinism. Only the direct shape is covered.
        {
            let mut remembered: Vec<(u64, u64)> = Vec::new();
            for candidate in &self.close_candidates {
                let Some(joined) = candidate.backing.as_ref() else {
                    continue;
                };
                let joined_pair = (joined.ino, joined.offset);
                for (imp, ino, off) in frozen_backings.iter().copied().chain(
                    self.slot_backing
                        .iter()
                        .map(|((_, _, imp), b)| (*imp, b.ino, b.offset)),
                ) {
                    if imp == candidate.impl_addr && (ino, off) != joined_pair {
                        remembered.push((ino, off));
                    }
                }
            }
            remembered.sort_unstable();
            remembered.dedup();
            self.close_remembered = remembered;
        }
        self.last_links = env.link_counts();
        // Pre-wipe final: every poll's joins plus the close-time
        // tail count, before the recycle wipe below destroys the
        // tracker. A reaped owned child (custody-known exit, not a
        // recycle) keeps this state via the error carrier instead of
        // losing the close-time magnitude (G07: the doc records the
        // event AND its count, never stderr-only).
        let final_snap = self.snapshot();
        if env.verify_pin().is_err() {
            self.mark_recycled();
            return Err(self.recycled_err_with_final(final_snap));
        }
        Ok(self.snapshot())
    }
}

/// Advertising identity for one array: the owning mapping's
/// (path, dev, ino) triple, or empty/zero for anonymous/unmapped
/// arrays (which carry no attributable owner). The triple travels
/// on the candidate (F-A/A3) so capture verifies the array's
/// current owner instead of re-resolving a bare locator.
fn array_owner(maps: &[maps::Mapping], arr: u64) -> (String, String, u64) {
    maps.iter()
        .find(|m| m.start <= arr && arr < m.end && m.ino != 0)
        .map(|m| (m.path.clone(), backing_dev(m), m.ino))
        .unwrap_or_default()
}

/// Backing device for one mapping (H5): STAT-domain (fstat
/// dev_t, rendered `MM:mm`), so x-subvol/x-mount twins (same
/// maps-dev + ino — measured btrfs/overlay/tmpfs) separate and
/// btrfs/overlay stat-vs-maps divergence never false-fails a
/// downstream stat-stat bind. Unstatable paths (`(deleted)`,
/// foreign mount namespaces) fall back to the maps dev-string:
/// downstream stat compares then safely mismatch (loud miss),
/// while turnover keeps unlinked-but-mapped files via
/// maps-identity (dual-facet bindings). Spike:
/// evidence/2026-10-11-h5-spike/.
pub(crate) fn backing_dev(m: &maps::Mapping) -> String {
    // Maps fallback (H5 tension, sol round 2): keeps
    // deleted-but-mapped files trackable, but one file may then
    // group under two device facets across an unlink. Triple
    // grouping does not dual-facet (bindings do); consumers that
    // must survive the flip match (ino, offset) instead (capture's
    // close reconcile) rather than comparing this string.
    stat_dev_of(&m.path).unwrap_or_else(|| m.dev.clone())
}

/// Resolve-time stat device for one mapped path (H5): `None`
/// when unstatable (`(deleted)`, foreign mount namespaces).
/// The `Some` facet compares stat-vs-stat; the `None` facet
/// keeps deleted-but-mapped files via path + ino (dual-facet
/// bindings — the maps dev-string is never compared).
pub(crate) fn stat_dev_of(path: &str) -> Option<String> {
    std::fs::metadata(path).ok().map(|meta| {
        use std::os::unix::fs::MetadataExt as _;
        crate::plan::render_stat_dev(meta.dev())
    })
}

/// Anchor aliveness (H5 single-domain): a stored (path,
/// stat-dev, ino) binding is alive iff some mapping still backs
/// the same file — stat-vs-stat when the mapping is statable,
/// else same-path + same-ino (the file was unlinked but stays
/// mapped). The maps dev-string is NEVER compared (btrfs /
/// overlay diverge it from stat — reconciling against it
/// detached live anchors every poll on such filesystems).
fn bindings_alive(
    maps: &[maps::Mapping],
    stat_devs: &[Option<String>],
    path: &str,
    dev: &str,
    ino: u64,
) -> bool {
    maps.iter().zip(stat_devs.iter()).any(|(m, stat)| {
        m.ino == ino
            && match stat {
                Some(cur) => cur == dev,
                None => m.path == path,
            }
    })
}

/// Relocate one implementation address to its claimed backing
/// triple plus the owning locator: the provider mapping first,
/// then any file mapping (shared-code rows), else unbacked. This
/// mirrors the document render's mapping rule minus the
/// executable/ELF-segment verification, which stays render-side.
/// Backing device is STAT-domain ([`backing_dev`]).
fn attribute_impl(
    maps: &[maps::Mapping],
    provider: &Path,
    canon: &str,
    addr: u64,
) -> (Option<BackingRef>, String) {
    if let Some((m, _)) = maps::provider_mapping(maps, provider, canon, addr) {
        let backing = BackingRef {
            dev: backing_dev(m),
            ino: m.ino,
            offset: addr - m.start + m.offset,
        };
        return (Some(backing), m.path.clone());
    }
    if let Some(m) = maps
        .iter()
        .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
    {
        let backing = BackingRef {
            dev: backing_dev(m),
            ino: m.ino,
            offset: addr - m.start + m.offset,
        };
        return (Some(backing), m.path.clone());
    }
    (None, String::new())
}

/// Ranked union of retained and live gap reasons: the frozen
/// ranking orders known reasons; unrecognized strings (newer
/// producer than consumer) append sorted rather than vanishing.
fn union_reasons(retained: &[String], live: &[String]) -> Vec<String> {
    use coverage::ReasonFlags;
    let has = |r: &str| retained.iter().any(|x| x == r) || live.iter().any(|x| x == r);
    let mut out: Vec<String> = coverage::ranked_reasons(&ReasonFlags {
        fenced: has(coverage::REASON_FENCED_ROWS),
        loss: has(coverage::REASON_DISCOVERY_LOSS),
        unreadable: has(coverage::REASON_UNREADABLE_ALG),
        truncated: has(coverage::REASON_TRUNCATED_WALK),
        prefix: has(coverage::REASON_PREFIX_WALK),
        zero_row: has(coverage::REASON_ZERO_ROW_OPS),
    })
    .into_iter()
    .map(str::to_string)
    .collect();
    let known = |r: &str| {
        [
            coverage::REASON_FENCED_ROWS,
            coverage::REASON_DISCOVERY_LOSS,
            coverage::REASON_UNREADABLE_ALG,
            coverage::REASON_TRUNCATED_WALK,
            coverage::REASON_PREFIX_WALK,
            coverage::REASON_ZERO_ROW_OPS,
        ]
        .contains(&r)
    };
    let mut extra: Vec<String> = retained
        .iter()
        .chain(live.iter())
        .filter(|r| !known(r))
        .cloned()
        .collect();
    extra.sort_unstable();
    extra.dedup();
    out.extend(extra);
    out
}

// ---------------------------------------------------------------------------
// Live environment: BPF resources owned until session drop.
// ---------------------------------------------------------------------------

/// Attach-link plane: dispatch anchors/pairs vs tripwires (the
/// liveness witness keeps the planes separate). Stage-2 query
/// pairs are their own kind so replacement reconciliation can
/// detach them per cookie without touching the anchors (F-D/A11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkKind {
    Init,
    Query,
    Tripwire,
    Stage2,
}

/// One owned multi link (drop = detach) with its plane record
/// and the open-file pin it bound through (H4: one fd per link
/// entry, dup'd at push — the pin drops WITH its link, so
/// selective detach releases pins with their links and no pin
/// outlives (or pre-dies) its link).
///
/// `link`/`pin` are pure RAII guards (drop = detach/release),
/// never read by design.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct LinkEntry {
    link: OwnedFd,
    pin: OwnedFd,
    kind: LinkKind,
    cookies: Vec<u64>,
}

/// Owned multi links with their plane records. Cookies ride
/// along so selective detach can identify batch members
/// (tripwire links carry the whole batch's cookies).
#[derive(Default)]
pub(crate) struct LinkSet {
    links: Vec<LinkEntry>,
}

impl LinkSet {
    fn push(&mut self, link: OwnedFd, pin: OwnedFd, kind: LinkKind, cookies: Vec<u64>) {
        self.links.push(LinkEntry {
            link,
            pin,
            kind,
            cookies,
        });
    }

    fn clear(&mut self) {
        self.links.clear();
    }

    // H4 removed `truncate` with the rollback-after-attach sites:
    // rejection happens strictly before any link exists, so no
    // installed link is ever rolled back. Design:
    // docs/2026-10-11-h4-descriptor-custody-design.md §3.

    /// Detach every link matching `pred` (fd close = detach;
    /// each link's pin drops with it).
    fn remove_matching(&mut self, mut pred: impl FnMut(LinkKind, &[u64]) -> bool) {
        self.links.retain(|e| !pred(e.kind, &e.cookies));
    }

    fn counts(&self) -> (u64, u64) {
        let mut dispatch = 0u64;
        let mut tripwire = 0u64;
        for e in &self.links {
            match e.kind {
                LinkKind::Init | LinkKind::Query | LinkKind::Stage2 => dispatch += 1,
                LinkKind::Tripwire => tripwire += 1,
            }
        }
        (dispatch, tripwire)
    }
}

/// Path for a multi link: the kernel resolves it per mapping, so
/// the caller's (possibly relative) path is passed through as-is.
fn link_path(path: &Path) -> anyhow::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("attach path contains NUL: {}", path.display()))
}

fn prog_fd(loaded: &Loaded, name: &str) -> anyhow::Result<std::os::fd::RawFd> {
    loaded
        .progs
        .get(name)
        .map(AsRawFd::as_raw_fd)
        .ok_or_else(|| anyhow!("missing program {name}"))
}

#[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
fn attach_pair(
    loaded: &Loaded,
    links: &mut LinkSet,
    entry: &str,
    ret: &str,
    offset: u64,
    pin: &crate::plan::PinnedFile,
    pid: u32,
    cookie: u64,
    kind: LinkKind,
) -> anyhow::Result<()> {
    // H4: attach through the pin's fd-path — the kernel binds the
    // open file description, so no path move can race the attach.
    // One fd per link entry: the pin dups once per push and drops
    // with its link.
    let fd_path = pin.link_path();
    let cpath = link_path(Path::new(&fd_path))?;
    // Both links publish only after the pair succeeds: a failed
    // return-probe attach must not leave its entry link live (the
    // session retries, so a leak would accumulate double-firing
    // entry probes).
    let entry_link = ossl_bpf_sys::link_create_uprobe_multi(
        prog_fd(loaded, entry)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {entry}@{offset:#x}: {e}"))?;
    let ret_link = ossl_bpf_sys::link_create_uretprobe_multi(
        prog_fd(loaded, ret)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {ret}@{offset:#x}: {e}"))?;
    // Dup both pins BEFORE publishing either link (a dup can only
    // fail on fd exhaustion, but a half-published pair would
    // strand a firing entry link — same rule as the attaches).
    let entry_pin = pin.fd.try_clone()?;
    let ret_pin = pin.fd.try_clone()?;
    links.push(entry_link, entry_pin, kind, vec![cookie]);
    links.push(ret_link, ret_pin, kind, vec![cookie]);
    Ok(())
}

/// Attach legacy tripwires: one multi link per (module, program)
/// with the probes' offsets + cookies batched.
fn attach_trips(
    loaded: &Loaded,
    links: &mut LinkSet,
    set: &legacy::ProbeSet,
    pid: u32,
) -> anyhow::Result<()> {
    type OffsetsCookies = (Vec<u64>, Vec<u64>);
    let mut groups: HashMap<(&str, &str), OffsetsCookies> = HashMap::new();
    for p in &set.probes {
        let (offs, cookies) = groups.entry((p.module.as_str(), p.program)).or_default();
        offs.push(p.offset);
        cookies.push(p.cookie);
    }
    let mut keys: Vec<(&str, &str)> = groups.keys().copied().collect();
    keys.sort_unstable();
    for (module, prog_name) in keys {
        let (offsets, cookies) = &groups[&(module, prog_name)];
        // H4: pin the module (open, bounded retries) and attach
        // through the fd-path. Caller modules carry no planned
        // identity (only libcrypto is plan-bound — checked by the
        // caller pre-attach), so the pin alone fixes their
        // attach-time TOCTOU: the link binds exactly the opened
        // inode, deliberately. One group → one link → the pin
        // moves in whole (no dup needed).
        let pin = crate::plan::resolve_pinned_retry(|| crate::plan::resolve_pinned(module))
            .map_err(|e| anyhow!("pin {module} for {prog_name}: {e}"))?;
        let fd_path = pin.link_path();
        let cpath = link_path(Path::new(&fd_path))?;
        let link = ossl_bpf_sys::link_create_uprobe_multi(
            prog_fd(loaded, prog_name)?,
            &cpath,
            offsets,
            cookies,
            pid,
        )
        .map_err(|e| anyhow!("attach {prog_name}@{module}+{}: {e}", offsets.len()))?;
        links.push(link, pin.fd, LinkKind::Tripwire, cookies.clone());
    }
    Ok(())
}

/// Load the frozen harvest shape: `prepare` asserts dims vs the
/// object (fail-closed on drift), `load` creates maps + progs raw
/// with `expected_attach_type=UPROBE_MULTI`. Verifier failures
/// surface before any attach.
fn load_frozen(obj_bytes: &[u8]) -> anyhow::Result<Loaded> {
    let prep = crate::loader::prepare(
        obj_bytes,
        &crate::loader::HARVEST_MAPS,
        &crate::loader::HARVEST_PROGS,
    )?;
    crate::loader::load(&prep)
}

/// Populate the kernel classifier tables right after map creation,
/// before any attach can fire. Observer-owned registry bytes only;
/// no target memory is involved.
fn populate_classifier_maps(maps: &HashMap<String, OwnedFd>) -> anyhow::Result<()> {
    let put = |map: &str, key: &[u8], value: &[u8]| -> anyhow::Result<()> {
        let fd = maps
            .get(map)
            .ok_or_else(|| anyhow!("missing classifier map {map}"))?;
        // SAFETY: lengths are exact per HARVEST_MAPS — ALG_CLASS is
        // key 8 / value 42 (`u64` key, `[u8; 42]` encoder),
        // TRIP_CLASS is key 8 / value 22 (`u64` key, `[u8; 22]`
        // encoder); both plain HASH maps, fd live from `load()`.
        unsafe { ossl_bpf_sys::map_update_elem(fd.as_raw_fd(), key, value, 0) }
            .with_context(|| format!("populate {map}"))?;
        Ok(())
    };
    for (h, v) in harvest::build_alg_entries()? {
        put("ALG_CLASS", &h.to_le_bytes(), &wire::alg_value_bytes(&v))?;
    }
    for (h, v) in harvest::build_trip_entries()? {
        put("TRIP_CLASS", &h.to_le_bytes(), &wire::trip_value_bytes(&v))?;
    }
    Ok(())
}

/// P5-probe hook: `OSSL_JUMPS_HOLE=<idx>` leaves one jump-table
/// slot empty so C4 can measure hole tolerance live (the chain
/// stops at the hole with an honest advance — rate-only, never a
/// coverage skip). Absent/unparseable/out-of-range = no hole.
/// P7 either adopts best-effort holes (keeping the tolerance,
/// dropping this hook) or stays fail-closed (dropping the hook).
fn jump_hole_idx() -> Option<u32> {
    jump_hole_idx_from(std::env::var("OSSL_JUMPS_HOLE").ok().as_deref())
}

fn jump_hole_idx_from(raw: Option<&str>) -> Option<u32> {
    let idx: u32 = raw?.parse().ok()?;
    if idx < 8 { Some(idx) } else { None }
}

/// Populate the chain jump table right after load, before any attach
/// can fire (P5a): `JUMPS[i]` = hop `ci`. Values are raw prog fds
/// (u32, kernel takes its own ref). Fail-closed: any population
/// failure (or a missing hop program) fails the attach — an
/// accidental hole would silently cut the slots/query rate (only
/// the explicit `OSSL_JUMPS_HOLE` probe hook leaves one).
fn populate_jump_table(loaded: &Loaded) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::fd::AsRawFd as _;
    let jumps = loaded
        .maps
        .get("JUMPS")
        .ok_or_else(|| anyhow::anyhow!("missing chain map JUMPS"))?;
    let hole = jump_hole_idx();
    for i in 0..8u32 {
        if hole == Some(i) {
            continue;
        }
        let name = format!("c{i}");
        let callee = prog_fd(loaded, &name)?;
        // SAFETY: JUMPS is key 4 / value 4 (PROG_ARRAY); both slices
        // are `u32` encodings, fd live from `load()`.
        unsafe {
            ossl_bpf_sys::map_update_elem(
                jumps.as_raw_fd(),
                &i.to_le_bytes(),
                &(callee as u32).to_le_bytes(),
                0,
            )
        }
        .with_context(|| format!("populate JUMPS[{i}]={name}"))?;
    }
    Ok(())
}

/// Fault in the provider file's mapped pages (best-effort, one byte
/// per page via process_vm_readv). BPF probe reads are nofault: a
/// query whose alg tables were never touched aborts the walk even
/// though the table is valid. Failures only degrade to abort-retry
/// + loud TRUNC, never to silence.
fn pretouch_mappings(pid: u32, live: &[maps::Mapping], path: &Path, canon: &str) {
    let arg = path.to_string_lossy();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut pages: Vec<u64> = Vec::new();
    for m in live {
        if m.ino == 0
            || !(m.path == arg || m.path == canon || (!canon.is_empty() && m.path.ends_with(canon)))
        {
            continue;
        }
        let mut p = m.start & !(page - 1);
        while p < m.end {
            pages.push(p);
            p += page;
        }
    }
    if pages.is_empty() {
        return;
    }
    // One local byte per remote page; chunk under UIO_MAXIOV (1024).
    let mut sink = vec![0u8; pages.len().min(1000)];
    for chunk in pages.chunks(1000) {
        sink.resize(chunk.len(), 0);
        let local = libc::iovec {
            iov_base: sink.as_mut_ptr() as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        let remote: Vec<libc::iovec> = chunk
            .iter()
            .map(|p| libc::iovec {
                iov_base: *p as *mut libc::c_void,
                iov_len: 1,
            })
            .collect();
        let n = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                &local,
                1,
                remote.as_ptr(),
                remote.len() as libc::c_ulong,
                0,
            )
        };
        if n < 0 && debug_session() {
            eprintln!(
                "HARVESTDBG pretouch pid={pid} pages={} err={}",
                chunk.len(),
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Candidate legacy.so paths for pre-mapping init attach: the
/// target's OPENSSL_MODULES dir plus libcrypto's ossl-modules dir
/// (existing files only; whichever loads fires the cookie-1 init).
fn legacy_candidates(pid: u32, libcrypto: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut consider = |p: PathBuf| {
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
        for kv in env.split(|b| *b == 0) {
            if let Some(v) = kv
                .strip_prefix(b"OPENSSL_MODULES=")
                .and_then(|v| std::str::from_utf8(v).ok())
            {
                for dir in v.split(':') {
                    consider(PathBuf::from(dir).join("legacy.so"));
                }
            }
        }
    }
    if let Some(dir) = Path::new(libcrypto).parent() {
        consider(dir.join("ossl-modules").join("legacy.so"));
    }
    out
}

/// Typed hash-map handle over a dup'd raw fd (aya in its P2
/// role: typed access only — load/attach went raw).
fn open_hash<K, V>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<aya::maps::HashMap<MapData, K, V>>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    let fd = maps
        .get(name)
        .and_then(|f| f.try_clone().ok())
        .ok_or_else(|| anyhow!("missing map {name}"))?;
    let data = MapData::from_fd(fd).map_err(|e| anyhow!("{name} mapdata: {e}"))?;
    let map = Map::from_map_data(data).map_err(|e| anyhow!("{name} map: {e}"))?;
    aya::maps::HashMap::<_, K, V>::try_from(map).map_err(|e| anyhow!("{name} shape: {e}"))
}

/// Typed hash-map read: returns the rows plus whether the snapshot
/// failed (setup or iteration). Every map reads checked, so a
/// failed snapshot becomes explicit snapshot loss, never a silent
/// "no truncation / no loss" read.
fn read_kv_checked<K, V>(maps: &HashMap<String, OwnedFd>, name: &str) -> (Vec<(K, V)>, bool)
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    let Ok(map) = open_hash::<K, V>(maps, name) else {
        return (Vec::new(), true);
    };
    let mut out = Vec::new();
    let mut failed = false;
    for r in map.iter() {
        match r {
            Ok(kv) => out.push(kv),
            Err(_) => failed = true,
        }
    }
    (out, failed)
}

/// Per-CPU counter fold (F-C/A8): wrapping sum across CPUs.
/// Overflow wraps (the core's high-water baselines ignore the
/// dip, same as the old shared counters).
fn fold_percpu_sum(slots: &[u64]) -> u64 {
    slots.iter().fold(0u64, |a, &b| a.wrapping_add(b))
}

/// Per-CPU flag fold (F-C/A8): OR across CPUs — a bit set on any
/// CPU is set.
fn fold_percpu_or(slots: &[u64]) -> u64 {
    slots.iter().fold(0u64, |a, &b| a | b)
}

fn open_percpu_hash<K>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<aya::maps::PerCpuHashMap<MapData, K, u64>>
where
    K: aya::Pod + Eq + std::hash::Hash,
{
    let fd = maps
        .get(name)
        .and_then(|f| f.try_clone().ok())
        .ok_or_else(|| anyhow!("missing map {name}"))?;
    let data = MapData::from_fd(fd).map_err(|e| anyhow!("{name} mapdata: {e}"))?;
    let map = Map::from_map_data(data).map_err(|e| anyhow!("{name} map: {e}"))?;
    aya::maps::PerCpuHashMap::<_, K, u64>::try_from(map).map_err(|e| anyhow!("{name} shape: {e}"))
}

/// Typed per-CPU map read (F-C/A8): folds each key's slots with
/// `fold` (sum for counters, OR for flags) and returns the rows
/// plus whether the snapshot failed. Same checked discipline as
/// [`read_kv_checked`].
fn read_percpu_checked<K>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
    fold: fn(&[u64]) -> u64,
) -> (Vec<(K, u64)>, bool)
where
    K: aya::Pod + Eq + std::hash::Hash,
{
    let Ok(map) = open_percpu_hash::<K>(maps, name) else {
        return (Vec::new(), true);
    };
    let mut out = Vec::new();
    let mut failed = false;
    for r in map.iter() {
        match r {
            Ok((k, slots)) => out.push((k, fold(&slots))),
            Err(_) => failed = true,
        }
    }
    (out, failed)
}

/// Delete one hash-map element; an absent key succeeds (already
/// evicted), anything else reports.
fn delete_elem<K, V>(map: &mut aya::maps::HashMap<MapData, K, V>, key: &K) -> anyhow::Result<()>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    match map.remove(key) {
        Ok(()) => Ok(()),
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// Evict one array's `TERMD` proof: a sticky proof from a retired
/// incarnation must never satisfy the next one.
fn evict_termd(maps: &HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<()> {
    let mut termd = open_hash::<u64, u64>(maps, "TERMD")?;
    delete_elem(&mut termd, &arr).context("evict TERMD")
}

/// Delete one array's `GEN` entry (F-H/H1): the retired
/// incarnation's cookie must not validate any later record. An
/// absent entry succeeds (same tolerance as `TERMD`).
fn evict_gen(maps: &HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<()> {
    let mut table = open_hash::<u64, u64>(maps, "GEN")?;
    delete_elem(&mut table, &arr).context("evict GEN")
}

/// Install one array's incarnation generation (F-H/H1): BPF
/// stamps every record the array produces with this value until
/// the next bump or eviction.
fn install_gen(maps: &HashMap<String, OwnedFd>, arr: u64, gen_value: u64) -> anyhow::Result<()> {
    let mut table = open_hash::<u64, u64>(maps, "GEN")?;
    table
        .insert(arr, gen_value, 0)
        .map_err(|e| anyhow!("install GEN failed (gen {gen_value}): {e}"))
}

/// Evict one array's `QUERY_NEXT` cursors across all threads (low
/// key half is the array base): the next incarnation's walk
/// restarts at slot 0 instead of resuming mid-array.
fn evict_cursors(maps: &HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<()> {
    let mut cursors = open_hash::<u128, u64>(maps, "QUERY_NEXT")?;
    // Collect first: deleting during iteration races concurrent
    // kernel inserts.
    let mut victims = Vec::new();
    for r in cursors.iter() {
        let (k, _) = r.map_err(|e| anyhow!("iterate QUERY_NEXT: {e}"))?;
        if k as u64 == arr {
            victims.push(k);
        }
    }
    for k in victims {
        delete_elem(&mut cursors, &k).context("evict QUERY_NEXT")?;
    }
    Ok(())
}

/// Load-mandated init anchor, present even in stripped modules.
pub(crate) const INIT_ANCHOR: &str = "OSSL_provider_init";

/// The privileged [`SessionEnv`]: real ring, maps, links, pin, and
/// `/proc` reads. Owned by [`DiscoverySession`] until session drop.
pub struct LiveEnv {
    pid: u32,
    provider: PathBuf,
    canon: String,
    loaded: Loaded,
    links: LinkSet,
    ring: RingBuf<MapData>,
    pin: crate::pin::TargetPin,
    /// Retained dispatch anchor recipe (F-D/A11): reinstall
    /// re-resolves with the same flavor/table/flags as attach.
    /// `None` when attach installed no dispatch anchor.
    dispatch_spec: Option<DispatchSpec>,
}

/// Dispatch anchor recipe retained for post-replacement
/// reinstalls: the same resolution the attach used.
#[derive(Clone, Debug)]
pub(crate) enum DispatchSpec {
    Init,
    Builtin {
        table: builtin::Table,
        force_offset: Option<u64>,
        explicit_offsets: bool,
    },
}

impl SessionEnv for LiveEnv {
    fn next_event(&mut self) -> Option<Vec<u8>> {
        self.ring.next().map(|item| item.to_vec())
    }

    fn current_maps(&mut self) -> Option<Vec<maps::Mapping>> {
        maps::read_maps(self.pid).ok()
    }

    fn join_maps(&mut self) -> MapSnapshots {
        // F-C/A8: counter/flag maps are per-CPU in BPF (exact
        // single-writer slots); the loader folds to scalars here
        // so the snapshot shape — and every downstream join —
        // is unchanged.
        let (trunc, trunc_failed) = read_percpu_checked(&self.loaded.maps, "TRUNC", fold_percpu_or);
        let (termd, termd_failed) = read_kv_checked(&self.loaded.maps, "TERMD");
        let (losses, losses_failed) =
            read_percpu_checked(&self.loaded.maps, "LOSS", fold_percpu_sum);
        // Call volume from the CALLS map (`None` only when the map
        // itself is absent — the core falls back to the QUERY_RET
        // event count then). All counter maps read checked: a
        // failed iteration is explicit snapshot loss, never a
        // silent partial sum (the core's high-water baselines
        // additionally ignore the dip).
        let (call_rows, calls_failed): (Vec<(u32, u64)>, bool) =
            read_percpu_checked(&self.loaded.maps, "CALLS", fold_percpu_sum);
        let calls = if call_rows.is_empty() && !self.loaded.maps.contains_key("CALLS") {
            None
        } else {
            Some(call_rows.iter().map(|(_, n)| n).sum())
        };
        let (trip, trip_failed): (Vec<(u64, u64)>, bool) =
            read_percpu_checked(&self.loaded.maps, "TRIP", fold_percpu_sum);
        let (lg_rows, lgcalls_failed): (Vec<(u32, u64)>, bool) =
            read_percpu_checked(&self.loaded.maps, "LGCALLS", fold_percpu_sum);
        let lgcalls: u64 = lg_rows.iter().map(|(_, n)| n).sum();
        MapSnapshots {
            trunc,
            trunc_failed,
            termd,
            termd_failed,
            losses,
            losses_failed,
            calls,
            calls_by_op: call_rows,
            calls_failed,
            trip,
            trip_failed,
            lgcalls,
            lgcalls_failed,
        }
    }

    fn install_stage2(
        &mut self,
        cookie: u64,
        offset: u64,
        path: &Path,
        pid: u32,
        expected: Option<(u64, u64)>,
    ) -> anyhow::Result<()> {
        // H4: pin the path (open, bounded retries over transient
        // absence) and compare the pin's fstat against the
        // resolve-time `expected` BEFORE attaching — no
        // before/after sampling, no rollback: the fd IS the pin,
        // and the pair binds through its fd-path. Mismatch (or
        // `None` expected — unstatable at resolve) fails loud
        // having bound nothing; the cookie retries next poll
        // (T14r4-2b) against fresh maps. NOTE the domain bridge:
        // `expected` is raw (dev_t, ino) per the trait, the pin
        // is encoded — the comparison encodes explicitly.
        let path_str = path.to_string_lossy();
        let pin =
            crate::plan::resolve_pinned_retry(|| crate::plan::resolve_pinned(path_str.as_ref()))
                .map_err(|e| {
                    anyhow!(
                        "stage-2 pin open failed for {} (cookie retries next poll): {e}",
                        path.display()
                    )
                })?;
        let matches = expected.is_some_and(|(raw_dev, ino)| {
            let enc = crate::plan::encode_device(
                libc::major(raw_dev as libc::dev_t),
                libc::minor(raw_dev as libc::dev_t),
            );
            pin.device == enc && pin.ino == ino
        });
        if !matches {
            bail!(
                "stage-2 pin for {} misses the resolve-time identity (cookie retries next poll)",
                path.display()
            );
        }
        attach_pair(
            &self.loaded,
            &mut self.links,
            "query_entry",
            "query_return",
            offset,
            &pin,
            pid,
            cookie,
            LinkKind::Stage2,
        )?;
        eprintln!("INSPECT stage=query off={offset:#x} cookie={cookie}");
        Ok(())
    }

    fn install_trips(
        &mut self,
        set: &legacy::ProbeSet,
        pid: u32,
        maps: &[maps::Mapping],
    ) -> anyhow::Result<Option<String>> {
        // H4 (was F-D/A11 whole-batch check): the plan's offsets
        // describe its bound libcrypto — pin libcrypto FIRST and
        // compare against the plan's identity BEFORE attaching
        // anything. Mismatch (or unopenable libcrypto on a bound
        // plan) fails the batch having bound nothing; unbound
        // plans (hand-built sets only) skip verification, as
        // before. Transient-typed (InvalidData): the core retries
        // next poll without latching blind or failing the poll.
        // No post-batch sampling, no rollback: each trip module
        // binds through its own pin inside `attach_trips`.
        if let Some((lc_path, (enc, ino))) = set.libcrypto.as_ref().and_then(|(path, dev, ino)| {
            crate::plan::device_id_of_dev_str(dev).map(|enc| (path, (enc, *ino)))
        }) {
            let pin = crate::plan::resolve_pinned_retry(|| crate::plan::resolve_pinned(lc_path))
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("tripwire install: bound libcrypto unopenable ({lc_path}): {e}"),
                    )
                })?;
            if pin.device != enc || pin.ino != ino {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "tripwire install: bound libcrypto replaced since plan",
                )
                .into());
            }
        }
        attach_trips(&self.loaded, &mut self.links, set, pid)?;
        eprintln!("INSPECT stage=legacy trips={}", set.probes.len());
        let mut note = None;
        if let Some(lc_path) = legacy::find_libcrypto(maps) {
            for cand in legacy_candidates(pid, &lc_path) {
                // Pin-first per candidate (H4): offsets resolve
                // against the OPEN file and the pair binds through
                // its fd-path. Unopenable candidates skip silently
                // (as before — a pre-loaded legacy stays
                // unattributed, documented edge); attach failures
                // stay loud in-doc (executed_queries would read a
                // false 0) while the run continues for tripwires.
                let pin = match crate::plan::resolve_pinned_retry(|| {
                    crate::plan::resolve_pinned(cand.to_string_lossy().as_ref())
                }) {
                    Ok(pin) => pin,
                    Err(_) => continue,
                };
                let off = std::fs::read(pin.link_path())
                    .ok()
                    .and_then(|b| elf::dynsym_file_offset(&b, INIT_ANCHOR).ok());
                if let Some(off) = off
                    && let Err(e) = attach_pair(
                        &self.loaded,
                        &mut self.links,
                        "init_entry",
                        "init_return",
                        off,
                        &pin,
                        pid,
                        harvest::LEGACY_COOKIE,
                        LinkKind::Init,
                    )
                {
                    note = Some(format!("legacy tripwire attach failed: {e:#}"));
                    eprintln!("INSPECT legacy attach failed: {e:#}");
                }
            }
        }
        Ok(note)
    }

    fn plan_trips(&mut self, maps: &[maps::Mapping]) -> anyhow::Result<Option<legacy::ProbeSet>> {
        let Some(entry) = libcrypto_entry(maps) else {
            return Ok(None);
        };
        let lc_path = entry.path.clone();
        // H5 (was F-D/A11 mixed-domain): the plan binds the
        // mapped file in the STAT domain — the bytes must be the
        // mapped file's, else a swap between the maps read and
        // this read resolves offsets for the wrong bytes.
        // Checks, all stat-domain except the domain-agnostic ino:
        // (1) the bound read is still current (fresh fstat equals
        // the read's identity — swap-during-plan fails);
        // (2) the bound ino is the mapped ino (swap-since-maps
        // fails). The maps dev-string is NEVER compared (btrfs /
        // overlay diverge it from stat — spike F1/F7).
        // Identity mismatch → InvalidData (the core retries
        // next poll as a transient, without latching blind);
        // unmapped-race (gone between find and read) → Ok(None);
        // other IO errors propagate (pre-existing posture).
        let bound = match crate::plan::read_file_bound(&lc_path) {
            Ok(fb) => fb,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let fresh = std::fs::metadata(&lc_path).ok().map(|m| {
            use std::os::unix::fs::MetadataExt as _;
            (crate::plan::render_stat_dev(m.dev()), m.ino())
        });
        let bound_ident = (crate::plan::render_device(bound.dev), bound.ino);
        if fresh.as_ref() != Some(&bound_ident) || bound.ino != entry.ino {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("libcrypto {lc_path} changed during plan"),
            )
            .into());
        }
        let lc_bytes = bound.bytes;
        // Caller modules for low-level PLT planning. Unreadable
        // files (deleted-but-mapped, permissions) are loud
        // findings: their imports stay unknown.
        let mut mod_bytes: Vec<(String, Vec<u8>)> = Vec::new();
        let mut unreadable: Vec<String> = Vec::new();
        for path in legacy::target_modules(maps, &lc_path) {
            match std::fs::read(&path) {
                Ok(bytes) => mod_bytes.push((path, bytes)),
                Err(_) => unreadable.push(path),
            }
        }
        let modules: Vec<legacy::Module> = mod_bytes
            .iter()
            .map(|(p, b)| legacy::Module { path: p, bytes: b })
            .collect();
        // H5: the plan identity is the BOUND read's stat
        // identity (not the maps entry's dev-string) — install
        // compares pin-vs-plan stat-vs-stat.
        let mut set = legacy::probes_for(
            &lc_path,
            &lc_bytes,
            &modules,
            (crate::plan::render_device(bound.dev), bound.ino),
        )?;
        for path in &unreadable {
            set.findings
                .push(format!("unreadable module: {path} (imports unknown)"));
        }
        Ok(Some(set))
    }

    fn pretouch(&mut self, cookie: u64, addr: u64) {
        // Re-pretouch on repeat inits (unload/reload cycles): the
        // new mapping's pages are cold and nofault BPF reads fail
        // on them. Best-effort, never fatal.
        if let Ok(live) = maps::read_maps(self.pid) {
            let path = if cookie == harvest::LEGACY_COOKIE {
                live.iter()
                    .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
                    .map(|m| PathBuf::from(&m.path))
            } else {
                Some(self.provider.clone())
            };
            if let Some(p) = path {
                pretouch_mappings(self.pid, &live, &p, &self.canon);
            }
        }
    }

    fn evict_array_state(&mut self, arr: u64) -> anyhow::Result<()> {
        evict_termd(&self.loaded.maps, arr)?;
        evict_cursors(&self.loaded.maps, arr)?;
        evict_gen(&self.loaded.maps, arr)?;
        Ok(())
    }

    fn install_generation(&mut self, arr: u64, generation: u64) -> anyhow::Result<()> {
        install_gen(&self.loaded.maps, arr, generation)
    }

    fn verify_pin(&self) -> anyhow::Result<()> {
        self.pin.verify().map_err(|e| anyhow!("{e}"))
    }

    fn quiesce(&mut self) {
        self.links.clear();
    }

    fn link_counts(&self) -> (u64, u64) {
        self.links.counts()
    }

    fn provider_stat(&self) -> Option<(String, u64)> {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(&self.provider).ok()?;
        Some((crate::plan::render_device(md.dev()), md.ino()))
    }

    fn detach_trips(&mut self) {
        // The whole tripwire plane, including the legacy-init
        // pairs installed with the batch (Init links carrying the
        // legacy cookie).
        self.links.remove_matching(|kind, cookies| {
            kind == LinkKind::Tripwire
                || (kind == LinkKind::Init && cookies.contains(&harvest::LEGACY_COOKIE))
        });
    }

    fn detach_dispatch_anchors(&mut self) {
        // Init/query anchors only: stage-2 pairs (their own kind)
        // and legacy-init pairs (tripwire batch) survive.
        self.links.remove_matching(|kind, cookies| {
            (kind == LinkKind::Init && !cookies.contains(&harvest::LEGACY_COOKIE))
                || kind == LinkKind::Query
        });
    }

    fn detach_stage2(&mut self, cookie: u64) {
        self.links
            .remove_matching(|kind, cookies| kind == LinkKind::Stage2 && cookies.contains(&cookie));
    }

    fn reinstall_dispatch(&mut self) -> anyhow::Result<DispatchReinstall> {
        // H4 (was F-D/A11 + A1-grade check with rollback): pin the
        // CURRENT provider file FIRST (open, bounded retries),
        // then read the resolve bytes THROUGH the pin's fd-path
        // (same inode, guaranteed — the A3 helper's open/read
        // still applies, now trivially tear-proof) and compare
        // against the maps entry. Mismatch is a transient race
        // (InvalidData, retry next poll); the attach binds through
        // the fd-path with no post-attach sampling — the fd IS
        // the pin.
        let spec = self
            .dispatch_spec
            .clone()
            .context("no dispatch anchor to reinstall")?;
        let live = maps::read_maps(self.pid)?;
        let prov_path = self.provider.to_string_lossy().into_owned();
        let entry = live
            .iter()
            .find(|m| m.path == prov_path || m.path == self.canon);
        // H10: unmapped-but-present installs kernel-pending on the
        // current file (no maps entry to compare — the pin IS the
        // binding; the spike proved the kernel accepts this and
        // arms on first map). Only a missing file stays a retry.
        let pin = crate::plan::resolve_pinned_retry(|| crate::plan::resolve_pinned(&prov_path))
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("provider {prov_path} unopenable during reinstall: {e}"),
                )
            })?;
        let bound = crate::plan::read_file_bound(&pin.link_path())?;
        // H5 (was F-D/A11 mixed-domain): the bound read binds the
        // CURRENT file at the provider path; the maps entry backs
        // the file the TARGET still maps. Ino (domain-agnostic)
        // detects a swap; the maps dev-string is NEVER compared
        // (btrfs/overlay diverge it from stat — a same-ino
        // x-device swap at one path is the accepted residual,
        // same as schema.rs). Mismatch is a transient race
        // (InvalidData, retry next poll). No maps entry (H10
        // pending) skips the compare — there is nothing mapped
        // to contradict the pin.
        if entry.as_ref().is_some_and(|e| bound.ino != e.ino) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("provider {prov_path} changed during reinstall"),
            )
            .into());
        }
        let (off, prog_entry, prog_ret, resolution) = match &spec {
            DispatchSpec::Init => {
                let (off, res) = elf::dynsym_file_offset(&bound.bytes, INIT_ANCHOR)
                    .map(|off| (off, None))
                    .or_else(|_| {
                        elf::symtab_file_offset(&bound.bytes, INIT_ANCHOR)
                            .map(|off| (off, Some("symtab".to_string())))
                    })
                    .map_err(|e| anyhow!("reinstall anchor unresolved: {e:#}"))?;
                (off, "init_entry", "init_return", res)
            }
            DispatchSpec::Builtin {
                table,
                force_offset,
                explicit_offsets,
            } => {
                let (off, r) = if *explicit_offsets {
                    builtin::resolve_query_offset(&bound.bytes, table, *force_offset)
                } else {
                    builtin::resolve_supported_offset(&bound.bytes, table)
                }
                .map_err(|e| anyhow!("reinstall anchor unresolved: {e:#}"))?;
                let res = (r != builtin::Resolution::Table).then(|| r.as_str().to_string());
                (off, "query_entry", "query_return", res)
            }
        };
        attach_pair(
            &self.loaded,
            &mut self.links,
            prog_entry,
            prog_ret,
            off,
            &pin,
            self.pid,
            0,
            if matches!(spec, DispatchSpec::Init) {
                LinkKind::Init
            } else {
                LinkKind::Query
            },
        )?;
        eprintln!("INSPECT stage=reinstall off={off:#x}");
        Ok(DispatchReinstall {
            // H5: the binding is the PIN-VERIFIED read's stat
            // identity (reconcile compares stat-vs-stat) — never
            // the maps entry's dev-string.
            binding: (prov_path, crate::plan::render_device(bound.dev), bound.ino),
            resolution,
        })
    }
}

// ---------------------------------------------------------------------------
// DiscoverySession: the live persistent engine.
// ---------------------------------------------------------------------------

/// Persistent discovery engine: owns loaded programs/maps, attach
/// links, the ring consumer, the target pin, and all discovery
/// state until the session drops. Poll in bounded batches;
/// [`DiscoverySession::close`] (quiesce-then-PROCESS) before drop
/// for exact tail accounting.
pub struct DiscoverySession {
    core: SessionCore,
    env: LiveEnv,
}

impl DiscoverySession {
    /// Attach a discovery session to `pid`: pin, load, populate
    /// classifiers, install dispatch anchors and (when configured)
    /// legacy tripwires. Dispatch-blind runs (unresolvable anchor)
    /// still attach when tripwires can observe — the preset reason
    /// travels in the snapshot.
    pub fn attach(cfg: &DiscoveryConfig, pid: u32) -> anyhow::Result<Self> {
        let nz = NonZeroU32::new(pid).ok_or_else(|| anyhow!("pid must be non-zero"))?;
        // Pin FIRST: every later /proc/<pid> read and every
        // pid-scoped attach is verified against this identity.
        let pin = crate::pin::pin(pid)?;
        if let Some(marker) = &cfg.cmdline_marker {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))?;
            let m = marker.as_bytes();
            if !cmdline.windows(m.len()).any(|w| w == m) {
                bail!("pid {pid} cmdline lacks marker {marker}");
            }
        }
        // H4: pin the provider file FIRST (open, bounded
        // retries) — offsets resolve against the pinned bytes and
        // every bootstrap pair binds through its fd-path. Named
        // `prov_pin`: `pin` is the target (pid) pin above.
        let prov_path_str = cfg.provider.to_string_lossy().into_owned();
        let prov_pin =
            crate::plan::resolve_pinned_retry(|| crate::plan::resolve_pinned(&prov_path_str))?;
        let elf_bytes = std::fs::read(prov_pin.link_path())?;
        let canon = std::fs::canonicalize(&cfg.provider)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Triple runs load the retained harvest snapshot (no
        // re-read — identity and loading share these bytes);
        // otherwise a bounded path read (never unbounded).
        let obj_bytes = match &cfg.object_bytes {
            Some(snapshot) => snapshot.clone(),
            None => crate::discovery::onboard::read_bounded(
                &cfg.object,
                crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES,
            )
            .map_err(|e| anyhow::anyhow!("harvest object {}: {e}", cfg.object.display()))?,
        };
        if pin.verify().is_err() {
            let mut core = SessionCore::new(cfg.provider.clone(), canon, cfg.legacy, pid);
            core.mark_recycled();
            return Err(core.recycled_err());
        }

        let loaded = load_frozen(&obj_bytes)?;
        // Classifier tables before any attach can fire: the kernel
        // classifies every string-bearing event against these.
        populate_classifier_maps(&loaded.maps)?;
        // Chain jump table likewise: every query tail-calls into it.
        populate_jump_table(&loaded)?;
        // Owns every multi link (drop = detach, all paths).
        let mut links = LinkSet::default();
        let mut builtin_query_attached = false;
        let mut builtin_query_offset = 0u64;
        let mut resolution: Option<String> = None;
        // F-D/A11 anchor bindings: the identities the installed
        // links pin, plus the recipe to reinstall them.
        let mut dispatch_spec: Option<DispatchSpec> = None;
        let mut dispatch_binding: Option<(String, String, u64)> = None;
        // Dispatch-blind runs preset their PARTIAL reason but still
        // drain for legacy tripwires (dispatch and legacy observe
        // independently).
        let mut preset_reason: Option<String> = None;
        if cfg.builtin {
            let table = match &cfg.table {
                Some(path) => {
                    let text = std::fs::read_to_string(path)?;
                    builtin::load_table_str(&text)?
                }
                None => builtin::shipped_table(),
            };
            // Automatic discovery uses the supported-only ladder
            // (table hit or symtab); the anchor+delta rung needs an
            // explicitly selected table (R09: never guessed offsets).
            let resolved = if cfg.explicit_offsets {
                builtin::resolve_query_offset(&elf_bytes, &table, cfg.force_offset)
            } else {
                builtin::resolve_supported_offset(&elf_bytes, &table)
            };
            match resolved {
                Ok((off, r)) => {
                    if r != builtin::Resolution::Table {
                        resolution = Some(r.as_str().to_string());
                    }
                    attach_pair(
                        &loaded,
                        &mut links,
                        "query_entry",
                        "query_return",
                        off,
                        &prov_pin,
                        nz.get(),
                        0,
                        LinkKind::Query,
                    )?;
                    eprintln!("INSPECT stage=builtin off={off:#x} via={}", r.as_str());
                    builtin_query_attached = true;
                    builtin_query_offset = off;
                    dispatch_spec = Some(DispatchSpec::Builtin {
                        table,
                        force_offset: cfg.force_offset,
                        explicit_offsets: cfg.explicit_offsets,
                    });
                }
                Err(e) => {
                    eprintln!("INSPECT builtin unresolved: {e:#}");
                    preset_reason = Some("anchor-unresolved".to_string());
                }
            }
        } else {
            // Init ladder: load-mandated dynsym first, debug symtab second.
            let init_off = elf::dynsym_file_offset(&elf_bytes, INIT_ANCHOR)
                .map(|off| (off, None))
                .or_else(|_| {
                    elf::symtab_file_offset(&elf_bytes, INIT_ANCHOR)
                        .map(|off| (off, Some("symtab".to_string())))
                });
            match init_off {
                Ok((off, res)) => {
                    resolution = res;
                    attach_pair(
                        &loaded,
                        &mut links,
                        "init_entry",
                        "init_return",
                        off,
                        &prov_pin,
                        nz.get(),
                        0,
                        LinkKind::Init,
                    )?;
                    dispatch_spec = Some(DispatchSpec::Init);
                    // H4: the binding is EXACT now — the pin's own
                    // identity (the link bound through its fd-path),
                    // not a best-effort post-attach stat.
                    dispatch_binding = Some((
                        cfg.provider.to_string_lossy().into_owned(),
                        crate::plan::render_device(prov_pin.device),
                        prov_pin.ino,
                    ));
                }
                Err(e) => {
                    eprintln!("INSPECT anchor unresolved: {e:#}");
                    preset_reason = Some("anchor-unresolved".to_string());
                }
            }
            // Machine-readable progress on stderr (stdout stays pure
            // JSON): harnesses gate fixture GO lines on these.
            eprintln!("INSPECT stage=init attached=2");
        }

        let ev_fd = loaded
            .maps
            .get("EVENTS")
            .context("no EVENTS map")?
            .try_clone()?;
        let ev_data = MapData::from_fd(ev_fd).map_err(|e| anyhow!("EVENTS mapdata: {e}"))?;
        let ev_map = Map::from_map_data(ev_data).map_err(|e| anyhow!("EVENTS map: {e}"))?;
        let ring = RingBuf::try_from(ev_map)?;

        let mut core = SessionCore::new(cfg.provider.clone(), canon.clone(), cfg.legacy, pid);
        if builtin_query_attached {
            // H4: backing identity for the reuse comparison —
            // EXACT from the bootstrap pin (the builtin pair bound
            // through its fd-path), replacing the best-effort
            // post-attach stat (whose unstatable-fallback is now
            // unreachable — the pin opened or bootstrap failed).
            let pdev = crate::plan::render_device(prov_pin.device);
            let pino = prov_pin.ino;
            dispatch_binding = Some((
                cfg.provider.to_string_lossy().into_owned(),
                pdev.clone(),
                pino,
            ));
            core.mark_query_attached(
                0,
                builtin_query_offset,
                cfg.provider.to_string_lossy().into_owned(),
                pdev,
                pino,
            );
        }
        let mut env = LiveEnv {
            pid,
            provider: cfg.provider.clone(),
            canon,
            loaded,
            links,
            ring,
            pin,
            dispatch_spec,
        };

        // Legacy tripwires (dispatch-independent: attach even when
        // the dispatch anchor failed — a blind dispatch can still
        // observe legacy calls; only a missing libcrypto mapping is
        // truly blind). Planned now when libcrypto is already mapped
        // and deferred to the first post-exec poll otherwise.
        if cfg.legacy {
            match env.current_maps() {
                Some(maps0) if legacy::find_libcrypto(&maps0).is_some() => {
                    if let Some(set) = env.plan_trips(&maps0)? {
                        let note = env.install_trips(&set, pid, &maps0)?;
                        core.adopt_legacy_plan(set, note);
                    }
                }
                Some(_) => {
                    eprintln!("INSPECT stage=legacy blind=no-libcrypto-mapping");
                }
                // F-D/Am1: a failed bootstrap read defers like a
                // pre-exec image (the first successful poll plans),
                // with explicit loss — never misdiagnosed as a
                // missing libcrypto mapping.
                None => {
                    core.tracker.note_maps_read();
                    eprintln!("INSPECT stage=legacy blind=maps-read-failed");
                }
            }
        }
        core.set_bootstrap(
            preset_reason.is_none(),
            preset_reason,
            resolution,
            dispatch_binding,
        );

        // Post-attach verify: every maps read and attach above
        // resolved through /proc/<pid> — confirm the identity.
        if env.verify_pin().is_err() {
            core.mark_recycled();
            return Err(core.recycled_err());
        }
        Ok(Self { core, env })
    }

    /// One bounded poll; see [`SessionCore::poll`].
    pub fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        self.core.poll(&mut self.env, budget)
    }

    /// Cumulative discovery state; see [`SessionCore::snapshot`].
    pub fn snapshot(&self) -> DiscoverySnapshot {
        self.core.snapshot()
    }

    /// Builtin query anchor (attach path, file offset) for the
    /// traversal backend: pinned at bootstrap when the builtin
    /// query pair attaches. `None` in init mode and when
    /// dispatch-blind (no builtin anchor — traversal refuses, it
    /// never guesses an offset).
    pub fn query_anchor(&self) -> Option<(PathBuf, u64)> {
        self.core.builtin_anchor()
    }

    /// Quiesce-then-PROCESS teardown; see [`SessionCore::close`].
    /// Prefer this over `drop()` for exact tail accounting.
    pub fn close(mut self) -> anyhow::Result<DiscoverySnapshot> {
        self.core.close(&mut self.env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_hole_parses_in_range_only() {
        // P5 C4 probe hook: absent/unparseable/out-of-range = no hole.
        assert_eq!(jump_hole_idx_from(None), None);
        assert_eq!(jump_hole_idx_from(Some("")), None);
        assert_eq!(jump_hole_idx_from(Some("x")), None);
        assert_eq!(jump_hole_idx_from(Some("8")), None);
        assert_eq!(jump_hole_idx_from(Some("4294967295")), None);
        assert_eq!(jump_hole_idx_from(Some("0")), Some(0));
        assert_eq!(jump_hole_idx_from(Some("1")), Some(1));
        assert_eq!(jump_hole_idx_from(Some("7")), Some(7));
    }

    #[test]
    fn percpu_folds_sum_and_or() {
        // F-C/A8: counters wrap-sum across CPUs (overflow wraps —
        // session high-water baselines ignore the dip); flags
        // OR (a bit set on any CPU is set).
        assert_eq!(fold_percpu_sum(&[]), 0);
        assert_eq!(fold_percpu_sum(&[7]), 7);
        assert_eq!(fold_percpu_sum(&[3, 5, 0, 9]), 17);
        assert_eq!(fold_percpu_sum(&[u64::MAX, 2]), 1);
        assert_eq!(fold_percpu_or(&[]), 0);
        assert_eq!(fold_percpu_or(&[0, 0]), 0);
        assert_eq!(fold_percpu_or(&[0b0101, 0b1010, 0]), 0b1111);
    }

    fn sample_maps() -> Vec<maps::Mapping> {
        vec![
            maps::Mapping {
                start: 0x1000,
                end: 0x2000,
                x: true,
                offset: 0x500,
                dev: "08:01".to_string(),
                ino: 7,
                path: "/prov.so".to_string(),
            },
            maps::Mapping {
                start: 0x3000,
                end: 0x4000,
                x: true,
                offset: 0,
                dev: "08:01".to_string(),
                ino: 9,
                path: "/lib/libcrypto.so".to_string(),
            },
            maps::Mapping {
                start: 0x5000,
                end: 0x6000,
                x: true,
                offset: 0,
                dev: "00:00".to_string(),
                ino: 0,
                path: String::new(),
            },
        ]
    }

    #[test]
    fn attribution_splits_advertising_and_backing() {
        let m = sample_maps();
        // Array owner is the file mapping covering the array.
        assert_eq!(
            array_owner(&m, 0x1400),
            ("/prov.so".to_string(), "08:01".to_string(), 7)
        );
        assert_eq!(
            array_owner(&m, 0x3500),
            ("/lib/libcrypto.so".to_string(), "08:01".to_string(), 9)
        );
        // Anonymous/unmapped arrays carry no attributable owner.
        assert_eq!(array_owner(&m, 0x5500), (String::new(), String::new(), 0));
        assert_eq!(array_owner(&m, 0x9000), (String::new(), String::new(), 0));
        // Backing prefers the provider mapping, then any file
        // mapping, else unbacked (render fences it). The canon is
        // a realistic non-empty path (live canonicalize only
        // yields "" when it fails outright).
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x1400);
        assert_eq!(
            b,
            Some(BackingRef {
                dev: "08:01".to_string(),
                ino: 7,
                offset: 0x900,
            })
        );
        assert_eq!(loc, "/prov.so");
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x3500);
        assert_eq!(b.as_ref().unwrap().ino, 9);
        assert_eq!(loc, "/lib/libcrypto.so");
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x5500);
        assert_eq!((b, loc.as_str()), (None, ""));
    }

    #[test]
    fn incarnation_ignores_anonymous_ranges() {
        let m = sample_maps();
        assert_eq!(
            incarnation_of(&m, 0x1400),
            Some(("08:01".to_string(), 7, 0x1000, 0x2000, 0x500))
        );
        // Anonymous and unmapped addresses carry no identity to
        // bind (same-address content swaps there are the documented
        // residual — exact coverage is the backstop).
        assert_eq!(incarnation_of(&m, 0x5500), None);
        assert_eq!(incarnation_of(&m, 0x9000), None);
    }

    #[test]
    fn reason_union_ranks_and_retains_unknowns() {
        let ranked = union_reasons(
            &["prefix-walk".to_string()],
            &["discovery-loss".to_string(), "prefix-walk".to_string()],
        );
        assert_eq!(ranked, vec!["discovery-loss", "prefix-walk"]);
        // Unrecognized reasons append sorted rather than vanishing.
        let ranked = union_reasons(&["zzz-next".to_string()], &["aaa-next".to_string()]);
        assert_eq!(ranked, vec!["aaa-next", "zzz-next"]);
        let ranked = union_reasons(&["prefix-walk".to_string(), "zzz-next".to_string()], &[]);
        assert_eq!(ranked, vec!["prefix-walk", "zzz-next"]);
    }

    #[test]
    fn debug_alg_line_prints_classified_fields_only() {
        let line = debug_alg_line(1, 0, "other", false, wire::ALG_UNKNOWN);
        assert_eq!(
            line,
            "HARVESTDBG alg op=1 idx=0 class=other weak=0 status=1"
        );
        assert!(!line.contains("0x"), "address leaked: {line}");
        assert!(!line.contains("len="), "length leaked: {line}");
    }

    // ------------------------------------------------------------------
    // F-D/A11: anchor reconciliation after replacement.
    // ------------------------------------------------------------------

    use std::collections::VecDeque;

    struct MiniEnv {
        maps: Vec<maps::Mapping>,
        plan: Option<legacy::ProbeSet>,
        plan_calls: u32,
        trip_installs: u32,
        trip_detaches: u32,
        dispatch_detaches: u32,
        stage2_installs: Vec<(u64, u64, String)>,
        stage2_detaches: Vec<u64>,
        stage2_fail_first: u32,
        /// Scripted maps-read failures (F-D/Am1): `current_maps`
        /// fails this many times before succeeding (mirrors
        /// `stage2_fail_first`).
        maps_fail_first: u32,
        /// Maps threaded into the last `install_trips` call
        /// (F-D/Am1 T3'): proves the caller passes its explicit
        /// maps instead of the installer re-reading.
        last_install_maps: Vec<maps::Mapping>,
        reinstall_script: VecDeque<anyhow::Result<DispatchReinstall>>,
        reinstall_calls: u32,
        pin_ok: bool,
        provider_stat: Option<(String, u64)>,
        /// Scripted ring events, popped in order by `next_event`
        /// (P6: close-time tail-join tests).
        events: VecDeque<Vec<u8>>,
    }

    impl MiniEnv {
        fn new() -> Self {
            Self {
                maps: Vec::new(),
                plan: None,
                plan_calls: 0,
                trip_installs: 0,
                trip_detaches: 0,
                dispatch_detaches: 0,
                stage2_installs: Vec::new(),
                stage2_detaches: Vec::new(),
                stage2_fail_first: 0,
                maps_fail_first: 0,
                last_install_maps: Vec::new(),
                reinstall_script: VecDeque::new(),
                reinstall_calls: 0,
                pin_ok: true,
                provider_stat: None,
                events: VecDeque::new(),
            }
        }
    }

    impl SessionEnv for MiniEnv {
        fn next_event(&mut self) -> Option<Vec<u8>> {
            self.events.pop_front()
        }

        fn current_maps(&mut self) -> Option<Vec<maps::Mapping>> {
            if self.maps_fail_first > 0 {
                self.maps_fail_first -= 1;
                return None;
            }
            Some(self.maps.clone())
        }

        fn join_maps(&mut self) -> MapSnapshots {
            MapSnapshots::default()
        }

        fn install_stage2(
            &mut self,
            cookie: u64,
            offset: u64,
            path: &Path,
            _pid: u32,
            _expected: Option<(u64, u64)>,
        ) -> anyhow::Result<()> {
            if self.stage2_fail_first > 0 {
                self.stage2_fail_first -= 1;
                return Err(anyhow::anyhow!("scripted install failure"));
            }
            self.stage2_installs
                .push((cookie, offset, path.to_string_lossy().into_owned()));
            Ok(())
        }

        fn install_trips(
            &mut self,
            _set: &legacy::ProbeSet,
            _pid: u32,
            maps: &[maps::Mapping],
        ) -> anyhow::Result<Option<String>> {
            self.trip_installs += 1;
            self.last_install_maps = maps.to_vec();
            Ok(None)
        }

        fn plan_trips(
            &mut self,
            _maps: &[maps::Mapping],
        ) -> anyhow::Result<Option<legacy::ProbeSet>> {
            self.plan_calls += 1;
            Ok(self.plan.clone())
        }

        fn pretouch(&mut self, _cookie: u64, _addr: u64) {}

        fn evict_array_state(&mut self, _arr: u64) -> anyhow::Result<()> {
            Ok(())
        }

        fn install_generation(&mut self, _arr: u64, _gen: u64) -> anyhow::Result<()> {
            Ok(())
        }

        fn verify_pin(&self) -> anyhow::Result<()> {
            if self.pin_ok {
                Ok(())
            } else {
                anyhow::bail!("pid recycled")
            }
        }

        fn quiesce(&mut self) {}

        fn link_counts(&self) -> (u64, u64) {
            (0, 0)
        }

        fn detach_trips(&mut self) {
            self.trip_detaches += 1;
        }

        fn detach_dispatch_anchors(&mut self) {
            self.dispatch_detaches += 1;
        }

        fn detach_stage2(&mut self, cookie: u64) {
            self.stage2_detaches.push(cookie);
        }

        fn reinstall_dispatch(&mut self) -> anyhow::Result<DispatchReinstall> {
            self.reinstall_calls += 1;
            self.reinstall_script
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("no reinstall scripted")))
        }

        fn provider_stat(&self) -> Option<(String, u64)> {
            self.provider_stat.clone()
        }
    }

    fn lc_mapping(ino: u64) -> maps::Mapping {
        maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0,
            dev: "08:01".to_string(),
            ino,
            path: "/lib/libcrypto.so.3".to_string(),
        }
    }

    fn prov_mapping(ino: u64, start: u64) -> maps::Mapping {
        maps::Mapping {
            start,
            end: start + 0x1000,
            x: true,
            offset: 0,
            dev: "08:01".to_string(),
            ino,
            path: "/p/provider.so".to_string(),
        }
    }

    fn trip_probe(cookie: u64, symbol: &str, offset: u64) -> legacy::Probe {
        legacy::Probe {
            cookie,
            symbol: symbol.to_string(),
            offset,
            module: "/app/target".to_string(),
            family: None,
            str_arg: None,
            program: "trip_count",
        }
    }

    fn trip_set(ino: u64, offsets: &[u64]) -> legacy::ProbeSet {
        let probes = ["ENGINE_by_id", "RSA_new"]
            .iter()
            .zip(offsets.iter().chain(std::iter::repeat(&0x100)))
            .enumerate()
            .map(|(i, (sym, off))| trip_probe(7 + i as u64, sym, *off))
            .collect();
        legacy::ProbeSet {
            probes,
            engine_uninstrumented: 0,
            meth_uninstrumented: 0,
            lowlevel_uninstrumented: 0,
            address_taken: Vec::new(),
            unprobed_engine_syms: Vec::new(),
            unprobed_meth_syms: Vec::new(),
            unprobed_lowlevel_syms: Vec::new(),
            findings: Vec::new(),
            by_id_cookies: HashSet::from([7]),
            load_cookies: HashSet::new(),
            libcrypto: Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), ino)),
        }
    }

    fn a11_core() -> SessionCore {
        SessionCore::new(
            PathBuf::from("/p/provider.so"),
            "/canon/provider.so".to_string(),
            true,
            4242,
        )
    }

    fn a11_budget() -> PollBudget {
        PollBudget::new(65536, 64)
    }

    #[test]
    fn trip_replacement_same_mapping_replans() {
        // F-D/A11: libcrypto replaced (same path, new inode), fresh
        // plan with the identical (cookie, symbol) mapping — detach
        // the stale links and re-attach (offsets-only change is
        // cookie-continuous, so accumulation stays sound).
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        let s1 = trip_set(100, &[0x100, 0x200]);
        env.plan = Some(s1.clone());
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_installs, 1);
        assert!(core.snapshot().legacy.planned);
        assert_eq!(core.snapshot().legacy.set.as_ref(), Some(&s1));

        env.maps = vec![lc_mapping(200)];
        let s2 = trip_set(200, &[0x110, 0x220]);
        env.plan = Some(s2.clone());
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_detaches, 1, "stale links must detach");
        assert_eq!(env.trip_installs, 2, "same-mapping plan must re-attach");
        assert!(core.snapshot().legacy.planned);
        assert_eq!(
            core.snapshot().legacy.set.as_ref(),
            Some(&s2),
            "fresh offsets adopted"
        );
        assert!(
            delta
                .attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Tripwires { .. }) && a.failed.is_some()),
            "replan must carry a continuity-loss signal: {:?}",
            delta.attaches
        );
    }

    #[test]
    fn trip_replacement_changed_mapping_goes_blind() {
        // F-D/A11: replacement with a changed probe mapping (cookie
        // meanings shifted) — detach, but do NOT re-attach (new
        // cookies would collide with old meanings): honestly blind
        // with the last-good set retained for rendering history.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        let s1 = trip_set(100, &[0x100, 0x200]);
        env.plan = Some(s1.clone());
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();

        env.maps = vec![lc_mapping(200)];
        let mut s2 = trip_set(200, &[0x110, 0x220]);
        s2.probes.push(trip_probe(9, "EVP_new", 0x330));
        env.plan = Some(s2);
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_detaches, 1);
        assert_eq!(env.trip_installs, 1, "changed mapping must not re-attach");
        assert!(!core.snapshot().legacy.planned);
        assert_eq!(
            core.snapshot().legacy.set.as_ref(),
            Some(&s1),
            "last-good set retained for rendering"
        );
        assert!(
            delta
                .attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Tripwires { .. }) && a.failed.is_some()),
            "blind latch must signal loss: {:?}",
            delta.attaches
        );
    }

    #[test]
    fn trip_blind_retries_on_new_fingerprint() {
        // F-D/A11: a blind latch does not retry while the libcrypto
        // fingerprint is unchanged (bounded file reads), and resumes
        // planning when it changes.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100, 0x200]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();

        env.maps = vec![lc_mapping(200)];
        let mut changed = trip_set(200, &[0x110]);
        changed.probes.push(trip_probe(9, "EVP_new", 0x330));
        env.plan = Some(changed);
        core.poll(&mut env, a11_budget()).unwrap();
        assert!(!core.snapshot().legacy.planned);
        let plan_calls = env.plan_calls;

        // Same fingerprint: no replan attempt.
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.plan_calls, plan_calls, "latched blind must not retry");
        assert!(!core.snapshot().legacy.planned);

        // New fingerprint with a same-mapping plan: re-attach.
        env.maps = vec![lc_mapping(300)];
        env.plan = Some(trip_set(300, &[0x140, 0x240]));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.plan_calls, plan_calls + 1);
        assert_eq!(env.trip_installs, 2);
        assert!(core.snapshot().legacy.planned);
    }

    #[test]
    fn h5_t1_backing_identity_is_stat_domain() {
        // H5 (spike vectors, both directions in one test):
        // (a) btrfs-shape divergence (maps dev-string says
        // "00:22", the file's stat says otherwise, same ino):
        // the backing CARRIES stat, so downstream stat-stat
        // binds HOLD (no D1 failure);
        // (b) planted x-fs same-ino twins (forged identical
        // maps-dev + ino, different files on different
        // filesystems): backings DIFFER by stat-dev, so
        // downstream binds REFUSE cross-lending (no B-4 lend).
        // RED pre-H5 (backing echoes the maps dev-string).
        use std::os::unix::fs::MetadataExt as _;
        struct Rm(Vec<std::path::PathBuf>);
        impl Drop for Rm {
            fn drop(&mut self) {
                for p in &self.0 {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        let dir = std::env::temp_dir().join(format!("osslscope-h5t1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("twin1.so");
        // Second twin MUST live on another filesystem
        // (separation needs differing stat-devs).
        let f2 =
            std::path::PathBuf::from(format!("/dev/shm/osslscope-h5t1-{}", std::process::id()));
        std::fs::write(&f1, b"one").unwrap();
        std::fs::write(&f2, b"two").unwrap();
        let _rm = Rm(vec![f1.clone(), f2.clone()]);
        let stat_dev = |p: &std::path::Path| {
            let m = std::fs::metadata(p).unwrap();
            format!("{:02x}:{:02x}", libc::major(m.dev()), libc::minor(m.dev()))
        };
        // Canned twin vectors: identical maps identity, distinct
        // files (the maps dev-string ALSO diverges from both
        // files' stat-devs — the btrfs shape).
        let m1 = maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0,
            dev: "00:22".to_string(),
            ino: 999,
            path: f1.to_str().unwrap().to_string(),
        };
        let m2 = maps::Mapping {
            start: 0x3000,
            end: 0x4000,
            x: true,
            offset: 0,
            dev: "00:22".to_string(),
            ino: 999,
            path: f2.to_str().unwrap().to_string(),
        };
        assert_ne!(
            stat_dev(&f1),
            stat_dev(&f2),
            "twins need distinct stat-devs"
        );
        let live = vec![m1, m2];
        let nop = std::path::PathBuf::from("/nonexistent-osslscope-provider");
        let (b1, loc1) = attribute_impl(&live, &nop, "", 0x1500);
        let (b2, loc2) = attribute_impl(&live, &nop, "", 0x3500);
        let (b1, b2) = (b1.expect("twin1 backs"), b2.expect("twin2 backs"));
        // (a) btrfs shape: stat carried, maps text NOT echoed.
        assert_eq!(b1.dev, stat_dev(&f1), "backing must carry fstat dev");
        assert_ne!(
            b1.dev, "00:22",
            "maps dev-string must not leak into identity"
        );
        assert_eq!((b1.ino, b1.offset), (999, 0x500));
        assert_eq!(loc1, f1.to_str().unwrap());
        // (b) twins separate by stat-dev (same maps identity!).
        assert_eq!(b2.dev, stat_dev(&f2));
        assert_ne!(b1.dev, b2.dev, "x-fs twins must not share identity");
        assert_eq!(loc2, f2.to_str().unwrap());
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn dispatch_replacement_reinstalls() {
        // F-D/A11: provider file replaced (bound inode unmapped) —
        // detach the stale dispatch links and reinstall against the
        // current file, with a continuity-loss signal.
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 0);
        assert_eq!(env.reinstall_calls, 0);

        env.maps = vec![prov_mapping(60, 0x1000)];
        env.reinstall_script.push_back(Ok(DispatchReinstall {
            binding: ("/p/provider.so".to_string(), "08:01".to_string(), 60),
            resolution: None,
        }));
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 1);
        assert_eq!(env.reinstall_calls, 1);
        assert!(core.dispatch_live);
        assert_eq!(
            core.dispatch_bound,
            Some(("/p/provider.so".to_string(), "08:01".to_string(), 60))
        );
        assert!(core.snapshot().dispatch.attached);
        assert!(
            delta.attaches.iter().any(|a| matches!(
                a.kind,
                AttachKind::DispatchAnchors { .. }
            ) && a.failed.is_some()),
            "reinstall must carry a continuity-loss signal: {:?}",
            delta.attaches
        );
    }

    #[test]
    fn dispatch_reinstall_failure_latches_blind() {
        // F-D/A11: a failed dispatch reinstall leaves readiness
        // false (honest coverage) and retries only when the provider
        // fingerprint changes.
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        core.poll(&mut env, a11_budget()).unwrap();

        env.maps = vec![prov_mapping(60, 0x1000)];
        env.reinstall_script
            .push_back(Err(anyhow::anyhow!("anchor unresolvable")));
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 1);
        assert!(!core.dispatch_live);
        assert!(!core.snapshot().dispatch.attached);
        assert!(
            delta.attaches.iter().any(|a| matches!(
                a.kind,
                AttachKind::DispatchAnchors { .. }
            ) && a.failed.is_some()),
            "failed reinstall must signal loss: {:?}",
            delta.attaches
        );

        // Same fingerprint: no retry.
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.reinstall_calls, 1);

        // New fingerprint: retry, and success clears the latch.
        env.maps = vec![prov_mapping(70, 0x1000)];
        env.reinstall_script.push_back(Ok(DispatchReinstall {
            binding: ("/p/provider.so".to_string(), "08:01".to_string(), 70),
            resolution: None,
        }));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.reinstall_calls, 2);
        assert!(core.dispatch_live);
        assert!(core.snapshot().dispatch.attached);
    }

    #[test]
    fn h10_t1_pending_anchor_retained_across_unmapped_polls() {
        // T1 (RED): configured provider never mapped → the
        // kernel-pending links are RETAINED across unmapped polls
        // (zero detaches, stays live, no reinstall, no blind
        // latch); then mapped → still live, still zero detaches.
        // (No A11 test asserted pending detach — both dispatch
        // tests start mapped — so nothing flips.)
        let mut env = MiniEnv::new();
        env.maps = Vec::new();
        env.provider_stat = Some(("08:01".to_string(), 50));
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        for _ in 0..3 {
            core.poll(&mut env, a11_budget()).unwrap();
        }
        assert_eq!(env.dispatch_detaches, 0, "pending links retained");
        assert!(core.dispatch_live, "pending stays live");
        assert_eq!(env.reinstall_calls, 0, "no reinstall while pending");
        assert!(!core.dispatch_blind, "no blind latch while pending");
        env.maps = vec![prov_mapping(50, 0x1000)];
        core.poll(&mut env, a11_budget()).unwrap();
        assert!(core.dispatch_live, "armed stays live");
        assert_eq!(env.dispatch_detaches, 0, "map-in detaches nothing");
    }

    #[test]
    fn h10_t2_mapped_then_unmapped_detaches() {
        // T2 (RED): GONE preserved — mapped (armed) then unmapped
        // (dlclose) detaches exactly once. The post-dlclose maps
        // stay NON-empty (a live address space always carries
        // mappings — an empty snapshot is the zombie phase, not
        // an unmap, and takes the failed-read arm per Am1 T1').
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        env.provider_stat = Some(("08:01".to_string(), 50));
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 0);
        env.maps = vec![lc_mapping(99)];
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 1, "gone detaches once");
        assert!(!core.dispatch_live);
    }

    #[test]
    fn h10_t3_replace_before_map_reinstalls_on_new_inode() {
        // T3: pending links pin inode 50; the path is replaced
        // (stat now 60) before any map → detach the stale pin +
        // reinstall on the current file (same poll), still
        // never-mapped (a later map arms the NEW links).
        let mut env = MiniEnv::new();
        env.maps = Vec::new();
        env.provider_stat = Some(("08:01".to_string(), 60));
        env.reinstall_script.push_back(Ok(DispatchReinstall {
            binding: ("/p/provider.so".to_string(), "08:01".to_string(), 60),
            resolution: None,
        }));
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 1, "stale pin detaches");
        assert_eq!(env.reinstall_calls, 1, "reinstall on current file");
        // Pending replace is provably lossless (nothing was ever
        // mapped in this pid): no continuity caveat rides along.
        assert!(
            delta.attaches.iter().all(|a| a.failed.is_none()),
            "pending re-resolve carries no failure: {:?}",
            delta.attaches
        );
        assert!(core.dispatch_live, "pending again on inode 60");
        assert_eq!(
            core.dispatch_bound,
            Some(("/p/provider.so".to_string(), "08:01".to_string(), 60))
        );
        assert!(!core.dispatch_ever_mapped, "still never mapped");
        // The new links arm when the new file maps.
        env.maps = vec![prov_mapping(60, 0x1000)];
        core.poll(&mut env, a11_budget()).unwrap();
        assert!(core.dispatch_live);
        assert_eq!(env.dispatch_detaches, 1, "map-in detaches nothing");
    }

    #[test]
    fn h10_t4_unconfigured_map_installs_nothing() {
        // T4 (core half): a dlopen the session never configured
        // installs no dispatch anchors — the stranger's map-in
        // changes nothing (still pending on the configured file;
        // PARTIAL verdict pinned by the live leg).
        let mut env = MiniEnv::new();
        env.maps = vec![maps::Mapping {
            start: 0x5000,
            end: 0x6000,
            x: true,
            offset: 0,
            dev: "08:01".to_string(),
            ino: 70,
            path: "/p/stranger.so".to_string(),
        }];
        env.provider_stat = Some(("08:01".to_string(), 50));
        let mut core = a11_core();
        core.dispatch_bound = Some(("/p/provider.so".to_string(), "08:01".to_string(), 50));
        core.dispatch_live = true;
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.dispatch_detaches, 0);
        assert_eq!(env.reinstall_calls, 0, "stranger triggers no install");
        assert!(core.dispatch_live, "still pending on configured file");
        assert!(!core.dispatch_ever_mapped, "stranger is not our map");
    }

    #[test]
    fn stage2_target_change_detaches_old_link() {
        // F-D/A11: same cookie re-resolves to a different target
        // (replacement with both instances mapped) — detach the old
        // link before installing the new one (same cookie, new
        // target), with a supersede signal.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);

        env.maps = vec![prov_mapping(50, 0x1000), prov_mapping(60, 0x3000)];
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x3500));
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_detaches, vec![LEGACY_COOKIE]);
        assert_eq!(env.stage2_installs.len(), 2);
        let target = core.attached_targets.get(&LEGACY_COOKIE).unwrap();
        assert_eq!((target.2.as_str(), target.3), ("08:01", 60));
        assert!(
            delta
                .attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Stage2 { .. }) && a.failed.is_some()),
            "supersede must signal loss: {:?}",
            delta.attaches
        );
        assert!(
            delta
                .attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Stage2 { .. }) && a.failed.is_none()),
            "reinstall still reports its install: {:?}",
            delta.attaches
        );
    }

    #[test]
    fn stage2_unmapped_target_is_detached_and_dropped() {
        // F-D/A11: a stage-2 target whose backing is no longer mapped
        // (exec) is detached and forgotten — dead links never count
        // as live coverage.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert!(core.attached_queries.contains(&LEGACY_COOKIE));

        env.maps = vec![prov_mapping(60, 0x3000)];
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_detaches, vec![LEGACY_COOKIE]);
        assert!(!core.attached_queries.contains(&LEGACY_COOKIE));
        assert!(!core.attached_targets.contains_key(&LEGACY_COOKIE));
        assert_eq!(env.stage2_installs.len(), 1, "no reinstall without events");
        assert!(
            delta
                .attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Stage2 { .. }) && a.failed.is_some()),
            "unmapped drop must signal loss: {:?}",
            delta.attaches
        );
    }

    #[test]
    fn failed_stage2_retries_next_poll() {
        // F-D/A12: a transient install failure queues a retry —
        // the next poll re-attempts WITHOUT needing a fresh init
        // (quiet systems recover), clearing the sticky failure.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        env.stage2_fail_first = 1;
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        let d = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);
        assert!(d.attaches.iter().any(|a| a.failed.is_some()));
        assert!(
            core.snapshot()
                .dispatch
                .attach_failures
                .iter()
                .any(|f| f.cookie == LEGACY_COOKIE)
        );

        // No fresh events: the retry still attempts and succeeds.
        let d = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);
        assert!(core.attached_queries.contains(&LEGACY_COOKIE));
        assert!(core.snapshot().dispatch.attach_failures.is_empty());
        assert!(
            d.attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Stage2 { .. }) && a.failed.is_none()),
            "retry success reports its install: {:?}",
            d.attaches
        );
    }

    #[test]
    fn retry_respects_replacement_staleness() {
        // F-D/A12: a queued retry whose bytes changed under it
        // (replacement, no fresh init) is dropped, never attached
        // to the wrong bytes — with one loss signal.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        env.stage2_fail_first = 1;
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);

        // Same address, replaced bytes, no fresh init: drop.
        env.maps = vec![prov_mapping(60, 0x1000)];
        let d = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0, "stale retry must not attach");
        assert!(
            d.attaches
                .iter()
                .any(|a| matches!(a.kind, AttachKind::Stage2 { .. }) && a.failed.is_some()),
            "stale drop signals loss: {:?}",
            d.attaches
        );

        // Dropped means dropped: restoring the old bytes does not
        // resurrect the retry (a fresh init would).
        env.maps = vec![prov_mapping(50, 0x1000)];
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);
    }

    #[test]
    fn resolve_failure_retries_until_mapped() {
        // F-D/A12: an unmapped address queues without an identity
        // and retries silently until it maps (no event spam while
        // failing — the first record stands).
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x9500));
        let d = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);
        assert_eq!(d.attaches.len(), 1, "first failure records once");

        // Still unmapped: silent retry (no new events).
        let d = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);
        assert!(
            d.attaches.is_empty(),
            "retries must not spam: {:?}",
            d.attaches
        );
        assert!(
            core.snapshot()
                .dispatch
                .attach_failures
                .iter()
                .any(|f| f.cookie == LEGACY_COOKIE)
        );

        // The mapping appears (no fresh init): retry attaches.
        env.maps = vec![prov_mapping(50, 0x1000), prov_mapping(50, 0x9000)];
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);
        assert!(core.attached_queries.contains(&LEGACY_COOKIE));
        assert!(core.snapshot().dispatch.attach_failures.is_empty());
    }

    #[test]
    fn fresh_init_unqueues_retry() {
        // F-D/A12: a fresh init for a queued cookie hands recovery
        // to the pending path (fresh address) — the stale queued
        // address must not fire a spurious supersede later.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000), prov_mapping(50, 0x3000)];
        env.stage2_fail_first = 1;
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);

        // Fresh init at a new address installs via pending.
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x3500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);

        // The stale queued address never fires (else it would
        // supersede the fresh install with a second install).
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);
        let target = core.attached_targets.get(&LEGACY_COOKIE).unwrap();
        assert_eq!(target.0, 0x500, "fresh install stands: {target:?}");
    }

    #[test]
    fn retry_shares_attach_budget() {
        // F-D/A12: retries consume the same attach budget, fresh
        // work first — a starved retry defers (flagging exhaustion)
        // instead of starving the tripwire batch.
        use crate::discovery::harvest::LEGACY_COOKIE;
        let mut env = MiniEnv::new();
        env.maps = vec![prov_mapping(50, 0x1000)];
        env.stage2_fail_first = 1;
        let mut core = a11_core();
        core.pending_stage2.push_back((LEGACY_COOKIE, 0x1500));
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.stage2_installs.len(), 0);

        // Budget 1: the tripwire install wins, the retry defers.
        let tight = || PollBudget::new(65536, 1);
        env.maps = vec![prov_mapping(50, 0x1000), lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100, 0x200]));
        let d = core.poll(&mut env, tight()).unwrap();
        assert_eq!(env.trip_installs, 1);
        assert_eq!(
            env.stage2_installs.len(),
            0,
            "retry must defer, not starve trips"
        );
        assert!(d.budget_exhausted, "deferred retry flags exhaustion");

        // Budget free: the retry attaches.
        let d = core.poll(&mut env, tight()).unwrap();
        assert_eq!(env.stage2_installs.len(), 1);
        assert!(!d.budget_exhausted);
    }

    #[test]
    fn trip_mapping_compare_ignores_offsets() {
        // Cookie-meaning equality: same (cookie, symbol, module,
        // family, program) pairs in any order re-attaches soundly;
        // any pair change (or add/drop) does not.
        let a = trip_set(100, &[0x100, 0x200]);
        let b = trip_set(200, &[0x110, 0x220]);
        assert!(trip_mapping_equal(&a, &b));
        let mut reordered = trip_set(200, &[0x110, 0x220]);
        reordered.probes.reverse();
        assert!(trip_mapping_equal(&a, &reordered));
        let mut extra = trip_set(200, &[0x110, 0x220]);
        extra.probes.push(trip_probe(9, "EVP_new", 0x330));
        assert!(!trip_mapping_equal(&a, &extra));
        let mut renamed = trip_set(200, &[0x110, 0x220]);
        renamed.probes[0].symbol = "OTHER_by_id".to_string();
        assert!(!trip_mapping_equal(&a, &renamed));
        let mut shifted = trip_set(200, &[0x110, 0x220]);
        shifted.probes[0].cookie = 42;
        assert!(!trip_mapping_equal(&a, &shifted));
    }

    #[test]
    fn maps_failure_keeps_last_good_and_reports_loss() {
        // F-D/Am1 T1: a failed maps read is NOT empty maps — links
        // stay attached against the last-good snapshot and the
        // failure is an explicit delta loss, never a silent
        // mass-detach.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_installs, 1);
        env.maps_fail_first = 1;
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(
            env.trip_detaches, 0,
            "maps failure must not detach: last-good keeps links"
        );
        assert!(
            core.snapshot().legacy.planned,
            "legacy plan must survive a maps failure"
        );
        assert!(
            delta
                .losses
                .iter()
                .any(|l| l.source == coverage::HOST_MAPS_READ && l.count == 1 && l.op.is_none()),
            "maps failure must be explicit unlocalizable loss: {:?}",
            delta.losses
        );
    }

    #[test]
    fn empty_maps_snapshot_keeps_last_good_and_reports_loss() {
        // F-D/Am1 T1': an EMPTY maps snapshot is information-free,
        // not an unmap — a zombie (dead, not yet reaped) reads 0
        // bytes successfully, and a live address space is never
        // empty (exe/vdso/stack at minimum). Like a failed read it
        // keeps links against last-good with explicit loss; the
        // old clobber terminally detached stage-2 in the
        // death-during-poll race (P5d: bailed ~1/4 of speed legs
        // plus the dgst specimen — same arm feeds trips, dispatch
        // and stage-2, so the trip assertions pin the shared fix).
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_installs, 1);
        env.maps = vec![];
        let delta = core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(
            env.trip_detaches, 0,
            "empty snapshot must not detach: last-good keeps links"
        );
        assert!(
            core.snapshot().legacy.planned,
            "legacy plan must survive an empty snapshot"
        );
        assert!(
            delta
                .losses
                .iter()
                .any(|l| l.source == coverage::HOST_MAPS_READ && l.count == 1 && l.op.is_none()),
            "empty snapshot must be explicit unlocalizable loss: {:?}",
            delta.losses
        );
    }

    /// One QUERY_RET ring item (48-byte RowEvent layout):
    /// op/addr/generation carried, funcid 0.
    fn query_ret_bytes(op: u32, addr: u64, generation: u64) -> Vec<u8> {
        let mut b = vec![0u8; 48];
        b[0..4].copy_from_slice(&wire::KIND_QUERY_RET.to_le_bytes());
        b[4..8].copy_from_slice(&op.to_le_bytes());
        b[8..12].copy_from_slice(&0u32.to_le_bytes());
        b[16..24].copy_from_slice(&addr.to_le_bytes());
        b[40..48].copy_from_slice(&generation.to_le_bytes());
        b
    }

    /// One ROW ring item (48-byte RowEvent layout):
    /// op/funcid/impl/arr/idx/generation carried.
    fn row_bytes(
        op: u32,
        funcid: u32,
        impl_addr: u64,
        arr: u64,
        idx: u64,
        generation: u64,
    ) -> Vec<u8> {
        let mut b = vec![0u8; 48];
        b[0..4].copy_from_slice(&wire::KIND_ROW.to_le_bytes());
        b[4..8].copy_from_slice(&op.to_le_bytes());
        b[8..12].copy_from_slice(&funcid.to_le_bytes());
        b[16..24].copy_from_slice(&impl_addr.to_le_bytes());
        b[24..32].copy_from_slice(&arr.to_le_bytes());
        b[32..40].copy_from_slice(&idx.to_le_bytes());
        b[40..48].copy_from_slice(&generation.to_le_bytes());
        b
    }

    /// One ALG ring item (40-byte AlgEvent layout, class 0 / OK /
    /// non-weak): op/arr/idx/generation carried.
    fn alg_bytes(op: u32, arr: u64, idx: u64, generation: u64) -> Vec<u8> {
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(&wire::KIND_ALG.to_le_bytes());
        b.extend_from_slice(&op.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(wire::ALG_OK);
        b.push(0u8);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&arr.to_le_bytes());
        b.extend_from_slice(&idx.to_le_bytes());
        b.extend_from_slice(&generation.to_le_bytes());
        b
    }

    #[test]
    fn close_joins_ring_tail_instead_of_counting_shortfall() {
        // P6 §6ii: close() ingests the quiesced ring tail through
        // the same ingest_one path as poll (bounded) instead of
        // counting every tail item as drain shortfall. Pre-fix, a
        // fast-dying target's in-ring wave became shortfall (live
        // dgst specimen: 193 shortfall, 0 rows, queries kept only
        // via CALLS); post-fix it joins the snapshot.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.events.push_back(query_ret_bytes(12, 0x1000, 0));
        let mut core = a11_core();
        let snap = core.close(&mut env).unwrap();
        assert_eq!(snap.queries_observed, 1, "tail query must join");
        assert_eq!(snap.queries_by_op, vec![(12u32, 1u64)]);
        assert_eq!(snap.ops_hit, vec![12u32]);
        assert!(
            !snap
                .losses
                .iter()
                .any(|(s, _)| *s == coverage::HOST_DRAIN_SHORTFALL),
            "joined tail must not count as shortfall: {:?}",
            snap.losses
        );
    }

    #[test]
    fn close_tail_join_is_bounded_with_residual_shortfall() {
        // P6 §6ii companion: the close-time join is bounded (one
        // default poll budget); items past the bound stay honest
        // shortfall instead of stalling close on a huge tail.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        for _ in 0..PollBudget::default().max_events + 3 {
            env.events.push_back(query_ret_bytes(12, 0x1000, 0));
        }
        let mut core = a11_core();
        let snap = core.close(&mut env).unwrap();
        assert_eq!(
            snap.queries_observed,
            PollBudget::default().max_events,
            "close joins exactly one budget of tail"
        );
        let short: u64 = snap
            .losses
            .iter()
            .filter(|(s, _)| *s == coverage::HOST_DRAIN_SHORTFALL)
            .map(|(_, n)| *n)
            .sum();
        assert_eq!(short, 3, "residual past the bound stays shortfall");
    }

    #[test]
    fn reconcile_blind_first_poll_keeps_stage2_instead_of_terminal_detach() {
        // P6 §6ii follow-up: a blind session (no successful maps read
        // yet — last-good itself empty) must not read empty maps as an
        // unmap. This is the death-during-first-poll race: a 10ms dgst
        // dies after install but before the first drain poll, whose
        // empty (zombie) read would terminally detach stage-2
        // ("stage-2 target unmapped; link detached") even though the
        // drain's should_stop already owns death.
        let mut env = MiniEnv::new();
        let mut core = a11_core();
        assert!(core.last_good_maps.is_empty(), "precondition: never primed");
        core.attached_targets.insert(
            9,
            (
                0x1000,
                "/x/libcrypto.so.3".to_string(),
                "253:0".to_string(),
                7,
            ),
        );
        core.attached_queries.insert(9);
        let mut delta = DiscoveryDelta::default();
        core.reconcile_anchors(&mut env, &[], &mut delta);
        assert!(
            core.attached_targets.contains_key(&9),
            "blind first poll must not detach stage-2"
        );
        assert!(
            delta.attaches.iter().all(|a| a.failed.is_none()),
            "no terminal detach signal on empty maps: {:?}",
            delta.attaches
        );
        assert!(
            env.stage2_detaches.is_empty(),
            "no detach call issued: {:?}",
            env.stage2_detaches
        );
    }

    #[test]
    fn reconcile_blind_first_poll_keeps_trips_instead_of_detaching() {
        // Same class as the stage-2 blind-detach above: trips
        // installed at attach time must survive a blind first poll
        // (empty maps carry no unmap information).
        let mut env = MiniEnv::new();
        let mut core = a11_core();
        core.trip_live = true;
        core.trip_bound = Some(("/x/libcrypto.so.3".to_string(), "253:0".to_string(), 7));
        let mut delta = DiscoveryDelta::default();
        core.reconcile_anchors(&mut env, &[], &mut delta);
        assert!(core.trip_live, "blind first poll must not detach trips");
        assert_eq!(env.trip_detaches, 0, "no trip detach call issued");
    }

    #[test]
    fn close_rebirth_drops_queued_stamp0_with_straggler_loss() {
        // P6 §6ii sol blocker 1: close reconciles epochs (2→3
        // rebirth) BEFORE tail ingestion; the previous poll's
        // bootstrap grace must not survive the retirement. A queued
        // stamp-0 ALG belongs to the retired incarnation: it drops
        // with op-localized straggler loss, never attributed to the
        // replacement.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        // Simulate "last poll bootstrapped gen 2 for array
        // 0x1500": tracked table at the predecessor fingerprint
        // (ino 99) + live binding + drain grace.
        core.table_epochs.insert(
            (1, 0x1500),
            TableEpoch {
                epoch: 0,
                fingerprint: Some(("08:01".to_string(), 99, 0x1000, 0x2000, 0)),
            },
        );
        core.array_gen.insert(0x1500, 2);
        core.bootstrap_grace.insert(0x1500);
        // Queued stamp-0 ALG from the retired incarnation.
        env.events.push_back(alg_bytes(1, 0x1500, 0, 0));
        let snap = core.close(&mut env).unwrap();
        // Precondition: the rebirth happened (2→3, ino 100).
        assert_eq!(
            core.array_gen.get(&0x1500),
            Some(&3),
            "close must rebirth the replaced array 2→3"
        );
        assert!(
            !core.alg_records.contains_key(&(0x1500, 0)),
            "retired stamp-0 ALG must not attribute to the replacement"
        );
        let stragglers: u64 = snap
            .losses
            .iter()
            .filter(|(s, _)| *s == coverage::HOST_STRAGGLER)
            .map(|(_, n)| *n)
            .sum();
        assert_eq!(stragglers, 1, "dropped stamp-0 must record straggler loss");
    }

    #[test]
    fn close_reports_tail_joined_candidates_for_capture_reconcile() {
        // P6 §6ii sol blocker 2 (discovery half): candidates first
        // joined (or refreshed) by close's tail ingest never rode a
        // poll delta, so capture's adapter never saw them. Close
        // reports them for the finish-time reconcile (taint, never
        // silent census).
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        core.alg_records.insert(
            (0x1500, 0),
            ("AES-128-CBC".to_string(), false, "ok".to_string()),
        );
        // Novel ROW (new key) arriving only in the close tail.
        env.events.push_back(row_bytes(1, 0, 0x1600, 0x1500, 0, 0));
        let snap = core.close(&mut env).unwrap();
        assert_eq!(
            snap.close_candidates.len(),
            1,
            "close must report its tail-joined candidate"
        );
        let c = &snap.close_candidates[0];
        assert_eq!(c.op, 1);
        assert_eq!(c.arr, 0x1500);
        assert_eq!(c.impl_addr, 0x1600);
        assert!(
            snap.candidates.iter().any(|k| k.op == 1 && k.arr == 0x1500),
            "the candidate joins the cumulative set too"
        );
    }

    #[test]
    fn close_reports_remembered_backings_for_joined_impls() {
        // P6 §6ii sol round-3 remap variant: M4's first-cell arm
        // silently adopts a close-joined ROW's backing — but the
        // impl may have remapped since the ROW was queued (the
        // record is stale, the adoption misattributes it). Close
        // reports the M4-remembered backings for each joined impl
        // that DIFFER from the joined backing, so capture can
        // revise the old sites too (whose sets may miss the
        // alias). Consistent memory reports nothing.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        // M4 remembers impl 0x1600 under a DIFFERENT backing
        // (ino 999 — the pre-remap file) for another cell.
        core.slot_backing.insert(
            (0x1500, 7, 0x1600),
            BackingRef {
                dev: "08:01".to_string(),
                ino: 999,
                offset: 0x600,
            },
        );
        // Consistent memory for impl 0x1700 (same backing the ROW
        // will attribute): reports nothing.
        core.slot_backing.insert(
            (0x1500, 8, 0x1700),
            BackingRef {
                dev: "08:01".to_string(),
                ino: 100,
                offset: 0x700,
            },
        );
        core.alg_records.insert(
            (0x1500, 0),
            ("AES-128-CBC".to_string(), false, "ok".to_string()),
        );
        core.alg_records.insert(
            (0x1500, 1),
            ("AES-128-CBC".to_string(), false, "ok".to_string()),
        );
        // Novel ROWs (new keys) arriving only in the close tail.
        env.events.push_back(row_bytes(1, 0, 0x1600, 0x1500, 0, 0));
        env.events.push_back(row_bytes(1, 0, 0x1700, 0x1500, 1, 0));
        let snap = core.close(&mut env).unwrap();
        assert_eq!(snap.close_candidates.len(), 2);
        // Only the DIVERGING memory is reported (ino 999); the
        // consistent one (ino 100) is not.
        assert_eq!(snap.close_remembered, vec![(999u64, 0x600u64)]);
    }

    #[test]
    fn close_remembered_survives_silent_terminated_retirement() {
        // P6 §6ii sol round-4: a TERMINATED table retires SILENTLY
        // (no retained reason — it carried no gap) while still
        // wiping its array's M4 cells. The remap-evidence scan
        // must therefore read memory FROZEN at close entry
        // (pre-reconciliation), not the post-reconcile map —
        // else a queued first-cross-op ROW joining a remapped
        // impl loses its old backing and the old counted site
        // never revises. Pins the silence (empty retained
        // reasons) AND the surviving evidence together.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        // op-1's table at the predecessor fingerprint (ino 99):
        // close will rebirth it (2→3). Observed + terminated ⟹
        // the retirement is silent.
        core.table_epochs.insert(
            (1, 0x1500),
            TableEpoch {
                epoch: 0,
                fingerprint: Some(("08:01".to_string(), 99, 0x1000, 0x2000, 0)),
            },
        );
        core.array_gen.insert(0x1500, 2);
        // Observed (a query arrived) + terminated (TERMD proof
        // names len 0 with nothing walked) ⟹ silent retirement.
        core.tracker.note_query_ret(1, 0x1500);
        core.tracker.ingest_termd(&[(0x1500, 1)]);
        // M4 remembers impl 0x1900 under the OLD backing (ino
        // 999) — wiped by the rebirth below.
        core.slot_backing.insert(
            (0x1500, 7, 0x1900),
            BackingRef {
                dev: "08:01".to_string(),
                ino: 999,
                offset: 0x600,
            },
        );
        // Queued first op-2 ROW from ANOTHER, unchanged array
        // for the same impl (novel cell → silent adopt).
        core.alg_records.insert(
            (0x1800, 0),
            ("AES-128-CBC".to_string(), false, "ok".to_string()),
        );
        env.events.push_back(row_bytes(2, 0, 0x1900, 0x1800, 0, 0));
        let snap = core.close(&mut env).unwrap();
        // Preconditions: the rebirth ran, and it was silent.
        assert_eq!(
            core.array_gen.get(&0x1500),
            Some(&3),
            "close must rebirth the replaced array 2→3"
        );
        assert!(
            snap.retained_reasons.is_empty(),
            "terminated retirement must stay silent: {:?}",
            snap.retained_reasons
        );
        assert_eq!(snap.close_candidates.len(), 1);
        assert_eq!(
            snap.close_remembered,
            vec![(999u64, 0x600u64)],
            "frozen memory must survive the silent wipe"
        );
    }

    #[test]
    fn install_trips_receives_caller_maps() {
        // F-D/Am1 T3': the trip installer uses the caller's
        // explicit maps (last-good-or-fresh, failure already
        // handled) instead of re-reading /proc itself — no second
        // conflation site.
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        assert_eq!(env.trip_installs, 1);
        assert!(
            legacy::find_libcrypto(&env.last_install_maps).is_some(),
            "installer must see the caller's libcrypto mapping: {:?}",
            env.last_install_maps
        );
    }

    #[test]
    fn close_maps_failure_reconciles_last_good_with_loss() {
        // F-D/Am1 T4: close against a failed maps read reconciles
        // the stale epoch against the last-good snapshot (precise
        // retire, not skip-all) and records the failure — the
        // single close-time count with an exited target is
        // expected (final drain runs against last-good).
        let mut env = MiniEnv::new();
        env.maps = vec![lc_mapping(100)];
        env.plan = Some(trip_set(100, &[0x100]));
        let mut core = a11_core();
        core.poll(&mut env, a11_budget()).unwrap();
        // Stale table epoch: array 0x1500 lives in lc_mapping
        // (0x1000..0x2000, ino 100) but the epoch still carries
        // the predecessor file's fingerprint.
        core.table_epochs.insert(
            (1, 0x1500),
            TableEpoch {
                epoch: 0,
                fingerprint: Some(("08:01".to_string(), 99, 0x1000, 0x2000, 0)),
            },
        );
        env.maps_fail_first = 1;
        let snap = core.close(&mut env).unwrap();
        // The stale epoch retires against last-good and rebirths
        // with the last-good fingerprint (ino 100, not the seeded
        // predecessor 99) — precise reconcile, not skip-all.
        assert_eq!(
            core.table_epochs
                .get(&(1, 0x1500))
                .and_then(|t| t.fingerprint.clone()),
            Some(("08:01".to_string(), 100, 0x1000, 0x2000, 0)),
            "stale epoch must retire+rebirth against last-good"
        );
        assert!(
            snap.losses
                .iter()
                .any(|(s, n)| *s == coverage::HOST_MAPS_READ && *n == 1),
            "close-time maps failure must be explicit loss: {:?}",
            snap.losses
        );
    }

    #[test]
    fn calls_join_source_pins_permanently() {
        // P5d: the first join decides the query-count source forever.
        // CALLS-absent pins the event fallback — a later-appearing
        // map does not flip mid-stream (same rule as the total).
        let mut delta = DiscoveryDelta::default();
        let mut core = a11_core();
        core.join_snapshots(
            &MapSnapshots {
                calls: None,
                ..Default::default()
            },
            &mut delta,
        );
        // Simulate three accepted QUERY_RET events on op 2 (ring
        // ingestion is covered by integration tests; the source
        // SELECTION is what's under test here).
        core.queries_events = 3;
        core.queries_by_op.insert(2, 3);
        core.join_snapshots(
            &MapSnapshots {
                calls: Some(50),
                calls_by_op: vec![(2, 50)],
                ..Default::default()
            },
            &mut delta,
        );
        let snap = core.snapshot();
        assert_eq!(snap.queries_observed, 3);
        assert_eq!(snap.queries_by_op, vec![(2, 3)]);
    }

    #[test]
    fn calls_join_partial_read_inflates_perop_recovers_on_complete() {
        // P5d: good {1:5,2:5}, then a failed partial {1:9} — the
        // total stays 10 (max-of-sums) while the per-op high-water
        // sums to 14. A later complete read restores equality.
        // (Sum > total is legitimate ONLY with a failed read behind
        // it; silent dips are ignored without record.)
        let mut delta = DiscoveryDelta::default();
        let mut core = a11_core();
        core.join_snapshots(
            &MapSnapshots {
                calls: Some(10),
                calls_by_op: vec![(1, 5), (2, 5)],
                ..Default::default()
            },
            &mut delta,
        );
        let snap = core.snapshot();
        assert_eq!(snap.queries_observed, 10);
        assert_eq!(snap.queries_by_op, vec![(1, 5), (2, 5)]);
        core.join_snapshots(
            &MapSnapshots {
                calls: Some(9),
                calls_by_op: vec![(1, 9)],
                calls_failed: true,
                ..Default::default()
            },
            &mut delta,
        );
        let snap = core.snapshot();
        assert_eq!(snap.queries_observed, 10);
        assert_eq!(snap.queries_by_op, vec![(1, 9), (2, 5)]);
        core.join_snapshots(
            &MapSnapshots {
                calls: Some(14),
                calls_by_op: vec![(1, 9), (2, 5)],
                ..Default::default()
            },
            &mut delta,
        );
        let snap = core.snapshot();
        assert_eq!(snap.queries_observed, 14);
        assert_eq!(snap.queries_by_op, vec![(1, 9), (2, 5)]);
    }

    #[test]
    fn builtin_anchor_bootstrap_only_and_recycle_cleared() {
        // Traversal anchor: None fresh; set by the bootstrap
        // mark; poll-time stage-2 cookie-0 installs (init anchor)
        // write `attached_targets` directly and must NOT move it;
        // recycle clears it with all lineage.
        let mut core = a11_core();
        assert_eq!(core.builtin_anchor(), None);
        core.mark_query_attached(
            0,
            0x1234,
            "/p/libcrypto.so.3".to_string(),
            "08:01".to_string(),
            99,
        );
        assert_eq!(
            core.builtin_anchor(),
            Some((PathBuf::from("/p/libcrypto.so.3"), 0x1234))
        );
        // A poll-time stage-2 cookie-0 install (init mode):
        // overwrites the cookie row, leaves the anchor pinned.
        core.attached_queries.insert(0);
        core.attached_targets.insert(
            0,
            (
                0x9999,
                "/p/libcrypto.so.3".to_string(),
                "08:01".to_string(),
                99,
            ),
        );
        assert_eq!(
            core.builtin_anchor(),
            Some((PathBuf::from("/p/libcrypto.so.3"), 0x1234))
        );
        core.mark_recycled();
        assert_eq!(core.builtin_anchor(), None);
    }
}
