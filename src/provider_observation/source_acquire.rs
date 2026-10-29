// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owner source acquisition core. Pure sequencing plus unloaded-root
//! custody. Source mode stays 0: loading the retained roots, enabling mode 1
//! and attaching to live targets require source/artifact review plus an
//! explicit native lease. Nothing in this module performs those effects.
//!
//! Ordinary-RCU writer proof (premises frozen by test, see the bpf-sys
//! attribute test and the real-object writer-inventory test):
//! every source writer loads non-sleepable (`prog_flags == 0`, hence
//! `prog->sleepable == false` per `syscall.c:2778`), so fentry/fexit roots
//! execute under ordinary `rcu_read_lock` via `__bpf_prog_enter`
//! (`kernel/bpf/trampoline.c:1017-1026`, selected at `:1049-1060`) and raw
//! lifecycle roots via `__bpf_trace_run` (`kernel/trace/bpf_trace.c:2313-2337`)
//! on inspected stable 6.12.113. ADMIT dominates every writer mutation (each
//! root's first operation is the ADMIT lookup and every root carries an ADMIT
//! fixup), and the shared gate close deletes the outer map, whose reviewed
//! RCU wait covers all admitted non-sleepable writers. Sleepable execution
//! would use Tasks-Trace RCU instead and is refused by the frozen loaders.

use super::{ObservationGap, source_owner::contract};
use crate::loader;
use std::{collections::BTreeMap, os::fd::OwnedFd};

/// Conservative accounted host capacity for the acquisition core, charged once
/// by the source owner before any acquisition. These are reservations, not
/// measured kernel allocation or RSS.
pub(super) const NOOP_PROGRAM_RESERVE: usize = 128 << 10;
pub(super) const PROVISIONAL_LINK_RESERVE: usize = 32 << 10;
pub(super) const SOURCE_PROGRAM_RESERVE: usize = 32 << 10;
pub(super) const SOURCE_LINK_RESERVE: usize = 32 << 10;
pub(super) const SOURCE_ROOT_COUNT: usize = 4;
pub(super) const LEDGER_RESERVE: usize = 4096;
pub(super) const DOMAIN_INDEX_RESERVE: usize = 8192;
pub(super) const IDS_RESERVE: usize = 8;
pub(super) const ACQUIRE_CORE_RESERVE: usize = NOOP_PROGRAM_RESERVE
    + PROVISIONAL_LINK_RESERVE
    + SOURCE_ROOT_COUNT * (SOURCE_PROGRAM_RESERVE + SOURCE_LINK_RESERVE)
    + LEDGER_RESERVE
    + DOMAIN_INDEX_RESERVE
    + IDS_RESERVE;

/// Host ledger capacities are fixed shares of the shared kernel budgets from
/// the source-capability contract, never object counts. No "16 code-object
/// selector" authority exists in the contracts, PLAN, feasibility or plan
/// records; one anchor alone needs 17 registrations for the typed public
/// roles (objects.rs TYPED_PUBLIC_ROLES, pinned by
/// TYPED_PUBLIC_ROLE_COUNT in the capacity control), plus independently
/// registered provider-callback sites.
///
/// Derivation: worst-case logical rows must fit the shared 8192 budget
/// (capability contract "Finite records and ownership": every row, guard,
/// projection, index, enrollment cell and tombstone consumes it).
/// - Anchors: at most one anchor per admitted target domain. SOURCE_DOMAIN
///   admits at most 64 rows (`source_owner::MAPS` spec
///   `SOURCE_DOMAIN 1/4/64/64`, `MAX_DOMAINS`), and each SOURCE_ANCHOR key
///   (process_incarnation/image_epoch) selects one admitted target
///   configuration. 64 anchors x 2 rows (SOURCE_ANCHOR + anchor guard) = 128.
/// - Registrations: each registration charges at least 3 rows (SOURCE_REG +
///   adoption guard + SOURCE_READY; capability "Capacity and acceptance").
///   1024 x 3 = 3072 rows, under half the shared 8192 budget, leaving
///   headroom for anchors (<=128), domains (<=64), the observer cell (1) and
///   CODE_ROLE/index rows. 1024 covers the 17 typed roles plus callback
///   sites on one anchor with margin.
///
/// Both admissions are plain sequential checks inside the serialized source
/// owner: no host racing read-modify-write. All charges stay inside the
/// existing reserves (`ACQUIRE_CORE_RESERVE` unchanged).
const MAX_ANCHOR_GUARDS: usize = 64;
const MAX_REGISTRATION_GUARDS: usize = 1024;
/// One domain row per admitted process at most.
const MAX_DOMAINS: usize = 64;
/// Kernel verdict word for a completed successful hook pair.
const VERDICT_SUCCESS: u32 = 1;

/// One collision-free session allocator for every host-minted source ID:
/// anchor-guard IDs, registration-adoption-guard IDs and request nonces all
/// come from this single monotonic sequence, so distinct classes can never
/// collide. Kernel observation IDs occupy `1..2^63-1`; host IDs occupy the
/// upper nonzero half and are never reused or wrapped.
pub(super) struct HostIds {
    next: u64,
}
impl HostIds {
    pub(super) fn new() -> Self {
        Self {
            next: contract::HOST_ID_FIRST,
        }
    }
    // Phase-2 native lease: minting runs from the future after-open
    // acquisition path, after source/artifact review plus explicit lease.
    #[allow(dead_code)]
    pub(super) fn fresh(&mut self) -> Result<u64, ObservationGap> {
        // u64::MAX is the exhaustion sentinel, never a minted ID: minting it
        // would leave no representable successor and risk wrap or reuse.
        if self.next == u64::MAX {
            return Err(ObservationGap::StateLimit);
        }
        let id = self.next;
        self.next = id + 1;
        Ok(id)
    }
}

/// Synchronous terminal observations of completed trigger invocations. Each
/// receipt binds the exact nonce the host armed; counts and verdict prove the
/// kernel completed one hook pair. No in-flight request word is a receipt.
/// Private fields with no constructors: only tests build literals in phase 1;
/// validated phase-2 constructors mint these from completed native calls.
pub(super) struct AnchorReceipt {
    anchor_id: u64,
    nonce: u64,
    entry_count: u32,
    exit_count: u32,
    verdict: u32,
}
pub(super) struct EntryReceipt {
    nonce: u64,
    registration_id: u64,
    entry_count: u32,
    exit_count: u32,
    verdict: u32,
    /// The actual target link_create returned a usable FD. Kernel hook success
    /// alone never authorizes guard creation without the adopted descriptor.
    syscall_ok: bool,
}
pub(super) struct EnrollmentReceipt {
    nonce: u64,
    host_pid_tgid: u64,
}
pub(super) struct ReadyReceipt {
    nonce: u64,
    registration_id: u64,
    entry_count: u32,
    exit_count: u32,
    verdict: u32,
    sequence: u64,
}

/// Proof that every required actual link FD for one registration was adopted
/// into the retained owner. Private fields with no phase-1 constructor: only
/// the future adoption path may mint this after retaining all FDs.
pub(super) struct AdoptedLinks {
    registration_id: u64,
    anchor_id: u64,
    epoch: u64,
    links: u8,
}

/// Host record of a guard the host minted or created. `Minted` has no kernel
/// row yet; the remaining states mirror the kernel SOURCE_GUARD word. This is
/// host issuance bookkeeping, never a readback of private REL state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GuardLife {
    Minted,
    Preparing,
    Live,
    Retired,
    Conflict,
}
impl GuardLife {
    fn terminal(self) -> bool {
        matches!(self, Self::Retired | Self::Conflict)
    }
}
struct AnchorGuard {
    epoch: u64,
    nonce: u64,
    life: GuardLife,
}
struct RegistrationGuard {
    anchor_id: u64,
    epoch: u64,
    nonce: u64,
    life: GuardLife,
}

/// Receipt-based guard issuance. The host creates the registration adoption
/// guard strictly after that registration's ENTRY hook pair completes and
/// strictly before its RETURN hook pair may arm: ENTRY fentry terminally
/// poisons the observer if the guard already exists, while RETURN fentry
/// requires it in PREPARING. Minted IDs are bound to their arming nonce at
/// mint time; creation consumes an exact terminal receipt.
pub(super) struct GuardLedger {
    anchors: BTreeMap<u64, AnchorGuard>,
    registrations: BTreeMap<u64, RegistrationGuard>,
}
// Phase-2 native lease: transitions run only from the future after-open
// acquisition path, after source/artifact review plus explicit lease.
#[allow(dead_code)]
impl GuardLedger {
    pub(super) fn new() -> Self {
        Self {
            anchors: BTreeMap::new(),
            registrations: BTreeMap::new(),
        }
    }
    fn nonce_recorded(&self, nonce: u64) -> bool {
        self.anchors.values().any(|g| g.nonce == nonce)
            || self.registrations.values().any(|g| g.nonce == nonce)
    }
    fn nonce_checks(&self, nonce: u64) -> Result<(), ObservationGap> {
        // The single allocator makes collisions impossible for correct
        // callers; a caller-supplied nonce that collides anyway is refused
        // rather than recorded, since nonces never repeat. This runs before
        // allocation so invalid input never burns a fresh ID.
        if nonce < contract::HOST_ID_FIRST || self.nonce_recorded(nonce) {
            return Err(ObservationGap::Invalidated);
        }
        Ok(())
    }
    fn id_checks(&self, id: u64, nonce: u64) -> Result<(), ObservationGap> {
        // Only a caller nonce equal to the just-minted ID can reach this;
        // correct callers mint the nonce before the ID, so they never do.
        if id == nonce || self.anchors.contains_key(&id) || self.registrations.contains_key(&id) {
            return Err(ObservationGap::Invalidated);
        }
        Ok(())
    }
    pub(super) fn mint_anchor(
        &mut self,
        ids: &mut HostIds,
        epoch: u64,
        nonce: u64,
    ) -> Result<u64, ObservationGap> {
        if epoch == 0 {
            return Err(ObservationGap::Invalidated);
        }
        if self.anchors.len() >= MAX_ANCHOR_GUARDS {
            return Err(ObservationGap::StateLimit);
        }
        self.nonce_checks(nonce)?;
        let id = ids.fresh()?;
        self.id_checks(id, nonce)?;
        self.anchors.insert(
            id,
            AnchorGuard {
                epoch,
                nonce,
                life: GuardLife::Minted,
            },
        );
        Ok(id)
    }
    pub(super) fn mint_registration(
        &mut self,
        ids: &mut HostIds,
        anchor_id: u64,
        epoch: u64,
        nonce: u64,
    ) -> Result<u64, ObservationGap> {
        // ENTRY fentry requires the anchor guard LIVE; the host enforces that
        // precondition at mint time instead of arming a doomed request.
        let anchor = self
            .anchors
            .get(&anchor_id)
            .ok_or(ObservationGap::Invalidated)?;
        if anchor.life != GuardLife::Live || anchor.epoch != epoch || epoch == 0 {
            return Err(ObservationGap::Invalidated);
        }
        if self.registrations.len() >= MAX_REGISTRATION_GUARDS {
            return Err(ObservationGap::StateLimit);
        }
        self.nonce_checks(nonce)?;
        let id = ids.fresh()?;
        self.id_checks(id, nonce)?;
        self.registrations.insert(
            id,
            RegistrationGuard {
                anchor_id,
                epoch,
                nonce,
                life: GuardLife::Minted,
            },
        );
        Ok(id)
    }
    fn anchor_receipt_matches(guard: &AnchorGuard, receipt: &AnchorReceipt) -> bool {
        guard.nonce == receipt.nonce
            && receipt.entry_count == 1
            && receipt.exit_count == 1
            && receipt.verdict == VERDICT_SUCCESS
    }
    /// Record a successful NOEXIST PREPARING insert after the phase-1 hook
    /// pair completed. Call only after the native insert succeeded.
    pub(super) fn create_anchor(
        &mut self,
        id: u64,
        receipt: &AnchorReceipt,
    ) -> Result<(), ObservationGap> {
        let guard = self
            .anchors
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Minted
            || receipt.anchor_id != id
            || !Self::anchor_receipt_matches(guard, receipt)
        {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Preparing;
        Ok(())
    }
    /// A failed anchor-guard insert terminally refuses the capability. A
    /// failed creation is never retried: EEXIST in particular proves an ID or
    /// lifecycle defect the host must not paper over with a second insert.
    pub(super) fn fail_anchor(&mut self, id: u64) -> Result<(), ObservationGap> {
        let guard = self
            .anchors
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Minted {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Conflict;
        Ok(())
    }
    /// PREPARING becomes LIVE only after retained self-mapping/hash custody
    /// and the complete anchor verdict, both established by the phase-2
    /// anchor path before it calls here.
    pub(super) fn live_anchor(&mut self, id: u64) -> Result<(), ObservationGap> {
        let guard = self
            .anchors
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Preparing {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Live;
        Ok(())
    }
    /// Record a successful NOEXIST PREPARING insert for the adoption guard.
    /// This must run strictly after the ENTRY hook pair completed with an
    /// exact success receipt plus a usable link FD: creating earlier kills
    /// all source at ENTRY fentry, and the kernel refuses double creation.
    /// Bookkeeping half only: production creation runs through the
    /// `create_adoption_guarded` chokepoint, which validates this same
    /// receipt BEFORE the injected insert and calls here only after the
    /// insert succeeds.
    pub(super) fn create_adoption(
        &mut self,
        id: u64,
        receipt: &EntryReceipt,
    ) -> Result<(), ObservationGap> {
        let guard = self
            .registrations
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Minted
            || receipt.registration_id != id
            || guard.nonce != receipt.nonce
            || receipt.entry_count != 1
            || receipt.exit_count != 1
            || receipt.verdict != VERDICT_SUCCESS
            || !receipt.syscall_ok
        {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Preparing;
        Ok(())
    }
    /// A failed adoption-guard insert terminally refuses the capability; a
    /// failed creation is never retried.
    pub(super) fn fail_adoption(&mut self, id: u64) -> Result<(), ObservationGap> {
        let guard = self
            .registrations
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Minted {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Conflict;
        Ok(())
    }
    /// The RETURN hook pair may arm only after the adoption guard exists in
    /// PREPARING. This is the host half of the I-2 creation ordering.
    pub(super) fn return_may_arm(&self, id: u64) -> Result<(), ObservationGap> {
        let guard = self
            .registrations
            .get(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Preparing {
            return Err(ObservationGap::Invalidated);
        }
        Ok(())
    }
    /// PREPARING becomes LIVE only with proof that ALL actual required link
    /// FDs were adopted into the retained owner. No partial READY exists.
    pub(super) fn live_adoption(
        &mut self,
        id: u64,
        adopted: &AdoptedLinks,
    ) -> Result<(), ObservationGap> {
        let guard = self
            .registrations
            .get_mut(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Preparing
            || adopted.registration_id != id
            || adopted.anchor_id != guard.anchor_id
            || adopted.epoch != guard.epoch
            || adopted.links == 0
        {
            return Err(ObservationGap::Invalidated);
        }
        guard.life = GuardLife::Live;
        Ok(())
    }
    /// Retire a created guard. Idempotent on terminal rows (first terminal
    /// state wins) so teardown can retire everything unconditionally. Minted
    /// IDs with no kernel row are refused here; abandon them instead.
    pub(super) fn retire(&mut self, id: u64) -> Result<(), ObservationGap> {
        if let Some(guard) = self.anchors.get_mut(&id) {
            return Self::retire_life(&mut guard.life);
        }
        if let Some(guard) = self.registrations.get_mut(&id) {
            return Self::retire_life(&mut guard.life);
        }
        Err(ObservationGap::Invalidated)
    }
    fn retire_life(life: &mut GuardLife) -> Result<(), ObservationGap> {
        match life {
            GuardLife::Minted => Err(ObservationGap::Invalidated),
            GuardLife::Preparing | GuardLife::Live => {
                *life = GuardLife::Retired;
                Ok(())
            }
            GuardLife::Retired | GuardLife::Conflict => Ok(()),
        }
    }
    /// Conflict a guard after an observed collision or failed invariant.
    /// First terminal state wins; a minted ID with no kernel row conflicts
    /// without needing any map effect.
    pub(super) fn conflict(&mut self, id: u64) -> Result<(), ObservationGap> {
        if let Some(guard) = self.anchors.get_mut(&id) {
            if !guard.life.terminal() {
                guard.life = GuardLife::Conflict;
            }
            return Ok(());
        }
        if let Some(guard) = self.registrations.get_mut(&id) {
            if !guard.life.terminal() {
                guard.life = GuardLife::Conflict;
            }
            return Ok(());
        }
        Err(ObservationGap::Invalidated)
    }
    /// Drop a minted-never-created ID. Only Minted records may be abandoned;
    /// anything created needs explicit retire/conflict for its kernel row.
    pub(super) fn abandon(&mut self, id: u64) -> Result<(), ObservationGap> {
        if self
            .anchors
            .get(&id)
            .is_some_and(|g| g.life == GuardLife::Minted)
        {
            self.anchors.remove(&id);
            return Ok(());
        }
        if self
            .registrations
            .get(&id)
            .is_some_and(|g| g.life == GuardLife::Minted)
        {
            self.registrations.remove(&id);
            return Ok(());
        }
        Err(ObservationGap::Invalidated)
    }
    pub(super) fn anchor_live(&self, id: u64) -> bool {
        self.anchors
            .get(&id)
            .is_some_and(|g| g.life == GuardLife::Live)
    }
    pub(super) fn adoption_live(&self, id: u64) -> bool {
        self.registrations
            .get(&id)
            .is_some_and(|g| g.life == GuardLife::Live)
    }
}

/// Proof that the host holds the original pre-exec child for one TGID, so
/// ARMED configuration cannot be installed for a recycled or unheld TGID.
/// Private field with no phase-1 constructor: only the future held-child
/// startup path may mint this while it retains the stopped child.
pub(super) struct OriginalCustody {
    tgid: u32,
}

/// Host mirror of the SOURCE_DOMAIN index, keyed by the exact existing
/// MEMBERS/NAMESPACE-normalized TGID coordinate. Only original held-child
/// custody may configure ARMED. ARMED admits exactly one consumable
/// original-to-planned image transition; every later or mismatched exec, and
/// every normalization failure for a seeded domain, retires that domain.
/// Retired rows stay as tombstones: a TGID is never re-armed in one session.
pub(super) struct DomainIndex {
    domains: BTreeMap<u32, contract::SourceDomain>,
    /// Host-initiated shared logical claims, starting at the fixed observer
    /// enrollment cell. Mirrors the kernel relationship budget; never exceeds
    /// the shared 8192 allowance.
    claims: u64,
}
// Phase-2 native lease: transitions run only from the future after-open
// acquisition path, after source/artifact review plus explicit lease.
#[allow(dead_code)]
impl DomainIndex {
    pub(super) fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
            claims: 1,
        }
    }
    fn terminal(state: u64) -> bool {
        state == contract::DOMAIN_RETIRED || state == contract::DOMAIN_POISON
    }
    pub(super) fn arm(
        &mut self,
        tgid: u32,
        incarnation: u64,
        original: u64,
        planned: u64,
        custody: &OriginalCustody,
    ) -> Result<(), ObservationGap> {
        // The kernel retires equal original/planned images at exec; the host
        // refuses such a configuration instead of arming a doomed domain.
        if tgid == 0
            || custody.tgid != tgid
            || incarnation == 0
            || original == 0
            || planned == 0
            || original == planned
            || self.domains.contains_key(&tgid)
        {
            return Err(ObservationGap::Invalidated);
        }
        if self.domains.len() >= MAX_DOMAINS || self.claims >= 8192 {
            return Err(ObservationGap::StateLimit);
        }
        self.domains.insert(
            tgid,
            contract::SourceDomain {
                process_incarnation: incarnation,
                original_image: original,
                planned_image: planned,
                current_image: original,
                state: contract::DOMAIN_ARMED,
                loss_epoch: 0,
                reserved: [0, 0],
            },
        );
        self.claims += 1;
        Ok(())
    }
    /// Mirror the one consumable planned exec. Only ARMED with the exact
    /// planned image becomes ACTIVE; anything else (including a second exec
    /// on an ACTIVE domain) retires, exactly like the kernel root.
    pub(super) fn note_planned_exec(
        &mut self,
        tgid: u32,
        image: u64,
    ) -> Result<(), ObservationGap> {
        let row = self
            .domains
            .get_mut(&tgid)
            .ok_or(ObservationGap::Invalidated)?;
        if row.state == contract::DOMAIN_ARMED
            && image == row.planned_image
            && image != row.original_image
        {
            row.current_image = image;
            row.state = contract::DOMAIN_ACTIVE;
        } else if !Self::terminal(row.state) {
            row.state = contract::DOMAIN_RETIRED;
        }
        Ok(())
    }
    /// A normalization failure for a seeded domain revokes exactly that
    /// domain. Unseeded TGIDs are ignored: before a seed no certificates
    /// exist to retire, and unrelated tasks must not poison the session.
    pub(super) fn note_normalization_failure(&mut self, tgid: u32) {
        if let Some(row) = self.domains.get_mut(&tgid) {
            if !Self::terminal(row.state) {
                row.state = contract::DOMAIN_RETIRED;
            }
        }
    }
    pub(super) fn retire(&mut self, tgid: u32) -> Result<(), ObservationGap> {
        let row = self
            .domains
            .get_mut(&tgid)
            .ok_or(ObservationGap::Invalidated)?;
        if !Self::terminal(row.state) {
            row.state = contract::DOMAIN_RETIRED;
        }
        Ok(())
    }
    pub(super) fn poison(&mut self, tgid: u32) -> Result<(), ObservationGap> {
        let row = self
            .domains
            .get_mut(&tgid)
            .ok_or(ObservationGap::Invalidated)?;
        if !Self::terminal(row.state) {
            row.state = contract::DOMAIN_POISON;
        }
        Ok(())
    }
    pub(super) fn state(&self, tgid: u32) -> Option<u64> {
        self.domains.get(&tgid).map(|row| row.state)
    }
}

/// After-open acquisition order. Legacy resources are fully reserved before
/// the gate opens; after the open the observer enrolls, sources anchor, the
/// sole required target links are adopted, and post-adoption READY publishes
/// before the held child is released. Every step is one-way; any failure
/// refuses the acquisition without disturbing legacy facts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum AcquisitionStage {
    LegacyReserved,
    GateOpen,
    ObserverEnrolled,
    SourceAnchored,
    LinksAdopted,
    ReadyPublished,
    Refused,
}
pub(super) struct AcquisitionOrder {
    stage: AcquisitionStage,
}
// Phase-2 native lease: transitions run only from the future after-open
// acquisition path, after source/artifact review plus explicit lease.
#[allow(dead_code)]
impl AcquisitionOrder {
    pub(super) fn new() -> Self {
        Self {
            stage: AcquisitionStage::LegacyReserved,
        }
    }
    pub(super) fn note_gate_open(&mut self) -> Result<(), ObservationGap> {
        if self.stage != AcquisitionStage::LegacyReserved {
            return Err(ObservationGap::Invalidated);
        }
        self.stage = AcquisitionStage::GateOpen;
        Ok(())
    }
    /// Observer enrollment binds the exact armed nonce to nonzero host
    /// coordinates derived through enrollment, never a guessed libc ID.
    pub(super) fn note_enrolled(
        &mut self,
        expected_nonce: u64,
        receipt: &EnrollmentReceipt,
    ) -> Result<(), ObservationGap> {
        if self.stage != AcquisitionStage::GateOpen
            || expected_nonce < contract::HOST_ID_FIRST
            || receipt.nonce != expected_nonce
            || receipt.host_pid_tgid == 0
        {
            return Err(ObservationGap::Invalidated);
        }
        self.stage = AcquisitionStage::ObserverEnrolled;
        Ok(())
    }
    pub(super) fn note_anchored(
        &mut self,
        ledger: &GuardLedger,
        anchor_id: u64,
    ) -> Result<(), ObservationGap> {
        if self.stage != AcquisitionStage::ObserverEnrolled || !ledger.anchor_live(anchor_id) {
            return Err(ObservationGap::Invalidated);
        }
        self.stage = AcquisitionStage::SourceAnchored;
        Ok(())
    }
    pub(super) fn note_links_adopted(
        &mut self,
        ledger: &GuardLedger,
        registration_id: u64,
    ) -> Result<(), ObservationGap> {
        if self.stage != AcquisitionStage::SourceAnchored || !ledger.adoption_live(registration_id)
        {
            return Err(ObservationGap::Invalidated);
        }
        self.stage = AcquisitionStage::LinksAdopted;
        Ok(())
    }
    /// READY publishes only after adoption, consuming the exact phase-4
    /// receipt: matching nonce and registration, one completed hook pair, a
    /// success verdict, and a nonzero publication sequence older than every
    /// consuming callback entry.
    pub(super) fn note_ready(
        &mut self,
        expected_nonce: u64,
        expected_registration: u64,
        receipt: &ReadyReceipt,
    ) -> Result<(), ObservationGap> {
        if self.stage != AcquisitionStage::LinksAdopted
            || receipt.nonce != expected_nonce
            || receipt.registration_id != expected_registration
            || receipt.entry_count != 1
            || receipt.exit_count != 1
            || receipt.verdict != VERDICT_SUCCESS
            || receipt.sequence == 0
        {
            return Err(ObservationGap::Invalidated);
        }
        self.stage = AcquisitionStage::ReadyPublished;
        Ok(())
    }
    /// Refuse the acquisition from any non-terminal stage. READY is terminal:
    /// published source evidence is revoked by guard retirement, never by
    /// regressing this order.
    pub(super) fn refuse(&mut self) -> Result<(), ObservationGap> {
        match self.stage {
            AcquisitionStage::ReadyPublished => Err(ObservationGap::Invalidated),
            AcquisitionStage::Refused => Ok(()),
            _ => {
                self.stage = AcquisitionStage::Refused;
                Ok(())
            }
        }
    }
    /// The held child may run only after post-adoption READY published.
    pub(super) fn child_may_release(&self) -> bool {
        self.stage == AcquisitionStage::ReadyPublished
    }
}

/// Observer-only provisional trigger custody. The built-in literal 16-byte
/// NoOp program (BPF_MOV64_IMM r0,0; BPF_EXIT: no helpers, maps, context
/// reads or mutation) supplies the enrollment, phase-1 anchor and phase-4
/// READY triggers. At most one provisional link is ever in flight, attached
/// only to the retained nonzero observer PID; it can never seed a target,
/// count, or act as source authority.
// Phase-2 native lease: FD slots fill only from the future trigger path.
#[allow(dead_code)]
pub(super) struct NoOpTrigger {
    provisional: Option<OwnedFd>,
    program: Option<OwnedFd>,
    observer_pid: u32,
}
// Phase-2 native lease: the PID gate runs from the future trigger path,
// after source/artifact review plus explicit lease. `new` is already live.
#[allow(dead_code)]
impl NoOpTrigger {
    pub(super) fn new(observer_pid: u32) -> Result<Self, ObservationGap> {
        if observer_pid == 0 {
            return Err(ObservationGap::Invalidated);
        }
        Ok(Self {
            provisional: None,
            program: None,
            observer_pid,
        })
    }
    /// A provisional trigger attaches only to the retained observer PID.
    /// PID 0 and any non-observer PID are refused, never retargeted.
    pub(super) fn check_observer_pid(&self, pid: u32) -> Result<(), ObservationGap> {
        if pid == 0 || pid != self.observer_pid {
            return Err(ObservationGap::Invalidated);
        }
        Ok(())
    }
}

/// Validated unloaded source roots plus their future program/link custody.
/// Fields drop in declaration order: links release before programs, and the
/// owner declares its roots before its maps so all FDs release before maps.
// Phase-2 native lease: retained bytes and the FUNC ID load only after
// source/artifact review plus explicit lease.
#[allow(dead_code)]
pub(super) struct RetainedSourceRoots {
    links: Vec<OwnedFd>,
    programs: Vec<OwnedFd>,
    noop: NoOpTrigger,
    prepared: loader::Prepared,
    attach_btf_id: u32,
}
impl RetainedSourceRoots {
    /// Exact admission for the source half: the four retained roots with
    /// their exact sections, no return-mode roots, an ADMIT fixup on every
    /// root, exactly the seven source maps with exact dimensions, and the
    /// validated nonzero registration FUNC ID. Pure and caps-free.
    pub(super) fn check(
        prepared: &loader::Prepared,
        attach_btf_id: u32,
    ) -> Result<(), ObservationGap> {
        if attach_btf_id == 0 {
            return Err(ObservationGap::InvalidObject);
        }
        let mut seen = [false; SOURCE_ROOT_COUNT];
        if prepared.progs.len() != SOURCE_ROOT_COUNT {
            return Err(ObservationGap::InvalidObject);
        }
        for root in &prepared.progs {
            let slot = match (root.name.as_str(), root.section.as_str()) {
                ("source_reg_in", "fentry/uprobe_register") => 0,
                ("source_reg_out", "fexit/uprobe_register") => 1,
                ("attr_exit", "raw_tracepoint/sched_process_exit") => 2,
                ("attr_exec", "raw_tracepoint/sched_process_exec") => 3,
                _ => return Err(ObservationGap::InvalidObject),
            };
            if root.is_return || seen[slot] {
                return Err(ObservationGap::InvalidObject);
            }
            seen[slot] = true;
            // ADMIT dominates every writer mutation: a root without the
            // shared-gate fixup can never load under this owner.
            if !root.map_fixups.iter().any(|fix| fix.map == "ADMIT") {
                return Err(ObservationGap::InvalidObject);
            }
        }
        if prepared.maps.len() != super::source_owner::MAPS.len() {
            return Err(ObservationGap::InvalidObject);
        }
        for spec in super::source_owner::MAPS {
            let found = prepared.maps.iter().find(|m| m.name == spec.name);
            let Some(found) = found else {
                return Err(ObservationGap::InvalidObject);
            };
            if found.map_type != spec.map_type
                || found.key_size != spec.key_size
                || found.value_size != spec.value_size
                || found.max_entries != spec.max_entries
                || found.flags != spec.flags
            {
                return Err(ObservationGap::InvalidObject);
            }
        }
        Ok(())
    }
    /// Move validated custody into the owner. Call `check` first; the owner
    /// does. Program/link FDs stay empty until the phase-2 native lease.
    pub(super) fn retain(
        prepared: loader::Prepared,
        attach_btf_id: u32,
        observer_pid: u32,
    ) -> Self {
        debug_assert!(Self::check(&prepared, attach_btf_id).is_ok());
        debug_assert!(observer_pid != 0);
        Self {
            links: Vec::new(),
            programs: Vec::new(),
            noop: NoOpTrigger {
                provisional: None,
                program: None,
                observer_pid,
            },
            prepared,
            attach_btf_id,
        }
    }
}

fn guard_value_bytes(epoch: u64, state: u64) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&epoch.to_ne_bytes());
    value[8..].copy_from_slice(&state.to_ne_bytes());
    value
}
/// Exact NOEXIST creation bytes for a PREPARING guard. The syscall is
/// injected so attribute tests run caps-free; production passes the real
/// map-update call.
fn guard_create_with(
    id: u64,
    epoch: u64,
    call: impl FnOnce(&[u8; 8], &[u8; 16], u64) -> std::io::Result<()>,
) -> std::io::Result<()> {
    call(
        &id.to_ne_bytes(),
        &guard_value_bytes(epoch, contract::GUARD_PREPARING),
        ossl_bpf_sys::BPF_NOEXIST,
    )
}
/// Exact must-update bytes for a guard transition. Creation uses NOEXIST;
/// every later transition requires the row to exist.
fn guard_advance_with(
    id: u64,
    epoch: u64,
    state: u64,
    call: impl FnOnce(&[u8; 8], &[u8; 16], u64) -> std::io::Result<()>,
) -> std::io::Result<()> {
    call(
        &id.to_ne_bytes(),
        &guard_value_bytes(epoch, state),
        ossl_bpf_sys::BPF_EXIST,
    )
}
// Phase-2 native lease: guard map effects run only from the future after-open
// acquisition path, after source/artifact review plus explicit lease.
#[allow(dead_code)]
impl GuardLedger {
    /// The ONLY adoption-guard creation path with a kernel effect. It takes
    /// the ENTRY receipt (plus the map FD), validates it against the minted
    /// record FIRST, performs the single NOEXIST PREPARING insert, then
    /// records PREPARING. No raw id/epoch creation entry point remains: an
    /// early insert — the exact operation that terminally poisons ENTRY
    /// fentry — cannot be expressed. A failed insert terminally conflicts
    /// the record, so a failed creation is structurally never retried.
    pub(super) fn create_adoption_guarded(
        &mut self,
        map_fd: std::os::fd::RawFd,
        id: u64,
        receipt: &EntryReceipt,
    ) -> Result<(), ObservationGap> {
        self.create_adoption_guarded_with(id, receipt, |key, value, flags| unsafe {
            ossl_bpf_sys::map_update_elem(map_fd, key, value, flags)
        })
    }
    /// Caps-free seam of the creation chokepoint: identical validation and
    /// bookkeeping with an injected insert operation. Tests drive schedules
    /// through this; production passes the real map-update call.
    pub(super) fn create_adoption_guarded_with(
        &mut self,
        id: u64,
        receipt: &EntryReceipt,
        call: impl FnOnce(&[u8; 8], &[u8; 16], u64) -> std::io::Result<()>,
    ) -> Result<(), ObservationGap> {
        // Receipt validation strictly precedes the injected insert: nothing
        // reaches the map without an exact terminal ENTRY receipt plus a
        // usable adopted FD for this minted ID.
        let epoch = self.validated_adoption_epoch(id, receipt)?;
        if guard_create_with(id, epoch, call).is_err() {
            // Terminal refusal: EEXIST in particular proves an ID or
            // lifecycle defect the host must not paper over with a second
            // insert. Validation above proved Minted on the serialized
            // owner, so conflict here is infallible in practice.
            self.fail_adoption(id)?;
            return Err(ObservationGap::BpfUnavailable);
        }
        // The insert succeeded; record PREPARING under the same receipt.
        self.create_adoption(id, receipt)
    }
    fn validated_adoption_epoch(
        &self,
        id: u64,
        receipt: &EntryReceipt,
    ) -> Result<u64, ObservationGap> {
        let guard = self
            .registrations
            .get(&id)
            .ok_or(ObservationGap::Invalidated)?;
        if guard.life != GuardLife::Minted
            || receipt.registration_id != id
            || guard.nonce != receipt.nonce
            || receipt.entry_count != 1
            || receipt.exit_count != 1
            || receipt.verdict != VERDICT_SUCCESS
            || !receipt.syscall_ok
        {
            return Err(ObservationGap::Invalidated);
        }
        Ok(guard.epoch)
    }
    pub(super) fn advance_guard(
        map_fd: std::os::fd::RawFd,
        id: u64,
        epoch: u64,
        state: u64,
    ) -> Result<(), ObservationGap> {
        guard_advance_with(id, epoch, state, |key, value, flags| unsafe {
            ossl_bpf_sys::map_update_elem(map_fd, key, value, flags)
        })
        .map_err(|_| ObservationGap::BpfUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn anchor_receipt(anchor_id: u64, nonce: u64) -> AnchorReceipt {
        AnchorReceipt {
            anchor_id,
            nonce,
            entry_count: 1,
            exit_count: 1,
            verdict: VERDICT_SUCCESS,
        }
    }
    fn entry_receipt(registration_id: u64, nonce: u64) -> EntryReceipt {
        EntryReceipt {
            nonce,
            registration_id,
            entry_count: 1,
            exit_count: 1,
            verdict: VERDICT_SUCCESS,
            syscall_ok: true,
        }
    }
    fn live_anchor() -> (HostIds, GuardLedger, u64, u64) {
        let mut ids = HostIds::new();
        let mut ledger = GuardLedger::new();
        let epoch = 7;
        let nonce = ids.fresh().unwrap();
        let anchor = ledger.mint_anchor(&mut ids, epoch, nonce).unwrap();
        ledger
            .create_anchor(anchor, &anchor_receipt(anchor, nonce))
            .unwrap();
        ledger.live_anchor(anchor).unwrap();
        assert!(ledger.anchor_live(anchor));
        (ids, ledger, anchor, epoch)
    }
    #[test]
    fn host_ids_mint_monotonic_upper_half_ids() {
        let mut ids = HostIds::new();
        let anchor = ids.fresh().unwrap();
        let adoption = ids.fresh().unwrap();
        let nonce = ids.fresh().unwrap();
        assert_eq!(anchor, contract::HOST_ID_FIRST);
        assert_eq!(adoption, contract::HOST_ID_FIRST + 1);
        assert_eq!(nonce, contract::HOST_ID_FIRST + 2);
        assert!(anchor < adoption && adoption < nonce);
        // The lower half stays reserved for kernel observation IDs.
        assert!(anchor > contract::KERNEL_ID_LAST);
    }
    #[test]
    fn host_ids_refuse_exhaustion_without_wrap_or_reuse() {
        let mut ids = HostIds::new();
        ids.next = u64::MAX - 1;
        assert_eq!(ids.fresh().unwrap(), u64::MAX - 1);
        assert!(matches!(ids.fresh(), Err(ObservationGap::StateLimit)));
        // The failed mint neither wraps nor consumes the exhausted value.
        assert_eq!(ids.next, u64::MAX);
        assert!(matches!(ids.fresh(), Err(ObservationGap::StateLimit)));
    }
    #[test]
    fn anchor_mint_binds_epoch_and_fresh_nonce() {
        let mut ids = HostIds::new();
        let mut ledger = GuardLedger::new();
        let nonce = ids.fresh().unwrap();
        let anchor = ledger.mint_anchor(&mut ids, 11, nonce).unwrap();
        assert_eq!(anchor, contract::HOST_ID_FIRST + 1);
        assert_ne!(anchor, nonce);
        assert!(!ledger.anchor_live(anchor));
        // Zero epochs never identify source authority.
        let spare = ids.fresh().unwrap();
        assert!(ledger.mint_anchor(&mut ids, 0, spare).is_err());
    }
    #[test]
    fn anchor_mint_refuses_collisions_and_caps() {
        let mut ids = HostIds::new();
        let mut ledger = GuardLedger::new();
        // A caller nonce below the host half is not a fresh host mint.
        assert!(ledger.mint_anchor(&mut ids, 1, 42).is_err());
        // A nonce equal to the about-to-mint ID collides by construction.
        assert!(
            ledger
                .mint_anchor(&mut ids, 1, contract::HOST_ID_FIRST)
                .is_err()
        );
        let nonce = ids.fresh().unwrap();
        ledger.mint_anchor(&mut ids, 1, nonce).unwrap();
        // The recorded nonce never repeats, even for a new anchor.
        assert!(ledger.mint_anchor(&mut ids, 1, nonce).is_err());
        for _ in 1..MAX_ANCHOR_GUARDS {
            let nonce = ids.fresh().unwrap();
            ledger.mint_anchor(&mut ids, 1, nonce).unwrap();
        }
        let nonce = ids.fresh().unwrap();
        assert!(matches!(
            ledger.mint_anchor(&mut ids, 1, nonce),
            Err(ObservationGap::StateLimit)
        ));
    }
    #[test]
    fn anchor_create_consumes_exact_phase1_receipt() {
        let mut ids = HostIds::new();
        let mut ledger = GuardLedger::new();
        let nonce = ids.fresh().unwrap();
        let anchor = ledger.mint_anchor(&mut ids, 3, nonce).unwrap();
        // Every inexact receipt refuses: wrong ID, wrong nonce, partial
        // counts, non-success verdict. Mint state survives each refusal.
        let mut bad = anchor_receipt(anchor + 100, nonce);
        assert!(ledger.create_anchor(anchor, &bad).is_err());
        bad = anchor_receipt(anchor, nonce + 100);
        assert!(ledger.create_anchor(anchor, &bad).is_err());
        for (entry, exit, verdict) in [
            (0, 1, 1),
            (1, 0, 1),
            (2, 1, 1),
            (1, 2, 1),
            (1, 1, 0),
            (1, 1, 2),
        ] {
            bad = AnchorReceipt {
                anchor_id: anchor,
                nonce,
                entry_count: entry,
                exit_count: exit,
                verdict,
            };
            assert!(ledger.create_anchor(anchor, &bad).is_err());
        }
        assert!(
            ledger
                .create_anchor(anchor, &anchor_receipt(anchor, nonce))
                .is_ok()
        );
        // Creation is one-shot: a second receipt for the same ID refuses.
        assert!(
            ledger
                .create_anchor(anchor, &anchor_receipt(anchor, nonce))
                .is_err()
        );
        // LIVE requires PREPARING first, then refuses to advance twice.
        assert!(ledger.live_anchor(anchor).is_ok());
        assert!(ledger.live_anchor(anchor).is_err());
        assert!(ledger.anchor_live(anchor));
    }
    #[test]
    fn registration_mint_requires_live_anchor_and_matching_epoch() {
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        // Unknown anchors and non-matching epochs never mint.
        let nonce = ids.fresh().unwrap();
        assert!(
            ledger
                .mint_registration(&mut ids, anchor + 500, epoch, nonce)
                .is_err()
        );
        let nonce = ids.fresh().unwrap();
        assert!(
            ledger
                .mint_registration(&mut ids, anchor, epoch + 1, nonce)
                .is_err()
        );
        // A merely minted (non-LIVE) anchor cannot back a registration.
        let mut ids = HostIds::new();
        let mut ledger = GuardLedger::new();
        let nonce = ids.fresh().unwrap();
        let pending = ledger.mint_anchor(&mut ids, 9, nonce).unwrap();
        let nonce = ids.fresh().unwrap();
        assert!(
            ledger
                .mint_registration(&mut ids, pending, 9, nonce)
                .is_err()
        );
        // The LIVE anchor mints exactly one registration per fresh nonce.
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        assert_ne!(registration, anchor);
        assert_ne!(registration, nonce);
        assert!(!ledger.adoption_live(registration));
    }
    #[test]
    fn registration_capacity_covers_typed_roles_and_callback_sites_on_one_anchor() {
        use super::super::{objects::TYPED_PUBLIC_ROLE_COUNT, schema::APIS};
        // Structural pin: the registration cap must cover every typed public
        // role on one anchor plus independently registered callback sites —
        // one registration per inventoried/operational API as the finite
        // callback population — with margin under the shared budgets.
        let required = TYPED_PUBLIC_ROLE_COUNT + APIS.len();
        assert_eq!(TYPED_PUBLIC_ROLE_COUNT, 17);
        assert!(MAX_REGISTRATION_GUARDS >= required);
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let mut minted = Vec::with_capacity(required);
        for _ in 0..required {
            let nonce = ids.fresh().unwrap();
            minted.push(
                ledger
                    .mint_registration(&mut ids, anchor, epoch, nonce)
                    .unwrap(),
            );
        }
        assert_eq!(minted.len(), required);
        minted.sort_unstable();
        minted.dedup();
        assert_eq!(minted.len(), required);
        // The cap still binds: fill to it, then the next mint refuses with a
        // capacity verdict, never an identity verdict.
        while ledger.registrations.len() < MAX_REGISTRATION_GUARDS {
            let nonce = ids.fresh().unwrap();
            ledger
                .mint_registration(&mut ids, anchor, epoch, nonce)
                .unwrap();
        }
        let nonce = ids.fresh().unwrap();
        assert!(matches!(
            ledger.mint_registration(&mut ids, anchor, epoch, nonce),
            Err(ObservationGap::StateLimit)
        ));
    }
    #[test]
    fn registration_guard_created_strictly_between_entry_and_return_fentries() {
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        // Before the ENTRY receipt the guard must not exist: RETURN cannot
        // arm, and the kernel would poison an early creation at ENTRY fentry.
        assert!(ledger.return_may_arm(registration).is_err());
        assert!(ledger.return_may_arm(registration + 500).is_err());
        // Every inexact ENTRY receipt refuses creation: wrong registration,
        // wrong nonce, partial or extra counts, non-success verdict, and a
        // failed native link call without a usable FD.
        let mut bad = entry_receipt(registration + 500, nonce);
        assert!(ledger.create_adoption(registration, &bad).is_err());
        bad = entry_receipt(registration, nonce + 500);
        assert!(ledger.create_adoption(registration, &bad).is_err());
        for (entry, exit, verdict, syscall) in [
            (0, 1, 1, true),
            (1, 0, 1, true),
            (2, 1, 1, true),
            (1, 2, 1, true),
            (1, 1, 0, true),
            (1, 1, 2, true),
            (1, 1, 1, false),
        ] {
            bad = EntryReceipt {
                nonce,
                registration_id: registration,
                entry_count: entry,
                exit_count: exit,
                verdict,
                syscall_ok: syscall,
            };
            assert!(ledger.create_adoption(registration, &bad).is_err());
        }
        // The exact ENTRY success receipt plus a usable FD creates PREPARING.
        assert!(
            ledger
                .create_adoption(registration, &entry_receipt(registration, nonce))
                .is_ok()
        );
        // Double creation refuses, mirroring the kernel's terminal poison on
        // a reused adoption ID at ENTRY fentry.
        assert!(
            ledger
                .create_adoption(registration, &entry_receipt(registration, nonce))
                .is_err()
        );
        // Only now may RETURN arm: strictly after ENTRY, strictly before.
        assert!(ledger.return_may_arm(registration).is_ok());
    }
    #[test]
    fn adoption_creation_trace_orders_entry_insert_before_return() {
        // Caps-free operation trace around the creation chokepoint: every
        // schedule below runs through `create_adoption_guarded_with` with an
        // injected insert, so no carrier FD or privilege is involved.
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        let mut events: Vec<&str> = Vec::new();
        let mut inserts = 0u32;
        // RETURN must not arm before ENTRY completes and the guard exists.
        assert!(ledger.return_may_arm(registration).is_err());
        events.push("return-refused-before-entry");
        // EARLY: a non-terminal ENTRY observation refuses with NO map effect,
        // and the mint survives for the later exact receipt.
        let pending = EntryReceipt {
            nonce,
            registration_id: registration,
            entry_count: 0,
            exit_count: 0,
            verdict: 0,
            syscall_ok: true,
        };
        assert!(
            ledger
                .create_adoption_guarded_with(registration, &pending, |_, _, _| {
                    inserts += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(inserts, 0);
        events.push("early-refused-without-insert");
        // ENTRY completes: the exact receipt drives exactly one NOEXIST
        // PREPARING insert with exact key/value bytes, then RETURN arms.
        events.push("entry");
        ledger
            .create_adoption_guarded_with(
                registration,
                &entry_receipt(registration, nonce),
                |key, value, flags| {
                    inserts += 1;
                    assert_eq!(key, &registration.to_ne_bytes());
                    assert_eq!(value, &guard_value_bytes(epoch, contract::GUARD_PREPARING));
                    assert_eq!(flags, ossl_bpf_sys::BPF_NOEXIST);
                    Ok(())
                },
            )
            .unwrap();
        events.push("insert-ok");
        ledger.return_may_arm(registration).unwrap();
        events.push("return-armed");
        // DUPLICATE: a second creation refuses with no second insert.
        assert!(
            ledger
                .create_adoption_guarded_with(
                    registration,
                    &entry_receipt(registration, nonce),
                    |_, _, _| {
                        inserts += 1;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert_eq!(inserts, 1);
        events.push("duplicate-refused-without-insert");
        assert_eq!(
            events,
            [
                "return-refused-before-entry",
                "early-refused-without-insert",
                "entry",
                "insert-ok",
                "return-armed",
                "duplicate-refused-without-insert",
            ]
        );
        // LATE: creation after the guard already went LIVE refuses with no
        // further insert.
        let late_nonce = ids.fresh().unwrap();
        let late = ledger
            .mint_registration(&mut ids, anchor, epoch, late_nonce)
            .unwrap();
        ledger
            .create_adoption_guarded_with(late, &entry_receipt(late, late_nonce), |_, _, _| {
                inserts += 1;
                Ok(())
            })
            .unwrap();
        ledger
            .live_adoption(
                late,
                &AdoptedLinks {
                    registration_id: late,
                    anchor_id: anchor,
                    epoch,
                    links: 1,
                },
            )
            .unwrap();
        assert!(
            ledger
                .create_adoption_guarded_with(late, &entry_receipt(late, late_nonce), |_, _, _| {
                    inserts += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(inserts, 2);
        // FAILED: a failed insert maps to BpfUnavailable (never a state
        // verdict), terminally conflicts the record, and is never retried: a
        // second attempt refuses with no second insert and RETURN never arms.
        let failed_nonce = ids.fresh().unwrap();
        let failed = ledger
            .mint_registration(&mut ids, anchor, epoch, failed_nonce)
            .unwrap();
        let error = ledger
            .create_adoption_guarded_with(
                failed,
                &entry_receipt(failed, failed_nonce),
                |_, _, _| {
                    inserts += 1;
                    Err(std::io::Error::from_raw_os_error(libc::EEXIST))
                },
            )
            .unwrap_err();
        assert_eq!(error, ObservationGap::BpfUnavailable);
        assert_eq!(inserts, 3);
        assert!(ledger.return_may_arm(failed).is_err());
        assert!(
            ledger
                .create_adoption_guarded_with(
                    failed,
                    &entry_receipt(failed, failed_nonce),
                    |_, _, _| {
                        inserts += 1;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert_eq!(inserts, 3);
        assert!(ledger.return_may_arm(failed).is_err());
    }
    #[test]
    fn adoption_live_requires_complete_adoption_proof() {
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        // LIVE before creation refuses, even with a well-formed proof.
        let proof = AdoptedLinks {
            registration_id: registration,
            anchor_id: anchor,
            epoch,
            links: 2,
        };
        assert!(ledger.live_adoption(registration, &proof).is_err());
        ledger
            .create_adoption(registration, &entry_receipt(registration, nonce))
            .unwrap();
        // The proof must bind the exact registration, anchor and epoch, and
        // must attest at least one adopted link: no partial READY exists.
        for tampered in [
            AdoptedLinks {
                registration_id: registration + 1,
                ..proof_fields(&proof)
            },
            AdoptedLinks {
                anchor_id: anchor + 1,
                ..proof_fields(&proof)
            },
            AdoptedLinks {
                epoch: epoch + 1,
                ..proof_fields(&proof)
            },
            AdoptedLinks {
                links: 0,
                ..proof_fields(&proof)
            },
        ] {
            assert!(ledger.live_adoption(registration, &tampered).is_err());
        }
        assert!(ledger.live_adoption(registration, &proof).is_ok());
        assert!(ledger.adoption_live(registration));
        // LIVE never advances twice.
        assert!(ledger.live_adoption(registration, &proof).is_err());
    }
    fn proof_fields(proof: &AdoptedLinks) -> AdoptedLinks {
        AdoptedLinks {
            registration_id: proof.registration_id,
            anchor_id: proof.anchor_id,
            epoch: proof.epoch,
            links: proof.links,
        }
    }
    #[test]
    fn guard_terminal_states_never_return_to_live() {
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        ledger
            .create_adoption(registration, &entry_receipt(registration, nonce))
            .unwrap();
        // Retire refuses minted IDs (abandon them) and unknown IDs.
        assert!(ledger.retire(registration + 900).is_err());
        let spare = ids.fresh().unwrap();
        let minted = ledger.mint_anchor(&mut ids, epoch, spare).unwrap();
        assert!(ledger.retire(minted).is_err());
        assert!(ledger.abandon(minted).is_ok());
        assert!(ledger.abandon(minted).is_err());
        assert!(ledger.retire(minted).is_err());
        // Created guards retire; retirement is idempotent for teardown.
        assert!(ledger.retire(registration).is_ok());
        assert!(ledger.retire(registration).is_ok());
        assert!(ledger.retire(anchor).is_ok());
        // Terminal rows never revive: no LIVE, no re-create, no re-arm.
        assert!(
            ledger
                .live_adoption(
                    registration,
                    &AdoptedLinks {
                        registration_id: registration,
                        anchor_id: anchor,
                        epoch,
                        links: 1,
                    }
                )
                .is_err()
        );
        assert!(ledger.live_anchor(anchor).is_err());
        assert!(
            ledger
                .create_anchor(anchor, &anchor_receipt(anchor, 1))
                .is_err()
        );
        assert!(
            ledger
                .create_adoption(registration, &entry_receipt(registration, nonce))
                .is_err()
        );
        assert!(ledger.return_may_arm(registration).is_err());
        assert!(!ledger.anchor_live(anchor));
        assert!(!ledger.adoption_live(registration));
        // Conflict is terminal too, and first-terminal-wins: a conflicted
        // guard stays Conflict through a later retire.
        let spare = ids.fresh().unwrap();
        let doomed = ledger.mint_anchor(&mut ids, epoch, spare).unwrap();
        assert!(ledger.fail_anchor(doomed).is_ok());
        assert!(ledger.fail_anchor(doomed).is_err());
        assert!(ledger.conflict(doomed).is_ok());
        assert!(ledger.retire(doomed).is_ok());
        assert!(ledger.live_anchor(doomed).is_err());
        assert!(ledger.conflict(anchor + 700).is_err());
    }
    #[test]
    fn guard_native_seams_use_exact_noexist_and_exist_bytes() {
        let id = contract::HOST_ID_FIRST + 9;
        let epoch = 21u64;
        let expected_key = id.to_ne_bytes();
        let mut expected_preparing = [0u8; 16];
        expected_preparing[..8].copy_from_slice(&epoch.to_ne_bytes());
        expected_preparing[8..].copy_from_slice(&contract::GUARD_PREPARING.to_ne_bytes());
        let mut calls = 0;
        guard_create_with(id, epoch, |key, value, flags| {
            calls += 1;
            assert_eq!(key, &expected_key);
            assert_eq!(value, &expected_preparing);
            assert_eq!(flags, ossl_bpf_sys::BPF_NOEXIST);
            Err(std::io::Error::from_raw_os_error(libc::EEXIST))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        let mut expected_live = [0u8; 16];
        expected_live[..8].copy_from_slice(&epoch.to_ne_bytes());
        expected_live[8..].copy_from_slice(&contract::GUARD_LIVE.to_ne_bytes());
        let mut calls = 0;
        guard_advance_with(id, epoch, contract::GUARD_LIVE, |key, value, flags| {
            calls += 1;
            assert_eq!(key, &expected_key);
            assert_eq!(value, &expected_live);
            assert_eq!(flags, ossl_bpf_sys::BPF_EXIST);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        // Native-failure mapping to BpfUnavailable is pinned by the creation
        // operation-trace test through the guarded chokepoint.
    }
    #[test]
    fn domain_arm_binds_held_custody_and_charges_claim() {
        let mut domains = DomainIndex::new();
        assert_eq!(domains.claims, 1);
        let custody = OriginalCustody { tgid: 4242 };
        domains.arm(4242, 5, 6, 7, &custody).unwrap();
        assert_eq!(domains.claims, 2);
        let row = domains.domains.get(&4242).unwrap();
        assert_eq!(row.process_incarnation, 5);
        assert_eq!(row.original_image, 6);
        assert_eq!(row.planned_image, 7);
        assert_eq!(row.current_image, 6);
        assert_eq!(row.state, contract::DOMAIN_ARMED);
        assert_eq!(row.loss_epoch, 0);
        assert_eq!(row.reserved, [0, 0]);
        assert_eq!(domains.state(4242), Some(contract::DOMAIN_ARMED));
        assert_eq!(domains.state(9999), None);
    }
    #[test]
    fn domain_arm_refuses_identity_and_capacity_violations() {
        let mut domains = DomainIndex::new();
        let custody = OriginalCustody { tgid: 100 };
        // Zero TGID, mismatched custody, zero identities, and a planned
        // image equal to the original (which the kernel would retire).
        assert!(
            domains
                .arm(0, 1, 2, 3, &OriginalCustody { tgid: 0 })
                .is_err()
        );
        assert!(
            domains
                .arm(100, 1, 2, 3, &OriginalCustody { tgid: 101 })
                .is_err()
        );
        assert!(domains.arm(100, 0, 2, 3, &custody).is_err());
        assert!(domains.arm(100, 1, 0, 3, &custody).is_err());
        assert!(domains.arm(100, 1, 2, 0, &custody).is_err());
        assert!(domains.arm(100, 1, 2, 2, &custody).is_err());
        domains.arm(100, 1, 2, 3, &custody).unwrap();
        // A TGID is never re-armed, even after retirement: tombstones stay.
        domains.retire(100).unwrap();
        assert!(domains.arm(100, 4, 5, 6, &custody).is_err());
        for tgid in 101..101 + MAX_DOMAINS as u32 - 1 {
            domains
                .arm(tgid, 1, 2, 3, &OriginalCustody { tgid })
                .unwrap();
        }
        assert!(matches!(
            domains.arm(9000, 1, 2, 3, &OriginalCustody { tgid: 9000 }),
            Err(ObservationGap::StateLimit)
        ));
        // The shared 8192 logical budget binds host claims too.
        let mut domains = DomainIndex::new();
        domains.claims = 8192;
        assert!(matches!(
            domains.arm(50, 1, 2, 3, &OriginalCustody { tgid: 50 }),
            Err(ObservationGap::StateLimit)
        ));
    }
    #[test]
    fn planned_exec_is_one_consumable_transition() {
        let mut domains = DomainIndex::new();
        let custody = OriginalCustody { tgid: 77 };
        domains.arm(77, 1, 10, 11, &custody).unwrap();
        // A mismatched exec image retires instead of activating.
        domains.note_planned_exec(77, 12).unwrap();
        assert_eq!(domains.state(77), Some(contract::DOMAIN_RETIRED));
        let mut domains = DomainIndex::new();
        domains
            .arm(78, 1, 10, 11, &OriginalCustody { tgid: 78 })
            .unwrap();
        domains.note_planned_exec(78, 11).unwrap();
        assert_eq!(domains.state(78), Some(contract::DOMAIN_ACTIVE));
        assert_eq!(domains.domains.get(&78).unwrap().current_image, 11);
        // A second exec on an ACTIVE domain retires: one-shot only.
        domains.note_planned_exec(78, 11).unwrap();
        assert_eq!(domains.state(78), Some(contract::DOMAIN_RETIRED));
        assert!(domains.note_planned_exec(7979, 11).is_err());
    }
    #[test]
    fn planned_exec_preserves_first_terminal_state() {
        let mut domains = DomainIndex::new();
        domains
            .arm(70, 1, 10, 11, &OriginalCustody { tgid: 70 })
            .unwrap();
        domains.poison(70).unwrap();
        // Exec on a poisoned domain must not overwrite POISON with RETIRED.
        domains.note_planned_exec(70, 11).unwrap();
        assert_eq!(domains.state(70), Some(contract::DOMAIN_POISON));
        domains.note_planned_exec(70, 12).unwrap();
        assert_eq!(domains.state(70), Some(contract::DOMAIN_POISON));
        domains
            .arm(71, 1, 10, 11, &OriginalCustody { tgid: 71 })
            .unwrap();
        domains.retire(71).unwrap();
        domains.note_planned_exec(71, 11).unwrap();
        assert_eq!(domains.state(71), Some(contract::DOMAIN_RETIRED));
    }
    #[test]
    fn normalization_failure_retires_only_seeded_domains() {
        let mut domains = DomainIndex::new();
        // Unseeded TGIDs are ignored: no certificates exist to retire.
        domains.note_normalization_failure(31337);
        let custody = OriginalCustody { tgid: 60 };
        domains.arm(60, 1, 2, 3, &custody).unwrap();
        domains.note_normalization_failure(60);
        assert_eq!(domains.state(60), Some(contract::DOMAIN_RETIRED));
        // Terminal rows keep their first terminal state.
        domains.note_normalization_failure(60);
        assert_eq!(domains.state(60), Some(contract::DOMAIN_RETIRED));
        let mut domains = DomainIndex::new();
        domains
            .arm(61, 1, 2, 3, &OriginalCustody { tgid: 61 })
            .unwrap();
        domains.poison(61).unwrap();
        domains.note_normalization_failure(61);
        assert_eq!(domains.state(61), Some(contract::DOMAIN_POISON));
    }
    #[test]
    fn domain_retire_and_poison_are_terminal() {
        let mut domains = DomainIndex::new();
        assert!(domains.retire(5).is_err());
        assert!(domains.poison(5).is_err());
        domains
            .arm(5, 1, 2, 3, &OriginalCustody { tgid: 5 })
            .unwrap();
        assert!(domains.retire(5).is_ok());
        assert!(domains.retire(5).is_ok());
        // First terminal state wins across retire/poison.
        assert!(domains.poison(5).is_ok());
        assert_eq!(domains.state(5), Some(contract::DOMAIN_RETIRED));
        domains
            .arm(6, 1, 2, 3, &OriginalCustody { tgid: 6 })
            .unwrap();
        assert!(domains.poison(6).is_ok());
        assert!(domains.retire(6).is_ok());
        assert_eq!(domains.state(6), Some(contract::DOMAIN_POISON));
    }
    fn adopted_ledger() -> (HostIds, GuardLedger, u64, u64) {
        let (mut ids, mut ledger, anchor, epoch) = live_anchor();
        let nonce = ids.fresh().unwrap();
        let registration = ledger
            .mint_registration(&mut ids, anchor, epoch, nonce)
            .unwrap();
        ledger
            .create_adoption(registration, &entry_receipt(registration, nonce))
            .unwrap();
        ledger
            .live_adoption(
                registration,
                &AdoptedLinks {
                    registration_id: registration,
                    anchor_id: anchor,
                    epoch,
                    links: 2,
                },
            )
            .unwrap();
        assert!(ledger.adoption_live(registration));
        (ids, ledger, anchor, registration)
    }
    #[test]
    fn acquisition_order_runs_legacy_to_ready_before_child_release() {
        let (mut ids, ledger, anchor, registration) = adopted_ledger();
        let mut order = AcquisitionOrder::new();
        assert!(!order.child_may_release());
        order.note_gate_open().unwrap();
        assert!(!order.child_may_release());
        let nonce = ids.fresh().unwrap();
        order
            .note_enrolled(
                nonce,
                &EnrollmentReceipt {
                    nonce,
                    host_pid_tgid: (99u64 << 32) | 99,
                },
            )
            .unwrap();
        assert!(!order.child_may_release());
        order.note_anchored(&ledger, anchor).unwrap();
        assert!(!order.child_may_release());
        order.note_links_adopted(&ledger, registration).unwrap();
        assert!(!order.child_may_release());
        let ready_nonce = ids.fresh().unwrap();
        let ready = ReadyReceipt {
            nonce: ready_nonce,
            registration_id: registration,
            entry_count: 1,
            exit_count: 1,
            verdict: VERDICT_SUCCESS,
            sequence: 41,
        };
        // A zero sequence is never a READY receipt.
        let mut bad = ReadyReceipt {
            sequence: 0,
            ..ready_fields(&ready)
        };
        assert!(order.note_ready(ready_nonce, registration, &bad).is_err());
        bad = ReadyReceipt {
            nonce: ready_nonce + 1,
            ..ready_fields(&ready)
        };
        assert!(order.note_ready(ready_nonce, registration, &bad).is_err());
        order.note_ready(ready_nonce, registration, &ready).unwrap();
        assert!(order.child_may_release());
    }
    fn ready_fields(receipt: &ReadyReceipt) -> ReadyReceipt {
        ReadyReceipt {
            nonce: receipt.nonce,
            registration_id: receipt.registration_id,
            entry_count: receipt.entry_count,
            exit_count: receipt.exit_count,
            verdict: receipt.verdict,
            sequence: receipt.sequence,
        }
    }
    #[test]
    fn acquisition_order_refuses_skips_and_regression() {
        let (mut ids, ledger, anchor, registration) = adopted_ledger();
        let mut order = AcquisitionOrder::new();
        // No step runs before its predecessor.
        let nonce = ids.fresh().unwrap();
        assert!(
            order
                .note_enrolled(
                    nonce,
                    &EnrollmentReceipt {
                        nonce,
                        host_pid_tgid: 1,
                    }
                )
                .is_err()
        );
        assert!(order.note_anchored(&ledger, anchor).is_err());
        assert!(order.note_links_adopted(&ledger, registration).is_err());
        let early = ReadyReceipt {
            nonce,
            registration_id: registration,
            entry_count: 1,
            exit_count: 1,
            verdict: VERDICT_SUCCESS,
            sequence: 1,
        };
        assert!(order.note_ready(nonce, registration, &early).is_err());
        order.note_gate_open().unwrap();
        assert!(order.note_gate_open().is_err());
        // Enrollment binds the exact armed nonce and nonzero host coords.
        assert!(
            order
                .note_enrolled(
                    nonce,
                    &EnrollmentReceipt {
                        nonce: nonce + 1,
                        host_pid_tgid: 1,
                    }
                )
                .is_err()
        );
        assert!(
            order
                .note_enrolled(
                    nonce,
                    &EnrollmentReceipt {
                        nonce,
                        host_pid_tgid: 0,
                    }
                )
                .is_err()
        );
        order
            .note_enrolled(
                nonce,
                &EnrollmentReceipt {
                    nonce,
                    host_pid_tgid: 1,
                },
            )
            .unwrap();
        // Anchoring and adoption require actually LIVE guards.
        assert!(order.note_anchored(&ledger, anchor + 300).is_err());
        order.note_anchored(&ledger, anchor).unwrap();
        assert!(
            order
                .note_links_adopted(&ledger, registration + 300)
                .is_err()
        );
        assert!(order.note_anchored(&ledger, anchor).is_err());
        order.note_links_adopted(&ledger, registration).unwrap();
        assert!(order.note_links_adopted(&ledger, registration).is_err());
        let ready_nonce = ids.fresh().unwrap();
        let ready = ReadyReceipt {
            nonce: ready_nonce,
            registration_id: registration,
            entry_count: 1,
            exit_count: 1,
            verdict: VERDICT_SUCCESS,
            sequence: 2,
        };
        order.note_ready(ready_nonce, registration, &ready).unwrap();
        // READY never regresses; refusal after READY refuses.
        let later = ReadyReceipt {
            sequence: 3,
            ..ready_fields(&ready)
        };
        assert!(order.note_ready(ready_nonce, registration, &later).is_err());
        assert!(order.refuse().is_err());
        assert!(order.child_may_release());
        // Refusal from a middle stage is terminal and blocks release.
        let mut order = AcquisitionOrder::new();
        order.note_gate_open().unwrap();
        order.refuse().unwrap();
        assert!(order.refuse().is_ok());
        assert!(order.note_gate_open().is_err());
        assert!(!order.child_may_release());
    }
    fn valid_source_prepared() -> loader::Prepared {
        let progs = [
            ("source_reg_in", "fentry/uprobe_register"),
            ("source_reg_out", "fexit/uprobe_register"),
            ("attr_exit", "raw_tracepoint/sched_process_exit"),
            ("attr_exec", "raw_tracepoint/sched_process_exec"),
        ]
        .into_iter()
        .map(|(name, section)| loader::PreparedProg {
            name: name.to_string(),
            section: section.to_string(),
            is_return: false,
            insns: Vec::new(),
            map_fixups: vec![loader::MapFixup {
                insn_off: 0,
                map: "ADMIT".to_string(),
            }],
            subprogs: Vec::new(),
        })
        .collect();
        let maps = super::super::source_owner::MAPS
            .into_iter()
            .map(|spec| loader::MapSpecLite {
                name: spec.name.to_string(),
                map_type: spec.map_type,
                key_size: spec.key_size,
                value_size: spec.value_size,
                max_entries: spec.max_entries,
                flags: spec.flags,
            })
            .collect();
        loader::Prepared { progs, maps }
    }
    #[test]
    fn source_half_check_admits_exact_roots_and_maps() {
        let prepared = valid_source_prepared();
        assert_eq!(prepared.progs.len(), SOURCE_ROOT_COUNT);
        assert_eq!(prepared.maps.len(), super::super::source_owner::MAPS.len());
        RetainedSourceRoots::check(&prepared, 1234).unwrap();
        let roots = RetainedSourceRoots::retain(prepared, 1234, 5678);
        assert_eq!(roots.attach_btf_id, 1234);
        assert_eq!(roots.noop.observer_pid, 5678);
        // Phase-1 retention holds no program or link FDs: mode stays 0 and
        // no root is loaded or attached.
        assert!(roots.programs.is_empty());
        assert!(roots.links.is_empty());
        assert!(roots.noop.program.is_none());
        assert!(roots.noop.provisional.is_none());
    }
    #[test]
    fn source_half_check_refuses_shape_drift() {
        // Zero registration FUNC IDs never admit a tracing root.
        assert!(RetainedSourceRoots::check(&valid_source_prepared(), 0).is_err());
        // Missing, extra, duplicated or renamed roots all refuse.
        let mut prepared = valid_source_prepared();
        prepared.progs.pop();
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.progs.push(loader::PreparedProg {
            name: "observation_entry".to_string(),
            section: "uprobe".to_string(),
            is_return: false,
            insns: Vec::new(),
            map_fixups: vec![loader::MapFixup {
                insn_off: 0,
                map: "ADMIT".to_string(),
            }],
            subprogs: Vec::new(),
        });
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.progs[0].name = "source_reg_out".to_string();
        prepared.progs[0].section = "fexit/uprobe_register".to_string();
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.progs[2].section = "raw_tracepoint/sched_process_fork".to_string();
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        // Return-mode roots and roots without the ADMIT fixup refuse: ADMIT
        // must dominate every writer mutation.
        let mut prepared = valid_source_prepared();
        prepared.progs[1].is_return = true;
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.progs[3].map_fixups.clear();
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        // Maps must match the seven source specs exactly: no missing, extra
        // or redimensioned map.
        let mut prepared = valid_source_prepared();
        prepared.maps.pop();
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.maps[0].max_entries += 1;
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
        let mut prepared = valid_source_prepared();
        prepared.maps.push(loader::MapSpecLite {
            name: "ADMIT".to_string(),
            map_type: 12,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
            flags: 0,
        });
        assert!(RetainedSourceRoots::check(&prepared, 7).is_err());
    }
    #[test]
    fn noop_trigger_binds_observer_pid_only() {
        assert!(NoOpTrigger::new(0).is_err());
        let trigger = NoOpTrigger::new(97531).unwrap();
        assert!(trigger.check_observer_pid(97531).is_ok());
        assert!(trigger.check_observer_pid(0).is_err());
        assert!(trigger.check_observer_pid(97532).is_err());
        assert!(trigger.check_observer_pid(u32::MAX).is_err());
    }
}
