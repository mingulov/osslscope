// SPDX-License-Identifier: GPL-2.0-only
//! Kernel typed attribution producer (first MAC/KDF slice). Public fetch and
//! context roles plus copied provider-callback roles stage 304-byte pending
//! transactions, publish REL kinds 6-14 rows with exact-name/digest indexes
//! and the safe selector dictionary, and resolve operational callbacks to
//! per-CPU partition aggregates in the same focused handler after the
//! physical store. All opaque handles stay kernel-private; the host sees only
//! observer-issued IDs through the selector dictionary and partition map.
//!
//! Inert unless every gate holds: writer-gate admission (checked by the
//! calling program), `ATTRIB_CONTROL` admitted mode with exact nonzero
//! coordinates, per-(site, process, image) typed admission plus site bind,
//! that site's `SOURCE_READY` row with both guards `LIVE` and a publication
//! sequence at or before the captured entry sequence. Any miss leaves the
//! physical hit unresolved; nothing here invents attribution.
use crate::{
    shared_maps::{
        ATTRIB_CONTROL, BIND_PENDING, DIGEST_INDEX, EXACT_NAME, PARTITION, PRODUCER_LOSS, REL,
        SEGMENT_INDEX, SELECTOR_DICT, SITE_BIND, SOURCE_CONFIG, SOURCE_DOMAIN, SOURCE_GUARD,
        THREAD_IDENTITY, TYPED_ADMISSION,
    },
    source_vma, writer_gate,
};
use aya_ebpf::{
    helpers,
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use core::ptr::addr_of_mut;
use osslscope_bpf_contract::{
    attribution::*,
    source::{DOMAIN_ACTIVE, DOMAIN_LIVE, GUARD_LIVE, SOURCE_ANCHOR, SOURCE_READY, SOURCE_REG},
};

/// Kernel UAPI insert flags; aya-ebpf exposes no consts.
const BPF_NOEXIST: u64 = 1;

/// Producer loss cells in `PRODUCER_LOSS`. Cells 5-7 are reserved zero.
const LOSS_CHARGE: u32 = 0;
const LOSS_MAP: u32 = 1;
const LOSS_PAIR: u32 = 2;
const LOSS_POISON: u32 = 3;
const LOSS_CONFLICT: u32 = 4;

#[inline(always)]
unsafe fn ordered_read(pointer: *mut u64) -> u64 {
    core::intrinsics::atomic_cxchg::<
        u64,
        { core::intrinsics::AtomicOrdering::SeqCst },
        { core::intrinsics::AtomicOrdering::SeqCst },
    >(pointer, 0, 0)
    .0
}
#[inline(always)]
unsafe fn compare(pointer: *mut u64, old: u64, new: u64) -> bool {
    core::intrinsics::atomic_cxchg::<
        u64,
        { core::intrinsics::AtomicOrdering::SeqCst },
        { core::intrinsics::AtomicOrdering::SeqCst },
    >(pointer, old, new)
    .1
}
#[inline(always)]
unsafe fn exchange(pointer: *mut u64, new: u64) {
    core::intrinsics::atomic_xchg::<u64, { core::intrinsics::AtomicOrdering::SeqCst }>(
        pointer, new,
    );
}

#[inline(always)]
fn loss(cell: u32) {
    if let Some(slot) = PRODUCER_LOSS.get_ptr_mut(cell) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Resolved target-domain coordinates for one typed read. The entry sequence
/// is captured before any attribution decision or physical mutation; every
/// selected owner and dependency must already be published in that snapshot.
pub(crate) struct Target {
    process: u64,
    image: u64,
    relation: u64,
    loss_epoch: u64,
    entry_seq: u64,
}

/// BPF subprograms take at most five register arguments and share one
/// 512-byte stack across the whole call chain. Paired entry handlers borrow
/// the root's Target storage and revalidate its captured sequence; other
/// handlers retain their scalar/map interfaces. Cookies and operands come
/// from the probe context, clocks from the helper, and pending fields from
/// their frame pointer. Packed thread identifiers carry `(tgid << 32) | tid`
/// in one register argument.
#[inline(always)]
fn split_ids(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

/// Pending-frame staging parameters, consumed by inlined bookkeeping.
pub(crate) struct StageParams<'a> {
    target: &'a Target,
    thread: u64,
    cookie: u64,
    role: u32,
    occurrence: u64,
    now_ns: u64,
}

/// Tombstone parameters, built inside the inlined quarantine wrapper.
pub(crate) struct Tombstone<'a> {
    control: *mut ProducerControl,
    target: &'a Target,
    handle: u64,
    domain: u64,
    reason: u64,
    occurrence: u64,
    now_ns: u64,
}

/// Same-handler operational parameters, built by the focused counter.
pub struct OpParams {
    pub cookie: u64,
    pub tgid: u32,
    pub generation: u32,
    pub now_ns: u64,
    pub entry_seq: u64,
}

/// Commit-plan staging layout in the per-CPU cell's second half. The owner
/// commit splits into a shallow bind-preparation call (validation, digest,
/// ID allocation) and a shallow locked publication call; the plan crosses
/// between them in per-CPU staging, which is sound because BPF runs
/// non-preemptibly (no same-CPU interleaver, no migration mid-program) and
/// each CPU has its own cell. Offsets in bytes from the cell base:
/// `[144..176)` the 32-byte request digest (create path only);
/// `[176..184)` selector ID, `[184..192)` dictionary epoch,
/// `[192..200)` code object (reuse path carries all three, create path the
/// object only); `[200..208)` owner ID, `[208..216)` continuity ID,
/// `[216..224)` context epoch, `[224..232)` prepared set ID,
/// `[232..240)` OBJECT_SELECTOR relation ID. Bytes `[240..256)` are spare
/// zero. The digest/message/key scratches live in `[0..192)` and are dead
/// before the plan is consumed.
const PLAN_DIGEST: usize = 144;
const PLAN_SELECTOR: usize = 176;
const PLAN_EPOCH: usize = 184;
const PLAN_OBJECT: usize = 192;
const PLAN_OWNER: usize = 200;
const PLAN_CONTINUITY: usize = 208;
const PLAN_CONTEXT_EPOCH: usize = 216;
const PLAN_SET: usize = 224;
const PLAN_SELECTOR_RELATION: usize = 232;

/// Commit-tail arguments staged in per-CPU cell 1. The locked worker builds
/// this block at `[0..168)` AFTER the bound-selector phase (whose OBJECT
/// build clobbers cell 0), then runs the ordered tail — X flip, U index,
/// OWNER_SELECTOR, OWNER — as shallow one-argument subprograms. One pointer
/// crosses the five-argument call boundary instead of fourteen scalars, and
/// the worker holds almost nothing live across each call, so the shared
/// 512-byte stack stays shallow. Cell 1 survives the whole tail because
/// every `RelValue` build stages in cell 0; no tail step writes cell 1.
///
/// Discipline: every tail subprogram copies the fields it needs into locals
/// FIRST, before any cell-0 staging use, and never writes cell 1.
const TAIL_SLOT: u32 = 1;
#[repr(C)]
pub(crate) struct TailArgs {
    process: u64,
    image: u64,
    relation: u64,
    owner: u64,
    owner_id: u64,
    staged_x: u64,
    occurrence: u64,
    next_seq: u64,
    family: u64,
    now_ns: u64,
    request: u64,
    source_epoch: u64,
    method: u64,
    method_observation: u64,
    provider: u64,
    continuity: u64,
    set_id: u64,
    context_epoch: u64,
    object: u64,
    selector: u64,
    epoch: u64,
}
const TAIL_PROCESS: usize = 0;
const TAIL_IMAGE: usize = 8;
const TAIL_RELATION: usize = 16;
const TAIL_OWNER: usize = 24;
const TAIL_OWNER_ID: usize = 32;
const TAIL_STAGED_X: usize = 40;
const TAIL_OCCURRENCE: usize = 48;
const TAIL_NEXT_SEQ: usize = 56;
const TAIL_FAMILY: usize = 64;
const TAIL_NOW_NS: usize = 72;
const TAIL_REQUEST: usize = 80;
const TAIL_SOURCE_EPOCH: usize = 88;
const TAIL_METHOD: usize = 96;
const TAIL_METHOD_OBSERVATION: usize = 104;
const TAIL_PROVIDER: usize = 112;
const TAIL_CONTINUITY: usize = 120;
const TAIL_SET: usize = 128;
const TAIL_CONTEXT_EPOCH: usize = 136;
const TAIL_OBJECT: usize = 144;
const TAIL_SELECTOR: usize = 152;
const TAIL_EPOCH: usize = 160;

#[inline(always)]
fn control_cell() -> Option<*mut ProducerControl> {
    ATTRIB_CONTROL.get_ptr_mut(0)
}

/// Full producer gate: admitted control cell plus a live target domain.
/// Returns `None` (quiet, unresolved) unless every coordinate is exact.
/// The entry sequence is captured here for typed entry/return paths; the
/// operational path passes the sequence its handler captured before the
/// physical store, so dependencies must predate the hit itself.
#[inline(always)]
fn resolve_target(tgid: u32) -> Option<Target> {
    let state = crate::shared_maps::ATTR_STATE.get_ptr_mut(0)?;
    let entry_seq = unsafe { ordered_read(addr_of_mut!((*state).published_sequence)) };
    let mut target: Target = unsafe { core::mem::zeroed() };
    if resolve_inner(tgid, entry_seq, &mut target) {
        Some(target)
    } else {
        None
    }
}

#[no_mangle]
pub fn resolve_inner(tgid: u32, entry_seq: u64, out: &mut Target) -> bool {
    match resolve_inner_opt(tgid, entry_seq) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn resolve_inner_opt(tgid: u32, entry_seq: u64) -> Option<Target> {
    let control = control_cell()?;
    let admitted = unsafe {
        (*control).producer_mode == PRODUCER_ADMITTED
            && (*control).session_id != 0
            && (*control).admission_epoch != 0
            && (*control).cut_id != 0
            && (*control).next_producer_id != 0
            && (*control).relation_epoch != 0
            && (*control).loss_epoch != 0
            && (*control).reserved == 0
    };
    if !admitted {
        return None;
    }
    let domain = SOURCE_DOMAIN.get_ptr_mut(&tgid)?;
    let (process, image, live) = unsafe {
        let state = ordered_read(addr_of_mut!((*domain).state));
        let current = ordered_read(addr_of_mut!((*domain).current_image));
        let live = matches!(state, DOMAIN_LIVE | DOMAIN_ACTIVE)
            && current != 0
            && (*domain).process_incarnation != 0
            && (*domain).reserved == [0, 0]
            && ordered_read(addr_of_mut!((*domain).state)) == state;
        ((*domain).process_incarnation, current, live)
    };
    if !live {
        return None;
    }
    let (relation, loss_epoch) = unsafe { ((*control).relation_epoch, (*control).loss_epoch) };
    if relation == 0 || loss_epoch == 0 {
        return None;
    }
    Some(Target {
        process,
        image,
        relation,
        loss_epoch,
        entry_seq,
    })
}

/// Retirement-only process lookup: no state or mode gate, so exit/exec roots
/// retire rows in every domain state. A missing domain means this TGID never
/// held producer state, so there is nothing to retire.
#[inline(always)]
fn process_of(tgid: u32) -> Option<u64> {
    let domain = SOURCE_DOMAIN.get_ptr_mut(&tgid)?;
    let process = unsafe { (*domain).process_incarnation };
    (process != 0).then_some(process)
}

/// Allocate one fresh nonzero observer ID from the session allocator. IDs are
/// never derived from pointers or hashes and never reused; wrap poisons the
/// producer terminally instead of recycling an ID.
#[no_mangle]
pub fn alloc_id(control: *mut ProducerControl, out: &mut u64) -> bool {
    match alloc_id_opt(control) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn alloc_id_opt(control: *mut ProducerControl) -> Option<u64> {
    let next = unsafe { addr_of_mut!((*control).next_producer_id) };
    let mut current = unsafe { ordered_read(next) };
    for _ in 0..8 {
        if current == 0 || current == u64::MAX {
            unsafe { exchange(addr_of_mut!((*control).producer_mode), PRODUCER_POISONED) };
            loss(LOSS_POISON);
            return None;
        }
        let observed = unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::SeqCst },
                { core::intrinsics::AtomicOrdering::SeqCst },
            >(next, current, current + 1)
        };
        if observed.1 {
            return Some(current);
        }
        current = observed.0;
    }
    None
}

/// Charge logical relationship/index/projection/thread/tombstone rows against
/// the shared 8192 budget on `ATTR_STATE.relationship_claims`, the same
/// counter the source publisher charges. Failed or partial work never
/// refunds; exhaustion fails the transaction, never evicts silently.
#[no_mangle]
pub fn spend(amount: u64) -> bool {
    if amount == 0 || amount > MAX_RELATIONSHIPS as u64 {
        return false;
    }
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let claims = unsafe { addr_of_mut!((*state).relationship_claims) };
    let mut current = unsafe { ordered_read(claims) };
    for _ in 0..8 {
        if current > MAX_RELATIONSHIPS as u64 - amount {
            loss(LOSS_CHARGE);
            return false;
        }
        let (observed, charged) = unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::SeqCst },
                { core::intrinsics::AtomicOrdering::SeqCst },
            >(claims, current, current + amount)
        };
        if charged {
            return true;
        }
        current = observed;
    }
    loss(LOSS_CHARGE);
    false
}

/// Poison the relation domain: advance both epochs under the shared publisher
/// lock so every current-epoch row (METHOD, X/U indexes, in-flight frames)
/// becomes unreachable for new positives while already emitted partitions
/// stay immutable. A contended lock poisons by terminal mode instead, which
/// is strictly stronger. Already-terminal control stays quiet.
#[no_mangle]
pub fn poison_domain() {
    loss(LOSS_POISON);
    let Some(control) = control_cell() else {
        return;
    };
    let mode = unsafe { addr_of_mut!((*control).producer_mode) };
    if unsafe { ordered_read(mode) } != PRODUCER_ADMITTED {
        return;
    }
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        unsafe { exchange(mode, PRODUCER_POISONED) };
        return;
    };
    let busy = unsafe { addr_of_mut!((*state).publication_busy) };
    let mut locked = false;
    for _ in 0..8 {
        if unsafe { compare(busy, 0, 1) } {
            locked = true;
            break;
        }
    }
    if !locked {
        unsafe { exchange(mode, PRODUCER_POISONED) };
        return;
    }
    let relation = unsafe { addr_of_mut!((*control).relation_epoch) };
    let loss_epoch = unsafe { addr_of_mut!((*control).loss_epoch) };
    let current_relation = unsafe { ordered_read(relation) };
    let current_loss = unsafe { ordered_read(loss_epoch) };
    if current_relation == 0
        || current_loss == 0
        || current_relation == u64::MAX
        || current_loss == u64::MAX
        || unsafe { ordered_read(mode) } != PRODUCER_ADMITTED
    {
        unsafe { exchange(mode, PRODUCER_POISONED) };
    } else {
        unsafe {
            compare(relation, current_relation, current_relation + 1);
            compare(loss_epoch, current_loss, current_loss + 1);
        }
    }
    unsafe {
        compare(busy, 1, 0);
    }
}

/// Typed admission for one (site, process, image) key. The role table is
/// checked exactly; reserved roles and epoch-zero rows never admit.
#[inline(always)]
fn admission(cookie: u64, target: &Target) -> Option<TypedAdmission> {
    if cookie == 0 {
        return None;
    }
    let key = TypedSiteKey {
        cookie,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    let found = unsafe { TYPED_ADMISSION.get(&key).copied() }?;
    found.valid().then_some(found)
}

/// Site bind for one (site, process, image) key. All IDs are nonzero.
#[inline(always)]
fn site_bind(cookie: u64, target: &Target) -> Option<SiteBindValue> {
    if cookie == 0 {
        return None;
    }
    let key = TypedSiteKey {
        cookie,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    // 56 bytes: copied only on the cold admission path, never nested under
    // the digest frame. The hot operational path uses the pointer form.
    let found = unsafe { SITE_BIND.get(&key).copied() }?;
    found.valid().then_some(found)
}

/// Pointer form of the site bind for the hot operational path: validated
/// once, then read field-by-field without a 56-byte stack copy.
#[inline(always)]
fn site_bind_ptr(cookie: u64, target: &Target) -> Option<*mut SiteBindValue> {
    if cookie == 0 {
        return None;
    }
    let key = TypedSiteKey {
        cookie,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    let found = SITE_BIND.get_ptr_mut(&key)?;
    unsafe { (*found).valid() }.then_some(found)
}

/// Pointer form of typed admission for the hot operational path.
#[inline(always)]
fn admission_ptr(cookie: u64, target: &Target) -> Option<*mut TypedAdmission> {
    if cookie == 0 {
        return None;
    }
    let key = TypedSiteKey {
        cookie,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    let found = TYPED_ADMISSION.get_ptr_mut(&key)?;
    unsafe { (*found).valid() }.then_some(found)
}

/// Source authority for one site: its immutable `SOURCE_READY` row plus both
/// guards `LIVE`, with the ready publication at or before the captured entry
/// sequence so an old callback can never pick up later readiness.
#[no_mangle]
pub fn ready_and_guards(cookie: u64, source_epoch: u64, entry_seq: u64, target: &Target) -> bool {
    if cookie == 0 || source_epoch == 0 {
        return false;
    }
    let key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: 0,
        primary_handle: cookie,
        secondary_handle: source_epoch,
        kind: SOURCE_READY,
        operation: 0,
    };
    let Some(row) = REL.get_ptr_mut(&key) else {
        return false;
    };
    unsafe {
        if (*row).evidence_epoch != source_epoch
            || (*row).data[2] == 0
            || (*row).data[2] > entry_seq
            || ordered_read(addr_of_mut!((*row).state).cast::<u64>()) != REL_WITNESS as u64
        {
            return false;
        }
        let anchor = (*row).data[0];
        let registration = (*row).data[1];
        if anchor == 0 || registration == 0 {
            return false;
        }
        let anchor_live = SOURCE_GUARD
            .get(&anchor)
            .is_some_and(|g| g.source_epoch == source_epoch && g.state == GUARD_LIVE);
        let registration_live = SOURCE_GUARD
            .get(&registration)
            .is_some_and(|g| g.source_epoch == source_epoch && g.state == GUARD_LIVE);
        anchor_live && registration_live
    }
}

/// Observer thread incarnation for (process, TID): the live row for the
/// current image, or a freshly allocated nonzero ID when the thread is first
/// seen or its image changed. Stale rows are removed, never reused. A racing
/// exit may delete our fresh row before use; the next read re-allocates from
/// the monotonic allocator, so incarnations are never recycled.
#[no_mangle]
pub fn thread_incarnation(
    control: *mut ProducerControl,
    target: &Target,
    tid: u32,
    out: &mut u64,
) -> bool {
    match thread_incarnation_opt(control, target, tid) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn thread_incarnation_opt(control: *mut ProducerControl, target: &Target, tid: u32) -> Option<u64> {
    if tid == 0 {
        return None;
    }
    let key = ThreadIdentityKey {
        process_incarnation: target.process,
        tid,
        reserved: 0,
    };
    if let Some(found) = unsafe { THREAD_IDENTITY.get(&key).copied() } {
        if found.image_epoch == target.image && found.thread_incarnation != 0 {
            return Some(found.thread_incarnation);
        }
        let _ = THREAD_IDENTITY.remove(&key);
    }
    if !spend(1) {
        return None;
    }
    let mut id = 0u64;
    if !alloc_id(control, &mut id) {
        return None;
    }
    let value = ThreadIdentityValue {
        thread_incarnation: id,
        image_epoch: target.image,
    };
    if THREAD_IDENTITY.insert(key, value, BPF_NOEXIST).is_err() {
        // A racer won the insert; use its row only after full validation.
        // Our charge stays spent: failed work never refunds.
        let found = unsafe { THREAD_IDENTITY.get(&key).copied() }?;
        if found.image_epoch != target.image || found.thread_incarnation == 0 {
            return None;
        }
        return Some(found.thread_incarnation);
    }
    Some(id)
}

/// Private staging result; the caller already owns every key coordinate.
/// Only nested child entry needs the exact successful insertion depth.
struct StagedFrame {
    frame: *mut BindPendingValue,
    depth: u32,
}

/// Initialize the entire pending ABI, including all reserved/name-tail bytes.
/// Raw stores avoid ever constructing a reference to uninitialized fields.
#[inline(always)]
fn initialize_pending_zero(out: &mut core::mem::MaybeUninit<BindPendingValue>) {
    const _: () = {
        assert!(core::mem::size_of::<BindPendingValue>() == 304);
        assert!(core::mem::align_of::<BindPendingValue>() == 8);
    };
    let words = out.as_mut_ptr().cast::<u64>();
    // Fixed volatile local stores prevent a nested memset from extending the
    // insertion chain. The emitted object, not this annotation, proves that.
    unsafe {
        core::ptr::write_volatile(words.add(0), 0);
        core::ptr::write_volatile(words.add(1), 0);
        core::ptr::write_volatile(words.add(2), 0);
        core::ptr::write_volatile(words.add(3), 0);
        core::ptr::write_volatile(words.add(4), 0);
        core::ptr::write_volatile(words.add(5), 0);
        core::ptr::write_volatile(words.add(6), 0);
        core::ptr::write_volatile(words.add(7), 0);
        core::ptr::write_volatile(words.add(8), 0);
        core::ptr::write_volatile(words.add(9), 0);
        core::ptr::write_volatile(words.add(10), 0);
        core::ptr::write_volatile(words.add(11), 0);
        core::ptr::write_volatile(words.add(12), 0);
        core::ptr::write_volatile(words.add(13), 0);
        core::ptr::write_volatile(words.add(14), 0);
        core::ptr::write_volatile(words.add(15), 0);
        core::ptr::write_volatile(words.add(16), 0);
        core::ptr::write_volatile(words.add(17), 0);
        core::ptr::write_volatile(words.add(18), 0);
        core::ptr::write_volatile(words.add(19), 0);
        core::ptr::write_volatile(words.add(20), 0);
        core::ptr::write_volatile(words.add(21), 0);
        core::ptr::write_volatile(words.add(22), 0);
        core::ptr::write_volatile(words.add(23), 0);
        core::ptr::write_volatile(words.add(24), 0);
        core::ptr::write_volatile(words.add(25), 0);
        core::ptr::write_volatile(words.add(26), 0);
        core::ptr::write_volatile(words.add(27), 0);
        core::ptr::write_volatile(words.add(28), 0);
        core::ptr::write_volatile(words.add(29), 0);
        core::ptr::write_volatile(words.add(30), 0);
        core::ptr::write_volatile(words.add(31), 0);
        core::ptr::write_volatile(words.add(32), 0);
        core::ptr::write_volatile(words.add(33), 0);
        core::ptr::write_volatile(words.add(34), 0);
        core::ptr::write_volatile(words.add(35), 0);
        core::ptr::write_volatile(words.add(36), 0);
        core::ptr::write_volatile(words.add(37), 0);
    }
}

/// Own exactly one complete pending value. Quota, loss and clock work stay
/// in the caller, so this key-only scalar-returning leaf adds no nested frame.
#[inline(never)]
#[no_mangle]
pub fn insert_empty_frame(key: &BindPendingKey) -> bool {
    let mut storage = core::mem::MaybeUninit::<BindPendingValue>::uninit();
    initialize_pending_zero(&mut storage);
    // Every byte was initialized above; borrowing it avoids a second copy.
    BIND_PENDING
        .insert(key, unsafe { &*storage.as_ptr() }, BPF_NOEXIST)
        .is_ok()
}

/// Stage one zeroed pending frame at the lowest free depth for this thread.
/// Depth occupancy is slot-exclusion: an occupied slot is never reused, so a
/// stuck frame (lost return) degrades its thread toward depth refusal instead
/// of corrupting a later transaction. The shared pending quota is claimed
/// before insertion and refunded only when no frame was created.
#[inline(always)]
fn stage_frame(params: &StageParams, out: &mut StagedFrame) -> bool {
    match stage_frame_opt(params) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Finite bookkeeping inlined into each entry caller; the complete pending
/// value lives only in the separate insertion leaf.
#[inline(always)]
fn stage_frame_opt(params: &StageParams) -> Option<StagedFrame> {
    if params.thread == 0 || params.cookie == 0 || params.occurrence == 0 {
        return None;
    }
    for depth in 0..MAX_DEPTH {
        let key = BindPendingKey {
            process_incarnation: params.target.process,
            image_epoch: params.target.image,
            thread_incarnation: params.thread,
            depth,
            reserved: 0,
        };
        if BIND_PENDING.get_ptr_mut(&key).is_some() {
            continue;
        }
        if !crate::source_state::claim_pending() {
            loss(LOSS_MAP);
            return None;
        }
        if !insert_empty_frame(&key) {
            let _ = crate::source_state::release_pending();
            continue;
        }
        let Some(frame) = BIND_PENDING.get_ptr_mut(&key) else {
            let _ = crate::source_state::release_pending();
            loss(LOSS_MAP);
            return None;
        };
        unsafe {
            (*frame).occurrence_id = params.occurrence;
            (*frame).api_cookie = params.cookie;
            (*frame).relation_epoch = params.target.relation;
            (*frame).loss_epoch = params.target.loss_epoch;
            (*frame).entry_ns = params.now_ns;
            (*frame).api_role = params.role;
        }
        return Some(StagedFrame { frame, depth });
    }
    loss(LOSS_MAP);
    None
}

/// Pop the deepest frame for this (thread, cookie): by slot-exclusion that is
/// the innermost live call with this cookie, hence the returning call. The
/// caller validates the frame and always consumes it with `release_frame`.
#[inline(always)]
fn pop_frame(
    target: &Target,
    thread: u64,
    cookie: u64,
) -> Option<(BindPendingKey, *mut BindPendingValue)> {
    if thread == 0 || cookie == 0 {
        return None;
    }
    let mut depth = MAX_DEPTH;
    while depth > 0 {
        depth -= 1;
        let key = BindPendingKey {
            process_incarnation: target.process,
            image_epoch: target.image,
            thread_incarnation: thread,
            depth,
            reserved: 0,
        };
        let Some(frame) = BIND_PENDING.get_ptr_mut(&key) else {
            continue;
        };
        if unsafe { (*frame).api_cookie } == cookie && unsafe { (*frame).occurrence_id } != 0 {
            return Some((key, frame));
        }
    }
    loss(LOSS_PAIR);
    None
}

/// Consume a popped frame: remove it, then release its quota claim. A missed
/// release keeps its reservation until the final cut; it cannot create
/// headroom for another frame.
#[inline(always)]
fn release_frame(key: &BindPendingKey) {
    let _ = BIND_PENDING.remove(key);
    if !crate::source_state::release_pending() {
        loss(LOSS_PAIR);
    }
}

/// Exact packed row-state read: the aligned (state, cardinality) pair must be
/// exactly the expected state with zero cardinality. Cardinality-bearing
/// relationship kinds never reach this helper.
#[inline(always)]
unsafe fn row_state_is(row: *mut RelValue, state: u32) -> bool {
    unsafe { ordered_read(addr_of_mut!((*row).state).cast::<u64>()) == state as u64 }
}

/// Retire one producer row WITNESS(1) -> RETIRED(3). Any other state is left
/// untouched: double retirement is quiet, conflict is never downgraded.
#[inline(always)]
fn retire_row(row: *mut RelValue) {
    unsafe {
        compare(
            addr_of_mut!((*row).state).cast::<u64>(),
            REL_WITNESS as u64,
            REL_RETIRED as u64,
        );
    }
}

/// Conflict one producer row * -> CONFLICT(4) unless already terminal.
/// Terminal rows (RETIRED/CONFLICT) keep their first verdict.
#[inline(always)]
fn conflict_row(row: *mut RelValue) {
    unsafe {
        let word = addr_of_mut!((*row).state).cast::<u64>();
        let current = ordered_read(word);
        if current != REL_RETIRED as u64 && current != REL_CONFLICT as u64 {
            compare(word, current, REL_CONFLICT as u64);
        }
    }
}

#[inline(always)]
fn method_key(target: &Target, method: u64, family: u32) -> RelKey {
    RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: target.relation,
        primary_handle: method,
        secondary_handle: 0,
        kind: REL_METHOD,
        operation: family,
    }
}

#[inline(always)]
fn ambiguity_key(target: &Target, method: u64, family: u32) -> RelKey {
    RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: 0,
        primary_handle: method,
        secondary_handle: 0,
        kind: REL_METHOD_AMBIGUITY,
        operation: family,
    }
}

#[inline(always)]
fn quarantine_key(target: &Target, handle: u64, domain: u64) -> RelKey {
    RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: 0,
        primary_handle: handle,
        secondary_handle: domain,
        kind: REL_CONTEXT_QUARANTINE,
        operation: 0,
    }
}

/// A quarantine marker exists for this handle: any state except absent means
/// the handle can never certify again in this process/image. Tombstones
/// survive free, refetch, reset and relation/loss epoch changes.
#[no_mangle]
pub fn quarantined(target: &Target, handle: u64, domain: u64) -> bool {
    if handle == 0 {
        return true;
    }
    REL.get_ptr_mut(&quarantine_key(target, handle, domain))
        .is_some()
}

/// Publish a persistent quarantine tombstone, charging one row. Returns
/// false unless the marker is durably recorded; the caller poisons on
/// false, because an unrecorded required marker must never leave stale
/// eligibility behind. Poisoning lives with the caller (not nested here)
/// to keep the deepest BPF call chain inside the 512-byte stack.
#[no_mangle]
pub fn quarantine(tomb: &Tombstone) -> bool {
    if tomb.handle == 0 || tomb.reason == 0 || tomb.occurrence == 0 {
        return false;
    }
    let key = quarantine_key(tomb.target, tomb.handle, tomb.domain);
    if REL.get_ptr_mut(&key).is_some() {
        return true;
    }
    if !spend(1) {
        return false;
    }
    let mut id = 0u64;
    if !alloc_id(tomb.control, &mut id) {
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    // Quarantine rows need no publisher-lock ordering: they are epoch-0
    // tombstones consulted before every positive, and a concurrent duplicate
    // insert is idempotent (same key, same meaning). The staging cell is
    // safe without the lock here because no digest input is live: tombstone
    // publication never hashes, and every hashing path holds the lock, so a
    // hashing path can never observe this transient staging use... except a
    // source publisher hashing nothing either. Staging users that hash hold
    // the lock; this user does not hash. No observer can confuse the two.
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = id;
        (*staging).evidence_epoch = tomb.target.relation;
        (*staging).born_ns = tomb.now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = tomb.reason;
        (*staging).data[1] = tomb.occurrence;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            // A racing tombstone for the same key is the same verdict.
            if REL.get_ptr_mut(&key).is_none() {
                loss(LOSS_MAP);
                return false;
            }
        }
    }
    loss(LOSS_CONFLICT);
    true
}

/// Quarantine-or-poison: every required tombstone poisons when the
/// marker cannot be recorded. Inlined so the tombstone parameters and the
/// poison call nest in the caller's frame instead of deepening the chain.
#[inline(always)]
fn must_quarantine(
    control: *mut ProducerControl,
    target: &Target,
    handle: u64,
    domain: u64,
    reason: u64,
    occurrence: u64,
    now_ns: u64,
) {
    let tomb = Tombstone {
        control,
        target,
        handle,
        domain,
        reason,
        occurrence,
        now_ns,
    };
    if !quarantine(&tomb) {
        poison_domain();
    }
}

/// Retire the live METHOD row for (method, family) at entry of the matching
/// method-free role. Committed owners survive under their own context-owned
/// reference; ambiguity tombstones are preserved, never cleared.
#[no_mangle]
pub fn retire_method(target: &Target, method: u64, family: u32) {
    if method == 0 || !matches!(family, 3 | 4) {
        return;
    }
    if let Some(row) = REL.get_ptr_mut(&method_key(target, method, family)) {
        retire_row(row);
    }
}

/// Resolve the committed-or-pending index row for X or U. Retired rows are
/// reported as absent: only live claims collide or resolve.
#[inline(always)]
fn live_index(target: &Target, kind: u32, handle: u64) -> Option<*mut RelValue> {
    if handle == 0 || !matches!(kind, REL_X_INDEX | REL_U_INDEX) {
        return None;
    }
    let key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: target.relation,
        primary_handle: handle,
        secondary_handle: 0,
        kind,
        operation: 0,
    };
    let row = REL.get_ptr_mut(&key)?;
    let live = unsafe { (*row).data[5] == 1 || (*row).data[5] == 2 };
    live.then_some(row)
}

/// Retire the owner reachable from a live X or U index row: the owner row, the
/// X row and the U row all retire together before the invalidator's target
/// body runs. Missing rows are quiet; quarantine is preserved.
#[no_mangle]
pub fn retire_owner_reachable(target: &Target, kind: u32, handle: u64) {
    let Some(index) = live_index(target, kind, handle) else {
        return;
    };
    let (owner_id, other) = unsafe { ((*index).data[0], (*index).data[4]) };
    unsafe {
        (*index).data[5] = 3;
    }
    if owner_id == 0 {
        // A pending index has no committed owner yet; its transaction fails
        // its own commit-time live-index check.
        return;
    }
    let (primary, secondary) = if kind == REL_X_INDEX {
        (other, handle)
    } else {
        (handle, other)
    };
    if primary == 0 || secondary == 0 {
        return;
    }
    // The index row carries the owner family; a corrupt family retires
    // nothing here, and the commit-time checks independently refuse it.
    let family = unsafe { (*index).data[6] } as u32;
    if !matches!(family, 3 | 4) {
        return;
    }
    let owner = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: owner_id,
        primary_handle: primary,
        secondary_handle: secondary,
        kind: REL_OWNER,
        operation: family,
    };
    if let Some(row) = REL.get_ptr_mut(&owner) {
        if unsafe { (*row).witness_id } == owner_id {
            retire_row(row);
        }
    }
    // Retire the sibling index row (U for X, X for U) when it names this
    // same owner. A sibling naming another owner is a separate claim.
    let sibling = if kind == REL_X_INDEX {
        REL_U_INDEX
    } else {
        REL_X_INDEX
    };
    if let Some(row) = live_index(target, sibling, other) {
        if unsafe { (*row).data[0] } == owner_id {
            unsafe {
                (*row).data[5] = 3;
            }
        }
    }
}

/// Intern the unbound exact request (object 0, family, name) and return its
/// observer request relation ID, charging one REL row plus one index entry
/// for a new request. An existing immutable entry is reused only after full
/// key equality, which the map contract guarantees. The 144-byte key is
/// staged in the per-CPU cell (validated bytes in, never a stack copy) and
/// the REL value reuses the same cell afterwards; inlined into its single
/// caller so no key crosses a call boundary.
#[inline(always)]
fn intern_request(
    control: *mut ProducerControl,
    family: u32,
    length: u32,
    bytes: &[u8; 128],
    now_ns: u64,
) -> Option<u64> {
    if !matches!(family, 3 | 4) || !exact_name_canonical(bytes, length) {
        return None;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return None;
    };
    let base = unsafe { addr_of_mut!((*slot).staging) };
    let keyed = base.cast::<ExactNameKey>();
    unsafe {
        (*keyed).object_domain = 0;
        (*keyed).operation = family;
        (*keyed).name_length = length;
        let mut i = 0;
        while i < 128 {
            (*keyed).name[i] = bytes[i];
            i += 1;
        }
        if let Some(found) = EXACT_NAME.get(&*keyed).copied() {
            return (found != 0).then_some(found);
        }
    }
    if !spend(2) {
        return None;
    }
    let mut id = 0u64;
    if !alloc_id(control, &mut id) {
        return None;
    }
    // Same lock-free staging rationale as `quarantine`: request rows are
    // immutable session facts published with NOEXIST, never hashed here.
    let staging = base.cast::<RelValue>();
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = id;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = u64::from(family);
        (*staging).data[1] = u64::from(length);
        let mut i = 0;
        while i < 128 {
            (*staging).tail[i] = bytes[i];
            i += 1;
        }
        let key = RelKey {
            process_incarnation: 0,
            image_epoch: 0,
            relation_epoch: 0,
            primary_handle: id,
            secondary_handle: 0,
            kind: REL_REQUEST_NAME,
            operation: family,
        };
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            return None;
        }
        // Rebuild the exact key (the REL staging overwrote the cell) for
        // the index insert and the racer-adoption lookup below.
        (*keyed).object_domain = 0;
        (*keyed).operation = family;
        (*keyed).name_length = length;
        let mut i = 0;
        while i < 128 {
            (*keyed).name[i] = bytes[i];
            i += 1;
        }
    }
    if EXACT_NAME
        .insert(unsafe { &*keyed }, &id, BPF_NOEXIST)
        .is_err()
    {
        // A racer published the same request: adopt its ID only after the
        // map's full key-equality match. Our REL row stays as an unreachable
        // duplicate session fact; charges never refund.
        let found = unsafe { EXACT_NAME.get(&*keyed).copied() }?;
        if found == 0 {
            return None;
        }
        return Some(found);
    }
    Some(id)
}

/// Map the raw `bpf_probe_read_user_str_bytes` outcome to the stored name
/// state. The wrapper's slice excludes the NUL, so the contract's helper
/// return (which includes it) is `len + 1`; errors are unreadable.
#[inline(always)]
fn name_state(len: Result<usize, i32>) -> (u32, u32) {
    match len {
        Err(_) => (NAME_UNREADABLE, 0),
        Ok(n) => {
            let result = n as u64 + 1;
            if result == 1 {
                (NAME_EMPTY, 0)
            } else if (2..=127).contains(&result) {
                (NAME_COMPLETE, (result - 1) as u32)
            } else {
                (NAME_BOUNDARY, 0)
            }
        }
    }
}

/// Lossless private scalar ABI for validated entry configuration. Refuse a
/// future role-table expansion that would exceed the two 16-bit coordinates.
#[inline(always)]
fn pack_entry_role(role: u32, operation: u32, function: u32) -> u64 {
    if role == 0 {
        return 0;
    }
    if operation > u16::MAX as u32 || function > u16::MAX as u32 {
        return 0;
    }
    // valid() restricts role to <= 308, operation to <= 4 and function to
    // <= 6. These are the earlier scalar snapshots, with no truncated field.
    // Returning a scalar keeps the root free of an address-taken output.
    u64::from(role) | (u64::from(operation) << 32) | (u64::from(function) << 48)
}

/// Complete the root admission/READY phase before any paired handler. The
/// finite key and guard temporaries need not overlap pending initialization.
#[inline(never)]
#[no_mangle]
fn entry_authorized(cookie: u64, target: &Target) -> u64 {
    let Some(admitted) = admission_ptr(cookie, target) else {
        return 0;
    };
    let (role, operation, function) = unsafe {
        (
            (*admitted).role_id,
            (*admitted).operation,
            (*admitted).function,
        )
    };
    if unsafe { (*admitted).operational() } || role == 308 {
        return 0;
    }
    let Some(bound) = site_bind_ptr(cookie, target) else {
        return 0;
    };
    let source_epoch = unsafe { (*bound).source_epoch };
    if !ready_and_guards(cookie, source_epoch, target.entry_seq, target) {
        return 0;
    }
    pack_entry_role(role, operation, function)
}
/// Invalidator-only work cannot stage a frame. Keep its VMA and relationship
/// key temporaries out of the paired-entry root frame while preserving the
/// lazy operand reads and copied-role authority checks.
#[inline(never)]
#[no_mangle]
fn entry_invalidate(ctx: &ProbeContext, target: &Target, cookie: u64, admitted: u64) -> u32 {
    let role = admitted as u32;
    let operation = ((admitted >> 32) & 0xffff) as u32;
    let function = (admitted >> 48) as u32;
    match role {
        136 | 137 => {
            let arg0: u64 = ctx.arg(0).unwrap_or(0);
            retire_method(target, arg0, operation);
            0
        }
        149 | 150 | 153 => {
            let arg0: u64 = ctx.arg(0).unwrap_or(0);
            retire_owner_reachable(target, REL_U_INDEX, arg0);
            0
        }
        274 | 275 => {
            let opfun = (u64::from(function) << 32) | u64::from(operation);
            let Some((inode, file_offset)) = join_firing_identity(ctx) else {
                return 0;
            };
            if !code_role_check(target, cookie, inode, file_offset, opfun) {
                return 0;
            }
            let arg0: u64 = ctx.arg(0).unwrap_or(0);
            retire_owner_reachable(target, REL_X_INDEX, arg0);
            0
        }
        5 | 18 | 154 | 155 => {
            // Coarse full-domain poison: unknown or unbounded teardown scope
            // must invalidate before the target body runs. Scoped refinement
            // is a phase-2 optimization, never a soundness requirement.
            poison_domain();
            0
        }
        _ => 0,
    }
}

/// Initialize all root Target storage before forming its typed reference.
/// Fixed stores keep captured entry state out of a nested memory-helper call.
#[inline(always)]
fn initialize_entry_target(out: &mut core::mem::MaybeUninit<Target>) {
    const _: () = {
        assert!(core::mem::size_of::<Target>() == 40);
        assert!(core::mem::align_of::<Target>() == 8);
    };
    let pointer = out.as_mut_ptr();
    // Initialize the root directly without a memory-helper call that spills
    // the already captured sequence and IDs. All fields precede the reference.
    unsafe {
        core::ptr::write_volatile(addr_of_mut!((*pointer).process), 0);
        core::ptr::write_volatile(addr_of_mut!((*pointer).image), 0);
        core::ptr::write_volatile(addr_of_mut!((*pointer).relation), 0);
        core::ptr::write_volatile(addr_of_mut!((*pointer).loss_epoch), 0);
        core::ptr::write_volatile(addr_of_mut!((*pointer).entry_seq), 0);
    }
}

/// Typed uprobe entry. Stages a pending frame for paired roles, retires
/// eligibility for invalidator roles, and stays quiet otherwise. Operational
/// roles (304-308) are refused here: they are served by the same-handler
/// operational check in the focused counter, never by a second program.
pub fn typed_entry(ctx: &ProbeContext, cookie: u64, tgid: u32, tid: u32, _now_ns: u64) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    // Capture at the same point as resolve_target, but resolve directly into
    // the root-owned storage. Returning Option<Target> materializes a second
    // 40-byte stack object before the paired handler can borrow it.
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        return 0;
    };
    let entry_seq = unsafe { ordered_read(addr_of_mut!((*state).published_sequence)) };
    let mut storage = core::mem::MaybeUninit::<Target>::uninit();
    initialize_entry_target(&mut storage);
    let target = unsafe { &mut *storage.as_mut_ptr() };
    if !resolve_inner(tgid, entry_seq, target) {
        return 0;
    }
    let admitted = entry_authorized(cookie, target);
    if admitted == 0 {
        return 0;
    }
    let role = admitted as u32;
    let Some(control) = control_cell() else {
        return 0;
    };
    let ids = ((tgid as u64) << 32) | tid as u64;
    // Paired handlers borrow this root-owned storage and re-resolve at the
    // original point using its captured sequence. No domain-dependent work
    // follows those calls. Retire arms read arg0 lazily so
    // copied-role invalidators (274/275) join live CODE_ROLE authority
    // before any operand read; first-slice arms read the same value later.
    match role {
        130 | 131 => fetch_entry(ctx, control, ids, target),
        147 | 148 => ctx_new_entry(ctx, control, ids, target),
        151 | 152 => dup_entry(ctx, control, ids, target),
        142 | 143 | 146 | 258 | 259 | 290 | 291 => child_entry(ctx, control, ids, target),
        161 => typed_query_entry(ctx, control, ids, target),
        _ => entry_invalidate(ctx, target, cookie, admitted),
    }
}

/// Entry-only admission phase. Return the validated immutable configuration
/// pointer as a scalar; callers snapshot its fields immediately, before any
/// unrelated helper. The lookup key and validation spills end before staging.
#[inline(never)]
#[no_mangle]
fn entry_admission(cookie: u64, target: &Target) -> *mut TypedAdmission {
    admission_ptr(cookie, target).unwrap_or(core::ptr::null_mut())
}

/// Fetch entry (130/131): stage the libctx handle and read the bounded
/// public algorithm name into the frame. Only a1 is read; a2 (properties)
/// is never touched. A NULL libctx stages normally: the association stays
/// unresolved (recorded as null, never labeled global) while full-domain
/// poison on any libctx teardown keeps the lifetime guard sound.
#[inline(never)]
#[no_mangle]
pub fn fetch_entry(
    ctx: &ProbeContext,
    control: *mut ProducerControl,
    ids: u64,
    target: &mut Target,
) -> u32 {
    let (tgid, tid) = split_ids(ids);
    let captured_entry_seq = target.entry_seq;
    if !resolve_inner(tgid, captured_entry_seq, target) {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let admitted = entry_admission(cookie, target);
    if admitted.is_null() {
        return 0;
    }
    let role = unsafe { (*admitted).role_id };
    if !matches!(role, 130 | 131) {
        return 0;
    }
    let mut thread = 0u64;
    if !thread_incarnation(control, target, tid, &mut thread) {
        return 0;
    }
    let mut occurrence = 0u64;
    if !alloc_id(control, &mut occurrence) {
        return 0;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let params = StageParams {
        target,
        thread,
        cookie,
        role,
        occurrence,
        now_ns,
    };
    let mut staged: StagedFrame = unsafe { core::mem::zeroed() };
    if !stage_frame(&params, &mut staged) {
        return 0;
    }
    let frame = staged.frame;
    unsafe {
        (*frame).entry_handle = ctx.arg(0).unwrap_or(0);
    }
    let name_ptr: u64 = ctx.arg(1).unwrap_or(0);
    let outcome = if name_ptr == 0 {
        Err(-1)
    } else {
        unsafe { helpers::bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*frame).name) }
            .map(|bytes| bytes.len())
            .map_err(|_| -1)
    };
    let (state, length) = name_state(outcome);
    unsafe {
        (*frame).name_state = state;
        (*frame).name_length = length;
    }
    0
}

/// Constructor inputs captured from the live, unambiguous method row.
struct MethodEntry {
    witness: u64,
    request: u64,
}

/// Finish method validation before staging. The output retains the same
/// immutable scalar snapshot while the two relation-key temporaries end here.
#[inline(never)]
#[no_mangle]
fn method_entry(target: &Target, method: u64, operation: u32, out: &mut MethodEntry) -> bool {
    let Some(row) = REL.get_ptr_mut(&method_key(target, method, operation)) else {
        return false;
    };
    let (witness, request, live) = unsafe {
        (
            (*row).witness_id,
            (*row).parent_id,
            row_state_is(row, REL_WITNESS),
        )
    };
    if !live
        || witness == 0
        || request == 0
        || REL
            .get_ptr_mut(&ambiguity_key(target, method, operation))
            .is_some()
    {
        return false;
    }
    *out = MethodEntry { witness, request };
    true
}

/// Public context-constructor entry (147/148): the consumed method must name
/// a live observed METHOD row for this family, with no ambiguity tombstone.
/// Unknown, retired, ambiguous or poisoned methods refuse the transaction.
#[inline(never)]
#[no_mangle]
pub fn ctx_new_entry(
    ctx: &ProbeContext,
    control: *mut ProducerControl,
    ids: u64,
    target: &mut Target,
) -> u32 {
    let (tgid, tid) = split_ids(ids);
    let captured_entry_seq = target.entry_seq;
    if !resolve_inner(tgid, captured_entry_seq, target) {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let admitted = entry_admission(cookie, target);
    if admitted.is_null() {
        return 0;
    }
    let (role, operation) = unsafe { ((*admitted).role_id, (*admitted).operation) };
    if !matches!(role, 147 | 148) {
        return 0;
    }
    let method: u64 = ctx.arg(0).unwrap_or(0);
    if method == 0 {
        return 0;
    }
    let mut method_inputs = MethodEntry {
        witness: 0,
        request: 0,
    };
    if !method_entry(target, method, operation, &mut method_inputs) {
        return 0;
    }
    let mut thread = 0u64;
    if !thread_incarnation(control, target, tid, &mut thread) {
        return 0;
    }
    let mut occurrence = 0u64;
    if !alloc_id(control, &mut occurrence) {
        return 0;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let params = StageParams {
        target,
        thread,
        cookie,
        role,
        occurrence,
        now_ns,
    };
    let mut staged: StagedFrame = unsafe { core::mem::zeroed() };
    if !stage_frame(&params, &mut staged) {
        return 0;
    }
    let frame = staged.frame;
    unsafe {
        (*frame).entry_handle = method;
        (*frame).method_observation_id = method_inputs.witness;
        (*frame).selector_or_set_id = method_inputs.request;
    }
    0
}

/// Public context-dup entry (151/152): stage the source owner handle. The
/// destination stays unresolved (no positive propagation); the return path
/// only enforces collision invalidation.
#[inline(never)]
#[no_mangle]
pub fn dup_entry(
    ctx: &ProbeContext,
    control: *mut ProducerControl,
    ids: u64,
    target: &mut Target,
) -> u32 {
    let (tgid, tid) = split_ids(ids);
    let captured_entry_seq = target.entry_seq;
    if !resolve_inner(tgid, captured_entry_seq, target) {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let admitted = entry_admission(cookie, target);
    if admitted.is_null() {
        return 0;
    }
    let role = unsafe { (*admitted).role_id };
    if !matches!(role, 151 | 152) {
        return 0;
    }
    let source: u64 = ctx.arg(0).unwrap_or(0);
    if source == 0 {
        return 0;
    }
    let mut thread = 0u64;
    if !thread_incarnation(control, target, tid, &mut thread) {
        return 0;
    }
    let mut occurrence = 0u64;
    if !alloc_id(control, &mut occurrence) {
        return 0;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let params = StageParams {
        target,
        thread,
        cookie,
        role,
        occurrence,
        now_ns,
    };
    let mut staged: StagedFrame = unsafe { core::mem::zeroed() };
    if !stage_frame(&params, &mut staged) {
        return 0;
    }
    let frame = staged.frame;
    unsafe {
        (*frame).entry_handle = source;
    }
    0
}

/// Nested child entry (getters 142/143/146, constructors 258/259,
/// dup-context 290/291): link to the nearest enclosing public parent frame
/// in this thread, validating full incarnation, expected depth order and the
/// parent API role. Standalone children (no enclosing parent) stage with no
/// parent link; their returns stay unresolved.
#[inline(never)]
#[no_mangle]
pub fn child_entry(
    ctx: &ProbeContext,
    control: *mut ProducerControl,
    ids: u64,
    target: &mut Target,
) -> u32 {
    let (tgid, tid) = split_ids(ids);
    let captured_entry_seq = target.entry_seq;
    if !resolve_inner(tgid, captured_entry_seq, target) {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let admitted = entry_admission(cookie, target);
    if admitted.is_null() {
        return 0;
    }
    let (role, operation, function) = unsafe {
        (
            (*admitted).role_id,
            (*admitted).operation,
            (*admitted).function,
        )
    };
    if !matches!(role, 142 | 143 | 146 | 258 | 259 | 290 | 291) {
        return 0;
    }
    if matches!(role, 258 | 259 | 290 | 291) {
        let opfun = (u64::from(function) << 32) | u64::from(operation);
        let Some((inode, file_offset)) = join_firing_identity(ctx) else {
            return 0;
        };
        if !code_role_check(target, cookie, inode, file_offset, opfun) {
            return 0;
        }
    }
    let arg0: u64 = ctx.arg(0).unwrap_or(0);
    if arg0 == 0 {
        return 0;
    }
    let mut thread = 0u64;
    if !thread_incarnation(control, target, tid, &mut thread) {
        return 0;
    }
    let mut occurrence = 0u64;
    if !alloc_id(control, &mut occurrence) {
        return 0;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let params = StageParams {
        target,
        thread,
        cookie,
        role,
        occurrence,
        now_ns,
    };
    let mut staged: StagedFrame = unsafe { core::mem::zeroed() };
    if !stage_frame(&params, &mut staged) {
        return 0;
    }
    let frame = staged.frame;
    unsafe {
        (*frame).entry_handle = arg0;
        if matches!(role, 258 | 259 | 290 | 291) {
            (*frame).constructor_cookie = cookie;
        }
    }
    // Nearest enclosing public parent: scan depths below ours for the
    // closest CTX_new (147/148) or, for dup-context, dup (151/152) frame.
    // Transitive dynamic extent is the sound nesting relation: any nested
    // child is genuinely within its parent's call.
    let mut depth = staged.depth;
    while depth > 0 {
        depth -= 1;
        let parent_key = BindPendingKey {
            process_incarnation: target.process,
            image_epoch: target.image,
            thread_incarnation: thread,
            depth,
            reserved: 0,
        };
        let Some(parent) = BIND_PENDING.get_ptr_mut(&parent_key) else {
            continue;
        };
        let (parent_role, parent_occurrence, parent_method) = unsafe {
            (
                (*parent).api_role,
                (*parent).occurrence_id,
                (*parent).entry_handle,
            )
        };
        let wants_dup_parent = matches!(role, 290 | 291);
        let parent_ok = if wants_dup_parent {
            matches!(parent_role, 151 | 152)
        } else {
            matches!(parent_role, 147 | 148)
        };
        if !parent_ok || parent_occurrence == 0 {
            continue;
        }
        if matches!(role, 142 | 143) && parent_method != arg0 {
            continue;
        }
        unsafe {
            (*frame).parent_occurrence_id = parent_occurrence;
        }
        break;
    }
    0
}

/// Typed uretprobe return. Pairs the frame, validates incarnation, role,
/// epochs and transaction flags, dispatches by role, and always consumes
/// the frame. A popped frame is the returning call by slot-exclusion, so a
/// validation failure consumes it: its transaction can never complete.
pub fn typed_return(ctx: &RetProbeContext, cookie: u64, tgid: u32, tid: u32, _now_ns: u64) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let Some(mut target) = resolve_target(tgid) else {
        return 0;
    };
    let Some(admitted) = admission(cookie, &target) else {
        return 0;
    };
    if !admitted.valid() || !admitted.paired() {
        return 0;
    }
    let Some(bound) = site_bind(cookie, &target) else {
        return 0;
    };
    if !ready_and_guards(cookie, bound.source_epoch, target.entry_seq, &target) {
        return 0;
    }
    let Some(control) = control_cell() else {
        return 0;
    };
    if tid == 0 {
        return 0;
    }
    let thread_key = ThreadIdentityKey {
        process_incarnation: target.process,
        tid,
        reserved: 0,
    };
    let Some(identity) = (unsafe { THREAD_IDENTITY.get(&thread_key).copied() }) else {
        return 0;
    };
    if identity.image_epoch != target.image || identity.thread_incarnation == 0 {
        return 0;
    }
    let thread = identity.thread_incarnation;
    let Some((key, frame)) = pop_frame(&target, thread, cookie) else {
        return 0;
    };
    let valid = unsafe {
        (*frame).api_role == admitted.role_id
            && (*frame).relation_epoch == target.relation
            && (*frame).loss_epoch == target.loss_epoch
            && (*frame).mapping_epoch == 0
            && (*frame).reserved == 0
            && (*frame).transaction_flags == 0
    };
    if !valid {
        release_frame(&key);
        return 0;
    }
    // Handlers re-read the return value, target snapshot and frame fields;
    // only scalars and synchronous stack borrows cross the call boundary.
    // The owner commit splits into two shallow siblings sharing
    // the per-CPU staging plan; either may refuse, and any refusal retires
    // our pending X before the frame is consumed.
    let role = admitted.role_id;
    let ids = ((tgid as u64) << 32) | tid as u64;
    let entry_seq = target.entry_seq;
    if role == 130 || role == 131 {
        fetch_return(ctx, control, frame, ids, entry_seq);
    } else if role == 147 || role == 148 {
        // The split commit executes here: bind-prepare stages the plan,
        // locked publication returns outcome bits, and this shallow frame
        // executes any deferred quarantine/poison before consuming the
        // frame. Half-written state fails closed by absence in between.
        let owner = ctx.ret();
        if !bind_prepare(control, frame, ids, entry_seq, owner) {
            cleanup_pending_x(&target, frame);
        } else {
            let outcome = commit_publish(control, frame, ids, entry_seq, owner);
            if outcome != OUT_OK {
                if outcome & (OUT_QX | OUT_QU | OUT_POISON) != 0 {
                    dispatch_producer_outcome(control, &target, frame, owner, outcome);
                }
                cleanup_pending_x(&target, frame);
            }
        }
    } else if role == 151 || role == 152 {
        dup_return(ctx, control, frame, ids, entry_seq);
    } else if role == 142 || role == 143 {
        getter_mp_return(ctx, control, frame, ids, entry_seq);
    } else if role == 146 {
        getter_pc_return(ctx, control, frame, ids, entry_seq);
    } else if role == 258 || role == 259 {
        newctx_return(ctx, control, frame, ids, entry_seq);
    } else if role == 290 || role == 291 {
        dupctx_return(ctx, control, frame, ids, entry_seq);
    } else if role == 161 {
        // Query revalidation reuses this now-dead target storage. The
        // pending key is independent, and only frame release follows.
        typed_query_return(ctx, control, frame, tgid, &mut target);
    }
    release_frame(&key);
    0
}

/// Fetch return (130/131): on a non-NULL method with a complete exact name,
/// intern the request and publish (or join) the METHOD row. Incompatible
/// observed spellings for one method create a persistent ambiguity tombstone
/// and revoke the association; free/refetch can never restore uniqueness.
#[inline(never)]
#[no_mangle]
pub fn fetch_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let (tgid, _) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let method: u64 = ctx.ret();
    if method == 0 {
        return;
    }
    let family = unsafe {
        match (*frame).api_role {
            130 => 3,
            131 => 4,
            _ => return,
        }
    };
    let (state, length, libctx) = unsafe {
        (
            (*frame).name_state,
            (*frame).name_length,
            (*frame).entry_handle,
        )
    };
    if state != NAME_COMPLETE || length == 0 || length > 126 {
        return;
    }
    if REL
        .get_ptr_mut(&ambiguity_key(&target, method, family))
        .is_some()
    {
        return;
    }
    // The frame was zero-inserted and the helper wrote a complete
    // NUL-terminated name, so the tail is zero; interning re-validates
    // every byte through the keyless check and stages the 144-byte key in
    // the per-CPU cell, never on the stack.
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let Some(request) = intern_request(control, family, length, unsafe { &(*frame).name }, now_ns)
    else {
        return;
    };
    let key = method_key(&target, method, family);
    if let Some(existing) = REL.get_ptr_mut(&key) {
        let (same_request, live) = unsafe {
            (
                (*existing).parent_id == request,
                row_state_is(existing, REL_WITNESS),
            )
        };
        if same_request {
            // Idempotent refetch of the same observed spelling: the live
            // association stands, whether still live or already retired.
            return;
        }
        // Observed incompatible spellings for one method: tombstone the
        // pair persistently and revoke the old association for the future.
        // The tombstone key is epoch-0, so no later epoch advance, free or
        // refetch can clear it; the old row retires so no later CTX_new can
        // join it, while already committed owners keep their own reference.
        let occurrence = unsafe { (*frame).occurrence_id };
        if !publish_ambiguity(control, &target, method, family, occurrence, now_ns) {
            poison_domain();
        }
        if live {
            retire_row(existing);
        }
        return;
    }
    if !spend(1) {
        return;
    }
    let mut id = 0u64;
    if !alloc_id(control, &mut id) {
        return;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return;
    };
    // Same lock-free staging rationale as `quarantine`: METHOD rows are
    // published with NOEXIST and validated at every use; no hash here.
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = id;
        (*staging).parent_id = request;
        (*staging).evidence_epoch = target.relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = libctx;
        (*staging).data[1] = target.relation;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            // A racing incompatible fetch is handled by the racer's own
            // conflict path when it observes our row; either way this
            // transaction does not certify on a contested method.
        }
    }
}

/// Publish the persistent method-ambiguity tombstone. Returns false unless
/// the marker is durably recorded; the caller poisons on false, because the
/// conflict must be recorded before any later positive can linearize.
/// Inlined into its single caller: six scalar arguments would exceed the
/// BPF call ABI, and the merged frame stays shallow.
#[inline(always)]
fn publish_ambiguity(
    control: *mut ProducerControl,
    target: &Target,
    method: u64,
    family: u32,
    occurrence: u64,
    now_ns: u64,
) -> bool {
    let key = ambiguity_key(target, method, family);
    if REL.get_ptr_mut(&key).is_some() {
        return true;
    }
    if !spend(1) {
        return false;
    }
    let mut id = 0u64;
    if !alloc_id(control, &mut id) {
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = id;
        (*staging).evidence_epoch = target.relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = CONFLICT_METHOD_NAME;
        (*staging).data[1] = occurrence;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() && REL.get_ptr_mut(&key).is_none() {
            loss(LOSS_MAP);
            return false;
        }
    }
    loss(LOSS_CONFLICT);
    true
}

/// Resolve the linked public parent frame for a child return, validating the
/// stored parent occurrence against the live parent row. Occurrence IDs are
/// session-unique, so a full depth scan is unambiguous.
#[no_mangle]
pub fn child_parent(
    target: &Target,
    thread: u64,
    frame: *mut BindPendingValue,
    out: &mut *mut BindPendingValue,
) -> bool {
    match child_parent_opt(target, thread, frame) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn child_parent_opt(
    target: &Target,
    thread: u64,
    frame: *mut BindPendingValue,
) -> Option<*mut BindPendingValue> {
    let parent_occurrence = unsafe { (*frame).parent_occurrence_id };
    if parent_occurrence == 0 {
        return None;
    }
    let mut scan = 0;
    while scan < MAX_DEPTH {
        let key = BindPendingKey {
            process_incarnation: target.process,
            image_epoch: target.image,
            thread_incarnation: thread,
            depth: scan,
            reserved: 0,
        };
        if let Some(parent) = BIND_PENDING.get_ptr_mut(&key) {
            if unsafe { (*parent).occurrence_id } == parent_occurrence {
                return Some(parent);
            }
        }
        scan += 1;
    }
    None
}

/// Current thread incarnation for a handler that only knows its packed IDs.
/// Refuses stale images and zero rows exactly like the allocator path.
#[inline(always)]
fn handler_thread(target: &Target, tid: u32) -> Option<u64> {
    if tid == 0 {
        return None;
    }
    let key = ThreadIdentityKey {
        process_incarnation: target.process,
        tid,
        reserved: 0,
    };
    let found = unsafe { THREAD_IDENTITY.get(&key).copied() }?;
    if found.image_epoch != target.image || found.thread_incarnation == 0 {
        return None;
    }
    Some(found.thread_incarnation)
}

/// Recover a frame's own depth by its session-unique occurrence. Handlers
/// that only receive the frame pointer re-derive the depth for reservation
/// provenance instead of carrying it across the call boundary.
#[no_mangle]
pub fn frame_depth(target: &Target, thread: u64, occurrence: u64, out: &mut u32) -> bool {
    match frame_depth_opt(target, thread, occurrence) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn frame_depth_opt(target: &Target, thread: u64, occurrence: u64) -> Option<u32> {
    if thread == 0 || occurrence == 0 {
        return None;
    }
    let mut scan = 0;
    while scan < MAX_DEPTH {
        let key = BindPendingKey {
            process_incarnation: target.process,
            image_epoch: target.image,
            thread_incarnation: thread,
            depth: scan,
            reserved: 0,
        };
        if let Some(candidate) = BIND_PENDING.get_ptr_mut(&key) {
            if unsafe { (*candidate).occurrence_id } == occurrence {
                return Some(scan);
            }
        }
        scan += 1;
    }
    None
}

/// Method-getter return (142/143): intersect the parent's provider handle.
/// Additional direct evidence: it stages P without incrementing the getter
/// count. A mismatching P flags ambiguity on the parent.
#[inline(never)]
#[no_mangle]
pub fn getter_mp_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let _ = control;
    let (tgid, tid) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let provider: u64 = ctx.ret();
    if provider == 0 {
        return;
    }
    let method = unsafe { (*frame).entry_handle };
    let Some(thread) = handler_thread(&target, tid) else {
        return;
    };
    let mut parent: *mut BindPendingValue = core::ptr::null_mut();
    if !child_parent(&target, thread, frame, &mut parent) {
        return;
    }
    unsafe {
        if !matches!((*parent).api_role, 147 | 148) || (*parent).entry_handle != method {
            return;
        }
        if (*parent).current_p == 0 {
            (*parent).current_p = provider;
        } else if (*parent).current_p != provider {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
        }
    }
}

/// Provider-context-getter return (146): establish or intersect the parent's
/// provider handle and stage its context, requiring exactly one getter per
/// parent transaction. A second getter flags ambiguity, never wraps. The
/// natural getter nested in the consuming call is the P/C evidence; a
/// mismatching or repeated getter refuses the transaction, never selects
/// first or latest.
#[inline(never)]
#[no_mangle]
pub fn getter_pc_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let _ = control;
    let (tgid, tid) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let context: u64 = ctx.ret();
    if context == 0 {
        return;
    }
    let provider = unsafe { (*frame).entry_handle };
    let Some(thread) = handler_thread(&target, tid) else {
        return;
    };
    let mut parent: *mut BindPendingValue = core::ptr::null_mut();
    if !child_parent(&target, thread, frame, &mut parent) {
        return;
    }
    unsafe {
        if !matches!((*parent).api_role, 147 | 148) {
            return;
        }
        if (*parent).current_p == 0 {
            (*parent).current_p = provider;
        } else if (*parent).current_p != provider {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
            return;
        }
        if (*parent).getter_count != 0 {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
            return;
        }
        (*parent).current_c = context;
        (*parent).getter_count = 1;
    }
}

/// Reserve an X index row as pending for a freshly constructed context.
/// Returns true with the row reserved, or flags the parent transaction and
/// returns false. A live competing claim collides: the handle is
/// quarantined and the old owner conflicted before any later positive.
/// Inlined into both constructor handlers so the reservation shares their
/// frame instead of deepening the call chain under the tombstone call.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn reserve_pending_x(
    control: *mut ProducerControl,
    target: &Target,
    parent: *mut BindPendingValue,
    family: u32,
    context: u64,
    thread: u64,
    depth: u32,
    now_ns: u64,
) -> bool {
    if quarantined(target, context, QUARANTINE_CONTEXT_X) {
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return false;
    }
    if let Some(old) = live_index(target, REL_X_INDEX, context) {
        collide_old_owner(target, REL_X_INDEX, context, old);
        must_quarantine(
            control,
            target,
            context,
            QUARANTINE_CONTEXT_X,
            CONFLICT_SHARED_X,
            unsafe { (*parent).occurrence_id },
            now_ns,
        );
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return false;
    }
    if !spend(1) {
        unsafe {
            (*parent).transaction_flags |= TXN_PUBLICATION_FAILED;
        }
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        unsafe {
            (*parent).transaction_flags |= TXN_PUBLICATION_FAILED;
        }
        return false;
    };
    let key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: target.relation,
        primary_handle: context,
        secondary_handle: 0,
        kind: REL_X_INDEX,
        operation: 0,
    };
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = (*parent).occurrence_id;
        (*staging).parent_id = (*parent).occurrence_id;
        (*staging).evidence_epoch = target.relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[1] = (*parent).occurrence_id;
        (*staging).data[2] = thread;
        (*staging).data[3] = u64::from(depth);
        (*staging).data[5] = 1;
        (*staging).data[6] = u64::from(family);
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            // A racing reservation for the same X is the same collision both
            // transactions must observe: quarantine and flag.
            if let Some(old) = live_index(target, REL_X_INDEX, context) {
                collide_old_owner(target, REL_X_INDEX, context, old);
            }
            must_quarantine(
                control,
                target,
                context,
                QUARANTINE_CONTEXT_X,
                CONFLICT_SHARED_X,
                (*parent).occurrence_id,
                now_ns,
            );
            (*parent).transaction_flags |= TXN_COLLISION;
            return false;
        }
    }
    true
}

/// Conflict the owner named by a collided live index row and retire that
/// row, before any later positive can linearize. The new candidate is
/// refused by its own caller; quarantine is published separately.
#[no_mangle]
pub fn collide_old_owner(target: &Target, kind: u32, handle: u64, index: *mut RelValue) {
    let (owner_id, other, family) =
        unsafe { ((*index).data[0], (*index).data[4], (*index).data[6] as u32) };
    unsafe {
        (*index).data[5] = 3;
    }
    if owner_id == 0 || other == 0 || !matches!(family, 3 | 4) {
        return;
    }
    let (primary, secondary) = if kind == REL_X_INDEX {
        (other, handle)
    } else {
        (handle, other)
    };
    let owner = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: owner_id,
        primary_handle: primary,
        secondary_handle: secondary,
        kind: REL_OWNER,
        operation: family,
    };
    if let Some(row) = REL.get_ptr_mut(&owner) {
        if unsafe { (*row).witness_id } == owner_id {
            conflict_row(row);
        }
    }
    let sibling = if kind == REL_X_INDEX {
        REL_U_INDEX
    } else {
        REL_X_INDEX
    };
    if let Some(row) = live_index(target, sibling, other) {
        if unsafe { (*row).data[0] } == owner_id {
            unsafe {
                (*row).data[5] = 3;
            }
        }
    }
    loss(LOSS_CONFLICT);
}

/// Provider constructor return (258/259): stage the fresh provider context
/// and reserve its X index entry as pending. The staged C must equal the
/// getter-established context; exactly one constructor per parent.
#[inline(never)]
#[no_mangle]
pub fn newctx_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let (tgid, tid) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let context: u64 = ctx.ret();
    if context == 0 {
        return;
    }
    let family = unsafe {
        match (*frame).api_role {
            258 => 3,
            259 => 4,
            _ => return,
        }
    };
    let provider_input = unsafe { (*frame).entry_handle };
    let Some(thread) = handler_thread(&target, tid) else {
        return;
    };
    let mut parent: *mut BindPendingValue = core::ptr::null_mut();
    if !child_parent(&target, thread, frame, &mut parent) {
        // Standalone provider construction: no public parent consumes it,
        // so no index row is reserved and nothing can inherit it.
        return;
    }
    let constructor_site = unsafe { (*frame).constructor_cookie };
    unsafe {
        if !matches!((*parent).api_role, 147 | 148) {
            return;
        }
        if (*parent).current_c == 0 || (*parent).current_c != provider_input {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
            return;
        }
        if (*parent).constructor_count != 0 {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
            return;
        }
    }
    // The parent inherits the constructor site's source authority: the
    // commit path reauthorizes this exact site before publishing. A lost
    // bind refuses the transaction without touching the parent staging. The
    // 56-byte bind is validated here but re-read after the reservation, so
    // it is never live across the deeper call chain.
    let constructor_key = TypedSiteKey {
        cookie: constructor_site,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    let bind_ok = unsafe { SITE_BIND.get(&constructor_key).copied() }.is_some_and(|b| b.valid());
    if !bind_ok {
        unsafe {
            (*parent).transaction_flags |= TXN_GUARD_CHANGED;
        }
        return;
    }
    let occurrence = unsafe { (*frame).occurrence_id };
    let mut depth = 0u32;
    if !frame_depth(&target, thread, occurrence, &mut depth) {
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    if !reserve_pending_x(
        control, &target, parent, family, context, thread, depth, now_ns,
    ) {
        return;
    }
    let Some(constructor_bind) = (unsafe { SITE_BIND.get(&constructor_key).copied() }) else {
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return;
    };
    if !constructor_bind.valid() {
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return;
    }
    unsafe {
        (*parent).staged_x = context;
        (*parent).constructor_count = 1;
        (*parent).constructor_cookie = constructor_site;
        (*parent).source_object_id = constructor_site;
        (*parent).source_epoch = constructor_bind.source_epoch;
    }
}

/// Provider dup-context return (290/291): stage the fresh context under the
/// enclosing public dup after checking source consistency. Standalone
/// provider dups reserve nothing: provider-internal duplication never
/// inherits an owner.
#[inline(never)]
#[no_mangle]
pub fn dupctx_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let (tgid, tid) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let context: u64 = ctx.ret();
    if context == 0 {
        return;
    }
    let family = unsafe {
        match (*frame).api_role {
            290 => 3,
            291 => 4,
            _ => return,
        }
    };
    let source_x = unsafe { (*frame).entry_handle };
    let occurrence = unsafe { (*frame).occurrence_id };
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    if source_x == context {
        must_quarantine(
            control,
            &target,
            source_x,
            QUARANTINE_CONTEXT_X,
            CONFLICT_DUP_EQUALITY,
            occurrence,
            now_ns,
        );
        return;
    }
    let Some(thread) = handler_thread(&target, tid) else {
        return;
    };
    let mut parent: *mut BindPendingValue = core::ptr::null_mut();
    if !child_parent(&target, thread, frame, &mut parent) {
        return;
    }
    let (role, source_u, staged) = unsafe {
        (
            (*parent).api_role,
            (*parent).entry_handle,
            (*parent).staged_x,
        )
    };
    if !matches!(role, 151 | 152) {
        return;
    }
    if staged != 0 {
        unsafe {
            (*parent).transaction_flags |= TXN_AMBIGUITY;
        }
        return;
    }
    // When the dup source owner is known, its context must equal the dup
    // source X; an unresolved source skips this check and stays unresolved.
    if let Some(index) = live_index(&target, REL_U_INDEX, source_u) {
        let (owner_id, known_x, owner_family) =
            unsafe { ((*index).data[0], (*index).data[4], (*index).data[6] as u32) };
        if owner_id != 0 && matches!(owner_family, 3 | 4) && known_x != source_x {
            unsafe {
                (*parent).transaction_flags |= TXN_AMBIGUITY;
            }
            return;
        }
    }
    let mut depth = 0u32;
    if !frame_depth(&target, thread, occurrence, &mut depth) {
        unsafe {
            (*parent).transaction_flags |= TXN_COLLISION;
        }
        return;
    }
    if !reserve_pending_x(
        control, &target, parent, family, context, thread, depth, now_ns,
    ) {
        return;
    }
    unsafe {
        (*parent).staged_x = context;
    }
}

/// Public context-dup return (151/152): collision-invalidate the destination
/// and retire any staged provider result. No OWNER is published for the
/// destination: dup propagation stays unresolved in this slice.
#[inline(never)]
#[no_mangle]
pub fn dup_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) {
    let (tgid, _) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return;
    }
    let destination: u64 = ctx.ret();
    let (source_u, staged_x, occurrence) = unsafe {
        (
            (*frame).entry_handle,
            (*frame).staged_x,
            (*frame).occurrence_id,
        )
    };
    if staged_x != 0 {
        retire_pending_x(&target, occurrence, staged_x);
    }
    if destination == 0 {
        return;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    if destination == source_u {
        must_quarantine(
            control,
            &target,
            destination,
            QUARANTINE_OWNER_U,
            CONFLICT_DUP_EQUALITY,
            occurrence,
            now_ns,
        );
        return;
    }
    if quarantined(&target, destination, QUARANTINE_OWNER_U) {
        return;
    }
    if let Some(old) = live_index(&target, REL_U_INDEX, destination) {
        collide_old_owner(&target, REL_U_INDEX, destination, old);
        must_quarantine(
            control,
            &target,
            destination,
            QUARANTINE_OWNER_U,
            CONFLICT_SHARED_U,
            occurrence,
            now_ns,
        );
    }
}

/// Retire our own pending X reservation after a dup return. Only the exact
/// pending row owned by this occurrence retires; anything else is left for
/// its own owner's lifecycle with a pairing loss recorded.
#[no_mangle]
pub fn retire_pending_x(target: &Target, occurrence: u64, context: u64) {
    if occurrence == 0 || context == 0 {
        return;
    }
    let key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: target.relation,
        primary_handle: context,
        secondary_handle: 0,
        kind: REL_X_INDEX,
        operation: 0,
    };
    let Some(row) = REL.get_ptr_mut(&key) else {
        return;
    };
    unsafe {
        if (*row).data[0] == 0 && (*row).data[1] == occurrence && (*row).data[5] == 1 {
            (*row).data[5] = 3;
        } else {
            loss(LOSS_PAIR);
        }
    }
}

/// Retire our own pending X reservation after an aborted owner commit. Only
/// the exact pending row owned by this occurrence retires; a flipped or
/// foreign row is left untouched.
#[no_mangle]
pub fn cleanup_pending_x(target: &Target, frame: *mut BindPendingValue) {
    let (occurrence, staged) = unsafe { ((*frame).occurrence_id, (*frame).staged_x) };
    retire_pending_x(target, occurrence, staged);
}

/// Public context-constructor return (147/148), split into two shallow
/// siblings sharing the per-CPU staging plan: `bind_prepare` validates the
/// staged transaction, resolves the prepared selector (hashing once on the
/// create path) and allocates every ID; `commit_publish` takes the lock,
/// revalidates, publishes rows in dependency order and commits the
/// sequence. Either phase may refuse; any refusal retires our pending X.
#[inline(never)]
/// Bind preparation writes the per-CPU plan and consumes the pending X
/// claim. `rv` is the constructed owner handle; a null pointer return can
/// never become an owner.
#[no_mangle]
pub fn bind_prepare(
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
    rv: u64,
) -> bool {
    let (tgid, _) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return false;
    }
    let family = unsafe {
        match (*frame).api_role {
            147 => 3,
            148 => 4,
            _ => return false,
        }
    };
    // Pure validation: staged counts, handles, epochs and flags.
    let (method, method_observation, request, provider, provider_input, staged_x) = unsafe {
        (
            (*frame).entry_handle,
            (*frame).method_observation_id,
            (*frame).selector_or_set_id,
            (*frame).current_p,
            (*frame).current_c,
            (*frame).staged_x,
        )
    };
    let (getter_count, constructor_count, constructor_site, source_epoch, source_object) = unsafe {
        (
            (*frame).getter_count,
            (*frame).constructor_count,
            (*frame).constructor_cookie,
            (*frame).source_epoch,
            (*frame).source_object_id,
        )
    };
    let epochs_ok = unsafe {
        (*frame).relation_epoch == target.relation
            && (*frame).loss_epoch == target.loss_epoch
            && (*frame).mapping_epoch == 0
            && (*frame).reserved == 0
            && (*frame).transaction_flags == 0
    };
    if !epochs_ok
        || rv == 0
        || method == 0
        || method_observation == 0
        || request == 0
        || provider == 0
        || provider_input == 0
        || staged_x == 0
        || getter_count != 1
        || constructor_count != 1
        || constructor_site == 0
        || source_epoch == 0
        || source_object == 0
    {
        return false;
    }
    let Some(method_row) = REL.get_ptr_mut(&method_key(&target, method, family)) else {
        return false;
    };
    let method_ok = unsafe {
        row_state_is(method_row, REL_WITNESS)
            && (*method_row).witness_id == method_observation
            && (*method_row).parent_id == request
    };
    if !method_ok
        || REL
            .get_ptr_mut(&ambiguity_key(&target, method, family))
            .is_some()
        || quarantined(&target, staged_x, QUARANTINE_CONTEXT_X)
        || !own_pending_x(&target, frame, staged_x, family)
    {
        return false;
    }
    // Constructor bind and request row: the prepared object, its retained
    // hash, and the immutable exact name parts for the digest or reuse.
    let bind_key = TypedSiteKey {
        cookie: constructor_site,
        process_incarnation: target.process,
        image_epoch: target.image,
    };
    let Some(bind) = SITE_BIND.get_ptr_mut(&bind_key) else {
        return false;
    };
    let (code_object, bind_ok) = unsafe { ((*bind).code_object_id, (*bind).valid()) };
    if !bind_ok {
        return false;
    }
    let request_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: request,
        secondary_handle: 0,
        kind: REL_REQUEST_NAME,
        operation: family,
    };
    let Some(request_row) = REL.get_ptr_mut(&request_key) else {
        return false;
    };
    let (stored_family, name_length, request_live) = unsafe {
        (
            (*request_row).data[0] as u32,
            (*request_row).data[1] as u32,
            row_state_is(request_row, REL_WITNESS) && (*request_row).witness_id == request,
        )
    };
    if !request_live || stored_family != family || name_length == 0 || name_length > 126 {
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    // Allocate every ID up front. Reused rows leave their reserve unspent;
    // reserves never refund, and IDs never recycle.
    // All seven calls evaluate unconditionally, exactly as the previous
    // tuple match: quota charges never refund, so a short-circuit would
    // observably spend less on the failure path.
    let mut owner_id = 0u64;
    let mut continuity = 0u64;
    let mut context_epoch = 0u64;
    let mut set_id = 0u64;
    let mut selector_relation = 0u64;
    let mut selector_fresh = 0u64;
    let mut epoch_fresh = 0u64;
    let ok_owner = alloc_id(control, &mut owner_id);
    let ok_continuity = alloc_id(control, &mut continuity);
    let ok_context = alloc_id(control, &mut context_epoch);
    let ok_set = alloc_id(control, &mut set_id);
    let ok_relation = alloc_id(control, &mut selector_relation);
    let ok_selector = alloc_id(control, &mut selector_fresh);
    let ok_epoch = alloc_id(control, &mut epoch_fresh);
    if !(ok_owner
        && ok_continuity
        && ok_context
        && ok_set
        && ok_relation
        && ok_selector
        && ok_epoch)
    {
        return false;
    }
    let ids_out = (
        owner_id,
        continuity,
        context_epoch,
        set_id,
        selector_relation,
        selector_fresh,
        epoch_fresh,
    );
    // Reuse probe: stage the bound key and look up the immutable entry.
    // This is a lock-free read; publication revalidates under the lock.
    let keyed = unsafe { (*slot).staging.as_mut_ptr().cast::<ExactNameKey>() };
    let found = unsafe {
        (*keyed).object_domain = code_object;
        (*keyed).operation = family;
        (*keyed).name_length = name_length;
        let mut i = 0;
        while i < 128 {
            (*keyed).name[i] = (*request_row).tail[i];
            i += 1;
        }
        EXACT_NAME.get(&*keyed).copied().unwrap_or(0)
    };
    if found != 0 {
        // Reuse path: adopt the immutable coordinates after validation.
        // The digest/IDs allocated above stay spent but unused.
        let mut reused: BoundSelector = unsafe { core::mem::zeroed() };
        if !reuse_bound_selector(found, code_object, family, request, &mut reused) {
            return false;
        }
        unsafe {
            plan_store(slot, PLAN_SELECTOR, reused.selector);
            plan_store(slot, PLAN_EPOCH, reused.epoch);
            plan_store(slot, PLAN_OBJECT, code_object);
            plan_store(slot, PLAN_OWNER, ids_out.0);
            plan_store(slot, PLAN_CONTINUITY, ids_out.1);
            plan_store(slot, PLAN_CONTEXT_EPOCH, ids_out.2);
            plan_store(slot, PLAN_SET, ids_out.3);
            plan_store(slot, PLAN_SELECTOR_RELATION, 0);
            plan_store(slot, PLAN_OWNER_HANDLE, rv);
        }
        return true;
    }
    // Create path: marshal the digest input directly from the immutable
    // request row and the retained artifact hash into the staging message
    // scratch. No 144-byte key and no message buffer share the stack.
    let message = unsafe { (*slot).staging.as_mut_ptr().cast::<[u8; 192]>() };
    let digest = unsafe {
        selector_digest_parts(
            family,
            name_length,
            &(*request_row).tail,
            &(*bind).object_sha256,
            &mut *message,
        )
    };
    let Some(digest) = digest else {
        return false;
    };
    unsafe {
        let base = (*slot).staging.as_mut_ptr().cast::<u8>();
        let mut i = 0;
        while i < 32 {
            *base.add(PLAN_DIGEST + i) = digest[i];
            i += 1;
        }
        plan_store(slot, PLAN_SELECTOR, ids_out.5);
        plan_store(slot, PLAN_EPOCH, ids_out.6);
        plan_store(slot, PLAN_OBJECT, code_object);
        plan_store(slot, PLAN_OWNER, ids_out.0);
        plan_store(slot, PLAN_CONTINUITY, ids_out.1);
        plan_store(slot, PLAN_CONTEXT_EPOCH, ids_out.2);
        plan_store(slot, PLAN_SET, ids_out.3);
        plan_store(slot, PLAN_SELECTOR_RELATION, ids_out.4);
        plan_store(slot, PLAN_OWNER_HANDLE, rv);
    }
    true
}

/// Store one plan word into per-CPU staging. Offsets are 8-aligned by
/// construction; the caller holds no lock because the cell is per-CPU
/// private to this non-preemptible run.
#[inline(always)]
unsafe fn plan_store(
    slot: *mut osslscope_bpf_contract::source::SourceSlot,
    offset: usize,
    value: u64,
) {
    unsafe {
        (*slot)
            .staging
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<u64>()
            .write(value);
    }
}

/// Load one plan word from per-CPU staging.
#[inline(always)]
unsafe fn plan_load(slot: *mut osslscope_bpf_contract::source::SourceSlot, offset: usize) -> u64 {
    unsafe {
        (*slot)
            .staging
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<u64>()
            .read()
    }
}

/// Commit outcome codes. The locked worker never calls quarantine or
/// poison itself (that would nest two more frames under the deepest chain);
/// it returns bits and the shallow dispatcher executes them microseconds
/// later, before the frame is consumed. In the deferral window half-written
/// state fails closed by absence: the OWNER row does not exist yet, so no
/// positive can resolve through it.
const OUT_OK: u64 = 0;
const OUT_QX: u64 = 1;
const OUT_QU: u64 = 2;
const OUT_POISON: u64 = 4;
const OUT_ABORT: u64 = 8;

/// Plan spare word staging the constructed owner handle U, so the locked
/// worker recovers it without a sixth call argument.
const PLAN_OWNER_HANDLE: usize = 240;

/// Execute a nonzero locked-publish outcome in this shallow frame. The
/// pending frame is still alive (the caller consumes it next), so the X
/// handle and occurrence re-derive from it. Quarantine of X uses the
/// context-X domain; quarantine of U uses the owner-U domain. Never called
/// on the success path.
#[inline(never)]
#[no_mangle]
pub fn dispatch_producer_outcome(
    control: *mut ProducerControl,
    target: &Target,
    frame: *mut BindPendingValue,
    owner: u64,
    outcome: u64,
) {
    let (staged_x, occurrence) = unsafe { ((*frame).staged_x, (*frame).occurrence_id) };
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    if outcome & OUT_QX != 0 && staged_x != 0 && occurrence != 0 {
        must_quarantine(
            control,
            target,
            staged_x,
            QUARANTINE_CONTEXT_X,
            CONFLICT_SHARED_X,
            occurrence,
            now,
        );
    }
    if outcome & OUT_QU != 0 && owner != 0 && occurrence != 0 {
        must_quarantine(
            control,
            target,
            owner,
            QUARANTINE_OWNER_U,
            CONFLICT_SHARED_U,
            occurrence,
            now,
        );
    }
    if outcome & OUT_POISON != 0 {
        poison_domain();
    }
}

/// Locked owner publication: revalidate every dependency, take the shared
/// publisher lock, publish the bound selector rows (or adopt the reused
/// ones), then the ordered tail (X flip, U, OWNER_SELECTOR, OWNER, sequence
/// commit last). Returns the outcome code; any nonzero outcome retires our
/// pending X, and the quarantine/poison bits execute in the dispatcher.
#[inline(never)]
#[no_mangle]
pub fn commit_publish(
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
    owner: u64,
) -> u64 {
    let (tgid, _) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return OUT_ABORT;
    }
    if owner == 0 {
        return OUT_ABORT;
    }
    let family = unsafe {
        match (*frame).api_role {
            147 => 3,
            148 => 4,
            _ => return OUT_ABORT,
        }
    };
    if !commit_precheck(&target, frame, family, owner) {
        return OUT_ABORT;
    }
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        return OUT_ABORT;
    };
    let busy = unsafe { addr_of_mut!((*state).publication_busy) };
    let mut locked = false;
    for _ in 0..8 {
        if unsafe { compare(busy, 0, 1) } {
            locked = true;
            break;
        }
    }
    if !locked {
        // Contended publication leaves this transaction unresolved; it never
        // poisons unrelated owners or revives a concurrent quarantine.
        return OUT_ABORT;
    }
    let outcome = commit_publish_locked(control, state, frame, ids, entry_seq);
    unsafe {
        compare(busy, 1, 0);
    }
    outcome
}

/// Pre-lock dependency revalidation. Pure reads; any failure aborts cleanly
/// before charges, IDs or rows are touched.
#[no_mangle]
pub fn commit_precheck(
    target: &Target,
    frame: *mut BindPendingValue,
    family: u32,
    owner: u64,
) -> bool {
    let pre_ok = unsafe {
        (*frame).relation_epoch == target.relation
            && (*frame).loss_epoch == target.loss_epoch
            && (*frame).transaction_flags == 0
            && (*frame).getter_count == 1
            && (*frame).constructor_count == 1
    };
    if !pre_ok {
        return false;
    }
    let (method, method_observation, request, provider, staged_x) = unsafe {
        (
            (*frame).entry_handle,
            (*frame).method_observation_id,
            (*frame).selector_or_set_id,
            (*frame).current_p,
            (*frame).staged_x,
        )
    };
    if method == 0 || method_observation == 0 || request == 0 || provider == 0 || staged_x == 0 {
        return false;
    }
    let (constructor_site, source_epoch) =
        unsafe { ((*frame).constructor_cookie, (*frame).source_epoch) };
    if constructor_site == 0 || source_epoch == 0 {
        return false;
    }
    let Some(method_row) = REL.get_ptr_mut(&method_key(target, method, family)) else {
        return false;
    };
    let method_ok = unsafe {
        row_state_is(method_row, REL_WITNESS)
            && (*method_row).witness_id == method_observation
            && (*method_row).parent_id == request
    };
    if !method_ok
        || REL
            .get_ptr_mut(&ambiguity_key(target, method, family))
            .is_some()
        || quarantined(target, owner, QUARANTINE_OWNER_U)
        || quarantined(target, staged_x, QUARANTINE_CONTEXT_X)
        || !own_pending_x(target, frame, staged_x, family)
    {
        return false;
    }
    let own_cookie = unsafe { (*frame).api_cookie };
    reauthorize_site(target, own_cookie)
        && ready_and_guards(constructor_site, source_epoch, target.entry_seq, target)
}

/// Monotonic clock read for publication timestamps. Handlers timestamp at
/// use instead of carrying `now` across the five-argument call boundary.
#[inline(always)]
fn now_of() -> u64 {
    unsafe { helpers::bpf_ktime_get_ns() }
}

/// The locked section of owner publication as a real call: five scalars in,
/// one outcome code out, target/family/owner re-derived inside. Holding the
/// sequence word across a BPF-to-BPF call is sound (same CPU,
/// non-preemptible, no sleep); the caller always releases it. Never calls
/// quarantine or poison (outcome bits instead), so the deepest chain stays
/// inside the shared stack.
#[inline(never)]
#[no_mangle]
pub fn commit_publish_locked(
    control: *mut ProducerControl,
    state: *mut osslscope_bpf_contract::source::SourceControl,
    frame: *mut BindPendingValue,
    ids: u64,
    entry_seq: u64,
) -> u64 {
    let (tgid, _) = split_ids(ids);
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut target) {
        return OUT_ABORT;
    }
    let family = unsafe {
        match (*frame).api_role {
            147 => 3,
            148 => 4,
            _ => return OUT_ABORT,
        }
    };
    // Revalidate mode and coordinates under the lock; the dependency
    // revalidation above ran microseconds earlier on this same CPU. Epoch
    // and flag races fail closed through the checks below.
    let mode_ok = unsafe {
        (*control).producer_mode == PRODUCER_ADMITTED
            && (*control).session_id != 0
            && (*control).admission_epoch != 0
            && (*control).cut_id != 0
            && (*control).reserved == 0
    };
    if !mode_ok {
        return OUT_ABORT;
    }
    let epoch_ok = unsafe {
        (*frame).relation_epoch == target.relation
            && (*frame).loss_epoch == target.loss_epoch
            && (*frame).transaction_flags == 0
    };
    if !epoch_ok {
        return OUT_ABORT;
    }
    let old_seq = unsafe { ordered_read(addr_of_mut!((*state).published_sequence)) };
    let Some(next_seq) = old_seq.checked_add(1) else {
        return OUT_POISON;
    };
    if next_seq == 0 {
        return OUT_POISON;
    }
    // Reserve every charge before publishing: OWNER, OWNER_SELECTOR, U
    // index, plus the full bound-selector set. Reused rows leave their
    // reserve unspent; reserves never refund.
    if !spend(7) {
        return OUT_ABORT;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return OUT_ABORT;
    };
    // Copy the plan survivors before any staging write clobbers the plan.
    // Every word must be nonzero except the reuse-path relation spare.
    let selector = unsafe { plan_load(slot, PLAN_SELECTOR) };
    let epoch = unsafe { plan_load(slot, PLAN_EPOCH) };
    let object = unsafe { plan_load(slot, PLAN_OBJECT) };
    let owner_id = unsafe { plan_load(slot, PLAN_OWNER) };
    let continuity = unsafe { plan_load(slot, PLAN_CONTINUITY) };
    let context_epoch = unsafe { plan_load(slot, PLAN_CONTEXT_EPOCH) };
    let set_id = unsafe { plan_load(slot, PLAN_SET) };
    let selector_relation = unsafe { plan_load(slot, PLAN_SELECTOR_RELATION) };
    let owner = unsafe { plan_load(slot, PLAN_OWNER_HANDLE) };
    if selector == 0
        || epoch == 0
        || object == 0
        || owner_id == 0
        || continuity == 0
        || context_epoch == 0
        || set_id == 0
        || owner == 0
    {
        return OUT_ABORT;
    }
    let request = unsafe { (*frame).selector_or_set_id };
    if request == 0 {
        return OUT_ABORT;
    }
    if selector_relation == 0 {
        // Reuse path: the immutable bound set already exists; adopt it
        // after full validation of its row.
        let Some(found) = bound_lookup(request, family, object) else {
            return OUT_ABORT;
        };
        let mut reused: BoundSelector = unsafe { core::mem::zeroed() };
        if !reuse_bound_selector(found, object, family, request, &mut reused) {
            return OUT_POISON;
        }
        if reused.object != object || reused.selector != selector || reused.epoch != epoch {
            return OUT_POISON;
        }
    } else {
        // Create path: publish the bound set from the staged plan. The
        // digest crosses in staging (never on the stack); the OBJECT row
        // build clobbers the plan, so the digest index and safe projection
        // read the digest back from the published OBJECT row.
        let outcome = publish_bound_selector(slot, request, family, target.relation);
        if outcome != OUT_OK {
            return outcome;
        }
    }
    // The bound phase clobbered staging, so the tail arguments rebuild
    // there from the survivors above plus the still-live frame (a map
    // value, not staging). Coordinates re-resolve here instead of crossing
    // the publish call: a domain change mid-commit fails closed rather
    // than publishing under superseded coordinates.
    let occurrence = unsafe { (*frame).occurrence_id };
    let staged_x = unsafe { (*frame).staged_x };
    let method = unsafe { (*frame).entry_handle };
    let method_observation = unsafe { (*frame).method_observation_id };
    let provider = unsafe { (*frame).current_p };
    let source_epoch = unsafe { (*frame).source_epoch };
    let frame_relation = unsafe { (*frame).relation_epoch };
    let mut post: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(tgid, entry_seq, &mut post) {
        return OUT_ABORT;
    }
    if post.relation != frame_relation || post.relation != target.relation {
        return OUT_ABORT;
    }
    let now_ns = now_of();
    let Some(tslot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(TAIL_SLOT) else {
        return OUT_ABORT;
    };
    unsafe {
        plan_store(tslot, TAIL_PROCESS, post.process);
        plan_store(tslot, TAIL_IMAGE, post.image);
        plan_store(tslot, TAIL_RELATION, post.relation);
        plan_store(tslot, TAIL_OWNER, owner);
        plan_store(tslot, TAIL_OWNER_ID, owner_id);
        plan_store(tslot, TAIL_STAGED_X, staged_x);
        plan_store(tslot, TAIL_OCCURRENCE, occurrence);
        plan_store(tslot, TAIL_NEXT_SEQ, next_seq);
        plan_store(tslot, TAIL_FAMILY, u64::from(family));
        plan_store(tslot, TAIL_NOW_NS, now_ns);
        plan_store(tslot, TAIL_REQUEST, request);
        plan_store(tslot, TAIL_SOURCE_EPOCH, source_epoch);
        plan_store(tslot, TAIL_METHOD, method);
        plan_store(tslot, TAIL_METHOD_OBSERVATION, method_observation);
        plan_store(tslot, TAIL_PROVIDER, provider);
        plan_store(tslot, TAIL_CONTINUITY, continuity);
        plan_store(tslot, TAIL_SET, set_id);
        plan_store(tslot, TAIL_CONTEXT_EPOCH, context_epoch);
        plan_store(tslot, TAIL_OBJECT, object);
        plan_store(tslot, TAIL_SELECTOR, selector);
        plan_store(tslot, TAIL_EPOCH, epoch);
    }
    let tail = unsafe { (*tslot).staging.as_ptr().cast::<TailArgs>() };
    // Tail: X flip first (clean abort when it fails: nothing is published).
    if !flip_x_tail(tail) {
        return OUT_ABORT;
    }
    // U insert-or-reclaim. From here on every failure quarantines the
    // affected handles: X is already committed, so the transaction must
    // revoke before any later positive instead of silently dropping.
    match insert_u_tail(tail) {
        OUT_OK => {}
        OUT_POISON => return OUT_QX | OUT_QU | OUT_POISON,
        _ => return OUT_QX | OUT_QU,
    }
    if !insert_owner_selector_tail(tail) {
        return OUT_QX | OUT_QU | OUT_POISON;
    }
    if !insert_owner_tail(tail) {
        return OUT_QX | OUT_QU | OUT_POISON;
    }
    if !unsafe { compare(addr_of_mut!((*state).published_sequence), old_seq, next_seq) } {
        // No legitimate writer can change the sequence under our lock: a
        // failed commit is a lock breach, so poison terminally.
        return OUT_QX | OUT_QU | OUT_POISON;
    }
    if unsafe { ordered_read(addr_of_mut!((*control).producer_mode)) } != PRODUCER_ADMITTED {
        // A poison raced us through the lock-free terminal path after our
        // revalidation: our rows reference a superseded mode, so revoke the
        // affected handles instead of certifying on them.
        return OUT_QX | OUT_QU;
    }
    OUT_OK
}
/// Look up the bound exact-name entry for (object, family, request),
/// staging the 144-byte key in the per-CPU cell. Returns the bound
/// OBJECT_SELECTOR relation ID, or `None` when no bound entry exists.
/// Inlined so the lookup shares the caller's key slot instead of nesting.
/// The request-name rows live in the global (0, 0, 0) domain, so no target
/// coordinates enter this lookup.
#[inline(always)]
fn bound_lookup(request: u64, family: u32, object: u64) -> Option<u64> {
    let request_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: request,
        secondary_handle: 0,
        kind: REL_REQUEST_NAME,
        operation: family,
    };
    let Some(request_row) = REL.get_ptr_mut(&request_key) else {
        return None;
    };
    let (stored_family, name_length, live) = unsafe {
        (
            (*request_row).data[0] as u32,
            (*request_row).data[1] as u32,
            row_state_is(request_row, REL_WITNESS) && (*request_row).witness_id == request,
        )
    };
    if !live || stored_family != family || name_length == 0 || name_length > 126 {
        return None;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return None;
    };
    let keyed = unsafe { (*slot).staging.as_mut_ptr().cast::<ExactNameKey>() };
    unsafe {
        (*keyed).object_domain = object;
        (*keyed).operation = family;
        (*keyed).name_length = name_length;
        let mut i = 0;
        while i < 128 {
            (*keyed).name[i] = (*request_row).tail[i];
            i += 1;
        }
        match EXACT_NAME.get(&*keyed).copied() {
            Some(found) if found != 0 => Some(found),
            _ => None,
        }
    }
}

/// Publish the bound selector set from the staged plan under the lock:
/// exact index, OBJECT_SELECTOR, safe projection, digest index. A real
/// subprogram so its keys and lookups leave the caller's frame: the worker
/// holds only spilled survivors across this call. Coordinates re-derive
/// from the plan (object, relation, selector, epoch); only the evidence
/// epoch crosses as an argument. The OBJECT build clobbers the plan, so
/// the projection and digest index read the digest back from the published
/// OBJECT row. Under the lock no concurrent publisher can interleave, so
/// any insert failure is impossible-state and poisons.
#[inline(never)]
#[no_mangle]
pub fn publish_bound_selector(
    slot: *mut osslscope_bpf_contract::source::SourceSlot,
    request: u64,
    family: u32,
    relation: u64,
) -> u64 {
    let (object, selector_relation, selector, epoch) = unsafe {
        (
            plan_load(slot, PLAN_OBJECT),
            plan_load(slot, PLAN_SELECTOR_RELATION),
            plan_load(slot, PLAN_SELECTOR),
            plan_load(slot, PLAN_EPOCH),
        )
    };
    if request == 0 || object == 0 || selector_relation == 0 || selector == 0 || epoch == 0 {
        return OUT_ABORT;
    }
    // Digest conflict gate first: a live entry for this digest with
    // unequal exact bytes conflicts and refuses; a zeroed entry refuses.
    // A failed conflict analysis is impossible-state and poisons. The key
    // is staged, never on the stack: the 16-byte header lands at
    // `[128..144)` (dead name scratch) and the digest already sits at
    // `[144..176)`, so `&DigestKey` reads straight off the cell.
    let digest_key = unsafe {
        let base = (*slot).staging.as_mut_ptr().cast::<u8>();
        base.add(128).cast::<u64>().write(object);
        base.add(136).cast::<u32>().write(family);
        base.add(140).cast::<u32>().write(0);
        &*base.add(128).cast::<DigestKey>()
    };
    if let Some(other) = unsafe { DIGEST_INDEX.get(digest_key).copied() } {
        if other == 0 {
            return OUT_ABORT;
        }
        if !conflict_digest(other, request, family, object) {
            return OUT_POISON;
        }
        return OUT_ABORT;
    }
    // Exact insert from the staged key. A hit here means a lock-racer
    // published first, which is impossible under our lock.
    // `bound_lookup` leaves the key staged in `[0..144)` on every path.
    if bound_lookup(request, family, object).is_some() {
        return OUT_POISON;
    }
    let keyed = unsafe { (*slot).staging.as_mut_ptr().cast::<ExactNameKey>() };
    if EXACT_NAME
        .insert(unsafe { &*keyed }, &selector_relation, BPF_NOEXIST)
        .is_err()
    {
        return OUT_POISON;
    }
    // OBJECT_SELECTOR build. The plan digest at `[144..176)` is forwarded
    // staging-to-staging into the value tail at `[120..152)` with a
    // forward copy (every read precedes its source's overwrite by
    // construction, so no read observes a clobbered byte); the value words
    // around it are zeroed in two parts, preserving the forwarded digest.
    // After this write the plan is clobbered, so the projection and digest
    // index below read the digest back from the published OBJECT row.
    // Keep overlapping staging views on one raw base: a fresh mutable
    // array borrow would invalidate the value pointer before its stores.
    let staging_base = unsafe { addr_of_mut!((*slot).staging) };
    let value = staging_base.cast::<RelValue>();
    unsafe {
        let base = staging_base.cast::<u8>();
        let mut i = 0;
        while i < 32 {
            *base.add(120 + i) = *base.add(PLAN_DIGEST + i);
            i += 1;
        }
        let words = staging_base.cast::<u64>();
        let mut w = 0;
        while w < 15 {
            *words.add(w) = 0;
            w += 1;
        }
        w = 19;
        while w < 32 {
            *words.add(w) = 0;
            w += 1;
        }
        (*value).witness_id = selector_relation;
        (*value).parent_id = request;
        (*value).evidence_epoch = relation;
        (*value).born_ns = now_of();
        (*value).state = REL_WITNESS;
        (*value).data[0] = object;
        (*value).data[1] = u64::from(family);
        (*value).data[2] = request;
        (*value).data[3] = selector;
        (*value).data[4] = epoch;
        let key = RelKey {
            process_incarnation: 0,
            image_epoch: 0,
            relation_epoch: 0,
            primary_handle: selector_relation,
            secondary_handle: 0,
            kind: REL_OBJECT_SELECTOR,
            operation: family,
        };
        if REL.insert(&key, &*value, BPF_NOEXIST).is_err() {
            return OUT_POISON;
        }
    }
    // Safe projection and digest index, reading the digest back from the
    // published OBJECT row (the plan is clobbered by now). Both values are
    // staged in the cell; no digest bytes sit on the stack.
    let published_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: selector_relation,
        secondary_handle: 0,
        kind: REL_OBJECT_SELECTOR,
        operation: family,
    };
    let Some(published) = REL.get_ptr_mut(&published_key) else {
        return OUT_POISON;
    };
    let Some(control) = control_cell() else {
        return OUT_ABORT;
    };
    let session = unsafe { (*control).session_id };
    if session == 0 {
        return OUT_ABORT;
    }
    let projection = unsafe {
        (*slot)
            .staging
            .as_mut_ptr()
            .cast::<SelectorDictionaryValue>()
    };
    unsafe {
        (*projection).object_id = object;
        (*projection).operation = family;
        (*projection).encoding = SELECTOR_ENCODING;
        let mut i = 0;
        while i < 32 {
            (*projection).digest[i] = (*published).tail[i];
            i += 1;
        }
        (*projection).dictionary_epoch = epoch;
        (*projection).reserved = 0;
        let key = SelectorDictionaryKey {
            session_id: session,
            selector_id: selector,
        };
        if SELECTOR_DICT
            .insert(&key, &*projection, BPF_NOEXIST)
            .is_err()
        {
            return OUT_POISON;
        }
    }
    let digest_key = unsafe { (*slot).staging.as_mut_ptr().cast::<DigestKey>() };
    unsafe {
        (*digest_key).code_object_id = object;
        (*digest_key).operation = family;
        (*digest_key).reserved = 0;
        let mut i = 0;
        while i < 32 {
            (*digest_key).digest[i] = (*published).tail[i];
            i += 1;
        }
        if DIGEST_INDEX
            .insert(&*digest_key, &selector_relation, BPF_NOEXIST)
            .is_err()
        {
            return OUT_POISON;
        }
    }
    OUT_OK
}

/// Reauthorize the consuming site's source authority under the lock through
/// its own current site bind. A missing or zero bind refuses the commit.
#[no_mangle]
pub fn reauthorize_site(target: &Target, cookie: u64) -> bool {
    let Some(bound) = site_bind(cookie, target) else {
        return false;
    };
    ready_and_guards(cookie, bound.source_epoch, target.entry_seq, target)
}

/// Flip our pending X reservation to committed, recording the owner, peer,
/// family and commit sequence. The state word flips last with CAS: a
/// concurrent retire wins the race and fails the commit instead of being
/// resurrected by it. Tail subprogram: fields copy out of staging first.
#[inline(never)]
#[no_mangle]
pub fn flip_x_tail(tail: *const TailArgs) -> bool {
    let (process, image, relation, staged_x, occurrence, owner, owner_id, next_seq, family) = unsafe {
        (
            (*tail).process,
            (*tail).image,
            (*tail).relation,
            (*tail).staged_x,
            (*tail).occurrence,
            (*tail).owner,
            (*tail).owner_id,
            (*tail).next_seq,
            (*tail).family as u32,
        )
    };
    let key = RelKey {
        process_incarnation: process,
        image_epoch: image,
        relation_epoch: relation,
        primary_handle: staged_x,
        secondary_handle: 0,
        kind: REL_X_INDEX,
        operation: 0,
    };
    let Some(row) = REL.get_ptr_mut(&key) else {
        return false;
    };
    unsafe {
        if (*row).data[0] != 0
            || (*row).data[1] != occurrence
            || (*row).data[5] != 1
            || (*row).data[6] != u64::from(family)
        {
            return false;
        }
        (*row).witness_id = owner_id;
        (*row).data[0] = owner_id;
        (*row).data[4] = owner;
        (*row).data[6] = u64::from(family);
        (*row).data[7] = next_seq;
        compare(addr_of_mut!((*row).data[5]), 1, 2)
    }
}

/// Insert the committed U index row, reclaiming a retired row for the same
/// handle under the lock when address reuse left one behind. Returns the
/// outcome code: a live competing claim collides (conflict the old owner
/// inline, quarantine deferred to the dispatcher), anything impossible
/// poisons. Tail subprogram: fields copy out of cell 1 first; the value
/// build stages in cell 0.
#[inline(never)]
#[no_mangle]
pub fn insert_u_tail(tail: *const TailArgs) -> u64 {
    let (process, image, relation, owner, staged_x, owner_id, occurrence, next_seq, family, now_ns) = unsafe {
        (
            (*tail).process,
            (*tail).image,
            (*tail).relation,
            (*tail).owner,
            (*tail).staged_x,
            (*tail).owner_id,
            (*tail).occurrence,
            (*tail).next_seq,
            (*tail).family as u32,
            (*tail).now_ns,
        )
    };
    // Collide-path coordinates only: `collide_old_owner` and `live_index`
    // read process/image/relation and never the epochs, which the worker
    // already revalidated before staging this block.
    let target = Target {
        process,
        image,
        relation,
        loss_epoch: 0,
        entry_seq: 0,
    };
    let key = RelKey {
        process_incarnation: process,
        image_epoch: image,
        relation_epoch: relation,
        primary_handle: owner,
        secondary_handle: 0,
        kind: REL_U_INDEX,
        operation: 0,
    };
    if let Some(old) = REL.get_ptr_mut(&key) {
        let state = unsafe { (*old).data[5] };
        if state == 1 || state == 2 {
            collide_old_owner(&target, REL_U_INDEX, owner, old);
            return OUT_QU;
        }
        if state != 3 {
            return OUT_POISON;
        }
        // Sequenced reclaim of a retired row: the quarantine check above
        // already excluded a concurrent quarantine, and the lock excludes a
        // concurrent publisher, so this overwrite cannot resurrect either.
        unsafe {
            (*old).witness_id = owner_id;
            (*old).parent_id = occurrence;
            (*old).evidence_epoch = relation;
            (*old).born_ns = now_ns;
            (*old).state = REL_WITNESS;
            (*old).data[0] = owner_id;
            (*old).data[1] = occurrence;
            (*old).data[2] = 0;
            (*old).data[3] = 0;
            (*old).data[4] = staged_x;
            (*old).data[5] = 2;
            (*old).data[6] = u64::from(family);
            (*old).data[7] = next_seq;
            (*old).data[8] = 0;
            (*old).data[9] = 0;
        }
        return OUT_OK;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return OUT_POISON;
    };
    // From here the tail block is garbage: the value build reuses staging.
    // Every field above is already copied out.
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = owner_id;
        (*staging).parent_id = occurrence;
        (*staging).evidence_epoch = relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = owner_id;
        (*staging).data[1] = occurrence;
        (*staging).data[4] = staged_x;
        (*staging).data[5] = 2;
        (*staging).data[6] = u64::from(family);
        (*staging).data[7] = next_seq;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            return OUT_POISON;
        }
    }
    OUT_OK
}

/// Publish the OWNER_SELECTOR row binding this owner to its prepared
/// selector. Fresh keys cannot collide; any failure is impossible-state and
/// poisons. Tail subprogram: fields copy out of cell 1 first; the value
/// build stages in cell 0.
#[inline(never)]
#[no_mangle]
pub fn insert_owner_selector_tail(tail: *const TailArgs) -> bool {
    let (
        process,
        image,
        relation,
        owner_id,
        set_id,
        object,
        selector,
        epoch,
        request,
        source_epoch,
        family,
        now_ns,
    ) = unsafe {
        (
            (*tail).process,
            (*tail).image,
            (*tail).relation,
            (*tail).owner_id,
            (*tail).set_id,
            (*tail).object,
            (*tail).selector,
            (*tail).epoch,
            (*tail).request,
            (*tail).source_epoch,
            (*tail).family as u32,
            (*tail).now_ns,
        )
    };
    let key = RelKey {
        process_incarnation: process,
        image_epoch: image,
        relation_epoch: owner_id,
        primary_handle: set_id,
        secondary_handle: object,
        kind: REL_OWNER_SELECTOR,
        operation: family,
    };
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = set_id;
        (*staging).parent_id = owner_id;
        (*staging).evidence_epoch = relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = selector;
        (*staging).data[1] = epoch;
        (*staging).data[2] = request;
        (*staging).data[3] = source_epoch;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            return false;
        }
    }
    true
}

/// Publish the immutable OWNER row. Fresh keys cannot collide; any failure
/// is impossible-state and poisons. Tail subprogram: fields copy out of
/// cell 1 first; the value build stages in cell 0.
#[inline(never)]
#[no_mangle]
pub fn insert_owner_tail(tail: *const TailArgs) -> bool {
    let (process, image, relation) = unsafe { ((*tail).process, (*tail).image, (*tail).relation) };
    let (owner_id, owner, staged_x, family) = unsafe {
        (
            (*tail).owner_id,
            (*tail).owner,
            (*tail).staged_x,
            (*tail).family as u32,
        )
    };
    let (method, method_observation, request) =
        unsafe { ((*tail).method, (*tail).method_observation, (*tail).request) };
    let (continuity, set_id, context_epoch, provider, next_seq, now_ns) = unsafe {
        (
            (*tail).continuity,
            (*tail).set_id,
            (*tail).context_epoch,
            (*tail).provider,
            (*tail).next_seq,
            (*tail).now_ns,
        )
    };
    let key = RelKey {
        process_incarnation: process,
        image_epoch: image,
        relation_epoch: owner_id,
        primary_handle: owner,
        secondary_handle: staged_x,
        kind: REL_OWNER,
        operation: family,
    };
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
    unsafe {
        staging.write_bytes(0, 1);
        (*staging).witness_id = owner_id;
        (*staging).parent_id = method_observation;
        (*staging).evidence_epoch = relation;
        (*staging).born_ns = now_ns;
        (*staging).state = REL_WITNESS;
        (*staging).data[0] = continuity;
        (*staging).data[1] = request;
        (*staging).data[2] = set_id;
        (*staging).data[3] = context_epoch;
        (*staging).data[4] = provider;
        (*staging).data[5] = relation;
        (*staging).data[6] = 0;
        (*staging).data[7] = method;
        (*staging).data[8] = next_seq;
        if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
            return false;
        }
    }
    true
}

/// A bound prepared selector: the shared immutable (object, operation,
/// request) identity plus its safe-dictionary coordinates.
pub(crate) struct BoundSelector {
    object: u64,
    selector: u64,
    epoch: u64,
}

/// Adopt an existing bound selector after full validation of its immutable
/// row. A mismatching row is impossible-state and poisons. A real
/// subprogram so the reuse path keeps the caller's frame shallow.
#[inline(never)]
#[no_mangle]
pub fn reuse_bound_selector(
    selector_relation: u64,
    code_object: u64,
    family: u32,
    request: u64,
    out: &mut BoundSelector,
) -> bool {
    match reuse_bound_selector_opt(selector_relation, code_object, family, request) {
        Some(value) => {
            *out = value;
            true
        }
        None => false,
    }
}

/// Original body, always inlined into the global wrapper above: BPF
/// subprograms cannot return aggregates across the external ABI, so the
/// wrapper converts to an out-parameter plus a boolean.
#[inline(always)]
fn reuse_bound_selector_opt(
    selector_relation: u64,
    code_object: u64,
    family: u32,
    request: u64,
) -> Option<BoundSelector> {
    let key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: selector_relation,
        secondary_handle: 0,
        kind: REL_OBJECT_SELECTOR,
        operation: family,
    };
    let Some(row) = REL.get_ptr_mut(&key) else {
        return None;
    };
    let (object, operation, bound_request, selector, epoch, live) = unsafe {
        (
            (*row).data[0],
            (*row).data[1] as u32,
            (*row).data[2],
            (*row).data[3],
            (*row).data[4],
            row_state_is(row, REL_WITNESS),
        )
    };
    if !live
        || object != code_object
        || operation != family
        || bound_request != request
        || selector == 0
        || epoch == 0
    {
        return None;
    }
    Some(BoundSelector {
        object: code_object,
        selector,
        epoch,
    })
}

/// Resolve a digest-index hit against our candidate: equal exact bytes are
/// impossible (our exact lookup missed), so unequal bytes conflict the live
/// selector and refuse the candidate. Both the index (to zero) and the live
/// row are conflicted before any later positive. A real subprogram: the only
/// caller is the publish conflict gate, where staging `[0..48)` is dead
/// scratch, so the rebuilt key stages there instead of costing 80 stack
/// bytes.
#[inline(never)]
#[no_mangle]
pub fn conflict_digest(other_relation: u64, request: u64, family: u32, code_object: u64) -> bool {
    let other_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: other_relation,
        secondary_handle: 0,
        kind: REL_OBJECT_SELECTOR,
        operation: family,
    };
    let Some(other_row) = REL.get_ptr_mut(&other_key) else {
        return false;
    };
    let (other_object, other_operation, other_request, live) = unsafe {
        (
            (*other_row).data[0],
            (*other_row).data[1] as u32,
            (*other_row).data[2],
            row_state_is(other_row, REL_WITNESS),
        )
    };
    if !live || other_object != code_object || other_operation != family || other_request == 0 {
        return false;
    }
    // Compare exact bytes through both immutable request rows.
    let our_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: request,
        secondary_handle: 0,
        kind: REL_REQUEST_NAME,
        operation: family,
    };
    let their_key = RelKey {
        process_incarnation: 0,
        image_epoch: 0,
        relation_epoch: 0,
        primary_handle: other_request,
        secondary_handle: 0,
        kind: REL_REQUEST_NAME,
        operation: family,
    };
    let (Some(our_row), Some(their_row)) = (REL.get_ptr_mut(&our_key), REL.get_ptr_mut(&their_key))
    else {
        return false;
    };
    let (our_len, their_len) = unsafe { ((*our_row).data[1], (*their_row).data[1]) };
    let mut equal = our_len == their_len && our_len != 0;
    let mut i = 0;
    while i < 128 {
        if unsafe { (*our_row).tail[i] != (*their_row).tail[i] } {
            equal = false;
        }
        i += 1;
    }
    if equal {
        // Same exact bytes with a missed exact lookup is a logic error:
        // fail closed rather than certifying on inconsistent indexes.
        return false;
    }
    conflict_row(other_row);
    // The digest key is rebuilt from the live row's stored digest into
    // staging `[0..48)`: header first, then the 32 digest bytes copied one
    // at a time (register only, nothing on the stack).
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let keyed = unsafe { (*slot).staging.as_mut_ptr().cast::<DigestKey>() };
    unsafe {
        (*keyed).code_object_id = code_object;
        (*keyed).operation = family;
        (*keyed).reserved = 0;
        let mut i = 0;
        while i < 32 {
            (*keyed).digest[i] = (*other_row).tail[i];
            i += 1;
        }
        let zero = 0u64;
        if DIGEST_INDEX.insert(&*keyed, &zero, 0).is_err() {
            return false;
        }
    }
    loss(LOSS_CONFLICT);
    true
}

/// Capture the atomic published sequence for one callback entry. The
/// focused handler calls this before any attribution decision or physical
/// mutation and passes the snapshot to `operational_check`, so selected
/// owners and dependencies must already be published in that snapshot.
#[allow(dead_code)]
#[no_mangle]
pub fn capture_entry_seq() -> u64 {
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        return 0;
    };
    unsafe { ordered_read(addr_of_mut!((*state).published_sequence)) }
}

/// Same-handler operational check, called by the focused counter after a
/// successful physical store in the same count generation. Resolves the
/// callback's provider context X to its committed owner and prepared
/// selector, then assigns at most one partition to this hit. Any miss
/// leaves the stored physical hit unresolved. Role 308 (KDF reset) retires
/// instead of attributing and never produces a partition.
///
/// The check splits into three shallow sequential phases sharing
/// per-CPU staging (BPF shares one 512-byte stack across the chain, so
/// one frame cannot hold the resolution and the 104-byte key, and the
/// 6.9 verifier sums caller frames along the path): phase A
/// (`op_resolve_segment_a`) validates admission, authority, committed
/// X/OWNER and tombstones, then stages a handoff; phase B
/// (`op_resolve_segment_b`) validates the selector, projection and
/// digest, allocates the segment, and stages the tuple;
/// `op_store_partition` re-checks freshness and inserts. Staging is
/// per-CPU private to a non-preemptible run — BPF programs run to
/// completion, so no nested handler can interleave — and the store
/// revalidates liveness, so a race that retires between the siblings
/// fails closed.
#[allow(dead_code)]
#[no_mangle]
pub fn operational_check(ctx: &ProbeContext, params: &OpParams) -> bool {
    if !writer_gate::admitted() {
        return false;
    }
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(params.tgid, params.entry_seq, &mut target) {
        return false;
    }
    let Some(admitted) = admission_ptr(params.cookie, &target) else {
        return false;
    };
    let (role, operation, function) = unsafe {
        (
            (*admitted).role_id,
            (*admitted).operation,
            (*admitted).function,
        )
    };
    if !matches!(role, 304 | 305 | 306 | 307 | 308) {
        return false;
    }
    if role == 308 {
        // KDF reset retires its dependent owner before the target body.
        // Retirement is fail-closed, so it needs admission but not source
        // authority: an authority lapse must still retire, never certify.
        // This retire sits above the CODE_ROLE join (admission-only):
        // placing it below would narrow retirement to authorized sites,
        // letting a pre-reset owner survive an authority lapse.
        let context: u64 = ctx.arg(0).unwrap_or(0);
        if context == 0 {
            return false;
        }
        retire_owner_reachable(&target, REL_X_INDEX, context);
        return false;
    }
    // 304-307: the joined exact identity plus SOURCE_READY/guards and
    // exact CODE_ROLE authority precede every argument read, including
    // the resolver's read below.
    let opfun = (u64::from(function) << 32) | u64::from(operation);
    let Some((inode, file_offset)) = join_firing_identity(ctx) else {
        return false;
    };
    if !code_role_check(&target, params.cookie, inode, file_offset, opfun) {
        return false;
    }
    let context: u64 = ctx.arg(0).unwrap_or(0);
    if context == 0 {
        return false;
    }
    if !op_resolve_segment_a(ctx, params) {
        return false;
    }
    let segment = op_resolve_segment_b(params);
    if segment == 0 {
        return false;
    }
    op_store_partition(params, segment)
}

/// Attribution tuple staging offsets in the per-CPU cell's first half:
/// eighteen words the resolver stages for the store. [0..8) owner ID,
/// [8..16) owner handle U, [16..24) continuity, [24..32) prepared set,
/// [32..40) evidence epoch, [40..48) owner sequence, [48..56) method,
/// [56..64) definition, [64..72) selector, [72..80) dictionary epoch,
/// [80..88) site, [88..96) source epoch, [96..104) code object,
/// [104..112) operation, [112..120) function, [120..128) segment,
/// [128..136) session, [136..144) cut.

/// Operational phase scratch in ITER_SLOT cell 0 (`staging` words).
/// Words 0..18 carry the attribution tuple from the resolve phases to
/// the store sibling. Words 18..32 are phase scratch, reused
/// sequentially and never overlapping live data:
///
/// - Phase A stages transient lookup keys at `KEY_SCRATCH` (six words
///   cover any RelKey-class key) and, after its last lookup, writes
///   the thirteen-word handoff at `HANDOFF` (words 18..31).
/// - Phase B first copies the handoff into the tuple words, then
///   reuses `KEY_SCRATCH` for its own lookup keys; every later read
///   comes from the tuple, never from the clobbered handoff.
/// - The store sibling reads the tuple (words 0..18) while scratching
///   keys in the disjoint upper words (RelKey at `KEY_SCRATCH`,
///   PartitionKey at `PARTITION_SCRATCH`, words 18..31).
///
/// Every phase fully rewrites its scratch before reading. Sequential
/// reuse on one CPU is sound: BPF runs to completion, so no async user
/// interleaves, and the VMA join's slot use in `operational_check`
/// completes (releases) before the first phase runs — the same
/// discipline the tuple staging already relies on.
const KEY_SCRATCH: usize = 18;
const PARTITION_SCRATCH: usize = 18;
const HANDOFF: usize = 18;
/// Handoff words: owner_id, owner_handle, continuity, set_id,
/// evidence, method, definition, site_id, source_epoch, code_object,
/// operation, function, context.
const HANDOFF_WORDS: usize = 13;
const _: () = assert!(HANDOFF + HANDOFF_WORDS <= 32);
const _: () = assert!(KEY_SCRATCH + 6 <= 32);
const _: () = assert!(PARTITION_SCRATCH + 13 <= 32);

/// Stage one RelKey-class key (48 bytes) in phase scratch, field by
/// field so the compiler owns the layout. Returns a lookup pointer.
/// Each lookup fully rewrites the six words.
#[inline(always)]
fn stage_rel_key(
    slot: *mut osslscope_bpf_contract::source::SourceSlot,
    process: u64,
    image: u64,
    relation: u64,
    primary: u64,
    secondary: u64,
    kind: u32,
    operation: u32,
) -> *mut RelKey {
    unsafe {
        let staged = (*slot)
            .staging
            .as_mut_ptr()
            .add(KEY_SCRATCH)
            .cast::<RelKey>();
        (*staged).process_incarnation = process;
        (*staged).image_epoch = image;
        (*staged).relation_epoch = relation;
        (*staged).primary_handle = primary;
        (*staged).secondary_handle = secondary;
        (*staged).kind = kind;
        (*staged).operation = operation;
        staged
    }
}

/// First operational phase: admission, source authority, committed X
/// and OWNER at or before the entry snapshot, and tombstones. Stages
/// the thirteen-word handoff for phase B and returns true, or false on
/// any miss. Split from phase B so no single frame holds the whole
/// resolution live range (the 6.9 verifier sums caller frames along
/// the path against 512 bytes).
#[inline(never)]
#[no_mangle]
pub fn op_resolve_segment_a(ctx: &ProbeContext, params: &OpParams) -> bool {
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(params.tgid, params.entry_seq, &mut target) {
        return false;
    }
    let Some(admitted) = admission_ptr(params.cookie, &target) else {
        return false;
    };
    let (operation, function) = unsafe { ((*admitted).operation, (*admitted).function) };
    let Some(bound) = site_bind_ptr(params.cookie, &target) else {
        return false;
    };
    let (site_id, source_epoch, code_object) = unsafe {
        (
            (*bound).site_id,
            (*bound).source_epoch,
            (*bound).code_object_id,
        )
    };
    // SOURCE_READY/guards precede this phase's own argument read. Exact
    // CODE_ROLE authority was validated by `operational_check` before
    // this call in the same non-preemptible run, so no second VMA join
    // is due here; this guard re-check keeps the phase
    // self-sufficiently ordered for any future caller.
    if !ready_and_guards(params.cookie, source_epoch, target.entry_seq, &target) {
        return false;
    }
    let context: u64 = ctx.arg(0).unwrap_or(0);
    if context == 0 {
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    // Committed X row at or before the entry snapshot, for this family.
    let index_key = stage_rel_key(
        slot,
        target.process,
        target.image,
        target.relation,
        context,
        0,
        REL_X_INDEX,
        0,
    );
    let Some(index) = REL.get_ptr_mut(unsafe { &*index_key }) else {
        return false;
    };
    let (owner_id, owner_handle, index_family, index_seq, committed) = unsafe {
        (
            (*index).data[0],
            (*index).data[4],
            (*index).data[6] as u32,
            (*index).data[7],
            (*index).data[5] == 2,
        )
    };
    if !committed
        || owner_id == 0
        || owner_handle == 0
        || index_family != operation
        || index_seq == 0
        || index_seq > target.entry_seq
    {
        return false;
    }
    // Owner row: live, same identity, published at or before the snapshot.
    let owner_key = stage_rel_key(
        slot,
        target.process,
        target.image,
        owner_id,
        owner_handle,
        context,
        REL_OWNER,
        operation,
    );
    let Some(owner_row) = REL.get_ptr_mut(unsafe { &*owner_key }) else {
        return false;
    };
    let owner_ok = unsafe {
        row_state_is(owner_row, REL_WITNESS)
            && (*owner_row).witness_id == owner_id
            && (*owner_row).data[0] != 0
            && (*owner_row).data[2] != 0
            && (*owner_row).evidence_epoch != 0
            && (*owner_row).data[8] != 0
            && (*owner_row).data[8] <= target.entry_seq
            && (*owner_row).data[7] != 0
    };
    if !owner_ok {
        return false;
    }
    // Extract the ambiguity method alone for the tombstone checks; the
    // remaining owner fields are extracted after them so they never
    // spill across the nested quarantine calls (narrow frame).
    let method = unsafe { (*owner_row).data[7] };
    // Tombstones: quarantined contexts and ambiguous methods never certify.
    let ambiguity = stage_rel_key(
        slot,
        target.process,
        target.image,
        0,
        method,
        0,
        REL_METHOD_AMBIGUITY,
        operation,
    );
    if quarantined(&target, context, QUARANTINE_CONTEXT_X)
        || quarantined(&target, owner_handle, QUARANTINE_OWNER_U)
        || REL.get_ptr_mut(unsafe { &*ambiguity }).is_some()
    {
        return false;
    }
    // Handoff for phase B (thirteen words); this overwrites the key
    // scratch above, whose lookups are all complete. Owner fields are
    // extracted here, after the last nested call, so they stay in
    // registers on the way to staging.
    let (continuity, set_id, evidence, definition) = unsafe {
        (
            (*owner_row).data[0],
            (*owner_row).data[2],
            (*owner_row).evidence_epoch,
            (*owner_row).data[6],
        )
    };
    unsafe {
        let base = (*slot).staging.as_mut_ptr().add(HANDOFF);
        base.add(0).write(owner_id);
        base.add(1).write(owner_handle);
        base.add(2).write(continuity);
        base.add(3).write(set_id);
        base.add(4).write(evidence);
        base.add(5).write(method);
        base.add(6).write(definition);
        base.add(7).write(site_id);
        base.add(8).write(source_epoch);
        base.add(9).write(code_object);
        base.add(10).write(u64::from(operation));
        base.add(11).write(u64::from(function));
        base.add(12).write(context);
    }
    true
}
/// Read one phase-handoff word from per-CPU staging.
#[inline(always)]
fn handoff_word(slot: *mut osslscope_bpf_contract::source::SourceSlot, word: usize) -> u64 {
    unsafe { (*slot).staging.as_mut_ptr().add(HANDOFF + word).read() }
}

/// Second operational phase: prepared selector, safe projection,
/// digest conflict refusal, and the once-per-tuple segment allocation.
/// Consumes phase A's handoff with an early copy into the tuple words,
/// then reuses the handoff words as key scratch; every later read
/// comes from the tuple, never from the clobbered handoff. Stages the
/// attribution tuple and returns the nonzero segment, or zero on any
/// miss.
#[inline(never)]
#[no_mangle]
pub fn op_resolve_segment_b(params: &OpParams) -> u64 {
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return 0;
    };
    tuple_store(slot, 0, handoff_word(slot, 0));
    tuple_store(slot, 1, handoff_word(slot, 1));
    tuple_store(slot, 2, handoff_word(slot, 2));
    tuple_store(slot, 3, handoff_word(slot, 3));
    tuple_store(slot, 4, handoff_word(slot, 4));
    tuple_store(slot, 5, handoff_word(slot, 5));
    tuple_store(slot, 6, handoff_word(slot, 6));
    tuple_store(slot, 9, handoff_word(slot, 7));
    tuple_store(slot, 10, handoff_word(slot, 8));
    tuple_store(slot, 11, handoff_word(slot, 9));
    tuple_store(slot, 12, handoff_word(slot, 10));
    tuple_store(slot, 13, handoff_word(slot, 11));
    tuple_store(slot, 17, handoff_word(slot, 12));
    // From here on every read comes from the tuple; words 18..32 are
    // transient key scratch.
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(params.tgid, params.entry_seq, &mut target) {
        return 0;
    }
    let owner_id = tuple_word(slot, 0);
    let set_id = tuple_word(slot, 3);
    let code_object = tuple_word(slot, 11);
    let operation = tuple_word(slot, 12) as u32;
    if owner_id == 0 || set_id == 0 || code_object == 0 {
        return 0;
    }
    // This site's prepared selector for the firing code object.
    let selector_key = stage_rel_key(
        slot,
        target.process,
        target.image,
        owner_id,
        set_id,
        code_object,
        REL_OWNER_SELECTOR,
        operation,
    );
    let Some(selector_row) = REL.get_ptr_mut(unsafe { &*selector_key }) else {
        return 0;
    };
    let (parent, selector, dictionary_epoch, selector_live) = unsafe {
        (
            (*selector_row).parent_id,
            (*selector_row).data[0],
            (*selector_row).data[1],
            row_state_is(selector_row, REL_WITNESS),
        )
    };
    if !selector_live || parent != owner_id || selector == 0 || dictionary_epoch == 0 {
        return 0;
    }
    tuple_store(slot, 7, selector);
    tuple_store(slot, 8, dictionary_epoch);
    // Safe dictionary projection: exact object, family, encoding and epoch.
    let Some(control) = control_cell() else {
        return 0;
    };
    let (session, cut_id) = unsafe { ((*control).session_id, (*control).cut_id) };
    if session == 0 || cut_id == 0 {
        return 0;
    }
    let dictionary_key = SelectorDictionaryKey {
        session_id: session,
        selector_id: selector,
    };
    let Some(dictionary) = SELECTOR_DICT.get_ptr_mut(&dictionary_key) else {
        return 0;
    };
    let dictionary_ok = unsafe {
        (*dictionary).object_id == code_object
            && (*dictionary).operation == operation
            && (*dictionary).encoding == SELECTOR_ENCODING
            && (*dictionary).dictionary_epoch == dictionary_epoch
            && (*dictionary).reserved == 0
    };
    if !dictionary_ok {
        return 0;
    }
    // Digest conflict refusal: an absent or zeroed digest entry withholds
    // the hit. The index value cannot name our exact relation here, but a
    // recorded collision zeroes it, which this check refuses.
    if !digest_live_staged(slot, code_object, operation, unsafe {
        &(*dictionary).digest
    }) {
        return 0;
    }
    // One segment per immutable tuple, allocated once and reused.
    let site_id = tuple_word(slot, 9);
    let function = tuple_word(slot, 13) as u32;
    let segment_key = SegmentIndexKey {
        site_id,
        owner_id,
        count_generation: params.generation,
        operation,
        function,
        reserved: 0,
    };
    let segment = match unsafe { SEGMENT_INDEX.get(&segment_key).copied() } {
        Some(value) if value != 0 => value,
        _ => {
            if !spend(1) {
                return 0;
            }
            let mut fresh = 0u64;
            if !alloc_id(control, &mut fresh) {
                return 0;
            }
            if SEGMENT_INDEX
                .insert(&segment_key, &fresh, BPF_NOEXIST)
                .is_err()
            {
                match unsafe { SEGMENT_INDEX.get(&segment_key).copied() } {
                    Some(value) if value != 0 => value,
                    _ => {
                        loss(LOSS_MAP);
                        return 0;
                    }
                }
            } else {
                fresh
            }
        }
    };
    tuple_store(slot, 14, segment);
    tuple_store(slot, 15, session);
    tuple_store(slot, 16, cut_id);
    segment
}

/// Store one attribution-tuple word into per-CPU staging.
#[inline(always)]
fn tuple_store(slot: *mut osslscope_bpf_contract::source::SourceSlot, index: usize, value: u64) {
    unsafe {
        (*slot).staging.as_mut_ptr().add(index).write(value);
    }
}

/// Load one attribution-tuple word from per-CPU staging.
#[inline(always)]
fn tuple_word(slot: *mut osslscope_bpf_contract::source::SourceSlot, index: usize) -> u64 {
    unsafe { (*slot).staging.as_mut_ptr().add(index).read() }
}

/// Digest conflict refusal for one (object, operation, digest) triple:
/// absent or zeroed entries withhold the hit. The key is staged in
/// phase scratch (six words) so no 48-byte DigestKey shares the
/// narrow frame.
#[inline(always)]
fn digest_live_staged(
    slot: *mut osslscope_bpf_contract::source::SourceSlot,
    code_object: u64,
    operation: u32,
    digest: &[u8; 32],
) -> bool {
    unsafe {
        let staged = (*slot)
            .staging
            .as_mut_ptr()
            .add(KEY_SCRATCH)
            .cast::<DigestKey>();
        (*staged).code_object_id = code_object;
        (*staged).operation = operation;
        (*staged).reserved = 0;
        (*staged).digest = *digest;
        matches!(DIGEST_INDEX.get(&*staged).copied(), Some(value) if value != 0)
    }
}

/// Stage one PartitionKey (104 bytes, thirteen words) in phase
/// scratch, reading the tuple fields at build time so they are never
/// live across the freshness lookups. Returns a lookup/insert pointer.
#[inline(always)]
fn stage_partition_key(
    slot: *mut osslscope_bpf_contract::source::SourceSlot,
    segment: u64,
    generation: u32,
    operation: u32,
    source_epoch: u64,
) -> Option<*mut PartitionKey> {
    let session = tuple_word(slot, 15);
    let cut_id = tuple_word(slot, 16);
    let site_id = tuple_word(slot, 9);
    let definition = tuple_word(slot, 6);
    let continuity = tuple_word(slot, 2);
    let selector = tuple_word(slot, 7);
    let dictionary_epoch = tuple_word(slot, 8);
    let evidence = tuple_word(slot, 4);
    let function = tuple_word(slot, 13) as u32;
    if continuity == 0
        || selector == 0
        || dictionary_epoch == 0
        || site_id == 0
        || session == 0
        || cut_id == 0
        || evidence == 0
    {
        return None;
    }
    unsafe {
        let staged = (*slot)
            .staging
            .as_mut_ptr()
            .add(PARTITION_SCRATCH)
            .cast::<PartitionKey>();
        (*staged).version = VERSION;
        (*staged).size = 128;
        (*staged).session_id = session;
        (*staged).cut_id = cut_id;
        (*staged).site_id = site_id;
        (*staged).segment_id = segment;
        (*staged).provider_definition_object_id = definition;
        (*staged).provider_continuity_id = continuity;
        (*staged).selector_id = selector;
        (*staged).dictionary_epoch = dictionary_epoch;
        (*staged).relation_epoch = evidence;
        (*staged).source_epoch = source_epoch;
        (*staged).count_generation = generation;
        (*staged).operation = operation;
        (*staged).function = function;
        (*staged).selector_encoding = SELECTOR_ENCODING;
        Some(staged)
    }
}

/// Second operational sibling: re-check liveness (committed X, live OWNER,
/// source authority) so a race that retires between the siblings fails
/// closed, then build the 104-byte key and insert or bump the one partition
/// for this hit in this same generation.
#[inline(never)]
#[no_mangle]
pub fn op_store_partition(params: &OpParams, segment: u64) -> bool {
    if segment == 0 {
        return false;
    }
    let mut target: Target = unsafe { core::mem::zeroed() };
    if !resolve_inner(params.tgid, params.entry_seq, &mut target) {
        return false;
    }
    let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    // Read tuple words on demand through the staging pointer: no array
    // copy and no eighteen-local destructure share the narrow frame.
    let staged_segment = tuple_word(slot, 14);
    let context = tuple_word(slot, 17);
    if staged_segment != segment || context == 0 {
        return false;
    }
    let owner_id = tuple_word(slot, 0);
    let owner_handle = tuple_word(slot, 1);
    let operation = tuple_word(slot, 12) as u32;
    if owner_id == 0 || owner_handle == 0 || !matches!(operation, 3 | 4) {
        return false;
    }
    // Freshness: the X row is still committed for this owner, the OWNER row
    // is still live, and the site's source authority still holds. Anything
    // that retired between the siblings refuses the store.
    let index_key = stage_rel_key(
        slot,
        target.process,
        target.image,
        target.relation,
        context,
        0,
        REL_X_INDEX,
        0,
    );
    let Some(index) = REL.get_ptr_mut(unsafe { &*index_key }) else {
        return false;
    };
    let index_ok = unsafe {
        (*index).data[0] == owner_id
            && (*index).data[4] == owner_handle
            && (*index).data[5] == 2
            && (*index).data[6] == u64::from(operation)
            && (*index).data[7] != 0
            && (*index).data[7] <= target.entry_seq
    };
    if !index_ok {
        return false;
    }
    let owner_key = stage_rel_key(
        slot,
        target.process,
        target.image,
        owner_id,
        owner_handle,
        context,
        REL_OWNER,
        operation,
    );
    let Some(owner_row) = REL.get_ptr_mut(unsafe { &*owner_key }) else {
        return false;
    };
    let owner_ok = unsafe {
        row_state_is(owner_row, REL_WITNESS)
            && (*owner_row).witness_id == owner_id
            && (*owner_row).data[8] != 0
            && (*owner_row).data[8] <= target.entry_seq
    };
    if !owner_ok {
        return false;
    }
    let source_epoch = tuple_word(slot, 10);
    if source_epoch == 0 {
        return false;
    }
    if quarantined(&target, context, QUARANTINE_CONTEXT_X)
        || quarantined(&target, owner_handle, QUARANTINE_OWNER_U)
        || !ready_and_guards(params.cookie, source_epoch, target.entry_seq, &target)
    {
        return false;
    }
    // The one partition write for this hit, in this same generation.
    // The 104-byte key is staged in phase scratch (disjoint from the
    // live tuple words); the tuple fields are read at build time so
    // they are never live across the freshness lookups above.
    let Some(key) = stage_partition_key(slot, segment, params.generation, operation, source_epoch)
    else {
        return false;
    };
    let key = unsafe { &*key };
    if let Some(slot) = PARTITION.get_ptr_mut(key) {
        unsafe {
            if (*slot).calls == 0 {
                (*slot).first_ns = params.now_ns;
            }
            (*slot).calls = (*slot).calls.saturating_add(1);
            (*slot).last_ns = params.now_ns;
        }
        return true;
    }
    let fresh = PartitionValue {
        calls: 1,
        first_ns: params.now_ns,
        last_ns: params.now_ns,
    };
    let inserted = PARTITION.insert(key, &fresh, BPF_NOEXIST).is_ok();
    if let Some(slot) = PARTITION.get_ptr_mut(key) {
        if inserted {
            return true;
        }
        // A racing insert won and this hit still needs its count.
        unsafe {
            if (*slot).calls == 0 {
                (*slot).first_ns = params.now_ns;
            }
            (*slot).calls = (*slot).calls.saturating_add(1);
            (*slot).last_ns = params.now_ns;
        }
        return true;
    }
    loss(LOSS_MAP);
    false
}

/// Retire one thread's producer state: its incarnation row plus its at-most-8
/// pending depth slots, each released with its quota claim. Runs
/// synchronously in the exit root before kernel TID reuse. Present rows
/// that fail deletion poison, because an unretired row could certify for a
/// recycled TID; absent rows are quiet.
#[no_mangle]
pub fn retire_thread(device: u64, inode: u64) {
    use aya_ebpf::bindings::bpf_pidns_info;
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    if unsafe { helpers::bpf_get_ns_current_pid_tgid(device, inode, &mut ids, 8) } != 0 {
        poison_domain();
        loss(LOSS_PAIR);
        return;
    }
    let Some(process) = process_of(ids.tgid) else {
        return;
    };
    if ids.pid == 0 {
        return;
    }
    let key = ThreadIdentityKey {
        process_incarnation: process,
        tid: ids.pid,
        reserved: 0,
    };
    let Some(found) = (unsafe { THREAD_IDENTITY.get(&key).copied() }) else {
        return;
    };
    if found.thread_incarnation == 0 || found.image_epoch == 0 {
        return;
    }
    retire_thread_rows(
        process,
        ids.pid,
        found.thread_incarnation,
        found.image_epoch,
    );
}

/// Retire the execing thread's producer state before the image transition.
/// Sibling threads retire through their own synchronous exits; the execing
/// thread's old-image rows must be gone before new-image activity starts.
#[no_mangle]
pub fn retire_image(device: u64, inode: u64) {
    use aya_ebpf::bindings::bpf_pidns_info;
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    if unsafe { helpers::bpf_get_ns_current_pid_tgid(device, inode, &mut ids, 8) } != 0 {
        poison_domain();
        loss(LOSS_PAIR);
        return;
    }
    let Some(process) = process_of(ids.tgid) else {
        return;
    };
    if ids.pid == 0 {
        return;
    }
    let key = ThreadIdentityKey {
        process_incarnation: process,
        tid: ids.pid,
        reserved: 0,
    };
    let Some(found) = (unsafe { THREAD_IDENTITY.get(&key).copied() }) else {
        return;
    };
    if found.thread_incarnation == 0 || found.image_epoch == 0 {
        return;
    }
    retire_thread_rows(
        process,
        ids.pid,
        found.thread_incarnation,
        found.image_epoch,
    );
}

/// Delete one thread's incarnation row and its pending frames. The row is
/// read first so the frame keys use the retired incarnation even if the row
/// is gone by the time the frames are visited.
#[no_mangle]
pub fn retire_thread_rows(process: u64, tid: u32, incarnation: u64, image: u64) {
    let key = ThreadIdentityKey {
        process_incarnation: process,
        tid,
        reserved: 0,
    };
    if THREAD_IDENTITY.get_ptr_mut(&key).is_some() && THREAD_IDENTITY.remove(&key).is_err() {
        poison_domain();
        loss(LOSS_PAIR);
    }
    let mut depth = 0;
    while depth < MAX_DEPTH {
        let frame_key = BindPendingKey {
            process_incarnation: process,
            image_epoch: image,
            thread_incarnation: incarnation,
            depth,
            reserved: 0,
        };
        if BIND_PENDING.get_ptr_mut(&frame_key).is_some() {
            if BIND_PENDING.remove(&frame_key).is_err() {
                poison_domain();
                loss(LOSS_PAIR);
            } else if !crate::source_state::release_pending() {
                loss(LOSS_PAIR);
            }
        }
        depth += 1;
    }
}

/// Our X reservation is still pending for this occurrence and family.
#[no_mangle]
pub fn own_pending_x(
    target: &Target,
    frame: *mut BindPendingValue,
    staged_x: u64,
    family: u32,
) -> bool {
    let occurrence = unsafe { (*frame).occurrence_id };
    if occurrence == 0 || staged_x == 0 {
        return false;
    }
    let key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: target.relation,
        primary_handle: staged_x,
        secondary_handle: 0,
        kind: REL_X_INDEX,
        operation: 0,
    };
    let Some(row) = REL.get_ptr_mut(&key) else {
        return false;
    };
    unsafe {
        (*row).data[0] == 0
            && (*row).data[1] == occurrence
            && (*row).data[5] == 1
            && (*row).data[6] == u64::from(family)
    }
}

/// U1 copied-role live authority (CODE_ROLE, REL kind 5).
///
/// A staged copied-role site (constructor 258/259, lifecycle 274/275,
/// dup 290/291, operational 304-308) carries host-programmed admission,
/// but admission alone never authorizes an operand read: every copied
/// path additionally requires a kernel-published CODE_ROLE row proving
/// that a completed natural live query for the same (operation,
/// function) advertised code in the firing callback's own file.
///
/// Publication: the typed query role (161) walks the live returned
/// OSSL_ALGORITHM/OSSL_DISPATCH tables at query return (public UAPI
/// layouts only), joins each in-slice callback address to its exact
/// (inode, file offset) through the current-VMA join, and publishes one
/// CERTIFIED row per (process, image, inode, file offset, operation,
/// function) carrying that observed offset in the key and the value.
/// CERTIFIED means code ABI only, never provider identity.
///
/// Join: at copied-role entry the handler takes the kernel-supplied
/// firing IP (no subtraction: Linux rewinds it to the probe address),
/// joins it to the same (inode, file offset) through the same VMA
/// policy, requires the firing cookie's retained registration/source
/// epoch to be live, requires the joined identity to equal the
/// registration-time identity retained for that cookie (SOURCE_REG
/// offset plus SOURCE_ANCHOR inode, with witness relationships — a
/// snapshot taken after a concurrent remap joins the transient
/// identity and must never authorize), and requires the matching row
/// — same observed offset, publication sequence at or before the entry
/// snapshot. Return paths pair to entry-verified frames and need no
/// second join. A query advertising callback A never authorizes a
/// separately staged callback B at another offset in the same file:
/// the offsets differ.
///
/// Key amendment note: the source-capability contract sketches
/// cookie-keyed CODE_ROLE rows, but the firing cookie does not exist at
/// query time, so cookie keying cannot be published from a live walk.
/// Two-phase binding preserves the amendment's intent with a stronger,
/// kernel-grounded identity: phase 1 publishes the VMA-joined exact
/// inode-and-offset without any cookie; phase 2 (this join) binds it
/// to the consuming cookie's live registration/source epoch. The
/// retained anchor's pinned file pins the inode for the session (no
/// reuse aliasing), and the registration-time anchor join still
/// precedes every use. Host staging (offsets from retained dispatch
/// bytes) is a claim; this join is the kernel's independent
/// verification of it.
///
/// Walk bounds: the first 64 algorithms and 32 dispatch entries per
/// table publish; anything beyond stops with LOSS_MAP and stays
/// unauthorized (fail closed). Real MAC/KDF tables are far smaller.
/// U1 publishes cacheable queries only; no-store queries stay
/// unpublished (documented limit, not silent manufacture).

/// Query-walk bounds (see the section doc above).
const QUERY_MAX_ALGORITHMS: u64 = 64;
const QUERY_MAX_ENTRIES: u64 = 32;

/// CODE_ROLE ABI shape IDs (`data[2]`, informational: the join matches
/// key + state + sequence; the shape records the reviewed signature the
/// publisher attributed to the (operation, function) pair).
const CODE_SHAPE_NEWCTX: u64 = 1;
const CODE_SHAPE_DUPCTX: u64 = 2;
const CODE_SHAPE_FREECTX: u64 = 3;
const CODE_SHAPE_MAC_INIT: u64 = 4;
const CODE_SHAPE_UPDATE: u64 = 5;
const CODE_SHAPE_MAC_FINAL: u64 = 6;
const CODE_SHAPE_KDF_RESET: u64 = 7;

/// Reviewed first-slice (operation, function) to ABI-shape map. `None`
/// means out of slice: the entry is silently skipped, never published.
#[inline(always)]
fn code_shape(operation: u32, function: u32) -> Option<u64> {
    match (operation, function) {
        (3, 1) | (4, 1) => Some(CODE_SHAPE_NEWCTX),
        (3, 2) | (4, 2) => Some(CODE_SHAPE_DUPCTX),
        (3, 3) | (4, 3) => Some(CODE_SHAPE_FREECTX),
        (3, 4) => Some(CODE_SHAPE_MAC_INIT),
        (3, 5) | (4, 5) => Some(CODE_SHAPE_UPDATE),
        (3, 6) => Some(CODE_SHAPE_MAC_FINAL),
        (4, 4) => Some(CODE_SHAPE_KDF_RESET),
        _ => None,
    }
}

/// CODE_ROLE key: inode-SCOPED, never cookie-bound. The key selects
/// the (process, image, inode, file offset, operation, function) row —
/// one row per (file, offset, op, fun) — and the consuming join binds
/// it to the firing cookie's live registration/source epoch
/// (two-phase binding).
///
/// The source-capability contract's key amendment
/// (`docs/2026-10-29-v050-source-capability.md:36`) names cookie keying
/// ("actual callback lookup uses its firing cookie"), but the firing
/// cookie is unknowable at query-publication time: `publish_code_role`
/// runs in `typed_query_return` while walking the provider's returned
/// dispatch table, where the kernel observes bare code addresses with
/// no ambient attach cookie. The firing cookie exists only inside the
/// copied callback's own probe context (via `bpf_get_attach_cookie`),
/// which the query-return path never enters — and the admission index
/// runs cookie-to-site, never address-to-cookie, so no reverse lookup
/// can supply one without trusting the very VA the amendment refuses.
/// Cookie-keyed rows would therefore be unwritable at the only moment
/// publication is possible, so phase 1 publishes the exact observed
/// inode-and-offset without any cookie and phase 2 (the join) binds it.
///
/// Guarantees preserved, and how:
/// - Kernel-observed identity: both sides derive (inode, file offset)
///   from live kernel VMA state through the same qualified join
///   (`code_vma_join`, `Policy::Code`): publication joins each walked
///   table address, the callback join joins the firing IP. The
///   retained anchor's pinned file pins the inode for the session (no
///   reuse aliasing), and the consuming cookie's live
///   registration/source epoch is required before the code identity is
///   even consulted.
/// - No VA trust: no VA is stored in the key or trusted across time;
///   the join revalidates the live mapping on every use, and a stale
///   or remapped VA fails the join (fail closed). Same-file
///   different-offset substitution refuses: the offsets differ.
/// - Full target-domain scope: `process_incarnation` + `image_epoch`
///   scope the row, and `relation_epoch` 0 keeps ordinary
///   relation/loss advance from clearing code facts (tombstone
///   precedent); code replacement changes the inode or image instead.
/// The amendment's "candidate VA only proposes" half holds verbatim:
/// host offsets (the plan) propose sites; this join is the kernel's
/// independent verification. Only the lookup handle adapts
/// (cookie to inode-plus-offset-plus-cookie-binding); the finite
/// operation/function/signature/query-witness/object/publication fields
/// are unchanged.
///
/// Delegates to the contract-crate constructor (same bytes, pinned by
/// `code_role_identity_binds_inode_offset_and_cookie_epoch`); the path
/// is fully qualified because this wrapper intentionally shadows the
/// glob import.
#[inline(always)]
fn code_role_key(
    target: &Target,
    inode: u64,
    file_offset: u64,
    function: u32,
    operation: u32,
) -> RelKey {
    osslscope_bpf_contract::attribution::code_role_key(
        target.process,
        target.image,
        inode,
        file_offset,
        function,
        operation,
    )
}

/// VMA-join one address under the Code policy (exec, not write/shared).
/// Inlined at every site so the callback join stays shallow: the 6.9
/// verifier sums caller frames along the path (512 B total), and an
/// outlined join level plus the check level overflow it. Every inlined
/// copy keeps the same iterator-slot discipline (acquire, join, release
/// on every path); only `current_source_at` stays outlined, keeping one
/// set of finite patch sites per root for the loader.
#[inline(always)]
fn code_vma_join(address: u64, out: &mut source_vma::SourceLocation) -> bool {
    if address == 0 {
        return false;
    }
    let Some(cell) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let slot = unsafe { addr_of_mut!((*cell).slot) };
    if !unsafe { compare(slot, 0, 1) } {
        return false;
    }
    let found = match SOURCE_CONFIG.get(0) {
        Some(config) => unsafe {
            source_vma::current_source_at(
                address,
                source_vma::Policy::Code,
                config.page_shift,
                &mut *out,
            )
        },
        None => false,
    };
    if !unsafe { compare(slot, 1, 0) } {
        return false;
    }
    found
}

/// Firing instruction pointer for a uprobe entry: Linux rewinds the saved
/// IP to the probe address before invoking consumers (see `handle_swbp`
/// in `kernel/events/uprobes.c`), so the kernel-supplied entry IP is the
/// firing callback address with no subtraction. Subtracting one selects
/// the preceding byte, which at an executable VMA's first byte lands in
/// another mapping or a hole and rejects a valid callback. x86_64 only;
/// other arches fail closed (copied roles stay unresolved there).
#[inline(always)]
fn callback_ip(ctx: &ProbeContext) -> Option<u64> {
    #[cfg(bpf_target_arch = "x86_64")]
    {
        let rip = unsafe { (*ctx.regs).rip };
        (rip != 0).then_some(rip)
    }
    #[cfg(not(bpf_target_arch = "x86_64"))]
    {
        let _ = ctx;
        None
    }
}

/// Join the firing callback's exact (inode, file offset) identity
/// through the current-VMA join. Inlined so the identity stays in the
/// caller's frame for the shallow `code_role_check` call below.
#[inline(always)]
fn join_firing_identity(ctx: &ProbeContext) -> Option<(u64, u64)> {
    let firing = callback_ip(ctx)?;
    let mut location: source_vma::SourceLocation = unsafe { core::mem::zeroed() };
    if !code_vma_join(firing, &mut location) || location.inode == 0 {
        return None;
    }
    Some((location.inode, location.file_offset))
}

/// Registration-identity cross-check (remap-TOCTOU closure): the
/// caller-joined (inode, file offset) must equal the registration-time
/// identity the kernel retained for THIS firing cookie. The VMA snapshot
/// races concurrent remaps — Linux releases mmap_lock before invoking
/// uprobe consumers — so a snapshot taken after another thread remapped
/// the firing VA joins a transient identity: without this bind, a
/// previously published CODE_ROLE row for that transient identity would
/// authorize while this cookie's guards stay LIVE, leaving readiness
/// and identity two independent facts.
///
/// The bind is to kernel witnesses, never host claims: the joined
/// offset must equal the SOURCE_REG row selected by the firing
/// (cookie, source epoch) — the exact offset the kernel observed in
/// the registration arguments — and the joined inode must carry that
/// registration's retained SOURCE_ANCHOR. Witness relationships are
/// validated, not just raw numbers: READY→REG→ANCHOR linkage through
/// (anchor_id, registration_id), WITNESS states, evidence epochs,
/// proved==required completion, object agreement between REG and
/// ANCHOR, and publication sequences at or before the entry snapshot.
/// Guard liveness for both IDs rides the `ready_and_guards` pass the
/// caller just performed in this same run (immutable READY body, so
/// the extracted IDs are the guarded ones). Any miss refuses.
///
/// Field positions mirror the source publisher (`source_publish_new`)
/// and its sibling validators (`anchor`, `registration_matches`): a
/// skew between the two statements breaks every copied-role positive
/// loudly (the re-green controls pin the agreement behaviorally).
/// Inlined with one reused key slot so the 6.9 static chain gains no
/// extra frame level.
#[inline(always)]
fn registration_identity_matches(
    target: &Target,
    cookie: u64,
    source_epoch: u64,
    inode: u64,
    file_offset: u64,
) -> bool {
    // The READY row `ready_and_guards` just validated: re-read to
    // extract the witness IDs (immutable body) and re-check state and
    // sequence, so a quarantine landing between the two reads refuses.
    let mut key = RelKey {
        process_incarnation: target.process,
        image_epoch: target.image,
        relation_epoch: 0,
        primary_handle: cookie,
        secondary_handle: source_epoch,
        kind: SOURCE_READY,
        operation: 0,
    };
    let Some(ready) = REL.get_ptr_mut(&key) else {
        return false;
    };
    let (anchor_id, registration_id) = unsafe {
        if !row_state_is(ready, REL_WITNESS)
            || (*ready).evidence_epoch != source_epoch
            || (*ready).data[2] == 0
            || (*ready).data[2] > target.entry_seq
        {
            return false;
        }
        ((*ready).data[0], (*ready).data[1])
    };
    if anchor_id == 0 || registration_id == 0 {
        return false;
    }
    // SOURCE_REG selected by the firing (cookie, source epoch): same
    // key, REG kind. Its data[1] is the registration-time offset.
    key.kind = SOURCE_REG;
    let Some(reg) = REL.get_ptr_mut(&key) else {
        return false;
    };
    let reg_object = unsafe {
        if !row_state_is(reg, REL_WITNESS)
            || (*reg).witness_id != registration_id
            || (*reg).parent_id != anchor_id
            || (*reg).evidence_epoch != source_epoch
            || (*reg).data[0] == 0
            || (*reg).data[1] != file_offset
            || (*reg).data[2] != cookie
            || (*reg).data[3] == 0
            || (*reg).data[4] != (*reg).data[3]
            || (*reg).data[5] == 0
            || (*reg).data[5] > target.entry_seq
        {
            return false;
        }
        (*reg).data[0]
    };
    // SOURCE_ANCHOR retained for the joined inode under this
    // registration's anchor: keyed (inode, anchor_id).
    key.primary_handle = inode;
    key.secondary_handle = anchor_id;
    key.kind = SOURCE_ANCHOR;
    let Some(anchor) = REL.get_ptr_mut(&key) else {
        return false;
    };
    unsafe {
        row_state_is(anchor, REL_WITNESS)
            && (*anchor).witness_id == anchor_id
            && (*anchor).parent_id == 0
            && (*anchor).evidence_epoch == source_epoch
            && (*anchor).data[0] == reg_object
            && (*anchor).data[1] == source_epoch
            && (*anchor).data[2] != 0
            && (*anchor).data[2] <= target.entry_seq
    }
}

/// Copied-role callback check (two-phase binding, phase 2): the firing
/// cookie's retained registration/source epoch must be live, the joined
/// identity must equal the registration-time identity retained for that
/// cookie (remap-TOCTOU bind), and the caller-joined exact observed
/// inode-and-offset identity must match the query-published CODE_ROLE
/// row with code-ABI certification and a publication sequence at or
/// before the entry snapshot. Phase 1 (query time) publishes the
/// inode-and-offset identity without any cookie, which is unknowable
/// then; this phase binds it to the consuming cookie. Any miss refuses
/// before any operand read.
///
/// The caller performs the VMA join first (`join_firing_identity`,
/// inlined) and passes the joined identity here: splitting the join
/// from the check keeps the call chain shallow (the 6.9 verifier sums
/// caller frames along the path against 512 B; a five-deep chain
/// overflows it). `opfun` packs the staged admission pair (low 32 =
/// operation, high 32 = function) so the five-argument call ABI holds;
/// the entry sequence rides `target`.
#[inline(never)]
#[no_mangle]
pub fn code_role_check(
    target: &Target,
    cookie: u64,
    inode: u64,
    file_offset: u64,
    opfun: u64,
) -> bool {
    let operation = opfun as u32;
    let function = (opfun >> 32) as u32;
    if inode == 0 || code_shape(operation, function).is_none() {
        return false;
    }
    // Consuming-cookie binding: the cookie's retained registration and
    // source epoch must be live before the code identity is consulted.
    let Some(bound) = site_bind_ptr(cookie, target) else {
        return false;
    };
    let source_epoch = unsafe { (*bound).source_epoch };
    if !ready_and_guards(cookie, source_epoch, target.entry_seq, target) {
        return false;
    }
    // Registration-identity binding: the joined offset/inode must equal
    // the registration-time identity retained for this firing cookie
    // (SOURCE_REG/SOURCE_ANCHOR witnesses). A VMA snapshot taken after
    // a concurrent remap joins the transient identity; without this
    // bind a CODE_ROLE row published for it would authorize while this
    // cookie's guards stay LIVE.
    if !registration_identity_matches(target, cookie, source_epoch, inode, file_offset) {
        return false;
    }
    let key = code_role_key(target, inode, file_offset, function, operation);
    let Some(row) = REL.get_ptr_mut(&key) else {
        return false;
    };
    unsafe {
        row_state_is(row, REL_CERTIFIED)
            && (*row).witness_id != 0
            && (*row).evidence_epoch != 0
            && (*row).data[0] == u64::from(operation)
            && (*row).data[1] == u64::from(function)
            && (*row).data[3] == file_offset
            && (*row).data[6] != 0
            && (*row).data[6] <= target.entry_seq
    }
}

/// Publish one CODE_ROLE row under the shared publisher lock (two-phase
/// binding, phase 1): record the query-observed exact inode-and-offset
/// identity without any cookie, which is unknowable at query time; the
/// consuming join binds it to the firing cookie. Dedup by key adopts
/// only an identical live row (same file, offset, op and fun,
/// re-verified from the value; a same-key different-identity
/// re-advertisement refuses, fail closed), then spend, allocate, build
/// in the per-CPU cell, NOEXIST insert, and the ordered sequence
/// commit. Any failure leaves the entry unauthorized for this query; a
/// later query republishes (self-healing, no poison: a CODE_ROLE
/// hiccup must never kill unrelated positives).
#[inline(never)]
#[no_mangle]
pub fn publish_code_role(
    control: *mut ProducerControl,
    target: &Target,
    location: &source_vma::SourceLocation,
    opfun: u64,
    occurrence: u64,
) -> bool {
    let operation = opfun as u32;
    let function = (opfun >> 32) as u32;
    if location.inode == 0 || occurrence == 0 {
        return false;
    }
    let Some(shape) = code_shape(operation, function) else {
        return false;
    };
    let key = code_role_key(
        target,
        location.inode,
        location.file_offset,
        function,
        operation,
    );
    let Some(state) = crate::shared_maps::ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let busy = unsafe { addr_of_mut!((*state).publication_busy) };
    let mut locked = false;
    for _ in 0..8 {
        if unsafe { compare(busy, 0, 1) } {
            locked = true;
            break;
        }
    }
    if !locked {
        return false;
    }
    let result = (|| {
        if let Some(existing) = REL.get_ptr_mut(&key) {
            return unsafe {
                row_state_is(existing, REL_CERTIFIED)
                    && (*existing).witness_id != 0
                    && (*existing).evidence_epoch != 0
                    && (*existing).data[0] == u64::from(operation)
                    && (*existing).data[1] == u64::from(function)
                    && (*existing).data[2] == shape
                    && (*existing).data[3] == location.file_offset
                    && (*existing).data[6] != 0
            };
        }
        let mode_ok = unsafe {
            (*control).producer_mode == PRODUCER_ADMITTED
                && (*control).session_id != 0
                && (*control).admission_epoch != 0
                && (*control).cut_id != 0
                && (*control).reserved == 0
        };
        if !mode_ok {
            return false;
        }
        if !spend(1) {
            return false;
        }
        let mut id = 0u64;
        if !alloc_id(control, &mut id) {
            return false;
        }
        let Some(slot) = crate::shared_maps::ITER_SLOT.get_ptr_mut(0) else {
            return false;
        };
        let old_seq = unsafe { ordered_read(addr_of_mut!((*state).published_sequence)) };
        let Some(next_seq) = old_seq.checked_add(1) else {
            return false;
        };
        if next_seq == 0 {
            return false;
        }
        let staging = unsafe { (*slot).staging.as_mut_ptr().cast::<RelValue>() };
        unsafe {
            staging.write_bytes(0, 1);
            (*staging).witness_id = id;
            (*staging).parent_id = 0;
            (*staging).evidence_epoch = target.relation;
            (*staging).born_ns = now_of();
            (*staging).state = REL_CERTIFIED;
            (*staging).data = code_role_data(
                u64::from(operation),
                u64::from(function),
                shape,
                location.file_offset,
                occurrence,
                next_seq,
            );
            if REL.insert(&key, &*staging, BPF_NOEXIST).is_err() {
                return false;
            }
            if !compare(addr_of_mut!((*state).published_sequence), old_seq, next_seq) {
                return false;
            }
            (*control).producer_mode == PRODUCER_ADMITTED
        }
    })();
    unsafe {
        compare(busy, 1, 0);
    }
    result
}

/// Query entry (161): stage the queried operation (a1) and the no-cache
/// out-param pointer (a2) for the return walk. Only MAC (3) and KDF (4)
/// stage a frame; every other op stays quiet here (out of slice, no
/// loss: unobserved ops simply authorize nothing). The a2 pointer is
/// staged, never dereferenced at entry.
#[inline(never)]
#[no_mangle]
pub fn typed_query_entry(
    ctx: &ProbeContext,
    control: *mut ProducerControl,
    ids: u64,
    target: &mut Target,
) -> u32 {
    let (tgid, tid) = split_ids(ids);
    let captured_entry_seq = target.entry_seq;
    if !resolve_inner(tgid, captured_entry_seq, target) {
        return 0;
    }
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let admitted = entry_admission(cookie, target);
    if admitted.is_null() {
        return 0;
    }
    let role = unsafe { (*admitted).role_id };
    if role != 161 {
        return 0;
    }
    let op: u64 = ctx.arg(1).unwrap_or(0);
    if !matches!(op, 3 | 4) {
        return 0;
    }
    let nocache: u64 = ctx.arg(2).unwrap_or(0);
    if nocache == 0 {
        return 0;
    }
    let mut thread = 0u64;
    if !thread_incarnation(control, target, tid, &mut thread) {
        return 0;
    }
    let mut occurrence = 0u64;
    if !alloc_id(control, &mut occurrence) {
        return 0;
    }
    let now_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let params = StageParams {
        target,
        thread,
        cookie,
        role,
        occurrence,
        now_ns,
    };
    let mut staged: StagedFrame = unsafe { core::mem::zeroed() };
    if !stage_frame(&params, &mut staged) {
        return 0;
    }
    let frame = staged.frame;
    unsafe {
        (*frame).entry_handle = op;
        (*frame).provider_witness = nocache;
    }
    0
}

/// Query return (161): on a non-NULL table with cacheable outcome, walk
/// the live OSSL_ALGORITHM array and publish CODE_ROLE rows for every
/// in-slice dispatch entry. No-store, failed, unreadable or out-of-slice
/// queries publish nothing; the frame is always consumed by the caller.
// Reuse the caller-owned target storage while repeating exactly the same
// source revalidation. A second Target would deepen the publication stack.
#[inline(never)]
#[no_mangle]
pub fn typed_query_return(
    ctx: &RetProbeContext,
    control: *mut ProducerControl,
    frame: *mut BindPendingValue,
    tgid: u32,
    target: &mut Target,
) {
    if !resolve_inner(tgid, target.entry_seq, target) {
        return;
    }
    let table: u64 = ctx.ret();
    if table == 0 {
        return;
    }
    let (op, nocache, occurrence) = unsafe {
        (
            (*frame).entry_handle,
            (*frame).provider_witness,
            (*frame).occurrence_id,
        )
    };
    if !matches!(op, 3 | 4) || nocache == 0 || occurrence == 0 {
        return;
    }
    match unsafe { helpers::bpf_probe_read_user(nocache as *const u32) } {
        Ok(0) => {}
        Ok(_) => return,
        Err(_) => {
            loss(LOSS_MAP);
            return;
        }
    }
    query_walk_table(control, target, table, op as u32, occurrence);
}

/// Invocation-owned query walk state. Static callees borrow this stack
/// state and the target only for the synchronous return walk; no target
/// address or table borrow is retained after it returns.
#[repr(C)]
struct QueryAlgoScan<'a> {
    control: *mut ProducerControl,
    target: &'a Target,
    table: u64,
    operation: u32,
    stopped: u32,
    occurrence: u64,
}
#[repr(C)]
struct QueryDispatchScan<'a, 't> {
    algorithm: &'a QueryAlgoScan<'t>,
    imp: u64,
    stopped: u32,
}

/// Walk one live OSSL_ALGORITHM array (32-byte records: names @ +0,
/// implementation @ +16), dispatching each non-NULL table. Ordinary
/// bounded loops and static callees require no program callback BTF.
/// A NULL names word terminates the walk; a failed read or arithmetic
/// stops it with LOSS_MAP, as does an unterminated full bound.
// The own-stack scan shares the return frame rather than adding a frame
// along the already deep publication path. Slot bodies stay outlined.
#[inline(always)]
fn query_walk_table(
    control: *mut ProducerControl,
    target: &Target,
    table: u64,
    operation: u32,
    occurrence: u64,
) {
    let mut scan = QueryAlgoScan {
        control,
        target,
        table,
        operation,
        stopped: 0,
        occurrence,
    };
    for index in 0..QUERY_MAX_ALGORITHMS {
        if query_algo_slot(index, &mut scan) {
            break;
        }
    }
    if scan.stopped == 0 {
        loss(LOSS_MAP);
    }
}

/// One algorithm slot: read names/implementation, walk a non-NULL table.
/// True stops the loop (terminator or fatal read); false continues.
#[inline(never)]
#[no_mangle]
fn query_algo_slot(index: u64, scan: &mut QueryAlgoScan<'_>) -> bool {
    let Some(slot) = scan.table.checked_add(index * 32) else {
        scan.stopped = 1;
        loss(LOSS_MAP);
        return true;
    };
    let names = match unsafe { helpers::bpf_probe_read_user(slot as *const u64) } {
        Ok(value) => value,
        Err(_) => {
            scan.stopped = 1;
            loss(LOSS_MAP);
            return true;
        }
    };
    if names == 0 {
        scan.stopped = 1;
        return true;
    }
    let Some(implementation) = slot.checked_add(16) else {
        scan.stopped = 1;
        loss(LOSS_MAP);
        return true;
    };
    match unsafe { helpers::bpf_probe_read_user(implementation as *const u64) } {
        Ok(0) => loss(LOSS_MAP),
        Ok(imp) => {
            let mut dispatch = QueryDispatchScan {
                algorithm: scan,
                imp,
                stopped: 0,
            };
            for index in 0..QUERY_MAX_ENTRIES {
                if query_dispatch_slot(index, &mut dispatch) {
                    break;
                }
            }
            if dispatch.stopped == 0 {
                loss(LOSS_MAP);
            }
        }
        Err(_) => {
            scan.stopped = 1;
            loss(LOSS_MAP);
            return true;
        }
    }
    false
}

/// One dispatch slot (16-byte entries: id @ +0, function @ +8):
/// publish CODE_ROLE rows for in-slice entries. Out-of-slice IDs are
/// silently skipped; unreadable, NULL, unjoinable or refused entries
/// record LOSS_MAP and never publish. True stops the loop.
#[inline(never)]
#[no_mangle]
fn query_dispatch_slot(index: u64, scan: &mut QueryDispatchScan<'_, '_>) -> bool {
    let Some(entry) = scan.imp.checked_add(index * 16) else {
        scan.stopped = 1;
        loss(LOSS_MAP);
        return true;
    };
    let id = match unsafe { helpers::bpf_probe_read_user(entry as *const u32) } {
        Ok(value) => value,
        Err(_) => {
            scan.stopped = 1;
            loss(LOSS_MAP);
            return true;
        }
    };
    if id == 0 {
        scan.stopped = 1;
        return true;
    }
    if id > i32::MAX as u32 {
        scan.stopped = 1;
        loss(LOSS_MAP);
        return true;
    }
    let Some(function) = entry.checked_add(8) else {
        scan.stopped = 1;
        loss(LOSS_MAP);
        return true;
    };
    let fun = match unsafe { helpers::bpf_probe_read_user(function as *const u64) } {
        Ok(value) => value,
        Err(_) => {
            scan.stopped = 1;
            loss(LOSS_MAP);
            return true;
        }
    };
    if fun == 0 {
        loss(LOSS_MAP);
        return false;
    }
    if code_shape(scan.algorithm.operation, id).is_none() {
        return false;
    }
    let mut location: source_vma::SourceLocation = unsafe { core::mem::zeroed() };
    if !code_vma_join(fun, &mut location) || location.inode == 0 {
        loss(LOSS_MAP);
        return false;
    }
    let opfun = (u64::from(id) << 32) | u64::from(scan.algorithm.operation);
    if !publish_code_role(
        scan.algorithm.control,
        scan.algorithm.target,
        &location,
        opfun,
        scan.algorithm.occurrence,
    ) {
        loss(LOSS_MAP);
    }
    false
}
