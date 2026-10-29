// SPDX-License-Identifier: GPL-2.0-only
//! Observer-only registration proof. No target operand reader or public event.
use crate::{source_state as atom, source_vma, writer_gate, CONFIG, MEMBERS, NAMESPACE};
use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers,
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use core::ptr::addr_of_mut;
use osslscope_bpf_contract::{
    attribution::{RelKey, RelValue},
    source::*,
};

#[map]
pub static REL: HashMap<RelKey, RelValue> = HashMap::with_max_entries(8192, 0);
#[map]
pub static SOURCE_GUARD: HashMap<u64, SourceGuard> = HashMap::with_max_entries(8192, 0);
#[map]
pub static SOURCE_REQUEST: HashMap<u64, SourceRequest> = HashMap::with_max_entries(4096, 0);
#[map]
pub static SOURCE_PAIR: Array<SourcePair> = Array::with_max_entries(1, 0);
#[map]
pub static SOURCE_DOMAIN: HashMap<u32, SourceDomain> = HashMap::with_max_entries(64, 0);
#[map]
pub static SOURCE_OBSERVER: Array<SourceObserver> = Array::with_max_entries(1, 0);
#[map]
pub static ITER_SLOT: PerCpuArray<SourceSlot> = PerCpuArray::with_max_entries(1, 0);

// Staging casts to the REL value for typed stores. Same size, same alignment.
const _: () = {
    assert!(core::mem::size_of::<[u64; 32]>() == core::mem::size_of::<RelValue>());
    assert!(core::mem::align_of::<[u64; 32]>() == core::mem::align_of::<RelValue>());
    assert!(core::mem::offset_of!(SourceSlot, staging) == 8);
};

#[inline(always)]
fn observer_live() -> bool {
    SOURCE_OBSERVER
        .get_ptr_mut(0)
        .is_some_and(|p| unsafe { atom::ordered_read(addr_of_mut!((*p).state)) == 2 })
}
#[inline(always)]
fn terminal_observer() {
    if let Some(observer) = SOURCE_OBSERVER.get_ptr_mut(0) {
        unsafe {
            atom::terminate_observer(addr_of_mut!((*observer).state));
        }
    }
}
/// Only this exact enrolled host thread can reach request or context operands.
/// Namespace failure for an unrelated global callback remains quiet.
#[inline(never)]
#[no_mangle]
pub fn source_observer_key() -> u64 {
    let Some(observer) = SOURCE_OBSERVER.get_ptr_mut(0) else {
        return 0;
    };
    let host = helpers::bpf_get_current_pid_tgid();
    let state = unsafe { atom::ordered_read(addr_of_mut!((*observer).state)) };
    if state != 1 && state != 2 {
        return 0;
    }
    if state == 2 && unsafe { (*observer).host_pid_tgid } != host {
        return 0;
    }
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let result = unsafe {
        helpers::bpf_get_ns_current_pid_tgid(
            (*observer).namespace_device,
            (*observer).namespace_inode,
            &mut ids,
            8,
        )
    };
    if result != 0 {
        if state == 2 {
            terminal_observer();
        }
        return 0;
    }
    if (u64::from(ids.tgid) << 32) | u64::from(ids.pid) != unsafe { (*observer).local_pid_tgid } {
        return 0;
    }
    if state == 1 {
        if unsafe { (*observer).nonce } < HOST_ID_FIRST {
            terminal_observer();
            return 0;
        }
        unsafe {
            (*observer).host_pid_tgid = host;
            // Terminal raw retirement wins; no re-enrollment after state3.
            atom::compare(addr_of_mut!((*observer).state), 1, 2);
        }
        // Enrollment's trigger never doubles as a source request.
        return 0;
    }
    if observer_live() {
        host
    } else {
        0
    }
}
#[inline(always)]
fn refuse(request: *mut SourceRequest, pair: *mut SourcePair) {
    unsafe {
        (*request).verdict = 2;
        // Pair has only one nonterminal active value. A refused pair is never
        // reset by the host, nor by a later request on a recycled numeric TID.
        atom::compare(addr_of_mut!((*pair).state), 1, 2);
    }
}
#[inline(always)]
fn key(request: &SourceRequest, kind: u32, primary: u64, secondary: u64) -> RelKey {
    RelKey {
        process_incarnation: request.process_incarnation,
        image_epoch: request.image_epoch,
        relation_epoch: 0,
        primary_handle: primary,
        secondary_handle: secondary,
        kind,
        operation: 0,
    }
}
#[inline(always)]
fn guard(id: u64, epoch: u64, wanted: u64) -> bool {
    // Host replaces immutable hash values. Lookup is the guard observation;
    // the retained source/file owner outlives every old RCU value and final cut.
    unsafe { SOURCE_GUARD.get(&id) }.is_some_and(|g| g.source_epoch == epoch && g.state == wanted)
}
#[inline(always)]
fn source_domain(request: &SourceRequest) -> bool {
    let Some(config) = (unsafe { CONFIG.get(&request.site_cookie) }) else {
        return false;
    };
    if config.pid == 0 {
        return false;
    }
    let Some(domain) = SOURCE_DOMAIN.get_ptr_mut(&config.pid) else {
        return false;
    };
    unsafe {
        if (*domain).process_incarnation != request.process_incarnation
            || (*domain).reserved != [0, 0]
        {
            return false;
        }
        let state = atom::ordered_read(addr_of_mut!((*domain).state));
        let current = atom::ordered_read(addr_of_mut!((*domain).current_image));
        let valid = match state {
            DOMAIN_LIVE | DOMAIN_ACTIVE => current == request.image_epoch,
            DOMAIN_ARMED => {
                current == (*domain).original_image
                    && (*domain).planned_image == request.image_epoch
                    && current != request.image_epoch
                    && current != 0
            }
            _ => false,
        };
        valid && atom::ordered_read(addr_of_mut!((*domain).state)) == state
    }
}
#[inline(always)]
fn witness(value: *mut RelValue) -> bool {
    // Only source-kind callers reach this helper. Their aligned state/cardinality
    // pair is exactly (WITNESS, 0); cardinality-bearing relationship kinds never do.
    unsafe { atom::ordered_read(addr_of_mut!((*value).state).cast::<u64>()) == 1 }
}
#[inline(always)]
fn quarantine_source(value: *mut RelValue, kind: u32) {
    if !matches!(kind, SOURCE_ANCHOR | SOURCE_REG | SOURCE_READY) {
        terminal_observer();
        return;
    }
    // Validate the full packed word in the transition itself. No store of a
    // payload or publication sequence ever touches this word after insertion.
    let word = unsafe { addr_of_mut!((*value).state).cast::<u64>() };
    if !unsafe { atom::compare(word, 1, 4) } && unsafe { atom::ordered_read(word) } != 4 {
        terminal_observer();
    }
}
#[inline(always)]
fn source_row(request: &SourceRequest, kind: u32) -> Option<*mut RelValue> {
    REL.get_ptr_mut(&key(
        request,
        kind,
        request.site_cookie,
        request.source_epoch,
    ))
}
#[inline(always)]
fn anchor(request: &SourceRequest, inode: u64, entry_sequence: u64) -> bool {
    let Some(value) = REL.get_ptr_mut(&key(request, SOURCE_ANCHOR, inode, request.anchor_id))
    else {
        return false;
    };
    unsafe {
        witness(value)
            && (*value).witness_id == request.anchor_id
            && (*value).parent_id == 0
            && (*value).evidence_epoch == request.source_epoch
            && (*value).data[0] == request.object_id
            && (*value).data[1] == request.source_epoch
            && (*value).data[2] != 0
            && (*value).data[2] <= entry_sequence
            && guard(request.anchor_id, request.source_epoch, GUARD_LIVE)
    }
}

/// Source kinds have exactly one serialized observer writer. A conflicting
/// existing key is quarantined before trying the shared publication lock. An
/// absent key cannot race another source insertion: nested entry poisons PAIR,
/// unrelated threads cannot pass enrollment, and raw roots never insert.
#[inline(never)]
#[no_mangle]
pub fn source_publish_new(
    request: &SourceRequest,
    kind: u32,
    inode: u64,
    output: &mut u64,
) -> bool {
    if !matches!(kind, SOURCE_ANCHOR | SOURCE_REG | SOURCE_READY) {
        return false;
    }
    let relation = if kind == SOURCE_ANCHOR {
        key(request, kind, inode, request.anchor_id)
    } else {
        key(request, kind, request.site_cookie, request.source_epoch)
    };
    if let Some(existing) = REL.get_ptr_mut(&relation) {
        quarantine_source(existing, kind);
        return false;
    }
    let Some(control) = atom::ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let busy = unsafe { addr_of_mut!((*control).publication_busy) };
    if !unsafe { atom::compare(busy, 0, 1) } {
        return false;
    }
    let result = (|| {
        if !observer_live() || kind != SOURCE_ANCHOR && !source_domain(request) {
            return None;
        }
        // Finish dependency lookups before materializing the 256-byte value.
        // This keeps bounded stack frames reusable across the actual call chain.
        if kind == SOURCE_REG && !anchor(request, inode, request.publication_sequence)
            || kind == SOURCE_READY && !ready_dependencies(request)
        {
            return None;
        }
        let old = unsafe { atom::ordered_read(addr_of_mut!((*control).published_sequence)) };
        let complete = kind != SOURCE_REG || request.required_mask == 1;
        let sequence = if complete { old.checked_add(1)? } else { 0 };
        // Stage the complete value in the per-CPU slot cell instead of a
        // 256-byte stack temporary. Same bytes, same single NOEXIST insert.
        let Some(cell) = ITER_SLOT.get_ptr_mut(0) else {
            return None;
        };
        let staging = unsafe { (*cell).staging.as_mut_ptr().cast::<RelValue>() };
        unsafe {
            staging.write_bytes(0, 1);
            (*staging).evidence_epoch = request.source_epoch;
            (*staging).born_ns = helpers::bpf_ktime_get_ns();
            (*staging).state = 1;
        }
        match kind {
            SOURCE_ANCHOR => unsafe {
                (*staging).witness_id = request.anchor_id;
                (*staging).data[0] = request.object_id;
                (*staging).data[1] = request.source_epoch;
                (*staging).data[2] = sequence;
            },
            SOURCE_REG => unsafe {
                (*staging).witness_id = request.registration_id;
                (*staging).parent_id = request.anchor_id;
                (*staging).data[0] = request.object_id;
                (*staging).data[1] = request.file_offset;
                (*staging).data[2] = request.site_cookie;
                (*staging).data[3] = u64::from(request.required_mask);
                (*staging).data[4] = 1;
                (*staging).data[5] = sequence;
            },
            SOURCE_READY => unsafe {
                (*staging).witness_id = request.nonce;
                (*staging).parent_id = request.registration_id;
                (*staging).data[0] = request.anchor_id;
                (*staging).data[1] = request.registration_id;
                (*staging).data[2] = sequence;
            },
            _ => return None,
        }
        if REL.insert(&relation, unsafe { &*staging }, 1).is_err() {
            return None;
        }
        if complete
            && !unsafe { atom::compare(addr_of_mut!((*control).published_sequence), old, sequence) }
        {
            // No legitimate writer can change this sequence under our lock.
            terminal_observer();
            return None;
        }
        observer_live().then_some(sequence)
    })();
    if !unsafe { atom::compare(busy, 1, 0) } {
        terminal_observer();
        return false;
    }
    if let Some(sequence) = result {
        *output = sequence;
        true
    } else {
        false
    }
}
#[inline(always)]
fn registration_matches(request: &SourceRequest, value: *mut RelValue) -> bool {
    unsafe {
        witness(value)
            && (*value).witness_id == request.registration_id
            && (*value).parent_id == request.anchor_id
            && (*value).evidence_epoch == request.source_epoch
            && (*value).data[0] == request.object_id
            && (*value).data[1] == request.file_offset
            && (*value).data[2] == request.site_cookie
            && (*value).data[3] == u64::from(request.required_mask)
    }
}
#[inline(always)]
fn ready_dependencies(request: &SourceRequest) -> bool {
    let Some(value) = source_row(request, SOURCE_REG) else {
        return false;
    };
    unsafe {
        registration_matches(request, value)
            && (*value).data[4] == u64::from(request.required_mask)
            && (*value).data[5] != 0
            && (*value).data[5] <= request.publication_sequence
            && guard(request.anchor_id, request.source_epoch, GUARD_LIVE)
            && guard(request.registration_id, request.source_epoch, GUARD_LIVE)
    }
}
#[inline(never)]
#[no_mangle]
pub fn source_anchor_exit(request: &SourceRequest, output: &mut u64) -> bool {
    // One fresh join, one anchor row, one host-created guard; all remain spent
    // even if the CPU slot, iterator, publication or later adoption fails.
    if !atom::spend_source_bundle(3) {
        return false;
    }
    let Some(cell) = ITER_SLOT.get_ptr_mut(0) else {
        return false;
    };
    let slot = unsafe { addr_of_mut!((*cell).slot) };
    if !unsafe { atom::compare(slot, 0, 1) } {
        return false;
    }
    let mut location = source_vma::SourceLocation {
        inode: 0,
        file_offset: 0,
    };
    let found = match atom::SOURCE_CONFIG.get(0) {
        Some(config) => unsafe {
            source_vma::current_source_at(
                request.observer_anchor_address,
                source_vma::Policy::Anchor,
                config.page_shift,
                &mut location,
            )
        },
        None => false,
    };
    // current_source_at destroys every initialized iterator before returning.
    if !unsafe { atom::compare(slot, 1, 0) } {
        terminal_observer();
        return false;
    }
    if !found {
        return false;
    }
    if location.file_offset != 0 || !observer_live() {
        return false;
    }
    source_publish_new(request, SOURCE_ANCHOR, location.inode, output)
}
#[inline(never)]
#[no_mangle]
pub fn source_complete_registration(request: &SourceRequest, inode: u64, output: &mut u64) -> bool {
    if !source_domain(request)
        || !anchor(request, inode, request.publication_sequence)
        || !guard(
            request.registration_id,
            request.source_epoch,
            GUARD_PREPARING,
        )
    {
        return false;
    }
    let Some(value) = source_row(request, SOURCE_REG) else {
        return false;
    };
    if !registration_matches(request, value)
        || unsafe { (*value).data[4] != 1 || (*value).data[5] != 0 }
    {
        quarantine_source(value, SOURCE_REG);
        return false;
    }
    let Some(control) = atom::ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let busy = unsafe { addr_of_mut!((*control).publication_busy) };
    if !unsafe { atom::compare(busy, 0, 1) } {
        return false;
    }
    let result = (|| {
        if !observer_live() || !witness(value) || !source_domain(request) {
            return None;
        }
        let old = unsafe { atom::ordered_read(addr_of_mut!((*control).published_sequence)) };
        let next = old.checked_add(1)?;
        unsafe {
            // Still ineligible staging until the sequence commit. After that,
            // this payload is immutable; later invalidation changes only state.
            (*value).data[4] = 3;
            (*value).data[5] = next;
            if !atom::compare(addr_of_mut!((*control).published_sequence), old, next) {
                terminal_observer();
                return None;
            }
        }
        (observer_live() && witness(value)).then_some(next)
    })();
    if !unsafe { atom::compare(busy, 1, 0) } {
        terminal_observer();
        return false;
    }
    if let Some(sequence) = result {
        *output = sequence;
        true
    } else {
        false
    }
}

#[fentry(function = "uprobe_register")]
pub fn source_reg_in(ctx: FEntryContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let host = source_observer_key();
    if host == 0 {
        return 0;
    }
    let Some(request) = SOURCE_REQUEST.get_ptr_mut(&host) else {
        return 0;
    };
    let Some(pair) = SOURCE_PAIR.get_ptr_mut(0) else {
        terminal_observer();
        return 0;
    };
    unsafe {
        let previous = (*request).entry_count;
        (*request).entry_count = previous.saturating_add(1);
        if previous != 0
            || (*request).exit_count != 0
            || (*request).verdict != 0
            || (*request).publication_sequence != 0
            || !(*request).valid_input()
            || !atom::compare(addr_of_mut!((*pair).state), 0, 1)
        {
            refuse(request, pair);
            atom::compare(addr_of_mut!((*pair).state), 0, 2);
            return 0;
        }
        let Some(control) = atom::ATTR_STATE.get_ptr_mut(0) else {
            refuse(request, pair);
            return 0;
        };
        if (*control).source_mode != 1 {
            refuse(request, pair);
            return 0;
        }
        (*request).publication_sequence =
            atom::ordered_read(addr_of_mut!((*control).published_sequence));
        (*pair).request = *request;
        (*pair).entry_inode = 0;
        match (*request).phase {
            PHASE_ANCHOR => return 0,
            PHASE_READY => {
                if let Some(old) = source_row(&*request, SOURCE_READY) {
                    quarantine_source(old, SOURCE_READY);
                    refuse(request, pair);
                } else if !source_domain(&*request) || !ready_dependencies(&*request) {
                    refuse(request, pair);
                }
                return 0;
            }
            PHASE_ENTRY => {
                if let Some(old) = source_row(&*request, SOURCE_REG) {
                    quarantine_source(old, SOURCE_REG);
                    refuse(request, pair);
                    return 0;
                }
                if SOURCE_GUARD.get(&(*request).registration_id).is_some() {
                    // Reusing an adoption ID is an actual owner protocol defect;
                    // its unknown old cookie cannot be safely selected by guess.
                    terminal_observer();
                    refuse(request, pair);
                    return 0;
                }
                if !atom::spend_source_bundle(2) {
                    refuse(request, pair);
                    return 0;
                }
            }
            PHASE_RETURN => {
                let Some(old) = source_row(&*request, SOURCE_REG) else {
                    refuse(request, pair);
                    return 0;
                };
                if !registration_matches(&*request, old)
                    || (*old).data[4] != 1
                    || (*old).data[5] != 0
                    || !guard(
                        (*request).registration_id,
                        (*request).source_epoch,
                        GUARD_PREPARING,
                    )
                {
                    quarantine_source(old, SOURCE_REG);
                    refuse(request, pair);
                    return 0;
                }
            }
            _ => {
                refuse(request, pair);
                return 0;
            }
        }
        if !source_domain(&*request)
            || !guard((*request).anchor_id, (*request).source_epoch, GUARD_LIVE)
        {
            refuse(request, pair);
            return 0;
        }
        // The only registration entry operands: exact validated four-argument
        // trampoline slots0/1/2. Consumer slot3 is never read or dereferenced.
        // Volatile prevents compiler speculation across the preceding guards;
        // it is not an acquire primitive or a claim about target memory.
        let context = ctx.as_ptr().cast::<u64>();
        let inode = core::ptr::read_volatile(context);
        let offset = core::ptr::read_volatile(context.add(1)) as i64;
        let ref_counter = core::ptr::read_volatile(context.add(2)) as i64;
        if inode == 0 || offset < 0 || offset as u64 != (*request).file_offset || ref_counter != 0 {
            refuse(request, pair);
            return 0;
        }
        (*pair).entry_inode = inode;
        if !anchor(&*request, inode, (*request).publication_sequence) {
            refuse(request, pair);
        }
    }
    0
}
#[fexit(function = "uprobe_register")]
pub fn source_reg_out(ctx: FExitContext) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    let host = source_observer_key();
    if host == 0 {
        return 0;
    }
    let Some(request) = SOURCE_REQUEST.get_ptr_mut(&host) else {
        return 0;
    };
    let Some(pair) = SOURCE_PAIR.get_ptr_mut(0) else {
        terminal_observer();
        return 0;
    };
    unsafe {
        (*request).exit_count = (*request).exit_count.saturating_add(1);
        if (*request).entry_count != 1
            || (*request).exit_count != 1
            || (*request).verdict != 0
            || atom::ordered_read(addr_of_mut!((*pair).state)) != 1
            || !(*request).same_input(&(*pair).request)
            || (*request).publication_sequence != (*pair).request.publication_sequence
        {
            refuse(request, pair);
            return 0;
        }
        let captured = &(*pair).request;
        let mut sequence = 0;
        let result = match captured.phase {
            PHASE_ANCHOR => {
                if (*pair).entry_inode != 0 {
                    false
                } else {
                    source_anchor_exit(captured, &mut sequence)
                }
            }
            PHASE_ENTRY | PHASE_RETURN => {
                // Immediately classify the pointer scalar from slot4. No return
                // pointer is retained, dereferenced, exported or used as an ID.
                if !registration_succeeded(core::ptr::read_volatile(
                    ctx.as_ptr().cast::<u64>().add(4),
                )) || (*pair).entry_inode == 0
                {
                    false
                } else if captured.phase == PHASE_ENTRY {
                    source_publish_new(captured, SOURCE_REG, (*pair).entry_inode, &mut sequence)
                } else {
                    source_complete_registration(captured, (*pair).entry_inode, &mut sequence)
                }
            }
            PHASE_READY => {
                if (*pair).entry_inode != 0
                    || !source_domain(captured)
                    || !ready_dependencies(captured)
                    || !atom::spend_source_bundle(1)
                {
                    false
                } else {
                    source_publish_new(captured, SOURCE_READY, 0, &mut sequence)
                }
            }
            _ => false,
        };
        if result && observer_live() {
            (*request).publication_sequence = sequence;
            (*request).verdict = 1;
            // The sole observer thread is the only pair writer; raw roots
            // retire the observer independently and never overwrite capture.
            if !atom::compare(addr_of_mut!((*pair).state), 1, 0) {
                terminal_observer();
                refuse(request, pair);
            }
        } else {
            refuse(request, pair);
        }
    }
    0
}

#[inline(never)]
#[no_mangle]
pub fn retire_source_observer(exec: bool) {
    let Some(observer) = SOURCE_OBSERVER.get_ptr_mut(0) else {
        return;
    };
    let host = helpers::bpf_get_current_pid_tgid();
    unsafe {
        let state = atom::ordered_read(addr_of_mut!((*observer).state));
        if state != 1 && state != 2 {
            return;
        }
        let recorded = (*observer).host_pid_tgid;
        let matches = if recorded != 0 {
            if exec {
                host >> 32 == recorded >> 32
            } else {
                host == recorded
            }
        } else {
            // An armed enrollment has no host coordinate yet. Normalize using
            // its original held namespace; failure creates no new authority.
            let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
            if helpers::bpf_get_ns_current_pid_tgid(
                (*observer).namespace_device,
                (*observer).namespace_inode,
                &mut ids,
                8,
            ) != 0
            {
                return;
            }
            let local = (u64::from(ids.tgid) << 32) | u64::from(ids.pid);
            if exec {
                local >> 32 == (*observer).local_pid_tgid >> 32
            } else {
                local == (*observer).local_pid_tgid
            }
        };
        if matches {
            atom::terminate_observer(addr_of_mut!((*observer).state));
        }
    }
}
#[inline(always)]
unsafe fn retire_domain(domain: *mut SourceDomain) {
    let state = addr_of_mut!((*domain).state);
    let mut current = atom::ordered_read(state);
    for _ in 0..8 {
        if current == DOMAIN_RETIRED || current == DOMAIN_POISON {
            return;
        }
        if atom::compare(state, current, DOMAIN_RETIRED) {
            return;
        }
        current = atom::ordered_read(state);
    }
    // This row only transitions finitely; exhausting the retry bound is an
    // actual unexplained invalidation loss, not normal callback contention.
    terminal_observer();
}
#[no_mangle]
#[link_section = "raw_tracepoint/sched_process_exit"]
pub extern "C" fn attr_exit(_ctx: *mut core::ffi::c_void) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    retire_source_observer(false);
    // Source eligibility does not count participating threads or infer group
    // death from a leader/last-observed crypto-thread exit. Typed pending/thread
    // incarnation retirement must be added before its target readers are armed.
    0
}
#[no_mangle]
#[link_section = "raw_tracepoint/sched_process_exec"]
pub extern "C" fn attr_exec(_ctx: *mut core::ffi::c_void) -> u32 {
    if !writer_gate::admitted() {
        return 0;
    }
    retire_source_observer(true);
    let Some(namespace) = NAMESPACE.get(0) else {
        return 0;
    };
    let mut ids = bpf_pidns_info { pid: 0, tgid: 0 };
    let normalized = unsafe {
        helpers::bpf_get_ns_current_pid_tgid(namespace.device, namespace.inode, &mut ids, 8)
    };
    // This pre-seed path retires staged source-only evidence. No runtime owner
    // certificates exist before the later exact-cookie host-TGID index seed.
    // Its independent failure-retirement path is required before target readers.
    if normalized != 0 || unsafe { MEMBERS.get(&ids.tgid) }.is_none() {
        return 0;
    }
    let Some(domain) = SOURCE_DOMAIN.get_ptr_mut(&ids.tgid) else {
        return 0;
    };
    unsafe {
        if !atom::compare(
            addr_of_mut!((*domain).state),
            DOMAIN_ARMED,
            DOMAIN_TRANSITION,
        ) {
            retire_domain(domain);
            return 0;
        }
        let old = (*domain).original_image;
        let planned = (*domain).planned_image;
        if old == 0
            || planned == 0
            || old == planned
            || (*domain).reserved != [0, 0]
            || !atom::compare(addr_of_mut!((*domain).current_image), old, planned)
            || !atom::compare(
                addr_of_mut!((*domain).state),
                DOMAIN_TRANSITION,
                DOMAIN_ACTIVE,
            )
        {
            retire_domain(domain);
        }
    }
    0
}
