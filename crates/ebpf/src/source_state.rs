// SPDX-License-Identifier: GPL-2.0-only
//! Shared live pending capacity in the actual provider entry/return handlers.
use aya_ebpf::{macros::map, maps::Array};
use core::intrinsics::{atomic_cxchg, AtomicOrdering::SeqCst};
use osslscope_bpf_contract::source::{
    pending_claim_value, pending_release_value, SourceConfig, SourceControl,
};

#[map]
pub static ATTR_STATE: Array<SourceControl> = Array::with_max_entries(1, 0);
#[map]
pub static SOURCE_CONFIG: Array<SourceConfig> = Array::with_max_entries(1, 0);

// A single atomic compare/exchange with equal replacement is a real ordered
// read. Do not substitute volatile loads or LLVM fences that BPF may discard.
#[inline(always)]
pub(crate) unsafe fn ordered_read(pointer: *mut u64) -> u64 {
    atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(pointer, 0, 0).0
}
#[inline(never)]
#[no_mangle]
pub fn claim_pending() -> bool {
    let Some(state) = ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    // Immutable after gate-open. Host initialization precedes publication of
    // ADMIT; no host or BPF writer changes source_mode during an open capture.
    let mode = unsafe { (*state).source_mode };
    if mode == 0 {
        return true;
    }
    if mode != 1 {
        return false;
    }
    let Some(config) = SOURCE_CONFIG.get(0) else {
        return false;
    };
    let pending = unsafe { core::ptr::addr_of_mut!((*state).pending_claims) };
    let mut current = unsafe { ordered_read(pending) };
    // Bounded contention refuses this frame only, not session eligibility.
    for _ in 0..8 {
        let Some(next) = pending_claim_value(current, config.pending_limit) else {
            return false;
        };
        let (observed, claimed) =
            unsafe { atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(pending, current, next) };
        if claimed {
            return true;
        }
        current = observed;
    }
    false
}
#[inline(never)]
#[no_mangle]
pub fn release_pending() -> bool {
    let Some(state) = ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let mode = unsafe { (*state).source_mode };
    if mode == 0 {
        return true;
    }
    if mode != 1 {
        return false;
    }
    let pending = unsafe { core::ptr::addr_of_mut!((*state).pending_claims) };
    let mut current = unsafe { ordered_read(pending) };
    for _ in 0..8 {
        let Some(next) = pending_release_value(current) else {
            return false;
        };
        let (observed, released) =
            unsafe { atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(pending, current, next) };
        if released {
            return true;
        }
        current = observed;
    }
    // A missed release keeps its reservation until final cut. It cannot create
    // headroom, underflow or refund another live frame. Caller records loss.
    false
}

#[inline(always)]
pub(crate) unsafe fn compare(pointer: *mut u64, old: u64, new: u64) -> bool {
    atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(pointer, old, new).1
}
#[inline(always)]
pub(crate) unsafe fn terminate_observer(pointer: *mut u64) {
    core::intrinsics::atomic_xchg::<u64, { SeqCst }>(pointer, 3);
}
/// Permanently charge a whole fresh source bundle before a join/publication.
/// Failed/partial work never refunds these claims. Actual pending is separate.
#[inline(never)]
#[no_mangle]
pub fn spend_source_bundle(amount: u64) -> bool {
    if amount == 0 || amount > 8192 {
        return false;
    }
    let Some(state) = ATTR_STATE.get_ptr_mut(0) else {
        return false;
    };
    let claims = unsafe { core::ptr::addr_of_mut!((*state).relationship_claims) };
    let mut current = unsafe { ordered_read(claims) };
    for _ in 0..8 {
        if current > 8192 - amount {
            return false;
        }
        let (observed, charged) = unsafe {
            atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(claims, current, current + amount)
        };
        if charged {
            return true;
        }
        current = observed;
    }
    false
}
