// SPDX-License-Identifier: GPL-2.0-or-later
//! Private source publication ABI. No record in this module is a public event.

pub const SOURCE_ANCHOR: u32 = 15;
pub const SOURCE_REG: u32 = 16;
pub const SOURCE_READY: u32 = 17;
pub const GUARD_PREPARING: u64 = 0;
pub const GUARD_LIVE: u64 = 1;
pub const GUARD_RETIRED: u64 = 2;
pub const GUARD_CONFLICT: u64 = 3;
pub const PHASE_ANCHOR: u32 = 1;
pub const PHASE_ENTRY: u32 = 2;
pub const PHASE_RETURN: u32 = 3;
pub const PHASE_READY: u32 = 4;
pub const HOST_ID_FIRST: u64 = 1 << 63;
pub const KERNEL_ID_LAST: u64 = HOST_ID_FIRST - 1;
/// Last legacy counter cookie admitted as a registration site cookie.
pub const LEGACY_COOKIE_LAST: u64 = 4096;
/// First typed-site cookie admitted as a registration site cookie. Typed
/// cookies stay u32-fitting so the focused counter can pin the same cookie
/// for the same site; the gap between the legacy and typed ranges admits
/// nothing, so a legacy/typed cookie can never alias one registration row.
pub const TYPED_COOKIE_FIRST: u64 = 1 << 31;
/// One past the last typed-site cookie (u32 range end, exclusive).
pub const TYPED_COOKIE_END: u64 = 1 << 32;

/// Registration site cookies for ENTRY/RETURN/READY phases: the legacy
/// counter range plus the typed-site range. The kernel keys SOURCE_REG and
/// SOURCE_READY rows by (process, image, cookie, epoch) and never indexes
/// an array by cookie, so both ranges share the one receipt protocol with
/// the same NOEXIST/quarantine semantics. Pure predicate: no ctx read.
#[inline(always)]
pub fn valid_site_cookie(cookie: u64) -> bool {
    (1..=LEGACY_COOKIE_LAST).contains(&cookie)
        || (TYPED_COOKIE_FIRST..TYPED_COOKIE_END).contains(&cookie)
}

/// Observer-only configuration, frozen before source writers start.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceConfig {
    pub page_shift: u32,
    pub pending_limit: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceRequest {
    pub nonce: u64,
    pub anchor_id: u64,
    pub object_id: u64,
    pub source_epoch: u64,
    pub site_cookie: u64,
    pub file_offset: u64,
    pub observer_anchor_address: u64,
    pub phase: u32,
    pub required_mask: u32,
    pub entry_count: u32,
    pub exit_count: u32,
    pub verdict: u32,
    pub reserved: u32,
    pub publication_sequence: u64,
    pub process_incarnation: u64,
    pub image_epoch: u64,
    pub registration_id: u64,
}
impl SourceRequest {
    #[inline(always)]
    pub fn valid_input(&self) -> bool {
        if self.nonce < HOST_ID_FIRST
            || self.anchor_id < HOST_ID_FIRST
            || self.nonce == self.anchor_id
            || self.nonce == self.registration_id
            || self.object_id == 0
            || self.source_epoch == 0
            || self.process_incarnation == 0
            || self.image_epoch == 0
            || self.reserved != 0
        {
            return false;
        }
        match self.phase {
            PHASE_ANCHOR => {
                self.site_cookie == 0
                    && self.registration_id == 0
                    && self.file_offset == 0
                    && self.required_mask == 0
                    && self.observer_anchor_address != 0
            }
            PHASE_ENTRY | PHASE_RETURN | PHASE_READY => {
                valid_site_cookie(self.site_cookie)
                    && self.registration_id >= HOST_ID_FIRST
                    && self.registration_id != self.anchor_id
                    && self.observer_anchor_address == 0
                    && self.file_offset <= i64::MAX as u64
                    && (self.required_mask == 3
                        || self.required_mask == 1 && self.phase != PHASE_RETURN)
            }
            _ => false,
        }
    }
    /// Exact immutable input association; counters/verdict/sequence are separate
    /// kernel outputs checked at their respective entry/exit/receipt boundaries.
    #[inline(always)]
    pub fn same_input(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.anchor_id == other.anchor_id
            && self.object_id == other.object_id
            && self.source_epoch == other.source_epoch
            && self.site_cookie == other.site_cookie
            && self.file_offset == other.file_offset
            && self.observer_anchor_address == other.observer_anchor_address
            && self.phase == other.phase
            && self.required_mask == other.required_mask
            && self.reserved == other.reserved
            && self.process_incarnation == other.process_incarnation
            && self.image_epoch == other.image_epoch
            && self.registration_id == other.registration_id
    }
}

pub const DOMAIN_LIVE: u64 = 1;
pub const DOMAIN_ARMED: u64 = 2;
pub const DOMAIN_ACTIVE: u64 = 3;
pub const DOMAIN_RETIRED: u64 = 4;
pub const DOMAIN_POISON: u64 = 5;
pub const DOMAIN_TRANSITION: u64 = 6;

/// Keyed by the exact existing MEMBERS/NAMESPACE normalized TGID coordinate.
/// Initial host configuration requires original held custody for ARMED. After
/// writers start, current_image/state/loss_epoch are accessed atomically; neither
/// numeric TGID reuse nor a later exec may retarget or revive this retained row.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceDomain {
    pub process_incarnation: u64,
    pub original_image: u64,
    pub planned_image: u64,
    pub current_image: u64,
    pub state: u64,
    pub loss_epoch: u64,
    pub reserved: [u64; 2],
}

/// Kernel-private matching entry. Never host-read or exported: entry_inode is
/// populated only from the approved registration operand in phases2/3. Anchor
/// snapshot work happens at matched exit and leaves this operand slot zero.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourcePair {
    pub request: SourceRequest,
    pub entry_inode: u64,
    pub state: u64,
}
#[inline(always)]
pub const fn registration_succeeded(return_pointer: u64) -> bool {
    return_pointer != 0 && return_pointer < u64::MAX - 4094
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceGuard {
    pub source_epoch: u64,
    pub state: u64,
}
/// Per-CPU source serialization cell: iterator slot plus REL staging.
/// `slot@0` keeps its exact single-word CAS semantics for the current-VMA
/// join. `staging@8` stages one complete REL value for NOEXIST publication
/// without a 256-byte stack temporary. Only the serialized source writer
/// touches staging, and every publication zeroes it before writing fields;
/// stale bytes from a previous CPU-local insert can never enter a new row.
/// The typed producer reuses this same cell for its 192-byte digest message
/// scratch, strictly while holding the shared publisher lock that already
/// serializes every staging user on every CPU; the digest input is fully
/// rewritten before hashing, and the REL staging write after hashing fully
/// rewrites the cell again. The split owner commit additionally crosses a
/// 96-byte plan (digest plus IDs) in bytes `[144..240)` between its two
/// shallow phases, with `[240..256)` spare zero; that region is per-CPU
/// private to a non-preemptible BPF run, so no interleaver can observe or
/// corrupt it. Staging is word-typed
/// so this module stays dependency-free; the BPF writer casts it to the
/// same-sized, same-aligned REL value for typed stores.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceSlot {
    pub slot: u64,
    pub staging: [u64; 32],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceObserver {
    pub namespace_device: u64,
    pub namespace_inode: u64,
    pub local_pid_tgid: u64,
    pub nonce: u64,
    pub host_pid_tgid: u64,
    pub state: u64,
}
/// Host initializes once before writers. All later mutations are kernel-owned.
/// publication_busy is used only for bounded immutable publication, never as a
/// session-wide operational callback lock. No BTF spinlock is embedded here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceControl {
    pub published_sequence: u64,
    pub publication_busy: u64,
    pub relationship_claims: u64,
    pub pending_claims: u64,
    pub source_mode: u64,
    pub loss_sequence: u64,
    pub next_kernel_id: u64,
    pub reserved: u64,
}
impl SourceControl {
    pub const PREPARED: Self = Self {
        published_sequence: 0,
        publication_busy: 0,
        relationship_claims: 1, // The fixed observer enrollment row.
        pending_claims: 2,      // One serialized request and its entry witness.
        source_mode: 0,
        loss_sequence: 0,
        next_kernel_id: 1,
        reserved: 0,
    };
}

/// The serialized source request and entry witness keep the base two claims.
/// Actual pending insertion may proceed only after a successful atomic CAS to
/// this value. A smaller caller limit remains binding for every producer.
#[inline(always)]
pub const fn pending_claim_value(current: u64, limit: u32) -> Option<u64> {
    if limit < 2 || limit > 4096 || current < 2 || current >= limit as u64 {
        None
    } else {
        Some(current + 1)
    }
}
/// Release only after actual frame removal. Failure to release is conservative;
/// never refund a still-live frame or the two fixed source pairing reservations.
#[inline(always)]
pub const fn pending_release_value(current: u64) -> Option<u64> {
    if current <= 2 || current > 4096 {
        None
    } else {
        Some(current - 1)
    }
}
/// Batched release of `n` removed frames (Task 0 verifier fix): one
/// atomic CAS instead of `n` sequential single-release CAS loops, so
/// the BPF discard path makes ONE quota call per return instead of up
/// to 27 (the 27-in-loop calls blew the verifier's jump budget —
/// `observation_return` failed to load with E2BIG). All-or-nothing:
/// `Some(current - n)` iff the batch keeps the counter above the two
/// fixed reservations and within the cap; else `None` (the caller
/// records loss and the claims stay held — the same fail-safe
/// direction as a failed single release). `n == 0` and `n > 27` refuse
/// (the discard path frees at most 8 bodies × 3 kinds = 24 — level 0
/// never takes a body — so 27 is a defensive never-hit ceiling).
#[inline(always)]
pub const fn pending_release_n_value(current: u64, n: u32) -> Option<u64> {
    if n == 0 || n > 27 || current <= 2 || current > 4096 || current - 2 < n as u64 {
        None
    } else {
        Some(current - n as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SourceRequest>() == 112);
    assert!(core::mem::size_of::<SourcePair>() == 128);
    assert!(core::mem::size_of::<SourceDomain>() == 64);
    assert!(core::mem::size_of::<SourceObserver>() == 48);
    assert!(core::mem::size_of::<SourceGuard>() == 16);
    assert!(core::mem::size_of::<SourceControl>() == 64);
    assert!(core::mem::size_of::<SourceConfig>() == 8);
    assert!(core::mem::size_of::<SourceSlot>() == 264);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};
    #[test]
    fn source_domain_has_exact_planned_transition_fields() {
        assert_eq!(size_of::<SourceDomain>(), 64);
        assert_eq!(align_of::<SourceDomain>(), 8);
        assert_eq!(offset_of!(SourceDomain, process_incarnation), 0);
        assert_eq!(offset_of!(SourceDomain, original_image), 8);
        assert_eq!(offset_of!(SourceDomain, planned_image), 16);
        assert_eq!(offset_of!(SourceDomain, current_image), 24);
        assert_eq!(offset_of!(SourceDomain, state), 32);
        assert_eq!(offset_of!(SourceDomain, loss_epoch), 40);
        assert_eq!(offset_of!(SourceDomain, reserved), 48);
    }
    #[test]
    fn source_requests_reject_phase_confusion_and_match_the_full_domain() {
        let mut request = SourceRequest {
            nonce: HOST_ID_FIRST + 1,
            anchor_id: HOST_ID_FIRST + 2,
            object_id: 3,
            source_epoch: 4,
            observer_anchor_address: 0x1000,
            phase: PHASE_ANCHOR,
            process_incarnation: 5,
            image_epoch: 6,
            ..SourceRequest::default()
        };
        assert!(request.valid_input());
        let mut replay = request;
        replay.nonce = replay.anchor_id;
        assert!(!replay.valid_input());
        request.phase = PHASE_ENTRY;
        assert!(!request.valid_input());
        request.observer_anchor_address = 0;
        request.site_cookie = 1;
        request.registration_id = HOST_ID_FIRST + 3;
        request.required_mask = 3;
        assert!(request.valid_input());
        for field in [0, 1, 2, 3] {
            let mut other = request;
            match field {
                0 => other.nonce += 1,
                1 => other.process_incarnation += 1,
                2 => other.image_epoch += 1,
                _ => other.registration_id += 1,
            }
            assert!(!request.same_input(&other));
        }
        let mut output = request;
        output.entry_count = 1;
        output.exit_count = 1;
        output.verdict = 1;
        output.publication_sequence = 42;
        assert!(request.same_input(&output));
        request.phase = PHASE_RETURN;
        request.required_mask = 1;
        assert!(!request.valid_input());
        request.required_mask = 3;
        request.file_offset = 1 << 63;
        assert!(!request.valid_input());
    }
    #[test]
    fn source_requests_admit_legacy_and_typed_cookies_only() {
        // P3-I1: typed cookies join the receipt protocol under the same
        // predicate the kernel enforces; the gap between the ranges and
        // everything outside both ranges still refuses in every phase.
        let mut request = SourceRequest {
            nonce: HOST_ID_FIRST + 1,
            anchor_id: HOST_ID_FIRST + 2,
            object_id: 3,
            source_epoch: 4,
            site_cookie: 1,
            phase: PHASE_ENTRY,
            required_mask: 3,
            process_incarnation: 5,
            image_epoch: 6,
            registration_id: HOST_ID_FIRST + 3,
            ..SourceRequest::default()
        };
        assert!(request.valid_input());
        for cookie in [
            1,
            LEGACY_COOKIE_LAST,
            TYPED_COOKIE_FIRST,
            TYPED_COOKIE_FIRST + 1,
            TYPED_COOKIE_END - 1,
        ] {
            for phase in [PHASE_ENTRY, PHASE_RETURN, PHASE_READY] {
                request.site_cookie = cookie;
                request.phase = phase;
                assert!(request.valid_input(), "cookie {cookie} phase {phase}");
            }
        }
        for cookie in [
            0,
            LEGACY_COOKIE_LAST + 1,
            TYPED_COOKIE_FIRST - 1,
            TYPED_COOKIE_END,
            u64::MAX,
        ] {
            for phase in [PHASE_ENTRY, PHASE_RETURN, PHASE_READY] {
                request.site_cookie = cookie;
                request.phase = phase;
                assert!(
                    !request.valid_input(),
                    "cookie {cookie} phase {phase} must refuse"
                );
            }
        }
    }
    #[test]
    fn source_slot_keeps_serialization_word_and_staging_in_reviewed_slots() {
        assert_eq!(size_of::<SourceSlot>(), 264);
        assert_eq!(align_of::<SourceSlot>(), 8);
        assert_eq!(offset_of!(SourceSlot, slot), 0);
        assert_eq!(offset_of!(SourceSlot, staging), 8);
        assert_eq!(size_of::<[u64; 32]>(), 256);
    }
    #[test]
    fn source_pair_keeps_request_and_inode_in_the_reviewed_slots() {
        assert_eq!(size_of::<SourcePair>(), 128);
        assert_eq!(align_of::<SourcePair>(), 8);
        assert_eq!(offset_of!(SourcePair, request), 0);
        assert_eq!(offset_of!(SourcePair, entry_inode), 112);
        assert_eq!(offset_of!(SourcePair, state), 120);
        assert!(!registration_succeeded(0));
        assert!(!registration_succeeded(u64::MAX));
        assert!(!registration_succeeded(u64::MAX - 4094));
        assert!(registration_succeeded(u64::MAX - 4095));
        assert!(registration_succeeded(1));
    }
    #[test]
    fn joint_pending_bounds_preserve_reserved_pair_and_caller_limit() {
        assert_eq!(pending_claim_value(2, 3), Some(3));
        assert_eq!(pending_claim_value(3, 3), None);
        assert_eq!(pending_claim_value(4095, 4096), Some(4096));
        assert_eq!(pending_claim_value(4096, 4096), None);
        assert_eq!(pending_release_value(3), Some(2));
        assert_eq!(pending_release_value(2), None);
        for current in [0, 1, u64::MAX] {
            assert_eq!(pending_claim_value(current, 4096), None);
            assert_eq!(pending_release_value(current), None);
        }
        for limit in [0, 1, 4097, u32::MAX] {
            assert_eq!(pending_claim_value(2, limit), None);
        }
    }
    #[test]
    fn batched_pending_release_keeps_reserved_pair_and_caps_the_batch() {
        // Task 0 verifier fix: n=1 matches the single release exactly.
        for current in [3u64, 4, 100, 4096] {
            assert_eq!(
                pending_release_n_value(current, 1),
                pending_release_value(current),
                "current={current}"
            );
        }
        // Exact batches across the counter range.
        assert_eq!(pending_release_n_value(29, 27), Some(2));
        assert_eq!(pending_release_n_value(30, 27), Some(3));
        assert_eq!(pending_release_n_value(4096, 27), Some(4069));
        assert_eq!(pending_release_n_value(5, 3), Some(2));
        assert_eq!(pending_release_n_value(12, 10), Some(2));
        // The reserved pair is never refunded (all-or-nothing).
        for (current, n) in [(2, 1), (3, 2), (28, 27), (4, 3), (10, 9)] {
            assert_eq!(pending_release_n_value(current, n), None, "{current}-{n}");
        }
        // Degenerate batches refuse.
        for n in [0, 28, u32::MAX] {
            assert_eq!(pending_release_n_value(4096, n), None, "n={n}");
        }
        // Out-of-range counters refuse (mirrors the single release).
        for current in [0, 1, 2, 4097, u64::MAX] {
            assert_eq!(pending_release_n_value(current, 1), None, "{current}");
            assert_eq!(pending_release_n_value(current, 27), None, "{current}");
        }
    }
    #[test]
    fn source_records_match_exact_reviewed_offsets() {
        assert_eq!(
            (size_of::<SourceRequest>(), align_of::<SourceRequest>()),
            (112, 8)
        );
        assert_eq!(offset_of!(SourceRequest, phase), 56);
        assert_eq!(offset_of!(SourceRequest, reserved), 76);
        assert_eq!(offset_of!(SourceRequest, publication_sequence), 80);
        assert_eq!(offset_of!(SourceRequest, process_incarnation), 88);
        assert_eq!(offset_of!(SourceRequest, image_epoch), 96);
        assert_eq!(offset_of!(SourceRequest, registration_id), 104);
        assert_eq!(size_of::<SourceGuard>(), 16);
        assert_eq!(size_of::<SourceConfig>(), 8);
        assert_eq!(size_of::<SourceObserver>(), 48);
        assert_eq!(offset_of!(SourceObserver, host_pid_tgid), 32);
        assert_eq!(offset_of!(SourceObserver, state), 40);
        assert_eq!(size_of::<SourceControl>(), 64);
        assert_eq!(offset_of!(SourceControl, next_kernel_id), 48);
        let control = SourceControl::PREPARED;
        assert_eq!(control.relationship_claims, 1);
        assert_eq!(control.pending_claims, 2);
        assert_eq!(control.source_mode, 0);
        assert_eq!(control.published_sequence, 0);
    }
}
