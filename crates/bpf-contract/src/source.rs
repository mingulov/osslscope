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
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SourceGuard {
    pub source_epoch: u64,
    pub state: u64,
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

const _: () = {
    assert!(core::mem::size_of::<SourceRequest>() == 112);
    assert!(core::mem::size_of::<SourceObserver>() == 48);
    assert!(core::mem::size_of::<SourceGuard>() == 16);
    assert!(core::mem::size_of::<SourceControl>() == 64);
    assert!(core::mem::size_of::<SourceConfig>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};
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
