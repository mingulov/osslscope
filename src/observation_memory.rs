// SPDX-License-Identifier: GPL-3.0-or-later
//! Single-threaded admission for retained sessions and temporary parser work.
//! Leases account declared bounded allocations; this is not an RSS measurement.
use std::{cell::Cell, rc::Rc};
#[derive(Clone)]
pub(crate) struct MemoryPool(Rc<State>);
struct State {
    limit: usize,
    used: Cell<usize>,
    peak: Cell<usize>,
}
pub(crate) struct MemoryLease {
    pool: MemoryPool,
    bytes: usize,
}
impl MemoryPool {
    pub(crate) fn new(limit: usize) -> Self {
        Self(Rc::new(State {
            limit,
            used: Cell::new(0),
            peak: Cell::new(0),
        }))
    }
    pub(crate) fn peak(&self) -> usize {
        self.0.peak.get()
    }
    /// Live spend (diagnostic readback; the peak above is monotonic).
    pub(crate) fn used(&self) -> usize {
        self.0.used.get()
    }
    pub(crate) fn limit(&self) -> usize {
        self.0.limit
    }
    /// Non-committal capacity probe: true iff `bytes` would fit
    /// now. Reads only (no spend, no peak bump), so admission can
    /// prove a working envelope without holding it.
    pub(crate) fn fits(&self, bytes: usize) -> bool {
        self.0
            .used
            .get()
            .checked_add(bytes)
            .is_some_and(|next| next <= self.0.limit)
    }
    /// Contention clamp (test pin): hold a filler lease that
    /// leaves exactly `target_free` bytes unspent, or `None`
    /// when free space is already at or below the target.
    /// Session reservations grow with the host CPU count, so
    /// few-CPU hosts leave slack where many-CPU hosts are
    /// contended; the clamp pins the contended state
    /// deterministically on any host.
    #[cfg(test)]
    pub(crate) fn clamp_free_to(&self, target_free: usize) -> Option<MemoryLease> {
        let headroom = self.limit().checked_sub(self.used())?;
        let fill = headroom.checked_sub(target_free)?;
        if fill == 0 {
            return None;
        }
        self.reserve(fill)
    }
    pub(crate) fn reserve(&self, bytes: usize) -> Option<MemoryLease> {
        let next = self.0.used.get().checked_add(bytes)?;
        if next > self.0.limit {
            return None;
        }
        self.0.used.set(next);
        self.0.peak.set(self.0.peak.get().max(next));
        Some(MemoryLease {
            pool: self.clone(),
            bytes,
        })
    }
}
impl MemoryLease {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn pool(&self) -> MemoryPool {
        self.pool.clone()
    }
}
impl Drop for MemoryLease {
    fn drop(&mut self) {
        self.pool.0.used.set(self.pool.0.used.get() - self.bytes);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ci_shaped_pool_refuses_stock_parse_under_two_sessions() {
        // CI regression pin (check.yml runs 42861210551 +
        // 42974059023, 4-CPU ubuntu-24.04): the session reservation
        // there measured 119_588_180 B (printed by
        // `session_reservation_precedes_open...`), leaving
        // 29_259_096 B free after two sessions — room the stock
        // scratch (23_229_281 B) fit, so the un-clamped refusal
        // legs failed. The contention clamp takes that
        // host-dependent slack deterministically. RED-first: this
        // test failed with the pre-fix un-clamped logic.
        const CI_FOUR_CPU_SESSION_BYTES: usize = 119_588_180;
        let pool = MemoryPool::new(256 << 20);
        let _one = pool.reserve(CI_FOUR_CPU_SESSION_BYTES).unwrap();
        let two = pool.reserve(CI_FOUR_CPU_SESSION_BYTES).unwrap();
        let stock = crate::inventory::elf::parser_scratch_bytes(6_386_528).unwrap();
        let small = crate::inventory::elf::parser_scratch_bytes(1 << 20).unwrap();
        // The clamp takes the CI slack, leaving exactly one
        // small-module scratch free.
        let pressure = pool.clamp_free_to(small);
        assert_eq!(
            pressure.as_ref().map(|lease| lease.bytes()),
            Some((256 << 20) - 2 * CI_FOUR_CPU_SESSION_BYTES - small)
        );
        // Contended: the stock parse refuses; a small module fits.
        assert!(
            pool.reserve(stock).is_none(),
            "stock libcrypto parse refuses under two CI-shaped sessions"
        );
        {
            let _fit = pool
                .reserve(small)
                .expect("small-module parse fits under two CI-shaped sessions");
        }
        // Already at target: the clamp takes nothing further.
        assert!(pool.clamp_free_to(small).is_none());
        assert!(pool.clamp_free_to(small + 1).is_none());
        // Recovery: the stock parse fits again once a session ends.
        drop(two);
        let _recovered = pool
            .reserve(stock)
            .expect("stock parse recovers after a CI-shaped session ends");
        assert!(pool.peak() <= pool.limit());
    }
    #[test]
    fn shared_scratch_is_released_and_refusal_does_not_charge() {
        let pool = MemoryPool::new(256 << 20);
        let a = pool.reserve(104 << 20).unwrap();
        let b = pool.reserve(104 << 20).unwrap();
        let scratch = pool.reserve(22 << 20).unwrap();
        assert!(pool.reserve(144 << 20).is_none());
        drop(scratch);
        drop(b);
        let largest = pool.reserve(144 << 20).unwrap();
        drop(largest);
        drop(a);
        assert!(pool.reserve(256 << 20).is_some());
    }
}
