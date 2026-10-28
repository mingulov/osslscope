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
