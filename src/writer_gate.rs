// SPDX-License-Identifier: GPL-3.0-or-later
//! One-way, shared non-sleepable writer cut. No target reads or pointer export.
use crate::{
    loader,
    observation_memory::{MemoryLease, MemoryPool},
};
use std::{
    cell::RefCell,
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

// Two small kernel maps plus allocator pages, template metadata, FD/host owners.
// Injected loader descriptors are reserved separately before each duplication.
pub(crate) const RESERVATION_BYTES: usize = 64 << 10;
pub(crate) const INJECTION_BYTES: usize = 4096;
pub(crate) const SPEC: loader::MapSpec = loader::MapSpec {
    name: "ADMIT",
    map_type: 12,
    key_size: 4,
    value_size: 4,
    max_entries: 1,
    flags: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClosedReceipt {
    pub(crate) map_id: u32,
}
#[derive(Clone, Copy, Debug)]
enum GateState {
    Setup,
    Open,
    Closing,
    Closed(ClosedReceipt),
    Unavailable,
}
impl GateState {
    fn receipt(self) -> Option<ClosedReceipt> {
        if let Self::Closed(r) = self {
            Some(r)
        } else {
            None
        }
    }
    fn open_with(&mut self, call: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if !matches!(self, Self::Setup) {
            return Err(io::Error::other("writer gate cannot reopen"));
        }
        *self = Self::Unavailable;
        call()?;
        *self = Self::Open;
        Ok(())
    }
    fn close_with(
        &mut self,
        map_id: u32,
        call: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<ClosedReceipt> {
        if let Some(r) = self.receipt() {
            return Ok(r);
        }
        if !matches!(self, Self::Open) {
            *self = Self::Unavailable;
            return Err(io::Error::other("no successful writer cut"));
        }
        *self = Self::Closing;
        if let Err(error) = call() {
            *self = Self::Unavailable;
            return Err(error);
        }
        let receipt = ClosedReceipt { map_id };
        *self = Self::Closed(receipt);
        Ok(receipt)
    }
}
struct Inner {
    outer: OwnedFd,
    token: OwnedFd,
    id: u32,
    state: RefCell<GateState>,
    _reservation: MemoryLease,
    injections: RefCell<Vec<MemoryLease>>,
    pool: MemoryPool,
}
#[derive(Clone)]
pub(crate) struct WriterGate(Rc<Inner>);
impl WriterGate {
    pub(crate) fn create(pool: &MemoryPool) -> io::Result<Self> {
        let reservation = pool
            .reserve(RESERVATION_BYTES)
            .ok_or_else(|| io::Error::other("writer gate reservation refused"))?;
        let token = ossl_bpf_sys::map_create(2, 4, 8, 1, None, "admit_token")?;
        ossl_bpf_sys::map_freeze(token.as_raw_fd())?;
        let outer = ossl_bpf_sys::writer_gate_outer(&token)?;
        let map = loader::BorrowedMap::new(outer.as_fd())?;
        map.shape(&[12], 4, 4).map_err(io::Error::other)?;
        if map.info.max_entries != 1 || map.info.flags != 0 {
            return Err(io::Error::other("writer gate shape"));
        }
        let id = map.info.id;
        Ok(Self(Rc::new(Inner {
            outer,
            token,
            id,
            state: RefCell::new(GateState::Setup),
            _reservation: reservation,
            injections: RefCell::new(Vec::new()),
            pool: pool.clone(),
        })))
    }
    pub(crate) fn open(&self) -> io::Result<Duration> {
        let start = Instant::now();
        self.0.state.borrow_mut().open_with(|| {
            loader::BorrowedMap::new(self.0.outer.as_fd())?
                .update(&0u32.to_ne_bytes(), &self.0.token.as_raw_fd().to_ne_bytes())
        })?;
        Ok(start.elapsed())
    }
    pub(crate) fn close(&self) -> io::Result<ClosedReceipt> {
        self.0.state.borrow_mut().close_with(self.0.id, || {
            // SAFETY: private immutable outer owner comes only from the typed constructor.
            unsafe { ossl_bpf_sys::writer_gate_delete(self.0.outer.as_raw_fd()) }
        })
    }
    pub(crate) fn receipt(&self) -> Option<ClosedReceipt> {
        self.0.state.borrow().receipt()
    }
    pub(crate) fn admitting(&self) -> bool {
        matches!(*self.0.state.borrow(), GateState::Setup | GateState::Open)
    }
    pub(crate) fn inject(&self, spec: &loader::MapSpecLite) -> io::Result<OwnedFd> {
        if !self.admitting()
            || spec.name != SPEC.name
            || spec.map_type != 12
            || spec.key_size != 4
            || spec.value_size != 4
            || spec.max_entries != 1
            || spec.flags != 0
        {
            return Err(io::Error::other("shared writer gate injection refused"));
        }
        let lease = self
            .0
            .pool
            .reserve(INJECTION_BYTES)
            .ok_or_else(|| io::Error::other("writer descriptor reservation refused"))?;
        let fd = self.0.outer.try_clone()?;
        if loader::BorrowedMap::new(fd.as_fd())?.info.id != self.0.id {
            return Err(io::Error::other("shared writer gate identity mismatch"));
        }
        self.0.injections.borrow_mut().push(lease);
        Ok(fd)
    }
    pub(crate) fn attest(&self, fd: &OwnedFd) -> io::Result<()> {
        if !ossl_bpf_sys::prog_map_ids(fd.as_raw_fd())?.contains(&self.0.id) {
            return Err(io::Error::other("producer missing shared writer gate"));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_refuses_before_any_kernel_map_creation() {
        let pool = MemoryPool::new(RESERVATION_BYTES - 1);
        assert!(WriterGate::create(&pool).is_err());
        assert_eq!(pool.peak(), 0);
    }
    #[test]
    #[ignore = "requires privileged BPF and both freshly built production objects"]
    fn native_actual_rust_roots_share_one_map_and_successful_delete_receipt() {
        let pool = MemoryPool::new(256 << 20);
        let gate = WriterGate::create(&pool).unwrap();
        let outer = loader::BorrowedMap::new(gate.0.outer.as_fd()).unwrap();
        let mut token_id = [0u8; 4];
        assert_eq!(
            outer
                .lookup(&0u32.to_ne_bytes(), &mut token_id)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        let count =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let provider =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count = loader::prepare_focused_count(&count).unwrap();
        let provider = crate::provider_observation::session::prepare_object(&provider).unwrap();
        assert!(loader::load(&count).is_err(), "unshared load must refuse");
        let c = loader::load_gated(&count, &gate).unwrap();
        let p = loader::load_gated(&provider, &gate).unwrap();
        assert_eq!(c.progs.len() + p.progs.len(), 3);
        let second = WriterGate::create(&pool).unwrap();
        for root in c.progs.values().chain(p.progs.values()) {
            gate.attest(root).unwrap();
            assert!(
                second.attest(root).is_err(),
                "wrong shared identity accepted"
            );
        }
        let wrong = loader::MapSpecLite {
            name: "ADMIT".into(),
            map_type: 12,
            key_size: 4,
            value_size: 4,
            max_entries: 2,
            flags: 0,
        };
        assert!(gate.inject(&wrong).is_err());
        let open_time = gate.open().unwrap();
        outer.lookup(&0u32.to_ne_bytes(), &mut token_id).unwrap();
        assert_eq!(
            u32::from_ne_bytes(token_id),
            loader::BorrowedMap::new(gate.0.token.as_fd())
                .unwrap()
                .info
                .id
        );
        let start = Instant::now();
        let receipt = gate.close().unwrap();
        let close_time = start.elapsed();
        assert_eq!(gate.receipt(), Some(receipt));
        assert_eq!(gate.close().unwrap(), receipt);
        assert!(gate.open().is_err());
        assert!(
            gate.inject(count.maps.iter().find(|m| m.name == "ADMIT").unwrap())
                .is_err()
        );
        assert_eq!(
            outer
                .lookup(&0u32.to_ne_bytes(), &mut token_id)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        eprintln!(
            "gate_map_id={} roots=3 open_ns={} delete_ns={} reserved_peak={}",
            receipt.map_id,
            open_time.as_nanos(),
            close_time.as_nanos(),
            pool.peak()
        );
    }
    #[test]
    fn failed_delete_never_certifies_or_rearms() {
        let mut state = GateState::Open;
        assert!(
            state
                .close_with(17, || Err(std::io::Error::from_raw_os_error(libc::ENOENT)))
                .is_err()
        );
        assert!(state.receipt().is_none());
        assert!(state.open_with(|| panic!("must not rearm")).is_err());
        assert!(
            state
                .close_with(17, || panic!("failed close is terminal"))
                .is_err()
        );
    }
    #[test]
    fn successful_delete_receipt_survives_repeated_close() {
        let mut state = GateState::Open;
        let first = state.close_with(17, || Ok(())).unwrap();
        let second = state
            .close_with(17, || panic!("must not delete twice"))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.map_id, 17);
        assert!(state.open_with(|| panic!("must not rearm")).is_err());
    }
    #[test]
    fn absent_setup_is_not_a_completed_barrier() {
        let mut state = GateState::Setup;
        assert!(state.close_with(17, || panic!("not open")).is_err());
        assert!(state.receipt().is_none());
        assert!(
            state.open_with(|| Ok(())).is_err(),
            "finalization of an unopened domain must prevent later admission"
        );
    }
    #[test]
    fn open_failure_is_not_retryable_admission() {
        let mut state = GateState::Setup;
        assert!(
            state
                .open_with(|| Err(std::io::Error::from_raw_os_error(libc::EIO)))
                .is_err()
        );
        assert!(state.open_with(|| panic!("must not retry")).is_err());
    }
}
