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
    pub(crate) close_before_ns: u64,
    pub(crate) close_after_ns: u64,
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
        *self = Self::Unavailable;
        let close_before_ns = monotonic_ns()?;
        *self = Self::Closing;
        if let Err(error) = call() {
            *self = Self::Unavailable;
            return Err(error);
        }
        *self = Self::Unavailable;
        let close_after_ns = monotonic_ns()?;
        if close_after_ns < close_before_ns {
            return Err(io::Error::other("writer cut clock regression"));
        }
        let receipt = ClosedReceipt {
            map_id,
            close_before_ns,
            close_after_ns,
        };
        *self = Self::Closed(receipt);
        Ok(receipt)
    }
}
fn monotonic_ns() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid writable timespec and the process-independent monotonic clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|n| s.checked_add(n))
        })
        .filter(|&n| n != 0)
        .ok_or_else(|| io::Error::other("writer cut clock range"))
}
/// Non-Clone capability retaining the actual shared map/FD owner. Numeric map
/// IDs and copied diagnostic receipts cannot construct this capability.
pub(crate) struct OwnedClosedGate {
    gate: WriterGate,
    receipt: ClosedReceipt,
}
impl OwnedClosedGate {
    pub(crate) fn matches(&self, gate: &WriterGate) -> bool {
        Rc::ptr_eq(&self.gate.0, &gate.0) && self.gate.receipt() == Some(self.receipt)
    }
    pub(crate) fn receipt(&self) -> ClosedReceipt {
        self.receipt
    }
}
/// Each global raw link retains the same gate owner and its accounted capacity.
/// No caller can construct this owner from a numeric map/program identity.
pub(crate) struct LifecycleWriter {
    _link: OwnedFd,
    _gate: WriterGate,
    _reservation: MemoryLease,
}
const LIFECYCLE_RESERVATION_BYTES: usize = 32 << 10;

struct Inner {
    #[cfg(test)]
    fail_delete: std::cell::Cell<bool>,
    outer: OwnedFd,
    token: OwnedFd,
    id: u32,
    state: RefCell<GateState>,
    _reservation: MemoryLease,
    injections: RefCell<Vec<MemoryLease>>,
    pool: MemoryPool,
}
#[cfg(test)]
thread_local! { static HOST_GATE_CREATES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }
fn create_maps() -> io::Result<(OwnedFd, OwnedFd, u32)> {
    #[cfg(test)]
    if HOST_GATE_CREATES.with(|count| count.get().is_some()) {
        let acquire = || -> io::Result<OwnedFd> {
            let fd = std::fs::File::open("/dev/null")?.into();
            HOST_GATE_CREATES.with(|count| count.set(Some(count.get().unwrap() + 1)));
            Ok(fd)
        };
        return Ok((acquire()?, acquire()?, 1));
    }
    let token = ossl_bpf_sys::map_create(2, 4, 8, 1, None, "admit_token")?;
    ossl_bpf_sys::map_freeze(token.as_raw_fd())?;
    let outer = ossl_bpf_sys::writer_gate_outer(&token)?;
    let map = loader::BorrowedMap::new(outer.as_fd())?;
    map.shape(&[12], 4, 4).map_err(io::Error::other)?;
    if map.info.max_entries != 1 || map.info.flags != 0 {
        return Err(io::Error::other("writer gate shape"));
    }
    let id = map.info.id;
    Ok((outer, token, id))
}
#[cfg(test)]
pub(crate) fn host_acquisition_history(blocked: bool) {
    HOST_GATE_CREATES.with(|count| count.set(Some(0)));
    let pool = MemoryPool::new(RESERVATION_BYTES);
    let result = WriterGate::create(&pool);
    let creates = HOST_GATE_CREATES.with(|count| count.replace(None)).unwrap();
    if blocked {
        assert!(
            result.is_err(),
            "Starting must refuse typed writer-gate acquisition"
        );
        assert_eq!(creates, 0, "Starting reached a native create seam");
    } else {
        let gate = result.expect("harmless owned-FD creation seam");
        assert_eq!(creates, 2);
        let fds = [gate.0.outer.as_raw_fd(), gate.0.token.as_raw_fd()];
        drop(gate);
        for fd in fds {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        }
    }
}
/// Hermetic closed-gate pair for custody tests: a fake gate plus the
/// `OwnedClosedGate` its successful close minted. Two pairs share the
/// fake map id but never match each other, which is exactly what the
/// swapped-owner rejection tests need. No BPF syscalls, no real barrier.
#[cfg(test)]
pub(crate) fn fake_closed_for_shape_tests(
    pool: &MemoryPool,
) -> io::Result<(WriterGate, OwnedClosedGate)> {
    let gate = fake_for_shape_tests(pool)?;
    *gate.0.state.borrow_mut() = GateState::Open;
    gate.0.state.borrow_mut().close_with(gate.0.id, || Ok(()))?;
    let closed = gate.owned_closed()?;
    debug_assert!(closed.matches(&gate));
    Ok((gate, closed))
}
#[cfg(test)]
pub(crate) fn fake_for_shape_tests(pool: &MemoryPool) -> io::Result<WriterGate> {
    // Hermetic caps-free gate value for gated-shape tests: plain /dev/null
    // fds, no BPF syscalls, no bootstrap-registry touch, so concurrent
    // bootstrap tests cannot flake the holder. Unusable for real loads by
    // construction: any injection identity check against these fds fails.
    let reservation = pool
        .reserve(RESERVATION_BYTES)
        .ok_or_else(|| io::Error::other("writer gate reservation refused"))?;
    Ok(WriterGate(Rc::new(Inner {
        fail_delete: std::cell::Cell::new(false),
        outer: std::fs::File::open("/dev/null")?.into(),
        token: std::fs::File::open("/dev/null")?.into(),
        id: 1,
        state: RefCell::new(GateState::Setup),
        _reservation: reservation,
        injections: RefCell::new(Vec::new()),
        pool: pool.clone(),
    })))
}
#[derive(Clone)]
pub(crate) struct WriterGate(Rc<Inner>);
impl WriterGate {
    pub(crate) fn create(pool: &MemoryPool) -> io::Result<Self> {
        let reservation = pool
            .reserve(RESERVATION_BYTES)
            .ok_or_else(|| io::Error::other("writer gate reservation refused"))?;
        crate::lifecycle_producer::note_acquisition().map_err(io::Error::other)?;
        let (outer, token, id) = create_maps()?;
        Ok(Self(Rc::new(Inner {
            #[cfg(test)]
            fail_delete: std::cell::Cell::new(false),
            outer,
            token,
            id,
            state: RefCell::new(GateState::Setup),
            _reservation: reservation,
            injections: RefCell::new(Vec::new()),
            pool: pool.clone(),
        })))
    }
    pub(crate) fn preparing(&self) -> bool {
        matches!(*self.0.state.borrow(), GateState::Setup)
    }
    pub(crate) fn attach_lifecycle(
        &self,
        program: &OwnedFd,
        root: ossl_bpf_sys::LifecycleTracepoint,
    ) -> io::Result<LifecycleWriter> {
        if !self.preparing() {
            return Err(io::Error::other("lifecycle writers require unopened gate"));
        }
        let reservation = self
            .0
            .pool
            .reserve(LIFECYCLE_RESERVATION_BYTES)
            .ok_or_else(|| io::Error::other("lifecycle writer reservation refused"))?;
        self.attest(program)?;
        if ossl_bpf_sys::prog_type(program.as_raw_fd())? != 17 {
            return Err(io::Error::other("lifecycle program type mismatch"));
        }
        crate::lifecycle_producer::note_acquisition().map_err(io::Error::other)?;
        let link = ossl_bpf_sys::raw_tracepoint_open(program.as_raw_fd(), root)?;
        Ok(LifecycleWriter {
            _link: link,
            _gate: self.clone(),
            _reservation: reservation,
        })
    }
    pub(crate) fn open(&self) -> io::Result<Duration> {
        let start = Instant::now();
        self.0.state.borrow_mut().open_with(|| {
            loader::BorrowedMap::new(self.0.outer.as_fd())?
                .update(&0u32.to_ne_bytes(), &self.0.token.as_raw_fd().to_ne_bytes())
        })?;
        Ok(start.elapsed())
    }
    #[cfg(test)]
    pub(crate) fn map_memlock(&self) -> [u64; 2] {
        [&self.0.token, &self.0.outer].map(|fd| {
            let info =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
            info.lines()
                .find_map(|line| {
                    line.strip_prefix("memlock:")
                        .and_then(|v| v.trim().parse().ok())
                })
                .unwrap()
        })
    }
    #[cfg(test)]
    pub(crate) fn fail_next_delete(&self) {
        self.0.fail_delete.set(true);
    }
    pub(crate) fn close(&self) -> io::Result<ClosedReceipt> {
        self.0.state.borrow_mut().close_with(self.0.id, || {
            #[cfg(test)]
            if self.0.fail_delete.replace(false) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            // SAFETY: private immutable outer owner comes only from the typed constructor.
            unsafe { ossl_bpf_sys::writer_gate_delete(self.0.outer.as_raw_fd()) }
        })
    }
    pub(crate) fn owned_closed(&self) -> io::Result<OwnedClosedGate> {
        let receipt = self
            .receipt()
            .ok_or_else(|| io::Error::other("shared writer owner not closed"))?;
        Ok(OwnedClosedGate {
            gate: self.clone(),
            receipt,
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
        let budget = crate::provider_observation::ObservationBudget::default();
        let count = loader::prepare_focused_count(&count, &budget).unwrap();
        let provider =
            crate::provider_observation::session::prepare_legacy_object(&provider).unwrap();
        assert!(loader::load(&count).is_err(), "unshared load must refuse");
        let c = loader::load_gated(&count, &gate).unwrap();
        let p = loader::load_gated(&provider, &gate).unwrap();
        // Legacy-split expectation: the count object loads its single
        // count_entry root; the shared legacy provider preparation loads
        // exactly observation_entry (uprobe) + observation_return
        // (uretprobe) with its 16 legacy maps (ADMIT plus the 15
        // observation/classifier/control maps). Source roots
        // (source_reg_in/source_reg_out) and lifecycle roots stay in the
        // unloaded source half and never reach the gated loader.
        assert_eq!(c.progs.len(), 1);
        assert_eq!(p.progs.len(), 2);
        assert_eq!(p.maps.len(), 16);
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
    fn lifecycle_attachment_refuses_budget_and_open_gate_before_syscalls() {
        HOST_GATE_CREATES.with(|count| count.set(Some(0)));
        let pool = MemoryPool::new(RESERVATION_BYTES);
        let gate = WriterGate::create(&pool).unwrap();
        HOST_GATE_CREATES.with(|count| count.set(None));
        let program: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(gate.preparing());
        let error = gate
            .attach_lifecycle(&program, ossl_bpf_sys::LifecycleTracepoint::Exit)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "lifecycle writer reservation refused");
        assert_eq!(pool.peak(), RESERVATION_BYTES);
        *gate.0.state.borrow_mut() = GateState::Open;
        let error = gate
            .attach_lifecycle(&program, ossl_bpf_sys::LifecycleTracepoint::Exec)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "lifecycle writers require unopened gate");
        assert_eq!(pool.peak(), RESERVATION_BYTES);
    }

    #[test]
    fn closed_capability_rejects_another_owner_with_the_same_numeric_map_id() {
        HOST_GATE_CREATES.with(|count| count.set(Some(0)));
        let pool = MemoryPool::new(2 * RESERVATION_BYTES);
        let first = WriterGate::create(&pool).unwrap();
        let second = WriterGate::create(&pool).unwrap();
        HOST_GATE_CREATES.with(|count| count.set(None));
        assert_eq!(first.0.id, second.0.id);
        *first.0.state.borrow_mut() = GateState::Open;
        *second.0.state.borrow_mut() = GateState::Open;
        first
            .0
            .state
            .borrow_mut()
            .close_with(first.0.id, || Ok(()))
            .unwrap();
        second
            .0
            .state
            .borrow_mut()
            .close_with(second.0.id, || Ok(()))
            .unwrap();
        let closed = first.owned_closed().unwrap();
        assert!(closed.matches(&first));
        assert!(!closed.matches(&second));
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
        assert!(first.close_before_ns > 0);
        assert!(first.close_after_ns >= first.close_before_ns);
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
