//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-private syscall seam. It neither publishes nor clones count FDs.
use super::protocol::*;
use super::registry::{CountLoadSink, Registry, preallocated};
use super::{Shared, locked};
use crate::loader::MapSpecLite;
use osslscope_ebpf_common::CountValue;
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Instant;

pub(super) fn possible_cpu_count() -> io::Result<usize> {
    // Pinned Aya reads /sys/devices/system/cpu/possible, not the online mask.
    // Linux's documented possible mask is fixed during boot; online/offline
    // hotplug does not change the raw per-CPU map buffer dimension.
    aya::util::nr_cpus().map_err(|(_, error)| error)
}

// Every operation is called by the same prepared owner, including raw map I/O.
pub(crate) trait CountIoDriver: Send {
    fn map_create(&mut self, spec: &MapSpecLite) -> io::Result<OwnedFd>;
    fn load_program(
        &mut self,
        insns: &[u8],
        name: &str,
        log: Option<&mut [u8]>,
    ) -> io::Result<OwnedFd>;
    fn open_pin(&mut self, locator: &CStr) -> io::Result<OwnedFd>;
    fn pin_identity(&mut self, pin: BorrowedFd<'_>) -> io::Result<BackingIdentity>;
    fn attach(
        &mut self,
        prog: BorrowedFd<'_>,
        pin_path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        tgid: u32,
    ) -> io::Result<OwnedFd>;
    /// # Safety
    /// The borrowed map and both slices must have the validated map dimensions,
    /// including aligned per-CPU value stride and the possible-CPU count.
    unsafe fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()>;
    /// # Safety
    /// The borrowed map and input/output slices must have validated dimensions.
    unsafe fn lookup(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &mut [u8])
    -> io::Result<()>;
    /// # Safety
    /// All present key slices must match the borrowed map's validated key size.
    unsafe fn next_key(
        &mut self,
        fd: BorrowedFd<'_>,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> io::Result<()>;
    /// Consume ownership before one close attempt, even on error; never retry.
    fn close(&mut self, fd: OwnedFd) -> io::Result<()>;
    fn now(&self) -> Instant;
    fn monotonic_ns(&self) -> Option<u64>;
}

/// Checked lengths precede every raw map call. These maps are from the exact
/// seven-map load; no MapData wrapper, clone or descriptor alias is created.
pub(super) struct MapIo<'a> {
    shared: &'a Shared,
    registry: &'a Registry,
    loaded: &'a crate::loader::CountLoadedSlots,
    deadline: Instant,
    operation: CountOperation,
    terminal: bool,
}
impl<'a> MapIo<'a> {
    pub(super) fn new(
        shared: &'a Shared,
        registry: &'a Registry,
        loaded: &'a crate::loader::CountLoadedSlots,
        deadline: Instant,
        operation: CountOperation,
    ) -> Self {
        Self {
            shared,
            registry,
            loaded,
            deadline,
            operation,
            terminal: false,
        }
    }
    pub(super) fn terminal(
        shared: &'a Shared,
        registry: &'a Registry,
        loaded: &'a crate::loader::CountLoadedSlots,
        deadline: Instant,
        operation: CountOperation,
    ) -> Self {
        Self {
            shared,
            registry,
            loaded,
            deadline,
            operation,
            terminal: true,
        }
    }
    pub(super) fn stop(&self, driver: &mut impl CountIoDriver) -> SealBracket {
        let before_ns = driver.monotonic_ns();
        let result = self.write(driver, CountMap::Target, 0, &0u64.to_ne_bytes());
        let after_ns = driver.monotonic_ns();
        SealBracket {
            before_ns,
            after_ns,
            result: match result {
                Ok(()) => StopResult::Stopped,
                Err(failure) => StopResult::Failed(failure),
            },
        }
    }
    fn failure(&self, map: CountMap, class: FailureClass) -> OwnerFailure {
        OwnerFailure {
            operation: self.operation,
            resource: ResourceId::Map(map),
            class,
            errno: None,
        }
    }
    fn check(&self, driver: &impl CountIoDriver) -> Result<(), OwnerFailure> {
        if driver.now() >= self.deadline {
            return Err(OwnerFailure::engine(self.operation, FailureClass::Deadline));
        }
        let state = locked(&self.shared.state);
        if !self.terminal
            && (state.terminal.is_some()
                || self
                    .shared
                    .abandoned
                    .load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(OwnerFailure::engine(
                self.operation,
                FailureClass::Disconnected,
            ));
        }
        Ok(())
    }
    fn enter(&self, driver: &impl CountIoDriver) -> Result<(), OwnerFailure> {
        if driver.now() >= self.deadline {
            return Err(OwnerFailure::engine(self.operation, FailureClass::Deadline));
        }
        let mut state = locked(&self.shared.state);
        if !self.terminal
            && (state.terminal.is_some()
                || self
                    .shared
                    .abandoned
                    .load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(OwnerFailure::engine(
                self.operation,
                FailureClass::Disconnected,
            ));
        }
        // This is the operation's admission point relative to the sticky seal.
        // A previously admitted call may return late; the next call must check
        // again. The publication lock is released before entering the driver.
        state.active_operation = Some(self.operation);
        Ok(())
    }
    fn write(
        &self,
        driver: &mut impl CountIoDriver,
        map: CountMap,
        key: u32,
        value: &[u8],
    ) -> Result<(), OwnerFailure> {
        if self.terminal
            && (self.operation != CountOperation::Stop
                || map != CountMap::Target
                || value != 0u64.to_ne_bytes())
        {
            return Err(self.failure(map, FailureClass::InvalidInput));
        }
        let spec = crate::loader::COUNT_MAPS[map.index()];
        if spec.map_type != 2
            || spec.key_size != 4
            || spec.value_size as usize != value.len()
            || key >= spec.max_entries
        {
            return Err(self.failure(map, FailureClass::InvalidInput));
        }
        self.enter(driver)?;
        // SAFETY: the tracked load validates the exact map shape; the key and
        // scalar value lengths and index were just checked against that shape.
        unsafe {
            driver.update(
                self.registry.borrow(self.loaded.maps[map.index()]),
                &key.to_ne_bytes(),
                value,
            )
        }
        .map_err(|e| OwnerFailure::io(self.operation, ResourceId::Map(map), &e))
    }
    pub(super) fn generation(
        &self,
        driver: &mut impl CountIoDriver,
        generation: u32,
    ) -> Result<(), OwnerFailure> {
        self.write(driver, CountMap::Gen, 0, &generation.to_ne_bytes())
    }
    pub(super) fn open(
        &self,
        driver: &mut impl CountIoDriver,
        request: &OpenRequest,
    ) -> Result<OpenReceipt, OwnerFailure> {
        let mut receipt = OpenReceipt::pending(self.shared.epoch, request);
        locked(&self.shared.state).resolved_open = Some(receipt);
        let writes: [(CountMap, u32, &[u8], OpenWriteFrontier); 4] = [
            (
                CountMap::Window,
                0,
                &request.start_ns.to_ne_bytes(),
                OpenWriteFrontier::WindowStart,
            ),
            (
                CountMap::Window,
                1,
                &request.deadline_ns.to_ne_bytes(),
                OpenWriteFrontier::WindowDeadline,
            ),
            (
                CountMap::Gen,
                0,
                &request.generation.to_ne_bytes(),
                OpenWriteFrontier::Generation,
            ),
            (
                CountMap::Target,
                0,
                &request.tgid.to_ne_bytes(),
                OpenWriteFrontier::Target,
            ),
        ];
        for (map, key, value, frontier) in writes {
            if let Err(failure) = self.write(driver, map, key, value) {
                receipt.outcome = OpenOutcome::Failed;
                locked(&self.shared.state).resolved_open = Some(receipt);
                return Err(failure);
            }
            receipt.completed_writes = frontier;
            if frontier == OpenWriteFrontier::Target {
                receipt.outcome = OpenOutcome::Completed;
            }
            locked(&self.shared.state).resolved_open = Some(receipt);
        }
        Ok(receipt)
    }
    fn lookup(
        &self,
        driver: &mut impl CountIoDriver,
        map: CountMap,
        key: &[u8],
        value: &mut [u8],
        cpus: usize,
    ) -> Result<(), OwnerFailure> {
        let spec = crate::loader::COUNT_MAPS[map.index()];
        let bytes = checked_per_cpu_bytes(spec.value_size as usize, cpus)
            .ok_or_else(|| self.failure(map, FailureClass::InvalidInput))?;
        if !matches!(spec.map_type, 5 | 6)
            || key.len() != spec.key_size as usize
            || value.len() != bytes
        {
            return Err(self.failure(map, FailureClass::InvalidInput));
        }
        self.enter(driver)?;
        // SAFETY: the key and complete aligned possible-CPU value buffer have
        // exactly the dimensions of this validated tracked per-CPU map.
        unsafe {
            driver.lookup(
                self.registry.borrow(self.loaded.maps[map.index()]),
                key,
                value,
            )
        }
        .map_err(|e| OwnerFailure::io(self.operation, ResourceId::Map(map), &e))
    }
    fn next(
        &self,
        driver: &mut impl CountIoDriver,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> Result<(), OwnerFailure> {
        let spec = crate::loader::COUNT_MAPS[CountMap::Counts.index()];
        if spec.key_size as usize != next.len()
            || key.is_some_and(|k| k.len() != spec.key_size as usize)
        {
            return Err(self.failure(CountMap::Counts, FailureClass::InvalidInput));
        }
        self.enter(driver)?;
        // SAFETY: all key slices match the tracked COUNTS key dimensions.
        unsafe {
            driver.next_key(
                self.registry
                    .borrow(self.loaded.maps[CountMap::Counts.index()]),
                key,
                next,
            )
        }
        .map_err(|e| OwnerFailure::io(self.operation, ResourceId::Map(CountMap::Counts), &e))
    }
}

fn checked_per_cpu_bytes(value_size: usize, cpus: usize) -> Option<usize> {
    if cpus == 0 || value_size == 0 {
        return None;
    }
    value_size
        .checked_add(7)?
        .checked_div(8)?
        .checked_mul(8)?
        .checked_mul(cpus)
        .filter(|n| *n <= isize::MAX as usize)
}
fn unavailable(map: CountMap, key: u32) -> Component<u64> {
    Component::Unavailable(ComponentFailure {
        map,
        key,
        operation: CountOperation::Read,
        class: None,
        errno: None,
    })
}
fn empty_snapshot(rows: Vec<(u64, CountValue)>) -> RawSnapshot {
    RawSnapshot {
        sequence: SnapshotSeq::checked(1).expect("nonzero initial private image"),
        rows,
        admitted: unavailable(CountMap::Admitted, 0),
        dropfail: unavailable(CountMap::Dropfail, 0),
        latc: std::array::from_fn(|key| unavailable(CountMap::Latc, key as u32)),
        enumeration: EnumerationStatus::Unfinished,
    }
}
/// Exactly three row allocations and one checked CPU-fold scratch exist before
/// the first map create. Arc handles share these images without cloning rows.
pub(super) struct ReadWorkspace {
    images: [Arc<RawSnapshot>; 3],
    building: Option<usize>,
    pub(super) sequences: IdCounter,
    scratch: Vec<u8>,
    seen: Vec<u64>,
    cpus: usize,
    capacity: usize,
}
impl ReadWorkspace {
    pub(super) fn allocate(
        limits: CountOwnerLimits,
        (rows, scratch): (Vec<(u64, CountValue)>, Vec<u8>),
    ) -> Result<Self, OwnerFailure> {
        if checked_per_cpu_bytes(24, limits.possible_cpus) != Some(limits.cpu_scratch_bytes)
            || limits.raw_rows != 8192
            || rows.capacity() < limits.raw_rows
            || scratch.len() != limits.cpu_scratch_bytes
        {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::InvalidInput,
            ));
        }
        Ok(Self {
            images: [
                Arc::new(empty_snapshot(rows)),
                Arc::new(empty_snapshot(preallocated(limits.raw_rows)?)),
                Arc::new(empty_snapshot(preallocated(limits.raw_rows)?)),
            ],
            building: None,
            sequences: IdCounter::default(),
            scratch,
            seen: preallocated(limits.raw_rows)?,
            cpus: limits.possible_cpus,
            capacity: limits.raw_rows,
        })
    }
    fn available(&self, index: usize) -> bool {
        Arc::strong_count(&self.images[index]) == 1 && Arc::weak_count(&self.images[index]) == 0
    }
    fn image(&mut self) -> &mut RawSnapshot {
        Arc::get_mut(&mut self.images[self.building.expect("read building image")])
            .expect("building image is exclusive")
    }
    fn begin(&mut self) -> Result<(), OwnerFailure> {
        let index = (0..3)
            .find(|i| self.available(*i))
            .ok_or_else(|| OwnerFailure::engine(CountOperation::Read, FailureClass::Capacity))?;
        self.building = Some(index);
        self.seen.clear();
        let image = self.image();
        image.rows.clear();
        image.admitted = unavailable(CountMap::Admitted, 0);
        image.dropfail = unavailable(CountMap::Dropfail, 0);
        image.latc = std::array::from_fn(|key| unavailable(CountMap::Latc, key as u32));
        image.enumeration = EnumerationStatus::Unfinished;
        Ok(())
    }
    fn copy_image(&mut self, source: usize, destination: usize) {
        let (source, destination) = if source < destination {
            let (left, right) = self.images.split_at_mut(destination);
            (&left[source], &mut right[0])
        } else {
            let (left, right) = self.images.split_at_mut(source);
            (&right[0], &mut left[destination])
        };
        let destination = Arc::get_mut(destination).expect("available image");
        destination.rows.clear();
        assert!(destination.rows.capacity() >= source.rows.len());
        destination.rows.extend_from_slice(&source.rows);
        destination.admitted = source.admitted;
        destination.dropfail = source.dropfail;
        destination.latc = source.latc;
        destination.enumeration = source.enumeration;
    }
    fn sequence(&mut self) -> Result<SnapshotSeq, OwnerFailure> {
        self.sequences
            .next()
            .and_then(SnapshotSeq::checked)
            .map_err(|mut failure| {
                failure.operation = CountOperation::Read;
                failure
            })
    }
    fn publish_prefix(&mut self, shared: &Shared) -> Result<(), OwnerFailure> {
        let index = self.building.expect("building image");
        let Some(spare) = (0..3).find(|i| *i != index && self.available(*i)) else {
            return Ok(());
        };
        self.copy_image(index, spare);
        let phase = locked(&shared.state).phase;
        let Ok(mut latest) = shared.latest_progress.try_lock() else {
            return Ok(());
        };
        let sequence = self.sequence()?;
        self.image().sequence = sequence;
        *latest = Some(RawCheckpoint {
            snapshot: Arc::clone(&self.images[index]),
            phase,
            published_at: Instant::now(),
        });
        self.building = Some(spare);
        Ok(())
    }
    fn finish(&mut self, shared: &Shared) -> Result<Arc<RawSnapshot>, OwnerFailure> {
        let sequence = self.sequence()?;
        self.image().sequence = sequence;
        let index = self.building.take().expect("building image");
        let snapshot = Arc::clone(&self.images[index]);
        let phase = locked(&shared.state).phase;
        if let Ok(mut latest) = shared.latest_progress.try_lock() {
            *latest = Some(RawCheckpoint {
                snapshot: Arc::clone(&snapshot),
                phase,
                published_at: Instant::now(),
            });
        }
        Ok(snapshot)
    }
    pub(super) fn read(
        &mut self,
        driver: &mut impl CountIoDriver,
        io: &MapIo<'_>,
    ) -> Result<Arc<RawSnapshot>, OwnerFailure> {
        self.begin()?;
        io.check(driver)?;
        self.publish_prefix(io.shared)?;
        self.read_rows(driver, io)?;
        let len = checked_per_cpu_bytes(8, self.cpus)
            .ok_or_else(|| io.failure(CountMap::Admitted, FailureClass::InvalidInput))?;
        for (map, key) in [(CountMap::Admitted, 0u32), (CountMap::Dropfail, 0u32)]
            .into_iter()
            .chain((0..16u32).map(|key| (CountMap::Latc, key)))
        {
            let component = match io.lookup(
                driver,
                map,
                &key.to_ne_bytes(),
                &mut self.scratch[..len],
                self.cpus,
            ) {
                Ok(()) => Component::Available(self.scratch[..len].chunks_exact(8).fold(
                    0u64,
                    |sum, bytes| {
                        sum.saturating_add(u64::from_ne_bytes(
                            bytes.try_into().expect("checked u64 stride"),
                        ))
                    },
                )),
                Err(failure) => {
                    self.record_failure(io, failure);
                    let component = ComponentFailure {
                        map,
                        key,
                        operation: CountOperation::Read,
                        class: Some(failure.class),
                        errno: failure.errno,
                    };
                    locked(&io.shared.state)
                        .failures
                        .record_component(component);
                    Component::Unavailable(component)
                }
            };
            match map {
                CountMap::Admitted => self.image().admitted = component,
                CountMap::Dropfail => self.image().dropfail = component,
                _ => self.image().latc[key as usize] = component,
            }
            self.publish_prefix(io.shared)?;
        }
        self.finish(io.shared)
    }
    fn record_failure(&self, io: &MapIo<'_>, failure: OwnerFailure) {
        let mut state = locked(&io.shared.state);
        if state.read_failure.is_none() {
            state.read_failure = Some(failure);
        }
        state.failures.record(failure);
    }
    fn read_rows(
        &mut self,
        driver: &mut impl CountIoDriver,
        io: &MapIo<'_>,
    ) -> Result<(), OwnerFailure> {
        let mut previous: Option<[u8; 8]> = None;
        let mut unread_keys = 0u64;
        loop {
            let mut next = [0; 8];
            match io.next(
                driver,
                previous.as_ref().map(<[u8; 8]>::as_slice),
                &mut next,
            ) {
                Err(failure) if failure.errno == Some(libc::ENOENT) => {
                    self.image().enumeration = EnumerationStatus::Complete { unread_keys };
                    break;
                }
                Err(failure) => {
                    self.record_failure(io, failure);
                    break;
                }
                Ok(()) => {}
            }
            let key = u64::from_ne_bytes(next);
            // A concurrently removed cursor can restart the kernel iterator.
            // Remember even absent lookups: an absent-key cycle is untrusted
            // too. Never restart or turn such a prefix into an exact census.
            if self.seen.contains(&key) {
                self.record_failure(io, io.failure(CountMap::Counts, FailureClass::Inventory));
                break;
            }
            if self.seen.len() == self.capacity {
                self.record_failure(io, io.failure(CountMap::Counts, FailureClass::Capacity));
                break;
            }
            self.seen.push(key);
            match io.lookup(
                driver,
                CountMap::Counts,
                &next,
                &mut self.scratch,
                self.cpus,
            ) {
                Ok(()) => {
                    let mut total = CountValue::default();
                    for bytes in self.scratch.chunks_exact(24) {
                        total.fold(&CountValue {
                            count: u64::from_ne_bytes(
                                bytes[..8].try_into().expect("checked CountValue count"),
                            ),
                            first_ns: u64::from_ne_bytes(
                                bytes[8..16].try_into().expect("checked CountValue first"),
                            ),
                            last_ns: u64::from_ne_bytes(
                                bytes[16..24].try_into().expect("checked CountValue last"),
                            ),
                        });
                    }
                    if total.count != 0 {
                        assert!(self.image().rows.len() < self.capacity);
                        self.image().rows.push((key, total));
                    }
                    // Small prefixes survive an immediately blocked third read;
                    // larger reads publish bounded batches without quadratic
                    // copying of every accumulated row at all 8192 positions.
                    if self.seen.len() <= 2 || self.seen.len().is_multiple_of(64) {
                        self.publish_prefix(io.shared)?;
                    }
                }
                Err(failure) if failure.errno == Some(libc::ENOENT) => {
                    // The key disappeared between enumeration and lookup. Only
                    // natural enumeration completion can make this count exact.
                    unread_keys = unread_keys
                        .checked_add(1)
                        .ok_or_else(|| io.failure(CountMap::Counts, FailureClass::Capacity))?;
                }
                Err(failure) => {
                    self.record_failure(io, failure);
                    break;
                }
            }
            previous = Some(next);
        }
        self.publish_prefix(io.shared)
    }
}

pub(super) struct LiveCountIoDriver;
impl CountIoDriver for LiveCountIoDriver {
    fn map_create(&mut self, spec: &MapSpecLite) -> io::Result<OwnedFd> {
        ossl_bpf_sys::map_create(
            spec.map_type,
            spec.key_size,
            spec.value_size,
            spec.max_entries,
            None,
            &spec.name,
        )
    }
    fn load_program(
        &mut self,
        insns: &[u8],
        name: &str,
        log: Option<&mut [u8]>,
    ) -> io::Result<OwnedFd> {
        match log {
            None => ossl_bpf_sys::prog_load_kprobe_quiet(insns, c"GPL", None, name, None),
            Some(log) => ossl_bpf_sys::prog_load_kprobe(insns, c"GPL", None, log, name, None),
        }
    }
    fn open_pin(&mut self, locator: &CStr) -> io::Result<OwnedFd> {
        // SAFETY: locator is terminated, flags need no mode argument. No fstat,
        // formatting or publication occurs before the caller installs this FD.
        let fd = unsafe { libc::open(locator.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned this fresh descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn pin_identity(&mut self, pin: BorrowedFd<'_>) -> io::Result<BackingIdentity> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the borrowed FD is live, and fstat initializes stat on success.
        if unsafe { libc::fstat(pin.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstat succeeded.
        let stat = unsafe { stat.assume_init() };
        Ok(BackingIdentity {
            device: crate::plan::encode_device(libc::major(stat.st_dev), libc::minor(stat.st_dev)),
            inode: stat.st_ino,
        })
    }
    fn attach(
        &mut self,
        prog: BorrowedFd<'_>,
        pin_path: &CStr,
        offsets: &[u64],
        cookies: &[u64],
        tgid: u32,
    ) -> io::Result<OwnedFd> {
        if offsets.is_empty() || offsets.len() != cookies.len() || offsets.len() > 8192 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        ossl_bpf_sys::link_create_uprobe_multi(prog.as_raw_fd(), pin_path, offsets, cookies, tgid)
    }
    unsafe fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
        // SAFETY: the caller proves the exact map/key/value dimensions.
        unsafe { ossl_bpf_sys::map_update_elem(fd.as_raw_fd(), key, value, ossl_bpf_sys::BPF_ANY) }
    }
    unsafe fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8],
        value: &mut [u8],
    ) -> io::Result<()> {
        // SAFETY: the caller proves the exact map/key/value dimensions.
        unsafe { ossl_bpf_sys::map_lookup_elem(fd.as_raw_fd(), key, value) }
    }
    unsafe fn next_key(
        &mut self,
        fd: BorrowedFd<'_>,
        key: Option<&[u8]>,
        next: &mut [u8],
    ) -> io::Result<()> {
        // SAFETY: the owner validates the exact key dimensions before entry.
        unsafe { ossl_bpf_sys::map_get_next_key(fd.as_raw_fd(), key, next) }
    }

    fn close(&mut self, fd: OwnedFd) -> io::Result<()> {
        ossl_bpf_sys::close_owned(fd)
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn monotonic_ns(&self) -> Option<u64> {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: time is writable for the clock_gettime result.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: successful clock_gettime initialized time.
        let time = unsafe { time.assume_init() };
        u64::try_from(time.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(time.tv_nsec).ok()?)
    }
}
