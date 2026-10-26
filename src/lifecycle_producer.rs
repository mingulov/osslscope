// SPDX-License-Identifier: GPL-3.0-or-later
//! Early, private-table lifecycle helper custody. See docs/lifecycle-producer.md.
mod launcher;
mod protocol;
use protocol::*;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerFailure {
    pub reason: &'static str,
    pub errno: Option<i32>,
    pub cleanup_pending: bool,
}
impl std::fmt::Display for ProducerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lifecycle producer: {}", self.reason)?;
        if let Some(e) = self.errno {
            write!(f, " (errno {e})")?
        }
        if self.cleanup_pending {
            write!(f, "; launcher cleanup pending")?;
        }
        Ok(())
    }
}
impl std::error::Error for ProducerFailure {}
fn failure(reason: &'static str) -> ProducerFailure {
    ProducerFailure {
        reason,
        errno: None,
        cleanup_pending: false,
    }
}
fn os_failure(reason: &'static str) -> ProducerFailure {
    ProducerFailure {
        reason,
        errno: io::Error::last_os_error().raw_os_error(),
        cleanup_pending: false,
    }
}
#[derive(Debug, Clone, Copy)]
pub struct BootstrapGateError;
impl std::fmt::Display for BootstrapGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("producer bootstrap is in progress")
    }
}
impl std::error::Error for BootstrapGateError {}
#[derive(Clone, Copy, PartialEq, Eq)]
enum History {
    Empty,
    Starting,
    Closed,
    Created,
}
struct Registry {
    history: History,
    installed: Option<Weak<Shared>>,
    reserved: Option<Weak<Shared>>,
}
static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    history: History::Empty,
    installed: None,
    reserved: None,
});
/// Must precede every protected acquisition, including ordinary non-capture use.
pub fn note_acquisition() -> Result<(), BootstrapGateError> {
    let mut g = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if g.history == History::Starting {
        return Err(BootstrapGateError);
    }
    if g.history == History::Empty {
        g.history = History::Closed
    }
    Ok(())
}
pub(crate) fn registered() -> Option<ProducerHandle> {
    REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reserved
        .as_ref()
        .and_then(Weak::upgrade)
        .map(ProducerHandle)
}
pub(crate) fn target_registration() -> Result<Option<ProducerHandle>, ProducerFailure> {
    if CONSTRUCTION_UNCERTAIN.load(Ordering::Acquire) {
        return Err(failure(
            "unresolved producer construction blocks target fork",
        ));
    }
    Ok(registered())
}
pub(crate) fn installed() -> Result<ProducerHandle, ProducerFailure> {
    REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .installed
        .as_ref()
        .and_then(Weak::upgrade)
        .map(ProducerHandle)
        .filter(|h| {
            h.0.installation_active.load(Ordering::Acquire) && !h.0.sealed.load(Ordering::Acquire)
        })
        .ok_or_else(|| failure("explicit early runtime installation required"))
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProducerDomain {
    namespaces: Vec<(u64, u64)>,
    offsets: Vec<u8>,
}
impl ProducerDomain {
    fn read() -> Result<Self, ProducerFailure> {
        #[cfg(test)]
        {
            HOST_DOMAIN_READS.fetch_add(1, Ordering::AcqRel);
            if HOST_DOMAIN_REJECT.load(Ordering::Acquire) {
                return Err(failure("HOST domain read refusal"));
            }
        }
        let mut namespaces = Vec::with_capacity(7);
        for name in [
            "pid",
            "pid_for_children",
            "user",
            "net",
            "time",
            "time_for_children",
        ] {
            let f = std::fs::File::open(format!("/proc/self/ns/{name}"))
                .map_err(|_| os_failure("namespace binding"))?;
            #[cfg(test)]
            if HOST_DOMAIN_HOLD.load(Ordering::Acquire) {
                HOST_DOMAIN_FD.store(f.as_raw_fd() as usize + 1, Ordering::Release);
                while HOST_DOMAIN_HOLD.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            use std::os::unix::fs::MetadataExt;
            let m = f.metadata().map_err(|_| os_failure("namespace stat"))?;
            namespaces.push((m.dev(), m.ino()));
        }
        if namespaces[0] != namespaces[1] || namespaces[4] != namespaces[5] {
            return Err(failure("child namespace differs"));
        }
        use std::io::Read;
        let mut offsets = Vec::new();
        std::fs::File::open("/proc/self/timens_offsets")
            .map_err(|_| os_failure("time namespace offsets unavailable"))?
            .take(257)
            .read_to_end(&mut offsets)
            .map_err(|_| os_failure("time namespace offsets read"))?;
        if offsets.len() > 256 {
            return Err(failure("time namespace offsets too large"));
        }
        let text = std::str::from_utf8(&offsets)
            .map_err(|_| failure("time namespace offsets malformed"))?;
        let mut mono = false;
        let mut boot = false;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3
                || !["monotonic", "boottime"].contains(&fields[0])
                || fields[1] != "0"
                || fields[2] != "0"
            {
                return Err(failure("nonzero or malformed time namespace offset"));
            }
            if fields[0] == "monotonic" {
                if mono {
                    return Err(failure("duplicate monotonic offset"));
                }
                mono = true
            } else {
                if boot {
                    return Err(failure("duplicate boottime offset"));
                }
                boot = true
            }
        }
        if !mono || !boot {
            return Err(failure("monotonic offset not proven"));
        }
        Ok(Self {
            namespaces,
            offsets,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerShutdownState {
    Complete,
    Pending,
    Unknown,
}
#[derive(Debug, Clone)]
pub struct ProducerShutdownReceipt {
    pub state: ProducerShutdownState,
    pub launcher_status: Option<i32>,
    pub failure: Option<ProducerFailure>,
}
struct Slot {
    command: Option<Frame>,
    reply: Option<Frame>,
    active: bool,
    busy: bool,
    target_active: bool,
    abandon: bool,
    shutdown: Option<Instant>,
    receipt: Option<ProducerShutdownReceipt>,
    failure: Option<ProducerFailure>,
    next: u64,
}
struct Shared {
    slot: Mutex<Slot>,
    wake: Condvar,
    sealed: AtomicBool,
    subscriptions: AtomicUsize,
    audit_active: AtomicBool,
    domain: ProducerDomain,
    session: u64,
    launcher: i32,
    endpoint: RawFd,
    pidfd: RawFd,
    ready: AtomicBool,
    installation_active: AtomicBool,
    release_burst: AtomicBool,
    release_target: AtomicBool,
    abort_requested: AtomicBool,
    shutdown_origin: Instant,
    shutdown_stamp: AtomicU64,
    returned_pending: AtomicBool,

    #[cfg(test)]
    host_child: Mutex<Option<Frame>>,
    #[cfg(test)]
    host_disposed: AtomicBool,
}
#[derive(Clone)]
pub struct ProducerHandle(Arc<Shared>);
pub struct LifecycleRuntime {
    shared: Arc<Shared>,
}
pub struct InstalledProducerGuard {
    shared: Arc<Shared>,
    unregister: bool,
}
impl Drop for InstalledProducerGuard {
    fn drop(&mut self) {
        if self.unregister {
            self.shared
                .installation_active
                .store(false, Ordering::Release);
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct ProducerChildCloseSet(pub [RawFd; 2]);
pub(crate) struct ProducerTargetLease {
    shared: Arc<Shared>,
    inherited: bool,
}
impl ProducerTargetLease {
    pub(crate) fn inherited(&mut self) {
        self.inherited = true;
    }
    pub(crate) fn closed(&mut self) {
        self.inherited = false;
    }
    pub(crate) fn confirm_closed(
        &mut self,
        pid: u32,
        deadline: Instant,
    ) -> Result<(), ProducerFailure> {
        let mut s = self.shared.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.shared, &mut s);
        if !s.target_active
            || self.shared.audit_active.load(Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Err(failure("target closure audit admission refused"));
        }
        self.shared.audit_active.store(true, Ordering::Release);
        let _audit = ProducerDomainAudit(self.shared.clone());
        drop(s);
        // The exact stopped child remains guarded by its original pidfd. Only
        // absence of the directory entry proves slot closure; never follow a
        // potentially dangling fd symlink and never accept EACCES as absence.
        let directory = std::fs::File::open(format!("/proc/{pid}/fd"))
            .map_err(|_| os_failure("target descriptor directory unavailable"))?;
        for fd in [self.shared.endpoint, self.shared.pidfd] {
            let name = std::ffi::CString::new(fd.to_string())
                .map_err(|_| failure("target descriptor name"))?;
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    &mut metadata,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                return Err(failure("target retains producer descriptor"));
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(os_failure("target descriptor closure uncertain"));
            }
        }
        if Instant::now() >= deadline {
            return Err(failure("target closure audit deadline"));
        }
        self.closed();
        Ok(())
    }
}
impl Drop for ProducerTargetLease {
    fn drop(&mut self) {
        // An unresolved child retains the charged reservation. Only an actual
        // stop/exit/positive wait may release a copied table reference.
        if !self.inherited {
            self.shared.release_target.store(true, Ordering::Release);
        }
        self.shared.wake.notify_all();
    }
}
pub(crate) struct ProducerDomainAudit(Arc<Shared>);
impl Drop for ProducerDomainAudit {
    fn drop(&mut self) {
        self.0.audit_active.store(false, Ordering::Release);
        self.0.wake.notify_all();
    }
}
pub struct ShutdownTicket {
    shared: Arc<Shared>,
    deadline: Instant,
}
impl ShutdownTicket {
    pub fn wait(&self) -> ProducerShutdownReceipt {
        loop {
            if self.shared.returned_pending.load(Ordering::Acquire) {
                return pending_shutdown();
            }
            if let Ok(mut s) = self.shared.slot.try_lock() {
                if let Some(receipt) = &s.receipt {
                    return receipt.clone();
                }
                if Instant::now() >= self.deadline {
                    self.shared.returned_pending.store(true, Ordering::Release);
                    let receipt = pending_shutdown();
                    s.receipt = Some(receipt.clone());
                    return receipt;
                }
            } else if Instant::now() >= self.deadline {
                self.shared.returned_pending.store(true, Ordering::Release);
                return pending_shutdown();
            }
            std::thread::sleep(
                Duration::from_millis(1)
                    .min(self.deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}
fn pending_shutdown() -> ProducerShutdownReceipt {
    ProducerShutdownReceipt {
        state: ProducerShutdownState::Pending,
        launcher_status: None,
        failure: Some(failure("shutdown deadline; custody retained")),
    }
}
impl LifecycleRuntime {
    /// Construct before threads and all target/native/Count acquisition.
    ///
    /// # Safety
    /// Caller guarantees pristine acquisition history, no preloaded protected
    /// mappings, concurrent descriptor or namespace mutation, SIGCHLD auto-reap,
    /// or competing waiter. The bootstrap thread must outlive this runtime.
    pub unsafe fn bootstrap_early(
        deadline: Instant,
        workload_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self, ProducerFailure> {
        let mut g = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if g.history != History::Empty {
            return Err(failure("bootstrap history permanently closed"));
        }
        g.history = History::Starting;
        drop(g);
        let result = unsafe { bootstrap(deadline, workload_fd) };
        let mut g = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        g.history = if result.is_ok() {
            History::Created
        } else {
            History::Closed
        };
        if let Ok(shared) = &result {
            g.reserved = Some(Arc::downgrade(shared));
        }
        drop(g);
        result.map(|shared| Self { shared })
    }
    pub fn handle(&self) -> ProducerHandle {
        ProducerHandle(self.shared.clone())
    }
    pub fn install(&self) -> Result<InstalledProducerGuard, ProducerFailure> {
        if self.shared.sealed.load(Ordering::Acquire) {
            return Err(failure("producer sealed"));
        }
        let mut g = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if g.installed
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|s| s.installation_active.load(Ordering::Acquire))
        {
            return Err(failure("producer already installed"));
        }
        g.installed = Some(Arc::downgrade(&self.shared));
        self.shared
            .installation_active
            .store(true, Ordering::Release);
        Ok(InstalledProducerGuard {
            shared: self.shared.clone(),
            unregister: true,
        })
    }
    pub fn request_shutdown(&self, deadline: Instant) -> ShutdownTicket {
        request_shutdown(&self.shared, deadline)
    }
    pub fn shutdown(&self, deadline: Instant) -> ProducerShutdownReceipt {
        self.request_shutdown(deadline).wait()
    }
}
fn request_shutdown(shared: &Arc<Shared>, deadline: Instant) -> ShutdownTicket {
    shared.sealed.store(true, Ordering::Release);
    let stamp = (deadline
        .saturating_duration_since(shared.shutdown_origin)
        .as_nanos()
        .min((u64::MAX - 1) as u128) as u64)
        + 1;
    let selected =
        match shared
            .shutdown_stamp
            .compare_exchange(0, stamp, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => stamp,
            Err(first) => first,
        };
    shared.abort_requested.store(true, Ordering::Release);
    shared.wake.notify_all();
    let deadline = shared
        .shutdown_origin
        .checked_add(Duration::from_nanos(selected - 1))
        .unwrap_or(shared.shutdown_origin);
    ShutdownTicket {
        shared: shared.clone(),
        deadline,
    }
}
fn reconcile(shared: &Shared, s: &mut Slot) {
    if shared.release_burst.swap(false, Ordering::AcqRel) {
        s.active = false;
    }
    if shared.release_target.swap(false, Ordering::AcqRel) {
        s.target_active = false;
    }
    // The seal is itself revocation, including the interval before shutdown's
    // remaining atomic publications are reconciled. No caller must acquire this
    // mutex to seal or abandon a lease.
    if shared.abort_requested.swap(false, Ordering::AcqRel) || shared.sealed.load(Ordering::Acquire)
    {
        s.abandon = true;
    }
    let stamp = shared.shutdown_stamp.load(Ordering::Acquire);
    if stamp != 0 && s.shutdown.is_none() {
        s.shutdown = Some(
            shared
                .shutdown_origin
                .checked_add(Duration::from_nanos(stamp - 1))
                .unwrap_or(shared.shutdown_origin),
        );
    }
}
impl Drop for LifecycleRuntime {
    fn drop(&mut self) {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        let _ = request_shutdown(&self.shared, deadline);
    }
}
fn normalize(fd: OwnedFd) -> Result<OwnedFd, ProducerFailure> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(os_failure("descriptor normalization"));
    }
    let old = fd.as_raw_fd();
    drop(fd);
    let normalized = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(old, libc::F_GETFD) } >= 0
        || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
    {
        return Err(failure("normalized original slot closure uncertain"));
    }
    Ok(normalized)
}
struct BootstrapCustody {
    endpoint: OwnedFd,
    pidfd: Option<OwnedFd>,
    pid: i32,
}
#[cfg(test)]
static HOST_DOMAIN_HOLD: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static HOST_DOMAIN_FD: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HOST_DOMAIN_READS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HOST_DOMAIN_REJECT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static HOST_BOOT_SHARED: Mutex<Option<Arc<Shared>>> = Mutex::new(None);
#[cfg(test)]
static HOST_PIDFD_FAILURE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static HOST_BOOTSTRAP_SETTLE_HOLD: AtomicBool = AtomicBool::new(false);
static CONSTRUCTION_UNCERTAIN: AtomicBool = AtomicBool::new(false);
static QUARANTINED_BOOTSTRAP: Mutex<Option<BootstrapCustody>> = Mutex::new(None);
fn settle_bootstrap(owner: BootstrapCustody, deadline: Instant) -> bool {
    // Before Ready, no helper can exist. Only this exact owned launcher is killed.
    let _ = unsafe { libc::kill(owner.pid, libc::SIGKILL) };
    while Instant::now() < deadline {
        #[cfg(test)]
        if HOST_BOOTSTRAP_SETTLE_HOLD.load(Ordering::Acquire) {
            break;
        }
        let mut status = 0;
        let r = unsafe { libc::waitpid(owner.pid, &mut status, libc::WNOHANG) };
        if r == owner.pid {
            #[cfg(test)]
            eprintln!(
                "HOST construction positive-wait pid={} raw-status={status}",
                owner.pid
            );
            let _ = close_owned(owner.endpoint);
            if let Some(fd) = owner.pidfd {
                let _ = close_owned(fd);
            }
            return true;
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
        std::thread::yield_now();
    }
    CONSTRUCTION_UNCERTAIN.store(true, Ordering::Release);
    *QUARANTINED_BOOTSTRAP
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(owner);
    false
}
struct SignalMask(u64);
impl SignalMask {
    fn block() -> Result<Self, ProducerFailure> {
        let all = u64::MAX;
        let mut saved = 0;
        let r = unsafe {
            launcher::raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                &all as *const _ as usize,
                &mut saved as *mut _ as usize,
                8,
                0,
                0,
            )
        };
        if r < 0 {
            return Err(failure("raw signal block failed"));
        }
        Ok(Self(saved))
    }
    fn restore(self) -> Result<(), ProducerFailure> {
        let r = unsafe {
            launcher::raw(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK as usize,
                &self.0 as *const _ as usize,
                0,
                8,
                0,
                0,
            )
        };
        if r < 0 {
            Err(failure("raw signal restoration failed"))
        } else {
            Ok(())
        }
    }
}
unsafe fn bootstrap(
    deadline: Instant,
    workload: Option<BorrowedFd<'_>>,
) -> Result<Arc<Shared>, ProducerFailure> {
    if deadline <= Instant::now() {
        return Err(failure("bootstrap deadline"));
    }
    if let Some(fd) = workload {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } < 0 {
            return Err(os_failure("closed workload descriptor"));
        }
    }
    let mask = SignalMask::block()?;
    let originally_closed=[0,1,2].map(|fd|unsafe {libc::fcntl(fd,libc::F_GETFD)}<0 && io::Error::last_os_error().raw_os_error()==Some(libc::EBADF));
    let prepared = (|| {
        if std::fs::read_dir("/proc/self/task")
            .map_err(|_| os_failure("task inventory"))?
            .take(2)
            .count()
            != 1
        {
            return Err(failure("bootstrap requires exactly one thread"));
        }
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut act) } < 0
            || act.sa_sigaction != libc::SIG_DFL
            || act.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            return Err(failure("SIGCHLD ownership unavailable"));
        }
        let mut originals: Vec<i32> = (0..=2)
            .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0)
            .collect();
        if let Some(fd) = workload {
            originals.push(fd.as_raw_fd())
        }
        originals.sort_unstable();
        originals.dedup();
        let inventory =
            std::fs::File::open("/proc/self/fd").map_err(|_| os_failure("descriptor inventory"))?;
        let audit_fd = inventory.as_raw_fd();
        let mut entries = [0u8; 4096];
        loop {
            let bytes = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    audit_fd,
                    entries.as_mut_ptr(),
                    entries.len(),
                )
            };
            if bytes < 0 {
                return Err(os_failure("descriptor inventory"));
            }
            if bytes == 0 {
                break;
            }
            let mut offset = 0;
            while offset < bytes as usize {
                if bytes as usize - offset < 20 {
                    return Err(failure("descriptor inventory malformed"));
                }
                let size =
                    u16::from_ne_bytes([entries[offset + 16], entries[offset + 17]]) as usize;
                if size < 20 || size > bytes as usize - offset {
                    return Err(failure("descriptor inventory malformed"));
                }
                let name = &entries[offset + 19..offset + size];
                let end = name
                    .iter()
                    .position(|&v| v == 0)
                    .ok_or_else(|| failure("descriptor inventory malformed"))?;
                let name = &name[..end];
                offset += size;
                if name == b"." || name == b".." {
                    continue;
                }
                let fd = std::str::from_utf8(name)
                    .ok()
                    .and_then(|v| v.parse::<i32>().ok())
                    .ok_or_else(|| failure("descriptor inventory malformed"))?;
                if fd == audit_fd {
                    continue;
                }
                if !originals.contains(&fd) {
                    return Err(failure("unknown descriptor before bootstrap"));
                }
                let link = std::fs::read_link(format!("/proc/self/fd/{fd}"))
                    .map_err(|_| os_failure("descriptor inventory link"))?;
                let target = link.to_string_lossy();
                if target.starts_with("anon_inode:")
                    || target == "/proc"
                    || target.starts_with("/proc/")
                    || [
                        "net:[", "pid:[", "user:[", "time:[", "mnt:[", "uts:[", "ipc:[", "cgroup:[",
                    ]
                    .iter()
                    .any(|prefix| target.starts_with(prefix))
                {
                    return Err(failure("protected original descriptor"));
                }
            }
        }
        drop(inventory);
        use std::io::Read;
        let mut maps = Vec::new();
        std::fs::File::open("/proc/self/maps")
            .map_err(|_| os_failure("mapping audit"))?
            .take(262145)
            .read_to_end(&mut maps)
            .map_err(|_| os_failure("mapping audit"))?;
        if maps.len() > 262144 {
            return Err(failure("mapping inventory exceeds bound"));
        }
        let text =
            std::str::from_utf8(&maps).map_err(|_| failure("mapping inventory malformed"))?;
        let mut extent = 0u64;
        let mut count = 0;
        for line in text.lines() {
            count += 1;
            let range = line
                .split_whitespace()
                .next()
                .ok_or_else(|| failure("mapping range"))?;
            let (a, b) = range
                .split_once('-')
                .ok_or_else(|| failure("mapping range"))?;
            let a = u64::from_str_radix(a, 16).map_err(|_| failure("mapping range"))?;
            let b = u64::from_str_radix(b, 16).map_err(|_| failure("mapping range"))?;
            extent = extent
                .checked_add(b.checked_sub(a).ok_or_else(|| failure("mapping range"))?)
                .ok_or_else(|| failure("mapping extent"))?;
        }
        if count > 4096 || extent > 1 << 30 {
            return Err(failure("inherited mapping bound exceeded"));
        }
        drop(maps);
        let domain = ProducerDomain::read()?;
        let mut pair = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                pair.as_mut_ptr(),
            )
        } < 0
        {
            return Err(os_failure("socketpair"));
        }
        let original_e = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let original_l = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let e = normalize(original_e)?;
        let l = normalize(original_l)?;
        let mut close = [-1; 5];
        let mut n = 0;
        for fd in originals.into_iter().chain([e.as_raw_fd()]) {
            if fd != l.as_raw_fd() && !close[..n].contains(&fd) {
                close[n] = fd;
                n += 1
            }
        }
        let parent = std::process::id() as i32;
        let session = (launcher::monotonic() ^ ((parent as u64) << 32)).max(1);
        let boot_deadline = deadline_ns(deadline);
        let pid = unsafe { launcher::raw(libc::SYS_clone, 17, 0, 0, 0, 0, 0) };
        if pid == 0 {
            unsafe { launcher::run(l.as_raw_fd(), close, n, parent, session, boot_deadline) }
        }
        drop(l);
        if pid < 0 {
            return Err(failure("launcher clone failed"));
        }
        let pidfd_flags = 0;
        #[cfg(test)]
        let pidfd_flags = if HOST_PIDFD_FAILURE.load(Ordering::Acquire) {
            1
        } else {
            pidfd_flags
        };
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, pidfd_flags) } as i32;
        let (p, problem) = if raw < 0 {
            (None, Some(os_failure("launcher pidfd_open failed")))
        } else {
            match normalize(unsafe { OwnedFd::from_raw_fd(raw) }) {
                Ok(p) => (Some(p), None),
                Err(e) => (None, Some(e)),
            }
        };
        Ok((e, p, pid as i32, session, domain, n, boot_deadline, problem))
    })();
    let slots_restored = originally_closed.iter().enumerate().all(|(fd, closed)| {
        !closed
            || (unsafe { libc::fcntl(fd as i32, libc::F_GETFD) } < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF))
    });
    if !slots_restored {
        // A failed close/normalization cannot be called a restored standard slot.
        // Keep the mask blocked, poison admission, and retain the construction
        // reservation rather than entering capture with an unknown slot state.
        CONSTRUCTION_UNCERTAIN.store(true, Ordering::Release);
        if let Ok((endpoint, pidfd, pid, _, _, _, _, _)) = prepared {
            let _ = settle_bootstrap(
                BootstrapCustody {
                    endpoint,
                    pidfd,
                    pid,
                },
                deadline,
            );
        }
        let mut error = failure("standard descriptor restoration uncertain; bootstrap poisoned");
        error.cleanup_pending = true;
        return Err(error);
    }
    let restore = mask.restore();
    let (endpoint, pidfd, pid, session, domain, count, boot_deadline, problem) = match prepared {
        Ok(v) => v,
        Err(e) => {
            restore?;
            return Err(e);
        }
    };
    if let Err(mut e) = restore {
        e.cleanup_pending = !settle_bootstrap(
            BootstrapCustody {
                endpoint,
                pidfd,
                pid,
            },
            deadline,
        );
        return Err(e);
    }
    if let Some(mut e) = problem {
        e.cleanup_pending = !settle_bootstrap(
            BootstrapCustody {
                endpoint,
                pidfd,
                pid,
            },
            deadline,
        );
        return Err(e);
    }
    let pidfd = pidfd.expect("validated pidfd construction");
    #[cfg(test)]
    eprintln!(
        "HOST producer observer={} launcher={pid}",
        std::process::id()
    );
    let shared = Arc::new(Shared {
        slot: Mutex::new(Slot {
            command: None,
            reply: None,
            active: false,
            busy: false,
            target_active: false,
            abandon: false,
            shutdown: None,
            receipt: None,
            failure: None,
            next: 0,
        }),
        wake: Condvar::new(),
        sealed: AtomicBool::new(false),
        subscriptions: AtomicUsize::new(0),
        audit_active: AtomicBool::new(false),
        domain,
        session,
        launcher: pid,
        endpoint: endpoint.as_raw_fd(),
        pidfd: pidfd.as_raw_fd(),
        ready: AtomicBool::new(false),
        installation_active: AtomicBool::new(false),
        release_burst: AtomicBool::new(false),
        release_target: AtomicBool::new(false),
        abort_requested: AtomicBool::new(false),
        shutdown_origin: Instant::now(),
        shutdown_stamp: AtomicU64::new(0),
        returned_pending: AtomicBool::new(false),

        #[cfg(test)]
        host_child: Mutex::new(None),
        #[cfg(test)]
        host_disposed: AtomicBool::new(false),
    });
    #[cfg(test)]
    {
        *HOST_BOOT_SHARED.lock().unwrap() = Some(shared.clone());
    }
    // Publication precedes supervisor escape, including failed Ready cleanup.
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).reserved = Some(Arc::downgrade(&shared));
    let owner = shared.clone();
    // The caller retains the resource cell until supervisor spawn succeeds.
    let custody = Arc::new(Mutex::new(Some((endpoint, pidfd))));
    let transfer = custody.clone();
    if std::thread::Builder::new()
        .name("lifecycle-custody".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            let (endpoint, pidfd) = transfer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("one custody transfer");
            supervise_caught(owner, endpoint, pidfd, count, boot_deadline)
        })
        .is_err()
    {
        let (endpoint, pidfd) = custody
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("failed spawn retains custody");
        let settled = settle_bootstrap(
            BootstrapCustody {
                endpoint,
                pidfd: Some(pidfd),
                pid,
            },
            deadline,
        );
        let mut error = failure("supervisor spawn failed");
        error.cleanup_pending = !settled;
        return Err(error);
    }
    let mut s = shared.slot.lock().unwrap_or_else(|e| e.into_inner());
    while !shared.ready.load(Ordering::Acquire) && s.failure.is_none() && Instant::now() < deadline
    {
        let (next, _) = shared
            .wake
            .wait_timeout(s, Duration::from_millis(1))
            .unwrap_or_else(|e| e.into_inner());
        s = next;
    }
    if !shared.ready.load(Ordering::Acquire) {
        let mut e = s
            .failure
            .clone()
            .unwrap_or_else(|| failure("bootstrap Ready deadline"));
        e.cleanup_pending = true;
        drop(s);
        let _ = request_shutdown(&shared, deadline);
        return Err(e);
    }
    drop(s);
    Ok(shared)
}
fn deadline_ns(deadline: Instant) -> u64 {
    launcher::monotonic().saturating_add(
        deadline
            .saturating_duration_since(Instant::now())
            .as_nanos()
            .min(u64::MAX as u128) as u64,
    )
}
fn send_frame(fd: i32, frame: Frame) -> Result<(), ProducerFailure> {
    let b = frame.encode();
    let r = unsafe {
        libc::send(
            fd,
            b.as_ptr().cast(),
            64,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if r != 64 {
        Err(os_failure("producer send failed"))
    } else {
        #[cfg(test)]
        match frame.kind {
            OBSERVED => {
                HOST_OBSERVED_SENT.fetch_add(1, Ordering::AcqRel);
            }
            ABORT => {
                HOST_ABORT_SENT.fetch_add(1, Ordering::AcqRel);
            }
            _ => {}
        }
        Ok(())
    }
}
fn recv_frame(fd: i32) -> Result<Option<Frame>, ProducerFailure> {
    let mut b = [0u8; 65];
    let r = unsafe {
        libc::recv(
            fd,
            b.as_mut_ptr().cast(),
            b.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(os_failure("producer receive failed"));
    }
    Frame::decode(&b[..(r as usize).min(65)])
        .map(Some)
        .ok_or_else(|| failure("producer EOF or malformed frame"))
}
struct RetainedSupervisor {
    _shared: Arc<Shared>,
    _descriptors: Option<(OwnedFd, OwnedFd)>,
}
static RETAINED_SUPERVISOR: Mutex<Option<RetainedSupervisor>> = Mutex::new(None);
fn supervise_caught(
    owner: Arc<Shared>,
    endpoint: OwnedFd,
    pidfd: OwnedFd,
    count: usize,
    boot_deadline: u64,
) {
    let mut descriptors = Some((endpoint, pidfd));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        supervise(owner.clone(), &mut descriptors, count, boot_deadline)
    }));
    if result.is_err() {
        owner.sealed.store(true, Ordering::Release);
        let mut error = failure("supervisor unwound; custody retained");
        error.cleanup_pending = true;
        {
            let mut slot = owner.slot.lock().unwrap_or_else(|e| e.into_inner());
            slot.failure = Some(error.clone());
            if slot.receipt.is_none() {
                slot.receipt = Some(ProducerShutdownReceipt {
                    state: ProducerShutdownState::Unknown,
                    launcher_status: None,
                    failure: Some(error),
                });
            }
        }
        owner.wake.notify_all();
        *RETAINED_SUPERVISOR
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(RetainedSupervisor {
            _shared: owner,
            _descriptors: descriptors,
        });
    }
}
#[cfg(test)]
static HOST_LAUNCHER_WAIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
#[cfg(test)]
static HOST_SUPERVISOR_PANIC: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static HOST_COMMAND_HOLD: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static HOST_OBSERVED_SENT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HOST_ABORT_SENT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HOST_SUPERVISOR_WAIT_HOLD: AtomicBool = AtomicBool::new(false);
fn supervise(
    shared: Arc<Shared>,
    descriptors: &mut Option<(OwnedFd, OwnedFd)>,
    count: usize,
    boot_deadline: u64,
) {
    let fd = descriptors
        .as_ref()
        .expect("supervisor owns endpoint")
        .0
        .as_raw_fd();
    let launcher_fd = descriptors
        .as_ref()
        .expect("supervisor owns pidfd")
        .1
        .as_raw_fd();
    let mut handshake = 0;
    let mut current: Option<Frame> = None;
    let mut child = false;
    let mut possible_child = false;
    let mut aborted = false;
    let mut shutdown_sent = false;
    let mut done = false;
    let mut poisoned = false;
    let mut waited: Option<(bool, i32)> = None;
    let mut bootstrap_kill = false;
    let mut child_pid = 0u64;
    let mut last_completion: Option<Frame> = None;
    let mut launcher_checked = false;
    let mut launcher_wake = false;
    loop {
        #[cfg(test)]
        if HOST_SUPERVISOR_PANIC.swap(false, Ordering::AcqRel) {
            panic!("HOST supervisor unwind fault");
        }
        let now = Instant::now();
        {
            let mut s = shared.slot.lock().unwrap_or_else(|e| e.into_inner());
            reconcile(&shared, &mut s);
            let command = {
                #[cfg(test)]
                {
                    if HOST_COMMAND_HOLD.load(Ordering::Acquire) {
                        None
                    } else {
                        s.command.take()
                    }
                }
                #[cfg(not(test))]
                {
                    s.command.take()
                }
            };
            // Revocation wins over queued evidence. A command already sent
            // before the seal may settle physically, but a revoked lease cannot
            // consume that settlement as new lifecycle evidence (see poll).
            if shared.sealed.load(Ordering::Acquire)
                || shared.abort_requested.load(Ordering::Acquire)
            {
                s.abandon = true;
            }
            if let Some(f) = current {
                if f.kind == SPAWN && !aborted && (s.abandon || launcher::monotonic() >= f.deadline)
                {
                    let mut a = f;
                    a.kind = ABORT;
                    a.arg0 = 1;
                    a.arg1 = 0;
                    if send_frame(fd, a).is_ok() {
                        aborted = true
                    }
                }
            }
            if let Some(f) = command {
                let revoked = s.abandon
                    || (f.kind == OBSERVED && aborted)
                    || shared.sealed.load(Ordering::Acquire)
                    || shared.abort_requested.load(Ordering::Acquire)
                    || launcher::monotonic() >= f.deadline;
                if revoked {
                    // Only an undispatched SPAWN with no current request can
                    // release busy here. Dispatched children still require the
                    // launcher's matching positive-wait receipt below.
                    if f.kind == SPAWN && current.is_none() {
                        s.busy = false;
                    }
                } else if current.is_some() && f.kind == SPAWN {
                    s.failure = Some(failure("overlapping producer request"));
                    poisoned = true;
                } else {
                    if f.kind == SPAWN {
                        possible_child = true;
                    }
                    if send_frame(fd, f).is_err() {
                        s.failure = Some(failure("producer command delivery"));
                        poisoned = true;
                    }
                    if f.kind == SPAWN {
                        current = Some(f);
                        child = false;
                        aborted = false;
                    }
                }
            }
            // Launcher settlement does not release the observer's descriptor
            // custody. Send after actual helper settlement, while the original
            // shutdown deadline is still usable, even if a lease retains that
            // custody. Disposal below still waits for both lease releases.
            if shared.ready.load(Ordering::Acquire)
                && s.shutdown.is_some()
                && current.is_none()
                && !shutdown_sent
                && !poisoned
            {
                s.next = s.next.saturating_add(1);
                let f = Frame {
                    kind: SHUTDOWN,
                    session: shared.session,
                    request: s.next,
                    deadline: deadline_ns(s.shutdown.unwrap()),
                    floor: launcher::monotonic(),
                    arg0: 0,
                    arg1: 0,
                };
                if send_frame(fd, f).is_ok() {
                    shutdown_sent = true;
                    current = Some(f)
                } else {
                    poisoned = true
                }
            }
            if handshake < 2 && launcher::monotonic() >= boot_deadline {
                s.failure = Some(failure("launcher handshake expired"));
                poisoned = true;
            }
            if poisoned || (s.shutdown.is_some_and(|d| now >= d) && !s.active) {
                shared.sealed.store(true, Ordering::Release);
            }
            shared.wake.notify_all();
        }
        match recv_frame(fd) {
            Ok(Some(f)) => {
                let mut s = shared.slot.lock().unwrap_or_else(|e| e.into_inner());
                reconcile(&shared, &mut s);
                if last_completion == Some(f) {
                    continue;
                }
                let valid = f.session == shared.session
                    && if handshake < 2 {
                        f.request == 0
                            && f.deadline == boot_deadline
                            && f.floor == 0
                            && if handshake == 0 {
                                f.kind == HELLO
                                    && f.arg0 == shared.launcher as u64
                                    && f.arg1 == std::process::id() as u64
                            } else {
                                f.kind == READY && f.arg0 == count as u64 && f.arg1 == 1
                            }
                    } else {
                        current.is_some_and(|r| {
                            r.request == f.request
                                && r.deadline == f.deadline
                                && match f.kind {
                                    CHILD => {
                                        !child
                                            && r.kind == SPAWN
                                            && f.arg0 > 0
                                            && f.arg0 <= i32::MAX as u64
                                            && f.arg1 == r.arg0
                                            && f.floor >= r.floor
                                    }
                                    REAPED => {
                                        child
                                            && f.arg0 == child_pid
                                            && f.arg0 > 0
                                            && f.arg0 <= i32::MAX as u64
                                            && f.arg1 <= u32::MAX as u64
                                            && f.floor == r.floor
                                    }
                                    FAILED => {
                                        r.kind == SPAWN
                                            && !child
                                            && f.floor == r.floor
                                            && f.arg0 == 1
                                            && f.arg1 <= i32::MAX as u64
                                    }
                                    DONE => {
                                        r.kind == SHUTDOWN
                                            && f.floor == r.floor
                                            && f.arg0 == 0
                                            && f.arg1 == 0
                                    }
                                    _ => false,
                                }
                        })
                    };
                if !valid {
                    s.failure = Some(failure("producer response binding"));
                    poisoned = true;
                    shared.sealed.store(true, Ordering::Release);
                } else if handshake < 2 {
                    handshake += 1;
                    if handshake == 2 {
                        shared.ready.store(true, Ordering::Release);
                    }
                } else {
                    match f.kind {
                        CHILD => {
                            #[cfg(test)]
                            eprintln!(
                                "HOST helper launcher={} request={} pid={} cpu={} birth={}",
                                shared.launcher, f.request, f.arg0, f.arg1, f.floor
                            );
                            child = true;
                            child_pid = f.arg0;
                            s.reply = Some(f);
                            #[cfg(test)]
                            {
                                *shared.host_child.lock().unwrap() = Some(f);
                            }
                        }
                        REAPED | FAILED => {
                            #[cfg(test)]
                            eprintln!(
                                "HOST helper reply={} launcher={} request={} pid-or-class={} status-or-errno={}",
                                f.kind, shared.launcher, f.request, f.arg0, f.arg1
                            );
                            last_completion = Some(f);
                            current = None;
                            child = false;
                            s.busy = false;
                            possible_child = false;
                            s.reply = Some(f)
                        }
                        DONE => {
                            done = true;
                            current = None
                        }
                        _ => {}
                    }
                }
                shared.wake.notify_all();
            }
            Ok(None) => {}
            Err(e) => {
                if !done {
                    let mut s = shared.slot.lock().unwrap_or_else(|e| e.into_inner());
                    reconcile(&shared, &mut s);
                    s.failure.get_or_insert(e);
                    poisoned = true;
                    shared.sealed.store(true, Ordering::Release);
                    shared.wake.notify_all();
                }
            }
        }
        // Only the supervisor consumes this exact owned launcher, never foreign children.
        if handshake < 2 && poisoned && !bootstrap_kill {
            let r = unsafe { libc::kill(shared.launcher, libc::SIGKILL) };
            bootstrap_kill = r == 0;
        }
        if done || poisoned || shared.sealed.load(Ordering::Acquire) {
            let may_wait = {
                #[cfg(test)]
                {
                    !HOST_SUPERVISOR_WAIT_HOLD.load(Ordering::Acquire)
                }
                #[cfg(not(test))]
                {
                    true
                }
            };
            if waited.is_none() && may_wait && (!launcher_checked || launcher_wake) {
                launcher_checked = true;
                launcher_wake = false;
                let mut status = 0;
                let r = unsafe { libc::waitpid(shared.launcher, &mut status, libc::WNOHANG) };
                if r == shared.launcher {
                    #[cfg(test)]
                    eprintln!(
                        "HOST launcher positive-wait pid={} raw-status={status}",
                        shared.launcher
                    );
                    #[cfg(test)]
                    HOST_LAUNCHER_WAIT.store(status, Ordering::Release);
                    waited = Some((true, status))
                } else if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    waited = Some((false, 0))
                }
            }
            if let Some((positive, status)) = waited {
                let mut s = shared.slot.lock().unwrap_or_else(|e| e.into_inner());
                reconcile(&shared, &mut s);
                if s.active || s.target_active || shared.audit_active.load(Ordering::Acquire) {
                    drop(
                        shared
                            .wake
                            .wait_timeout(s, Duration::from_millis(1))
                            .unwrap_or_else(|e| e.into_inner()),
                    );
                    continue;
                }
                if !positive || child || possible_child {
                    if s.receipt.is_none() {
                        s.receipt = Some(ProducerShutdownReceipt {
                            state: ProducerShutdownState::Unknown,
                            launcher_status: positive.then_some(status),
                            failure: Some(failure(
                                "launcher or helper wait ownership lost; custody retained",
                            )),
                        });
                    }
                    shared.wake.notify_all();
                    drop(s);
                    // No helper can be reaped or signalled by this observer. Keep
                    // the fixed charged custody slot without a repeated wait loop.
                    let _custody = descriptors.take().expect("retained supervisor descriptors");
                    loop {
                        std::thread::park();
                    }
                }
                let (endpoint, pidfd) = descriptors.take().expect("one normal descriptor disposal");
                let endpoint_closed = close_owned(endpoint);
                let pidfd_closed = close_owned(pidfd);
                #[cfg(test)]
                eprintln!(
                    "HOST producer disposal launcher={} endpoint-closed={endpoint_closed} pidfd-closed={pidfd_closed}",
                    shared.launcher
                );
                #[cfg(test)]
                if positive && !child && endpoint_closed && pidfd_closed {
                    shared.host_disposed.store(true, Ordering::Release);
                }
                let complete = done
                    && positive
                    && status == 0
                    && !child
                    && endpoint_closed
                    && pidfd_closed
                    && !poisoned;
                let expired = s.shutdown.is_some_and(|d| Instant::now() > d);
                if s.receipt.is_none() {
                    s.receipt = Some(ProducerShutdownReceipt {
                        state: if expired {
                            ProducerShutdownState::Pending
                        } else if complete {
                            ProducerShutdownState::Complete
                        } else {
                            ProducerShutdownState::Unknown
                        },
                        launcher_status: positive.then_some(status),
                        failure: (!complete || expired).then(|| {
                            failure("launcher disposal not proven complete within deadline")
                        }),
                    });
                }
                shared.wake.notify_all();
                return;
            }
        }
        let passive = poisoned || current.is_some_and(|f| launcher::monotonic() >= f.deadline);
        let mut p = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: launcher_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        unsafe {
            libc::poll(p.as_mut_ptr(), 2, if passive { -1 } else { 1 });
        }
        launcher_wake |= p[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
    }
}
fn close_owned(fd: OwnedFd) -> bool {
    use std::os::fd::IntoRawFd;
    let raw = fd.into_raw_fd();
    unsafe { libc::close(raw) == 0 }
}
#[derive(Clone, Copy)]
pub(crate) enum BurstPhase {
    Initial = 1,
    Terminal = 2,
}
#[derive(Clone, Copy)]
pub(crate) enum WitnessKind {
    Fork = 1,
    Exit = 2,
}
#[derive(Clone, Copy)]
pub(crate) enum AbortReason {
    Abandoned = 1,
}
pub(crate) enum ProducerReply {
    Child {
        pid: u32,
        cpu: u32,
        birth_floor_ns: u64,
    },
    Reaped {
        pid: u32,
        status: i32,
    },
    Failed(ProducerFailure),
}
pub(crate) struct BurstLease {
    shared: Arc<Shared>,
    phase: BurstPhase,
    deadline: Instant,
    floor: u64,
    request: Option<Frame>,
}
pub(crate) struct ProducerSubscription(ProducerHandle);
impl Drop for ProducerSubscription {
    fn drop(&mut self) {
        self.0.0.subscriptions.fetch_sub(1, Ordering::AcqRel);
    }
}
impl ProducerHandle {
    pub(crate) fn setup_admission(&self) -> Result<(), ProducerFailure> {
        let mut s = self.0.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.0, &mut s);
        if s.active
            || s.busy
            || s.target_active
            || self.0.audit_active.load(Ordering::Acquire)
            || self.0.sealed.load(Ordering::Acquire)
        {
            return Err(failure("previous producer custody is unsettled"));
        }
        Ok(())
    }
    pub(crate) fn target_lease(&self) -> Result<ProducerTargetLease, ProducerFailure> {
        let mut s = self.0.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.0, &mut s);
        if s.active
            || s.busy
            || s.target_active
            || self.0.audit_active.load(Ordering::Acquire)
            || self.0.sealed.load(Ordering::Acquire)
        {
            return Err(failure("target alias admission refused"));
        }
        s.target_active = true;
        Ok(ProducerTargetLease {
            shared: self.0.clone(),
            inherited: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn host_child(&self) -> Option<(u32, u32, u64)> {
        self.0
            .host_child
            .lock()
            .unwrap()
            .map(|f| (f.arg0 as u32, f.arg1 as u32, f.floor))
    }
    pub(crate) fn install_for_call(&self) -> Result<InstalledProducerGuard, ProducerFailure> {
        if self.0.sealed.load(Ordering::Acquire) {
            return Err(failure("producer sealed"));
        }
        let mut g = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = g
            .installed
            .as_ref()
            .and_then(Weak::upgrade)
            .filter(|s| s.installation_active.load(Ordering::Acquire))
        {
            if Arc::ptr_eq(&current, &self.0) {
                return Ok(InstalledProducerGuard {
                    shared: self.0.clone(),
                    unregister: false,
                });
            }
            return Err(failure("another producer installed"));
        }
        g.installed = Some(Arc::downgrade(&self.0));
        self.0.installation_active.store(true, Ordering::Release);
        Ok(InstalledProducerGuard {
            shared: self.0.clone(),
            unregister: true,
        })
    }
    pub(crate) fn child_close_set(&self) -> Result<ProducerChildCloseSet, ProducerFailure> {
        if self.0.sealed.load(Ordering::Acquire) {
            return Err(failure("producer sealed"));
        }
        Ok(ProducerChildCloseSet([self.0.endpoint, self.0.pidfd]))
    }
    pub(crate) fn launcher_pid(&self) -> u32 {
        self.0.launcher as u32
    }
    pub(crate) fn domain_audit(
        &self,
        deadline: Instant,
    ) -> Result<ProducerDomainAudit, ProducerFailure> {
        let mut s = self.0.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.0, &mut s);
        if s.target_active
            || self.0.audit_active.load(Ordering::Acquire)
            || self.0.sealed.load(Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Err(failure("producer domain audit admission refused"));
        }
        self.0.audit_active.store(true, Ordering::Release);
        let audit = ProducerDomainAudit(self.0.clone());
        drop(s);
        if ProducerDomain::read()? != self.0.domain {
            return Err(failure("producer domain changed"));
        }
        if Instant::now() >= deadline || self.0.sealed.load(Ordering::Acquire) {
            return Err(failure("producer domain audit expired or revoked"));
        }
        Ok(audit)
    }
    pub(crate) fn subscribe(&self) -> Result<ProducerSubscription, ProducerFailure> {
        if self.0.sealed.load(Ordering::Acquire) {
            return Err(failure("producer sealed"));
        }
        self.0
            .subscriptions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .map_err(|_| failure("four subscriptions already reserved"))?;
        Ok(ProducerSubscription(self.clone()))
    }
    pub(crate) fn begin(
        &self,
        phase: BurstPhase,
        deadline: Instant,
        floor: u64,
    ) -> Result<BurstLease, ProducerFailure> {
        let mut s = self.0.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.0, &mut s);
        if s.active
            || s.busy
            || s.target_active
            || s.command.is_some()
            || self.0.audit_active.load(Ordering::Acquire)
            || self.0.sealed.load(Ordering::Acquire)
            || deadline <= Instant::now()
            || floor == 0
        {
            return Err(failure("burst admission refused"));
        }
        if let Some(e) = &s.failure {
            return Err(e.clone());
        }
        s.active = true;
        s.abandon = false;
        s.reply = None;
        let lease = BurstLease {
            shared: self.0.clone(),
            phase,
            deadline,
            floor,
            request: None,
        };
        drop(s);
        let _audit = self.domain_audit(deadline)?;
        Ok(lease)
    }
}
impl BurstLease {
    pub(crate) fn spawn(&mut self, cpu: u32) -> Result<(), ProducerFailure> {
        if self.request.is_some() || cpu >= 1024 || Instant::now() >= self.deadline {
            return Err(failure("burst spawn refused"));
        }
        let _audit = ProducerHandle(self.shared.clone()).domain_audit(self.deadline)?;
        let mut s = self.shared.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.shared, &mut s);
        if s.command.is_some()
            || s.abandon
            || self.shared.sealed.load(Ordering::Acquire)
            || self.shared.abort_requested.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Err(failure("producer revoked, expired or busy"));
        }
        s.next = s
            .next
            .checked_add(1)
            .ok_or_else(|| failure("producer request exhausted"))?;
        let f = Frame {
            kind: SPAWN,
            session: self.shared.session,
            request: s.next,
            deadline: deadline_ns(self.deadline),
            floor: launcher::monotonic().max(self.floor),
            arg0: cpu as u64,
            arg1: self.phase as u64,
        };
        s.busy = true;
        s.command = Some(f);
        self.request = Some(f);
        self.shared.wake.notify_all();
        Ok(())
    }
    pub(crate) fn observed(&self, cpu: u32, kind: WitnessKind) -> Result<(), ProducerFailure> {
        let mut f = self.request.ok_or_else(|| failure("no child request"))?;
        if f.arg0 != cpu as u64 {
            return Err(failure("received CPU differs"));
        }
        f.kind = OBSERVED;
        f.arg0 = cpu as u64;
        f.arg1 = kind as u64;
        self.publish(f)
    }
    fn publish(&self, f: Frame) -> Result<(), ProducerFailure> {
        let mut s = self.shared.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.shared, &mut s);
        if s.abandon
            || self.shared.sealed.load(Ordering::Acquire)
            || self.shared.abort_requested.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Err(failure("burst revoked or expired"));
        }
        if s.command.is_some() {
            return Err(failure("command slot occupied"));
        }
        s.command = Some(f);
        self.shared.wake.notify_all();
        Ok(())
    }
    pub(crate) fn abort(&self, _reason: AbortReason) -> Result<(), ProducerFailure> {
        self.shared.abort_requested.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        Ok(())
    }
    pub(crate) fn poll(&mut self) -> Result<Option<ProducerReply>, ProducerFailure> {
        let mut s = self.shared.slot.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(&self.shared, &mut s);
        if s.abandon
            || self.shared.sealed.load(Ordering::Acquire)
            || self.shared.abort_requested.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            // Physical REAPED custody is reconciled by the supervisor even
            // when the revoked consumer is no longer allowed to use it.
            return Err(failure("burst revoked or expired"));
        }
        if let Some(e) = &s.failure {
            return Err(e.clone());
        }
        let Some(f) = s.reply.take() else {
            return Ok(None);
        };
        if self.request.is_none_or(|r| r.request != f.request) {
            return Err(failure("reply request differs"));
        }
        Ok(Some(match f.kind {
            CHILD => ProducerReply::Child {
                pid: f.arg0 as u32,
                cpu: f.arg1 as u32,
                birth_floor_ns: f.floor,
            },
            REAPED => {
                self.request = None;
                ProducerReply::Reaped {
                    pid: f.arg0 as u32,
                    status: f.arg1 as u32 as i32,
                }
            }
            FAILED => {
                self.request = None;
                ProducerReply::Failed(ProducerFailure {
                    reason: "launcher could not create lane",
                    errno: Some(f.arg1 as i32),
                    cleanup_pending: false,
                })
            }
            _ => return Err(failure("unexpected producer reply")),
        }))
    }
}
impl Drop for BurstLease {
    fn drop(&mut self) {
        if self.request.is_some() {
            self.shared.abort_requested.store(true, Ordering::Release);
        }
        self.shared.release_burst.store(true, Ordering::Release);
        self.shared.wake.notify_all();
    }
}
#[cfg(test)]
pub(crate) mod tests;
