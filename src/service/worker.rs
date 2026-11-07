//! SPDX-License-Identifier: GPL-3.0-or-later
//! §7.2 bounded cancellation on EVERY blocking path: the
//! `Control<T>`/`run_under_control` pattern (abandonment flag stored
//! by the waiter; a started worker keeps running detached and owns
//! its captures; the waiter's abandonment path takes only the
//! registry short critical section — never a worker-dependent wait
//! — and performs no blocking syscall), per-destination epochs +
//! fencing, the tap receipt protocol, and the diagnostics worker.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::service::envelope::OpOutcome;
use crate::service::signals::{Signal, SignalFd};

/// Destination classes (§7.2). P-effects (`EvidenceLink`, `OwnTmp`,
/// `TapWrite`) are the abandonment allowlist; the fenced classes
/// re-check flag AND epoch immediately before their ONE destination
/// mutation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DestClass {
    EvidenceLink,
    OwnTmp,
    TapWrite,
    StateMut,
    Delete,
    Rotate,
}

impl DestClass {
    pub fn fenced(&self) -> bool {
        matches!(
            self,
            DestClass::StateMut | DestClass::Delete | DestClass::Rotate
        )
    }
}

/// A fenced destination: class + identity key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination {
    pub class: DestClass,
    pub key: String,
}

/// Control outcome (the waiter-observed disposition).
#[derive(Debug)]
pub enum Control<T> {
    Done(T),
    Cancelled,
    Expired,
    /// Worker-creation failure (fail-closed, §7.2 F-015).
    SpawnFailed,
}

/// Worker-visible gate: the abandonment flag + the destination
/// epoch at spawn. Fenced workers re-check BOTH immediately before
/// their ONE destination mutation.
#[derive(Debug, Clone)]
pub struct Gate {
    flag: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    epoch_at_spawn: u64,
    fenced: bool,
}

impl Gate {
    /// True ⟹ the worker MUST NOT INITIATE a destination mutation
    /// (F1–F6); it performs only P2+P4 (cleanup own tmp, exit).
    pub fn abandoned(&self) -> bool {
        if self.flag.load(Ordering::Acquire) {
            return true;
        }
        self.fenced && self.epoch.load(Ordering::Acquire) != self.epoch_at_spawn
    }
}

/// Tap completion receipt (§7.2): stored worker-side INTO the
/// worker's own registry slot at exit through the same `on_exit` as
/// its unregister (dispatch-known record + destination identity —
/// no reread needed, FIFO-capable).
#[derive(Debug, Clone)]
pub struct TapReceipt {
    pub op_id: u64,
    pub state: TapReceiptState,
    pub kind: String,
    pub seq: Option<u64>,
    pub span: Option<(u64, u64)>,
    pub record_bytes: u64,
    pub dest_path: String,
    pub dest_dev: u64,
    pub dest_ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapReceiptState {
    Complete { bytes: u64 },
    Partial { bytes: u64 },
    Failed { errno: i32 },
}

struct Slot {
    worker: u64,
    live: bool,
    result: Option<Box<dyn Any + Send>>,
    receipt: Option<TapReceipt>,
}

fn registry() -> &'static Mutex<HashMap<Destination, Slot>> {
    static REGISTRY: OnceLock<Mutex<HashMap<Destination, Slot>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_WORKER: AtomicU64 = AtomicU64::new(1);

/// Signal consumption DURING a worker wait (R1 finding 3): the
/// waiter drains signalfd every poll quantum so a second signal
/// updates the latches + cancel promptly instead of sitting
/// unread until the coordinator returns to signal consumption.
/// All shared refs (disjoint `Run` fields at the call sites).
pub struct WaitPoll<'a> {
    /// The signalfd to drain (non-blocking, consuming).
    pub signals: &'a SignalFd,
    /// This wait's cancel (the run cancel — or a fresh flag where
    /// the op must survive the first stop, e.g. in-run spills).
    pub cancel: &'a AtomicBool,
    /// First-stop latch (set on the first observed `Term`).
    pub latched: &'a AtomicBool,
    /// Second-observed-`Term` latch (C4 semantics — the immediate
    /// stop trigger).
    pub double: &'a AtomicBool,
    /// SIGHUP flag (consumed at the next boundary).
    pub reload: &'a AtomicBool,
}

impl<'a> WaitPoll<'a> {
    pub fn new(
        signals: &'a SignalFd,
        cancel: &'a AtomicBool,
        latched: &'a AtomicBool,
        double: &'a AtomicBool,
        reload: &'a AtomicBool,
    ) -> Self {
        Self {
            signals,
            cancel,
            latched,
            double,
            reload,
        }
    }

    /// Drain + apply one batch. A first observed `Term` latches
    /// ONLY (the op runs on — the loop cuts after the boundary);
    /// the second observed `Term` latches double AND stores cancel
    /// (this wait — and every later close wait — Cancels promptly,
    /// expediting the close instead of expiring blind).
    pub fn poll(&self) {
        for sig in self.signals.drain() {
            match sig {
                Signal::Term => {
                    if self.latched.swap(true, Ordering::SeqCst) {
                        self.double.store(true, Ordering::SeqCst);
                        self.cancel.store(true, Ordering::SeqCst);
                    }
                }
                Signal::Hup => {
                    self.reload.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    /// True once the second stop is observed (prompt-exit checks
    /// outside worker waits).
    pub fn doubled(&self) -> bool {
        self.double.load(Ordering::SeqCst)
    }
}

/// Run one blocking op on a control worker under `budget` +
/// `cancel`. At most one live worker per destination (a successor
/// while the prior is registered is refused fail-closed → `Expired`,
/// retried at the next boundary — never concurrent).
///
/// The waiter's abandonment path stores the flag + bumps the epoch
/// and takes only the registry short critical section (all holders
/// are microsecond HashMap ops — never worker progress); the
/// detached worker reconciles at exit via worker-side `on_exit`.
///
/// `wait_poll` (when present) drains signalfd every poll quantum
/// (R1 finding 3) so waits observe the second signal.
pub fn run_under_control<T, F>(
    dest: Destination,
    budget: Duration,
    cancel: &AtomicBool,
    op: F,
    wait_poll: Option<&WaitPoll>,
) -> Control<T>
where
    T: Send + 'static,
    F: FnOnce(Gate) -> WorkerOut<T> + Send + 'static,
{
    // Register (single map op; never on the abandonment path).
    // Refused while ANY slot exists for the destination — live or
    // finished-unconsumed. This structurally enforces
    // reconcile-before-next-use: an abandoned op's receipt (or its
    // Lost absence) must be consumed via `view_slot` before a
    // successor registers; a successor can never destroy an
    // unreconciled receipt.
    let worker = NEXT_WORKER.fetch_add(1, Ordering::Relaxed);
    let (flag, epoch, epoch_at_spawn) = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if reg.contains_key(&dest) {
            // Successor refused while the prior op is still
            // registered (fail-closed Expired + accounting).
            return Control::Expired;
        }
        let flag = Arc::new(AtomicBool::new(false));
        let epoch = Arc::new(AtomicU64::new(0));
        reg.insert(
            dest.clone(),
            Slot {
                worker,
                live: true,
                result: None,
                receipt: None,
            },
        );
        (flag, epoch, 0)
    };
    let gate = Gate {
        flag: flag.clone(),
        epoch: epoch.clone(),
        epoch_at_spawn,
        fenced: dest.class.fenced(),
    };
    let dest_key = dest.clone();
    let exit_flag = flag.clone();
    let spawn = std::thread::Builder::new()
        .name(format!("sixb-{}", short_dest(&dest_key)))
        .spawn(move || {
            // Panics need no special rule: `on_exit` below still
            // runs and the no-receipt + unregistered row catches
            // them (Lost).
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op(gate)));
            let (value, receipt) = match out {
                Ok(WorkerOut { value, receipt }) => (Some(value), receipt),
                Err(_) => (None, None),
            };
            // Worker-side `on_exit`: store receipt + result,
            // unregister — but ONLY when the slot is still this
            // worker's (a successor may have registered since).
            // R3 Gate 3 F2: when the waiter abandoned (flag set —
            // checked under this lock, so the waiter's
            // abandon-or-consume and this exit serialize), the
            // result is dropped unread (no consumer can read a
            // result post-abandonment — `view_slot` exposes
            // receipts only) and the slot unregisters unless a
            // receipt needs reconciling (nonce destinations have no
            // successor to reconcile — retention would accumulate
            // unboundedly across closes).
            // R4 finding 2: the unread result drops OUTSIDE the
            // registry lock (production values own
            // `OpenTap{File}` — destructor syscalls inside the
            // critical section would stall abandonment, which takes
            // the same mutex with no deadline). Only HashMap ops +
            // small POD moves run under the lock (slot/receipt
            // drops are allocator-only — no `Drop` impls, no
            // syscalls); no holder ever waits on worker progress.
            let deferred: Option<T> = {
                let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
                let mut deferred = None;
                if let Some(slot) = reg.get_mut(&dest_key) {
                    if slot.worker == worker {
                        if exit_flag.load(Ordering::Acquire) {
                            deferred = value;
                            match receipt {
                                Some(r) => {
                                    slot.live = false;
                                    slot.receipt = Some(r);
                                }
                                None => {
                                    reg.remove(&dest_key);
                                }
                            }
                        } else {
                            slot.live = false;
                            if let Some(v) = value {
                                slot.result = Some(Box::new(v));
                            }
                            slot.receipt = receipt;
                        }
                    }
                }
                deferred
            };
            drop(deferred);
        });
    if spawn.is_err() {
        // Worker-creation failure: Expired immediately, fail-closed.
        // (Unregister: no worker will ever exit to do it.)
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.remove(&dest);
        return Control::SpawnFailed;
    }
    let deadline = Instant::now() + budget;
    loop {
        // Completion check (single map op): only this worker's slot
        // completes this waiter (a successor's slot never does).
        // The boxed value unboxes OUTSIDE the lock (R4 finding 2 —
        // value destruction never runs in the critical section, so
        // a concurrent abandonment never waits on it).
        let polled: Option<Option<Box<dyn Any + Send>>> = {
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            match reg.get_mut(&dest) {
                Some(slot) if slot.worker == worker && !slot.live => {
                    let result = slot.result.take();
                    reg.remove(&dest);
                    Some(result)
                }
                Some(slot) if slot.worker != worker => {
                    // A successor registered: this waiter lost its
                    // slot (only via another driver on the same
                    // destination — the coordinator never does
                    // this in-run). Fail closed.
                    let _ = slot;
                    return Control::Expired;
                }
                _ => None,
            }
        };
        if let Some(result) = polled {
            match result.and_then(|b| b.downcast::<T>().ok()).map(|b| *b) {
                Some(v) => return Control::Done(v),
                None => return Control::Expired,
            }
        }
        // Consume signals BEFORE the cancel check (a second stop
        // observed here Cancels this wait within one quantum).
        if let Some(poll) = wait_poll {
            poll.poll();
        }
        if cancel.load(Ordering::Relaxed) {
            // Abandonment path: flag + epoch, then the registry
            // short critical section (never worker-dependent), NO
            // blocking syscall (a consumed raced-in result leaves
            // for the deferred reaper — never dropped here).
            flag.store(true, Ordering::Release);
            epoch.fetch_add(1, Ordering::AcqRel);
            consume_if_finished(&dest, worker);
            return Control::Cancelled;
        }
        if Instant::now() >= deadline {
            flag.store(true, Ordering::Release);
            epoch.fetch_add(1, Ordering::AcqRel);
            consume_if_finished(&dest, worker);
            return Control::Expired;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Abandonment-path consume (R3 Gate 3 F2): a worker that finished
/// between the waiter's last completion check and the abandonment
/// stores its result just as the waiter leaves — consume the
/// finished slot here (the disposition stays Expired/Cancelled —
/// the deadline/cancel fired first) so no race retains a result.
/// Receiptless slots unregister; receipt-bearing slots drop their
/// (unreadable) result but stay for the reconciler. Short critical
/// section only (no worker progress needed): the consumed result
/// leaves for the deferred reaper (R5 finding 2 — the waiter never
/// waits on destructor progress, its own or a foreign worker's;
/// dropping here would run a raced-in `OpenTap{File}` close on the
/// abandonment path).
fn consume_if_finished(dest: &Destination, worker: u64) {
    let deferred: Option<Box<dyn Any + Send>> = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let finished = matches!(
            reg.get(dest),
            Some(slot) if slot.worker == worker && !slot.live
        );
        if !finished {
            None
        } else if reg.get(dest).is_some_and(|slot| slot.receipt.is_none()) {
            reg.remove(dest).and_then(|slot| slot.result)
        } else {
            reg.get_mut(dest).and_then(|slot| slot.result.take())
        }
    };
    if let Some(boxed) = deferred {
        deferred_drop(boxed);
    }
}

/// Deferred result disposal (R5 finding 2): the abandoning waiter
/// hands a consumed raced-in result here instead of dropping it —
/// the value's destructor (production values own `OpenTap{File}`,
/// whose close is a blocking syscall past budget) runs on a
/// dedicated detached reaper thread, never on the abandonment
/// path. The waiter performs only a non-blocking channel send
/// (allocator-only, never destructor progress, never a blocking
/// syscall), so the frozen "abandonment performs no blocking
/// syscall and reclaims nothing" rule (D-record:1524 — a rule
/// about the waiter's path: no join, no result drop, return
/// within budget whatever the worker/destructor does) holds:
/// consumption is unchanged (the registry slot unregisters or
/// takes exactly as before — no retained results, the R3-F2 race
/// stays consumed) while reclamation moves off-path. If the
/// reaper is unavailable (thread-spawn failure), the value is
/// leaked rather than dropped — bounded abandonment wins over
/// reclamation, and leaked memory is unreachable (never a
/// retained registry result).
fn deferred_drop(deferred: Box<dyn Any + Send>) {
    if let Err(failed) = reaper_tx().send(deferred) {
        std::mem::forget(failed.0);
    }
}

/// The reaper channel (spawned once, lazily, on first deferred
/// disposal; detached — process exit reaps it with the workers).
fn reaper_tx() -> &'static std::sync::mpsc::Sender<Box<dyn Any + Send>> {
    static REAPER: OnceLock<std::sync::mpsc::Sender<Box<dyn Any + Send>>> = OnceLock::new();
    reaper_tx_in(&REAPER)
}

/// RED-gated init (R6-1(i)): the same lazy init against an
/// explicit lock so the first-use schedule is deterministic at
/// the helper level (a fresh lock = a fresh process).
fn reaper_tx_in(
    lock: &OnceLock<std::sync::mpsc::Sender<Box<dyn Any + Send>>>,
) -> &std::sync::mpsc::Sender<Box<dyn Any + Send>> {
    lock.get_or_init(|| {
        #[cfg(test)]
        red_setup_gate();
        let (tx, rx) = std::sync::mpsc::channel::<Box<dyn Any + Send>>();
        // On spawn failure the closure (owning `rx`) drops, so every
        // send fails and `deferred_drop` leaks — bounded, never
        // blocking.
        let _ = std::thread::Builder::new()
            .name("sixb-reaper".to_string())
            .spawn(move || {
                for deferred in rx {
                    drop(deferred);
                }
            });
        tx
    })
}

/// RED discriminator gate (R6-1(i), tests only): while armed,
/// first-use reaper setup blocks — the direct gate on the setup
/// point, no libc fault injection.
#[cfg(test)]
static RED_SETUP_ARMED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static RED_SETUP_GATE: OnceLock<(
    std::sync::mpsc::Sender<()>,
    Mutex<std::sync::mpsc::Receiver<()>>,
)> = OnceLock::new();
#[cfg(test)]
fn red_setup_gate() {
    if RED_SETUP_ARMED.load(Ordering::SeqCst) {
        let gate = RED_SETUP_GATE.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            (tx, Mutex::new(rx))
        });
        let _ = gate
            .1
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_timeout(Duration::from_secs(30));
    }
}
#[cfg(test)]
fn red_setup_release() {
    RED_SETUP_ARMED.store(false, Ordering::SeqCst);
    if let Some(gate) = RED_SETUP_GATE.get() {
        let _ = gate.0.send(());
    }
}

/// Worker output: value + optional tap receipt (stored into the
/// worker's own slot at exit).
pub struct WorkerOut<T> {
    pub value: T,
    pub receipt: Option<TapReceipt>,
}

impl<T> WorkerOut<T> {
    pub fn value(value: T) -> Self {
        Self {
            value,
            receipt: None,
        }
    }
}

fn short_dest(dest: &Destination) -> String {
    let class = match dest.class {
        DestClass::EvidenceLink => "link",
        DestClass::OwnTmp => "tmp",
        DestClass::TapWrite => "tap",
        DestClass::StateMut => "state",
        DestClass::Delete => "del",
        DestClass::Rotate => "rot",
    };
    format!("{class}-{}", &dest.key[..dest.key.len().min(16)])
}

/// Reconciliation query (§7.2): read a destination's slot WITHOUT
/// locks-held-across-syscalls (single map op): live? receipt?
/// Consumes a finished slot.
#[derive(Debug)]
pub struct SlotView {
    pub live: bool,
    pub receipt: Option<TapReceipt>,
}

pub fn view_slot(dest: &Destination) -> Option<SlotView> {
    // A consumed finished slot's unreadable result drops OUTSIDE
    // the lock (R4 finding 2 — same rule as every other site).
    let (view, deferred) = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let slot = reg.get_mut(dest)?;
        let view = SlotView {
            live: slot.live,
            receipt: slot.receipt.clone(),
        };
        let deferred = if !slot.live {
            reg.remove(dest).and_then(|slot| slot.result)
        } else {
            None
        };
        (view, deferred)
    };
    drop(deferred);
    Some(view)
}

/// Non-consuming slot read (R4 finding 1): availability probes use
/// this — a finished prior receipt must reconcile before tap
/// reuse, never be consumed-and-dropped by a liveness check.
pub fn peek_slot(dest: &Destination) -> Option<SlotView> {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.get(dest).map(|slot| SlotView {
        live: slot.live,
        receipt: slot.receipt.clone(),
    })
}

/// Map a `Control` to its `close_accounting` outcome word.
pub fn outcome_of<T>(control: &Control<T>) -> OpOutcome {
    match control {
        Control::Done(_) => OpOutcome::Done,
        Control::Cancelled => OpOutcome::Cancelled,
        Control::Expired => OpOutcome::Expired,
        Control::SpawnFailed => OpOutcome::WorkerUnavailable,
    }
}

/// Capped `close_accounting[]`: most recent 256 + overflow count.
pub fn push_accounting(
    log: &mut Vec<crate::service::envelope::CloseOp>,
    overflow: &mut u64,
    op: String,
    outcome: OpOutcome,
) {
    log.push(crate::service::envelope::CloseOp { op, outcome });
    while log.len() > 256 {
        log.remove(0);
        *overflow += 1;
    }
}

/// Diagnostics worker (§7.2): ONE per run with a bounded internal
/// queue (64 lines; the coordinator `try_send`s without blocking —
/// full means the arriving line is counted into
/// `diagnostics_dropped` and skipped; queued lines are never
/// evicted). The worker performs ONE `write()` per line with NO
/// retry: short write or error drops the line + counts it. On
/// abandonment the worker drops its queue (counted) and exits.
/// `diagnostics` is a `close_accounting` op like any other.
pub struct Diagnostics {
    tx: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    dropped: Arc<AtomicU64>,
    abandon: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Diagnostics {
    pub fn spawn() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(64);
        let dropped = Arc::new(AtomicU64::new(0));
        let abandon = Arc::new(AtomicBool::new(false));
        let dropped_w = dropped.clone();
        let abandon_w = abandon.clone();
        let handle = std::thread::Builder::new()
            .name("sixb-diag".to_string())
            .spawn(move || {
                for line in rx.iter() {
                    if abandon_w.load(Ordering::Acquire) {
                        // Drop the queue (counted) and exit: drain
                        // without writing. Empty vectors are the
                        // abandonment wake itself, never
                        // diagnostics — counted out.
                        let mut n = u64::from(!line.is_empty());
                        while let Ok(queued) = rx.try_recv() {
                            n += u64::from(!queued.is_empty());
                        }
                        dropped_w.fetch_add(n, Ordering::Relaxed);
                        return;
                    }
                    if line.is_empty() {
                        // Abandonment wake observed without the
                        // flag (ordering race) — not a diagnostic.
                        continue;
                    }
                    // ONE write() per line, NO retry, NO O_NONBLOCK
                    // claim: boundedness comes from detachment +
                    // drop, not the flag.
                    let rc = unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            line.as_ptr() as *const libc::c_void,
                            line.len(),
                        )
                    };
                    if rc < 0 || (rc as usize) < line.len() {
                        dropped_w.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
            .ok();
        Self {
            tx: Some(tx),
            dropped,
            abandon,
            handle,
        }
    }

    /// Non-blocking emit (preformatted line WITHOUT trailing
    /// newline). Full ⟹ counted + skipped, never evicted, never
    /// blocking the coordinator.
    pub fn emit(&self, line: &[u8]) {
        let Some(tx) = self.tx.as_ref() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut owned = line.to_vec();
        owned.push(b'\n');
        if tx.try_send(owned).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Abandon: the worker drops its queue (counted) and exits.
    /// Joins up to `budget`, then detaches (process exit reaps).
    pub fn abandon(mut self, budget: Duration) -> u64 {
        self.abandon.store(true, Ordering::Release);
        // Wake the worker if it blocks in `recv`.
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(Vec::new());
        }
        if let Some(h) = self.handle.take() {
            let start = Instant::now();
            loop {
                if h.is_finished() {
                    let _ = h.join();
                    break;
                }
                if start.elapsed() >= budget {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        self.dropped()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(key: &str) -> Destination {
        Destination {
            class: DestClass::StateMut,
            key: key.to_string(),
        }
    }

    #[test]
    fn done_op_returns_value() {
        let cancel = AtomicBool::new(false);
        let c: Control<u64> = run_under_control(
            dest("done"),
            Duration::from_secs(5),
            &cancel,
            |_| WorkerOut::value(41),
            None,
        );
        assert!(matches!(c, Control::Done(41)));
        assert_eq!(outcome_of(&c), OpOutcome::Done);
    }

    #[test]
    fn expiry_abandons_without_join() {
        let cancel = AtomicBool::new(false);
        let started = Arc::new(AtomicBool::new(false));
        let started_w = started.clone();
        let t0 = Instant::now();
        let c: Control<u64> = run_under_control(
            dest("expiry"),
            Duration::from_millis(50),
            &cancel,
            move |gate| {
                started_w.store(true, Ordering::Release);
                // A started worker past abandonment keeps running
                // detached (here: brief, then exits + unregisters).
                while !gate.abandoned() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                WorkerOut::value(1)
            },
            None,
        );
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert!(matches!(c, Control::Expired));
        assert!(started.load(Ordering::Acquire));
        // Successor refused while the abandoned worker is registered.
        let c2: Control<u64> = run_under_control(
            dest("expiry"),
            Duration::from_millis(50),
            &cancel,
            |_| WorkerOut::value(2),
            None,
        );
        assert!(matches!(c2, Control::Expired));
        // Reconcile: the abandoned receiptless slot is gone
        // (worker-side self-reclaim — R3 Gate 3 F2: nothing to
        // consume) or finished; then reuse works.
        let mut tries = 0;
        loop {
            match view_slot(&dest("expiry")) {
                None => break,
                Some(v) if !v.live => break,
                Some(_) => {}
            }
            tries += 1;
            assert!(tries < 500, "worker must exit + unregister");
            std::thread::sleep(Duration::from_millis(5));
        }
        let c3: Control<u64> = run_under_control(
            dest("expiry"),
            Duration::from_secs(5),
            &cancel,
            |_| WorkerOut::value(3),
            None,
        );
        assert!(matches!(c3, Control::Done(3)));
    }

    #[test]
    fn cancel_abandons() {
        let cancel = AtomicBool::new(false);
        cancel.store(true, Ordering::Release);
        let c: Control<u64> = run_under_control(
            dest("cancel"),
            Duration::from_secs(5),
            &cancel,
            |_| WorkerOut::value(1),
            None,
        );
        assert!(matches!(c, Control::Cancelled));
        assert_eq!(outcome_of(&c), OpOutcome::Cancelled);
    }

    #[test]
    fn fenced_gate_sees_abandonment_and_epoch() {
        let cancel = AtomicBool::new(false);
        let c: Control<u64> = run_under_control(
            dest("fence"),
            Duration::from_millis(30),
            &cancel,
            |gate| {
                // Fenced worker re-checks before its ONE mutation.
                let mut rechecks = 0;
                while !gate.abandoned() && rechecks < 1000 {
                    rechecks += 1;
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert!(gate.abandoned(), "abandonment must be visible");
                WorkerOut::value(rechecks)
            },
            None,
        );
        assert!(matches!(c, Control::Expired));
    }

    #[test]
    fn tap_receipt_visible_at_exit() {
        let cancel = AtomicBool::new(false);
        let d = Destination {
            class: DestClass::TapWrite,
            key: "taprec".to_string(),
        };
        let receipt = TapReceipt {
            op_id: 5,
            state: TapReceiptState::Complete { bytes: 10 },
            kind: "window-ref".to_string(),
            seq: Some(2),
            span: None,
            record_bytes: 10,
            dest_path: "/tmp/x".to_string(),
            dest_dev: 1,
            dest_ino: 2,
        };
        let receipt_w = receipt.clone();
        let c: Control<u64> = run_under_control(
            d.clone(),
            Duration::from_secs(5),
            &cancel,
            move |_| WorkerOut {
                value: 1,
                receipt: Some(receipt_w),
            },
            None,
        );
        assert!(matches!(c, Control::Done(1)));
        // Waiter-Done consumes the slot (no reconcile needed).
        assert!(view_slot(&d).is_none());
    }

    #[test]
    fn diagnostics_drops_under_flood() {
        let diag = Diagnostics::spawn();
        // 64-line queue: a 10k-line flood must drop, never block.
        let t0 = Instant::now();
        for i in 0..10_000 {
            diag.emit(format!("flood line {i}").as_bytes());
        }
        assert!(t0.elapsed() < Duration::from_secs(5));
        let dropped = diag.abandon(Duration::from_secs(2));
        assert!(dropped > 0, "flood must drop + count, got {dropped}");
    }

    /// R4 finding 2: abandonment returns within its budget while a
    /// FOREIGN worker's result destructor is still blocked — result
    /// destruction runs outside the registry lock, so the waiter's
    /// abandonment path never waits on worker-held state. RED
    /// pre-fix (the waiter blocks on the mutex the destructor
    /// holds); GREEN post-fix. The R3-F2 race leg
    /// (`t74_seal_bound`, no retained results) stays green.
    #[test]
    fn abandonment_returns_while_foreign_destructor_blocks() {
        use std::sync::mpsc;
        struct BlockingDrop {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            exited: mpsc::Sender<()>,
        }
        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                let _ = self.entered.send(());
                let _ = self.release.recv();
                let _ = self.exited.send(());
            }
        }
        let tag = format!(
            "r42-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        // Op A: abandoned immediately (zero budget, worker gated),
        // then released — the flagged exit drops its value.
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (exited_tx, exited_rx) = mpsc::channel::<()>();
        let dest_a = Destination {
            class: DestClass::OwnTmp,
            key: format!("{tag}-a"),
        };
        let cancel_a = AtomicBool::new(false);
        let ctrl_a: Control<BlockingDrop> = run_under_control(
            dest_a.clone(),
            Duration::from_millis(0),
            &cancel_a,
            move |_gate| {
                let _ = gate_rx.recv();
                WorkerOut::value(BlockingDrop {
                    entered: entered_tx,
                    release: release_rx,
                    exited: exited_tx,
                })
            },
            None,
        );
        assert!(matches!(ctrl_a, Control::Expired));
        gate_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the abandoned value's destructor must run");
        // Op B (a different destination on the same global
        // registry): its abandonment must return within budget
        // while A's destructor is still blocked on `release`.
        let dest_b = Destination {
            class: DestClass::OwnTmp,
            key: format!("{tag}-b"),
        };
        let (done_tx, done_rx) = mpsc::channel::<(bool, Duration)>();
        let waiter = std::thread::spawn(move || {
            let cancel_b = AtomicBool::new(false);
            let t0 = Instant::now();
            let ctrl_b: Control<u64> = run_under_control(
                dest_b,
                Duration::from_millis(200),
                &cancel_b,
                move |gate| {
                    while !gate.abandoned() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    WorkerOut::value(7)
                },
                None,
            );
            let _ = done_tx.send((matches!(ctrl_b, Control::Expired), t0.elapsed()));
        });
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok((is_expired, dt)) => {
                assert!(is_expired, "B must abandon with Expired, not hang");
                assert!(
                    exited_rx.try_recv().is_err(),
                    "A's destructor must still be blocked when B abandons"
                );
                assert!(
                    dt < Duration::from_secs(2),
                    "abandonment must return within budget, took {dt:?}"
                );
            }
            Err(_) => {
                release_tx.send(()).unwrap();
                let _ = waiter.join();
                panic!("RED: abandonment waited on worker-held destructor progress");
            }
        }
        release_tx.send(()).unwrap();
        exited_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the destructor exits once released");
        let _ = waiter.join();
        // Settle: A's receiptless abandoned slot self-reclaims.
        for _ in 0..400 {
            if view_slot(&dest_a).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(view_slot(&dest_a).is_none(), "A's slot must self-reclaim");
    }

    /// R5 finding 2: an abandoning waiter must not synchronously
    /// destroy a result caught by the completion race — disposal
    /// runs OFF the waiter's path (deferred reaper) while the race
    /// stays consumed (no retained results). Deterministic at the
    /// helper level: the manually constructed finished slot is
    /// exactly the post-race state (the worker stored T and set
    /// live=false after the waiter's last completion check, before
    /// the waiter's abandonment consume). RED pre-fix (the waiter
    /// blocks on the raced-in destructor — the 5 s watchdog);
    /// GREEN post-fix (the consume returns in-budget with the
    /// destructor still blocked; the result is eventually disposed
    /// without retention). Both slot arms (receiptless unregister
    /// + receipt-bearing take) ride the same disposal.
    #[test]
    fn abandonment_defers_raced_in_blocked_result() {
        use std::sync::mpsc;
        struct BlockingDrop {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            exited: mpsc::Sender<()>,
        }
        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                let _ = self.entered.send(());
                let _ = self.release.recv();
                let _ = self.exited.send(());
            }
        }
        let tag = format!(
            "r52-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        for (case, with_receipt) in [("bare", false), ("receipt", true)] {
            let (entered_tx, entered_rx) = mpsc::channel::<()>();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let (exited_tx, exited_rx) = mpsc::channel::<()>();
            let dest = Destination {
                class: DestClass::OwnTmp,
                key: format!("{tag}-{case}"),
            };
            // A real sequence id (never collides with a live worker).
            let worker = NEXT_WORKER.fetch_add(1, Ordering::Relaxed);
            let receipt = with_receipt.then(|| TapReceipt {
                op_id: 3,
                state: TapReceiptState::Complete { bytes: 9 },
                kind: "window-ref".to_string(),
                seq: Some(3),
                span: None,
                record_bytes: 9,
                dest_path: "/tmp/x".to_string(),
                dest_dev: 1,
                dest_ino: 2,
            });
            {
                let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
                reg.insert(
                    dest.clone(),
                    Slot {
                        worker,
                        live: false,
                        result: Some(Box::new(BlockingDrop {
                            entered: entered_tx,
                            release: release_rx,
                            exited: exited_tx,
                        })),
                        receipt,
                    },
                );
            }
            // The abandoning waiter's consume runs on its own thread
            // under a watchdog (RED must fail, never hang the suite).
            let (done_tx, done_rx) = mpsc::channel::<()>();
            let dest_w = dest.clone();
            let t0 = Instant::now();
            let waiter = std::thread::spawn(move || {
                consume_if_finished(&dest_w, worker);
                let _ = done_tx.send(());
            });
            match done_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(()) => {
                    let dt = t0.elapsed();
                    assert!(
                        dt < Duration::from_secs(2),
                        "{case}: the consume must return in-budget, took {dt:?}"
                    );
                }
                Err(_) => {
                    release_tx.send(()).unwrap();
                    let _ = waiter.join();
                    panic!(
                        "RED ({case}): the abandoning waiter blocked on the raced-in destructor"
                    );
                }
            }
            let _ = waiter.join();
            // Disposal started off-path (entered) while still blocked
            // (no exit) — the waiter never waited on it.
            entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the deferred destructor must run off-path");
            assert!(
                exited_rx.try_recv().is_err(),
                "{case}: the destructor must still be blocked when the waiter returns"
            );
            // Release: the result is eventually disposed (no leak) and
            // the race stays consumed (no retained result).
            release_tx.send(()).unwrap();
            exited_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the deferred result must dispose once released");
            if with_receipt {
                let slot = registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&dest);
                let slot = slot.expect("the receipt-bearing slot stays for the reconciler");
                assert!(slot.result.is_none(), "the raced-in result stays consumed");
                assert!(
                    slot.receipt.is_some(),
                    "the receipt stays for the reconciler"
                );
            } else {
                assert!(
                    view_slot(&dest).is_none(),
                    "the receiptless slot unregisters"
                );
            }
        }
    }

    /// S4 expedite independence: a wait poll over a FRESH cancel
    /// observes the second stop independently of the sticky run
    /// cancel — the first `Term` drained while the first-stop latch
    /// is already set stores the wait's cancel + the double latch
    /// (the poll never reads the run cancel — it only drains
    /// signalfd into the latches). Close-critical staging relies on
    /// this: fresh cancel + this poll survives the first stop and
    /// still expedites on the second.
    #[test]
    fn wait_poll_second_term_expedites_despite_sticky_run_cancel() {
        struct MaskGuard;
        impl Drop for MaskGuard {
            fn drop(&mut self) {
                crate::service::signals::restore_test_mask();
            }
        }
        // NOTE: installs the process-wide mask (serial suite).
        let signals = SignalFd::install().expect("signalfd installs");
        let _guard = MaskGuard;
        // Post-first-stop state: the run cancel is sticky-true and
        // the first-stop latch is set; this wait's cancel is fresh.
        let run_cancel = AtomicBool::new(true);
        let latched = AtomicBool::new(true);
        let double = AtomicBool::new(false);
        let reload = AtomicBool::new(false);
        let wait_cancel = AtomicBool::new(false);
        let poll = WaitPoll::new(&signals, &wait_cancel, &latched, &double, &reload);
        unsafe { libc::raise(libc::SIGTERM) };
        poll.poll();
        assert!(
            wait_cancel.load(Ordering::SeqCst),
            "second stop must cancel the fresh wait"
        );
        assert!(
            double.load(Ordering::SeqCst),
            "second stop must latch double"
        );
        assert!(
            run_cancel.load(Ordering::SeqCst),
            "the poll never clears the sticky run cancel"
        );
        assert!(signals.drain().is_empty(), "the poll consumed the signal");
    }

    /// R6-1(i) RED: fresh-process first-use — the disposal
    /// facility is uninitialized and setup stalls: the
    /// abandonment handoff must still return in-budget. The
    /// fresh lock is the fresh process; the armed setup gate is
    /// the stalled setup (gated directly, no libc fault
    /// injection). RED pre-fix (init runs on the waiter path —
    /// the 2 s watchdog); GREEN post-fix (setup never runs on
    /// abandonment).
    #[test]
    fn r61_first_use_setup_can_stall_abandonment() {
        use std::sync::mpsc;
        let lock: OnceLock<mpsc::Sender<Box<dyn Any + Send>>> = OnceLock::new();
        RED_SETUP_ARMED.store(true, Ordering::SeqCst);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let t0 = Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                // The abandonment handoff (old shape:
                // init-on-path).
                let _ = reaper_tx_in(&lock).send(Box::new(1u64));
                let _ = done_tx.send(());
            });
            if done_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                // Release so the suite never hangs; the
                // elapsed assert below records the RED.
                red_setup_release();
            }
        });
        RED_SETUP_ARMED.store(false, Ordering::SeqCst);
        let dt = t0.elapsed();
        assert!(
            dt < Duration::from_secs(2),
            "RED: first-use setup stalled the abandonment handoff ({dt:?})"
        );
    }
}
