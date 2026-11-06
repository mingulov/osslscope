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
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = reg.get_mut(&dest_key) {
                if slot.worker == worker {
                    if exit_flag.load(Ordering::Acquire) {
                        drop(value);
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
        {
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            match reg.get_mut(&dest) {
                Some(slot) if slot.worker == worker && !slot.live => {
                    let result = slot.result.take();
                    reg.remove(&dest);
                    match result.and_then(|b| b.downcast::<T>().ok()).map(|b| *b) {
                        Some(v) => return Control::Done(v),
                        None => return Control::Expired,
                    }
                }
                Some(slot) if slot.worker != worker => {
                    // A successor registered: this waiter lost its
                    // slot (only via another driver on the same
                    // destination — the coordinator never does
                    // this in-run). Fail closed.
                    let _ = slot;
                    return Control::Expired;
                }
                _ => {}
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
            // blocking syscall.
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
/// section only (no worker progress needed).
fn consume_if_finished(dest: &Destination, worker: u64) {
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let finished = matches!(
        reg.get(dest),
        Some(slot) if slot.worker == worker && !slot.live
    );
    if !finished {
        return;
    }
    if reg.get(dest).is_some_and(|slot| slot.receipt.is_none()) {
        reg.remove(dest);
    } else if let Some(slot) = reg.get_mut(dest) {
        slot.result = None;
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
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let slot = reg.get_mut(dest)?;
    let view = SlotView {
        live: slot.live,
        receipt: slot.receipt.clone(),
    };
    if !slot.live {
        reg.remove(dest);
    }
    Some(view)
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
}
