// SPDX-License-Identifier: GPL-3.0-or-later
//! T7.4 fix3 Gate 3 (F2): abandoned worker ops must not retain
//! their results — late completions reconcile (worker-side
//! self-cleanup) instead of accumulating slots + bytes across
//! closes. Adopted from the R3 seal probe (3 expired reads each
//! retaining ~2 MiB until explicit `view_slot`).
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::SeqCst);
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Counting = Counting;

#[test]
fn abandoned_control_ops_do_not_retain_results() {
    use osslscope::service::worker::{
        Control, DestClass, Destination, WorkerOut, run_under_control,
    };
    use std::sync::atomic::AtomicBool;
    // Warmup: one abandoned op (thread-spawn shape) outside the
    // measurement.
    {
        let cancel = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let dest = Destination {
            class: DestClass::OwnTmp,
            key: format!("t74-sealbound-warm-{}", std::process::id()),
        };
        let ctrl: Control<Vec<u8>> = run_under_control(
            dest,
            std::time::Duration::from_millis(0),
            &cancel,
            move |_gate| {
                let _ = rx.recv();
                WorkerOut::value(vec![0u8; 1024])
            },
            None,
        );
        assert!(matches!(ctrl, Control::Expired));
        tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    for i in 0..3 {
        let base = LIVE.load(Ordering::SeqCst);
        let cancel = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let dest = Destination {
            class: DestClass::OwnTmp,
            key: format!("t74-sealbound-{i}-{}", std::process::id()),
        };
        // Zero budget: the waiter abandons immediately (the worker
        // is deterministically mid-recv — it cannot have finished).
        let ctrl: Control<Vec<u8>> = run_under_control(
            dest,
            std::time::Duration::from_millis(0),
            &cancel,
            move |_gate| {
                let _ = rx.recv();
                WorkerOut::value(vec![0u8; 2 * 1024 * 1024])
            },
            None,
        );
        assert!(matches!(ctrl, Control::Expired));
        // The worker completes late with 2 MiB — nothing ever
        // reconciles this nonce destination explicitly.
        tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let growth = LIVE.load(Ordering::SeqCst).saturating_sub(base);
        eprintln!("abandoned op {i}: live growth after late completion = {growth}");
        assert!(
            growth < 256 * 1024,
            "late results must not accumulate (op {i} retained {growth} bytes)"
        );
    }
}
