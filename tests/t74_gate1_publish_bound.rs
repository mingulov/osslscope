// SPDX-License-Identifier: GPL-3.0-or-later
//! T7.4 fix2 Gate1 (F2): duplicate-convergence allocation bounded.
//! Adopted from the R2 publication probe
//! (`/tmp/t74-r2-publish-iugkuj8l/probe.rs`): identical 16 MiB retry
//! must converge through bounded buffers (<2 MiB extra heap), not
//! by reading + parsing the whole window.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Write as _,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = LIVE.fetch_add(l.size(), Ordering::SeqCst) + l.size();
            PEAK.fetch_max(n, Ordering::SeqCst);
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
fn duplicate_convergence_uses_bounded_buffers() {
    let dir = std::env::temp_dir().join(format!(
        "t74-gate1-publish-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let array = dir.join("array");
    {
        let mut f = std::fs::File::create(&array).unwrap();
        f.write_all(b"{\"pad\":\"").unwrap();
        let chunk = [b'x'; 65536];
        for _ in 0..256 {
            f.write_all(&chunk).unwrap();
        }
        f.write_all(b"\"}").unwrap();
    }
    let head = br#"{"seq":3,"run_id":{"pid":7,"starttime":8,"boot_id":"boot"},"crypto_watch":"#;
    let tail = b"}";
    let key = osslscope::service::publish::AttemptKey {
        seq: 3,
        pid: 7,
        starttime: 8,
        boot_id: "boot".into(),
    };
    for i in 0..2 {
        let base = LIVE.load(Ordering::SeqCst);
        PEAK.store(base, Ordering::SeqCst);
        let r = osslscope::service::publish::publish_window_streaming(
            &dir, 3, "probe", head, tail, &array, &key,
        );
        let peak = PEAK.load(Ordering::SeqCst) - base;
        eprintln!("attempt {i}: {:?}, peak_extra={peak}", r.0);
        if i == 1 {
            assert_eq!(r.0, osslscope::service::publish::PublishStep::Converged);
            assert!(
                peak < 2 * 1024 * 1024,
                "duplicate convergence must use bounded buffers (peak {peak})"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// R3 Gate 1 (F1): production-order twin — identity (`run_id`,
/// `seq`) renders AFTER the large `crypto_watch` array
/// (alphabetical keys via `to_value`), so the bounded scan must
/// stream past megabytes of preceding values with O(chunk)
/// memory. Same <2 MiB peak bound as the identity-first case.
#[test]
fn duplicate_convergence_production_order_uses_bounded_buffers() {
    let dir = std::env::temp_dir().join(format!(
        "t74-gate1-prodorder-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let array = dir.join("array");
    {
        let mut f = std::fs::File::create(&array).unwrap();
        f.write_all(b"{\"pad\":\"").unwrap();
        let chunk = [b'x'; 65536];
        for _ in 0..256 {
            f.write_all(&chunk).unwrap();
        }
        f.write_all(b"\"}").unwrap();
    }
    // Production key order: the large array value precedes the
    // identity fields (identity sits ~16 MiB into the file).
    let head = br#"{"crypto_watch":"#;
    let tail = br#","run_id":{"pid":7,"starttime":8,"boot_id":"boot"},"seq":3,"document":{}}"#;
    let key = osslscope::service::publish::AttemptKey {
        seq: 3,
        pid: 7,
        starttime: 8,
        boot_id: "boot".into(),
    };
    for i in 0..2 {
        let base = LIVE.load(Ordering::SeqCst);
        PEAK.store(base, Ordering::SeqCst);
        let r = osslscope::service::publish::publish_window_streaming(
            &dir, 3, "probe", head, tail, &array, &key,
        );
        let peak = PEAK.load(Ordering::SeqCst) - base;
        eprintln!("production-order attempt {i}: {:?}, peak_extra={peak}", r.0);
        if i == 1 {
            assert_eq!(r.0, osslscope::service::publish::PublishStep::Converged);
            assert!(
                peak < 2 * 1024 * 1024,
                "production-order convergence must use bounded buffers (peak {peak})"
            );
        }
    }
    // The full-parse twin agrees (sanity: ordering is valid).
    let bytes = std::fs::read(dir.join("window-0000000003.json")).unwrap();
    assert!(key.matches_bytes(&bytes));
    let _ = std::fs::remove_dir_all(&dir);
}
