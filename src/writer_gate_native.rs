// SPDX-License-Identifier: GPL-3.0-or-later
//! Native controls use the production Rust objects and loader. Only finite
//! count/API/error cells are read; pending and thread operands stay in kernel.
use crate::{loader, observation_memory::MemoryPool, writer_gate::WriterGate};
use std::{
    ffi::CString,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
static CALLS: AtomicU64 = AtomicU64::new(0);
static INSIDE: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn osslscope_native_cut_callback(block: u32) -> i32 {
    CALLS.fetch_add(1, Ordering::SeqCst);
    if block == 1 {
        INSIDE.store(true, Ordering::SeqCst);
        while !RELEASE.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
    if block >= 2 {
        osslscope_native_cut_callback(if block == 2 { 0 } else { block - 1 });
    }
    std::hint::black_box(1)
}
struct Producers {
    gate: WriterGate,
    count: loader::Loaded,
    provider: loader::Loaded,
    links: Vec<OwnedFd>,
    cpus: usize,
}
impl Producers {
    fn new() -> Self {
        let gate = WriterGate::create(&MemoryPool::new(256 << 20)).unwrap();
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let count =
            loader::load_gated(&loader::prepare_focused_count(&bytes).unwrap(), &gate).unwrap();
        let bytes =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let provider = loader::load_gated(
            &crate::provider_observation::session::prepare_object(&bytes).unwrap(),
            &gate,
        )
        .unwrap();
        let mut this = Self {
            gate,
            count,
            provider,
            links: vec![],
            cpus: aya::util::nr_cpus().unwrap(),
        };
        let ns = crate::focused_capture::observer_namespace().unwrap();
        let ns = [ns.device.to_ne_bytes(), ns.inode.to_ne_bytes()].concat();
        this.write(false, "NS_CONFIG", &0u32.to_ne_bytes(), &ns);
        this.write(
            false,
            "TARGET",
            &0u32.to_ne_bytes(),
            &u64::from(std::process::id()).to_ne_bytes(),
        );
        this.write(false, "GEN", &0u32.to_ne_bytes(), &1u32.to_ne_bytes());
        this.write(false, "WINDOW", &0u32.to_ne_bytes(), &0u64.to_ne_bytes());
        this.write(
            false,
            "WINDOW",
            &1u32.to_ne_bytes(),
            &u64::MAX.to_ne_bytes(),
        );
        this.write(true, "NAMESPACE", &0u32.to_ne_bytes(), &ns);
        this.write(
            true,
            "API_WINDOW",
            &0u32.to_ne_bytes(),
            &[0u64.to_ne_bytes(), u64::MAX.to_ne_bytes()].concat(),
        );
        this.write(
            true,
            "MEMBERS",
            &std::process::id().to_ne_bytes(),
            &[
                1u64.to_ne_bytes().as_slice(),
                &0u64.to_ne_bytes(),
                &0u32.to_ne_bytes(),
                &0u32.to_ne_bytes(),
            ]
            .concat(),
        );
        this.write(
            true,
            "CONFIG",
            &7u64.to_ne_bytes(),
            &[
                1u64.to_ne_bytes().as_slice(),
                &1u64.to_ne_bytes(),
                &std::process::id().to_ne_bytes(),
                &20u32.to_ne_bytes(),
            ]
            .concat(),
        );
        // Operational public ABI: no argument/target-memory reads. Seed every CPU.
        let zero = vec![0; 72 * this.cpus];
        unsafe {
            ossl_bpf_sys::map_update_elem(
                this.provider.maps["API_TOTALS"].as_raw_fd(),
                &7u64.to_ne_bytes(),
                &zero,
                0,
            )
        }
        .unwrap();
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let symbol = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("osslscope_native_cut_callback"))
            .unwrap();
        let segment = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == 1
                    && symbol.st_value >= p.p_vaddr
                    && symbol.st_value < p.p_vaddr + p.p_filesz
            })
            .unwrap();
        let offset = segment.p_offset + symbol.st_value - segment.p_vaddr;
        let path = CString::new(exe.as_os_str().as_encoded_bytes()).unwrap();
        for (loaded, root, returns) in [
            (&this.count, "count_entry", false),
            (&this.provider, "observation_entry", false),
            (&this.provider, "observation_return", true),
        ] {
            let attach = if returns {
                ossl_bpf_sys::link_create_uretprobe_multi
            } else {
                ossl_bpf_sys::link_create_uprobe_multi
            };
            this.links.push(
                attach(
                    loaded.progs[root].as_raw_fd(),
                    &path,
                    &[offset],
                    &[7],
                    std::process::id(),
                )
                .unwrap(),
            );
        }
        this.gate.open().unwrap();
        this
    }
    fn write(&self, provider: bool, name: &str, key: &[u8], value: &[u8]) {
        let loaded = if provider {
            &self.provider
        } else {
            &self.count
        };
        loader::BorrowedMap::new(loaded.maps[name].as_fd())
            .unwrap()
            .update(key, value)
            .unwrap();
    }
    fn cells(&self, provider: bool, name: &str, key: &[u8]) -> Vec<u64> {
        // This allowlist prevents accidental pointer-bearing map transport.
        assert!(matches!(
            name,
            "COUNTS" | "ADMITTED" | "DROPFAIL" | "NSFAIL" | "LATC" | "LOSS" | "API_TOTALS"
        ));
        let loaded = if provider {
            &self.provider
        } else {
            &self.count
        };
        let map = loader::BorrowedMap::new(loaded.maps[name].as_fd()).unwrap();
        let mut bytes = vec![0; map.info.value_size as usize * self.cpus];
        map.lookup(key, &mut bytes).unwrap();
        bytes
            .chunks_exact(8)
            .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
            .collect()
    }
    fn count(&self) -> u64 {
        self.cells(false, "COUNTS", &((7u64 << 32) | 1).to_ne_bytes())
            .chunks_exact(3)
            .map(|c| c[0])
            .sum()
    }
    fn api(&self) -> [u64; 9] {
        let mut totals = [0; 9];
        for cpu in self
            .cells(true, "API_TOTALS", &7u64.to_ne_bytes())
            .chunks_exact(9)
        {
            for (total, value) in totals.iter_mut().zip(cpu) {
                *total += value;
            }
        }
        totals
    }
    fn snapshot(&self) -> Vec<u64> {
        let mut out = self.cells(false, "COUNTS", &((7u64 << 32) | 1).to_ne_bytes());
        for name in ["ADMITTED", "DROPFAIL", "NSFAIL"] {
            out.extend(self.cells(false, name, &0u32.to_ne_bytes()));
        }
        for i in 0u32..16 {
            out.extend(self.cells(false, "LATC", &i.to_ne_bytes()));
        }
        for i in 0u32..8 {
            out.extend(self.cells(true, "LOSS", &i.to_ne_bytes()));
        }
        out.extend(self.cells(true, "API_TOTALS", &7u64.to_ne_bytes()));
        out
    }
}
fn available_cpus() -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}
fn pin(cpu: usize) {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_SET(cpu, &mut set);
    }
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) },
        0
    );
}
#[test]
#[ignore = "requires privileged BPF, two CPUs and fresh production objects"]
fn native_shared_cut_conserves_concurrent_calls_with_duplicate_links_and_late_return() {
    CALLS.store(0, Ordering::SeqCst);
    INSIDE.store(false, Ordering::SeqCst);
    RELEASE.store(false, Ordering::SeqCst);
    let producers = Producers::new();
    // An independently open production domain demonstrates that closing our
    // original link descriptors is not sufficient while duplicates survive.
    let mut control = Producers::new();
    let duplicates: Vec<_> = control
        .links
        .iter()
        .map(|fd| fd.try_clone().unwrap())
        .collect();
    control.links.clear();
    let cpus = available_cpus();
    assert!(cpus.len() >= 2);
    let start = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        for &cpu in &cpus[..2] {
            let start = start.clone();
            scope.spawn(move || {
                pin(cpu);
                start.wait();
                for _ in 0..1000 {
                    assert_eq!(osslscope_native_cut_callback(0), 1);
                }
            });
        }
    });
    assert_eq!(CALLS.load(Ordering::SeqCst), 2000);
    assert_eq!(producers.count(), 2000);
    assert_eq!(producers.api(), [2000, 2000, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        control.count(),
        2000,
        "close-only counterexample must actually run"
    );
    let admitted: u64 = producers
        .cells(false, "ADMITTED", &0u32.to_ne_bytes())
        .iter()
        .sum();
    assert_eq!(admitted, producers.count());
    assert!(
        producers
            .cells(false, "DROPFAIL", &0u32.to_ne_bytes())
            .iter()
            .all(|&n| n == 0)
    );
    let held: Vec<_> = producers
        .links
        .iter()
        .map(|fd| fd.try_clone().unwrap())
        .collect();
    let fd = held[0].as_raw_fd();
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let stop_read = stop.clone();
    let read_count = reads.clone();
    let reader = std::thread::spawn(move || {
        while !stop_read.load(Ordering::SeqCst) {
            // Never log fdinfo (which can contain target offsets).
            assert!(
                !std::fs::read(format!("/proc/self/fdinfo/{fd}"))
                    .unwrap()
                    .is_empty()
            );
            read_count.fetch_add(1, Ordering::SeqCst);
        }
    });
    struct ReleaseOnDrop(Arc<AtomicBool>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            RELEASE.store(true, Ordering::SeqCst);
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let _release = ReleaseOnDrop(stop.clone());
    let late = std::thread::spawn(|| osslscope_native_cut_callback(1));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !INSIDE.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(producers.api()[0..2], [2001, 2000]);
    let receipt = producers.gate.close().unwrap();
    let before = producers.snapshot();
    RELEASE.store(true, Ordering::SeqCst);
    assert_eq!(late.join().unwrap(), 1);
    for _ in 0..1000 {
        assert_eq!(osslscope_native_cut_callback(0), 1);
    }
    assert_eq!(CALLS.load(Ordering::SeqCst), 3001);
    assert_eq!(
        producers.snapshot(),
        before,
        "late return/entries mutated protected outputs"
    );
    assert_eq!(
        producers.api()[0..2],
        [2001, 2000],
        "pending return remains incomplete"
    );
    assert_eq!(control.count(), 3001);
    assert_eq!(control.api()[0..2], [3001, 3001]);
    assert_eq!(producers.gate.close().unwrap(), receipt);
    assert!(producers.gate.open().is_err());
    stop.store(true, Ordering::SeqCst);
    reader.join().unwrap();
    assert!(reads.load(Ordering::SeqCst) > 0);
    control.gate.close().unwrap();
    drop((held, duplicates));
    eprintln!(
        "independent_calls=3001 cut_entries=2001 cut_returns=2000 open_control=3001 cpus=2 duplicate_links=6 fdinfo_reads={}",
        reads.load(Ordering::SeqCst)
    );
}

#[test]
#[ignore = "requires privileged BPF and fresh production objects"]
fn native_error_writers_and_full_count_map_stop_at_shared_cut() {
    let mut p = Producers::new();
    osslscope_native_cut_callback(0);
    // Both namespace failure writers must be reached while open.
    p.write(false, "NS_CONFIG", &0u32.to_ne_bytes(), &[0; 16]);
    p.write(true, "NAMESPACE", &0u32.to_ne_bytes(), &[0; 16]);
    osslscope_native_cut_callback(0);
    assert_eq!(
        p.cells(false, "NSFAIL", &0u32.to_ne_bytes())
            .iter()
            .sum::<u64>(),
        1
    );
    assert_eq!(
        p.cells(true, "LOSS", &7u32.to_ne_bytes())
            .iter()
            .sum::<u64>(),
        3 // one entry and both existing return identity attempts
    );
    let ns = crate::focused_capture::observer_namespace().unwrap();
    let ns = [ns.device.to_ne_bytes(), ns.inode.to_ne_bytes()].concat();
    p.write(false, "NS_CONFIG", &0u32.to_ne_bytes(), &ns);
    p.write(true, "NAMESPACE", &0u32.to_ne_bytes(), &ns);
    // The real production 8192-key map is exhausted, without reducing its bound.
    let zero = vec![0; 24 * p.cpus];
    for generation in 2u64..=8192 {
        let key = (7u64 << 32) | generation;
        unsafe {
            ossl_bpf_sys::map_update_elem(
                p.count.maps["COUNTS"].as_raw_fd(),
                &key.to_ne_bytes(),
                &zero,
                0,
            )
        }
        .unwrap();
    }
    p.write(false, "GEN", &0u32.to_ne_bytes(), &8193u32.to_ne_bytes());
    osslscope_native_cut_callback(0);
    assert_eq!(
        p.cells(false, "DROPFAIL", &0u32.to_ne_bytes())
            .iter()
            .sum::<u64>(),
        1
    );
    assert_eq!(
        p.cells(false, "ADMITTED", &0u32.to_ne_bytes())
            .iter()
            .sum::<u64>(),
        p.count() + 1
    );
    // Nine nested application entries exercise actual API depth refusal.
    osslscope_native_cut_callback(9);
    assert!(p.api()[7] > 0);
    // Remove just the entry link; the actual return producer must report pairing loss.
    drop(p.links.remove(1));
    let before_pair = p.api()[8];
    osslscope_native_cut_callback(0);
    assert_eq!(p.api()[8], before_pair + 1);
    // Seed finite physical lower bounds only; the real BPF bump must saturate.
    let mut saturated = vec![0; 24 * p.cpus];
    for cpu in saturated.chunks_exact_mut(24) {
        cpu[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        cpu[8..16].copy_from_slice(&1u64.to_ne_bytes());
        cpu[16..24].copy_from_slice(&1u64.to_ne_bytes());
    }
    unsafe {
        ossl_bpf_sys::map_update_elem(
            p.count.maps["COUNTS"].as_raw_fd(),
            &((7u64 << 32) | 1).to_ne_bytes(),
            &saturated,
            0,
        )
    }
    .unwrap();
    p.write(false, "GEN", &0u32.to_ne_bytes(), &1u32.to_ne_bytes());
    osslscope_native_cut_callback(0);
    assert!(
        p.cells(false, "COUNTS", &((7u64 << 32) | 1).to_ne_bytes())
            .chunks_exact(3)
            .all(|cpu| cpu[0] == u64::MAX)
    );
    // Error stimuli remain in place after closure: no protected error writer may run.
    p.write(false, "NS_CONFIG", &0u32.to_ne_bytes(), &[0; 16]);
    p.write(true, "NAMESPACE", &0u32.to_ne_bytes(), &[0; 16]);
    p.gate.close().unwrap();
    let before = p.snapshot();
    for _ in 0..100 {
        osslscope_native_cut_callback(0);
    }
    assert_eq!(p.snapshot(), before);
    eprintln!(
        "native_errors namespace_count=1 namespace_provider=3 full_keys=8192 pairing=1 depth_observed=true after_cut_unchanged=true"
    );
}

#[test]
#[ignore = "timing: requires quiet native lease, two exact Rust object generations"]
fn native_gate_cost_against_historical_rust_count_and_resource_release() {
    let original_affinity = {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
            0
        );
        set
    };
    struct RestoreAffinity(libc::cpu_set_t);
    impl Drop for RestoreAffinity {
        fn drop(&mut self) {
            assert_eq!(
                unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&self.0), &self.0) },
                0
            );
        }
    }
    let _restore = RestoreAffinity(original_affinity);
    pin(available_cpus()[0]);
    let fd_count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let descriptors_before = fd_count();
    let pool = MemoryPool::new(256 << 20);
    let mut setup = Vec::new();
    let mut open = Vec::new();
    let mut close = Vec::new();
    let mut memlock = Vec::new();
    for _ in 0..15 {
        let start = Instant::now();
        let gate = WriterGate::create(&pool).unwrap();
        setup.push(start.elapsed().as_nanos());
        // Only finite kernel map accounting, never fdinfo target offsets.
        let spec = loader::MapSpecLite {
            name: "ADMIT".into(),
            map_type: 12,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
            flags: 0,
        };
        let fd = gate.inject(&spec).unwrap();
        let second = gate.inject(&spec).unwrap();
        assert_eq!(fd_count(), descriptors_before + 4);
        memlock.push(gate.map_memlock());
        open.push(gate.open().unwrap().as_nanos());
        let start = Instant::now();
        gate.close().unwrap();
        close.push(start.elapsed().as_nanos());
        let raw = fd.as_raw_fd();
        drop(fd);
        drop(second);
        drop(gate);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
    }
    let gate_peak = pool.peak();
    assert!(
        pool.reserve(256 << 20).is_some(),
        "gate resources were not returned"
    );
    assert_eq!(fd_count(), descriptors_before);
    let exe = std::env::current_exe().unwrap();
    let bytes = std::fs::read(&exe).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let symbol = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("osslscope_native_cut_callback"))
        .unwrap();
    let segment = elf
        .program_headers
        .iter()
        .find(|p| {
            p.p_type == 1
                && symbol.st_value >= p.p_vaddr
                && symbol.st_value < p.p_vaddr + p.p_filesz
        })
        .unwrap();
    let offset = segment.p_offset + symbol.st_value - segment.p_vaddr;
    let path = CString::new(exe.as_os_str().as_encoded_bytes()).unwrap();
    let cpus = aya::util::nr_cpus().unwrap();
    let ns = crate::focused_capture::observer_namespace().unwrap();
    let ns = [ns.device.to_ne_bytes(), ns.inode.to_ne_bytes()].concat();
    let current =
        std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
    let historical =
        std::fs::read(std::env::var_os("OSSL_HISTORICAL_FOCUSED_OBJECT").unwrap()).unwrap();
    let baseline_specs: Vec<_> = loader::FOCUSED_COUNT_MAPS
        .iter()
        .copied()
        .filter(|m| m.name != "ADMIT")
        .collect();
    loader::validate_count_object(&historical).unwrap();
    let baseline = loader::prepare(&historical, &baseline_specs, &loader::COUNT_PROGS).unwrap();
    assert_eq!(baseline.maps.len(), 9);
    let current = loader::prepare_focused_count(&current).unwrap();
    let mut samples = Vec::new();
    // Alternating AB/BA order, two warmup pairs then eleven retained pairs.
    for pair in 0..13 {
        for gated in if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let gate = gated.then(|| WriterGate::create(&pool).unwrap());
            let loaded = match &gate {
                Some(g) => loader::load_gated(&current, g).unwrap(),
                None => loader::load(&baseline).unwrap(),
            };
            let write = |name: &str, key: u32, bytes: &[u8]| {
                loader::BorrowedMap::new(loaded.maps[name].as_fd())
                    .unwrap()
                    .update(&key.to_ne_bytes(), bytes)
                    .unwrap()
            };
            write("NS_CONFIG", 0, &ns);
            write("TARGET", 0, &u64::from(std::process::id()).to_ne_bytes());
            write("GEN", 0, &1u32.to_ne_bytes());
            write("WINDOW", 0, &0u64.to_ne_bytes());
            write("WINDOW", 1, &u64::MAX.to_ne_bytes());
            let link = ossl_bpf_sys::link_create_uprobe_multi(
                loaded.progs["count_entry"].as_raw_fd(),
                &path,
                &[offset],
                &[7],
                std::process::id(),
            )
            .unwrap();
            if let Some(g) = &gate {
                g.open().unwrap();
            }
            for _ in 0..1000 {
                osslscope_native_cut_callback(0);
            }
            let start = Instant::now();
            for _ in 0..20000 {
                osslscope_native_cut_callback(0);
            }
            let elapsed = start.elapsed().as_nanos();
            if let Some(g) = &gate {
                g.close().unwrap();
            }
            drop(link);
            let mut bytes = vec![0; 24 * cpus];
            loader::BorrowedMap::new(loaded.maps["COUNTS"].as_fd())
                .unwrap()
                .lookup(&((7u64 << 32) | 1).to_ne_bytes(), &mut bytes)
                .unwrap();
            let counted: u64 = bytes
                .chunks_exact(24)
                .map(|cpu| u64::from_ne_bytes(cpu[..8].try_into().unwrap()))
                .sum();
            assert_eq!(counted, 21000);
            if pair >= 2 {
                samples.push((pair - 2, gated, elapsed));
            }
        }
    }
    assert_eq!(fd_count(), descriptors_before);
    eprintln!(
        "gate_setup_ns={setup:?} gate_open_ns={open:?} gate_delete_ns={close:?} inner_outer_memlock={memlock:?} accounted_gate_peak={} descriptors_before={descriptors_before} descriptors_after={} count_batches_20000={samples:?}",
        gate_peak,
        fd_count()
    );
}

#[test]
#[ignore = "requires privileged BPF, two CPUs and fresh production objects"]
fn native_active_workers_span_delete_and_preserve_independent_bounds() {
    CALLS.store(0, Ordering::SeqCst);
    let p = Producers::new();
    let control = Producers::new();
    let cpus = available_cpus();
    assert!(cpus.len() >= 2);
    let stop = Arc::new(AtomicBool::new(false));
    let start = Arc::new(Barrier::new(3));
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    std::thread::scope(|scope| {
        // Drop on either success or assertion unwind before scope joins workers.
        let _stop = StopOnDrop(stop.clone());
        for &cpu in &cpus[..2] {
            let stop = stop.clone();
            let start = start.clone();
            scope.spawn(move || {
                pin(cpu);
                start.wait();
                while !stop.load(Ordering::SeqCst) {
                    assert_eq!(osslscope_native_cut_callback(0), 1);
                }
            });
        }
        start.wait();
        let deadline = Instant::now() + Duration::from_secs(5);
        while CALLS.load(Ordering::SeqCst) < 5000 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let before = CALLS.load(Ordering::SeqCst);
        // No deliberate BPF-handler suspension: workers remain active across
        // the actual syscall. Its reviewed RCU semantics establish the cut.
        p.gate.close().unwrap();
        let after = CALLS.load(Ordering::SeqCst);
        let snapshot = p.snapshot();
        let physical = p.count();
        let api = p.api();
        assert!(physical >= before && physical <= after + 2);
        assert!(
            api[0].abs_diff(physical) <= 2,
            "at most one entry probe sequence per worker can straddle the cut"
        );
        assert!(api[0] >= api[1] && api[0] - api[1] <= 2);
        assert_eq!(
            p.cells(false, "ADMITTED", &0u32.to_ne_bytes())
                .iter()
                .sum::<u64>(),
            physical
        );
        assert!(
            p.cells(false, "DROPFAIL", &0u32.to_ne_bytes())
                .iter()
                .all(|&n| n == 0)
        );
        while CALLS.load(Ordering::SeqCst) < after + 1000 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            p.snapshot(),
            snapshot,
            "active post-cut callbacks changed safe writer outputs"
        );
        eprintln!(
            "active_cut independent_before={before} independent_after={after} physical={physical} api_entries={} api_returns={} post_cut_calls_at_least=1000 cpus=2",
            api[0], api[1]
        );
    });
    let independent = CALLS.load(Ordering::SeqCst);
    control.gate.close().unwrap();
    assert_eq!(control.count(), independent);
    assert_eq!(
        control.api(),
        [independent, independent, 0, 0, 0, 0, 0, 0, 0]
    );
    eprintln!("active_cut independent_final={independent} open_control_exact=true");
}
