// SPDX-License-Identifier: GPL-3.0-or-later
//! Private post-clone execution: fixed stack storage and raw Linux syscalls.
use super::protocol::*;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
pub(super) static HOST_READY_DELAY: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) static HOST_BEFORE_CHILD_EXIT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) static HOST_RESTORE_FAILURE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) static HOST_CHILD_PID_WORD: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) static HOST_HELPER_HOLD: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) static HOST_CLOSE_PAUSE: AtomicBool = AtomicBool::new(false);
static CHILD_SIGNAL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) static HOST_FORBIDDEN_SYSCALL: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn signal(sig: i32) {
    if sig == libc::SIGTERM {
        STOP.store(true, Ordering::Relaxed);
    } else if sig == libc::SIGCHLD {
        CHILD_SIGNAL.store(true, Ordering::Relaxed);
    }
}
#[unsafe(naked)]
unsafe extern "C" fn producer_sigreturn() {
    std::arch::naked_asm!("mov rax, 15", "syscall");
}
#[inline(always)]
pub(super) unsafe fn raw(
    n: i64,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> i64 {
    let out: i64;
    unsafe {
        std::arch::asm!("syscall",inlateout("rax") n=>out,in("rdi")a,in("rsi")b,in("rdx")c,in("r10")d,in("r8")e,in("r9")f,lateout("rcx") _,lateout("r11") _,options(nostack));
    }
    out
}
// Explicit arities keep all raw calls allocation- and errno-free.
unsafe fn call(n: i64, a: usize, b: usize, c: usize) -> i64 {
    unsafe { raw(n, a, b, c, 0, 0, 0) }
}
pub(super) fn monotonic() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = unsafe {
        call(
            libc::SYS_clock_gettime,
            libc::CLOCK_MONOTONIC as usize,
            &mut t as *mut _ as usize,
            0,
        )
    };
    if r < 0 {
        0
    } else {
        (t.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(t.tv_nsec as u64)
    }
}
fn exit(code: usize) -> ! {
    unsafe {
        call(libc::SYS_exit_group, code, 0, 0);
    }
    loop {
        std::hint::spin_loop();
    }
}
fn parent_is(pid: i32) -> bool {
    unsafe { call(libc::SYS_getppid, 0, 0, 0) == pid as i64 }
}
fn death(sig: i32) -> bool {
    unsafe {
        call(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG as usize,
            sig as usize,
            0,
        ) == 0
    }
}
fn send(fd: i32, f: Frame) -> bool {
    let b = f.encode();
    unsafe {
        raw(
            libc::SYS_sendto,
            fd as usize,
            b.as_ptr() as usize,
            64,
            libc::MSG_NOSIGNAL as usize,
            0,
            0,
        ) == 64
    }
}
fn receive(fd: i32) -> Result<Option<Frame>, ()> {
    let mut b = [0u8; 65];
    let r = unsafe {
        raw(
            libc::SYS_recvfrom,
            fd as usize,
            b.as_mut_ptr() as usize,
            b.len(),
            libc::MSG_DONTWAIT as usize,
            0,
            0,
        )
    };
    if r == -(libc::EAGAIN as i64) || r == -(libc::EINTR as i64) {
        return Ok(None);
    }
    if r != 64 {
        return Err(());
    }
    Frame::decode(&b[..64]).map(Some).ok_or(())
}
fn nap(fd: i32) {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe {
        call(libc::SYS_poll, &mut p as *mut _ as usize, 1, 1);
    }
}
fn close_checked(fd: i32) -> bool {
    unsafe {
        call(libc::SYS_close, fd as usize, 0, 0);
        call(libc::SYS_fcntl, fd as usize, libc::F_GETFD as usize, 0) == -(libc::EBADF as i64)
    }
}
// Linux x86-64 kernel sigaction layout (libc's sigset_t is larger).
#[repr(C)]
struct Action {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}
fn reset_handlers() -> bool {
    for sig in 1..=64 {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        let handler = match sig {
            libc::SIGINT | libc::SIGQUIT | libc::SIGHUP | libc::SIGPIPE => 1,
            libc::SIGTERM | libc::SIGCHLD => signal as usize,
            _ => 0,
        };
        let a = Action {
            handler,
            flags: 0x04000000,
            restorer: producer_sigreturn as usize,
            mask: u64::MAX,
        };
        if unsafe {
            raw(
                libc::SYS_rt_sigaction,
                sig as usize,
                &a as *const _ as usize,
                0,
                8,
                0,
                0,
            )
        } < 0
        {
            return false;
        }
    }
    true
}
// Construct classic seccomp directly on the stack. Argument checks fail closed.
fn filter(fd: i32) -> bool {
    const LD: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const RET: u16 = 0x06;
    let mut p = [libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; 160];
    let mut n = 0;
    let mut add = |code, jt, jf, k| {
        p[n] = libc::sock_filter { code, jt, jf, k };
        n += 1;
    };
    add(LD, 0, 0, 4);
    add(JEQ, 1, 0, 0xc000003e);
    add(RET, 0, 0, 0x80000000);
    add(LD, 0, 0, 0);
    for sys in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
    ] {
        add(JEQ, 0, 4, sys as u32);
        add(LD, 0, 0, 16);
        add(JEQ, 0, 1, fd as u32);
        add(RET, 0, 0, 0x7fff0000);
        add(RET, 0, 0, 0x80000000);
    }
    add(JEQ, 0, 7, libc::SYS_clone as u32);
    add(LD, 0, 0, 16);
    add(JEQ, 0, 4, 17);
    add(LD, 0, 0, 20);
    add(JEQ, 0, 2, 0);
    add(RET, 0, 0, 0x7fff0000);
    add(RET, 0, 0, 0x80000000);
    add(RET, 0, 0, 0x80000000);
    for (sys, off, val) in [
        (libc::SYS_clock_gettime, 16, libc::CLOCK_MONOTONIC),
        (libc::SYS_prctl, 16, libc::PR_SET_PDEATHSIG),
        (libc::SYS_kill, 24, libc::SIGKILL),
    ] {
        add(JEQ, 0, 4, sys as u32);
        add(LD, 0, 0, off);
        add(JEQ, 0, 1, val as u32);
        add(RET, 0, 0, 0x7fff0000);
        add(RET, 0, 0, 0x80000000);
    }
    for sys in [
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        add(JEQ, 0, 1, sys as u32);
        add(RET, 0, 0, 0x7fff0000);
    }
    add(RET, 0, 0, 0x80000000);
    let prog = libc::sock_fprog {
        len: n as u16,
        filter: p.as_mut_ptr(),
    };
    unsafe {
        call(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS as usize, 1, 0) == 0
            && call(
                libc::SYS_prctl,
                libc::PR_SET_SECCOMP as usize,
                2,
                &prog as *const _ as usize,
            ) == 0
    }
}
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
/// Called only in the private raw-clone child while every signal is blocked.
pub(super) unsafe fn run(
    fd: i32,
    close: [i32; 5],
    count: usize,
    parent: i32,
    session: u64,
    boot_deadline: u64,
) -> ! {
    if !death(libc::SIGKILL) || !parent_is(parent) || !reset_handlers() {
        exit(120)
    }
    let h = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe {
        call(
            libc::SYS_capset,
            &h as *const _ as usize,
            data.as_ptr() as usize,
            0,
        )
    } < 0
    {
        exit(121)
    }
    if unsafe {
        raw(
            libc::SYS_prctl,
            libc::PR_CAP_AMBIENT as usize,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as usize,
            0,
            0,
            0,
            0,
        )
    } < 0
    {
        exit(121)
    }
    if !death(libc::SIGKILL) || !parent_is(parent) {
        exit(122)
    }
    #[cfg(test)]
    if HOST_CLOSE_PAUSE.load(Ordering::Relaxed) {
        unsafe {
            call(libc::SYS_poll, 0, 0, 500);
        }
    }
    for &slot in &close[..count] {
        if !close_checked(slot) {
            exit(123)
        }
    }
    let limit = libc::rlimit {
        rlim_cur: 1 << 30,
        rlim_max: 1 << 30,
    };
    if unsafe {
        call(
            libc::SYS_setrlimit,
            libc::RLIMIT_AS as usize,
            &limit as *const _ as usize,
            0,
        )
    } < 0
    {
        exit(124)
    }
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe {
        call(
            libc::SYS_setrlimit,
            libc::RLIMIT_CORE as usize,
            &no_core as *const _ as usize,
            0,
        )
    } < 0
    {
        exit(124)
    }
    if unsafe { call(libc::SYS_prctl, libc::PR_SET_DUMPABLE as usize, 0, 0) } < 0 {
        exit(124)
    }
    if !filter(fd) || !death(libc::SIGTERM) || !parent_is(parent) {
        exit(125)
    }
    let empty = 0u64;
    if unsafe {
        raw(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as usize,
            &empty as *const _ as usize,
            0,
            8,
            0,
            0,
        )
    } < 0
    {
        exit(126)
    }
    #[cfg(test)]
    if HOST_FORBIDDEN_SYSCALL.load(Ordering::Relaxed) {
        unsafe {
            call(libc::SYS_getuid, 0, 0, 0);
        }
    }
    let pid = unsafe { call(libc::SYS_getpid, 0, 0, 0) } as u64;
    let mut base = Frame {
        kind: HELLO,
        session,
        request: 0,
        deadline: boot_deadline,
        floor: 0,
        arg0: pid,
        arg1: parent as u64,
    };
    if STOP.load(Ordering::Relaxed)
        || !parent_is(parent)
        || monotonic() >= boot_deadline
        || !send(fd, base)
    {
        exit(127)
    }
    #[cfg(test)]
    if HOST_READY_DELAY.load(Ordering::Relaxed) {
        unsafe {
            call(libc::SYS_poll, 0, 0, 200);
        }
    }
    base.kind = READY;
    base.arg0 = count as u64;
    base.arg1 = 1;
    if !send(fd, base) {
        exit(127)
    }
    let mut last = 0u64;
    loop {
        if STOP.load(Ordering::Relaxed) || !parent_is(parent) {
            exit(0)
        }
        let f = match receive(fd) {
            Ok(Some(f)) => f,
            Ok(None) => {
                nap(fd);
                continue;
            }
            Err(_) => exit(128),
        };
        if f.session != session || f.request <= last || f.floor == 0 || f.deadline <= monotonic() {
            exit(129)
        }
        if f.kind == SHUTDOWN && f.arg0 == 0 && f.arg1 == 0 {
            let mut done = f;
            done.kind = DONE;
            if !send(fd, done) {
                exit(130)
            }
            exit(0)
        }
        if f.kind != SPAWN || f.arg0 >= 1024 || !(1..=2).contains(&f.arg1) || f.floor > monotonic()
        {
            exit(131)
        }
        last = f.request;
        let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_SET(f.arg0 as usize, &mut set);
        }
        let saved_ok = unsafe {
            call(
                libc::SYS_sched_getaffinity,
                0,
                std::mem::size_of_val(&saved),
                &mut saved as *mut _ as usize,
            )
        } >= 0;
        let pin = saved_ok
            && unsafe {
                call(
                    libc::SYS_sched_setaffinity,
                    0,
                    std::mem::size_of_val(&set),
                    &set as *const _ as usize,
                )
            } == 0;
        let birth = monotonic();
        let child = if pin {
            unsafe { raw(libc::SYS_clone, 17, 0, 0, 0, 0, 0) }
        } else {
            -(libc::EINVAL as i64)
        };
        if child == 0 {
            if !death(libc::SIGKILL) || !parent_is(pid as i32) {
                exit(132)
            }
            unsafe {
                call(libc::SYS_close, fd as usize, 0, 0);
            }
            #[cfg(test)]
            if HOST_HELPER_HOLD.load(Ordering::Relaxed) {
                unsafe {
                    call(libc::SYS_poll, 0, 0, 200);
                }
            }
            exit(0)
        }
        let restored = !saved_ok
            || unsafe {
                call(
                    libc::SYS_sched_setaffinity,
                    0,
                    std::mem::size_of_val(&saved),
                    &saved as *const _ as usize,
                )
            } == 0;
        #[cfg(test)]
        let restored = restored && !HOST_RESTORE_FAILURE.load(Ordering::Relaxed);
        #[cfg(test)]
        if child > 0 {
            let word =
                HOST_CHILD_PID_WORD.load(Ordering::Relaxed) as *const std::sync::atomic::AtomicU32;
            if !word.is_null() {
                unsafe {
                    (*word).store(child as u32, Ordering::Release);
                }
            }
            if HOST_BEFORE_CHILD_EXIT.load(Ordering::Relaxed) {
                exit(133);
            }
        }
        let mut reply = f;
        if child < 0 {
            reply.kind = FAILED;
            reply.arg0 = 1;
            reply.arg1 = (-child) as u64;
            if !send(fd, reply) {
                exit(134)
            }
            if !restored {
                exit(133);
            }
            continue;
        }
        reply.kind = CHILD;
        reply.arg0 = child as u64;
        reply.arg1 = f.arg0;
        reply.floor = birth;
        let delivered = send(fd, reply);
        // Even restoration failure still owns the cloned helper. Announce its
        // actual identity if possible, kill and positively wait before exiting.
        let mut abandon = !restored || !delivered;
        let mut kill_sent = false;
        let mut approved = false;
        let mut protocol_failed = false;
        loop {
            abandon |=
                STOP.load(Ordering::Relaxed) || !parent_is(parent) || monotonic() >= f.deadline;
            if !abandon {
                match receive(fd) {
                    Ok(Some(a)) => {
                        if a.session != session
                            || a.request != f.request
                            || a.deadline != f.deadline
                            || a.floor != f.floor
                        {
                            abandon = true;
                            protocol_failed = true;
                        } else if a.kind == OBSERVED
                            && a.arg0 == f.arg0
                            && (1..=2).contains(&a.arg1)
                        {
                            approved = true
                        } else if a.kind == ABORT && a.arg0 == 1 && a.arg1 == 0 {
                            abandon = true
                        } else {
                            abandon = true;
                            protocol_failed = true
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        abandon = true;
                        protocol_failed = true
                    }
                }
            }
            if abandon && !kill_sent {
                let r = unsafe { call(libc::SYS_kill, child as usize, libc::SIGKILL as usize, 0) };
                if r == 0 {
                    kill_sent = true
                } else if r != -(libc::ESRCH as i64) {
                    exit(135)
                }
            }
            if approved || abandon {
                let passive = abandon && kill_sent;
                let all = u64::MAX;
                let mut saved = 0u64;
                if passive
                    && unsafe {
                        raw(
                            libc::SYS_rt_sigprocmask,
                            libc::SIG_SETMASK as usize,
                            &all as *const _ as usize,
                            &mut saved as *mut _ as usize,
                            8,
                            0,
                            0,
                        )
                    } < 0
                {
                    exit(139)
                }
                let mut status = 0i32;
                let r = unsafe {
                    raw(
                        libc::SYS_wait4,
                        child as usize,
                        &mut status as *mut _ as usize,
                        libc::WNOHANG as usize,
                        0,
                        0,
                        0,
                    )
                };
                if passive && r == 0 {
                    // Atomic unmask-and-wait avoids losing SIGCHLD between the
                    // exact WNOHANG step and a passive cleanup wake.
                    // Cleanup needs no more control messages. Excluding the
                    // control FD prevents persistent EOF/HUP from repeatedly
                    // waking an otherwise passive exact-child wait.
                    unsafe {
                        raw(libc::SYS_ppoll, 0, 0, 0, &saved as *const _ as usize, 8, 0);
                    }
                }
                if passive
                    && unsafe {
                        raw(
                            libc::SYS_rt_sigprocmask,
                            libc::SIG_SETMASK as usize,
                            &saved as *const _ as usize,
                            0,
                            8,
                            0,
                            0,
                        )
                    } < 0
                {
                    exit(139)
                }
                if r == child {
                    reply = f;
                    reply.kind = REAPED;
                    reply.arg0 = child as u64;
                    reply.arg1 = status as u32 as u64;
                    if !send(fd, reply) {
                        exit(136)
                    }
                    if !restored {
                        exit(133);
                    }
                    if protocol_failed {
                        exit(138)
                    }
                    break;
                }
                if r < 0 && r != -(libc::EINTR as i64) {
                    exit(137)
                }
                if passive {
                    continue;
                }
            }
            if !CHILD_SIGNAL.swap(false, Ordering::Relaxed) {
                nap(fd);
            }
        }
    }
}
