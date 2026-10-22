//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-private syscall seam. It neither publishes nor clones count FDs.
use super::protocol::BackingIdentity;
use crate::loader::MapSpecLite;
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Instant;

// The remaining methods are the binding interfaces for the serial attach/read
// tasks. The live implementation is real even before those handlers are wired.
#[allow(dead_code)]
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
            device: stat.st_dev,
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
        // BPF_MAP_GET_NEXT_KEY uses the same 32-byte bpf_attr map-element union.
        #[repr(C)]
        struct NextAttr {
            map_fd: u32,
            pad: u32,
            key: u64,
            next: u64,
            flags: u64,
        }
        let mut attr = NextAttr {
            map_fd: fd.as_raw_fd() as u32,
            pad: 0,
            key: key.map_or(0, |k| k.as_ptr() as u64),
            next: next.as_mut_ptr() as u64,
            flags: 0,
        };
        // SAFETY: the caller proves map/key sizes. attr and buffers remain live
        // through this synchronous syscall, command 4 is BPF_MAP_GET_NEXT_KEY.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                4,
                &mut attr as *mut NextAttr,
                std::mem::size_of::<NextAttr>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
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
