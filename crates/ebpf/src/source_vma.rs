// SPDX-License-Identifier: GPL-2.0-only
//! Finite current-task source snapshot. No maps, admission or publication live here.
//!
//! The caller owns ADMIT, exact domain/borrow/epoch/guard checks and the charged
//! atomic per-CPU iterator slot, held until this call returns. A table borrow must
//! remain valid throughout the snapshot and the caller's revalidation. The loader
//! must validate the running kernel's exact kfuncs, six field types/extents and
//! base-page shift, and patch only the reserved sites below before use.
use core::ffi::c_void;

#[derive(Clone, Copy)]
pub enum Policy {
    Anchor,
    Code,
}

/// Private equality evidence, meaningful only against a retained actual anchor
/// and file owner. Never export, hash, dereference or treat inode as ownership.
#[derive(Clone, Copy)]
pub struct SourceLocation {
    pub inode: u64,
    pub file_offset: u64,
}

#[repr(C, align(8))]
struct Iter {
    opaque: u64,
}

// These flags are the native Linux vm_flags semantics. Loader capability checks
// must admit these semantics; they are not member offsets or kernel layouts.
const VM_READ: u64 = 1;
const VM_WRITE: u64 = 2;
const VM_EXEC: u64 = 4;
const VM_SHARED: u64 = 8;

#[inline(always)]
fn source_offset(
    start: u64,
    end: u64,
    pgoff: u64,
    flags: u64,
    address: u64,
    policy: Policy,
    page_shift: u32,
) -> Option<u64> {
    if address < start || address >= end || page_shift == 0 || page_shift >= 64 {
        return None;
    }
    let (required, forbidden) = match policy {
        Policy::Anchor => (VM_READ, VM_WRITE | VM_EXEC | VM_SHARED),
        Policy::Code => (VM_EXEC, VM_WRITE | VM_SHARED),
    };
    if flags & required == 0 || flags & forbidden != 0 {
        return None;
    }
    // checked_shl alone checks the shift count, NOT shifted-out high bits.
    if pgoff > (u64::MAX >> page_shift) {
        return None;
    }
    (pgoff << page_shift).checked_add(address.checked_sub(start)?)
}

/// Read exactly one admitted 64-bit field. Volatile offset materialization keeps
/// each marker as one MOV64 immediate, including zero-offset patched fields;
/// it prevents LLVM from folding the marker into unchecked address arithmetic.
#[inline(always)]
unsafe fn field(base: u64, marker: u64) -> Option<u64> {
    let offset = core::ptr::read_volatile(&marker);
    let address = base.checked_add(offset)?;
    address.checked_add(7)?;
    let mut value = 0u64;
    let read: unsafe extern "C" fn(*mut u64, u32, *const c_void) -> i64 =
        core::mem::transmute(113usize); // bpf_probe_read_kernel
    if read(&mut value, 8, address as *const c_void) != 0 {
        return None;
    }
    Some(value)
}

#[inline(always)]
unsafe fn inspect(
    vma: *mut c_void,
    address: u64,
    policy: Policy,
    page_shift: u32,
) -> Option<SourceLocation> {
    if vma.is_null() {
        return None;
    }
    let base = vma as u64;
    // Ordered finite patch identities: vm_start/end/pgoff/flags/file, f_inode.
    // Exactly one MOV64_IMM per identity; never patch arbitrary constants.
    let start = field(base, 0x6f001)?;
    let end = field(base, 0x6f002)?;
    let pgoff = field(base, 0x6f003)?;
    let flags = field(base, 0x6f004)?;
    let file_offset = source_offset(start, end, pgoff, flags, address, policy, page_shift)?;
    let file = field(base, 0x6f005)?;
    if file == 0 {
        return None;
    }
    let inode = field(file, 0x6f006)?;
    if inode == 0 {
        return None;
    }
    Some(SourceLocation { inode, file_offset })
}

/// Obtain one coherent iterator-owned snapshot, never a persistent VA census.
///
/// # Safety
/// Caller/loader must satisfy the module preconditions before invocation. In
/// particular these marker calls are not callable helpers until exactly patched.
/// Actual retained file/anchor custody must outlive the returned equality token.
/// A non-inlined single body keeps one set of finite patch sites for all callers.
#[inline(never)]
#[no_mangle]
pub unsafe fn current_source_at(
    address: u64,
    policy: Policy,
    page_shift: u32,
    output: &mut SourceLocation,
) -> bool {
    let task: unsafe extern "C" fn() -> *mut c_void = core::mem::transmute(158usize);
    // Raw CALL src=0 markers; loader changes src to BPF_PSEUDO_KFUNC_CALL (2)
    // and imm to the exact validated running-vmlinux FUNC ID, with off=0.
    let new: unsafe extern "C" fn(*mut Iter, *mut c_void, u64) -> i32 =
        core::mem::transmute(0x7f001usize);
    let next: unsafe extern "C" fn(*mut Iter) -> *mut c_void = core::mem::transmute(0x7f002usize);
    let destroy: unsafe extern "C" fn(*mut Iter) = core::mem::transmute(0x7f003usize);
    let mut it = Iter { opaque: 0 };
    let rc = new(&mut it, task(), address);
    let vma = next(&mut it);
    let result = if rc == 0 {
        inspect(vma, address, policy, page_shift)
    } else {
        None
    };
    // Even failed new creates verifier-owned iterator state. The selected kernel
    // leaves null internal data on failure, making next/destroy safe. Every path
    // after new reaches the one destroy, including failed reads and arithmetic.
    // Force pointer-derived nullness and all result fields to scalar stack data
    // BEFORE destroy: LLVM must not defer a lifetime-sensitive use until after it.
    let (present, inode, offset) = match result {
        Some(location) => (1u64, location.inode, location.file_offset),
        None => (0, 0, 0),
    };
    let mut saved_present = 0u64;
    let mut saved_inode = 0u64;
    let mut saved_offset = 0u64;
    core::ptr::write_volatile(&mut saved_present, present);
    core::ptr::write_volatile(&mut saved_inode, inode);
    core::ptr::write_volatile(&mut saved_offset, offset);
    destroy(&mut it);
    let present = core::ptr::read_volatile(&saved_present);
    let inode = core::ptr::read_volatile(&saved_inode);
    let file_offset = core::ptr::read_volatile(&saved_offset);
    if present == 0 {
        false
    } else {
        *output = SourceLocation { inode, file_offset };
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Literal cases catch hole acceptance, permission widening and wrapping
    // page multiplication/addition; they do not simulate kernel reads.
    #[test]
    fn containment_permissions_and_checked_file_offset() {
        let cases = [
            (0x1000, 0x2000, 3, 4, 0x1234, Policy::Code, 12, Some(0x3234)),
            (0x1000, 0x2000, 0, 1, 0x1000, Policy::Anchor, 12, Some(0)),
            (
                0x1000,
                0x2000,
                0,
                1,
                0x1fff,
                Policy::Anchor,
                12,
                Some(0xfff),
            ),
            (0x1000, 0x2000, 0, 1, 0x2000, Policy::Anchor, 12, None),
            (0x1000, 0x2000, 0, 4, 0xfff, Policy::Code, 12, None),
            (0x1000, 0x1000, 0, 4, 0x1000, Policy::Code, 12, None),
            (0x2000, 0x1000, 0, 4, 0x2000, Policy::Code, 12, None),
            (0x1000, 0x2000, 0, 0, 0x1000, Policy::Code, 12, None),
            (0x1000, 0x2000, 0, 6, 0x1000, Policy::Code, 12, None),
            (0x1000, 0x2000, 0, 12, 0x1000, Policy::Code, 12, None),
            (0x1000, 0x2000, 0, 5, 0x1000, Policy::Code, 12, Some(0)),
            (0x1000, 0x2000, 0, 0, 0x1000, Policy::Anchor, 12, None),
            (0x1000, 0x2000, 0, 3, 0x1000, Policy::Anchor, 12, None),
            (0x1000, 0x2000, 0, 5, 0x1000, Policy::Anchor, 12, None),
            (0x1000, 0x2000, 0, 9, 0x1000, Policy::Anchor, 12, None),
            (0, 2, 1, 4, 0, Policy::Code, 64, None),
            (0, 2, 1, 4, 0, Policy::Code, 0, None),
            (0, 2, 2, 4, 0, Policy::Code, 63, None),
            (0, 2, 1, 4, 1, Policy::Code, 63, Some(0x8000000000000001)),
            (
                0,
                8192,
                0xfffffffffffff,
                4,
                4095,
                Policy::Code,
                12,
                Some(u64::MAX),
            ),
            (0, 8192, 0xfffffffffffff, 4, 4096, Policy::Code, 12, None),
            (0, 2, 0x10000000000000, 4, 0, Policy::Code, 12, None),
            (
                0x1000,
                0x2000,
                3,
                0x10004,
                0x1234,
                Policy::Code,
                12,
                Some(0x3234),
            ),
        ];
        for (index, (start, end, pgoff, flags, address, policy, shift, want)) in
            cases.into_iter().enumerate()
        {
            assert_eq!(
                source_offset(start, end, pgoff, flags, address, policy, shift),
                want,
                "case {index}"
            );
        }
    }
}
