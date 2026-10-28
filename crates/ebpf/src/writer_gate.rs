// SPDX-License-Identifier: GPL-2.0-only
//! Legacy 28-byte map definition: no object BTF and no inner pointer access.
use core::cell::UnsafeCell;
#[repr(transparent)]
struct Outer(UnsafeCell<[u32; 7]>);
// The kernel owns this storage; the program only passes its relocation to lookup.
unsafe impl Sync for Outer {}
#[aya_ebpf::macros::map]
static ADMIT: Outer = Outer(UnsafeCell::new([12, 4, 4, 1, 0, 0, 0]));
#[inline(always)]
pub fn admitted() -> bool {
    let zero = 0u32;
    // The result is consumed only for nullness, never dereferenced or exported.
    !unsafe {
        aya_ebpf::helpers::bpf_map_lookup_elem(
            ADMIT.0.get().cast(),
            core::ptr::addr_of!(zero).cast(),
        )
    }
    .is_null()
}
