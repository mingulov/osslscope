//! Key/event structs shared between `crates/ebpf` and userspace.
//! The key-id struct is owned here (P2). `no_std`-compatible by
//! construction; the `user` feature gates userspace-only impls.
#![no_std]
