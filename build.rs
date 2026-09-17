//! P1-0: build script placeholder. The eBPF object build hookup
//! (nightly shell-out + OUT_DIR copy, p11scope build.rs precedent)
//! lands at P2 when `crates/ebpf` is promoted from the spike.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=crates/ebpf/src");
}
