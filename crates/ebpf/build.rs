// SPDX-License-Identifier: GPL-2.0-only
//! Emit `--cfg bpf_target_arch="..."` for BPF register-layout selection.
//!
//! This replicates `aya_build::emit_bpf_target_arch_cfg` with std only so
//! the crate needs no new build dependency: the observed kernel's register
//! layout is the build host's architecture (BPF observes the host it loads
//! on), overridable via `AYA_BPF_TARGET_ARCH` for cross builds, exactly
//! like aya callers. Only the U1 copied-role join reads the trap IP
//! (`x86_64` `pt_regs.rip`); every other arch fails that join closed.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"aarch64\", \"arm\", \"loongarch64\", \"mips\", \"mips64\", \"powerpc64\", \"riscv64\", \"s390x\", \"x86_64\"))");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=AYA_BPF_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=HOST");
    if std::env::var_os("CARGO_CFG_BPF_TARGET_ARCH").is_some() {
        return;
    }
    let arch = std::env::var("AYA_BPF_TARGET_ARCH")
        .ok()
        .filter(|v| !v.is_empty());
    let arch = arch.or_else(|| {
        std::env::var("HOST").ok().map(|host| {
            host.split_once('-')
                .map_or(host.clone(), |(arch, _)| arch.to_string())
        })
    });
    if let Some(arch) = arch {
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    }
}
