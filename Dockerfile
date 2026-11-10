# SPDX-License-Identifier: GPL-3.0-or-later
# osslscope limited-capability container image (0.5.0).
#
# Multi-stage source build. The builder compiles the pinned toolchains
# (Rust 1.88.0 + nightly-2026-05-20 + bpf-linker 0.10.4) and runs the
# product's own build + prefix-install scripts, so the runtime prefix
# carries a manifest-verified install receipt for /usr/local. The
# runtime stage is a slim Debian with file capabilities on the
# root-owned binary: tracing needs container caps (BPF+PERFMON
# minimum, 5-cap set for host-observer), never --privileged.
# See docs/container.md for the supported run recipes.

# Pinned base (Debian trixie slim). Re-pin deliberately, never float.
ARG BASE=debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

FROM ${BASE} AS builder
ENV DEBIAN_FRONTEND=noninteractive
# Builder apt set deliberately unpinned (policy): trixie stable via the
# base-image keyring + TLS, and builder layers never ship. Re-pin the
# BASE digest (top of file) to move the builder forward as one unit.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl ca-certificates git python3 \
    file binutils coreutils sed diffutils \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH CARGO_BUILD_JOBS=2
# Pinned rustup bootstrap (never `curl|sh` float): versioned rustup-init
# from the immutable static.rust-lang.org archive, SHA-256 verified
# before execution. Re-pin deliberately with the toolchains below.
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
RUN curl --proto '=https' --tlsv1.2 -sSf -o /tmp/rustup-init \
    "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain 1.88.0 \
    && rm /tmp/rustup-init \
    && rustup toolchain install 1.88.0 --profile minimal \
    && rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src \
    && cargo +1.88.0 install --locked bpf-linker --version 0.10.4 \
    && rustc --version && bpf-linker --version
WORKDIR /src/osslscope
# The build context is the product repo root INCLUDING .git: build-dev.sh
# binds the install receipt to the committed source identity, and the
# resolver refuses dirty/unknown-source installs for tracing.
COPY . .
RUN ./scripts/build-dev.sh --release \
    && ./scripts/install-dev.sh --prefix /usr/local \
    && /usr/local/bin/osslscope --version

FROM ${BASE} AS runtime
ENV DEBIAN_FRONTEND=noninteractive
# Runtime apt set version-pinned (trixie, re-pin with BASE).
# libcap2-bin exists only for the one setcap below and is purged after.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcap2-bin=1:2.75-10+deb13u1+b3 openssl=3.5.7-1~deb13u3 ca-certificates=20250419+deb13u1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 65532 -s /usr/sbin/nologin osslscope
COPY --from=builder --chown=root:root /usr/local/bin/osslscope /usr/local/bin/osslscope
COPY --from=builder --chown=root:root /usr/local/lib/osslscope/ /usr/local/lib/osslscope/
COPY --from=builder --chown=root:root /usr/local/share/osslscope/ /usr/local/share/osslscope/
COPY --from=builder --chown=root:root /usr/local/share/doc/osslscope/ /usr/local/share/doc/osslscope/
# File caps (not setuid): the binary gains BPF+PERFMON only when the
# container bounding set grants them. Never add NoNewPrivileges
# (it voids file capabilities). Stable uid 65532 (mirrored by the
# Job manifest's numeric runAsUser — kubelet cannot verify a
# name-based image USER).
RUN setcap 'cap_bpf,cap_perfmon=ep' /usr/local/bin/osslscope \
    && getcap /usr/local/bin/osslscope \
    && apt-get purge -y libcap2-bin \
    && apt-get autoremove -y
ENV PATH=/usr/local/bin:$PATH
USER osslscope
ENTRYPOINT ["osslscope"]
