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
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl ca-certificates git python3 \
    file binutils coreutils sed diffutils \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH CARGO_BUILD_JOBS=2
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.88.0 \
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcap2-bin openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin osslscope
COPY --from=builder --chown=root:root /usr/local/bin/osslscope /usr/local/bin/osslscope
COPY --from=builder --chown=root:root /usr/local/lib/osslscope/ /usr/local/lib/osslscope/
COPY --from=builder --chown=root:root /usr/local/share/osslscope/ /usr/local/share/osslscope/
COPY --from=builder --chown=root:root /usr/local/share/doc/osslscope/ /usr/local/share/doc/osslscope/
# File caps (not setuid): the binary gains BPF+PERFMON only when the
# container bounding set grants them. Never add NoNewPrivileges
# (it voids file capabilities).
RUN setcap 'cap_bpf,cap_perfmon=ep' /usr/local/bin/osslscope \
    && getcap /usr/local/bin/osslscope
ENV PATH=/usr/local/bin:$PATH
USER osslscope
ENTRYPOINT ["osslscope"]
