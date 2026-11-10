<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Container image

The `osslscope:0.5.0` image runs the same root-owned `/usr/local` prefix
install as a host install, under the non-root `osslscope` user by
default with file capabilities (host-observer mode runs as
root-in-container; see Mode 2).
Both supported modes drop every capability and add back only named ones;
no supported recipe uses `--privileged`, `CAP_SYS_ADMIN`, host networking,
or `NoNewPrivileges` (which would void the file capabilities).

Support floor (same as host): Linux x86-64, kernel 6.9+ (feature-probed,
not `uname`), host BTF at `/sys/kernel/btf/vmlinux`, cgroup v2. Reports
stay PARTIAL (exit 3); see [usage](usage.md) for the contract.

## Build

From the product repo root (a clean checkout — the install receipt binds
to the committed source identity and the resolver refuses dirty builds):

```sh
docker build -t osslscope:0.5.0 .
```

The builder stage installs the pinned toolchains (rustup 1.29.3
bootstrap, SHA-256 verified; Rust 1.88.0, nightly-2026-05-20 with
`rust-src`, bpf-linker 0.10.4) and runs `./scripts/build-dev.sh
--release` plus `./scripts/install-dev.sh --prefix /usr/local`.
The runtime stage is slim Debian with `openssl` (the demo workload
— the Job manifest's default args run `openssl dgst`), the prefix,
`cap_bpf,cap_perfmon=ep` file caps on the root-owned binary, and
the `osslscope` user (stable uid 65532). `libcap2-bin` exists only
for the one `setcap` at build time and is purged after. 0.x images
ship no signatures, SLSA provenance, or SBOM — verify by digest
after pinning. Build from a real
checkout: a linked `git worktree` ships a `.git` pointer file whose
target lies outside the build context, which yields an
unknown-source install that tracing refuses (build-identity
semantics; no worktree build log retained in the lane); a full
clone builds clean (`product: e112a5e (dirty=false)` at the
Task-2 base — your build shows its own HEAD — v2 receipt).

Minimum capabilities: the binary carries file caps, so the container
bounding set must grant at least `BPF`+`PERFMON` even for `--help` —
with `--cap-drop ALL` alone, `exec` fails with `operation not
permitted` (file-caps bounding-set semantics; the drill transcripts
below all run with the granting tier).

## Seccomp

`deploy/seccomp-osslscope.json` is the Docker default profile (moby
v28.0.0) plus one unconditional `bpf` allowance. Current Docker
defaults already allow `bpf`/`perf_event_open` when the container holds
`CAP_BPF`/`CAP_PERFMON`; the shipped profile additionally covers
engines whose defaults lack that cap-conditional `bpf` allowance. A spike with
`perf_event_open` denied still attached and observed (see below), so the
profile adds no `perf_event_open` allowance. `seccomp=unconfined` is a
diagnostic fallback only, never the default recipe.

## Mode 1: owned workload (SUPPORTED)

The container traces a workload it launches itself. Minimum working
tier, proven by spike: user `osslscope`, caps `BPF`+`PERFMON`, shipped
seccomp profile.

```sh
docker run --rm --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  osslscope:0.5.0 report --duration 5 --format json run -- openssl dgst -sha256 /dev/null
```

Expected: exit 3 PARTIAL with nonzero observed counts. Drill output
(shipped image, shipped seccomp profile):

```text
$ docker run --rm --cap-drop ALL --cap-add BPF --cap-add PERFMON \
    --security-opt seccomp=deploy/seccomp-osslscope.json \
    osslscope:0.5.0 report --duration 5 --format json run -- openssl dgst -sha256 /dev/null
osslscope: focused callbacks attached (pid=7, sites=2780)
osslscope: partial evidence (11 gaps: unknown-denominator, …)
exit code: 3
```

`api_activity` excerpt from the JSON report (one of the observed APIs;
totals `entries=2 observed_success=2`):

```json
{
 "api": 20,
 "entries": 2,
 "observed_failure": 0,
 "observed_success": 2,
 "unsupported": 0,
 "verification_mismatch": 0,
 "gaps": {…}
}
```
(`…` marks the trimmed `gaps` object — the row carries seven fields.)

Spike evidence (throwaway image, same prefix): non-root file caps
attached 2780 sites (repeated); a root run attached 2855 with
identical entries=2 counts — run-to-run site variance, not a user
gap. A `bpf`-denied seccomp variant attached nothing (zeros),
proving the filter is load-bearing; a `perf_event_open`-denied
variant stayed green, so the shipped profile adds no
`perf_event_open` allowance.

## Mode 2: host observer (SUPPORTED, root-in-container)

The container observes a host-visible PID. Minimum working tier, proven
by spike: user `root` (`--user root`: the image defaults to
`osslscope`), caps `BPF`+`PERFMON`+`SYS_PTRACE`+`CHECKPOINT_RESTORE`+
`DAC_READ_SEARCH`, shipped seccomp profile, `apparmor=unconfined`,
read-only mounts of `/sys/kernel/btf`, `/sys/fs/cgroup` and
`/sys/kernel/security`. Two findings force this shape: the stock
`docker-default` AppArmor profile denies ptrace reads, so caps alone
leave `/proc/PID/exe` and `/proc/PID/maps` unreadable
(`Permission denied` as container root); and a non-root observer
stays exit-4 FATAL because the file caps grant only BPF+PERFMON while
foreign-UID verification needs effective PTRACE plus the verify caps
(carrying all five as file caps is not an option: file caps outside
the container bounding set fail `exec`, as the `--cap-drop ALL` probe
below shows, so a 5-cap binary would break the owned mode's 2-cap
tier).

```sh
docker run --rm --user root --pid=host \
  --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE \
  --cap-add CHECKPOINT_RESTORE --cap-add DAC_READ_SEARCH \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  osslscope:0.5.0 doctor --format json
```

Expected: exit 0 with osslscope-silent stderr (the lane's dockerd
prints one `WARNING: IPv4 forwarding is disabled. Networking will
not work.` line — the lane runs `--iptables=false --bridge=none`;
real hosts with networking show fully silent stderr). Drill output
(shipped image, shipped seccomp profile, dockerd WARNING trimmed):

```text
$ docker run --rm --user root --pid=host \
    --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE \
    --cap-add CHECKPOINT_RESTORE --cap-add DAC_READ_SEARCH \
    --security-opt apparmor=unconfined \
    --security-opt seccomp=deploy/seccomp-osslscope.json \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /sys/kernel/security:/sys/kernel/security:ro \
    osslscope:0.5.0 doctor --format json
{"capabilities":{"bpf":"available","count_companion":"available","count_load":"available","inventory":"available","observation_companion":"available","observation_load":"available","pid_namespace":"available","ring_buffer":"available","uprobe_multi":"available","user_read":"available"},"execution":"not_observed","historical_activation":"unknown","record":"doctor","schema_version":"osslscope.focused.doctor.v1"}
exit code: 0
```

Then, against a live host PID:

```sh
docker run --rm --user root --pid=host \
  --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE \
  --cap-add CHECKPOINT_RESTORE --cap-add DAC_READ_SEARCH \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  osslscope:0.5.0 report --pid "$HOST_PID" --duration 5 --format json
```

Expected: exit 3 PARTIAL with nonzero observed counts. Drill output
(workload: a host `python3` hashlib loop whose libcrypto was staged on
tmpfs; totals `entries=609 observed_success=609` over 2849 sites):

```text
osslscope: focused callbacks attached (pid=678, sites=2849)
osslscope: partial evidence (11 gaps: unknown-denominator, …)
exit code: 3
```

Resolve `$HOST_PID` in host PID coordinates (the observer refuses PID
namespace mismatch). `run --` inside the container keeps mode-1
semantics; `--pid` selects one host incarnation only.

## Verify the bounding set

`docker inspect` must show `Privileged: false` and exactly the
documented caps. Owned mode (12 KB embedded seccomp profile abridged;
verified present and identical to the shipped file):

```text
Privileged=false CapAdd=[CAP_BPF CAP_PERFMON] CapDrop=[ALL] User=osslscope
SecurityOpt=[seccomp=<shipped deploy/seccomp-osslscope.json, 12 KB>]
```

Host-observer mode (same abridgement; mounts verified
`/sys/fs/cgroup`, `/sys/kernel/btf`, `/sys/kernel/security`, all `ro`):

```text
Privileged=false CapAdd=[CAP_BPF CAP_CHECKPOINT_RESTORE CAP_DAC_READ_SEARCH CAP_PERFMON CAP_SYS_PTRACE]
CapDrop=[ALL] User=root PidMode=host
SecurityOpt=[apparmor=unconfined seccomp=<shipped deploy/seccomp-osslscope.json, 12 KB>]
```
(`label=disable` lane SELinux artifact trimmed from the pasted
`SecurityOpt`.)

## Limits

- No first-call guarantee, warm zero counts, and overlay locator gaps
  apply as on host ([usage](usage.md)); prefer `run --` over `--pid`
  for short-lived targets.
- Foreign `--pid` attach against an overlay-backed libcrypto observes
  nothing (exit 3, zero counts, no attach line): in a kernel-shared
  guest lane whose root is overlayfs, stage the workload's libcrypto
  on tmpfs for observer drills. Owned `run --` mode attaches to
  overlay libcrypto normally (2780 sites above). Real hosts on
  btrfs/ext4/xfs are unaffected.
- `apparmor=unconfined` is required for host-observer (the stock
  `docker-default` profile denies ptrace reads) and only there; owned
  mode keeps the default profile. A custom AppArmor profile allowing
  ptrace read is untested and not shipped.
- Any `--privileged` invocation is unsupported. `seccomp=unconfined`
  is a diagnostic fallback only, never a recipe (same posture as
  above): if a supported recipe fails where unconfined works,
  report it with the denial instead of shipping unconfined. On
  Kubernetes there is no `seccomp=unconfined` recipe at all.
