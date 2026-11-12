<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Discover OpenSSL-compatible libraries, provider modules and consumers, then
observe public provider interfaces and count entries at learned callback sites
for selected processes or automatically discovered watched scopes. Normal workflows
need no enrolled library profile,
manual offsets or application changes.

**v0.6.0 RnD release (initial public 0.x).** Honest PARTIAL-only
observation on one declared lane (table below): short owned commands,
warm processes and sampled watched scopes expose physical callback
entries and separate public API activity. Reports stay PARTIAL,
algorithm checks stay inconclusive on Unknown-only evidence, and no
definite algorithm/provider count or CBOM asset is claimed. Start with
the [quickstart](docs/quickstart.md). The [v0.4.0 alpha
notes](docs/release-v0.4.0.md) and the [v0.3.0 release
record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
retain their historical artifact-specific scope.

## Support matrix (0.5.0 lane)

| Requirement | Lane |
| --- | --- |
| Architecture | x86-64 only (ARM64 deferred) |
| Kernel | 6.9+, feature-probed (kprobe-load + ringbuf + uprobe-multi + `probe_read_user`); the release number is informational only |
| BTF | `/sys/kernel/btf/vmlinux` readable |
| Cgroup | v2 hierarchy |
| OpenSSL | Stock 3.5.x (3.0.x/4.x matrix deferred; the pinned 4.0.3 note is unqualified) |
| Owned `run --` caps | `CAP_BPF` + `CAP_PERFMON` (file caps on a root-owned prefix; containers: `--cap-drop ALL` + add `BPF,PERFMON`) |
| Foreign `--pid`/observer caps | Above + `CAP_SYS_PTRACE` + `CAP_CHECKPOINT_RESTORE` + `CAP_DAC_READ_SEARCH` (5-cap set, matches the systemd unit; containers run root-in-container with `apparmor=unconfined`) |
| Never in supported recipes | `--privileged`, `CAP_SYS_ADMIN`, host networking, `NoNewPrivileges` (voids file caps), `seccomp=unconfined` |

**Privilege warning.** Tracing needs BPF/perf rights; the app never
grants capabilities or changes kernel/security settings, and LSM,
seccomp, lockdown, namespace policy or target access can deny
operations despite capability bits. A user-owned `$HOME/.local`
install is passive-discovery only: placing file capabilities on a
user-owned binary does not create a tracing install — automatic
companion selection refuses it. The tracing recipe is a root-owned
prefix (`/usr` from packages, `/usr/local` from source) plus the two
file capabilities; see [install](docs/install.md).

**Measured cost (one number).** Tracing cut a stock SHA-256 hot loop's
throughput by **5.425×** (median baseline/observed ratio on the
v0.5.0 candidate; [campaign and
limits](docs/overhead-matrix.md#v050-candidate-repeat-t64d)). The older
4.66× figure is the published v0.4.0-tree measurement; the same
campaign re-ran a rebuilt v0.4.0 control at 4.661 (inside the published
4.637–4.699 range), validating machine and method — the +0.76× delta
is qualified-attributed to the larger observed API surface, not to
method drift. Tight loops can be expensive; no per-call or rate bound
is claimed.

## Discover, select, observe

Build the host CLI with `cargo build --locked --bin osslscope` for passive
inventory. Tracing additionally needs the source-built BPF companions and
BPF/perf privileges; follow [build](docs/build.md) and [install](docs/install.md).
Use actual host-visible PIDs and file paths:

```sh
osslscope scan --json
osslscope scan --watch --interval 1 --duration 30 --json
osslscope scan --watch --observe-crypto --duration 30
osslscope scan --cgroup /sys/fs/cgroup/example.service --json
osslscope inspect --pid 1234 --json
osslscope inspect --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
osslscope doctor --format json
osslscope report --pid 1234 --duration 30 --format json --out report.json --cbom bom.json
osslscope check --pid 1234 --duration 30 --require-executed SHA256
```

Scan/watch narrows PID, cgroup and supplied-module selectors by intersection.
For [Docker/kind](docs/usage.md#host-side-container-workflows), independently
resolve the workload in host PID/cgroup coordinates, inventory it, then pass
one selected PID to report/check, or watch the scope with `--observe-crypto`.
Report/check cover one process incarnation and its threads. Crypto watch streams
separate per-incarnation documents as eligible processes enter and leave the
sampled scope; it never creates a cross-process aggregate.

Passive discovery uses ordinary procfs/filesystem access and loads no supplied
module. Add `--observe-providers` to a PID scan/watch or PID inspection for
bounded public lifecycle/query observation. Report/check automatically use the
installed `osslscope-provider-observation` and `osslscope-focused-count` pair.
Doctor checks inventory, namespace and companion integrity and performs
scanner-owned functional BPF load/self-attachment controls. Target attachment
and access remain scope dependent.

## Interpret the evidence

ELF interfaces and mappings establish metadata inventory, not activation or
execution. Public queries advertise callbacks; advertisement is not execution.
A physical callback entry establishes neither cryptographic nor application
success. A shared implementation contributes its physical count once.
Candidates and their coverage remain **Unknown**; learned advertisements do
not establish a definite algorithm/provider count or definite CBOM asset.
Normal reports remain **PARTIAL** and algorithm checks remain inconclusive.

Report/check also discover entry-only candidates from public-table shapes in
verified mapped ELF files. This allows warm ordinary default-provider activity
to produce physical entry evidence without an application query or build
profile. These candidates are hints, not proof of an advertised OpenSSL ABI or
of crypto use. A called lookalike is counted without reading its arguments or
return value. Public query/getter observations remain a separate evidence source.
Zero counts do not establish non-use: coverage, unsupported linkage, attach
latency and bounded discovery can leave gaps.

Owned foreground commands prearm entry-only sites from retained executable and
dependency files before release, preserving counts even after a short command exits.
Independently verified public operational exports also provide scalar API activity
for digest, cipher, MAC, KDF, PKEY and RAND. Candidate hints/custom IDs and API
returns are displayed separately from callback totals; wrappers and size queries
are included, and no algorithm/provider binding or crypto-success claim is inferred.

There is no universal first-call guarantee. Warm/built-in activation can remain
unknown; startup, polling, invalidation and final drain leave explicit gaps.
Calls before attachment or after retirement are uncovered. Unavailable backing,
permissions, namespace mismatch and resource caps retain partial/unavailable
semantics. The supported scope is the lane table above; kernel admission
is feature based. Broader OpenSSL 3.0.x/4.x matrices, ARM64, pre-3.0
and RHEL/Secure Boot remain deferred. See [usage](docs/usage.md) for
bounds, privacy, exit codes and cancellation.

## Historical diagnostics and documentation

Explicit `--libcrypto PATH` selects the v0.2 fixed-profile foreground diagnostic.
Its exact enrolled-library/kernel and Count-only restrictions still apply.
Historical results in the [v0.2 release notes](docs/release-v0.2.0.md),
[catalogue](profiles/README.md) and [overhead matrix](docs/overhead-matrix.md)
retain their original scope. A separate [bounded v0.3 inventory cost
sample](docs/release-v0.3.0.md#measured-inventory-cost) measures one selected PID
with tracing disabled; it does not establish broad performance limits.

- [Quickstart](docs/quickstart.md), [CLI and policy files](docs/usage.md), [build](docs/build.md), [install](docs/install.md)
- [Container image](docs/container.md), [Kubernetes](deploy/kubernetes/README.md)
- [v0.3 release notes](docs/release-v0.3.0.md), [roadmap](ROADMAP.md), [documentation index](docs/README.md)
- [Output contract](docs/observed-crypto-v2.md), [observation meaning](docs/what-it-proves.md)

Permanent boundaries: no keys, passwords, plaintext or application payload
capture; no TLS interception, interposition or target environment/argv readers.

## Uninstall

```sh
sudo systemctl disable --now osslscope-service 2>/dev/null || true  # if ever enabled
sudo dpkg -r osslscope        # or: sudo rpm -e osslscope
sudo rm -rf /var/lib/osslscope
```

```sh
sudo setcap -r /usr/bin/osslscope 2>/dev/null || true            # tar installs (prefix /usr)
sudo rm -rf /usr/bin/osslscope /usr/lib/osslscope /usr/share/osslscope /usr/share/doc/osslscope
sudo setcap -r /usr/local/bin/osslscope 2>/dev/null || true      # source installs (prefix /usr/local)
sudo rm -rf /usr/local/bin/osslscope /usr/local/lib/osslscope /usr/local/share/osslscope /usr/local/share/doc/osslscope
```

```sh
docker rmi osslscope:0.6.0
kubectl delete -f deploy/kubernetes/daemonset.yaml \
  -f deploy/kubernetes/job-report.yaml \
  -f deploy/kubernetes/configmap.yaml \
  -f deploy/kubernetes/namespace.yaml
```

DEB removal stops the unit and clears the file caps, and keeps the
conffile plus `/var/lib/osslscope` (windows, `sequence.json`,
reports) — delete that directory yourself. The RPM ships no unit.
Then verify the clean
state (osslscope never pins under `/sys/fs/bpf`):

```sh
hash -r; command -v osslscope || echo "binary gone"
getcap /usr/bin/osslscope /usr/local/bin/osslscope 2>/dev/null | grep . || echo "caps gone"
systemctl is-active osslscope-service 2>/dev/null || echo "service gone"
ls /sys/fs/bpf | grep -i ossl || echo "no osslscope pins"
```

Full path: [install — uninstall](docs/install.md#uninstall).

## Documented CLI limits

Accepted-but-undocumented surface, stated here instead of left
silent. `report`/`check` additionally accept manual/legacy flags not
shown in their usage lines (`--object`, `--members-object`,
`--dev-bundle`, `--provider`, `--builtin`, `--settle`,
`--image-digest`, `--force-offset`); `--table`/`--provider-table`
are accepted and then refused (`table enrollment is deferred beyond
v0.2`). The normal workflow needs none of them. `doctor --pid PID`
and `doctor --exe PATH` select a sectioned foreign preflight (named in
the top-level help, not in `doctor --help`); that route needs
install-package metadata and refuses with exit 4 where the image
carries none. `service-witness` and `service-attempt-trace` are
harness-only signal-observation commands (absent from the top-level
help; each has its own `--help`), not operator tools. Name
collision: `osslscope inspect` (process/module inventory) is unrelated
to `docker inspect` (container config; used to verify
`Privileged=false` and the cap set).

## License

GPL-3.0-or-later for the host, documentation and scripts. BPF/common and
independent contract components have distinct terms; see
[component licensing](docs/licensing.md) and [LICENSES](LICENSES/README.md).
