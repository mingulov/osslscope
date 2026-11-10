<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install from source

The v0.5.0 automatic observation candidate uses the pinned [build recipe](build.md) and a
manifest-verified install. Source/install simulations do not qualify actual
BPF loading, provider behavior or a platform.

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh --prefix "$HOME/.local"
"$HOME/.local/bin/osslscope" --version
"$HOME/.local/bin/osslscope" scan --json
```

The manifest installs `bin/osslscope`, five development BPF objects under
`lib/osslscope/`, and `share/osslscope/install-manifest.json`. Normal tracing
selects `osslscope-provider-observation` and `osslscope-focused-count`
automatically relative to the actual executable: `PREFIX/lib/osslscope` when the executable is in `PREFIX/bin`.
A non-bin development executable can use fixed sibling names. It does not search
CWD, environment paths or unrelated build trees. A host-only build supports
passive inventory but does not supply tracing companions.

A full clean source-bearing manifest installs a current v2 receipt. Automatic
installed tracing checks its exact CLI plus five-role membership, consistent
source reference and every hash, including the running CLI. Missing, historical,
partial, mixed or mutated receipts/objects refuse normal loading; an unreceipted
sibling cannot bypass a prefix receipt. Dirty, partial and explicit-override
installs retain historical v1 receipts for their explicit development routes.
For example, a `--bpf-only` build can be composed with installer `--binary`,
or a `--host-only` build with installer `--harvest`/`--count`; explicit artifacts
remain operator-trusted and the composed v1 receipt cannot enable normal tracing.
Commit reviewed source and rebuild the full tree for normal installed tracing.

Manifest files are staged and checked against recorded hashes/lengths before
publication. The receipt publishes atomically; destination replacement can
still fail part way. Rerun installation after failure. Explicit installer/BPF
object overrides remain operator-trusted inputs and do not inherit release
qualification. Do not combine CLI/companion versions or reuse old runtime
receipts after rebuilding source or objects.

## Tracing privileges and trusted installation

Passive scan/inspect need ordinary procfs/filesystem access. Provider observation,
report/check and functional doctor need BPF/perf rights. The app never grants
capabilities or changes kernel/security settings. LSM, seccomp, lockdown,
namespace policy and target access can deny operations despite capability bits.

A user-owned local prefix is usable for passive discovery and ordinary-user
controls. Automatic companion selection under root, set-ID, file-capability or
effective/permitted-capability invocation requires root-owned executable and
companion files, with root-owned ancestor directories. Those files and
directories must not be group/world writable. Placing file capabilities on a
user-owned `$HOME/.local` binary does not create a protected automatic tracing
install; automatic companion selection refuses it under privileged invocation.

An administrator can install the already built manifest into a protected prefix:

```sh
sudo ./scripts/install-dev.sh --prefix /usr/local
sudo setcap 'cap_bpf,cap_perfmon=ep' /usr/local/bin/osslscope
getcap /usr/local/bin/osslscope
/usr/local/bin/osslscope doctor --format json
```

Review ownership/permissions through the entire prefix and use local security
policy to decide privileges. Replacing the binary may require restoring file
capabilities. Explicit `--observation-object` and `--count-object` paths select
operator-trusted code snapshots. They check regular-file identity, bounded
nonzero length, stability during reading and companion ABI, and retain the
validated bytes. They permit symlink traversal and do not enforce the automatic
resolver's ownership, mode or ancestor protections, including under privileged
invocation. The operator must establish the safety and provenance of explicitly
selected code. Object shape/hash checks establish compatibility and identity,
not the safety of arbitrary supplied BPF. A normal same-source build provides
the retained companion pair without manual object flags.

Doctor performs scanner-owned program/map load, self-attachment and companion
load controls, and checks inventory/namespaces. It reports denied/unavailable
capabilities explicitly. An available doctor result is not target-specific
runtime qualification. A namespace mismatch, unreadable backing or unsupported
feature remains a refusal/gap; osslscope does not enter target namespaces.

## Verify a selected process

Use a real host-visible PID found with scan/inspect:

```sh
/usr/local/bin/osslscope inspect --pid 1234 --json
/usr/local/bin/osslscope report --pid 1234 --duration 5 --format json
/usr/local/bin/osslscope check --pid 1234 --duration 5 --require-executed SHA256
/usr/local/bin/osslscope report --duration 5 --format json run -- openssl dgst -sha256 /dev/null
```

Report remains PARTIAL (3); Unknown-only algorithm evidence is inconclusive
(11). Workload success alone does not prove observation. See [usage](usage.md)
for limits, failure precedence, output delivery and cleanup.

## Install a release package

From the 0.5.0 release artifacts (revision 1):

```sh
sudo dpkg -i osslscope_0.5.0-1_amd64.deb      # Debian/Ubuntu
osslscope --version
osslscope doctor --format json
```

```sh
sudo rpm -i osslscope-0.5.0-1.x86_64.rpm      # Fedora/RHEL
osslscope --version
osslscope doctor --format json
```
(RPM proven live in the 0.5.0 lane, not just `rpm -qlp`: Fedora
43 cell, install exit 0 → version 0.5.0 → caps `cap_perfmon,
cap_bpf=ep` → doctor exit 0 with silent stderr → erase exit 0
with file-level verify. Container-cell caveats only: install
with default caps — `rpm -i` under `--cap-drop ALL` fails in
cpio — and grant `BPF`+`PERFMON` to run, or exec refuses the
file caps with `Operation not permitted`.)

```sh
sudo tar -xzf osslscope-0.5.0-prefix.tar.gz -C /usr   # any lane host
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope
osslscope --version
osslscope doctor --format json
```

The DEB `Depends: libcap2-bin` and the RPM `Requires: libcap` pull in
`setcap`. The DEB grants the two file capabilities in postinst and
reloads systemd; it never enables the service — see [Installed
service](#installed-service-deb). The RPM carries the caps as a file
attribute and ships no unit. The tarball's receipt binds `/usr`:
extract into that exact protected prefix, never over an existing
install. Then verify a selected process as below.

## Uninstall

Stop and disable the service first if it was ever enabled, then remove
by install kind:

```sh
sudo systemctl disable --now osslscope-service 2>/dev/null || true
```

```sh
sudo dpkg -r osslscope        # DEB: stops the unit, clears file caps
sudo rm -rf /var/lib/osslscope
```

```sh
sudo rpm -e osslscope         # RPM: clears file caps
sudo rm -rf /var/lib/osslscope
```

```sh
sudo setcap -r /usr/bin/osslscope 2>/dev/null || true            # tarball (prefix /usr)
sudo rm -rf /usr/bin/osslscope /usr/lib/osslscope /usr/share/osslscope /usr/share/doc/osslscope
```

```sh
sudo setcap -r /usr/local/bin/osslscope 2>/dev/null || true      # source install (prefix /usr/local)
sudo rm -rf /usr/local/bin/osslscope /usr/local/lib/osslscope /usr/local/share/osslscope /usr/local/share/doc/osslscope
```

```sh
rm -rf "$HOME/.local/bin/osslscope" "$HOME/.local/lib/osslscope" \
  "$HOME/.local/share/osslscope"               # passive-only prefix, if used
```

DEB removal keeps the `/etc/osslscope/service.toml` conffile and
the `/var/lib/osslscope` out-DIR (windows, `sequence.json`,
`run-summary.json`, reports) — delete them yourself if no reinstall
follows. The RPM ships no unit or conffile. Also delete any
`--out`/`--cbom` artifacts you wrote elsewhere. Containers and
Kubernetes:

```sh
docker rmi osslscope:0.5.0
kubectl delete -f deploy/kubernetes/daemonset.yaml \
  -f deploy/kubernetes/job-report.yaml \
  -f deploy/kubernetes/configmap.yaml \
  -f deploy/kubernetes/namespace.yaml
sudo rm /var/lib/kubelet/seccomp/osslscope.json   # every node
```

Verify the clean state. osslscope never pins programs or maps under
`/sys/fs/bpf`, so unrelated entries such as snapd's `snap` may list —
the grep must find no `ossl`. All four echoes firing is the proof nothing
remains:

```sh
hash -r; command -v osslscope || echo "binary gone"
getcap /usr/bin/osslscope /usr/local/bin/osslscope 2>/dev/null | grep . || echo "caps gone"
systemctl is-active osslscope-service 2>/dev/null || echo "service gone"
ls /sys/fs/bpf | grep -i ossl || echo "no osslscope pins"
```

## Matched development packages

From a clean reviewed product checkout:

```sh
./scripts/build-dev.sh --release --offline
python3 packaging/build-package.py --source-archives /path/to/source-archives --output dist/current
```

This constructs a prefix tarball, DEB, RPM, exact product source archive,
accompanying-source bundle and package manifest. All formats include the CLI,
five roles and protected current receipt plus installed source/notices. The
`--source-archives` directory must hold the original locked `.crate` files and
reviewed runtime source components; see [packaging](../packaging/README.md) for
format selection, prefix binding, prerequisites and installed acceptance gates.
Construction/extraction does not establish platform support or release readiness.

## Installed service (DEB)

The DEB ships the D-record §1.4 installed-service layout:

- `/lib/systemd/system/osslscope-service.service` — the frozen unit
  (runs `/usr/bin/osslscope service --config
  /etc/osslscope/service.toml` as root with a
  `CAP_BPF+CAP_PERFMON+CAP_SYS_PTRACE+CAP_CHECKPOINT_RESTORE+CAP_DAC_READ_SEARCH`
  bounding set (§1.4 Amendment A1: the two verification caps are
  required for foreign-identity verification); windows land in
  the `StateDirectory` out-DIR below).
- `/etc/osslscope/service.toml` — the default service config (a
  conffile: edits survive upgrades). It pins the code-default
  timings and `out = "/var/lib/osslscope/windows"` but selects NO
  targets: without a `pid`/`cgroup` selection the service refuses
  loudly instead of observing nothing.
- `/var/lib/osslscope/windows` — created at first start
  (`StateDirectory` + service-side creation); window files,
  `sequence.json`, `run-summary.json`, and the stream tap (when
  configured) live here.

Prerequisite: a 6.9+ kernel. Ubuntu 24.04 servers default to the
6.8 GA kernel, which is below the support floor — install the HWE
kernel first (recipe: [Runner image](ci-recipes.md#runner-image)).
`doctor` never compares the release number: the `kernel` row runs
feature probes (kprobe-load, ringbuf, uprobe-multi, probe_read_user)
and the release is informational only. A below-floor kernel usually
fails a probe (`wrong kernel: … (feature probe, not uname; release …
informational)` with the remediation `need a kernel with kprobe-load
+ ringbuf + uprobe-multi + probe_read_user (6.9+ verified; 6.12-LTS
oldest tested)`), but probes can also pass (`features ok …
(informational)`) or fail closed with a permission diagnostic
(denied-with-caps attribution, or `kernel features unverifiable
without CAP_BPF` when caps are missing). The `token-support` row is
independently informational — `BPF_TOKEN_CREATE present (6.9+ floor
signal; …)`, `BPF_TOKEN_CREATE absent (pre-6.9? — informational only;
file-caps path needs multi+ringbuf+cookie, not tokens)`, or `token
existence unverifiable without CAP_BPF (informational only)` —
whatever the kernel verdict.

The package installs but never enables the unit. Select targets in
`/etc/osslscope/service.toml` BEFORE enabling: with the stock
config (no selection) the service refuses at startup with exit 2
(`service requires at least one of --pid/--cgroup` in the journal)
and the unit stays stopped without restarting. To run it:

```sh
sudo systemctl enable --now osslscope-service
systemctl is-active osslscope-service
sudo journalctl -u osslscope-service -n 20
```

Exit 2 at startup is startup/admission refusal — never a crash.
Config causes (no target selection, an unknown key, or a bad value)
refuse in CLI admission; operational causes refuse in `run_service`
before any window opens: signals unavailable, an uncreatable `--out`,
a refused `--stream` tap, `--reset-sequence` against an out-DIR that
holds windows, an unreadable out-DIR or run identity, and a locked or
un-lockable out-DIR. All refuse with exit 2 by design. Recovery: fix
the cause the journal names — the refusal line is specific (e.g.
`osslscope service: --out not creatable: Not a directory (os error
20)`) — then `sudo systemctl restart osslscope-service` (if the unit
already sits in `failed` behind a start-rate trip from an older unit,
`sudo systemctl reset-failed osslscope-service` first).

Policy reloads go through `systemctl reload` (SIGHUP at the next
window boundary). `Restart=on-failure` restarts abnormal deaths
after 5 s; exit 2 (startup/admission refused) (§1.4 Amendment A2: the stock
config refuses with exit 2, so prevention holds the unit stopped
instead of restart-looping) and exit 4 (scope unavailable —
nothing finalized, operator needed) hold the unit stopped without
restarting, as does the start-rate backstop (5 starts per 300 s).
Removing the package stops the unit and keeps both the conffile
and the out-DIR; upgrades preserve a modified config and leave a
running unit alone until it is restarted.

## Watch capacity and ParseCache

The watch pool is 256 MiB. A maximal session reserves
122,990,172 B (pinned by the tight reservation test with
production object sizes); two maximal sessions leave ~21 MiB,
while a fresh uncached ELF parse needs a 22 MiB transient
(inventory + export scratch) — so two maximal sessions plus a
fresh parse do not fit. The run-shared `ParseCache`
(Stamp-keyed: dev, inode, size, mode, links, mtime, ctime; cap
16 entries, first-fill wins, pure optimization) lets later
sessions clone already-parsed offsets without the transient, so
same-file second sessions fit. A miss falls back to the uncached
parse, which may then fail with a `StateLimit`/`ReadLimit` gap
when the pool is contended — miss-fallback is not equivalent
availability.

- Cap (≤16 distinct files, stable): hits fit — demonstrated
  reservation/cache property only (an admitted same-file
  session reuses cached offsets without the 22 MiB transient,
  inside the pinned reservation). Admission proves one stock
  parse transient per session until a member attaches; attached
  members warm admission to the lease alone (their parses are
  cached for followers to clone). Members beyond pool capacity
  refuse with an explicit `global_state_limit` gap instead of
  starving live members. Runtime multi-worker observation is
  not yet qualified and is not claimed here.
- Full (16 cached): further distinct files always miss
  (uncached; may gap under contention).
- Churn (Stamps changing across snapshots, e.g. upgrades or
  container layer turnover): new Stamps miss until filled (if
  room) or always (if full).
- Distinct-object (17+ distinct libcrypto builds, e.g. many
  containers/namespaces): exceeds the cap; misses may gap.

Gaps are reported (never silent success, never quiet loss); the
refused scope is not qualified. The cache does not by itself
restore a two-session guarantee for churning or over-cap working
sets — narrow the scope or stabilize the image set and re-qualify.
See `packaging/deb/README.Debian` and the
[overhead matrix](overhead-matrix.md) for the full arithmetic.

## Historical and deferred distribution

`--libcrypto PATH` explicitly selects the historical v0.2 exact-profile Count
route; its [release notes](release-v0.2.0.md) and [catalogue](../profiles/README.md)
retain their original qualification scope. They do not qualify v0.3 automatic
discovery or focused execution. The discovery preview does not claim DEB/RPM,
RHEL/Secure Boot, ARM64 or broader platform qualification. Packaging tooling
in the tree does not establish a supported binary distribution.
