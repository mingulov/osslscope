<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install from source

The v0.4.0 automatic observation candidate uses the pinned [build recipe](build.md) and a
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

The package installs but never enables the unit. To run it, select
targets in `/etc/osslscope/service.toml`, then:

```sh
sudo systemctl enable --now osslscope-service
systemctl is-active osslscope-service
sudo journalctl -u osslscope-service -n 20
```

Policy reloads go through `systemctl reload` (SIGHUP at the next
window boundary). `Restart=on-failure` restarts abnormal deaths
after 5 s; exit 4 (scope unavailable — nothing finalized, operator
needed) holds the unit stopped, as does the start-rate backstop
(5 starts per 300 s). Removing the package stops the unit and keeps
both the conffile and the out-DIR; upgrades preserve a modified
config and leave a running unit alone until it is restarted.

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
  reservation/cache property only (a same-file second session
  reuses cached offsets without the 22 MiB transient, inside the
  pinned reservation). Runtime multi-worker observation is not
  yet qualified and is not claimed here.
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
