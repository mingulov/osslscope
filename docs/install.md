<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install from source

The v0.3.0 source candidate uses the pinned [build recipe](build.md) and a
manifest-verified install. It is not released. Source/install simulations do
not qualify actual BPF loading, provider behavior or a platform.

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh --prefix "$HOME/.local"
"$HOME/.local/bin/osslscope" --version
"$HOME/.local/bin/osslscope" scan --json
```

The manifest installs `bin/osslscope`, five development BPF objects under
`lib/osslscope/`, and `share/osslscope/install-manifest.json`. Normal tracing
selects `osslscope-provider-observation` and `osslscope-focused-count`
automatically relative to the actual executable: fixed sibling names or
`PREFIX/lib/osslscope` when the executable is in `PREFIX/bin`. It does not search
CWD, environment paths or unrelated build trees. A host-only build supports
passive inventory but does not supply tracing companions.

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

## Historical and deferred distribution

`--libcrypto PATH` explicitly selects the historical v0.2 exact-profile Count
route; its [release notes](release-v0.2.0.md) and [catalogue](../profiles/README.md)
retain their original qualification scope. They do not qualify v0.3 automatic
discovery or focused execution. The source candidate does not claim DEB/RPM,
RHEL/Secure Boot, ARM64 or broader platform qualification. Packaging tooling
in the tree does not establish a supported binary distribution.
