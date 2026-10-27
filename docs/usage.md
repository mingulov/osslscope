<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Usage

Discovery is the starting point for the v0.3.0 development tree. v0.3.0 is not
released; watch/scopes/namespaces (D2), provider events/interfaces (D3) and
learned-site execution plus installed qualification (D4) remain required.

## Passive discovery

```sh
osslscope scan [--pid PID ...] [--json]
osslscope inspect --pid PID [--json]
osslscope inspect --module PATH [--module PATH ...] [--json]
```

With no PID, `scan` inventories visible numeric entries in the observer's
procfs view. Repeated PIDs are deduplicated. `inspect` requires exactly one
positive PID or one or more module paths; selector families cannot be mixed.
Unknown, missing or conflicting arguments fail with exit 2 before discovery IO.
`scan --help` and `inspect --help` exit 0. Watch and cgroup flags are not yet
supported. PID namespaces and mount namespaces are not exhaustively resolved.

No `--libcrypto`, enrolled profile, manual offset, BPF object, or privilege
setup is required. Normal procfs and filesystem permissions apply. No supplied
module is loaded or executed. Process discovery reads file-backed metadata,
not target memory, environment, command lines, keys or payloads; it sends no
signals to targets. It does not inject code or change the target. Procfs
pseudofiles are unavailable as module inputs; procfs links to ordinary ELF
backing (such as `/proc/PID/exe` or `/proc/self/fd/N`) remain supported.

For example, substitute a visible PID and actual file paths:

```sh
osslscope scan --pid 1234 --pid 5678 --json
osslscope inspect --pid 1234
osslscope inspect --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
osslscope inspect --module /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so --json
```

Both JSON modes use `schema_version: "osslscope.discovery.v1"`. Process output
has `mode: "snapshot"`, selected PIDs, process/starttime identities, relevant
module metadata, finite gaps, work totals, limits and capability status.
Module output has `mode: "module"`, deduplicated `modules`, finite `errors`
with zero-based `input_index`, work totals, limits and capability status. No
raw target paths, names, symbol strings or mapping addresses enter either
output or discovery diagnostics. Human output includes the interpretation
followed by the same readable structured records.

Module metadata describes a SHA-256, numeric device/inode/size, architecture,
finite recognized exports and dependency flags. The interface classifications
are `openssl_compatible`, `provider_module`, `openssl_consumer` or `other`;
they do not authenticate a vendor. Mapped records distinguish `verified`
backing association from `locator_candidate` file metadata. A path lookup or
matching device/inode alone never promotes a candidate to verified backing;
permissions and filesystem semantics may leave useful candidates and gaps.

**ELF exports and mappings do not prove activation or execution.** Provider
activation and advertised runtime interfaces remain `unknown`; execution is
`not_observed`, including for warm processes. Unknown prior activation is
normal capability status. These commands create no executed CBOM or policy
verdict and do not prove non-use when no module is found.

All modes bound work with the shared defaults: 128 MiB per module, 4 MiB per
maps read, 4096 processes, 1024 objects per process, 16384 total object attempts,
1 GiB aggregate charged read work and a 30-second cooperative deadline.
Supplied files use the module, total object, read and deadline limits, with
repeated unchanged files cached rather than hashed again. Read totals are
conservative charges including EOF probes, not exact kernel byte counts. The
deadline is checked between operations; it cannot interrupt a stalled syscall
or an admitted bounded parse. A budget failure preserves earlier independent
results and reports a finite gap/error. Discovery snapshots are not atomic;
detectable mapping/file/process churn is reported, and later changes or
undetectable mutate-and-restore races are not ruled out.

Discovery exits: **0** requested inventory completed without access/resource
failure; **3** useful partial inventory; **4** wholly unavailable observation;
**2** invalid arguments; **1** output/internal failure. Complete metadata
inventory does not imply activation, execution or completeness beyond the
requested visible scope. An accepted process with no relevant modules remains
useful inventory. Output failure takes exit 1 even if discovery was partial.

## Legacy foreground diagnostic

The v0.2.0 foreground route supports one exact enrolled x86-64 library/kernel
profile, one owned foreground process and its threads. Native qualification is
described in the [release notes](release-v0.2.0.md). Start with [build](build.md),
[install](install.md) and the [catalogue](../profiles/README.md).

## Commands

```sh
osslscope doctor --libcrypto LIB [--count-object COUNT] [--format human|json]
osslscope report --libcrypto LIB [capture/output options] run -- COMMAND
osslscope check --libcrypto LIB [capture/output options] [rules] run -- COMMAND
```

`--libcrypto` selects the actual root-owned, protected library file. Its bytes,
GNU build identity and executable callback offsets must match the built-in
catalogue. The exact kernel build and initial PID namespace must also match.
No caller catalogue, guessed offset or unsupported-profile fallback is accepted.

`--count-object` selects operator-trusted locally built BPF bytes. A user-owned
prefix requires this explicit path. Omission searches trusted system Count
locations and applies the existing install-receipt checks. Only Count is
resolved/loaded: harvest, members and identity bundles are not part of this route.
Role/ABI/hash checks establish compatibility and identity, not authentication
or a reader-free guarantee for an arbitrary supplied object.

Doctor opens no live target and loads no BPF. It checks the exact profile,
namespaces, Count compatibility and effective capability bits, and labels
runtime permissions as unprobed. Report/check perform actual load and attach
checks while their owned child is still stopped.

## Capture and output options

| Option | Meaning |
| --- | --- |
| `--duration S` | Requested observation duration: `(0,3600]` seconds, default 30. |
| `--timeout S` | Stopped-target/count setup budget: `[0,120]` seconds, default 60. Zero expires before acquisition. |
| `--grace S` | Count close/read budget: `[0,30]` seconds, default 5. Incomplete cleanup remains explicit. |
| `--format human\|json` | Primary output, default human. |
| `--out FILE` | Write the primary artifact to a file; default stdout. |
| `--cbom FILE` | Also write a definite-only CycloneDX crypto-BOM from the same document. |
| `--workload-out FILE` | Redirect the workload's stdout/stderr to a fresh file. |
| `--workload-out-fd N` | Redirect workload output to a caller-owned open fd; mutually exclusive with the file option. |

Nonfinite, negative, out-of-range and positive-rounded-to-zero durations are
usage errors before acquisition. Workload stdout/stderr go to `/dev/null` by
default; observer stdout is an artifact channel. Prefer an independent fd for
workload output. Selecting fd 1 or 2 intentionally shares an observer channel
and can mix workload bytes with JSON or diagnostics. A nonzero workload exit
prints a rerun hint rather than workload bytes.

The observer uses a safe `owned-process` label, not argv or comm. Reports retain
exact object fingerprints, callback candidates, conserved entry counts, window
bounds and typed gaps. `count_object` records the selected Count digest/length
and trust selection. Provider labels describe compiled candidates, not runtime
provider activation. All formats carry the profile's unknown-denominator gap.

Choose distinct primary and CBOM destinations. If both resolve to the same
file or stdout, CBOM delivery fails and the primary artifact is preserved.
This includes relative/absolute path aliases, hard links and symlinks.

## Algorithm rules and policy files

At least one active rule is required by `check`:

```sh
osslscope check --libcrypto LIB --count-object COUNT \
  --require-executed SHA256 run -- COMMAND
osslscope check --libcrypto LIB --count-object COUNT \
  --deny-algorithm AES-256-GCM run -- COMMAND
```

Names must exist in the frozen registry. Known but unobserved algorithms remain
inconclusive; a typo is a usage error. The same rules may come from a bounded
version-1 TOML file:

```toml
version = 1
require-executed = ["SHA256"]
```

Pass it with `--policy FILE`. Command-line rules are additive. Contradictory
requirements/denials refuse; provider, ENGINE and weak predicates in either
source refuse rather than being silently dropped.

## Coverage and custody

Normal results are **PARTIAL**, including a successful positive requirement.
The catalogue has no known global denominator. A shared site contributes N
calls once; it cannot establish N calls for every possible algorithm. NEWCTX
entries describe context creation attempts. GCM UPDATE can include AAD, empty
input or failure. Counts establish neither message processing nor crypto success.

Probes are installed before child release using the original nonzero group
identity. No numeric reattachment or per-image following occurs. Exit is
observed without reaping, then the count terminal is selected before final
reap/detach. Pending cleanup and unknown writer tails remain visible. Coverage
can be lost at leader retirement/nonleader exec; aggregate identity does not
promise seamless exec coverage.

A released live child is left running when observation ends. Normal setup
failure/SIGINT/SIGTERM resolves stopped children and count resources. A crash or
SIGKILL in the stopped pre-exec interval can strand the child; external cleanup
is then required. There is no crash-safe startup custodian in this preview.

## Legacy foreground exit codes

| Code | Meaning |
| --- | --- |
| 0 | Help/offline success or doctor preflight without a hard failure; ordinary preview captures remain partial. |
| 1 | Failed child, failed artifact delivery or a usable post-observation runtime failure. |
| 2 | Invalid or deferred CLI/policy input, before acquisition. |
| 3 | PARTIAL observation, including satisfied positive rules. |
| 4 | Profile, namespace, Count ABI or setup/environment refusal without usable observation. |
| 10 | A definite policy violation; dominates child, artifact and usable runtime failure. |
| 11 | Policy inconclusive, including known algorithms unobserved under incomplete coverage. |

For `report`/`check`, foreign `--pid`, `--provider`, `--builtin`, `--object`,
`--members-object`, `--dev-bundle`, table/offset overrides, `--settle`,
`--image-digest`, provider/ENGINE/weak rules, services and following are deferred.
Offline `alias-audit` remains available for an existing harvest document; it
performs no live acquisition. Its input does not become new runtime evidence.
