<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Usage

Discovery is the starting point for the v0.3.0 development tree. v0.3.0 is not
released. Watch/scopes/namespaces are implemented with D2 acceptance still in
progress. Provider events/interfaces (D3) and learned-site execution plus
installed qualification (D4) remain mandatory delivery stages.

## Passive discovery

```sh
osslscope scan [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--interval S] [--duration S]] [--json]
osslscope inspect --pid PID [--json]
osslscope inspect --module PATH [--module PATH ...] [--json]
```

With no selectors, `scan` inventories visible numeric entries in the observer's
procfs view. Repeated PIDs are deduplicated. `--cgroup` selects a cgroup-v2
directory and its inclusive subtree. `--module` selects mapped ELF content by
SHA-256; repeat it to accept any supplied hash. PID, cgroup and module selector
families intersect. A resolved empty intersection stays empty. Unavailable,
invalid or changed selectors never widen the request to the system population.
Physical copies with the same hash retain their distinct native file identities.
`inspect` requires exactly one positive PID or one or more module paths;
its selector families cannot be mixed. Unknown, missing or conflicting arguments
fail with exit 2 before discovery IO. `scan --help` and `inspect --help` exit 0.
`scan --watch` streams sampled changes; `inspect` keeps its snapshot/file grammar.

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
osslscope scan --cgroup /sys/fs/cgroup/example.service --json
osslscope scan --pid 1234 --cgroup /sys/fs/cgroup/example.service \
  --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
osslscope inspect --pid 1234
osslscope inspect --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
osslscope inspect --module /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so --json
```

### From snapshot to watch to scope

Start with `osslscope scan --json` to inventory the visible population once.
Use `osslscope scan --watch --interval 1 --duration 30 --json` to sample that
population repeatedly. Then add `--pid`, `--cgroup` or `--module` to either
snapshot or watch. For example:

```sh
osslscope scan --watch --pid 1234 --pid 5678 --interval 0.5 --duration 30 --json
osslscope scan --watch --cgroup /sys/fs/cgroup/example.service --json
osslscope scan --watch --cgroup /sys/fs/cgroup/example.service \
  --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
```

Repeated PIDs select their union; repeated module files select any matching
hash. Different selector families intersect, so the final example selects only
members of that cgroup subtree with a matching mapped module. The supplied file
must have the desired bytes; a host library with the same filename but different
bytes does not select a container's library. Use `inspect --module` to inspect
the supplied file independently, or `inspect --pid` for one process snapshot.
Module inspection by itself makes no claim that a process maps the file.

Use a cgroup scope to discover new members during watch. An explicit PID list
stays a numeric PID selection; it does not grow to include children. Process
starttime and namespace identities distinguish observed incarnations, including
PID reuse. Review those identities when correlating samples with other tools.
No selector grants additional access or enters a target namespace.

### Host-side container workflows

Run osslscope in the host procfs and cgroup view when selecting host processes.
Docker, `kubectl` and the shell utilities below help the operator resolve a
scope; osslscope itself has no Docker socket or Kubernetes-client dependency.
These examples assume a host cgroup-v2 hierarchy mounted at `/sys/fs/cgroup`
with its hierarchy root exposed. Check your mount layout independently (for
example, `findmnt -t cgroup2`); do not concatenate a container-relative cgroup
path with an unrelated host mount. Numeric membership must use the same PID
coordinates as the observer's procfs.

For a running ordinary Docker container, resolve its init PID on the Docker
host, then inspect its host membership and namespace identities:

```sh
container=example-container
host_pid=$(docker inspect --format '{{.State.Pid}}' "$container")
test "$host_pid" -gt 0 || exit 1
cat "/proc/$host_pid/cgroup"
readlink "/proc/$host_pid/ns/pid" "/proc/$host_pid/ns/mnt"
osslscope inspect --pid "$host_pid" --json
osslscope scan --watch --pid "$host_pid" --duration 30 --json
```

This watches that PID selection, not every process in the container. To select
its cgroup subtree, first derive and review the host path:

```sh
relative_cgroup=$(awk -F: '$1 == "0" && $2 == "" { print $3 }' "/proc/$host_pid/cgroup")
test -n "$relative_cgroup" && test "$relative_cgroup" != / || exit 1
cgroup_path="/sys/fs/cgroup$relative_cgroup"
printf '%s\n' "$cgroup_path"
```

Confirm that the printed path is the intended container cgroup, rather than
`/`, `init.scope` or another shared ancestor. Confirm its `cgroup.procs` and
relevant descendant membership against the host PIDs you intend to include;
then run:

```sh
osslscope scan --cgroup "$cgroup_path" --json
osslscope scan --watch --cgroup "$cgroup_path" --duration 30 --json
```

For kind, a Docker node container is not a pod scope. Docker's `State.Pid` may
belong to `init.scope`; neither that PID nor that scope represents all pods or
the intended workload. Resolve the actual pod process in host coordinates.
One way to find candidate host membership records is to obtain the pod UID
and search host procfs for its cgroup component:

```sh
namespace=default
pod=example-pod
pod_uid=$(kubectl get pod -n "$namespace" "$pod" -o jsonpath='{.metadata.uid}')
test -n "$pod_uid" || exit 1
systemd_uid=$(printf '%s' "$pod_uid" | tr '-' '_')
sudo grep -l -F -e "$pod_uid" -e "$systemd_uid" /proc/[0-9]*/cgroup
```

This is a candidate search, not a portable Kubernetes-to-PID resolver. Runtime,
cgroup driver and procfs access vary, and processes can exit during resolution.
Use your runtime's inspection tools plus host `/proc/PID/cgroup`, `status`
(`NSpid`) and namespace links to independently confirm the workload process
and its host PID. Select the pod subtree only after checking its membership;
a container leaf selects only that container's subtree. If UID components are
unavailable, resolve membership with your runtime instead of guessing an
ancestor. Once resolved, substitute that host PID or reviewed host cgroup path
in the same snapshot/watch commands above. A PID reported inside the kind node
or pod is not automatically a host PID.

Container mappings may remain `locator_candidate`, including on overlay
filesystems, or be unavailable under host access restrictions. A candidate hash
can support inventory/matching but never proves mapped backing or execution.
Keep exit 3, `identity_unverified`, `backing_unavailable` and other gaps visible;
do not reinterpret them as complete container coverage. Watch output reports
namespace identities when available, not container names, pod names or a
cluster inventory. It does not bypass permissions or discover invisible hosts.

Stop a foreground watch with Ctrl-C, or send SIGINT/SIGTERM to the osslscope
observer PID from another terminal. Watch ends with `interrupted` and exit 3;
it sends no signal to the selected targets. Avoid sending a signal to a shell
process group that also contains your workload. Check workload survival using
your independent runtime/host tools. See [sampled watch](#sampled-watch) for
cooperative cancellation and output-delivery limits.

### Discovery records and limits

Both JSON modes use `schema_version: "osslscope.discovery.v1"`. Process output
has `mode: "snapshot"`, selected PIDs, process/starttime identities, relevant
module metadata, finite gaps, work totals, limits and capability status.
Snapshot and process `interval` fields contain optional observer Unix-millisecond
start/finish clocks and monotonic `elapsed_ns`. Wall clocks may move independently.
Process `namespaces` contain optional native device/inode identities for the PID
and mount namespaces. Unreadable or changing namespace metadata stays unknown
with a gap. `scope_record` contains only the selected cgroup's native device/inode
identity and computed supplied-module SHA-256 IDs.
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

Cgroup selection pins the actual cgroup2 directory and samples numeric membership
before and after inventory. Both passes together admit at most 4096 directory
visits and 4 MiB of numeric membership bytes; their reads also consume the shared
read/deadline budget. Only domain cgroups are supported: threaded, inaccessible,
malformed or invisible membership produces a finite refusal/gap. The real
hierarchy root has an implicit domain type. Membership changes produce a gap;
retained process records must be in the same single native cgroup at both sample
boundaries. Nested mount crossings or unavailable mount identities omit the
uncertain subtree and add a gap, preserving independently validated members.
`statx` mount identity support is required for cgroup subtree traversal.
Procfs and cgroup PID coordinates must agree. Visibility remains the
observer's namespace/permission view, with no claim about inaccessible host or
cluster populations. A cgroup pathname supplied inside a container must be
visible to the observer in its mount namespace.

Module selectors are opened, bounded and hashed once during scanner construction,
with unchanged descriptor metadata checked at each snapshot boundary. This setup
has its own shared read/object/deadline limits; snapshot work totals describe
sampling after setup. Replaced paths do not retarget the pinned selection.
Changed selector descriptors make the scope unavailable. Supplied hashes can
select ELF files classified as `other`; automatic unfiltered discovery still
reports only relevant OpenSSL interfaces/dependencies.

Discovery exits: **0** requested inventory completed without access/resource
failure; **3** useful partial inventory; **4** wholly unavailable observation;
**2** invalid arguments; **1** output/internal failure. Complete metadata
inventory does not imply activation, execution or completeness beyond the
requested visible scope. An accepted process with no relevant modules remains
useful inventory. Output failure takes exit 1 even if discovery was partial.

## Sampled watch

```sh
osslscope scan --watch --pid 1234 --interval 1 --duration 30 --json
osslscope scan --watch --cgroup /sys/fs/cgroup/example.service \
  --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3
```

`--interval` defaults to one second and accepts `[0.05,3600]` seconds.
`--duration` accepts `(0,3600]` seconds; omit it to watch until cancellation.
Timing options require `--watch`. Repeated flags, nonfinite values, values
outside those ranges, and positive durations rounding to zero are usage errors
before scope acquisition. Sampling starts immediately. The interval is the
minimum period between sample starts; a slow sample delays the next one, with
no catch-up queue. A duration also caps each remaining cooperative sample
budget. Neither duration nor cancellation can interrupt a stalled filesystem
syscall or an already admitted bounded ELF parse. Selector preparation is
separately bounded as described above and consumes elapsed watch time.

JSON watch output is NDJSON: one compact `osslscope.discovery.v1` record per
sample, followed by one end record. Sample records have `mode: "watch"`,
`record: "snapshot"`, increasing `sequence` starting at 1, observer `interval`,
requested `poll_interval`, the ordinary `snapshot`, and finite `changes`.
Duration fields use `{ "secs": N, "nanos": N }`. Changes carry a finite `kind`,
PID/starttime, and optional module metadata. `process_seen` and `module_seen`
mean present in this sample relative to the previous one. They do not mean a
process just started or a provider just loaded. `process_not_seen` and
`module_not_seen` require usable current inventory for that process; they mean
absent from the sampled selection, never process exit or provider unload.
Read, backing, membership, namespace, identity-change and resource failures
produce `visibility_lost` instead of absence claims. Successfully enumerated
locator candidates keep their candidate status; their `identity_unverified`
association gap alone does not hide a mapping-list observation. Unresolved,
deleted or mismatched executable backing instead has `backing_unavailable`,
which forbids absence claims even when module selection filters out a process.
A newly visible incarnation or namespace is a fresh observation. Human output shows the same finite changes.

All watch records state `sampled_history: "incomplete"`, independently of the
snapshot's inventory completeness. Polling can miss activity entirely between
samples and has sampling/read lag. Only the immediately previous bounded
snapshot is retained, so visibility recovery may report `seen` again. Watch
establishes no lossless event history, activation, execution or non-use claim.

`ScopedScanner` retains at most `max_objects` metadata/descriptor cache entries
between snapshots. Stable native file fingerprints reuse parsed metadata;
file bytes and maps buffers are transient. Changed or no-longer-seen entries
are evicted; stale parse failures cannot survive fingerprint validation.
Cache hits still resolve each executable mapping's backing and recheck held
file metadata. They save ELF read/hash work rather than bypassing mapping or
process identity checks. Work totals count only each snapshot's new inspections
and charged reads. Repeated caps use circular PID admission/progression; they
remain partial inventory, and changing/inaccessible populations have no fixed
coverage-time guarantee.

End records carry `record: "end"`, snapshot count in `sequence`, `elapsed`,
`limits`, numeric `status`, optional finite `gap`, and reason `duration`,
`interrupted`, `scope_unavailable` or `output`. Normal duration expiry returns
the last snapshot status (or 4 if none could be sampled). SIGINT/SIGTERM stop
only the observer, restore its prior signal handlers, and end with exit 3;
workloads keep running. The library `watch::run` uses a caller-supplied
`AtomicBool` and never installs signal handlers. Output failure returns exit 1
and stops acquisition. An output end record is attempted once, but a failed
sink may prevent delivery, including delivery of the end record itself.

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
