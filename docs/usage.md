<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Usage

The v0.5.0 observer starts with passive discovery, optionally observes
public provider interfaces, and counts learned physical callback entries for
one selected process. The supported lane (x86-64, 6.9+ feature-probed
kernel, BTF, cgroup v2, stock OpenSSL 3.5.x) is in the
[README support matrix](../README.md#support-matrix-050-lane); start with the
[quickstart](quickstart.md). Installed/platform qualification is separate
from source behavior; the latest qualification record is
[v0.4.0](release-v0.4.0.md) (no v0.5.0 record exists yet).

## Automatic crypto watch

```sh
osslscope scan --watch --observe-crypto --duration 30
osslscope scan --watch --observe-crypto --pid 1234 --pid 5678 --json
osslscope scan --watch --observe-crypto --cgroup /sys/fs/cgroup/example.service --json
osslscope scan --watch --observe-crypto --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
```

With no selectors this watches the visible host population. PID, cgroup and
module selectors retain the intersection rules below. A module selector chooses
processes with matching mapped content; observation then covers the selected
process's full discovered inventory, including other compatible libraries.
`--observe-crypto` requires `scan --watch` and cannot be combined with
`--observe-providers`. Report/check retain their one-process contract.

The default duration is 30 seconds, with a one-second rescan interval, at most
four active processes, and 256 MiB of accounted observer state shared by sessions,
scanner metadata, parser scratch and output. The slot cap does not promise four
maximal sessions fit. Larger inputs can exhaust the shared budget without
changing file or algorithm eligibility. `--interval` controls sampled discovery;
setup, parsing and output can delay sampling. Cancellation is checked between
bounded work phases; a stalled filesystem/output syscall is not interruptible.

Sessions start when a sample finds compatible-library, provider or consumer
interfaces/dependencies. No-candidate processes remain visible and are rescanned
for later loads. “No candidate interfaces in this sample” is not proof of no
OpenSSL or crypto use; visibility/read/limit failures remain explicit uncertainty.
Library names, versions and algorithms do not select the tracing backend.

Default output is a compact human summary per process incarnation: passive
objects, sampled membership, limits, unavailable tracing and partial activity.
Physical entries and API entries are separate units; unknown attribution stays
explicit. Each summary shows at most eight object or gap rows and reports how
many were omitted. Passive `not_observed` does not override later activity.

With `--json`, output is NDJSON with `schema_version: "crypto-watch-v1"` and
increasing `sequence`. Records:

- `start`: duration, interval and resource bounds.
- `discovery`: the existing sanitized passive `ProcessRecord`, including file
  identities, finite interfaces, namespaces and sample timing. These facts stay
  available when tracing is unavailable or a member exceeds an admission cap.
- `membership`: sampled identity and admission/retirement reason. Segment zero
  means discovery only; each admitted segment gets its own increasing number.
- `gap`, `tracing_gap`, `session_gap`, `limit`: visibility, tracing, acquisition
  or resource uncertainty. Known uncovered members retain their incarnation;
  a scope-wide gap does not invent identities for unseen members.
- `process_observation`: one ordinary `observed-crypto-v2.4` document, its
  incarnation, segment and retirement reason. Links close before that document
  is streamed. Physical entries and public API activity remain separate.
- `end`: stop reason, segment count and peak declared accounting (not measured
  RSS). Coverage remains partial; records never manufacture a cross-process
  execution total, definite CBOM asset or policy result.

Consumer identity domains differ: discovery `ModuleInfo.device` is native Linux
`st_dev`; report `site.device` encodes `(major << 32) | minor`. For major 8,
minor 1 these values are **2049** and **34359738369**, respectively. Decode the
proper domain before correlating device/inode identities; never join raw values.
Discovery `process.execution = "not_observed"` describes the passive inventory
view. It does not override positive evidence in a `process_observation` record.

Membership is sampled. Removal/reentry produces distinct segments even for the
same incarnation. PID reuse or missing/denied visibility never becomes a claim
that the old process exited. Observations between samples, before attachment or
after retirement remain uncovered. SIGINT/SIGTERM stops the observer and retires
its links; it never signals the foreign applications. Exit 3 means at least one
partial process observation; exit 4 means none could be observed, including
useful discovery-only output. Invalid grammar exits 2; output failure exits 1.

## Passive discovery

```sh
osslscope scan [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--interval S] [--duration S]] [--json] [--resolve-paths]
osslscope inspect --pid PID [--json] [--resolve-paths]
osslscope inspect --module PATH [--module PATH ...] [--json] [--resolve-paths]
```

With no selectors, `scan` inventories visible numeric entries in the observer's
procfs view. Repeated PIDs are deduplicated. `--cgroup` selects a cgroup-v2
directory and its inclusive subtree. `--module` takes a file PATH (repeatable);
each file is hashed and mapped ELF content matching any supplied hash is
selected. Bare hashes are not accepted; they fail with exit 4 and a message
naming the PATH form. Digest selectors (`sha256:...`) are not accepted in v0.6.
PID, cgroup and module selector families intersect. A resolved empty
intersection stays empty. Unavailable, invalid or changed selectors never widen
the request to the system population.
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

Machine records always carry path evidence: `--json`/NDJSON documents
include `verified_path`/`verified_path_unavailable`/`maps_spelling` on
every mapped record whether or not `--resolve-paths` is passed, so
machine bytes are identical with the flag on or off. That machine
output may disclose sensitive filenames and exe spellings wherever
those bytes travel — redirects, logs, support bundles, tickets,
pastes — regardless of `--resolve-paths`; treat captured discovery
output as potentially sensitive.
`--resolve-paths` (argv only, default off) gates only the human `path=`
fragment, and only on an interactive terminal. CBOM, policy records,
diagnostics, and exit codes are byte-identical with the flag on or off;
redirected human output renders `path=(not-a-terminal)` placeholders
instead of paths (so redirected human bytes do differ from flag-off by
those placeholders — never by path text). Only objects whose identity was
verified render a path; locator candidates render `path=(unverified)`
without any resolution attempt, and failures render `(unavailable)` or
`(changed)` without ever publishing the attempted spelling. Resolved
strings are sanitized (control bytes neutralized) and bounded to 200
chars for terminal display. Residuals, documented and accepted: with
the flag on, terminal scrollback becomes host-path-bearing — visible
to terminal recording, shared tmux/screen sessions, screen sharing,
shoulder-surfing, and anyone receiving support bundles, tickets, or
pastes of that scrollback — so avoid the flag when the viewing
context itself is sensitive. Sanitization preserves filename TEXT
(other than escapes/bounds), so a name carrying secrets or identifiers
still discloses them.

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
To run osslscope itself inside a container, see [container](container.md).
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
with zero-based `input_index`, work totals, limits and capability status.
Mapped records carry path evidence. `verified_path` is set only for
`verified` rows and holds the proven object path: `path` (the retained
identity, re-proven at capture time), `path_encoding` (`utf8` verbatim,
or `utf8_percent_escaped` when the raw bytes were not valid UTF-8 —
valid runs stay verbatim, each invalid byte becomes uppercase `%XX`;
over-long spellings truncate with `…`), `locator_kind`
(`host_direct`, `container_layer`, or `proc_root_anchored` — HOW the
path was proven), and `capture_unix_ms` (WHEN — an observer wall
clock). Every other row instead carries the finite
`verified_path_unavailable` reason (`unverified_identity`, `no_locator`,
`resolve_failed`, `changed`, `missing`, `unavailable`) — never a path.
`maps_spelling` is the row's OWN `/proc/PID/maps` pathname for this
pid+starttime (`spelling`, `source: proc_maps`, `verification:
unverified`): an unverified hint, never authority, and never joined
across processes by device/inode. A path lookup or matching
device/inode alone never promotes a candidate to verified backing.
Process records carry `comm`/`comm_status` and `exe`/`exe_status`
sampled from `/proc` (operator-visible readings, never authentication
or proof): each status is `available`, `unreadable`, `changed` (the
incarnation recycled mid-sample — both values are dropped), or
`too_long` (over the 64-byte `comm` / 4096-byte `exe` bound — the
truncated prefix is still published). `comm` is sanitized for display;
`exe` is verbatim lossy-decoded bytes, so human renderers must sanitize
it before display. Module facts carry the file's OWN `file_soname`
(`DT_SONAME`, never inherited from a dependency) plus the singular
validated rodata `file_openssl_version` with `file_version_status`
(`present`, `absent`, `ambiguous`, or `not_fully_scanned` — only
`present` carries a version string). Gaps may carry `errno`/`actor_euid`
from a refused open (backing, process, maps, or namespace). File evidence is never a runtime
claim: SONAME and rodata version strings describe bytes on disk, not
loaded, activated, or executed code — no version-to-vulnerability claim
may be derived from them. The machine shape is pinned by
`schemas/discovery-v1.json` (snapshot, module, and watch records).
Reader break: v0.5 `deny_unknown_fields` readers reject v0.6 documents;
v0.6 readers accept v0.5 documents. No raw symbol strings or mapping
addresses enter either output or discovery diagnostics; target path and
identity strings enter machine JSON as documented above. Machine
consumers must parse `--json`/NDJSON only: the human stdout shape is
owned by the human-surface plan
(`docs/superpowers/plans/2026-11-11-v060-human-surface.md`), which splits
stdout by mode (human rows by default, pure JSON under `--json`).

Module metadata describes a SHA-256, numeric device/inode/size, architecture,
finite recognized exports and dependency flags. The interface classifications
are `openssl_compatible` (the file exports recognized OpenSSL API symbols as
defined dynamic code exports, provider-init excluded), `provider_module` (the
file exports `OSSL_PROVIDER_init`), `openssl_consumer` (the file needs
OpenSSL: a `DT_NEEDED` `libcrypto`/`libssl` entry in a known SONAME form, or
an undefined reference to a recognized API symbol), or `other` (none of the
above — an ELF object with no recognized OpenSSL interface evidence, such as
NSS `libssl3.so`); they do not authenticate a vendor. Human output and
`scan --help` carry a one-line `kinds:` legend decoding every word. `other`
objects are counted per process, never listed — except under `scan --module`,
where a selector-matched `other` is listed as a module row and not counted:
`other_objects` reports
`verified` (backing proof closed) vs `candidate` (unverified locator only —
an `identity_unverified` gap names the same mapping) vs `failed` (the mapping
errored before any classification — every one also carries a gap).
Non-executable mappings, skipped non-regular files, and files determined to
be non-ELF are outside the counted population, so the counts never claim
"every mapping is an Other object". A process with `0 modules` still reports
how many other objects were scanned; any gap — or a module-selector scope —
keeps the "conclusively without OpenSSL" statement silent. Mapped records
distinguish `verified` backing association from `locator_candidate` file
metadata. A path lookup or matching device/inode alone never promotes a
candidate to verified backing; permissions and filesystem semantics may leave
useful candidates and gaps.

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
conservative charges including EOF probes, not exact kernel byte counts.
Live `/proc` bytes are charged too, so `read_bytes` varies across runs
against a running target and must not be compared for equality. The
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

### Privilege

Discovery is passive but not permission-free: unreadable processes and
mappings become finite gaps, and the inventory states them instead of
guessing. When a gap carries a refused-open `errno` of `EPERM`/`EACCES`
— proof the kernel denied this observer — stderr carries one privilege
hint naming the unverified portion (`{u} of {t} modules unverified`),
the remedy, and this section. The hint fires only on such errno-proven
denials: never for `too_large`, `changed`, limits, or dead PIDs, and it
fires for root too when root is actually denied. It is emitted once per
invocation on stderr only (a watch run retains one hint for the whole
run, never one per tick) and is identical at every verbosity level.

The supported path to a complete inventory is re-running as root.
Capability recipes are best-effort: this project publishes a recipe
only against the exact matrix it was tested on — kernel, distribution,
namespace layout, LSM policy, and backing-proof path — and never
advertises a universal minimal capability set derived from `EPERM`
alone. Container root is not host visibility: mount/PID namespaces,
LSM policy, and `hidepid` mounts can deny reads that succeed
elsewhere, and only the `verified` backing proof promotes a candidate
— a readable pathname alone never does. When the hint fires, compare
runs at the same privilege before concluding anything changed in the
target.

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

## Provider observation

```sh
osslscope scan --pid 1234 --observe-providers --json
osslscope scan --pid 1234 --observe-providers --watch --duration 30 --json
osslscope inspect --pid 1234 --observe-providers --json
```

This opt-in observes public provider lifecycle/query/getter interfaces using the fixed
observation companion. It does not count callback execution. Public interfaces
are incomplete advertisements; warm and built-in activation may stay unknown.
Unsupported observations retain passive inventory and explicit gaps. Supplied
module inspection remains passive and rejects provider observation.

Kernel-panic quarantine: `EVP_DigestInit_ex2` (API 21) stays
unprobed — probing its entry stub panics kernels. Its activity
row shows `not_attached` with zero entries. Where the attach is
attempted and refused, it surfaces as the `quarantined_api`
setup gap plus the `focused.attach_refused_quarantined` loss
counter (see
[kernel-quarantine-note](kernel-quarantine-note.md)).

## Execution report and check

```sh
osslscope doctor --format json
osslscope report --pid 1234 --duration 30 --format json --out report.json --cbom bom.json
osslscope check --pid 1234 --duration 30 --require-executed SHA256
osslscope report --duration 5 --format json run -- openssl dgst -sha256 /dev/null
osslscope check --duration 5 --require-executed SHA256 run -- openssl dgst -sha256 /dev/null
```

Report/check require exactly one positive host-visible `--pid` or `run -- COMMAND`.
They select the fixed installed observation/focused-count companions automatically;
no `--libcrypto`, profile or manual callback offsets are required. There is no
hidden fallback to historical diagnostics. See [install](install.md) for trust
requirements. Explicit `--observation-object` and `--count-object` overrides are
operator-trusted BPF code snapshots: regular-file identity, bounded nonzero
length, read stability and companion ABI are checked before retaining bytes.
Explicit paths permit symlink traversal and do not enforce automatic selection's
ownership, mode or ancestor protections, including under privileged invocation.
Compatibility and hashes do not authenticate arbitrary BPF or establish its
privacy; the operator must establish the safety of explicitly selected code.

For `run --`, the observer holds its child while inspecting ELF executable,
interpreter and dependency files and installing entry-only probes. Short commands
can therefore retain physical counts after exit. Dependency prediction is bounded;
scripts, loader cache/hwcaps overrides, preloads and later `dlopen` can leave misses.
`focused.startup_partial` records that uncertainty; prearming does not establish
complete startup coverage or turn a static candidate into a public ABI. Setup and
polling deadlines are cooperative between file operations: an in-flight blocking
filesystem syscall cannot be interrupted by the observation deadline. A fully
preflighted, bounded native attachment transaction may finish after its scheduling
tick expires. Cancellation and identity checks still apply between native calls,
and no new link is attached after the hard observation window ends. Unfinished
discovery retains its progress for a later tick.

A document covers one process incarnation and its threads. Cgroup/container
inventory chooses a PID, not an implicit tracing group. Forks, children, process
replacement and later numeric PID reuse do not acquire execution coverage.
The observer requires matching PID namespace coordinates and refuses mismatch
or unavailable namespace identity. It does not enter target namespaces.

Doctor checks scanner-owned inventory, namespace and companion integrity,
functional program/map loading and self-attachment. Its JSON distinguishes
available, denied, unavailable and not-checked capabilities; an available
self-control does not establish target-specific access or observation success.
`doctor --discovery --json` retains the discovery-only capability route.

| Option | Meaning |
| --- | --- |
| `--duration S` | Observation window `(0,3600]` seconds, default 30. |
| `--timeout S` | Setup budget `(0,120]` seconds, default 60. |
| `--grace S` | Cleanup budget `(0,30]` seconds, default 5. |
| `--format human\|json` | Primary output, default human. Report/check use `--format`, not `--json`. |
| `--out FILE` | Primary artifact; default stdout. |
| `--cbom FILE` | Definite-only CycloneDX export from the same document. |
| `--workload-out FILE` | Owned-run stdout/stderr to a fresh file. |
| `--workload-out-fd N` | Owned-run output to a caller-owned fd; excludes `--workload-out`. |

Nonfinite, nonpositive, out-of-range and positive-rounded-to-zero timing values
are refused before acquisition. Workload redirection requires `run --`; its
default is `/dev/null`. Fd 1 or 2 intentionally shares an observer channel and
can mix workload bytes with artifacts/diagnostics. The observer does not include
argv, target environment, raw provider/algorithm spellings, paths, addresses,
keys or application payload in its output. Workload output is separately
operator-selected data. Choose distinct primary/CBOM destinations; aliasing
refuses CBOM delivery and preserves the primary artifact.

### Physical counts, policy and limits

Advertisement alone produces no callback count. Learned sites require verified
mapped backing, current incarnation/namespace and candidate revalidation.
Static public-table shapes in retained ELF files also admit entry-only probes,
without application queries or build enrollment. They grant no argument/return
reads or advertised ABI authority. Static and learned associations share one
physical cookie; offsets in one file can share a link FD. Future positive
operation/function IDs and unknown algorithm identities remain eligible.
Unquery, volatile-query and ring/read losses downgrade live metadata while
retained file-backed entry counts continue. Actual process, namespace, mapping
or backing changes retire links; calls before reattachment remain uncovered. The stderr readiness line proves verified
attachment at that point, not semantic attribution or complete coverage.

Physical counts are conserved across current/fenced rows; a shared implementation
contributes N entries once rather than N per candidate. Candidate coverage and
expected scope remain Unknown. Even a recognized advertised SHA256 spelling
does not establish a definite SHA256/provider count. Callback entry does not
prove crypto success, FIPS state, key size, message processing or application
success. Unknown candidates create no definite CBOM asset, and absence never
proves non-use. Production first-call and final-tail coverage remain unknown.

<a id="reusable-policy-files"></a>

`check` accepts algorithm rules (`--require-executed`, `--deny-algorithm`),
provider rules (`--require-provider`, `--deny-provider`), `--deny-engine` and
`--deny-weak`. At least one rule is required, supplied on the CLI or in a
bounded policy file:

```toml
version = 1
require-executed = ["SHA256"]
```

Use `--policy FILE`; CLI constraints are additive. Algorithm names must exist
in the frozen registry; provider identities can include opaque third-party
classes. With `--policy`, required providers denied by provider/ENGINE rules
and required algorithms denied directly or by `--deny-weak` are rejected.
CLI-only rules do not receive this contradiction check. Unknown-only normal
evidence leaves algorithm rules inconclusive, including when the physical
fixture count is positive. Accepting provider/ENGINE/weak rules does not turn
Unknown attribution into definite policy evidence.

Policy version 2 adds object-bound execution selectors
(`deny-selector`, `require-selector`), evaluated against the
v2.5 execution plane instead of candidates; v1 files are
accepted unchanged, and unknown versions fail before capture:

```toml
version = 2
deny-selector = [{ object = "<64-hex code object>", id = "<64-hex digest>" }]
```

Both identities are 64 lowercase hex. Observe the selectors in
a `report` document's `algorithm_selectors` first, then pin and
enforce: the same spelling under another build is another
identity, so a migrated algorithm (or rebuilt library) stops
matching. A positive partition violates a deny rule even in a
`PARTIAL` window; unresolved calls keep unmatched rules
inconclusive.

Explicit legacy diagnostics (`--libcrypto`) accept only `--require-executed`
and `--deny-algorithm`; provider, ENGINE and weak predicates are refused.

The provider observation session admits one process, 256 objects, 512 observer
links, 4096 pending calls, depth 8, 4096 learned physical sites and 16384 facts,
with a 1 MiB ring, 64 MiB cumulative host-state charges and its own 256 MiB
cumulative ELF-read budget. The separate passive inventory scanner receives
a per-snapshot read allowance of 256 MiB minus the initial inventory read
charges. That allowance renews for each snapshot; repeated snapshots can
exceed 256 MiB of total read work across the command. Counting adds at most
512 active link FDs (independent of physical site count), 4096 lifetime cookies, 8192 map keys, 256 possible CPUs and
32 MiB host-state charges; the combined link bound is 1024. Charges precede
allocation/attachment; cookie meanings are never recycled. Fixed maps bound kernel storage separately; host-state charges
are not a total kernel memory claim. Resource/deadline failures remain gaps.

The controller polls/drains every 100 ms and rescans every second, with a
25 ms finite observation-drain deadline per iteration. These are cooperative
budgets, not guarantees against a stalled syscall or delayed work. Startup,
warm/built-in activation, query races, sampling and cleanup gaps are explicit.
There is no universal first-call or terminal-count guarantee. Normal capture
is PARTIAL. A [measured single-PID inventory sample](release-v0.3.0.md#measured-inventory-cost)
reports scanner cost with tracing disabled; it does not establish system-wide
or callback-tracing performance. The [historical matrix](overhead-matrix.md)
measures an earlier route only.

Timeout/cancellation closes observer resources. An independently running target
and a released owned workload are left running when observation ends; signal
the observer PID rather than a process group containing the workload. Setup
failure resolves stopped owned children. Observer crash/SIGKILL before child
release can strand a stopped child and requires external cleanup.

<a id="exit-codes"></a>

### Execution exit codes

| Code | Meaning |
| --- | --- |
| 0 | COMPLETE report window, or satisfied definite policy on one (schema case; normal runs are PARTIAL, exit 3). |
| 1 | Child failure, artifact delivery failure or runtime failure (with or without usable observation). |
| 2 | Invalid arguments/policy or invalid explicit companion. |
| 3 | PARTIAL report or doctor unavailable/denied capability. |
| 4 | Report/check setup/environment refusal without usable observation. |
| 10 | Definite policy violation, taking precedence over other usable-result failures. |
| 11 | Policy inconclusive; normal Unknown-only candidate evidence cannot satisfy definite algorithm rules. |

Artifact/runtime/child failure takes precedence over partial or inconclusive
status, while a definite violation retains exit 10. Retain artifacts and gaps
when interpreting failure; successful stimulus alone proves no observation.

### Accepted-but-undocumented surface (documented limits)

Stated here instead of left silent. `report`/`check` accept
manual/legacy flags not shown in their usage lines: `--object`,
`--members-object`, `--dev-bundle`, `--provider`, `--builtin`,
`--settle`, `--image-digest` and `--force-offset`. `--table` and
`--provider-table` parse and then refuse (`table enrollment is deferred
beyond v0.2`). The normal workflow needs none of these; explicit object
overrides stay operator-trusted as described above.

`doctor --pid PID` and `doctor --exe PATH` select a sectioned
foreign-backing/target preflight. That route is named in the top-level
help but not in `doctor --help`, and it needs install-package metadata:
where the install carries none (containers) it refuses with exit 4, so
container probes use bare `doctor --format json` (exit 0/3) instead —
see [container](container.md) and
[deploy/kubernetes/README.md](../deploy/kubernetes/README.md).

`service-witness` and `service-attempt-trace` are harness-only
signal-observation commands (absent from the top-level help; each
prints its own `--help`). They observe a test harness's signal traffic
for verdict adjudication and are not operator tools.

Name collision: `osslscope inspect` (this page's process/module
inventory) is unrelated to `docker inspect` (container config; the
container page uses it to verify `Privileged=false` and the cap set).

## Legacy foreground diagnostic

Explicit `--libcrypto PATH` selects the v0.2 fixed-profile route:

```sh
osslscope doctor --libcrypto LIB --count-object COUNT --format json
osslscope report --libcrypto LIB --count-object COUNT --duration 5 run -- COMMAND
osslscope check --libcrypto LIB --count-object COUNT --require-executed SHA256 run -- COMMAND
```

It requires the exact enrolled x86-64 library/kernel identity and protected
backing, accepts only one owned run and loads legacy Count alone. `--libcrypto`
conflicts with `--pid` and `--observation-object`. It is not an automatic
fallback. Legacy timeout/grace permit zero for immediate expiry. Its definite
catalogue entries, partial positive-policy behavior and qualification are
historical; see [v0.2 notes](release-v0.2.0.md), [catalogue](../profiles/README.md)
and [historical overhead](overhead-matrix.md). Offline `alias-audit` remains
available; its input does not become new runtime evidence. Manual offsets,
reader/member objects, services and following are outside the normal workflow.

### Candidate hints and public API activity

Current automatic report/check output adds optional v2.4 candidate identities,
site provenance and a separate public API activity ledger. Known vocabulary is
only a display hint; custom opaque IDs remain visible. Positive entries from
retired generations are retained. Candidate associations never multiply physical
counts or establish definite algorithm/provider attribution.

Available public digest, cipher, MAC, KDF, PKEY and RAND exports are observed
using scalar entry/return aggregates. Operators still select only scope and
duration. The observer does not read operational arguments, buffers or opaque
contexts. Success means the documented integer return was observed; wrappers,
setup and size queries are included. It does not mean a cryptographic result was
produced. API activity is separate from callback totals and definite policy/CBOM
assets. Missing attachments, pairing/depth/map losses, tails and unknown returns
remain explicit. A fetched but unused method has no operational entries.

For owned short commands, independently validated operational exports can be
prearmed on retained executable/dependency files before release. This is a
separate capability from entry-only static table shapes. Predicted loader files,
late modules and available prefixes still leave gaps; a static lookalike never
authorizes a target-memory decoder. See the [output contract](observed-crypto-v2.md)
and [privacy read set](privacy/allowlist-v1.md).
