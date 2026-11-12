<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope 0.6.0 quickstart

Passive discovery with no privileges and no install: Linux x86-64
with stock OpenSSL 3.5.x on the target. Every command below ran
verbatim against this tree (yours prints your own PIDs, paths, and
counts); container commands ran against the freshly built
`osslscope:0.6.0` image. Tracing (`report`/`check`,
`--observe-crypto`, `--observe-providers`) needs a qualified host
and is out of scope here — see [usage](usage.md) and the drilled
[container](container.md) recipes.

**Before you paste anything.** Inventory rows describe ELF bytes and
mappings — never activation, execution, or non-use
(`not_observed` stays explicit, including for warm processes).
Exit 3 PARTIAL is the normal outcome wherever evidence is partial:
gaps stay visible, never silent success. A sample is not a lossless
history: mappings loaded after the sample stay uncovered, and
`locator_candidate` rows are unproven as mapped backing (overlayfs
mappings stay candidates) — only `verified` rows close the proof.
`comm=`/`exe=` are sanitized display fragments. Discovery output
may carry sensitive path spellings — treat redirects, logs, and
pastes as potentially sensitive.

## 1. Build from source

From the repo root (prerequisites: Rust 1.88.0 — see
[build](build.md)):

```sh
cargo +1.88.0 build --locked
export PATH="$PWD/target/debug:$PATH"
osslscope --version
echo "exit=$?"
```

```text
osslscope 0.6.0
exit=0
```

This page exercises passive discovery only. Tracing needs a
qualified host with the dev build, a root-owned install, and file
capabilities — see [build](build.md) and [install](install.md).
0.6.0 binary packages are not published yet.

## 2. Doctor: this host fails loud, discovery still works

```sh
osslscope doctor --format json
echo "exit=$?"
```

```text
{"capabilities":{"bpf":"denied","count_companion":"available","count_load":"unavailable","inventory":"available","observation_companion":"available","observation_load":"unavailable","pid_namespace":"available","ring_buffer":"not_checked","uprobe_multi":"not_checked","user_read":"not_checked"},"execution":"not_observed","historical_activation":"unknown","record":"doctor","schema_version":"osslscope.focused.doctor.v1"}
exit=3
```

stderr:

```text
osslscope doctor: capability unavailable: bpf(denied), count_load(unavailable), observation_load(unavailable), ring_buffer(not_checked), uprobe_multi(not_checked), user_read(not_checked) (see capabilities above)
```

`bpf: denied` means this observer may not load BPF here, so the
companion loads stay `unavailable` and the rest goes unchecked —
exit 3 with the reason on stderr, never silent success. Passive
discovery below is unaffected. On a qualified host every
capability reads `available` with exit 0 — see the drilled
transcripts in [container](container.md).

## 3. Scan: one process reads as rows

Pick a target mapping OpenSSL (yours prints your own PIDs):

```sh
grep -l 'libcrypto\|libssl' /proc/[0-9]*/maps 2>/dev/null | head
```

```text
/proc/457173/maps
/proc/467976/maps
```

```sh
T=457173
osslscope scan --pid $T
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
pid=457173 comm=python3 exe=bin/python3.14 modules=3 status=partial
  openssl_consumer sha256=53789b72a501 identity=locator-candidate size=236736 path=(unverified maps hint: /usr/lib/python3.14/lib-dynload/_ssl.cpython-314-x86_64-… version=none
  openssl_compatible sha256=5385f0436ac2 identity=locator-candidate size=6386528 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libcrypto.so.3) version=OpenSSL 3.5.5 27 Jan 2026
  openssl_consumer sha256=63b47f444efa identity=locator-candidate size=1114280 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libssl.so.3) version=libssl.so.3
identity: 0 verified, 3 locator-candidate of 3 modules (0% verified)
gaps: 10 (identity_unverified=10; rerun with -v for per-object detail)
  identity_unverified: candidate file metadata is unproven as the mapped backing; the mapping's true kind is unknown
exit=3
```

stderr:

```text
osslscope discovery: inventory partial: identity_unverified (10 gaps; see records above)
osslscope discovery: 13 of 13 modules unverified: permission denied (EPERM); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege
```

Top to bottom: the meaning boundary, the `kinds:` legend, one
verdict line per process, one row per OpenSSL-kind module
(short hash, identity, size, path evidence, file version),
verified-vs-candidate totals, and per-reason gap meanings. The
second stderr line is the privilege hint: the kernel denied this
observer (`EPERM`), so it names the supported remedy — it fires
only on such errno-proven denials.

## 4. Scan: the visible population

```sh
osslscope scan
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
pid=2 comm=- exe=unavailable modules=0 status=partial (0 OpenSSL modules, 0 other objects scanned)
pid=3 comm=- exe=unavailable modules=0 status=partial (0 OpenSSL modules, 0 other objects scanned)
pid=4 comm=- exe=unavailable modules=0 status=partial (0 OpenSSL modules, 0 other objects scanned)
pid=5 comm=- exe=unavailable modules=0 status=partial (0 OpenSSL modules, 0 other objects scanned)
pid=6 comm=- exe=unavailable modules=0 status=partial (0 OpenSSL modules, 0 other objects scanned)
[... 320 lines cut: 316 further verdicts, 3 module rows, identity totals; 321 verdicts total, then:]
gaps: 892 (backing_unavailable=31 identity_unverified=322 namespace_unavailable=414 process_unavailable=121 too_large=4; rerun with -v for per-object detail)
  backing_unavailable: executable backing could not be opened or its identity mismatched; the mapping's bytes are unknown
  identity_unverified: candidate file metadata is unproven as the mapped backing; the mapping's true kind is unknown
  namespace_unavailable: namespace identity could not be read; process coordinates are unverified
  process_unavailable: process exited or its /proc entries were unreadable; its inventory is unknown
  too_large: file over the 128 MiB read cap was not read; its kind, sha256, and version are unknown
exit=3
```

stderr:

```text
osslscope discovery: inventory partial: backing_unavailable, identity_unverified, namespace_unavailable (+2 more) (892 gaps; see records above)
osslscope discovery: 895 of 895 modules unverified: permission denied (EACCES); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege
```

Unprivileged, the whole population reads partial: 321 processes,
892 gaps, every reason counted and explained. Processes with no
OpenSSL modules still disclose how many other objects were
scanned — never a silent zero.

## 5. Verbosity: `-v` adds detail, never changes the answer

```sh
osslscope scan --pid $T -v
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
pid=457173 comm=python3 exe=bin/python3.14 modules=3 status=partial starttime=23978956 namespaces=pid=5:4026531836,mount=5:4026531832 provider_activation=unknown provider_interfaces=unknown execution=not_observed
  openssl_consumer sha256=53789b72a501 identity=locator-candidate size=236736 path=(unverified maps hint: /usr/lib/python3.14/lib-dynload/_ssl.cpython-314-x86_64-… version=none exports=[]
  openssl_compatible sha256=5385f0436ac2 identity=locator-candidate size=6386528 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libcrypto.so.3) version=OpenSSL 3.5.5 27 Jan 2026 exports=[ossl_provider_load, ossl_provider_try_load, ... 69 names total, cut ...]
[... libssl row and gap meanings as in step 3, then:]
gaps (10 total in 1 group):
  identity_unverified device=35 pid=457173: 10
exit=3
```

`-v` adds full per-process state, per-module exports, and grouped
gap blocks. `-vv` adds per-object gap records and a counters
line. Exits, stderr, counts, and `--json` bytes are identical at
every level; there is no `-q` — the default is already quiet.

## 6. JSON: pure machine bytes

```sh
osslscope scan --pid $T --json > scan.json
echo "exit=$?"
python3 -c "import json; d=json.load(open('scan.json')); print(d['schema_version'], d['mode'])"
```

```text
exit=3
osslscope.discovery.v1 snapshot
```

stdout parses alone — since 0.6 nothing else shares the channel
(tooling that parsed pre-0.6 mixed stdout must pass `--json`).
The evidence keys:

```sh
python3 -c "import json; d=json.load(open('scan.json')); p=d['processes'][0]; print('comm:', p['comm'], p['comm_status'], '| exe:', p['exe'], p['exe_status']); m=p['modules'][1]; print('identity:', m['identity_status'], '| unavailable:', m['verified_path_unavailable']); print('maps:', m['maps_spelling']['spelling']); print('soname:', m['info']['file_soname'], '| version:', m['info']['file_openssl_version'], m['info']['file_version_status'])"
```

```text
comm: python3 available | exe: /usr/bin/python3.14 available
identity: locator_candidate | unavailable: unverified_identity
maps: /usr/lib/x86_64-linux-gnu/libcrypto.so.3
soname: libcrypto.so.3 | version: OpenSSL 3.5.5 27 Jan 2026 present
```

Every mapped record carries `verified_path` /
`verified_path_unavailable` / `maps_spelling`, every process
carries `comm`/`exe` with availability, and every module carries
its own SONAME plus the validated rodata version. SONAME and
version strings describe bytes on disk — never loaded or
executed code. The shape is pinned by
`schemas/discovery-v1.json`; v0.5 `deny_unknown_fields` readers
reject v0.6 documents.

## 7. Watch: deltas plus a heartbeat

```sh
osslscope scan --watch --pid $T --interval 1 --duration 2
echo "exit=$?"
```

```text
Passive sampled inventory: mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
tick 1: initial state (status partial, processes 1, modules 0/3 verified)
  process_seen pid=457173 starttime=23978956
  module_seen pid=457173 starttime=23978956 sha256=53789b72a501 path=(unverified maps hint: /usr/lib/python3.14/lib-dynload/_ssl.cpython-314-x86_64-…
  module_seen pid=457173 starttime=23978956 sha256=5385f0436ac2 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libcrypto.so.3)
  module_seen pid=457173 starttime=23978956 sha256=63b47f444efa path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libssl.so.3)
pid=457173 comm=python3 exe=bin/python3.14 modules=3 status=partial
  openssl_consumer sha256=53789b72a501 identity=locator-candidate size=236736 path=(unverified maps hint: /usr/lib/python3.14/lib-dynload/_ssl.cpython-314-x86_64-… version=none
  openssl_compatible sha256=5385f0436ac2 identity=locator-candidate size=6386528 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libcrypto.so.3) version=OpenSSL 3.5.5 27 Jan 2026
  openssl_consumer sha256=63b47f444efa identity=locator-candidate size=1114280 path=(unverified maps hint: /usr/lib/x86_64-linux-gnu/libssl.so.3) version=libssl.so.3
identity: 0 verified, 3 locator-candidate of 3 modules (0% verified)
gaps: 10 (identity_unverified=10; rerun with -v for per-object detail)
  identity_unverified: candidate file metadata is unproven as the mapped backing; the mapping's true kind is unknown
tick 2: no changes (status partial, processes 1, modules 0/3 verified)
Watch ended: duration (status 3, snapshots 2, cumulative: partial-seen). Sampled history remains incomplete.
note: sample 1 was partial; history remains uncertain
  elapsed=2s+111074ns; limits: pids=4096 objects=16384 charged_bytes=1073741824 timeout=30s+0ns
  privilege: permission-denied gaps this run; remediation hint on stderr (see usage.md#privilege)
exit=3
```

stderr:

```text
osslscope discovery: watch inventory partial (see records above)
osslscope discovery: 13 of 13 modules unverified: permission denied (EPERM); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege
```

Quiet ticks print one line; change lines carry the same `path=`
evidence as the state beneath. The end verdict keeps cumulative
history — a later complete sample never erases earlier
uncertainty. Stop a foreground watch with Ctrl-C: one stderr
ack, the end record, exit 3, and the workload keeps running
(see [usage](usage.md#interrupt-contract)).

## 8. Inspect: one process, one file

```sh
osslscope inspect --pid $T
echo "exit=$?"
```

stdout is byte-for-byte the step-3 inventory for that PID
(verified with `diff`), exit 3. For a file on disk:

```sh
LIBCRYPTO=$(ldd "$(command -v openssl)" | awk '/libcrypto/ {print $3; exit}')
osslscope inspect --module "$LIBCRYPTO"
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
  openssl_compatible sha256=5385f0436ac2 size=6386528 path=(operator-supplied: /usr/lib/x86_64-linux-gnu/libcrypto.so.3) version=OpenSSL 3.5.5 27 Jan 2026
errors: 0
exit=0
```

Exit 0: the file inventory completed with no errors. The
`path=` labels the operator-supplied spelling — inspecting a
file makes no claim any process maps it, let alone executes it.

## 9. Containers: the same scans behind caps

From the repo root, build the image (never `--privileged`):

```sh
docker build -t osslscope:0.6.0 .
docker images osslscope:0.6.0
```

```text
IMAGE             ID             DISK USAGE   CONTENT SIZE   EXTRA
osslscope:0.6.0   cc33ef6065cd        171MB         42.6MB
```

A bare run fails — the image binary carries file capabilities,
so the caps must be granted or `exec` is refused:

```sh
docker run --rm osslscope:0.6.0 --version
echo "exit=$?"
```

```text
exec /usr/local/bin/osslscope: operation not permitted
exit=255
```

Owned workload, minimum caps (BPF+PERFMON), shipped seccomp
profile — the container sees only its own population:

```sh
docker run --rm --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  osslscope:0.6.0 scan
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
pid=1 comm=osslscope exe=bin/osslscope modules=0 status=partial (0 OpenSSL modules, 4 other objects scanned)
identity: no modules inventoried
gaps: 5 (changed=1 identity_unverified=4; rerun with -v for per-object detail)
  changed: file or process changed mid-sample, so the stale reading was discarded
  identity_unverified: candidate file metadata is unproven as the mapped backing; the mapping's true kind is unknown
exit=3
```

stderr:

```text
osslscope discovery: inventory partial: changed, identity_unverified (5 gaps; see records above)
osslscope discovery: 5 of 5 modules unverified: permission denied (EPERM); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege
```

Host observer: root-in-container, host PIDs, the 5-cap set,
`apparmor=unconfined`, read-only BTF/cgroup/security mounts —
here scanning host PID 1, whose rows verify:

```sh
docker run --rm --user root --pid=host \
  --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE \
  --cap-add CHECKPOINT_RESTORE --cap-add DAC_READ_SEARCH \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  osslscope:0.6.0 scan --pid 1
echo "exit=$?"
```

```text
Passive inventory: ELF exports and mappings do not prove activation or execution.
Provider activation/interfaces: unknown; execution: not_observed.
kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>
pid=1 comm=systemd exe=systemd/systemd modules=2 status=complete
  openssl_compatible sha256=5385f0436ac2 identity=verified size=6386528 path=/usr/lib/x86_64-linux-gnu/libcrypto.so.3 version=OpenSSL 3.5.5 27 Jan 2026
  openssl_consumer sha256=248673c0b485 identity=verified size=5017560 path=/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-259.so version=libsystemd-shared-259.so
identity: 2 verified, 0 locator-candidate of 2 modules (100% verified)
gaps: 0
exit=0
```

Exit 0 with `identity=verified` rows carrying plain `path=`
values: with host visibility the backing proof closes. Tracing
recipes stay in [container](container.md) (container drills);
Kubernetes stays in
[deploy/kubernetes/README.md](../deploy/kubernetes/README.md).

## 10. Exit codes: every one demonstrated

Discovery exits, each shown on this page:

| Code | Meaning | Shown in |
| --- | --- | --- |
| 0 | Complete inventory, no access/resource failure | steps 8–9 |
| 1 | Output/internal failure | below |
| 2 | Invalid arguments | below |
| 3 | Useful partial inventory | steps 2–7, 9 |
| 4 | Wholly unavailable observation | below |

```sh
osslscope scan --pid $T --json > /dev/full
echo "exit=$?"
```

stderr is `osslscope discovery: output failed`, exit 1.

```sh
osslscope scan --bogus-flag
echo "exit=$?"
```

stderr is `osslscope discovery: invalid arguments (see scan
--help or inspect --help)`, exit 2.

```sh
osslscope scan --pid 99999999
echo "exit=$?"
```

stdout ends with the `process_unavailable` gap and meaning,
stderr is `osslscope discovery: inventory unavailable:
process_unavailable (1 gap; see records above)`, exit 4.

```sh
osslscope scan --module deadbeef
echo "exit=$?"
```

stderr is `osslscope discovery: requested scope unavailable
(scan --module takes a file PATH, not a hash; see scan --help)`,
exit 4.

`report`/`check` add 10 (definite policy violation) and 11
(policy inconclusive) — see [usage](usage.md#exit-codes).

## 11. Cleanup

```sh
docker rmi osslscope:0.6.0
echo "rmi exit=$?"
rm -f scan.json
echo "rm exit=$?"
```

```text
Untagged: osslscope:0.6.0
Deleted: sha256:cc33ef6065cd402cdd09f9045f2675b968ee7ee4724f75143564bb4030de35a9
rmi exit=0
rm exit=0
```

This page grants no file capabilities, loads no BPF, and
installs no service — removing the image, the JSON artifact,
and the source clone leaves nothing behind.
