<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope 0.5.0 quickstart

One lane, honest output: Linux x86-64, kernel 6.9+ (feature-probed, not
`uname`), BTF at `/sys/kernel/btf/vmlinux`, cgroup v2, stock OpenSSL
3.5.x. Reports stay **PARTIAL** (exit 3); algorithm checks stay
inconclusive (exit 11) on Unknown-only evidence. Host commands below
ran verbatim in a fresh-guest drill from a clean clone; container
commands repeat the drilled recipes from the container and Kubernetes
pages.

**Before you paste anything.** Warm processes can report zero counts
without proving non-use. There is no first-call guarantee: calls
before attachment or after retirement are uncovered, and startup,
polling, invalidation and final drain leave explicit gaps. Mappings
on overlayfs stay `locator_candidate` and foreign `--pid` attach there
observes nothing — if `stat -f -c %T /usr` prints `overlayfs`, stage
the traced libcrypto on tmpfs first (step 4). Prefer `run --` over `--pid`
for short-lived targets: the observer prearms the child before release,
so counts survive even after it exits. A user-owned `$HOME/.local`
install is passive-discovery only; tracing needs the root-owned
install below. Bare `cargo build` traces nothing — the source path
(step 6) starts with `build-dev.sh`.

## 1. Install a binary package

From the release artifacts (`osslscope_0.5.0-1_amd64.deb`,
`osslscope-0.5.0-1.x86_64.rpm`, `osslscope-0.5.0-prefix.tar.gz`):

```sh
sudo dpkg -i osslscope_0.5.0-1_amd64.deb      # Debian/Ubuntu
osslscope --version
```

```sh
sudo rpm -i osslscope-0.5.0-1.x86_64.rpm      # Fedora/RHEL
osslscope --version
```
(RPM proven live in the 0.5.0 lane: Fedora 43 cell, `rpm -i`
exit 0 → `--version` 0.5.0 → getcap `cap_perfmon,cap_bpf=ep` →
`doctor --format json` exit 0 with silent stderr → `rpm -e`
exit 0 with file-level verify.)

```sh
sudo tar -xzf osslscope-0.5.0-prefix.tar.gz -C /usr   # any lane host
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope
osslscope --version
```

The DEB grants the two file capabilities in postinst and reloads
systemd; it never enables the service. The RPM carries the caps as a
file attribute and ships no unit. The tarball's receipt binds `/usr`:
extract into that exact prefix, never over an existing install.

## 2. Doctor: prove the host qualifies

```sh
osslscope doctor --format json
echo "exit=$?"
```

```text
{"capabilities":{"bpf":"available","count_companion":"available","count_load":"available","inventory":"available","observation_companion":"available","observation_load":"available","pid_namespace":"available","ring_buffer":"available","uprobe_multi":"available","user_read":"available"},"execution":"not_observed","historical_activation":"unknown","record":"doctor","schema_version":"osslscope.focused.doctor.v1"}
exit=0
```

Exit 0 with every capability `available` and empty stderr: the host
qualifies. Anything else fails loud — fix the named capability first.

## 3. Scan: passive inventory, no privileges needed

```sh
osslscope scan --json
```

```text
{
  "interval": {
    "started_unix_ms": 1794323498311,
    "finished_unix_ms": 1794323498625,
    "elapsed_ns": 313452508
  },
  "scope_record": {
    "cgroup": null,
    "modules": []
  },
  "schema_version": "osslscope.discovery.v1",
  "mode": "snapshot",
[…truncated: 94748 bytes total; stderr:]
osslscope discovery: inventory partial: identity_unverified (27 gaps; see records above)
```

Useful partial inventory, exit 3: metadata without activation or
execution claims. Gaps stay visible — never silent success.

## 4. Report: trace one owned command

If `/usr` is overlayfs (containers, throwaway guests), stage the
traced library on tmpfs first — `run --` inherits `LD_LIBRARY_PATH`:

```sh
mkdir -p /dev/shm/ossl-tmpfs
LIBCRYPTO=$(ldd "$(command -v openssl)" | awk '/libcrypto/ {print $3; exit}')
cp "$LIBCRYPTO" /dev/shm/ossl-tmpfs/
export LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs
```

Then:

```sh
osslscope report --duration 5 --format json --out report.json run -- openssl dgst -sha256 /dev/null
echo "exit=$?"
```

```text
osslscope: focused callbacks attached (pid=465, sites=2857)
osslscope: partial evidence (11 gaps: unknown-denominator, …)
exit=3
```

Exit 3 PARTIAL is the normal outcome. `report.json` is ~8 MB; its
verdict and nonzero counts:

```sh
python3 -c "import json; d=json.load(open('report.json')); print(d['schema_version'], d['completeness']['status']); print([(r['api'], r['entries'], r['observed_success']) for r in d['api_activity'] if r['entries']])"
```

```text
observed-crypto-v2.6 PARTIAL
[(20, 2, 2)]
```

Exit meanings (`report`/`check`): **0** a COMPLETE window (schema case;
not observed on this lane — normal runs exit 3); **1** child, artifact
or runtime failure; **2** invalid arguments/policy; **3** PARTIAL
report or unavailable/denied capability; **4** setup/environment
refusal with no verdict; **10** definite policy violation; **11**
policy inconclusive on Unknown-only evidence. A `check` on this lane
exits 11:

```sh
osslscope check --duration 5 --require-executed SHA256 run -- openssl dgst -sha256 /dev/null
echo "exit=$?"
```

```text
osslscope: focused callbacks attached (pid=470, sites=2857)
[…263 KB human summary on stdout, ending:]
policy: inconclusive
  rule require-executed (SHA256): inconclusive (definite=0, possible=unknown, relevant_complete=false)

status=PARTIAL
absence = not-observed in window (never "not present / never used")
exit=11
```

The `COMPLETE` examples in [the output
contract](observed-crypto-v2.md) are synthetic pinned fixtures
(`tests/goldens/report-v2-complete.json`), not field samples: normal
runs are PARTIAL.

## 5. Containers and Kubernetes

With Docker installed, build the image from the repo root (never
`--privileged`, always `--cap-drop ALL` + named caps + the shipped
seccomp profile). Owned workload first:

```sh
docker build -t osslscope:0.5.0 .
docker run --rm --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --security-opt seccomp=deploy/seccomp-osslscope.json \
  osslscope:0.5.0 report --duration 5 --format json run -- openssl dgst -sha256 /dev/null
```

Exit 3 PARTIAL, 2780 sites, `entries=2 observed_success=2` (drilled;
see [container](container.md)). Host observer (root-in-container,
5 caps, `apparmor=unconfined`, read-only BTF/cgroup/security mounts):

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

Exit 0, then a host-PID `report` exits 3 PARTIAL (2849 sites,
`entries=609`; stage tmpfs libcrypto on overlay hosts). Full recipes
and inspect evidence: [container](container.md).

On Kubernetes (amd64 nodes, kubelet ≥ 1.30, seccomp profile installed
on every node, ~2 GiB per pod), Job first, then the EXPERIMENTAL
DaemonSet:

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml \
  -f deploy/kubernetes/configmap.yaml \
  -f deploy/kubernetes/job-report.yaml
kubectl -n osslscope get job osslscope-report
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

The Job reads `Failed` with exit 3 — that `Failed` + PARTIAL log IS
the success signal. The stock DaemonSet refuses with exit 2 until you
select a target in the ConfigMap. Full drill transcript:
[deploy/kubernetes/README.md](../deploy/kubernetes/README.md).

## 6. From source (no package)

Bare `cargo build` traces nothing: it builds the host CLI without the
five BPF companions. First confirm the floor, then build, install to a
root-owned prefix, grant caps, and re-run doctor:

```sh
uname -r
ls -l /sys/kernel/btf/vmlinux
findmnt -t cgroup2
git clone https://github.com/mingulov/osslscope.git
cd osslscope
./scripts/build-dev.sh --release
sudo ./scripts/install-dev.sh --prefix /usr/local
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/osslscope
/usr/local/bin/osslscope doctor --format json
```

Prerequisites (Rust 1.88.0 + nightly-2026-05-20 + bpf-linker 0.10.4,
Python 3.11+): [build](build.md). `$HOME/.local` stays passive-only:
file capabilities on a user-owned binary do not create a tracing
install — automatic companion selection refuses it.

## 7. Uninstall

Tar (prefix `/usr`) and source (prefix `/usr/local`) — also clears the
file caps, which live on the inode:

```sh
sudo setcap -r /usr/bin/osslscope 2>/dev/null || true
sudo rm -rf /usr/bin/osslscope /usr/lib/osslscope /usr/share/osslscope /usr/share/doc/osslscope
rm -rf report.json
```

```sh
sudo setcap -r /usr/local/bin/osslscope 2>/dev/null || true
sudo rm -rf /usr/local/bin/osslscope /usr/local/lib/osslscope /usr/local/share/osslscope /usr/local/share/doc/osslscope
rm -rf report.json
```

```sh
sudo dpkg -r osslscope
sudo rm -rf /var/lib/osslscope
```

```sh
sudo rpm -e osslscope
sudo rm -rf /var/lib/osslscope
```

DEB removal stops the unit (never enabled by install) and keeps the
conffile plus the out-DIR; the RPM ships no unit. Delete
`/var/lib/osslscope` (windows, `sequence.json`, reports) yourself.
Containers:

```sh
docker rmi osslscope:0.5.0
kubectl delete -f deploy/kubernetes/daemonset.yaml \
  -f deploy/kubernetes/job-report.yaml \
  -f deploy/kubernetes/configmap.yaml \
  -f deploy/kubernetes/namespace.yaml
```

Verify nothing remains (osslscope never pins under `/sys/fs/bpf`,
so unrelated entries such as snapd's `snap` may list — the grep must
find no `ossl`):

```sh
hash -r; command -v osslscope || echo "binary gone"
getcap /usr/bin/osslscope /usr/local/bin/osslscope 2>/dev/null | grep . || echo "caps gone"
systemctl is-active osslscope-service 2>/dev/null || echo "service gone"
ls /sys/fs/bpf | grep -i ossl || echo "no osslscope pins"
```
