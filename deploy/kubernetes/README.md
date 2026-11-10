# osslscope on Kubernetes (0.5.0)

Plain-YAML manifests, no Helm. Two workloads:

| Manifest | What | Status |
|---|---|---|
| `namespace.yaml` | `osslscope` namespace | required |
| `configmap.yaml` | service config for the DaemonSet | required |
| `daemonset.yaml` | continuous observer, one pod per amd64 node | EXPERIMENTAL |
| `job-report.yaml` | one-shot owned-workload report | SUPPORTED |

The SUPPORTED in-cluster path is the one-shot Job. The DaemonSet service
is EXPERIMENTAL in 0.5.0: it runs, its Ready state tracks per-node
doctor qualification, but continuous in-cluster observation has not had
the soak or matrix a supported claim needs.

## Requirements

- amd64 nodes (`nodeSelector: kubernetes.io/arch=amd64` on both
  workloads), Linux kernel 6.9+ (feature-probed), BTF
  (`/sys/kernel/btf/vmlinux`), cgroup v2.
- kubelet >= 1.30 (the DaemonSet uses the `appArmorProfile` field).
- The published image `ghcr.io/mingulov/osslscope:0.5.0`
  (`imagePullPolicy: IfNotPresent`; pre-publish, `kind load` a local
  build — see below).
- ~2 GiB allocatable memory per osslscope pod. Measured, not guessed:
  the tracing engine peaks at ~1.31 GiB (memcg-charged kernel BPF
  memory — guest dmesg forensics; a 1 Gi limit OOMs with exit 137),
  so both workloads request 1 Gi and limit 2 Gi. Proven over drill
  windows only; longer service soaks are unproven in 0.x.
- The shipped seccomp profile installed on EVERY node as the kubelet
  localhost profile `osslscope.json`:

```console
$ sudo cp deploy/seccomp-osslscope.json /var/lib/kubelet/seccomp/osslscope.json
```

Both workloads set `seccompProfile: {type: Localhost,
localhostProfile: osslscope.json}`. There is no
`seccomp=unconfined` recipe on Kubernetes (on Docker it is a
diagnostic fallback only, never a recipe). The profile is the container-runtime
default plus exactly one appended `bpf` allowance (see
`../seccomp-osslscope.json` and `docs/container.md`).

## Privilege posture

Never `--privileged`, never hostNetwork, never `CAP_SYS_ADMIN`, never
`NoNewPrivileges` (it voids the file capabilities). Both workloads
`drop: [ALL]` and add named caps only:

- Job: `BPF, PERFMON` (the minimal 2-cap owned tier), non-root
  `osslscope` user, no host mounts, no hostPID. This is the documented
  `docker run` owned recipe, moved into a Pod.
- DaemonSet: `BPF, PERFMON, SYS_PTRACE, CHECKPOINT_RESTORE,
  DAC_READ_SEARCH` (the 5-cap set the systemd unit carries, see
  `packaging/deb/osslscope-service.service`), root in-container,
  `hostPID: true`, read-only host mounts for BTF, cgroup v2, and
  kernel security. (YAML spells caps WITHOUT the `CAP_` prefix.)
  AppArmor is explicitly `Unconfined`: the container default profile
  denies the ptrace reads host-observer mode needs (proven: 5 caps
  alone fail with `EACCES` on `/proc/PID/exe`+`/proc/PID/maps`; see
  `docs/container.md`).

The namespace enforces `pod-security.kubernetes.io/enforce:
privileged` (see the comment in `namespace.yaml`): these pods cannot
run under `restricted`, so restricted clusters are UNSUPPORTED in 0.x.
There is no RBAC to apply: osslscope ships no Kubernetes client and
talks to no API server.

## Apply

```console
$ kubectl apply -f deploy/kubernetes/namespace.yaml \
    -f deploy/kubernetes/configmap.yaml \
    -f deploy/kubernetes/job-report.yaml \
    -f deploy/kubernetes/daemonset.yaml
```

Namespace first (the rest live in it). Job before DaemonSet is the
suggested order: the Job proves the node can trace before you install
the continuous observer. The manifests carry NO tolerations: tainted nodes are excluded from
the DaemonSet's desired count (observed in the drill: a tainted node
gets no pod and does not count against Ready). On a single-node kind
cluster, remove the control-plane taint first (`kubectl taint nodes
--all node-role.kubernetes.io/control-plane-`), otherwise desired
stays 0 and nothing ever schedules. Real clusters follow their own
control-plane taint policy — check `desired` covers the nodes you
intend to observe.

## Reading the results (honest exits)

Reports are PARTIAL, checks fail loud. The exit contract:

- Job: a useful-but-gapped run exits **3** with a PARTIAL report — the
  NORMAL outcome. The Job object therefore reads `Failed` with exit
  code 3. That `Failed` + PARTIAL log IS the success signal (see the
  transcript below); `backoffLimit: 0` keeps a PARTIAL from retrying
  into a second identical PARTIAL. Exit 4 with no verdict = a
  setup/environment refusal, fail LOUD.
- DaemonSet: readiness AND liveness are exec probes running `osslscope
  doctor --format json`. osslscope exposes NO HTTP endpoint, so there
  is no httpGet probe to write. That command routes to the focused
  capability checks: exit 0 on a qualifying node, exit 3 with a loud
  stderr reason when a capability is unavailable — DaemonSet Ready
  therefore tracks per-node qualification, and unqualifying nodes
  fail loud (probe failures in pod events) instead of green. (The
  sectioned exit-4 vetting route is NOT usable here: it refuses with
  exit 4 on every container — `package admission refused: unavailable
  package metadata` — because it needs install-package metadata the
  image does not carry. Exit 3 is the honest unqualifying signal for
  these probes.)

## Stock config refuses (operator action required)

The shipped ConfigMap selects NO targets, and the service refuses to
run observe-nothing: DaemonSet pods exit **2** (`service requires at
least one of --pid/--cgroup`) until you pick ONE target shape. Edit
the ConfigMap (uncomment and fill in `pid` or `cgroup` — PIDs are
node-local under hostPID, so prefer `cgroup` for durable selections),
then roll the DaemonSet:

```console
$ kubectl -n osslscope edit configmap osslscope-service
$ kubectl -n osslscope rollout restart daemonset/osslscope
```

## No-install option: none supported in 0.5.0

There is NO supported no-install recipe in this release. What was
tried and rejected: `kubectl debug` with the default profile cannot
exec the file-caps binary at all (`operation not permitted`, exit
255), and `--profile=sysadmin` would create a PRIVILEGED ephemeral
container — contradicting the posture above — so it is not offered.
To trace without installing the DaemonSet, run the one-shot Job (it
needs no prior install beyond `kubectl apply -f job-report.yaml`).

## Uninstall

```console
$ kubectl delete -f deploy/kubernetes/daemonset.yaml \
    -f deploy/kubernetes/job-report.yaml \
    -f deploy/kubernetes/configmap.yaml \
    -f deploy/kubernetes/namespace.yaml
$ sudo rm /var/lib/kubelet/seccomp/osslscope.json   # every node
```

## Drill transcript (kind, guest lane)

Provenance: single-node kind v0.27.0 (node image
`kindest/node:v1.32.2`, kubectl + server v1.32.2, control-plane taint
removed for the drill), image `ghcr.io/mingulov/osslscope:0.5.0` via
`kind load docker-image` (pre-publish equivalent of the published
image tag — for release manifests use a FRESH kind cluster (delete +
recreate): kind keeps loaded images in node-local containerd, so
host-side `docker rmi` does NOT evict them and `IfNotPresent` would
otherwise shadow the release image with no warning; confirm digest
identity via `kubectl get pod -o jsonpath={..imageID}` before
trusting a run),
seccomp profile copied into the node at
`/var/lib/kubelet/seccomp/osslscope.json`. The cluster ran inside a
KVM guest (the live-BPF containment lane). kind shares the host
kernel, so this drill proves the MANIFESTS (apply → schedule →
probe → report), not kernel breadth. (`-o wide` tables below
show the decision columns only — CONTAINERS/IMAGES/SELECTOR and
IP/NODE columns trimmed for readability; shown values are verbatim.)

> NOTE: kind-in-guest containers sit on overlayfs, and foreign attach
> to overlay-backed libcrypto observes nothing (a guest-lane artifact,
> same as the Docker observer drill — see `docs/container.md`). The
> DaemonSet therefore attaches but reports zero observations in this
> lane; the Job (owned mode, which attaches fine on overlay) carries
> the nonzero-counts proof.

### 1. Stock config refuses (exit 2, loud)

```console
$ kubectl apply -f namespace.yaml -f configmap.yaml -f daemonset.yaml
namespace/osslscope created
configmap/osslscope-service created
daemonset.apps/osslscope created
$ kubectl -n osslscope get ds osslscope -o wide
NAME        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   AGE
osslscope   1         1         0       1            0           75s
$ kubectl -n osslscope get pods -o wide
NAME              READY   STATUS             RESTARTS      AGE
osslscope-x4hsv   0/1     CrashLoopBackOff   3 (38s ago)   75s
$ kubectl -n osslscope logs -l app.kubernetes.io/component=service
[pod/osslscope-x4hsv/osslscope] osslscope service: service requires at least one of --pid/--cgroup
```

Last exit code 2, reason Error. Ready stays 0 until the operator
selects targets — it never runs observe-nothing.

### 2. Job emits a PARTIAL report (exit 3)

```console
$ kubectl apply -f job-report.yaml
job.batch/osslscope-report created
$ kubectl -n osslscope get job osslscope-report -o wide
NAME               STATUS   COMPLETIONS   DURATION   AGE
osslscope-report   Failed   0/1           15s        15s
$ # pod exit: exit=3 reason=Error
```

`Failed` with exit code 3 IS the success signal (see above). The
report itself (16.7 MB CRI log on the node, 10088 × `partial`):

```text
osslscope: focused callbacks attached (pid=12, sites=2780)
"entries": 2,
"observed_success": 2
```

Same 2780 sites and entries=2 as the documented Docker owned drill.
Note: `kubectl logs` returned only a ~250-byte tail of this report
in the drill lane (mechanism unidentified); the full report was
read from the node's `/var/log/pods/...` files. Raising the
kubelet's `containerLogMaxSize`/`containerLogMaxFiles` does NOT
restore it — tested with `containerLogMaxSize: 50Mi` (rotation
stopped, single 16.7 MB node file) and `kubectl logs` still
returned a 253-byte tail. For multi-MB reports, fetch the full
log from the node's `/var/log/pods/...` files (the drilled
fallback).

### 3. Unqualifying node fails loud (BTF masked → exit 3)

A pod identical to the DaemonSet's container (root, 5 caps, hostPID,
seccomp, AppArmor unconfined, cgroup/security mounts) except `/sys/kernel/btf`
masked by an emptyDir, running `doctor --format json`:

```console
$ kubectl -n osslscope logs pod/doc-nobtf
osslscope doctor: capability unavailable: count_companion(unavailable), count_load(not_checked), observation_load(unavailable) (see capabilities above)
{"capabilities":{"bpf":"available","count_companion":"unavailable",...},"record":"doctor","schema_version":"osslscope.focused.doctor.v1"}
$ # pod exit: exit=3 reason=Error
```

The control pod (same spec, real BTF mount) exits 0 with every
capability `available` — BTF is the isolated single variable, and
the failure is loud (nonzero exit + stderr reason + JSON), never
silent green. The DaemonSet's exec probes run this same command, so
a BTF-less node can never report Ready.

### 4. Configured DaemonSet: Ready tracks doctor

After selecting the workload's cgroup in the ConfigMap and rolling:

```console
$ kubectl -n osslscope get ds osslscope -o wide
NAME        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   AGE
osslscope   1         1         1       1            1           3m
$ kubectl -n osslscope get pods -l app.kubernetes.io/component=service -o wide
NAME              READY   STATUS    RESTARTS   AGE
osslscope-d5mt6   1/1     Running   0          3m
```

Pod events are clean (Scheduled/Pulled/Created/Started, no probe
failures). The service tiles windows to its out-DIR (emptyDir).
(Pasted from two drill runs: the `get` is drill6, the `exec`
is drill7 — pod hashes differ across runs.)

```console
$ kubectl -n osslscope exec osslscope-cb4wl -- ls /var/lib/osslscope/windows/
policy-status.json  sequence.json  service.lock
window-0000000000.json  window-0000000001.json  window-0000000002.json
window-0000000003.json  window-0000000004.json  window-0000000005.json
```

Six 30-second windows in ~3.5 minutes, as configured. (Window
*contents* in this lane carry the overlay caveat above; the Job's
entries=2 is the nonzero-counts proof.)

### 5. Tainted node evicts loud, reschedules on untaint

```console
$ kubectl taint nodes ossl-control-plane osslscope-drill-unqualified=true:NoExecute
node/ossl-control-plane tainted
$ kubectl -n osslscope get ds osslscope -o wide
NAME        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   AGE
osslscope   0         0         0       0            0           4m49s
$ kubectl taint nodes ossl-control-plane osslscope-drill-unqualified=true:NoExecute-
node/ossl-control-plane untainted
$ kubectl -n osslscope get ds osslscope -o wide
NAME        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   AGE
osslscope   1         1         0       1            0           5m49s
```

Eviction drops desired to 0 (a pod disappears — impossible to miss);
untainting reschedules (Ready follows per step 4).
