<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Attach failures: exit-4 decision tree

Exit 4 means evidence is unusable/no verdict: environment failure,
bare AttachZero, recycled target, or an unsuitable target. Runtime
fatal remains policy-eligible even with zero calls; AttachZero with
proved positive in-window ENGINE evidence is also eligible. A proved
violation exits 10; otherwise usable fatal exits 1. Eligibility does
not prove any rule. Follow the exit-4 tree for unusable evidence;
see [the full precedence](usage.md#exit-codes).
<!-- source: exit precedence + Fatal kinds: src/report.rs,
     src/check.rs, src/capture.rs (FatalKind) -->

```text
exit 4
  |
  +-- from `doctor`? -----------------> read the failing check below,
  |                                     remediate, re-run `doctor`
  |
  +-- from `report`/`check`?
        |
        +-- message says pid recycled / target gone?
        |     YES -> short-lived or exited target: re-run; prefer
        |            `run --` over `--pid` for short-lived processes
        |
        +-- message says zero probes attached?
        |     YES -> run `doctor` (env) and `doctor --pid P` /
        |            `doctor --libcrypto PATH` (target), remediate
        |            the failing check, re-run
        |
        +-- otherwise (BPF load / fork / setup maps failure)?
              YES -> run `doctor`, remediate, re-run; a maps/uid
                     failure on a foreign-uid target usually means
                     file caps plus CAP_SYS_PTRACE (or run as the
                     target user / root)
```

Requested artifacts are attempted independently even on fatal paths.
An artifact write/delivery failure is a tool failure (exit 1 when
no higher priority result applies), not an exit-4 setup category.

After `doctor` is green, walk up the ladder before re-gating:
`inspect` (does discovery produce rows?) then `report` (does a
window open?) then `check` (does the rule evaluate?).

## Failing-check to remediation map

`doctor` prints one line per check plus a `remediate:` line on
failure and exits 4. The checks, in the order to fix them:

| Failing check | Cause | Remediation |
|---|---|---|
| `caps` | Neither file caps nor root effective. | One-time setup: `sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope`, then re-run unprivileged. Install on a filesystem that honors file capabilities -- setcap is silently stripped on `nosuid` mounts. |
| `kernel` (feature probe) | Missing BPF features (`uprobe_multi`, ringbuf, `probe_read_user`, cookie). The floor is 6.9; this is a functional probe, never a version match. | Move to a 6.9+ kernel (on Ubuntu 24.04 servers, install the HWE kernel -- see [CI recipes](ci-recipes.md#runner-image)). Pre-6.9 is not supported, no fallback exists. |
| `lockdown=confidentiality` | Lockdown blocks the attempted BPF operation even with caps held. | Retain the required security state and record the refusal. An approved alternative observation environment does not qualify the confidentiality-lockdown or Secure Boot cell. |
| `lsm` | Active LSM denial (AppArmor/SELinux policy). | Inspect the denial with the security owner and use an approved policy that preserves required enforcement. Do not disable SELinux/LSM controls to pass; re-run in the required state. |
| `seccomp` | A seccomp filter may be EPERMing `bpf`/`perf_event_open` syscalls. | Restricted-seccomp environments (locked-down shared CI, Autopilot-class) are unproven stretch: move the gate to a VM/self-hosted runner where `doctor` goes green. |
| `spawn-access` | The spawn-setup probe child maps are unreadable or empty (the observer's pre-exec self-dumpable call failed, or the kernel denies same-uid reads anyway). `run --` setup would fail the same way. | Run once with sudo to confirm the environment, then report it: this row failing means the product mechanism broke, not the install. |
| `pidns` | Observer and target are in different pid namespaces. | Observe from the target's pid namespace (see [staging deploy](staging-deploy.md)). |
| `libcrypto-found` | Target maps no readable libcrypto (wrong path, `ENOENT`, `(deleted)` after upgrade, or a static binary). | Fix the path; for static binaries see below. |
| `arch` | Non-x86-64 target (including 32-bit). | Current observation is x86-64-only; observe an admitted x86-64 build. |
| `flavor` | Not OpenSSL 3.x/4.x (BoringSSL/AWS-LC lookalike, unrecognized bytes, or path confusion such as pointing `--libcrypto` at a static server binary). | Point at a real OpenSSL libcrypto, or use `--builtin` provider mode with an enrolled build. |
| `build-id` / `dispatch-anchor` | An unknown id alone is informational when a supported symtab route resolves. The current table has eleven exact builds; unknown stripped builds lack that route. Rebuilds can change ids/offsets. | Read the anchor/admission verdict. Recheck exact bytes after rebuild; explicitly enroll unknown stripped builds per [the built-in runbook](builtin-runbook.md), using the same table on doctor and capture. |
| `btf` | Informational only: the probe path has zero BTF dependence. | Nothing required. |
| `token-support` / `perf` rows | Informational only. | Nothing required. |

<!-- source: check names + verdicts: src/doctor.rs; build-id
     table size: etc/build-id-table.json, tests/build_id_table.rs;
     admission routes: tests/onboarding.rs -->

## Target-shape refusals (correct behavior, not bugs)

- **Static binary as `--libcrypto`:** `doctor` exits 4 with a
  flavor/path-confusion failure -- a static server is not a
  library. Observe it in `--builtin` provider mode instead (see
  [the static-target recipe](staging-deploy.md#observe)); a
  *stripped* unknown static binary needs explicit enrollment for
  report/check; inspect may expose disclosed zero-row blindness.
- **Static target under `doctor --pid`:** `no libcrypto.so
  mapped in target` is the designed refusal; same `--builtin`
  path applies.
- **FIPS libcrypto unknown to the build-id table:** provider-mode
  observation (`--provider .../fips.so`, not `--builtin`) is the
  supported FIPS path; see [the FIPS interim rule](fips-interim.md).
- **`--pid` on a pre-loaded provider** can miss discovery when no
  post-attach query occurs. Inspect uses harvest reasons such as
  `no-query`; report/check use typed coverage/window/loss reasons.
  Read the actual status, including AttachZero if no provider
  probes attached. `run --` improves custody without guaranteeing
  startup completeness.
