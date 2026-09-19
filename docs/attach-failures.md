<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Attach failures: exit-4 decision tree

Exit 4 means the evidence is unusable (or there is no evidence at
all): environment failure, zero probes attached, recycled target,
or an unsuitable target. Policy is never evaluated on fatal
evidence (`check` prints NO VERDICT). Follow the tree; every leaf
ends in a re-run.
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
        +-- otherwise (BPF load / fork / maps / write failure)?
              YES -> run `doctor`, remediate, re-run; a maps/uid
                     failure on a foreign-uid target usually means
                     file caps plus CAP_SYS_PTRACE (or run as the
                     target user / root)
```

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
| `lockdown=confidentiality` | Lockdown blocks BPF even with caps held. | Observe on a host without confidentiality lockdown. |
| `lsm` | Active LSM denial (AppArmor/SELinux policy). | Adjust the host policy per the `remediate:` line (package note included); re-run `doctor`. |
| `seccomp` | A seccomp filter may be EPERMing `bpf`/`perf_event_open` syscalls. | Restricted-seccomp environments (locked-down shared CI, Autopilot-class) are unproven stretch: move the gate to a VM/self-hosted runner where `doctor` goes green. |
| `pidns` | Observer and target are in different pid namespaces. | Observe from the target's pid namespace (see [staging deploy](staging-deploy.md)). |
| `libcrypto-found` | Target maps no readable libcrypto (wrong path, `ENOENT`, `(deleted)` after upgrade, or a static binary). | Fix the path; for static binaries see below. |
| `arch` | Non-x86-64 target (including 32-bit). | v1 is x86-64-only; observe an x86-64 build. |
| `flavor` | Not OpenSSL 3.x/4.x (BoringSSL/AWS-LC lookalike, unrecognized bytes, or path confusion such as pointing `--libcrypto` at a static server binary). | Point at a real OpenSSL libcrypto, or use `--builtin` provider mode with an enrolled build. |
| `build-id` | Unknown libcrypto build-id (not in the frozen 10-entry table and no `--table` override). Rebuilds always mint new ids (date-stamped builds). | Enroll the exact build per [the built-in runbook](builtin-runbook.md), or pass `--table` for the run. |
| `btf` | Informational only: the probe path has zero BTF dependence. | Nothing required. |
| `token-support` / `perf` rows | Informational only. | Nothing required. |

<!-- source: check names + verdicts: src/doctor.rs; build-id
     table size: etc/build-id-table.json; nosuid/file-caps lesson:
     customer-acceptance note -->

## Target-shape refusals (correct behavior, not bugs)

- **Static binary as `--libcrypto`:** `doctor` exits 4 with a
  flavor/path-confusion failure -- a static server is not a
  library. Observe it in `--builtin` provider mode instead (see
  [the design-partner static shape](staging-deploy.md)); a
  *stripped* static binary yields disclosed zero-row blindness.
- **Static target under `doctor --pid`:** `no libcrypto.so
  mapped in target` is the designed refusal; same `--builtin`
  path applies.
- **FIPS libcrypto unknown to the build-id table:** provider-mode
  observation (`--provider .../fips.so`, not `--builtin`) is the
  supported FIPS path; see [the FIPS interim rule](fips-interim.md).
- **`--pid` on a pre-loaded provider** yields zero rows
  (`no-query` / `pid-prewindow-blind` PARTIAL), not an error:
  harvest needs a post-attach query. Use `run --` so init
  postdates attach.
