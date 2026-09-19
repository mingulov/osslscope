# CI gate recipes

CI gates use `check` in spawn mode (`run --`). Never `--pid` in
CI: pid attach is racy and staging-only by contract.
<!-- source: CI MUST use run: PRD.md section 6 -->

## Runner image

- Preferred: GHA `ubuntu-24.04` runners (full VM with sudo) or
  self-hosted 6.9+ runners with sudo for the one-time file-caps
  setup. The gate itself then runs unprivileged.
  <!-- source: beachhead + setup/assert split: ebpf-privileges note -->
- Avoid `ubuntu-22.04` images (below the kernel floor; see
  [who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)).
- On Ubuntu 24.04 **servers** (which default to the GA kernel),
  install the HWE kernel first -- the 6.8 GA kernel is below the
  6.9 floor and `doctor` will refuse it:

```sh
sudo apt-get install -y linux-generic-hwe-24.04
sudo reboot
# after reboot: uname -r must show a 6.9+ kernel
```

<!-- source: Server-defaults-GA + HWE recipe: ebpf-privileges note -->

## Setup phase (privileged, once per runner)

```sh
sudo dpkg -i osslscope_<ver>-1_amd64.deb   # or: sudo dnf install ./osslscope-<ver>-1.*.x86_64.rpm
getcap /usr/bin/osslscope                  # expect: cap_bpf,cap_perfmon+ep
```

Build the BPF objects the gate needs (nightly toolchain, see the
project README), then place them where the gate step can read
them. If the install hook warned about caps, re-apply:
`sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope`.
See [install](install.md).

## Gate step (unprivileged)

```sh
osslscope doctor || exit 4                      # preflight first, always

osslscope check \
  --provider /path/to/libcrypto.so.3 --builtin \
  --object ./osslscope-harvest --count-object ./osslscope-count \
  --deny-weak --deny-provider legacy \
  --require-executed ML-KEM-768 \
  --duration 30 --grace 5 \
  --format json --out gate.json --image-digest "$IMAGE_DIGEST" \
  run -- ./my-app --smoke-test
```

Notes:

- `check` needs at least one rule; a ruleless pass is a usage
  error (exit 2), never a green gate.
- `--builtin` observes libcrypto's built-in provider; drop it
  and point `--provider` at a provider `.so` to observe an
  external provider module instead.
- `--image-digest` records the container digest in the actionability
  tuple (empty string on bare metal).
- Defaults when flags are omitted: `--duration 30`,
  `--settle 2`, `--timeout 60`, `--grace 5` (all seconds).
  <!-- source: defaults: src/report.rs, src/check.rs, src/capture.rs -->

## Exit handling

<!-- source: CI handling table: PRD.md section 6 -->

| Exit | Meaning | Gate action |
|---|---|---|
| 0 | clean (COMPLETE, no violation) | pass |
| 3 | PARTIAL evidence, no violation | warn + upload artifacts; gate passes by default (strict-fail is team policy) |
| 10 | policy violation (on COMPLETE or PARTIAL) | fail; triage per [violation triage](violation-triage.md) |
| 4 | environment/attach failure | fail; run `doctor`, remediate, retry (see [attach failures](attach-failures.md)) |
| 1 | child failed (`child_exit` present) or observer bug (`child_exit` absent) | fail; branch on `child_exit` in gate.json |
| 2 | usage/config error | fail; fix the invocation |

Do NOT gate on COMPLETE status or exit 0 on real TLS apps: v1 is
explicitly not qualified for that (see [who should NOT
adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)).
Exit 3 with a passing policy verdict is the normal shape for
TLS-terminating services.

## Artifact upload

Always upload the gate artifacts, even on violation/PARTIAL --
they are written in all non-fatal outcomes:

- `gate.json` (the full evidence document: window, completeness,
  executions, legacy block, policy).
- The CBOM file when `--cbom` is passed (CycloneDX 1.6; PARTIAL
  evidence travels as a `metadata` disclaimer property).

Example (GitHub Actions):

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: cryptogate
    path: |
      gate.json
      cbom.json
```

## CI timeout

The CI step timeout must exceed the capture window plus drain
grace plus twice the unobserved test baseline:

```text
CI timeout >= duration + grace + test-baseline x 2
```

With defaults (30 s window, 5 s grace) and a 60 s smoke test,
set the step timeout above 155 s. A live child at window expiry
is `over-budget` PARTIAL by design (the observer never kills its
child), and a signal-cut window is always PARTIAL -- both are
avoided by sizing the timeout, not by raising the duration.
<!-- source: timeout rule: PLAN.md P6 exit 2; over-budget/signal
     semantics: PRD.md sections 5-6 -->
