<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Foreground preview usage

The v0.2.0 development route supports one exact enrolled x86-64 library/kernel
profile, one owned foreground process and its threads. Runtime qualification is
still open. Start with [build](build.md), [install](install.md) and the
[catalogue](../profiles/README.md). Broader modes in older developer references
are deferred; their flags are rejected by the current CLI.

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

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Help/offline success or doctor preflight without a hard failure; ordinary preview captures remain partial. |
| 1 | Failed child, failed artifact delivery or a usable post-observation runtime failure. |
| 2 | Invalid or deferred CLI/policy input, before acquisition. |
| 3 | PARTIAL observation, including satisfied positive rules. |
| 4 | Profile, namespace, Count ABI or setup/environment refusal without usable observation. |
| 10 | A definite policy violation; dominates child, artifact and usable runtime failure. |
| 11 | Policy inconclusive, including known algorithms unobserved under incomplete coverage. |

Live `inspect`, foreign `--pid`, `--provider`, `--builtin`, `--object`,
`--members-object`, `--dev-bundle`, table/offset overrides, `--settle`,
`--image-digest`, provider/ENGINE/weak rules, services and following are deferred.
Offline `alias-audit` remains available for an existing harvest document; it
performs no live acquisition. Its input does not become new runtime evidence.
