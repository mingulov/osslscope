<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope CLI usage

Current commands: `inspect` / `report` / `check` / `doctor` /
`alias-audit`. Examples assume the binary is built
(`cargo build`) and you have elevated BPF rights — run
`osslscope doctor` first; it tells you exactly what is
missing and how to fix it.

## inspect — inventory a live process

Attach eBPF probes to a running process and list every OpenSSL
provider it has loaded, with per-provider algorithm coverage:

```sh
osslscope inspect --pid 1234 --provider /opt/openssl/lib64/ossl-modules/legacy.so \
  --object crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest --out inspect.json
```

- `--builtin` inventories libcrypto's built-in provider instead
  of a `.so` (with `--table`/`--force-offset` for stripped
  binaries — see [the built-in runbook](builtin-runbook.md)).
- `--legacy` additionally attaches ENGINE/low-level tripwires
  (fails loud if the target lacks them).
- The pid is pinned against reuse: if the process exits and
  its pid is recycled mid-run, osslscope refuses rather than
  attributing to the wrong process (exit 4 with a discard
  doc, never rows).
- `--settle S` / `--timeout S` bound the attach-settle and
  trigger-wait phases; `--marker M` requires the target's
  cmdline to contain `M` (matched at admission, never emitted);
  `--out FILE` writes the JSON doc instead of stdout.
- A degraded inventory is `PARTIAL` in the JSON doc and the
  process exits 3 — always read `status` (`inspect` shares
  the 3-on-PARTIAL rule with `report`/`check`).

## report — human/JSON summary over a capture window

`report` runs a bounded capture of `OSSL_FUNC_*` dispatch
calls (with wall-clock timestamps) and renders the verdict
directly. Discovery is automatic: BPF objects resolve from
trusted installed locations and the target's libcrypto from
its live mappings (in-libcrypto default provider mode):

```sh
osslscope report run -- ./my-app --serve
osslscope report --pid 1234 --duration 60
osslscope report --format json --out report.json --cbom bom.json run -- ./my-app --serve
```

- `run -- <cmd>` (spawn-and-observe) is the reliable mode;
  `--pid` (attach to live) is inherently racy — anything the
  target did before attach is invisible (cold-start gap).
- Output policy: the spawned workload's stdout and stderr both
  go to /dev/null by default — observer stderr carries ONLY
  observer diagnostics, and observer stdout stays a pure
  artifact channel (workload bytes can neither corrupt
  `--format json` nor leak workload secrets into captured
  JSON/diagnostics). Capture workload output explicitly per
  run: `--workload-out FILE` (create+truncate) or
  `--workload-out-fd N` (a caller-held fd, e.g. a harness
  pipe; mutually exclusive). Any non-negative fd parses,
  including 1/2 -- but an fd shared with the observer routes
  workload bytes into that observer channel (JSON corruption,
  secret mixing), so prefer an independent fd. Validity is
  checked pre-fork: a fd that is not open fails setup before
  any spawn. A child-side log-open failure exits 126 and
  fails setup naming the path (never silent null); a nonzero
  child exit without a destination prints one re-run hint
  line (exit + `--workload-out FILE`) and no workload bytes.
  `run --` predicts the target libcrypto pre-exec from the
  exe's `DT_NEEDED` closure plus loader search
  (`LD_LIBRARY_PATH`, rpath/runpath, system defaults);
  scripts, `dlopen`-only loads, unresolvable names, and
  dual-load closures (two libcryptos, refused) need explicit
  `--provider`.
- `--format json --out report.json` for machine consumption;
  `--cbom FILE` emits a CycloneDX crypto-BOM alongside.
- `--provider P` names a provider file explicitly (a `.so`
  for file-provider mode, or libcrypto with `--builtin`);
  `--object O` / `--count-object C` name explicit BPF
  objects. These are diagnosis/developer overrides — the
  defaults above are the normal path.
- `--table F` / `--force-offset N` / `--provider-table F`
  enroll an unknown local build explicitly (see [the
  built-in runbook](builtin-runbook.md)); unknown stripped
  builds are refused with enrollment remediation, never
  guessed.
- `--settle`, `--timeout`, `--grace` bound the run phases;
  `--duration` bounds the count window; `--image-digest D`
  records the container image digest in the target
  provenance.
- A capture may end `PARTIAL` (exit 3) instead of `COMPLETE`
  when evidence is degraded — e.g. events were dropped under
  load, the ring buffer overran, or the child exited early.
  PARTIAL is a result, not a failure: the JSON says what is
  missing and why. Treat PARTIAL captures as lower bounds,
  not inventories.

## check — policy gate (CI)

`check` captures and evaluates policy rules, exiting 10 on
violation, 11 when a rule is unproven under relevant
uncertainty (clean exit 0; at least one rule is required):

```sh
osslscope check --deny-engine --deny-weak run -- ./my-app --self-test
osslscope check --require-provider default --pid 1234 --duration 60
```

Rules: `--require-provider P`, `--deny-provider P`,
`--deny-engine`, `--deny-algorithm X`, `--deny-weak`,
`--require-executed X` (repeatable; provider matchers must be
nonempty -- an empty value is a usage error, exit 2, before
any side effect). Discovery and overrides work exactly as in
`report`. Verdicts are three-valued: violation on definite
evidence (exit 10), pass (exit 0/3), or inconclusive (exit 11)
when a requirement is unproven under relevant uncertainty --
see the result JSON, not just the exit code.

## doctor — environment diagnosis

```sh
osslscope doctor                        # am I ready to observe anything?
osslscope doctor --pid 1234             # can I observe THIS process?
osslscope doctor --libcrypto /path/to/libcrypto.so.3  # can I inventory THIS lib?
osslscope doctor --exe ./my-app         # would `run --` discover THIS exe?
```

`doctor` checks privileges (CAP_BPF/CAP_PERFMON or file
caps), kernel features, lockdown/LSM/seccomp, the spawn-setup
maps read (`spawn-access`: a stopped self-dumpable child, exactly
as `run --` sets up, predicting filecaps setup success without a
target), installed BPF objects (trusted locations,
compatibility), and — with a
target — architecture, OpenSSL flavor, build enrollment,
the dispatch anchor, provider class, and coverage caveats
(cold-start, auto-discovery scope, address-taken gaps).
Target verdicts use the same qualification as
`report`/`check`, so a `pass` here means the backend would
attach the same way. On failure it prints the concrete fix
(e.g. the exact `setcap` recipe, or the enrollment steps).
An unsuitable target exits 4. `--table FILE`,
`--force-offset N`, and `--provider-table FILE` vet with
explicit local enrollment; `--object O` / `--count-object
C` vet explicit BPF objects; `--format json` emits
machine-readable output. Implicitly trusted object
locations are the root-owned system dirs
(`/usr/local/lib/osslscope`, `/usr/local/lib64/osslscope`,
`/usr/lib/osslscope`, `/usr/lib64/osslscope` -- first complete
pair wins; user-owned prefixes never resolve implicitly);
anything else needs explicit flags. `doctor` vets objects with
the same primitives the backend composes, so preflight with
the same explicit pair (or none) predicts exactly what
`report`/`check` will resolve.

## alias-audit — find shared dispatch addresses

```sh
osslscope inspect --pid 1234 ... > inspect.json
osslscope alias-audit --in inspect.json
```

Groups a harvest doc's rows by shared `addr_hash` and reports
addresses claimed by several (provider, op, funcid) triples.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | ok (check: no violation) |
| 1 | tool failure: observed child failed (`run --`), artifact delivery failed, or a post-observation close failure (salvaged `runtime`-fatal doc — observations kept, see JSON) |
| 2 | usage error |
| 3 | PARTIAL — degraded evidence, see JSON (`inspect`/`report`/`check` all exit 3 on PARTIAL) |
| 4 | fatal setup failure — evidence unusable because observation never started (incl. unsuitable target, pid recycled, environment/attach failure) |
| 10 | policy violation (`check`) — dominates every tool failure (a proved violation in salvaged sites still exits 10) |
| 11 | inconclusive (`check`) — requirement unproven under relevant uncertainty |

Priority (PRD §14, H7-extended): 2 usage > 10 violation > 1 salvaged runtime-fatal > 4 setup-no-verdict > 1 failed child / failed delivery > 11 inconclusive > 3 partial > 0 clean. Exit 1 says "the tool broke" (with observations kept on the salvaged row); exit 3 says "the observation is incomplete"; exit 4 says "observation never started".

## Current limitations (honest)

- x86-64 Linux only; kernel ≥ 6.9 for stable BPF token /
  `bpf_timer` behavior the probes rely on.
- `--pid` attach cannot see pre-attach history (cold-start
  gap); use `run --` when completeness matters.
- Under sustained high dispatch rates the ring buffer can
  drop events; drops are counted and reported (PARTIAL),
  never silent — but size `--duration` windows accordingly.
- Stripped libcrypto needs `--table`/`--force-offset` help
  for built-in observation unless the build is enrolled
  ([recipe](builtin-runbook.md)); the shipped table covers
  ten historical builds only, not arbitrary binaries.
- FIPS-provider builds change dispatch shapes; support is
  best-effort and explicitly versioned per release.
