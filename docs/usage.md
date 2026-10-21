<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope CLI usage

Current commands: `inspect` / `report` / `check` / `doctor` /
`alias-audit`. Examples assume the binary is built
(`cargo build`) and you have elevated BPF rights — run
`osslscope doctor` first; it tells you exactly what is
missing and how to fix it.

## inspect — inventory a live process

Attach eBPF probes to a running process and harvest provider
algorithms exposed by observed post-attach queries, with coverage:

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
calls (with monotonic execution timestamps from
`bpf_ktime_get_ns`; wall-clock window edges are separate
correlation context) and renders the verdict
directly. Discovery is automatic: BPF objects resolve from
trusted installed locations and the target's libcrypto from
its live mappings (in-libcrypto default provider mode):

```sh
osslscope report run -- ./my-app --serve
osslscope report --pid 1234 --duration 60
osslscope report --format json --out report.json --cbom bom.json run -- ./my-app --serve
```

- `run -- <cmd>` (spawn-and-observe) improves target custody;
  `--pid` (attach to live) is inherently racy — anything the
  target did before attach is invisible (cold-start gap).
  Spawn mode and warmup do not guarantee first-call or COMPLETE
  coverage; inspect effective window edges and typed reasons.
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
  any spawn. File preparation happens parent-side before
  fork: a log-open failure fails setup naming the path
  (never silent null) and the run exits 4; exit 126 stays
  for the remaining child-side stdio-redirect failures. A
  nonzero child exit without a destination prints one re-run hint
  line (exit + `--workload-out FILE`) and no workload bytes.
  Future rejection of shared-fd sinks is a separate policy change
  (announced, versioned, with a migration path) — never a silent
  fix. The current implementation accepts them.
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
  objects; `--members-object M` demands traversal, which requires
  a resolved builtin query anchor. File-provider/dispatch-blind
  runs without an anchor refuse that explicit request; automatic
  triple selection can stay harvest-only instead.
  Trusted installed selection is automatic. User-owned prefixes
  need explicit role flags; use the same selected pair/triple
  for preflight and capture per [install](install.md).
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

`check` captures and evaluates policy rules. A proved violation
exits 10. An aggregate inconclusive verdict exits 11 when no
higher priority failure applies; at least one rule is required:

```sh
osslscope check --deny-engine --deny-weak run -- ./my-app --self-test
osslscope check --require-provider default --pid 1234 --duration 60
```

Rules: `--require-provider P`, `--deny-provider P`,
`--deny-engine`, `--deny-algorithm X`, `--deny-weak`,
`--require-executed X` (repeatable; provider matchers must be
nonempty -- an empty value is a usage error, exit 2, before
any side effect). Discovery and overrides work exactly as in
`report`. Each rule's `result` is pass, violation or inconclusive;
aggregate `policy.verdict` can also be `no-verdict` on unusable
fatal evidence. Require rules pass on definite use, violate only
on proved absence under complete relevant coverage, and otherwise
remain inconclusive. Deny rules violate on definite use and pass
only on proved relevant absence. Read `policy.rules[]` bounds and
evidence as well as the [exit precedence](#exit-codes).

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
C` / `--members-object M` vet explicit BPF objects;
`--format json` emits machine-readable output. Implicitly
trusted object locations are the root-owned system dirs
(`/usr/local/lib/osslscope`, `/usr/local/lib64/osslscope`,
`/usr/lib/osslscope`, `/usr/lib64/osslscope` -- triple-first:
pair-only directories are skipped while searching, so a
later complete triple supersedes an earlier pair-only
directory; pair fallback applies only when no trusted
members object exists anywhere; user-owned prefixes never
resolve implicitly);
anything else needs explicit flags. `doctor` vets objects with
the same primitives the backend composes, so preflight with
the same explicit pair/triple (or none) predicts what
`report`/`check` will resolve. The `objects-members`
row covers the traversal object: `pass` when installed and
compatible, `info` when absent (traversal unavailable — old
harvest/count pair installs stay valid), `fail` when present
but unresolvable (reinstall that object). `report`/`check`
traverse automatically when the installed triple resolves
(receipt-verified, trusted) and the target is builtin-mode
with a resolved dispatch anchor; otherwise they stay
harvest-only (pair-only installs, file-provider runs, and
dispatch-blind targets never traverse). `--members-object`
explicitly demands traversal (missing/mixed/stale sets are
actionable refusals, never silent harvest-only); without it,
selection is automatic and the report's `traversal` section
names the exact triple that ran.

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
| 0 | COMPLETE with passing policy, or a successful non-capture command |
| 1 | usable fatal document, failed observed child (`run --`), or failed artifact delivery; see precedence below |
| 2 | usage error |
| 3 | PARTIAL when no higher priority result applies (`check`: passing policy); inspect also uses 3 for degraded harvest |
| 4 | unusable fatal/no policy verdict, including environment, recycled target and bare AttachZero; doctor also uses 4 for failed preflight |
| 10 | proved policy violation (`check`), including on usable fatal evidence; dominates tool/delivery failure |
| 11 | aggregate inconclusive policy when no higher priority result applies |

Priority (`src/report.rs` `exit_for`): 2 usage (before capture) >
10 violation > 1 usable fatal > 4 no-verdict > 1 failed child /
failed delivery > 11 inconclusive > 3 PARTIAL > 0 clean.

Runtime fatal is eligible for policy even with no positive counts.
AttachZero is eligible only with proved positive in-window typed
ENGINE evidence; it describes provider attachment, not the
independent ENGINE plane. Environment, Recycled and bare AttachZero
remain unusable. Eligibility does not make a rule decidable or a
candidate definite. A usable fatal without a violation exits 1,
including when its policy is inconclusive. Exit 4 is not a universal
claim that no observation ever occurred: a recycled target's evidence
is discarded as unusable. Requested artifacts are attempted
independently, including fatal output; delivery is not guaranteed.

## Current limitations (honest)

- x86-64 Linux only; kernel 6.9 is the support floor.
  The [historical matrix](overhead-matrix.md) includes a 6.9
  lane; current integrated artifacts still need qualification.
  Admission is by functional
  feature probe (kprobe-load, ringbuf, uprobe-multi+cookies,
  `probe_read_user`) with the release itself informational;
  BPF tokens are a debug-only floor signal, never used for
  privilege.
- `--pid` attach cannot see pre-attach history (cold-start
  gap); `run --` improves custody without proving completeness.
- Under sustained high dispatch rates the ring buffer can
  drop events; drops are counted and reported (PARTIAL),
  never silent — but size `--duration` windows accordingly.
- Stripped libcrypto needs `--table`/`--force-offset` help
  for built-in observation unless the build is enrolled
  ([recipe](builtin-runbook.md)); the shipped table covers
  eleven exact builds only, not arbitrary binaries. Supported
  symtab resolution can admit an unknown unstripped build without
  adding a table row; enrollment does not qualify performance.
- FIPS-provider builds change dispatch shapes; support is
  best-effort and explicitly versioned per release.
