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
  --object ./target/debug/build/osslscope-ebpf/out/ebpf.o --out inspect.json
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
  cmdline to contain `M`; `--out FILE` writes the JSON doc
  instead of stdout.

## report — human/JSON summary over a capture window

`report` runs a bounded capture of `OSSL_FUNC_*` dispatch
calls (with wall-clock timestamps) and renders the verdict
directly:

```sh
osslscope report --provider legacy --object EVP_DigestInit \
  --count-object EVP_DigestUpdate run -- ./my-app --serve
osslscope report --provider legacy --object EVP_DigestInit \
  --count-object EVP_DigestUpdate --pid 1234 --duration 60
```

- `run -- <cmd>` (spawn-and-observe) is the reliable mode;
  `--pid` (attach to live) is inherently racy — anything the
  target did before attach is invisible (cold-start gap).
- `--format json --out report.json` for machine consumption;
  `--cbom FILE` emits a CycloneDX crypto-BOM alongside.
- `--builtin` selects libcrypto built-ins; `--settle`,
  `--timeout`, `--grace` bound the run phases; `--duration`
  bounds the count window; `--image-digest D` records the
  container image digest in the target provenance.
- A capture may end `PARTIAL` (exit 3) instead of `COMPLETE`
  when evidence is degraded — e.g. events were dropped under
  load, the ring buffer overran, or the child exited early.
  PARTIAL is a result, not a failure: the JSON says what is
  missing and why. Treat PARTIAL captures as lower bounds,
  not inventories.

## check — policy gate (CI)

`check` captures and evaluates policy rules, exiting 10 on
violation (clean exit 0; at least one rule is required):

```sh
osslscope check --provider legacy --object EVP_DigestInit \
  --count-object EVP_DigestUpdate --deny-engine --deny-weak \
  run -- ./my-app --self-test
```

Rules: `--require-provider P`, `--deny-provider P`,
`--deny-engine`, `--deny-algorithm X`, `--deny-weak`,
`--require-executed X` (repeatable). A `check` over a PARTIAL
capture fails closed where the missing evidence matters — see
the result JSON, not just the exit code.

## doctor — environment diagnosis

```sh
osslscope doctor                        # am I ready to observe anything?
osslscope doctor --pid 1234             # can I observe THIS process?
osslscope doctor --libcrypto /path/to/libcrypto.so.3  # can I inventory THIS lib?
```

`doctor` checks privileges (CAP_BPF/CAP_PERFMON or file caps),
BPF JIT hardening, kernel lockdown, BTF availability, the
host/container split, and per-target ptrace rights. On
failure it prints the concrete fix (e.g. the exact `setcap`
recipe). An unsuitable target exits 4. `--table FILE`
overrides the built-in build-id table; `--format json`
emits machine-readable output.

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
| 1 | observed child failed (`run --`) or internal error |
| 2 | usage error |
| 3 | PARTIAL — degraded evidence, see JSON |
| 4 | fatal — evidence unusable (incl. unsuitable target, pid recycled) |
| 10 | policy violation (`check`) |

## Current limitations (honest)

- x86-64 Linux only; kernel ≥ 6.9 for stable BPF token /
  `bpf_timer` behavior the probes rely on.
- `--pid` attach cannot see pre-attach history (cold-start
  gap); use `run --` when completeness matters.
- Under sustained high dispatch rates the ring buffer can
  drop events; drops are counted and reported (PARTIAL),
  never silent — but size `--duration` windows accordingly.
- Stripped libcrypto needs `--table`/`--force-offset` help
  for built-in inventory
  ([recipe](builtin-runbook.md)).
- FIPS-provider builds change dispatch shapes; support is
  best-effort and explicitly versioned per release.
