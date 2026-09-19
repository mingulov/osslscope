# FIPS interim rule

v1 has no KAT discriminator: it cannot distinguish the FIPS
module's self-test calls (startup KATs, deferred first-use
KATs, conditional pairwise-consistency tests) from workload
crypto, because both execute the same provider dispatch
functions. Any capture whose harvested rows name the `fips`
provider module therefore finishes PARTIAL with reason
`fips-unlabeled`. Silently dropping KAT calls would undercount
real executions that share entry points with self-tests;
unlabeled-plus-loud beats filtered-plus-wrong.
<!-- source: no-discriminator decision: capture-semantics.md;
     fips_touched wiring: src/capture.rs -->

**The rule: FIPS-lane violations need manual triage.** Do not
auto-pass or auto-fail a `fips-unlabeled` window on counts
alone. Read the window composition against the quantified
rates below, decide by human judgment, and record the
rationale with the artifact.

## Quantified rates

Measured on OpenSSL 4.0.2, default install unless noted:

| Workload | Self-test content of `executions` |
|---|---|
| Load burst (45 KAT tests, about 86 ms) | 0 counted -- always pre-window, never observed |
| Steady digest / cipher | 0 observed (0 non-workload executions in about 2M counted per run) |
| EC P-256 keygen | At least 8 self-test executions per keygen (53% of 15 counted; lower bound -- the PCT sign/verify calls sit outside the v1 harvest prefix) |
| RSA-2048 keygen | 1 PCT per keygen (oracle-confirmed; count partition not run) |
| `defer-tests=1` (non-default, 4.0+): first use per algorithm family | One-time 43+ executions inside the window when first use lands there (43 measured for first AES-ECB use) |

<!-- source: KAT noise rates + 4.0 deferred-KAT timing:
     fips-rates note -->

Reading guidance:

- Steady digest/cipher windows: the caveat is pure conservatism
  (measured noise 0). Triage these nearly as normal windows.
- Keygen-heavy windows: majority noise by count. Partition the
  keygen contribution before judging any require/deny rule.
- `defer-tests=1` installs: first-use KATs land inside the
  window. Tiny windows dominated by a first use are mostly KAT;
  the KAT is one-time per process, so longer windows dilute it.
- Load KATs never count. A load-only target yields `no-query`
  PARTIAL with no window at all.

## Observation recipe

- Observe the FIPS provider module in provider mode:
  `--provider .../ossl-modules/fips.so`, NOT `--builtin`.
  (`doctor --libcrypto` on the FIPS libcrypto reports an
  unknown build-id; provider-mode observation is the supported
  path.)
- Ensure a real in-window crypto workload: load-only targets
  exit before the window opens (`no-query`). The workload must
  still be running when harvest settles and the window opens.
- `--pid` onto a pre-loaded provider yields zero rows (init
  predates attach) -- same pre-window blindness as any `--pid`
  run, not a FIPS bug.

<!-- source: provider-mode recipe + recipe constraints:
     p6-entry-envs note (FIPS env), fips-rates note -->

## Triage steps

1. Confirm the shape: exit 3, `status: PARTIAL`, reasons
   exactly [`fips-unlabeled`], child exited cleanly, gap
   counters otherwise zero.
2. Classify the window: steady (digest/cipher bulk) vs keygen
   counts vs first-use-under-defer-tests, using the rates
   above.
3. For a violation on the window: re-derive what the counts
   would be minus the expected self-test contribution. If the
   verdict still stands without the KAT component, treat it as
   a real violation and follow [violation
   triage](violation-triage.md); if the verdict depends on the
   KAT component, record a manual pass with the arithmetic
   attached.
4. Keep the oracle in mind for keygen: the 53% is an observed
   lower bound (PCT sign/verify unobserved). Keygen-heavy
   manual passes should say so explicitly.
