<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# FIPS interim rule

There is no KAT discriminator: self-tests, deferred first-use KATs
and conditional pairwise-consistency tests can execute the same
provider callbacks as workload crypto. Their calls remain counted;
policy does not subtract them. Provider-class enrollment describes
exact binary provenance, never FIPS certification.

**FIPS-lane policy results require manual interpretation.** Do not
infer application use or compliance from counts alone. Record the
workload, self-test context, independent oracle and rationale with
the artifact.

## Read the current evidence

Report/check use v2 `sites`, candidate metadata, typed coverage/loss/
window reasons and per-rule evidence. FIPS identity is pinned
provider-class metadata when enrolled, not a filename inference.
The finalizer has no categorical FIPS exclusion from COMPLETE, and
COMPLETE does not establish that counts exclude self-tests.

Legacy harvest/inspect and capture display vocabulary differs from
the v2 document. In particular, `src/capture.rs` adds
`fips-unlabeled` to legacy display reasons for a configured
`fips`-shaped provider path with positive provider-plane calls,
after finalizing the v2 document. That is not a guaranteed
machine-readable v2 caveat or a promise of one exact PARTIAL reason.
Likewise, legacy `no-query` / `pid-prewindow-blind` text must not be
substituted for current typed reasons. See
[the evidence contract](observed-crypto-v2.md#completeness-coverage-counters).

## Historical self-test measurements

The following OpenSSL 4.0.2 setup measurements are historical,
source/workload-specific observations, not current integrated
qualification or universal timing guarantees:

| Workload | Self-test content observed in the historical setup |
|---|---|
| Load burst (45 KAT tests, about 86 ms) | 0 counted; the measured burst preceded that setup's count window |
| Steady digest / cipher | 0 non-workload executions observed in about 2M counted per run |
| EC P-256 keygen | At least 8 self-test executions per keygen (53% of 15 counted); PCT sign/verify lay outside that harvest prefix |
| RSA-2048 keygen | 1 PCT per keygen, oracle-confirmed; count partition was not run |
| `defer-tests=1` (non-default, 4.0+), first use | One-time 43+ in-window executions; 43 measured for first AES-ECB use |

These numbers do not justify subtracting a fixed noise allowance
from a new capture. Startup KATs are not universally pre-window;
deferred tests and keygen can occur in-window. Longer windows may
dilute a one-time burst without making its calls application crypto.

## Observation recipe

- Use provider mode for the module: `--provider
  .../ossl-modules/fips.so`, without `--builtin`. Run `doctor`
  with the same selected BPF objects and target settings first.
  Omit explicit `--members-object`: traversal needs a builtin query
  anchor, while automatic triple selection can stay harvest-only
  for file-provider observation.
- Drive representative crypto during the effective count window;
  record whether load/first-use/keygen overlaps it. A load-only
  attempt or a preloaded `--pid` target may yield no harvest rows;
  read the actual typed gaps and exit status rather than assuming
  a fixed `no-query` result.
- Keep startup and pre-attach limits explicit. `run --` improves
  custody but supplies no first-call or COMPLETE guarantee.

## Triage steps

1. Read completeness, fatal eligibility, typed reasons, counters,
   candidate certainty and child disposition. Attribute each gap;
   do not demand one particular FIPS-only reason shape.
2. Classify the workload and gather an independent self-test oracle.
   Historical steady/keygen/first-use rates are context only.
3. Inspect `policy.rules[]` results and their site/ENGINE evidence.
   Distinguish observed callback execution from application crypto
   where the oracle permits it. If it does not, record uncertainty
   or a documented manual gate exception; retain the original
   machine verdict and counts.
4. Re-verify under a comparable window and preserve the rationale.
   No manual adjustment establishes certification or recovers
   unobserved parameter values.
