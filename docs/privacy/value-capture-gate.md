<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Value-capture approval gate (P1-0 follow-up)

v1 captures NO values (allowlist-v1.md "Not captured"). The P1-0
digest/mdname value-allowlist proposal stays deferred. Any future
value capture needs ALL of, in one reviewed commit:

1. Per-key-set user approval recorded in the commit message
   (`Approved-value-capture: <key set>` trailer + rationale).
2. Exact key/shape gates: enumerated keys, exact-match admission,
   fixed shapes — no prefix/substring matching, no open enums.
3. Its own canary lanes: new sentinels through the captured path
   proving secret bytes still reach no artifact (green suite +
   live-map scan), plus a positive control proving the read fired.
4. Allowlist update: the new field in allowlist-v1.md §5 inventory
   with source/retirement/certainty/compatibility notes.
5. accompanying old-reader + additive-field tests (schema evolution
   rule) and a privacy-agreement test for the new section.

Anything less is rejected at review. There is no implicit capture.
