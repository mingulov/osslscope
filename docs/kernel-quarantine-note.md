<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Kernel-panic quarantine: residual-risk note

`EVP_DigestInit_ex2` (stable API id 21) is REFUSED at attach: probing
its entry stub panics kernels. This note is the in-repo record (the
code pointer used to cite a workspace path outside this repo).

## Trigger

- Export: `EVP_DigestInit_ex2`, an 11-byte `endbr`+`xor`+`jmp`
  trampoline to a shared local impl — the stub body never returns
  (tail-jmp). Highest-rate site (tight EVP init loops).
- Fault: `bpf_prog observation_ent+0x1ee` GPF via `uprobe_prog_run`
  (garbage-RSI map-slot deref). Seen as 2 host kernel panics +
  7 guest oopses (same prog tag, offset, trace).
- Product fix: `attach_pair` refuses stable API id 21 before any
  link/config effect (`src/provider_observation/session.rs`,
  `quarantined_api`), keyed by id — not file offset — so it holds
  across libcrypto builds. Fail-open per site, fail-visible: where
  the attach is attempted and refused, it surfaces as the
  `quarantined_api` setup gap and the
  `focused.attach_refused_quarantined` loss counter. Owned `run --`
  targets whose api-21 site never resolves record no refusal (a
  pre-existing resolution behavior, unchanged by the quarantine);
  the API 21 activity row shows `not_attached` with zero entries
  in every mode.

## Evidence level (guest-statistical, not a proof)

- Baseline oops rate ≈1/6 pairs; 30 quarantine pairs clean
  (p≈0.4% by luck), 0 oopses, 0 unregister leaks, 0 wedges.
- Guest oopses ≠ host panics (containment differs); host re-proof:
  none post-fix, by design — live-BPF never runs on hosts.
- No CI test can re-prove kernel safety; the in-tree pins guard the
  refusal itself (unit id↔name binding, smoke exactly-one-gap).

## Sibling class (tracked follow-up)

Same `_ex`/`_ex2` init-pair shape through the same attach funnel.
Cipher-heavy evidence (2026-11-10, guest): a 15-minute traced run
with sustained cipher-init churn (~2.3M entries each on apis
24/25/28/29, ~6.8M on api 32) produced 0 oopses, 0 unregister
leaks, 0 leftover progs/links. Not a proof, but the unmeasured
class now has a clean bounded run. Extension order on ANY
sibling oops (re-grade to Critical, extend before release):
**20, then 25, 29, 24, 28** — the `_ex` digest twin first, then
the cipher pairs (`EVP_EncryptInit_ex2`, `EVP_DecryptInit_ex2`,
`EVP_EncryptInit_ex`, `EVP_DecryptInit_ex`).

## Kernel-bug status: DEFERRED (dated, owned)

The exact kernel line corrupting the slot is unidentified
(kernel-side race shape in uprobe-multi close-vs-fire/find paths;
KASAN run inconclusive). No upstream report filed as of 0.5.0 —
deferred, owner: osslscope maintainers. The guest repro recipe is
the filing basis when pursued (control_1 → control_2 pairs,
oops ≈1/6, tmpfs-staged libcrypto; see the 0.5.0 lane notes).
The product fix does not depend on that step: removing the probe
removes the fault (0/30).

## Carried hardening (not this fix)

- The `failed to unregister, leaking uprobe` WARN path is real but
  INDEPENDENT of the panic (oopses precede it / occur without it).
- Detach-path error visibility (fd-dropper swallows link-close
  errors) remains a hardening item.
