<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# docs

Product documentation. The current supported development route is the
foreground preview: start with [usage](usage.md), [build](build.md),
[install](install.md), [limits](what-it-proves.md) and the
[release roadmap](../ROADMAP.md). The broader discovery/provider/service/package
references below are retained developer/future material and do not expand the
preview's enforced CLI scope.

- `build.md` - reproducible source build (host + BPF), manifests, lockfiles
- `licensing.md` - component terms and the BPF object/load license boundary
- `install.md` - local prefix and package install, doctor-first verify, uninstall
- `usage.md` - scoped foreground CLI (`report` / `check` / `doctor` / offline `alias-audit`)
- `what-it-proves.md` - claim chain, non-goals, who-should-NOT-adopt
- `overhead-matrix.md` - overhead and support matrix (worst cells)
- `auditor-story.md` - end-to-end auditor walk: evidence to verdict
- `ci-recipes.md` - CI gate recipes (`check` in spawn mode)
- `partial-runbook.md` - PARTIAL runbook: per-reason response
- `attach-failures.md` - attach failures: exit-4 decision tree
- `violation-triage.md` - `check` violation triage (exit 10)
- `staging-deploy.md` - staging deploy for already-running targets
- `fips-interim.md` - FIPS interim rule (no KAT discriminator)
- `promotion-checklist.md` - staging-to-production promotion checklist
- `builtin-runbook.md` - stripped/unknown-libcrypto recipe for
  `--builtin` inventory
- `trace-gap.md` - osslscope vs OSSL_TRACE side-by-side
- `observed-crypto-v2.md` - v2 report/check JSON, human and CBOM contract
- `privacy/allowlist-v1.md` - capture allowlist: what may be observed
- `privacy/residuals.md` - privacy residuals beyond the allowlist
