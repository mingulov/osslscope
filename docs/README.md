<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# docs

Current v0.3.0 workflows include passive discovery/watch, PID/cgroup/module
inventory, public provider observation and focused PID/owned-run callback
counting. Start with [usage](usage.md), [build](build.md), [install](install.md),
[meaning and limits](what-it-proves.md), [release notes](release-v0.3.0.md) and
the [roadmap](../ROADMAP.md). The
[published release record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
records actual installed checks; it does not remove the default-provider,
attribution, startup or completeness gaps.

- `build.md` - reproducible source build (host + BPF), manifests, lockfiles
- `licensing.md` - component terms and the BPF object/load license boundary
- `install.md` - local prefix and package install, doctor-first verify, uninstall
- `usage.md` - discovery, watch, provider observation, PID/run reports and policy
- `what-it-proves.md` - claim chain, non-goals, who-should-NOT-adopt
- `release-v0.3.0.md` - discovery preview scope, qualification procedure and inventory cost
- `release-v0.2.0.md` - source preview scope, native checks and limits
- `overhead-matrix.md` - measured preview timings and historical broader matrix
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
- `trace-gap.md` - OpenSSL tracing and external observation compared
- `observed-crypto-v2.md` - v2 report/check JSON, human and CBOM contract
- `privacy/allowlist-v1.md` - capture allowlist: what may be observed
- `privacy/residuals.md` - privacy residuals beyond the allowlist

Older auditor stories, deployment/runbooks, `--builtin` examples, package and
service references retain their historical/developer scope. They do not expand
the current CLI or qualify deferred features; use current usage/release notes
when an example disagrees.
