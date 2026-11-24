<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# docs

Current v0.7.0 workflows include passive discovery/watch, PID/cgroup/module
inventory, public provider observation and focused PID/owned-run callback
counting. Start with [quickstart](quickstart.md), [usage](usage.md),
[build](build.md), [install](install.md),
[meaning and limits](what-it-proves.md) and
the [roadmap](../ROADMAP.md). The
[published release record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
records historical v0.3 installed checks; the [v0.4.0 alpha
notes](release-v0.4.0.md) record the latest qualification. Neither qualifies
this tree or removes attribution, startup or completeness gaps.

- `quickstart.md` - one-page first run: binary install to uninstall
- `container.md` - limited-capability image: owned and host-observer modes
- `build.md` - reproducible source build (host + BPF), manifests, lockfiles
- `licensing.md` - component terms and the BPF object/load license boundary
- `install.md` - local prefix and package install, doctor-first verify, uninstall
- `usage.md` - discovery, watch, provider observation, PID/run reports,
  policy, and continuous operation (`service`/`export`/`watch`)
- `what-it-proves.md` - claim chain, non-goals, who-should-NOT-adopt
- `observation-contract.md` - public query forwarding, authority and attribution limits
- `release-v0.4.0.md` - automatic observation candidate and artifact-specific limits
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
- `builtin-runbook.md` - stripped/unknown-libcrypto doctor vetting
  (anchor ladder; no `--builtin` mode on the current CLI)
- `trace-gap.md` - OpenSSL tracing and external observation compared
- `observed-crypto-v2.md` - v2 report/check JSON, human and CBOM contract
- `provider-observation.md` - public provider-API observation,
  fetch evidence and `--trace` options
- `engine-observations.md` - typed ENGINE tripwire observations
- `id-map.md` - frozen operation/function/API id registry (display aids)
- `kernel-quarantine-note.md` - API-21 kernel-panic quarantine residuals
- `lifecycle-producer.md` - report/check lifecycle runtime init contract
- `live-seal-checklist.md` - live-run sealed-evidence checklist
- `privacy/allowlist-v1.md` - capture allowlist: what may be observed
- `privacy/residuals.md` - privacy residuals beyond the allowlist
- `privacy/value-capture-gate.md` - approval gate for any future value capture

Older auditor stories and deployment/runbooks retain their
historical/developer scope. They do not expand the current CLI
or qualify deferred features; use current usage/release notes
when an example disagrees. Current continuous-operation
commands (`service`/`export`/`watch`) are documented in
[usage](usage.md#continuous-operation-service-export-watch).
