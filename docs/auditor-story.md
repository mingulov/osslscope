<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Auditor story: from evidence to verdict

This is the end-to-end story an auditor walks: capture evidence,
check its shape, gate on violations, and compare declared versus
executed crypto. It ties the reference docs together with one
worked example: a TLS-terminating service observed over a window
of PQC handshakes.
<!-- source: worked example: staging end-to-end record (private);
     observer at cf7f9a0; T9/T10 changed packaging + docs only, so
     observation behavior equals current -->

## 1. Capture: report + CBOM

One window, spawn mode, JSON evidence plus a CycloneDX CBOM:

```sh
osslscope report \
  --provider /path/to/libcrypto.so.3 --builtin \
  --object ./osslscope-harvest --count-object ./osslscope-count \
  --duration 30 --settle 5 \
  --format json --out story.json --cbom story.cdx.json \
  run -- /path/to/service --foreground
```

Drive representative traffic in-window (warmup handshakes while the
window opens, measured handshakes inside it), then quit the child
cleanly before expiry. The example window ran 2 warmup + 10 measured
PQC handshakes and exited 3: PARTIAL with the single structural
reason `lowlevel-fallback-uninstrumented`, 62 execution rows,
`child_exit` 0, all gap counters zero. Exit 3 with a clean policy
read is the normal shape for TLS services -- see
[who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)
for why v1 never promises COMPLETE there.

The CBOM (`story.cdx.json`) carries one `cryptographic-asset`
component per executed identity (62 here), each with algorithm,
provider (+ object path / build-id), op, funcid, call count,
generation, window edges, and per-component completeness. PARTIAL
evidence travels as a `metadata` disclaimer property, so the
completeness caveat survives export.

## 2. Trust the bytes: the golden conformance test

`tests/auditor_golden.json` freezes the auditor-visible report shape
for a small deterministic fixture; `tests/auditor_report.rs` checks
exact key sets, exact types, and the frozen vocabularies (status,
the 29 PARTIAL reasons, the 6 rule names) -- and rejects tampered
documents (dropped/added keys, type flips, off-vocabulary tokens
all fail; the suite asserts each rejection). The same checker
validates live story output, which never ships in this repo:

```sh
OSSLSCOPE_AUDITOR_STORY=/path/to/story.json \
  cargo test --offline --test auditor_report story_output_conforms
```

The checker is deliberately stricter than the reader contract in
`schemas/observed-crypto-v1.json` (readers must ignore unknown keys
for forward compatibility). The auditor's job is the opposite:
surface any unexpected byte, then update golden + checker together,
by review.

## 3. Gate: violation detection on evidence

CI gates on violations, never on COMPLETE. Two runs from the
example window:

```sh
# Expected crypto executed: policy pass (exit 3 = PARTIAL, no violation).
osslscope check ... --require-executed HKDF \
  --format json --out pass.json run -- /path/to/service --foreground
# verdict: pass, HKDF matches 630.

# Required crypto absent: fail closed (exit 10).
osslscope check ... --require-executed SNMPKDF \
  --format json --out viol.json run -- /path/to/service --foreground
# verdict: violation, matches 0.
```

Exit 10 dominates: it fires on COMPLETE or PARTIAL evidence alike.
The violation entry carries the actionability tuple -- rule +
matcher, the executed identity (or `absent: true` with zero counts
when nothing matched), window epochs, full cmdline, container id,
image digest, and provider object path + build-id -- which is what
[violation triage](violation-triage.md) walks to the owning service.
Wire it per [CI gate recipes](ci-recipes.md): exit 3 + `pass` is
green-with-artifacts, exit 10 fails the gate.

## 4. Declared versus executed

A static inventory answers "what could run"; the CBOM answers "what
ran". For the example window, `openssl list` across the cipher /
digest / KDF / MAC / KEM / key-exchange / signature / key-manager /
random groups declares 277 distinct primary names, while the window
executed 62 identities in 16 algorithm classes (15 registry classes
plus `other`). The delta has three parts worth naming to an auditor:

- 262 declared names never executed in-window. Absence here means
  not-observed-in-window, never "not present / never used" -- a
  longer or differently-loaded window may execute them.
- 18 executed rows classify as `other` (KEYMGMT / KEYEXCH / DECODER
  dispatch for the negotiated PQC hybrid group): executed but
  unclassified, because the provider alias-list primary is not a
  registry spelling. Triage, never auto-deny.
- `other`-class executions are counted in `weak.unknown_calls`,
  not in any algorithm bucket: unknown spellings stay visible
  without being misattributed.

## 5. Downstream: Dependency-Track status

The CBOM is schema-valid CycloneDX 1.6 (62 components). Uploading it
to Dependency-Track 4.14.4 accepts the BOM (HTTP 200 + token) and
creates the project, but the async import task fails: DT's
`Classifier` enum has no `CRYPTOGRAPHIC_ASSET` member, so 0 of 62
components land and finding queries return empty. Re-verify the DT
leg on a release whose classifier model covers cryptographic
assets; until then the DT path is documented-but-blocked, and the
auditor trail is the report JSON + CBOM + gate artifacts above, not
a DT project page.

## The one-paragraph version

Observe the service in spawn mode, keep the JSON + CBOM + gate
artifacts together, validate the JSON shape with the golden
conformance test, gate CI on `check` violations (exit 10 fails,
exit 3 + `pass` is normal), and read declared-vs-executed as
"could run" versus "ran" -- with `other` rows and window-only
absence stated explicitly. That packet is the v1 audit trail.
