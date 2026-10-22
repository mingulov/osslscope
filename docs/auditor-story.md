<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Auditor story: from evidence to verdict

This is the end-to-end story an auditor walks: capture evidence,
check its shape, gate on violations, and compare declared versus
executed crypto. It ties the reference docs together with one
worked example: a historical TLS-terminating service window of PQC
handshakes, followed by current v2 contract guidance. The old
measurement used an earlier observer; it is not current integrated
live or package qualification. Current output must be recaptured.

## 1. Capture: report + CBOM

One window, spawn mode, JSON evidence plus a CycloneDX CBOM.
With a trusted system install the BPF objects resolve
implicitly when the selected roles pass trust/receipt checks.
Otherwise pass the same explicit harvest/count/members paths to
`doctor` and capture, as in [install](install.md). Deliberate
pair-only installs stay harvest-only:

```sh
osslscope doctor || exit 4

osslscope report \
  --provider /path/to/libcrypto.so.3 --builtin \
  --duration 30 --settle 5 \
  --format json --out story.json --cbom story.cdx.json \
  --workload-out story.workload.log \
  run -- /path/to/service --foreground \
  >story.driver.log 2>&1
```

Drive representative traffic in-window (warmup handshakes while the
window opens, measured handshakes inside it), then quit the child
cleanly before expiry. The staging record replayed here ran 2
warmup + 10 measured PQC handshakes and exited 3: PARTIAL with
a structural low-level coverage gap in that target (see [who should NOT
adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)),
62 counted sites, disposition `exited` code 0, and no counted
transport drops in that historical accounting.
These are historical measurements, not a v2 site/component
mapping: re-run to get the current definite-asset count, since
unresolved `other` sites never qualify as definite. Neither this
traffic shape nor one PARTIAL reason is a universal TLS result.
Spawn custody and warmup do not prove first-call or COMPLETE
coverage. The workload's own output lands in `story.workload.log`;
observer stdout stays a pure artifact channel and observer
diagnostics stay in `story.driver.log`.

The v2 JSON carries no raw argv: `target` holds pid, comm,
container/image provenance, and unconditional
`argv_redacted: true`. Window edges are monotonic nanoseconds
(requested versus effective coverage); the optional `context`
key adds host kernel release plus wall-clock edges for
correlation only. The CBOM (`story.cdx.json`) carries one
`cryptographic-asset` component per definite site, each with
provider and backing-object fingerprints (no display paths),
op, funcid, call count,
generation, and window edges (the staging record historically
counted 62 sites; the v2 definite-component count needs a
re-run). Display paths live in the report's `objects`
section, joined by fingerprint. Ambiguous and unresolved sites contribute no
components; their omitted counts stay explicit metadata, and
PARTIAL evidence travels as a `metadata` disclaimer property, so
both caveats survive export.

## 2. Trust the bytes: the v2 conformance test

`tests/auditor_golden_v2.json` freezes the auditor-visible v2
report shape; `tests/auditor_report.rs` (v2 suite) checks exact
key sets, exact types, and the frozen vocabularies -- and
rejects tampered documents (dropped/added keys, type flips,
off-vocabulary tokens all fail; the suite asserts each
rejection). The same checker validates live story output, which
never ships in this repo (the v1 suite and its
`OSSLSCOPE_AUDITOR_STORY` / `story_output_conforms` pair are
frozen history):

```sh
OSSLSCOPE_AUDITOR_STORY_V2=/path/to/story.json \
  cargo test --offline --test auditor_report story_v2_output_conforms
```

The checker runs both validation layers from [the v2
contract](observed-crypto-v2.md#reader-contract): `validate_v2`
(JSON Schema: types, enums, required fields,
`additionalProperties: false` on every object) and
`check_v2_semantics` (cross-field rules -- object reference
integrity, effective-inside-requested windows, ordered site
timestamps, status/reasons agreement, conserved policy bounds,
legacy-partition conservation, and the forbidden
argv/cmdline/address key sweep). It is deliberately stricter
than field-level readers, which must ignore unknown keys for
forward compatibility. The auditor's job is the opposite:
surface any unexpected byte, then update golden + checker
together, by review.

The committed fixture controls cover
`tests/goldens/report-v2-violation.json` and
`tests/goldens/report-v2-partial.json`, and reject the same
violation document with one added unknown key. These source/fixture
controls are distinct from a new live run.

Compatibility is deliberate: producers emit exactly
`observed-crypto-v2.2`, readers accept `observed-crypto-v2` and
`observed-crypto-v2.<digits>` and reject every other major, and
minor versions add OPTIONAL keys only. A v2.0 validator fails
closed on v2.1 keys it does not know (upgrade the validator);
field-level readers keep working. Old readers never misparse
across majors, and no one claims an older reader reconstructs
new evidence it cannot represent.

## 3. Gate: violation detection on evidence

Current integrated COMPLETE-window gating remains unqualified.
These illustrative runs show policy verdicts using the example's
invocation shape. Exit comments assume no higher priority failure:

```sh
# Expected crypto executed: policy pass (exit 3 = PARTIAL, no violation).
osslscope check ... --require-executed HKDF \
  --format json --out pass.json run -- /path/to/service --foreground
# verdict: pass, HKDF definite use proved.

# Banned crypto executed: violation (exit 10).
osslscope check ... --deny-algorithm DES \
  --format json --out viol.json run -- /path/to/service --foreground
# verdict: violation, definite DES use proved.

# Required crypto absent under a relevant gap: inconclusive (exit 11).
osslscope check ... --require-executed SNMPKDF \
  --format json --out inconc.json run -- /path/to/service --foreground
# verdict: inconclusive, the requirement is unproven, never fabricated.
```

Exit 10 dominates: it fires on COMPLETE, PARTIAL or usable FATAL
evidence alike, even when artifact delivery
failed -- an artifact failure never overrides a proved
violation. Exit 11 is the honest middle: relevant loss blocks
the absence proof, while unrelated gaps preserve proved
positive evidence. If the close flow itself breaks mid-run
(drain, discovery finish, or disposition), the document is
salvaged as `runtime`-fatal: every collected observation
survives, policy still evaluates (a proved violation exits 10),
and anything else exits 1. Runtime eligibility holds even with no
positive counts. AttachZero with proved positive in-window ENGINE
evidence is also policy-eligible; Environment, Recycled and bare
AttachZero are not. Eligibility does not make an individual rule
decidable. A usable fatal, child failure or delivery failure can
outrank an inconclusive policy; see [the exit table](usage.md#exit-codes).

Select `policy.rules[]` entries whose `result` is `violation`.
Their `rule`, `predicate`, conserved definite/possible bounds and
site `evidence` refs (object/device/inode/offset, generation, calls)
explain the rule; optional `engine_evidence` refs identify ENGINE
observations. There is no separate `violations[]` wire field;
the rest of the actionability tuple -- window edges,
pid/comm, container id, image digest, provider display paths
(no cmdline: argv is redacted) -- joins through the
`target`, `window`, `sites`, `fenced`, `objects`, and
`engine_observations` sections, which is what [violation
triage](violation-triage.md) walks to the owning service. Wire
it per [CI gate recipes](ci-recipes.md): exit 3 + `pass` is
green-with-artifacts, exit 10 fails the gate, exit 11 fails
pending gap triage.

## 4. Declared versus executed

A static inventory answers "what could run"; the CBOM answers "what
ran". For the staging record replayed here, `openssl list`
across the cipher / digest / KDF / MAC / KEM / key-exchange /
signature / key-manager / random groups declares 277 distinct
primary names, while the window counted 62 executed sites across
16 algorithm classes (15 registry classes plus `other`). All
counts in this section are that historical measurement, not a
current v2 mapping. The delta has three parts worth naming to an
auditor:

- 262 declared names never executed in-window. Absence here means
  not-observed-in-window, never "not present / never used" -- a
  longer or differently-loaded window may execute them.
- 18 executed sites carry only `other`-bucket candidates (KEYMGMT
  / KEYEXCH / DECODER dispatch for the negotiated PQC hybrid
  group): executed but unresolved, because the provider
  alias-list primary is not a registry spelling. Under v2
  accounting these 18 never qualify as definite assets, so the
  historical 62-site count is not a 62-component claim.
  Triage, never auto-deny.
- Unresolved sites stay visible with their candidate sets and
  weak-alias flags rather than being misattributed to any
  algorithm bucket; sites are counted once each no matter how
  many candidates share them.

## 5. Downstream: Dependency-Track status

The historical CBOM is schema-valid CycloneDX 1.6 (62 components
in that staging record). Uploading it to Dependency-Track 4.14.4
accepts the BOM (HTTP 200 + token) and creates the project, but
the async import task fails: DT's `Classifier` enum has no
`CRYPTOGRAPHIC_ASSET` member, so 0 of 62 components land and
finding queries return empty. Re-verify the DT
leg on a release whose classifier model covers cryptographic
assets; until then the DT path is documented-but-blocked, and the
auditor trail is the report JSON + CBOM + gate artifacts above, not
a DT project page.

## The one-paragraph version

Observe the service in spawn mode, keep the JSON + CBOM + gate
artifacts together, validate the JSON shape with the v2
conformance test, gate CI on `check` verdicts (exit 10 fails,
exit 11 fails pending gap triage, exit 3 + `pass` is normal),
and read declared-vs-executed as "could run" versus "ran" -- with
ambiguous sites and window-only absence stated explicitly. That
packet is the v2 audit trail.

The v2.2 optional count-admission bounds describe the actual completed Open
separately from coverage time. An early-cut callback retains its real sample
inside that original half-open interval, with PARTIAL/FATAL coverage and a
tail gap. Strict older window readers reject the optional object; tolerant
field readers preserve the fields they understand. Absent metadata retains
strict effective-window containment. These source and host controls do not
qualify live clock-domain compatibility or first-call capture.
