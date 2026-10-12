<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `observed-crypto-v2` documents

Public contract for the v2 report/check JSON document, the human
report, and the CycloneDX CBOM. All three derive from one finalized
`CaptureDocument` for the same window (`src/evidence.rs`, rendered by
`src/report.rs`); the JSON shape is pinned by
`schemas/observed-crypto-v2.json` and `tests/output_contract.rs`.

Every example below is verbatim test output (goldens under
`tests/goldens/`), never invented. v1 files
(`schemas/observed-crypto-v1.json`, `report-*.json`, `cbom-*.json`
goldens, the v1 auditor suite) are frozen history: old readers
reject v2 documents and there is no dual live producer.

## Reader contract

Producers emit exactly `observed-crypto-v2.1`. Readers accept
`observed-crypto-v2` and `observed-crypto-v2.<digits>` and reject
every other major (`src/schema.rs` `check_version_v2`, pinned by
`compat_matrix_v2` and `output_contract::schema_version_gate`).
Minor versions add OPTIONAL keys only. A v1 reader refuses v2
documents (`check_version` rejects `observed-crypto-v2.0`).

Validation is strict per minor while field extraction stays
lenient: `validate_v2` rejects unknown keys (a v2.0 validator
cannot verify v2.1 keys it does not know — fail closed, upgrade
the validator), but field-level readers ignore unknown keys and
keep working. The version gate answers "is this major ours"
(never misparse across majors); validation answers "does this
document verify against this minor's schema".

Validation has two layers, shared by the contract tests and the
auditor v2 suite (`tests/auditor_report.rs`):

- `validate_v2`: actual JSON Schema validation against the schema
  file (types, enums, required fields, `minimum`/`maximum`,
  `additionalProperties: false` on every object, `$ref`). Schemas
  using an unsupported keyword fail closed.
- `check_v2_semantics`: cross-field rules JSON Schema cannot
  express — object reference integrity over full
  fingerprint/device/inode triples, effective-inside-requested
  windows, openssl/disposition/coverage/fatal-kind invariants,
  ordered site timestamps, unique site keys, status/reasons
  agreement, policy verdict combination with
  definite-within-possible bounds and per-site evidence totals,
  fenced-bucket generation agreement, legacy-partition
  conservation (buckets sum to the sites plus fenced call
  total), and the forbidden argv/cmdline/address key sweep.

## Top-level sections

Required: `schema_version`, `target`, `openssl`, `window`,
`completeness`, `sites`, `fenced`, `objects`, `coverage`,
`legacy_partition`.
Optional: `disposition` (omitted when never recorded), `policy`
(`check` documents only; `report` omits it).

Target, OpenSSL version, window and disposition, values verbatim
from `tests/goldens/report-v2-violation.json` (whitespace
compressed):

```json
{"target": {
  "argv_redacted": true,
  "comm": "demo",
  "container_id": "",
  "image_digest": "",
  "pid": 7
}}
{"openssl": {"state": "verified", "version": "3.5.1"}}
{"window": {
  "effective_end_ns": 100,
  "effective_start_ns": 0,
  "requested_end_ns": 100,
  "requested_start_ns": 0,
  "signal_cut": false
}}
{"disposition": {"code": 0, "outcome": "exited", "pid": null}}
```

Notes:

- `target` carries safe actionability only: pid, comm,
  container/image provenance, and unconditional
  `argv_redacted: true`. Raw argv/cmdline has no carrier anywhere.
- `openssl.version` is emitted only from verified object metadata;
  otherwise `state` is `unknown` with a null version (never
  guessed).
- Window edges are monotonic nanoseconds: requested versus
  effective coverage. The effective window may be narrower (gaps),
  never wider. There is no wall clock in v2; correlate by pid,
  disposition and counter evidence.
- `disposition` mirrors custody: `exited` (code), `detached-running`
  (owned child left running), `foreign-observed` (`--pid` target
  left untouched).

## Sites and uncertainty

The counted unit is entry into a provider-dispatch callback at one
physical site. `calls` is counted once per site per generation;
`candidates` are sorted attribution metadata describing identities
that could explain that entry — never definite executed-algorithm
identity. Two algorithms sharing a site with N calls render N site
calls, not 2N; candidates carry no counts of their own.

An ambiguous site, values verbatim from
`tests/goldens/report-v2-complete.json` (100 shared calls, two
candidates, one weak alias):

```json
{
  "calls": 100,
  "candidates": [
    {
      "algorithm_classes": ["AES-256-GCM"],
      "funcid": 21,
      "op": 2,
      "provider": "build:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "provider_class": "default",
      "weak_alias": false
    },
    {
      "algorithm_classes": ["ARIA-256-GCM"],
      "funcid": 21,
      "op": 2,
      "provider": "build:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "provider_class": "default",
      "weak_alias": true
    }
  ],
  "candidates_coverage": "complete",
  "device": 8,
  "first_ns": 10,
  "generation": 0,
  "inode": 200,
  "last_ns": 90,
  "object": "build:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "offset": 4096
}
```

(The golden fixture predates install walls, so no `installed_at`
key renders above.) Since v2.1, sites carry the optional
`installed_at`: the cookie's probe-attachment wall in monotonic
ns, omitted when the producer never recorded it. Installed is not
counted — `installed_at` bounds the install moment while
`first_ns` stamps the first counted execution, so per site
installed-at vs first-counted is distinguishable; a site with no
counted executions never renders (quiet cookies stay covered by
`ScopeCoverage.attached`, not gaps — the per-site never-counted
rendering is P7's per-site spec).

A site is *definite* only when it executed, its candidate set is
complete, and every candidate agrees on provider, provider class,
op, funcid and one single *resolved* algorithm class
(`weak_alias` may vary and is surfaced). Anything else is
ambiguous (`complete` set, disagreeing or multi-class),
unresolved (`complete` set stuck in the `other` bucket: provider,
op and funcid are certain, the algorithm is not), unattributed
(`unknown` set or no candidates), or quiet (zero calls). `fenced`
carries earlier generations in the same shape so fence crossings
preserve candidates. Every site backing triple
(fingerprint/device/inode) and every candidate advertising
provider resolves into `objects` (verified fingerprint plus
display locator); dangling or contradicting references fail
validation.

`legacy_partition` splits every counted call (current plus
fenced sites) by candidate class and backing identity:
`legacy_exclusive_calls` (all candidates legacy-class, backed by
the legacy provider file), `non_legacy_exclusive_calls` (no
legacy-class candidate), `shared_ambiguous_calls` (mixed classes,
or all-legacy backed by a foreign file), `unfenced_tail_calls`
(sites with no candidates). The four buckets conserve exactly:
their sum equals the sites plus fenced call total, enforced by
`check_v2_semantics`.

## Completeness, coverage, counters

`completeness.status` is `COMPLETE`, `PARTIAL` or `FATAL`.
`fatal_kind` is null unless `FATAL` (`recycled`, `attach-zero`, or
`environment`/`runtime` with detail). `runtime` is a salvaged
post-observation tool failure: the close flow broke mid-run, every
collected observation survives, and policy still evaluates (a proved
violation exits 10; otherwise exit 1). `reasons` are typed objects
with a `kind` discriminator:

| kind | fields |
|---|---|
| `unknown-denominator` | `scope` |
| `undiscovered-sites` | `scope`, `missing` |
| `unattached-sites` | `scope`, `missing` |
| `loss` | `counter`, `source`, `value` |
| `unattributed-calls` | `sites`, `calls` |
| `startup-gap` | `missing_ns` |
| `tail-gap` | `missing_ns` |
| `signal-cut` | (none) |

`coverage` rows describe per-scope instrumentation readiness
(expected/discovered/attached); quiet but fully attached sites are
covered, not gaps. `counters` are source-tagged with published
units (`calls`, `sites`, `table-rows`, `events`, `probes`) and kind
(`loss`, `activity`); only a positive loss forces `PARTIAL`.

## Policy section (`check` only)

T10 evaluates rules and fills `PolicyRecord`; T11 renders it.
`verdict` is `pass`, `violation`, `inconclusive` or `no-verdict`
(`no-verdict` exactly on `FATAL` documents with policy). The
verdict is the AND of its rules: any `violation` rules a
violation, else any `inconclusive` rules inconclusive, else `pass`.
Each rule carries three-valued `result`, conserved
`definite`/`possible` bounds (`possible: null` means the upper
bound is unknown; `definite` never exceeds a known `possible`) and
site `evidence` for definite matches. Every evidence ref resolves
to a listed site key and, summed per site within one rule, never
claims more calls than that site executed (citing one site from
two rules stays legal: bounds are per-predicate). Values verbatim
from `tests/goldens/report-v2-violation.json`:

```json
{
  "rules": [
    {
      "definite": 550,
      "evidence": [
        {
          "calls": 500,
          "device": 8,
          "generation": 0,
          "inode": 100,
          "object": "build:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "offset": 4096
        },
        {
          "calls": 50,
          "device": 8,
          "generation": 1,
          "inode": 100,
          "object": "build:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "offset": 4096
        }
      ],
      "possible": 550,
      "predicate": "algorithm=DES",
      "result": "violation",
      "rule": "deny-algorithm"
    },
    {
      "definite": 0,
      "evidence": [],
      "possible": 0,
      "predicate": "weak-alias",
      "result": "pass",
      "rule": "deny-weak"
    }
  ],
  "verdict": "violation"
}
```

## CBOM mapping

`render_cbom` emits CycloneDX 1.6 with one `cryptographic-asset`
component per *definite* site (current plus fenced generations) —
never one full-count asset per candidate. Each component references
its provider and backing objects, op, funcid, calls, generation and
the report window. Ambiguous, unknown-coverage and quiet sites
contribute no components; omitted ambiguous/unknown counts plus
evidence refs stay explicit metadata, values verbatim from
`tests/goldens/cbom-v2-complete.json` (whitespace compressed):

```json
{"metadata": {"properties": [
  {"name": "osslscope:schema-version", "value": "observed-crypto-v2.1"},
  {"name": "osslscope:execution-evidence-completeness", "value": "COMPLETE"},
  {"name": "osslscope:omitted-ambiguous-sites", "value": "1"},
  {"name": "osslscope:omitted-ambiguous-calls", "value": "100"},
  {"name": "osslscope:omitted-unknown-coverage-sites", "value": "0"},
  {"name": "osslscope:omitted-unknown-coverage-calls", "value": "0"},
  {"name": "osslscope:omitted-evidence-refs", "value": "build:fedcba@4096#0:100"},
  {"name": "osslscope:window-requested-start-ns", "value": "0"},
  {"name": "osslscope:window-requested-end-ns", "value": "100"},
  {"name": "osslscope:window-effective-start-ns", "value": "0"},
  {"name": "osslscope:window-effective-end-ns", "value": "100"}
]}}
```

Evidence refs read `fingerprint12@file-offset#generation:calls`
(16 refs max, then a count). The CBOM carries the same window on
pass/violation/`PARTIAL`/inconclusive (plus `policy-verdict` when
evaluated); `PARTIAL`/`FATAL` ride an in-band disclaimer and
`FATAL` has zero components (the evidence is unusable).

## Human report

Byte-verbatim `tests/goldens/report-v2-complete.txt`:

```text
osslscope report (observed-crypto-v2.1): pid=7 (demo) window=0..100ns effective=0..100ns
openssl: 3.5.1 (verified object metadata)
target: argv_redacted=true container_id=(none) image_digest=(none)
disposition: exited code=0

sites (4, 900 calls):
  site build:012345 file-offset=4096 gen=0: 500 calls, definite: AES-128-GCM (CIPHER) via default
  site build:012345 file-offset=8192 gen=0: 300 calls, definite: SHA-256 (DIGEST) via default
  site build:fedcba file-offset=4096 gen=0: 100 calls, AMBIGUOUS (2 candidates, attribution uncertain):
    candidate: provider=build:fedcba class=default op=CIPHER funcid=21 algs=[AES-256-GCM]
    candidate: provider=build:fedcba class=default op=CIPHER funcid=21 algs=[ARIA-256-GCM] weak
  site unverified:8 file-offset=12288 gen=0: 0 calls, quiet (no calls in window)

coverage:
  provider/default: expected=3 discovered=3 attached=3 (complete)
  provider/legacy: not applicable

counters:
  loss count.map_insert_dropped (events from kernel-map) = 0
  activity count.windows_closed (events from drain) = 1

completeness: COMPLETE

policy: (not evaluated)

status=COMPLETE
absence = not-observed in window (never "not present / never used")
note: argv redacted; file offsets are not runtime addresses; window-only claims
```

Candidate lines never carry counts (the site total is shared, not
per-alias). Offsets are decimal file offsets, explicitly labeled;
no `0x` bytes appear anywhere (`output_contract` scans for them).

## Delivery API (T10 checkpoint)

```rust
pub fn render_json(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>>;
pub fn render_human(doc: &CaptureDocument) -> String;
pub fn render_cbom(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>>;
pub fn write_artifacts(doc: &CaptureDocument, req: &OutputRequest) -> DeliveryResult;
```

`OutputRequest` selects the primary format (`Human`/`Json`), the
primary destination (`Stdout`/`File`) and an optional CBOM sidecar.
`write_artifacts` renders once per format and attempts every
destination independently: a failed primary never suppresses the
CBOM attempt and vice versa. `DeliveryResult` carries per-artifact
outcomes plus bounded stderr diagnostics (at most 8 lines, 200
chars each; `emit_diagnostics` prints them).

Exit mapping (R06, owned by T10; PRD §14 order, H7-extended): 2
usage > 10 violation (even when delivery failed, even on salvaged
docs) > 1 salvaged `runtime`-fatal doc > 4 setup-no-verdict > 1
failed child / failed delivery > 11 inconclusive > `PARTIAL` 3 >
clean 0. `DeliveryResult` preserves this priority via
`failed()`/`delivered_all()` — it reports, never decides.

Primary and CBOM targeting one sink is refused (stdout would
concatenate two artifacts into unparseable bytes; one file would
overwrite the primary): the primary delivers, the CBOM outcome
records the refusal. Path comparison is lexical.

## Privacy

- No raw argv, cmdline, environment or runtime addresses in any
  artifact. `FORBIDDEN_V2_KEYS` (`src/schema.rs`) is the single
  vocabulary enforced by the schema structurally and by semantics
  by name.
- Fingerprints are opaque display strings (short form: first 12
  characters); file offsets render decimal.
- `display_locator` values are operator-visible provenance with
  stated limits, not target buffer dumps.

## v1 versus v2

v1 counted per-identity executions with a first-alias bias, flat
string reasons, fixed counter maps, and raw `cmdline` in target
sections. v2 counts physical sites once, types reasons/counters/
coverage/policy, drops `cmdline` for `argv_redacted`, and splits
validation into schema plus semantics. Keep v1 readers and
fixtures as history; write new consumers against v2.

## Provenance

JSON/CBOM/human examples: `tests/goldens/report-v2-*`,
`tests/goldens/cbom-v2-*` (pinned by
`output_contract::v2_goldens_pinned`, generated from the fixtures
in `tests/output_contract.rs`). Auditor shape:
`tests/auditor_golden_v2.json` (pinned by `tests/auditor_report.rs`
v2 suite). CLI wiring examples stay with T10; no command above was
run against a live target for this document.
