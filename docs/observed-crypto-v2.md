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

## Foreground preview

The count-only foreground producer retains the same v2.4 report/check family.
It always records an unknown-denominator profile scope and stays PARTIAL.
Candidate/provider labels describe compiled callback membership; entry counts
prove neither provider activation nor crypto/message success.

Its optional `count_object` uses the existing per-role provenance fields:
`selection` (`operator-explicit` or `installed-matched`), lowercase-hex `sha256`,
`bytes` (1 through 536870912), and `build_input_id` (null). It records the actual
retained Count bytes and operator trust selection. A Count-only document cannot
also claim a harvest/members `selected_objects`, traversal or full package build.
The digest is identity, not runtime authentication or proof that arbitrary BPF
contains no readers. The current source-built object still needs actual live
qualification. Human and CBOM metadata carry the same Count identity/profile gap.

## Reader contract

Producers emit `observed-crypto-v2.4` through `observed-crypto-v2.9`
(`src/evidence.rs` is the emitter of record: v2.5 when the window
certified execution attribution, v2.6 when a sysctl context was
sampled, v2.7 when the capture retired an owned corpse, v2.8 when
the window projected request/fetch/load/query evidence, v2.9 when
the window sealed a 6D trace fold). Readers accept
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

The optional v2.2 `window.count_admission` object records the actual
completed count Open's `start_ns` and exclusive `deadline_ns`. These bounds
are distinct from conservative effective coverage. For an earlier cut, a
callback can read TARGET before sealing and sample its timestamp later;
its real timestamp remains positive evidence within the original admission
interval even when it is past `effective_end_ns`. Such a tail requires
PARTIAL/FATAL status and a recorded coverage tail gap. Lower containment
is unchanged: no row may precede the effective or requested start. The
seal operation's return sample is not an upper bound on that callback.

Owned requested time starts at the captured lower edge immediately before
the successful release operation, before comm settling. The internal
before/after bracket does not identify the exact kernel resume instant.
External requested time retains its acquisition sample. Independently
fulfilled owned exits and exact empty overlaps omit the optional object;
without it every row retains strict effective-window containment. Strict
pre-extension validators/readers reject the new object, while tolerant
field readers can retain historical fields and ignore it. Neither the
minor version nor these arithmetic checks prove startup, clock-domain,
kernel-build or live count qualification; those remain unproven here.

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
(`check` documents only; `report` omits it), `context`
(omitted when unrecorded), `engine_observations` (omitted when
none were observed), `traversal` (omitted on harvest-only
runs; traversal runs name the exact selected triple plus
provenance and per-record facts: records, findings, polls,
admitted, admitted_unknown, census_loss, entries),
`selected_objects` (omitted when no run-set selection was recorded;
otherwise harvest/count paths and sha256, with members only for a
selected triple — pair-only selection is recorded too),
`attach_diagnostics` (omitted when no
attach failed: sorted, deduped, capped producer literals
identifying failed attaches — diagnostic only, counters stay
the exact counts), `refusal_diagnostics` (omitted when no
budget refusal was recorded: sorted, deduped, capped numeric
entries identifying device/inode, refusal kind, bytes and allowance;
diagnostic only, not an exhaustive refusal count), the v2.5
execution-attribution triple `execution_attributions`,
`algorithm_selectors`, `attribution_bounds` (present only when
the window certified a closed attribution result; see below),
and the v2.8 `request_evidence` section (present only when the
window ran a provider session and projected its request fold;
see below).
Both diagnostic
sections contain no target strings or runtime addresses;
refusal entries contain no paths. Selection paths identify
observer BPF objects, not target memory.

`algorithm_identities` and `site_provenance` (both omitted when
no candidate metadata was retained) carry the bounded
candidate-metadata projection: executed-site rows first, then
remaining rows in stable input order, whole rows only, under the
frozen 64MiB projection budget. When rows are omitted,
`completeness.counters` carries `focused.metadata_output_limit`
(kind `loss`, value 1) plus the exact
`focused.metadata_omitted_sites` (units `sites`) and
`focused.metadata_omitted_associations` (units `table-rows`)
activity counts. Physical sites, counts, attribution and policy
inputs are never reduced by projection.

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
  never wider. The monotonic `window` carries no wall clock;
  correlate by pid, disposition and counter evidence, plus the
  wall edges in optional `context` (correlation only, never
  authoritative).
- `disposition` mirrors custody: `exited` (code), `detached-running`
  (owned child left running), `foreign-observed` (`--pid` target
  left untouched).
- `context` is execution context only: host kernel release plus
  the wall-clock window edges in unix nanoseconds (either edge
  may be null for explicit unknown). The monotonic `window`
  fields stay authoritative for durations and deadlines; wall
  edges may run backward across a clock adjustment without
  affecting verdicts. Old field readers ignore this key; strict
  validators pinned to a pre-`context` schema reject documents
  carrying it (expected):

```json
{"context": {
  "kernel_release": "6.9.0-test",
  "wall_end_unix_ns": 1700000030000000000,
  "wall_start_unix_ns": 1700000000000000000
}}
```

- `engine_observations` is the replayable engine plane: one
  typed record per ENGINE tripwire observation (pinned
  caller-module triple, stub file offset, binding generation,
  frozen-registry entrypoint index + display name, window
  provenance `in-window`/`pre-window`/`untimed`, untimed call
  count). Engine observations never join site call totals or
  the legacy partition; per-rule `engine_evidence` refs (in
  `policy` rules, rendered only when present) resolve to
  observations listed in the same document.

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
installed-at vs first-counted is distinguishable. Zero-call
sites still render in the document (`0 calls, quiet`); the
never-counted omission applies only to live capture's
counted-executions list (quiet cookies stay covered by
`ScopeCoverage.attached`, not gaps).

A site is *definite* only when it executed, its candidate set is
complete, and every candidate agrees on provider, provider class,
op, funcid and one single *resolved* algorithm class
(`weak_alias` may vary and is surfaced). Anything else is
ambiguous (`complete` set, disagreeing or multi-class),
unresolved (`complete` set stuck in the `other` bucket: provider,
op and funcid are certain, the algorithm is not), unattributed
(`unknown` set or no candidates), or quiet (zero calls). A site
whose set is complete but every row mixed two or more algorithm
identities renders `candidates_coverage: "ambiguous_complete"`:
terminated tables prove no rows are missing, yet each retained
class is only its row's minimum with the alternatives unlisted, so
every predicate reads `(0, Some(calls))` — never definite, never
proved-absent — and no definite asset is minted. `fenced`
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
`environment`/`runtime` with detail). Runtime fatal retains collected
observations and is policy-eligible by kind, even without positive
counts. AttachZero is also eligible when it carries proved positive
in-window typed ENGINE evidence: provider attachment failure does
not erase that independent plane. Environment, Recycled and bare
AttachZero are unusable. Usability establishes no rule or candidate
certainty. A proved violation exits 10; other usable fatal outcomes
exit 1. `reasons` are typed objects with a `kind` discriminator:

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
The sole finalizer (`src/evidence.rs` `finalize`) also checks
unknown candidate coverage on executed sites and requested/effective
window gaps. COMPLETE can contain ambiguous complete candidate sets
and nonzero activity counters. FIPS identity is not a categorical
COMPLETE exclusion; counts can include self-tests. Flat legacy
display reasons such as `no-query` and `fips-unlabeled` are not v2
typed reasons. See [the FIPS interim rule](fips-interim.md).

Before a stopped owned child is successfully released, there is no
release-based observation interval. A cancelled or already-exited child with
no actual setup error uses the zero requested/effective window sentinel,
unknown wall edges, no count admission metadata, and no in-window execution
sites. The producer adds exactly one `capture.no_observation` counter with
kind `loss`, units `events`, source `setup`, value 1. It records that no
observation scope was established; it does not estimate missed callbacks or
a duration. This makes the document PARTIAL and every absence claim
inconclusive. Cancellation also sets `signal_cut`; an already-exited child
does not. Its actual reaped status is preserved, including status 0.
Rejected pre-release count prefixes are retained internally, never policy
hits. The external-target setup-elapsed case keeps its actual acquisition
bounds and empty effective interval at requested end.

Actual setup, release, count I/O or custody failures before a valid scope
remain FATAL Environment/no-verdict. After successful release or a completed
external Open, failures retain representable current/fenced and independent
other-plane facts as FATAL Runtime. A binding contradiction preserves its
original rejected terminal image separately; neither clipping timestamps nor
reclassifying the error as setup may manufacture a clean capture.

## Policy section (`check` only)

`src/policy.rs` evaluates rules; `src/check.rs` fills `PolicyRecord`
and `src/report.rs` renders it.
`verdict` is `pass`, `violation`, `inconclusive` or `no-verdict`
(`no-verdict` exactly on unusable `FATAL` documents with policy,
under the shared eligibility rule above). Runtime and qualifying
AttachZero documents evaluate every requested rule; uncertain
rules stay inconclusive. The
verdict is the AND of its rules: any `violation` rules a
violation, else any `inconclusive` rules inconclusive, else `pass`.
Relevance is per-rule: a `--require-executed` name absent from
the evidence violates only when the relevant coverage is
complete with zero possible use; under a relevant gap the rule
is inconclusive -- the requirement is unproven, never
fabricated into a violation or a pass. Deny rules mirror this:
only definite use violates. Positive evidence dominates: a
proved violation exits 10 on COMPLETE, PARTIAL, or usable FATAL
documents alike, even when artifact delivery failed. A rule's
inconclusive result is not an unconditional exit-11 promise;
violations, usable fatal, child and delivery failures have higher
priority. See [the exit table](usage.md#exit-codes).
`deny-selector`/`require-selector` rules (policy v2) evaluate
the execution plane instead of candidates: `definite` sums the
certified partition calls behind the exact pinned
(code-object, digest) identity, and `possible` adds the
document's certified unresolved bound (unknown when the plane
is absent or the window is relevant-partial). A positive
partition violates a deny rule even in a `PARTIAL` window;
unresolved calls can never satisfy a require rule or acquit a
deny rule. API-success rows and candidate hints never enter
execution bounds. Selector predicates render as
`object-bound:<object>:<id>` (full pinned identity, never a
truncation), and violation evidence cites the matched
partitions' sites with partition calls.
Each rule carries three-valued `result`, conserved
`definite`/`possible` bounds (`possible: null` means the upper
bound is unknown; `definite` never exceeds a known `possible`),
per-rule `relevant_complete` (true iff no gap relevant to that
rule's area remains — this is what explains a PARTIAL
pass/inconclusive mix), and site `evidence` for definite
matches. Every evidence ref resolves to a listed site key and,
summed per site within one rule, never claims more calls than
that site executed (citing one site from two rules stays legal:
bounds are per-predicate). The section also carries
`param_blind` (algorithm rules meet executed parameter-blind
operations), `unseen_deny_providers` (deny-provider matchers
proved absent — typo visibility), `kat_excluded` (always 0) with
`kat_note`, and `fips_unlabeled_executions` (FIPS-class calls
that may include self-tests). The human block shows
`relevant_complete` on every rule line and repeats the firing
caveats as `param_blind`, `unseen_deny_providers`,
`fips_unlabeled_executions` and `kat_excluded` lines. Values
verbatim from `tests/goldens/report-v2-violation.json`
(`output_contract::v2_goldens_pinned`):

```json
{
  "fips_unlabeled_executions": 0,
  "kat_excluded": 0,
  "kat_note": "executions are unlabeled (no KAT discriminator); exclusion vacuous — see fips_unlabeled_executions",
  "param_blind": false,
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
      "predicate": "DES",
      "relevant_complete": true,
      "result": "violation",
      "rule": "deny-algorithm"
    },
    {
      "definite": 0,
      "evidence": [],
      "possible": 0,
      "predicate": "weak",
      "relevant_complete": true,
      "result": "pass",
      "rule": "deny-weak"
    }
  ],
  "unseen_deny_providers": [],
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
`tests/goldens/cbom-v2-complete.json` (whitespace compressed;
`output_contract::v2_goldens_pinned`):

```json
{"metadata": {"properties": [
  {"name": "osslscope:schema-version", "value": "observed-crypto-v2.4"},
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
evaluated); `PARTIAL`/`FATAL` ride an in-band disclaimer. An
unusable `FATAL` has zero components; usable Runtime and qualifying
AttachZero documents export any definite sites under the same
certainty rules as non-fatal documents. ENGINE observations stay
separate count metadata, never provider-site assets.

Each certified execution partition (v2.5) renders exactly one
`cryptographic-asset` component (`urn:osslscope:exec-attr:v2.5:…`,
keyed by site plus segment — never a bare algorithm name, so no
cross-build equivalence is implied). The provider definition
(often `unknown`) stays separate from the executing code
object; identities are labeled `object-bound`, with a
`canonical-algorithm` property only when the spelling resolved
(opaque legs name `object-bound:<digest-prefix>` and invent no
name). When the attribution plane is present, assets render
exclusively from certified partitions: the legacy site-rule
asset is suppressed on every site (partition-covered or not),
uncovered Complete-coverage calls ride as explicit
`omitted-unpartitioned-*` omission metadata, and the
unresolved/withheld counts ride alongside. Fetch/query/API rows
and hints never mint components.

## Human report

Byte-verbatim `tests/goldens/report-v2-complete.txt` (golden
shape, with recorded execution context;
`output_contract::v2_goldens_pinned`):

```text
osslscope report (observed-crypto-v2.4): pid=7 (demo) window=0..100ns effective=0..100ns
duration: requested=100ns effective=100ns (monotonic; authoritative)
kernel: 6.9.0-test
wall: start=1700000000000000000 end=1700000030000000000 (unix-ns; context only)
openssl: 3.5.1 (verified object metadata)
target: argv_redacted=true container_id=(none) image_digest=(none)
disposition: exited code=0

sites (4, 900 calls):
  site build:012345 file-offset=4096 gen=0: 500 calls, definite: AES-128-GCM (CIPHER) via default
  site build:012345 file-offset=8192 gen=0: 300 calls, definite: SHA-256 (DIGEST) via default
  site build:fedcba file-offset=4096 gen=0: 100 calls, AMBIGUOUS (2 candidates, attribution uncertain):
    candidate: provider=build:fedcba class=default op=CIPHER funcid=FUNC21 algs=[AES-256-GCM]
    candidate: provider=build:fedcba class=default op=CIPHER funcid=FUNC21 algs=[ARIA-256-GCM] weak
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
numeric offsets and addresses never render `0x`-shaped
(`output_contract` scans for address-shaped bytes). That
guarantee covers numeric formatting only: where `--image-digest`
is admitted (the legacy `--libcrypto` route only — the normal
route refuses the flag), its text passes through control
neutralization (`safe_display` maps control/display-control
characters to `?`) but is otherwise preserved byte-for-byte, so
operator-supplied text may contain `0x`. The v0.2-era note that
nonempty values were rejected describes that preview's
validation, not the current route split above.

The three context lines after the header always render
(`src/report.rs` `render_human`): `duration` derives from the
monotonic window (always known), while `kernel` and the `wall`
edges render `unknown` when execution context was never
recorded:

```text
duration: requested=100ns effective=100ns (monotonic; authoritative)
kernel: unknown
wall: start=unknown end=unknown (unix-ns; context only)
```

Every human-rendered string passes display neutralization
(`src/report.rs` `safe_display`): control characters plus the
finite `is_display_control` set -- bidi overrides/isolates,
listed zero-width characters, WORD JOINER through INVISIBLE
PLUS (U+2060-U+2064), line/paragraph separators, and
interlinear-annotation controls -- render as `?`. Deprecated
U+206A-U+206F and other unlisted format controls pass through,
so the guarantee covers the listed set, not every invisible
format character.

## Delivery API

```rust
pub fn render_json(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>>;
pub fn render_human(doc: &CaptureDocument) -> String;
pub fn render_cbom(doc: &CaptureDocument) -> anyhow::Result<Vec<u8>>;
pub fn write_artifacts(doc: &CaptureDocument, req: &OutputRequest) -> DeliveryResult;
```

`OutputRequest` selects the primary format (`Human`/`Json`), the
primary destination (`Stdout`/`File`) and an optional CBOM sidecar.
`write_artifacts` renders once per format and attempts every
destination independently, including fatal primary/CBOM output:
a failed primary never suppresses the CBOM attempt and vice versa.
An attempt does not guarantee successful delivery. `DeliveryResult`
carries per-artifact
outcomes plus bounded stderr diagnostics (at most 8 lines, 200
chars each; `emit_diagnostics` prints them).

Exit mapping (`src/report.rs` `exit_for`): 2
usage > 10 violation (even when delivery failed, even on salvaged
docs) > 1 usable fatal doc > 4 no-verdict > 1
failed child / failed delivery > 11 inconclusive > `PARTIAL` 3 >
clean 0. `DeliveryResult` preserves this priority via
`failed()`/`delivered_all()` — it reports, never decides.

Both commands pass the entire capture result through
`consume_capture_result`; its writer-taking counterpart
`consume_capture_result_with_diagnostics` uses the same presentation, actual
requested check rules, artifact attempts and exit table. Known typed failures
survive error context wrappers. The consumer performs no count close, target
signal, wait, reap or renewed grace period. A failed diagnostic writer is
advisory and does not change artifact outcomes or exit status.

The combined diagnostic list has at most eight lines of 200 characters:
`capture cause` names a finite cause; `count terminal=epoch:sequence` names the
cleanup ticket, `cleanup` state and `unresolved-slots` count; `count prepare ticket` retains a preparation failure's ticket when no terminal was
published. `rejected-prefix` labels `known-rows`/`known-calls`, enumeration and
tail knowledge. These are retained high-water summaries, not additional
observations or a presumed zero tail. `custody` names its resolution and
actual or unknown child status; `boundary` preserves stage, class, errno and
bounded observer error detail. An optional discarded-workload hint and at
most two actual artifact failures complete the list. Raw descriptors,
arguments, candidates, payloads and terminal debug images are never emitted.
Count FD admission is a checked process-local snapshot of existing and
reserved demand, not a reservation against unrelated/future opens or a
whole-process resource guarantee. A later EMFILE still follows the retained
fatal error route.

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
- Algorithm names do not reveal key sizes or parameter-selected
  digest/cipher identities in MAC, KDF, SIGNATURE or ASYM_CIPHER.
  The current human footer states argv redaction, file-offset and
  window-only limits; it does not emit an automatic strength or
  parameter warning. These doctrinal limits apply to every format.
- Human output neutralizes display controls (`?` for control
  characters and the finite `is_display_control` set: bidi,
  listed zero-width, U+2060-U+2064, separators, and annotation
  controls; U+206A-U+206F and other unlisted format controls
  pass through), so listed hostile display characters in
  rendered provenance cannot reshape the terminal or log that
  shows it.

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
v2 suite). The `context` JSON above is verbatim from the
`context`-carrying golden shape (optional keys, omitted in JSON
when unrecorded); the human report always renders the three
context lines, with explicit `unknown`s when unrecorded. CLI
wiring is in `src/report.rs` and `src/check.rs`; these fixtures
are not current live or package qualification.

## Traversal evidence limits

- Conservative recovery can retain uncertain positive findings
  without restoring COMPLETE (`src/scan/oracle.rs`).
- Native traversal records do not establish a complete real-traffic
  window. Current integrated qualification remains open.
- Inspect `tests/scan_oracle.rs` controls for truncation, cache,
  settle and drain ordering behavior; source/fixture checks do not
  substitute for current live acceptance.

## Optional dynamic evidence (v2.4)

All older required fields keep their meanings. Three optional sections explain
observations without changing attribution, completeness, policy or CBOM:

- `algorithm_identities` contains observer-generated opaque IDs and optional
  numeric hints from the frozen presentation vocabulary. Custom IDs remain
  distinct. A hint does not admit an algorithm, identify a provider, or prove use.
- `site_provenance` references the exact physical site and count generation,
  including retained fenced generations. Each association records its origin,
  numeric operation/function IDs, alias quality, observation generation and
  first-observed timestamp. Static shapes have storage/provenance evidence and
  no invented advertiser; public ABI observations may have advertiser candidates.
  A late association never reallocates earlier calls. There is no second count
  in this section.
- `api_activity` contains per-export entries and paired observed-success/failure
  scalar returns. IDs 20–72 cover reviewed digest, cipher, MAC, KDF, PKEY and
  RAND operations; IDs 1–19 in the observation ABI remain unchanged. The exact
  operational registry is `src/api_activity.rs`. It includes generic cipher and
  one-shot DigestSign/Verify APIs, independently of algorithm names. IDs 49–72
  add KEM/keygen/paramgen/derive/check, DigestSign/Verify setup, one-shot
  Q_digest/Q_mac, RAND nonce/context and MD/CIPHER context constructor/
  destructor coverage. Pointer-returning exports classify NULL as failure and
  any nonzero pointer as success; void-returning destructor exports record a
  paired return as success (completed teardown call — failures are
  unobservable for void); check-family exports classify every non-1 return
  except documented −2 (unsupported) as failure, per the pinned docs.

API entries are not unique cryptographic operations. Nested wrappers may produce
several rows; a successful size query may produce no cryptographic output. No
arguments, opaque contexts, buffers, runtime aliases or provider handles are
read by the operational probes. Verification mismatch and documented unsupported
returns are mutually exclusive subsets of failure returns, never extra entries.
Their checked sum cannot exceed observed failures. Unknown return
values remain `unsupported_return` gaps. `tail` is entries without a classified
paired return, including depth/pending losses and in-flight calls. Other gap
counters can overlap it and must not be summed as a call total. `not_attached`
means no admitted operational attachment for that API (attachment ONLY — a
failed terminal read of an admitted owner's map keeps it false); zero entries
then cannot establish inactivity. `read_receipt` is the separate
successful-terminal-read receipt (true only on rows built after a successful
terminal read — admitted owners, plus verified-positive rows for unadmitted
owners whose terminal read vouched genuine BPF-counted totals; those
preserved positives earn no scope receipt): the request-evidence gate counts
this receipt — never the attachment bit — behind an observed zero. The key
serializes only when set — unreceipted rows are byte-identical to legacy
output, and legacy-stamped service windows strip the receipt on copy, so
receipt vocabulary stays within versioned request-evidence output.
`saturated` identifies a saturated scalar counter.
Attachment and finality gaps disclose the available-prefix observation boundary.

Human output prints qualified candidate hints beside positive current/fenced
sites and a separate API summary. Callback totals, the legacy partition,
`--require-executed` and definite CBOM assets use only their existing evidence
rules. Unknown candidate coverage stays Unknown even when a familiar hint or a
successful API return is shown. v2.3 documents without these sections preserve
their prior interpretation.

## Certified execution attribution (v2.5)

All older required fields keep their meanings. When the window ran
the closed attribution collect and it certified a result, the
producer projects three optional sections and upgrades
`schema_version` to `observed-crypto-v2.5` (v2.4 documents never
carry them; strict validators pinned to v2.4 reject documents
that do):

- `execution_attributions` holds one record per certified
  definite partition: the proved slice of one physical site's
  calls (site key plus generation, nonzero unique segment,
  inclusive hit extrema, calls, provider definition or
  explicit `unknown`, nonzero continuity id, operation,
  function, and an index into `algorithm_selectors`). Per-site
  partition sums never exceed the site's executed calls. A
  positive partition coexists with a `PARTIAL` window: the gap
  widens the upper bound, never the proved calls.
- `algorithm_selectors` is the document-scoped selector
  dictionary: the opaque object-bound request identities
  (retained code object, operation, digest) plus an optional
  `canonical_name`. The name is proved by re-hashing the
  observer's own frozen registry against the digest — the host
  never reads a request spelling back. Unregistered spellings
  stay opaque (`null`) but observable and matchable by
  object-bound policy; a present-but-unregistered name is
  malformed. The same spelling under another code object is
  another identity: selectors never match across builds.
- `attribution_bounds` carries the certified unresolved
  remainder (`unresolved_calls`, plus `withheld_uncertain`
  segments whose calls stay inside it) from the same closed
  result as the definite rows — present even when the definite
  set is empty (an explicit certified zero, never an absent
  plane).

Published selector digests carry the producer's 192-bit
projection (digest bytes `[8..32)` plus an 8-zero tail);
canonical resolution matches that projection explicitly and
treats any other shape as opaque. Human output adds an
`execution attributions` block only when the plane is present.
The observe → pin → enforce workflow is: `report` shows the
observed selectors, the operator pins them into a policy-v2
file (`deny-selector`/`require-selector`), and `check` enforces
the exact identities — a migrated algorithm (or rebuilt
library) carries a different identity and stops matching.

## Request/fetch/load/query evidence (v2.8)

All older required fields keep their meanings. When the window ran
a provider session, the producer folds its request facts into one
optional `request_evidence` section and upgrades `schema_version`
to `observed-crypto-v2.8` (older documents never carry it).
The section is structurally separate from the physical execution
ledger: fetch, load, and query facts never mean the fetched
object was used, and no field here names a serving provider, a
winner, or a used implementation.

- `fetches` holds one row per fetch surface with in-window edges
  (stable IDs 10–15 and 73–80, in ID order): attempts, outcomes,
  and the capability class. Capabilities differ by surface: STORE
  takes a scheme rather than an algorithm, and encoder/decoder
  selection is not an execution claim. `properties` is always the
  explicit `not_captured` gap — raw property-query strings are
  forbidden in records, and Phase 1 captures no property content.
  Every row carries at least one nonzero count (unmatched
  attempts and unmatched results are both legitimate); an
  explicit all-zero row is fabricated — the producer never emits
  one — and both readers reject it.
- `loads` holds one row per observed provider name class with
  the `candidate` tier only: successful loads are candidates,
  and same-name providers stay candidates here, never a forced
  winner (name classes cannot count distinct providers).
- `inits` counts actual init-callback outcomes (the
  `get0_dispatch` table getter and `add_builtin` registration
  records are not init executions); `queries` counts query
  outcomes per operation with cacheability, split by observation
  side (`wrapper` = public `OSSL_PROVIDER_query_operation`,
  `callback` = provider query callback — the same traversal at
  two layers, never collapsed); `advertisements` counts
  returned-table ALGORITHM ROWS per operation at the `candidate`
  tier (per-dispatch-function facts are not additional entries; a
  sole advertiser never proves execution).
- `default_activation` is `load_observed` only when an explicit
  in-window GENUINE load success for the default class was
  observed (`add_builtin` registration never qualifies), and
  `unknown` otherwise — silence covers both silent auto-loading
  and pre-attach loads, and is never manufactured into either
  positive or negative. Human output names the positive state an
  observed default-class load.
- `unattributed` is the operational remainder with no proven
  fetch: `unknown` when the operational plane was unobserved
  (never a zero over an unobserved population — refused attaches
  and failed terminal count reads observe nothing, so the
  producer maps them to `unknown`, not to an observed zero),
  else every observed operational entry — Phase 1 proves no
  fetch-to-execution continuity, so observed fetches never
  shrink it. Implicit one-shot/direct-init paths land here. The
  plane is observed only when a successful scoped count read
  vouches for it (or positive entries exist); an armed-idle
  window is the only honest observed zero — including through a
  clean preserving retirement, whose retired idle publishes its
  observed zero with its interval. A mid-window fence
  voids the zero when its sealed cut intersects the claimed
  interval (terminal readability is not observability across a
  counting cut — verified positives are still retained). A
  mid-run disarm without a sealed fence (an additive
  retire/re-add is the live case) voids it too — the receipt
  needs CONTINUOUS coverage across the claimed interval, and a
  final source refusal disqualifies it (no valid source custody,
  no zero). The void lands AT the disarm transition: a retirement
  that defers past worker saturation has already disarmed when it
  returns, so a seal while the retry is still outstanding sees
  the gap (and the disarmed plane cannot establish a claim). An
  UNESTABLISHED claim — establishment refused, fenced, expired,
  or disarmed — never certifies an operational zero
  either: the idle plane stays `unknown` (terminal reads alone
  never stand in for an established silence interval — there is
  no setup-time fallback). Zero eligibility further binds to
  live operational admission for the exact incarnation at claim
  start: a retired incarnation's still-admitted cookies (stale
  map rows) never certify a re-added incarnation's interval —
  only cookies live for that incarnation when the claim advances
  vouch (historical positives still project as rows). An owner
  admitted after the claim advances (a late joiner) earns no
  receipt for the claimed interval — its coverage starts
  mid-window — though its verified positives still project;
  runs that never advance a claim evaluate liveness at seal
  instead, so a late arrival into a claimless run receipts like
  any live owner. And like the fetch plane, the operational plane needs
  EVERY eligible site: an eligible operational attach that never
  armed, or an operational surface discovery skipped, voids the
  zero even when a same-API sibling reads zero (the explicit API
  21 quarantine never voids — quarantine is the only gap the
  full-budget idle control carries, and the exclusion applies to
  both the attach gaps and the discovery verdict, so an
  API-21-only refusal on either still receipts). A discovery
  parse refusal records operational uncertainty only for
  mappings eligible for the refused API — a fetch-only
  exporter's refusal vetoes no operational zero — while
  whole-API skips from process revalidation failure still track.
  A preserving terminal retirement removes the target but keeps
  its gap verdict for the exact claimed incarnation through the
  seal (a clean sibling read never certifies the retired blind
  site) — and only for exact members of an ESTABLISHED claim: a
  late, claimless, or otherwise off-cohort retiree retains
  nothing and fires no latch (a claimless retire removes its
  owner from the live seal fallback, so retention could only
  waste the slot or latch an unrelated scope). Continuity marks
  are incarnation-exact `(pid, starttime)` pairs retained only
  for the active claim cohort under the session bound (stale
  re-retires of historical owners retain nothing, and a retire
  with no live incarnation marks nothing — a replacement
  incarnation's retirement never revokes an earlier preserving
  retiree's receipt after PID reuse). A custody refusal live
  drain directly observes on a claimed original's rows persists
  for the exact historical incarnation through the evicting
  retire (the seal cannot revalidate a discarded source, so
  without retention its stale readable counters would certify
  zero); a refusal the retirement recheck observes on the
  rechecked original, or reconcile observes under a matching
  historical record, persists the same way (the evicting
  retire's incoming gap skips its own recheck, so the recheck
  is the only observation point — including deferred
  evictions, whose retry can re-record past the recheck);
  externally-attributed retire gaps (ring-event, re-add) say
  nothing about the historical source's custody and retain
  nothing; a record mismatch over clean backing likewise
  retains nothing (a different incarnation). But a mismatch
  never skips validation of ANY retained original: EVERY
  retained original's descriptor is checked independently
  before the mismatch-driven eviction — several distinct
  backing files can sit under one PID, so a healthy first
  backing must not hide a refused later one — and any genuine
  backing refusal persists for its exact incarnation
  alongside the mismatch gap (else the orphaned stale reads
  would certify). All three retention blocks are allocated exactly at
  the session cap with their worst-case bytes on the session
  lease, so the lease covers actual storage, not a key-payload
  estimate; past the cap the receipt fails closed session-wide
  rather than drop a mark or verdict.
  Whole-pid terminal refusals stay pid-wide deliberately:
  refused records cannot be attributed to an incarnation, so
  genuinely uncertain custody still voids every scope.
  Serially, an observed zero requires successful reads of the
  COMPLETE eligible cohort behind it: every claim-eligible cookie
  must read successfully — one successful zero read never
  certifies past an unread sibling, which may hold positives
  (failed reads and deadline-skipped reads project their
  diagnostic rows but carry no receipt, and their
  `not_attached` bit stays false: the owner was admitted — the
  read failed, not the attach).
- `fetch_coverage` records per-surface EFFECTIVE probe coverage
  for all 14 surfaces: an absent fetch row under coverage is an
  armed-idle in-window zero, while an absent row WITHOUT coverage
  is unknown, never a zero. Covered means armed at or before the
  claimed-interval start — effective admission (the focused run
  path establishes the start after the first completed attach, so
  setup arms precede the claim and the blind setup prefix stays
  outside it) — with continuous coverage of the claimed interval:
  no mid-window disarm (retire, fence, re-add, or a deferred
  retirement's disarm transition — disarmed arms void at once,
  stale arm timestamps never certify, and a post-claim
  arm with no edges is unknown, never an in-window zero, even
  when it precedes the first drain), no observed in-window
  loss (a dropped edge may have been the missing one; loss-lane
  deltas, fact/state-limit drops, failed terminal loss-map
  reads, and wire-decoding rejections — a refused record's api
  word is untrusted, so no surface can be excluded — all void
  zeros), EVERY eligible site armed (one armed export never
  certifies a surface whose second resolved site stayed blind —
  including a site discovery never resolved: an inventoried
  exporter skipped by a parse refusal, cached or uncached, or by
  a revalidation skip (a transient that resolves nothing still
  records its API into the pass verdict), withholds its surface
  until a later pass resolves and arms every eligible site),
  no unmarked learned-role conflict (a conflict disarms its site
  and marks every disarmed surface — a surviving same-API sibling
  never certifies a surface whose evidence was discarded — while
  queued facts from unrelated surfaces are preserved),
  and, for terminal owners, terminal
  custody for EACH contributing attachment (one valid startup
  original never authorizes a sibling mapped-only fetch whose
  edge the terminal binding drops). Surfaces with folded edges
  are observed by evidence regardless.
- `silence_window` (window scope only) publishes the narrower
  `[start_ns, end_ns)` silence interval the section's zeros are
  claimed over, in both formats: request ROWS cover the whole
  published capture window (genuine setup-prefix edges are
  preserved as positives), while an absent row's zero — and the
  unattributed observed zero — hold only from effective
  admission through the writer cut. The seal samples its end
  instant AFTER closing the writers, so the claimed end is the
  successful cut's conservative `close_before_ns` (bounded by
  the capture deadline — a failed cut keeps the end sample and
  gaps instead). Every zero claim rides a NONEMPTY published
  interval: a late claim clamped empty publishes no interval and
  certifies no zeros (idle planes read `unknown`, armed-but-edgeless
  surfaces read unobserved — positives still project), claim
  establishment is refused at/after the deadline, when no interval
  remains, and an unestablished claim publishes no interval at
  all (never a setup-time fallback). The gate binds the interval
  inside the document's effective window; per-batch sections omit
  it (no window, no silence claim). Readers decode the interval
  object directly from the wire (duplicate members rejected —
  a collapsed re-read would last-win them away), and the
  raw-text document intake rejects duplicate section keys before
  `Value` normalization (which would collapse them invisibly). A
  repeated top-level `request_evidence` member is rejected the
  same way — the scan used to walk only the first member while
  parsing last-wins, letting a second member replace the checked
  one and conceal nested duplicates.

Per-surface zeros are coverage-gated in-window zeros over an
armed window; attach refusals ride as gaps in the same document.
Human output adds a `request evidence` block after the physical
ledger with the same honesty banner. CBOM, policy, and
completeness rules are unchanged by this section.

## 6D trace projection (v2.9)

All older required fields keep their meanings. When the window ran
a provider session in a pairing mode (`latency`, `status`, `all`)
or the D0-6 aggregate-only fallback, the producer seals its trace
fold into one optional `trace_summary` section and stamps
`observed-crypto-v2.9` (older documents never carry the
section; P2fix8 NEW-51: producer documents spell the
discriminator `schema`, rendered/raw v2 documents spell it
`schema_version` — each input shape binds its CANONICAL
spelling, a foreign alias rejects, and duplicate raw
discriminators reject). The section lives on the PUBLIC-API
plane: pairs,
return classes, and durations of public export invocations —
never physical callback entries, never observer overhead, never
application outcomes.

- `window` is the sealed §6D-7 record: paired/unpaired counts,
  depth/dropped/capped/nonmonotonic/rejected counters, the 8 loss
  lanes, per-class window counts, and hashed exemplars (`gaps`
  stays empty — no GAP-kind producer exists on this plane, so
  loss rides GapCounters, lanes, and unpaired counts instead;
  nonempty GAP inputs reject until a typed producer exists).
  `class_epoch` folds the epoch pair counts; `histograms` carries
  the cumulative latency distributions under the frozen
  `6d-frozen-18` edge set in latency-bearing modes only (`status`
  carries none).
- `by_api`/`by_api_availability` ride the `--trace-histogram-by-api`
  opt-in only: sparse per-API distributions over covered
  operational IDs plus the dense 53-ID availability map
  (`covered`/`not_attached`/`partial_coverage`, read from the
  window's `ApiActivityRow` gaps — never from trace presence).
  Current producers report an EMPTY covered population (terminal
  rows hard-set attachment+finality — first-call coverage is
  future producer work), so the sparse L1 block is empty by
  construction while the dense map still flows; P-16/P-17 adapter
  ingestion is proven via injected summary vectors, not yet via
  live covered populations.
- `mode` names the effective word, `fallback` marks D0-6 state
  (fetch/lifecycle class-0 pairs only; operational
  edges/durations/classes 1..4 unreachable). Human output adds a
  `trace` block after the request section. ONE TYPED
  document-level trace contract runs identically across every
  reader — raw intake, both presenter inputs, and restored
  checkpoints run the same function (P2fix4 NEW-P3 — narrowed
  to the proven paths; P2fix8 NEW-51 — the section/version
  trigger binds the input shape's CANONICAL discriminator,
  producer `schema` vs raw/doc_json `schema_version`, never a
  uniform either/or selector): the section/version trigger both
  ways (minor 9 needs its section; a section needs minor ≥ 9;
  a foreign alias or duplicate raw discriminator rejects),
  required-nullable presence + null rules (explicit
  `class_epoch`/`class_window`, no null on non-nullables),
  required-vs-withheld field rules, inner/outer mode +
  uncertainty coherence (closed reason vocabulary,
  uncertain-iff-nonempty, unbound-mark-iff-late-cut), EXACT
  class/paired conservation (widened arithmetic — no
  saturating-sum equality — plus combined L1 count/bucket/sum
  conservation into the default fold), cumulative-bucket
  invariants, the mode binding, the shared §6D-6
  fallback-family classifier at production pairing and intake
  alike, and coverage-vs-`api_activity` reconciliation (EVERY
  availability word binds to the producer worst-wins rule over
  the rows — not just `covered` claims; a PRESENT collection
  must be an array and EVERY row carries the COMPLETE
  raw-schema shape — all required keys with exact types, api in
  20..=72, no duplicate apis — validated before ranking, with
  no skips and no short-circuit, EVEN with the by-api opt-in
  disabled; API+flags alone is insufficient on every reader —
  P2fix6 NEW-37, P2fix7 NEW-42). Raw pre-normalization
  duplicate checks run on every path that receives raw text
  (document text: the `request_evidence`, `trace_summary`, and
  `api_activity` sections plus the top-level discriminator
  members — P2fix8 NEW-51; window envelopes and checkpoint
  files: whole-tree — P2fix7 NEW-42); Value-only intake
  validates the typed contract (no raw text exists to check).
  Typed readers enforce the raw schema's closed shape (extra
  properties reject at every level, never discard; exemplar
  hashes spell canonical lowercase like the raw pattern).
  CBOM and policy rules are unchanged by this section.
- Loss/completeness (corrected producer): the six `trace_*`
  counters project as Loss-kind GapCounters (PARTIAL iff
  positive) through the shared finalizer AND as the same-named
  record fields, and a pairing-uncertain seal degrades focused
  completeness through the seal-gap word (mirroring the
  standalone seal-degrade rule) — counted loss and seal taint
  alike surface in the document verdict; neither hides in a
  COMPLETE focused/standalone document. After pairing-state
  corruption (pending eviction, depth overflow, decode
  rejection, late cut), interpreted duration/status
  distributions withhold until a proved fresh boundary on a
  successful producer boundary (P2fix7 NEW-41, attribution
  P2fix8 NEW-49 — a successful RCU gate close (map-in-map
  deletion waits out the grace period, so writers are detached
  and no new reserves can start — THAT is writer quiescence)
  AND affirmative ring exhaustion (the terminal drain samples
  ringbuf producer/consumer positions: a bare ring `None` is
  busy-or-empty and proves nothing, but producer==consumer
  proves zero outstanding bytes — a busy head implies producer
  > consumer, so equality rules it out by construction; two
  consecutive equal samples straddling a scheduling
  opportunity prove exhaustion stable across the sleep, a
  recovered record resets the count and folds first, and
  outstanding/unreadable positions or an expired deadline fail
  closed, never confirm) AND successful terminal loss-lane
  reads on every lane (P2fix7 NEW-47 — the loss poll precedes
  the receipt; a missing/failed terminal loss read withholds
  and voids) AND proof acquisition inside the terminal
  deadline (P2fix8 NEW-49 — a final sweep + recheck finishing
  at/past the deadline withholds, never mints, while the
  observed terminal loss stays accounted) AND terminal
  settlement AND a clean close with empty pending and no fresh
  corruption, WITH the positive terminal-drain receipt the
  drain stores; host finalization alone — settled and clean
  with no drainage evidence — carries taint, never clears it;
  an explicit failed/unproved terminal boundary (failed gate
  close OR dirty/unproved terminal drain OR failed terminal
  loss read OR post-deadline proof) withholds interpretations
  even with clean history — the seal names
  `terminal-boundary-failed`, never clears it).
  Raw counters/lanes/unpaired/exemplars flow —
  EXCEPT the late-cut window projection: a late cut marks the
  sealed window unbound and withholds its paired/detail counts
  as window-scoped evidence across EVERY focused output (seal
  record, human summary line, follow frames — each withholds
  as `paired=withheld (late-cut)`; the explicit
  `cut_unbound=true` mark rides the seal record and the human
  summary line, while follow frames name the cause inline on
  the TRACE line without a separate mark token); the retained
  count stays only in explicitly unbound
  diagnostics (the marked document JSON — never a clean
  reading). Service epochs withhold epoch trace
  series (`class_epoch`, histograms, `by_outcome`, P-16/P-17)
  until the per-window producer contract exists. No
  latency/throughput budget is claimed qualified (C023
  acceptance stays OPEN): short-run characterization numbers
  are disclosed measurements, never sustained ceilings.
- Claim qualification (NEW-P3 — what the above does and does not
  cover): the completeness/withholding claims hold on the PROVEN
  producer + cut paths only — focused captures and standalone
  scan/inspect seals with terminal finalize-then-close (single
  window each; mid-run closes carry taint; no multi-window
  production sealing exists, and production service windows emit
  no trace at all). Intake validates shape, vocabulary,
  coherence, and conservation — never producer truth (a
  well-formed section from a faulty producer validates; the
  contract rejects malformed sections, not honest mistakes
  inside well-formed ones). Window-bound evidence binds to the
  EFFECTIVE cut (the reported effective end, not the requested
  deadline): records at/above the cut skip the trace fold, and
  pairs already consumed past a late cut taint instead of
  standing. Reconciliation with the actual receipts: sealed
  evidence is not delivered telemetry (OTLP outcomes account
  every push — pushed, partial rejection with
  `partial_rejected`, malformed responses never counting as
  acceptance, transport failures retried then dropped with
  `dropped_push`, backpressure handoff drops counted as
  `dropped_queue`; scrapes serve last-good with serve-time
  freshness or an explicit error — while scrapes shed past the
  concurrency cap shed silently by design, as server-side load
  protection the scraper retries, never as data loss); the C023
  oracle (exact estimator on matched schedules) is
  characterization, not qualification (short-run numbers
  disclosed with their schedules, never ceilings); and
  retry-dependent evidence carries its retry basis (fetch
  failed-then-exact-on-retry, focused exact-on-retry documents)
  rather than a first-try claim.
