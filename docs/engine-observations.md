<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Typed ENGINE observations

Public design note for the replayable ENGINE plane (R05/F06):
typed tripwire observations enter the finalized document so policy
and renderers replay from the same evidence.

## Tripwire source

Production ENGINE probes are caller-module PLT stubs
(`src/discovery/legacy.rs` `probes_for`): each `ENGINE_*` import in
a scanned caller module becomes a probe at that module's stub
offset. Provider loads stay on libcrypto (global events); ENGINE,
meth, and low-level call sites are caller-attributed per module.
Low-level families, meth symbols, and load cookies route through
the same counters but never become ENGINE observations.

## Pin, generation, retirement

Each `(module, program)` attach group pins separately
(`src/discovery/session.rs` `attach_trips`): the uprobe link binds
the opened file description, and the session retains each group's
`(dev, ino)` from its pin at install time. Observations key each
probe's stub to its own group's pinned identity — never to
libcrypto — so two callers sharing an entrypoint and stub offset
keep distinct keys, and so does one pathname bound through two
programs when it is replaced between the groups' attaches.

The tripwire binding generation is 0 at the first bind, +1 per
install. Counts key per `(generation, cookie)`; a replacement can
never join two bindings' probes into one row. Before a replacement
install, the session fences the retired binding by draining the
cumulative `TRIP` map under the retired generation (retired news
rides the poll tagged with its generation). The `TRIP` and
`LGCALLS` streams fence independently: one stream's failure never
discards the other's successful drain. A failed `TRIP` fence
refuses attribution (loud snapshot loss) rather than joining
ambiguous counts to fresh meanings, and the refusal latches until
a trustworthy `TRIP` read re-baselines.

## Window binding

The live path emits `in-window` observations only: counters
baseline at the window boundary and accumulate from in-window
polls. Straddling polls (completing at/after the deadline) and the
post-count-close tail are explicit loss, never observations.
`pre-window` observations are retained replay context, excluded
from verdict bounds. Documents may also carry `untimed`
observations (constructed/imported evidence with unknown window
binding); the live path never emits them.

## Timing and count certainty

Trip counters are untimed by construction (hits carry no
timestamps), so observations carry no first/last fields: the window
binding is the certainty. `definite` sums in-window calls; any
executed untimed observation forces the upper bound unknown (fail
closed — untimed evidence must not let deny-engine pass as proved
absence). Engine-area rules keep trusting no gap: any relevant gap
forces `possible = None`.

## Additive representation

`engine_observations` (on the document) and `engine_evidence` (on
policy rule results) are OPTIONAL schema keys and serde-`default`
fields: old documents read as empty, and old validators refuse new
documents (strict `additionalProperties: false`) rather than
evaluating deny-engine over evidence they cannot see. Definite
refs resolve to `in-window` observations only, with per-rule
no-double-claim. Provider `total_calls()` and the legacy call
partition keep their conserved dispatch unit: ENGINE calls never
join them. The legacy tripwire fallback stays until every caller
uses typed input.
