<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Built-in provider runbook: stripped or unknown libcrypto

Vetting a stripped or unknown libcrypto means resolving one
file offset inside it: the provider-query operation.
`doctor` runs that four-rung ladder for its `dispatch-anchor`
row and reports which rung won (`resolution`):

1. `--force-offset N` — your explicit offset, always wins
   (doctor-only: `report`/`check` reject the flag everywhere).
2. Build-id table — the stripped binary's `.note.gnu.build-id`
   looked up in the shipped table (`etc/build-id-table.json`,
   eleven exact builds), or your explicit `--table FILE`
   (doctor-only). A hit is verified against the object's own
   anchor symbol; a mismatch fails closed, never silently.
3. Symtab — direct symbol lookup; works only when the binary
   (or debug info) still has a symbol table.
4. Anchor+delta — exported anchor symbol plus a per-OpenSSL-version
   delta from an **explicitly selected** `--table FILE` only.
   This rung never runs automatically: unknown stripped
   builds need explicit enrollment, never a guessed offset.

An unknown build-id alone does not imply refusal: supported symtab
resolution can admit an unstripped build without a new table row.
Rebuilds can change identities and offsets; recheck the exact bytes
and repeat admission rather than assuming every rebuild changes
the id. Table enrollment proves an anchor, not current live or
performance qualification (`tests/build_id_table.rs`,
`tests/onboarding.rs`).

If every rung fails, `doctor` shows `unqualified build` in its
`dispatch-anchor` row (exit 4) — never a guess. Live
`report`/`check` do not consult this ladder at all: the focused
controller observes without resolving or gating on the query
anchor, so an unresolvable offset never refuses a capture
(verify by running: an unknown stripped libcrypto still
produces `PARTIAL` with rows when the workload executes
crypto). Enrollment is therefore doctor-only vetting:
`report`/`check` reject the flags outright.

`doctor --exe` predicts the target libcrypto by the loader
rule: the exe's `DT_NEEDED` closure (direct and transitive)
via `LD_LIBRARY_PATH`, rpath/runpath (`$ORIGIN` expanded),
and system defaults. RPATH beats `LD_LIBRARY_PATH`; with
RUNPATH the reverse holds; `ld.so.cache` is not consulted.
Scripts, `dlopen`-only loads, unresolvable names, and
closures mapping two distinct libcryptos (dual-load) are
refused fail-closed wherever prediction runs, with no
per-run override on the current surface (`--provider` is
rejected everywhere: on `report`/`check` without
`--libcrypto`, and the legacy route is count-only): reduce
to a single libcrypto visible to the loader. Live
`report`/`check` perform no loader prediction or libcrypto
qualification themselves.

## Recipe

1. Ask doctor what it sees. For a live process mapping the
   library:

   ```sh
   osslscope doctor --pid <pid>
   ```

   `dispatch-anchor: supported via table|symtab` means the
   anchor resolves with no enrollment. `unqualified build`
   means proceed to enrollment (step 4) to vet it.
   (`build-id: unknown` alone is not the verdict; the
   anchor row is.) Sectioned `doctor` needs package admission
   first (a release install, or the explicit object pair from
   step 4). The verdict qualifies the anchor only — live
   `report`/`check` observe with or without it.

   A bare `doctor --libcrypto PATH` instead runs the legacy
   exact-profile diagnostic (`profile`/`count-object`/
   `capabilities` rows, no anchor verdict); vetting a bare path
   with explicit enrollment is step 4's
   `doctor --libcrypto PATH --table ...` form.

2. Find the query offset from an **unstripped twin** of the same
   build (same compiler, flags, and sources — verify with
   `readelf -n`: the build-id must match the stripped binary's):

   ```sh
   readelf -sW libcrypto.so.3 | grep -E 'OSSL_PROVIDER_available|provider_query_operation'
   ```

   The table wants *file* offsets. For a normal `-pie`/shared
   link the symbol value minus its section's load bias is the
   file offset; confirm by checking the value falls inside the
   `PT_LOAD` (R E) segment's file range (`readelf -lW`).

3. Run without enrollment flags. `report`/`check` reject
   `--table` and `--force-offset` everywhere (parse-rejected
   outright; `--force-offset` is runtime-rejected even with
   `--libcrypto` — both are doctor-only), and the focused
   controller neither resolves nor gates on the query anchor:
   observation proceeds with or without a resolvable offset,
   `PARTIAL` when other gaps apply:

   ```sh
   osslscope report --duration 30 --format json run -- ./my-app --serve
   osslscope inspect --pid 1234
   ```

   Require expected rows under representative traffic. Zero
   rows can reflect a missing trigger or an observation gap;
   diagnose both, never ship a guess. COMPLETE coverage alone
   does not settle candidate identity.

4. To persist it, write a `--table` entry (only `build_id`,
   `query_offset`, `anchor`, and `anchor_offset` are required):

   ```json
   {"table_version": 1,
    "entries": [{"build_id": "<from readelf -n>",
      "query_offset": 2612992,
      "anchor": "OSSL_PROVIDER_available",
      "anchor_offset": 2612560}]}
   ```

   `report`/`check` neither consume this file (rejected
   outright: table enrollment is deferred-by-design beyond
   v0.2) nor need the anchor it proves. Only `doctor` vets
   explicit enrollment, with the same file — but sectioned
   `doctor` needs package admission first: either a release
   install whose binary carries the matching embedded package
   contract, or an explicit harvest/count object pair
   (dev-built binaries embed no contract, so a bare
   `--libcrypto --table` run exits 4 with `package admission refused`
   before any target check runs). Vet with the pair from the
   repo build (or the installed `$PREFIX/lib/osslscope/` pair):

   ```sh
   osslscope doctor --libcrypto /path/to/libcrypto.so.3 --table my-table.json \
     --object crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest \
     --count-object crates/ebpf/target/bpfel-unknown-none/release/osslscope-count
   ```

   (`--exe ./my-app --table my-table.json` with the same pair
   vets the spawn-predicted library instead of a fixed path.)

   A `fallback` section with a per-version `delta` re-enables
   rung 4 for the named versions — but only through this
   explicit file. Exit 0 needs effective `CAP_BPF`+`CAP_PERFMON`
   or effective `CAP_SYS_ADMIN`, with no UID-0 exemption (root
   with dropped caps fails like any unprivileged user);
   without them the target/table rows still run but the
   verdict fails closed on `caps`.

`--table` also works with `doctor --pid`: the same file drives
vetting with the same admission requirement (bare
`--libcrypto` selects the legacy diagnostics, which take no
enrollment flags), so every target selector vets through the
same ladder.

## Provider-class enrollment

Separately from offsets, `doctor --provider-table FILE` pins
which provider class an exact build-id carries (see
`etc/provider-table.example.json` for the shape;
`report`/`check` reject the flag — class enrollment is
doctor-only vetting, like offset enrollment). Classes are
`default`, `legacy`, `fips`, or `third-party`; build-ids are
lowercase hex. Without enrollment, `doctor` labels a builtin
target's class `default` by operator assertion, and a file
provider's class unknown; live `report`/`check` carry no
class labels (providers appear under opaque identities).
A pinned `fips` class is provenance metadata about those
exact bytes — never a certification claim.
