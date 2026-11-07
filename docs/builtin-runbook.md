<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Built-in provider runbook: stripped or unknown libcrypto

Built-in observation (`report`/`check` automatic discovery,
`inspect --builtin`) must find one file offset inside
libcrypto: the provider-query operation. It tries four rungs
in order and reports which one won (`resolution`):

1. `--force-offset N` — your explicit offset, always wins.
2. Build-id table — the stripped binary's `.note.gnu.build-id`
   looked up in the shipped table (`etc/build-id-table.json`,
   eleven exact builds) or your `--table FILE`. A hit is
   verified against the object's own anchor symbol; a
   mismatch fails closed, never silently.
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

If every rung fails, `report`/`check` refuse with enrollment
remediation (exit 4) and `inspect` reports PARTIAL
(`anchor-unresolved`) — never a guess. If a rung yields a
dead offset you get zero rows: the output itself is the
proof, so always re-run after a change and demand rows.

`run --` finds the libcrypto to qualify by predicting the
loader: the exe's `DT_NEEDED` closure (direct and transitive)
via `LD_LIBRARY_PATH`, rpath/runpath (`$ORIGIN` expanded),
and system defaults. RPATH beats `LD_LIBRARY_PATH`; with
RUNPATH the reverse holds; `ld.so.cache` is not consulted.
Scripts, `dlopen`-only loads, unresolvable names, and
closures mapping two distinct libcryptos (dual-load, refused
fail-closed) need explicit `--provider` (`doctor --exe`
shows the same prediction before you run).

## Recipe

1. Ask doctor what it sees:

   ```sh
   osslscope doctor --libcrypto /path/to/libcrypto.so.3
   ```

   `dispatch-anchor: supported via table|symtab` means you are
   covered — no flags needed. `unqualified build` means
   proceed. (`build-id: unknown` alone is not the verdict; the
   anchor row is.)

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

3. Run without enrollment flags. Explicit offset/table
   enrollment is deferred-by-design on `report`/`check` (both
   reject `--table` outright, and `--force-offset` outside the
   legacy `--libcrypto` diagnostics), and the current surface
   admits static entry shapes automatically, without build
   enrollment:

   ```sh
   osslscope report --duration 30 --format json run -- ./my-app --serve
   osslscope inspect --pid 1234
   ```

   Require expected rows under representative traffic. Zero
   rows can reflect a missing trigger or an unadmitted shape;
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

   `report`/`check` do not consume this file: table enrollment
   is deferred-by-design beyond v0.2. Only `doctor` still vets
   explicit enrollment, with the same file — but sectioned
   `doctor` needs package admission first: either a release
   install whose binary carries the matching embedded package
   contract, or an explicit harvest/count object pair
   (dev-built binaries embed no contract, so a bare
   `--exe --table` run exits 4 with `package admission refused`
   before any target check runs). Vet with the pair from the
   repo build (or the installed `$PREFIX/lib/osslscope/` pair):

   ```sh
   osslscope doctor --exe ./my-app --table my-table.json \
     --object crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest \
     --count-object crates/ebpf/target/bpfel-unknown-none/release/osslscope-count
   ```

   A `fallback` section with a per-version `delta` re-enables
   rung 4 for the named versions — but only through this
   explicit file. Exit 0 needs effective `CAP_BPF`+`CAP_PERFMON`
   or effective `CAP_SYS_ADMIN`, with no UID-0 exemption (root
   with dropped caps fails like any unprivileged user);
   without them the target/table rows still run but the
   verdict fails closed on `caps`.

`--table` also works with `doctor --pid`: the same file drives
vetting with the same admission requirement (the `--libcrypto`
diagnostics take no enrollment flags), so doctor agrees with
the backend.

## Provider-class enrollment

Separately from offsets, `--provider-table FILE` pins which
provider class an exact build-id carries (see
`etc/provider-table.example.json` for the shape). Classes are
`default`, `legacy`, `fips`, or `third-party`; build-ids are
lowercase hex. Without enrollment, builtin observation
labels the class `default` by operator assertion, and file
providers stay unknown (observed under an opaque identity).
A pinned `fips` class is provenance metadata about those
exact bytes — never a certification claim.
