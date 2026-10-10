<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Built-in provider runbook: stripped or unknown libcrypto

Built-in observation (`report`/`check` automatic discovery,
`inspect --builtin`) must find one file offset inside
libcrypto: the provider-query operation. It tries four rungs
in order and reports which one won (`resolution`):

1. `--force-offset N` — your explicit offset, always wins.
2. Build-id table — the stripped binary's `.note.gnu.build-id`
   looked up in the shipped table (`etc/build-id-table.json`,
   ten historical builds) or your `--table FILE`. A hit is
   verified against the object's own anchor symbol; a
   mismatch fails closed, never silently.
3. Symtab — direct symbol lookup; works only when the binary
   (or debug info) still has a symbol table.
4. Anchor+delta — exported anchor symbol plus a per-OpenSSL-version
   delta from an **explicitly selected** `--table FILE` only.
   This rung never runs automatically: unknown stripped
   builds need explicit enrollment, never a guessed offset.

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

3. Use it for one run:

   ```sh
   osslscope report --force-offset 0x27df00 run -- ./my-app --serve
   osslscope inspect --pid 1234 --provider /path/to/libcrypto.so.3 \
     --object crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest \
     --builtin --force-offset 0x27df00 --out inspect.json
   ```

   `--force-offset` takes decimal or `0x` hex. Demand a COMPLETE
   verdict with rows; zero rows means the offset is dead —
   re-derive, never ship the guess.

4. To persist it, write a `--table` entry (only `build_id`,
   `query_offset`, `anchor`, and `anchor_offset` are required):

   ```json
   {"table_version": 1,
    "entries": [{"build_id": "<from readelf -n>",
      "query_offset": 2612992,
      "anchor": "OSSL_PROVIDER_available",
      "anchor_offset": 2612560}]}
   ```

   Then `osslscope report --table my-table.json run -- ...`
   (or the same flag on `inspect`/`check`/`doctor`). A
   `fallback` section with a per-version `delta` re-enables
   rung 4 for the named versions — but only through this
   explicit file.

`--table` also works with `doctor --libcrypto` and
`doctor --pid`: the same file drives vetting and capture, so
doctor agrees with the backend.

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
