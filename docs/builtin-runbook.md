# Built-in provider runbook: stripped or unknown libcrypto

`inspect --builtin` (and `report --builtin`) must find one file
offset inside libcrypto: the provider-query operation. It tries
four rungs in order and reports which one won (`resolution`):

1. `--force-offset N` — your explicit offset, always wins.
2. Build-id table — the stripped binary's `.note.gnu.build-id`
   looked up in the built-in table (`etc/build-id-table.json`)
   or your `--table FILE`.
3. Symtab — direct symbol lookup; works only when the binary
   (or debug info) still has a symbol table.
4. Anchor+delta — exported anchor symbol plus a per-OpenSSL-version
   delta; a degraded fallback, not a promise.

If every rung fails you get PARTIAL (`anchor-unresolved`),
never a guess. If a rung yields a dead offset you get zero
rows (PARTIAL `no-query-trigger`): the output itself is the
proof, so always re-run after a change and demand rows.

## Recipe

1. Ask doctor what it sees:

   ```sh
   osslscope doctor --libcrypto /path/to/libcrypto.so.3
   ```

   `known build <id> (OpenSSL X, query_offset N)` means rung 2
   covers you — no flags needed. `unknown build-id <id>` means
   proceed.

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
   osslscope inspect --pid 1234 --provider /path/to/libcrypto.so.3 \
     --object ebpf.o --builtin --force-offset 0x27df00 --out inspect.json
   ```

   `--force-offset` takes decimal or `0x` hex. Demand a COMPLETE
   verdict with rows; zero rows means the offset is dead —
   re-derive, never ship the guess.

4. To persist it, append a `--table` entry (only `build_id`,
   `query_offset`, and `anchor_offset` are required):

   ```json
   {"entries": [{"build_id": "<from readelf -n>",
     "query_offset": 2612992,
     "anchor": "OSSL_PROVIDER_available",
     "anchor_offset": 2612560}]}
   ```

   Then `osslscope inspect ... --builtin --table my-table.json`.

`--table` also works with `doctor --libcrypto`: the same file
drives both. (`report` needs no `--table` — it observes dispatch
rather than resolving the query offset, so there is nothing to
enroll for it.)
