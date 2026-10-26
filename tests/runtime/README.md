<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Finite foreground workload

`preview_workload.c` exercises the installed app's small SHA-256/AES-GCM
catalogue. It is a workload, not an observer or a runtime qualification runner.
Build it against the enrolled system OpenSSL headers/library:

```sh
mkdir -p target
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  tests/runtime/preview_workload.c -lcrypto -o target/preview-workload
OSSL_PREVIEW_WORKLOAD="$(realpath target/preview-workload)"
"$OSSL_PREVIEW_WORKLOAD" both
```

The optional iteration count defaults to 32 and accepts 1 through 100000.
SHA-256 checks the known digest of the public input `abc`. AES-GCM uses fresh
ephemeral key/IV bytes from the OS, one data update, and authenticated decryption
in a separate child to verify plaintext/tag success. Raw cryptographic values
are never printed or written to files. Only success/failure and public operation
totals are printed. Every required EVP return value is checked.

For N iterations, the predicted **original thread-group** physical entry totals
are:

| Mode | SHA-256 NEWCTX | AES-256-GCM NEWCTX | Shared GCM UPDATE |
| --- | ---: | ---: | ---: |
| `sha` | N | 0 | 0 |
| `aes` | 0 | N | N |
| `both`, `worker`, `mixed-fork` | N | N | N |
| `forked`, `quiet` | 0 | 0 | 0 |
| `exec` | N | 0 | 0 |

The stock default provider is selected explicitly by the fixture's fetch
property. A fresh EVP context causes one enrolled NEWCTX entry; each AES loop
has exactly one stream UPDATE. Fetch, init/update/final/free helpers add no
other enrolled calls in the matching source. These are source-derived
expectations, not measured runtime passes. See the [catalogue](../../profiles/README.md).

`worker` moves the two loops into one joined worker. AES verification starts
after the worker joins; its decryption callbacks belong to a separate thread
group and must contribute zero to target totals. This also applies to `aes`,
`both` and `mixed-fork`. `forked` runs both loops only in a child while the
original group waits. `mixed-fork` runs both loops in the original group and
another child, within the same observation window. Both verify child success.

`exec` replaces the leader with the same workload's `sha` mode. `worker-exec`
does that from a worker; the preview documents possible coverage loss at
nonleader exec, so this mode has no promised positive-count total. Use an
absolute workload path for these exec controls. `quiet` performs no EVP work
and sleeps for two seconds, also providing a bounded signal/deadline control.

Run the installed app using its documented [usage](../../docs/usage.md), for
example `report ... run -- "$OSSL_PREVIEW_WORKLOAD" both`. An observer needs
authorized BPF/perf privileges; the workload alone does not. A valid workload
exit does not establish observer counts, process isolation, cleanup or release
qualification. The shared UPDATE's N calls remain N total across all candidates.
