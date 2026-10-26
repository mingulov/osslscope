<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Observe entries into enrolled OpenSSL implementation callbacks with eBPF
uprobes, without changing application code, libraries or configuration.
Counts stay attached to physical code sites; shared candidates retain their
uncertainty and each entry is counted once.

**Status: v0.2.0 source preview candidate.** The foreground count-only route
has native count, isolation, policy and lifecycle checks on the exact profile
below. This is a bounded inventory tool with material overhead on tight loops;
see [measured limits](docs/overhead-matrix.md). Reports use the
[observed-crypto-v2.3 contract](docs/observed-crypto-v2.md).

## The foreground preview

The initial enrollment is one exact Ubuntu OpenSSL `3.5.5-1ubuntu3.7` amd64
library and kernel `7.0.0-38-generic` build. Admission checks the actual library
SHA-256/build ID, protected file backing, kernel build ID and initial PID
namespace. The [catalogue](profiles/README.md) documents the three callback
sites: definite SHA-256 and AES-256-GCM context creation entries, plus a shared
GCM update with seven possible algorithm meanings. Qualification covers this
exact profile; additional OpenSSL and Linux builds need separate enrollment.

Supported commands are `doctor`, `report`, `check` and offline `alias-audit`.
`report` and `check` launch one owned foreground process and observe its threads.
They require `--libcrypto PATH` and load only the Count object. There are no
target-memory discovery readers in this route.

Captures remain **PARTIAL** because the small catalogue has an unknown global
denominator. Positive definite entries are useful; absence is inconclusive.
Callback entry does not establish message processing, crypto success, key size,
runtime provider activation or FIPS state. Shared counts are not duplicated
across candidate algorithms. CBOM exports contain definite assets only.

Foreign `--pid`, live `inspect`, dynamic provider discovery, reader-object
selection, provider/ENGINE policy rules, services and process following are
deferred. See the [roadmap](ROADMAP.md) for later releases.

## Build and try the development route

Use the pinned Rust/BPF tools and [build recipe](docs/build.md). The existing
build/install tools still prepare three development objects; the preview loads
only `osslscope-count`.

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh --prefix "$HOME/.local"
```

Grant BPF/perf rights using the [installation instructions](docs/install.md).
The app does not change privileges or host settings itself. Then select the
enrolled library and the actual locally built Count object:

```sh
OSSL_PREVIEW_LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
OSSL_PREVIEW_PREFIX="$HOME/.local"

"$OSSL_PREVIEW_PREFIX/bin/osslscope" doctor \
  --libcrypto "$OSSL_PREVIEW_LIBCRYPTO" \
  --count-object "$OSSL_PREVIEW_PREFIX/lib/osslscope/osslscope-count"

"$OSSL_PREVIEW_PREFIX/bin/osslscope" report \
  --libcrypto "$OSSL_PREVIEW_LIBCRYPTO" \
  --count-object "$OSSL_PREVIEW_PREFIX/lib/osslscope/osslscope-count" \
  --duration 5 --format json --out report.json --cbom bom.json \
  run -- openssl dgst -sha256 /dev/null

"$OSSL_PREVIEW_PREFIX/bin/osslscope" check \
  --libcrypto "$OSSL_PREVIEW_LIBCRYPTO" \
  --count-object "$OSSL_PREVIEW_PREFIX/lib/osslscope/osslscope-count" \
  --require-executed SHA256 --duration 5 \
  run -- openssl dgst -sha256 /dev/null
```

A normal report, or a satisfied positive rule with partial coverage, exits **3**.
A definite deny violation exits **10**; an unobserved known algorithm is
inconclusive (**11**). Usage errors exit **2**, setup/environment refusals **4**.
See [usage](docs/usage.md) for failure precedence, policy files and output sinks.
Doctor checks metadata, namespaces, Count compatibility and capability bits;
it explicitly labels runtime permission/attachment as unprobed. Report/check
validate load and attachment before releasing the workload.

Explicit `--count-object` is operator-trusted code. Compatibility checks and a
hash do not authenticate arbitrary BPF or establish its privacy. No-reader and
release claims apply to the exact source-built object actually qualified.
Implicit selection is limited to trusted installed Count locations and retains
the existing install-receipt checks.

A released live workload is left running at observation end. Normal setup and
signal cleanup handle owned resources. A crash/SIGKILL while the child is held
stopped before exec can strand it; this preview does not provide crash-safe
startup custody.

## Documentation

- [Build](docs/build.md) and [install](docs/install.md)
- [CLI and policy files](docs/usage.md)
- [Observation meaning and limits](docs/what-it-proves.md)
- [Catalogue provenance](profiles/README.md)
- [Output contract](docs/observed-crypto-v2.md)
- [Roadmap](ROADMAP.md), [documentation index](docs/README.md)
- [Component licensing](docs/licensing.md)
- [v0.2.0 source release notes](docs/release-v0.2.0.md)

Permanent boundaries: no keys, passwords, plaintext or application payload
capture; no TLS interception or interposition. The broader discovery/package
source and its developer references remain for later releases.

## License

GPL-3.0-or-later for the host, documentation and scripts. BPF/common and
independent contract components have distinct terms; see
[component licensing](docs/licensing.md) and [LICENSES](LICENSES/README.md).
