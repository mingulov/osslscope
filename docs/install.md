<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install the source-built foreground preview

The v0.2.0 source preview uses a source build and local-prefix installation.
Native installed checks cover the [advertised profile](release-v0.2.0.md):
Ubuntu OpenSSL `3.5.5-1ubuntu3.7` amd64 and one exact `7.0.0-38-generic` kernel
build, with protected file backing and the initial PID namespace. See the
[catalogue](../profiles/README.md). A general kernel/OpenSSL version match is
insufficient; mismatches refuse before releasing a workload.

## Build and install

Follow [build](build.md), then install the resulting development manifest:

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh --prefix "$HOME/.local"
```

The existing installer prepares the host and development objects under
`bin/osslscope` and `lib/osslscope/`, and writes
`share/osslscope/install-manifest.json`. It can still install harvest/members
for later developer work; the foreground preview resolves and loads only
`osslscope-count`. It rejects those reader-role CLI overrides.

Manifest-selected files are staged and checked against their recorded hashes
and lengths before publication. The install receipt publishes atomically.
A failure during destination replacement can leave a partial install; rerun
installation rather than treating it as qualified. Explicit installer overrides
remain operator-built inputs and do not inherit source/release qualification.

## Privileges and preflight

The operator must provide BPF/perf privileges. One possible one-time setup,
where filesystem and local policy permit file capabilities, is:

```sh
sudo setcap 'cap_bpf,cap_perfmon=ep' "$HOME/.local/bin/osslscope"
getcap "$HOME/.local/bin/osslscope"
```

The app grants no capabilities and changes no host settings. Replacing the
binary may require repeating the capability setup. LSM, seccomp, lockdown and
capability namespace policy can still deny runtime operations.

A user-owned prefix is never searched implicitly. Select its actual Count file:

```sh
"$HOME/.local/bin/osslscope" doctor \
  --libcrypto /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count"
```

Doctor validates metadata, namespaces, Count compatibility and capability bits.
It labels actual BPF load/attach permission as unprobed; `verdict: ok` is a
preflight result, not installed runtime qualification. Report/check validate
load and all enrolled attachments before releasing their stopped child.

Implicit Count selection is limited to protected installed locations:
`/usr/local/lib/osslscope`, `/usr/local/lib64/osslscope`, `/usr/lib/osslscope`,
`/usr/lib64/osslscope`. Existing receipt checks apply when a receipt is present.
This keeps legacy receiptless Count compatibility; it is not a matched-builder
identity claim. An explicit `--count-object` is operator-trusted code; its ABI
and digest do not authenticate an arbitrary program or establish its privacy.

## Verify the workflow

Use the [README example](../README.md#build-and-try-the-development-route) or
[usage](usage.md). A normal partial report exits 3; a positive require can also
exit 3. A known unobserved algorithm is inconclusive (11), not an absence pass.
The report, JSON and CBOM retain the same profile gap and Count fingerprint.
Read the [measured limits](overhead-matrix.md) before using tight loops or
applying broader performance expectations.

## Deferred distribution

DEB/RPM, advanced matched builders and the broader install lifecycle remain
future tracks in the [roadmap](../ROADMAP.md). Their source/tooling references
under `packaging/` are not the supported v0.2 distribution workflow.
