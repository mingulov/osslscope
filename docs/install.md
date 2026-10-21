<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install

`osslscope` proves which OpenSSL crypto implementations actually
execute in a running Linux application — without changing the
application. Install the package or a local prefix build, then start
with `doctor`: it preflights the environment (kernel, caps, LSM,
lockdown) and prints `verdict: ok` when the machine can observe, or
`verdict: FAIL-CLOSED` with a remediation when it cannot.

Prerequisites: Linux x86-64, kernel >= 6.9.

> Development status: this branch is unreleased work. No deb/rpm
> built from it is a final distributable. Current builders omit BPF;
> build and install matching development roles per [build](build.md).
> Matched redistributable host+BPF packages remain forthcoming,
> subject to licensing, provenance and exact-package qualification.
> For day-to-day development use the local prefix install below.

## Local prefix install (development)

Build once per [build](build.md), then install into a user-owned
prefix (default `$HOME/.local`):

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh --prefix "$HOME/.local"
```

The prefix layout mirrors the system layout that automatic
object discovery trusts — but a user-owned prefix is never
trusted implicitly, so every `doctor`/`report`/`check` run from
this prefix passes explicit `--object`/`--count-object` flags
(`--members-object` for the traversal object, when installed).
Only the same `lib/osslscope/` layout under a root-owned system
dir (`/usr/local/lib{,64}/osslscope`, `/usr/lib{,64}/osslscope`)
resolves without flags:

```text
$PREFIX/bin/osslscope
$PREFIX/lib/osslscope/osslscope-harvest
$PREFIX/lib/osslscope/osslscope-count
$PREFIX/lib/osslscope/osslscope-members   # traversal runs only; pair-only installs stay valid
$PREFIX/share/doc/osslscope/install.md
$PREFIX/share/osslscope/install-manifest.json
```

The installer reads artifact paths from
`target/dev-build-manifest.json`; pass `--manifest PATH` to use a
different build, or `--binary F --harvest F --count F` to install
explicit operator-built objects (`--members F` adds an explicit
traversal object — without it the members object installs only
when the build manifest lists it). The build manifest is read once per
run — revision metadata, hashes, and lengths all come from that single
snapshot, and staged bytes are re-verified against it before the
receipt publishes. The complete artifact set is staged
and validated before anything in the prefix is replaced, so a validation
failure leaves an existing install byte-identical. Once replacement
begins, a failure (I/O error, `chmod`, receipt write) stops the install
and may leave a partially updated prefix; rerun the install to complete
it. The receipt itself publishes atomically (fresh per-run temp file +
rename), so a failed install never leaves a truncated receipt; each
destination likewise installs through a fresh temporary file, and a
leftover `<file>.install-tmp` path refuses the install (remove it and
re-run) instead of being reused. Manifest-selected
artifacts must match the recorded `sha256` and byte length — a stale
manifest or modified bytes fail closed with a rebuild hint. Every
object is also screened before copying: the host binary must be an
x86-64 ELF executable and the BPF objects ELF64 little-endian EM_BPF
relocatables; anything else fails closed with a diagnosis. Whether an
object is usable for its role stays a loader/`doctor` decision, not the
installer's. Explicit overrides are screened the same way but never
hash-checked against the manifest. Installing into `/` or `/usr` is
refused: `/usr` is system package territory.

`share/osslscope/install-manifest.json` is the install receipt: per
artifact it records the installed `sha256`/byte length plus how the
artifact was selected — `manifest-verified` (bytes matched the build
manifest, whose revision the entry keeps) or `explicit-override` (an
operator-built object with no recorded revision, so its revision stays
unknown rather than asserting the manifest's). The receipt's top-level
revision is set only when every artifact is `manifest-verified`;
any override leaves it unknown.

Grant capabilities once (needs privilege), then verify:

```sh
sudo setcap cap_bpf,cap_perfmon+ep "$HOME/.local/bin/osslscope"
getcap "$HOME/.local/bin/osslscope"   # expect: cap_bpf,cap_perfmon+ep
"$HOME/.local/bin/osslscope" doctor \
  --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count" \
  --members-object "$HOME/.local/lib/osslscope/osslscope-members"
# expect: verdict: ok (the objects-members row reports pass)
# On a pair-only install, omit --members-object entirely (passing
# an explicit path to a missing object fails the row instead):
"$HOME/.local/bin/osslscope" doctor \
  --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count"
# expect: verdict: ok; the objects-members row reports info —
# traversal unavailable, the harvest/count pair unaffected
"$HOME/.local/bin/osslscope" --help   # lists doctor|inspect|report|check|alias-audit
```

`install-dev.sh --setcap` applies the capabilities during install
instead of printing the follow-up; it fails deterministically if
`setcap` is missing or the call is denied (exit 3 with a libcap
install hint when the tool is absent, exit 1 with the labeled-sudo
fallback otherwise).

Diagnostics to know:

- Missing `setcap` (`libcap2-bin` on Debian/Ubuntu, `libcap` on
  Fedora/RHEL) never fails a default install or a package
  transaction; every script prints the labeled-sudo fallback
  and `doctor` repeats the remediation. Explicit
  `install-dev.sh --setcap` is the exception: it exits 3 with
  a libcap install hint when the tool is absent.
- `NoNewPrivs=1` in the install report or `NNP=1` in `doctor`
  means processes exec'd from that environment cannot gain file
  capabilities — run the installed binary outside it.
- A stale manifest (artifacts moved, rebuilt, or modified after the
  build so the recorded hashes no longer match) fails with a rebuild
  hint; rerun `scripts/build-dev.sh`.

## Debian/Ubuntu (.deb)

```sh
sudo dpkg -i osslscope_<ver>-1_amd64.deb
# if Depends are missing: sudo apt-get install -f
```

## Fedora/RHEL (.rpm)

```sh
sudo dnf install ./osslscope-<ver>-1.*.x86_64.rpm
```

Both packages install `/usr/bin/osslscope` plus this file at
`/usr/share/doc/osslscope/install.md`, and grant the binary
`CAP_BPF`+`CAP_PERFMON` file capabilities at install time so it runs
unprivileged. Upgrading keeps the capabilities: the rpm restores
them at the end of the transaction even when upgrading from a
package whose old cleanup script predates the fix (see
[packaging](../packaging/README.md)).

## Verify (doctor-first)

```sh
getcap /usr/bin/osslscope   # expect: cap_perfmon,cap_bpf=ep
osslscope doctor            # expect: verdict: ok once objects are staged (below)
osslscope --help            # lists doctor|inspect|report|check|alias-audit
```

Current packages omit BPF objects, so a bare `doctor` reports the
objects rows `FAIL` until compatible objects are available. Build
the matching roles per [build](build.md), then pass explicit
`--object`/`--count-object`/`--members-object` paths on both
preflight and capture, as in the local-prefix recipe. For automatic
traversal use `scripts/install-dev.sh` into a trusted system prefix
with its matching receipt. Copying three loose files into
`/usr/local/lib/osslscope/` does not establish that receipt.
A deliberate pair-only harvest/count install remains supported;
it supplies no traversal. See the selection rules below.

If the caps are missing (e.g. the cap hook warned at install),
re-apply them and re-run doctor:

```sh
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope
osslscope doctor
```

`doctor` is fail-closed by design: any environment it cannot verify
ends in `verdict: FAIL-CLOSED` with a `remediate:` line, never a
silent partial run. An unprivileged `doctor` on a fresh install
reports `FAIL-CLOSED` and names the `setcap` remediation above;
granting caps plus staged objects flips it to `verdict: ok` on a
capable machine.

The capability set is complete at `cap_bpf,cap_perfmon`: `run --`
needs no `cap_sys_ptrace` for owned targets, because each spawned
child opts itself dumpable pre-exec (see the `spawn-access` row in
`doctor`, which replicates that setup read and predicts success).
Only foreign non-dumpable `--pid` targets (setuid/filecaps
binaries) need `CAP_SYS_PTRACE` in the observer, and `doctor --pid`
says so explicitly for that target.

## Next steps

- Vet a target before observing: `osslscope doctor --pid PID` (or
  `--libcrypto PATH`).
- `report`/`check` need BPF objects: a user-owned prefix install
  needs explicit role paths into `$PREFIX/lib/osslscope/`, including
  `--members-object` for the triple. Current packages omit objects;
  build per [build](build.md). Reuse the selected objects for
  doctor and capture; implicit traversal requires a verified receipt.

## Uninstall

```sh
sudo dpkg -P osslscope      # deb: purge, removes caps with the binary
sudo dnf remove osslscope   # rpm
rm -rf "$HOME/.local/bin/osslscope" "$HOME/.local/lib/osslscope" \
  "$HOME/.local/share/doc/osslscope" "$HOME/.local/share/osslscope/install-manifest.json"
```

The last line removes a default-prefix local install; adjust paths
for a custom `--prefix`.

## Object roles and selection

Members is the third installed/loadable BPF role, alongside harvest
and count (`scripts/build-dev.sh`, `src/discovery/onboard.rs`).
Local integration does not mean current packages distribute it:

- explicit `--members-object` demands the triple and requires a
  resolved builtin query anchor. Explicit roles are operator-trusted.
  The implicit members role needs a matching receipt; legacy implicit
  harvest/count roles may be receiptless. When a receipt is present,
  implicit roles are verified against it and stale/mismatched entries
  refuse. Explicit members with a receiptless implicit harvest/count
  pair is supported without receipt-backed matching provenance;
- ordinary runs traverse when the triple resolves complete,
  the target is builtin-mode and a dispatch anchor is resolved;
  pair-only installs stay harvest-only. Automatic triple selection
  without an anchor (including file-provider mode) also stays
  harvest-only; an explicit traversal request refuses instead;
- trusted-directory selection searches for a complete triple
  before falling back to a pair. Pair fallback requires members
  to be absent everywhere in the trusted search; a found broken
  triple (receiptless/stale/mixed) refuses;
- provenance hashes loaded bytes; `selected_objects` also records
  pair-only selection, while `traversal` describes runs using members.

All-explicit triples are supported operator overrides. They bypass
receipt verification for those roles; the operator must select
matching bytes. See `tests/onboarding.rs` for selection/refusal
controls and [usage](usage.md#doctor--environment-diagnosis).
