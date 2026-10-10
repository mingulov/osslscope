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
> built from it is a final distributable; BPF objects are always
> operator-built (see [build](build.md)) and are never shipped in a
> package. For day-to-day development use the local prefix install
> below.

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
this prefix passes explicit `--object`/`--count-object` flags.
Only the same `lib/osslscope/` layout under a root-owned system
dir (`/usr/local/lib{,64}/osslscope`, `/usr/lib{,64}/osslscope`)
resolves without flags:

```text
$PREFIX/bin/osslscope
$PREFIX/lib/osslscope/osslscope-harvest
$PREFIX/lib/osslscope/osslscope-count
$PREFIX/share/doc/osslscope/install.md
$PREFIX/share/osslscope/install-manifest.json
```

The installer reads artifact paths from
`target/dev-build-manifest.json`; pass `--manifest PATH` to use a
different build, or `--binary F --harvest F --count F` to install
explicit operator-built objects. Every object is validated before
copying: the host binary must be an x86-64 ELF executable and the
BPF objects eBPF relocatables — anything else fails closed with a
diagnosis. Installing into `/` or `/usr` is refused: `/usr` is
system package territory.

Grant capabilities once (needs privilege), then verify:

```sh
sudo setcap cap_bpf,cap_perfmon+ep "$HOME/.local/bin/osslscope"
getcap "$HOME/.local/bin/osslscope"   # expect: cap_bpf,cap_perfmon+ep
"$HOME/.local/bin/osslscope" doctor \
  --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count"
# expect: verdict: ok
"$HOME/.local/bin/osslscope" --help   # lists doctor|inspect|report|check|alias-audit
```

`install-dev.sh --setcap` applies the capabilities during install
instead of printing the follow-up; it fails deterministically if
`setcap` is missing or the call is denied (exit 3 with a libcap
install hint when the tool is absent, exit 1 with the labeled-sudo
fallback otherwise).

Diagnostics to know:

- Missing `setcap` (`libcap2-bin` on Debian/Ubuntu, `libcap` on
  Fedora/RHEL) never fails an install or a package transaction;
  every script prints the labeled-sudo fallback and `doctor`
  repeats the remediation.
- `NoNewPrivs=1` in the install report or `NNP=1` in `doctor`
  means processes exec'd from that environment cannot gain file
  capabilities — run the installed binary outside it.
- A stale manifest (artifacts moved or rebuilt elsewhere) fails
  with a rebuild hint; rerun `scripts/build-dev.sh`.

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

Packages never ship BPF objects, so a bare `doctor` reports the
objects rows `FAIL` until the operator stages them: build per
[build](build.md), then either copy both objects into root-owned
`/usr/local/lib/osslscope/` (implicitly trusted) or pass
`--object`/`--count-object` explicitly on every run.

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

## Next steps

- Vet a target before observing: `osslscope doctor --pid PID` (or
  `--libcrypto PATH`).
- `report`/`check` need BPF objects: a user-owned prefix install
  always needs `--object`/`--count-object` pointing at
  `$PREFIX/lib/osslscope/`; packages never ship objects, so build
  per [build](build.md) and either stage them into root-owned
  `/usr/local/lib/osslscope/` (auto-discovered) or pass the flags.

## Uninstall

```sh
sudo dpkg -P osslscope      # deb: purge, removes caps with the binary
sudo dnf remove osslscope   # rpm
rm -rf "$HOME/.local/bin/osslscope" "$HOME/.local/lib/osslscope" \
  "$HOME/.local/share/doc/osslscope" "$HOME/.local/share/osslscope/install-manifest.json"
```

The last line removes a default-prefix local install; adjust paths
for a custom `--prefix`.
