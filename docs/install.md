# Install

`osslscope` proves which OpenSSL crypto implementations actually
execute in a running Linux application — without changing the
application. Install the package, then start with `doctor`: it
preflights the environment (kernel, caps, LSM, lockdown) and prints
`verdict: ok` when the machine can observe, or `verdict:
FAIL-CLOSED` with a remediation when it cannot.

Prerequisites: Linux x86-64, kernel >= 6.9.

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
unprivileged.

## Verify (doctor-first)

```sh
getcap /usr/bin/osslscope   # expect: cap_bpf,cap_perfmon+ep
osslscope doctor            # expect: verdict: ok
osslscope --help            # lists doctor|inspect|report|check|alias-audit
```

If the caps are missing (e.g. the cap hook warned at install),
re-apply them and re-run doctor:

```sh
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope
osslscope doctor
```

`doctor` is fail-closed by design: any environment it cannot verify
ends in `verdict: FAIL-CLOSED` with a `remediate:` line, never a
silent partial run.

## Next steps

- Vet a target before observing: `osslscope doctor --pid PID` (or
  `--libcrypto PATH`).
- `report`/`check` need operator-built BPF objects, which are
  intentionally not in the package (build with nightly per the
  project README, then pass `--object` and `--count-object`).

## Uninstall

```sh
sudo dpkg -P osslscope      # deb: purge, removes caps with the binary
sudo dnf remove osslscope   # rpm
```
