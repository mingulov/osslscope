# SPDX-License-Identifier: GPL-3.0-or-later
%{!?pkg_version: %{error:pass --define "pkg_version <ver>" (read from Cargo.toml, see packaging/README.md)}}

# Prebuilt cargo binary: no debuginfo/debugsource subpackages.
%global debug_package %{nil}

Name:           osslscope
Version:        %{pkg_version}
# pkg_release is 1 unless overridden for upgrade-path testing
# (build old=1, new=2 from different refs; see packaging/README.md).
Release:        %{?pkg_release}%{!?pkg_release:1}%{?dist}
Summary:        Non-interposing OpenSSL observer on eBPF uprobes
License:        GPL-3.0-or-later
Packager:       Denis Mingulov <denis@mingulov.com>
Source0:        %{name}-%{pkg_version}.tar.gz
Requires:       libcap
BuildArch:      x86_64

%description
Prove which OpenSSL crypto implementations actually execute in a
running Linux application, without changing the application.
The %%post script grants CAP_BPF+CAP_PERFMON file capabilities so that
the tool runs unprivileged.

%prep
%setup -q -n %{name}-%{pkg_version}

%build
# Binary is prebuilt by cargo (see packaging/README.md); nothing to compile.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/doc/%{name}
install -m0755 osslscope %{buildroot}/usr/bin/osslscope
install -m0644 install.md %{buildroot}/usr/share/doc/%{name}/install.md

%post
if command -v setcap >/dev/null 2>&1; then
  if setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope 2>/dev/null; then
    :
  else
    echo "osslscope: setcap failed; fallback (labeled sudo): run 'sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope' then 'osslscope doctor'." >&2
  fi
else
  echo "osslscope: setcap not found (install libcap); fallback (labeled sudo): run 'sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope' then 'osslscope doctor'." >&2
fi
exit 0

%preun
# Erase-only cleanup ($1 == 0): caps live on the binary inode and vanish
# with the file; clear best-effort anyway. On upgrade ($1 >= 1) do nothing:
# rpm runs old %preun AFTER new %post, so clearing here would strip the
# new binary's freshly applied caps. Never fail the transaction.
if [ "$1" -eq 0 ]; then
  if command -v setcap >/dev/null 2>&1; then
    setcap -r /usr/bin/osslscope 2>/dev/null || true
  fi
fi
exit 0

%posttrans
# Final-transaction capability restoration. Upgrading FROM the 1.0.0 package
# still runs that package's UNGUARDED old %preun after our %post, stripping
# the new binary's caps; guarding our own %preun cannot prevent the old
# script from running. %posttrans runs at the end of the transaction (after
# old %preun) on install and upgrade, so re-apply caps idempotently here.
# $1 (1 install / 2 upgrade) is intentionally ignored: always restore.
# OSSLSCOPE_BIN overrides the path only for host simulation tests;
# packaging always uses the default.
BIN="${OSSLSCOPE_BIN:-/usr/bin/osslscope}"
if [ -f "$BIN" ]; then
  if command -v setcap >/dev/null 2>&1; then
    if setcap cap_bpf,cap_perfmon+ep "$BIN" 2>/dev/null; then
      :
    else
      echo "osslscope: setcap failed; fallback (labeled sudo): run 'sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope' then 'osslscope doctor'." >&2
    fi
  else
    echo "osslscope: setcap not found (install libcap); fallback (labeled sudo): run 'sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope' then 'osslscope doctor'." >&2
  fi
fi
exit 0

%files
/usr/bin/osslscope
%dir /usr/share/doc/%{name}
/usr/share/doc/%{name}/install.md

%changelog
* Sat Sep 19 2026 Denis Mingulov <denis@mingulov.com> - 1.0.0-1
- 1.0.0 release: GPL-3.0-or-later, deb/rpm file-caps install.
