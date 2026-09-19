# SPDX-License-Identifier: GPL-3.0-or-later
%{!?pkg_version: %{error:pass --define "pkg_version <ver>" (read from Cargo.toml, see packaging/README.md)}}

# Prebuilt cargo binary: no debuginfo/debugsource subpackages.
%global debug_package %{nil}

Name:           osslscope
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Non-interposing OpenSSL observer on eBPF uprobes
License:        GPL-3.0-or-later
Source0:        %{name}-%{pkg_version}.tar.gz
Requires:       libcap
BuildArch:      x86_64

%description
Prove which OpenSSL crypto implementations actually execute in a
running Linux application, without changing the application.
The %%post script grants CAP_BPF+CAP_PERFMON file capabilities so that
doctor, inspect, report, and check run unprivileged.

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
# Caps live on the binary inode and vanish with the file; clear
# best-effort anyway. Never fail uninstall.
if command -v setcap >/dev/null 2>&1; then
  setcap -r /usr/bin/osslscope 2>/dev/null || true
fi
exit 0

%files
/usr/bin/osslscope
%dir /usr/share/doc/%{name}
/usr/share/doc/%{name}/install.md
