Name:           scandump
Version:        2.3.0
Release:        1%{?dist}
Summary:        Wi-Fi scanner that writes nl80211 scan results in PCAP format

License:        GPL-3.0-only
URL:            https://github.com/intuitibits/scandump
Source:         %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig(libnl-genl-3.0)
BuildRequires:  pkgconfig(libpcap)

%description
scandump triggers a Wi-Fi scan through the Linux 802.11 netlink API
(nl80211) and writes every network found as a synthetic radiotap and
802.11 beacon frame to a PCAP file or to standard output.

This lets scripts and tools consume scan results with any PCAP reader,
such as tcpdump or Wireshark, instead of parsing the text output of iw,
and works with wireless interfaces that do not support monitor mode.

Triggering a scan requires root or the CAP_NET_ADMIN capability. The
package does not grant either; see the README for setup options.


%prep
%autosetup


%build
%set_build_flags
%make_build WERROR=


%install
%make_install PREFIX=%{_prefix} BINDIR=%{_bindir} MANDIR=%{_mandir}


%check
%set_build_flags
%make_build check WERROR=
./scandump --version | grep -qx "scandump version %{version}"


%files
%license LICENSE
%doc README.md CHANGELOG.md examples/sudoers
%{_bindir}/scandump
%{_mandir}/man8/scandump.8*


%changelog
* Tue Oct 20 2026 Adrian Granados <support@intuitibits.com> - 2.3.0-1
- Initial package
