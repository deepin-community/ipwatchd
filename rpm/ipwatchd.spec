Name:              ipwatchd
Version:           1.2.1.6
Release:           1%{?dist}
Summary:           IP conflict detection tool

License:           GPLv2
URL:               http://ipwatchd.sf.net
%if 0%{?fedora}
Source0:           http://sourceforge.net/projects/ipwatchd/files/ipwatchd/%{version}/ipwatchd-%{version}.tar.gz
%else
Source0:           %{name}-%{version}.orig.tar.xz
%endif

BuildRequires:     gcc, libpcap-devel, libnet-devel, systemd
BuildRequires:     make
BuildRequires:     pkgconfig(dbus-1)
BuildRequires:     pkgconfig(polkit-gobject-1)
BuildRequires:     pkgconfig(json-c)

Requires(post):    systemd
Requires(preun):   systemd
Requires(postun):  systemd

%description
IPwatchD is a simple daemon that analyses all incoming ARP packets in order 
to detect IP conflicts on Linux. It can be configured to listen on one or 
more interfaces (alias interfaces are also supported) in active or passive 
mode. In active mode IPwatchD protects your host before IP takeover by 
answering Gratuitous ARP requests received from conflicting system. 
In passive mode it just records information about conflict through standard 
syslog interface.

%prep
%setup -q

%build
make -C src %{?_smp_mflags} CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags}"

%install
make -C src install DESTDIR=%{buildroot}

%files
%config(noreplace) %{_sysconfdir}/ipwatchd.conf
%{_sysconfdir}/init.d/ipwatchd
%{_sbindir}/ipwatchd
%{_sbindir}/ipwatchd-script
%{_mandir}/man8/ipwatchd.8*
%{_mandir}/man5/ipwatchd.conf.5*
%{_mandir}/man1/ipwatchd-script.1*
%{_datadir}/dbus-1/system-services/
%{_datadir}/dbus-1/system.d/
%{_datadir}/polkit-1/actions/
%doc LICENSE

%changelog
* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.2.1-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.2.1-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.2.1-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.2.1-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Wed Oct 09 2013 Jaroslav Imrich <jariq@jariq.sk> 1.2.1-3
- Passing optflags to compiler during build
- Added LICENSE to the files section
- Other minor spec improvements

* Wed Oct 09 2013 Jaroslav Imrich <jariq@jariq.sk> 1.2.1-2
- Removed Group tag as it is no longer required
- Using version macro in URL tag
- Requires systemd instead of systemd-units
- Changed systemd service type to forking (ipwatchd-systemd.patch)

* Sun Jul 31 2011 Jaroslav Imrich <jariq@jariq.sk> 1.2.1-1
- Initial release
