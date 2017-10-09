%define logdir %{_var}/log/%{name}

Summary: Event logger for Linux netfilter conntrack
Name: ctrecorder
Version: 0.1.3
Release: 2%{?dist}
License: GNU
Group: System Environment/Daemons
URL: http://software.klolik.org/ctrecorder/
Source0: http://software.klolik.org/files/ctrecorder-%{version}.tar.gz
Source1: ctrecorder.init.d
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# The svn sources needs autoconf, automake and libtool to generate a suitable
# configure script. Release tarballs would not need this
#BuildRequires: automake autoconf libtool
BuildRequires: libnetfilter_conntrack-devel
Packager: Nuno Fernandes <npf@eurotux.com>

%description
ctrecorder uses nf_conntrack_netlink module to receive and then save netfilter events, that is adding and destroying conntrack entries.
This means saving start and end time of connection for specific protocol. Currently TCP and UDP are supported.
Main application of ctrecorder is connections logging for security and anti-abuse reasons.

Logs are especially useful for NAT-ed connection, as they contain both pre-NAT and post-NAT IPs and ports.
Be aware, that using NOTRACK in raw table will effectively hide packets from conntrack and ctrecorder.

%prep
%setup -q

%build
%configure
%{__make} %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_sysconfdir}/init.d/
install -m755 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/init.d/ctrecorder
mkdir -p %{buildroot}%{logdir}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sbindir}/*
%{_mandir}/man5/*.5*
%{_mandir}/man8/*.8*
%{_mandir}/manh/*
%{_sysconfdir}/init.d/ctrecorder
%dir %{logdir}

%changelog
* Tue Feb 22 2011 Nuno Fernandes <npf@eurotux.com> - 0.1.3-2
- Init script

* Mon Feb 21 2011 Nuno Fernandes <npf@eurotux.com> - 0.1.3-1
- First Build
