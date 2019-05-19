%define ver 8.0p1
%define rel 1%{?dist}

Summary: The OpenSSH implementation of SSH protocol version 2.
Name: sshd-passwd-pot
Version: %{ver}
Release: %{rel}
URL: https://www.openssh.com/portable.html
#Source0: https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Group: System Environment/Daemons
Requires: json-c

%{?systemd_requires}

%description
SSH (Secure SHell) is a program for logging into and executinggre
commands on a remote machine. SSH is intended to replace rlogin and
rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing
it up to date in terms of security and features, as well as removing
all patented algorithms to separate libraries.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%prep

%build
cd /root/build 
autoconf -f
autoheader -f
./configure \
 --disable-suid-ssh\
 --without-stackprotect\
 --without-hardening\
 --with-ssl-engine\
 --disable-lastlog\
 --disable-wtmp\
 --without-rsh\
 --with-privsep-user=nobody\
 --prefix=/opt/sshd-passwd-pot\
 --with-audit-passwd-url=yes \
 --with-systemd
make

%install
cd /root/build 
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT/
install -d -m755 $RPM_BUILD_ROOT%{_var}/empty/sshd
install -d -m755 $RPM_BUILD_ROOT/opt/sshd-passwd-pot
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -m644 /root/build/contrib/passwd-pot/sshd_config $RPM_BUILD_ROOT/opt/sshd-passwd-pot/etc/sshd_config
install -m644 /root/build/contrib/passwd-pot/sshd-passwd-pot $RPM_BUILD_ROOT/etc/sysconfig/sshd-passwd-pot
install -m644 /root/build/contrib/passwd-pot/sshd-passwd-pot.service $RPM_BUILD_ROOT/%{_unitdir}/sshd-passwd-pot.service

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %attr(0711,root,root) %{_var}/empty/sshd
%attr(0755,root,root) /opt/sshd-passwd-pot/bin/ssh-keygen
%attr(0755,root,root) /opt/sshd-passwd-pot/sbin/sshd
%attr(0644,root,root) /opt/sshd-passwd-pot/etc/sshd_config
%attr(0644,root,root) /opt/sshd-passwd-pot/etc/moduli
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/sshd-passwd-pot
%attr(0644,root,root) %{_unitdir}/sshd-passwd-pot.service

%post
%systemd_post sshd-passwd-pot.service

%preun
%systemd_preun sshd-passwd-pot.service

%postun
%systemd_postun_with_restart sshd-passwd-pot.service

%changelog
