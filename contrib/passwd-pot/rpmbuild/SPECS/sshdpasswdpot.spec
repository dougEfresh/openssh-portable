%define ver 8.0p1
%define rel 1%{?dist}

# OpenSSH privilege separation requires a user & group ID
%define sshd_uid    74
%define sshd_gid    74

Summary: The OpenSSH implementation of SSH protocol version 2.
Name: ssh-passwd-pot
Version: %{ver}
Release: %{rel}
URL: https://www.openssh.com/portable.html
#Source0: https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Group: System Environment/Daemons

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

#%triggerun server -- ssh-server
#if [ "$1" != 0 -a -r /var/run/sshd.pid ] ; then
#	touch /var/run/sshd.restart
#fi

#%triggerun server -- openssh-server < 2.5.0p1
# Count the number of HostKey and HostDsaKey statements we have.
#gawk	'BEGIN {IGNORECASE=1}
#	 /^hostkey/ || /^hostdsakey/ {sawhostkey = sawhostkey + 1}
#	 END {exit sawhostkey}' /etc/ssh/sshd_config
# And if we only found one, we know the client was relying on the old default
# behavior, which loaded the the SSH2 DSA host key when HostDsaKey wasn't
# specified.  Now that HostKey is used for both SSH1 and SSH2 keys, specifying
# one nullifies the default, which would have loaded both.
#if [ $? -eq 1 ] ; then
#	echo HostKey /etc/ssh/ssh_host_rsa_key >> /etc/ssh/sshd_config
#	echo HostKey /etc/ssh/ssh_host_dsa_key >> /etc/ssh/sshd_config
#fi

#%triggerpostun server -- ssh-server
#if [ "$1" != 0 ] ; then
#	/sbin/chkconfig --add sshd
#	if test -f /var/run/sshd.restart ; then
#		rm -f /var/run/sshd.restart
#		/sbin/service sshd start > /dev/null 2>&1 || :
#	fi
#fi

#%pre server
#%{_sbindir}/groupadd -r -g %{sshd_gid} sshd 2>/dev/null || :
#%{_sbindir}/useradd -d /var/empty/sshd -s /bin/false -u %{sshd_uid} \
#	-g sshd -M -r sshd 2>/dev/null || :

#%post
#

#%postun
#/usr/bin/systemctl daemon-reload && /usr/bin/systemctl start sshd-passwd-pot
#/sbin/service sshd condrestart > /dev/null 2>&1 || :

#%preun server
#if [ "$1" = 0 ]
#then
#	/sbin/service sshd stop > /dev/null 2>&1 || :
#	/sbin/chkconfig --del sshd
#fi

%files
%defattr(-,root,root,-)
%dir %attr(0711,root,root) %{_var}/empty/sshd
%attr(0755,root,root) /opt/sshd-passwd-pot/bin/ssh-keygen
%attr(0755,root,root) /opt/sshd-passwd-pot/sbin/sshd
%attr(0644,root,root) /opt/sshd-passwd-pot/etc/sshd_config
%attr(0644,root,root) /opt/sshd-passwd-pot/etc/moduli
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/sshd-passwd-pot
%attr(0644,root,root) %{_unitdir}/sshd-passwd-pot.service

%changelog
