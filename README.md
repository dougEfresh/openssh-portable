# OpenSSH Honey pot

Patched OpenSSH that logs passwords or sends them to a REST api

[![Build Status][ci-img]][ci]


## Quick Start

```shell
$ docker run -t -i -p 2222:2222 dougefresh/sshd-passwd-pot sshd -d
$ ssh -l hacker -p 2222 localhost
```


```shell
{ "time": 1522258349538, "user": "hacker", "passwd": "password", "remoteAddr": "172.17.0.1", "remotePort": 52708, "remoteName": "172.17.0.1", "remoteVersion": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4", "application": "OpenSSH_7.7p1", "protocol": "ssh" }
Could not get shadow information for NOUSER
Failed password for invalid user hacker from 172.17.0.1 port 52708 ssh2
debug1: userauth-request for user hacker service ssh-connection method password [preauth]
debug1: attempt 5 failures 4 [preauth]
{ "time": 1522258351748, "user": "hacker", "passwd": "hacker", "remoteAddr": "172.17.0.1", "remotePort": 52708, "remoteName": "172.17.0.1", "remoteVersion": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4", "application": "OpenSSH_7.7p1", "protocol": "ssh" }
Failed password for invalid user hacker from 172.17.0.1 port 52708 ssh2
debug1: userauth-request for user hacker service ssh-connection method password [preauth]
debug1: attempt 6 failures 5 [preauth]
{ "time": 1522258356303, "user": "hacker", "passwd": "password1", "remoteAddr": "172.17.0.1", "remotePort": 52708, "remoteName": "172.17.0.1", "remoteVersion": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4", "application": "OpenSSH_7.7p1", "protocol": "ssh" }
```


## Building from source

```
$ ./docker-build.sh
$ docker build . -t sshd-passwdpot
```


## Environment Variables

`SSHD_OPTS`

You can pass any valid OpenSSH [options](https://man.openbsd.org/sshd)

```shell
docker run  -e SSHD_OPTS="-o Audit=no" -t -i -p 2222:2222 dougefresh/sshd-passwd-pot
```

`RSYSLOG_SERVER`

The container is running rsyslogd and will forward messages to `172.17.0.1` by default

You can enable your host's rsyslog to accept messages with 

```
module(load="imtcp")
input(type="imtcp" port="514" address="172.17.0.1")'
``` 

```shell
echo -e 'module(load="imtcp")\ninput(type="imtcp" port="514" address="172.17.0.1")' > /etc/rsyslog.d/99_listen.conf
```


## Default config

```
AddressFamily any
AllowAgentForwarding no
AllowTcpForwarding no
Audit yes
AuthorizedKeysFile	.ssh/authorized_keys
ListenAddress 0.0.0.0
LogLevel INFO
MaxAuthTries 50
MaxSessions 0
PermitEmptyPasswords no
PermitRootLogin no
PermitTTY no
PermitUserEnvironment no
Port 2222
PrintMotd no
StrictModes no
SyslogFacility local7
TCPKeepAlive no
UseDNS yes
X11Forwarding no
X11UseLocalhost no
```

### Custom config

Audit yes will log username/password to  syslog

```
Audit [yes|no]
```

AuditUrl will POST json to url

```
AuditUrl http://localhost
```

AuditSocket will POST json to this socket file. AuditUrl must be specified

```
AuditSocket /var/run/passwd.socket
```

## Examples
    
* http://github.com/dougEfresh/passwd-pot


## Contributing
 All PRs are welcome


## Authors

* **Douglas Chimento**  - [dougEfresh](https://github.com/dougEfresh)


[ci-img]: https://travis-ci.org/dougEfresh/sshd-passwd-pot.svg?branch=master
[ci]: https://travis-ci.org/dougEfresh/sshd-passwd-pot

# Portable OpenSSH

[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/openssh.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:openssh)

OpenSSH is a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client ``ssh`` and server ``sshd``, file transfer utilities ``scp`` and ``sftp`` as well as tools for key generation (``ssh-keygen``), run-time key storage (``ssh-agent``) and a number of supporting programs.

This is a port of OpenBSD's [OpenSSH](https://openssh.com) to most Unix-like operating systems, including Linux, OS X and Cygwin. Portable OpenSSH polyfills OpenBSD APIs that are not available elsewhere, adds sshd sandboxing for more operating systems and includes support for OS-native authentication and auditing (e.g. using PAM).

## Documentation

The official documentation for OpenSSH are the man pages for each tool:

* [ssh(1)](https://man.openbsd.org/ssh.1)
* [sshd(8)](https://man.openbsd.org/sshd.8)
* [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [scp(1)](https://man.openbsd.org/scp.1)
* [sftp(1)](https://man.openbsd.org/sftp.1)
* [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Stable Releases

Stable release tarballs are available from a number of [download mirrors](https://www.openssh.com/portable.html#downloads). We recommend the use of a stable release for most users. Please read the [release notes](https://www.openssh.com/releasenotes.html) for details of recent changes and potential incompatibilities.

## Building Portable OpenSSH

### Dependencies

Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers, and [zlib](https://www.zlib.net/). ``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used, but OpenSSH may be built without it supporting a subset of crypto algorithms.

FIDO security token support need [libfido2](https://github.com/Yubico/libfido2) and its dependencies. Also, certain platforms and build-time options may require additional dependencies, see README.platform for details.

### Building a release

Releases include a pre-built copy of the ``configure`` script and may be built using:

```
tar zxvf openssh-X.YpZ.tar.gz
cd openssh
./configure # [options]
make && make tests
```

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.
 
### Building from git

If building from git, you'll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the ``configure`` script. The following commands will check out and build portable OpenSSH from git:

```
git clone https://github.com/openssh/openssh-portable # or https://anongit.mindrot.org/openssh.git
cd openssh-portable
autoreconf
./configure
make && make tests
```

### Build-time Customisation

There are many build-time customisation options available. All Autoconf destination path flags (e.g. ``--prefix``) are supported (and are usually required if you want to install OpenSSH).

For a full list of available flags, run ``configure --help`` but a few of the more frequently-used ones are described below. Some of these flags will require additional libraries and/or headers be installed.

Flag | Meaning
--- | ---
``--with-pam`` | Enable [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) support. [OpenPAM](https://www.openpam.org/), [Linux PAM](http://www.linux-pam.org/) and Solaris PAM are supported.
``--with-libedit`` | Enable [libedit](https://www.thrysoee.dk/editline/) support for sftp.
``--with-kerberos5`` | Enable Kerberos/GSSAPI support. Both [Heimdal](https://www.h5l.org/) and [MIT](https://web.mit.edu/kerberos/) Kerberos implementations are supported.
``--with-selinux`` | Enable [SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) support.
``--with-security-key-builtin`` | Include built-in support for U2F/FIDO2 security keys. This requires [libfido2](https://github.com/Yubico/libfido2) be installed.

## Development

Portable OpenSSH development is discussed on the [openssh-unix-dev mailing list](https://lists.mindrot.org/mailman/listinfo/openssh-unix-dev) ([archive mirror](https://marc.info/?l=openssh-unix-dev)). Bugs and feature requests are tracked on our [Bugzilla](https://bugzilla.mindrot.org/).

## Reporting bugs

_Non-security_ bugs may be reported to the developers via [Bugzilla](https://bugzilla.mindrot.org/) or via the mailing list above. Security bugs should be reported to [openssh@openssh.com](mailto:openssh.openssh.com).
>>>>>>> openssh/V_8_0
