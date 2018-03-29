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

```
Audit [yes|no]
```

Audit yes will log username/password to  syslog

```
AuditUrl http://localhost
```

AuditUrl will POST json to url

```
AuditSocket /var/run/passwd.socket
```

AuditSocket will POST json to this socket file. AuditUrl must be specified 


## Examples
    
* http://github.com/dougEfresh/passwd-pot


## Contributing
 All PRs are welcome


## Authors

* **Douglas Chimento**  - [dougEfresh](https://github.com/dougEfresh)


[ci-img]: https://travis-ci.org/dougEfresh/lambdazap.svg?branch=master
[ci]: https://travis-ci.org/dougEfresh/lambdazap
