# OpenSSH Honey pot

Patched OpenSSH server captures passwords and stores them or sends them to a REST api

[![Build Status][ci-img]][ci]


## Quick Start

```shell
$ docker run -t -i -p 2222:2222 dougefresh/sshd-passwd-pot /opt/ssh/sbin/sshd -d
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

You can pass any valid OpenSSH options https://man.openbsd.org/sshd


## Examples
    
* http://github.com/dougEfresh/passwd-pot


## Contributing
 All PRs are welcome


## Authors

* **Douglas Chimento**  - [dougEfresh][me]




[ci-img]: https://travis-ci.org/dougEfresh/lambdazap.svg?branch=master
[ci]: https://travis-ci.org/dougEfresh/lambdazap
