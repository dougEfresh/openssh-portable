#!/bin/bash
echo "Using rsyslog $RSYSLOG_SERVER"
echo "Starting $@"
export PATH=$PATH:/opt/ssh/bin

rm -f /opt/ssh/etc/ssh_host_dsa_key
rm -f /opt/ssh/etc/ssh_host_rsa_key 
rm -f /opt/ssh/etc/ssh_host_ed25519_key 
rm -f /opt/ssh/etc/ssh_host_ecdsa_key

ssh-keygen -t dsa -f /opt/ssh/etc/ssh_host_dsa_key -N ""
ssh-keygen -t rsa -f /opt/ssh/etc/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /opt/ssh/etc/ssh_host_ed25519_key -N ""
ssh-keygen -t ecdsa -f /opt/ssh/etc/ssh_host_ecdsa_key -N ""

sed -i -e  "s/%RSYSLOG_SERVER%/$RSYSLOG_SERVER/g" /etc/rsyslog.d/10-sshd.conf

nohup rsyslogd -n > /dev/null &

for i in /docker-entrypoint.d/* ; do
    [ -f "$i" ] && source "$i"
done

function getout() {
  parent=$1
 for i in `pgrep -P $parent`; do
    kill $i 2>/dev/null &&  wait $i
 done
}

function asyncRun() {
    "$@" &
    pid="$!"
    parent=$$
    trap "getout $parent" SIGINT SIGTERM
    wait
}

if [ "$1" == "/opt/ssh/sbin/sshd" ] ; then
    asyncRun "$@" $SSHD_OPTS
else
    exec "$@"
fi
