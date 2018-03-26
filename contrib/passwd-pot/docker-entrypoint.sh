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

nohup rsyslogd -n &

for i in /docker-entrypoint.d/* ; do
    [ -f "$i" ] && source "$i"
done
asyncRun() {
    "$@" &
    pid="$!"
    trap "echo -e '\nStopping sshd[$pid]'; kill  $pid" SIGINT SIGTERM

    # A signal emitted while waiting will make the wait command return code > 128
    # Let's wrap it in a loop that doesn't end before the process is indeed stopped
     wait
}


if [ "$1" == "/opt/ssh/sbin/sshd" ] ; then
    asyncRun "$@" $SSHD_OPTS
else
    exec "$@"
fi
