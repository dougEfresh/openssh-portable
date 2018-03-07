from alpine:3.7

MAINTAINER Doug Chimento <dchimento@gmail.com>
RUN apk add --no-cache curl zlib json-c libressl bash rsyslog

RUN mkdir -p /var/empty /opt/ssh
RUN touch /var/log/btmp
RUN chmod 500 /var/log/btmp
COPY build/bin /opt/ssh/bin
COPY build/sbin /opt/ssh/sbin
COPY build/etc /opt/ssh/etc
COPY build/libexec /opt/ssh/libexec
COPY build/share /opt/ssh/share
COPY contrib/passwd-pot/sshd_config /opt/ssh/etc/sshd_config
COPY contrib/passwd-pot/docker-entrypoint.sh /docker-entrypoint.sh
COPY contrib/passwd-pot/10-sshd.conf /etc/rsyslog.d/10-sshd.conf

RUN rm -f /opt/ssh/etc/ssh_host*key
RUN mkdir /docker-entrypoint.d

EXPOSE 2222

ENV RSYSLOG_SERVER 172.17.0.1

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD [ "/opt/ssh/sbin/sshd", "-D"]
