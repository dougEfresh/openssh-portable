from ubuntu:latest

MAINTAINER Doug Chimento <dchimento@gmail.com>

ENV DEBIAN_FRONTEND noninteractive
RUN apk add --no-cache \
    curl-dev zlib-dev openssl-dev rsyslog ca-certificates curl json-c-dev 

RUN mkdir /var/empty
RUN mkdir /opt/ssh
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
