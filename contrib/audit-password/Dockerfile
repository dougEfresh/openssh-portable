from mysql:5.6


ADD *.sql /docker-entrypoint-initdb.d/
ENV MYSQL_ALLOW_EMPTY_PASSWORD yes
EXPOSE 3306

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["mysqld"]
