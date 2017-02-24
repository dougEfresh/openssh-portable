#!/bin/bash
echo "Starting local mysql"
id=`docker ps -q -f name=ssh_audit `
[ -n "$id" ]  && docker stop $id 
docker rm ssh_audit 2> /dev/null
docker run -p 33306:3306 -d --name ssh_audit  -e MYSQL_ROOT_PASSWORD=root ssh_audit
