#!/bin/bash
source table.conf
sed -e "s/%SCHEMA%/$SCHEMA/" -e "s/%AUDIT_TABLE%/$AUDIT_TABLE/" -e "s/%AUDIT_TABLE_GEO%/$AUDIT_TABLE_GEO/" -e "s/%AUDIT_TABLE_EVENT%/$AUDIT_TABLE_EVENT/" schema.sql.template > schema.sql
docker build -t ssh_audit .
