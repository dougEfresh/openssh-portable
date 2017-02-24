create database audit
  DEFAULT CHARACTER SET utf8
  DEFAULT COLLATE utf8_general_ci;

use audit;

CREATE TABLE sshAuditPasswd (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `time` bigint(20) unsigned NOT NULL,
  `user` varchar(1024) NOT NULL DEFAULT '',
  `passwd` varchar(1024) NOT NULL DEFAULT '',
  `remoteAddr` varchar(16) NOT NULL DEFAULT '',
  `remotePort` int(10) unsigned DEFAULT NULL,
  `remoteName` varchar(256) DEFAULT NULL,
  `remoteVersion` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
) CHARACTER SET utf8 COLLATE utf8_general_ci;


CREATE TABLE sshAuditPasswdGeo (
  `id` bigint NOT NULL,
  `longitude`  DECIMAL(5,2)  NOT NULL DEFAULT 0,
  `latitude`  DECIMAL(5,2) NOT NULL DEFAULT 0,
  `country` char(2) NOT NULL DEFAULT 'ZZ',
  `city` varchar(128),
  `postal` varchar(16),
  `metroCode` bigint(20) NOT NULL DEFAULT 0,
   FOREIGN KEY (id)
   REFERENCES sshAuditPasswd(id)
) CHARACTER SET utf8 COLLATE utf8_general_ci;

CREATE OR REPLACE VIEW sshEvent AS
select a.id, FROM_UNIXTIME(time/1000) as time, user, passwd, remoteAddr, remotePort, remoteName, remoteVersion,
COALESCE(b.latitude, 0.0) as latitude,
COALESCE(b.longitude,0.0) as longitude,
COALESCE(b.country, 'ZY') as country,
COALESCE(b.city, '') as city, 
COALESCE(b.postal, '') as postal,
COALESCE(b.metroCode, 0) as metroCode
FROM sshAuditPasswd a left join sshAuditPasswdGeo b on
a.id = b.id;
