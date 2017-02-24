create database audit
  DEFAULT CHARACTER SET utf8
  DEFAULT COLLATE utf8_general_ci;

use audit;

CREATE TABLE %%TABLE%% (
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
