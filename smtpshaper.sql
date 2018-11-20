CREATE TABLE IF NOT EXISTS `saslstat` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `address_id` int(10) unsigned NOT NULL,
  `cdate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `rcptcount` int(10) unsigned NOT NULL,
  `ip` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `address_id` (`address_id`,`cdate`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='remember emails sent by the server to prevent abuses';

