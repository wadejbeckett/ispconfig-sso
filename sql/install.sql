-- ispconfig-sso — one-time panel login tokens for ISPConfig.
-- Copyright (c) 2026 Wade Beckett. GPLv3 — see ../LICENSE.
--
-- Applied by bin/connectsso_schema.php against the ISPConfig interface
-- database (the one named in interface/lib/config.inc.php). Both statements are
-- idempotent, so install.sh can be re-run safely.
--
-- These tables are module-owned. Nothing in ISPConfig core references them, and
-- they carry no ISPConfig permission columns (sys_userid / sys_groupid / …)
-- because nothing in the panel lists or edits them.

CREATE TABLE IF NOT EXISTS `connectsso_token` (
  -- SHA-256 of the clear token. The clear token is returned to the API caller
  -- once and never stored: reading this table must not yield a usable login.
  `token_id`    int(11) unsigned NOT NULL AUTO_INCREMENT,
  `token_hash`  char(64)         NOT NULL,
  -- The panel account the token logs in as, and the client it belongs to.
  `sys_userid`  int(11) unsigned NOT NULL,
  `client_id`   int(11) unsigned NOT NULL,
  -- Optional: the address the token may be redeemed FROM (the end user's
  -- browser, not the API caller). '' = unbound. 45 chars fits IPv6 + zone.
  `bind_ip`     varchar(45)      NOT NULL DEFAULT '',
  `created_at`  int(11) unsigned NOT NULL,
  `expires_at`  int(11) unsigned NOT NULL,
  -- NULL until redeemed. The single-use guard is an UPDATE conditional on this
  -- being NULL, so it must stay nullable and must never default to 0.
  `used_at`     int(11) unsigned          DEFAULT NULL,
  `used_ip`     varchar(45)               DEFAULT NULL,
  -- remote_user.remote_userid that minted it, for the audit trail.
  `created_by`  int(11) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`token_id`),
  UNIQUE KEY `token_hash` (`token_hash`),
  KEY `expires_at` (`expires_at`),
  KEY `client_id` (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `connectsso_attempt` (
  -- md5(REMOTE_ADDR), matching ISPConfig's own attempts_login convention. This
  -- is a bucket key, not a secret: an IP is enumerable under any hash.
  `ip_hash`       char(32)         NOT NULL,
  `attempts`      int(11) unsigned NOT NULL DEFAULT 0,
  `first_attempt` int(11) unsigned NOT NULL,
  `last_attempt`  int(11) unsigned NOT NULL,
  PRIMARY KEY (`ip_hash`),
  KEY `last_attempt` (`last_attempt`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
