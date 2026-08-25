-- ispconfig-sso — one-time panel login tokens for ISPConfig.
-- Copyright (c) 2026 Wade Beckett. GPLv3 — see ../LICENSE.
--
-- Applied by bin/connectsso_schema.php --drop (uninstall.sh).
--
-- Dropping loses nothing: connectsso_token holds only unredeemed or
-- recently-redeemed one-time tokens, all of which expire within a minute, and
-- connectsso_attempt holds a five-minute rate-limit window.

DROP TABLE IF EXISTS `connectsso_token`;
DROP TABLE IF EXISTS `connectsso_attempt`;
