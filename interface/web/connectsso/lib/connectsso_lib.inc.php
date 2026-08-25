<?php

/*
 * ispconfig-sso — one-time panel login tokens for ISPConfig.
 * Copyright (c) 2026 Wade Beckett.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See ../../../../LICENSE.
 *
 * -----------------------------------------------------------------------------
 * Shared constants and helpers for BOTH halves of the module:
 *   - lib/classes/remote.d/connectsso.inc.php  (mints tokens over the remote API)
 *   - index.php                                (redeems them and logs the user in)
 *
 * This file is include_once'd from the remote.d class, which ISPConfig loads on
 * EVERY remote API request (remoting_handler_base.inc.php globs
 * interface/web/*&#47;lib/classes/remote.d/*.inc.php). It must therefore stay
 * small and free of side effects: constants and functions only, no queries, no
 * output.
 *
 * ISPConfig 3.x runs on a wide PHP range and its own code is PHP 5-flavoured;
 * this file matches that style deliberately (no strict_types, no namespaces,
 * no typed properties) so the module loads on every panel its host supports.
 */

//* Direct-request guard. This file lives under the panel DOCROOT. Both stock
//* vhost templates serve interface/web/; the Apache one denies only *.lng
//* (install/tpl/apache_ispconfig.vhost.master, <FilesMatch "\.lng$">) and the
//* nginx one denies *.lng plus dotfiles (install/tpl/nginx_ispconfig.vhost.master,
//* location ~ /\.). Neither denies a .php under lib/, so every one of them
//* executes over HTTP. An .htaccess would not help:
//* AllowOverride is None in the mpm_itk branch and nginx ignores it entirely.
//* Legitimate inclusion always happens after interface/lib/config.inc.php has
//* run, which defines ISPC_ROOT_PATH (config.inc.php:85) — the remoting
//* handler loads remote.d classes from a bootstrapped app, and index.php
//* requires config.inc.php first. The CLI escape keeps tests/run.php working.
//* 404 rather than 403: the guard should not advertise that a file exists.
if (!defined('ISPC_ROOT_PATH') && PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
	http_response_code(404);
	die();
}

if (!defined('CONNECTSSO_VERSION')) {

	define('CONNECTSSO_VERSION', '1.0.0');

	/** Module directory name under interface/web — also the sys_user.modules entry. */
	define('CONNECTSSO_MODULE', 'connectsso');

	/** Path of the consumer page, reported to callers so they never hard-code it. */
	define('CONNECTSSO_ENDPOINT_PATH', '/connectsso/');

	/** Query-string parameter the consumer page reads the token from. */
	define('CONNECTSSO_TOKEN_PARAM', 'token');

	/**
	 * Token lifetime in seconds. This is a hand-off window, not a session: the
	 * only thing that happens between minting and redeeming is one HTTP
	 * redirect. Anything longer widens the window in which a token captured
	 * from a web-server access log or a browser history entry is still live.
	 * Keep <= 60.
	 */
	define('CONNECTSSO_TOKEN_TTL', 45);

	/** Entropy of the token, in bytes, before hex encoding. 32 bytes = 256 bits. */
	define('CONNECTSSO_TOKEN_BYTES', 32);

	/**
	 * How long a REDEEMED token row is kept. Used rows are retained briefly so
	 * that a replay attempt is recognisably a replay (and audited as one)
	 * rather than an unknown token, then garbage-collected.
	 */
	define('CONNECTSSO_USED_RETENTION', 3600);

	/** Redemption rate limit: attempts per source IP inside the window. */
	define('CONNECTSSO_ATTEMPT_LIMIT', 10);
	define('CONNECTSSO_ATTEMPT_WINDOW', 300);

	define('CONNECTSSO_TOKEN_TABLE', 'connectsso_token');
	define('CONNECTSSO_ATTEMPT_TABLE', 'connectsso_attempt');

	/** The one remote function this module registers. */
	define('CONNECTSSO_REMOTE_FUNCTION', 'connect_sso_token_create');
}

if (!function_exists('connectsso_token_is_wellformed')) {

	/**
	 * A token is exactly bin2hex(random_bytes(CONNECTSSO_TOKEN_BYTES)).
	 * Checked before the value is used in a query or a hash so that anything
	 * else is rejected as cheaply as possible.
	 *
	 * @param mixed $token
	 * @return bool
	 */
	function connectsso_token_is_wellformed($token) {
		if (!is_string($token)) {
			return false;
		}
		$expected = CONNECTSSO_TOKEN_BYTES * 2;

		return strlen($token) === $expected && preg_match('/^[a-f0-9]+$/', $token) === 1;
	}

	/**
	 * The value stored in the database. The clear token is NEVER stored and
	 * never logged: a read of connectsso_token must not yield a usable login.
	 *
	 * @param string $token
	 * @return string
	 */
	function connectsso_token_hash($token) {
		return hash('sha256', $token);
	}

	/**
	 * Compare two IP addresses by their binary form, so that equivalent
	 * spellings of the same address (leading zeroes, compressed IPv6, mixed
	 * case) match and nothing else does. hash_equals keeps the comparison
	 * length-independent.
	 *
	 * @param string $a
	 * @param string $b
	 * @return bool
	 */
	function connectsso_ip_equals($a, $b) {
		$pa = @inet_pton((string)$a);
		$pb = @inet_pton((string)$b);
		if ($pa === false || $pb === false) {
			return false;
		}

		return hash_equals($pa, $pb);
	}

	/**
	 * Source address of the current request, as the panel sees it.
	 *
	 * Deliberately REMOTE_ADDR only: X-Forwarded-For and friends are supplied
	 * by the client, and this value gates both the rate limiter and the
	 * optional IP binding. Operators running the panel behind a reverse proxy
	 * must make the proxy set REMOTE_ADDR (mod_remoteip / realip) rather than
	 * have this module trust a header.
	 *
	 * @return string
	 */
	function connectsso_remote_addr() {
		return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
	}

	/**
	 * Did this request arrive over TLS, as PHP sees it?
	 *
	 * Same signal ISPConfig itself uses to decide whether its session cookie
	 * gets the Secure flag ($_SERVER['HTTPS'] == 'on', app.inc.php:101), widened
	 * only to the spellings other SAPIs use: IIS sends HTTPS=1 and 'off' when
	 * it is NOT on, and Apache/nginx set REQUEST_SCHEME.
	 *
	 * Deliberately NOT consulted: X-Forwarded-Proto and friends. They are
	 * client-supplied, and this value gates whether a login credential may be
	 * created at all. Where a proxy really does terminate TLS, the operator
	 * declares it in security_settings.ini — see connectsso_proxy_declared().
	 *
	 * @return bool
	 */
	function connectsso_request_is_secure() {
		if (isset($_SERVER['HTTPS'])) {
			$https = strtolower(trim((string)$_SERVER['HTTPS']));
			if ($https !== '' && $https !== 'off') {
				return true;
			}
		}
		if (isset($_SERVER['REQUEST_SCHEME'])
			&& strtolower(trim((string)$_SERVER['REQUEST_SCHEME'])) === 'https'
		) {
			return true;
		}

		return false;
	}

	/**
	 * Has the operator told ISPConfig that a reverse proxy sits in front of the
	 * panel?
	 *
	 * `reverse_proxy_panel_allowed` in the [permissions] section of
	 * /usr/local/ispconfig/security/security_settings.ini ships as `none`
	 * (install/tpl/security_settings.ini.master:18) and is read through core's
	 * own getconf (interface/lib/classes/getconf.inc.php:60-73). Anything other
	 * than `none` is the operator stating that requests reach PHP through a
	 * proxy — which is exactly the topology in which PHP cannot see the real
	 * request scheme, so the TLS gate below cannot be enforced and TLS
	 * termination becomes the proxy's job.
	 *
	 * Fails CLOSED: an $app without getconf, an unreadable ini, a missing
	 * section or a missing key all read as "no proxy declared".
	 *
	 * @param object $app
	 * @return bool
	 */
	function connectsso_proxy_declared($app) {
		if (!is_object($app) || !isset($app->getconf) || !is_object($app->getconf)
			|| !method_exists($app->getconf, 'get_security_config')
		) {
			return false;
		}
		//* @: get_security_config() file_get_contents() the ini and indexes a
		//* section that a hand-edited file may not have. A warning on an auth
		//* path is noise; the fail-closed default below is the real answer.
		$permissions = @$app->getconf->get_security_config('permissions');
		if (!is_array($permissions) || !isset($permissions['reverse_proxy_panel_allowed'])) {
			return false;
		}
		$value = strtolower(trim((string)$permissions['reverse_proxy_panel_allowed']));

		return $value !== '' && $value !== 'none';
	}

	/**
	 * May this request mint or redeem a token?
	 *
	 * A token is a password substitute that travels in a URL. Over plain HTTP
	 * the mint response, the redirect that carries the token and the panel
	 * session that follows are all readable by anything on the path — and
	 * single use plus a 45-second TTL buy nothing against an interceptor who
	 * simply redeems the token before the customer's browser does. Both halves
	 * therefore refuse on a non-TLS request.
	 *
	 * The one exception is a panel the operator has declared to be behind a
	 * reverse proxy: there PHP sees the proxy's plaintext hop and the gate
	 * would refuse every request, so it steps aside and the operator owns TLS
	 * termination. That is an explicit local declaration in ISPConfig's own
	 * security settings, never a request header.
	 *
	 * @param object $app
	 * @return bool
	 */
	function connectsso_transport_is_acceptable($app) {
		return connectsso_request_is_secure() || connectsso_proxy_declared($app);
	}

	/**
	 * Delete tokens that can no longer be redeemed, and rate-limit buckets that
	 * have fallen out of the window. Called on every mint and at the start of
	 * every redemption, so both tables stay small without a cron job.
	 *
	 * @param object $app
	 * @param int    $now
	 * @return void
	 */
	function connectsso_gc($app, $now) {
		$app->db->query(
			'DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `expires_at` < ? AND (`used_at` IS NULL OR `used_at` < ?)',
			(int)$now,
			(int)$now - CONNECTSSO_USED_RETENTION
		);
		$app->db->query(
			'DELETE FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `last_attempt` < ?',
			(int)$now - CONNECTSSO_ATTEMPT_WINDOW
		);
	}

	/**
	 * Failed redemption attempts from this address inside the window.
	 *
	 * The address is stored as md5(), matching ISPConfig's own attempts_login
	 * table. That is a bucket key and a small PII-hygiene measure, NOT a
	 * secrecy control — the IPv4 space is enumerable under any hash — so the
	 * weakness of md5 is irrelevant here and parity with core is worth more.
	 *
	 * @param object $app
	 * @param string $ip
	 * @param int    $now
	 * @return int
	 */
	function connectsso_attempts($app, $ip, $now) {
		$row = $app->db->queryOneRecord(
			'SELECT `attempts` FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `ip_hash` = ? AND `last_attempt` > ?',
			md5((string)$ip),
			(int)$now - CONNECTSSO_ATTEMPT_WINDOW
		);

		return is_array($row) ? (int)$row['attempts'] : 0;
	}

	/**
	 * Record one failed redemption.
	 *
	 * Called from every refusal reached by PRESENTING A TOKEN VALUE THAT DID
	 * NOT CHECK OUT — malformed, unknown, expired, replayed, IP-mismatched, and
	 * a burn that did not take — so guessing is bounded no matter which of them
	 * does the rejecting.
	 *
	 * It is deliberately NOT called from the refusals on either side of that:
	 * the ones before the token is read (a non-TLS request, a request already
	 * at the limit) and the ones after it checked out and was burned
	 * (maintenance mode, a vanished or inactive panel user, a client suspended
	 * since minting, a session that cannot be started or regenerated). Neither
	 * kind can be used to guess — the first never touches a token, the second
	 * costs a genuine one that is already spent — and counting them would let
	 * one configuration mistake, one maintenance window or one suspended
	 * customer exhaust the budget of every visitor sharing that source address.
	 * index.php's header comment carries the same split; keep them in step.
	 *
	 * ONE atomic statement on purpose: a SELECT-then-INSERT/UPDATE pair loses
	 * counts when two rejected redemptions race (both SELECT no row, one INSERT
	 * wins the primary key, the other's INSERT fails and its attempt is never
	 * counted — an attacker parallelising guesses would be under-counted).
	 * `ip_hash` is the PRIMARY KEY (sql/install.sql), so INSERT ... ON
	 * DUPLICATE KEY UPDATE is increment-or-create in a single statement.
	 *
	 * The IF()s keep the stale-window semantics: a row whose last_attempt fell
	 * out of the window restarts at 1 instead of carrying yesterday's failures
	 * into today's budget. Assignment ORDER is load-bearing — MySQL/MariaDB
	 * evaluate ON DUPLICATE KEY assignments left to right and later ones see
	 * earlier results, so `attempts` and `first_attempt` (which must read the
	 * OLD `last_attempt`) are assigned before `last_attempt`.
	 *
	 * @param object $app
	 * @param string $ip
	 * @param int    $now
	 * @return void
	 */
	function connectsso_record_attempt($app, $ip, $now) {
		$stale = (int)$now - CONNECTSSO_ATTEMPT_WINDOW;
		$app->db->query(
			'INSERT INTO `' . CONNECTSSO_ATTEMPT_TABLE . '` (`ip_hash`, `attempts`, `first_attempt`, `last_attempt`) VALUES (?, 1, ?, ?)'
			. ' ON DUPLICATE KEY UPDATE `attempts` = IF(`last_attempt` <= ?, 1, `attempts` + 1),'
			. ' `first_attempt` = IF(`last_attempt` <= ?, ?, `first_attempt`), `last_attempt` = ?',
			md5((string)$ip),
			(int)$now,
			(int)$now,
			$stale,
			$stale,
			(int)$now,
			(int)$now
		);
	}

	/**
	 * A successful redemption clears the address's budget, mirroring how
	 * ISPConfig clears attempts_login after a successful login.
	 *
	 * @param object $app
	 * @param string $ip
	 * @return void
	 */
	function connectsso_clear_attempts($app, $ip) {
		$app->db->query(
			'DELETE FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `ip_hash` = ?',
			md5((string)$ip)
		);
	}

	/**
	 * Audit trail. Writes to sys_log (visible under Monitor > System Log) and,
	 * for events about a real login, to the panel's auth.log alongside
	 * ISPConfig's own login records (app.inc.php auth_log(), :215-221).
	 *
	 * The sys_log priority is ALWAYS 2 (LOGLEVEL_ERROR), never configurable:
	 * app.inc.php log() (interface/lib/app.inc.php:190-192) silently drops any
	 * message below $conf['log_priority'], and the installer writes
	 * log_priority = 2 on every shipped distribution
	 * (install/tpl/config.inc.php.master:145 filled from
	 * install/dist/conf/*.conf.php:39, ispconfig_log_priority = 2). Everything
	 * this module logs is a security event — a token mint, a refusal, a
	 * sign-in — and a security event logged at 0 or 1 would be recorded
	 * NOWHERE on a real install.
	 *
	 * NEVER pass a token, a token hash, or any part of either: the whole point
	 * of hashing at rest is that a log reader cannot reconstruct a login.
	 *
	 * @param object $app
	 * @param string $message
	 * @param bool   $auth_log also append to the panel auth log
	 * @return void
	 */
	function connectsso_audit($app, $message, $auth_log = false) {
		$line = '[connectsso] ' . $message . ' from ' . connectsso_remote_addr();
		$app->log($line, 2); // LOGLEVEL_ERROR — see the docblock; lower is dropped
		if ($auth_log) {
			$app->auth_log($line . ' at ' . date('Y-m-d H:i:s'));
		}
	}
}
