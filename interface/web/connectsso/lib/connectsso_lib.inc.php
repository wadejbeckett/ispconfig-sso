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
 * small and cheap: constants and functions only, no queries, no output.
 *
 * The ONE side effect it does have is the optional override file — a single
 * stat() when it is absent (the normal case) and one parse_ini_file() when it
 * is present. See the OVERRIDE FILE block below for where it lives and why.
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

/* ---------------------------------------------------------------------------
 * OVERRIDE FILE
 *
 * Everything below that an operator may reasonably want to tune used to be a
 * define() in this shipped file, which meant editing it — and losing the edit
 * on the next ./install.sh. These functions read an OPTIONAL ini file instead,
 * validate it, clamp it, and leave the shipped defaults in force when it is
 * absent, unreadable or broken.
 *
 * WHERE IT LIVES, and why:  <ispconfig>/interface/lib/connectsso.ini
 *
 *   - NOT WEB-SERVABLE. ISPConfig's panel vhost roots at
 *     <ispconfig>/interface/web/ — install/tpl/apache_ispconfig.vhost.master:53
 *     (DocumentRoot) and install/tpl/nginx_ispconfig.vhost.master:16 (root).
 *     interface/lib/ is the directory ABOVE that root, holding the panel's own
 *     config.inc.php, and no request can reach it. Anything under
 *     interface/web/connectsso/ could be, which is why the module's own .php
 *     files each carry a direct-request guard — a plain ini could carry none.
 *   - SURVIVES AN ADD-ON UPDATE. ./install.sh only ever writes and removes
 *     interface/web/connectsso; it never touches this path, and ./uninstall.sh
 *     reports the file rather than deleting it.
 *   - SURVIVES AN ISPCONFIG UPGRADE. ispconfig_update.sh runs install/update.php,
 *     which calls the SAME install_ispconfig() a first install does
 *     (update.php:643). That deploys the interface with
 *     `cp -rf ../interface <install_dir>`
 *     (install/lib/installer_base.lib.php:3599) — a MERGE, not a replace, which
 *     is the same reason the module directory itself survives — and then
 *     re-runs `chown -R ispconfig:ispconfig <install_dir>/interface` (:3774),
 *     so the panel can still read this file afterwards.
 *   - NOT security_settings.ini. That would have been the obvious home, but the
 *     installer REWRITES it from a master template on every install and upgrade
 *     (installer_base.lib.php:3613-3618, keeping only a `~` backup), so a
 *     setting placed there is exactly the thing this file exists to prevent:
 *     an operator's configuration silently lost on update.
 *
 * WHAT MAY BE CHANGED is deliberately a short list — token lifetime, the two
 * rate-limit numbers, and whether a token may be minted unbound. The controls
 * that make a leaked token worth little (256-bit entropy, SHA-256 at rest,
 * single use, and the refusal to ever mint for an administrator) and the TLS
 * gate are NOT overridable: a key naming one of them is refused by name, with a
 * reason, rather than quietly ignored. connectsso.ini.example says the same
 * thing in the file the operator is actually looking at.
 * ------------------------------------------------------------------------- */
if (!function_exists('connectsso_config_defaults')) {

	/**
	 * Basename of the override file. Only ever joined to a directory that is
	 * above the panel's document root — see the block comment above.
	 */
	define('CONNECTSSO_CONFIG_NAME', 'connectsso.ini');

	/**
	 * The shipped value of every tunable. These are the numbers the README
	 * documents and the ones in force when there is no override file.
	 *
	 * @return array
	 */
	function connectsso_config_defaults() {
		return array(
			'token_ttl'            => 45,
			'attempt_limit'        => 10,
			'attempt_window'       => 300,
			'allow_unbound_tokens' => true,
		);
	}

	/**
	 * Hard bounds for the numeric tunables, as array(min, max). A value outside
	 * them is CLAMPED and reported — never obeyed, and never silently dropped:
	 * the operator asked for something, so give them the nearest thing that is
	 * still safe and say so.
	 *
	 *   token_ttl      5..60   the README's contract, and what tests/run.php
	 *                          asserts. It is a hand-off window covering one
	 *                          HTTP redirect; longer widens the window in which
	 *                          a token scraped from an access log is still live.
	 *                          Below 5 s a slow redirect fails legitimately.
	 *   attempt_limit  1..1000 0 would refuse every visitor from an address
	 *                          forever; past 1000 the limiter bounds nothing.
	 *   attempt_window 60..86400
	 *
	 * @return array
	 */
	function connectsso_config_bounds() {
		return array(
			'token_ttl'      => array(5, 60),
			'attempt_limit'  => array(1, 1000),
			'attempt_window' => array(60, 86400),
		);
	}

	/**
	 * Keys that name a SECURITY-CRITICAL control, mapped to the reason they are
	 * not yours to change. Present in the file they are ignored and reported by
	 * name — deliberately distinct from "unrecognised key", which reads like a
	 * typo. An operator who tried to turn one of these off must be told that it
	 * is still on.
	 *
	 * @return array
	 */
	function connectsso_config_refused() {
		$entropy = 'token entropy is fixed at 32 bytes (256 bits)';
		$hashing = 'tokens are always stored as SHA-256 and never in clear';
		$oneshot = 'a token is always burned on its first redemption';
		$noadmin = 'administrator accounts can never be minted for';
		$tls     = 'the TLS gate is not a setting; declare a reverse proxy in'
			. ' security_settings.ini (reverse_proxy_panel_allowed) instead';

		return array(
			'token_bytes'   => $entropy,
			'token_entropy' => $entropy,
			'token_hash'    => $hashing,
			'hash_algo'     => $hashing,
			'single_use'    => $oneshot,
			'allow_reuse'   => $oneshot,
			'allow_admin'   => $noadmin,
			'require_tls'   => $tls,
			'allow_http'    => $tls,
		);
	}

	/**
	 * Interpret an ini value as a boolean. Returns null when it is neither,
	 * so the caller can complain rather than guess.
	 *
	 * parse_ini_file() with INI_SCANNER_TYPED already turns yes/no/true/false/
	 * on/off into real booleans; the string forms are handled too because an
	 * older PHP falls back to INI_SCANNER_NORMAL, where they arrive as strings.
	 *
	 * @param mixed $value
	 * @return bool|null
	 */
	function connectsso_config_bool($value) {
		if (is_bool($value)) {
			return $value;
		}
		if (is_int($value)) {
			return $value === 1 ? true : ($value === 0 ? false : null);
		}
		if (!is_string($value)) {
			return null;
		}
		$v = strtolower(trim($value));
		if (in_array($v, array('1', 'yes', 'true', 'on'), true)) {
			return true;
		}
		if (in_array($v, array('0', 'no', 'false', 'off'), true)) {
			return false;
		}

		return null;
	}

	/**
	 * Where the override file lives.
	 *
	 * CONNECTSSO_CONFIG_FILE, if something defined it before this file loaded,
	 * wins outright — that is the seam tests/run.php drives, and it is the only
	 * way an operator could relocate the file.
	 *
	 * Otherwise ISPC_LIB_PATH, which config.inc.php defines as
	 * ISPC_ROOT_PATH . '/lib' — i.e. <ispconfig>/interface/lib
	 * (install/tpl/config.inc.php.master:99-100). Both halves of this module run
	 * after that file, so on a panel this is always the answer.
	 *
	 * The last resort walks up from this file, for a CLI context with no panel
	 * bootstrap. Note it is deliberately NOT the primary: with
	 * `./install.sh --symlink` __DIR__ resolves into the clone, not the panel.
	 *
	 * @return string
	 */
	function connectsso_config_path() {
		if (defined('CONNECTSSO_CONFIG_FILE')) {
			return (string)CONNECTSSO_CONFIG_FILE;
		}
		if (defined('ISPC_LIB_PATH')) {
			return rtrim((string)ISPC_LIB_PATH, '/') . '/' . CONNECTSSO_CONFIG_NAME;
		}
		//* .../interface/web/connectsso/lib -> .../interface
		$interface = realpath(__DIR__ . '/../../..');
		if ($interface === false) {
			$interface = __DIR__ . '/../../..';
		}

		return $interface . '/lib/' . CONNECTSSO_CONFIG_NAME;
	}

	/**
	 * Read the override file into raw key => value pairs.
	 *
	 * Returns an empty array for every failure, so the caller always ends up
	 * with the shipped defaults. A file that is MISSING is the normal case and
	 * says nothing; a file that exists but could not be used appends to
	 * $problems, because an operator who believes their settings are in force
	 * when they are not is the failure this whole mechanism exists to avoid.
	 *
	 * @param string $path
	 * @param array  $problems appended to
	 * @return array
	 */
	function connectsso_config_read($path, &$problems) {
		if (!is_array($problems)) {
			$problems = array();
		}
		$path = (string)$path;
		if ($path === '' || !file_exists($path)) {
			return array();
		}
		if (is_dir($path)) {
			$problems[] = $path . ' is a directory, not a file; no overrides were applied.';

			return array();
		}
		if (!is_readable($path)) {
			$problems[] = $path . ' exists but is not readable by the panel user;'
				. ' no overrides were applied.';

			return array();
		}
		//* process_sections = false: a [section] header the operator added for
		//* tidiness is flattened away rather than hiding every key under it.
		//* @: a syntax error raises a warning AND returns false; the complaint
		//* below is the report, and a warning on an auth path is noise.
		$flags = defined('INI_SCANNER_TYPED') ? INI_SCANNER_TYPED : INI_SCANNER_NORMAL;
		$raw = @parse_ini_file($path, false, $flags);
		if (!is_array($raw)) {
			$problems[] = $path . ' could not be parsed as an ini file;'
				. ' no overrides were applied.';

			return array();
		}

		return $raw;
	}

	/**
	 * Validate raw key => value pairs into the effective configuration.
	 *
	 * Total: it ALWAYS returns exactly the keys connectsso_config_defaults()
	 * declares, whatever the file contained, so a caller can never be handed a
	 * setting the module does not know about.
	 *
	 * @param mixed $raw      whatever connectsso_config_read() produced
	 * @param array $problems appended to
	 * @return array
	 */
	function connectsso_config_resolve($raw, &$problems) {
		$values = connectsso_config_defaults();
		if (!is_array($problems)) {
			$problems = array();
		}
		if (!is_array($raw)) {
			return $values;
		}
		$bounds  = connectsso_config_bounds();
		$refused = connectsso_config_refused();

		foreach ($raw as $key => $value) {
			$name = strtolower(trim((string)$key));

			if (isset($refused[$name])) {
				$problems[] = "'" . $name . "' is not an overridable setting and was ignored: "
					. $refused[$name] . '.';
				continue;
			}
			if (!array_key_exists($name, $values)) {
				$problems[] = "'" . $name . "' is not a recognised setting and was ignored"
					. ' (settings this file accepts: ' . implode(', ', array_keys($values)) . ').';
				continue;
			}

			if (is_bool($values[$name])) {
				$bool = connectsso_config_bool($value);
				if ($bool === null) {
					$problems[] = "'" . $name . "' is not a yes/no value; keeping the default ("
						. ($values[$name] ? 'yes' : 'no') . ').';
					continue;
				}
				$values[$name] = $bool;
				continue;
			}

			//* Whole numbers only. A float, an array or a word keeps the
			//* default rather than becoming (int)0, which for attempt_limit
			//* would have locked every visitor out.
			if (!is_int($value)
				&& !(is_string($value) && preg_match('/^[+-]?[0-9]+$/', trim($value)) === 1)
			) {
				$problems[] = "'" . $name . "' is not a whole number; keeping the default ("
					. $values[$name] . ').';
				continue;
			}
			$number = (int)$value;
			$min = $bounds[$name][0];
			$max = $bounds[$name][1];
			if ($number < $min) {
				$problems[] = "'" . $name . "' was " . $number . ', below the minimum of '
					. $min . '; clamped to ' . $min . '.';
				$number = $min;
			} elseif ($number > $max) {
				$problems[] = "'" . $name . "' was " . $number . ', above the maximum of '
					. $max . '; clamped to ' . $max . '.';
				$number = $max;
			}
			$values[$name] = $number;
		}

		return $values;
	}

	/**
	 * Everything the override file was complained about, this request.
	 *
	 * A store rather than a constant because the list is built before the
	 * constants exist. The $record parameter is INTERNAL — it is called exactly
	 * once, from the load block below; everything else calls this with no
	 * argument to read.
	 *
	 * @param array|null $record internal
	 * @return array
	 */
	function connectsso_config_problems($record = null) {
		static $problems = array();
		if (is_array($record)) {
			$problems = $record;
		}

		return $problems;
	}

	/**
	 * Write any override-file complaints to the panel's own log, once per
	 * request. Called from both halves once the request has proved itself, so
	 * that an operator watching Monitor > System Log sees a broken
	 * connectsso.ini without having to go looking for it.
	 *
	 * Not auth_log: a configuration complaint is not an authentication event.
	 *
	 * @param object $app
	 * @return void
	 */
	function connectsso_config_report($app) {
		static $reported = false;
		if ($reported) {
			return;
		}
		$reported = true;
		$problems = connectsso_config_problems();
		if (!$problems || !is_object($app) || !method_exists($app, 'log')) {
			return;
		}
		$path = connectsso_config_path();
		foreach ($problems as $problem) {
			connectsso_audit($app, 'configuration problem in ' . $path . ': ' . $problem);
		}
	}

	/**
	 * The effective configuration as key=value lines. This is what
	 * `./install.sh --status` prints, so the operator reads the numbers the
	 * panel is actually running on rather than the numbers in the README.
	 *
	 * @return array
	 */
	function connectsso_config_describe() {
		$path  = connectsso_config_path();
		$lines = array(
			'version=' . CONNECTSSO_VERSION,
			'file=' . $path,
			'present=' . (is_file($path) ? 'yes' : 'no'),
			'token_ttl=' . CONNECTSSO_TOKEN_TTL,
			'attempt_limit=' . CONNECTSSO_ATTEMPT_LIMIT,
			'attempt_window=' . CONNECTSSO_ATTEMPT_WINDOW,
			'allow_unbound_tokens=' . (CONNECTSSO_ALLOW_UNBOUND ? 'yes' : 'no'),
		);
		foreach (connectsso_config_problems() as $problem) {
			//* One line per problem, and never a newline inside one.
			$lines[] = 'problem=' . str_replace(array("\r", "\n"), ' ', $problem);
		}

		return $lines;
	}
}

if (!defined('CONNECTSSO_VERSION')) {

	define('CONNECTSSO_VERSION', '1.0.0');

	/** Module directory name under interface/web — also the sys_user.modules entry. */
	define('CONNECTSSO_MODULE', 'connectsso');

	/** Path of the consumer page, reported to callers so they never hard-code it. */
	define('CONNECTSSO_ENDPOINT_PATH', '/connectsso/');

	/** Query-string parameter the consumer page reads the token from. */
	define('CONNECTSSO_TOKEN_PARAM', 'token');

	/** Entropy of the token, in bytes, before hex encoding. 32 bytes = 256 bits.
	 *  NOT overridable — see connectsso_config_refused(). */
	define('CONNECTSSO_TOKEN_BYTES', 32);

	/**
	 * How long a REDEEMED token row is kept. Used rows are retained briefly so
	 * that a replay attempt is recognisably a replay (and audited as one)
	 * rather than an unknown token, then garbage-collected.
	 */
	define('CONNECTSSO_USED_RETENTION', 3600);

	//* ---- the four tunables, resolved from the optional override file -------
	//* Read once, here, because everything below is a constant: the values must
	//* exist before the first define(). A missing file — the normal case — is
	//* one stat(). Anything the file got wrong is CLAMPED or ignored, never
	//* obeyed, and lands in $connectsso_problems.
	$connectsso_problems = array();
	$connectsso_config = connectsso_config_resolve(
		connectsso_config_read(connectsso_config_path(), $connectsso_problems),
		$connectsso_problems
	);
	connectsso_config_problems($connectsso_problems);

	//* Backstop so a broken file is never silent, even in a context that never
	//* reaches connectsso_config_report() — a direct include, a CLI tool, a
	//* request that dies earlier (the TLS gate refuses before either half gets
	//* that far). sys_log gets the same lines from the two request paths, and
	//* ./install.sh --status prints them as a FAILED check.
	//*
	//* This IS one error-log line per request for as long as the file is broken,
	//* including on the unauthenticated redemption endpoint. That is the
	//* trade-off, taken deliberately: silence about a configuration the operator
	//* believes is in force is the failure this whole mechanism exists to
	//* prevent, and the volume is bounded by the same requests the web server is
	//* already writing an access-log line for. The expensive sink — sys_log, a
	//* database write — stays behind the gates in connectsso_config_report().
	/** Most per-request error_log lines one broken override file may write. */
	if (!defined('CONNECTSSO_CONFIG_LOG_LIMIT')) {
		define('CONNECTSSO_CONFIG_LOG_LIMIT', 5);
	}

	//* Bounded on purpose: a file with 500 bad keys must not write 500 lines on
	//* every request - that is an operator's typo turning the unauthenticated
	//* redemption endpoint into a disk-filler. The first few problems are what
	//* anyone needs to fix the file; the rest are counted, and ./install.sh
	//* --status prints the full list on demand.
	if ($connectsso_problems) {
		$connectsso_shown = 0;
		foreach ($connectsso_problems as $connectsso_problem) {
			if ($connectsso_shown >= CONNECTSSO_CONFIG_LOG_LIMIT) {
				error_log(sprintf(
					'[connectsso] %s: %d further problem(s) not listed - run ./install.sh --status for all of them',
					connectsso_config_path(),
					count($connectsso_problems) - $connectsso_shown
				));
				break;
			}
			error_log('[connectsso] ' . connectsso_config_path() . ': ' . $connectsso_problem);
			$connectsso_shown++;
		}
		unset($connectsso_problem, $connectsso_shown);
	}

	/**
	 * Token lifetime in seconds. This is a hand-off window, not a session: the
	 * only thing that happens between minting and redeeming is one HTTP
	 * redirect. Anything longer widens the window in which a token captured
	 * from a web-server access log or a browser history entry is still live.
	 * Clamped to 5..60 — see connectsso_config_bounds().
	 */
	define('CONNECTSSO_TOKEN_TTL', $connectsso_config['token_ttl']);

	/** Redemption rate limit: attempts per source IP inside the window. */
	define('CONNECTSSO_ATTEMPT_LIMIT', $connectsso_config['attempt_limit']);
	define('CONNECTSSO_ATTEMPT_WINDOW', $connectsso_config['attempt_window']);

	/**
	 * May a token be minted with an empty bind_ip? Panels where the operator
	 * knows the panel and the calling system see the same client address can
	 * turn this off and make IP binding mandatory. Default: allowed, because
	 * binding fails outright behind a CDN or a proxy that does not set
	 * REMOTE_ADDR — see the README's note on bind_ip.
	 */
	define('CONNECTSSO_ALLOW_UNBOUND', $connectsso_config['allow_unbound_tokens']);

	unset($connectsso_config, $connectsso_problems);

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

		//* /D: without it '$' also matches before a final newline.
		return strlen($token) === $expected && preg_match('/^[a-f0-9]+$/D', $token) === 1;
	}

	/**
	 * A client id as the remote API delivered it, or 0 when it is not a whole
	 * number. intval() alone is NOT validation: it turns true and array(7) into
	 * 1, '5abc' into 5, '1e3' into 1000 and 5.9 into 5 — each a different,
	 * valid-looking client that a token would then be minted for. SOAP delivers
	 * digit strings and JSON delivers ints (or, rarely, an integral float);
	 * those are the only spellings accepted.
	 *
	 * @param mixed $value
	 * @return int
	 */
	function connectsso_client_id($value) {
		if (is_int($value)) {
			return $value;
		}
		if (is_float($value)) {
			return (is_finite($value) && $value == floor($value) && abs($value) < PHP_INT_MAX) ? (int)$value : 0;
		}
		if (is_string($value) && preg_match('/^[0-9]+$/D', trim($value)) === 1) {
			return intval(trim($value));
		}

		return 0;
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
