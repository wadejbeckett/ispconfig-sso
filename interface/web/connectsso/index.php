<?php

/*
 * ispconfig-sso — one-time panel login tokens for ISPConfig.
 * Copyright (c) 2026 Wade Beckett.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See ../../../LICENSE.
 *
 * -----------------------------------------------------------------------------
 * Token consumer: redeem a one-time token, establish the panel session, redirect.
 *
 * This file is an AUTHENTICATION ENDPOINT. Every check below is load-bearing;
 * read the README's security model before changing any of them. In particular:
 *
 *   - it burns the token with a conditional UPDATE, and treats the affected-row
 *     count as the lock — the earlier SELECT is a lookup, not the guard, so two
 *     simultaneous redemptions cannot both win;
 *   - it regenerates the PHP session id before writing anything into the
 *     session, and refuses to continue if that fails (session fixation);
 *   - it never takes a redirect target from the request — the destination is
 *     always the panel's own start page;
 *   - it refuses outright unless the request arrived over TLS (or the operator
 *     declared a reverse proxy in security_settings.ini);
 *   - it rate-limits by source address. A failure counts when it was reached by
 *     PRESENTING A TOKEN VALUE THAT DID NOT CHECK OUT — malformed, unknown,
 *     expired, replayed, IP-mismatched, failed burn. Those are the guessing
 *     paths. Refusals BEFORE the token is read (transport, already at the
 *     limit) and refusals AFTER it checked out and was burned (maintenance,
 *     vanished/inactive user, suspended client, broken session handling)
 *     deliberately do NOT count: neither kind can be used to guess, and
 *     counting them would let one config mistake or one suspended customer
 *     exhaust the budget of every visitor sharing that source address;
 *   - it never emits the token, the token hash, or the reason for a refusal.
 *
 * The session it builds mirrors interface/web/login/index.php exactly (verified
 * 3.3.1p1, lines 96-127): same keys, same theme-compatibility gate, same
 * startmodule/menu load, same 2FA and forced-password-change hand-offs. If the
 * panel would have demanded a second factor at the login form, it demands one
 * here too — an SSO link is a password replacement, not a 2FA bypass.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';
require_once ISPC_WEB_PATH . '/common.php';
require_once __DIR__ . '/lib/connectsso_lib.inc.php';

//* This response is a login hand-off: never cached, never indexed, and never a
//* Referer that carries the token to whatever the panel start page links to.
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
header('X-Frame-Options: DENY');

$connectsso_now = time();
$connectsso_ip  = connectsso_remote_addr();

/**
 * Refuse, audit, and stop. The visitor is told nothing beyond "this link did
 * not work": distinguishing expired from replayed from unknown would turn this
 * page into an oracle about other people's tokens.
 *
 * @param string $reason internal, for the audit log only
 * @param int    $status HTTP status
 * @return void
 */
function connectsso_refuse($reason, $status = 403) {
	global $app;

	connectsso_audit($app, 'refused a login token: ' . $reason, true);

	if (!headers_sent()) {
		$phrases = array(429 => ' Too Many Requests', 503 => ' Service Unavailable');
		header('HTTP/1.1 ' . (int)$status . (isset($phrases[$status]) ? $phrases[$status] : ' Forbidden'));
		header('Content-Type: text/html; charset=utf-8');
	}
	echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
		. '<meta name="robots" content="noindex,nofollow">'
		. '<title>Sign-in link not accepted</title></head><body>'
		. '<h1>Sign-in link not accepted</h1>'
		. '<p>This one-time sign-in link is no longer valid. It may have already been used,'
		. ' or it may have expired &mdash; these links last less than a minute.</p>'
		. '<p>Please return to your hosting account and try again, or '
		. '<a href="/login/">sign in with your username and password</a>.</p>'
		. '</body></html>';
	die();
}

//* ------------------------------------------------------------------- TLS
//* Before ANYTHING else, including the token lookup. A token that arrived over
//* plain HTTP has already been exposed on the wire, and finishing the login
//* would hand the customer a panel session that is exposed for its whole life.
//* Refuse unless the operator declared a reverse proxy in ISPConfig's own
//* security_settings.ini — the only topology where PHP cannot see the real
//* scheme, and where TLS termination is therefore the proxy's job.
//* No attempt is recorded: this is a server-configuration refusal, not a guess
//* at somebody's token, and it must not spend a real visitor's rate-limit
//* budget (which on a shared/NATed address is shared with everyone else).
if (!connectsso_transport_is_acceptable($app)) {
	connectsso_refuse(
		'the request did not arrive over TLS and no reverse proxy is declared in'
		. ' security_settings.ini (reverse_proxy_panel_allowed); single sign-on is disabled'
	);
}

//* ---------------------------------------------------------------- rate limit
//* Before the token is even looked at, so a guessing loop is bounded no matter
//* which check would have rejected it.
connectsso_gc($app, $connectsso_now);
if (connectsso_attempts($app, $connectsso_ip, $connectsso_now) >= CONNECTSSO_ATTEMPT_LIMIT) {
	connectsso_refuse('rate limit reached', 429);
}

//* An override file the operator got wrong is reported here, once per request,
//* and deliberately AFTER the rate-limit gate: this endpoint is unauthenticated,
//* so the limiter is the only thing that stops a broken connectsso.ini becoming
//* a sys_log flood. The mint half reports it too, behind its own auth gates.
connectsso_config_report($app);

//* ---------------------------------------------------------------- the token
//* GET is what a redirect can carry, so that is the primary form; POST is
//* accepted too, for callers able to submit a form (it keeps the token out of
//* access logs and browser history — see the README).
$connectsso_token = '';
if (isset($_POST[CONNECTSSO_TOKEN_PARAM])) {
	$connectsso_token = (string)$_POST[CONNECTSSO_TOKEN_PARAM];
} elseif (isset($_GET[CONNECTSSO_TOKEN_PARAM])) {
	$connectsso_token = (string)$_GET[CONNECTSSO_TOKEN_PARAM];
}

if (!connectsso_token_is_wellformed($connectsso_token)) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('malformed token');
}

$connectsso_hash = connectsso_token_hash($connectsso_token);
//* The clear token is no longer needed anywhere. Drop it so it cannot reach a
//* later var_dump, exception trace, or template variable.
$connectsso_token = '';
unset($_GET[CONNECTSSO_TOKEN_PARAM], $_POST[CONNECTSSO_TOKEN_PARAM], $_REQUEST[CONNECTSSO_TOKEN_PARAM]);

$connectsso_row = $app->db->queryOneRecord(
	'SELECT `token_id`, `token_hash`, `sys_userid`, `client_id`, `bind_ip`, `expires_at`, `used_at`'
	. ' FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `token_hash` = ?',
	$connectsso_hash
);

//* hash_equals over the stored hash. The index lookup above already did the
//* matching, and a 256-bit random token is not realistically attackable by
//* timing — this is belt-and-braces for the case where a future change makes
//* the lookup fuzzier (collation, LIKE, a cache).
if (!is_array($connectsso_row) || !hash_equals((string)$connectsso_row['token_hash'], $connectsso_hash)) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('unknown token');
}

if ((int)$connectsso_row['expires_at'] < $connectsso_now) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('expired token for client ' . (int)$connectsso_row['client_id']);
}

if ($connectsso_row['used_at'] !== null) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('REPLAY of an already-used token for client ' . (int)$connectsso_row['client_id'], 403);
}

//* IP binding is checked BEFORE the token is burned on purpose: someone who
//* scraped the token from a log should not be able to invalidate the real
//* customer's link simply by opening it from the wrong address.
if ((string)$connectsso_row['bind_ip'] !== ''
	&& !connectsso_ip_equals((string)$connectsso_row['bind_ip'], $connectsso_ip)
) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('bind-IP mismatch for client ' . (int)$connectsso_row['client_id']);
}

//* ---------------------------------------------------------------- burn it
//* THIS is the single-use guard, not the used_at check above: the conditional
//* UPDATE plus the affected-row count is atomic in the database, so of two
//* requests arriving together exactly one can proceed.
$connectsso_burned = $app->db->query(
	'UPDATE `' . CONNECTSSO_TOKEN_TABLE . '` SET `used_at` = ?, `used_ip` = ? WHERE `token_id` = ? AND `used_at` IS NULL',
	$connectsso_now,
	$connectsso_ip,
	(int)$connectsso_row['token_id']
);
//* affectedRows() alone is NOT proof the burn happened: it maps to
//* mysqli_affected_rows() on the CONNECTION (db_mysql.inc.php:604-606 ->
//* affected(), :507-512), so if the UPDATE itself never ran — query() returns
//* false on a securityScan() rejection or a query error (db_mysql.inc.php:331,
//* :275-332) — the connection still reports the row count of the PREVIOUS
//* statement (the token SELECT above, which matched exactly 1). Require BOTH:
//* the UPDATE executed, and it matched exactly the one still-unused row.
if ($connectsso_burned === false || (int)$app->db->affectedRows() !== 1) {
	connectsso_record_attempt($app, $connectsso_ip, $connectsso_now);
	connectsso_refuse('could not burn the token for client ' . (int)$connectsso_row['client_id']
		. ($connectsso_burned === false ? ' (the burn UPDATE failed)' : ' (already used: lost the race)'));
}

//* ------------------------------------------------------- re-check the user
//* State can have changed between minting and redeeming (seconds, but a
//* suspension is exactly the kind of thing that happens in those seconds).
$connectsso_user = $app->db->queryOneRecord(
	'SELECT * FROM `sys_user` WHERE `userid` = ?',
	(int)$connectsso_row['sys_userid']
);
if (!is_array($connectsso_user)) {
	connectsso_refuse('token names a panel user that no longer exists');
}
//* Lower-case the column names once, here, exactly as login/index.php does
//* before putting the row in the session — so every read below and the session
//* copy itself see the same keys.
$connectsso_user = $app->db->toLower($connectsso_user);

if ($connectsso_user['typ'] === 'admin') {
	//* Unreachable through the minting function, which refuses admins. Kept as
	//* a second gate so a hand-inserted row cannot become an admin login.
	connectsso_refuse('token names an administrator account');
}
if ((int)$connectsso_user['active'] !== 1) {
	connectsso_refuse('panel user ' . $connectsso_user['username'] . ' is not active');
}

$connectsso_client = $app->db->queryOneRecord(
	'SELECT `locked`, `canceled` FROM `client` WHERE `client_id` = ?',
	(int)$connectsso_row['client_id']
);
if (is_array($connectsso_client)
	&& ($connectsso_client['locked'] === 'y' || $connectsso_client['canceled'] === 'y')
) {
	connectsso_refuse('client ' . (int)$connectsso_row['client_id'] . ' is locked or cancelled');
}

//* Maintenance gate, mirroring the panel's own login form: login/index.php:79
//* refuses every non-admin login while $app->is_under_maintenance() is true
//* (the check honours maintenance_mode_exclude_ips — app.inc.php:353-368).
//* Without this, an SSO link would walk a customer straight past the closed
//* front door. Admins pass, exactly as at the form — unreachable today, since
//* both mint and redeem refuse admin accounts, but the parity is kept so the
//* two gates cannot drift. method_exists: is_under_maintenance() is newer
//* than the remote.d extension point, and a missing gate on an old panel must
//* degrade to core behaviour, not a fatal on the auth endpoint.
if (method_exists($app, 'is_under_maintenance')
	&& $app->is_under_maintenance()
	&& $connectsso_user['typ'] != 'admin'
) {
	connectsso_refuse('the panel is under maintenance', 503);
}

//* --------------------------------------------------------- the panel session
connectsso_clear_attempts($app, $connectsso_ip);

//* Session fixation defence. An attacker who can plant an ISPCSESS cookie in
//* the victim's browser must not end up holding the session this endpoint
//* authenticates. ISPConfig's own login makes this optional (Security settings
//* > session_regenerate_id, because of core issue #3827); here it is mandatory
//* and failing it is fatal — a token-based login with a predictable session id
//* is worse than no SSO at all.
if (session_status() !== PHP_SESSION_ACTIVE) {
	//* app.inc.php starts the session when $conf['start_session'] is true (the
	//* default). If it did not, there is nothing to authenticate into.
	connectsso_refuse('no PHP session is active; check $conf[start_session]');
}
if (!session_regenerate_id(true)) {
	connectsso_refuse('could not regenerate the session id');
}

$_SESSION = array();
$_SESSION['s']['id'] = session_id();
$_SESSION['s']['user'] = $connectsso_user;
$_SESSION['s']['user']['theme'] = (isset($connectsso_user['app_theme']) && $connectsso_user['app_theme'] != '')
	? $connectsso_user['app_theme']
	: 'default';
$_SESSION['s']['language'] = $app->functions->check_language($connectsso_user['language']);
$_SESSION['s']['theme'] = $_SESSION['s']['user']['theme'];

//* Start module + its menu files, exactly as login/index.php:112-116 does. The
//* module name is re-validated against core's own pattern (capp.php) because it
//* becomes part of an include path.
$connectsso_startmodule = isset($_SESSION['s']['user']['startmodule'])
	? (string)$_SESSION['s']['user']['startmodule']
	: '';
if (preg_match('/^[a-z]{2,20}$/i', $connectsso_startmodule)
	&& is_file(ISPC_WEB_PATH . '/' . $connectsso_startmodule . '/lib/module.conf.php')
) {
	$module = array();
	include ISPC_WEB_PATH . '/' . $connectsso_startmodule . '/lib/module.conf.php';
	include_menu_dir_files(ISPC_WEB_PATH . '/' . $connectsso_startmodule . '/lib/menu.d');
	$_SESSION['s']['module'] = $module;
}

//* Theme-compatibility gate (login/index.php:118-127): an incompatible theme is
//* reset to default rather than rendering a broken panel.
if ($_SESSION['s']['user']['theme'] != 'default') {
	$connectsso_theme_path = ISPC_THEMES_PATH . '/' . $_SESSION['s']['user']['theme'];
	if (!@is_dir($connectsso_theme_path)
		|| !@file_exists($connectsso_theme_path . '/ispconfig_version')
		|| trim(file_get_contents($connectsso_theme_path . '/ispconfig_version')) != ISPC_APP_VERSION
	) {
		$_SESSION['s']['user']['theme'] = 'default';
		$_SESSION['s']['theme'] = 'default';
	}
}

//* ------------------------------------------------------------- second factor
//* An SSO link replaces the PASSWORD. It does not replace the second factor:
//* park the session exactly the way login/index.php:143-158 parks it and hand
//* the visitor to the panel's own OTP page.
if (isset($connectsso_user['otp_type']) && $connectsso_user['otp_type'] != 'none') {
	$_SESSION['s_pending'] = $_SESSION['s'];
	unset($_SESSION['s']);
	$_SESSION['otp']['session_attempts'] = 0;
	$_SESSION['otp']['type'] = $connectsso_user['otp_type'];
	$_SESSION['otp']['data'] = $connectsso_user['otp_data'];

	connectsso_audit(
		$app,
		'accepted a login token for ' . $connectsso_user['username'] . '; handing over to two-factor authentication',
		true
	);
	session_write_close();
	header('Location: /login/otp.php');
	die();
}

//* --------------------------------------------------- forced password change
//* Same reasoning: if the panel would force a password change at the login
//* form, it forces one here (login/index.php:160-163). The redirect is written
//* out in full rather than calling core's redirect_to_password_change(), whose
//* Location header is relative to /login/.
if (is_file(ISPC_WEB_PATH . '/login/lib/password_check.inc.php')) {
	require_once ISPC_WEB_PATH . '/login/lib/password_check.inc.php';
	if (function_exists('is_password_change_required')
		&& is_password_change_required($app, $_SESSION['s']['user'])
	) {
		$_SESSION['s_pending'] = $_SESSION['s'];
		unset($_SESSION['s']);
		$_SESSION['force_password_change'] = true;

		connectsso_audit(
			$app,
			'accepted a login token for ' . $connectsso_user['username'] . '; a password change is required first',
			true
		);
		session_write_close();
		header('Location: /login/force_password_change.php');
		die();
	}
}

connectsso_audit($app, 'signed in ' . $connectsso_user['username'] . ' with a one-time token', true);

session_write_close();
//* Fixed destination. The request never gets to choose where it lands, which is
//* what keeps this page from being an open redirect.
header('Location: /index.php');
die();
