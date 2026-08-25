<?php

/*
 * ispconfig-sso — one-time panel login tokens for ISPConfig.
 * Copyright (c) 2026 Wade Beckett.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See ../../../../../../LICENSE.
 *
 * -----------------------------------------------------------------------------
 * Remote API extension: mint a short-lived, single-use panel-login token.
 *
 * HOW ISPCONFIG FINDS THIS FILE (verified, 3.3.1p1):
 *   interface/lib/classes/remoting_handler_base.inc.php:47 globs
 *     realpath(__DIR__) . '/../../web/*&#47;lib/classes/remote.d/*.inc.php'
 *   include_once's each match, and registers the class named
 *     'remoting_' . basename-without-.inc.php
 *   mapping EVERY public method of that class into the handler's method map
 *   (lines 58-74). No core file is modified to add a remote function; this is
 *   the same mechanism the ten built-in remote.d classes use.
 *
 *   Consequence worth knowing: get_class_methods() also sees the PUBLIC methods
 *   inherited from `remoting` — login, logout, get_function_list, server_get,
 *   server_get_all. The handler constructor re-pins the first three to the
 *   `remoting` instance immediately afterwards (lines 50-52); server_get and
 *   server_get_all end up dispatched to THIS class instead. That is harmless —
 *   they are inherited verbatim, not overridden — and it is what already
 *   happens between the built-in classes on a stock install (remoting_sites,
 *   loaded last, owns them today). It is also why this class declares exactly
 *   ONE public method of its own.
 *
 * WHY THIS MODULE EXISTS: ISPConfig core has no one-time-login API.
 * client_login_get() only validates credentials, and login($u, $p, true) mints
 * an API session, not a panel session. Without something like this, any
 * "Log in to panel" button — in a billing system, a support desk, an in-house
 * script — can only be implemented by storing the customer's panel password
 * and replaying it into the login form, which is what the existing
 * integrations had to do and exactly what this module exists to make
 * unnecessary. Nothing here is specific to one caller: the API contract is
 * the same for every consumer that holds a granted remote-API session.
 *
 * The clear token is returned ONCE, to the caller, and is never stored, logged
 * or re-derivable: the database holds only its SHA-256.
 */

//* Direct-request guard: this file sits under the panel docroot (both vhost
//* templates serve interface/web/, and neither denies a .php under lib/), and
//* requesting it over HTTP would otherwise fatal on `extends remoting` with
//* the class undefined. Legitimate loading — the remoting handler's glob, or
//* the tests — always has ISPC_ROOT_PATH (config.inc.php:85) or runs on the
//* CLI. Mirrors the guard in connectsso_lib.inc.php; see the rationale there.
if (!defined('ISPC_ROOT_PATH') && PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
	http_response_code(404);
	die();
}

require_once realpath(__DIR__ . '/../../connectsso_lib.inc.php');

class remoting_connectsso extends remoting {

	/**
	 * Mint a single-use panel-login token for one ISPConfig client.
	 *
	 * @param string $session_id remote API session (remoting::login)
	 * @param int    $client_id  client.client_id to log in as
	 * @param string $bind_ip    optional: the address the token may be redeemed
	 *                           FROM. This is the END USER's browser address,
	 *                           not the API caller's — the caller mints, the
	 *                           browser redeems. '' leaves the token unbound.
	 * @return array{token: string, path: string, expires_in: int, client_id: int, username: string}
	 * @throws SoapFault
	 */
	public function connect_sso_token_create($session_id, $client_id, $bind_ip = '') {
		global $app;

		//* Every exit from here is either the token or an AUDITED refusal.
		//* Core will not audit for us: checkPerm()'s own "REMOTE-LIB DENY" line
		//* is written at LOGLEVEL_WARN, and app.inc.php log() drops anything
		//* below $conf['log_priority'], which every shipped install sets to 2
		//* (interface/lib/app.inc.php:190-192,
		//* install/tpl/config.inc.php.master:145). A refused attempt to mint a
		//* password substitute must not be the one event that is recorded
		//* nowhere, so this function writes its own line at priority 2 to
		//* sys_log and to auth.log for each of them.
		if (!$this->checkPerm($session_id, CONNECTSSO_REMOTE_FUNCTION)) {
			$this->refuse(
				$client_id,
				'the remote user does not hold the ' . CONNECTSSO_REMOTE_FUNCTION . ' grant',
				// Verbatim core wording (remoting.inc.php) so existing clients
				// classify it as a permission problem, not an unknown fault.
				'permission_denied',
				'You do not have the permissions to access this function.'
			);
		}

		//* checkPerm() alone does NOT authorise this function. For a
		//* client_login session — a CUSTOMER who called login($u, $p, true),
		//* which any client with can_use_api = 'y' may do — checkPerm()
		//* returns true unconditionally ("permissions are checked at an other
		//* place", remoting.inc.php:542-547), and such sessions are stored
		//* with client_login = 1 and remote_functions = ''
		//* (remoting.inc.php:99-156). Trusting checkPerm() here would let any
		//* API-enabled customer mint a panel login for any other non-admin
		//* client: cross-tenant panel takeover. A legitimate consumer — a
		//* billing system, a support tool, a script — authenticates as a
		//* REMOTE USER (client_login = 0), never as a client, so client
		//* sessions are refused outright, with core's verbatim wording,
		//* because WHY is nobody's business but the log's.
		//* Fail closed: only a session that PROVABLY carries client_login = 0
		//* (the column is NOT NULL in remote_session) may proceed — a missing
		//* key must refuse, not default to "remote user".
		$session = $this->getSession($session_id);
		if (!is_array($session) || !isset($session['client_login']) || (int)$session['client_login'] !== 0) {
			$this->refuse(
				$client_id,
				'the API session is a client session, not a remote user',
				'permission_denied',
				'You do not have the permissions to access this function.'
			);
		}

		//* TLS GATE. This function hands back a password substitute that the
		//* caller is about to put in a URL. On a plaintext request the response
		//* is readable on the wire, and an interceptor who redeems the token
		//* first wins outright — single use and a 45-second TTL do not help
		//* when the attacker is ahead of the customer's browser. So: refuse,
		//* unless the operator declared a reverse proxy in ISPConfig's own
		//* security_settings.ini, the one topology where PHP cannot see the
		//* real scheme and TLS termination is the proxy's job.
		//* Placed AFTER the two authorisation gates on purpose: only a session
		//* that already proved itself can write these audit lines, so a panel
		//* accidentally served over HTTP cannot be turned into a log flood by
		//* anonymous requests.
		if (!connectsso_transport_is_acceptable($app)) {
			$this->refuse(
				$client_id,
				'the API request did not arrive over TLS and no reverse proxy is declared'
				. ' in security_settings.ini (reverse_proxy_panel_allowed)',
				'sso_insecure_transport',
				'Single sign-on requires an encrypted (https) connection to the panel.'
			);
		}

		$client_id = intval($client_id);
		if ($client_id < 1) {
			$this->refuse(
				$client_id,
				'the client id is not a positive integer',
				'invalid_client_id',
				'The client id must be an integer greater than zero.'
			);
		}

		$bind_ip = trim((string)$bind_ip);
		if ($bind_ip !== '' && !filter_var($bind_ip, FILTER_VALIDATE_IP)) {
			$this->refuse(
				$client_id,
				'the bind IP is not a literal address',
				'invalid_bind_ip',
				'The bind IP address is invalid.'
			);
		}

		//* The panel user this client logs in as. sys_user.client_id is set by
		//* remoting_lib::ispconfig_sysuser_add() when the client is created.
		$user = $app->db->queryOneRecord(
			'SELECT `userid`, `username`, `active`, `typ` FROM `sys_user` WHERE `client_id` = ? ORDER BY `userid` ASC',
			$client_id
		);
		if (!is_array($user)) {
			$this->refuse(
				$client_id,
				'no sys_user row carries that client id',
				'sso_no_user',
				'There is no panel user for this client id.'
			);
		}

		//* Never mint for an administrator. Tokens bypass password and IP
		//* checks by design; an admin token is a full panel takeover, and no
		//* legitimate caller of this function needs one.
		//* NOTE the boundary this does NOT draw: a RESELLER's panel user is
		//* typ = 'user' like any other customer (remoting_lib.inc.php:329 sets
		//* $type = 'user' for every client the API creates; limit_client > 0
		//* only adds the `client` module, :311-313). A reseller is therefore
		//* mintable, and their panel session administers their sub-clients.
		//* That is deliberate — resellers are sold and supported through the
		//* same systems customers are — but it is documented in the README's
		//* security model rather than left implied.
		if ($user['typ'] === 'admin') {
			$this->refuse(
				$client_id,
				'the target panel user ' . $user['username'] . ' is an administrator',
				'sso_refused',
				'Single sign-on is not available for administrator accounts.'
			);
		}
		if ((int)$user['active'] !== 1) {
			$this->refuse(
				$client_id,
				'the target panel user ' . $user['username'] . ' is not active',
				'sso_user_inactive',
				'The panel user for this client is not active.'
			);
		}

		//* A locked or cancelled client is a SUSPENDED customer. Handing out a
		//* login that ignores that would quietly undo the suspension the
		//* billing system just applied.
		$client = $app->db->queryOneRecord(
			'SELECT `locked`, `canceled` FROM `client` WHERE `client_id` = ?',
			$client_id
		);
		if (is_array($client) && ($client['locked'] === 'y' || $client['canceled'] === 'y')) {
			$this->refuse(
				$client_id,
				'the client account is locked or cancelled',
				'sso_client_locked',
				'The client account is locked; single sign-on is refused.'
			);
		}

		$now = time();
		connectsso_gc($app, $now);

		//* One live token per client: minting a new one invalidates any unused
		//* predecessor. That caps how many redeemable tokens a caller can
		//* accumulate (mint-side rate limit) and means an abandoned SSO click
		//* cannot be redeemed later from a browser history entry.
		$app->db->query(
			'DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `client_id` = ? AND `used_at` IS NULL',
			$client_id
		);

		$token = bin2hex(random_bytes(CONNECTSSO_TOKEN_BYTES));

		//* $session was fetched by the client_login gate above.
		$created_by = isset($session['remote_userid']) ? (int)$session['remote_userid'] : 0;

		$app->db->query(
			'INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`'
			. ' (`token_hash`, `sys_userid`, `client_id`, `bind_ip`, `created_at`, `expires_at`, `created_by`)'
			. ' VALUES (?, ?, ?, ?, ?, ?, ?)',
			connectsso_token_hash($token),
			(int)$user['userid'],
			$client_id,
			$bind_ip,
			$now,
			$now + CONNECTSSO_TOKEN_TTL,
			$created_by
		);

		//* auth_log = true: issuing a token CREATES a login credential, so the
		//* record belongs in auth.log beside ISPConfig's own login records —
		//* sys_log alone is browsable panel state, not a durable auth trail.
		connectsso_audit(
			$app,
			'minted a login token for client ' . $client_id . ' (user ' . $user['username'] . ')'
			. ($bind_ip === '' ? ', unbound' : ', bound to ' . $bind_ip)
			. ' for remote user ' . $created_by,
			true
		);

		return array(
			'token'      => $token,
			'path'       => CONNECTSSO_ENDPOINT_PATH,
			'expires_in' => CONNECTSSO_TOKEN_TTL,
			'client_id'  => $client_id,
			'username'   => (string)$user['username'],
		);
	}

	/**
	 * Audit a refused mint and throw. The internal $reason is written to
	 * sys_log and auth.log; the caller only ever sees $message, which for the
	 * authorisation paths is core's verbatim wording.
	 *
	 * PRIVATE on purpose. remoting_handler_base maps every method
	 * get_class_methods() reports into the remote API's method map, and that
	 * call is made from outside the class, so only public methods are exposed
	 * — this class still declares exactly one public method of its own, which
	 * tests/run.php asserts.
	 *
	 * @param mixed  $client_id as received, before validation
	 * @param string $reason    internal, for the audit trail only
	 * @param string $code      SoapFault code
	 * @param string $message   SoapFault message, seen by the caller
	 * @return void
	 * @throws SoapFault always
	 */
	private function refuse($client_id, $reason, $code, $message) {
		global $app;

		connectsso_audit(
			$app,
			'refused to mint a token for client ' . intval($client_id) . ': ' . $reason,
			true
		);

		throw new SoapFault($code, $message);
	}
}
