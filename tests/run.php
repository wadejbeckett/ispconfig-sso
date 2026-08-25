<?php
/**
 * ispconfig-sso — standalone harness.
 * Copyright (c) 2026 Wade Beckett. GPLv3 — see ../LICENSE.
 *
 * The panel-side code cannot run under an ordinary PHPUnit suite: it needs
 * ISPConfig's runtime ($app, its db class, the `remoting` base class). What it
 * CAN be checked against is a faithful stand-in for the two contracts it
 * depends on — core's remote.d auto-loader and core's $app/db surface — and
 * that is what this harness does. No dependencies, no database, no panel, and
 * nothing from any consuming project.
 *
 *   php tests/run.php
 *
 * It covers the token MINT half (the remote.d class) plus the shared helpers.
 * The REDEEM half (index.php) is a top-level script that redirects and exits,
 * so it stays manual — see the checklist at the bottom of this file, and run it
 * on a real panel before shipping.
 */

$FAILURES = 0;
$CHECKS   = 0;

function ok($condition, $label) {
    global $FAILURES, $CHECKS;
    $CHECKS++;
    if ($condition) {
        echo "  ok    $label\n";
    } else {
        echo "  FAIL  $label\n";
        $FAILURES++;
    }
}

function section($title) {
    echo "\n== $title\n";
}

/**
 * Throws-and-returns-the-message helper: runs $fn and returns the SoapFault
 * message, or '' when nothing was thrown.
 */
function fault_from(callable $fn) {
    try {
        $fn();
    } catch (SoapFault $e) {
        return $e->getMessage();
    }

    return '';
}

// ---------------------------------------------------------------------------
// Stand-in for ISPConfig's `remoting` base class, with the same PUBLIC surface
// as 3.3.1p1 (login, logout, server_get, server_get_all, get_function_list) and
// the same protected auth helpers our class inherits.
// ---------------------------------------------------------------------------
class remoting {
    public static $perm = true;
    //* client_login = 0 is the REMOTE USER case. Core's login($u,$p,true)
    //* stores customer sessions with client_login = 1 and remote_functions = ''
    //* (remoting.inc.php:99-156), and checkPerm() returns TRUE for those
    //* unconditionally (remoting.inc.php:542-547) — the mint function must
    //* refuse them itself (asserted below).
    public static $session = array('remote_userid' => 42, 'client_login' => 0);

    private $_methods = array();

    public function __construct($methods = array()) { $this->_methods = $methods; }
    public function login($username, $password, $client_login = false) {}
    public function logout($session_id) {}
    public function server_get($session_id, $server_id = null, $section = '') {}
    public function server_get_all($session_id) {}
    public function get_function_list($session_id) { return $this->_methods; }

    protected function checkPerm($session_id, $function_name) { return self::$perm; }
    protected function getSession($session_id) { return self::$session; }
}

// ---------------------------------------------------------------------------
// Stand-in for $app / $app->db. queryOneRecord() serves queued rows in order,
// which is enough because the module's read order is fixed and short; query()
// records the statement and its parameters so writes can be asserted.
// ---------------------------------------------------------------------------
class FakeDb {
    public $rows = array();      // queued queryOneRecord() results
    public $writes = array();    // [sql, params...] of every query()
    public $affected = 1;

    public function queryOneRecord($sql) {
        return array_shift($this->rows);
    }

    public function query($sql) {
        $args = func_get_args();
        $this->writes[] = $args;

        return true;
    }

    public function affectedRows() { return $this->affected; }
    public function toLower($record) {
        $out = array();
        if (is_array($record)) {
            foreach ($record as $k => $v) { $out[strtolower($k)] = $v; }
        }

        return $out;
    }

    /** All recorded statements whose SQL contains $needle. */
    public function writesMatching($needle) {
        $hits = array();
        foreach ($this->writes as $w) {
            if (strpos($w[0], $needle) !== false) { $hits[] = $w; }
        }

        return $hits;
    }
}

/**
 * Stand-in for $app->getconf. Only get_security_config('permissions') is used,
 * and only for `reverse_proxy_panel_allowed` — the operator's own declaration
 * that something in front of the panel terminates TLS, which is the one case
 * where PHP cannot see the real request scheme.
 */
class FakeGetconf {
    public $permissions = array('reverse_proxy_panel_allowed' => 'none');

    public function get_security_config($section = '') {
        if ($section === 'permissions') { return $this->permissions; }

        return array('permissions' => $this->permissions);
    }
}

class FakeApp {
    public $db;
    public $getconf;
    public $log = array();
    public $authlog = array();
    //* Mirrors a SHIPPED install, not the dev tree: app.inc.php log() drops
    //* anything below $conf['log_priority'] (interface/lib/app.inc.php:190-192),
    //* and the installer writes log_priority = 2 on every distribution
    //* (install/tpl/config.inc.php.master:145 <- install/dist/conf/*.conf.php:39,
    //* ispconfig_log_priority = 2). Without this gate the harness would assert
    //* an audit trail that a real panel silently discards.
    public $log_priority = 2;

    public function __construct() { $this->db = new FakeDb(); $this->getconf = new FakeGetconf(); }
    public function log($msg, $priority = 0) {
        if ($priority >= $this->log_priority) { $this->log[] = $msg; }
    }
    public function auth_log($msg) { $this->authlog[] = $msg; }
}

// ---------------------------------------------------------------------------
section('remote.d auto-loader contract (remoting_handler_base.inc.php:44-74)');
// ---------------------------------------------------------------------------

$module_root = realpath(__DIR__ . '/..');
$files = glob($module_root . '/interface/web/*/lib/classes/remote.d/*.inc.php');
ok(count($files) === 1, 'exactly one file matches core\'s module glob');

$methods = array();
foreach ($files as $file) {
    $class_name = 'remoting_' . str_replace('.inc.php', '', basename($file));
    include_once $file;
    ok(class_exists($class_name, false), "core would register class $class_name");
    $instance = new $class_name();
    foreach (get_class_methods($instance) as $method) { $methods[$method] = $class_name; }
}
//* Core re-pins these three to the `remoting` instance right after loading.
$methods['login'] = 'remoting';
$methods['logout'] = 'remoting';
$methods['get_function_list'] = 'remoting';

ok(isset($methods['connect_sso_token_create'])
    && $methods['connect_sso_token_create'] === 'remoting_connectsso',
    'connect_sso_token_create dispatches to remoting_connectsso');
ok($methods['login'] === 'remoting' && $methods['logout'] === 'remoting'
    && $methods['get_function_list'] === 'remoting',
    'login/logout/get_function_list stay with core');

$own = array();
$reflection = new ReflectionClass('remoting_connectsso');
foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
    if ($m->getDeclaringClass()->getName() === 'remoting_connectsso') { $own[] = $m->getName(); }
}
sort($own);
ok($own === array('connect_sso_token_create'), 'declares exactly one public method of its own');

//* get_class_methods() also reports the inherited public methods, so the loader
//* points those at our class too. That is core behaviour for EVERY remote.d
//* class (on a stock panel remoting_sites, loaded last, owns them) and is safe
//* only while we inherit them verbatim — assert that we add nothing else.
$taken = array_keys(array_filter($methods, function ($c) { return $c === 'remoting_connectsso'; }));
sort($taken);
ok(array_diff($taken, array('__construct', 'connect_sso_token_create', 'server_get', 'server_get_all')) === array(),
    'takes over nothing beyond its own method and verbatim inherits (' . implode(', ', $taken) . ')');

//* json_handler.inc.php maps JSON body keys to PARAMETER NAMES by reflection,
//* so renaming a parameter is a wire-breaking change.
$rm = new ReflectionMethod('remoting_connectsso', 'connect_sso_token_create');
$names = array();
foreach ($rm->getParameters() as $p) { $names[] = $p->getName(); }
ok($names === array('session_id', 'client_id', 'bind_ip'),
    'wire parameter names are session_id, client_id, bind_ip');

// ---------------------------------------------------------------------------
section('shared helpers');
// ---------------------------------------------------------------------------

ok(CONNECTSSO_TOKEN_TTL > 0 && CONNECTSSO_TOKEN_TTL <= 60, 'token TTL is within 60 seconds');
ok(CONNECTSSO_TOKEN_BYTES >= 32, 'at least 32 bytes of entropy');
ok(CONNECTSSO_REMOTE_FUNCTION === 'connect_sso_token_create', 'grant name matches the method name');

$sample = bin2hex(random_bytes(CONNECTSSO_TOKEN_BYTES));
ok(connectsso_token_is_wellformed($sample), 'a real token is accepted');
ok(!connectsso_token_is_wellformed(strtoupper($sample)), 'uppercase hex is rejected');
ok(!connectsso_token_is_wellformed(substr($sample, 0, -1)), 'a short token is rejected');
ok(!connectsso_token_is_wellformed($sample . 'a'), 'a long token is rejected');
ok(!connectsso_token_is_wellformed(''), 'an empty token is rejected');
ok(!connectsso_token_is_wellformed(null), 'a null token is rejected');
ok(!connectsso_token_is_wellformed(array($sample)), 'an array is rejected');
ok(!connectsso_token_is_wellformed(str_repeat('z', strlen($sample))), 'non-hex is rejected');
ok(connectsso_token_hash($sample) === hash('sha256', $sample), 'the stored value is sha256(token)');
ok(connectsso_token_hash($sample) !== $sample, 'the stored value is not the token');

ok(connectsso_ip_equals('192.0.2.1', '192.0.2.1'), 'identical IPv4 matches');
ok(!connectsso_ip_equals('192.0.2.1', '192.0.2.2'), 'different IPv4 does not');
ok(connectsso_ip_equals('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001'),
    'equivalent IPv6 spellings match');
ok(!connectsso_ip_equals('2001:db8::1', '192.0.2.1'), 'IPv6 does not match IPv4');
ok(!connectsso_ip_equals('not-an-ip', 'not-an-ip'), 'garbage never compares equal');
ok(!connectsso_ip_equals('', ''), 'empty never compares equal');

// ---------------------------------------------------------------------------
section('transport security (TLS gate)');
// ---------------------------------------------------------------------------
//* A token is a password substitute that travels in a URL. Over plain HTTP the
//* mint response, the redirect and the panel session that follows are all
//* readable by anything on the path, and the single-use/45-second design does
//* nothing about an interceptor who simply redeems the token first. So both
//* halves refuse unless the request is TLS — or unless the operator has told
//* ISPConfig itself that a reverse proxy sits in front, which is the one case
//* where PHP genuinely cannot see the scheme.

$saved_server = $_SERVER;

unset($_SERVER['HTTPS'], $_SERVER['REQUEST_SCHEME']);
ok(!connectsso_request_is_secure(), 'no HTTPS marker -> not secure');
$_SERVER['HTTPS'] = 'off';
ok(!connectsso_request_is_secure(), 'HTTPS=off -> not secure');
$_SERVER['HTTPS'] = 'OFF';
ok(!connectsso_request_is_secure(), 'HTTPS=OFF -> not secure (case-insensitive)');
$_SERVER['HTTPS'] = '';
ok(!connectsso_request_is_secure(), 'HTTPS empty -> not secure');
$_SERVER['HTTPS'] = 'on';
ok(connectsso_request_is_secure(), 'HTTPS=on -> secure');
$_SERVER['HTTPS'] = '1';
ok(connectsso_request_is_secure(), 'HTTPS=1 (IIS-style) -> secure');
unset($_SERVER['HTTPS']);
$_SERVER['REQUEST_SCHEME'] = 'https';
ok(connectsso_request_is_secure(), 'REQUEST_SCHEME=https -> secure');
$_SERVER['REQUEST_SCHEME'] = 'http';
ok(!connectsso_request_is_secure(), 'REQUEST_SCHEME=http -> not secure');
unset($_SERVER['REQUEST_SCHEME']);

$probe = new FakeApp();
ok(!connectsso_proxy_declared($probe),
    'reverse_proxy_panel_allowed=none (the shipped default) declares no proxy');
$probe->getconf->permissions = array('reverse_proxy_panel_allowed' => 'sites');
ok(connectsso_proxy_declared($probe), 'reverse_proxy_panel_allowed=sites declares a proxy');
$probe->getconf->permissions = array('reverse_proxy_panel_allowed' => 'all');
ok(connectsso_proxy_declared($probe), 'reverse_proxy_panel_allowed=all declares a proxy');
$probe->getconf->permissions = array();
ok(!connectsso_proxy_declared($probe), 'a security_settings.ini without the key declares no proxy');
$probe->getconf = null;
ok(!connectsso_proxy_declared($probe), 'an $app with no getconf fails closed');
ok(!connectsso_proxy_declared(null), 'a missing $app fails closed');

$probe = new FakeApp();
$_SERVER['HTTPS'] = 'on';
ok(connectsso_transport_is_acceptable($probe), 'TLS is acceptable on a stock panel');
unset($_SERVER['HTTPS']);
ok(!connectsso_transport_is_acceptable($probe), 'plain HTTP is refused on a stock panel');
$probe->getconf->permissions = array('reverse_proxy_panel_allowed' => 'all');
ok(connectsso_transport_is_acceptable($probe),
    'plain HTTP is accepted only where the operator declared a reverse proxy');

$_SERVER = $saved_server;
//* Everything below drives the mint function, which now requires TLS.
$_SERVER['HTTPS'] = 'on';

// ---------------------------------------------------------------------------
section('every query survives ISPConfig\'s SQL scanner');
// ---------------------------------------------------------------------------
//* db_mysql.inc.php runs securityScan() over the FINAL query string and, when
//* it objects, query() returns false and the caller sees an empty result. There
//* is no exception and nothing in the module's own log — a statement that trips
//* it fails silently and permanently. It rejects ';', '#', '--', '/*', '*/' and
//* unbalanced backticks/quotes outside string literals, which is easy to walk
//* into with a hand-written DELETE. So: replay it here.

/** Verbatim port of db_mysql.inc.php securityScan(). Returns '' when accepted. */
function sql_scan($string) {
    $string = trim($string);
    if (substr($string, -1) == ';') { $string = substr($string, 0, -1); }
    $chars = array(';', '#', '/*', '*/', '--', '\\\'', '\\"');
    $string = str_replace('\\\\', '', $string);
    $string = preg_replace('/(^|[^\\\])([\'"])\\2/is', '$1', $string);
    $string = preg_replace('/(^|[^\\\])([\'"])(.*?[^\\\])\\2/is', '$1', $string);
    if (substr_count($string, '`') % 2 != 0
        || substr_count($string, "'") % 2 != 0
        || substr_count($string, '"') % 2 != 0) {
        return 'unbalanced quoting';
    }
    foreach ($chars as $char) {
        if (strpos($string, $char) !== false) { return "contains '$char'"; }
    }

    return '';
}

//* Transcribed from the two source files. KEEP IN SYNC — the tripwire below
//* fails if the source gains or loses a statement.
$statements = array(
    'DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `expires_at` < ? AND (`used_at` IS NULL OR `used_at` < ?)',
    'DELETE FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `last_attempt` < ?',
    'SELECT `attempts` FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `ip_hash` = ? AND `last_attempt` > ?',
    'INSERT INTO `' . CONNECTSSO_ATTEMPT_TABLE . '` (`ip_hash`, `attempts`, `first_attempt`, `last_attempt`) VALUES (?, 1, ?, ?)'
        . ' ON DUPLICATE KEY UPDATE `attempts` = IF(`last_attempt` <= ?, 1, `attempts` + 1),'
        . ' `first_attempt` = IF(`last_attempt` <= ?, ?, `first_attempt`), `last_attempt` = ?',
    'DELETE FROM `' . CONNECTSSO_ATTEMPT_TABLE . '` WHERE `ip_hash` = ?',
    'SELECT `userid`, `username`, `active`, `typ` FROM `sys_user` WHERE `client_id` = ? ORDER BY `userid` ASC',
    'SELECT `locked`, `canceled` FROM `client` WHERE `client_id` = ?',
    'DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `client_id` = ? AND `used_at` IS NULL',
    'INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '` (`token_hash`, `sys_userid`, `client_id`, `bind_ip`, `created_at`, `expires_at`, `created_by`) VALUES (?, ?, ?, ?, ?, ?, ?)',
    'SELECT `token_id`, `token_hash`, `sys_userid`, `client_id`, `bind_ip`, `expires_at`, `used_at` FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `token_hash` = ?',
    'UPDATE `' . CONNECTSSO_TOKEN_TABLE . '` SET `used_at` = ?, `used_ip` = ? WHERE `token_id` = ? AND `used_at` IS NULL',
    'SELECT * FROM `sys_user` WHERE `userid` = ?',
);

$rejected = array();
foreach ($statements as $sql) {
    //* queryOneRecord() appends this before the scan runs, so scan both forms.
    foreach (array('', ' LIMIT 0,1') as $suffix) {
        $why = sql_scan($sql . $suffix);
        if ($why !== '') { $rejected[] = substr($sql, 0, 40) . ' -> ' . $why; }
    }
}
ok($rejected === array(), count($statements) . ' statements accepted by securityScan()'
    . ($rejected ? ': ' . implode('; ', $rejected) : ''));

//* Tripwire: the module's SQL lives in string literals that are concatenated
//* with table-name constants, so it cannot be extracted mechanically. Counting
//* the literal STARTS at least catches a statement added without being listed
//* above. 13 occurrences, 12 distinct — the client lock/cancel SELECT appears
//* in both halves. (The rate-limit upsert's ON DUPLICATE KEY UPDATE sits in a
//* continuation literal, so it does not start with a quoted keyword and is
//* counted once.)
$sql_src = '';
foreach (array(
    '/interface/web/connectsso/index.php',
    '/interface/web/connectsso/lib/connectsso_lib.inc.php',
    '/interface/web/connectsso/lib/classes/remote.d/connectsso.inc.php',
) as $f) { $sql_src .= file_get_contents($module_root . $f); }
preg_match_all('/\'(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/', $sql_src, $sql_hits);
ok(count($sql_hits[0]) === 13,
    'the source still contains 13 SQL literals (found ' . count($sql_hits[0]) . '); update the list above if this changes');

// ---------------------------------------------------------------------------
section('connect_sso_token_create');
// ---------------------------------------------------------------------------

/**
 * Build a fresh $app with the read sequence the mint function performs:
 * sys_user row, then client row.
 */
function scenario($user, $client) {
    global $app;
    $app = new FakeApp();
    $app->db->rows = array($user, $client);

    return $app;
}

$active_user = array('userid' => 9, 'username' => 'acmeltd', 'active' => 1, 'typ' => 'user');
$open_client = array('locked' => 'n', 'canceled' => 'n');

$sso = new remoting_connectsso();

remoting::$perm = false;
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'You do not have the permissions to access this function.',
    'no grant -> core\'s verbatim permission_denied wording');
ok($app->db->writes === array(), 'no grant -> nothing is written');

remoting::$perm = true;

//* CROSS-TENANT GUARD. remoting::checkPerm() (remoting.inc.php:532-556) trusts
//* client_login sessions unconditionally ("permissions are checked at an other
//* place", :542-547) — and login($u,$p,true) hands one to ANY customer whose
//* client record has can_use_api = 'y' (remoting.inc.php:99-156). If the mint
//* function relied on checkPerm() alone, such a customer could mint a panel
//* login for any other non-admin client. The billing system authenticates as a
//* REMOTE USER (client_login = 0), so client sessions are refused outright.
remoting::$session = array('remote_userid' => 42, 'client_login' => 1);
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'You do not have the permissions to access this function.',
    'a client_login session is refused even though checkPerm() returns true for it');
ok($app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`') === array(),
    'a client_login session mints nothing');
ok(strpos(implode(' | ', $app->log), 'client session') !== false,
    'the client_login refusal is audited at a priority a shipped install keeps');

//* Fail-closed: a session record that cannot PROVE client_login = 0 refuses.
remoting::$session = array('remote_userid' => 42);
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'You do not have the permissions to access this function.',
    'a session without a client_login flag is refused (fail closed)');
remoting::$session = array('remote_userid' => 42, 'client_login' => 0);

//* TLS GATE. A minted token is a password substitute that the caller is about
//* to put in a URL. Over plain HTTP the mint response itself is readable on the
//* wire, and an interceptor can redeem the token before the customer's browser
//* does — single use and a 45-second TTL do not help when the attacker is
//* first. Refuse, unless the operator declared a reverse proxy in ISPConfig's
//* own security_settings.ini (the one case where PHP cannot see the scheme).
unset($_SERVER['HTTPS'], $_SERVER['REQUEST_SCHEME']);
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'Single sign-on requires an encrypted (https) connection to the panel.',
    'minting over plain HTTP is refused');
ok($app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`') === array(),
    'a plain-HTTP request mints nothing');
ok(strpos(implode(' | ', $app->log), 'not arrive over') !== false,
    'the plain-HTTP refusal is audited');

scenario($active_user, $open_client);
$app->getconf->permissions = array('reverse_proxy_panel_allowed' => 'all');
$proxied = $sso->connect_sso_token_create('sid', 5, '');
ok(is_array($proxied) && connectsso_token_is_wellformed($proxied['token']),
    'a declared reverse proxy is trusted to have terminated TLS');

$_SERVER['HTTPS'] = 'on';

scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 0, ''); })
    === 'The client id must be an integer greater than zero.', 'client id 0 is refused');
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', -3, ''); }) !== '',
    'a negative client id is refused');
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 'abc', ''); }) !== '',
    'a non-numeric client id is refused');

scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, 'evil.example.com'); })
    === 'The bind IP address is invalid.', 'a hostname bind value is refused');
scenario($active_user, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, '999.1.1.1'); }) !== '',
    'a malformed IP bind value is refused');

scenario(null, $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'There is no panel user for this client id.', 'a client with no panel user is refused');

scenario(array('userid' => 1, 'username' => 'admin', 'active' => 1, 'typ' => 'admin'), $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'Single sign-on is not available for administrator accounts.',
    'an administrator account is refused');

scenario(array('userid' => 9, 'username' => 'acmeltd', 'active' => 0, 'typ' => 'user'), $open_client);
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'The panel user for this client is not active.', 'a blocked panel user is refused');

scenario($active_user, array('locked' => 'y', 'canceled' => 'n'));
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); })
    === 'The client account is locked; single sign-on is refused.', 'a locked client is refused');

scenario($active_user, array('locked' => 'n', 'canceled' => 'y'));
ok(fault_from(function () use ($sso) { $sso->connect_sso_token_create('sid', 5, ''); }) !== '',
    'a cancelled client is refused');

//* Every refusal above must be a refusal, not a half-mint: the last scenario
//* left $app in place, so assert nothing was written on the way out.
ok($app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`') === array(),
    'a refused mint inserts no token row');

// ---------------------------------------------------------------------------
section('EVERY mint refusal is audited to both logs');
// ---------------------------------------------------------------------------
//* The README promises an audit line for every mint, every refusal and every
//* sign-in. Core will not supply one: checkPerm()'s own "REMOTE-LIB DENY" is
//* written at LOGLEVEL_WARN, which app.inc.php log() DROPS on every shipped
//* install (log_priority = 2). So each refusal below must write its own line,
//* at priority 2, to sys_log AND to auth.log — and none of them may contain a
//* token. This table is the enumeration: add a refusal to the function without
//* adding it here and the count assertion at the end fails.
$refusals = array(
    'missing grant' => array(
        'perm' => false, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => $active_user, 'client' => $open_client, 'args' => array(5, ''),
    ),
    'client_login session' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 1),
        'user' => $active_user, 'client' => $open_client, 'args' => array(5, ''),
    ),
    'session with no client_login flag' => array(
        'perm' => true, 'session' => array('remote_userid' => 42),
        'user' => $active_user, 'client' => $open_client, 'args' => array(5, ''),
    ),
    'plain HTTP' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => $active_user, 'client' => $open_client, 'args' => array(5, ''),
        'insecure' => true,
    ),
    'bad client id' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => $active_user, 'client' => $open_client, 'args' => array(0, ''),
    ),
    'bad bind ip' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => $active_user, 'client' => $open_client, 'args' => array(5, 'evil.example.com'),
    ),
    'no panel user' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => null, 'client' => $open_client, 'args' => array(5, ''),
    ),
    'administrator target' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => array('userid' => 1, 'username' => 'admin', 'active' => 1, 'typ' => 'admin'),
        'client' => $open_client, 'args' => array(5, ''),
    ),
    'inactive panel user' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => array('userid' => 9, 'username' => 'acmeltd', 'active' => 0, 'typ' => 'user'),
        'client' => $open_client, 'args' => array(5, ''),
    ),
    'locked client' => array(
        'perm' => true, 'session' => array('remote_userid' => 42, 'client_login' => 0),
        'user' => $active_user, 'client' => array('locked' => 'y', 'canceled' => 'n'),
        'args' => array(5, ''),
    ),
);

$unaudited = array();
foreach ($refusals as $label => $case) {
    remoting::$perm = $case['perm'];
    remoting::$session = $case['session'];
    if (!empty($case['insecure'])) {
        unset($_SERVER['HTTPS'], $_SERVER['REQUEST_SCHEME']);
    } else {
        $_SERVER['HTTPS'] = 'on';
    }
    scenario($case['user'], $case['client']);
    $message = fault_from(function () use ($sso, $case) {
        $sso->connect_sso_token_create('sid', $case['args'][0], $case['args'][1]);
    });
    $sys  = implode(' | ', $app->log);
    $auth = implode(' | ', $app->authlog);
    if ($message === ''
        || strpos($sys, '[connectsso] refused') === false
        || strpos($auth, '[connectsso] refused') === false
        || $app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`') !== array()) {
        $unaudited[] = $label;
    }
}
$_SERVER['HTTPS'] = 'on';
remoting::$perm = true;
remoting::$session = array('remote_userid' => 42, 'client_login' => 0);

ok(count($refusals) === 10, 'the refusal table still enumerates 10 paths (found ' . count($refusals) . ')');
ok($unaudited === array(),
    'every mint refusal writes an audit line to sys_log AND auth.log and mints nothing'
    . ($unaudited ? ': ' . implode(', ', $unaudited) . ' did not' : ''));

//* ---- happy path ----
scenario($active_user, $open_client);
$result = $sso->connect_sso_token_create('sid', 5, '203.0.113.9');

ok(is_array($result), 'returns an array');
ok(isset($result['token']) && connectsso_token_is_wellformed($result['token']),
    'the returned token is well-formed');
ok($result['path'] === CONNECTSSO_ENDPOINT_PATH, 'reports its endpoint path');
ok($result['expires_in'] === CONNECTSSO_TOKEN_TTL, 'reports its TTL');
ok($result['client_id'] === 5, 'echoes the client id as an int');
ok($result['username'] === 'acmeltd', 'reports the panel username');

$inserts = $app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`');
ok(count($inserts) === 1, 'exactly one token row is inserted');
$insert = $inserts[0];
ok($insert[1] === hash('sha256', $result['token']), 'the row stores sha256(token)');
ok($insert[1] !== $result['token'], 'the row does NOT store the token');
ok(!in_array($result['token'], $insert, true), 'the clear token appears in no INSERT parameter');
ok((int)$insert[2] === 9, 'the row targets the panel user id');
ok((int)$insert[3] === 5, 'the row targets the client id');
ok($insert[4] === '203.0.113.9', 'the bind IP is stored');
ok((int)$insert[6] - (int)$insert[5] === CONNECTSSO_TOKEN_TTL, 'expiry is created_at + TTL');
ok((int)$insert[7] === 42, 'the minting remote user id is recorded');

$deletes = $app->db->writesMatching('DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `client_id`');
ok(count($deletes) === 1 && (int)$deletes[0][1] === 5,
    'any unused predecessor token for that client is deleted first');

$gc = $app->db->writesMatching('DELETE FROM `' . CONNECTSSO_TOKEN_TABLE . '` WHERE `expires_at`');
ok(count($gc) === 1, 'expired tokens are garbage-collected on every mint');

$audit = implode(' | ', $app->log);
ok(strpos($audit, 'minted a login token for client 5') !== false,
    'the mint is audited at a priority a shipped install keeps (log_priority = 2)');
ok(strpos($audit, $result['token']) === false, 'the audit line contains no token');
ok(strpos($audit, hash('sha256', $result['token'])) === false, 'the audit line contains no token hash');
//* Token issuance is the creation of a login credential, so it must ALSO land
//* in the panel's auth.log beside ISPConfig's own login records (app.inc.php
//* auth_log(), :215) — sys_log alone is browsable panel state, not a durable
//* authentication trail.
$authaudit = implode(' | ', $app->authlog);
ok(strpos($authaudit, 'minted a login token for client 5') !== false,
    'the mint lands in auth.log beside core\'s own login records');
ok(strpos($authaudit, $result['token']) === false, 'the auth.log line contains no token');

//* ---- unbound tokens ----
scenario($active_user, $open_client);
$unbound = $sso->connect_sso_token_create('sid', 5, '');
$insert = $app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`');
ok($insert[0][4] === '', 'an empty bind_ip stores an empty binding');

//* ---- entropy ----
$seen = array();
for ($i = 0; $i < 200; $i++) {
    scenario($active_user, $open_client);
    $seen[] = $sso->connect_sso_token_create('sid', 5, '')['token'];
}
ok(count(array_unique($seen)) === 200, '200 consecutive tokens are all distinct');
ok(strlen($seen[0]) === CONNECTSSO_TOKEN_BYTES * 2, 'token length matches the configured entropy');

// ---------------------------------------------------------------------------
echo "\n";
echo $FAILURES === 0
    ? "ALL OK — $CHECKS checks passed\n"
    : "$FAILURES of $CHECKS checks FAILED\n";
echo <<<'NOTE'

Not covered here (needs a real panel — verify by hand before shipping):
  1. redeeming a token logs the browser into the panel and lands on /index.php
  2. the same URL opened twice: the second attempt is refused
  3. a token opened after ~60 s: refused
  4. a bound token opened from another address: refused, and the original
     address can still use it
  5. 10 bad tokens from one address: the 11th is refused with 429
  6. a user with otp_type != 'none': lands on /login/otp.php, not the dashboard
  7. suspending the client between minting and redeeming: refused
  8. the session cookie value CHANGES across the redirect (fixation defence)
  9. System > Remote Users shows the SSO checkbox after install.sh
 10. uninstall.sh: the function disappears from get_function_list
 11. CLIENT session cannot mint: log in over the remote API as a customer with
     can_use_api='y' (login with client_login=true), call
     connect_sso_token_create for ANOTHER client id -> permission_denied,
     no row in connectsso_token, refusal visible in sys_log and auth.log
 12. maintenance mode ON (System > Interface > Main Config > Misc): redeeming
     a valid customer token is refused with 503 and the token behaves per the
     panel's own login-form policy; turning it off restores sign-in
 13. audit trail on a SHIPPED install (log_priority = 2): a mint, a refusal
     and a sign-in each appear under Monitor > System Log AND in
     /var/log/ispconfig/auth.log; no line contains a token or its hash
 14. direct HTTP request of lib/connectsso_lib.inc.php, lib/remote.conf.php
     and lib/classes/remote.d/connectsso.inc.php under the panel vhost:
     each returns 404 with an empty body (no fatal, no path disclosure)
 15. burn race: two parallel redemptions of one token (e.g. xargs -P2 curl)
     -> exactly one lands on /index.php, the other is refused
 16. TLS gate, redemption half: with reverse_proxy_panel_allowed=none, open a
     valid token over http:// -> refused, audit line names the setting, and
     the token is still unused afterwards (no attempt recorded either); the
     same token over https:// still signs in
 17. TLS gate, mint half: call connect_sso_token_create over http://
     -> fault 'Single sign-on requires an encrypted (https) connection to the
     panel.', no row in connectsso_token, refusal in sys_log and auth.log
 18. reverse proxy: set reverse_proxy_panel_allowed=sites (or all) in
     /usr/local/ispconfig/security/security_settings.ini -> both halves work
     again over the proxy's plaintext hop

NOTE;

exit($FAILURES === 0 ? 0 : 1);
