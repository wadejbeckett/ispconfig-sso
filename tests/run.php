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
// CHILD PROBE MODE — how the override file is tested end to end.
//
// The tunables become CONSTANTS at include time, so ONE php process can only
// ever observe ONE override file. The override section further down therefore
// re-executes this script as a child, once per scenario, and asserts on what
// the child reports. This block is that child: it defines the two constants
// that steer where the module looks for its override file, loads the module for
// real (same file, same include path, same code the panel runs), exercises the
// one refusal that exists only when unbound tokens are turned off, and prints a
// single JSON line.
//
//   php tests/run.php --config-probe <ini-path|''> [ISPC_LIB_PATH]
//
// It is placed HERE, after the stand-ins and before the first check, because
// the constants must be defined before the module is included and the module
// must be included after `remoting` exists.
// ---------------------------------------------------------------------------
if (isset($argv[1]) && $argv[1] === '--config-probe') {
    $probe_ini = isset($argv[2]) ? $argv[2] : '';
    $probe_lib = isset($argv[3]) ? $argv[3] : '';
    if ($probe_ini !== '') { define('CONNECTSSO_CONFIG_FILE', $probe_ini); }
    if ($probe_lib !== '') { define('ISPC_LIB_PATH', $probe_lib); }

    require_once __DIR__ . '/../interface/web/connectsso/lib/classes/remote.d/connectsso.inc.php';

    $_SERVER['HTTPS'] = 'on';
    $probe_user   = array('userid' => 9, 'username' => 'acmeltd', 'active' => 1, 'typ' => 'user');
    $probe_client = array('locked' => 'n', 'canceled' => 'n');
    $probe_sso    = new remoting_connectsso();

    //* An UNBOUND mint. Succeeds on a stock panel; refused only where the
    //* override file turned unbound tokens off, which is the whole point of
    //* that setting.
    $app = new FakeApp();
    $app->db->rows = array($probe_user, $probe_client);
    $probe_unbound_fault = '';
    try {
        $probe_sso->connect_sso_token_create('sid', 5, '');
    } catch (SoapFault $e) {
        $probe_unbound_fault = $e->getMessage();
    }
    $probe_unbound_audit  = implode(' | ', $app->log) . ' ~~ ' . implode(' | ', $app->authlog);
    $probe_unbound_minted = count($app->db->writesMatching('INSERT INTO `' . CONNECTSSO_TOKEN_TABLE . '`'));

    //* A BOUND mint. Must succeed under EVERY configuration — no override may
    //* turn single sign-on off by accident.
    $app = new FakeApp();
    $app->db->rows = array($probe_user, $probe_client);
    $probe_bound_ttl   = -1;
    $probe_bound_fault = '';
    try {
        $probe_ticket    = $probe_sso->connect_sso_token_create('sid', 5, '203.0.113.9');
        $probe_bound_ttl = (int)$probe_ticket['expires_in'];
    } catch (SoapFault $e) {
        $probe_bound_fault = $e->getMessage();
    }

    echo json_encode(array(
        'path'            => connectsso_config_path(),
        'ttl'             => CONNECTSSO_TOKEN_TTL,
        'limit'           => CONNECTSSO_ATTEMPT_LIMIT,
        'window'          => CONNECTSSO_ATTEMPT_WINDOW,
        'unbound_allowed' => CONNECTSSO_ALLOW_UNBOUND,
        'problems'        => connectsso_config_problems(),
        'describe'        => connectsso_config_describe(),
        'unbound_fault'   => $probe_unbound_fault,
        'unbound_audit'   => $probe_unbound_audit,
        'unbound_minted'  => $probe_unbound_minted,
        'bound_ttl'       => $probe_bound_ttl,
        'bound_fault'     => $probe_bound_fault,
    )), "\n";
    exit(0);
}

/** Run one child probe and decode its report. */
function config_probe($ini, $lib_path = '') {
    //* stderr is discarded on purpose: a broken override file writes its
    //* complaint to the PHP error log as a backstop, and in CLI that is stderr.
    //* The parent asserts on the structured 'problems' list instead.
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__)
        . ' --config-probe ' . escapeshellarg((string)$ini) . ' ' . escapeshellarg((string)$lib_path)
        . ' 2>/dev/null';
    $decoded = json_decode((string)shell_exec($cmd), true);

    return is_array($decoded) ? $decoded : array();
}

$TMP_FILES = array();
$TMP_DIR   = sys_get_temp_dir() . '/connectsso-harness-' . getmypid();

/** Write one throwaway ini file and return its path. */
function tmp_ini($contents) {
    global $TMP_FILES, $TMP_DIR;
    static $n = 0;
    if (!is_dir($TMP_DIR)) { @mkdir($TMP_DIR, 0700, true); }
    $path = $TMP_DIR . '/cfg' . (++$n) . '.ini';
    file_put_contents($path, $contents);
    $TMP_FILES[] = $path;

    return $path;
}

/** Does any complaint in $problems mention $needle? */
function problem_mentions($problems, $needle) {
    foreach ((array)$problems as $problem) {
        if (stripos((string)$problem, $needle) !== false) { return true; }
    }

    return false;
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

//* install.sh --status compares the CONNECTSSO_VERSION of the INSTALLED module
//* against this checkout's VERSION file to decide whether the panel is running
//* what you have in front of you. If the two ever disagree here, that check
//* reports a false mismatch on every panel.
ok(CONNECTSSO_VERSION === trim((string)file_get_contents($module_root . '/VERSION')),
    'CONNECTSSO_VERSION matches the VERSION file (' . CONNECTSSO_VERSION . ')');

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
section('override file — defaults, validation and clamping');
// ---------------------------------------------------------------------------
//* Every tunable used to be a define() inside a shipped file, so an operator who
//* changed the token lifetime lost it on the next update. The override file is
//* the fix: an optional ini the installer never writes and never deletes.
//*
//* These checks drive the parser and the clamps directly, as pure functions.
//* The section after this one proves the file actually REACHES the constants,
//* which needs a child process — constants are set at include time.

$defaults = connectsso_config_defaults();
ok($defaults === array(
    'token_ttl'            => 45,
    'attempt_limit'        => 10,
    'attempt_window'       => 300,
    'allow_unbound_tokens' => true,
), 'the shipped defaults are 45 s TTL, 10 attempts, a 300 s window, unbound allowed');

$p = array();
ok(connectsso_config_resolve(array(), $p) === $defaults && $p === array(),
    'no overrides at all -> the shipped defaults, silently');

$p = array();
ok(connectsso_config_resolve(array(
    'token_ttl'            => 30,
    'attempt_limit'        => 5,
    'attempt_window'       => 120,
    'allow_unbound_tokens' => false,
), $p) === array(
    'token_ttl'            => 30,
    'attempt_limit'        => 5,
    'attempt_window'       => 120,
    'allow_unbound_tokens' => false,
) && $p === array(), 'every in-range override is taken as given, with no complaint');

//* Numbers arriving as strings: parse_ini_file() only types them when
//* INI_SCANNER_TYPED is available, so both forms must work.
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => '30'), $p)['token_ttl'] === 30 && $p === array(),
    'a numeric string is accepted and returned as an int');

//* ---- clamping. An out-of-range value is CLAMPED, never obeyed and never
//* silently dropped: the operator asked for something, so give them the nearest
//* thing that is still safe and say what happened.
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => 3600), $p)['token_ttl'] === 60
    && problem_mentions($p, 'clamped'), 'token_ttl 3600 clamps to 60 and complains');
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => 0), $p)['token_ttl'] === 5
    && problem_mentions($p, 'clamped'), 'token_ttl 0 clamps to 5 and complains');
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => -900), $p)['token_ttl'] === 5,
    'a negative token_ttl clamps to the minimum');
$p = array();
ok(connectsso_config_resolve(array('attempt_limit' => 0), $p)['attempt_limit'] === 1,
    'attempt_limit 0 clamps to 1 — zero would lock every visitor out permanently');
$p = array();
ok(connectsso_config_resolve(array('attempt_limit' => 999999), $p)['attempt_limit'] === 1000,
    'attempt_limit 999999 clamps to 1000 — beyond that it bounds nothing');
$p = array();
ok(connectsso_config_resolve(array('attempt_window' => 5), $p)['attempt_window'] === 60,
    'attempt_window 5 clamps to 60');
$p = array();
ok(connectsso_config_resolve(array('attempt_window' => 999999), $p)['attempt_window'] === 86400,
    'attempt_window 999999 clamps to 86400');

//* ---- booleans
$bool_fail = array();
foreach (array(false, 'no', 'No', 'off', 'false', '0', 0) as $falsey) {
    $p = array();
    $got = connectsso_config_resolve(array('allow_unbound_tokens' => $falsey), $p);
    if ($got['allow_unbound_tokens'] !== false || $p !== array()) {
        $bool_fail[] = var_export($falsey, true);
    }
}
ok(empty($bool_fail), 'every spelling of "no" turns unbound tokens off'
    . (empty($bool_fail) ? '' : ': ' . implode(', ', $bool_fail) . ' did not'));

$bool_fail = array();
foreach (array(true, 'yes', 'YES', 'on', 'true', '1', 1) as $truthy) {
    $p = array();
    $got = connectsso_config_resolve(array('allow_unbound_tokens' => $truthy), $p);
    if ($got['allow_unbound_tokens'] !== true || $p !== array()) {
        $bool_fail[] = var_export($truthy, true);
    }
}
ok(empty($bool_fail), 'every spelling of "yes" leaves unbound tokens on'
    . (empty($bool_fail) ? '' : ': ' . implode(', ', $bool_fail) . ' did not'));

$p = array();
ok(connectsso_config_resolve(array('allow_unbound_tokens' => 'maybe'), $p)['allow_unbound_tokens'] === true
    && problem_mentions($p, 'allow_unbound_tokens'),
    'a value that is neither yes nor no keeps the default and complains');

//* ---- garbage in a numeric field keeps the default rather than becoming 0.
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => 'soon'), $p)['token_ttl'] === 45
    && problem_mentions($p, 'token_ttl'), 'a non-numeric token_ttl keeps the default and complains');
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => 30.5), $p)['token_ttl'] === 45,
    'a fractional token_ttl keeps the default');
$p = array();
ok(connectsso_config_resolve(array('token_ttl' => array(30)), $p)['token_ttl'] === 45,
    'an array value keeps the default');

//* ---- unknown keys are ignored, loudly. A typo must not look like it worked.
$p = array();
$got = connectsso_config_resolve(array('token_lifetime' => 30), $p);
ok($got === $defaults && problem_mentions($p, 'token_lifetime'),
    'an unrecognised key changes nothing and is named in the complaint');

//* ---- SECURITY-CRITICAL keys are refused BY NAME, with a reason. The point of
//* the override file is that the operator can tune the safe knobs; it must not
//* become a way to turn the module's guarantees off.
$refusable = array('token_bytes', 'token_entropy', 'token_hash', 'hash_algo',
    'single_use', 'allow_reuse', 'allow_admin', 'require_tls', 'allow_http');
$not_refused = array();
foreach ($refusable as $key) {
    $p = array();
    $got = connectsso_config_resolve(array($key => 'whatever-i-want'), $p);
    //* refused: nothing changes, and the complaint names the key AND says it is
    //* not overridable — not merely "unrecognised", which would read like a typo.
    if ($got !== $defaults || !problem_mentions($p, $key) || !problem_mentions($p, 'not an overridable')) {
        $not_refused[] = $key;
    }
}
ok($not_refused === array(),
    count($refusable) . ' security-critical keys are refused by name'
    . ($not_refused ? ': ' . implode(', ', $not_refused) . ' were not' : ''));

//* Nothing the file contains can ever add a key the module did not define.
$p = array();
$got = connectsso_config_resolve(array('token_ttl' => 20, 'nonsense' => 1, 'allow_admin' => 'yes'), $p);
ok(array_keys($got) === array_keys($defaults), 'the resolved set never grows a key of its own');
ok($got['token_ttl'] === 20 && count($p) === 2,
    'a good key still applies when it shares the file with a bad one, and both bad ones complain');

//* Case and whitespace in key names: an ini file is hand-edited.
$p = array();
ok(connectsso_config_resolve(array('  TOKEN_TTL  ' => 30), $p)['token_ttl'] === 30,
    'key names are matched case-insensitively and trimmed');

//* A non-array (what a failed parse hands back) must degrade to defaults.
$p = array();
ok(connectsso_config_resolve(false, $p) === $defaults, 'a failed parse resolves to the defaults');

// ---------------------------------------------------------------------------
section('override file — reading it off disk');
// ---------------------------------------------------------------------------

$p = array();
ok(connectsso_config_read($TMP_DIR . '/definitely-not-there.ini', $p) === array() && $p === array(),
    'no override file at all is the normal case and says nothing');

$p = array();
$file = tmp_ini("; a comment\ntoken_ttl = 30\nattempt_limit = 5\nallow_unbound_tokens = no\n");
$raw = connectsso_config_read($file, $p);
ok($p === array(), 'a well-formed file parses without complaint');
$resolved = connectsso_config_resolve($raw, $p);
ok($resolved['token_ttl'] === 30 && $resolved['attempt_limit'] === 5
    && $resolved['allow_unbound_tokens'] === false && $resolved['attempt_window'] === 300,
    'values in the file win; anything absent from it keeps the shipped default');

$p = array();
ok(connectsso_config_read(tmp_ini(''), $p) === array() && $p === array(),
    'an empty file is not an error');
$p = array();
ok(connectsso_config_read(tmp_ini("; nothing but comments\n; really\n"), $p) === array() && $p === array(),
    'a comments-only file is not an error');

//* parse_ini_file() ignores section headers when sections are not requested, so
//* a file the operator organised into sections still works.
$p = array();
$sectioned = connectsso_config_read(tmp_ini("[connectsso]\ntoken_ttl = 20\n"), $p);
ok(connectsso_config_resolve($sectioned, $p)['token_ttl'] === 20 && $p === array(),
    'a [section] header is tolerated');

//* ---- MALFORMED. Loudly, never silently: a file the operator believes is in
//* force but which the module could not read is exactly the state that wastes
//* an afternoon.
$p = array();
$broken = tmp_ini("token_ttl = 30\n[unterminated\n\"\n");
ok(connectsso_config_read($broken, $p) === array() && problem_mentions($p, $broken),
    'an unparseable file yields no overrides and complains, naming the path');

$p = array();
ok(connectsso_config_read($TMP_DIR, $p) === array() && problem_mentions($p, 'directory'),
    'a directory where the file should be is reported, not fatal');

//* Unreadable is only testable as a non-root user — root reads everything.
$unreadable = tmp_ini("token_ttl = 30\n");
@chmod($unreadable, 0000);
if (!is_readable($unreadable)) {
    $p = array();
    ok(connectsso_config_read($unreadable, $p) === array() && problem_mentions($p, 'not readable'),
        'a file the panel cannot read is reported, not silently skipped');
} else {
    ok(true, 'a file the panel cannot read is reported (skipped: running as root)');
}
@chmod($unreadable, 0600);

//* ---- the shipped example. It is the only documentation an operator reads at
//* the moment they are editing the file, so it must itself be valid, must name
//* exactly the settings the resolver accepts, and must show the real defaults —
//* an example naming a key the module ignores is worse than no example at all.
$example = $module_root . '/conf/connectsso.ini.example';
ok(is_file($example), 'conf/connectsso.ini.example ships with the project');

$p = array();
ok(connectsso_config_read($example, $p) === array() && $p === array(),
    'the example parses cleanly and every setting in it is commented out,'
    . ' so copying it into place changes nothing');

$example_shown = array();
foreach (preg_split('/\R/', (string)file_get_contents($example)) as $line) {
    if (preg_match('/^;([a-z_]+)\s*=\s*(\S+)/', trim($line), $m)) {
        $example_shown[$m[1]] = $m[2];
    }
}
$example_keys = array_keys($example_shown);
sort($example_keys);
ok($example_keys === array('allow_unbound_tokens', 'attempt_limit', 'attempt_window', 'token_ttl'),
    'the example documents exactly the four overridable settings (found: '
    . implode(', ', $example_keys) . ')');

$p = array();
ok(connectsso_config_resolve($example_shown, $p) === $defaults && $p === array(),
    'the values the example shows ARE the shipped defaults, so uncommenting a line'
    . ' as-is changes nothing');

//* Every security-critical key must be named in the example's "what you cannot
//* change" list, or an operator has no way to learn it is refused.
$example_text = (string)file_get_contents($example);
$undocumented = array();
foreach (array_keys(connectsso_config_refused()) as $key) {
    if (strpos($example_text, $key) === false) { $undocumented[] = $key; }
}
ok($undocumented === array(),
    'the example names every refused key'
    . ($undocumented ? ': ' . implode(', ', $undocumented) . ' missing' : ''));

// ---------------------------------------------------------------------------
section('override file — end to end, in a child process');
// ---------------------------------------------------------------------------
//* Constants are set at include time, so this is the only honest way to prove
//* the file reaches them. Each probe is a fresh php running the real module.

$probe = config_probe('');
ok($probe !== array(), 'the child probe runs and reports');
ok(isset($probe['ttl']) && $probe['ttl'] === 45 && $probe['limit'] === 10
    && $probe['window'] === 300 && $probe['unbound_allowed'] === true,
    'with no override file the constants are the shipped defaults');
ok(isset($probe['problems']) && $probe['problems'] === array(),
    'with no override file there is nothing to complain about');
ok(isset($probe['unbound_fault']) && $probe['unbound_fault'] === '' && $probe['unbound_minted'] === 1,
    'with no override file an unbound mint succeeds');
ok(isset($probe['bound_ttl']) && $probe['bound_ttl'] === 45,
    'the TTL the caller is told matches the constant');

$probe = config_probe(tmp_ini("token_ttl = 30\nattempt_limit = 5\nattempt_window = 120\n"));
ok($probe['ttl'] === 30 && $probe['limit'] === 5 && $probe['window'] === 120,
    'an override file really does change the constants the module runs on');
ok($probe['bound_ttl'] === 30, 'the overridden TTL is what the caller is told');
ok($probe['problems'] === array(), 'a valid override file produces no complaint');

$probe = config_probe(tmp_ini("token_ttl = 9999\nattempt_limit = 0\n"));
ok($probe['ttl'] === 60 && $probe['limit'] === 1, 'out-of-range values are clamped in the live constants');
ok(count($probe['problems']) === 2, 'both clamps are reported');

$probe = config_probe(tmp_ini("[unterminated\n\"\n"));
ok($probe['ttl'] === 45 && $probe['limit'] === 10 && $probe['window'] === 300,
    'an unparseable override file leaves the shipped defaults in force');
ok(count($probe['problems']) === 1, 'and the unparseable file is complained about, not ignored');

//* ---- the one refusal that exists only under an override.
$probe = config_probe(tmp_ini("allow_unbound_tokens = no\n"));
ok($probe['unbound_allowed'] === false, 'allow_unbound_tokens = no reaches the constant');
ok($probe['unbound_fault'] === 'This panel requires single sign-on tokens to be bound to an IP address.',
    'an unbound mint is then refused with a message that says why');
ok($probe['unbound_minted'] === 0, 'and mints nothing');
ok(strpos($probe['unbound_audit'], '[connectsso] refused') !== false
    && substr_count($probe['unbound_audit'], '[connectsso] refused') >= 2,
    'the bind-IP refusal is audited to sys_log AND auth.log, like every other refusal');
ok($probe['bound_ttl'] === 45 && $probe['bound_fault'] === '',
    'a BOUND mint still succeeds when unbound ones are disabled');

//* ---- where the file lives. On a panel this is ISPC_LIB_PATH, which is
//* <ispconfig>/interface/lib — above the docroot (<ispconfig>/interface/web),
//* so it can never be fetched over HTTP.
$probe = config_probe('', '/somewhere/interface/lib');
ok($probe['path'] === '/somewhere/interface/lib/connectsso.ini',
    'on a real panel the file is looked for in ISPC_LIB_PATH, above the docroot');
ok(strpos($probe['path'], '/interface/web/') === false,
    'and never inside the directory the panel serves over HTTP');

//* ---- the machine-readable report install.sh --status parses.
$probe = config_probe(tmp_ini("token_ttl = 25\n"));
$described = implode("\n", $probe['describe']);
ok(strpos($described, 'token_ttl=25') !== false
    && strpos($described, 'attempt_limit=10') !== false
    && strpos($described, 'attempt_window=300') !== false
    && strpos($described, 'allow_unbound_tokens=yes') !== false
    && strpos($described, 'present=yes') !== false,
    'connectsso_config_describe() reports the effective configuration as key=value lines');
$probe = config_probe(tmp_ini("token_ttl = 9999\n"));
ok(problem_mentions($probe['describe'], 'problem='),
    'and carries any complaint through to install.sh --status');

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
//*
//* The mint function has ELEVEN refusal paths, not ten. The eleventh — no bind
//* IP where the override file made binding mandatory — cannot be reached in
//* this process, because CONNECTSSO_ALLOW_UNBOUND is a constant fixed at
//* include time. It is covered in the child-probe section above, with the same
//* two assertions this table makes: audited to both logs, and mints nothing.
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

ok(count($refusals) === 10,
    'the refusal table still enumerates 10 in-process paths (found ' . count($refusals)
    . '); the 11th, bind-IP-required, is covered by the child probe');
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
foreach ($TMP_FILES as $tmp) { @chmod($tmp, 0600); @unlink($tmp); }
@rmdir($TMP_DIR);

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
