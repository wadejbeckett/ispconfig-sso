<?php
/**
 * ispconfig-sso — add or remove 'connectsso' in every admin's module list.
 * Copyright (c) 2026 Wade Beckett. GPLv3 — see ../LICENSE.
 *
 * WHY THIS IS NEEDED (verified, ISPConfig 3.3.1p1):
 * System > Remote Users builds its "Functions" checkbox list by including
 * <module>/lib/remote.conf.php for every module named in the LOGGED-IN ADMIN's
 * sys_user.modules column (interface/web/admin/form/remote_user.tform.php:36-45).
 * Unless 'connectsso' is in that column, this module's remote.conf.php is never
 * read, the SSO grant has no checkbox — and saving the Remote Users form would
 * silently DROP the grant, because a CHECKBOXARRAY field is rebuilt from the
 * checkboxes that were posted (tform_base.inc.php:832).
 *
 * Adding the name does NOT put anything in the panel navigation: nav.php only
 * renders modules that have lib/module.conf.php, and this one deliberately has
 * none (interface/web/nav.php:58). Nothing else reads the column.
 *
 * CAVEAT worth knowing: the module checkbox list on the CP-user form is built
 * from directories that DO have module.conf.php (users.tform.php:90), so saving
 * an admin's CP-user record re-writes sys_user.modules from those checkboxes
 * and drops 'connectsso'. If the SSO checkbox ever disappears from the Remote
 * Users form, re-run install.sh (or this script with --assign).
 *
 * --status is READ-ONLY (SELECT only, no UPDATE) and reports, as key=value
 * lines for ./install.sh --status to parse:
 *   admins_total, admins_with_module, admin_without_module (one per admin)
 *   remote_users_total, grant_holder / grant_holder_localonly (one per user)
 * It exits 0 when it could produce a report and 1 when it could not; whether
 * the report is GOOD news is install.sh's decision, not this script's.
 *
 * Usage:
 *   php connectsso_module.php --assign   [/usr/local/ispconfig/interface/lib/config.inc.php]
 *   php connectsso_module.php --unassign [...]
 *   php connectsso_module.php --status   [...]
 */

define('CONNECTSSO_MODULE_NAME', 'connectsso');

//* The remote function name is frozen installed state: it is the literal string
//* stored in remote_user.remote_functions on every panel that granted it. See
//* the README, "Names are frozen".
define('CONNECTSSO_GRANT_NAME', 'connect_sso_token_create');

$mode = null;
$conf_path = '/usr/local/ispconfig/interface/lib/config.inc.php';
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--assign' || $arg === '--unassign' || $arg === '--status') {
        $mode = substr($arg, 2);
    } elseif ($arg === '-h' || $arg === '--help') {
        fwrite(STDOUT, "usage: connectsso_module.php --assign|--unassign|--status [config.inc.php]\n");
        exit(0);
    } else {
        $conf_path = $arg;
    }
}

if ($mode === null) {
    fwrite(STDERR, "ERROR: pass --assign, --unassign or --status\n");
    exit(2);
}
if (!is_readable($conf_path)) {
    fwrite(STDERR, "ERROR: ISPConfig config not readable: $conf_path\n");
    exit(1);
}

require $conf_path;
if (!isset($conf) || !is_array($conf) || empty($conf['db_host'])) {
    fwrite(STDERR, "ERROR: no database configuration found in $conf_path\n");
    exit(1);
}

if (function_exists('mysqli_report')) {
    mysqli_report(MYSQLI_REPORT_OFF);
}

$port = isset($conf['db_port']) ? (int)$conf['db_port'] : 3306;
try {
    $m = @new mysqli($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_database'], $port);
} catch (\Throwable $e) {
    $m = false;
}
if (!$m || $m->connect_errno) {
    fwrite(STDERR, "ERROR: database connection failed" . ($m ? ": " . $m->connect_error : "") . "\n");
    exit(1);
}

//* sys_user.modules is read back, re-joined and written whole, so the
//* connection charset must match the panel's or MySQL can replace characters it
//* cannot represent with '?' — silently corrupting an unrelated module name.
$db_charset = !empty($conf['db_charset']) ? $conf['db_charset'] : 'utf8mb4';
if (!@$m->set_charset($db_charset) && $db_charset !== 'utf8mb4') {
    @$m->set_charset('utf8mb4');
}

/**
 * A username is operator-supplied text that is about to be printed on one line
 * of a report install.sh parses. Strip anything that could break that — control
 * characters, newlines — and cap the length.
 */
function connectsso_safe_name($value) {
    $value = preg_replace('/[^\x20-\x7E]/', '', (string)$value);

    return substr((string)$value, 0, 64);
}

if ($mode === 'status') {
    //* READ-ONLY from here to exit. Nothing below writes.
    $out = array();

    $res = $m->query("SELECT username, modules FROM sys_user WHERE typ = 'admin'");
    if (!$res) {
        fwrite(STDERR, "ERROR: query failed: " . $m->error . "\n");
        $m->close();
        exit(1);
    }
    $admins_total = 0;
    $admins_with = 0;
    while ($r = $res->fetch_assoc()) {
        $admins_total++;
        $mods = array_map('trim', explode(',', (string)$r['modules']));
        if (in_array(CONNECTSSO_MODULE_NAME, $mods, true)) {
            $admins_with++;
        } else {
            $out[] = 'admin_without_module=' . connectsso_safe_name($r['username']);
        }
    }
    $res->free();
    array_unshift($out, 'admins_with_module=' . $admins_with);
    array_unshift($out, 'admins_total=' . $admins_total);

    //* Who actually holds the grant. checkPerm() splits remote_functions on
    //* ',' after replacing ';' with ',' (remoting.inc.php:552-553) — match that
    //* exactly, or this report would disagree with the panel about who is
    //* granted.
    $res = $m->query("SELECT remote_username, remote_functions, remote_access FROM remote_user");
    if (!$res) {
        fwrite(STDERR, "ERROR: query failed: " . $m->error . "\n");
        $m->close();
        exit(1);
    }
    $remote_total = 0;
    while ($r = $res->fetch_assoc()) {
        $remote_total++;
        $functions = explode(',', str_replace(';', ',', (string)$r['remote_functions']));
        $functions = array_map('trim', $functions);
        if (!in_array(CONNECTSSO_GRANT_NAME, $functions, true)) {
            continue;
        }
        //* remote_access = 'n' restricts that user to 127.0.0.1 / ::1
        //* (remoting.inc.php:195): a grant that only a local caller can use.
        $key = ($r['remote_access'] === 'y') ? 'grant_holder' : 'grant_holder_localonly';
        $out[] = $key . '=' . connectsso_safe_name($r['remote_username']);
    }
    $res->free();
    $out[] = 'remote_users_total=' . $remote_total;

    fwrite(STDOUT, implode("\n", $out) . "\n");
    $m->close();
    exit(0);
}

$res = $m->query("SELECT userid, username, modules FROM sys_user WHERE typ = 'admin'");
if (!$res) {
    fwrite(STDERR, "ERROR: query failed: " . $m->error . "\n");
    $m->close();
    exit(1);
}

$changed = 0;
while ($r = $res->fetch_assoc()) {
    $mods = array_values(array_filter(array_map('trim', explode(',', (string)$r['modules'])), 'strlen'));
    $has = in_array(CONNECTSSO_MODULE_NAME, $mods, true);

    if ($mode === 'assign' && !$has) {
        $mods[] = CONNECTSSO_MODULE_NAME;
    } elseif ($mode === 'unassign' && $has) {
        $mods = array_values(array_filter($mods, function ($v) {
            return $v !== CONNECTSSO_MODULE_NAME;
        }));
    } else {
        continue;
    }

    $csv = implode(',', $mods);
    $uid = (int)$r['userid'];
    $stmt = $m->prepare("UPDATE sys_user SET modules = ? WHERE userid = ?");
    if (!$stmt) {
        fwrite(STDERR, "ERROR: prepare failed: " . $m->error . "\n");
        $m->close();
        exit(1);
    }
    $stmt->bind_param('si', $csv, $uid);
    if (!$stmt->execute()) {
        fwrite(STDERR, "ERROR: update failed for user '" . $r['username'] . "': " . $stmt->error . "\n");
        $stmt->close();
        $m->close();
        exit(1);
    }
    $stmt->close();
    fwrite(STDOUT, "  " . ($mode === 'assign' ? '+' : '-') . " '" . CONNECTSSO_MODULE_NAME
        . "' " . ($mode === 'assign' ? 'assigned to' : 'removed from') . " admin user '" . $r['username'] . "'\n");
    $changed++;
}
$res->free();

if ($changed === 0) {
    fwrite(STDOUT, $mode === 'assign'
        ? "  all admin users already have the '" . CONNECTSSO_MODULE_NAME . "' module\n"
        : "  no admin user had the '" . CONNECTSSO_MODULE_NAME . "' module\n");
}

$m->close();
exit(0);
