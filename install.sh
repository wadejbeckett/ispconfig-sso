#!/usr/bin/env bash
#
# ispconfig-sso — installer.
#
# A single sign-on provider for ISPConfig. It adds ONE remote API function that
# mints a short-lived, single-use panel-login token, and one page that redeems
# it. Any caller holding a granted ISPConfig remote-API session — a billing
# system, a support desk, an in-house script — can then offer a working
# "Log in to panel" button without ever storing or replaying a customer's
# panel password.
#
# It deploys ONE directory:
#   interface/web/connectsso  ->  <ispconfig>/interface/web/connectsso
#
# and touches the database in exactly two ways, both reversible by ./uninstall.sh:
#   - creates its own two tables (connectsso_token, connectsso_attempt)
#   - adds 'connectsso' to each admin's sys_user.modules, which is what makes the
#     SSO permission checkbox appear under System > Remote Users. It adds NOTHING
#     to the panel navigation: nav.php only renders modules that ship
#     lib/module.conf.php, and this one deliberately does not.
#
# NO ISPConfig core file is modified, read-only or otherwise. The remote function
# is picked up by core's own auto-loader, which globs
# interface/web/*/lib/classes/remote.d/*.inc.php
# (interface/lib/classes/remoting_handler_base.inc.php:47) — the same mechanism
# the ten built-in remote.d classes use.
#
# Usage:
#   ./install.sh [--symlink] [--no-assign] [--no-schema] [ISPCONFIG_ROOT]
#   ./install.sh --status [ISPCONFIG_ROOT]
#
#     --symlink     symlink the module instead of copying it (development;
#                   the clone is then SERVED, so keep .git out of the way)
#     --no-assign   do not touch sys_user.modules; add 'connectsso' by hand
#     --no-schema   do not create the tables (you will apply sql/install.sql)
#     --status      report what is installed and what is in force, and change
#                   NOTHING. Every line is PASS, FAIL or INFO, and every FAIL
#                   carries the exact command that fixes it. Exits non-zero when
#                   anything essential is wrong, so it can be run from
#                   monitoring. Run it as root: some of what it reads — the
#                   panel's config.inc.php, its security settings — is root-only,
#                   and as anyone else the report is incomplete rather than
#                   wrong. -s is the short form.
#     ISPCONFIG_ROOT defaults to /usr/local/ispconfig
#
# TUNING IT. Every setting an operator may reasonably want to change lives in an
# OPTIONAL file this installer never writes and the uninstaller never deletes:
#   <ISPCONFIG_ROOT>/interface/lib/connectsso.ini
# Copy conf/connectsso.ini.example there to start. It is above the panel's
# document root, so it is not web-servable, and an ISPConfig upgrade leaves it
# alone. ./install.sh --status prints what it is actually doing.
#
# AFTER INSTALLING you must still grant the function: System > Remote Users >
# your API user > Functions > tick "Panel single sign-on (one-time login token)".
# Nothing can use SSO until that box is ticked — the installer deliberately does
# not grant permissions on an operator's behalf.
#
# THE PANEL MUST BE SERVED OVER HTTPS. A token is a password substitute carried
# in a URL, so both halves refuse on a plaintext request. Behind a
# TLS-terminating reverse proxy, declare that topology in
# <ispconfig>/security/security_settings.ini: reverse_proxy_panel_allowed, in
# the [permissions] section, set to anything other than the shipped 'none'.
#
set -euo pipefail

# A closed stdout (`./install.sh | head`) must never be able to interrupt a
# half-finished install, so SIGPIPE is ignored and informational output
# tolerates EPIPE.
trap '' PIPE
say() { echo "$@" 2>/dev/null || true; }

usage() { sed -n '2,/^set -euo pipefail/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; }

MODE=copy
ASSIGN=1
SCHEMA=1
ACTION=install
ISPCONFIG_ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --symlink)    MODE=symlink ;;
    --copy)       MODE=copy ;;
    --no-assign)  ASSIGN=0 ;;
    --no-schema)  SCHEMA=0 ;;
    -s|--status)  ACTION=status ;;
    -h|--help)    usage; exit 0 ;;
    -*)           echo "ERROR: unknown option $1" >&2; echo "Try --help." >&2; exit 2 ;;
    *)            ISPCONFIG_ROOT="$1" ;;
  esac
  shift
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISPCONFIG_ROOT="${ISPCONFIG_ROOT:-/usr/local/ispconfig}"
WEB_DIR="$ISPCONFIG_ROOT/interface/web"
CONF="$ISPCONFIG_ROOT/interface/lib/config.inc.php"
SEC="$ISPCONFIG_ROOT/security/security_settings.ini"
SRC="$HERE/interface/web/connectsso"
DEST="$WEB_DIR/connectsso"
# Where an operator's own settings live. NEVER written by this script and never
# deleted by ./uninstall.sh. It is above the panel's document root
# (<ISPCONFIG_ROOT>/interface/web), so it is not web-servable, and an ISPConfig
# upgrade merges rather than replaces interface/, so it survives one. The full
# reasoning is in conf/connectsso.ini.example and in the module's own
# lib/connectsso_lib.inc.php.
OVERRIDE="$ISPCONFIG_ROOT/interface/lib/connectsso.ini"
VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

# --- status -----------------------------------------------------------------
# READ-ONLY. Nothing in this section creates, edits or deletes a file, a table
# or a row: it stats, diffs, greps and SELECTs. It is safe to run on a live
# panel, from cron, at 2am.

status_failures=0

st() { printf '  [%s] %-19s %s\n' "$1" "$2" "$3" 2>/dev/null || true; }
st_pass() { st PASS "$1" "$2"; }
st_info() { st INFO "$1" "$2"; }
st_fail() { st FAIL "$1" "$2"; status_failures=$((status_failures + 1)); }
st_fix()  { printf '         %-19s %s\n' '' "-> $1" 2>/dev/null || true; }

# One value out of an ini section, without a parser: ini_value FILE SECTION KEY
ini_value() {
  [ -r "$1" ] || return 0
  sed -n "/^[[:space:]]*\[$2\]/,/^[[:space:]]*\[[^]]*\][[:space:]]*$/p" "$1" 2>/dev/null \
    | sed -n "s/^[[:space:]]*$3[[:space:]]*=[[:space:]]*\([^;#]*\).*/\1/p" \
    | head -n 1 | tr -d '[:space:]'
}

# One key=value line out of a helper's report: report_value "$report" key
report_value() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1; }
report_all()   { printf '%s\n' "$1" | sed -n "s/^$2=//p"; }
count_lines()  { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi; }

run_status() {
  say "ispconfig-sso $VERSION — status"
  say "  panel:    $ISPCONFIG_ROOT"
  say "  checkout: $HERE"
  say

  # --- 1. is this even an ISPConfig ----------------------------------------
  if [ -d "$WEB_DIR" ] && [ -f "$CONF" ]; then
    st_pass 'panel' "ISPConfig found at $ISPCONFIG_ROOT"
  else
    st_fail 'panel' "no ISPConfig at $ISPCONFIG_ROOT (interface/web or interface/lib/config.inc.php missing)"
    st_fix "./install.sh --status /path/to/ispconfig"
    say
    say "  Nothing else can be checked without a panel. $status_failures check(s) failed."
    return 1
  fi

  # --- 2. the module directory ---------------------------------------------
  symlinked=0
  if [ -L "$DEST" ]; then
    symlinked=1
    st_pass 'module directory' "symlinked: $DEST -> $(readlink "$DEST" 2>/dev/null || echo '?')"
    st_info '' 'a --symlink install SERVES the clone; keep .git and tooling state out of it'
  elif [ -d "$DEST" ]; then
    st_pass 'module directory' "$DEST"
  else
    st_fail 'module directory' "not installed: $DEST does not exist"
    st_fix "./install.sh $ISPCONFIG_ROOT"
  fi

  # --- 3. version, and whether the files still match this checkout ----------
  installed_lib="$DEST/lib/connectsso_lib.inc.php"
  if [ -r "$installed_lib" ]; then
    installed_version="$(sed -n "s/.*define('CONNECTSSO_VERSION'[[:space:]]*,[[:space:]]*'\([^']*\)').*/\1/p" \
      "$installed_lib" 2>/dev/null | head -n 1)"
    installed_version="${installed_version:-unknown}"
    if [ "$installed_version" = "$VERSION" ]; then
      st_pass 'version' "$installed_version installed, matching this checkout"
    else
      st_fail 'version' "$installed_version installed, but this checkout is $VERSION"
      st_fix "./install.sh $ISPCONFIG_ROOT"
    fi
  else
    st_fail 'version' "cannot read $installed_lib"
    st_fix "./install.sh $ISPCONFIG_ROOT"
  fi

  if [ "$symlinked" -eq 1 ]; then
    st_info 'file contents' 'symlinked, so the panel is running this checkout verbatim'
  elif [ ! -d "$DEST" ]; then
    : # already reported as not installed
  elif ! command -v diff >/dev/null 2>&1; then
    st_info 'file contents' 'diff not available; cannot compare with this checkout'
  elif diff -r -q -x '.*' "$SRC" "$DEST" >/dev/null 2>&1; then
    st_pass 'file contents' 'identical to this checkout'
  else
    differing="$(diff -r -q -x '.*' "$SRC" "$DEST" 2>/dev/null | head -n 5 || true)"
    st_fail 'file contents' 'the installed module DIFFERS from this checkout'
    printf '%s\n' "$differing" | while IFS= read -r d; do
      [ -z "$d" ] || st_info '' "$d"
    done
    st_fix "./install.sh $ISPCONFIG_ROOT"
  fi

  # --- 4. the extension point core loads it through ------------------------
  handler="$ISPCONFIG_ROOT/interface/lib/classes/remoting_handler_base.inc.php"
  if [ ! -f "$handler" ]; then
    st_fail 'extension point' "$handler is missing; this panel has no remote.d auto-loader"
    st_fix 'this ISPConfig cannot host the module; check the panel installation'
  elif grep -q "web/\*/lib/classes/remote.d" "$handler" 2>/dev/null; then
    st_pass 'extension point' 'core still auto-loads module remote.d classes'
  else
    st_fail 'extension point' 'core no longer globs web/*/lib/classes/remote.d'
    st_fix 'the SSO function will not register; re-verify against this ISPConfig version'
  fi

  # --- 5. the two tables ---------------------------------------------------
  if ! command -v php >/dev/null 2>&1; then
    st_fail 'database tables' 'php CLI not found, so the tables cannot be checked'
    st_fix 'install a php CLI, or check by hand: SHOW TABLES LIKE "connectsso_%"'
  elif php "$HERE/bin/connectsso_schema.php" --check "$CONF" >/dev/null 2>&1; then
    st_pass 'database tables' 'connectsso_token and connectsso_attempt both present'
  else
    st_fail 'database tables' 'one or both of connectsso_token / connectsso_attempt is missing'
    st_fix "php $HERE/bin/connectsso_schema.php --install $CONF"
  fi

  # --- 6/7. the grant checkbox, and who holds the grant --------------------
  mod_report=''
  mod_ok=0
  if command -v php >/dev/null 2>&1; then
    if mod_report="$(php "$HERE/bin/connectsso_module.php" --status "$CONF" 2>/dev/null)"; then
      mod_ok=1
    fi
  fi

  if [ "$mod_ok" -eq 0 ]; then
    st_fail 'grant checkbox' 'could not read the admin module list (no php CLI, or the database is unreachable)'
    st_fix "php $HERE/bin/connectsso_module.php --status $CONF"
    st_fail 'grant holders' 'could not read remote_user (same reason)'
    st_fix "php $HERE/bin/connectsso_module.php --status $CONF"
  else
    admins_total="$(report_value "$mod_report" admins_total)"
    admins_with="$(report_value "$mod_report" admins_with_module)"
    admins_without="$(report_all "$mod_report" admin_without_module)"

    if [ "${admins_with:-0}" -ge 1 ] && [ "${admins_with:-0}" -eq "${admins_total:-0}" ]; then
      st_pass 'grant checkbox' "'connectsso' is in the module list of all $admins_total admin(s)"
    elif [ "${admins_with:-0}" -ge 1 ]; then
      # Not cosmetic: System > Remote Users builds its Functions list from the
      # LOGGED-IN admin's modules, and a CHECKBOXARRAY field is rebuilt from the
      # checkboxes that were posted. An admin without 'connectsso' who saves that
      # form silently DROPS the grant for everyone.
      st_fail 'grant checkbox' "only $admins_with of $admins_total admin(s) have 'connectsso'"
      printf '%s\n' "$admins_without" | while IFS= read -r a; do
        [ -z "$a" ] || st_info '' "missing for admin '$a' — if THEY save System > Remote Users, the grant is dropped"
      done
      st_fix "php $HERE/bin/connectsso_module.php --assign $CONF"
    else
      st_fail 'grant checkbox' "no admin has 'connectsso' in sys_user.modules, so the checkbox never renders"
      st_fix "php $HERE/bin/connectsso_module.php --assign $CONF"
    fi

    holders="$(report_all "$mod_report" grant_holder)"
    local_holders="$(report_all "$mod_report" grant_holder_localonly)"
    holder_count=$(( $(count_lines "$holders") + $(count_lines "$local_holders") ))

    if [ "$holder_count" -eq 0 ]; then
      st_fail 'grant holders' 'NO remote user holds connect_sso_token_create — nothing can mint a token'
      st_fix 'System > Remote Users > (your API user) > Functions > tick'
      st_fix "'Panel single sign-on (one-time login token)' > Save"
    else
      st_pass 'grant holders' "$holder_count remote user(s) hold connect_sso_token_create"
      printf '%s\n' "$holders" | while IFS= read -r h; do
        [ -z "$h" ] || st_info '' "$h"
      done
      printf '%s\n' "$local_holders" | while IFS= read -r h; do
        [ -z "$h" ] || st_info '' "$h (remote_access = n: usable only from 127.0.0.1 / ::1)"
      done
    fi
  fi

  # --- 8. is the remote API switched on at all -----------------------------
  if [ ! -r "$SEC" ]; then
    st_fail 'remote API' "cannot read $SEC (run as root?)"
    st_fix "check remote_api_allowed in $SEC"
  else
    api="$(ini_value "$SEC" permissions remote_api_allowed)"
    if [ "$api" = "yes" ]; then
      st_pass 'remote API' 'remote_api_allowed = yes'
    else
      st_fail 'remote API' "remote_api_allowed = ${api:-<unset>}; remote/json.php and remote/index.php refuse EVERY call"
      st_fix "set remote_api_allowed=yes in the [permissions] section of $SEC"
    fi

    proxy="$(ini_value "$SEC" permissions reverse_proxy_panel_allowed)"
    if [ -z "$proxy" ] || [ "$proxy" = "none" ]; then
      st_info 'transport' 'no reverse proxy declared, so both halves require a real https request'
    else
      st_info 'transport' "reverse_proxy_panel_allowed = $proxy — TLS termination is the proxy's job"
    fi
  fi

  # --- 9. what the module is actually configured to do ---------------------
  cfg=''
  if command -v php >/dev/null 2>&1 && [ -r "$installed_lib" ]; then
    cfg="$(php -r '
        if ($argv[1] !== "") { define("CONNECTSSO_CONFIG_FILE", $argv[1]); }
        require $argv[2];
        foreach (connectsso_config_describe() as $line) { echo $line, "\n"; }
      ' -- "$OVERRIDE" "$installed_lib" 2>/dev/null || true)"
  fi

  if [ -z "$cfg" ]; then
    st_fail 'configuration' 'could not read the effective configuration from the installed module'
    st_fix "./install.sh $ISPCONFIG_ROOT   (the installed copy may predate the override file)"
  else
    st_info 'token lifetime' "$(report_value "$cfg" token_ttl) seconds"
    st_info 'rate limit' "$(report_value "$cfg" attempt_limit) failed redemptions per $(report_value "$cfg" attempt_window)s, per source address"
    st_info 'unbound tokens' "$(report_value "$cfg" allow_unbound_tokens)"

    problems="$(report_all "$cfg" problem)"
    if [ -n "$problems" ]; then
      st_fail 'override file' "$OVERRIDE has $(count_lines "$problems") problem(s); the shipped default is in force for each"
      printf '%s\n' "$problems" | while IFS= read -r pr; do
        [ -z "$pr" ] || st_info '' "$pr"
      done
      st_fix "edit $OVERRIDE, or delete it to go back to the shipped defaults"
    elif [ "$(report_value "$cfg" present)" = "yes" ]; then
      st_pass 'override file' "$OVERRIDE (in force, nothing wrong with it)"
    else
      st_info 'override file' 'none — the three values above are the shipped defaults'
      st_fix "cp $HERE/conf/connectsso.ini.example $OVERRIDE   (to change them)"
    fi
  fi

  say
  if [ "$status_failures" -eq 0 ]; then
    say "  All checks passed. Single sign-on should work on this panel."
    say "  What it cannot tell you: whether the panel is reachable over https from"
    say "  your billing system, and whether that system's address is in the API"
    say "  user's Remote Access IP list. Both are outside this machine."
    return 0
  fi
  say "  $status_failures check(s) FAILED. Single sign-on is not fully working on this panel."
  return 1
}

if [ "$ACTION" = "status" ]; then
  run_status || exit 1
  exit 0
fi

# --- preflight --------------------------------------------------------------

[ -d "$WEB_DIR" ] || {
  echo "ERROR: $WEB_DIR not found — is ISPCONFIG_ROOT correct?" >&2
  echo "       pass it explicitly, e.g.  ./install.sh /usr/local/ispconfig" >&2
  exit 1
}
[ -f "$CONF" ] || {
  echo "ERROR: $CONF not found — this does not look like an ISPConfig install." >&2
  exit 1
}
[ -d "$SRC" ] || { echo "ERROR: source not found at $SRC" >&2; exit 1; }

# The remote.d auto-loader globs interface/web/*/lib/classes/remote.d/*.inc.php.
# If that directory layout is not what this ISPConfig expects, the module would
# install silently and never register — fail loudly instead.
[ -f "$ISPCONFIG_ROOT/interface/lib/classes/remoting_handler_base.inc.php" ] || {
  echo "ERROR: interface/lib/classes/remoting_handler_base.inc.php is missing." >&2
  echo "       This ISPConfig has no remote.d module auto-loader, which is the" >&2
  echo "       only extension point this module uses. SSO cannot be installed here." >&2
  exit 1
}
if ! grep -q "web/\*/lib/classes/remote.d" "$ISPCONFIG_ROOT/interface/lib/classes/remoting_handler_base.inc.php"; then
  echo "WARNING: this ISPConfig's remoting handler does not appear to load module" >&2
  echo "         remote.d classes from interface/web/*/lib/classes/remote.d/." >&2
  echo "         Installing anyway, but the SSO function may not register." >&2
fi

# A symlinked directory is SERVED THROUGH the link, so anything sitting inside
# this clone would be reachable over HTTP as /connectsso/... — VCS metadata,
# editor or tooling state, dependency trees. The module itself ships no
# dot-entries, so ANY of them here is foreign and a reason to stop.
if [ "$MODE" = "symlink" ]; then
  stray="$(find "$SRC" -mindepth 1 \( -name '.*' -o -name 'node_modules' \) -print -quit 2>/dev/null || true)"
  if [ -n "$stray" ]; then
    echo "ERROR: $stray is inside the directory you are about to symlink." >&2
    echo "       It would be served over HTTP. Remove it, or install with --copy." >&2
    exit 1
  fi
fi

say "ispconfig-sso $VERSION"
say "  panel: $ISPCONFIG_ROOT"
say

# --- deploy -----------------------------------------------------------------

# Everything after this point can leave a half-installed panel, so say so if we
# die early rather than exiting silently.
INSTALL_COMPLETED=0
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$INSTALL_COMPLETED" -eq 0 ]; then
    echo >&2
    echo "ERROR: install did NOT complete (exit $rc)." >&2
    echo "       Re-run this script, or run ./uninstall.sh to remove what landed." >&2
  fi
}
trap on_exit EXIT

if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  say "  replacing existing $DEST"
  rm -rf "$DEST"
fi

if [ "$MODE" = "symlink" ]; then
  ln -s "$SRC" "$DEST"
  say "  symlinked interface/web/connectsso"
else
  # tar, not `cp -a`, so the excludes are honoured. The module ships no
  # dot-entries, so excluding all of them costs nothing and keeps VCS, editor
  # and tooling state out of a directory the panel serves over HTTP.
  tar cf - --exclude='.*' --exclude='node_modules' \
      -C "$HERE/interface/web" connectsso | tar xf - -C "$WEB_DIR"
  say "  copied interface/web/connectsso"
  if id -u ispconfig >/dev/null 2>&1; then
    chown -R ispconfig:ispconfig "$DEST" 2>/dev/null || true
  fi
  # An authentication endpoint should not be group- or world-writable.
  chmod -R go-w "$DEST" 2>/dev/null || true
fi

# --- schema -----------------------------------------------------------------

if [ "$SCHEMA" -eq 1 ]; then
  if command -v php >/dev/null 2>&1; then
    say "  database:"
    if ! php "$HERE/bin/connectsso_schema.php" --install "$CONF"; then
      echo "ERROR: could not create the module tables." >&2
      echo "       Apply sql/install.sql by hand against the ISPConfig database," >&2
      echo "       then re-run with --no-schema." >&2
      exit 1
    fi
  else
    echo "WARNING: php CLI not found — tables NOT created." >&2
    echo "         Apply sql/install.sql by hand; SSO fails until you do." >&2
  fi
else
  say "  database: skipped (--no-schema); apply sql/install.sql yourself"
fi

# --- module assignment ------------------------------------------------------

if [ "$ASSIGN" -eq 1 ]; then
  if command -v php >/dev/null 2>&1; then
    say "  permission checkbox:"
    # Capture the helper's output rather than letting it inherit a stdout the
    # operator may have closed: its own failed writes would otherwise be
    # reported here as an assignment failure that never happened.
    if assign_out="$(php "$HERE/bin/connectsso_module.php" --assign "$CONF" 2>&1)"; then
      [ -n "$assign_out" ] && say "$assign_out"
    else
      echo "WARNING: could not add 'connectsso' to the admin module list." >&2
      echo "         Without it the SSO permission checkbox will not appear under" >&2
      echo "         System > Remote Users. Add it by hand in the sys_user.modules" >&2
      echo "         column, or re-run: php bin/connectsso_module.php --assign $CONF" >&2
      [ -n "$assign_out" ] && echo "$assign_out" >&2
    fi
  else
    say "  NOTE: php CLI not found — 'connectsso' NOT added to the admin module list."
  fi
else
  say "  permission checkbox: skipped (--no-assign)"
fi

INSTALL_COMPLETED=1

say
say "Done. Two steps remain, and neither can be done for you:"
say
say "  1. Grant the function to your API user:"
say "     System > Remote Users > (your user) > Functions >"
say "     tick 'Panel single sign-on (one-time login token)' > Save."
say "     If the box is not there, log out and back in first — the checkbox list"
say "     is built from the module list of the admin who is logged in."
say
say "  2. Point your billing system (or your own code) at this panel. The"
say "     function to call is 'connect_sso_token_create'; a client can detect"
say "     that it is installed with one 'get_function_list' call. README.md has"
say "     the full API contract and a copy-and-paste PHP example."
say
say "Then check your work — this changes nothing and prints a PASS/FAIL checklist,"
say "including who currently holds the grant and what lifetime and rate limits are"
say "actually in force:"
say
say "  ./install.sh --status $ISPCONFIG_ROOT"
say
say "TO TUNE IT — token lifetime, rate limits, whether tokens may be minted"
say "unbound — create this file. It is optional, it is above the panel's document"
say "root so it is not web-servable, and NEITHER this installer NOR ./uninstall.sh"
say "will ever write or delete it, so your settings survive an update:"
say
say "  cp $HERE/conf/connectsso.ini.example \\"
say "     $OVERRIDE"
say
say "That file documents every setting, and says which ones cannot be weakened."
say
say
say "REQUIREMENT: serve the panel over HTTPS. A token is a password substitute in"
say "a URL, so both halves REFUSE on a plaintext request. Behind a TLS-terminating"
say "reverse proxy, declare it: reverse_proxy_panel_allowed in the [permissions]"
say "section of $ISPCONFIG_ROOT/security/security_settings.ini"
say "(anything other than the shipped 'none')."
say
say "Read README.md before exposing this to customers: it documents the token"
say "lifetime, the optional IP binding, what ends up in your access log, who can"
say "be minted for (resellers included), and how two-factor authentication is"
say "preserved."
