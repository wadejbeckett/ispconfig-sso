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
#
#     --symlink     symlink the module instead of copying it (development;
#                   the clone is then SERVED, so keep .git out of the way)
#     --no-assign   do not touch sys_user.modules; add 'connectsso' by hand
#     --no-schema   do not create the tables (you will apply sql/install.sql)
#     ISPCONFIG_ROOT defaults to /usr/local/ispconfig
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
ISPCONFIG_ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --symlink)    MODE=symlink ;;
    --copy)       MODE=copy ;;
    --no-assign)  ASSIGN=0 ;;
    --no-schema)  SCHEMA=0 ;;
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
SRC="$HERE/interface/web/connectsso"
DEST="$WEB_DIR/connectsso"
VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

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
