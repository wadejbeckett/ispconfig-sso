#!/usr/bin/env bash
#
# ispconfig-sso — uninstaller.
#
# Removes everything install.sh created, in the order that keeps the panel
# working at every step:
#   1. drop 'connectsso' from each admin's sys_user.modules
#   2. remove interface/web/connectsso (this is what unregisters the remote
#      function — core's auto-loader globs the directory, so once it is gone the
#      function is gone from the next request onward)
#   3. drop the module's two tables
#
# Nothing of ISPConfig's own is touched, so there is nothing to restore.
#
# IT DOES NOT DELETE YOUR OWN CONFIGURATION. If you created the optional
# override file — <ISPCONFIG_ROOT>/interface/lib/connectsso.ini — it is left
# exactly where it is and its path is printed at the end. An operator's own
# settings are not an uninstaller's to destroy, and the file is inert once the
# module is gone: nothing reads it. Delete it yourself if you want it gone.
#
# Dropping the tables loses nothing: connectsso_token holds only unredeemed or
# just-redeemed one-time tokens, every one of which expires within a minute, and
# connectsso_attempt holds a five-minute rate-limit window. --keep-data is there
# for the case where you are reinstalling and would rather not re-create them.
#
# Usage:
#   ./uninstall.sh [--keep-data] [ISPCONFIG_ROOT]
#
#     --keep-data   leave connectsso_token / connectsso_attempt in place
#     ISPCONFIG_ROOT defaults to /usr/local/ispconfig
#
# NOTE: it does NOT remove 'connect_sso_token_create' from any remote user's
# permission list. That value is harmless once the function no longer exists,
# and rewriting other people's permission rows is not an uninstaller's job.
# Untick it under System > Remote Users if you want it gone.
#
set -euo pipefail

trap '' PIPE
say() { echo "$@" 2>/dev/null || true; }
usage() { sed -n '2,/^set -euo pipefail/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; }

DROP_DATA=1
ISPCONFIG_ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-data) DROP_DATA=0 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "ERROR: unknown option $1" >&2; echo "Try --help." >&2; exit 2 ;;
    *)           ISPCONFIG_ROOT="$1" ;;
  esac
  shift
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISPCONFIG_ROOT="${ISPCONFIG_ROOT:-/usr/local/ispconfig}"
WEB_DIR="$ISPCONFIG_ROOT/interface/web"
CONF="$ISPCONFIG_ROOT/interface/lib/config.inc.php"
DEST="$WEB_DIR/connectsso"
# The operator's own settings, if they made any. Reported below, NEVER removed.
OVERRIDE="$ISPCONFIG_ROOT/interface/lib/connectsso.ini"

[ -d "$WEB_DIR" ] || {
  echo "ERROR: $WEB_DIR not found — is ISPCONFIG_ROOT correct?" >&2
  exit 1
}

say "ispconfig-sso — uninstall"
say "  panel: $ISPCONFIG_ROOT"
say

# 1. module list ------------------------------------------------------------
if command -v php >/dev/null 2>&1 && [ -f "$CONF" ]; then
  say "  admin module list:"
  if unassign_out="$(php "$HERE/bin/connectsso_module.php" --unassign "$CONF" 2>&1)"; then
    [ -n "$unassign_out" ] && say "$unassign_out"
  else
    echo "WARNING: could not remove 'connectsso' from the admin module list." >&2
    echo "         Harmless (the module is gone), but tidy it up by hand if you like." >&2
    [ -n "$unassign_out" ] && echo "$unassign_out" >&2
  fi
else
  say "  NOTE: php CLI or $CONF missing — module list left as it is."
fi

# 2. files ------------------------------------------------------------------
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  rm -rf "$DEST"
  say "  removed $DEST"
else
  say "  $DEST was not present"
fi

# 3. schema -----------------------------------------------------------------
if [ "$DROP_DATA" -eq 1 ]; then
  if command -v php >/dev/null 2>&1 && [ -f "$CONF" ]; then
    say "  database:"
    if ! php "$HERE/bin/connectsso_schema.php" --drop "$CONF"; then
      echo "WARNING: could not drop the module tables." >&2
      echo "         Apply sql/uninstall.sql by hand if you want them gone." >&2
    fi
  else
    say "  NOTE: php CLI or $CONF missing — tables left in place."
    say "        Apply sql/uninstall.sql by hand to remove them."
  fi
else
  say "  database: tables kept (--keep-data)"
fi

# 4. the operator's own configuration ---------------------------------------
# Reported, never removed. This file is not ours: the installer did not write
# it, so the uninstaller does not get to delete it. It is inert now — nothing
# reads it once interface/web/connectsso is gone — and it is exactly what you
# want still sitting there if this uninstall is really the first half of a
# reinstall.
if [ -e "$OVERRIDE" ]; then
  say "  configuration: KEPT (not ours to delete)"
  say "                 $OVERRIDE"
  say "                 Nothing reads it now. Re-installing picks it up again;"
  say "                 delete it by hand if you want it gone."
else
  say "  configuration: no override file was present"
fi

say
say "Done. Single sign-on is no longer available on this panel."
say "'connect_sso_token_create' is gone from the next remote API request onward,"
say "so a client that probes with get_function_list stops offering the button;"
say "one that calls it anyway gets ISPConfig's own method-does-not-exist error"
say "('invalid_method' over remote/json.php)."
