#!/usr/bin/env bash
# Thin launcher written by `warden init`. It runs the warden version pinned in warden.lock:
#  - uses the `warden` already installed on this machine when its version matches;
#  - otherwise installs the pinned version once into a private cache (~/.cache/warden/<version>) and uses that.
# So a teammate or a CI runner needs only Docker, Python 3 and access to the package source, no manual install.
# Do not edit. To move to a newer version run `warden upgrade` (with the newer warden installed).
set -uo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock() { sed -n "s/^$1=//p" "$D/warden.lock" 2>/dev/null | head -1 | tr -d '\r'; }
WANT="$(lock version)"; SRC="$(lock source)"
[ -n "$WANT" ] || { echo "warden: $D/warden.lock is missing or has no version. Run: warden init" >&2; exit 1; }
cur=""; command -v warden >/dev/null 2>&1 && cur="$(warden --version 2>/dev/null | head -1 | awk '{print $2}')"
if [ "$cur" = "$WANT" ]; then exec warden "$@"; fi
CACHE="${WARDEN_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/warden}/$WANT"
BIN="$CACHE/bin/warden"; [ -x "$BIN" ] || BIN="$CACHE/Scripts/warden.exe"
if [ ! -x "$BIN" ]; then
  [[ "$SRC" =~ ^[A-Za-z0-9_./:@+=~-]+$ ]] || { echo "warden: $D/warden.lock has no usable 'source='. Install warden $WANT yourself (see docs) or run: warden init" >&2; exit 1; }
  command -v python3 >/dev/null 2>&1 || { echo "warden: python3 is required" >&2; exit 1; }
  echo "warden $WANT (pinned by this repo) is not installed here; installing it once into $CACHE ..." >&2
  { python3 -m venv "$CACHE" && "$CACHE/bin/pip" install -q "$SRC" 2>&1 || "$CACHE/Scripts/pip.exe" install -q "$SRC" 2>&1; } >&2 \
    || { rm -rf "$CACHE"; echo "warden: could not install '$SRC' (is the package source reachable from this machine?)" >&2; exit 1; }
  BIN="$CACHE/bin/warden"; [ -x "$BIN" ] || BIN="$CACHE/Scripts/warden.exe"
fi
[ -n "$cur" ] && echo "warden: this repo pins $WANT (you have $cur installed); using $WANT. Run 'warden upgrade' to move the repo to $cur." >&2
exec "$BIN" "$@"
