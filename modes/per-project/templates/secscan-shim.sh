#!/usr/bin/env bash
# Thin launcher written by `secscan init`. It runs the secscan version pinned in secscan.lock:
#  - uses the `secscan` already installed on this machine when its version matches;
#  - otherwise installs the pinned version once into a private cache (~/.cache/secscan/<version>) and uses that.
# So a teammate or a CI runner needs only Docker, Python 3 and access to the package source, no manual install.
# Do not edit. To move to a newer version run `secscan upgrade` (with the newer secscan installed).
set -uo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock() { sed -n "s/^$1=//p" "$D/secscan.lock" 2>/dev/null | head -1 | tr -d '\r'; }
WANT="$(lock version)"; SRC="$(lock source)"
[ -n "$WANT" ] || { echo "secscan: $D/secscan.lock is missing or has no version. Run: secscan init" >&2; exit 1; }
cur=""; command -v secscan >/dev/null 2>&1 && cur="$(secscan --version 2>/dev/null | head -1 | awk '{print $2}')"
if [ "$cur" = "$WANT" ]; then exec secscan "$@"; fi
CACHE="${SECSCAN_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/secscan}/$WANT"
BIN="$CACHE/bin/secscan"; [ -x "$BIN" ] || BIN="$CACHE/Scripts/secscan.exe"
if [ ! -x "$BIN" ]; then
  [[ "$SRC" =~ ^[A-Za-z0-9_./:@+=~-]+$ ]] || { echo "secscan: $D/secscan.lock has no usable 'source='. Install secscan $WANT yourself (see docs) or run: secscan init" >&2; exit 1; }
  command -v python3 >/dev/null 2>&1 || { echo "secscan: python3 is required" >&2; exit 1; }
  echo "secscan $WANT (pinned by this repo) is not installed here; installing it once into $CACHE ..." >&2
  { python3 -m venv "$CACHE" && "$CACHE/bin/pip" install -q "$SRC" 2>&1 || "$CACHE/Scripts/pip.exe" install -q "$SRC" 2>&1; } >&2 \
    || { rm -rf "$CACHE"; echo "secscan: could not install '$SRC' (is the package source reachable from this machine?)" >&2; exit 1; }
  BIN="$CACHE/bin/secscan"; [ -x "$BIN" ] || BIN="$CACHE/Scripts/secscan.exe"
fi
[ -n "$cur" ] && echo "secscan: this repo pins $WANT (you have $cur installed); using $WANT. Run 'secscan upgrade' to move the repo to $cur." >&2
exec "$BIN" "$@"
