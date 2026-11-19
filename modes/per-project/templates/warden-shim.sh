#!/usr/bin/env bash
# Thin launcher written by `warden init`. It runs the warden described in warden.lock:
#  channel=auto   (default) follows the newest release of the pinned major line (git tag v1 moves with every v1.x release), so new checks reach this
#                 repo with no change here. The commit is resolved at run time and installed once into ~/.cache/warden/auto-<commit>.
#  channel=pinned runs exactly the version in warden.lock (`warden pin`), for teams that want reviewed, reproducible upgrades.
# A teammate or a CI runner needs only Docker, Python 3, git and access to the package source: no manual install.
# Offline with channel=auto: the newest previously downloaded copy is used. Do not edit; `warden upgrade` refreshes this file.
set -uo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock() { sed -n "s/^$1=//p" "$D/warden.lock" 2>/dev/null | head -1 | tr -d '\r'; }
WANT="$(lock version)"; SRC="$(lock source)"; CH="$(lock channel)"
[ -n "$WANT" ] || { echo "warden: $D/warden.lock is missing or has no version. Run: warden init" >&2; exit 1; }
ROOTC="${WARDEN_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/warden}"
pyexe() { command -v python3 >/dev/null 2>&1 || { echo "warden: python3 is required" >&2; exit 1; }; }
binof() { local b="$1/bin/warden"; [ -x "$b" ] || b="$1/Scripts/warden.exe"; echo "$b"; }
install_into() { # <cache dir> <pip source>
  [[ "$2" =~ ^[A-Za-z0-9_./:@+=~-]+$ ]] || { echo "warden: $D/warden.lock has no usable 'source=' ($2). Run: warden init" >&2; exit 1; }
  pyexe
  { python3 -m venv "$1" && "$1/bin/pip" install -q "$2" 2>&1 || "$1/Scripts/pip.exe" install -q "$2" 2>&1; } >&2 \
    || { rm -rf "$1"; echo "warden: could not install '$2' (is the package source reachable from this machine?)" >&2; exit 1; }
}

if [ "$CH" = auto ] && [[ "$SRC" == git+*@* ]]; then
  URL="${SRC#git+}"; REF="${URL##*@}"; URL="${URL%@*}"
  SHA=""
  if command -v git >/dev/null 2>&1; then
    TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 20"
    out="$(GIT_TERMINAL_PROMPT=0 $TO git ls-remote "$URL" "refs/tags/$REF^{}" "refs/tags/$REF" "refs/heads/$REF" 2>/dev/null)"
    SHA="$(printf '%s\n' "$out" | awk '/\^\{\}$/ {print $1; exit}')"; [ -n "$SHA" ] || SHA="$(printf '%s\n' "$out" | awk 'NF {print $1; exit}')"
  fi
  if [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
    CACHE="$ROOTC/auto-${SHA:0:12}"; BIN="$(binof "$CACHE")"
    if [ ! -x "$BIN" ]; then
      echo "warden: this repo follows '$REF'; installing the newest release (${SHA:0:12}) once into $CACHE ..." >&2
      install_into "$CACHE" "git+$URL@$SHA"; BIN="$(binof "$CACHE")"
      ls -dt "$ROOTC"/auto-* 2>/dev/null | tail -n +4 | xargs -r rm -rf      # keep the 3 newest copies
    fi
  else
    CACHE="$(ls -dt "$ROOTC"/auto-* 2>/dev/null | head -1)"
    [ -n "$CACHE" ] && [ -x "$(binof "$CACHE")" ] || { echo "warden: cannot reach $URL to find the newest '$REF' and no earlier copy is cached. Connect once, or run 'warden pin' to use a fixed version." >&2; exit 1; }
    echo "warden: cannot reach $URL; using the newest cached copy ($(basename "$CACHE"))." >&2; BIN="$(binof "$CACHE")"
  fi
  exec "$BIN" "$@"
fi

# pinned: exactly the version in warden.lock
cur=""; command -v warden >/dev/null 2>&1 && cur="$(warden --version 2>/dev/null | head -1 | awk '{print $2}')"
if [ "$cur" = "$WANT" ]; then exec warden "$@"; fi
CACHE="$ROOTC/$WANT"; BIN="$(binof "$CACHE")"
if [ ! -x "$BIN" ]; then
  echo "warden $WANT (pinned by this repo) is not installed here; installing it once into $CACHE ..." >&2
  install_into "$CACHE" "$SRC"; BIN="$(binof "$CACHE")"
fi
[ -n "$cur" ] && echo "warden: this repo pins $WANT (you have $cur installed); using $WANT. Run 'warden upgrade' to move the repo to $cur." >&2
exec "$BIN" "$@"
