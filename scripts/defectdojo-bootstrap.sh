#!/usr/bin/env bash
# One-time setup of DefectDojo for CI: create a service user (warden-ci-<timestamp>) and print its API token. Run it again any time to ROTATE the
# token (the previous service user is deactivated, so its token stops working).
# Usage: scripts/defectdojo-bootstrap.sh
# Env:   DEFECTDOJO_URL (default http://127.0.0.1:8100), DEFECTDOJO_ADMIN_PASSWORD (default: the value in ~/.warden-platform/platform.env)
# NOTE: DefectDojo Community has no "import only" role: a user that can create products and import must be a superuser. The token is therefore
# powerful: keep it in a restricted CI secret (see docs/integrations/defectdojo.md) and rotate it.
set -euo pipefail
ENVF="${WARDEN_PLATFORM_HOME:-$HOME/.warden-platform}/platform.env"
[ -z "${DEFECTDOJO_ADMIN_PASSWORD:-}" ] && [ -f "$ENVF" ] && DEFECTDOJO_ADMIN_PASSWORD="$(grep '^DEFECTDOJO_ADMIN_PASSWORD=' "$ENVF" | cut -d= -f2-)"
URL="${DEFECTDOJO_URL:-http://127.0.0.1:8100}"; URL="${URL%/}"
APW="${DEFECTDOJO_ADMIN_PASSWORD:?set DEFECTDOJO_ADMIN_PASSWORD (or run scripts/platform-up.sh --defectdojo first, which creates it)}"
echo "waiting for DefectDojo at $URL ..." >&2
for _ in $(seq 1 90); do curl -sf -o /dev/null "$URL/login?next=/" && break; sleep 3; done
curl -sf -o /dev/null "$URL/login?next=/" || { echo "DefectDojo is not answering at $URL" >&2; exit 1; }
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
login() { curl -s -X POST "$URL/api/v2/api-token-auth/" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jget 'd.get("token","")'; }
ADM="$(login admin "$APW")"; [ -n "$ADM" ] || { echo "admin login failed (is DEFECTDOJO_ADMIN_PASSWORD right?)" >&2; exit 1; }
api() { curl -s --fail-with-body -H "Authorization: Token $ADM" -H 'Content-Type: application/json' "$@"; }
# Each run creates a NEW service user (DefectDojo does not allow password changes through the API, and a user that reported findings cannot be
# deleted) and deactivates the earlier warden-ci-* users, which revokes their tokens. The random password is never stored: only the token is used.
CIPW="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24)+"-Aa9!")')"
CIUSER="warden-ci-$(date +%Y%m%d%H%M%S)"
OLD="$(api "$URL/api/v2/users/?limit=500" | jget '" ".join(str(u["id"]) for u in d["results"] if u["username"].startswith("warden-ci") and u["is_active"])')"
api -X POST "$URL/api/v2/users/" -d "{\"username\":\"$CIUSER\",\"first_name\":\"Warden\",\"last_name\":\"CI\",\"email\":\"$CIUSER@warden.local\",\"is_active\":true,\"is_superuser\":true,\"password\":\"$CIPW\"}" >/dev/null \
  || { echo "could not create the service user" >&2; exit 1; }
for id in $OLD; do api -X PATCH "$URL/api/v2/users/$id/" -d '{"is_active":false}' >/dev/null && echo "previous service user $id deactivated (its token no longer works)" >&2; done
echo "service user $CIUSER created" >&2
TOKEN="$(login "$CIUSER" "$CIPW")"; [ -n "$TOKEN" ] || { echo "could not obtain the warden-ci token" >&2; exit 1; }
echo "# repo setting (not secret):  SEC_DEFECTDOJO_URL=$URL      (use the address CI can reach; see docs/integrations/defectdojo.md)"
echo "export DEFECTDOJO_TOKEN=$TOKEN      # store as the CI secret DEFECTDOJO_TOKEN"
