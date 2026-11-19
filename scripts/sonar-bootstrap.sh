#!/usr/bin/env bash
# One-time setup of the central SonarQube: change the default admin password, create a scanner token.
# Usage: scripts/sonar-bootstrap.sh            (prints export lines; store the token in your secret manager / CI secret)
# Env:   SONAR_HOST_URL (default http://localhost:9000), SONAR_ADMIN_PASSWORD (required: new admin password, >=12 chars)
set -euo pipefail
URL="${SONAR_HOST_URL:-http://localhost:9000}"
NEWPW="${SONAR_ADMIN_PASSWORD:?set SONAR_ADMIN_PASSWORD to the new admin password}"
echo "waiting for SonarQube at $URL ..." >&2
for _ in $(seq 1 90); do [ "$(curl -s "$URL/api/system/status" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status"))' 2>/dev/null)" = UP ] && break; sleep 5; done
# default credentials admin/admin only work on first boot
if curl -sf -u admin:admin "$URL/api/authentication/validate" | grep -q '"valid":true'; then
  curl -s --fail-with-body -u admin:admin -X POST "$URL/api/users/change_password" --data-urlencode login=admin \
    --data-urlencode previousPassword=admin --data-urlencode "password=$NEWPW" >&2 || { echo "password change rejected (policy: >=12 chars, upper, lower, digit, special)" >&2; exit 1; }
  echo "admin password changed" >&2
fi
TOKEN_JSON="$(curl -s --fail-with-body -u "admin:$NEWPW" -X POST "$URL/api/user_tokens/generate" -d "name=scanner-$(date +%Y%m%d%H%M%S)" -d type=GLOBAL_ANALYSIS_TOKEN)" || { echo "token creation failed: $TOKEN_JSON" >&2; exit 1; }
TOKEN="$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
echo "export SONAR_HOST_URL=$URL"
echo "export SONAR_TOKEN=$TOKEN"
