#!/usr/bin/env bash
# One-time setup of Dependency-Track: replace the default admin password and create a CI API key that can ONLY upload SBOMs.
# Usage: scripts/dtrack-bootstrap.sh         (prints the repo setting and the CI secret to store; run it again any time to rotate the key)
# Env:   DTRACK_API_URL (default http://127.0.0.1:8111, the API server), DTRACK_ADMIN_PASSWORD (default: the value in ~/.warden-platform/platform.env)
set -euo pipefail
ENVF="${WARDEN_PLATFORM_HOME:-$HOME/.warden-platform}/platform.env"
[ -z "${DTRACK_ADMIN_PASSWORD:-}" ] && [ -f "$ENVF" ] && DTRACK_ADMIN_PASSWORD="$(grep '^DTRACK_ADMIN_PASSWORD=' "$ENVF" | cut -d= -f2-)"
URL="${DTRACK_API_URL:-http://127.0.0.1:8111}"; URL="${URL%/}"
PW="${DTRACK_ADMIN_PASSWORD:?set DTRACK_ADMIN_PASSWORD (or run scripts/platform-up.sh --dtrack first, which creates it)}"
echo "waiting for Dependency-Track at $URL ..." >&2
for _ in $(seq 1 90); do curl -sf -o /dev/null "$URL/api/version" && break; sleep 3; done
curl -sf -o /dev/null "$URL/api/version" || { echo "Dependency-Track is not answering at $URL" >&2; exit 1; }
# the default admin/admin only works until the first password change
if [ "$(curl -s -X POST "$URL/api/v1/user/login" --data-urlencode username=admin --data-urlencode password=admin)" = "FORCE_PASSWORD_CHANGE" ]; then
  curl -s --fail-with-body -X POST "$URL/api/v1/user/forceChangePassword" --data-urlencode username=admin --data-urlencode password=admin \
    --data-urlencode "newPassword=$PW" --data-urlencode "confirmPassword=$PW" >/dev/null || { echo "password change rejected by Dependency-Track" >&2; exit 1; }
  echo "admin password changed" >&2
fi
JWT="$(curl -s --fail-with-body -X POST "$URL/api/v1/user/login" --data-urlencode username=admin --data-urlencode "password=$PW")" || { echo "admin login failed (is DTRACK_ADMIN_PASSWORD the current password?)" >&2; exit 1; }
api() { curl -s --fail-with-body -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' "$@"; }
TEAM="$(api "$URL/api/v1/team" | python3 -c 'import sys,json;t=[x for x in json.load(sys.stdin) if x["name"]=="warden-ci"];print(t[0]["uuid"] if t else "")')"
[ -n "$TEAM" ] || TEAM="$(api -X PUT "$URL/api/v1/team" -d '{"name":"warden-ci"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["uuid"])')"
# least privilege: upload SBOMs (and create the project on first upload), read results back. Nothing else.
for perm in BOM_UPLOAD PROJECT_CREATION_UPLOAD VIEW_PORTFOLIO; do api -X POST "$URL/api/v1/permission/$perm/team/$TEAM" >/dev/null 2>&1 || true; done
KEY="$(api -X PUT "$URL/api/v1/team/$TEAM/key" | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')" || { echo "could not create the API key" >&2; exit 1; }
# Vulnerability data: out of the box Dependency-Track relies on NVD (poor at matching Python/npm/Maven packages) and Sonatype OSS Index (needs an
# account), so turn on the free Google OSV database for the common ecosystems. The mirror starts when the API server starts, so restart it once.
cfg() { api -X POST "$URL/api/v1/configProperty" -d "{\"groupName\":\"$1\",\"propertyName\":\"$2\",\"propertyValue\":\"$3\"}" >/dev/null; }
if ! api "$URL/api/v1/configProperty" | python3 -c 'import sys,json;sys.exit(0 if any(p["propertyName"]=="google.osv.enabled" and p.get("propertyValue") for p in json.load(sys.stdin)) else 1)'; then
  cfg vuln-source google.osv.enabled "PyPI;npm;Maven;Go;NuGet;crates.io;RubyGems;Packagist" && echo "Google OSV vulnerability source enabled" >&2
  if command -v docker >/dev/null && docker inspect warden-platform-dtrack-apiserver-1 >/dev/null 2>&1; then
    docker restart warden-platform-dtrack-apiserver-1 >/dev/null && echo "API server restarted to start the OSV download (takes a few minutes to fill)" >&2
    for _ in $(seq 1 60); do curl -sf -o /dev/null "$URL/api/version" && break; sleep 3; done
  else echo "NOTE: restart the Dependency-Track API server once so the OSV download starts (it also starts by itself within a day)" >&2; fi
  JWT="$(curl -s -X POST "$URL/api/v1/user/login" --data-urlencode username=admin --data-urlencode "password=$PW")"
fi
# optional: GitHub Advisories (needs a GitHub token with no scopes): DTRACK_GITHUB_TOKEN=... scripts/dtrack-bootstrap.sh
if [ -n "${DTRACK_GITHUB_TOKEN:-}" ]; then cfg vuln-source github.advisories.access.token "$DTRACK_GITHUB_TOKEN" && cfg vuln-source github.advisories.enabled true && echo "GitHub Advisories enabled" >&2; fi
echo "team 'warden-ci' ready (permissions: BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO)" >&2
echo "# repo setting (not secret):  SEC_DTRACK_URL=$URL      (use the address CI can reach; see docs/integrations/dependency-track.md)"
echo "export DTRACK_API_KEY=$KEY      # store as the CI secret DTRACK_API_KEY"
