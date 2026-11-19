#!/usr/bin/env bash
# Start (or update) the central platform on THIS server: SonarQube + the warden dashboard.
#   scripts/platform-up.sh [--host PUBLIC_HOST_OR_IP] [--sonar-port 9000] [--dashboard-port 8090] [--no-sonar-expose]
# First run generates strong credentials into ~/.warden-platform/platform.env (mode 600); later runs reuse them.
# It prints the URLs, logins and the exact CI settings. Open the two ports in the firewall / security group yourself.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${WARDEN_PLATFORM_HOME:-$HOME/.warden-platform}"; ENVF="$STATE/platform.env"
HOST="" SP=9000 DP=8090 EXPOSE_SONAR=1
while [ $# -gt 0 ]; do case "$1" in --host) HOST="$2"; shift 2;; --sonar-port) SP="$2"; shift 2;; --dashboard-port) DP="$2"; shift 2;; --no-sonar-expose) EXPOSE_SONAR=0; shift;; -h|--help) sed -n '2,6p' "$0"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; done
[ -n "$HOST" ] || HOST="$(hostname -I | awk '{print $1}')"
mkdir -p "$STATE"; chmod 700 "$STATE"
rand() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(int(__import__("sys").argv[1]))))' "$1"; }
if [ ! -f "$ENVF" ]; then
  # an existing SonarQube database keeps the password it was created with; only a fresh install gets a random one
  DBPW="$(rand 24)"; docker volume inspect mckesson-sonar_sonar_db >/dev/null 2>&1 && DBPW="sonar-local-only"
  ( umask 077; { echo "DASHBOARD_PASSWORD=$(rand 24)"; echo "DASHBOARD_INGEST_TOKEN=$(rand 40)"; echo "SONAR_DB_PASSWORD=$DBPW"; } > "$ENVF" ); echo "generated credentials in $ENVF"
fi
set -a; . "$ENVF"; set +a
export SONAR_PORT="$SP" DASHBOARD_PORT="$DP" SONAR_BIND="$([ "$EXPOSE_SONAR" = 1 ] && echo 0.0.0.0 || echo 127.0.0.1)" DASHBOARD_BIND=0.0.0.0
export SONAR_PUBLIC_URL="http://$HOST:$SP"
cd "$HERE/docker"
docker compose --env-file ../versions.env --profile dashboard up -d --build 2>&1 | tail -5
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$DP/health" >/dev/null && break; sleep 2; done
curl -sf "http://127.0.0.1:$DP/health" >/dev/null && echo "dashboard: up" || { echo "dashboard did not start: docker logs mckesson-sonar-dashboard-1" >&2; exit 1; }
cat <<OUT

================ warden platform is running ================
Dashboard : http://$HOST:$DP         login: ${DASHBOARD_USER:-warden} / (DASHBOARD_PASSWORD in $ENVF)
SonarQube : http://$HOST:$SP         login: admin / (see docs/dashboard.md; set once with scripts/sonar-bootstrap.sh)
Open ports $DP (and $SP) for the people / CI runners that need them. Plain HTTP: restrict by IP and see docs/dashboard.md for TLS.

Settings for your repos (non-secret, put in configs/central.env or .security/config.env):
  SEC_DASHBOARD_URL=http://$HOST:$DP
  SEC_SONAR_HOST_URL=http://$HOST:$SP
CI secrets (never in files):
  WARDEN_DASHBOARD_TOKEN = DASHBOARD_INGEST_TOKEN from $ENVF
  SONAR_TOKEN             = from: SONAR_ADMIN_PASSWORD=... SONAR_HOST_URL=http://127.0.0.1:$SP scripts/sonar-bootstrap.sh
=============================================================
OUT
