#!/usr/bin/env bash
# Start (or update) the central platform on THIS server: SonarQube + the warden dashboard, and optionally DefectDojo and Dependency-Track.
#   scripts/platform-up.sh [--host PUBLIC_HOST_OR_IP] [--sonar-port 9000] [--dashboard-port 8090] [--no-sonar-expose]
#                          [--defectdojo [--defectdojo-port 8100]] [--dtrack [--dtrack-port 8110] [--dtrack-api-port 8111]] [--expose]
#   DefectDojo and Dependency-Track listen on localhost only until you add --expose (then open their ports for the people / CI that need them).
# First run generates strong credentials into ~/.warden-platform/platform.env (mode 600); later runs reuse them.
# It prints the URLs, logins and the exact CI settings. Open the two ports in the firewall / security group yourself.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${WARDEN_PLATFORM_HOME:-$HOME/.warden-platform}"; ENVF="$STATE/platform.env"
HOST="" SP=9000 DP=8090 EXPOSE_SONAR=1 DD=0 DT=0 DDP=8100 DTP=8110 DTAP=8111 EXPOSE_EXTRA=0
while [ $# -gt 0 ]; do case "$1" in --host) HOST="$2"; shift 2;; --sonar-port) SP="$2"; shift 2;; --dashboard-port) DP="$2"; shift 2;; --no-sonar-expose) EXPOSE_SONAR=0; shift;;
  --defectdojo) DD=1; shift;; --defectdojo-port) DDP="$2"; shift 2;; --dtrack) DT=1; shift;; --dtrack-port) DTP="$2"; shift 2;; --dtrack-api-port) DTAP="$2"; shift 2;; --expose) EXPOSE_EXTRA=1; shift;;
  -h|--help) sed -n '2,8p' "$0"; exit 0;; *) echo "unknown option $1" >&2; exit 2;; esac; done
[ -n "$HOST" ] || HOST="$(hostname -I | awk '{print $1}')"
mkdir -p "$STATE"; chmod 700 "$STATE"
rand() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(int(__import__("sys").argv[1]))))' "$1"; }
if [ ! -f "$ENVF" ]; then
  # an existing SonarQube database keeps the password it was created with; only a fresh install gets a random one
  DBPW="$(rand 24)"; docker volume inspect warden-platform_sonar_db >/dev/null 2>&1 && DBPW="sonar-local-only"
  ( umask 077; { echo "DASHBOARD_PASSWORD=$(rand 24)"; echo "DASHBOARD_INGEST_TOKEN=$(rand 40)"; echo "SONAR_DB_PASSWORD=$DBPW"; } > "$ENVF" ); echo "generated credentials in $ENVF"
fi
# credentials for the optional tools are created the first time they are asked for (existing values are never changed)
ensure() { grep -q "^$1=" "$ENVF" || { ( umask 077; echo "$1=$(rand "$2")" >> "$ENVF" ); echo "generated $1 in $ENVF"; }; }
if [ "$DD" = 1 ]; then ensure DEFECTDOJO_ADMIN_PASSWORD 24; ensure DEFECTDOJO_DB_PASSWORD 24; ensure DEFECTDOJO_SECRET_KEY 50; ensure DEFECTDOJO_AES_KEY 32; fi
if [ "$DT" = 1 ]; then ensure DTRACK_DB_PASSWORD 24; ensure DTRACK_ADMIN_PASSWORD 24; fi
set -a; . "$ENVF"; set +a
export SONAR_PORT="$SP" DASHBOARD_PORT="$DP" SONAR_BIND="$([ "$EXPOSE_SONAR" = 1 ] && echo 0.0.0.0 || echo 127.0.0.1)" DASHBOARD_BIND=0.0.0.0
export SONAR_PUBLIC_URL="http://$HOST:$SP"
EXTRA_BIND="$([ "$EXPOSE_EXTRA" = 1 ] && echo 0.0.0.0 || echo 127.0.0.1)"
export DEFECTDOJO_PORT="$DDP" DEFECTDOJO_BIND="$EXTRA_BIND" DTRACK_PORT="$DTP" DTRACK_API_PORT="$DTAP" DTRACK_BIND="$EXTRA_BIND" DTRACK_API_PUBLIC_URL="http://$HOST:$DTAP"
PROFILES=(--profile dashboard); [ "$DD" = 1 ] && PROFILES+=(--profile defectdojo); [ "$DT" = 1 ] && PROFILES+=(--profile dtrack)
cd "$HERE/docker"
docker compose --env-file ../versions.env "${PROFILES[@]}" up -d --build 2>&1 | tail -8
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$DP/health" >/dev/null && break; sleep 2; done
curl -sf "http://127.0.0.1:$DP/health" >/dev/null && echo "dashboard: up" || { echo "dashboard did not start: docker logs warden-platform-dashboard-1" >&2; exit 1; }
if [ "$DD" = 1 ]; then
  for _ in $(seq 1 90); do curl -sf -o /dev/null "http://127.0.0.1:$DDP/login?next=/" && break; sleep 3; done
  curl -sf -o /dev/null "http://127.0.0.1:$DDP/login?next=/" && echo "defectdojo: up" || { echo "defectdojo did not start: docker logs warden-platform-defectdojo-uwsgi-1 (and ...-initializer-1)" >&2; exit 1; }
fi
if [ "$DT" = 1 ]; then
  for _ in $(seq 1 90); do curl -sf -o /dev/null "http://127.0.0.1:$DTAP/api/version" && break; sleep 3; done
  curl -sf -o /dev/null "http://127.0.0.1:$DTAP/api/version" && echo "dependency-track: up" || { echo "dependency-track did not start: docker logs warden-platform-dtrack-apiserver-1" >&2; exit 1; }
fi
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
if [ "$DD" = 1 ]; then cat <<OUT

DefectDojo : http://$HOST:$DDP        login: admin / (DEFECTDOJO_ADMIN_PASSWORD in $ENVF)
  One-time: scripts/defectdojo-bootstrap.sh  (creates a CI service user and prints the token)
  Repo setting: SEC_DEFECTDOJO_URL=http://$HOST:$DDP     CI secret: DEFECTDOJO_TOKEN
OUT
fi
if [ "$DT" = 1 ]; then cat <<OUT

Dependency-Track : http://$HOST:$DTP   (API http://$HOST:$DTAP)   login: admin / (DTRACK_ADMIN_PASSWORD in $ENVF, set by scripts/dtrack-bootstrap.sh)
  One-time: scripts/dtrack-bootstrap.sh  (changes the default admin password, creates a CI key limited to SBOM upload)
  Repo setting: SEC_DTRACK_URL=http://$HOST:$DTAP        CI secret: DTRACK_API_KEY
OUT
fi
if { [ "$DD" = 1 ] || [ "$DT" = 1 ]; } && [ "$EXPOSE_EXTRA" = 0 ]; then
  echo; echo "DefectDojo / Dependency-Track listen on localhost only. Add --expose (and open their ports) for CI runners and people on other machines."
fi
