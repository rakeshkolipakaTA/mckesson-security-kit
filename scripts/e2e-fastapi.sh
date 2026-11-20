#!/usr/bin/env bash
# End-to-end test on the intentionally vulnerable FastAPI sample: static scans (SAST/SCA/secrets/IaC), image scan,
# SonarQube (if SONAR_* set) and ZAP DAST against the RUNNING container on an isolated docker network.
# Usage: scripts/e2e-fastapi.sh        Takes ~6 min. Leaves nothing running.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
IMG=warden-fastapi-sample:test NET=sec-test NAME=fastapi-sample
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
docker build -q -t "$IMG" examples/fastapi-sample >/dev/null || exit 2
docker network create "$NET" >/dev/null 2>&1; docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" --network "$NET" "$IMG" >/dev/null
for _ in $(seq 1 30); do docker run --rm --network "$NET" curlimages/curl -sf "http://$NAME:8000/health" >/dev/null 2>&1 && break; sleep 1; done
S="http://$NAME:8000"
ARGS=(examples/fastapi-sample --image "$IMG" --zap-network "$NET" --zap-mode full
      --zap-url "$S/greet?name=world,$S/file?name=a.txt,$S/items/1,$S/hash?value=a" --enforce --out "reports/fastapi-sample/e2e-$(date +%H%M%S)")
[ -n "${SONAR_TOKEN:-}" ] && ARGS+=(--sonar)
scripts/scan.sh "${ARGS[@]}"
