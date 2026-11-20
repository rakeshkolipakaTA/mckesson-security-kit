#!/usr/bin/env bash
# Platform team: refresh the OWASP Dependency-Check vulnerability database ONCE (e.g. nightly cron / scheduled CI job)
# into the shared docker volume, so project scans can run with SEC_DEPCHECK_NOUPDATE=1 and stay fast.
# Needs NVD_API_KEY (free: https://nvd.nist.gov/developers/request-an-api-key). Without a key the download takes hours.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; source "$HERE/versions.env"
: "${NVD_API_KEY:?set NVD_API_KEY}"
docker volume inspect warden-depcheck-data >/dev/null 2>&1 || docker volume create warden-depcheck-data >/dev/null
docker run --rm --user root --entrypoint chmod -v warden-depcheck-data:/d "$DEPCHECK_IMAGE" 777 /d
docker run --rm --user "$(id -u):$(id -g)" -v warden-depcheck-data:/usr/share/dependency-check/data -e NVD_API_KEY \
  "$DEPCHECK_IMAGE" --updateonly --nvdApiKey "$NVD_API_KEY"
echo "Dependency-Check database updated."
