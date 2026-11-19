#!/usr/bin/env bash
# End-to-end test of the newer checks with real containers: git-history secrets (incl. shallow clone), SBOM, GitHub Actions security,
# Kubernetes posture, compliance crosswalk, dated baseline + overdue SLA, API fuzzing, exposure scan. ~3 min, needs Docker + network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
T="$(mktemp -d)"; PASS=0; FAILN=0
NET=nt-net; APP=nt-app
cleanup() { docker rm -f "$APP" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$T"; }; trap cleanup EXIT
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1 (expected $2, got $3)"; FAILN=$((FAILN+1)); fi; }
pyj() { python3 -I -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if ($2) else 1)" "$1"; }   # pyj <file> <python expression on d>
G="git -c user.name=t -c user.email=t@t"

echo "== repo with a deleted secret, an unsafe workflow and a Kubernetes manifest"
R="$T/repo"; cp -a examples/fastapi-sample "$R"; rm -rf "$R/.security"; mkdir -p "$R/.github/workflows" "$R/k8s"
cat > "$R/.github/workflows/ci.yml" <<'YML'
name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
YML
cat > "$R/k8s/deploy.yaml" <<'YML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: nginx:latest
          securityContext: {privileged: true}
YML
( cd "$R" && git init -q -b main . && $G add -A && $G commit -q -m one && printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n' > old-creds.env && $G add -A && $G commit -q -m two && git rm -q old-creds.env && $G commit -q -m three )
SEC_GITLEAKS_HISTORY=on scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit --out "$T/o1" >"$T/o1.log" 2>&1
S="$T/o1/summary.json"; F="$T/o1/findings.json"
pyj "$S" 'all(d["tool_status"].get(t)=="ok" for t in ("gitleaks-history","sbom","workflow-scan","k8s-posture"))'; check "new tools ran and report ok" 0 $?
pyj "$F" 'any(f["tool"]=="gitleaks-history" and f["path"]=="old-creds.env" for f in d)'; check "a secret deleted from the tree is still found in git history" 0 $?
pyj "$F" 'not any(f["tool"]=="gitleaks-history" and f["path"]=="app/main.py" for f in d)'; check "secrets still in the tree are not double-reported as history" 0 $?
pyj "$F" 'any(f["tool"]=="workflow-scan" and f["rule"]=="unpinned-uses" for f in d) and any(f["rule"]=="dangerous-triggers" for f in d)'; check "unpinned action and dangerous trigger found in the workflow" 0 $?
pyj "$F" 'any(f["tool"]=="k8s-posture" for f in d)'; check "Kubernetes posture findings (kubescape)" 0 $?
pyj "$S" 'd["sbom"]["components"]>0 and d["sbom"]["format"]=="CycloneDX"'; [ -s "$T/o1/sbom.cdx.json" ]; check "SBOM (CycloneDX) generated" 0 $?
pyj "$F" 'all("controls" in f for f in d) and any("P5-SECRETS" in f["controls"] for f in d) and any("P4-HARDEN" in f["controls"] for f in d)'; check "every finding is mapped to controls (crosswalk)" 0 $?
pyj "$S" 'len(d["crosswalk"])>=3'; [ -s "$T/o1/crosswalk.csv" ]; check "crosswalk summary + crosswalk.csv" 0 $?
grep -q 'Compliance view' "$T/o1/summary.md"; check "compliance view in the markdown report" 0 $?

echo "== shallow clone: history is truncated and the report says so"
git clone -q --depth 1 "file://$R" "$T/shallow" 2>/dev/null
SEC_GITLEAKS_HISTORY=on SEC_HISTORY_FETCH=off scripts/scan.sh "$T/shallow" --partial --skip semgrep,bandit,pip-audit,trivy,gitleaks,sbom,workflow-scan,k8s --out "$T/o2" >"$T/o2.log" 2>&1
pyj "$T/o2/summary.json" 'any("shallow clone" in m for m in d["degraded_manifests"])'; check "shallow clone is flagged as reduced coverage" 0 $?

echo "== git history is optional, limited by SEC_HISTORY_COMMITS, and a shallow CI checkout can fetch just what it needs"
scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit,trivy,gitleaks,sbom,workflow-scan,k8s --out "$T/h0" >"$T/h0.log" 2>&1
pyj "$T/h0/summary.json" '"gitleaks-history" not in d["tool_status"]'; check "history scan does not run unless switched on (default preset)" 0 $?
SEC_GITLEAKS_HISTORY=on SEC_HISTORY_COMMITS=1 scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit,trivy,gitleaks,sbom,workflow-scan,k8s --out "$T/h1" >"$T/h1.log" 2>&1
pyj "$T/h1/findings.json" 'not any(f["tool"]=="gitleaks-history" and f["path"]=="old-creds.env" for f in d)'; check "SEC_HISTORY_COMMITS=1 scans only the newest commit (older secret not seen)" 0 $?
pyj "$T/h1/summary.json" 'any("only the newest 1 of" in m for m in d["degraded_manifests"])'; check "the limit is reported as reduced coverage" 0 $?
rm -rf "$T/shallow2"; git clone -q --depth 1 "file://$R" "$T/shallow2" 2>/dev/null
SEC_GITLEAKS_HISTORY=on SEC_HISTORY_FETCH=on SEC_HISTORY_COMMITS=50 scripts/scan.sh "$T/shallow2" --partial --skip semgrep,bandit,pip-audit,trivy,gitleaks,sbom,workflow-scan,k8s --out "$T/h2" >"$T/h2.log" 2>&1
pyj "$T/h2/findings.json" 'any(f["tool"]=="gitleaks-history" and f["path"]=="old-creds.env" for f in d)'; check "SEC_HISTORY_FETCH=on deepens a shallow checkout and finds the old secret" 0 $?
pyj "$T/h2/summary.json" 'not any("shallow" in m for m in d["degraded_manifests"])'; check "no shallow warning once the history was fetched" 0 $?
SEC_GITLEAKS_HISTORY=on SEC_HISTORY_COMMITS=abc scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit,trivy,gitleaks,sbom,workflow-scan,k8s --out "$T/h3" >"$T/h3.log" 2>&1; check "a non-numeric SEC_HISTORY_COMMITS does not break the scan" 0 $?
grep -q "must be a positive number" "$T/h3.log"; check "and says what it did" 0 $?

echo "== dated baseline and SLA"
scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit --write-baseline --out "$T/o3" >/dev/null 2>&1
mkdir -p "$R/.security"; cp "$T/o3/baseline.json" "$R/.security/baseline.json" 2>/dev/null || true
[ -s "$R/.security/baseline.json" ] || { scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit --sec-dir "$R/.security" --write-baseline >/dev/null 2>&1; }
pyj "$R/.security/baseline.json" 'isinstance(d,dict) and len(d)>0 and all(len(v)==10 for v in d.values())'; check "baseline holds a date per finding" 0 $?
python3 -I - "$R/.security/baseline.json" <<'PY'
import json,sys,datetime as dt
p=sys.argv[1]; d=json.load(open(p)); old=(dt.date.today()-dt.timedelta(days=30)).isoformat()
json.dump({k:old for k in d},open(p,"w"))
PY
scripts/scan.sh "$R" --partial --skip semgrep,bandit,pip-audit --out "$T/o4" >/dev/null 2>&1
pyj "$T/o4/summary.json" 'd["overdue"]>0 and "HIGH" in d["overdue_by_severity"]'; check "baselined High findings older than the SLA are reported overdue" 0 $?
grep -q 'Past their remediation deadline' "$T/o4/summary.md"; check "overdue section in the report" 0 $?

echo "== API fuzzing + exposure scan of a running app (QA stand-in)"
docker build -q -t mckesson-fastapi-sample:test examples/fastapi-sample >/dev/null || exit 2
docker network create "$NET" >/dev/null 2>&1; docker rm -f "$APP" >/dev/null 2>&1; docker run -d --name "$APP" --network "$NET" mckesson-fastapi-sample:test >/dev/null
for _ in $(seq 1 30); do docker run --rm --network "$NET" curlimages/curl -sf "http://$APP:8000/health" >/dev/null 2>&1 && break; sleep 1; done
IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$APP")"
SEC_API_SPEC="http://$APP:8000/openapi.json" SEC_API_NETWORK="$NET" SEC_EXPOSURE_TARGETS="http://$IP:8000" \
  scripts/scan.sh examples/clean-python --partial --skip gitleaks,trivy,semgrep,bandit,pip-audit --out "$T/o5" >"$T/o5.log" 2>&1
pyj "$T/o5/summary.json" 'd["tool_status"].get("api-fuzz")=="ok" and d["tool_status"].get("exposure")=="ok"'; check "api-fuzz and exposure ran" 0 $?
pyj "$T/o5/findings.json" 'any(f["tool"]=="api-fuzz" and "/items/" in f["location"] and f["severity"]=="MEDIUM" for f in d)'; check "fuzzing finds the server error on the SQL-injection endpoint" 0 $?
pyj "$T/o5/findings.json" 'any(f["tool"]=="exposure" and f["rule"]=="EXP-CORS-WILDCARD" for f in d)'; check "exposure scan finds wildcard CORS with credentials" 0 $?
echo "== authenticated DAST: ZAP sends the token on every request"
cat > "$T/authsrv.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, f, *a): sys.stderr.write("AUTHHDR=%r\n" % (self.headers.get("Authorization"),)); sys.stderr.flush()
    def do_GET(self):
        ok = self.headers.get("Authorization") == "Bearer s3cr3t-token"
        self.send_response(200 if ok else 401); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b"<html>secret area</html>" if ok else b"nope")
http.server.ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
PY
docker rm -f nt-auth >/dev/null 2>&1; docker run -d --name nt-auth --network "$NET" -v "$T/authsrv.py:/a.py:ro" python:3.12-slim python /a.py >/dev/null; sleep 2
ZAP_AUTH_TOKEN=s3cr3t-token SEC_ZAP_NETWORK="$NET" scripts/scan.sh examples/clean-python --partial --skip gitleaks,trivy,semgrep,bandit,pip-audit --zap-url http://nt-auth:8000/ --out "$T/o6" >"$T/o6.log" 2>&1
docker logs nt-auth 2>&1 | grep -q "AUTHHDR='Bearer s3cr3t-token'"; check "ZAP requests carried the bearer token" 0 $?
grep -q 'authenticated' "$T/o6.log"; check "the scan log says the scan was authenticated" 0 $?
grep -q 's3cr3t-token' "$T/o6.log" "$T/o6/zap.log" 2>/dev/null; check "the token does not appear in the scan logs" 1 $?
docker rm -f nt-auth >/dev/null 2>&1
echo "== infrastructure as code: Terraform and CloudFormation"
scripts/scan.sh examples/iac-sample --partial --skip semgrep,bandit,pip-audit,gitleaks --out "$T/o7" >/dev/null 2>&1
pyj "$T/o7/findings.json" 'any(f["path"].endswith("main.tf") and f["category"]=="IaC/Config" for f in d) and any(f["path"].endswith("template.yaml") and f["category"]=="IaC/Config" for f in d)'; check "insecure Terraform and CloudFormation are flagged" 0 $?
echo "== image: CIS Docker benchmark + licences"
scripts/scan.sh examples/clean-python --partial --skip gitleaks,trivy,semgrep,bandit,pip-audit,sbom --image mckesson-fastapi-sample:test --out "$T/o8" >/dev/null 2>&1
pyj "$T/o8/findings.json" 'any(f["rule"].startswith("CIS-DOCKER-") and f["severity"] in ("MEDIUM","LOW") for f in d)'; check "CIS Docker benchmark controls reported (advisory)" 0 $?
echo "== switches"
o="$(SEC_SBOM=off scripts/scan.sh --explain examples/clean-python 2>&1)"; grep -qE "^  sbom +skip +turned off" <<< "$o"; check "SEC_SBOM=off is honoured" 0 $?

echo "== extra SAST packs (SEC_SEMGREP_PACKS)"
SKIPALL="gitleaks,trivy,bandit,pip-audit,npm-audit,eslint,agent-scan,modelscan,sbom,workflow-scan,k8s-posture,gitleaks-history"
SEC_SEMGREP_PACKS="p/jwt,../evil,p/x;rm" scripts/scan.sh "$R" --out "$T/pk1" --partial --skip "$SKIPALL" >"$T/pk1.log" 2>&1; check "scan with custom packs exits 0" 0 $?
grep -q "semgrep extra packs: p/jwt$" "$T/pk1.log"; check "only the valid pack is used" 0 $?
[ "$(grep -c 'ignored invalid Semgrep pack' "$T/pk1.log")" = 2 ]; check "malformed pack names are rejected (no argument injection)" 0 $?
pyj "$T/pk1/summary.json" "d['tool_status'].get('semgrep')=='ok'"; check "semgrep still ran fine" 0 $?
SEC_SEMGREP_PACKS=none scripts/scan.sh "$R" --out "$T/pk2" --partial --skip "$SKIPALL" >"$T/pk2.log" 2>&1; check "packs=none exits 0" 0 $?
grep -q "semgrep extra packs: none" "$T/pk2.log"; check "packs=none adds nothing" 0 $?
scripts/scan.sh "$R" --out "$T/pk3" --partial --skip "$SKIPALL" >"$T/pk3.log" 2>&1
grep -q "semgrep extra packs: .*p/security-audit.*p/fastapi.*p/dockerfile" "$T/pk3.log"; check "default adds security-audit, framework and Dockerfile packs for a Python app with a Dockerfile" 0 $?

echo; echo "new-tools test: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
