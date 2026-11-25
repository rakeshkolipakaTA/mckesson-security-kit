#!/usr/bin/env bash
# Proves the framework behaves as the plan's policy says. Run after any change to scripts/ or configs/.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAILN=0
check() { # name expected_exit actual_exit
  if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1 (expected exit $2, got $3)"; FAILN=$((FAILN+1)); grep -E 'Security gate|BLOCK|WARNING|NOTE|resolution failed|ERROR' "$T/last.log" | head -8 | sed 's/^/        | /'; fi; }
scan() { scripts/scan.sh "$@" >"$T/last.log" 2>&1; echo $?; }

echo "0. gate identity/dedupe unit tests"
python3 -I scripts/test_gate.py >"$T/unit.log" 2>&1; check "unit tests (alias order, tool set, per-manifest identity)" 0 $?; cp "$T/unit.log" "$T/last.log"
python3 -I scripts/test_toolplan.py >"$T/plan.log" 2>&1; check "tool-plan tests (presets, required-tool lock, waivers)" 0 $?
python3 -I scripts/test_tools.py >"$T/tools.log" 2>&1; check "helper tools (API fuzz report, exposure, repo posture) against mock servers" 0 $?; cp "$T/tools.log" "$T/last.log"
python3 -I scripts/test_tickets.py >"$T/tickets.log" 2>&1; check "ticketing (GitHub / Jira / Azure) against mock servers" 0 $?; cp "$T/tickets.log" "$T/last.log"
python3 -I scripts/test_platform_templates.py >"$T/ptpl.log" 2>&1; check "platform templates (Dependabot, workflows, process kit, SLA text matches policy)" 0 $?; cp "$T/ptpl.log" "$T/last.log"
python3 -I scripts/test_gh_report.py >"$T/ghr.log" 2>&1; check "GitHub reporting: summary, annotations, one PR comment (mock API)" 0 $?; cp "$T/ghr.log" "$T/last.log"
python3 -I scripts/test_zap_auth.py >"$T/zauth.log" 2>&1; check "ZAP login types: basic, cookie, JSON, form, OAuth2 / SSO token flows (mock app + identity provider)" 0 $?; cp "$T/zauth.log" "$T/last.log"
python3 -I scripts/test_creds.py >"$T/creds.log" 2>&1; check "local test-credential store (outside git, mode 600, profiles)" 0 $?; cp "$T/creds.log" "$T/last.log"
python3 -I scripts/test_publish_external.py >"$T/pubext.log" 2>&1; check "publish to DefectDojo and Dependency-Track (mock servers: reimport, SBOM upload, branch filter, failures, no secret echo)" 0 $?; cp "$T/pubext.log" "$T/last.log"
python3 -I scripts/test_wiz_scan.py >"$T/wiz.log" 2>&1; check "Wiz CLI runner (stand-in wizcli: no licence = nothing runs, secrets never printed, policy vs error, hash-checked install)" 0 $?; cp "$T/wiz.log" "$T/last.log"
python3 -I scripts/test_semgrep_rules.py >"$T/rules.log" 2>&1; check "Semgrep offline-rules downloader (good pack saved, bad answer / missing pack / unreachable server fail, names validated, licence README)" 0 $?; cp "$T/rules.log" "$T/last.log"
python3 -W ignore -I agentic/tests/test_agentsec_extra.py >"$T/agentx.log" 2>&1; check "agentsec extras (output integrity, classification, retention, secrets, PIP/PAP)" 0 $?; cp "$T/agentx.log" "$T/last.log"
python3 -W ignore -I agentic/tests/test_sandbox_docker.py >"$T/sandbox.log" 2>&1; check "agent code sandbox contains hostile code (real Docker)" 0 $?; cp "$T/sandbox.log" "$T/last.log"
python3 -I scripts/test_dashboard.py >"$T/dash.log" 2>&1; check "dashboard + publisher tests (auth, hostile input, ingest, views)" 0 $?; cp "$T/dash.log" "$T/last.log"
echo "0b. agentic controls: runtime library unit tests + Semgrep agent-rule tests"
python3 -W ignore -I agentic/tests/test_agentsec.py >"$T/agentsec.log" 2>&1; check "agentsec unit tests" 0 $?; cp "$T/agentsec.log" "$T/last.log"
( . ./versions.env; docker run --rm -v "$PWD/configs/semgrep/agentic:/rules" "$SEMGREP_IMAGE" semgrep --test --metrics=off --disable-version-check /rules >"$T/semtest.log" 2>&1 ); grep -q "All tests passed" "$T/semtest.log"; check "semgrep agentic rule tests (positive and negative cases)" 0 $?; cp "$T/semtest.log" "$T/last.log"
echo "1. vulnerable fixture must fail the gate when enforcing"
check "vulnerable + --enforce"        1 "$(scan examples/vulnerable-python --enforce --out $T/o1)"
echo "2. report-only must never fail the build (pilot phase, plan section 4 step 04)"
check "vulnerable report-only"        0 "$(scan examples/vulnerable-python --out $T/o2)"
echo "3. clean fixture must pass"
check "clean + --enforce"             0 "$(scan examples/clean-python --enforce --out $T/o3)"

echo "4. baseline + exceptions flow (plan section 7: block NEW High/Critical, legacy tracked)"
cp -a examples/vulnerable-python "$T/repo"; mkdir -p "$T/sec"
scan "$T/repo" --sec-dir "$T/sec" --write-baseline --out "$T/o4" >/dev/null
[ -s "$T/sec/baseline.json" ] && echo "  PASS  baseline written" && PASS=$((PASS+1)) || { echo "  FAIL  baseline written"; FAILN=$((FAILN+1)); }
check "baseline only (3 legacy CRITICAL still block)" 1 "$(scan "$T/repo" --sec-dir "$T/sec" --enforce --out $T/o5)"
python3 - "$T" <<'PY'
import json,sys,glob
T=sys.argv[1]; f=json.load(open(f"{T}/o5/findings.json"))
ex=[dict(fingerprint=x["fingerprint"],reason="selftest: legacy, remediation planned",approved_by="selftest",expires="2999-01-01") for x in f if x["severity"]=="CRITICAL"]
json.dump(ex,open(f"{T}/sec/exceptions.json","w"))
PY
check "baseline + approved exceptions" 0 "$(scan "$T/repo" --sec-dir "$T/sec" --enforce --out $T/o6)"
printf 'import subprocess\ndef go(c):\n    subprocess.Popen(c, shell=True)\n' > "$T/repo/app/new_issue.py"
check "NEW high-severity issue blocks" 1 "$(scan "$T/repo" --sec-dir "$T/sec" --enforce --out $T/o7)"
rm "$T/repo/app/new_issue.py"
sed -i 's/2999-01-01/2020-01-01/' "$T/sec/exceptions.json"
check "expired exceptions stop applying" 1 "$(scan "$T/repo" --sec-dir "$T/sec" --enforce --out $T/o8)"

echo "5. fail closed: missing scanner output must fail an enforced gate"
mkdir -p "$T/o9/raw"
python3 -I scripts/gate.py --out "$T/o9" --tools bandit --policy configs/policies/policy.json --enforce >/dev/null 2>&1
check "tool produced no report" 1 $?

echo "6. unresolvable manifest (conflicting pins, CRLF line endings) is audited pinned-only and flagged, never read as clean"
scan examples/conflicting-manifest --out "$T/o10" >/dev/null
python3 - "$T/o10" <<'PY'
import json,sys
R=sys.argv[1]; s=json.load(open(f"{R}/summary.json")); f=json.load(open(f"{R}/findings.json"))
ok = len(s["degraded_manifests"])==1 and s["degraded_manifests"][0].startswith("requirements.txt") and s["tool_status"]["pip-audit"]=="ok" and any("pip-audit" in x["tool"] for x in f)
sys.exit(0 if ok else 1)
PY
check "degraded manifest flagged and still audited" 0 $?

echo "7. Node manifest with no lockfile and a peer-dependency conflict is still audited (regression from a real app)"
scan examples/node-peer-conflict --partial --skip gitleaks,trivy,semgrep,eslint --out "$T/o11" >/dev/null
python3 - "$T/o11" <<'PY'
import json,sys
R=sys.argv[1]; s=json.load(open(f"{R}/summary.json")); f=json.load(open(f"{R}/findings.json"))
sys.exit(0 if s["tool_status"].get("npm-audit")=="ok" and any("npm-audit" in x["tool"] for x in f) and any("no lockfile" in m for m in s["degraded_manifests"]) else 1)
PY
check "npm audit works despite ERESOLVE, flagged as no-lockfile" 0 $?

echo; echo "selftest: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
