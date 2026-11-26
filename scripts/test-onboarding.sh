#!/usr/bin/env bash
# "Developer journey" test: exactly what a developer does, on every supported stack.
#   init -> doctor -> first scan (report-only, must not fail) -> enforce (must fail on the vulnerable fixture) -> upgrade keeps edits
# plus: config.env must be parsed, never executed. ~6 min. Run after changing scripts/, templates/ or configs/.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAILN=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1 (expected $2, got $3)"; FAILN=$((FAILN+1)); fi; }
exists() { [ -e "$2" ] && check "$1" 1 1 || check "$1" 1 0; }

journey() { # <name> <fixture-dir> <expected-profile> <expect-gate-fail:1|0>
  local name="$1" src="$2" prof="$3" expfail="$4" r="$T/$1"
  echo "== $name ($prof)"
  cp -a "$src" "$r"; rm -rf "$r/.security" "$r/reports"; git -C "$r" init -q 2>/dev/null
  out="$(scripts/warden init "$r" 2>&1)"; check "init succeeds" 0 $?
  echo "$out" | grep -q "detected stack : $prof" && check "detects $prof" 1 1 || check "detects $prof" 1 0
  exists "kit + shim + config installed" "$r/.security/warden"; exists "config.env created" "$r/.security/config.env"
  exists "GitHub workflow created" "$r/.github/workflows/security-scan.yml"
  ( cd "$r" && .security/warden doctor >/dev/null 2>&1 ); check "doctor passes" 0 $?
  ( cd "$r" && .security/warden scan >"$T/$name.scan.log" 2>&1 ); check "first scan is report-only (exit 0)" 0 $?
  exists "HTML report written" "$r/.security/reports/latest/summary.html"; exists "SARIF written" "$r/.security/reports/latest/results.sarif"
  grep -q 'report-only mode: the gate WOULD have failed' "$T/$name.scan.log" && w=1 || w=0; check "report-only tells the developer what would fail" "$expfail" "$w"
  ( cd "$r" && .security/warden config set SEC_PRESET standard >/dev/null 2>&1 ); check "config set SEC_PRESET standard" 0 $?
  grep -q '^SEC_PRESET=standard' "$r/.security/config.env" && check "config set edited the file in place" 1 1 || check "config set edited the file in place" 1 0
  ( cd "$r" && .security/warden scan >"$T/$name.enf.log" 2>&1 ); check "preset standard (enforce) -> exit" "$expfail" $?
  echo "# my edit" >> "$r/.security/config.env"
  scripts/warden init "$r" >/dev/null 2>&1; grep -q 'my edit' "$r/.security/config.env" && check "re-running init keeps my config" 1 1 || check "re-running init keeps my config" 1 0
}

journey python-vuln   examples/fastapi-sample python 1
journey node-vuln     examples/node-sample    node   1
journey java-vuln     examples/java-sample    java   1
journey python-clean  examples/clean-python   python 0
journey agent-vuln    examples/agent-sample   "python agent" 1

echo "== config.env is data, not code"
r="$T/evil"; cp -a examples/clean-python "$r"; scripts/warden init "$r" >/dev/null 2>&1
printf 'SEC_ENFORCE=0\nSEC_SKIP=$(touch %s/PWNED)\nEVIL_KEY=1\nSEC_GATE=pr; touch %s/PWNED2\nSEC_IMAGE=`touch %s/PWNED3`\n' "$T" "$T" "$T" >> "$r/.security/config.env"
( cd "$r" && .security/warden scan >"$T/evil.log" 2>&1 )
ls "$T"/PWNED* >/dev/null 2>&1 && check "malicious config.env executed code" 0 1 || check "malicious config.env executed nothing" 0 0
grep -q 'ignoring' "$T/evil.log" && check "unsafe values are reported and ignored" 1 1 || check "unsafe values are reported and ignored" 1 0

echo "== tool switches, required-tool lock, waivers, exclusions"
r="$T/python-clean"; rm -rf "$r/.security/reports"
( cd "$r" && .security/warden config set SEC_PRESET starter >/dev/null && .security/warden config set SEC_BANDIT off >/dev/null && .security/warden config set SEC_SEMGREP off >/dev/null )
show="$(cd "$r" && .security/warden config show 2>&1)"
echo "$show" | grep -qE '^  bandit +skip +turned off' && check "SEC_BANDIT=off is honoured" 1 1 || check "SEC_BANDIT=off is honoured" 1 0
echo "$show" | grep -qE '^  semgrep +RUN +REQUIRED' && check "required tool cannot be switched off" 1 1 || check "required tool cannot be switched off" 1 0
( cd "$r" && .security/warden scan >"$T/sw.log" 2>&1 ); check "scan with switches works" 0 $?
python3 -I - "$r/.security/reports/latest/summary.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); ts=d["tool_status"]
ok = "bandit" not in ts and "semgrep" in ts and "bandit" in d["tools_not_run"] and "semgrep" in d["tools_forced"]
sys.exit(0 if ok else 1)
PY
check "report records bandit as not run and semgrep as forced" 0 $?
printf '[{"tool":"semgrep","reason":"test waiver","approved_by":"sec-team","expires":"2099-01-01"}]' > "$r/.security/exceptions.json"
o="$(cd "$r" && .security/warden config show 2>&1)"; grep -qE '^  semgrep +skip +turned off, waived by sec-team' <<< "$o" && check "valid waiver lets a required tool be off" 1 1 || check "valid waiver lets a required tool be off" 1 0
printf '[{"tool":"semgrep","reason":"old","approved_by":"sec-team","expires":"2000-01-01"}]' > "$r/.security/exceptions.json"
o="$(cd "$r" && .security/warden config show 2>&1)"; grep -qE '^  semgrep +RUN' <<< "$o" && check "expired waiver is ignored" 1 1 || check "expired waiver is ignored" 1 0
echo '[]' > "$r/.security/exceptions.json"
o="$(cd "$r" && .security/warden config show 2>&1)"; grep -q 'preset=starter' <<< "$o" && check "config show prints the preset" 1 1 || check "config show prints the preset" 1 0
( cd "$r" && .security/warden config set 'SEC_BANDIT' 'x;touch PWNED4' >/dev/null 2>&1 ); check "config set rejects unsafe values" 2 $?
( cd "$r" && SEC_PRESET=nonsense .security/warden scan >/dev/null 2>&1 ); check "unknown preset fails fast (exit 2)" 2 $?

echo "== policy cannot be relaxed by the project"
printf '{"gates":{"pr":{"block_new":[],"block_existing":[]}},"severity_order":["CRITICAL"],"unknown_severity_as":"LOW","secret_severity":"LOW"}' > "$T/python-vuln/.security/policy.json"
( cd "$T/python-vuln" && .security/warden gate >/dev/null 2>&1 ); check "project policy.json is ignored (gate still fails)" 1 $?

echo "== git hook"
( cd "$T/python-clean" && .security/warden hook install >/dev/null 2>&1 && [ -x .git/hooks/pre-push ] ); check "pre-push hook installs" 0 $?

echo "== empty or new repo: sensible defaults, stacks picked up later without re-running init"
r="$T/emptyrepo"; mkdir -p "$r"; git -C "$r" init -q 2>/dev/null
out="$(scripts/warden init "$r" --ci github 2>&1)"; check "init works in an empty repo" 0 $?
grep -q "detected stack : generic" <<< "$out"; check "an empty repo is 'generic', not an AI-agent repo" 0 $?
grep -q "no code detected yet" <<< "$out"; check "init explains that language checks start by themselves" 0 $?
o="$(cd "$r" && .security/warden config show 2>&1)"; grep -qE '^  (gitleaks|semgrep|trivy-fs) +RUN' <<< "$o" && grep -qE '^  agent-scan +skip' <<< "$o"; check "stack-independent checks run and agent-scan stays off" 0 $?
printf 'flask==3.0.0\n' > "$r/requirements.txt"; printf 'print(1)\n' > "$r/app.py"
o="$(cd "$r" && .security/warden config show 2>&1)"; grep -qE '^  pip-audit +RUN' <<< "$o" && grep -q 'stacks=python' <<< "$o"; check "adding Python files later switches the Python checks on (no re-init)" 0 $?
for ex in java-sample iac-sample; do p="$(scripts/scan.sh "examples/$ex" --print-profiles)"; grep -qw agent <<< "$p" && check "$ex is not mistaken for an AI-agent repo" 0 1 || check "$ex is not mistaken for an AI-agent repo" 0 0; done

echo "== vendored kit is self-contained (nothing fetched from our repo)"
r="$T/vendored"; cp -a examples/clean-python "$r"; rm -rf "$r/.security"; git -C "$r" init -q 2>/dev/null
scripts/warden init "$r" --vendor --ci github >/dev/null 2>&1; check "vendored init succeeds" 0 $?
miss=""; for f in $(grep -ohE '(HERE|ROOT)/scripts/[A-Za-z_]+\.py' "$r/.security/kit/scripts/warden" "$r/.security/kit/scripts/scan.sh" | sed 's|.*/||' | sort -u); do [ -f "$r/.security/kit/scripts/$f" ] || miss="$miss $f"; done
[ -z "$miss" ] && check "every script the engine calls is inside .security/kit" 0 0 || { echo "    missing:$miss"; check "every script the engine calls is inside .security/kit" 0 1; }
( cd "$r" && .security/warden creds list >/dev/null 2>&1 ); check "vendored kit runs creds (copied helper works)" 0 $?
grep -qE 'git\+https|pip install|rakeshkolipakaTA' "$r/.github/workflows/security-scan.yml" "$r/.security/warden" && check "workflow and launcher do not fetch our repo" 0 1 || check "workflow and launcher do not fetch our repo" 0 0

echo; echo "onboarding test: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
