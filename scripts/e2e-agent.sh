#!/usr/bin/env bash
# End-to-end test of the agentic-AI controls: a VULNERABLE agent and the same agent HARDENED with agentic/agentsec.
# Builds and runs both on an isolated docker network, scans each (static + inventory + semgrep agent rules + red-team probes) and ASSERTS
# the outcomes. ~4 min. Exit 0 = every assertion held.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
NET=sec-test-agent; SECRET="e2e-broker-secret-$(openssl rand -hex 8 2>/dev/null || date +%s)"; T="$(mktemp -d)"
cleanup() { docker rm -f agent-v agent-s >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT
PASS=0; FAILN=0
check() { if [ "$2" = "OK" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1  ($2)"; FAILN=$((FAILN+1)); fi; }

echo "building images..."
docker build -q -t warden-agent-sample:test examples/agent-sample >/dev/null || exit 2
cp -r examples/agent-sample-secure/. "$T/ctx"; cp -r agentic/agentsec "$T/ctx/agentsec"
docker build -q -t warden-agent-sample-secure:test "$T/ctx" >/dev/null || exit 2
docker network create "$NET" >/dev/null 2>&1
docker run -d --name agent-v --network "$NET" warden-agent-sample:test >/dev/null
docker run -d --name agent-s --network "$NET" -e BROKER_SECRET="$SECRET" warden-agent-sample-secure:test >/dev/null
sleep 4
tok() { python3 -I -c "
import sys; sys.path.insert(0,'agentic')
from agentsec import CredentialBroker
print(CredentialBroker('$SECRET').issue(agent_id='login',on_behalf_of='$1',audience='agent-api',scopes=['chat','files:read','net:fetch','mail:send','data:delete'],extra={'roles':['user'],'tenant':'t1'},ttl=900))"; }

echo "== vulnerable agent"
( REDTEAM_TOKEN= REDTEAM_TOKEN_B= scripts/scan.sh examples/agent-sample --redteam-url http://agent-v:8000 --redteam-network "$NET" \
    --redteam-contract examples/agent-sample/redteam.json --enforce --out "$T/v" >"$T/v.log" 2>&1 ); RCV=$?
echo "== hardened agent"
( REDTEAM_TOKEN="$(tok alice)" REDTEAM_TOKEN_B="$(tok bob)" scripts/scan.sh examples/agent-sample-secure --redteam-url http://agent-s:8000 --redteam-network "$NET" \
    --redteam-contract examples/agent-sample-secure/redteam.json --enforce --out "$T/s" >"$T/s.log" 2>&1 ); RCS=$?
echo "== model file scan"
cp -a examples/clean-python "$T/models"; python3 -I - "$T/models" <<'PY'
import os, pickle, sys
class Evil:
    def __reduce__(self): return (os.system, ("echo pwned",))      # never executed here: modelscan only reads the bytes
open(os.path.join(sys.argv[1], "model.pkl"), "wb").write(pickle.dumps(Evil()))
PY
scripts/scan.sh "$T/models" --partial --skip gitleaks,trivy,semgrep,pip-audit --profile python --enforce --out "$T/m" >"$T/m.log" 2>&1; RCM=$?

python3 -I - "$T" "$RCV" "$RCS" "$RCM" <<'PY' > "$T/assert.txt"
import json, sys
T, rcv, rcs, rcm = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
def load(d):
    return json.load(open(f"{T}/{d}/summary.json")), json.load(open(f"{T}/{d}/findings.json"))
def emit(name, ok, why=""):
    print(f"{name}|{'OK' if ok else why or 'failed'}")
sv, fv = load("v"); ss, fs = load("s"); sm, fm = load("m")  # a missing report raises: the check script itself must fail loudly
emit("vulnerable: all tools ran", all(v == "ok" for v in sv["tool_status"].values()), str(sv["tool_status"]))
emit("vulnerable: enforced gate FAILS", rcv == 1, f"exit {rcv}")
rtv = [f for f in fv if f["tool"] == "redteam"]
emit("vulnerable: red team fails >= 18 probes", len(rtv) >= 18, f"{len(rtv)}")
agv = [f for f in fv if f["tool"] == "agent-scan"]
emit("vulnerable: inventory/governance finds >= 12 issues (MCP, prompt secret, tool, model, endpoint)", len(agv) >= 12, f"{len(agv)}")
need = {"tool-param-to-file", "tool-param-to-network", "tool-param-to-exec", "tool-param-to-sql", "guardrail-fail-open", "unauthenticated-route", "hardcoded-llm-key", "trust-remote-code", "dangerous-tool", "sensitive-data-in-logs"}
got = {k for k in need if any(k in f["rule"] for f in fv if "semgrep" in f["tool"])}
emit("vulnerable: agent Semgrep rules fire", got == need, f"missing {sorted(need - got)}")
emit("hardened: all tools ran", all(v == "ok" for v in ss["tool_status"].values()), str(ss["tool_status"]))
blocking_non_sca = [f for f in fs if f["severity"] in ("CRITICAL", "HIGH") and f["category"] != "SCA"]
emit("hardened: nothing blocks except third-party dependency CVEs (those change with the vulnerability DB over time)", not blocking_non_sca, str([f["rule"] for f in blocking_non_sca]))
fail_s = sorted(f["rule"] for f in fs if f["tool"] == "redteam")
emit("hardened: red team fails ONLY the paraphrased indirect-injection probe (known limit)", fail_s == ["RT-INJ-03"], str(fail_s))
emit("hardened: no agent governance findings", not [f for f in fs if f["tool"] == "agent-scan"], str([f["rule"] for f in fs if f["tool"] == "agent-scan"]))
emit("hardened: no agent Semgrep rule fires", not [f for f in fs if "semgrep" in f["tool"] and "warden-agent" in f["rule"]], "")
emit("red team probes were run, not skipped", ss.get("redteam", {}).get("probes_run", 0) >= 20 and sv.get("redteam", {}).get("probes_run", 0) >= 20, f"{sv.get('redteam', {}).get('probes_run')},{ss.get('redteam', {}).get('probes_run')}")
emit("modelscan flags the malicious pickle as CRITICAL and the gate fails", any(f["tool"] == "modelscan" and f["severity"] == "CRITICAL" for f in fm) and rcm == 1, f"exit {rcm}")
PY
while IFS='|' read -r name res; do check "$name" "$res"; done < "$T/assert.txt"
echo; echo "e2e-agent: $PASS passed, $FAILN failed"
[ "$FAILN" = 0 ]
