#!/usr/bin/env bash
# McKesson security scan runner.
#   scripts/scan.sh <repo-path> [options]        central mode: scan any repo from one install
#   .security/kit/scripts/scan.sh [options]      per-project kit: scans the enclosing repo
# Developers normally use the `warden` wrapper instead (docs/GETTING-STARTED.md).
#
# Settings come from (highest first): command-line flags > environment variables (SEC_*) > <repo>/.security/config.env > defaults.
#
# Options (each has an equivalent SEC_* key for config.env):
#   --profile auto|python|node|java|generic[,..]   SEC_PROFILE   stacks to scan (default auto-detect, several allowed)
#   --gate pr|release       SEC_GATE      which gate in policy.json to apply (default pr)
#   --enforce               SEC_ENFORCE=1 exit non-zero when the gate fails (default: report-only, never fails the build)
#   --preset NAME           SEC_PRESET    starter (default: report-only) | standard (blocks PRs) | strict (release gate + Sonar/Dependency-Check when configured)
#   per-tool switches       SEC_<TOOL>=auto|on|off   GITLEAKS SEMGREP TRIVY BANDIT PIP_AUDIT NPM_AUDIT ESLINT AGENT_SCAN MODELSCAN TRIVY_IMAGE DEPCHECK SONAR ZAP REDTEAM
#                           (tools the central policy marks REQUIRED ignore `off` unless .security/exceptions.json holds a valid waiver)
#   --skip a,b              SEC_SKIP      legacy list form of "=off": gitleaks,trivy,semgrep,bandit,pip-audit,npm-audit,eslint,agent-scan,modelscan
#   new checks (all SEC_<TOOL>=auto|on|off): GITLEAKS_HISTORY (secrets in past commits), SBOM, WORKFLOW_SCAN (GitHub Actions security), K8S_POSTURE,
#                           API_FUZZ (needs SEC_API_SPEC=<openapi url>), EXPOSURE (needs SEC_EXPOSURE_TARGETS=<urls/hosts you own>), REPO_POSTURE (needs GITHUB_TOKEN)
#   --partial               an intentionally incomplete local run (warden quick): required tools may be skipped
#   --publish-latest        send the newest report to the dashboard (needs SEC_DASHBOARD_URL + WARDEN_DASHBOARD_TOKEN)
#   --explain               print which tools would run and why, then exit (warden config show)
#   --exclude a,b           SEC_EXCLUDE_PATHS  path globs whose code findings (not dependency CVEs) are left out of the result, e.g. vendor/**,legacy/**
#   --no-semgrep            (same as --skip semgrep)
#   --sonar                 SEC_SONAR=1   SonarQube (needs SONAR_HOST_URL + SONAR_TOKEN env)   --sonar-key KEY  SEC_SONAR_KEY
#   --depcheck              SEC_DEPCHECK=1 OWASP Dependency-Check (needs NVD_API_KEY or a DB prepared by depcheck-update.sh)
#   --image NAME:TAG        SEC_IMAGE     also scan a built Docker image with Trivy
#   --zap-url URL[,URL..]   SEC_ZAP_URL   DAST with OWASP ZAP against a RUNNING app you are authorised to test (QA/UAT, never prod)
#   --zap-mode baseline|api|full   SEC_ZAP_MODE   baseline = passive crawl (finds little on pure APIs); api = OpenAPI import (needs
#                           --zap-openapi); full = ACTIVE scan of every URL in --zap-url (give URLs WITH query parameters)
#   --zap-network NET       SEC_ZAP_NETWORK  docker network the target lives on     --zap-openapi URL  SEC_ZAP_OPENAPI
#   --baseline FILE | --write-baseline   record today's findings as "existing" (default file <repo>/.security/baseline.json)
#   --sec-dir DIR           project config dir (default <repo>/.security): config.env, exceptions.json, baseline.json, overrides
#   --out DIR               report directory (default <reports>/<timestamp>, with a `latest` link)
#
#   --redteam-url URL       SEC_REDTEAM_URL  AI red-team probes against a RUNNING agent you own (QA/UAT only; real attacks). Tokens: REDTEAM_TOKEN[_B] env
#   --redteam-network NET   SEC_REDTEAM_NETWORK  docker network of the agent (enables the SSRF canary)   --redteam-contract FILE  SEC_REDTEAM_CONTRACT
#   (profile `agent` is auto-detected from agent frameworks/MCP config and adds: agentic Semgrep rules, inventory/registry scan, model-file scan)
#
# All tools run in pinned Docker images (versions.env). The target repo is mounted read-only; nothing is written into it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/versions.env"

REPO="" OUT="" SEC_DIR_ARG="" BASELINE="" WRITE_BASELINE=0 PRINT_PROFILES=0 EXPLAIN=0 PARTIAL=0 PUBLISH_LATEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) SEC_PROFILE="$2"; shift 2;; --gate) SEC_GATE="$2"; shift 2;; --enforce) SEC_ENFORCE=1; shift;;
    --skip) SEC_SKIP="$2"; shift 2;; --no-semgrep) SEC_SKIP="${SEC_SKIP:+$SEC_SKIP,}semgrep"; shift;;
    --sonar) SEC_SONAR=on; shift;; --sonar-key) SEC_SONAR_KEY="$2"; shift 2;; --depcheck) SEC_DEPCHECK=on; shift;;
    --image) SEC_IMAGE="$2"; shift 2;; --zap-url) SEC_ZAP_URL="$2"; shift 2;; --zap-mode) SEC_ZAP_MODE="$2"; shift 2;;
    --zap-network) SEC_ZAP_NETWORK="$2"; shift 2;; --zap-openapi) SEC_ZAP_OPENAPI="$2"; shift 2;;
    --baseline) BASELINE="$2"; shift 2;; --write-baseline) WRITE_BASELINE=1; shift;;
    --redteam-url) SEC_REDTEAM_URL="$2"; shift 2;; --redteam-network) SEC_REDTEAM_NETWORK="$2"; shift 2;; --redteam-contract) SEC_REDTEAM_CONTRACT="$2"; shift 2;;
    --preset) SEC_PRESET="$2"; shift 2;; --partial) PARTIAL=1; shift;; --explain) EXPLAIN=1; shift;; --publish-latest) PUBLISH_LATEST=1; shift;; --exclude) SEC_EXCLUDE_PATHS="$2"; shift 2;;
    --print-profiles) PRINT_PROFILES=1; shift;; --sec-dir) SEC_DIR_ARG="$2"; shift 2;; --out) OUT="$2"; shift 2;;
    -h|--help) sed -n '2,44p' "$0"; exit 0;;
    -*) echo "unknown option $1 (see --help)" >&2; exit 2;; *) REPO="$1"; shift;;
  esac
done

KIT_MODE=0
if [ "$(basename "$(dirname "$HERE")")" = ".security" ] && [ "$(basename "$HERE")" = "kit" ]; then
  KIT_MODE=1; [ -n "$REPO" ] || REPO="$(dirname "$(dirname "$HERE")")"
fi
[ -d "$REPO" ] || { echo "usage: scan.sh <repo-path> [options]   (see --help)" >&2; exit 2; }
REPO="$(cd "$REPO" && pwd)"; NAME="$(basename "$REPO")"
SEC_DIR="${SEC_DIR_ARG:-$REPO/.security}"; [ -d "$SEC_DIR" ] && SEC_DIR="$(cd "$SEC_DIR" && pwd)"

# ---- config.env: parsed, never sourced (a pull request must not be able to run code on the scanner) ----
CONFIG_KEYS=" SEC_HISTORY_FETCH SEC_SEMGREP_PACKS SEC_GITLEAKS_HISTORY SEC_SBOM SEC_WORKFLOW_SCAN SEC_K8S_POSTURE SEC_API_FUZZ SEC_EXPOSURE SEC_REPO_POSTURE SEC_API_SPEC SEC_API_NETWORK SEC_EXPOSURE_TARGETS SEC_HISTORY_COMMITS SEC_FUZZ_EXAMPLES SEC_SONAR_HOST_URL SEC_DASHBOARD_URL SEC_DISABLED_UNTIL SEC_PRESET SEC_EXCLUDE_PATHS SEC_GITLEAKS SEC_SEMGREP SEC_TRIVY SEC_BANDIT SEC_PIP_AUDIT SEC_NPM_AUDIT SEC_ESLINT SEC_AGENT_SCAN SEC_MODELSCAN SEC_TRIVY_IMAGE SEC_ZAP SEC_REDTEAM SEC_PROFILE SEC_GATE SEC_ENFORCE SEC_SKIP SEC_SONAR SEC_SONAR_KEY SEC_SEMGREP_RULES SEC_DEPCHECK SEC_DEPCHECK_NOUPDATE SEC_IMAGE SEC_ZAP_URL SEC_ZAP_MODE SEC_ZAP_NETWORK SEC_ZAP_OPENAPI SEC_REDTEAM_URL SEC_REDTEAM_NETWORK SEC_REDTEAM_CONTRACT "
load_config() {
  local line k v
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"; line="${line//$'\r'/}"
    [[ "$line" =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*[^[:space:]])?[[:space:]]*$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]:-}"; v="${v#\"}"; v="${v%\"}"
    [[ "$CONFIG_KEYS" == *" $k "* ]] || { echo "config.env: ignoring unknown key $k" >&2; continue; }
    [[ "$v" =~ ^[A-Za-z0-9_./:@,=?\&%+*-]*$ ]] || { echo "config.env: ignoring $k (value has unsupported characters)" >&2; continue; }
    [ -z "${!k:-}" ] && printf -v "$k" '%s' "$v"   # an empty env var counts as unset
  done < "$1"
}
[ -f "$SEC_DIR/config.env" ] && load_config "$SEC_DIR/config.env"
# organisation-wide defaults set once by the platform team (SonarQube / dashboard URLs): lowest precedence, a repo's config.env wins
[ -f "$HERE/configs/central.env" ] && load_config "$HERE/configs/central.env"
if [ -z "${SONAR_HOST_URL:-}" ] && [ -n "${SEC_SONAR_HOST_URL:-}" ]; then export SONAR_HOST_URL="$SEC_SONAR_HOST_URL"; fi
: "${SEC_PRESET:=starter}" "${SEC_PROFILE:=auto}" "${SEC_SKIP:=}" "${SEC_DEPCHECK_NOUPDATE:=0}" "${SEC_EXCLUDE_PATHS:=}" "${SEC_API_SPEC:=}" "${SEC_API_NETWORK:=}" "${SEC_EXPOSURE_TARGETS:=}" "${SEC_FUZZ_EXAMPLES:=40}"
# `warden disable --until DATE --reason ...` switches scanning off for a limited time only; after DATE it resumes by itself
if [ -n "${SEC_DISABLED_UNTIL:-}" ]; then
  if [[ "$SEC_DISABLED_UNTIL" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && ! [[ "$SEC_DISABLED_UNTIL" < "$(date +%F)" ]]; then
    echo "!! SECURITY SCANNING IS DISABLED for this repository until $SEC_DISABLED_UNTIL (see .security/config.env). Nothing was scanned." >&2; exit 0
  fi
  echo "note: SEC_DISABLED_UNTIL=$SEC_DISABLED_UNTIL has passed or is invalid; scanning is back on. Remove the line, or renew with: warden disable --until DATE --reason TEXT" >&2
fi
# the preset supplies the defaults for enforce/gate; anything set on the command line, in the environment or in config.env wins
POLICY="$HERE/configs/policies/policy.json"
PRESET_OUT="$(python3 -I "$HERE/scripts/toolplan.py" preset --policy "$POLICY" --preset "$SEC_PRESET")" || exit 2
read -r PRESET_ENFORCE PRESET_GATE <<< "$PRESET_OUT"
: "${SEC_ENFORCE:=$PRESET_ENFORCE}" "${SEC_GATE:=$PRESET_GATE}"
: "${SEC_IMAGE:=}" "${SEC_ZAP_URL:=}" "${SEC_ZAP_MODE:=baseline}" "${SEC_ZAP_NETWORK:=}" "${SEC_ZAP_OPENAPI:=}" "${SEC_SONAR_KEY:=}" "${SEC_SEMGREP_RULES:=}" "${SEC_SEMGREP_PACKS:=auto}" "${SEC_HISTORY_FETCH:=auto}"
: "${SEC_REDTEAM_URL:=}" "${SEC_REDTEAM_NETWORK:=}" "${SEC_REDTEAM_CONTRACT:=}"
case "$SEC_GATE" in pr|release) ;; *) echo "SEC_GATE must be pr or release" >&2; exit 2;; esac
ENFORCE=""; [ "$SEC_ENFORCE" = 1 ] && ENFORCE="--enforce"
skip() { [[ ",$SEC_SKIP," == *",$1,"* ]]; }

# reports go next to the repo's settings when it has a .security folder; a framework checkout keeps them under reports/; an installed package uses the user cache
if [ "$KIT_MODE" = 1 ] || [ -d "$REPO/.security" ]; then REPORT_BASE="$REPO/.security/reports"
elif [ -d "$HERE/.git" ]; then REPORT_BASE="$HERE/reports/$NAME"
else REPORT_BASE="${XDG_CACHE_HOME:-$HOME/.cache}/warden/reports/$NAME"; fi
if [ "$PUBLISH_LATEST" = 1 ]; then
  [ -f "$REPORT_BASE/latest/summary.json" ] || { echo "no report to publish yet: run a scan first" >&2; exit 1; }
  [ -n "${SEC_DASHBOARD_URL:-}" ] || { echo "SEC_DASHBOARD_URL is not set (config.env or configs/central.env); see docs/dashboard.md" >&2; exit 2; }
  exec python3 -I "$HERE/scripts/publish.py" --report "$REPORT_BASE/latest" --root "$REPO" --url "$SEC_DASHBOARD_URL" --strict
fi
if [ "$PRINT_PROFILES" != 1 ] && [ "$EXPLAIN" != 1 ]; then
  mkdir -p "$REPORT_BASE"
  OUT="${OUT:-$REPORT_BASE/$(date +%Y%m%d-%H%M%S)}"; mkdir -p "$OUT/raw"; OUT="$(cd "$OUT" && pwd)"
  ln -sfn "$OUT" "$REPORT_BASE/latest" 2>/dev/null || true
fi
BASELINE="${BASELINE:-$SEC_DIR/baseline.json}"
UIDGID="$(id -u):$(id -g)"
log() { printf '\n[%s] %s\n' "$(date +%T)" "$*"; }

# ---- stack detection: additive, one repo can be python + node (plan section 10) ----
PRUNE=(\( -name .git -o -name .venv -o -name venv -o -name node_modules -o -name .security -o -name build -o -name dist -o -name site-packages -o -name target -o -name __pycache__ \) -prune -o)
find_files() { find "$REPO" -maxdepth 5 "${PRUNE[@]}" -type f \( "$@" \) -print 2>/dev/null; }
has_files() { [ -n "$(find_files "$@" | head -1)" ]; }
PROFILES=()
if [ "$SEC_PROFILE" = auto ]; then
  has_files -name 'pyproject.toml' -o -name 'setup.py' -o -name 'requirements*.txt' -o -name 'Pipfile' -o -name '*.py' && PROFILES+=(python)
  has_files -name 'package.json' && PROFILES+=(node)
  has_files -name 'pom.xml' -o -name 'build.gradle' -o -name 'build.gradle.kts' -o -name '*.java' && PROFILES+=(java)
  # agentic AI: MCP config, or an agent/LLM framework in a dependency manifest or an import
  AGENT_FW='langchain|langgraph|llama[-_]index|openai|anthropic|autogen|crewai|fastmcp|(^|[^a-z])mcp([^a-z]|$)|semantic[-_]kernel|strands|pydantic[-_]ai|google-generativeai|dspy|haystack'
  if has_files -name '.mcp.json' -o -name 'mcp.json' -o -name 'claude_desktop_config.json' \
     || { find_files -name 'requirements*.txt' -o -name 'pyproject.toml' -o -name 'package.json' -o -name 'Pipfile'; } | xargs -r grep -qiE "$AGENT_FW" 2>/dev/null \
     || find_files -name '*.py' | xargs -r grep -qE "^[[:space:]]*(import|from)[[:space:]]+(langchain|langgraph|llama_index|openai|anthropic|autogen|crewai|fastmcp|mcp|semantic_kernel|strands|pydantic_ai|dspy|haystack)" 2>/dev/null; then PROFILES+=(agent); fi
  [ ${#PROFILES[@]} -gt 0 ] || PROFILES=(generic)
else
  IFS=',' read -ra PROFILES <<< "$SEC_PROFILE"
fi
is() { [[ " ${PROFILES[*]} " == *" $1 "* ]]; }
[ "$PRINT_PROFILES" = 1 ] && { echo "${PROFILES[*]}"; exit 0; }
model_files_present() { has_files -name '*.pkl' -o -name '*.pickle' -o -name '*.pt' -o -name '*.pth' -o -name '*.bin' -o -name '*.ckpt' -o -name '*.h5' -o -name '*.joblib' -o -name '*.npy' -o -name '*.keras'; }

# ---- which tools run: preset + SEC_<TOOL> switches + central required-tools lock + waivers (scripts/toolplan.py) ----
MODES=""; for kv in gitleaks:GITLEAKS semgrep:SEMGREP trivy-fs:TRIVY bandit:BANDIT pip-audit:PIP_AUDIT npm-audit:NPM_AUDIT eslint:ESLINT agent-scan:AGENT_SCAN \
  modelscan:MODELSCAN trivy-image:TRIVY_IMAGE dependency-check:DEPCHECK sonarqube:SONAR zap:ZAP redteam:REDTEAM \
  gitleaks-history:GITLEAKS_HISTORY sbom:SBOM workflow-scan:WORKFLOW_SCAN k8s-posture:K8S_POSTURE api-fuzz:API_FUZZ exposure:EXPOSURE repo-posture:REPO_POSTURE; do
  v="SEC_${kv#*:}"; [ -n "${!v:-}" ] && MODES="$MODES,${kv%%:*}=${!v}"
done
for t in ${SEC_SKIP//,/ }; do MODES="$MODES,$t=off"; done
# facts the plan needs: what this checkout looks like
FACTS=""
[ -d "$REPO/.git" ] && FACTS="$FACTS,git"
[ -d "$REPO/.github/workflows" ] && [ -n "$(ls "$REPO"/.github/workflows/*.y*ml 2>/dev/null | head -1)" ] && FACTS="$FACTS,workflows"
K8S_FILES="$(find_files -name '*.yaml' -o -name '*.yml' | xargs -r grep -lE '^kind:[[:space:]]*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|Service|Ingress|ClusterRole|Role|NetworkPolicy)([[:space:]]|$)' 2>/dev/null | xargs -r grep -L '{{' 2>/dev/null)"
[ -n "$K8S_FILES" ] && FACTS="$FACTS,k8s"
GH_SLUG="${GITHUB_REPOSITORY:-$(git -C "$REPO" config --get remote.origin.url 2>/dev/null | sed -nE 's#.*github\.com[:/]+([^/]+/[^/]+)$#\1#p' | sed 's/\.git$//')}"
[ -n "$GH_SLUG" ] && [ -n "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ] && FACTS="$FACTS,ghrepo"
PLAN_ARGS=(--facts "${FACTS#,}" --api-spec "$SEC_API_SPEC" --exposure-targets "$SEC_EXPOSURE_TARGETS" --policy "$HERE/configs/policies/policy.json" --preset "$SEC_PRESET" --profiles "$(IFS=,; echo "${PROFILES[*]}")" --modes "${MODES#,}"
  --image "${SEC_IMAGE:-}" --zap-url "${SEC_ZAP_URL:-}" --redteam-url "${SEC_REDTEAM_URL:-}")
[ -f "$SEC_DIR/exceptions.json" ] && PLAN_ARGS+=(--exceptions "$SEC_DIR/exceptions.json")
model_files_present && PLAN_ARGS+=(--model-files); [ "$PARTIAL" = 1 ] && PLAN_ARGS+=(--partial)
PLAN_JSON="$(python3 -I "$HERE/scripts/toolplan.py" plan "${PLAN_ARGS[@]}")" || exit 2
RUN_LIST="," PLAN_TXT="" CONFIG_ERR=0
while IFS=$'\t' read -r t r mode why; do
  [ "$r" = run ] && RUN_LIST="$RUN_LIST$t,"; PLAN_TXT="$PLAN_TXT$(printf '  %-17s %-5s %s' "$t" "$([ "$r" = run ] && echo RUN || echo skip)" "$why")"$'\n'
done < <(python3 -I -c 'import json,sys;d=json.loads(sys.argv[1]);[print("\t".join([t,"run" if v["run"] else "skip",v["mode"],v["reason"]])) for t,v in d["tools"].items()]' "$PLAN_JSON")
while IFS= read -r e; do [ -n "$e" ] || continue; echo "config: $e" >&2; case "$e" in *"=on but"*) CONFIG_ERR=1;; esac
done < <(python3 -I -c 'import json,sys;[print(x) for x in json.loads(sys.argv[1])["errors"]]' "$PLAN_JSON")
runs() { [[ "$RUN_LIST" == *",$1,"* ]]; }
if [ "$EXPLAIN" = 1 ]; then
  echo "preset=$SEC_PRESET enforce=$SEC_ENFORCE gate=$SEC_GATE stacks=${PROFILES[*]} (config: ${SEC_DIR}/config.env)"; printf '%s' "$PLAN_TXT"
  [ -n "$SEC_EXCLUDE_PATHS" ] && echo "  excluded paths (code findings only): $SEC_EXCLUDE_PATHS"
  echo "  sonarqube url: ${SONAR_HOST_URL:-not set}   token: $([ -n "${SONAR_TOKEN:-}" ] && echo set || echo 'not set (CI secret SONAR_TOKEN)')"
  echo "  dashboard url: ${SEC_DASHBOARD_URL:-not set}   token: $([ -n "${WARDEN_DASHBOARD_TOKEN:-}" ] && echo set || echo 'not set (CI secret WARDEN_DASHBOARD_TOKEN)')"
  exit "$CONFIG_ERR"
fi
[ "$CONFIG_ERR" = 0 ] || exit 2
log "target=$NAME profile=${PROFILES[*]} preset=$SEC_PRESET gate=$SEC_GATE mode=$([ -n "$ENFORCE" ] && echo enforce || echo report-only) out=$OUT"
printf '%s' "$PLAN_TXT" | grep -E ' (skip|RUN) .*(REQUIRED|waived)' | sed 's/^/  /'
printf '%s' "$PLAN_JSON" > "$OUT/plan.json"

# Project override files win over central defaults. The POLICY is deliberately NOT overridable by a project:
# a team must not be able to relax its own gate (change the policy centrally / via the kit upgrade).
cfg() { [ -f "$SEC_DIR/$2" ] && echo "$SEC_DIR/$2" || echo "$HERE/configs/$1/$2"; }
BANDIT_CFG="$(cfg bandit bandit.yaml)"; GITLEAKS_CFG="$(cfg gitleaks gitleaks.toml)"; TRIVY_CFG="$(cfg trivy trivy.yaml)"
ESLINT_CFG="$(cfg eslint eslint.config.mjs)"

ensure_image() { # <tag> <context-dir> [build-args...]
  local tag="$1" ctx="$2"; shift 2
  docker image inspect "$tag" >/dev/null 2>&1 || docker build -q -t "$tag" "$@" "$ctx" >/dev/null || { echo "failed to build $tag" >&2; return 1; }
}
ensure_scanner_image()      { ensure_image "$SCANNER_IMAGE" "$HERE/docker/scanner" --build-arg BANDIT_VERSION="$BANDIT_VERSION" --build-arg PIP_AUDIT_VERSION="$PIP_AUDIT_VERSION" --build-arg MODELSCAN_VERSION="$MODELSCAN_VERSION" --build-arg SCHEMATHESIS_VERSION="$SCHEMATHESIS_VERSION"; }
ensure_node_scanner_image() { ensure_image "$SCANNER_NODE_IMAGE" "$HERE/docker/scanner-node"; }
ensure_volume() { docker volume inspect "$1" >/dev/null 2>&1 || docker volume create "$1" >/dev/null; docker run --rm --user root --entrypoint chmod -v "$1:/v" "$2" 777 /v >/dev/null 2>&1; }
add_manifest() { # <map-file> <report-file> <manifest>
  local cur="{}"; [ -f "$1" ] && cur="$(cat "$1")"
  python3 -I -c 'import json,sys;d=json.loads(sys.argv[1]);d[sys.argv[2]]=sys.argv[3];print(json.dumps(d))' "$cur" "$2" "$3" > "$1"
}

TOOLS=()
run_gitleaks() {
  log "gitleaks: secrets in the working tree"
  docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -v "$GITLEAKS_CFG:/cfg/gitleaks.toml:ro" -v "$HERE/configs/gitleaks:/cfg-default:ro" -v "$OUT/raw:/out" \
    "$GITLEAKS_IMAGE" dir /src --config /cfg/gitleaks.toml --report-format json --report-path /out/gitleaks.json --redact --no-banner --exit-code 0 2>&1 | tail -2
  TOOLS+=(gitleaks)
}
run_trivy_fs() {
  log "trivy: dependency vulnerabilities, secrets, Dockerfile/IaC misconfiguration"
  ensure_volume mckesson-trivy-cache "$TRIVY_IMAGE"
  docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v mckesson-trivy-cache:/cache \
    -v "$REPO:/src:ro" -v "$TRIVY_CFG:/cfg/trivy.yaml:ro" -v "$OUT/raw:/out" \
    "$TRIVY_IMAGE" fs --config /cfg/trivy.yaml --format json --output /out/trivy-fs.json --quiet /src 2>&1 | tail -2
  TOOLS+=(trivy-fs)
}
run_gitleaks_history() {
  local max total note=""
  max="${SEC_HISTORY_COMMITS:-$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("history_scan",{}).get("max_commits",3000))' "$POLICY")}"
  total="$(git -C "$REPO" rev-list --count HEAD 2>/dev/null || echo 0)"
  [[ "$max" =~ ^[0-9]+$ ]] && [ "$max" -ge 1 ] || { echo "NOTE: SEC_HISTORY_COMMITS must be a positive number (got '$max'); using 3000" >&2; max=3000; }
  if [ "$(git -C "$REPO" rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    # A shallow checkout (CI default) has only the newest commit. SEC_HISTORY_FETCH=on (or auto with WARDEN_GIT_TOKEN set, as the generated GitHub workflow does)
    # fetches just the newest $max commits, so no full clone is needed.
    local want=0; case "$SEC_HISTORY_FETCH" in on) want=1;; auto) [ -n "${WARDEN_GIT_TOKEN:-}" ] && want=1;; esac
    if [ "$want" = 1 ]; then
      local hdr=() url base; url="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
      if [ -n "${WARDEN_GIT_TOKEN:-}" ] && [[ "$url" =~ ^(https?://[^/]+)/ ]]; then
        base="${BASH_REMATCH[1]}"; hdr=(-c "http.$base/.extraheader=AUTHORIZATION: basic $(printf 'x-access-token:%s' "$WARDEN_GIT_TOKEN" | base64 | tr -d '\n')")
      fi
      log "git history: shallow checkout, fetching the newest $max commits"
      local to=""; command -v timeout >/dev/null 2>&1 && to="timeout 240"
      $to git -C "$REPO" "${hdr[@]}" fetch --quiet --depth="$max" origin "$(git -C "$REPO" rev-parse HEAD)" >/dev/null 2>&1 \
        || echo "NOTE: could not fetch more history (no access to origin?); scanning what is available" >&2
    fi
  fi
  total="$(git -C "$REPO" rev-list --count HEAD 2>/dev/null || echo 0)"
  log "gitleaks: secrets in git history ($total commits, newest $max scanned at most)"
  [ "$(git -C "$REPO" rev-parse --is-shallow-repository 2>/dev/null)" = true ] && [ "$total" -lt "$max" ] && note="git history: shallow clone, so only $total commit(s) were available and older ones were not scanned (set SEC_HISTORY_FETCH=on to fetch up to $max, or check out with fetch-depth: 0)"
  [ "$total" -gt "$max" ] && note="${note:+$note; }git history: only the newest $max of $total commits were scanned (raise SEC_HISTORY_COMMITS)"
  docker run --rm --user "$UIDGID" -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src -v "$REPO:/src:ro" -v "$GITLEAKS_CFG:/cfg/gitleaks.toml:ro" \
    -v "$HERE/configs/gitleaks:/cfg-default:ro" -v "$OUT/raw:/out" "$GITLEAKS_IMAGE" git /src --config /cfg/gitleaks.toml --log-opts="--max-count=$max" \
    --report-format json --report-path /out/gitleaks-history.json --redact --no-banner --exit-code 0 2>&1 | tail -2
  [ -n "$note" ] && printf '%s\n' "$note" > "$OUT/raw/gitleaks-history.note"
  TOOLS+=(gitleaks-history)
}
run_sbom() {
  log "sbom: CycloneDX software bill of materials (Trivy)"
  ensure_volume mckesson-trivy-cache "$TRIVY_IMAGE"
  docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v mckesson-trivy-cache:/cache -v "$REPO:/src:ro" -v "$TRIVY_CFG:/cfg/trivy.yaml:ro" -v "$OUT/raw:/out" \
    "$TRIVY_IMAGE" fs --config /cfg/trivy.yaml --scanners vuln --format cyclonedx --output /out/sbom.json --quiet /src 2>&1 | tail -2
  [ -s "$OUT/raw/sbom.json" ] && cp "$OUT/raw/sbom.json" "$OUT/sbom.cdx.json"   # CycloneDX; kept next to the report for download
  TOOLS+=(sbom)
}
run_workflow_scan() {
  log "zizmor: GitHub Actions security (unpinned actions, script injection, excessive permissions)"
  docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -w /src "$ZIZMOR_IMAGE" --format json --no-progress --offline . > "$OUT/raw/workflow-scan.tmp" 2> "$OUT/workflow-scan.log"
  local rc=$?   # zizmor exits 10-14 when it has findings: only a missing/invalid JSON document is an error
  if python3 -I -c 'import json,sys;sys.exit(0 if isinstance(json.load(open(sys.argv[1])),list) else 1)' "$OUT/raw/workflow-scan.tmp" 2>/dev/null; then mv "$OUT/raw/workflow-scan.tmp" "$OUT/raw/workflow-scan.json"; else rm -f "$OUT/raw/workflow-scan.tmp"; echo "zizmor produced no report (exit $rc), see $OUT/workflow-scan.log"; fi
  TOOLS+=(workflow-scan)
}
run_k8s_posture() {
  log "kubescape: Kubernetes manifest posture (NSA hardening framework)"
  local tmp; tmp="$(mktemp -d)"; chmod 755 "$tmp"
  while IFS= read -r f; do [ -n "$f" ] && { mkdir -p "$tmp/$(dirname "${f#"$REPO"/}")"; cp "$f" "$tmp/${f#"$REPO"/}"; }; done <<< "$K8S_FILES"
  docker run --rm --user "$UIDGID" -e HOME=/tmp -v "$tmp:/src:ro" -v "$OUT/raw:/out" "$KUBESCAPE_IMAGE" scan framework nsa --format json --output /out/k8s-posture.json \
    --logger error --verbose=false --submit=false /src > "$OUT/k8s-posture.log" 2>&1 || true
  rm -rf "$tmp"
  [ -s "$OUT/raw/k8s-posture.json" ] || echo "kubescape produced no report (it downloads its control definitions: is github.com reachable?), see $OUT/k8s-posture.log"
  TOOLS+=(k8s-posture)
}
run_api_fuzz() {
  log "schemathesis: API fuzzing from the OpenAPI spec $SEC_API_SPEC (QA/UAT only)"
  ensure_scanner_image || return
  local net=(); [ -n "${SEC_API_NETWORK:-$SEC_ZAP_NETWORK}" ] && net=(--network "${SEC_API_NETWORK:-$SEC_ZAP_NETWORK}")
  docker run --rm "${net[@]}" -e API_TEST_TOKEN -v "$OUT/raw:/out" "$SCANNER_IMAGE" sh -c \
    'schemathesis run "$0" --checks all --hypothesis-max-examples="$1" --hypothesis-suppress-health-check=all ${API_TEST_TOKEN:+-H "Authorization: Bearer $API_TEST_TOKEN"} --junit-xml=/out/schemathesis.xml' \
    "$SEC_API_SPEC" "$SEC_FUZZ_EXAMPLES" > "$OUT/api-fuzz.log" 2>&1
  grep -E 'passed|failed|errored' "$OUT/api-fuzz.log" | tail -1
  python3 -I "$HERE/scripts/api_fuzz_report.py" --junit "$OUT/raw/schemathesis.xml" --spec "$SEC_API_SPEC" --out "$OUT/raw/api-fuzz.json" || echo "api-fuzz produced no report, see $OUT/api-fuzz.log"
  TOOLS+=(api-fuzz)
}
run_exposure() {
  log "exposure: TLS, headers, sensitive paths and open ports of $SEC_EXPOSURE_TARGETS (only systems you own)"
  python3 -I "$HERE/scripts/exposure.py" --targets "$SEC_EXPOSURE_TARGETS" --out "$OUT/raw/exposure.json" || echo "exposure check failed"
  TOOLS+=(exposure)
}
run_repo_posture() {
  log "repo-posture: GitHub repository settings ($GH_SLUG)"
  python3 -I "$HERE/scripts/repo_posture.py" --repo "$GH_SLUG" --root "$REPO" --out "$OUT/raw/repo-posture.json" || echo "repo-posture check failed (token without read access?)"
  TOOLS+=(repo-posture)
}
run_trivy_image() {
  log "trivy: container image $SEC_IMAGE"
  ensure_volume mckesson-trivy-cache "$TRIVY_IMAGE"
  docker run --rm -e TRIVY_CACHE_DIR=/cache -v mckesson-trivy-cache:/cache -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$OUT/raw:/out" "$TRIVY_IMAGE" image --scanners vuln,secret,license --format json --output /out/trivy-image.json --quiet "$SEC_IMAGE" 2>&1 | tail -2
  docker run --rm -e TRIVY_CACHE_DIR=/cache -v mckesson-trivy-cache:/cache -v /var/run/docker.sock:/var/run/docker.sock -v "$OUT/raw:/out" "$TRIVY_IMAGE" image \
    --compliance docker-cis-1.6.0 --format json --output /out/trivy-image-cis.json --quiet "$SEC_IMAGE" >/dev/null 2>&1 || true   # CIS Docker benchmark (advisory)
  TOOLS+=(trivy-image)
}
run_semgrep() {
  log "semgrep: code analysis (${PROFILES[*]})"
  local cfgs=(--config p/default --config p/owasp-top-ten) ex=() p
  if [ -n "$SEC_SEMGREP_RULES" ]; then cfgs=(--config /rules)   # offline / approved rule set
  else
    is python && cfgs+=(--config p/python)
    is node   && cfgs+=(--config p/javascript --config p/typescript --config p/nodejs)
    is java   && cfgs+=(--config p/java)
    # Extra SAST rule packs (injection, XSS, JWT, insecure transport, CWE Top 25, framework packs). SEC_SEMGREP_PACKS: auto (default) | none | p/a,p/b (replaces the list)
    local packs=()
    case "$SEC_SEMGREP_PACKS" in
      none) ;;
      auto) packs=(p/security-audit p/cwe-top-25 p/sql-injection p/command-injection p/insecure-transport p/jwt)
            is python && packs+=(p/flask p/django p/fastapi)
            is node   && packs+=(p/xss p/expressjs p/react)
            [ -n "$(find "$REPO" -maxdepth 4 -iname 'Dockerfile*' -not -path '*/node_modules/*' -print -quit 2>/dev/null)" ] && packs+=(p/dockerfile);;
      *)    IFS=, read -r -a packs <<<"$SEC_SEMGREP_PACKS";;
    esac
    local pk used_packs=(); for pk in "${packs[@]}"; do
      [[ "$pk" =~ ^[pr]/[A-Za-z0-9._-]+$ ]] || { echo "NOTE: ignored invalid Semgrep pack '$pk' in SEC_SEMGREP_PACKS (expected p/name)" >&2; continue; }
      cfgs+=(--config "$pk"); used_packs+=("$pk")
    done
    log "semgrep extra packs: ${used_packs[*]:-none}"
  fi
  local rmount=()
  if is agent; then cfgs+=(--config /agentic-rules); rmount=(-v "$HERE/configs/semgrep/agentic:/agentic-rules:ro"); fi
  for p in .security node_modules .venv venv build dist tests test '*.egg-info' '*.min.js' '*.yaml.test'; do ex+=(--exclude "$p"); done
  # rules that are noise for everyone (e.g. "python 3.7 compatibility"); one rule id per line in configs/semgrep/exclude-rules.txt
  while IFS= read -r p; do p="${p%%#*}"; p="${p//[[:space:]]/}"; [ -n "$p" ] && ex+=(--exclude-rule "$p"); done < "$HERE/configs/semgrep/exclude-rules.txt"
  local mounts=("${rmount[@]}"); [ -n "$SEC_SEMGREP_RULES" ] && mounts+=(-v "$SEC_SEMGREP_RULES:/rules:ro")
  docker run --rm --user "$UIDGID" -e HOME=/tmp -v "$REPO:/src:ro" -v "$OUT/raw:/out" "${mounts[@]}" "$SEMGREP_IMAGE" \
    semgrep scan --metrics=off --disable-version-check --quiet --json --output /out/semgrep.json "${cfgs[@]}" "${ex[@]}" /src 2>&1 | tail -3
  TOOLS+=(semgrep)
}
run_bandit() {
  log "bandit: Python code security"
  ensure_scanner_image || return
  docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -v "$BANDIT_CFG:/cfg/bandit.yaml:ro" -v "$OUT/raw:/out" "$SCANNER_IMAGE" \
    bandit -r /src -c /cfg/bandit.yaml -f json -o /out/bandit.json -q 2>&1 | tail -3
  TOOLS+=(bandit)
}
run_pip_audit() {
  log "pip-audit: Python dependencies (every requirements*.txt in the repo, plus root pyproject/setup.py)"
  ensure_scanner_image || return
  local manifests=() n=0 m
  while IFS= read -r m; do manifests+=("${m#"$REPO"/}"); done < <(find_files -name 'requirements*.txt' | sort)
  if [ ${#manifests[@]} -eq 0 ]; then
    if [ -f "$REPO/pyproject.toml" ] || [ -f "$REPO/setup.py" ]; then manifests=("."); else echo "no python dependency manifest found - skipping pip-audit"; return; fi
  fi
  TOOLS+=(pip-audit)
  for m in "${manifests[@]}"; do
    n=$((n+1)); local out="pip-audit-$n.json"; echo "  [$n/${#manifests[@]}] $m"
    if [ "$m" = "." ]; then
      # pyproject/setup.py: pip-audit builds the project in place, so give it a writable copy
      local tmp; tmp="$(mktemp -d)"; cp -a "$REPO/." "$tmp/" 2>/dev/null; rm -rf "$tmp/.git" "$tmp/.venv" "$tmp/venv" "$tmp/node_modules" "$tmp/.security"
      docker run --rm --user "$UIDGID" -v "$tmp:/src" -v "$OUT/raw:/out" "$SCANNER_IMAGE" pip-audit /src -f json -o "/out/$out" --progress-spinner off 2>&1 | tail -3
      rm -rf "$tmp"; m="pyproject.toml"
    else
      docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -v "$OUT/raw:/out" "$SCANNER_IMAGE" \
        pip-audit -r "/src/$m" -f json -o "/out/$out" --progress-spinner off >"$OUT/pip-audit-$n.log" 2>&1
      if [ ! -s "$OUT/raw/$out" ]; then
        # Normal mode resolves the whole tree and fails when the manifest is not installable (conflicting pins).
        # Fallback: audit only the pinned lines as written (no resolution, no transitive deps) and flag the manifest as degraded.
        echo "    resolution failed ($(grep -m1 -oE 'ResolutionImpossible|conflict[a-z ]*|No matching distribution[^"]*' "$OUT/pip-audit-$n.log" | head -1)); retrying pinned-only"
        local tmpd; tmpd="$(mktemp -d)"; tr -d '\r' < "$REPO/$m" | grep -E '^[][A-Za-z0-9_.-]+==' > "$tmpd/pinned.txt" || true   # CRLF-safe
        # never treat "nothing to audit" as "nothing vulnerable"
        [ -s "$tmpd/pinned.txt" ] && docker run --rm --user "$UIDGID" -v "$tmpd:/in:ro" -v "$OUT/raw:/out" "$SCANNER_IMAGE" \
          pip-audit -r /in/pinned.txt --no-deps --disable-pip -f json -o "/out/$out" --progress-spinner off 2>&1 | tail -2
        rm -rf "$tmpd"; [ -s "$OUT/raw/$out" ] && m="$m|degraded"
      fi
    fi
    [ -s "$OUT/raw/$out" ] || echo "NO-REPORT" > "$OUT/raw/$out"   # fail closed: shows up as a tool error
    add_manifest "$OUT/raw/pip-audit.manifests" "$out" "$m"
  done
}
run_npm_audit() {
  log "npm audit: Node dependencies (every package-lock.json in the repo)"
  ensure_node_scanner_image || return
  local dirs=() n=0 d
  while IFS= read -r d; do dirs+=("$(dirname "${d#"$REPO"/}")"); done < <(find_files -name 'package.json' | sort)
  [ ${#dirs[@]} -gt 0 ] || { echo "no package.json - skipping"; return; }
  for d in "${dirs[@]}"; do
    local lock="$d/package-lock.json"; [ "$d" = "." ] && lock="package-lock.json"
    local out="npm-audit-$((n+1)).json" mf
    if [ -f "$REPO/$lock" ] || [ -f "$REPO/$d/npm-shrinkwrap.json" ]; then
      n=$((n+1)); echo "  [$n] $lock"
      docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -w "/src/$d" "$SCANNER_NODE_IMAGE" npm audit --json --package-lock-only > "$OUT/raw/$out" 2>"$OUT/npm-audit-$n.log"
      mf="$lock"
    elif [ -f "$REPO/$d/yarn.lock" ] || [ -f "$REPO/$d/pnpm-lock.yaml" ]; then
      echo "  $d uses yarn/pnpm: dependencies are covered by Trivy only (npm audit needs package-lock.json)"; continue
    else
      n=$((n+1)); echo "  [$n] $d/package.json has NO lockfile: auditing freshly resolved versions (degraded)"
      local tmp; tmp="$(mktemp -d)"; cp "$REPO/$d/package.json" "$tmp/"
      docker run --rm --user "$UIDGID" -v "$tmp:/w" -w /w "$SCANNER_NODE_IMAGE" sh -c 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps >/tmp/npm-install.log 2>&1 || cp /tmp/npm-install.log /w/npm-install.log; npm audit --json --package-lock-only' > "$OUT/raw/$out" 2>"$OUT/npm-audit-$n.log"
      [ -f "$tmp/npm-install.log" ] && { echo "    resolving the dependency tree failed:"; grep -m3 'npm error' "$tmp/npm-install.log" | sed 's/^/      /'; }
      rm -rf "$tmp"; mf="$d/package.json|nolock"
    fi
    add_manifest "$OUT/raw/npm-audit.manifests" "$out" "$mf"
  done
  [ "$n" -gt 0 ] && TOOLS+=(npm-audit)
}
run_eslint() {
  has_files -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.mjs' || { echo "no JavaScript/TypeScript files - skipping eslint"; return; }
  log "eslint: JavaScript/TypeScript security rules"
  ensure_node_scanner_image || return
  docker run --rm --user "$UIDGID" -v "$REPO:/src:ro" -w /src -v "$ESLINT_CFG:/opt/eslint/eslint.config.mjs:ro" -v "$OUT/raw:/out" "$SCANNER_NODE_IMAGE" \
    eslint -c /opt/eslint/eslint.config.mjs --no-warn-ignored -f json -o /out/eslint.json . 2>&1 | tail -3
  TOOLS+=(eslint)
}
run_depcheck() {
  log "OWASP dependency-check"
  if [ -z "${NVD_API_KEY:-}" ] && [ "$SEC_DEPCHECK_NOUPDATE" != 1 ]; then echo "WARNING: NVD_API_KEY not set - the NVD download is very slow / rate limited. Prepare the database with scripts/depcheck-update.sh and set SEC_DEPCHECK_NOUPDATE=1."; fi
  ensure_volume mckesson-depcheck-data "$DEPCHECK_IMAGE"
  local extra=(); [ -n "${NVD_API_KEY:-}" ] && extra+=(--nvdApiKey "$NVD_API_KEY"); [ "$SEC_DEPCHECK_NOUPDATE" = 1 ] && extra+=(--noupdate)
  TOOLS+=(dependency-check)
  docker run --rm --user "$UIDGID" -v mckesson-depcheck-data:/usr/share/dependency-check/data \
    -v "$REPO:/src:ro" -v "$OUT/raw:/out" -v "$HERE/configs/dependency-check/suppression.xml:/cfg/suppression.xml:ro" \
    "$DEPCHECK_IMAGE" --scan /src --format JSON --out /out --project "$NAME" --suppression /cfg/suppression.xml \
    --exclude '**/.venv/**' --exclude '**/node_modules/**' "${extra[@]}" > "$OUT/depcheck.log" 2>&1
  tail -3 "$OUT/depcheck.log"
  [ -f "$OUT/raw/dependency-check-report.json" ] && mv "$OUT/raw/dependency-check-report.json" "$OUT/raw/dependency-check.json"
}
run_agent_scan() {
  log "agent-scan: inventory of models/endpoints/tools/MCP servers vs the central registry"
  TOOLS+=(agent-scan)
  python3 -I "$HERE/scripts/agent_scan.py" "$REPO" --registry "$HERE/configs/agentic/approved-models.json" --out "$OUT/raw" 2>&1 | tail -2
}
run_modelscan() {
  model_files_present || { echo "no model files - skipping modelscan"; return; }
  log "modelscan: serialized model files (malicious pickle / pytorch / keras payloads)"
  ensure_scanner_image || return
  TOOLS+=(modelscan)
  docker run --rm --user "$UIDGID" -e HOME=/tmp -v "$REPO:/m:ro" -v "$OUT/raw:/out" -w /tmp "$SCANNER_IMAGE" modelscan scan -p /m -r json -o /out/modelscan.json >/dev/null 2>&1
  [ -s "$OUT/raw/modelscan.json" ] && python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print("modelscan: %d issue(s)"%len(d.get("issues",[])))' "$OUT/raw/modelscan.json"
}
run_redteam() {
  log "AI red team against $SEC_REDTEAM_URL (real attack probes: only against QA/UAT you own)"
  ensure_scanner_image || return
  TOOLS+=(redteam)
  local contract="${SEC_REDTEAM_CONTRACT:-$SEC_DIR/redteam.json}" net=() canary=() name="warden-rt-$$"
  if [ -f "$contract" ]; then contract="$(readlink -f "$contract")"; else echo "no contract at $contract (see docs/agentic-redteam.md): using defaults"; contract=/dev/null; fi
  if [ -n "$SEC_REDTEAM_NETWORK" ]; then net=(--network "$SEC_REDTEAM_NETWORK"); canary=(--canary-host "$name"); else net=(--network host); fi
  docker run --rm --name "$name" "${net[@]}" -e REDTEAM_TOKEN -e REDTEAM_TOKEN_B -v "$HERE/scripts/redteam.py:/rt/redteam.py:ro" \
    -v "$contract:/rt/contract.json:ro" -v "$OUT/raw:/out" "$SCANNER_IMAGE" \
    python /rt/redteam.py --url "$SEC_REDTEAM_URL" --contract /rt/contract.json --out /out "${canary[@]}" > "$OUT/redteam.log" 2>&1
  local rc=$?; grep -E '^redteam:' "$OUT/redteam.log" | head -3
  [ "$rc" = 0 ] || echo "red team did not complete (exit $rc); see $OUT/redteam.log"
}
run_sonar() {
  : "${SONAR_HOST_URL:?set SONAR_HOST_URL (e.g. http://localhost:9000)}" "${SONAR_TOKEN:?set SONAR_TOKEN}"
  local key="${SEC_SONAR_KEY:-mckesson-$NAME}"
  log "sonarqube analysis (project key $key)"
  ensure_volume mckesson-sonar-scanner-cache "$SONAR_SCANNER_IMAGE"
  TOOLS+=(sonarqube)   # registered first: if anything below fails the gate reports it (fail closed)
  # -Dsonar.qualitygate.wait=true makes the scanner exit non-zero on a failed quality gate; gate.py judges that, so the exit code is ignored here
  docker run --rm --network host --user "$UIDGID" -e SONAR_HOST_URL -e SONAR_TOKEN -e SONAR_USER_HOME=/cache \
    -v mckesson-sonar-scanner-cache:/cache -v "$REPO:/usr/src:ro" -v "$OUT:/out" "$SONAR_SCANNER_IMAGE" sonar-scanner \
    -Dsonar.projectKey="$key" -Dsonar.projectName="$NAME" -Dsonar.sources=. \
    -Dsonar.scanner.metadataFilePath=/out/report-task.txt -Dsonar.qualitygate.wait=true \
    -Dsonar.exclusions='**/.security/**,**/node_modules/**,**/dist/**,**/build/**,**/.venv/**,**/venv/**,**/*.egg-info/**,**/__pycache__/**,**/.pytest_cache/**' \
    -Dsonar.working.directory=/tmp/scanwork > "$OUT/sonar-scanner.log" 2>&1
  grep -E 'ERROR|QUALITY GATE|ANALYSIS (SUCCESSFUL|FAILED)|EXECUTION' "$OUT/sonar-scanner.log" | tail -6
  if ! grep -q '^ceTaskId=' "$OUT/report-task.txt" 2>/dev/null; then echo "sonar analysis did not run (see $OUT/sonar-scanner.log)"; return; fi
  curl -sf -u "$SONAR_TOKEN:" "$SONAR_HOST_URL/api/issues/search?componentKeys=$key&resolved=false&ps=500" > "$OUT/raw/sonarqube.json" || rm -f "$OUT/raw/sonarqube.json"
  curl -sf -u "$SONAR_TOKEN:" "$SONAR_HOST_URL/api/qualitygates/project_status?projectKey=$key" > "$OUT/raw/sonarqube-qualitygate.json" || true
}
# Authenticated scans: ZAP_AUTH_TOKEN (sent as "Authorization: Bearer <token>") or ZAP_AUTH_HEADER ("Name: value"), both CI secrets.
# They reach the container through the environment (never the command line) and become a ZAP replacer rule on every request.
ZAP_WRAP='hn=""; if [ -n "$ZAP_AUTH_TOKEN" ]; then hn=Authorization; hv="Bearer $ZAP_AUTH_TOKEN"; elif [ -n "$ZAP_AUTH_HEADER" ]; then hn="${ZAP_AUTH_HEADER%%:*}"; hv="${ZAP_AUTH_HEADER#*:}"; hv="${hv# }"; fi
if [ -n "$hn" ]; then hv="${hv// /\\ }"; zo="-config replacer.full_list(0).description=warden-auth -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=$hn -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=$hv"; exec "$@" -z "$zo"; fi
exec "$@"'
run_zap() {
  log "OWASP ZAP $SEC_ZAP_MODE scan against $SEC_ZAP_URL (authorised, non-production targets only)$([ -n "${ZAP_AUTH_TOKEN:-}${ZAP_AUTH_HEADER:-}" ] && echo ', authenticated')"
  TOOLS+=(zap)
  chmod 777 "$OUT/raw"   # the ZAP image runs as its own user and writes its report here
  local netargs=(); [ -n "$SEC_ZAP_NETWORK" ] && netargs=(--network "$SEC_ZAP_NETWORK")
  local rules=(); [ -f "$SEC_DIR/zap-rules.tsv" ] && rules=(-c /zap/wrk/zap-rules.tsv) && cp "$SEC_DIR/zap-rules.tsv" "$OUT/raw/zap-rules.tsv"
  if [ "$SEC_ZAP_MODE" = api ]; then
    : "${SEC_ZAP_OPENAPI:?--zap-mode api needs --zap-openapi URL}"
    docker run --rm "${netargs[@]}" -e ZAP_AUTH_TOKEN -e ZAP_AUTH_HEADER -v "$OUT/raw:/zap/wrk:rw" "$ZAP_IMAGE" bash -c "$ZAP_WRAP" zap zap-api-scan.py -t "$SEC_ZAP_OPENAPI" -f openapi \
      -J zap.json -I "${rules[@]}" > "$OUT/zap.log" 2>&1
  elif [ "$SEC_ZAP_MODE" = full ]; then
    # one ACTIVE scan per seed URL, in parallel (ZAP is memory hungry: at most 3 at a time)
    local i=0 running=0 seed
    : > "$OUT/zap.log"
    for seed in ${SEC_ZAP_URL//,/ }; do
      i=$((i+1))
      docker run --rm "${netargs[@]}" -e ZAP_AUTH_TOKEN -e ZAP_AUTH_HEADER -v "$OUT/raw:/zap/wrk:rw" "$ZAP_IMAGE" bash -c "$ZAP_WRAP" zap zap-full-scan.py -t "$seed" -J "zap-$i.json" -I -m 1 \
        "${rules[@]}" > "$OUT/zap-$i.log" 2>&1 &
      running=$((running+1)); [ "$running" -ge 3 ] && { wait -n; running=$((running-1)); }
    done
    wait
    cat "$OUT"/zap-*.log >> "$OUT/zap.log" 2>/dev/null
    [ -n "$(ls "$OUT"/raw/zap-*.json 2>/dev/null)" ] || echo "ZAP produced no report (see $OUT/zap-*.log)"
  else
    docker run --rm "${netargs[@]}" -e ZAP_AUTH_TOKEN -e ZAP_AUTH_HEADER -v "$OUT/raw:/zap/wrk:rw" "$ZAP_IMAGE" bash -c "$ZAP_WRAP" zap zap-baseline.py -t "$SEC_ZAP_URL" \
      -J zap.json -I "${rules[@]}" > "$OUT/zap.log" 2>&1
  fi
  grep -E '^FAIL-NEW|^WARN-NEW' "$OUT/zap.log" | sort | uniq -c | head -12
  [ "$SEC_ZAP_MODE" = full ] || [ -s "$OUT/raw/zap.json" ] || echo "ZAP produced no report (see $OUT/zap.log)"
}

# ---- run the tools chosen above ----
runs gitleaks         && run_gitleaks
runs gitleaks-history && run_gitleaks_history
runs trivy-fs         && run_trivy_fs
runs sbom             && run_sbom
runs workflow-scan    && run_workflow_scan
runs k8s-posture      && run_k8s_posture
runs repo-posture     && run_repo_posture
runs semgrep          && run_semgrep
runs bandit           && run_bandit
runs pip-audit        && run_pip_audit
runs npm-audit        && run_npm_audit
runs eslint           && run_eslint
runs agent-scan       && run_agent_scan
runs modelscan        && run_modelscan
runs dependency-check && run_depcheck
runs sonarqube        && run_sonar
runs trivy-image      && run_trivy_image
runs zap              && run_zap
runs api-fuzz         && run_api_fuzz
runs exposure         && run_exposure
runs redteam          && run_redteam

# ---- gate ----
ARGS=(--out "$OUT" --tools "$(IFS=,; echo "${TOOLS[*]}")" --policy "$POLICY" --gate "$SEC_GATE" --root "$REPO" --target "$NAME" --plan "$OUT/plan.json" --crosswalk "$HERE/configs/compliance/crosswalk.json")
[ -n "$SEC_EXCLUDE_PATHS" ] && ARGS+=(--exclude "$SEC_EXCLUDE_PATHS")
[ -f "$SEC_DIR/exceptions.json" ] && ARGS+=(--exceptions "$SEC_DIR/exceptions.json")
if [ "$WRITE_BASELINE" = 1 ]; then
  mkdir -p "$SEC_DIR" 2>/dev/null || { echo "cannot write $SEC_DIR - writing baseline into $OUT instead"; SEC_DIR="$OUT"; }
  python3 -I "$HERE/scripts/gate.py" "${ARGS[@]}" --write-baseline "${BASELINE_OUT:-$SEC_DIR/baseline.json}"; exit $?
fi
[ -f "$BASELINE" ] && ARGS+=(--baseline "$BASELINE")
python3 -I "$HERE/scripts/gate.py" "${ARGS[@]}" $ENFORCE
RC=$?
if [ -n "${SEC_DASHBOARD_URL:-}" ] && [ -f "$OUT/summary.json" ]; then python3 -I "$HERE/scripts/publish.py" --report "$OUT" --root "$REPO" --url "$SEC_DASHBOARD_URL" || true; fi
echo "   report: $OUT/summary.html   (also summary.md, results.sarif, raw/)"
[ "$RC" = 0 ] && [ -z "$ENFORCE" ] && grep -q '"result": "FAIL' "$OUT/summary.json" 2>/dev/null && echo "   report-only mode: the gate WOULD have failed. Fix the findings, or baseline legacy ones (warden baseline), then switch the preset: warden config set SEC_PRESET standard."
exit $RC
