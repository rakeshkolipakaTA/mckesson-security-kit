#!/usr/bin/env bash
# Add the McKesson security kit to ONE repository (per-project mode).
#   secscan init [repo-path] [--ci github|jenkins|azure|all|none] [--preset starter|standard|strict] [--vendor] [--source SRC]
# Default (installed with pip): THIN - commits only config + CI + a version pin (secscan.lock); the engine is installed from the pin.
# --vendor (default when run from a framework checkout): copies the whole engine into .security/kit (works offline).
# Safe to re-run (= upgrade): refreshes generated files, never overwrites your config, exceptions or baseline.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$HERE/modes/per-project/templates"
REPO="." CI=auto PRESET="" VENDOR="" SOURCE="${SECSCAN_SOURCE:-}"
while [ $# -gt 0 ]; do
  case "$1" in --ci) CI="${2:?--ci needs github|jenkins|azure|all|none}"; shift 2;; --preset) PRESET="${2:?--preset needs starter|standard|strict}"; shift 2;;
    --vendor) VENDOR=1; shift;; --thin) VENDOR=0; shift;; --source) SOURCE="${2:?--source needs a pip source}"; shift 2;; -h|--help) sed -n '2,7p' "$0"; exit 0;; -*) echo "unknown option $1" >&2; exit 2;; *) REPO="$1"; shift;; esac
done
[ -d "${REPO:-}" ] || { echo "usage: secscan init [repo-path] [--ci github|jenkins|azure|all|none] [--preset ...] [--vendor]" >&2; exit 2; }
REPO="$(cd "$REPO" && pwd)"; S="$REPO/.security"; KIT="$S/kit"
case "$CI" in auto|github|jenkins|azure|all|none) ;; *) echo "--ci must be github|jenkins|azure|all|none" >&2; exit 2;; esac
if [ "$CI" = auto ]; then
  if [ -d "$REPO/.github" ]; then CI=github
  elif ls "$REPO"/Jenkinsfile* >/dev/null 2>&1; then CI=jenkins
  elif ls "$REPO"/azure-pipelines*.yml >/dev/null 2>&1; then CI=azure
  else CI=all; fi
fi

case "$PRESET" in ""|starter|standard|strict) ;; *) echo "--preset must be starter|standard|strict" >&2; exit 2;; esac
PROFILES="$("$HERE/scripts/scan.sh" "$REPO" --print-profiles)"
UPGRADE=0; [ -d "$KIT" ] || [ -f "$S/secscan.lock" ] && UPGRADE=1
# mode: an existing repo keeps its mode; otherwise thin when installed with pip (SECSCAN_VERSION is set by the pip entry point), vendored from a checkout
if [ -z "$VENDOR" ]; then
  if [ -d "$KIT" ]; then VENDOR=1; elif [ -f "$S/secscan.lock" ] && grep -q '^mode=thin' "$S/secscan.lock"; then VENDOR=0; elif [ -n "${SECSCAN_VERSION:-}" ]; then VENDOR=0; else VENDOR=1; fi
fi
VERSION_NOW="${SECSCAN_VERSION:-$(cat "$HERE/VERSION" 2>/dev/null || echo local)}"

# 1) engine
mkdir -p "$S/ci"
if [ "$VENDOR" = 1 ]; then
rm -rf "$KIT"; mkdir -p "$KIT/scripts" "$KIT/docker"
cp "$HERE/versions.env" "$KIT/"
cp "$HERE/scripts/scan.sh" "$HERE/scripts/toolplan.py" "$HERE/scripts/gate.py" "$HERE/scripts/secscan" "$HERE/scripts/agent_scan.py" "$HERE/scripts/redteam.py" "$HERE/scripts/publish.py" "$KIT/scripts/"
mkdir -p "$KIT/agentic" && cp -r "$HERE/agentic/agentsec" "$KIT/agentic/agentsec" && find "$KIT/agentic" -name __pycache__ -prune -exec rm -rf {} +
cp -r "$HERE/configs" "$KIT/configs"
cp -r "$HERE/docker/scanner" "$HERE/docker/scanner-node" "$KIT/docker/"
echo "kit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo local) $(date +%Y-%m-%d)" > "$KIT/VERSION"
chmod +x "$KIT/scripts/"*
printf '#!/usr/bin/env bash\nexec "$(dirname "$(readlink -f "$0")")/kit/scripts/secscan" "$@"\n' > "$S/secscan"; chmod +x "$S/secscan"
printf '# written by secscan init - commit this file\nversion=%s\nmode=vendored\n' "$VERSION_NOW" > "$S/secscan.lock"
else
  rm -rf "$KIT"
  [ -n "$SOURCE" ] || SOURCE="mckesson-secscan==$VERSION_NOW"
  cp "$T/secscan-shim.sh" "$S/secscan"; chmod +x "$S/secscan"
  printf '# written by secscan init - commit this file. CI and teammates install exactly this version.\nversion=%s\nsource=%s\nmode=thin\n' "$VERSION_NOW" "$SOURCE" > "$S/secscan.lock"
fi

# 2) your files (created once, never overwritten)
if [ ! -f "$S/config.env" ]; then cp "$T/config.env" "$S/config.env"; [ -n "$PRESET" ] && sed -i "s/^SEC_PRESET=.*/SEC_PRESET=$PRESET/" "$S/config.env"; fi
[ -f "$S/exceptions.json" ] || echo '[]' > "$S/exceptions.json"
cp "$T/README.md" "$S/README.md"
printf 'reports/\n' > "$S/.gitignore"

# 3) CI files
ci_dir="$S/ci"
put() { cp "$T/$1" "$ci_dir/$2"; }
want() { [ "$CI" = all ] || [ "$CI" = "$1" ]; }
INSTALLED=""
if want github; then
  put github-actions-release.yml security-release.github.yml; put github-actions-dast.yml security-dast.github.yml
  put github-actions-pr.yml security-scan.github.yml
  if [ ! -f "$REPO/.github/workflows/security-scan.yml" ]; then
    mkdir -p "$REPO/.github/workflows"; cp "$T/github-actions-pr.yml" "$REPO/.github/workflows/security-scan.yml"
    INSTALLED=".github/workflows/security-scan.yml"
  fi
fi
want jenkins && { put Jenkinsfile.security Jenkinsfile.security; put securityScan.groovy securityScan.groovy; }
want azure   && put azure-pipelines-security.yml azure-pipelines-security.yml
want github  && put github-actions-redteam.yml security-redteam.github.yml
put redteam.json redteam.json.example
put CODEOWNERS.snippet CODEOWNERS.snippet; put pre-commit-config.yaml pre-commit-config.yaml; put pull_request_template.md pull_request_template.md

echo
echo "Security kit $([ $UPGRADE = 1 ] && echo upgraded || echo installed) in $S"
echo "  detected stack : $PROFILES"
echo "  engine         : $([ "$VENDOR" = 1 ] && echo "vendored in .security/kit (works offline)" || echo "thin, pinned to secscan $VERSION_NOW in .security/secscan.lock")"
echo "  preset         : $(grep -m1 '^SEC_PRESET=' "$S/config.env" | cut -d= -f2) (set in .security/config.env; 'starter' = report-only, scans never fail your build yet)"
[ -n "$INSTALLED" ] && echo "  CI added       : $INSTALLED (GitHub Actions, report-only)"
[ -z "$INSTALLED" ] && [ "$CI" != none ] && echo "  CI templates   : .security/ci/  (copy the one for your platform, see docs/ci-github-actions.md / ci-jenkins.md / ci-azure-devops.md)"
cat <<NEXT

Next steps (about 10 minutes):
  1. cd "$REPO"
  2. .security/secscan doctor        # checks Docker + network, tells you exactly what to fix
  3. .security/secscan scan          # first scan; then:  .security/secscan open
  4. git add .security $([ -n "$INSTALLED" ] && echo .github) && git commit -m "Add security scanning (report-only)"
Later: fix findings or run '.security/secscan baseline' for legacy ones, then switch the preset: .security/secscan config set SEC_PRESET standard
NEXT
