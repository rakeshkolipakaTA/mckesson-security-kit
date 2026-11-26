#!/usr/bin/env bash
# Add the Warden security kit to ONE repository (per-project mode).
#   warden init [repo-path] [--ci github|jenkins|azure|all|none] [--preset starter|standard|strict] [--thin] [--pin] [--source SRC]
# Default: VENDORED - copies the whole engine into .security/kit, so CI needs nothing from the Warden repository or package index.
# --thin: commits only config + CI + a version pin (warden.lock); CI installs the engine from the pin (--source / --pin imply it).
# Safe to re-run (= upgrade): refreshes generated files, never overwrites your config, exceptions or baseline.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$HERE/modes/per-project/templates"
REPO="." CI=auto PRESET="" VENDOR="" PIN="" SOURCE="${WARDEN_SOURCE:-}" SOURCE_FLAG=""
while [ $# -gt 0 ]; do
  case "$1" in --ci) CI="${2:?--ci needs github|jenkins|azure|all|none}"; shift 2;; --preset) PRESET="${2:?--preset needs starter|standard|strict}"; shift 2;;
    --vendor) VENDOR=1; shift;; --thin) VENDOR=0; shift;; --pin) PIN=1; shift;; --source) SOURCE="${2:?--source needs a pip source}"; SOURCE_FLAG=1; shift 2;; -h|--help) sed -n '2,6p' "$0"; exit 0;; -*) echo "unknown option $1" >&2; exit 2;; *) REPO="$1"; shift;; esac
done
[ -d "${REPO:-}" ] || { echo "usage: warden init [repo-path] [--ci github|jenkins|azure|all|none] [--preset ...] [--thin]" >&2; exit 2; }
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
UPGRADE=0; [ -d "$KIT" ] || [ -f "$S/warden.lock" ] && UPGRADE=1
# mode: an existing repo keeps its mode; otherwise vendored (the default). --thin, --pin or --source choose thin
if [ -z "$VENDOR" ]; then
  if [ -d "$KIT" ]; then VENDOR=1; elif [ -f "$S/warden.lock" ] && grep -q '^mode=thin' "$S/warden.lock"; then VENDOR=0; elif [ -n "$PIN" ] || [ -n "$SOURCE_FLAG" ]; then VENDOR=0; else VENDOR=1; fi
fi
VERSION_NOW="${WARDEN_VERSION:-$(cat "$HERE/VERSION" 2>/dev/null || echo local)}"

# 1) engine
mkdir -p "$S/ci"
if [ "$VENDOR" = 1 ]; then
rm -rf "$KIT"; mkdir -p "$KIT/scripts" "$KIT/docker"
cp "$HERE/versions.env" "$KIT/"
cp "$HERE/scripts/scan.sh" "$HERE/scripts/toolplan.py" "$HERE/scripts/gate.py" "$HERE/scripts/warden" "$HERE/scripts/agent_scan.py" "$HERE/scripts/redteam.py" "$HERE/scripts/publish.py" "$HERE/scripts/exposure.py" "$HERE/scripts/repo_posture.py" "$HERE/scripts/api_fuzz_report.py" "$HERE/scripts/gh_report.py" "$HERE/scripts/publish_external.py" "$HERE/scripts/wiz_scan.py" "$HERE/scripts/zap_auth.py" "$HERE/scripts/creds.py" "$HERE/scripts/tickets.py" "$HERE/scripts/semgrep_rules.py" "$KIT/scripts/"
mkdir -p "$KIT/agentic" && cp -r "$HERE/agentic/agentsec" "$KIT/agentic/agentsec" && find "$KIT/agentic" -name __pycache__ -prune -exec rm -rf {} +
cp -r "$HERE/configs" "$KIT/configs"
find "$KIT/configs" -name __pycache__ -prune -exec rm -rf {} +
cp -r "$HERE/docker/scanner" "$HERE/docker/scanner-node" "$KIT/docker/"
echo "kit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo local) $(date +%Y-%m-%d)" > "$KIT/VERSION"
chmod +x "$KIT/scripts/"*
printf '#!/usr/bin/env bash\nexec "$(dirname "$(readlink -f "$0")")/kit/scripts/warden" "$@"\n' > "$S/warden"; chmod +x "$S/warden"
printf '# written by warden init - commit this file\nversion=%s\nmode=vendored\n' "$VERSION_NOW" > "$S/warden.lock"
else
  rm -rf "$KIT"
  [ -n "$SOURCE" ] || SOURCE="warden-kit==$VERSION_NOW"
  cp "$T/warden-shim.sh" "$S/warden"; chmod +x "$S/warden"
  # channel: an existing repo keeps its choice. New repos follow the newest release of the major line (auto) when installed from a git tag or branch,
  # and are pinned when the source is a plain version or a commit. --pin forces an exact version.
  CHANNEL=""; [ -f "$S/warden.lock" ] && CHANNEL="$(sed -n 's/^channel=//p' "$S/warden.lock" | head -1 | tr -d '\r')"
  if [ -f "$S/warden.lock" ] && [ "$CHANNEL" = auto ] && [ -z "$PIN" ]; then SOURCE="$(sed -n 's/^source=//p' "$S/warden.lock" | head -1 | tr -d '\r')"
  elif [ -n "$PIN" ] || [ "$CHANNEL" = pinned ]; then CHANNEL=pinned
  elif [[ "$SOURCE" =~ ^git\+.*@v([0-9]+)\.[0-9]+\.[0-9]+$ ]]; then CHANNEL=auto; SOURCE="${SOURCE%@*}@v${BASH_REMATCH[1]}"
  elif [[ "$SOURCE" =~ ^git\+.*@[A-Za-z][A-Za-z0-9._/-]*$ ]]; then CHANNEL=auto
  else CHANNEL=pinned; fi
  printf '# written by warden init - commit this file.\n# channel=auto: follows the newest release of the pinned major line automatically. channel=pinned: exactly this version (warden pin).\nversion=%s\nsource=%s\nchannel=%s\nmode=thin\n' "$VERSION_NOW" "$SOURCE" "$CHANNEL" > "$S/warden.lock"
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
  put github-actions-pr.yml security-scan.github.yml; put github-actions-codeql.yml security-codeql.github.yml
  put github-actions-wiz.yml security-wiz.github.yml        # optional, needs a Wiz licence
  if [ ! -f "$REPO/.github/workflows/security-scan.yml" ]; then
    mkdir -p "$REPO/.github/workflows"; cp "$T/github-actions-pr.yml" "$REPO/.github/workflows/security-scan.yml"
    INSTALLED=".github/workflows/security-scan.yml"
  fi
fi
want jenkins && { put Jenkinsfile.security Jenkinsfile.security; put securityScan.groovy securityScan.groovy; }
want azure   && { put azure-pipelines-security.yml azure-pipelines-security.yml; put azure-pipelines-wiz.yml azure-pipelines-wiz.yml; }
want github  && { put github-actions-redteam.yml security-redteam.github.yml
                 put github-actions-sign-release.yml security-sign-release.github.yml; put github-actions-scorecard.yml security-scorecard.github.yml; }
put renovate.json renovate.json
put redteam.json redteam.json.example
put CODEOWNERS.snippet CODEOWNERS.snippet; put pre-commit-config.yaml pre-commit-config.yaml; put pull_request_template.md pull_request_template.md

# 4) things outside .security/, written ONLY when absent (after that they are yours; uninstall leaves them alone)
EXTRA=""
find_dirs() {   # directories (as "/sub/dir", "/" for the root) holding a file that matches the given find expression
  find "$REPO" -maxdepth 4 \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name .security -o -name target -o -name build -o -name dist -o -name site-packages \) -prune -o -type f \( "$@" \) -print 2>/dev/null \
    | while IFS= read -r f; do d="${f%/*}"; d="${d#"$REPO"}"; echo "${d:-/}"; done | sort -u | sed -n '1,25p'
}
uses_github() { want github || [ -d "$REPO/.github" ] || git -C "$REPO" remote -v 2>/dev/null | grep -q 'github\.com'; }
if uses_github && [ ! -e "$REPO/.github/dependabot.yml" ] && [ ! -e "$REPO/.github/dependabot.yaml" ]; then
  mkdir -p "$REPO/.github"; dep="$REPO/.github/dependabot.yml"
  { echo "# Written by warden init (change freely: it is yours now). Opens weekly pull requests that update vulnerable / outdated dependencies."
    echo "# cooldown = ignore versions published in the last 7 days (a freshly published malicious release is usually caught within days). Security updates ignore it."
    echo "# Alternative: Renovate, see .security/ci/renovate.json."; echo "version: 2"; echo "updates:"
    emit() { printf '  - package-ecosystem: "%s"\n    directory: "%s"\n    schedule:\n      interval: "weekly"\n    cooldown:\n      default-days: 7\n    open-pull-requests-limit: 5\n' "$1" "$2"; }
    while IFS= read -r d; do [ -n "$d" ] && emit pip "$d"; done < <(find_dirs -name 'requirements*.txt' -o -name pyproject.toml -o -name Pipfile)
    while IFS= read -r d; do [ -n "$d" ] && emit npm "$d"; done < <(find_dirs -name package.json)
    while IFS= read -r d; do [ -n "$d" ] && emit maven "$d"; done < <(find_dirs -name pom.xml)
    while IFS= read -r d; do [ -n "$d" ] && emit gradle "$d"; done < <(find_dirs -name 'build.gradle' -o -name 'build.gradle.kts')
    while IFS= read -r d; do [ -n "$d" ] && emit docker "$d"; done < <(find_dirs -name 'Dockerfile*')
    emit github-actions "/"
  } > "$dep"
  EXTRA="$EXTRA .github/dependabot.yml"
fi
if [ ! -e "$REPO/.vscode/extensions.json" ]; then mkdir -p "$REPO/.vscode"; cp "$T/vscode-extensions.json" "$REPO/.vscode/extensions.json"; EXTRA="$EXTRA .vscode/extensions.json"; fi
if [ ! -e "$REPO/.vscode/settings.json" ]; then mkdir -p "$REPO/.vscode"; cp "$T/vscode-settings.json" "$REPO/.vscode/settings.json"; EXTRA="$EXTRA .vscode/settings.json"; fi

echo
echo "Security kit $([ $UPGRADE = 1 ] && echo upgraded || echo installed) in $S"
echo "  detected stack : $PROFILES"
[ "$PROFILES" != generic ] || echo "  no code detected yet: the checks that need no language (secrets, workflow security, Dockerfile / Kubernetes / Helm / Terraform settings, libraries once a manifest exists) run now. Python, Node, Java and AI-agent checks start by themselves when those files appear; nothing to re-run."
echo "  engine         : $([ "$VENDOR" = 1 ] && echo "vendored in .security/kit (works offline)" || { [ "${CHANNEL:-}" = auto ] && echo "thin, follows the newest release automatically (channel=auto in .security/warden.lock)" || echo "thin, pinned to warden $VERSION_NOW in .security/warden.lock"; })"
echo "  preset         : $(grep -m1 '^SEC_PRESET=' "$S/config.env" | cut -d= -f2) (set in .security/config.env; 'starter' = report-only, scans never fail your build yet)"
[ -n "$INSTALLED" ] && echo "  CI added       : $INSTALLED (GitHub Actions, report-only)"
[ -n "$EXTRA" ] && echo "  also added     :$EXTRA (only when missing; they are yours now)"
[ -z "$INSTALLED" ] && [ "$CI" != none ] && echo "  CI templates   : .security/ci/  (copy the one for your platform, see docs/ci-github-actions.md / ci-jenkins.md / ci-azure-devops.md)"
cat <<NEXT

Next steps (about 10 minutes):
  1. cd "$REPO"
  2. .security/warden doctor        # checks Docker + network, tells you exactly what to fix
  3. .security/warden scan          # first scan; then:  .security/warden open
  4. git add .security $([ -n "$INSTALLED$EXTRA" ] && echo .github .vscode) && git commit -m "Add security scanning (report-only)"
Later: fix findings or run '.security/warden baseline' for legacy ones, then switch the preset: .security/warden config set SEC_PRESET standard
NEXT
