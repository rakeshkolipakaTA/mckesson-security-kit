# Changelog

Repos on the default `channel=auto` follow the newest release of their major line (tag `v1`) automatically; `warden pin` freezes a version. See [docs/updates-and-versions.md](docs/updates-and-versions.md).

## 1.0.1 (2026-11-19)
- **Git-history secret scanning is optional.** Off on `starter` and `standard`, on for `strict`. Turn on with `SEC_GITLEAKS_HISTORY=on`.
- **`SEC_HISTORY_COMMITS=N`** limits how many of the newest commits are scanned (default 3000); invalid values fall back safely and say so.
- **`SEC_HISTORY_FETCH`** (default `auto`): in a shallow CI checkout, fetch just those commits when the workflow supplies `WARDEN_GIT_TOKEN`. No `fetch-depth: 0` needed.
- **Extra Semgrep SAST packs** (`SEC_SEMGREP_PACKS=auto|none|p/a,p/b`): security-audit, CWE Top 25, SQL/command injection, XSS, JWT, insecure transport, framework and Dockerfile packs; names are validated.
- **Optional CodeQL workflow** (`.security/ci/security-codeql.github.yml`), disabled by default.
- The GitHub workflow lists the checks that will run (`warden config show`).
- Fix: the agent sandbox library could report a memory-killed container as not OOM-killed (Docker sets the flag asynchronously).

## 1.0.0 (2026-11-19)
- First release. `warden init` for GitHub Actions with no server: run summary, file annotations and one updated pull request comment (`warden ci-report`); report artifact with HTML, SBOM and SARIF.
- Auto-update channel, `warden pin`, `scripts/release.sh`.
- Secrets, SAST, SCA, containers, IaC, workflows, Kubernetes, DAST and API fuzzing, exposure checks, AI-agent checks, central policy and gate, optional dashboard, tickets and alerts.
- The tool was renamed from `secscan` to Warden before this release.
