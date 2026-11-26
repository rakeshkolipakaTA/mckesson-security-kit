# Changelog

Repos on the default `channel=auto` follow the newest release of their major line (tag `v1`) automatically; `warden pin` freezes a version. See [docs/updates-and-versions.md](docs/updates-and-versions.md).

## 1.1.0 (not released yet)
- **DefectDojo and Dependency-Track integrations.** `SEC_DEFECTDOJO_URL` + secret `DEFECTDOJO_TOKEN`: the merged findings of every `main` scan are reimported into DefectDojo (new opened, fixed closed, approved exceptions as accepted risk, no duplicates). `SEC_DTRACK_URL` + secret `DTRACK_API_KEY`: the SBOM is uploaded to Dependency-Track, which keeps watching it for new CVEs. Pull request branches are skipped by default (`SEC_DEFECTDOJO_BRANCHES`, `SEC_DTRACK_BRANCHES`). A publishing problem is a warning, never a build failure. `warden publish` sends to every configured tool, `warden publish --dry-run` shows what would be sent. Code: `scripts/publish_external.py` (15 tests on mock servers; also verified on real DefectDojo 3.5.300 and Dependency-Track 4.14.7 containers).
- **Platform:** `scripts/platform-up.sh --defectdojo --dtrack` starts them (localhost only until `--expose`), `scripts/defectdojo-bootstrap.sh` and `scripts/dtrack-bootstrap.sh` do the one-time setup and print the CI secret. The Dependency-Track key can only upload SBOMs and read results; the bootstrap also enables the free OSV vulnerability source, without which it finds almost nothing for Python, npm and Maven. DefectDojo's token must belong to a superuser (the Community edition has no import-only role): keep it in a restricted CI secret and rotate it by running the bootstrap again.
- **Wiz (needs a licence; not tested against a real Wiz tenant).** `warden wiz` runs the Wiz CLI (`dir`, `iac`, `docker` scans) when the CI secrets `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` exist and does nothing otherwise; report-only unless `SEC_WIZ_ENFORCE=1`; `--install` downloads and hash-checks `wizcli`. Results can be imported into DefectDojo with its own Wiz parsers (verified on a real DefectDojo with Wiz's sample files). CI templates for GitHub Actions and Azure DevOps, and an Azure cloud-connection guide: `docs/integrations/wiz.md`. 14 tests with a stand-in `wizcli`.
- **Docs:** new `docs/integrations/` with a guide per tool (SonarQube, DefectDojo, Dependency-Track) for developers and the platform team, and `docs/checks/` describing every check category, what it protects against, and its limits.
- **`warden init` now copies the whole engine into the repo by default** (vendored), so GitHub Actions needs no access to our repository or package index. The old behaviour (a version pin, engine fetched from our repository) is `warden init --thin`; `--pin` and `--source` imply it, and an existing repo keeps its mode on `init`, `upgrade` and `reinstall`.
- **Semgrep on networks that block semgrep.dev:** `warden rules fetch` downloads the rule packs a repo uses into `.security/semgrep-rules`; `SEC_SEMGREP_RULES=.security/semgrep-rules` (a repo-relative path now works) runs Semgrep with no network. A missing or empty rules folder fails closed with a clear message, and a Semgrep run that produced nothing now prints what to do. 7 tests for the downloader, 5 for the offline scan.
- **Fix: empty repos, and repos without a Python or Node manifest (Java-only, Terraform-only, Helm-only), were detected as AI-agent repos**, so the agent checks ran and the report said "agent". Detection now needs a real match. An empty repo is `generic`: the language-independent checks run (secrets, workflow security, Dockerfile / Kubernetes / Helm / Terraform settings), `init` says so, and Python, Node, Java and agent checks start by themselves when those files appear (no re-run of `init`). 7 tests.
- **Fix: vendored mode was missing six scripts** (GitHub report, DefectDojo / Dependency-Track / Wiz publishing, logged-in ZAP helper, credentials and ticket helpers), so those features failed in a self-contained repo. All are copied now, and a test checks that every script the engine calls is inside `.security/kit`. Use this mode when GitHub Actions may not pull from our repository.
- **Fix:** the SonarQube database container had no restart policy, so after a server reboot SonarQube restarted in a loop. It now restarts with the server.

## 1.0.2 (2026-11-20)
- **Logged-in ZAP and API-fuzz scans with more login types** (`SEC_ZAP_AUTH`): basic, cookie, JSON login, HTML form (with CSRF), OAuth2 client credentials and password grant (the SSO-friendly token flows). A failed login stops the scan instead of running anonymously. See [docs/zap-authentication.md](docs/zap-authentication.md).
- **Test credentials stay out of git**: values from CI secrets, `NAME_FILE` (Docker/Kubernetes/Jenkins), a local credentials file outside the repo (`warden creds set|list|delete`, profiles), or a hidden prompt. A secret in `config.env` is refused. Logged-in tokens are masked in GitHub Actions logs.
- **`scripts/release.sh --roll`** moves the major tag without a new version number (everyday changes need no version bump).
- **Rename note:** Semgrep agent rule IDs changed from `mckesson-agent-*` to `warden-agent-*`; an exception or baseline entry that names an old rule ID needs updating. Docker image/volume names and SonarQube keys changed too.
- Names: the word "McKesson" is gone from the code and scan artifacts (rule IDs are now `warden-agent-*`, Docker images and volumes `warden-*`, SonarQube keys `warden-<repo>`). Only the GitHub repository name still contains it.

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
