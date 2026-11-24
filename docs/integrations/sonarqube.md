# SonarQube: code quality and security review

SonarQube analyses the **source code** of a project for bugs, code smells, duplication and security hot-spots, and applies its own *quality gate*. Warden runs Sonar's scanner as part of the scan, pulls the issues and the quality-gate result back into Warden's report, and makes a failed quality gate fail the Warden gate too. The client asked for SonarQube, so this is the integration to turn on for repos they look at.

## What you get
* A SonarQube **project per repository** (key `warden-<repo>` by default), created on the first analysis.
* Sonar's issues in Warden's findings (severity mapped BLOCKER to Critical, CRITICAL to High, MAJOR to Medium, MINOR to Low), merged with the other tools: the same hard-coded secret reported by gitleaks and Sonar is **one** finding.
* The quality-gate status in the report; a failed quality gate fails the Warden gate.
* In SonarQube itself: the code view with issues on the lines, hot-spots to review, duplication, coverage if you provide it, and history.

## Developer: turn it on for your repo
1. The platform team sets the SonarQube address once for everyone (`SEC_SONAR_HOST_URL` in `configs/central.env`). Make sure the CI secret `SONAR_TOKEN` exists (an organisation secret covers every repo).
2. In `.security/config.env`:
   ```ini
   SEC_SONAR=on
   # SEC_SONAR_KEY=warden-my-project      # optional: default is warden-<repo name>
   ```
3. Pass the token to the scan step (the generated GitHub workflow already does):
   ```yaml
   env:
     SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}      # optional if the address is in central.env
     SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
   ```
   Jenkins: *Secret text* credential `sonar-token` bound to `SONAR_TOKEN`. Azure DevOps: secret variable mapped to `SONAR_TOKEN`.
4. Run a scan. `warden config show` lists SonarQube as running; the report has a SonarQube section and the issues are in the findings table.

SonarQube runs **by itself when you set `SEC_SONAR=on`**, on every scan. (On the `strict` preset it runs automatically when the address and token are present.) It sends no data to anything other than your SonarQube server.

## Reading the result
| You want | Go to |
|---|---|
| Code smells, duplication, hot-spots of one project | SonarQube, *Projects*, your repository |
| Security findings from all tools together | the Warden report, GitHub PR comment or [DefectDojo](defectdojo.md) |
| Why the quality gate failed | the *Quality gate* line in the report, then SonarQube's project overview |

## For the platform team: start it and get the token
```bash
scripts/platform-up.sh [--host <address>]                                   # SonarQube on port 9000, with the dashboard
SONAR_ADMIN_PASSWORD='a-long-new-password-1!' SONAR_HOST_URL=http://127.0.0.1:9000 scripts/sonar-bootstrap.sh
```
The bootstrap changes the default `admin/admin` password and prints `SONAR_TOKEN=...` for the CI secret. Put `SEC_SONAR_HOST_URL=http://<address>:9000` in `configs/central.env` and release a new Warden version. Put TLS in front for anything beyond a trusted network, and set `vm.max_map_count>=262144` on the host. More: [../sonar-setup.md](../sonar-setup.md), [../integrations.md](../integrations.md).

The database container now has a restart policy, so SonarQube comes back by itself after a server reboot (earlier it did not: SonarQube restarted in a loop because its database stayed stopped).

## Limits
* **SonarQube Community** has no branch or pull request analysis and no pull-request decoration; those need a paid edition. Each scan updates the project's single main analysis, so run it on `main`.
* No taint analysis in the Community edition (CodeQL and Semgrep cover part of that gap).
* Verified on Python code; other languages depend on Sonar's analyzers.
* Sonar finds code-quality issues Warden's other scanners do not, and does not cover dependencies or secrets in history, so keep both.
