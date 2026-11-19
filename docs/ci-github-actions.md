# GitHub Actions

Two ways to use it. **Option A is the default**: `secscan init` sets it up for you.

## Option A: kit in your repo (default)
`secscan init` adds `.github/workflows/security-scan.yml` (also kept at `.security/ci/security-scan.github.yml`).
It runs `.security/secscan scan` on every pull request, every push to `main`/`master`, and manually (Actions tab > security-scan > Run workflow).

1. Commit and push `.security/` and `.github/workflows/security-scan.yml`.
2. Open a pull request. A check named **security-scan** appears. Open it: the run page shows the summary table, and the **security-report** artifact holds the HTML report.
3. The check is **green even with findings** while `SEC_PRESET=starter` (report-only). Set `SEC_PRESET=standard` in `.security/config.env` to make it fail on policy violations.

### Make it a required check (so a failing scan blocks the merge)
Repository **Settings > Branches > Branch protection rule** (or **Rulesets**) for `main` > tick *Require status checks to pass* > add **security-scan / scan**.
Do this only after you have switched to `SEC_PRESET=standard`.

### Secrets and variables (only if you use SonarQube)
Settings > Secrets and variables > Actions: add secret `SONAR_TOKEN` and variable `SONAR_HOST_URL`, then set `SEC_SONAR=1` in `config.env`. Never put tokens in `config.env` or in the workflow file.
Pull requests from forks do not get secrets; SonarQube is skipped for them by GitHub's design.

### Show findings in the Security tab (optional)
If your repo has GitHub code scanning (Advanced Security), uncomment the `upload-sarif` step at the bottom of the workflow and the `security-events: write` permission. Findings then appear under **Security > Code scanning**. SARIF contains source-code findings only (not ZAP URLs or image layers).

### Self-hosted runners
Use `runs-on: [self-hosted, linux]`. The runner needs Docker and outbound access listed by `secscan doctor`.

## Option B: central reusable workflow (no kit in your repo)
The platform team publishes `.github/workflows/security-scan-reusable.yml` in `mckesson-security-kit` (tag `v1`). Your repo only needs:
```yaml
# .github/workflows/security.yml     (template: modes/per-project/templates/github-actions-reusable-caller.yml)
name: security
on: { pull_request: , push: { branches: [main] } }
jobs:
  security:
    uses: rakeshkolipakaTA/mckesson-security-kit/.github/workflows/security-scan-reusable.yml@v1
    with: { enforce: false }
    secrets: inherit
```
Pros: upgrades happen centrally (move the tag). Cons: needs the templates repo to be readable by your repo (org/internal visibility, or a `FRAMEWORK_TOKEN` secret), and the platform team to publish it first. Your `.security/config.env`, `exceptions.json` and `baseline.json` still live in your repo.

## Deployment workflows
- Scan the Docker image before pushing it, and DAST against QA: [cd-release-gates.md](cd-release-gates.md). Templates: `.security/ci/security-release.github.yml`, `.security/ci/security-dast.github.yml`.

## Protect the setup from being weakened
Add `.security/ci/CODEOWNERS.snippet` to `.github/CODEOWNERS`, so changes to `.security/` and the security workflows need the security team's review. Exceptions are code: review them like code.
