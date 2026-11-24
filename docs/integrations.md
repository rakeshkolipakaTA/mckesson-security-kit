# Setup and integration guide: SonarQube, the dashboard, tokens, and where each value goes

> **Per-tool guides, for developers and for the platform team:** [integrations/](integrations/README.md) covers SonarQube, **DefectDojo** and **Dependency-Track**. This page remains the reference for where each URL and secret goes (GitHub, Jenkins, Azure DevOps) and for the dashboard, tickets and alerts.

Three kinds of values exist. Putting each in the right place is the whole job.

| Kind | Examples | Where it goes | Why |
|---|---|---|---|
| **Settings for everyone** (non-secret) | SonarQube URL, dashboard URL | `configs/central.env` in the warden package (platform team sets once, then releases a new version) | Every repo inherits them; nobody types a URL |
| **Settings for one repo** (non-secret) | preset, which tools, `SEC_SONAR_KEY`, a URL override | `.security/config.env` | Reviewed with the code |
| **Secrets** | `SONAR_TOKEN`, `WARDEN_DASHBOARD_TOKEN`, `NVD_API_KEY`, `REDTEAM_TOKEN` | the CI system's secret store, **never** a file in a repo | Anyone with repo access can read files |

Precedence for the non-secret settings: command line, environment variable, repo `config.env`, `central.env`, built-in defaults. `warden config show` prints the effective URLs and whether the tokens are present.

## 1. Run the central services (platform team, once, on a server)
```bash
scripts/platform-up.sh --host <the address CI and people will use>
```
It starts **SonarQube** (port 9000) and the **dashboard** (port 8090) with Docker, generates strong credentials into `~/.warden-platform/platform.env` (mode 600), and prints the exact values to configure below. Open the two ports for the people and CI runners that need them. Details and hardening: [dashboard.md](dashboard.md).

One-time SonarQube setup (changes the default admin password, makes a scanner token):
```bash
SONAR_ADMIN_PASSWORD='a-long-new-password-1!' SONAR_HOST_URL=http://127.0.0.1:9000 scripts/sonar-bootstrap.sh
```
The printed `SONAR_TOKEN` is the secret for step 3.

## 2. Tell the kit where the servers are (non-secret)
Edit `configs/central.env` in the warden source, then release a new version (or, for a single repo, put the same keys in `.security/config.env`):
```ini
SEC_SONAR_HOST_URL=http://sonar.example.com:9000
SEC_DASHBOARD_URL=http://warden.example.com:8090
```
## 3. Give CI the secrets
| Secret | Value | Needed for |
|---|---|---|
| `SONAR_TOKEN` | the token printed by `sonar-bootstrap.sh` | SonarQube (`SEC_SONAR=on`) |
| `WARDEN_DASHBOARD_TOKEN` | `DASHBOARD_INGEST_TOKEN` from `platform.env` | publishing to the dashboard |

**GitHub Actions**: repo (or organisation) *Settings > Secrets and variables > Actions > New secret*. The generated `.github/workflows/security-scan.yml` already passes both:
```yaml
env:
  SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
  WARDEN_DASHBOARD_TOKEN: ${{ secrets.WARDEN_DASHBOARD_TOKEN }}
```
An organisation-level secret covers every repo at once. The URLs come from `central.env`/`config.env`, so the YAML has no URL in it. (If you prefer, `SONAR_HOST_URL` can also be set as a GitHub *variable* and passed in `env:`; it wins over the config files.)

**Jenkins**: *Manage Jenkins > Credentials > Add > Secret text*, ids `sonar-token` and `warden-dashboard-token`. In the stage:
```groovy
withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN'),
                 string(credentialsId: 'warden-dashboard-token', variable: 'WARDEN_DASHBOARD_TOKEN')]) {
    sh '.security/warden scan'
}
```
**Azure DevOps**: *Pipelines > Library > Variable group* (or pipeline variables), mark the two as secret, then map them in the script step:
```yaml
- script: .security/warden scan
  env:
    SONAR_TOKEN: $(SONAR_TOKEN)
    WARDEN_DASHBOARD_TOKEN: $(WARDEN_DASHBOARD_TOKEN)
```
### Tickets and alerts (optional)
| Secret / setting | Value | Used by |
|---|---|---|
| `GITHUB_TOKEN` (`issues: write`) | provided by GitHub Actions automatically when the job has `permissions: issues: write` | `warden tickets` (GitHub issues) |
| `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT` | your Jira Cloud/Server URL, a service account, its API token, the project key | `warden tickets --target jira` |
| `AZDO_ORG_URL`, `AZDO_PROJECT`, `AZDO_TOKEN` | `https://dev.azure.com/<org>`, project name, a PAT (Work Items read/write) | `warden tickets --target azure` |
| `DASHBOARD_ALERT_WEBHOOK` | a Slack / Teams incoming-webhook URL. Set it on the **dashboard server** (`platform.env`), not in CI | dashboard alerts |

A scheduled CI job is the usual home for tickets, for example after the scan: `.security/warden tickets --dashboard "$SEC_DASHBOARD_URL" --apply` with `WARDEN_DASHBOARD_TOKEN` available. Run it as a dry run first. Details: [dashboard.md](dashboard.md).

**Network**: the CI runner must reach the SonarQube and dashboard addresses. GitHub-hosted runners can only reach public addresses; a server on a private network needs self-hosted runners (or a public, IP-restricted endpoint). A scan never fails because the dashboard is unreachable: publishing problems are warnings.

## 4. Switch things on in the repo
In `.security/config.env`:
```ini
SEC_SONAR=on                         # run SonarQube (needs SEC_SONAR_HOST_URL + the SONAR_TOKEN secret)
SEC_SONAR_KEY=warden-my-project    # the project key in SonarQube (default: warden-<repo folder>)
```
The dashboard needs no switch: the scan publishes whenever a dashboard URL and the token are both present. Check with `warden config show` (it prints both URLs and whether each token is set), then `warden scan`; the last lines say `dashboard: published ...`.

## 5. Check it works
```bash
export SONAR_TOKEN=...  WARDEN_DASHBOARD_TOKEN=...    # only for this test, in your shell
.security/warden config show        # URLs and tokens should say "set"
.security/warden scan
.security/warden publish            # re-send the latest report to the dashboard (fails loudly if it cannot)
```
Open the dashboard: the repo appears in the portfolio; click it for findings, tool coverage and history.

## Which UI for what
| Question | Look at |
|---|---|
| Which repos are failing, stale, or missing tools? Who has Critical findings? | **Dashboard** (all tools, all repos) |
| This repo's findings, trend, coverage notes, link to the CI run | **Dashboard**, repo page |
| Code smells, hotspots, line-level code review of one project | **SonarQube** (only Sonar's findings) |
| The full per-scan report with raw data | the `summary.html` artifact of the CI run |
