# Setup and integration guide: SonarQube, the dashboard, tokens, and where each value goes

Three kinds of values exist. Putting each in the right place is the whole job.

| Kind | Examples | Where it goes | Why |
|---|---|---|---|
| **Settings for everyone** (non-secret) | SonarQube URL, dashboard URL | `configs/central.env` in the secscan package (platform team sets once, then releases a new version) | Every repo inherits them; nobody types a URL |
| **Settings for one repo** (non-secret) | preset, which tools, `SEC_SONAR_KEY`, a URL override | `.security/config.env` | Reviewed with the code |
| **Secrets** | `SONAR_TOKEN`, `SECSCAN_DASHBOARD_TOKEN`, `NVD_API_KEY`, `REDTEAM_TOKEN` | the CI system's secret store, **never** a file in a repo | Anyone with repo access can read files |

Precedence for the non-secret settings: command line, environment variable, repo `config.env`, `central.env`, built-in defaults. `secscan config show` prints the effective URLs and whether the tokens are present.

## 1. Run the central services (platform team, once, on a server)
```bash
scripts/platform-up.sh --host <the address CI and people will use>
```
It starts **SonarQube** (port 9000) and the **dashboard** (port 8090) with Docker, generates strong credentials into `~/.secscan-platform/platform.env` (mode 600), and prints the exact values to configure below. Open the two ports for the people and CI runners that need them. Details and hardening: [dashboard.md](dashboard.md).

One-time SonarQube setup (changes the default admin password, makes a scanner token):
```bash
SONAR_ADMIN_PASSWORD='a-long-new-password-1!' SONAR_HOST_URL=http://127.0.0.1:9000 scripts/sonar-bootstrap.sh
```
The printed `SONAR_TOKEN` is the secret for step 3.

## 2. Tell the kit where the servers are (non-secret)
Edit `configs/central.env` in the secscan source, then release a new version (or, for a single repo, put the same keys in `.security/config.env`):
```ini
SEC_SONAR_HOST_URL=http://sonar.example.com:9000
SEC_DASHBOARD_URL=http://secscan.example.com:8090
```
## 3. Give CI the secrets
| Secret | Value | Needed for |
|---|---|---|
| `SONAR_TOKEN` | the token printed by `sonar-bootstrap.sh` | SonarQube (`SEC_SONAR=on`) |
| `SECSCAN_DASHBOARD_TOKEN` | `DASHBOARD_INGEST_TOKEN` from `platform.env` | publishing to the dashboard |

**GitHub Actions**: repo (or organisation) *Settings > Secrets and variables > Actions > New secret*. The generated `.github/workflows/security-scan.yml` already passes both:
```yaml
env:
  SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
  SECSCAN_DASHBOARD_TOKEN: ${{ secrets.SECSCAN_DASHBOARD_TOKEN }}
```
An organisation-level secret covers every repo at once. The URLs come from `central.env`/`config.env`, so the YAML has no URL in it. (If you prefer, `SONAR_HOST_URL` can also be set as a GitHub *variable* and passed in `env:`; it wins over the config files.)

**Jenkins**: *Manage Jenkins > Credentials > Add > Secret text*, ids `sonar-token` and `secscan-dashboard-token`. In the stage:
```groovy
withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN'),
                 string(credentialsId: 'secscan-dashboard-token', variable: 'SECSCAN_DASHBOARD_TOKEN')]) {
    sh '.security/secscan scan'
}
```
**Azure DevOps**: *Pipelines > Library > Variable group* (or pipeline variables), mark the two as secret, then map them in the script step:
```yaml
- script: .security/secscan scan
  env:
    SONAR_TOKEN: $(SONAR_TOKEN)
    SECSCAN_DASHBOARD_TOKEN: $(SECSCAN_DASHBOARD_TOKEN)
```
**Network**: the CI runner must reach the SonarQube and dashboard addresses. GitHub-hosted runners can only reach public addresses; a server on a private network needs self-hosted runners (or a public, IP-restricted endpoint). A scan never fails because the dashboard is unreachable: publishing problems are warnings.

## 4. Switch things on in the repo
In `.security/config.env`:
```ini
SEC_SONAR=on                         # run SonarQube (needs SEC_SONAR_HOST_URL + the SONAR_TOKEN secret)
SEC_SONAR_KEY=mckesson-my-project    # the project key in SonarQube (default: mckesson-<repo folder>)
```
The dashboard needs no switch: the scan publishes whenever a dashboard URL and the token are both present. Check with `secscan config show` (it prints both URLs and whether each token is set), then `secscan scan`; the last lines say `dashboard: published ...`.

## 5. Check it works
```bash
export SONAR_TOKEN=...  SECSCAN_DASHBOARD_TOKEN=...    # only for this test, in your shell
.security/secscan config show        # URLs and tokens should say "set"
.security/secscan scan
.security/secscan publish            # re-send the latest report to the dashboard (fails loudly if it cannot)
```
Open the dashboard: the repo appears in the portfolio; click it for findings, tool coverage and history.

## Which UI for what
| Question | Look at |
|---|---|
| Which repos are failing, stale, or missing tools? Who has Critical findings? | **Dashboard** (all tools, all repos) |
| This repo's findings, trend, coverage notes, link to the CI run | **Dashboard**, repo page |
| Code smells, hotspots, line-level code review of one project | **SonarQube** (only Sonar's findings) |
| The full per-scan report with raw data | the `summary.html` artifact of the CI run |
