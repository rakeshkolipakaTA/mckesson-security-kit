# DefectDojo: one register of all findings

DefectDojo (an OWASP project, free) collects findings from many scanners in one place. Warden sends it the **merged, de-duplicated findings of every scan**, so the security team sees one list across all repos, with owners and deadlines, instead of one report per repo.

## What you get
* **One product per repository**, one **engagement per branch** (named after the branch, normally `main`), one test called *Warden scan*.
* **Reimport on every run**, not a new import. A finding that is still there is left alone, a new one is opened, **a fixed one is closed automatically**, a returning one is reopened. You never get duplicates.
* Severity, tool, rule, file and line, title, fix hint and CVE id (where there is one) on every finding. Tags: `warden`, the tool, the category, and `baseline` for known legacy findings.
* A finding that Warden has an **approved, unexpired exception** for arrives as *risk accepted*, not as an open finding.
* Everything DefectDojo is good at on top: owners, SLAs and ageing, Jira tickets, notifications, reports by team and over time.

## Developer: turn it on for your repo
1. Ask the platform team for the DefectDojo address and make sure the CI secret `DEFECTDOJO_TOKEN` exists (organisation secret, or repo *Settings, Secrets and variables, Actions*).
2. In `.security/config.env`:
   ```ini
   SEC_DEFECTDOJO_URL=https://defectdojo.example.com
   # optional:
   # SEC_DEFECTDOJO_PRODUCT=my-service          # default: owner/repo. No spaces here (set it in the workflow env: if you need them)
   # SEC_DEFECTDOJO_PRODUCT_TYPE=Payments       # default: Warden (created on first use)
   # SEC_DEFECTDOJO_BRANCHES=main,release       # default: main,master. * = all branches. Pull request scans are not published by default
   ```
3. The generated GitHub workflow already passes the secret; if you removed it, add this to the scan step:
   ```yaml
   env:
     DEFECTDOJO_TOKEN: ${{ secrets.DEFECTDOJO_TOKEN }}
   ```
   Jenkins: a *Secret text* credential bound to the variable `DEFECTDOJO_TOKEN`. Azure DevOps: a secret variable mapped to `DEFECTDOJO_TOKEN` in the step's `env:`.
4. Run a scan on `main`. The last lines should say `defectdojo: published ... [201]`. Open DefectDojo, *Products*, your repository.

Check without sending anything: `.security/warden config show` shows the address and whether the token is set, and `.security/warden publish --dry-run` (after a scan) prints what would be sent and where, and contacts nobody.

## Reading the result in DefectDojo
| You want | Go to |
|---|---|
| All open findings of one repo | *Products*, the repo, *Findings* (filter *Active*) |
| What changed since the last scan | the repo's *Test* page, *Warden scan*: the history of imports shows new / closed |
| Everything Critical across all repos | *Findings*, filter severity Critical and Active |
| Who is late | set a product SLA configuration; DefectDojo then shows overdue findings |
| Accept a risk | open the finding, *Risk acceptance* (with an owner and an expiry). In Warden itself use `.security/exceptions.json`, which also arrives as *risk accepted* |

Fixing a finding in the code and merging to `main` closes it in DefectDojo on the next scan. Closing it by hand in DefectDojo does not stop it coming back if it still exists in the code.

## For the platform team: start it and get the token
```bash
scripts/platform-up.sh --defectdojo [--expose]      # starts DefectDojo on port 8100
scripts/defectdojo-bootstrap.sh                     # creates the CI service user and prints the token
```
The bootstrap prints two lines: the repo setting `SEC_DEFECTDOJO_URL=...` (use the address CI can reach, not `127.0.0.1`) and `export DEFECTDOJO_TOKEN=...`, which you store as the CI secret. The admin password is in `~/.warden-platform/platform.env` (`DEFECTDOJO_ADMIN_PASSWORD`).

**Rotating the token:** run `scripts/defectdojo-bootstrap.sh` again. It creates a new service user and deactivates the previous ones, so the old token stops working at once. Update the CI secret with the new value.

**Important: the token is powerful.** DefectDojo Community has no "import only" role: a user that can create products and import findings must be a **superuser**. Treat `DEFECTDOJO_TOKEN` like an admin password:
* store it as a **GitHub Environment secret** (an environment such as `security-registry`, limited to the `main` branch, with required reviewers if you like) rather than a plain repository secret, and give only the job that publishes access to it;
* never print it, never put it in a file in a repository;
* rotate it on a schedule and whenever someone with access to the secret leaves.

Warden never sends the token anywhere except the DefectDojo address you configured, and never prints it (the tests check this). If the server speaks plain HTTP the scan prints a note: put TLS in front, or restrict the port to your CI runners.

## How it works (for the curious)
Warden converts `findings.json` to DefectDojo's *Generic Findings Import* format and calls `POST /api/v2/reimport-scan/` with `auto_create_context=true` (creates the product type, product, engagement and test the first time) and `close_old_findings=true`. The same finding always gets the same title and description, which is how DefectDojo recognises it on the next run. The code is `scripts/publish_external.py`.

## Troubleshooting
| Message | Cause and fix |
|---|---|
| `DEFECTDOJO_TOKEN is not set` | The secret is not passed to the scan step. Add it to the step's `env:`. Secrets are not available to pull requests from forks, which is expected. |
| `token rejected` (HTTP 401) | Wrong or rotated token. Run the bootstrap again and update the secret. |
| `the token's user may not create products` (HTTP 403) | The token belongs to a user that is not a superuser, or is deactivated. Use the token from `defectdojo-bootstrap.sh`. |
| `could not reach ...` | The runner cannot reach the address: GitHub-hosted runners only reach public addresses. Use a self-hosted runner on the network, or an IP-restricted public address. |
| `skipped (branch '...' is not in SEC_DEFECTDOJO_BRANCHES)` | Intended for pull requests. Add the branch to the list, or use `*`. |
| Product name has `/` in it | Fine: the default is `owner/repo`. |

## Limits
* Tested against a real DefectDojo 3.5.300: first import creates everything, a repeat import changes nothing (68 findings stayed 68, no duplicates), a vanished finding is closed and a returning one reopened. Not yet run from a GitHub Actions runner.
* Sends findings only for the branches you allow, and one test per branch. Pull request scans are not copied in.
* DefectDojo Community has no per-team permissions (that is a paid feature), so everyone with a login sees every product.
