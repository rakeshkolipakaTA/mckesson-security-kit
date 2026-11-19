# Security in deployment (CD) pipelines

Not every scan belongs on every pull request. This is where each one goes (plan section 6):

```
 pull request ──► merge to main ──► build ──► IMAGE GATE ──► push to JFrog/ACR ──► deploy QA/UAT ──► DAST (ZAP) ──► release approval ──► prod
   scan (fast)       scan             docker     warden gate     (only if gate        (your              warden scan       (human)
   report/enforce                      build     --gate release     passed)            deploy job)        --zap-url QA
                                                 --image app:tag
```

| Stage | Command | Blocks when |
|---|---|---|
| Pull request / main | `.security/warden scan` (or `gate`) | new Critical/High findings (once `SEC_PRESET=standard`) |
| After `docker build`, before push | `.security/warden gate --gate release --image app:tag` | any Critical/High finding in code, dependencies **or the image**, unless it has an approved, unexpired exception |
| After deploying to QA/UAT | `.security/warden scan --zap-url https://qa-url --zap-mode baseline` | report-only by default: DAST results need human triage |

## The image gate (most important CD step)
```bash
docker build -t myapp:$GIT_SHA .
.security/warden gate --gate release --image myapp:$GIT_SHA     # exit 1 = do not push / deploy
docker push ...                                                  # only reached if the gate passed
```
It scans your source, dependencies and the built image (OS packages, Python/Node libraries inside it, secrets baked into layers, Dockerfile problems).
**Most image findings are fixed by rebuilding on a newer base image** (e.g. `python:3.12-slim` instead of an old tag) and `apt-get upgrade`. See [fixing-findings.md](fixing-findings.md).

Ready-made files: `.security/ci/security-release.github.yml` (GitHub Actions), `.security/ci/Jenkinsfile.security` stage 2, `.security/ci/azure-pipelines-security.yml` (commented step).

## DAST against QA (OWASP ZAP)
Rules of engagement: **QA/UAT only, never production; get the app owner's OK; the target must be reachable from the runner (self-hosted runner if QA is on a VPN).**

| Mode | Use when | Honest limits |
|---|---|---|
| `--zap-mode baseline` | Websites with links; safe passive crawl | Finds almost nothing on a pure JSON API (nothing to crawl) |
| `--zap-mode api --zap-openapi URL` | You have an OpenAPI file | Imports endpoints but uses example values; in our test it missed injection bugs that `full` mode found |
| `--zap-mode full --zap-url "URL1?x=1,URL2/5"` | You want an **active** attack on specific endpoints | Sends attack payloads: QA only. Needs URLs *with* realistic parameters. POST bodies and logins are not covered in v1 |

In our end-to-end test ZAP found XSS and a CORS misconfiguration but missed an SQL injection in a URL path. **A clean DAST report is not proof of safety**; it supplements code analysis, it does not replace it. Details: [fastapi-e2e.md](fastapi-e2e.md).

## AI agents: red-team stage
For agent services add a QA stage after deployment: `.security/warden redteam --redteam-url "$QA_AGENT_URL"` with test-user tokens from the CI secret store (template `.security/ci/security-redteam.github.yml`). Real attack probes: QA/UAT only. See [agentic-redteam.md](agentic-redteam.md).

## Exceptions at release time
A release is blocked by a Critical/High finding unless it is in `.security/exceptions.json` with reason, approver and expiry. Security approval for release exceptions should be recorded in the pull request that adds the exception (see [exceptions-and-baseline.md](exceptions-and-baseline.md)).

## Where reports go
Every run produces `summary.html`, `summary.md`, `results.sarif` (and `raw/` tool output, which can contain code snippets: do not publish it). CI templates upload the first three as pipeline artifacts. For an org-wide view across repos, the platform team can aggregate the `summary.json` files (see `scripts/aggregate.py`).
