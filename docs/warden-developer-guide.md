# Warden developer guide (one page)

Warden is one module that checks your repository for security problems on every pull request. You run a few commands, commit the result, and read the report in GitHub. It starts in **report-only mode**: nothing blocks your build until your team turns the gate on.

## 1. Set up once per repo (about 10 minutes)
You need **Docker**, **Python 3.8+** and **Git**.
```bash
warden init                      # detects your stack, adds .security/ and the GitHub workflow
.security/warden doctor          # every line should be a green tick
.security/warden scan            # first scan; a first scan usually finds things, that is normal
.security/warden open            # opens the HTML report
git add .security .github && git commit -m "Add security scanning" && git push
```
Installing `warden` itself and the Windows steps: [GETTING-STARTED.md](GETTING-STARTED.md). **`warden init` copies the whole engine into `.security/kit`**, so GitHub Actions needs no access to our repository ([details](per-project-mode.md#self-contained-repo-the-default-no-access-to-our-repository-needed)). If your network blocks semgrep.dev: [offline-and-blocked-networks.md](offline-and-blocked-networks.md). Teammates only need `git pull`; the repo's launcher (`.security/warden`) installs the pinned version by itself.

## 2. What you see on every pull request
| Where | What |
|---|---|
| Pull request comment | One comment, updated on every push: the findings you must look at |
| Changed lines | Markers on the risky lines in the diff |
| Run summary | The same result on the Actions run page, plus the HTML report as a download |
| Pass / fail | The gate: blocks only when the policy says so (see section 5) |

## 3. What is checked
Secrets, code patterns (SAST), vulnerable libraries, Dockerfiles / Kubernetes / Terraform, built images, GitHub Actions security, running apps in QA (optional) and AI-agent code. The list per category: [checks/](checks/README.md).

## 4. Fix a finding
1. Open the report or the PR comment: each finding names the file, the line and, when known, the fix.
2. Fix it and push. The comment updates itself.
3. Common fixes (move a secret out of code, upgrade a library, run a container as non-root): [fixing-findings.md](fixing-findings.md).
4. Cannot fix it now (false positive, no upstream fix)? Add a **time-boxed exception**, never a silent ignore: [exceptions-and-baseline.md](exceptions-and-baseline.md).
5. Old repo with many legacy findings? `.security/warden baseline` records them, so only **new** Critical and High findings block.

## 5. The one file you edit: `.security/config.env`
```ini
SEC_PRESET=starter     # starter = report-only | standard = blocks new Critical/High | strict = release gate
# SEC_BANDIT=off       # turn a tool off (gitleaks, Semgrep and Trivy cannot be turned off)
# SEC_IMAGE=myapp:ci   # setting a target switches the matching scan on
# SEC_EXCLUDE_PATHS=vendor/**,legacy/**
```
Change it with `warden config set KEY VALUE`; see what runs with `warden config show`. Rollout plan (report-only, baseline, then standard): [GETTING-STARTED.md](GETTING-STARTED.md#step-5-roll-out-safely-recommended-timeline).

## 6. Everyday commands
| Command | Use it to |
|---|---|
| `.security/warden quick` | Fast check (secrets + code) before you push. `warden hook install` runs it on every push |
| `.security/warden scan` | Full scan, report-only until the preset is `standard` |
| `.security/warden gate` | Same scan, but fail on policy violations (what CI uses) |
| `.security/warden open` | Open the latest HTML report |
| `.security/warden doctor` | Diagnose Docker, network or image problems |

## 7. Optional tools (three steps each)
Each tool is independent and none is needed for the scan. Ask the platform team for the address and the CI secret, put the address in `.security/config.env`, make sure the secret exists in CI.

| Tool | Use it for | Switch-on | CI secret |
|---|---|---|---|
| SonarQube | Code quality, smells, security hotspots | `SEC_SONAR=on` | `SONAR_TOKEN` |
| DefectDojo | All findings of all repos in one register | `SEC_DEFECTDOJO_URL=...` | `DEFECTDOJO_TOKEN` |
| Dependency-Track | Alerts when a new CVE hits a library you shipped | `SEC_DTRACK_URL=...` | `DTRACK_API_KEY` |
| Wiz (licence needed) | Wiz CLI scans of code, IaC and images | copy the Wiz workflow template | `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` |

DefectDojo and Dependency-Track receive scans of `main` and `master` only by default. A problem with any of these tools never breaks your build. Details: [integrations/](integrations/README.md).

## 8. Your own tests (pytest, Jest and so on)
Warden is a **security** scanner, not a test runner. Keep running your unit tests (for example `pytest`) as their own step in the same workflow. Warden does not run or replace them, and a failing test is not a security finding. Run the tests before or next to the scan, for example:
```yaml
- run: pip install -r requirements.txt pytest && pytest
```

## 9. Rules to remember
- **Never put a secret in `config.env` or in code.** Warden refuses secrets in `config.env`. On your machine use `warden creds set NAME`; in CI use CI secrets.
- A scan that cannot run a required tool **fails closed**; it never reports "clean" by accident.
- Do not edit generated files under `.security/`. `warden upgrade` refreshes them and keeps your config, exceptions and baseline.
- Stuck? [troubleshooting.md](troubleshooting.md) or `.security/warden doctor`.
