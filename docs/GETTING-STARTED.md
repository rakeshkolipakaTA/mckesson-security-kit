# Getting started: add security scanning to your repo (about 10 minutes)

You do **not** need to know the security tools, write pipeline YAML, or involve a DevOps person.
You run three commands, commit the result, and your pull requests get a security report.
It starts in **report-only mode**: nothing can break your build until *you* decide to turn enforcement on.

## What you get
On every pull request / push, these checks run (only the ones that fit your stack are used):

| Question it answers | Tool | Stacks |
|---|---|---|
| Did someone commit a password / token / key? | gitleaks, Trivy | all |
| Is the code insecure (injection, unsafe functions, weak crypto...)? | Semgrep, plus Bandit (Python) / ESLint security rules (JS/TS) | python, node, java |
| Do my libraries have known vulnerabilities (CVEs)? | pip-audit, `npm audit`, Trivy | python, node, java |
| Is my Dockerfile / image unsafe? | Trivy | anything with a Dockerfile |
| Code quality + security hotspots (optional) | SonarQube | all |
| Is my *running* app attackable? (optional, QA only) | OWASP ZAP | web apps / APIs |

**Building an AI agent / LLM app?** The same commands also detect that (agent frameworks, LLM SDKs, MCP config) and add agent-specific checks: unsafe tools, fail-open guardrails, unregistered models, risky MCP servers, secrets in prompts, malicious model files. Read [agentic-security.md](agentic-security.md); to test a running agent in QA use `warden redteam` ([agentic-redteam.md](agentic-redteam.md)); for code that fixes the findings use `warden agentlib` ([agentic-runtime-library.md](agentic-runtime-library.md)).

The result is one HTML report, a summary on the pipeline page, markers on the risky lines of a pull request, one updated pull request comment, and a pass/fail gate. **GitHub only, no server needed**: see [github-only-quickstart.md](github-only-quickstart.md).

## Before you start
- **Docker** installed and running (Docker Desktop on Windows/Mac, Docker Engine on Linux). On Windows use WSL2 or Git Bash.
- **Python 3.8+** and **Git**. That is all.
- **Who installs what.** The **team lead** installs `warden` once and runs `warden init`, which puts the engine in the repo. **Everyone else just runs `git pull`**: nothing else to install, and CI uses the same files.

## Step 1: install Warden once, then add it to your repo
**Linux / macOS**
```bash
python3 -m venv ~/.warden-venv
~/.warden-venv/bin/pip install "git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@main"
mkdir -p ~/.local/bin && ln -sf ~/.warden-venv/bin/warden ~/.local/bin/warden
```
**Windows (PowerShell)**
```powershell
py -m venv $env:USERPROFILE\.warden-venv
& "$env:USERPROFILE\.warden-venv\Scripts\pip.exe" install "git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@main"
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.warden-venv\Scripts", "User")
```
Open a new terminal and check `warden --version`. (Your platform team may give you an internal package index instead of the git URL; the rest is the same.)

Then, in your repo, once:
```bash
cd your-repo
warden init                      # add --preset standard to block PRs from day one
git add .security .github && git commit -m "Add security scanning (report-only)" && git push
```
`init` detects your stack, adds `.security/` (config, CI templates and **the whole engine in `.security/kit`**), and for GitHub adds `.github/workflows/security-scan.yml`. The repo is **self-contained**: GitHub Actions and teammates need no access to our repository or package index, only Docker. It never overwrites your own files; re-running it from a newer Warden refreshes the generated ones and shows up as a normal diff to review ([per-project-mode.md](per-project-mode.md#self-contained-repo-the-default-no-access-to-our-repository-needed)).
Prefer to follow our releases automatically instead (a small `warden.lock` pin, the engine fetched from our repository on each run)? Use `warden init --thin`: [updates-and-versions.md](updates-and-versions.md).

## Step 2: check your machine
```bash
.security/warden doctor
```
Every line should be a green tick. A red cross tells you exactly what to fix (Docker not running, a blocked website, ...).
Optionally `.security/warden pull` downloads the scanner images now (a few GB, one time) so your first scan is quick.

## Step 3: run your first scan
```bash
.security/warden scan
.security/warden open        # opens the HTML report in your browser
```
A first scan usually finds things. That is normal; do not panic. The report tells you what, where, and (when known) the fix.
How to read it: [reading-reports.md](reading-reports.md). How to fix the common ones: [fixing-findings.md](fixing-findings.md).

## Step 4: hook it into your pipeline
Commit `.security/` (reports are git-ignored) and your CI file. Then pick your platform:

| You use | Do this | Guide |
|---|---|---|
| **GitHub Actions** | Nothing: `init` already added `.github/workflows/security-scan.yml`. Commit and push. | [ci-github-actions.md](ci-github-actions.md) |
| **Jenkins** | Copy the stage from `.security/ci/Jenkinsfile.security` into your Jenkinsfile. | [ci-jenkins.md](ci-jenkins.md) |
| **Azure DevOps** | Create a pipeline from `.security/ci/azure-pipelines-security.yml`. | [ci-azure-devops.md](ci-azure-devops.md) |

For deployment pipelines (scan the Docker image before you push it, scan the running QA app) see [cd-release-gates.md](cd-release-gates.md).

## Step 5: roll out safely (recommended timeline)
| When | Do | Setting in `.security/config.env` |
|---|---|---|
| Week 1-2 | Run report-only. Look at the findings. Fix the easy ones (secrets, upgrades). | `SEC_PRESET=starter` |
| Week 2-4 | Legacy app with many old findings? Record them: `.security/warden baseline`. Commit `baseline.json`. Only *new* Critical/High findings will block. | `SEC_PRESET=starter` |
| Week 4+ | Turn the gate on. PRs that add Critical/High findings fail. | `SEC_PRESET=standard` |
| Before releases | Use the strict gate: `.security/warden gate --gate release` (see CD guide). | |

Cannot fix a finding right now (false positive, no upstream fix)? Add a time-boxed exception: [exceptions-and-baseline.md](exceptions-and-baseline.md).

## Everyday commands
| Command | What it does |
|---|---|
| `.security/warden scan` | Scan using your `config.env` settings (report-only until you choose the `standard` preset) |
| `.security/warden gate` | Same, but always fail on policy violations (what CI uses to block) |
| `.security/warden quick` | Fast check (secrets + code analysis only), good before pushing |
| `.security/warden open` | Open the latest HTML report |
| `.security/warden baseline` | Record today's findings as "existing" |
| `.security/warden doctor` | Diagnose problems |
| `.security/warden hook install` | Run `quick` automatically before every `git push` |
| `.security/warden redteam --redteam-url URL` | AI agents: attack probes against a running QA agent |
| `.security/warden agentlib` | AI agents: copy the runtime-controls library into your repo |
| `.security/warden config show` / `config set` | See / change what runs |
| `warden upgrade` | Move the repo to the installed (newer) warden version |
| `warden disable` / `enable` | Pause scanning for a limited time |
| `warden uninstall` / `reinstall` | Remove what `init` added / start fresh |

## The one file you edit: `.security/config.env`
```ini
SEC_PRESET=starter     # starter = report-only | standard = blocks new Critical/High | strict = release gate + Sonar/Dependency-Check
# SEC_BANDIT=off       # turn a tool off (required tools: gitleaks, semgrep, trivy cannot be)
# SEC_IMAGE=myapp:ci   # setting a target switches the matching tool on
# SEC_EXCLUDE_PATHS=vendor/**,legacy/**
```
`warden config show` prints what runs and why; `warden config set SEC_PRESET standard` edits the file safely.
Everything is explained in [configuration.md](configuration.md). To switch scanning off for a while: `warden disable --until 2026-12-31 --reason "..."` (it turns itself back on).

## Something went wrong?
[troubleshooting.md](troubleshooting.md), or run `.security/warden doctor`. Your security / platform contact is listed in your team's onboarding checklist ([onboarding-checklist.md](onboarding-checklist.md)).
