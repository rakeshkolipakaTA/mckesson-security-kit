# Developer setup guide: Warden (security) and Claude Cost Kit (cckit)

Two small tools go into a repository. **Warden** checks every pull request for security problems. **Claude Cost Kit (cckit)** gives everyone who uses Claude Code in the repo the same cheap, safe settings. Both follow the same pattern: **the team lead installs and sets up the repo once and commits the result; everyone else runs `git pull`.**

| | Warden | Claude Cost Kit (cckit) |
|---|---|---|
| What it does | Scans for secrets, insecure code, vulnerable libraries, Dockerfile / Kubernetes / Terraform settings, workflow risks and AI-agent code; reports in GitHub | Writes Claude Code settings, rules, helper agents and hooks that cut token cost, plus optional usage reporting |
| Command | `warden` (in the repo: `.security/warden`) | `cckit` |
| Lives in the repo as | `.security/`, `.github/workflows/security-scan.yml` | `CLAUDE.md` (one block), `.claude/`, `.cckit/` |
| Source | github.com/rakeshkolipakaTA/mckesson-security-kit | github.com/rakeshkolipakaTA/claude-c-kit |
| Deeper docs | [GETTING-STARTED.md](GETTING-STARTED.md), [warden-developer-guide.md](warden-developer-guide.md) | the cckit README |

---

## 1. Preparation

**Everyone (to use a repo that already has them)**
- Git, and Python 3 on the PATH (the cckit hooks are small Python files).
- Your company e-mail in git: `git config user.email firstname.lastname@tigeranalytics.com` (cckit takes it from here and never asks).
- Claude Code installed and signed in (see the setup at the top of [developer_guide.txt](developer_guide.txt)). Claude Code asks once to trust the folder; accept it, or the cckit settings do not apply.

**Team lead (to add them to a repo)**

| Need | Warden | cckit |
|---|---|---|
| Software | Docker running, Python 3.8+, Git. On Windows use WSL2 or Git Bash | Python 3.10+, Git |
| Network from your machine | Docker Hub, ghcr.io, PyPI, npm and semgrep.dev (run `warden doctor` to see what is blocked) | github.com (for the install) |
| From someone else | Nothing for the core scan. Optional tools need an address and a CI secret from the platform team: SonarQube, DefectDojo, Dependency-Track, Wiz (needs a licence) | The **team key** (a join code) from your admin, only if usage reporting is on |
| Repo rights | Push access, and permission to add a workflow file | Push access |

Decide before you start: which repo, who the security contact is, and whether the first run is report-only (the default and recommended).

## 2. Setup (team lead, once per repo)

**Warden**
```bash
python3 -m venv ~/.warden-venv
~/.warden-venv/bin/pip install "git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@main"
mkdir -p ~/.local/bin && ln -sf ~/.warden-venv/bin/warden ~/.local/bin/warden
cd your-repo
warden init                        # copies the whole engine into .security/kit; nothing is pulled from our repo later
.security/warden doctor            # every line should be a green tick
.security/warden scan && .security/warden open
git add .security .github && git commit -m "Add Warden security scanning (report-only)" && git push
```
- `main` carries 1.1.0, where `warden init` copies the engine into the repo. On the older release tag `v1.0.2`, add `--vendor` (`warden init --vendor`), otherwise the repo only gets a small pin and fetches the engine from our repository on every run.
- `warden init --thin` is the pinned, fetched-from-our-repo mode. Use it only if the client allows GitHub Actions to pull from our repository.
- Windows: use PowerShell for the install ([GETTING-STARTED.md](GETTING-STARTED.md) has the commands) and run `.security/warden` from Git Bash or WSL2.
- The generated workflow runs on pull requests and on pushes to `main` / `master`. It starts report-only: nothing blocks a merge yet.

**cckit**
```bash
python3 -m venv ~/.cckit-venv
~/.cckit-venv/bin/pip install "git+https://github.com/rakeshkolipakaTA/claude-c-kit.git@main"
mkdir -p ~/.local/bin && ln -sf ~/.cckit-venv/bin/cckit ~/.local/bin/cckit
cd your-repo
cckit init                         # asks for the team key once, only if none is set
cckit doctor                       # says what to fix
git add CLAUDE.md .claude .cckit && git commit -m "Add cckit" && git push
```
- Windows PowerShell install lines are in the cckit README. Check with `cckit --version`.
- `cckit init --dry-run` shows what would change first. If the repo already has a `CLAUDE.md`, your text is never touched: cckit adds one block between `cckit:begin` and `cckit:end` markers.
- Committing the team key (`.cckit/key.json`) lets teammates register automatically. Do it for **private repos only**.

**Everyone else:** `git pull`, open Claude Code, accept the folder-trust prompt. Nothing to install for Warden (CI uses the files in the repo) and nothing for cckit.

## 3. Guidelines

**Warden: day to day**
- Run `.security/warden quick` (about a minute: secrets and code) before you push. `.security/warden hook install` does it on every push.
- Read the pull request comment: one comment, updated on every push, plus markers on the risky lines in "Files changed". The full HTML report is a download on the run (`.security/warden open` locally).
- Fix the finding it names (file, line, fix hint), push, and the comment updates. Common fixes: [fixing-findings.md](fixing-findings.md).
- Cannot fix it now? Add a **time-boxed exception** in `.security/exceptions.json` with an owner and an expiry date. Never ignore silently.
- Old repo with hundreds of findings? `.security/warden baseline` records them, so only **new** Critical and High findings block.
- Roll out in steps: report-only for 1 to 2 weeks (`SEC_PRESET=starter`), baseline legacy findings, then `warden config set SEC_PRESET standard` to block new Critical and High.
- **Never put a secret in code or in `.security/config.env`** (Warden refuses it). Use CI secrets; on your machine `warden creds set NAME`.
- Optional tools (SonarQube, DefectDojo, Dependency-Track, Wiz) are each one address in `config.env` plus one CI secret. A problem with any of them never breaks your build: [integrations/](integrations/README.md).
- Warden is a security scanner, not a test runner. Keep running your own tests (for example `pytest`) as a separate step in the same workflow.
- Upgrading: re-run `warden init` from a newer Warden and review the diff in a pull request. Protect `.security/` and `.github/` with CODEOWNERS, because the engine now lives in the repo.

**cckit: day to day**
- Work as usual. The settings pick Sonnet with high effort, cap subagents, shorten test output and show `[Model] ctx 42% $0.31` in the status line. At 60% context, run `/compact`, or `/clear` between unrelated tasks.
- Keep `CLAUDE.md` and each rules file under 200 lines (`cckit doctor` fails above that). Put detail in `.claude/rules/` or a skill.
- The rule files are **starters**: edit them to your team's standards and commit. Once you edit a file, `cckit init` never overwrites it.
- Check your own usage: `cckit report --days 7` (numbers only, from your local Claude Code sessions).
- Start Claude Code with only the tools a task needs: `cckit run --profile docs`.
- Privacy: usage reporting sends numbers and tool **names** only, never prompts, code or replies. Switch it off on your machine with `CCKIT_TELEMETRY=off`; switch every cckit hook off with `CCKIT_DISABLED=1`.
- Upgrading is the lead's job: `pip install --upgrade` from `main`, `cckit init`, commit; everyone else `git pull`.
- A developer's own `settings.local.json` or `/model` choice can override repo settings; only managed settings are enforced. Spend limits are set in the admin console, not in the repo.

## 4. Troubleshooting

**Warden**

| Symptom | Fix |
|---|---|
| `warden doctor` shows a host as NOT reachable | A proxy or firewall blocks it. Ask the platform team to allow it or mirror it ([platform-setup.md](platform-setup.md)) |
| Docker errors, or `docker: command not found` | Start Docker Desktop (or the Docker service). On Windows use WSL2 or Git Bash |
| First scan is very slow | Images download once. `warden pull` does it ahead of time |
| Gate says `FAIL (with tool errors: semgrep=missing)` | semgrep.dev is blocked. Run `warden rules fetch` where it is reachable, then `warden config set SEC_SEMGREP_RULES .security/semgrep-rules` ([offline-and-blocked-networks.md](offline-and-blocked-networks.md)) |
| `X=missing` for another tool | That tool produced no report. Look in `.security/reports/<date>/raw/`. An enforced gate fails closed on purpose |
| Trivy cannot download its database | Needs ghcr.io / mirror.gcr.io. Mirror it and set `TRIVY_DB_REPOSITORY` |
| CI is green but the report says FAIL | Report-only mode (`SEC_PRESET=starter`). Set `standard` to enforce |
| Secret false positive in test data | Allowlist in `.security/gitleaks.toml`, or a time-boxed exception |
| `config.env: ignoring unknown key` | Only documented `SEC_*` keys and simple values are accepted. Secrets never belong there |
| `bash: warden: command not found` (Windows) | Use WSL2 or Git Bash and run `.security/warden` from the repo root |
| Repo got a pin instead of the engine | It was set up in thin mode or with `v1.0.2`. Run `warden init --vendor` (or `warden init` on 1.1.0) |
| Workflow does not start on a pull request | Check that `.github/workflows/security-scan.yml` is committed and Actions is enabled for the repo |
| Anything else | `.security/warden doctor`, then [troubleshooting.md](troubleshooting.md) |

Started over? `warden uninstall` removes what `init` added (it keeps your config, exceptions and baseline); `warden reinstall` starts fresh. `warden disable --until YYYY-MM-DD --reason "..."` pauses scanning for up to 90 days.

**cckit**

| Symptom | Fix |
|---|---|
| `requires a different Python` | The environment was made with an old Python. Delete `~/.cckit-venv` and recreate it with Python 3.10+ (`python3.12 -m venv ~/.cckit-venv`; Windows `py -3.12 -m venv ...`) |
| `cckit` is "not found" | Open a new terminal, or run `~/.cckit-venv/bin/cckit` (Windows `...\Scripts\cckit.exe`) |
| pip fails with a git error | Git is missing, or github.com is not reachable |
| Windows hooks do nothing | Set `python = "python"` under `[hooks]` in `.cckit/cckit.toml`, then `cckit init` |
| Settings seem ignored | Claude Code ignores project settings until the folder is trusted. Restart it and accept the prompt |
| `cckit init` stops with a marker message | `CLAUDE.md` has a `cckit:begin` without `cckit:end` (or reversed). Fix or remove the marker; nothing was written |
| `cckit doctor` fails on length | A `CLAUDE.md` or rules file is over 200 lines. Move detail into `.claude/rules/` |
| "No company e-mail" note at start-up | Run `git config user.email firstname.lastname@tigeranalytics.com` |
| Not registered / nothing reported | Run `cckit register`, or set `CCKIT_TEAM_KEY`; check with `cckit whoami --check` |
| Hooks behave oddly on one machine | `CCKIT_DISABLED=1` makes every hook do nothing; `cckit disable` does it for the repo |
| Anything else | `cckit doctor`; `cckit reinstall` (uninstall, then install again) |

## 5. Who to ask
Warden and cckit questions: the security / platform contact in your team's onboarding checklist ([onboarding-checklist.md](onboarding-checklist.md)). Usage-app and team-key questions: your cckit admin.
