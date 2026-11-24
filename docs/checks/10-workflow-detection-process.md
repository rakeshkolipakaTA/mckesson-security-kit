# 10. Developer workflow, detection and process

Three things a scanner cannot do alone: catch problems on the developer's machine **before** a push, notice an attack **in production**, and make sure people have the habits and procedures that no tool provides.

## A. Developer workflow: catch it before CI

| Check | What it does | Why it protects |
|---|---|---|
| **Pre-push hook** (`warden hook install`) | Runs `warden quick`: secrets and code analysis before every `git push` | A leaked key never reaches the remote at all |
| **pre-commit configuration** | Local checks on commit | Fastest feedback |
| **Pull request template and CODEOWNERS snippet** | A checklist on every PR; reviewers required for `.security/` (skip lists, waivers and exceptions live there) | Nobody quietly weakens the scan |
| **IDE recommendations** (`.vscode`) | Recommended SonarQube and Semgrep extensions and settings, written by `warden init` | Problems show while typing |
| **Auto-update channel** | Repos follow the moving tag `v1`, so a new check reaches every repo on its next run. `warden pin` freezes a version; `warden upgrade` changes it; `scripts/release.sh` cuts releases | New protections arrive without anyone editing every repo |
| **Test-credential handling** (`warden creds`) | Test usernames, passwords and tokens come from CI secrets, a file path, a local store **outside** git (mode 600, refuses a git folder) or a hidden prompt; `config.env` refuses secrets; tokens are masked in CI logs | Test accounts never end up in the repository |
| **`warden doctor` and `warden config show`** | Show what is running on a repo and why, and what is missing | You can see the real coverage |

Notes: the pre-push hook and the CODEOWNERS team name are templates to adapt (the team handle is a placeholder). The auto-update behaviour has been tested with a local git source (new release, offline fallback, pin, re-init) and against the real GitHub tags; it has not yet been run from a GitHub Actions runner. Protect `v*` tags in the Warden repository: whoever can move `v1` can run code in every repo that follows it ([06-supply-chain-and-cicd.md](06-supply-chain-and-cicd.md)).

## B. Detection and response: would we notice in production?

Scans find weaknesses before release. Runtime detection tells you when something is being exploited now.

| Check | What it detects | Priority | Status |
|---|---|---|---|
| **Falco rules for agent workloads** (7) | A shell started in an agent container; a package manager run; a network tool started; a service-account token or mounted secret read; the cloud metadata service contacted; a write into an executable directory; the agent audit log modified by an unexpected process | Warning to Critical, per rule | **Template.** Falco's own validator accepts the rules; never run on a live node |
| **SIEM shipping recipe** (Sentinel, Datadog) | Forwards Falco alerts and the agent audit log so security staff see them | n/a | **Documented.** A recipe, not a tested setup |

Details and the rule table: [../runtime-detection.md](../runtime-detection.md). Not provided: log collection, alert routing, 24x7 monitoring, an incident response team. Those are platform and people work.

## C. Process and governance: what tools cannot provide

Tools find known patterns. People find design flaws, decide what is acceptable, and handle incidents. The kit ships short templates, in [../process/](../process/README.md):

| Document | Use it when | How often |
|---|---|---|
| [Threat-model template](../process/threat-model-template.md) | Designing a feature, an integration, or an agent with tools | Per design; again on big changes |
| [Secure code-review checklist](../process/secure-code-review-checklist.md) | A PR touches authentication, data, tools or dependencies | Every relevant PR |
| [Vulnerability-management policy](../process/vulnerability-management-policy.md) | Deciding how fast a finding must be fixed and who may accept a risk | Reference; review yearly |
| [Incident-response runbook](../process/incident-response-runbook.md) | An agent is compromised, a secret leaked, or a dependency or the build is compromised | Rehearse twice a year |
| [Access-review checklist](../process/access-review-checklist.md) | Repository, CI, cloud, agent and tool permissions | Quarterly |
| [Security-training plan](../process/security-training-plan.md) | Onboarding and yearly refreshers | Onboarding and yearly |
| [Penetration-test scope and rules of engagement](../process/pentest-scope-template.md) | Commissioning a manual test | Before major releases; yearly |
| [Security-champions guide](../process/security-champions-guide.md) | Setting up one security contact per team | Ongoing |

## What this kit does not replace

| Need | Why a scanner kit does not cover it |
|---|---|
| **Manual penetration test** | Humans chain weaknesses and abuse business logic. Scanners and DAST find known patterns only (see [05-dynamic-testing-dast.md](05-dynamic-testing-dast.md)) |
| **Threat modelling and design review** | Design flaws have no code pattern |
| **Network, endpoint and cloud operations security** | Firewalls, EDR, identity governance and cloud configuration need their own tools. Only IaC files and optional posture checks are covered here |
| **Incident response** | The runbook is a document: people must own and rehearse it |
| **Privacy and data governance** | Classification and masking helpers exist for agents; policies and legal decisions do not come from code |

Status: pre-push hook, pre-commit, PR template and creds are **verified** (templates for the CODEOWNERS handle). IDE recommendations are a **template** (files validated, not exercised in an IDE). Falco rules are a **template**, the SIEM recipe and the process kit are **documented**.
