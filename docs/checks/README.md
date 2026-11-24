# Warden checks: what we test and how each check protects you

One page per category. Each page answers four questions:

1. **What attack or mistake does this category stop?**
2. **Which checks run**, what each one looks for, and how serious a hit is.
3. **What happens when it finds something** (does it block a merge?) and how to fix it.
4. **What it does not catch**, so nobody mistakes "no findings" for "safe".

| # | Category | Question it answers | Page |
|---|---|---|---|
| 1 | Secrets | Is a password, token or key sitting in the code or its history? | [01-secrets.md](01-secrets.md) |
| 2 | Code analysis (SAST) | Does our own code contain insecure patterns? | [02-code-analysis-sast.md](02-code-analysis-sast.md) |
| 3 | Dependencies (SCA) | Do the libraries we ship have known vulnerabilities or bad licences? | [03-dependencies-sca.md](03-dependencies-sca.md) |
| 4 | Containers and infrastructure as code | Are Dockerfiles, images, Kubernetes and Terraform configured safely? | [04-containers-and-iac.md](04-containers-and-iac.md) |
| 5 | Dynamic testing (DAST) | Can the running app be attacked from outside? | [05-dynamic-testing-dast.md](05-dynamic-testing-dast.md) |
| 6 | Supply chain and CI/CD | Can our pipeline or repository settings be abused? | [06-supply-chain-and-cicd.md](06-supply-chain-and-cicd.md) |
| 7 | AI agents: static checks and red-team probes | Is an agent built unsafely, and does a running agent resist attack? | [07-ai-agent-checks.md](07-ai-agent-checks.md) |
| 8 | AI agents: runtime controls library | Reusable guardrails, authorisation and audit for agent code | [08-ai-agent-runtime-controls.md](08-ai-agent-runtime-controls.md) |
| 9 | Gate, policy and reporting | Who decides pass or fail, and how are results tracked? | [09-gate-policy-reporting.md](09-gate-policy-reporting.md) |
| 10 | Developer workflow, detection and process | What catches problems before CI, in production, and in people's habits? | [10-workflow-detection-process.md](10-workflow-detection-process.md) |

Optional tools that receive scan results (SonarQube, DefectDojo, Dependency-Track): [../integrations/](../integrations/README.md).

The complete, filterable list with a status for every check is [../test-coverage.md](../test-coverage.md) and [../security-test-coverage.xlsx](../security-test-coverage.xlsx). To change what runs on one repo see [../configuration.md](../configuration.md).

## How protection works (applies to every category)

```
 developer pushes ──► scanners run ──► findings are merged and de-duplicated ──► gate decides ──► result shown in GitHub
                      (this folder)      (same CVE from two tools = one row)      (policy.json)    summary, markers, PR comment
```

* **Scan early, cheaply.** Secrets, code, dependencies, Dockerfiles and Kubernetes files are checked on every pull request. Running-app tests (DAST, API fuzzing, red-team) need a deployed QA system and run after deploy. Image checks run after `docker build`, before the push.
* **A scanner that breaks never looks like a pass.** With enforcement on, a tool that did not produce a valid report fails the gate. A skipped tool is listed under *Reduced coverage* in the report.
* **Three tools cannot be turned off by a team:** gitleaks, Semgrep and Trivy (plus agent-scan and modelscan where they apply). A time-boxed, approved waiver is the only way around, and it expires.
* **Severity thresholds are central.** A pull request cannot weaken them: a `policy.json` placed in `.security/` is ignored and `config.env` is read as data, never run.

### What blocks a merge

| Severity | Pull request gate | Release gate |
|---|---|---|
| Critical | Blocks (new and already-known findings) | Blocks |
| High | Blocks **new** findings; known findings block once they are older than their fix deadline | Blocks new and known findings |
| Medium, Low, Info | Reported only | Reported only |

Fix deadlines (SLA): Critical 3 days, High 14, Medium 60, Low 90. The `starter` preset reports only; `standard` enforces the pull request gate; `strict` enforces the release gate. Details: [../policy.md](../policy.md) and [09-gate-policy-reporting.md](09-gate-policy-reporting.md).

### How serious is a hit (severity words)

| Source of the finding | How severity is set |
|---|---|
| Secrets | High (a leaked secret is treated as usable until it is rotated) |
| Semgrep | ERROR = High, WARNING = Medium, INFO = Low |
| Dependency CVEs | The scanner's own rating. pip-audit gives none, so it counts as High unless Trivy rates the same CVE |
| Licences | Deny list = High, review list = Medium, unknown = Low |
| Advisory tools (kubescape, CIS benchmark) | One level below the main tool, never above Medium for CIS |
| Exposure and repo-settings checks | Set per rule, shown on each page |

### Status words used on every page

| Word | Meaning |
|---|---|
| **Verified** | Run end to end in this project or on a real app |
| **Verified (partial)** | Run, with a stated limit |
| **Template** | A ready-to-use file that has not been run against a real environment |
| **Reference library** | Working, unit-tested code that your platform has to wire in |
| **Documented** | A procedure or recipe, not code |

### Honest limits of any scanner kit

Automated scans find **known patterns and known vulnerabilities**. They do not replace a threat model, a code review of business logic, or a human penetration test. Broken access control in your own business rules, abuse of legitimate features and design flaws are mostly invisible to scanners. [10-workflow-detection-process.md](10-workflow-detection-process.md) lists what still needs people.
