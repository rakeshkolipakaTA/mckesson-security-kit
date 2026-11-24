# 6. Supply chain and CI/CD: can our pipeline or repository be abused?

## What it protects against
Attackers increasingly go after the **build** rather than the app: a compromised GitHub Action that runs in every pipeline, a workflow that treats a pull request title as a shell command, a token with write access to everything, a default branch anyone can force-push to, or a deployed image that is not the one CI built. These checks look at the pipeline files and the repository's settings.

## Checks

| Check | What it looks for | Severity | Stage |
|---|---|---|---|
| **zizmor** (GitHub Actions security) | Actions not pinned to a commit, script injection from untrusted input (issue titles, branch names), dangerous triggers (`pull_request_target`), excessive `GITHUB_TOKEN` permissions, credentials persisted by checkout. Warden's own templates give 0 findings | by rule | every PR / push |
| **Repository settings check** (needs `GITHUB_TOKEN`) | See the table below | per rule | scheduled / PR |
| **Dependabot / Renovate configuration** | Written by `warden init` so library and Action updates arrive as pull requests | n/a | setup |
| **Image signing + SLSA provenance** (cosign) | Proof that the deployed image is the one CI built | n/a | release (template) |
| **OpenSSF Scorecard** | A repository hygiene score | n/a | scheduled (template) |
| **Warden's own update channel** | See below | n/a | every run |

### Repository settings rules

| Rule id | Flags | Severity |
|---|---|---|
| `REPO-UNPROTECTED` | Default branch has no protection (no required reviews, checks or force-push block) | High |
| `REPO-FORCE-PUSH` | Force pushes allowed on the default branch (history can be rewritten) | High |
| `REPO-NO-REVIEWS` | Pull requests do not need an approving review | Medium |
| `REPO-NO-STATUS-CHECKS` | The security scan is not a required check, so it cannot block a merge | Medium |
| `REPO-NO-ALERTS` | Dependabot vulnerability alerts disabled | Medium |
| `REPO-SECRET-SCANNING`, `REPO-PUSH-PROTECTION`, `REPO-DEPENDABOT-UPDATES` | GitHub secret scanning, push protection (blocks a push that contains a secret) or Dependabot security updates not enabled | Medium |
| `REPO-NO-CODEOWNERS` | No CODEOWNERS file, so nobody is forced to review `.security/` changes | Medium |
| `REPO-NO-SECURITY-POLICY`, `REPO-NO-DEPENDENCY-UPDATES` | No `SECURITY.md` (how to report a vulnerability), no `dependabot.yml` or `renovate.json` | Low |
| `REPO-WORKFLOW-WRITE` | Workflows get read/write token permissions by default | Medium |
| `REPO-ACTIONS-APPROVE` | Workflows may approve pull requests | Low |
| `REPO-ADMIN-BYPASS` | Administrators can bypass branch protection | Low |
| `REPO-UNCHECKED` | Some settings need admin rights to read: reported as "could not check" | Info |

## How it protects
* Scans only matter if they can **stop** a merge. The settings check tells you when the security scan is not a required check or the default branch is unprotected.
* Warden's own workflow templates are least-privilege (read-only token, no persisted credentials) and every third-party Action is **pinned to a commit**.
* **Auto-update, with a trade-off you should know.** Repos created with `warden init` follow the moving tag `v1`, so a new scan or fix reaches every repo on its next run. Whoever can move `v1` can therefore run code in every repo's CI. Protect `v*` tags in the Warden repository (GitHub: Settings, Rules, tag ruleset) and use `warden pin` for repos that must change only on request. See [../updates-and-versions.md](../updates-and-versions.md).
* Reports from fork pull requests get no comment (the token is read-only there), which keeps untrusted code away from write tokens.

## When it fires
Pin Actions to a full commit SHA (Dependabot can update them), give each workflow the smallest `permissions:` it needs, never put `${{ github.event.* }}` text straight into a `run:` line (pass it through `env:`), and enable branch protection with a required security check.

## Limits
* Only GitHub is covered by the settings check; other CI systems (Jenkins, Azure DevOps) have templates but no equivalent settings audit.
* The check reads configuration. It does not see who actually has access, or whether a stolen token exists.
* Signing and Scorecard are shipped as templates only.
* Status: **Verified** for zizmor and the settings check. Dependabot/Renovate is **verified (partial)** (files validated; GitHub's service was not run here). Signing, provenance and Scorecard are **templates**, never run.
