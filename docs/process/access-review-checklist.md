# Access-review checklist (quarterly)

Access piles up: people change teams, tokens outlive projects, agents get "temporary" permissions that stay. Once a quarter, the team lead and a security contact check **who and what can do what**, and remove what is not needed. Record the date, the reviewer, and the changes made.

**Review date:** ____  **Reviewer(s):** ____  **Next review:** ____

## 1. People
| Check | Evidence | Done |
|---|---|---|
| Everyone with access to the repos, CI, cloud accounts and dashboards is still on the team and still needs it | export of members / roles | [ ] |
| Leavers and movers were removed the day they left (compare with the HR / team list) | list of removals | [ ] |
| Admin and "owner" roles are held by the fewest people possible (aim for two to four) | admin list | [ ] |
| Everyone uses multi-factor authentication; no shared accounts | identity-provider report | [ ] |
| External collaborators and contractors have an end date and are reviewed | list with expiry | [ ] |

## 2. Repositories and CI
| Check | Done |
|---|---|
| The default branch is protected: pull request required, status checks (including the security scan) required, no force-push | [ ] |
| `.security/` and `.github/workflows/` are covered by CODEOWNERS with a security reviewer | [ ] |
| CI secrets are scoped to the repo / environment that needs them; unused secrets deleted | [ ] |
| CI tokens have the minimum permissions (workflow `permissions:` blocks), deploy keys are read-only unless they must write | [ ] |
| Self-hosted runners are patched, isolated, and not shared with untrusted repos | [ ] |
| Third-party actions and integrations are on the approved list and pinned | [ ] |
| Active exceptions and waivers in `.security/exceptions.json` are still needed, approved and unexpired | [ ] |

## 3. Cloud, clusters and data
| Check | Done |
|---|---|
| Roles follow least privilege; no wildcard (`*`) permissions without a written reason | [ ] |
| Service accounts and access keys older than the rotation limit were rotated or removed | [ ] |
| Kubernetes RBAC: no broad `cluster-admin` bindings; ClusterRoles reviewed (the scanner flags over-broad ones) | [ ] |
| Databases, buckets and queues are private; public exposure is intentional and documented | [ ] |
| Backups and logs are readable only by those who need them | [ ] |

## 4. AI agents and their tools
| Check | Done |
|---|---|
| Each agent has its own identity (not a person's token) and a documented owner | [ ] |
| The list of tools per agent is current; unused tools are removed; destructive or outbound tools still require approval | [ ] |
| Credentials the agent can reach are short-lived and scoped (audience and scopes) | [ ] |
| Model / endpoint registry (`approved-models.json`) is reviewed: only approved, version-pinned models; retired ones removed | [ ] |
| MCP servers and plug-ins are on the approved list and pinned | [ ] |
| The agent audit log is still shipped off-host and its chain verifies | [ ] |
| The "off switch" was tested | [ ] |

## 5. Tool access (security tooling itself)
| Check | Done |
|---|---|
| Dashboard, SonarQube and ticketing logins reviewed; default passwords changed; shared login rotated | [ ] |
| `SECSCAN_DASHBOARD_TOKEN`, `SONAR_TOKEN` and ticketing tokens rotated on schedule | [ ] |

## Outcome
| Finding | Action | Owner | Done by |
|---|---|---|---|
| | | | |
