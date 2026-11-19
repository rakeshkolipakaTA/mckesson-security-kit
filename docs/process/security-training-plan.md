# Security-training plan

Goal: everyone who ships software knows the few habits that prevent most incidents, and each role goes one level deeper. Keep sessions short, use your own code and the scanner reports as examples, and track attendance.

## Who needs what
| Audience | Content | Format | When |
|---|---|---|---|
| **Everyone who commits code** | secrets never in code or prompts; reading a scanner report; fixing the common findings; phishing and MFA basics; how to report a concern | 60 min + this kit's [fixing-findings](../fixing-findings.md) and [reading-reports](../reading-reports.md) | onboarding (first month), then yearly |
| **Developers** | injection, authentication and authorisation (ownership checks), unsafe deserialisation, dependency hygiene, secure use of AI APIs | hands-on lab on the intentionally vulnerable examples (`examples/`) | onboarding, then yearly |
| **AI-agent builders** | prompt injection (direct and indirect), tool permissions and approval gates, egress control, fail-closed guardrails, output handling, audit logging; how to run `warden redteam` | workshop using `examples/agent-sample` vs the hardened sample | before building the first agent, then yearly |
| **Reviewers and team leads** | the [code-review checklist](secure-code-review-checklist.md), SLAs and exceptions, running a [threat model](threat-model-template.md) | 90 min working session | when taking the role, then yearly |
| **Security champions** | the [champions guide](security-champions-guide.md), triage, incident basics | monthly 45 min community call | ongoing |
| **On-call / operations** | the [incident runbook](incident-response-runbook.md), runtime alerts, rotating a secret fast | tabletop exercise | twice a year |
| **Managers and executives** | risk reading of the dashboard, SLA compliance, accepting risk, incident decisions | 30 min briefing | yearly |

## A one-year plan
| Quarter | Activity |
|---|---|
| Q1 | onboarding module for new joiners; kick-off of the champions programme; baseline the dashboard |
| Q2 | developer lab (injection and authorisation using the example apps); first access review ([checklist](access-review-checklist.md)) |
| Q3 | AI-agent workshop and a red-team exercise against a QA agent; tabletop incident exercise |
| Q4 | refresh for everyone; review the year's incidents and findings; update this plan |

## Make it stick
- **Learn from real findings:** every quarter pick the three most common finding types from the dashboard and teach those.
- **Capture the flag / lab days:** attack the vulnerable examples; a developer who has exploited an SQL injection rarely writes one.
- **Short feedback loops:** a pre-push hook and a scanner comment on the pull request teach more than a yearly slide deck.
- **Measure:** completion rate per role, time to fix Critical/High versus the SLA, number of secrets caught pre-commit, repeat findings per team.
- **Keep it blameless:** people report mistakes only if reporting is safe.

## Checklist for the training owner
- [ ] Each role above has a named owner and a date.
- [ ] Materials are in the repo or wiki and reviewed yearly.
- [ ] Attendance recorded; new joiners enrolled automatically.
- [ ] Contractors and temporary staff included.
- [ ] Results reviewed with the security lead each quarter.
