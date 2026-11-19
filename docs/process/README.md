# Security process kit

Tools find known patterns. People find design flaws, decide what is acceptable, and handle incidents. These short templates cover the human side that a scanner cannot. Copy a template into your own repo or wiki and fill it in; none of them needs a tool.

| Document | Use it when | Who | How often |
|---|---|---|---|
| [Threat-model template](threat-model-template.md) | designing a feature, a new integration, or an AI agent with tools | developers + security champion | per design; revisit on big changes |
| [Secure code-review checklist](secure-code-review-checklist.md) | reviewing a pull request that touches auth, data, tools, or dependencies | reviewers | every relevant PR |
| [Vulnerability-management policy](vulnerability-management-policy.md) | deciding how fast a finding must be fixed and who may accept a risk | team leads, security | reference; review yearly |
| [Incident-response runbook](incident-response-runbook.md) | an agent is compromised, a secret leaked, or a dependency / build is compromised | on-call, security, team lead | rehearse twice a year |
| [Access-review checklist](access-review-checklist.md) | repo, CI, cloud, agent and tool permissions | team lead + security | quarterly |
| [Security-training plan](security-training-plan.md) | onboarding and yearly refreshers | everyone, by role | onboarding + yearly |
| [Penetration-test scope and rules of engagement](pentest-scope-template.md) | commissioning a manual test of an app or agent | team lead, security, tester | before major releases; yearly |
| [Security-champions guide](security-champions-guide.md) | setting up one security contact per team | security lead, champions | ongoing |

How they connect to the tooling: the scanners in this kit produce findings and the [dashboard](../dashboard.md) tracks their age against the SLAs in the [policy](vulnerability-management-policy.md); [`warden tickets`](../dashboard.md#tickets) gives each finding an owner; [runtime detection](../runtime-detection.md) feeds the [runbook](incident-response-runbook.md).

These are starting points, not legal or compliance advice. Have your security and legal teams adapt them to your organisation and any regulation that applies.
