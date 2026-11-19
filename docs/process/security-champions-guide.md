# Security-champions guide

A security champion is a developer on each team who is the first point of contact for security: not a gatekeeper, and not a replacement for the security team. One champion per team (plus a deputy) is enough to turn "someone should look at this" into "a named person did".

## What a champion does (about 10% of their time)
| Area | Typical activities |
|---|---|
| **Triage** | looks at the team's dashboard weekly; sorts new Critical/High findings into *fix now*, *false positive* (with a justification), *needs help*; makes sure each has a ticket, an owner and a date |
| **Review** | second pair of eyes on pull requests that touch authentication, data, AI-agent tools or dependencies (use the [checklist](secure-code-review-checklist.md)) |
| **Design** | runs a short [threat model](threat-model-template.md) for new features and agents |
| **Exceptions** | prepares exception requests (reason, expiry) for the team lead and security to approve; reminds the team before they expire |
| **Teach** | shares one lesson per sprint from a real finding; helps new joiners with `secscan` |
| **Escalate** | brings anything unclear, a possible leak or an incident to the security contact straight away ([runbook](incident-response-runbook.md)) |
| **Improve the kit** | proposes new scanner rules, a better baseline, a probe for an attack the team met |

## What a champion does not do
Approve their own exceptions, sit on a finding to protect a deadline, or carry the whole team's security alone. Accountability for fixing stays with the team lead.

## Choosing and starting champions
1. Pick someone who is curious and respected by peers, not necessarily the most senior; volunteers beat nominees.
2. Give them time in the sprint (agree it with the manager) and recognition (goals, performance review, title).
3. Onboard with: the [training plan](security-training-plan.md) (developer and champion tracks), a walk through this kit, and an intro to the security team.
4. Give access: the dashboard, the scanner reports, and a channel to the security team.

## Running the programme
| Cadence | Activity |
|---|---|
| Weekly | champion triage of the team dashboard (15 to 30 min) |
| Monthly | champions' call (45 min): top findings, a short talk, a new threat; share what worked |
| Quarterly | [access review](access-review-checklist.md); review exceptions and waivers; SLA numbers per team |
| Twice a year | tabletop incident exercise; red-team a QA agent |
| Yearly | refresh training; rotate or confirm champions; review this guide |

## Measures (use them to help, not to rank teams)
- Time to fix Critical/High versus the SLA ([policy](vulnerability-management-policy.md)); number overdue.
- Findings by type over time; repeat findings per team.
- Share of repos reporting to the dashboard; share with required tools running.
- Exceptions open, and how many expired unrenewed.
- Threat models done for new features and agents.

## Escalation ladder
Team lead (fix and prioritise) > security contact (advice, risk decision) > security lead and management (risk acceptance above the team's authority, incidents).
