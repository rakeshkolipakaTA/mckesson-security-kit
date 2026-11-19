# Threat-model template (STRIDE + AI-agent questions)

A threat model is a one-hour structured conversation: *what are we building, what can go wrong, what will we do about it?* Fill this in during design, keep it next to the code (`docs/threat-model.md`), and revisit it when the design changes.

**Feature / system:** ____  **Date:** ____  **Participants (include a security champion):** ____

## 1. What are we building?
- One-paragraph description: ____
- Diagram (boxes and arrows are enough): users, services, data stores, third parties, and **trust boundaries** (where data or control crosses from one trust level to another).

| Asset (what an attacker wants) | Where it lives | Sensitivity (public / internal / confidential / regulated) |
|---|---|---|
| | | |

| Entry point (how data or commands get in) | Who can reach it | Authenticated? |
|---|---|---|
| | | |

## 2. What can go wrong? (STRIDE, per element and per trust boundary)
| Threat | Question to ask | Example finding | Mitigation / owner / ticket |
|---|---|---|---|
| **S**poofing | Can someone pretend to be a user, service or agent? | forged token, missing service-to-service auth | |
| **T**ampering | Can data or code be changed in transit, at rest, or in the build? | unsigned artefact, writable config | |
| **R**epudiation | Could someone deny an action, or could we not prove it? | no audit log, shared accounts | |
| **I**nformation disclosure | Where can data leak (logs, errors, prompts, backups, third parties)? | PII in logs, verbose errors | |
| **D**enial of service | Can one caller exhaust CPU, memory, tokens, money? | unbounded input, no rate limit | |
| **E**levation of privilege | Can a low-privilege caller act as a higher one? | missing ownership check, over-broad role | |

## 3. Extra questions when the system contains an AI agent
| Question | Answer / mitigation |
|---|---|
| Whose identity does the agent act under? Is it a separate, least-privilege identity or the user's token? | |
| List every **tool** the agent can call. Which are destructive, irreversible, or reach outside (email, payments, shell, network)? Which need human approval? | |
| What **untrusted text** enters the context (documents, web pages, emails, tool results)? Could instructions hidden in it change the agent's behaviour (indirect prompt injection)? | |
| Can the agent be made to reveal its system prompt, credentials, or another user's data? | |
| Where can the agent send data (allowed hosts)? Could a tool be pointed at an internal address (SSRF) or the cloud metadata service? | |
| Which model / endpoint / region is used, is it approved, and what data may be sent to it? | |
| What stops a runaway loop (step, time, token and cost budgets)? | |
| What does the audit log record, who can read or change it, and can an action be traced to a human and an agent? | |
| How would we **notice** the agent has been manipulated, and how do we switch it off? | |
| What happens when a guardrail fails or times out: allow or block? (Must fail closed.) | |

## 4. What are we going to do about it?
| # | Threat | Decision (mitigate / accept / transfer / avoid) | Owner | Due | Ticket |
|---|---|---|---|---|---|
| | | | | | |

Accepted risks need an approver and an expiry date, the same as scanner exceptions (see the [policy](vulnerability-management-policy.md)).

## 5. Did we do a good job?
- [ ] Every trust boundary on the diagram was discussed.
- [ ] Every high-severity row has an owner and a ticket.
- [ ] Tests or scanner rules exist for the mitigations where possible (for example a red-team probe for the injection case).
- [ ] Next review date: ____ (or "when the design changes")
