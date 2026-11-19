# Incident-response runbook

For three situations this framework makes more likely to be noticed: a **compromised AI agent**, a **leaked secret**, and a **compromised dependency or build**. Keep this where on-call can reach it without the systems that may be down. Rehearse it twice a year with a tabletop exercise.

**Rules for every incident:** write down what you do and when (a shared timeline); preserve evidence before you clean up; use a separate channel from the affected system; one person leads, one person scribes; tell your security contact early. Whether and what to tell customers or regulators is a decision for security, legal and management, not for the responder alone.

## Roles
| Role | Does |
|---|---|
| Incident lead | decides, assigns, keeps the timeline moving |
| Scribe | records every action and time |
| Technical responders | contain, investigate, fix |
| Security contact | classifies severity, links to legal / privacy / management |
| Communications | internal and external messages (only on the lead's approval) |

## Severity
| Level | Meaning | Response |
|---|---|---|
| SEV1 | confirmed data exposure, active attacker, production agent taking harmful actions | drop everything now; security + management informed immediately |
| SEV2 | likely compromise or a valid leaked production credential | same day, contain within hours |
| SEV3 | suspicious, no evidence of impact | next working day |

## Phases (all scenarios)
1. **Detect and triage** (alert, scanner finding, report): what happened, which systems, since when, SEV level.
2. **Contain** (stop the damage, keep the evidence).
3. **Eradicate and recover** (remove the cause, restore trusted state).
4. **Learn**: blameless review within 5 working days; fixes tracked as tickets; update the threat model, scanner rules and this runbook.

## A. Compromised AI agent (prompt injection, tool abuse, unexpected actions)
Signals: runtime alert (shell in an agent container, metadata-service connection, audit-chain failure), a red-team probe failing in production, users reporting odd behaviour, unusual tool use or spend.

| Step | Action | Done |
|---|---|---|
| Contain | switch the agent off or put it in read-only mode (feature flag / scale to zero); revoke its credentials and any tokens it holds; block its egress | [ ] |
| Preserve | snapshot the pod/VM; copy the audit log off the host and run `verify_chain` on the copy; keep conversation, tool-call and model-request logs | [ ] |
| Scope | list every tool call and data access in the window (audit log); which users, tenants, records; did it call out to external hosts? | [ ] |
| Find the vector | injected document or page? stolen user token? vulnerable dependency? over-broad tool? | [ ] |
| Eradicate | remove the poisoned content from the knowledge base; fix the tool or guardrail; rotate every secret the agent could read | [ ] |
| Recover | redeploy a clean image; re-enable with tighter permissions and approval gates; add a probe or rule that reproduces the attack | [ ] |
| Notify | affected owners / users per your policy (security and legal decide) | [ ] |

## B. Leaked secret (key, token, password in a repo, log, prompt or ticket)
Assume it is **already abused**: deleting the commit does not help, because history and forks keep it.

| Step | Action | Done |
|---|---|---|
| Revoke / rotate **first** | disable the credential at the provider and issue a new one; update secret stores and CI | [ ] |
| Scope | what could the credential do? check the provider's access logs from the day it was exposed; look for new users, keys, resources, unusual cost | [ ] |
| Clean up | remove it from the code and (if needed) rewrite history; purge it from logs, chat, tickets, build artifacts and caches; add it to the scanner baseline only after rotation | [ ] |
| Prevent | add a gitleaks / pre-commit check if one was missing; move the secret to a vault; shorten token lifetimes | [ ] |
| Review | how did it get there? update training and the code-review checklist | [ ] |

## C. Compromised dependency, image or build
Signals: a CVE or advisory for something you ship (especially "malicious package"), a scanner finding on a model or package, unexpected CI behaviour, an image signature that does not verify.

| Step | Action | Done |
|---|---|---|
| Identify | which repos, images and environments contain it? use the SBOM or `secscan` reports; search lockfiles | [ ] |
| Contain | stop deploying; pin or remove the dependency; roll back to the last known-good, signed image; block the package or registry source | [ ] |
| Assume secrets in CI were exposed | rotate every secret the build could read; review recent CI runs and workflow changes | [ ] |
| Verify | rebuild from clean runners; verify signatures and provenance (`cosign verify`, `gh attestation verify`); rescan the image | [ ] |
| Recover | redeploy; monitor for the indicators; document the affected window | [ ] |
| Prevent | pin versions and actions to digests, review the update PRs, restrict who can change workflows | [ ] |

## After every incident
- [ ] Timeline complete and stored.
- [ ] Blameless review held; root cause and contributing factors written.
- [ ] Each fix has an owner, a ticket and a date.
- [ ] Detection improved (a scanner rule, a runtime rule, a probe, a test).
- [ ] This runbook and the [threat model](threat-model-template.md) updated.
