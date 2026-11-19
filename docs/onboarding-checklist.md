# Team onboarding checklist (plan section 11)

Copy this into your team's tracker. A normal developer can complete every item; items marked (platform) need the platform/security team once.

## Setup
- [ ] Repository and owner identified: ______________  Security contact: ______________
- [ ] Docker available on dev machines and CI agents (`warden doctor` is green)
- [ ] `warden init` run; `.security/` committed
- [ ] CI pipeline added (GitHub Actions / Jenkins / Azure DevOps) and a run is green
- [ ] First report reviewed with the team; findings triaged (fix / baseline / exception)

## Optional tools
- [ ] (platform) SonarQube project and `SONAR_TOKEN` CI secret; `SEC_SONAR=1`
- [ ] (platform) NVD API key + `depcheck-update.sh` schedule for Java repos; `SEC_DEPCHECK=1`
- [ ] QA URL identified and DAST (ZAP) approved by the app owner; DAST job added
- [ ] Docker image gate added to the release pipeline

## AI agents (only if your repo builds an agent / LLM app)
- [ ] `agent` profile shows in the scan output; the **Agent inventory** in the report is correct (models, endpoints, tools, MCP servers)
- [ ] (platform) Models and endpoints you use are in the central registry (`configs/agentic/approved-models.json`)
- [ ] Tools run through a default-deny policy; destructive tools need human approval (`agentsec.PEP`)
- [ ] Guardrails fail closed; no secrets in prompts; prompts/logs masked
- [ ] `.security/redteam.json` written; two QA test users created; red-team job added for QA (never prod); owner approved
- [ ] Results reviewed, including the "known limit" probes (paraphrased injection)

## Rollout
- [ ] Report-only for 2-4 weeks (`SEC_PRESET=starter`); false positives tuned (allowlist/exceptions)
- [ ] Baseline recorded for legacy findings (`warden baseline`)
- [ ] Exceptions have reason, approver, expiry
- [ ] `SEC_PRESET=standard` set; **security-scan** is a required check on `main`
- [ ] `.security/` protected by CODEOWNERS
- [ ] Release pipeline uses `gate --gate release`

## Ongoing
- [ ] Team knows the remediation targets (proposed: Critical 3 days, High 14, Medium 60, Low 90; to be agreed with McKesson security)
- [ ] Kit upgraded when the platform team announces a new version (`warden init <repo>` again)
- [ ] Expired exceptions reviewed monthly
