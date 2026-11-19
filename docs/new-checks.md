# The newer checks: what they do, when they run, and their limits

All of them follow the same rules as the older tools: they are switched with `SEC_<TOOL>=auto|on|off` ([configuration.md](configuration.md)), their findings go through the same gate, baseline, exceptions and reports, and a tool that fails is a tool error (never a silent pass).

| Check | Runs when | One-line answer | Needs |
|---|---|---|---|
| [Secrets in git history](#secrets-in-git-history) | git checkout | Was a secret ever committed, even if deleted since? | full history |
| [SBOM and licences](#sbom-and-licences) | always | What exactly ships, and under which licences? | nothing |
| [GitHub Actions security](#github-actions-security) | workflows exist | Can a pull request take over our CI? | nothing |
| [Kubernetes posture](#kubernetes-posture-and-cis-benchmark) | manifests exist | Are the manifests hardened (NSA framework)? | network (downloads rules) |
| [CIS Docker benchmark](#kubernetes-posture-and-cis-benchmark) | image scan | Does the image follow the CIS Docker benchmark? | `SEC_IMAGE` |
| [IaC](#infrastructure-as-code) | Terraform / CloudFormation exist | Public buckets, open security groups, unencrypted databases? | nothing (part of Trivy) |
| [Repository settings](#repository-settings) | GitHub repo + token | Is branch protection / secret scanning really on? | `GITHUB_TOKEN` |
| [Authenticated DAST](#authenticated-dast-and-api-fuzzing) | `SEC_ZAP_URL` | Can ZAP see what is behind the login? | `ZAP_AUTH_TOKEN` |
| [API fuzzing](#authenticated-dast-and-api-fuzzing) | `SEC_API_SPEC` | Which operations crash or misbehave on crafted input? | OpenAPI URL (QA) |
| [Exposure scan](#exposure-scan) | `SEC_EXPOSURE_TARGETS` | What can the outside reach: TLS, headers, `.env`, metrics, open ports? | hosts you own |
| [Compliance view](#compliance-view-crosswalk) | every scan | Which architectural control does each finding evidence? | nothing |
| [Remediation deadlines](#remediation-deadlines-sla) | a dated baseline exists | Which accepted findings are past their deadline? | `secscan baseline` |

## Secrets in git history
A secret deleted in a later commit is still in the history and still valid until rotated. `gitleaks git` scans the newest 3000 commits (`SEC_HISTORY_COMMITS` to change). Results are grouped per file and rule ("2 commits, first abc1234 on 2024-01-02"); secrets still present in the working tree are reported once, by the normal gitleaks scan. **Fix = rotate the credential**; rewriting history is optional.
Limits: a shallow clone (CI default) hides older commits: the report says so under *Reduced coverage*; use `actions/checkout` with `fetch-depth: 0`. A git worktree or an exported folder has no history to scan.

## SBOM and licences
Trivy writes a CycloneDX bill of materials (`sbom.cdx.json` next to the report). Licences come from Trivy's scan: **deny list** (AGPL, SSPL, BUSL, non-commercial) is HIGH, **review list** (GPL, LGPL, MPL, EPL ...) is MEDIUM, unknown is LOW, permissive licences are not reported. The lists are in `configs/policies/policy.json` (`license_policy`): legal should own them.
Limits: licences are only known where the manifest or the installed package carries them (lockfiles with a `license` field, installed packages in an image). A plain `requirements.txt` has none, so scan the built image (`SEC_IMAGE`) for full licence coverage.

## GitHub Actions security
zizmor (offline) reads `.github/workflows`: **unpinned actions** (a moved tag can run attacker code), **script injection** through `${{ github.event... }}` in `run:`, dangerous triggers (`pull_request_target`), excessive token permissions, credential persistence. Fix unpinned actions by pinning to the full commit SHA (keep the tag in a comment). Dependabot or Renovate can then keep the SHAs current.

## Kubernetes posture and CIS benchmark
kubescape (NSA hardening framework) reads plain Kubernetes manifests and Trivy's built-in rules read them too (plus Helm); both are shown, kubescape one level lower in severity because Trivy's checks stay authoritative. Helm templates containing `{{ }}` are skipped by kubescape (Trivy covers them). The **CIS Docker benchmark** runs against a scanned image and reports failed controls as advisory (MEDIUM at most).
Limits: this checks files and images, not a live cluster. For cluster posture run `kubescape scan` or `kube-bench` from inside the cluster (see [cloud-and-cluster.md](cloud-and-cluster.md)). kubescape downloads its control definitions: allow github.com.

## Infrastructure as code
Trivy already scans Terraform and CloudFormation; `examples/iac-sample` proves it (public S3 ACL, SSH open to 0.0.0.0/0, public unencrypted database). Findings appear under *IaC/Config*.

## Repository settings
Reads settings through the GitHub API: branch protection or rulesets (reviews, required status checks, force pushes, admin bypass), secret scanning and push protection, Dependabot alerts and security updates, workflow token permissions, CODEOWNERS, SECURITY.md, dependency-update config. Settings your token cannot read are listed once as "could not check" (they need admin rights). In GitHub Actions the built-in `GITHUB_TOKEN` can read some of these; a fine-grained read-only token gives the full picture.
Why it matters: a required security check only blocks anything when branch protection requires it.

## Authenticated DAST and API fuzzing
**ZAP with a login:** set the CI secret `ZAP_AUTH_TOKEN` (sent as `Authorization: Bearer ...`) or `ZAP_AUTH_HEADER="Name: value"`. It reaches the container through the environment, never the command line, and is added to every ZAP request. Verified against a server that returns 401 without the header.
**API fuzzing:** Schemathesis reads your OpenAPI spec and sends crafted, schema-aware requests to every operation (bodies included), with `API_TEST_TOKEN` as bearer token if set. Findings: server errors (MEDIUM, often a sign of unhandled input or injection), operations that ignore authentication (HIGH), schema violations (LOW). Each finding carries a `curl` line to reproduce it (auth headers redacted).
**Only run both against QA/UAT you own**: they send real attack-style traffic and can create or modify data.
Limits: fuzzing finds crashes and contract violations, not business-logic flaws; a spec that is wrong or missing hides operations.

## Exposure scan
`scripts/exposure.py` checks hosts you own, from where the scan runs: plain HTTP, certificate problems (expired, self-signed, wrong host, trust), obsolete TLS, missing HSTS / CSP / nosniff / clickjacking protection, CORS that lets any site read authenticated responses, server version banners, well-known sensitive paths (`/.git`, `/.env`, actuator, `/metrics`, pprof, OTLP endpoints, API docs, backups) and risky ports (databases, Docker API, OTLP 4317/4318, Prometheus ...). Catch-all single-page apps do not produce false path findings. Only GET requests and TCP connects are made.
Run it from an outside network to see what an attacker sees; run it from the CI network to see what is reachable internally.

## Compliance view (crosswalk)
Every finding is tagged with the architectural control(s) it evidences (P1-P8 of the agentic security framework) using `configs/compliance/crosswalk.json`, which also holds each control's mapping to NIST AI RMF, NIST CSF 2.0, ISO/IEC 42001, OWASP LLM Top 10, EU AI Act and supervisory themes. The report gets a *Compliance view* table and `crosswalk.csv` lists every finding with its controls. It is a heuristic mapping that shows what each finding is evidence for, not a compliance verdict.

## Remediation deadlines (SLA)
`secscan baseline` now stores the date each finding was first accepted. A baselined finding older than the SLA for its severity (`sla_days` in the policy: Critical 3, High 14, Medium 60, Low 90) **blocks again** if its severity is listed in the gate's `block_overdue` (PR gate: Critical and High; release gate: both), and the report lists them under *Past their remediation deadline*. Re-running `secscan baseline` keeps the original date of findings that are still open. An old-format baseline (no dates) never ages: re-create it once. The dashboard additionally tracks first-seen per repo (see [dashboard.md](dashboard.md)).
