#!/usr/bin/env python3
"""Generate docs/warden-pov-full.html: the point-of-view deck, written as a plan (what we will put in place), in the layered style of the
Agentic Security deck (pillars, domains, threats, controls, crosswalk, then development / deployment / runtime). Integrations come first.
Counts, control names and fix deadlines come from tools/coverage_data.py, configs/compliance/crosswalk.json and configs/policies/policy.json,
so the deck cannot drift from the framework. No status tags: this is a proposal, not a progress report.
   python3 tools/build_pov.py       (standard library only)
Run tools/build_coverage.py first when coverage_data.py changed. The look is taken from docs/warden-pov-presentation.html (same style block)."""
import html
import json
import os
import re
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import coverage_data as D  # noqa: E402
import toolplan  # noqa: E402

DOCS = os.path.join(HERE, "..", "docs")
CROSS = json.load(open(os.path.join(HERE, "..", "configs", "compliance", "crosswalk.json")))["controls"]
OLD = open(os.path.join(DOCS, "warden-pov-presentation.html")).read()
STYLE = re.search(r"<style>(.*?)</style>", OLD, re.S).group(1)
SCRIPT = re.search(r"<script>(.*?)</script>", OLD, re.S).group(1)
NAV = re.search(r'(<div class="nav".*?</div>\n)\n?<script>', OLD, re.S).group(1)
EXTRA_CSS = """
.pill{display:inline-block;font-size:12px;font-weight:700;color:var(--accent);background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:1px 8px;margin-right:8px}
.small{font-size:13px;color:var(--muted)} .tight td,.tight th{padding:6px 10px;font-size:13.5px}
.cols td.what{color:var(--muted)} .num{font-size:34px;font-weight:800;line-height:1;letter-spacing:-.02em}
h2.sm{font-size:28px} .mt{margin-top:18px} .cardh{display:flex;justify-content:space-between;gap:8px;align-items:flex-start;margin-bottom:6px}
.cardh h3{margin:0}
"""

e = html.escape
TAG = {"Verified": "t-ok", "Covered": "t-ok", "Verified (partial)": "t-part", "Partial": "t-part", "Wired, not run": "t-part", "Template": "t-plan",
       "Reference library": "t-man", "Documented": "t-man", "Not covered": "t-gap", "Not enforced": "t-gap", "Done": "t-ok", "Partly": "t-part", "Planned": "t-plan"}


def tag(s):
    return f'<span class="tag {TAG.get(s, "t-man")}">{e(s)}</span>'


def table(head, rows, cls="tight", raw_cols=()):
    h = "".join(f"<th>{e(x)}</th>" for x in head)
    b = ""
    for r in rows:
        b += "<tr>" + "".join(f"<td>{c if i in raw_cols else e(str(c))}</td>" for i, c in enumerate(r)) + "</tr>"
    return f'<table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table>'


def card(title, body, status=None, extra=""):
    t = tag(status) if status else ""
    return f'<div class="card"><div class="cardh"><h3>{e(title)}</h3>{t}</div>{body}{extra}</div>'


def ul(items):
    return "<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>"


def slide(kick, title, body, sub=""):
    s = f'<section class="slide"><div class="kick">{e(kick)}</div><h2>{e(title)}</h2>'
    if sub:
        s += f'<p class="sub">{e(sub)}</p>'
    return s + body + "</section>\n"


def flow(steps):
    return '<div class="flow">' + "".join(f'<div class="step"><b>{e(a)}</b><span>{e(b)}</span></div>' for a, b in steps) + "</div>"


# ---------------------------------------------------------------- numbers (from the data)
N_CATS = len({r[0] for r in D.INVENTORY})
N_TOOLS = len(toolplan.ORDER)
POLICY = json.load(open(os.path.join(HERE, "..", "configs", "policies", "policy.json")))
SLA = POLICY["sla_days"]
CTL = [r for r in D.PRESENTATION if r[0] == "Architectural controls"]


def prow(section):
    return [r for r in D.PRESENTATION if r[0] == section]


slides = []

# 1 title
slides.append(f"""<section class="slide"><div class="kick">Enterprise security for applications and AI agents</div>
<h1>Warden: One Module for Complete DevSecOps Security</h1>
<p class="sub">What we will put in place: one framework that finds weaknesses in code, libraries, containers, infrastructure files, running systems and AI agents,
decides what blocks a release, and shows the result where people already work.</p>
<div class="grid g4 mt">
<div class="card"><div class="num">8</div><p>security domains, from identity to governance</p></div>
<div class="card"><div class="num">{N_CATS}</div><p>categories of checks</p></div>
<div class="card"><div class="num">5</div><p>integrations: GitHub, SonarQube, DefectDojo, Dependency-Track, Wiz</p></div>
<div class="card"><div class="num">4</div><p>stages: develop, pull request, deploy to QA, runtime</p></div>
</div></section>
""")

# 2 approach / lifecycle
slides.append(slide("Our approach", "Security at every stage, from the first commit to production",
                    flow([("Develop", "Secrets and code checks run on the developer machine before each push."),
                          ("Pull request", "Secrets, code, libraries, Dockerfiles, Kubernetes and Terraform files, pipeline files and AI agent checks. A gate decides."),
                          ("Build", "The image is scanned and gated before it is pushed. A bill of materials (SBOM) is produced."),
                          ("Deploy to QA", "Running-app tests: dynamic scanning, API fuzzing, exposure checks, AI red-team probes."),
                          ("Production", "Runtime controls for agents, detection rules, and the SBOM watched for new vulnerabilities.")]) +
                    '<div class="callout mt"><b>Principle.</b> Tools find known patterns; people find design flaws and decide what is acceptable. We will automate the first, '
                    'and give the second owners, deadlines and a process.</div>'))

# 3-6 integrations (first quarter of the deck)
slides.append(slide("Integrations", "How the results will reach each team",
                    table(["Integration", "What it will be used for", "Who will use it", "How it will connect"], [
                        ("GitHub (built in)", "Results on every pull request: run summary, markers on the changed lines, one updated comment", "Developers", "No server needed"),
                        ("SonarQube", "Code quality and code-security review with a quality gate; the view the client asked for", "Developers and the client", "One server address and one CI secret; switched on per repository"),
                        ("DefectDojo", "One register of all findings across all repositories: owners, deadlines, accepted risks, tickets, reports", "Security team and leads", "One address and one secret; scans of the main branch only"),
                        ("Dependency-Track", "Keeps watching the libraries of every released application and alerts when a new vulnerability is published", "Security team", "One address and one key that can only upload SBOMs"),
                        ("Wiz", "Wiz scans in the pipelines, and Wiz scanning of the running Azure cloud with attack paths", "Security and cloud teams", "Licence, a service account, and an Azure connector")]) +
                    '<p class="small mt">Each integration is optional and switched on per repository. A problem publishing to any of them will be a warning, never a failed build.</p>',
                    "Developers keep working in GitHub. The other tools serve people who need a wider view."))

slides.append(slide("Integrations · for developers", "GitHub and SonarQube: what a developer will see and do",
                    '<div class="grid g2">' +
                    card("What a developer will see", ul(["A summary on each pipeline run", "Markers on the risky lines in the pull request", "One comment on the pull request, updated on every push",
                                                          "In SonarQube: code smells, hot-spots and the quality gate for the project"])) +
                    card("What a developer will do", ul(["Run one command to add scanning to a repository", "Put the SonarQube address in one settings file (not secret)",
                                                         "Make sure the CI secret exists; one organisation-level secret covers every repository", "Run a scan on the main branch and check the last lines of the log"])) +
                    "</div>" + '<div class="callout mt"><b>Note.</b> SonarQube Community has no branch or pull-request analysis; it reports the main branch. Those features need a paid edition.</div>'))

slides.append(slide("Integrations · for the security team", "DefectDojo and Dependency-Track: two views no single scan can give",
                    '<div class="grid g2">' +
                    card("DefectDojo: one register", ul(["Every scan on the main branch will be sent as an update, not a new import: new findings open, fixed ones close, no duplicates",
                                                         "Findings approved as exceptions will appear as accepted risk", "Owners, fix deadlines, tickets and management reports across all repositories",
                                                         "Deliberate: one token with wide rights, kept in a restricted secret and rotated"])) +
                    card("Dependency-Track: watch after release", ul(["The SBOM of every main-branch scan will be uploaded", "It keeps re-checking it against OSV, GitHub advisories and NVD, even when nobody scans that week",
                                                                      "Alerts when a new vulnerability affects an application already released", "Answers 'which of our applications use this library?' in seconds",
                                                                      "The upload key can do nothing except upload SBOMs and read results"])) + "</div>"))

slides.append(slide("Integrations · Wiz and the Azure cloud", "Two jobs, two places: scan what is built, scan what is running",
                    '<div class="grid g2">' +
                    card("In the pipelines (GitHub Actions, Azure DevOps)", ul(["The Wiz command-line scanner will check code and libraries, Terraform, Kubernetes and ARM files, and built images",
                                                                              "Without a licence the step is skipped and passes", "Report-only first; blocking builds on a failed Wiz policy is switched on later",
                                                                              "Results in the Wiz portal, and in DefectDojo next to the other findings"])) +
                    card("In the Azure cloud (set up once, in the Wiz portal)", ul(["Choose the scope: a management group covers every subscription, now and later",
                                                                                   "Create a read-only app registration with the roles Wiz lists; admin consent in Microsoft Entra",
                                                                                   "Wiz then scans VMs, AKS, registries, storage and identities without agents, and shows attack paths",
                                                                                   "Container registries and clusters are connected separately when image and cluster coverage is wanted"])) + "</div>" +
                    '<div class="callout mt"><b>Needed from the client.</b> A Wiz licence and a service account for the command-line scanner; rights to grant read-only roles at the chosen Azure scope; '
                    'outbound access from the CI runners to Wiz. The exact roles and flags will be confirmed against the client\'s tenant in the pilot.</div>'))

# 7 key pillars
PIL = [("1. Agents as first-class identities", "A dedicated non-human identity, scoped credentials and short-lived tokens for every agent."),
       ("2. Tool isolation and sandboxing", "Anything an agent generates or runs is contained: no host, network or database access."),
       ("3. Least privilege and scoped permissions", "Default-deny authorisation on every tool call, with argument and ownership rules."),
       ("4. Continuous agent red teaming", "Attack the running agent in QA with repeatable probes and framework-based testing."),
       ("5. Robust guardrails", "Checks decided by code that fail closed, never by the model."),
       ("6. Human-in-the-loop oversight", "No irreversible action runs without a person approving it."),
       ("7. Runtime observability and auditing", "Tamper-evident records of what the agent did, and detection rules for misuse."),
       ("8. Data protection, governance and cryptography", "Classify, minimise and mask data; manage keys; map controls to standards.")]
slides.append(slide("Key pillars · defensive architecture", "Eight strategies we will apply to agentic security",
                    '<div class="grid g4">' + "".join(card(a, f"<p>{e(b)}</p>") for a, b in PIL) + "</div>"))

# 8 layer 1 domains
DOM = [("P1", "Identity & Access", "Who is allowed to act, and on whose data"), ("P2", "Agentic Execution & Injection", "What the agent is permitted to run"),
       ("P3", "AI Logic & Application Integrity", "Whether the agent's reasoning and output can be trusted"), ("P4", "Infrastructure & Network", "Where the agent runs and what it can reach"),
       ("P5", "Secrets & Cryptography", "How credentials and keys are protected"), ("P6", "Supply Chain & Model Provenance", "What third-party code and models are depended on"),
       ("P7", "Data Protection & Privacy", "What data leaves the boundary, and in what form"), ("P8", "Governance, Oversight & Assurance", "How the controls are proven and kept accountable")]
slides.append(slide("Layer 1 · security domains", "The eight domains of an enterprise agentic application",
                    '<div class="grid g4">' + "".join(card(f"{p} {n}", f"<p>{e(q)}</p>") for p, n, q in DOM) + "</div>",
                    "Every threat, control and check belongs to one domain."))

# 9 layer 2/3 threats and controls by domain (names only)
rows = []
for p, name, _ in DOM:
    th = prow(f"Threat catalog {p}")
    cs = [r[1].split(" ", 1)[1] for r in CTL if r[1].startswith(p + " ")]
    rows.append((f"{p} {name}", "; ".join(r[1] for r in th), "; ".join(cs)))
slides.append(slide("Layer 2 and 3 · threats and controls", "Threat scenarios, and the controls we will apply, by domain",
                    table(["Domain", "Threat scenarios", "Architectural controls"], rows)))

# 10 crosswalk
slides.append(slide("Governance and compliance crosswalk", "Controls mapped to the standards auditors ask about",
                    '<div class="grid g3">' + "".join(card(x, "") for x in ["NIST AI RMF", "NIST CSF 2.0", "ISO/IEC 42001", "OWASP LLM Top 10", "EU AI Act", "Supervisory themes"]) + "</div>" +
                    f'<p class="mt">{len(CROSS)} architectural controls will be mapped to all six. Every finding in every scan will be tagged to the control it relates to, and each scan will write a crosswalk file for audits.</p>'
                    '<div class="callout mt"><b>A mapping aid, not a compliance verdict.</b> It shows which control a finding relates to; it does not certify compliance.</div>'))

# 11 six categories
CATS6 = [("Secrets", "Is a password, token or key in the code or its history?", "gitleaks, Trivy, Semgrep"),
         ("Code analysis (SAST)", "Does our own code contain insecure patterns?", "Semgrep, Bandit, ESLint security, SonarQube, CodeQL (optional)"),
         ("Dependencies (SCA)", "Do the libraries have known vulnerabilities or unusable licences?", "pip-audit, npm audit, Trivy, SBOM, Dependency-Track"),
         ("Containers and infrastructure as code", "Are Dockerfiles, images, Kubernetes and Terraform safe?", "Trivy, kubescape, Wiz"),
         ("Dynamic testing (DAST)", "Can the running application be attacked from outside?", "OWASP ZAP, Schemathesis API fuzzing, exposure scan"),
         ("Supply chain and CI/CD", "Can the pipeline or the repository be abused?", "zizmor, repository settings check, Dependabot or Renovate")]
slides.append(slide("Application and delivery-pipeline security", "Six categories of scanning",
                    '<div class="grid g3">' + "".join(card(a, f"<p>{e(b)}</p>", extra=f'<p class="small mt">{e(c)}</p>') for a, b, c in CATS6) + "</div>",
                    "Chosen automatically for the stack. Secrets, code and dependency scanning cannot be switched off by a team."))


# 12 issue / fix
def issue(title, issue_t, check, fix):
    return card(title, f'<p><b>Issue.</b> {e(issue_t)}</p><p class="mt"><b>We will check.</b> {e(check)}</p><p class="mt"><b>Fix.</b> {e(fix)}</p>')


slides.append(slide("Code-level and dependency risks", "What the scans will find, and the fix that comes with each finding",
                    '<div class="grid g3">' +
                    issue("Secrets in code", "Keys, tokens and passwords committed to files or history are copied into clones, forks and logs.", "Files, optionally git history, and Docker image layers.",
                          "Rotate first, then move to a secret manager. Test credentials never go in git.") +
                    issue("Injection and unsafe patterns", "SQL built from strings, shell commands, unsafe deserialisation, path traversal, XSS, weak crypto.",
                          "Several analysers: OWASP Top 10 rules, Python and JavaScript specialists, SonarQube.", "Parameterised queries, input normalisation, fail-closed guardrails; before and after examples are in the cookbook.") +
                    issue("Vulnerable packages", "Known CVEs in direct and indirect libraries, and licences that cannot be used.",
                          "Python, Node and Java dependencies, de-duplicated across tools; licence rules; the SBOM.", "Upgrade the parent package; automatic update pull requests.") + "</div>"))

# 13 infrastructure and running systems
slides.append(slide("Infrastructure and running systems", "Check settings while they are still files, and test what is running in QA",
                    '<div class="grid g3">' +
                    card("Infrastructure as code", "<p>Dockerfiles, Kubernetes and Helm, Terraform and CloudFormation: root containers, privileged pods, public buckets, open ports, unencrypted databases. Images will be scanned before the push.</p>") +
                    card("Dynamic testing", "<p>OWASP ZAP, API fuzzing from the OpenAPI spec, and logged-in scans (basic, cookie, JSON, form, OAuth2 and SSO token flows). If a login fails the scan stops rather than report an anonymous scan as clean.</p>") +
                    card("Exposure checks", "<p>From outside: TLS, security headers, CORS, sensitive paths such as /.git, /.env, actuator and telemetry endpoints, and risky open ports.</p>") +
                    "</div>" + '<div class="callout mt"><b>Boundary.</b> Dynamic testing is not a penetration test. It finds known patterns; business-logic flaws and interactive SSO with MFA need a human test.</div>'))

# 14 supply chain
slides.append(slide("Supply chain and CI/CD", "Protect the pipeline and the repository, not only the code",
                    '<div class="grid g3">' +
                    card("Pipeline files", "<p>Unpinned actions, script injection, dangerous triggers and excess token permissions in the workflows.</p>") +
                    card("Repository settings", "<p>Branch protection, required checks, force-push, secret scanning, CODEOWNERS, so a failing scan can actually block a merge.</p>") +
                    card("What ships", "<p>An SBOM, licence rules, automatic dependency-update pull requests, and image signing with build provenance.</p>") + "</div>" +
                    '<div class="callout mt"><b>Auto-update trade-off.</b> Repositories will follow a moving version tag, so a new check reaches every repository on its next run. Whoever can move that tag can run code in every repository, so the tags are protected and a repository can pin a version.</div>'))

# 15 AI agents
N_PROBES = len([r for r in D.INVENTORY if r[0] == "AI agent: red-team probes" and r[1].startswith("RT-")])
N_LIB = len([r for r in D.INVENTORY if r[0] == "AI agent: runtime controls (library)"])
slides.append(slide("AI agents", "Three parts: find unsafe wiring, attack a running agent, and give the code safe controls",
                    '<div class="grid g3">' +
                    card("Static checks (pull request)", "<p>Agent-specific code rules, an inventory of models, endpoints, tools and MCP servers checked against an approved registry, and a scan of model files.</p>") +
                    card("Red teaming (QA)", f"<p>{N_PROBES} repeatable probes against a running agent: authentication, injection, tool abuse, excessive agency, leaks. Framework-based testing (OWASP Agents and LLM, NIST AI RMF, MITRE ATLAS, EU AI Act) with an approved model.</p>") +
                    card("Runtime controls (library)", f"<p>{N_LIB} reusable controls for agent code: policy engine, fail-closed guardrails, sandbox, egress control, masking, audit log, secrets handling.</p>") +
                    "</div>" + '<div class="callout mt"><b>Boundary.</b> No red-team approach proves an agent is safe. Paraphrased prompt injection can still beat heuristic checks, so least privilege and human approval carry the weight.</div>'))

# 16 pipeline
slides.append(slide("During deployment · DevSecOps pipeline", "Fast scans on the pull request, deep checks after the build and in QA",
                    flow([("Pull request", "Secrets, code, libraries, IaC, pipeline files, agent checks. Report and gate."), ("Merge to main", "Same scan; results published to the registers."),
                          ("Build", "docker build"), ("Image gate", "Critical or High findings block the push."), ("Deploy to QA", "Only if the gate passed."),
                          ("Dynamic tests", "Dynamic scanning, API fuzzing, exposure checks, red-team probes."), ("Release approval", "A person decides.")]) +
                    '<p class="small mt">GitHub Actions first; Jenkins and Azure DevOps use the same commands.</p>'))

# 17 gate
rowsg = [("Critical", "Blocks new and known", "Blocks", f"{SLA['CRITICAL']} days"), ("High", "Blocks new; known ones once overdue", "Blocks new and known", f"{SLA['HIGH']} days"),
         ("Medium", "Reported", "Reported", f"{SLA['MEDIUM']} days"), ("Low / Info", "Reported", "Reported", f"{SLA['LOW']} days")]
slides.append(slide("Governance and SLA enforcement", "One decision, the same for every repository, set centrally",
                    '<div class="grid g2">' + table(["Severity", "Pull request gate", "Release gate", "Fix deadline"], rowsg) +
                    '<div>' + card("Presets, in order", ul(["Starter: report-only, for the first weeks", "Standard: new Critical and High block pull requests", "Strict: release gate, git history, SonarQube and Dependency-Check"])) +
                    card("Controls that keep it honest", ul(["Legacy findings are baselined but still age against the deadline", "Exceptions need a reason, an approver and an expiry",
                                                           "Required tools cannot be turned off; a broken scanner never looks like a pass", "A pull request cannot weaken the policy"])) + "</div></div>"))

# 18 developer experience
slides.append(slide("Developer experience", "A developer will onboard a repository without help from DevOps",
                    '<div class="grid g2"><pre>pip install warden          # once, in a virtual environment\nwarden init                 # adds scanning and the GitHub workflow\nwarden scan                 # first scan; never breaks the build\nwarden config show          # what runs and why\nwarden hook install         # checks before every push</pre>' +
                    '<div>' + card("Designed for adoption", ul(["A small launcher in the repository; no engine to maintain", "New checks arrive automatically, or a repository pins a version",
                                                               "One settings file, read as data and never executed", "Test credentials from CI secrets, a local store or a prompt; never in git"])) + "</div></div>"))

# 19 runtime auth engine
slides.append(slide("During runtime · auth engine", "Policy decisions made by code that the model cannot talk its way past",
                    '<div class="grid g4">' +
                    card("PDP: decision point", "<p>Default-deny. Roles, scopes, argument rules, ownership and cross-tenant checks. Unknown means deny.</p>") +
                    card("PEP: enforcement point", "<p>Intercepts each tool call, asks the PDP, asks a person when policy says so, writes the audit log.</p>") +
                    card("PIP: information point", "<p>Context such as risk score, device and hours. A provider that fails means deny.</p>") +
                    card("PAP: administration point", "<p>Validate, version and disable policies with an audit trail; a kill switch per tool or agent.</p>") + "</div>" +
                    '<p class="mt">The model may propose an action. Authorisation, limits, approval and output checks are decided by ordinary code. Token exchange, so that tools never see the user token, needs the platform identity provider and vault.</p>'))

# 20 detection and process
slides.append(slide("Detection, response and process", "What tools cannot provide: noticing an attack, and people who know what to do",
                    '<div class="grid g2">' +
                    card("Detection", "<p>Detection rules for agent workloads, a recipe for sending alerts and audit logs to the SIEM (Sentinel, Datadog), and notifications when a gate fails, a new Critical appears or a deadline is missed.</p>") +
                    card("Process kit", "<p>Nine short documents: threat model, code-review checklist, vulnerability policy, incident runbook, access review, training plan, penetration-test scope, security champions.</p>") + "</div>"))

# 21 boundaries and next additions
NEXT = "; ".join(r[2].split(" (")[0] for r in D.ROADMAP if r[6] == "Planned")
slides.append(slide("Boundaries and next additions", "What automated scanning does not replace, and what comes next",
                    '<div class="grid g2">' +
                    card("Still needs people", ul(["A manual penetration test, before major releases", "Threat modelling and design review", "Network, endpoint and cloud operations security",
                                                  "Incident response, rehearsed", "Privacy and data-governance decisions"])) +
                    card("Next additions to the scanners", f"<p>{e(NEXT)}.</p><p class='small mt'>These extend the automated part of a penetration test; the manual test itself stays a human activity.</p>") + "</div>"))

# 22 adoption and pilot
slides.append(slide("Adoption", "From decision to enforced scanning, with a pilot that confirms the integrations",
                    flow([("Week 1", "Pick pilot repositories and owners. Install and run the first report-only scans."), ("Week 2", "Results in GitHub on every pull request. Connect SonarQube, DefectDojo and Dependency-Track."),
                          ("Week 4", "Review findings, baseline legacy ones, set fix deadlines. Connect Wiz once the licence is in place."),
                          ("Week 8", "Switch pilots to Standard: new Critical and High block. Plan the first manual penetration test.")]) +
                    '<div class="callout mt"><b>The pilot will confirm, in the client environment:</b> the Wiz scanner and Azure connector against the client\'s tenant; logged-in dynamic scans against a QA system; '
                    'detection rules on a non-production cluster; and that the CI runners can reach SonarQube, DefectDojo and Dependency-Track (self-hosted runners or allow-listed addresses).</div>'))

body_html = "".join(slides)
out = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warden: One Module for Complete DevSecOps Security</title>
<style>{STYLE}{EXTRA_CSS}</style>
</head>
<body class="nojs">

{body_html}{NAV}
<script>{SCRIPT}</script>
</body>
</html>
"""
path = os.path.join(DOCS, "warden-pov-full.html")
open(path, "w").write(out)
print(f"wrote {os.path.relpath(path)}: {len(slides)} slides, {len(out) // 1024} KB")
