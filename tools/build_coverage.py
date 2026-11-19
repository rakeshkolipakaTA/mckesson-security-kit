#!/usr/bin/env python3
"""Generate docs/security-test-coverage.xlsx and docs/test-coverage.md from tools/coverage_data.py.
   python3 tools/build_coverage.py        (the .xlsx needs openpyxl; the .md is always written)"""
import datetime as dt
import os
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import coverage_data as D  # noqa: E402
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import toolplan  # noqa: E402

N_TOOLS = len(toolplan.ORDER)

DOCS = os.path.join(HERE, "..", "docs")
cats = OrderedDict()
for r in D.INVENTORY:
    cats.setdefault(r[0], []).append(r)
pc = Counter(r[3] for r in D.PRESENTATION)
total_pres = len(D.PRESENTATION)
TOOLS = {  # tools per category, for the summary table
    "Secrets": "gitleaks (tree + git history), Trivy, Semgrep, agent-scan",
    "Code analysis (SAST)": "Semgrep, Bandit, ESLint security, SonarQube (optional)",
    "Dependencies (SCA)": "pip-audit, npm audit, Trivy (CVEs, licences, SBOM), Dependency-Check (optional)",
    "Container & IaC": "Trivy (Dockerfile, Kubernetes/Helm, Terraform/CloudFormation, image, CIS), kubescape; cluster/cloud docs + template",
    "Dynamic testing (DAST)": "OWASP ZAP (baseline, API, full, authenticated), Schemathesis, exposure scan",
    "Supply chain & CI/CD": "zizmor, repo-settings check, Dependabot/Renovate, signing + Scorecard templates",
    "AI agent: static checks": "17 Semgrep agent rules, 13 agent-scan checks, modelscan",
    "AI agent: red-team probes": "19 deterministic probes; DeepTeam (7 frameworks) and promptfoo templates",
    "AI agent: runtime controls (library)": "agentsec (16 modules)",
    "Gate, policy & reporting": "gate.py, crosswalk, SLA, dashboard, alerts, tickets",
    "Developer workflow": "pre-push hook, pre-commit, PR template, IDE recommendations",
    "Detection & response": "Falco rules (template), SIEM recipe",
    "Process & governance": "9 process documents",
}


def md_table(head, rows):
    esc = lambda x: str(x).replace("|", "\\|")
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows])


def write_md():
    today = dt.date.today().isoformat()
    L = ["# What we test: coverage by category", "",
         f"Generated from `tools/coverage_data.py` on {today}. The same data is in [security-test-coverage.xlsx](security-test-coverage.xlsx) (filterable, with roadmap and glossary).", "",
         "## 1. Categories and how many checks each has", "",
         md_table(["Category", "Question it answers", "Checks", "Tools"], [(c, D.CATEGORY_NOTES[c], len(v), TOOLS[c]) for c, v in cats.items()] + [("**Total**", "", f"**{len(D.INVENTORY)}**", f"{N_TOOLS} scanner tools plus the library, gate and process kit")]), "",
         "A *check* is one rule, probe or control we can name. Scanner tools such as Semgrep contain thousands of rules; they are counted once. "
         "Categories 1-8 find problems (scanners, probes, template/doc checks); the rest are controls you embed, decision logic and process.", "",
         "## 2. Status of every check", "",
         md_table(["Status", "Meaning", "Count"], [
             (D.V, "run end to end in this repo or on a real app", sum(1 for r in D.INVENTORY if r[5] == D.V)),
             (D.VP, "run, with a stated limit", sum(1 for r in D.INVENTORY if r[5] == D.VP)),
             (D.WN, "wired up but never run (needs a key)", sum(1 for r in D.INVENTORY if r[5] == D.WN)),
             (D.TP, "shipped template, not run with a real LLM", sum(1 for r in D.INVENTORY if r[5] == D.TP)),
             (D.RL, "working code with unit tests that you must wire into your platform", sum(1 for r in D.INVENTORY if r[5] == D.RL)),
             (D.NE, "described in policy but not enforced", sum(1 for r in D.INVENTORY if r[5] == D.NE)),
             (D.DOC, "procedure or recipe, not code", sum(1 for r in D.INVENTORY if r[5] == D.DOC))]), "",
         "## 3. Coverage of the Agentic Security presentation", "",
         f"{total_pres} items checked (pillars, threats, controls, red-team frameworks, pipeline and tool slides, auth engine): "
         f"**{pc['Covered']} covered ({round(pc['Covered'] * 100 / total_pres)}%), {pc['Partial']} partial ({round(pc['Partial'] * 100 / total_pres)}%), {pc['Not covered']} not covered ({round(pc['Not covered'] * 100 / total_pres)}%)**.", "",
         "**Short answer: no, not everything in the presentation is covered.** Scanning, pipeline gates, red-team probes and the runtime-controls library are covered. "
         "Platform services (sandbox runtime, identity provider / vault, policy admin UI, runtime detection) and several data and output-integrity items are not, because they are not things a scanner can provide.", "",
         "**What the words mean.** *Covered*: we ship working, tested code or a check for it (platform wiring, such as routing your agent through the sandbox, stays with the team). "
         "*Partial*: part of it is covered, or it is a template / recipe that has not run in a live environment. *Not covered*: nothing provided.", "",
         "Not covered:", ""]
    L += [f"- **{r[1]}** ({r[0]}): {r[4] or 'not provided'}" for r in D.PRESENTATION if r[3] == D.N]
    L += ["", "The full item-by-item table is in the Excel sheet *Presentation coverage*.", "",
          "## 4. What cyber security means", "",
          "Cyber security is protecting systems, networks, applications and data from unauthorised access, damage or disruption, and being able to detect and recover when something goes wrong. "
          "It is usually described by three goals: **confidentiality** (only the right people see the data), **integrity** (nothing is changed without permission, and tampering is noticed) and **availability** (the service keeps working).", "",
          md_table(["Area", "Meaning", "In this framework"], [(g[0], g[1], g[2]) for g in D.GLOSSARY[4:]]), "",
          "Our scans are **application and delivery-pipeline security** (the first rows), plus runtime controls for AI agents and starter kits for detection and process. That is one slice of cyber security: network, endpoint, cloud operations and people still need their own tools and activities.", "",
          "## 5. Roadmap: what was added and what is still open", "",
          f"{sum(1 for r in D.ROADMAP if r[6] == 'Done')} done, {sum(1 for r in D.ROADMAP if r[6] == 'Partly')} partly, {sum(1 for r in D.ROADMAP if r[6] == 'Documented')} documented only, {sum(1 for r in D.ROADMAP if r[6] == 'Planned')} planned and not built ({len(D.ROADMAP)} items incl. extras and the pen-test gaps).", "",
          md_table(["Priority", "Area", "Check", "Status", "What exists / what is missing"], [(("High", "Medium", "Low")[r[0] - 1], r[1], r[2], r[6], r[7]) for r in D.ROADMAP]), "",
          "## 6. How we know the framework itself works", "",
          md_table(["Suite", "What it proves", "Checks"], D.SUITES + [("**Total**", "", f"**{sum(s[2] for s in D.SUITES)}**")]), ""]
    open(os.path.join(DOCS, "test-coverage.md"), "w").write("\n".join(L))


def write_xlsx():
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("openpyxl not installed: skipped the .xlsx (pip install openpyxl)")
        return
    F = lambda **k: Font(name="Arial", size=k.pop("size", 10), **k)
    hfill = PatternFill("solid", fgColor="1F3864")
    thin = Side(style="thin", color="D0D5DD")
    box = Border(left=thin, right=thin, top=thin, bottom=thin)
    status_fill = {"Done": "C6EFCE", "Partly": "FFEB9C", "Documented": "DDEBF7", "Planned": "E4DFF7", D.DOC: "DDEBF7", D.V: "C6EFCE", D.VP: "E2F0D9", D.WN: "FFEB9C", D.TP: "FFEB9C", D.RL: "DDEBF7", D.NE: "F8CBAD", "Covered": "C6EFCE", "Partial": "FFEB9C", "Not covered": "F8CBAD"}
    wb = Workbook()

    def sheet(name, head, rows, widths, status_col=None, first=False):
        ws = wb.active if first else wb.create_sheet()
        ws.title = name
        ws.append(head)
        for c in ws[1]:
            c.font, c.fill, c.border = F(bold=True, color="FFFFFF"), hfill, box
            c.alignment = Alignment(vertical="center", wrap_text=True)
        for r in rows:
            ws.append(list(r))
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.font, c.border = F(), box
                c.alignment = Alignment(vertical="top", wrap_text=True)
            if status_col is not None:
                s = row[status_col]
                if s.value in status_fill:
                    s.fill = PatternFill("solid", fgColor=status_fill[s.value])
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        return ws

    # ---- Summary (formulas read the other sheets, so edits there flow through)
    ws = wb.active
    ws.title = "Summary"
    ws["A1"], ws["A1"].font = "McKesson security scanning kit: what we test", F(bold=True, size=14)
    ws["A2"], ws["A2"].font = f"Generated {dt.date.today().isoformat()} from tools/coverage_data.py. Counts below are formulas over the other sheets.", F(italic=True, color="666666")
    r0 = 4
    for j, h in enumerate(["Category", "Question it answers", "Checks", "Tools"], 1):
        c = ws.cell(r0, j, h)
        c.font, c.fill, c.border = F(bold=True, color="FFFFFF"), hfill, box
    r = r0 + 1
    first_cat = r
    for c_name in cats:
        ws.cell(r, 1, c_name)
        ws.cell(r, 2, D.CATEGORY_NOTES[c_name])
        ws.cell(r, 3, f"=COUNTIF('Test inventory'!$A:$A,A{r})")
        ws.cell(r, 4, TOOLS[c_name])
        r += 1
    last_cat = r - 1
    ws.cell(r, 1, "Total checks")
    ws.cell(r, 3, f"=SUM(C{first_cat}:C{last_cat})")
    for j in range(1, 5):
        ws.cell(r, j).font = F(bold=True)
    tot_row = r
    for rr in range(first_cat, r + 1):
        for j in range(1, 5):
            c = ws.cell(rr, j)
            c.border = box
            c.alignment = Alignment(vertical="top", wrap_text=True)
            if rr != tot_row:
                c.font = F()
    r += 2
    ws.cell(r, 1, "Status of every check").font = F(bold=True, size=12)
    r += 1
    for st, meaning in [(D.V, "run end to end here or on a real app"), (D.VP, "run, with a stated limit"), (D.WN, "wired, never run (needs a key)"), (D.TP, "template, not run with a real LLM"), (D.RL, "working code you must wire into your platform"), (D.NE, "in policy but not enforced"), (D.DOC, "procedure or recipe, not code")]:
        ws.cell(r, 1, st).font = F()
        ws.cell(r, 2, meaning).font = F()
        ws.cell(r, 3, f"=COUNTIF('Test inventory'!$F:$F,A{r})").font = F()
        ws.cell(r, 1).fill = PatternFill("solid", fgColor=status_fill[st])
        r += 1
    r += 1
    ws.cell(r, 1, "Coverage of the Agentic Security presentation").font = F(bold=True, size=12)
    r += 1
    ws.cell(r, 1, "Status").font = F(bold=True)
    ws.cell(r, 3, "Items").font = F(bold=True)
    ws.cell(r, 4, "Share").font = F(bold=True)
    r += 1
    p_first = r
    for st in ("Covered", "Partial", "Not covered"):
        ws.cell(r, 1, st).font = F()
        ws.cell(r, 1).fill = PatternFill("solid", fgColor=status_fill[st])
        ws.cell(r, 3, f"=COUNTIF('Presentation coverage'!$D:$D,A{r})").font = F()
        ws.cell(r, 4, f"=C{r}/SUM($C${p_first}:$C${p_first + 2})").font = F()
        ws.cell(r, 4).number_format = "0%"
        ws.cell(r, 4).alignment = Alignment(horizontal="left")
        r += 1
    ws.cell(r, 1, "Total items").font = F(bold=True)
    ws.cell(r, 3, f"=SUM(C{p_first}:C{r - 1})").font = F(bold=True)
    r += 2
    ws.cell(r, 1, "Our own regression checks").font = F(bold=True, size=12)
    ws.cell(r, 3, f"=SUM('Our test suites'!$C$2:$C${len(D.SUITES) + 1})").font = F(bold=True)
    ws.cell(r, 2, "Automated checks that prove the framework itself works (sheet 'Our test suites')").font = F()
    r += 2
    ws.cell(r, 1, "Sheets").font = F(bold=True, size=12)
    for name, what in [("Test inventory", "every check, filterable by category and status"), ("Presentation coverage", "every item of the Agentic Security deck: covered / partial / not covered"),
                       ("Roadmap", "every roadmap item with its implementation status (done / partly / documented)"), ("Our test suites", "regression tests of the framework"), ("Cyber security 101", "what cyber security means and where this framework sits")]:
        r += 1
        ws.cell(r, 1, name).font = F()
        ws.cell(r, 2, what).font = F()
    for col, w in zip("ABCD", (34, 62, 10, 58)):
        ws.column_dimensions[col].width = w
    for row in ws.iter_rows(min_row=r0 + 1):
        for c in row:
            if c.value is not None and c.font.name != "Arial":
                c.font = F()

    sheet("Test inventory", ["Category", "Check / tool", "What it detects", "Applies to", "Stage", "Status", "Notes and limits"], D.INVENTORY, (26, 44, 62, 24, 18, 18, 56), status_col=5)
    sheet("Presentation coverage", ["Section", "Item", "What we provide", "Status", "Gap / next step"], D.PRESENTATION, (24, 52, 60, 14, 56), status_col=3)
    sheet("Roadmap", ["Priority (1 = first)", "Area", "Check", "Why it matters", "Tool", "Effort", "Status now", "What exists / what is missing"], D.ROADMAP, (10, 14, 46, 52, 38, 10, 14, 62), status_col=6)
    ws4 = sheet("Our test suites", ["Suite", "What it proves", "Checks"], D.SUITES, (36, 90, 10))
    ws4.append(["Total", "", "=SUM(C2:C%d)" % (len(D.SUITES) + 1)])
    for c in ws4[len(D.SUITES) + 2]:
        c.font = F(bold=True)
    sheet("Cyber security 101", ["Term", "Meaning", "Where this framework stands"], D.GLOSSARY, (30, 90, 56))
    out = os.path.join(DOCS, "security-test-coverage.xlsx")
    wb.save(out)
    print("wrote", out)


def write_readme():
    """Refresh the generated block of README.md between the coverage markers."""
    path = os.path.join(HERE, "..", "README.md")
    txt = open(path).read()
    a, b = "<!-- coverage:start -->", "<!-- coverage:end -->"
    if a not in txt or b not in txt:
        print("README markers missing: skipped")
        return
    rows = [(c, D.CATEGORY_NOTES[c], len(v), TOOLS[c]) for c, v in cats.items()] + [("**Total**", "", f"**{len(D.INVENTORY)}**", f"{N_TOOLS} scanner tools plus the library and gate")]
    n_c, n_p, n_n = pc["Covered"], pc["Partial"], pc["Not covered"]
    block = "\n".join([a, md_table(["Category", "Question it answers", "Checks", "Tools"], rows), "",
                       f"**Coverage of the Agentic Security presentation:** {total_pres} items checked: {n_c} covered, {n_p} partial, {n_n} not covered. "
                       "Details and the list of what is not covered are in [docs/test-coverage.md](docs/test-coverage.md). "
                       f"Roadmap: {sum(1 for r in D.ROADMAP if r[6] == 'Done')} done, {sum(1 for r in D.ROADMAP if r[6] == 'Partly')} partly, "
                       f"{sum(1 for r in D.ROADMAP if r[6] == 'Documented')} documented only, {sum(1 for r in D.ROADMAP if r[6] == 'Planned')} planned (penetration-test gaps).", b])
    head, rest = txt.split(a, 1)
    _, tail = rest.split(b, 1)
    open(path, "w").write(head + block + tail)
    print("updated README coverage block")


if __name__ == "__main__":
    write_md()
    print("wrote", os.path.join(DOCS, "test-coverage.md"))
    write_xlsx()
    write_readme()
