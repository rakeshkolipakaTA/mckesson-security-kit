"""Tests for the security assessment report (scripts/assessment.py, written as assessment.html by gate.py). No Docker needed.
Run: python3 -I scripts/test_assessment.py"""
import importlib.util, json, os, re, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("assessment", os.path.join(HERE, "assessment.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
FAILS = 0


def check(name, ok):
    global FAILS
    print(("  PASS  " if ok else "  FAIL  ") + name)
    FAILS += 0 if ok else 1


def fnd(sev, tool="semgrep", path="app/a.py", **kw):
    return dict(category="SAST", fingerprint=sev + path, fix=kw.get("fix", ""), location=path + ":1", new=True, path=path, rule="r1", severity=sev,
                title=kw.get("title", "t"), tool=tool, tools=tool.split("+"), **({"excepted": kw["excepted"]} if "excepted" in kw else {}))


def summ(findings, **kw):
    c = {s: sum(1 for f in findings if f["severity"] == s and not f.get("excepted")) for s in a.SEV}
    d = dict(target="my-app", date="2026-01-01T00:00:00", gate="pr", mode="report-only", result="PASS", blocking=0, counts=c, new_counts=dict(c),
             tool_status={"gitleaks": "ok", "semgrep": "ok"}, baseline_used=False, exceptions_applied=0, expired_exceptions=[], sonar_quality_gate_failures=[],
             degraded_manifests=[], preset="starter", excluded_by_path=0, exclude_paths=[], tools_not_run={}, tool_waivers=[], tool_plan={}, crosswalk=[], overdue=0)
    d.update(kw)
    return d


META = dict(version="1.1.0", commit="abc123", branch="main", policy=dict(block_new=["CRITICAL", "HIGH"], block_existing=[]), sla_days={"HIGH": 30},
            hashes={"findings.json": "f" * 64})


def page(findings, blocking=(), **kw):
    return a.render(summ(findings, **kw), findings, list(blocking), META)


def key(findings, blocking=(), **kw):
    return a.verdict(summ(findings, **kw), findings, list(blocking))[0]


H = fnd("HIGH")
check("clean scan, everything ran: PASSED", key([]) == "passed" and ">PASSED<" in page([]))
check("findings below the gate threshold do not stop a pass", key([fnd("MEDIUM"), fnd("LOW")]) == "passed")
check("a blocking finding: FAILED, and the reason counts it", key([H], [H]) == "failed" and "1 finding(s) break the pr gate policy (1 High)" in page([H], [H]))
check("FAILED outranks INCOMPLETE", key([H], [H], tool_status={"gitleaks": "ok", "semgrep": "missing"}) == "failed")
check("a scanner that gave no result: INCOMPLETE, never a pass", key([], tool_status={"gitleaks": "ok", "semgrep": "missing"}) == "incomplete"
      and "semgrep (missing)" in page([], tool_status={"gitleaks": "ok", "semgrep": "missing"}))
check("a tool that was switched off: PASSED WITH CONDITIONS, with its reason", key([], tools_not_run={"eslint": "turned off"}) == "conditions" and "eslint was switched off" in page([], tools_not_run={"eslint": "turned off"}))
check("a tool waiver is a condition and names the approver and expiry", "approved by alice" in page([], tool_waivers=[dict(tool="trivy-fs", reason="vendor image", approved_by="alice", expires="2027-01-01")])
      and key([], tool_waivers=[dict(tool="trivy-fs", reason="r", approved_by="alice", expires="2027-01-01")]) == "conditions")
check("overdue and expired items are conditions", key([], overdue=2) == "conditions" and key([], expired_exceptions=["x"]) == "conditions")
check("paths left out of the scan are a condition", key([], excluded_by_path=3, exclude_paths=["legacy/**"]) == "conditions" and "legacy/**" in page([], excluded_by_path=3, exclude_paths=["legacy/**"]))
check("open Critical/High that do not block are a condition, not a clean pass", key([H]) == "conditions")
check("a SonarQube quality gate failure fails the assessment", key([], sonar_quality_gate_failures=["coverage 10 vs 80"]) == "failed")

# the table of what was checked
t = page([H], tool_status={"gitleaks": "ok", "semgrep": "ok", "npm-audit": "invalid"},
         tool_plan={"eslint": dict(run=False, reason="turned off"), "bandit": dict(run=False, reason="no Python files found")})
check("a tool that ran is Checked, with its finding count and worst severity", re.search(r"semgrep</td><td class=\"ok\">Checked</td><td>1 open finding\(s\), worst High", t) is not None)
check("a tool with no findings says so", re.search(r"gitleaks</td><td class=\"ok\">Checked</td><td>No findings", t) is not None)
check("a tool that broke is shown as Failed to run", "Failed to run" in t and "npm-audit" in t)
check("a tool turned off and one that does not apply show their reasons", "Turned off" in t and "no Python files found" in t and ">Not run<" in t)
check("a tool that never applied is not listed as if it were assessed", "pip-audit" not in t and "kubescape" not in t)
check("areas are grouped under headings", "Secrets in code and history" in t and "Code weaknesses (SAST)" in t)

# honesty and audit content
check("states it is automated and not a certification", "automated" in t and "not a penetration test" in t and "certification" in t)
check("a clean result is not described as proof of safety", "not that nothing exists" in t)
check("report-only mode is explained, enforcing mode is explained differently", "the build was not blocked" in t and "a failed verdict blocks the build" in page([], mode="enforce"))
check("policy, commit, branch, version and hashes are on the page", all(x in t for x in ("abc123", "main", "Warden 1.1.0", "Critical, High", "f" * 64, "Fix deadlines")))
check("a person's sign-off block is left blank", "Reviewer name" in t and "Signature" in t and "Warden does not fill this in" in t)
check("exceptions are listed with their basis", "legacy, owner Platform" in page([fnd("HIGH", excepted="legacy, owner Platform")]) and "None. No finding" in page([]))
check("the findings that break the policy are listed with their fix", "Upgrade to 2.0" in page([fnd("HIGH", fix="Upgrade to 2.0")], [fnd("HIGH", fix="Upgrade to 2.0")]))
check("light and dark colours are defined and the page prints on A4", "prefers-color-scheme:dark" in t and "@page{size:A4" in t)
check("the page is self-contained (no script, link, font or external address)", not re.search(r"<script|<link|@import|https?://|src=", t))
hostile = '"><script>alert(1)</script><img src=x onerror=alert(2)>'
hx = a.render(summ([fnd("HIGH", path=hostile, title=hostile, excepted=hostile)], target=hostile, tools_not_run={hostile: hostile}), [fnd("HIGH", path=hostile, title=hostile, excepted=hostile)],
              [fnd("HIGH", path=hostile, title=hostile)], dict(META, branch=hostile, commit=hostile))
check("hostile text in names, paths, titles, branch or target is escaped", "<script>" not in hx and "<img" not in hx and "&lt;script&gt;" in hx)

# end to end: the real gate.py writes assessment.html next to summary.html, and a scan with no findings passes
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, "out")
    os.makedirs(os.path.join(out, "raw"))
    json.dump([], open(os.path.join(out, "raw", "gitleaks.json"), "w"))
    policy = os.path.join(HERE, "..", "configs", "policies", "policy.json")
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "gate.py"), "--out", out, "--tools", "gitleaks", "--policy", policy, "--root", d, "--target", "demo"],
                       capture_output=True, text=True)
    p = os.path.join(out, "assessment.html")
    h = open(p).read() if os.path.exists(p) else ""
    check("gate.py writes assessment.html beside summary.html", r.returncode == 0 and bool(h) and os.path.exists(os.path.join(out, "summary.html")))
    check("a real clean run reads PASSED and names the target", ">PASSED<" in h and "demo" in h)
    check("the evidence hashes match the files on disk", all(a.sha(os.path.join(out, n)) in h for n in ("findings.json", "summary.json", "results.sarif")))
    check("the report names the Warden version from the VERSION file", "Warden " + open(os.path.join(HERE, "..", "VERSION")).read().strip() in h)
    summ_json = json.load(open(os.path.join(out, "summary.json")))
    check("summary.json records the tool plan so the report can be rebuilt", "tool_plan" in summ_json)
sys.exit(1 if FAILS else 0)
