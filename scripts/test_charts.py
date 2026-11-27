"""Tests for the charts in the HTML report (scripts/gate.py charts_html / write_html), no Docker and no browser needed.
Run: python3 -I scripts/test_charts.py"""
import importlib.util, os, re, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gate", os.path.join(HERE, "gate.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
FAILS = 0


def check(name, ok):
    global FAILS
    print(("  PASS  " if ok else "  FAIL  ") + name)
    FAILS += 0 if ok else 1


def fnd(sev, cat, tool, path, **kw):
    return dict(category=cat, fingerprint=f"{sev}{cat}{path}{kw.get('rule', '')}", fix="", location=f"{path}:1", new=True, path=path,
                rule=kw.get("rule", "r1"), severity=sev, title="t", tool=tool, tools=tool.split("+"), **({"excepted": kw["excepted"]} if "excepted" in kw else {}))


def summary(findings):
    c = {s: sum(1 for f in findings if f["severity"] == s and not f.get("excepted")) for s in g.SEV}
    return dict(target="t", date="2026-01-01T00:00:00", gate="pr", mode="report-only", result="PASS", blocking=0, counts=c, new_counts=dict(c),
                by_tool={}, tool_status={}, baseline_used=False, exceptions_applied=0, expired_exceptions=[], sonar_quality_gate_failures=[],
                degraded_manifests=[])


def render(findings):
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "summary.html")
        g.write_html(p, summary(findings), findings, [])
        return open(p).read()


F = [fnd("CRITICAL", "SCA", "trivy-fs+pip-audit", "requirements.txt"), fnd("HIGH", "SCA", "trivy-fs", "requirements.txt", rule="r2"),
     fnd("HIGH", "SAST", "semgrep", "app/a.py"), fnd("MEDIUM", "SAST", "bandit", "app/a.py", rule="r3"), fnd("LOW", "Secrets", "gitleaks", "app/b.py"),
     fnd("MEDIUM", "SCA", "trivy-fs", "requirements.txt", rule="r4"), fnd("HIGH", "SAST", "semgrep", "app/c.py", excepted="approved until 2027")]
h = render(F)
c = h[h.index('class="charts"'):h.index('id="tip"')] if 'class="charts"' in h else ""
check("report has the five charts", c.count("<figure") == 5 and all(t in c for t in ("by severity", "Findings by category", "Category by severity", "Findings by tool", "Top files")))
check("severity bars count only open findings (the excepted High is left out: 2 High of 6 open)", 'data-name="High" data-val="2" data-extra="33% of open findings"' in c and 'data-name="Medium" data-val="2"' in c)
check("category bars and tool bars add up (SCA 3, SAST 2, Secrets 1; trivy-fs 3)", 'data-name="SCA" data-val="3"' in c and 'data-name="SAST" data-val="2"' in c and 'data-name="trivy-fs" data-val="3"' in c)
check("a finding found by two tools counts once for each tool", 'data-name="pip-audit" data-val="1"' in c)
check("heat grid has a cell per category and severity with the count in it", 'data-name="SCA &middot; Critical"'.replace("&middot;", "·") in c and ">1</td>" in c)
check("top files lists the busiest file first", c.index("requirements.txt") < c.index("app/a.py") < c.index("app/b.py"))
check("every chart has a table view and every mark a tooltip, so the numbers never depend on hover", c.count("Table view") == 5 and c.count('class="rw mk" tabindex="0"') >= 12)
check("light and dark colours are both defined", "--bar:#2a78d6" in h and "--bar:#3987e5" in h and "prefers-color-scheme:dark" in h)
check("the report stays self-contained (no external script, stylesheet or font)", not re.search(r'<script[^>]+src=|<link[^>]+href=|@import|https?://', h))
check("no findings, or only excepted ones, means no chart block and no error", 'class="charts"' not in render([]) and 'class="charts"' not in render([F[-1]]))
bad = '"><script>alert(1)</script><img src=x onerror=alert(2)>'
hx = render([fnd("HIGH", bad, bad, bad, rule=bad)])
cx = hx[hx.index('class="charts"'):hx.index('id="tip"')]
check("hostile text in a category, tool or file name is escaped in the charts", "<script>" not in cx and "<img" not in cx and "&lt;script&gt;" in cx)
check("the tooltip is filled with textContent, never innerHTML", "innerHTML" not in g.CHART_JS and "textContent" in g.CHART_JS)
sys.exit(1 if FAILS else 0)
