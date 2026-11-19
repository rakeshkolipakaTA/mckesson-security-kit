#!/usr/bin/env python3
"""Unit tests for gate.py identity/dedupe logic (no Docker, no network). Run: python3 -I scripts/test_gate.py"""
import json, os, random, sys
sys.path.insert(0, os.path.dirname(__file__))
import gate

POL = {"unknown_severity_as": "HIGH", "secret_severity": "HIGH"}


def pip_audit_report():
    # real-world shape: same PYSEC id listed twice with different alias sets (seen for pyyaml 5.3)
    return {"dependencies": [{"name": "PyYAML", "version": "5.3", "vulns": [
        {"id": "PYSEC-2020-96", "aliases": ["CVE-2020-1747", "CVE-2025-50460", "GHSA-6757-jp84-gxfx", "GHSA-fm6c-f59h-7mmg"], "fix_versions": ["5.4"]},
        {"id": "PYSEC-2020-96", "aliases": ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"], "fix_versions": ["5.4"]},
        {"id": "PYSEC-2021-1", "aliases": [], "fix_versions": []}]}]}


def trivy_report():
    return {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-1747", "PkgName": "PyYAML", "InstalledVersion": "5.3", "Severity": "CRITICAL", "Title": "t"}]}]}


def run(shuffle, with_trivy=True):
    d = pip_audit_report()
    for dep in d["dependencies"]:
        for v in dep["vulns"]:
            if shuffle:
                random.shuffle(v["aliases"])
        if shuffle:
            random.shuffle(dep["vulns"])
    f = gate.f_pipaudit(d, POL, "/src", "requirements.txt")
    if with_trivy:
        f += gate.f_trivy(trivy_report(), POL, "/src", "trivy-fs")
    return gate.dedupe(f)


def test_same_vuln_listed_twice_is_one_finding():
    r = run(False)
    assert len([f for f in r if "PYSEC-2020-96" in f["all_ids"]]) == 1, [f["all_ids"] for f in r]


def test_trivy_and_pip_audit_merge_and_real_severity_wins():
    r = [f for f in run(False) if "CVE-2020-1747" in f["all_ids"]]
    assert len(r) == 1 and r[0]["tools"] == ["pip-audit", "trivy-fs"] and r[0]["severity"] == "CRITICAL"


def test_baseline_matches_regardless_of_alias_order():
    base = {x for f in run(False) for x in f["fps"]}
    for _ in range(200):
        for f in run(True):
            assert any(x in base for x in f["fps"]), f"unstable identity: {f['all_ids']}"


def test_baseline_survives_a_tool_being_removed():
    base = {x for f in run(False, with_trivy=True) for x in f["fps"]}
    for f in run(False, with_trivy=False):
        assert any(x in base for x in f["fps"]), f"identity depends on tool set: {f['all_ids']}"


def test_same_cve_in_two_manifests_stays_two_findings():
    a = gate.f_pipaudit(pip_audit_report(), POL, "/src", "a/requirements.txt")
    b = gate.f_pipaudit(pip_audit_report(), POL, "/src", "b/requirements.txt")
    assert len([f for f in gate.dedupe(a + b) if "PYSEC-2021-1" in f["all_ids"]]) == 2


def test_semgrep_secret_merges_with_gitleaks_and_hides_no_code():
    sg = {"results": [{"check_id": "generic.secrets.security.detected-github-token.detected-github-token", "path": "/src/app/main.py",
                       "start": {"line": 15}, "end": {"line": 15},
                       "extra": {"severity": "ERROR", "message": "GitHub token detected", "lines": "requires login"}}]}
    gl = [{"RuleID": "github-pat", "File": "/src/app/main.py", "StartLine": 15, "Description": "token", "Secret": "REDACTED"}]
    f = gate.dedupe(gate.f_semgrep(sg, POL, "/src") + gate.f_gitleaks(gl, POL, "/src"))
    assert len(f) == 1 and f[0]["category"] == "Secrets" and set(f[0]["tools"]) == {"semgrep", "gitleaks"}, f


def test_semgrep_fingerprint_survives_line_shift(tmp_path=None):
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.py"), "w").write("x = 1\nsubprocess.call(c, shell=True)\n")
    def run(line):
        r = {"results": [{"check_id": "r.subprocess-shell-true", "path": "a.py", "start": {"line": line}, "end": {"line": line},
                          "extra": {"severity": "ERROR", "message": "m"}}]}
        return gate.f_semgrep(r, POL, d)[0]["fingerprint"]
    a = run(2)
    open(os.path.join(d, "a.py"), "w").write("# new comment\n# another\nx = 1\nsubprocess.call(c, shell=True)\n")
    assert run(4) == a, "fingerprint must depend on the code, not the line number"


def test_semgrep_heuristic_rule_is_capped_at_medium():
    cid = "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query"
    pol = dict(POL, semgrep_severity_cap={cid: "MEDIUM"})
    r = {"results": [{"check_id": cid, "path": "a.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {"severity": "ERROR", "message": "m"}},
                     {"check_id": "x.other", "path": "a.py", "start": {"line": 2}, "end": {"line": 2}, "extra": {"severity": "ERROR", "message": "m"}}]}
    sev = {f["rule"]: f["severity"] for f in gate.f_semgrep(r, pol, "/src")}
    assert sev["sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query"] == "MEDIUM" and sev["x.other"] == "HIGH", sev


def test_semgrep_path_cannot_escape_root():
    assert gate.src_hash("/tmp", "../etc/passwd", 1) is None


def test_eslint_severity_mapping_and_parse_errors_ignored():
    d = [{"filePath": "/src/a.js", "messages": [
        {"ruleId": "security/detect-eval-with-expression", "severity": 1, "message": "eval", "line": 3},
        {"ruleId": "security/detect-non-literal-fs-filename", "severity": 1, "message": "fs", "line": 4},
        {"ruleId": None, "fatal": True, "severity": 2, "message": "Parsing error", "line": 1}]}]
    r = {f["rule"]: f["severity"] for f in gate.f_eslint(d, POL, "/src")}
    assert r == {"security/detect-eval-with-expression": "HIGH", "security/detect-non-literal-fs-filename": "LOW"}, r


def test_npm_audit_parsing_skips_transitive_strings_and_maps_moderate():
    d = {"vulnerabilities": {
        "lodash": {"name": "lodash", "range": "<4.17.21", "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": False},
                   "via": [{"source": 1, "name": "lodash", "title": "Prototype Pollution", "severity": "moderate",
                            "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]},
        "express": {"name": "express", "via": ["lodash"], "fixAvailable": True}}}
    r = gate.f_npmaudit(d, POL, "/src", "package-lock.json")
    assert len(r) == 1 and r[0]["severity"] == "MEDIUM" and "GHSA-aaaa-bbbb-cccc" in r[0]["ids"] and "4.17.21" in r[0]["fix"], r


def test_sarif_excludes_dast_and_marks_exceptions(tmp_path=None):
    import tempfile
    f1 = dict(tool="zap", tools=["zap"], category="DAST", severity="HIGH", rule="ZAP-1", title="x", location="GET /a", path="/a", fingerprint="1", fix=None)
    f2 = dict(tool="bandit", tools=["bandit"], category="SAST", severity="LOW", rule="B101", title="assert", location="a.py:3", path="a.py", fingerprint="2", fix=None, excepted="ok")
    p = os.path.join(tempfile.mkdtemp(), "r.sarif")
    gate.write_sarif(p, [f1, f2])
    res = json.load(open(p))["runs"][0]["results"]
    assert len(res) == 1 and res[0]["suppressions"][0]["justification"] == "ok" and res[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_html_report_escapes_content():
    f = dict(tool="bandit", tools=["bandit"], category="SAST", severity="HIGH", rule="B1", title="<script>alert(1)</script>", location="a.py:1", path="a.py", fingerprint="1", fix=None)
    summary = dict(target="t<b>", date="d", gate="pr", mode="report-only", result="FAIL", counts={s: 0 for s in gate.SEV}, new_counts={s: 0 for s in gate.SEV},
                   tool_status={"bandit": "ok"}, baseline_used=False, degraded_manifests=[], sonar_quality_gate_failures=[])
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "r.html")
    gate.write_html(p, summary, [f], [f])
    h = open(p).read()
    assert "<script>alert(1)</script>" not in h and "&lt;script&gt;" in h and "t&lt;b&gt;" in h


def test_agent_scan_parser_keeps_inventory_and_merges_prompt_secret_with_gitleaks():
    d = {"inventory": {"frameworks": ["LangChain"], "models": [], "endpoints": [], "tools": [], "mcp_servers": []},
         "findings": [{"rule": "AG-PROMPT-001", "severity": "HIGH", "title": "secret in prompt", "path": "prompts/system.txt", "line": 2,
                       "domain": "P5", "owasp": "LLM07", "fix": "remove", "dkey": ["secret", "prompts/system.txt", 2]}]}
    gl = [{"RuleID": "generic-api-key", "File": "/src/prompts/system.txt", "StartLine": 2, "Description": "key", "Secret": "x"}]
    f = gate.dedupe(gate.f_agentscan(d, POL, "/src") + gate.f_gitleaks(gl, POL, "/src"))
    assert len(f) == 1 and set(f[0]["tools"]) == {"agent-scan", "gitleaks"}, f
    assert gate.AGENT_INVENTORY["frameworks"] == ["LangChain"]


def test_redteam_parser_reports_only_real_failures():
    d = {"summary": {"probes_run": 3}, "results": [
        {"id": "RT-A", "title": "a", "severity": "HIGH", "passed": False, "evidence": "leaked", "location": "POST /chat", "fix": "f", "domain": "P3", "owasp": "LLM01"},
        {"id": "RT-B", "title": "b", "severity": "HIGH", "passed": True, "evidence": "", "location": "POST /chat"},
        {"id": "RT-C", "title": "c", "severity": "HIGH", "passed": True, "skipped": "no key", "location": None}]}
    r = gate.f_redteam(d, POL, "/src")
    assert [x["rule"] for x in r] == ["RT-A"] and r[0]["severity"] == "HIGH" and "leaked" in r[0]["title"]


def test_redteam_crashed_probe_counts_as_failure():
    d = {"summary": {}, "results": [{"id": "RT-X", "title": "x", "severity": "MEDIUM", "passed": False, "evidence": "probe crashed: KeyError", "location": None, "crashed": True}]}
    assert len(gate.f_redteam(d, POL, "/src")) == 1


def test_modelscan_parser():
    d = {"issues": [{"description": "Use of unsafe operator 'system' from module 'posix'", "operator": "system", "module": "posix", "source": "m/evil.pkl", "severity": "CRITICAL"}]}
    r = gate.f_modelscan(d, POL, "/src")
    assert r[0]["severity"] == "CRITICAL" and r[0]["rule"] == "modelscan:system"


def test_exclusions_drop_code_findings_but_never_dependency_cves():
    code = {"path": "vendor/lib/x.py", "category": "SAST"}
    secret = {"path": "legacy/a.env", "category": "Secrets"}
    sca = {"path": "vendor/requirements.txt", "category": "SCA", "all_ids": ["CVE-1"]}
    kept = {"path": "src/app.py", "category": "SAST"}
    out, n = gate.apply_exclusions([code, secret, sca, kept], ["vendor/**", "legacy"])
    assert n == 2 and sca in out and kept in out and code not in out and secret not in out


def test_tool_waivers_are_not_treated_as_finding_exceptions():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "e.json")
    open(p, "w").write('[{"tool": "semgrep", "reason": "r", "approved_by": "a", "expires": "2099-01-01"}]')
    f = [{"fps": ["x"], "rule": "R", "path": "a"}]
    kept, expired = gate.apply_exceptions(f, p)
    assert expired == [] and not kept[0].get("excepted")


if __name__ == "__main__":
    n = fail = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            n += 1
            try:
                fn(); print("  PASS ", name)
            except AssertionError as e:
                fail += 1; print("  FAIL ", name, e)
    print(f"{n - fail}/{n} passed"); sys.exit(1 if fail else 0)

