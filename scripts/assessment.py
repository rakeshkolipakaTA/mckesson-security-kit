"""Warden security assessment report: the one-document view for a security or audit team (assessment.html).

summary.html is the working report for developers. This one answers the questions a reviewer asks: what was assessed, which checks ran
(and which did not, and why), what the policy was, what the verdict is and why, what has been accepted as an exception, and what the
assessment cannot tell you. It is derived only from data the scan already recorded, so it can be regenerated from summary.json and
findings.json. It is an automated assessment, not a certification, and it says so.
"""
import hashlib, html, os

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
AREAS = [
    ("Secrets in code and history", ["gitleaks", "gitleaks-history"]),
    ("Vulnerable libraries (SCA)", ["trivy-fs", "pip-audit", "npm-audit", "dependency-check"]),
    ("Code weaknesses (SAST)", ["semgrep", "bandit", "eslint", "sonarqube"]),
    ("Infrastructure and containers", ["trivy-image", "k8s-posture"]),
    ("CI/CD pipelines and repository settings", ["workflow-scan", "repo-posture"]),
    ("Software bill of materials", ["sbom"]),
    ("AI and agent code", ["agent-scan", "modelscan", "redteam"]),
    ("Running application (dynamic tests)", ["zap", "api-fuzz", "exposure"]),
]
VERDICTS = {  # key: (headline, css class, one-line meaning)
    "passed": ("PASSED", "pass", "Every required check ran and nothing breaks the policy."),
    "conditions": ("PASSED WITH CONDITIONS", "cond", "Nothing breaks the policy, but the conditions below limit what this result means."),
    "incomplete": ("INCOMPLETE", "inc", "A required check did not produce a result, so the code could not be fully assessed."),
    "failed": ("FAILED", "fail", "Findings break the policy for this gate."),
}


def verdict(summary, findings, blocking):
    """(key, reasons, conditions). A broken scanner is never a pass: a missing result makes the assessment INCOMPLETE."""
    counts, status = summary["counts"], summary.get("tool_status", {})
    bad = {t: s for t, s in status.items() if s != "ok"}
    qg = summary.get("sonar_quality_gate_failures", [])
    reasons, cond = [], []
    if blocking:
        sev = ", ".join(f"{sum(1 for f in blocking if f['severity'] == s)} {LABEL[s]}" for s in SEV if any(f["severity"] == s for f in blocking))
        reasons.append(f"{len(blocking)} finding(s) break the {summary['gate']} gate policy ({sev}).")
    reasons += [f"SonarQube quality gate: {m}" for m in qg]
    if bad:
        reasons.append("No usable result from: " + ", ".join(f"{t} ({s})" for t, s in bad.items()) + ".")
    if summary.get("tools_not_run"):
        cond += [f"{t} was switched off" + (f" ({r})" if r and r != "turned off" else "") + ", so that area is not assessed." for t, r in summary["tools_not_run"].items()]
    cond += [f"Tool waiver until {w['expires']}, approved by {w['approved_by']}: {w['tool']} ({w['reason']})" for w in summary.get("tool_waivers", [])]
    cond += list(summary.get("degraded_manifests", []))
    if summary.get("excluded_by_path"):
        cond.append(f"{summary['excluded_by_path']} code finding(s) were left out by the excluded paths: {', '.join(summary.get('exclude_paths', []))}.")
    if summary.get("overdue"):
        cond.append(f"{summary['overdue']} baselined finding(s) are past their fix deadline.")
    if summary.get("expired_exceptions"):
        cond.append(f"{len(summary['expired_exceptions'])} exception(s) have expired.")
    ch = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    if ch and not blocking:
        cond.append(f"{ch} open Critical or High finding(s) do not block under this policy (existing findings in the baseline, or below the gate's threshold).")
    if blocking or qg:
        key = "failed"
    elif bad:
        key = "incomplete"
    elif cond:
        key = "conditions"
    else:
        key = "passed"
    return key, reasons, cond


def tool_state(t, summary, worst, n):
    """(label, css, detail) for one tool, from what ran and what the plan said."""
    st = summary.get("tool_status", {})
    plan = summary.get("tool_plan", {}).get(t)
    if t in st:
        if st[t] == "ok":
            return "Checked", "ok", (f"{n} open finding(s), worst {LABEL[worst]}" if n else "No findings")
        return "Failed to run", "bad", f"no usable result ({st[t]})"
    if plan and not plan.get("run"):
        r = plan.get("reason", "")
        return ("Turned off", "warn", r) if r.startswith("turned off") else ("Not run", "mut", r)
    return "", "", ""


def sha(path):
    try:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        return ""


def render(summary, findings, blocking, meta, out_dir=None):
    e = html.escape
    key, reasons, cond = verdict(summary, findings, blocking)
    head, cls, mean = VERDICTS[key]
    live = [f for f in findings if not f.get("excepted")]
    by_tool, worst = {}, {}
    for f in live:
        for t in f["tools"]:
            by_tool[t] = by_tool.get(t, 0) + 1
            if t not in worst or SEV.index(f["severity"]) < SEV.index(worst[t]):
                worst[t] = f["severity"]
    ran = [t for t, s in summary.get("tool_status", {}).items() if s == "ok"]
    mode = summary["mode"]
    mode_note = ("Report-only: the build was not blocked. This verdict shows how the code is judged under the gate policy below, so it is what would "
                 "happen once the gate is enforced." if mode == "report-only" else "Enforcing: a failed verdict blocks the build.")
    rows = []
    for area, tools in AREAS:
        states = [(t, tool_state(t, summary, worst.get(t, "INFO"), by_tool.get(t, 0))) for t in tools]
        states = [(t, s) for t, s in states if s[0]]
        if not states:
            continue
        rows.append(f'<tr class="area"><td colspan="3">{e(area)}</td></tr>')
        rows += [f'<tr><td>{e(t)}</td><td class="{c}">{e(l)}</td><td>{e(d)}</td></tr>' for t, (l, c, d) in states]
    gate = meta.get("policy", {})
    sev_rows = "".join(f'<tr><td><span class="sev {s}">{LABEL[s]}</span></td><td>{summary["counts"][s]}</td><td>{summary["new_counts"][s]}</td>'
                       f'<td>{"Blocks when new" if s in meta.get("policy", {}).get("block_new", []) else "Does not block"}</td></tr>' for s in SEV)
    top = sorted(blocking, key=lambda f: (SEV.index(f["severity"]), f["tool"], f["location"]))[:15]
    top_html = ""
    if top:
        top_html = ('<h2>Findings that break the policy</h2><table><tr><th>Severity</th><th>Where</th><th>What</th></tr>' + "".join(
            f'<tr><td><span class="sev {f["severity"]}">{LABEL[f["severity"]]}</span></td><td><code>{e(f["location"])}</code></td><td>{e(f["title"])}'
            + (f'<div class="fx">Fix: {e(f["fix"])}</div>' if f.get("fix") else "") + "</td></tr>" for f in top) + "</table>"
            + (f'<p class="mut">The {len(blocking) - len(top)} others are in summary.html.</p>' if len(blocking) > len(top) else ""))
    exc = [f for f in findings if f.get("excepted")]
    exc_html = "<h2>Accepted exceptions and waivers</h2>"
    if exc or summary.get("tool_waivers") or summary.get("expired_exceptions"):
        exc_html += "<table><tr><th>What</th><th>Where / tool</th><th>Basis</th></tr>"
        exc_html += "".join(f'<tr><td>{e(f["title"])} ({LABEL[f["severity"]]})</td><td><code>{e(f["location"])}</code></td><td>{e(f["excepted"])}</td></tr>' for f in exc[:25])
        exc_html += "".join(f'<tr><td>Tool waiver: {e(w["tool"])}</td><td>-</td><td>{e(w["reason"])} (approved by {e(w["approved_by"])}, until {e(w["expires"])})</td></tr>'
                            for w in summary.get("tool_waivers", []))
        exc_html += "".join(f'<tr><td class="bad">Expired exception</td><td>-</td><td>{e(str(x))}</td></tr>' for x in summary.get("expired_exceptions", []))
        exc_html += "</table>" + (f'<p class="mut">{len(exc) - 25} more exceptions are in summary.html.</p>' if len(exc) > 25 else "")
    else:
        exc_html += '<p class="mut">None. No finding or check has been excused.</p>'
    xw = summary.get("crosswalk") or []
    xw_html = ""
    if xw:
        xw_html = ("<h2>Controls evidenced</h2><table><tr><th>Control</th><th>Open findings</th><th>Standards</th></tr>" + "".join(
            f'<tr><td>{e(x["name"])}</td><td>{x["total"]}</td><td>{e("; ".join(f"{k}: {v}" for k, v in x["standards"].items()))}</td></tr>' for x in xw) + "</table>")
    pol = (f'<tr><td>Gate</td><td>{e(summary["gate"])}</td></tr><tr><td>Preset</td><td>{e(str(summary.get("preset") or "custom"))}</td></tr>'
           f'<tr><td>New findings that block</td><td>{e(", ".join(LABEL[s] for s in gate.get("block_new", [])) or "none")}</td></tr>'
           f'<tr><td>Existing (baselined) findings that block</td><td>{e(", ".join(LABEL[s] for s in gate.get("block_existing", [])) or "none")}</td></tr>'
           f'<tr><td>Fix deadlines (days)</td><td>{e(", ".join(f"{LABEL[s]} {d}" for s, d in (meta.get("sla_days") or {}).items()) or "not set")}</td></tr>'
           f'<tr><td>Baseline</td><td>{"in use (older findings are tracked separately)" if summary["baseline_used"] else "not used (every finding counts as new)"}</td></tr>')
    ev = "".join(f'<tr><td>{e(n)}</td><td><code>{e(h)}</code></td></tr>' for n, h in meta.get("hashes", {}).items() if h)
    why = "".join(f"<li>{e(r)}</li>" for r in reasons) or f"<li>All {len(ran)} checks that apply ran, and no finding breaks the policy.</li>"
    conds = ("<h3>Conditions</h3><ul>" + "".join(f"<li>{e(c)}</li>" for c in cond) + "</ul>") if cond else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security assessment - {e(summary['target'])}</title><style>
:root{{--bg:#fff;--fg:#1d2433;--mut:#5b6678;--line:#d5dae3;--card:#f6f8fb;--crit:#a3122a;--high:#d9480f;--med:#b7791f;--low:#2b6cb0;--ok:#1a7f4b;--warn:#9a6700;--inc:#6b4fbb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12161f;--fg:#e6e9ef;--mut:#9aa4b5;--line:#2b3342;--card:#1a202c;--crit:#ff6b81;--high:#ff9a5c;--med:#f0c15a;--low:#6cb2ff;--ok:#4cc38a;--warn:#e3b341;--inc:#b9a5ff}}}}
@page{{size:A4;margin:16mm}} @media print{{:root{{--bg:#fff;--fg:#1d2433;--mut:#5b6678;--line:#d5dae3;--card:#f6f8fb}} body{{padding:0}} h2{{break-after:avoid}} tr,.sign{{break-inside:avoid}}}}
body{{font:14px/1.55 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;padding:28px;max-width:960px}}
h1{{font-size:24px;margin:0}} h2{{font-size:16px;margin:28px 0 6px;border-bottom:2px solid var(--line);padding-bottom:4px}} h3{{font-size:14px;margin:14px 0 4px}}
.mut,.fx{{color:var(--mut)}} .fx{{font-size:12px}} code{{font-size:12px;word-break:break-all}}
table{{border-collapse:collapse;width:100%;margin:6px 0}} th,td{{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}} th{{color:var(--mut);font-weight:600}}
tr.area td{{background:var(--card);font-weight:700}} .ok{{color:var(--ok);font-weight:600}} .bad{{color:var(--crit);font-weight:700}} .warn{{color:var(--warn);font-weight:600}}
.sev{{font-weight:700;font-size:12px}} .sev.CRITICAL{{color:var(--crit)}} .sev.HIGH{{color:var(--high)}} .sev.MEDIUM{{color:var(--med)}} .sev.LOW{{color:var(--low)}}
.meta td:first-child{{width:200px;color:var(--mut)}}
.verdict{{border-radius:10px;padding:16px 20px;margin:18px 0;color:#fff}} .verdict.pass{{background:var(--ok)}} .verdict.cond{{background:#9a6700}} .verdict.fail{{background:#a3122a}} .verdict.inc{{background:#6b4fbb}}
.verdict b{{font-size:26px;display:block}} .verdict p{{margin:4px 0 0}} .verdict ul{{margin:8px 0 0;padding-left:20px}}
.sign{{display:grid;grid-template-columns:1fr 1fr;gap:28px 24px;margin-top:10px}} .sign div{{border-bottom:1px solid var(--fg);height:34px;font-size:12px;color:var(--mut)}}
</style></head><body>
<h1>Security assessment report</h1>
<div class="mut">Issued by Warden {e(meta.get('version', 'unknown'))} &middot; {e(summary['date'])}</div>
<table class="meta">
<tr><td>Application / repository</td><td><b>{e(summary['target'])}</b></td></tr>
<tr><td>Commit</td><td><code>{e(meta.get('commit') or 'not available')}</code></td></tr>
<tr><td>Branch</td><td>{e(meta.get('branch') or 'not available')}</td></tr>
<tr><td>Assessment type</td><td>Automated security scan ({e(summary['gate'])} gate, {e(mode)})</td></tr>
</table>
<div class="verdict {cls}"><b>{e(head)}</b><p>{e(mean)}</p><ul>{why}</ul></div>
<p class="mut">{e(mode_note)}</p>{conds}
<h2>Summary</h2>
<table><tr><th>Severity</th><th>Open</th><th>New since baseline</th><th>Under this policy</th></tr>{sev_rows}</table>
<p>{len(ran)} checks ran and produced a result. {len(live)} open finding(s); {len(exc)} covered by an exception.</p>
{top_html}
<h2>What was checked</h2>
<table><tr><th>Check</th><th>Status</th><th>Result</th></tr>{''.join(rows)}</table>
<h2>Policy applied</h2><table class="meta">{pol}</table>
{exc_html}{xw_html}
<h2>Basis and limits of this assessment</h2>
<ul>
<li>This is an <b>automated</b> assessment of the repository contents at the commit above. It is not a penetration test, a code review by a person, or a certification.</li>
<li>Scanners find known patterns: published vulnerabilities in libraries, known insecure code and configuration, and exposed secrets. A clean result means they found nothing, not that nothing exists.</li>
<li>Only the checks listed above were run. A check that is not applicable, turned off or waived is shown with its reason, and its area is not assessed.</li>
<li>Dynamic tests (the running application) are included only when they were requested and are listed above.</li>
<li>The result is valid for this commit only. A new commit needs a new assessment.</li>
</ul>
<h2>Evidence</h2>
<p class="mut">SHA-256 of the files this assessment was built from, so a copy of the report can be matched to the scan output.</p>
<table><tr><th>File</th><th>SHA-256</th></tr>{ev}</table>
<h2>Review and sign-off</h2>
<p class="mut">Completed by a person if your process needs one. Warden does not fill this in.</p>
<div class="sign"><div>Reviewer name</div><div>Role</div><div>Decision (accepted / accepted with actions / rejected)</div><div>Date</div><div>Actions agreed</div><div>Signature</div></div>
<p class="mut" style="margin-top:24px">This report can contain code paths and metadata about findings. Share it only with people who should see them.</p>
</body></html>"""


def write(path, summary, findings, blocking, meta):
    d = os.path.dirname(path)
    meta = dict(meta)
    meta["hashes"] = {n: sha(os.path.join(d, n)) for n in ("findings.json", "summary.json", "results.sarif")}
    open(path, "w").write(render(summary, findings, blocking, meta))
