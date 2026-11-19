#!/usr/bin/env python3
"""secscan dashboard: one place to see every repo's latest security scan. Standard library only (http.server + sqlite3).

CI publishes each scan to POST /api/ingest (Bearer DASHBOARD_INGEST_TOKEN); people view it with HTTP basic auth.
Env: DASHBOARD_PASSWORD (required), DASHBOARD_INGEST_TOKEN (required), DASHBOARD_USER=secscan, DASHBOARD_DB=/data/dashboard.db,
     DASHBOARD_PORT=8090, DASHBOARD_BIND=0.0.0.0, SONAR_PUBLIC_URL (adds a SonarQube link), STALE_DAYS=14, KEEP_SCANS=100
"""
import base64
import datetime as dt
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlparse

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
MAX_BODY = 8 * 1024 * 1024
MAX_FINDINGS = 1500
LOCK = threading.Lock()
FAILS = {}  # ip -> (count, first_ts): slows password guessing


def cfg():
    c = dict(user=os.environ.get("DASHBOARD_USER", "secscan"), password=os.environ.get("DASHBOARD_PASSWORD", ""),
             token=os.environ.get("DASHBOARD_INGEST_TOKEN", ""), db=os.environ.get("DASHBOARD_DB", "/data/dashboard.db"),
             stale=int(os.environ.get("STALE_DAYS", "14")), keep=int(os.environ.get("KEEP_SCANS", "100")),
             sonar=os.environ.get("SONAR_PUBLIC_URL", ""))
    return c


def db(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, repo TEXT, branch TEXT, commit_sha TEXT, run_url TEXT, created TEXT,
        result TEXT, mode TEXT, gate TEXT, preset TEXT, crit INT, high INT, med INT, low INT, new_ch INT, tools_ok INT, tools_total INT,
        summary TEXT, findings TEXT);
        CREATE INDEX IF NOT EXISTS i_repo ON scans(repo, branch, id);""")
    return con


def clip(v, n=300):
    return str(v if v is not None else "")[:n]


def safe_url(u):
    u = clip(u, 500)
    return u if re.match(r"^https?://[^\s<>\"']+$", u) else ""


def ingest(con, c, d):
    s = d.get("summary")
    if not isinstance(s, dict) or "counts" not in s or "tool_status" not in s:
        raise ValueError("payload needs a 'summary' object (summary.json from a scan)")
    repo = clip(d.get("repo") or s.get("target"), 200).strip()
    if not re.match(r"^[A-Za-z0-9_.@/ -]{1,200}$", repo):
        raise ValueError("repo name has unsupported characters")
    branch = clip(d.get("branch") or "unknown", 200)
    cn = s["counts"]
    new = s.get("new_counts", {})
    ts = s["tool_status"]
    fl = []
    for f in (d.get("findings") or [])[:MAX_FINDINGS]:
        if isinstance(f, dict):
            fl.append({k: clip(f.get(k), 300) for k in ("severity", "tool", "rule", "location", "title", "fix")} | {"new": bool(f.get("new")), "excepted": clip(f.get("excepted"), 200)})
    keep = {k: s.get(k) for k in ("target", "date", "gate", "mode", "result", "counts", "new_counts", "tool_status", "by_tool", "preset", "degraded_manifests",
                                  "tools_not_run", "tools_forced", "tool_waivers", "excluded_by_path", "exclude_paths", "exceptions_applied", "expired_exceptions",
                                  "agent_inventory", "redteam", "baseline_used", "sonar_quality_gate_failures")}
    with LOCK:
        con.execute("INSERT INTO scans(repo,branch,commit_sha,run_url,created,result,mode,gate,preset,crit,high,med,low,new_ch,tools_ok,tools_total,summary,findings) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (repo, branch, clip(d.get("commit"), 64), safe_url(d.get("run_url")), dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                     clip(s.get("result"), 200), clip(s.get("mode"), 20), clip(s.get("gate"), 20), clip(s.get("preset"), 20),
                     int(cn.get("CRITICAL", 0)), int(cn.get("HIGH", 0)), int(cn.get("MEDIUM", 0)), int(cn.get("LOW", 0)),
                     int(new.get("CRITICAL", 0)) + int(new.get("HIGH", 0)), sum(1 for v in ts.values() if v == "ok"), len(ts),
                     json.dumps(keep), json.dumps(fl)))
        con.execute("DELETE FROM scans WHERE repo=? AND branch=? AND id NOT IN (SELECT id FROM scans WHERE repo=? AND branch=? ORDER BY id DESC LIMIT ?)",
                    (repo, branch, repo, branch, c["keep"]))
        con.commit()
    return repo


def primary_rows(con):
    """Latest scan per repo, preferring the main/master branch (otherwise the most recent branch)."""
    rows = con.execute("SELECT * FROM scans WHERE id IN (SELECT MAX(id) FROM scans GROUP BY repo, branch)").fetchall()
    best = {}
    for r in rows:
        cur = best.get(r["repo"])
        rank = lambda x: (x["branch"] in ("main", "master"), x["id"])
        if cur is None or rank(r) > rank(cur):
            best[r["repo"]] = r
    return sorted(best.values(), key=lambda r: (-(r["crit"]), -r["high"], r["repo"]))


# ---------------------------------------------------------------- HTML
CSS = """:root{--bg:#f6f7f9;--fg:#1c2330;--mut:#667085;--card:#fff;--line:#e3e6ec;--crit:#b42318;--high:#d9480f;--med:#b7791f;--low:#2563a8;--ok:#1a7f4b;--bad:#b42318;--accent:#2457c5}
@media(prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6e9ef;--mut:#98a2b3;--card:#171c26;--line:#262d3a;--crit:#f97066;--high:#fb923c;--med:#fbbf24;--low:#7fb2ff;--ok:#4ade80;--bad:#f97066;--accent:#7fb2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;gap:16px;align-items:center;padding:12px 24px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:2}
header b{font-size:16px}header a{color:var(--accent);text-decoration:none}header .sp{flex:1}
main{max-width:1250px;margin:0 auto;padding:20px 24px 60px}h1{font-size:20px;margin:6px 0 2px}h2{font-size:15px;margin:26px 0 8px}
.sub{color:var(--mut);margin-bottom:16px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.tile b{display:block;font-size:26px;line-height:1.1}.tile span{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--mut);cursor:pointer;white-space:nowrap;user-select:none}
tr:last-child td{border-bottom:0}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}a{color:var(--accent)}code{font:12px ui-monospace,monospace;word-break:break-all}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid currentColor}.PASS{color:var(--ok)}.FAIL{color:var(--bad)}.STALE{color:var(--med)}
.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}.INFO{color:var(--mut)}.z{color:var(--mut)}
input,select{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font:inherit}.bar{display:flex;gap:8px;margin:0 0 10px;flex-wrap:wrap}
.note{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--med);border-radius:6px;padding:8px 12px;margin:6px 0}.mut{color:var(--mut)}
svg.chart{max-width:640px}#ft td:nth-child(4){min-width:260px}svg text{fill:var(--mut);font-size:11px}.tw{overflow-x:auto}@media(max-width:700px){main{padding:14px 12px}header{padding:10px 12px}}"""
JS = """function sortT(t,i,num){const b=t.tBodies[0],r=[...b.rows],d=t.dataset.d=t.dataset.d==='1'?'-1':'1';
r.sort((x,y)=>{let a=x.cells[i].dataset.v??x.cells[i].textContent,c=y.cells[i].dataset.v??y.cells[i].textContent;
if(num){a=+a;c=+c}return (a>c?1:a<c?-1:0)*d});r.forEach(x=>b.appendChild(x))}
document.querySelectorAll('table.s th').forEach((th,i)=>th.addEventListener('click',()=>sortT(th.closest('table'),i,th.classList.contains('n'))));
function filt(id,tid){const q=document.getElementById(id);const f=()=>{const v=q.value.toLowerCase(),s=(document.getElementById(id+'sev')||{}).value||'';
document.querySelectorAll('#'+tid+' tbody tr').forEach(r=>{r.style.display=(r.textContent.toLowerCase().includes(v)&&(!s||r.dataset.sev===s))?'':'none'})};
q.addEventListener('input',f);const e=document.getElementById(id+'sev');if(e)e.addEventListener('change',f)}
document.querySelectorAll('[data-filter]').forEach(e=>filt(e.id,e.dataset.filter))"""


def e(x):
    return html.escape(str(x if x is not None else ""), quote=True)


def ago(iso):
    try:
        t = dt.datetime.fromisoformat(iso)
        s = (dt.datetime.now(dt.timezone.utc) - t).total_seconds()
    except Exception:
        return "?"
    return "just now" if s < 90 else f"{int(s // 60)} min ago" if s < 5400 else f"{int(s // 3600)} h ago" if s < 172800 else f"{int(s // 86400)} days ago"


def age_days(iso):
    try:
        return (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(iso)).days
    except Exception:
        return 0


def spark(vals, w=90, h=22):
    if len(vals) < 2:
        return '<span class="z">-</span>'
    m = max(vals) or 1
    pts = " ".join(f"{i * (w - 2) / (len(vals) - 1) + 1:.1f},{h - 2 - v * (h - 4) / m:.1f}" for i, v in enumerate(vals))
    return f'<svg width="{w}" height="{h}" role="img" aria-label="trend of Critical+High findings"><polyline points="{pts}" fill="none" stroke="var(--accent)" stroke-width="1.6"/></svg>'


def page(title, body, c, nonce, user=""):
    son = f'<a href="{e(c["sonar"])}" target="_blank" rel="noopener">SonarQube</a>' if c["sonar"] else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>'
            f'<style nonce="{nonce}">{CSS}</style></head><body><header><b>secscan</b><a href="/">Portfolio</a>{son}<span class="sp"></span><span class="mut">{e(user)}</span></header>'
            f'<main>{body}</main><script nonce="{nonce}">{JS}</script></body></html>')


def portfolio(con, c):
    rows = primary_rows(con)
    stale = [r for r in rows if age_days(r["created"]) > c["stale"]]
    failing = [r for r in rows if r["result"].startswith("FAIL")]
    degraded = [r for r in rows if r["tools_ok"] < r["tools_total"]]
    tiles = [("Repos reporting", len(rows), ""), ("Gate failing", len(failing), "FAIL" if failing else ""), ("Critical (open)", sum(r["crit"] for r in rows), "CRITICAL"),
             ("High (open)", sum(r["high"] for r in rows), "HIGH"), (f"Stale (> {c['stale']} days)", len(stale), "STALE" if stale else ""),
             ("Tool problems", len(degraded), "STALE" if degraded else "")]
    t = "".join(f'<div class="tile"><b class="{k}">{v}</b><span>{e(n)}</span></div>' for n, v, k in tiles)
    trs = []
    for r in rows:
        hist = [x["crit"] + x["high"] for x in con.execute("SELECT crit,high FROM scans WHERE repo=? AND branch=? ORDER BY id DESC LIMIT 20", (r["repo"], r["branch"]))][::-1]
        res = r["result"].split(" ")[0]
        old = age_days(r["created"]) > c["stale"]
        cov = f'{r["tools_ok"]}/{r["tools_total"]}'
        stale_b = ' <span class="badge STALE">stale</span>' if old else ""
        trs.append(f'<tr><td data-v="{e(r["repo"])}"><a href="/repo/{quote(r["repo"], safe="/")}">{e(r["repo"])}</a></td><td>{e(r["branch"])}</td>'
                   f'<td data-v="{e(r["created"])}">{e(ago(r["created"]))}{stale_b}</td>'
                   f'<td><span class="badge {res}">{e(res)}</span><span class="mut"> {e(r["mode"])}</span></td>'
                   f'<td class="n CRITICAL">{r["crit"]}</td><td class="n HIGH">{r["high"]}</td><td class="n">{r["new_ch"]}</td>'
                   f'<td class="n{" STALE" if r["tools_ok"] < r["tools_total"] else ""}" data-v="{r["tools_ok"] - r["tools_total"]}">{cov}</td><td>{e(r["preset"] or "-")}</td><td>{spark(hist)}</td></tr>')
    if not trs:
        trs = ['<tr><td colspan="10" class="mut">No scans published yet. See docs/dashboard.md: set SEC_DASHBOARD_URL and the SECSCAN_DASHBOARD_TOKEN secret in CI.</td></tr>']
    return (f'<h1>Portfolio</h1><div class="sub">Latest scan per repository (main/master when available). Updated live as CI publishes.</div><div class="tiles">{t}</div>'
            '<div class="bar"><input id="q" data-filter="pt" placeholder="Filter repositories..." aria-label="Filter repositories"></div><div class="tw">'
            '<table class="s" id="pt"><thead><tr><th>Repository</th><th>Branch</th><th>Last scan</th><th>Gate</th><th class="n">Critical</th><th class="n">High</th>'
            '<th class="n" title="Critical+High not in the baseline">New C+H</th><th class="n" title="tools that ran OK / tools run">Tools ok</th><th>Preset</th><th>Trend (C+H)</th></tr></thead>'
            f'<tbody>{"".join(trs)}</tbody></table></div>')


def trend_svg(points):
    if len(points) < 2:
        return '<p class="mut">The trend appears after two or more scans.</p>'
    w, h, l, b = 640, 150, 34, 20
    m = max(max(p) for p in points) or 1
    def line(i, col):
        pts = " ".join(f"{l + k * (w - l - 8) / (len(points) - 1):.1f},{h - b - p[i] * (h - b - 8) / m:.1f}" for k, p in enumerate(points))
        return f'<polyline points="{pts}" fill="none" stroke="var({col})" stroke-width="2"/>'
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" class="chart" role="img" aria-label="Critical, High and Medium findings over the last {len(points)} scans">'
            f'<text x="2" y="12">{m}</text><text x="2" y="{h - b}">0</text><line x1="{l}" y1="{h - b}" x2="{w - 8}" y2="{h - b}" stroke="var(--line)"/>'
            f'{line(2, "--med")}{line(1, "--high")}{line(0, "--crit")}'
            f'<text x="{l}" y="{h - 4}">older</text><text x="{w - 36}" y="{h - 4}">newest</text></svg>'
            '<div class="mut"><span class="CRITICAL">&#9632; Critical</span> &nbsp; <span class="HIGH">&#9632; High</span> &nbsp; <span class="MEDIUM">&#9632; Medium</span></div>')


def repo_page(con, c, repo, branch):
    branches = [r["branch"] for r in con.execute("SELECT DISTINCT branch FROM scans WHERE repo=? ORDER BY branch", (repo,))]
    if not branches:
        return None
    if branch not in branches:
        branch = "main" if "main" in branches else "master" if "master" in branches else branches[0]
    r = con.execute("SELECT * FROM scans WHERE repo=? AND branch=? ORDER BY id DESC LIMIT 1", (repo, branch)).fetchone()
    s = json.loads(r["summary"])
    fl = json.loads(r["findings"])
    hist = con.execute("SELECT id,created,result,crit,high,med,commit_sha,run_url FROM scans WHERE repo=? AND branch=? ORDER BY id DESC LIMIT 30", (repo, branch)).fetchall()
    res = r["result"].split(" ")[0]
    bsel = " ".join(f'<a href="/repo/{quote(repo, safe="/")}?branch={quote(b)}">{"<b>" + e(b) + "</b>" if b == branch else e(b)}</a>' for b in branches)
    cards = "".join(f'<div class="tile"><b class="{k}">{s["counts"].get(k, 0)}</b><span>{k.title()} ({s.get("new_counts", {}).get(k, 0)} new)</span></div>' for k in SEV[:4])
    notes = []
    for t, why in (s.get("tools_not_run") or {}).items():
        notes.append(f'<b>{e(t)}</b> did not run: {e(why)}')
    notes += [f'<b>{e(t)}</b> is required by policy, so it ran although set to off' for t in s.get("tools_forced") or []]
    notes += [f'waiver in use: <b>{e(w.get("tool"))}</b> until {e(w.get("expires"))}, approved by {e(w.get("approved_by"))}: {e(w.get("reason"))}' for w in s.get("tool_waivers") or []]
    notes += [e(m) for m in s.get("degraded_manifests") or []]
    if s.get("excluded_by_path"):
        notes.append(f'{e(s["excluded_by_path"])} code finding(s) left out by SEC_EXCLUDE_PATHS')
    notes += [e(m) for m in s.get("sonar_quality_gate_failures") or []]
    tools = "".join(f'<tr><td>{e(t)}</td><td class="{"PASS" if v == "ok" else "FAIL"}">{e(v)}</td><td class="n">{e((s.get("by_tool") or {}).get(t, 0))}</td></tr>' for t, v in s["tool_status"].items())
    frows = "".join(f'<tr data-sev="{e(f["severity"])}"><td><span class="badge {e(f["severity"])}">{e(f["severity"])}</span></td><td>{e(f["tool"])}</td><td>{e(f["rule"])}</td><td><code>{e(f["location"])}</code></td>'
                    f'<td>{e(f["title"])}{"<div class=mut>Fix: " + e(f["fix"]) + "</div>" if f.get("fix") else ""}{"<div class=mut>Exception: " + e(f["excepted"]) + "</div>" if f.get("excepted") else ""}</td>'
                    f'<td>{"new" if f.get("new") else ""}</td></tr>' for f in sorted(fl, key=lambda x: (SEV.index(x["severity"]) if x["severity"] in SEV else 9, x["tool"])))
    hrows = "".join(f'<tr><td>{e(ago(x["created"]))}</td><td><span class="badge {x["result"].split(" ")[0]}">{e(x["result"].split(" ")[0])}</span></td><td class="n">{x["crit"]}</td><td class="n">{x["high"]}</td><td class="n">{x["med"]}</td>'
                    f'<td><code>{e(x["commit_sha"][:10])}</code></td><td>{"<a href=" + chr(34) + e(x["run_url"]) + chr(34) + " target=_blank rel=noopener>CI run</a>" if x["run_url"] else ""}</td></tr>' for x in hist)
    cut = f'<p class="mut">Showing the first {len(fl)} findings (sorted by severity); the full list is in the CI report artifact.</p>' if len(fl) >= MAX_FINDINGS else ""
    ci = f' · <a href="{e(r["run_url"])}" target="_blank" rel="noopener">CI run</a>' if r["run_url"] else ""
    return (f'<h1>{e(repo)} <span class="badge {res}">{e(res)}</span></h1><div class="sub">branch {bsel} · scanned {e(ago(r["created"]))} · gate {e(r["gate"])} ({e(r["mode"])}) · preset {e(r["preset"] or "-")} · commit <code>{e(r["commit_sha"][:10])}</code>{ci}</div>'
            f'<div class="tiles">{cards}</div>{"".join(f"<div class=note>{n}</div>" for n in notes)}'
            f'<h2>Trend</h2>{trend_svg([(x["crit"], x["high"], x["med"]) for x in hist][::-1])}'
            f'<h2>Tool coverage</h2><div class="tw"><table><thead><tr><th>Tool</th><th>Status</th><th class="n">Findings</th></tr></thead><tbody>{tools}</tbody></table></div>'
            f'<h2>Findings</h2><div class="bar"><input id="fq" data-filter="ft" placeholder="Search rule, file, text..." aria-label="Search findings"><select id="fqsev" aria-label="Severity"><option value="">All severities</option>'
            f'{"".join(f"<option>{k}</option>" for k in SEV[:4])}</select></div><div class="tw"><table id="ft"><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Location</th><th>Detail</th><th></th></tr></thead><tbody>{frows}</tbody></table></div>{cut}'
            f'<h2>Scan history</h2><div class="tw"><table><thead><tr><th>When</th><th>Gate</th><th class="n">Crit</th><th class="n">High</th><th class="n">Med</th><th>Commit</th><th></th></tr></thead><tbody>{hrows}</tbody></table></div>')


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "secscan-dashboard"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _html(self, code, title, body):
        n = secrets.token_urlsafe(12)
        self._send(code, page(title, body, self.server.c, n, self.server.c["user"]),
                   extra={"Content-Security-Policy": f"default-src 'none'; style-src 'nonce-{n}'; script-src 'nonce-{n}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})

    def _viewer_ok(self):
        ip = self.client_address[0]
        cnt, first = FAILS.get(ip, (0, time.time()))
        if time.time() - first > 300:
            cnt, first = 0, time.time()
        if cnt >= 10:
            self._send(429, "too many failed logins; wait 5 minutes", "text/plain")
            return False
        h = self.headers.get("Authorization", "")
        ok = False
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                ok = hmac.compare_digest(u, self.server.c["user"]) & hmac.compare_digest(p, self.server.c["password"])
            except Exception:
                ok = False
        if ok:
            FAILS.pop(ip, None)
            return True
        FAILS[ip] = (cnt + 1, first)
        self._send(401, "login required", "text/plain", {"WWW-Authenticate": 'Basic realm="secscan dashboard", charset="UTF-8"'})
        return False

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send(200, "ok", "text/plain")
        if not self._viewer_ok():
            return
        con = db(self.server.c["db"])
        try:
            if u.path == "/":
                return self._html(200, "secscan portfolio", portfolio(con, self.server.c))
            if u.path.startswith("/repo/"):
                q = dict(x.split("=", 1) for x in u.query.split("&") if "=" in x)
                body = repo_page(con, self.server.c, unquote(u.path[6:]), unquote(q.get("branch", "")))
                return self._html(200, "secscan repo", body) if body else self._html(404, "not found", "<h1>Not found</h1><p>No scans for that repository.</p>")
            if u.path == "/api/repos":
                rows = [{k: r[k] for k in ("repo", "branch", "created", "result", "crit", "high", "med", "low", "new_ch", "tools_ok", "tools_total", "preset")} for r in primary_rows(con)]
                return self._send(200, json.dumps(rows), "application/json")
            return self._html(404, "not found", "<h1>Not found</h1>")
        finally:
            con.close()

    def do_POST(self):
        if urlparse(self.path).path != "/api/ingest":
            return self._send(404, "not found", "text/plain")
        tok = self.headers.get("Authorization", "")[7:] if self.headers.get("Authorization", "").startswith("Bearer ") else ""
        if not hmac.compare_digest(tok.encode(), self.server.c["token"].encode()):
            time.sleep(0.5)
            return self._send(401, '{"error":"bad token"}', "application/json")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n <= 0 or n > MAX_BODY:
            self.close_connection = True  # the unread body must not be parsed as the next request
            return self._send(413, '{"error":"body missing or larger than 8 MB"}', "application/json", {"Connection": "close"})
        raw = self.rfile.read(n)
        con = db(self.server.c["db"])
        try:
            repo = ingest(con, self.server.c, json.loads(raw))
        except (ValueError, TypeError, KeyError) as ex:
            return self._send(400, json.dumps({"error": str(ex)[:200]}), "application/json")
        finally:
            con.close()
        self._send(200, json.dumps({"ok": True, "repo": repo}), "application/json")


def main():
    c = cfg()
    if len(c["password"]) < 12 or len(c["token"]) < 20:
        sys.exit("DASHBOARD_PASSWORD (>= 12 chars) and DASHBOARD_INGEST_TOKEN (>= 20 chars) must be set: there are no default credentials")
    os.makedirs(os.path.dirname(c["db"]) or ".", exist_ok=True)
    db(c["db"]).close()
    srv = ThreadingHTTPServer((os.environ.get("DASHBOARD_BIND", "0.0.0.0"), int(os.environ.get("DASHBOARD_PORT", "8090"))), H)
    srv.c = c
    print(f"secscan dashboard on {srv.server_address[0]}:{srv.server_address[1]} (db {c['db']})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
