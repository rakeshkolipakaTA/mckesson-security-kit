#!/usr/bin/env python3
"""Turn a scan's new / overdue Critical+High findings into tickets: GitHub issues, Jira issues, Azure DevOps work items.

  tickets.py [--report DIR] [--target github|jira|azure|all] [--apply] [options]

DRY-RUN by default: prints what it would create (and which tickets already exist). --apply creates them.
Findings are grouped (dependency CVEs per package+manifest; everything else per rule+file), one ticket per group, and each group
carries a stable label  warden-gk-<id>  so running again never creates a duplicate (and a closed ticket is not re-opened or re-created).
Nothing sensitive is sent: titles come from the already-redacted report and long token-like strings are scrubbed again.

Which findings:  severity >= --min-severity (default high), not excepted, and  NEW (not in the baseline)  or  OVERDUE (past the SLA, per the dashboard)
                 [--dashboard URL + WARDEN_DASHBOARD_TOKEN]  or  everything with --include-existing.

Credentials come from the environment (CI secrets), never from files:
  GitHub : GITHUB_TOKEN (issues:write)   repo = --repo or GITHUB_REPOSITORY      [GITHUB_API_URL for GitHub Enterprise]
  Jira   : JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT   [JIRA_ISSUE_TYPE=Bug]
  Azure  : AZDO_ORG_URL (https://dev.azure.com/<org>), AZDO_PROJECT, AZDO_TOKEN (a PAT with Work Items read/write)
http:// is refused except for localhost (or --allow-http): tokens must not travel in clear text.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
LOCAL = ("localhost", "127.0.0.1", "::1")


# ---------------------------------------------------------------- selection and grouping
def scrub(text, n=160):
    """Remove anything that looks like a credential, then clip."""
    t = str(text or "").replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\b(?:ghp|gho|ghs|github_pat|glpat|xox[bap]|sk|pk|AKIA|ASIA)[-_A-Za-z0-9]{12,}", "<redacted>", t)
    t = re.sub(r"\b(?=[A-Za-z0-9_\-]{28,}\b)(?=\w*\d)(?=\w*[A-Za-z])[A-Za-z0-9_\-]+", "<redacted>", t)
    return t[:n]


def group_key(f):
    cat = str(f.get("category") or "")
    path = f.get("path") or str(f.get("location") or "").split(":")[0]
    if cat.startswith("SCA") or f.get("all_ids"):
        loc = str(f.get("location") or "")
        pkg = loc.split(": ", 1)[1] if ": " in loc else loc
        bits = pkg.rsplit(" ", 1)
        pkg = bits[0] if len(bits) == 2 and bits[1][:1].isdigit() else pkg
        return "sca|%s|%s" % (path, pkg), ("Upgrade %s in %s" % (pkg, path)), pkg
    return "rule|%s|%s" % (f.get("rule"), path), "%s in %s" % (f.get("rule"), path), str(f.get("rule"))


def select(findings, min_sev, include_existing, overdue_fps):
    keep = []
    cut = SEV.index(min_sev.upper())
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        if sev not in SEV or SEV.index(sev) > cut or f.get("excepted"):
            continue
        if include_existing or f.get("new") or f.get("fingerprint") in overdue_fps:
            keep.append(dict(f, _overdue=f.get("fingerprint") in overdue_fps))
    return keep


def build_groups(findings):
    groups = {}
    for f in findings:
        key, title, _ = group_key(f)
        g = groups.setdefault(key, dict(key=key, title=title, items=[], gk=hashlib.sha256(key.encode()).hexdigest()[:12]))
        g["items"].append(f)
    out = []
    for g in groups.values():
        g["items"].sort(key=lambda x: SEV.index(str(x["severity"]).upper()))
        g["severity"] = str(g["items"][0]["severity"]).upper()
        n = len(g["items"])
        g["title"] = ("[warden] %s %s%s" % (g["severity"], g["title"], " (%d findings)" % n if n > 1 else ""))[:120]
        g["label"] = "warden-gk-" + g["gk"]
        out.append(g)
    return sorted(out, key=lambda g: (SEV.index(g["severity"]), -len(g["items"]), g["title"]))


def body_for(g, ctx):
    L = ["Found by the warden pipeline scan (%s, branch `%s`, commit `%s`)." % (ctx["repo"], ctx["branch"], (ctx["commit"] or "")[:10]), ""]
    if ctx.get("run"):
        L += ["Run: %s" % ctx["run"], ""]
    L += ["| Severity | Finding | Location | What | Fix |", "|---|---|---|---|---|"]
    for f in g["items"][:25]:
        L.append("| %s%s | %s | `%s` | %s | %s |" % (f["severity"], " (overdue)" if f.get("_overdue") else "", scrub(f.get("rule"), 60), scrub(f.get("location"), 120).replace("|", "/"),
                                                   scrub(f.get("title"), 160).replace("|", "/"), scrub(f.get("fix") or "", 100).replace("|", "/")))
    if len(g["items"]) > 25:
        L.append("\n...and %d more in the report." % (len(g["items"]) - 25))
    L += ["", "Fix it, or add a time-boxed exception (`.security/exceptions.json`). The remediation SLA is in the central policy.",
          "", "<!-- warden:gk=%s -->" % g["gk"]]
    return "\n".join(L)


# ---------------------------------------------------------------- HTTP
class Api:
    def __init__(self, base, headers, allow_http, delay):
        u = urllib.parse.urlparse(base)
        if u.scheme != "https" and not (u.scheme == "http" and (allow_http or u.hostname in LOCAL)):
            raise SystemExit("refusing to send a token over %s://%s: use https (or --allow-http for a trusted internal server)" % (u.scheme, u.hostname))
        self.base, self.headers, self.delay, self.last = base.rstrip("/"), headers, delay, 0.0

    def call(self, method, path, body=None, ctype="application/json"):
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(3):
            req = urllib.request.Request(self.base + path, data=data, method=method, headers=dict(self.headers, **{"Content-Type": ctype, "User-Agent": "warden-tickets"}))
            self.last = time.time()
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    raw = r.read()
                    return r.status, (json.loads(raw) if raw else None)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503) and attempt < 2:
                    time.sleep(min(float(e.headers.get("Retry-After") or 2 ** attempt), 30))
                    continue
                return e.code, {"error": e.read()[:200].decode(errors="replace")}
            except Exception as e:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                return 0, {"error": type(e).__name__}
        return 0, {"error": "unreachable"}


def basic(user, token):
    return "Basic " + base64.b64encode(("%s:%s" % (user, token)).encode()).decode()


class GitHub:
    name = "github"

    def __init__(self, repo, a):
        tok = os.environ.get("GITHUB_TOKEN", "")
        if not repo or not re.match(r"^[\w.-]+/[\w.-]+$", repo):
            raise SystemExit("github: set --repo owner/name (or GITHUB_REPOSITORY)")
        self.ok, self.repo = bool(tok), repo
        self.api = Api(os.environ.get("GITHUB_API_URL", "https://api.github.com"), {"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json"}, a.allow_http, a.delay)

    def exists(self, g):
        c, r = self.api.call("GET", "/repos/%s/issues?labels=%s&state=all&per_page=1" % (self.repo, urllib.parse.quote(g["label"])))
        return (c == 200 and bool(r)), c

    def create(self, g, body):
        c, r = self.api.call("POST", "/repos/%s/issues" % self.repo, {"title": g["title"], "body": body, "labels": ["warden", g["label"], "severity:" + g["severity"].lower()]})
        return c in (200, 201), (r or {}).get("html_url", "") if c in (200, 201) else str((r or {}).get("error", c))


class Jira:
    name = "jira"

    def __init__(self, repo, a):
        env = {k: os.environ.get(k, "") for k in ("JIRA_URL", "JIRA_USER", "JIRA_TOKEN", "JIRA_PROJECT")}
        if not env["JIRA_URL"] or not env["JIRA_PROJECT"]:
            raise SystemExit("jira: set JIRA_URL and JIRA_PROJECT (and JIRA_USER + JIRA_TOKEN to apply)")
        self.ok, self.project = bool(env["JIRA_USER"] and env["JIRA_TOKEN"]), env["JIRA_PROJECT"]
        self.itype = os.environ.get("JIRA_ISSUE_TYPE", "Bug")
        self.api = Api(env["JIRA_URL"], {"Authorization": basic(env["JIRA_USER"], env["JIRA_TOKEN"]), "Accept": "application/json"}, a.allow_http, a.delay)

    def exists(self, g):
        jql = 'project = "%s" AND labels = "%s"' % (self.project.replace('"', ""), g["label"])
        c, r = self.api.call("GET", "/rest/api/2/search?maxResults=1&fields=key&jql=" + urllib.parse.quote(jql))
        return (c == 200 and bool((r or {}).get("issues"))), c

    def create(self, g, body):
        desc = re.sub(r"<!--.*?-->", "", body)
        c, r = self.api.call("POST", "/rest/api/2/issue", {"fields": {"project": {"key": self.project}, "summary": g["title"], "description": desc, "issuetype": {"name": self.itype}, "labels": ["warden", g["label"]]}})
        return c in (200, 201), (r or {}).get("key", "") if c in (200, 201) else str((r or {}).get("error", c))


class Azure:
    name = "azure"

    def __init__(self, repo, a):
        env = {k: os.environ.get(k, "") for k in ("AZDO_ORG_URL", "AZDO_PROJECT", "AZDO_TOKEN")}
        if not env["AZDO_ORG_URL"] or not env["AZDO_PROJECT"]:
            raise SystemExit("azure: set AZDO_ORG_URL and AZDO_PROJECT (and AZDO_TOKEN to apply)")
        self.ok, self.project = bool(env["AZDO_TOKEN"]), urllib.parse.quote(env["AZDO_PROJECT"])
        self.api = Api(env["AZDO_ORG_URL"], {"Authorization": basic("", env["AZDO_TOKEN"])}, a.allow_http, a.delay)

    def exists(self, g):
        q = "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS '%s'" % g["label"]
        c, r = self.api.call("POST", "/%s/_apis/wit/wiql?api-version=7.0" % self.project, {"query": q})
        return (c == 200 and bool((r or {}).get("workItems"))), c

    def create(self, g, body):
        import html
        ops = [{"op": "add", "path": "/fields/System.Title", "value": g["title"]},
               {"op": "add", "path": "/fields/System.Description", "value": "<pre>%s</pre>" % html.escape(re.sub(r"<!--.*?-->", "", body))},
               {"op": "add", "path": "/fields/System.Tags", "value": "warden; " + g["label"]}]
        c, r = self.api.call("POST", "/%s/_apis/wit/workitems/$Bug?api-version=7.0" % self.project, ops, "application/json-patch+json")
        return c in (200, 201), str((r or {}).get("id", "")) if c in (200, 201) else str((r or {}).get("error", c))


# ---------------------------------------------------------------- main
def load_publish():
    spec = importlib.util.spec_from_file_location("warden_publish", os.path.join(os.path.dirname(os.path.abspath(__file__)), "publish.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def fetch_overdue(url, token, repo, branch, allow_http):
    api = Api(url, {"Authorization": "Bearer " + token}, allow_http, 0)
    c, r = api.call("GET", "/api/overdue?repo=%s&branch=%s" % (urllib.parse.quote(repo, safe="/"), urllib.parse.quote(branch)))
    if c != 200:
        print("tickets: could not read overdue findings from the dashboard (HTTP %s): only new findings are used" % c, file=sys.stderr)
        return set()
    return {i["fingerprint"] for i in r}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default=".security/reports/latest")
    ap.add_argument("--target", choices=["github", "jira", "azure", "all"], default="github")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--min-severity", choices=["critical", "high"], default="high")
    ap.add_argument("--include-existing", action="store_true", help="also ticket findings that are in the baseline")
    ap.add_argument("--dashboard", default=os.environ.get("SEC_DASHBOARD_URL", ""), help="read overdue findings from the dashboard (token: WARDEN_DASHBOARD_TOKEN)")
    ap.add_argument("--apply", action="store_true", help="create the tickets (default is a dry run)")
    ap.add_argument("--max-issues", type=int, default=20, help="most tickets to create per target in one run")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between API calls")
    ap.add_argument("--allow-http", action="store_true")
    a = ap.parse_args(argv)
    try:
        findings = json.load(open(os.path.join(a.report, "findings.json")))
    except (OSError, ValueError) as e:
        print("tickets: no readable findings.json in %s (%s). Run a scan first." % (a.report, e), file=sys.stderr)
        return 2
    pub = load_publish()
    repo, branch, commit, run = pub.ci_context(".")
    overdue = set()
    tok = os.environ.get("WARDEN_DASHBOARD_TOKEN", "")
    if a.dashboard and tok:
        overdue = fetch_overdue(a.dashboard, tok, repo, branch, a.allow_http)
    groups = build_groups(select(findings, a.min_severity, a.include_existing, overdue))
    ctx = dict(repo=a.repo or repo, branch=branch, commit=commit, run=run)
    print("tickets: %d finding(s) in %d group(s) (min severity %s%s, %d overdue)" % (sum(len(g["items"]) for g in groups), len(groups), a.min_severity, ", incl. baseline" if a.include_existing else ", new + overdue", len(overdue)))
    if not groups:
        return 0
    names = ["github", "jira", "azure"] if a.target == "all" else [a.target]
    classes = {"github": GitHub, "jira": Jira, "azure": Azure}
    rc = 0
    for n in names:
        try:
            t = classes[n](a.repo, a)
        except SystemExit as e:
            if a.target == "all":
                print("tickets: skipping %s (%s)" % (n, e))
                continue
            raise
        if a.apply and not t.ok:
            print("tickets: %s credentials are missing: nothing created" % n, file=sys.stderr)
            rc = 2
            continue
        made = 0
        for g in groups:
            ex, code = t.exists(g) if t.ok else (False, None)
            tag = "exists" if ex else ("lookup failed (HTTP %s)" % code if t.ok and code != 200 else "new")
            if tag.startswith("lookup failed"):
                print("  [%s] %-14s %s" % (n, tag, g["title"]))
                rc = rc or 1   # never create blind: a duplicate is worse than a delayed ticket
                continue
            if ex:
                print("  [%s] exists        %s" % (n, g["title"]))
                continue
            if not a.apply:
                print("  [%s] would create  %s  (%s)" % (n, g["title"], g["label"]))
                continue
            if made >= a.max_issues:
                print("  [%s] skipped (limit %d)  %s" % (n, a.max_issues, g["title"]))
                continue
            ok, ref = t.create(g, body_for(g, ctx))
            made += ok
            rc = rc or (0 if ok else 1)
            print("  [%s] %s  %s  %s" % (n, "created " if ok else "FAILED  ", g["title"], ref))
        if not a.apply:
            print("tickets: dry run for %s, nothing was created. Add --apply to create the tickets above." % n)
    return rc


if __name__ == "__main__":
    sys.exit(main())
