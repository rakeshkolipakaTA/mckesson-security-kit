#!/usr/bin/env python3
"""Show a Warden scan inside GitHub itself, with no server (standard library only).

  gh_report.py --report <report-dir> [--root <repo>] [--annotations N] [--no-comment] [--no-summary]

What it does, in GitHub Actions:
  1. Job summary   : a compact result page on the run (verdict, counts, which checks ran, top findings with file links).
  2. Annotations   : the worst findings appear as markers on the file lines ("Files changed" tab of a pull request).
  3. Pull request  : ONE comment, updated on every push (never a new comment each time).

Reporting never fails the build; the scan step decides pass or fail. Everything degrades quietly: no token, a fork pull
request (read-only token), or a push event simply skips the comment. Text that comes from scanned code is escaped so it cannot
inject markup, workflow commands or @mentions.
"""
import argparse
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
MARK = "<!-- warden-report -->"
GH_LIMIT = 10                       # GitHub shows at most 10 error and 10 warning annotations per step
COMMENT_MAX = 12000                 # a PR comment is capped at 65,536 characters; stay far below
SUMMARY_MAX = 900_000               # the job summary is capped at 1 MiB


# ---------- escaping ----------
def wc_data(s):
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def wc_prop(s):
    return wc_data(s).replace(":", "%3A").replace(",", "%2C")


def cell(s, n=130):
    """Make untrusted text safe for a markdown table cell / comment: no HTML, links, mentions, pipes or newlines."""
    s = " ".join(str(s or "").split())
    if len(s) > n:
        s = s[: n - 3] + "..."
    s = html.escape(s, quote=False)
    s = s.replace("|", "\\|").replace("[", "\\[").replace("]", "\\]").replace("`", "'")
    return s.replace("@", "@​")


# ---------- data ----------
def load(report):
    def j(name, default):
        try:
            with open(os.path.join(report, name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return default
    return j("summary.json", {}), j("findings.json", [])


def line_of(f):
    m = re.search(r":(\d+)", f.get("location") or "")
    return int(m.group(1)) if m else None


def repo_path(f, root):
    """The finding's file as a repo-relative path, only if it really is a file in the checkout (images and URLs are not)."""
    p = f.get("path") or ""
    if not p or p.startswith(("/", "http")) or ".." in p.split("/") or ":" in p or " " in p:
        return None
    return p if os.path.isfile(os.path.join(root, p)) else None


def ordered(findings):
    """New findings first, then by severity."""
    rank = {s: i for i, s in enumerate(SEV)}
    return sorted(findings, key=lambda f: (0 if f.get("new", True) else 1, rank.get(f.get("severity"), 9)))


def verdict(s):
    mode, res = s.get("mode", ""), s.get("result", "")
    nb = s.get("blocking", 0)
    errs = "" if "(" not in res else " Some checks had errors, see below."
    if res.startswith("PASS"):
        return ("PASS", "No blocking findings." + errs)
    if mode == "report-only":
        return ("REPORT", f"Report only: {nb} finding{'s' if nb != 1 else ''} would block under the standard preset; this build is not blocked.{errs}")
    return ("FAIL", f"{nb} blocking finding{'s' if nb != 1 else ''}: this build is blocked.{errs}")


def ctx(env):
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = env.get("GITHUB_REPOSITORY", "")
    sha, pr = env.get("GITHUB_SHA", ""), None
    try:
        with open(env.get("GITHUB_EVENT_PATH", ""), encoding="utf-8") as f:
            ev = json.load(f)
        pr = (ev.get("pull_request") or {}).get("number") or ev.get("number") if "pull_request" in ev else None
        sha = ((ev.get("pull_request") or {}).get("head") or {}).get("sha") or sha
    except (OSError, ValueError):
        pass
    if pr is None:
        m = re.match(r"refs/pull/(\d+)/", env.get("GITHUB_REF", ""))
        pr = int(m.group(1)) if m else None
    run = f"{server}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}" if repo and env.get("GITHUB_RUN_ID") else ""
    return dict(server=server, repo=repo, sha=sha, pr=pr, run=run, api=env.get("GITHUB_API_URL", "https://api.github.com"))


def file_link(c, path, line):
    if not (c["repo"] and c["sha"]):
        return f"`{cell(path)}{':' + str(line) if line else ''}`"
    url = f"{c['server']}/{c['repo']}/blob/{c['sha']}/{urllib.parse.quote(path)}" + (f"#L{line}" if line else "")
    return f"[{cell(path)}{':' + str(line) if line else ''}]({url})"


# ---------- outputs ----------
def annotations(findings, root, limit):
    out, used = [], {"error": 0, "warning": 0}
    seen = set()
    for f in ordered(findings):
        sev = f.get("severity")
        level = {"CRITICAL": "error", "HIGH": "warning"}.get(sev)
        if not level or used[level] >= min(limit, GH_LIMIT):
            continue
        p = repo_path(f, root)
        if not p:
            continue
        line = line_of(f)
        key = (p, line, f.get("rule"))
        if key in seen:
            continue
        seen.add(key)
        used[level] += 1
        title = f"Warden {sev}: {f.get('rule') or f.get('tool')}"
        msg = f"{f.get('title', '')} [{'+'.join(f.get('tools') or [f.get('tool', '')])}]" + (f" Fix: {f['fix']}" if f.get("fix") else "")
        props = f"file={wc_prop(p)},title={wc_prop(title)}" + (f",line={line}" if line else "")
        out.append(f"::{level} {props}::{wc_data(msg[:900])}")
    return out


def counts_table(s):
    c, n = s.get("counts", {}), s.get("new_counts", {})
    rows = ["| Severity | Open | New since baseline |", "|---|---|---|"]
    rows += [f"| {sv.title()} | {c.get(sv, 0)} | {n.get(sv, 0)} |" for sv in SEV[:4]]
    return "\n".join(rows)


def tools_line(s):
    st = s.get("tool_status", {})
    ok = [t for t, v in st.items() if v == "ok"]
    bad = {t: v for t, v in st.items() if v != "ok"}
    lines = []
    if ok:
        lines.append("Checks that ran: " + ", ".join(sorted(ok)) + ".")
    if bad:
        lines.append("**Did not complete:** " + ", ".join(f"{t} ({cell(v, 40)})" for t, v in sorted(bad.items())) + ". A check that did not run is not a clean result.")
    nr = s.get("tools_not_run") or {}
    if nr:
        lines.append("Switched off by the team: " + ", ".join(sorted(nr)) + ".")
    return "\n\n".join(lines)


def findings_table(findings, c, limit, root="."):
    top = [f for f in ordered(findings) if f.get("severity") in ("CRITICAL", "HIGH")][:limit]
    if not top:
        return "", 0
    rows = ["| Severity | Where | What | Found by |", "|---|---|---|---|"]
    for f in top:
        p, line = repo_path(f, root), line_of(f)
        where = file_link(c, p, line) if p else f"`{cell(f.get('location') or f.get('path'), 60)}`"
        rows.append(f"| {f['severity'].title()} | {where} | {cell(f.get('rule'), 30)}: {cell(f.get('title'))} | {cell('+'.join(f.get('tools') or [f.get('tool')]), 30)} |")
    more = len([f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]) - len(top)
    return "\n".join(rows), max(more, 0)


def build_summary(s, findings, c, report, root="."):
    tag, text = verdict(s)
    icon = {"PASS": "✅", "REPORT": "🟡", "FAIL": "❌"}[tag]
    tbl, more = findings_table(findings, c, 25, root)
    L = [f"## {icon} Warden security scan", "", f"**{text}**", "",
         counts_table(s), "", tools_line(s), ""]
    if tbl:
        L += ["### Most serious findings (new first)", "", tbl, ""]
        if more:
            L += [f"...and {more} more Critical/High. The full list is in the **security-report** artifact on this run (summary.html).", ""]
    else:
        L += ["No Critical or High findings.", ""]
    L += ["The full HTML report, the markdown summary, the SBOM and SARIF are in the **security-report** artifact of this run."]
    try:
        full = open(os.path.join(report, "summary.md"), encoding="utf-8").read()
        L += ["", "<details><summary>Full text summary</summary>", "", html.escape(full[:200_000], quote=False).replace("@", "@​"), "", "</details>"]
    except OSError:
        pass
    return "\n".join(L)[:SUMMARY_MAX]


def build_comment(s, findings, c, root="."):
    tag, text = verdict(s)
    icon = {"PASS": "✅", "REPORT": "🟡", "FAIL": "❌"}[tag]
    tbl, more = findings_table(findings, c, 10, root)
    n = s.get("new_counts", {})
    L = [MARK, f"### {icon} Warden security scan", "", f"**{text}**", "",
         f"New since baseline: **{n.get('CRITICAL', 0)} Critical, {n.get('HIGH', 0)} High**, {n.get('MEDIUM', 0)} Medium, {n.get('LOW', 0)} Low.", ""]
    if tbl:
        L += [tbl, ""]
        if more:
            L += [f"...and {more} more. See the run page for the full list.", ""]
    bad = {t: v for t, v in s.get("tool_status", {}).items() if v != "ok"}
    if bad:
        L += ["**Did not complete:** " + ", ".join(f"{t} ({cell(v, 40)})" for t, v in sorted(bad.items())) + ". A check that did not run is not a clean result.", ""]
    L += [f"[Open the full report and artifacts]({c['run']})" if c["run"] else "Full report: the **security-report** artifact of this run.",
          "", "<sub>Updated on every push. Written by Warden.</sub>"]
    return "\n".join(L)[:COMMENT_MAX]


# ---------- GitHub API (pull request comment) ----------
def api(c, token, method, path, body=None):
    req = urllib.request.Request(c["api"] + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "warden-ci-report",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read() or b"null")


def upsert_comment(c, token, body):
    base = f"/repos/{c['repo']}/issues/{c['pr']}/comments"
    cid, page = None, 1
    while cid is None and page <= 10:
        items = api(c, token, "GET", f"{base}?per_page=100&page={page}") or []
        for it in items:
            if MARK in (it.get("body") or "") and (it.get("user") or {}).get("type") == "Bot":   # never edit a human's comment that merely quotes the marker
                cid = it["id"]
                break
        if len(items) < 100:
            break
        page += 1
    if cid:
        api(c, token, "PATCH", f"/repos/{c['repo']}/issues/comments/{cid}", {"body": body})
        return "updated"
    api(c, token, "POST", base, {"body": body})
    return "created"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--root", default=os.environ.get("GITHUB_WORKSPACE") or ".")
    ap.add_argument("--annotations", type=int, default=GH_LIMIT, help="max annotations per level (0 = none)")
    ap.add_argument("--no-comment", action="store_true")
    ap.add_argument("--no-summary", action="store_true")
    a = ap.parse_args()
    env = os.environ
    s, findings = load(a.report)
    if not s:
        print("warden ci-report: no report found in " + a.report + " (did the scan step run?)", file=sys.stderr)
        return 0
    c = ctx(env)
    if a.annotations > 0:
        for line in annotations(findings, a.root, a.annotations):
            print(line)
    if not a.no_summary and env.get("GITHUB_STEP_SUMMARY"):
        try:
            with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
                f.write(build_summary(s, findings, c, a.report, a.root) + "\n")
        except OSError as e:
            print(f"warden ci-report: could not write the job summary: {e}", file=sys.stderr)
    off = (env.get("WARDEN_PR_COMMENT", "") or env.get("SEC_PR_COMMENT", "")).lower() in ("off", "0", "false", "no")
    if a.no_comment or off:
        pass
    elif not c["pr"] or not c["repo"]:
        print("warden ci-report: not a pull request run, no comment posted")
    elif not env.get("GITHUB_TOKEN"):
        print("warden ci-report: no GITHUB_TOKEN in the step environment, no comment posted (add `GITHUB_TOKEN: ${{ github.token }}` to the step)")
    else:
        try:
            print("warden ci-report: pull request comment " + upsert_comment(c, env["GITHUB_TOKEN"], build_comment(s, findings, c, a.root)))
        except urllib.error.HTTPError as e:
            why = "the token is read-only (a pull request from a fork, or the workflow lacks `pull-requests: write`)" if e.code in (401, 403, 404) else f"HTTP {e.code}"
            print(f"warden ci-report: pull request comment skipped: {why}. The job summary and annotations still work.")
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"warden ci-report: pull request comment skipped: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
