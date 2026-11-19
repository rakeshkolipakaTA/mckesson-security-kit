#!/usr/bin/env python3
"""Publish the latest scan report to the central dashboard (standard library only).

  publish.py --report <report-dir> [--url URL] [--root <repo>] [--repo NAME] [--strict]

URL comes from --url / SEC_DASHBOARD_URL (not secret); the token from SECSCAN_DASHBOARD_TOKEN (a CI secret, never a file).
A publishing problem is only a warning (exit 0) so the dashboard being down never breaks a build; --strict makes it exit 1.
Repo / branch / commit / run link are detected from GitHub Actions, Jenkins, Azure DevOps or the local git checkout.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def git(root, *args):
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def sla_days():
    """sla_days from the kit's central policy.json (scripts/ and configs/ sit side by side in the kit, the package and the checkout)."""
    try:
        pol = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "configs", "policies", "policy.json")))
        return {k: v for k, v in pol.get("sla_days", {}).items() if isinstance(v, int)}
    except (OSError, ValueError):
        return {}


def ci_context(root):
    env = os.environ
    if env.get("GITHUB_ACTIONS"):
        repo = env.get("GITHUB_REPOSITORY", "")
        run = f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{env.get('GITHUB_RUN_ID', '')}"
        branch = env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME", "")
        return repo, branch, env.get("GITHUB_SHA", ""), run
    if env.get("JENKINS_URL"):
        return env.get("JOB_NAME", "").split("/")[0] or "", (env.get("GIT_BRANCH", "") or env.get("BRANCH_NAME", "")).replace("origin/", ""), env.get("GIT_COMMIT", ""), env.get("BUILD_URL", "")
    if env.get("TF_BUILD"):
        run = f"{env.get('SYSTEM_TEAMFOUNDATIONCOLLECTIONURI', '')}{env.get('SYSTEM_TEAMPROJECT', '')}/_build/results?buildId={env.get('BUILD_BUILDID', '')}"
        return env.get("BUILD_REPOSITORY_NAME", ""), env.get("BUILD_SOURCEBRANCHNAME", ""), env.get("BUILD_SOURCEVERSION", ""), run
    remote = git(root, "config", "--get", "remote.origin.url")
    name = (remote.rstrip("/")[:-4] if remote.endswith(".git") else remote.rstrip("/")).replace(":", "/").split("/")[-2:] if remote else []
    return ("/".join(name) if len(name) == 2 else os.path.basename(os.path.abspath(root))), git(root, "rev-parse", "--abbrev-ref", "HEAD"), git(root, "rev-parse", "HEAD"), ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True)
    ap.add_argument("--url", default=os.environ.get("SEC_DASHBOARD_URL", ""))
    ap.add_argument("--root", default=".")
    ap.add_argument("--repo", default="")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()
    fail = (lambda m: (print(f"dashboard: {m}", file=sys.stderr), sys.exit(1 if a.strict else 0)))
    token = os.environ.get("SECSCAN_DASHBOARD_TOKEN", "")
    if not a.url.startswith(("http://", "https://")):
        fail("SEC_DASHBOARD_URL must start with http:// or https://")
    if not token:
        in_ci = any(os.environ.get(k) for k in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD"))
        if in_ci or a.strict:
            fail("SECSCAN_DASHBOARD_TOKEN is not set (add it as a CI secret); not publishing")
        return  # a developer's local scan: publishing is a CI job
    try:
        summary = json.load(open(os.path.join(a.report, "summary.json")))
        findings = json.load(open(os.path.join(a.report, "findings.json")))
    except (OSError, ValueError) as ex:
        fail(f"no readable report in {a.report}: {ex}")
    repo, branch, commit, run = ci_context(a.root)
    findings.sort(key=lambda f: (SEV.index(f["severity"]) if f.get("severity") in SEV else 9))
    slim = [{k: f.get(k) for k in ("severity", "tool", "rule", "location", "title", "fix", "new", "excepted", "fingerprint")} for f in findings[:1500]]
    summary["sla_days"] = sla_days()   # the central policy's remediation SLAs, so the dashboard can track overdue findings
    body = json.dumps({"repo": a.repo or repo or summary.get("target"), "branch": branch, "commit": commit, "run_url": run, "summary": summary,
                       "findings": slim, "findings_total": len(findings)}).encode()
    req = urllib.request.Request(a.url.rstrip("/") + "/api/ingest", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "secscan-publish"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print(f"dashboard: published {a.repo or repo} ({branch}) -> {a.url} [{r.status}]")
    except urllib.error.HTTPError as ex:
        fail(f"server answered {ex.code}: {ex.read()[:150].decode(errors='replace')}")
    except Exception as ex:
        fail(f"could not reach {a.url}: {ex}")


if __name__ == "__main__":
    main()
