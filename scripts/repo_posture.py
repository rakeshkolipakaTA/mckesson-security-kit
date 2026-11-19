#!/usr/bin/env python3
"""Repository settings check through the GitHub API (standard library only). Answers: is the repo set up so the scans actually matter?
  repo_posture.py --out repo-posture.json [--repo owner/name] [--root DIR]
Token: GITHUB_TOKEN or GH_TOKEN (read access is enough; some settings need repo-admin rights to read: those are reported as 'could not check').
Owner/name: --repo, GITHUB_REPOSITORY, or the git remote of --root. GITHUB_API_URL selects a GitHub Enterprise server."""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request


def slug_from_git(root):
    try:
        url = subprocess.run(["git", "-C", root, "config", "--get", "remote.origin.url"], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else ""


class Api:
    def __init__(self, token, base):
        self.token, self.base = token, base.rstrip("/")

    def get(self, path):
        req = urllib.request.Request(self.base + path, headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "User-Agent": "secscan-repo-posture",
                                                                 "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read().decode()
                return r.status, (json.loads(body) if body.strip().startswith(("{", "[")) else body)
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return 0, None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    slug = a.repo or os.environ.get("GITHUB_REPOSITORY") or slug_from_git(a.root)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if not slug or not token:
        print("repo-posture: needs an owner/name and GITHUB_TOKEN", file=sys.stderr)
        return 1
    api = Api(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    out, unchecked = [], []

    def add(sev, rule, title, fix):
        out.append(dict(severity=sev, rule=rule, title=title, location=slug, fix=fix))
    st, repo = api.get(f"/repos/{slug}")
    if st != 200 or not isinstance(repo, dict):
        print(f"repo-posture: cannot read {slug} (HTTP {st}); check the token", file=sys.stderr)
        return 1
    branch = repo.get("default_branch", "main")
    sa = repo.get("security_and_analysis") or {}
    for key, rule, label in (("secret_scanning", "REPO-SECRET-SCANNING", "Secret scanning"), ("secret_scanning_push_protection", "REPO-PUSH-PROTECTION", "Secret push protection"),
                             ("dependabot_security_updates", "REPO-DEPENDABOT-UPDATES", "Dependabot security updates")):
        if key in sa:
            if (sa[key] or {}).get("status") != "enabled":
                add("MEDIUM", rule, f"{label} is not enabled", f"Settings > Code security > enable {label.lower()}")
        else:
            unchecked.append(label.lower())
    # branch protection: classic rule or an active ruleset
    st, prot = api.get(f"/repos/{slug}/branches/{branch}/protection")
    rst, rules = api.get(f"/repos/{slug}/rules/branches/{branch}")
    rule_types = {r.get("type") for r in rules} if rst == 200 and isinstance(rules, list) else set()
    if st == 200 and isinstance(prot, dict):
        if not prot.get("required_pull_request_reviews") and "pull_request" not in rule_types:
            add("MEDIUM", "REPO-NO-REVIEWS", f"Branch '{branch}' does not require pull-request reviews", "Require at least one approving review")
        if not prot.get("required_status_checks") and "required_status_checks" not in rule_types:
            add("MEDIUM", "REPO-NO-STATUS-CHECKS", f"Branch '{branch}' does not require status checks, so the security scan cannot block a merge", "Make the security-scan check required")
        if (prot.get("allow_force_pushes") or {}).get("enabled"):
            add("HIGH", "REPO-FORCE-PUSH", f"Force pushes are allowed on '{branch}'", "Disable force pushes on the default branch")
        if not (prot.get("enforce_admins") or {}).get("enabled"):
            add("LOW", "REPO-ADMIN-BYPASS", f"Administrators can bypass the protection of '{branch}'", "Enable 'Do not allow bypassing the above settings'")
    elif st == 404 and not rule_types:
        add("HIGH", "REPO-UNPROTECTED", f"Default branch '{branch}' has no protection (no required reviews, checks or force-push block)", "Add a branch protection rule or ruleset")
    elif st == 404 and rule_types:
        if not rule_types & {"pull_request"}:
            add("MEDIUM", "REPO-NO-REVIEWS", f"Rulesets on '{branch}' do not require pull-request reviews", "Add a pull_request rule")
        if not rule_types & {"required_status_checks"}:
            add("MEDIUM", "REPO-NO-STATUS-CHECKS", f"Rulesets on '{branch}' do not require status checks", "Make the security-scan check required")
        if "non_fast_forward" not in rule_types:
            add("HIGH", "REPO-FORCE-PUSH", f"Rulesets on '{branch}' do not block force pushes", "Add a non_fast_forward rule")
    else:
        unchecked.append("branch protection")
    for rule, label, paths, sev in (("REPO-NO-CODEOWNERS", "CODEOWNERS file", [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"], "MEDIUM"),
                                    ("REPO-NO-SECURITY-POLICY", "SECURITY.md (how to report a vulnerability)", ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"], "LOW"),
                                    ("REPO-NO-DEPENDENCY-UPDATES", "dependabot.yml / renovate.json (automatic dependency updates)", [".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".github/renovate.json"], "LOW")):
        if not any(api.get(f"/repos/{slug}/contents/{p}")[0] == 200 for p in paths):
            add(sev, rule, f"No {label}", "Add the file (templates: secscan init)")
    st, _ = api.get(f"/repos/{slug}/vulnerability-alerts")
    if st == 404:
        add("MEDIUM", "REPO-NO-ALERTS", "Dependabot vulnerability alerts are disabled", "Settings > Code security > enable Dependabot alerts")
    elif st not in (204, 200):
        unchecked.append("vulnerability alerts")
    st, perms = api.get(f"/repos/{slug}/actions/permissions/workflow")
    if st == 200 and isinstance(perms, dict):
        if perms.get("default_workflow_permissions") == "write":
            add("MEDIUM", "REPO-WORKFLOW-WRITE", "Workflows get read/write GITHUB_TOKEN permissions by default", "Settings > Actions > Workflow permissions: read repository contents only")
        if perms.get("can_approve_pull_request_reviews"):
            add("LOW", "REPO-ACTIONS-APPROVE", "Workflows may approve pull requests", "Disable 'Allow GitHub Actions to create and approve pull requests'")
    else:
        unchecked.append("workflow permissions")
    if unchecked:
        add("INFO", "REPO-UNCHECKED", "Could not check (needs repository-admin rights): " + ", ".join(sorted(set(unchecked))), "Run the check with a token that has admin read access")
    json.dump({"repo": slug, "branch": branch, "findings": out}, open(a.out, "w"), indent=1)
    print(f"repo-posture: {slug} ({branch}): {len([x for x in out if x['severity'] != 'INFO'])} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
