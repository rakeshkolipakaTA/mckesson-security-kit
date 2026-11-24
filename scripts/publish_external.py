#!/usr/bin/env python3
"""Send a scan to DefectDojo (findings register) and Dependency-Track (SBOM monitor). Standard library only.

  publish_external.py --report <report-dir> [--root <repo>] [--only dojo,dtrack] [--strict] [--dry-run]

Settings (not secret; config.env / configs/central.env / environment):
  SEC_DEFECTDOJO_URL             e.g. http://host:8100             -> DefectDojo is used when set
  SEC_DEFECTDOJO_PRODUCT         product name (default: the repository, owner/name)
  SEC_DEFECTDOJO_PRODUCT_TYPE    product type, created if missing (default: Warden)
  SEC_DEFECTDOJO_BRANCHES        branches to publish, comma list or * (default: main,master)
  SEC_DTRACK_URL                 the API server URL, e.g. http://host:8111 -> Dependency-Track is used when set
  SEC_DTRACK_PROJECT             project name (default: the repository, owner/name); the project VERSION is the branch
  SEC_DTRACK_BRANCHES            branches to publish, comma list or * (default: main,master)
Secrets (CI secrets, never files): DEFECTDOJO_TOKEN, DTRACK_API_KEY.

DefectDojo gets one engagement per branch and a REIMPORT on every run: findings that are gone are closed, new ones opened, known ones
untouched (no duplicates). Dependency-Track gets the CycloneDX SBOM (sbom.cdx.json) as a project version, and keeps checking it for new CVEs.
A publishing problem is only a warning (exit 0), so a server being down never breaks a build; --strict makes it exit 1.
Pull-request branches are skipped by default (SEC_*_BRANCHES), so the registers hold the state of your main branch.
`warden publish` (--strict) is a deliberate send and ignores that filter."""
import argparse
import base64
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SEV_DOJO = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}


def load_ci_context():
    """Reuse publish.py's CI detection (this script may run with -I, which hides sibling modules, so load by path)."""
    spec = importlib.util.spec_from_file_location("warden_publish", os.path.join(os.path.dirname(os.path.abspath(__file__)), "publish.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ci_context


def branch_ok(branch, setting, default="main,master"):
    allowed = [b.strip() for b in (setting or default).split(",") if b.strip()]
    return "*" in allowed or branch in allowed


def multipart(fields, files):
    """fields: {name: str}; files: {name: (filename, bytes, content_type)} -> (body, content_type)."""
    b = "----warden" + uuid.uuid4().hex
    out = []
    for k, v in fields.items():
        out.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, (fn, data, ct) in files.items():
        out.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\nContent-Type: {ct}\r\n\r\n'.encode() + data + b"\r\n")
    out.append(f"--{b}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={b}"


def request(method, url, headers, body=None, timeout=60):
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "warden-publish", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip()[:1] in (b"{", b"[") else raw.decode(errors="replace"))
    except urllib.error.HTTPError as e:
        raw = e.read()[:300].decode(errors="replace")
        return e.code, raw
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(e)


def http_note(url):
    host = urllib.parse.urlparse(url).hostname or ""
    if url.startswith("http://") and host not in ("localhost", "127.0.0.1", "::1"):
        print("  note: this server is plain HTTP, so the token travels in clear text: put TLS in front of it or restrict the port (see docs/integrations/)", file=sys.stderr)


# ------------------------------------------------------------------ DefectDojo
def dojo_findings(findings, today):
    """Warden findings -> DefectDojo 'Generic Findings Import'. Titles and descriptions are deterministic so a reimport matches the same finding."""
    out = []
    for f in findings:
        loc = f.get("location") or ""
        path = f.get("path") or (loc.split(":")[0] if ":" in loc else loc)
        m = re.search(r":(\d+)$", loc)
        ids = [i for i in (f.get("all_ids") or []) if isinstance(i, str)]
        cve = next((i for i in ids + [f.get("rule") or ""] if re.fullmatch(r"CVE-\d{4}-\d{4,}", i or "")), "")
        desc = f"Tool: {f.get('tool')}\nRule: {f.get('rule')}\nCategory: {f.get('category')}\nLocation: {loc}" + (f"\nAlso reported as: {', '.join(ids[:8])}" if ids else "")
        item = {"title": (f.get("title") or f.get("rule") or "finding")[:250], "description": desc, "severity": SEV_DOJO.get(f.get("severity"), "Info"),
                "mitigation": f.get("fix") or "", "date": today, "file_path": path or "", "line": int(m.group(1)) if m else 0,
                "unique_id_from_tool": f.get("fingerprint") or "", "vuln_id_from_tool": f.get("rule") or "",
                "static_finding": f.get("category") not in ("DAST", "AI red team"), "dynamic_finding": f.get("category") in ("DAST", "AI red team"),
                "active": not f.get("excepted"), "risk_accepted": bool(f.get("excepted")), "verified": False,
                "tags": [t for t in ("warden", f.get("tool"), f.get("category"), None if f.get("new", True) else "baseline") if t]}
        if cve:
            item["cve"] = cve
        out.append(item)
    return out


def publish_dojo(a, ctx):
    url, token = os.environ.get("SEC_DEFECTDOJO_URL", "").rstrip("/"), os.environ.get("DEFECTDOJO_TOKEN", "")
    repo, branch, commit, run = ctx
    if not a.strict and not branch_ok(branch, os.environ.get("SEC_DEFECTDOJO_BRANCHES")):   # `warden publish` (--strict) is a deliberate send: any branch
        print(f"defectdojo: skipped (branch '{branch}' is not in SEC_DEFECTDOJO_BRANCHES, default main,master)")
        return True
    try:
        findings = json.load(open(os.path.join(a.report, "findings.json")))
    except (OSError, ValueError) as e:
        return err(a, f"defectdojo: no readable findings.json in {a.report}: {e}")
    product = os.environ.get("SEC_DEFECTDOJO_PRODUCT") or repo
    ptype = os.environ.get("SEC_DEFECTDOJO_PRODUCT_TYPE") or "Warden"
    body_json = json.dumps({"findings": dojo_findings(findings, time.strftime("%Y-%m-%d"))}).encode()
    fields = {"scan_type": "Generic Findings Import", "product_name": product, "product_type_name": ptype, "engagement_name": branch,
              "test_title": "Warden scan", "auto_create_context": "true", "close_old_findings": "true", "close_old_findings_product_scope": "false",
              "minimum_severity": "Info", "active": "true", "verified": "false", "branch_tag": branch, "commit_hash": commit[:100],
              "build_id": (run.rsplit("/", 1)[-1] if run else "")[:100], "environment": "Development", "tags": "warden"}
    if a.dry_run:
        print(f"defectdojo (dry run): would reimport {len(findings)} findings into product '{product}' (type '{ptype}'), engagement '{branch}' at {url or '<SEC_DEFECTDOJO_URL>'}")
        return True
    if not token:
        return err(a, "defectdojo: DEFECTDOJO_TOKEN is not set (add it as a CI secret); not publishing")
    http_note(url)
    body, ctype = multipart(fields, {"file": ("warden-findings.json", body_json, "application/json")})
    st, res = request("POST", url + "/api/v2/reimport-scan/", {"Authorization": f"Token {token}", "Content-Type": ctype}, body, timeout=180)
    if st in (200, 201) and isinstance(res, dict):
        stats = res.get("statistics") if isinstance(res.get("statistics"), dict) else {}
        delta, after = stats.get("delta") or {}, stats.get("after") or {}

        def total(block, key="total"):
            try:
                return int(((block or {}).get("total") or {}).get(key, 0))
            except (TypeError, ValueError):
                return 0
        new = total(delta.get('created')) or (total(after) if total(stats.get('before')) == 0 else 0)   # a first import creates the whole test
        print(f"defectdojo: published {product} ({branch}) -> {url} [{st}]  new {new}, closed {total(delta.get('closed'))}, "
              f"reactivated {total(delta.get('reactivated'))}, open now {total(after, 'active')}")
        return True
    why = {401: "token rejected (is DEFECTDOJO_TOKEN correct?)", 403: "the token's user may not create products or import here: see docs/integrations/defectdojo.md", 0: f"could not reach {url}: {res}"}.get(st, f"server answered {st}: {str(res)[:200]}")
    return err(a, f"defectdojo: {why}")


# ------------------------------------------------------------------ Dependency-Track
def publish_dtrack(a, ctx):
    url, key = os.environ.get("SEC_DTRACK_URL", "").rstrip("/"), os.environ.get("DTRACK_API_KEY", "")
    repo, branch, commit, run = ctx
    if not a.strict and not branch_ok(branch, os.environ.get("SEC_DTRACK_BRANCHES")):   # `warden publish` (--strict) is a deliberate send: any branch
        print(f"dependency-track: skipped (branch '{branch}' is not in SEC_DTRACK_BRANCHES, default main,master)")
        return True
    sbom = os.path.join(a.report, "sbom.cdx.json")
    if not os.path.isfile(sbom) or os.path.getsize(sbom) == 0:
        print("dependency-track: skipped (this scan produced no SBOM: SEC_SBOM is off or Trivy found no supported manifests)")
        return True
    project = os.environ.get("SEC_DTRACK_PROJECT") or repo
    latest = "true" if branch in ("main", "master") else "false"
    if a.dry_run:
        print(f"dependency-track (dry run): would upload {os.path.getsize(sbom)} bytes of SBOM as project '{project}' version '{branch}' to {url or '<SEC_DTRACK_URL>'}")
        return True
    if not key:
        return err(a, "dependency-track: DTRACK_API_KEY is not set (add it as a CI secret); not publishing")
    http_note(url)
    body, ctype = multipart({"projectName": project, "projectVersion": branch, "autoCreate": "true", "isLatest": latest, "projectTags": "warden"},
                            {"bom": ("sbom.cdx.json", open(sbom, "rb").read(), "application/json")})
    st, res = request("POST", url + "/api/v1/bom", {"X-Api-Key": key, "Content-Type": ctype}, body, timeout=120)
    if st not in (200, 201, 202) or not isinstance(res, dict):
        why = {401: "API key rejected (is DTRACK_API_KEY correct?)", 403: "the key needs the BOM_UPLOAD and PROJECT_CREATION_UPLOAD permissions: see docs/integrations/dependency-track.md", 0: f"could not reach {url}: {res}"}.get(st, f"server answered {st}: {str(res)[:200]}")
        return err(a, f"dependency-track: {why}")
    token = res.get("token")
    msg = f"dependency-track: uploaded SBOM for {project} version {branch} -> {url} [{st}]"
    # best effort: wait for processing and report the numbers (needs VIEW_PORTFOLIO; never an error)
    try:
        for _ in range(30):
            s2, r2 = request("GET", f"{url}/api/v1/bom/token/{urllib.parse.quote(str(token))}", {"X-Api-Key": key}, timeout=15)
            if s2 == 200 and isinstance(r2, dict) and r2.get("processing") is False:
                break
            if s2 != 200:
                raise RuntimeError
            time.sleep(2)
        s3, p = request("GET", f"{url}/api/v1/project/lookup?name={urllib.parse.quote(project)}&version={urllib.parse.quote(branch)}", {"X-Api-Key": key}, timeout=15)
        if s3 == 200 and isinstance(p, dict):
            time.sleep(3)   # vulnerability analysis starts after the SBOM is processed
            s4, m = request("GET", f"{url}/api/v1/metrics/project/{p['uuid']}/current", {"X-Api-Key": key}, timeout=15)
            if s4 == 200 and isinstance(m, dict):
                msg += f"  components {m.get('components', 0)}, vulnerabilities critical {m.get('critical', 0)} high {m.get('high', 0)} medium {m.get('medium', 0)} low {m.get('low', 0)}"
    except Exception:
        pass
    print(msg)
    return True


def err(a, msg):
    print(msg, file=sys.stderr)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True)
    ap.add_argument("--root", default=".")
    ap.add_argument("--only", default="", help="dojo, dtrack or both (default: whichever has its URL set)")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="show what would be sent; contact nobody")
    a = ap.parse_args()
    want = {x.strip() for x in a.only.split(",") if x.strip()} or {k for k, v in (("dojo", "SEC_DEFECTDOJO_URL"), ("dtrack", "SEC_DTRACK_URL")) if os.environ.get(v)}
    for url_var in ("SEC_DEFECTDOJO_URL", "SEC_DTRACK_URL"):
        u = os.environ.get(url_var, "")
        if u and not u.startswith(("http://", "https://")):
            print(f"{url_var} must start with http:// or https://", file=sys.stderr)
            return 1 if a.strict else 0
    if not want:
        print("nothing to publish: set SEC_DEFECTDOJO_URL and/or SEC_DTRACK_URL", file=sys.stderr)
        return 1 if a.strict else 0
    in_ci = any(os.environ.get(k) for k in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD"))
    if not in_ci and not a.strict and not a.dry_run:
        return 0   # a developer's local scan: publishing is a CI job (run `warden publish` on purpose to send one)
    repo, branch, commit, run = load_ci_context()(a.root)
    ctx = (repo, branch or "unknown", commit or "", run or "")   # a detached checkout still gets a usable (non-empty) engagement / version name
    ok = True
    if "dojo" in want:
        ok = publish_dojo(a, ctx) and ok
    if "dtrack" in want:
        ok = publish_dtrack(a, ctx) and ok
    return 0 if ok or not a.strict else 1


if __name__ == "__main__":
    sys.exit(main())
