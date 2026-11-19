"""Installer extras + templates (no Docker, no network): dependabot per ecosystem, VS Code files only when absent, CI templates parse,
Falco rules have a sound structure, no template contains a floating action tag. Run: python3 -I scripts/test_platform_templates.py
Needs PyYAML (pip install pyyaml); the checks are skipped with a message when it is missing."""
import json, os, re, shutil, subprocess, sys, tempfile
try:
    import yaml
except ImportError:
    print("PyYAML missing: skipped"); sys.exit(0)
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TPL = os.path.join(ROOT, "modes", "per-project", "templates")


def init(repo, *args):
    r = subprocess.run([os.path.join(ROOT, "scripts", "warden"), "init", repo, "--vendor", *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
    return r.stdout


def mono():
    d = tempfile.mkdtemp()
    for sub, src in (("backend/requirements.txt", "examples/fastapi-sample/requirements.txt"), ("backend/Dockerfile", "examples/fastapi-sample/Dockerfile"), ("frontend/package.json", "examples/node-sample/package.json"), ("svc/pom.xml", "examples/java-sample/pom.xml")):
        os.makedirs(os.path.dirname(os.path.join(d, sub)), exist_ok=True)
        shutil.copy(os.path.join(ROOT, src), os.path.join(d, sub))
    subprocess.run(["git", "-C", d, "init", "-q"], check=True)
    return d


def test_dependabot_covers_each_ecosystem_in_its_own_directory():
    d = mono(); out = init(d)
    dep = yaml.safe_load(open(d + "/.github/dependabot.yml"))
    got = {(u["package-ecosystem"], u["directory"]) for u in dep["updates"]}
    assert got == {("pip", "/backend"), ("docker", "/backend"), ("npm", "/frontend"), ("maven", "/svc"), ("github-actions", "/")}, got
    assert all(u["schedule"]["interval"] == "weekly" for u in dep["updates"]) and dep["version"] == 2
    assert ".github/dependabot.yml" in out


def test_existing_files_are_never_overwritten_and_rerun_is_stable():
    d = mono(); init(d)
    open(d + "/.vscode/extensions.json", "w").write('{"recommendations": ["mine.ext"]}')
    before = open(d + "/.github/dependabot.yml").read()
    open(d + "/.github/dependabot.yml", "a").write("# edited\n")
    out = init(d)
    assert "mine.ext" in open(d + "/.vscode/extensions.json").read() and "# edited" in open(d + "/.github/dependabot.yml").read()
    assert "dependabot" not in out and before in open(d + "/.github/dependabot.yml").read()


def test_a_repo_with_its_own_dependabot_or_renovate_choice_is_respected():
    d = mono(); os.makedirs(d + "/.github"); open(d + "/.github/dependabot.yaml", "w").write("version: 2\nupdates: []\n")
    init(d)
    assert not os.path.exists(d + "/.github/dependabot.yml")


def test_ci_templates_are_installed_and_parse():
    d = mono(); init(d)
    ci = d + "/.security/ci"
    for name in ("security-sign-release.github.yml", "security-scorecard.github.yml", "security-scan.github.yml", "security-release.github.yml"):
        y = yaml.safe_load(open(f"{ci}/{name}")); assert "jobs" in y, name
    r = json.load(open(ci + "/renovate.json")); assert "config:recommended" in r["extends"]
    ve = json.load(open(d + "/.vscode/extensions.json")); assert "Semgrep.semgrep" in ve["recommendations"] and "SonarSource.sonarlint-vscode" in ve["recommendations"]
    json.load(open(d + "/.vscode/settings.json"))


def test_every_workflow_template_pins_actions_and_does_not_persist_credentials():
    """The kit's own scanner (zizmor) flags unpinned actions, persisted checkout credentials and inline ${{ vars }} in scripts: the files
    `warden init` writes into a repo must pass it, or a brand-new repo fails its first scan."""
    names = sorted(f for f in os.listdir(TPL) if f.startswith("github-actions-") and f.endswith(".yml")) + ["../../../.github/workflows/security-scan-reusable.yml"]
    for name in names:
        text = open(os.path.join(TPL, name)).read()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for m in re.finditer(r"uses:\s*([\w./-]+)@(\S+)", code):
            assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), f"{name}: {m.group(1)}@{m.group(2)} is not pinned to a commit SHA"
        y = yaml.safe_load(text)
        for job in y["jobs"].values():
            for st in job.get("steps", []):
                if str(st.get("uses", "")).startswith("actions/checkout@"):
                    assert (st.get("with") or {}).get("persist-credentials") is False, f"{name}: checkout keeps credentials"
                assert "${{ vars." not in str(st.get("run", "")) and "${{ inputs." not in str(st.get("run", "")), f"{name}: expression inlined in a script"
    assert "secrets: inherit" not in open(f"{TPL}/github-actions-reusable-caller.yml").read()


def test_generated_dependabot_has_a_cooldown():
    d = mono(); init(d)
    dep = yaml.safe_load(open(d + "/.github/dependabot.yml"))
    assert all(u.get("cooldown", {}).get("default-days", 0) >= 3 for u in dep["updates"])


def test_release_templates_pin_actions_to_commit_shas_and_declare_least_privilege():
    for name in ("github-actions-sign-release.yml", "github-actions-scorecard.yml"):
        text = open(f"{TPL}/{name}").read()
        for m in re.finditer(r"uses:\s*([\w./-]+)@(\S+)", text):
            assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), f"{name}: {m.group(1)} is not pinned to a commit SHA"
        y = yaml.safe_load(text)
        assert y["permissions"] in ("read-all", {"contents": "read"}), name           # top level is read-only; jobs add what they need
    sign = yaml.safe_load(open(f"{TPL}/github-actions-sign-release.yml"))["jobs"]["build-sign-attest"]["permissions"]
    assert sign["id-token"] == "write" and sign["attestations"] == "write" and sign["packages"] == "write"
    assert "TEMPLATE, NOT RUN" in open(f"{TPL}/github-actions-sign-release.yml").read()


def test_falco_rules_are_structurally_sound():
    d = yaml.safe_load(open(f"{ROOT}/configs/runtime/falco-agent-rules.yaml"))
    names = {x[k] for x in d for k in ("list", "macro") if k in x}
    rules = [x for x in d if "rule" in x]
    assert len(rules) >= 7 and any("required_engine_version" in x for x in d)
    for r in rules:
        assert all(k in r for k in ("desc", "condition", "output", "priority")) and r["priority"] in ("DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY"), r["rule"]
        for ref in re.findall(r"\b(agent_[a-z_]+)\b", r["condition"]):
            assert ref in names, f"{r['rule']}: {ref} is not defined"
    assert any(r["priority"] == "CRITICAL" and "metadata" in r["rule"].lower() for r in rules)


def test_policy_text_sla_matches_policy_json():
    sla = json.load(open(f"{ROOT}/configs/policies/policy.json"))["sla_days"]
    text = open(f"{ROOT}/docs/process/vulnerability-management-policy.md").read()
    for sev, days in sla.items():
        assert re.search(r"\|\s*\*\*%s\*\*\s*\|\s*\*\*%d days\*\*" % (sev.title(), days), text) or re.search(r"\|\s*%s\s*\|\s*%d days" % (sev.title(), days), text), f"{sev} {days} days is not in the policy text"


def test_relative_links_in_the_new_docs_resolve():
    files = [os.path.join(ROOT, "docs", "process", f) for f in os.listdir(os.path.join(ROOT, "docs", "process"))] + [os.path.join(ROOT, "docs", n) for n in ("runtime-detection.md", "dashboard.md", "integrations.md")]
    bad = []
    for f in files:
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", open(f).read()):
            if re.match(r"^(https?:|mailto:)", target):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(f), target))):
                bad.append((os.path.relpath(f, ROOT), target))
    assert not bad, bad


if __name__ == "__main__":
    n = fail = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            n += 1
            try:
                fn(); print("  PASS ", name)
            except Exception as e:
                fail += 1; print("  FAIL ", name, repr(e)[:300])
    print(f"{n - fail}/{n} passed"); sys.exit(1 if fail else 0)
