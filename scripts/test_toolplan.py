import argparse, datetime as dt, json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(__file__))
import toolplan as tp

POLICY = os.path.join(os.path.dirname(__file__), "..", "configs", "policies", "policy.json")


def A(**kw):
    d = dict(policy=POLICY, preset="starter", profiles=["python"], modes="", exceptions=None, image="", zap_url="", redteam_url="", model_files=False, partial=False, facts=[], api_spec="", exposure_targets="")
    d.update(kw)
    return argparse.Namespace(**d)


def runs(p):
    return {t for t, v in p["tools"].items() if v["run"]}


def test_defaults_python():
    p = tp.plan(A())
    assert runs(p) == {"gitleaks", "semgrep", "trivy-fs", "sbom", "bandit", "pip-audit"}
    assert "not a Node" in p["tools"]["eslint"]["reason"]


def test_node_and_agent_profiles():
    r = runs(tp.plan(A(profiles=["node", "agent"])))
    assert {"npm-audit", "eslint", "agent-scan"} <= r and "bandit" not in r


def test_optional_tools_follow_targets():
    r = runs(tp.plan(A(image="app:1", zap_url="http://x", redteam_url="http://y")))
    assert {"trivy-image", "zap", "redteam"} <= r
    assert not runs(tp.plan(A())) & {"trivy-image", "zap", "redteam", "sonarqube", "dependency-check"}


def test_off_switch_for_optional_tool():
    assert "bandit" not in runs(tp.plan(A(modes="bandit=off")))


def test_required_tool_cannot_be_turned_off():
    p = tp.plan(A(modes="semgrep=off,gitleaks=off,trivy=off"))
    assert {"semgrep", "gitleaks", "trivy-fs"} <= runs(p)
    assert p["tools"]["semgrep"]["forced"] and "REQUIRED" in p["tools"]["semgrep"]["reason"]


def test_required_for_agent_profile_only():
    assert "agent-scan" in runs(tp.plan(A(profiles=["python", "agent"], modes="agent-scan=off")))


def test_modelscan_required_only_when_models_exist():
    assert "modelscan" in runs(tp.plan(A(model_files=True, modes="modelscan=off")))
    assert "modelscan" not in runs(tp.plan(A(model_files=False, modes="modelscan=off")))


def test_partial_run_may_skip_required():
    p = tp.plan(A(modes="trivy=off", partial=True))
    assert "trivy-fs" not in runs(p)


def _ex(entries):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(entries, f); f.close()
    return f.name


def test_waiver_allows_off_and_is_reported():
    tomorrow = (dt.date.today() + dt.timedelta(days=5)).isoformat()
    p = tp.plan(A(modes="semgrep=off", exceptions=_ex([{"tool": "semgrep", "reason": "no rules offline", "approved_by": "sec-team", "expires": tomorrow}])))
    assert "semgrep" not in runs(p) and "waived by sec-team" in p["tools"]["semgrep"]["reason"] and p["waivers"][0]["tool"] == "semgrep"


def test_expired_or_incomplete_waiver_is_ignored():
    old = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    p = tp.plan(A(modes="semgrep=off,gitleaks=off", exceptions=_ex([{"tool": "semgrep", "reason": "x", "approved_by": "y", "expires": old}, {"tool": "gitleaks", "reason": "x"}])))
    assert {"semgrep", "gitleaks"} <= runs(p) and len(p["errors"]) == 2


def test_presets():
    assert tp.preset_defaults(json.load(open(POLICY)), "strict")["gate"] == "release"
    assert tp.preset_defaults(json.load(open(POLICY)), "starter")["enforce"] == 0
    os.environ["SONAR_HOST_URL"] = "http://s"; os.environ["SONAR_TOKEN"] = "t"
    try:
        assert "sonarqube" not in runs(tp.plan(A(preset="standard")))
        assert "sonarqube" in runs(tp.plan(A(preset="strict")))
    finally:
        del os.environ["SONAR_HOST_URL"], os.environ["SONAR_TOKEN"]


def test_legacy_names_and_on_without_target_is_reported():
    assert "bandit" not in runs(tp.plan(A(modes="bandit=0")))
    assert tp.plan(A(modes="zap=on"))["errors"]


def test_unknown_setting_is_reported_not_fatal():
    assert tp.plan(A(modes="nope=off,bandit=maybe"))["errors"]


def test_only_explicit_off_is_marked_explicit():
    p = tp.plan(A(modes="bandit=off"))
    assert p["tools"]["bandit"]["explicit"] and not p["tools"]["sonarqube"]["explicit"]   # sonarqube is off by preset default only
    assert not p["tools"]["gitleaks"]["explicit"]


def test_new_tools_follow_their_facts():
    base = runs(tp.plan(A()))
    assert "sbom" in base and not base & {"gitleaks-history", "workflow-scan", "k8s-posture", "api-fuzz", "exposure", "repo-posture"}
    r = runs(tp.plan(A(facts=["git", "workflows", "k8s", "ghrepo"], modes="history=on", api_spec="http://x/openapi.json", exposure_targets="https://qa.example")))
    assert {"gitleaks-history", "workflow-scan", "k8s-posture", "repo-posture", "api-fuzz", "exposure"} <= r


def test_git_history_scanning_is_opt_in_on_starter_and_standard_and_on_for_strict():
    for preset in ("starter", "standard"):
        assert "gitleaks-history" not in runs(tp.plan(A(facts=["git"], preset=preset))), preset
        assert "gitleaks-history" in runs(tp.plan(A(facts=["git"], preset=preset, modes="history=on"))), preset
        assert "gitleaks-history" in runs(tp.plan(A(facts=["git"], preset=preset, modes="gitleaks-history=on")))
    assert "gitleaks-history" in runs(tp.plan(A(facts=["git"], preset="strict")))
    assert "gitleaks-history" not in runs(tp.plan(A(facts=[], preset="strict"))), "no git checkout: nothing to scan"


def test_new_tools_can_be_switched_and_on_without_target_is_reported():
    assert "sbom" not in runs(tp.plan(A(modes="sbom=off"))) and "gitleaks-history" not in runs(tp.plan(A(facts=["git"], modes="history=off")))
    assert tp.plan(A(modes="api-fuzz=on"))["errors"] and tp.plan(A(modes="exposure=on"))["errors"]


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
