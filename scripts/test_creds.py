"""Tests for `warden creds` (scripts/creds.py): the local test-credential store. Run: python3 -I scripts/test_creds.py"""
import os, stat, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "creds.py")
HOME = tempfile.mkdtemp()


def run(*args, stdin=None, **env):
    e = {k: v for k, v in os.environ.items() if not k.startswith(("WARDEN_", "SEC_", "XDG_"))}
    e.update(HOME=HOME, XDG_CONFIG_HOME=os.path.join(HOME, ".config"), **env)
    p = subprocess.run([sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True, env=e, input=stdin, timeout=30, start_new_session=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def f(profile=""):
    return os.path.join(HOME, ".config", "warden", f"credentials.{profile}.env" if profile else "credentials.env")


def t_set_list_delete_never_shows_values_and_file_is_private():
    rc, out, err = run("set", "ZAP_AUTH_PASSWORD", "--stdin", stdin="Sup3r-S3cret\n"); assert rc == 0, err
    assert "Sup3r-S3cret" not in out + err
    assert stat.S_IMODE(os.stat(f()).st_mode) == 0o600 and stat.S_IMODE(os.stat(os.path.dirname(f())).st_mode) == 0o700
    run("set", "ZAP_AUTH_USER", "--stdin", stdin="tester\n")
    rc, out, _ = run("list"); assert "ZAP_AUTH_PASSWORD" in out and "ZAP_AUTH_USER" in out and "Sup3r-S3cret" not in out and "tester" not in out
    assert "ZAP_AUTH_PASSWORD=Sup3r-S3cret" in open(f()).read()
    assert run("delete", "ZAP_AUTH_USER")[0] == 0 and "ZAP_AUTH_USER" not in open(f()).read()
    assert "was not stored" in run("delete", "ZAP_AUTH_USER")[1]


def t_only_known_names_and_clean_values_are_accepted():
    assert run("set", "PATH", "--stdin", stdin="x\n")[0] != 0
    assert run("set", "zap_auth_password", "--stdin", stdin="x\n")[0] != 0
    assert run("set", "ZAP_AUTH_TOKEN", "--stdin", stdin="\n")[0] != 0, "an empty value is not stored"
    assert run("set")[0] != 0


def t_profiles_keep_environments_apart():
    run("set", "API_TEST_TOKEN", "--stdin", "--profile", "qa", stdin="qa-token\n"); run("set", "API_TEST_TOKEN", "--stdin", "--profile", "uat", stdin="uat-token\n")
    assert "qa-token" in open(f("qa")).read() and "uat-token" in open(f("uat")).read() and "qa-token" not in open(f("uat")).read()
    assert run("set", "API_TEST_TOKEN", "--stdin", "--profile", "../evil", stdin="x\n")[0] != 0
    assert run("list", SEC_CREDENTIALS_PROFILE="qa")[1].count("API_TEST_TOKEN") == 1, "the profile can come from SEC_CREDENTIALS_PROFILE"


def t_it_refuses_to_store_credentials_inside_a_git_repository():
    repo = tempfile.mkdtemp(); subprocess.run(["git", "init", "-q", repo], check=True)
    rc, out, err = run("set", "ZAP_AUTH_TOKEN", "--stdin", stdin="x\n", WARDEN_CREDENTIALS_FILE=os.path.join(repo, "creds.env"))
    assert rc != 0 and "git working tree" in err and not os.path.exists(os.path.join(repo, "creds.env"))
    ok = os.path.join(tempfile.mkdtemp(), "elsewhere.env")
    assert run("set", "ZAP_AUTH_TOKEN", "--stdin", stdin="x\n", WARDEN_CREDENTIALS_FILE=ok)[0] == 0 and os.path.exists(ok)


TESTS = [(n, fn) for n, fn in sorted(globals().items()) if n.startswith("t_") and callable(fn)]
ok = 0
for n, fn in TESTS:
    try:
        fn(); ok += 1; print("  PASS ", n[2:])
    except Exception as e:
        import traceback; print("  FAIL ", n[2:], repr(e)); traceback.print_exc(limit=3)
print("%d/%d passed" % (ok, len(TESTS)))
sys.exit(0 if ok == len(TESTS) else 1)
