"""REAL HashiCorp Vault (dev mode, throw-away container, own docker network, port bound to 127.0.0.1) tests for agentsec.secrets.
Skips (does not fail) when Docker or the vault image is unavailable. Everything it creates is removed afterwards.
Run: python3 -W ignore -I agentic/tests/test_vault_docker.py (~20 s)"""
import json
import os
import secrets as pysecrets
import subprocess
import sys
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agentsec.secrets import RotatingSecret, SecretError, SecretNotFound, VaultKV2Provider, age_report  # noqa: E402

IMAGE = os.environ.get("VAULT_TEST_IMAGE", "hashicorp/vault:1.18")
SUFFIX = pysecrets.token_hex(4)
NAME, NET = f"secscan-vault-test-{SUFFIX}", f"secscan-vault-net-{SUFFIX}"
ROOT_TOKEN = "root-" + pysecrets.token_hex(12)          # random per run: nothing reusable
STATE = {}


def sh(*a, **k):
    return subprocess.run(list(a), capture_output=True, text=True, **k)


def api(method, path, body=None, token=ROOT_TOKEN):
    req = urllib.request.Request(STATE["addr"] + path, data=None if body is None else json.dumps(body).encode(), method=method,
                                 headers={"X-Vault-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def setUpModule():
    if sh("docker", "info").returncode != 0:
        raise unittest.SkipTest("docker not available")
    if sh("docker", "image", "inspect", IMAGE).returncode != 0 and sh("docker", "pull", "-q", IMAGE).returncode != 0:
        raise unittest.SkipTest(f"cannot pull {IMAGE}")
    assert sh("docker", "network", "create", NET).returncode == 0
    r = sh("docker", "run", "-d", "--name", NAME, "--network", NET, "--cap-add=IPC_LOCK", "-p", "127.0.0.1::8200",
           "-e", f"VAULT_DEV_ROOT_TOKEN_ID={ROOT_TOKEN}", "-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200", IMAGE)
    if r.returncode != 0:
        tearDownModule()
        raise unittest.SkipTest("vault container did not start: " + r.stderr[:200])
    port = sh("docker", "port", NAME, "8200/tcp").stdout.split(":")[-1].strip()
    STATE["addr"] = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(STATE["addr"] + "/v1/sys/health", timeout=2)
            break
        except Exception:
            time.sleep(0.5)
    else:
        tearDownModule()
        raise unittest.SkipTest("vault did not become ready")
    api("POST", "/v1/secret/data/app/db", {"data": {"value": "v1-db-password", "user": "svc"}})
    api("POST", "/v1/secret/data/other/x", {"data": {"value": "not-for-the-app"}})
    api("POST", "/v1/sys/auth/approle", {"type": "approle"})
    api("PUT", "/v1/sys/policies/acl/app-read", {"policy": 'path "secret/data/app/*" { capabilities = ["read"] }'})
    for role, ttl in (("app", "10m"), ("short", "2s")):
        api("POST", f"/v1/auth/approle/role/{role}", {"token_policies": ["app-read"], "token_ttl": ttl, "token_max_ttl": ttl if role == "short" else "1h"})
        STATE[role] = (api("GET", f"/v1/auth/approle/role/{role}/role-id")["data"]["role_id"],
                       api("POST", f"/v1/auth/approle/role/{role}/secret-id", {})["data"]["secret_id"])


def tearDownModule():
    sh("docker", "rm", "-f", "-v", NAME)
    sh("docker", "network", "rm", NET)


class VaultRealTests(unittest.TestCase):
    def test_token_read_with_version_and_age(self):
        s = VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN).get("app/db")
        self.assertEqual(s.reveal(), "v1-db-password")
        self.assertEqual(s.version, 1)
        self.assertLess(s.age_days(), 1)
        self.assertGreaterEqual(s.age_days(), 0)
        self.assertNotIn("v1-db-password", repr(s))

    def test_field_selection_and_missing(self):
        v = VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN)
        self.assertEqual(v.get("app/db#user").reveal(), "svc")
        with self.assertRaises(SecretNotFound):
            v.get("app/does-not-exist")
        with self.assertRaises(SecretNotFound):
            v.get("app/db#nofield")

    def test_approle_login_and_least_privilege(self):
        v = VaultKV2Provider(STATE["addr"], role_id=STATE["app"][0], secret_id=STATE["app"][1])
        self.assertEqual(v.get("app/db").reveal(), "v1-db-password")
        with self.assertRaises(SecretError) as cm:                              # policy allows secret/data/app/* only
            v.get("other/x")
        self.assertIn("403", str(cm.exception))
        self.assertNotIn("not-for-the-app", str(cm.exception))

    def test_bad_credentials_never_appear_in_errors(self):
        with self.assertRaises(SecretError) as cm:
            VaultKV2Provider(STATE["addr"], token="hvs.wrong-token-value").get("app/db")
        self.assertNotIn("wrong-token-value", str(cm.exception))
        with self.assertRaises(SecretError) as cm:
            VaultKV2Provider(STATE["addr"], role_id=STATE["app"][0], secret_id="00000000-not-the-secret-id").get("app/db")
        self.assertNotIn("not-the-secret-id", str(cm.exception))
        self.assertNotIn(ROOT_TOKEN, repr(VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN)))

    def test_expired_token_triggers_a_fresh_login(self):
        v = VaultKV2Provider(STATE["addr"], role_id=STATE["short"][0], secret_id=STATE["short"][1], ttl=0)
        self.assertEqual(v.get("app/db").reveal(), "v1-db-password")
        first = v._token
        time.sleep(4)                                                           # the 2 s token has expired inside Vault
        self.assertEqual(v.get("app/db").reveal(), "v1-db-password")
        self.assertNotEqual(v._token, first)

    def test_cache_ttl_and_invalidate_see_new_versions(self):
        api("POST", "/v1/secret/data/app/cache-test", {"data": {"value": "one"}})
        v = VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN, ttl=60)
        self.assertEqual(v.get("app/cache-test").reveal(), "one")
        api("POST", "/v1/secret/data/app/cache-test", {"data": {"value": "two"}})
        self.assertEqual(v.get("app/cache-test").reveal(), "one")               # cached
        v.invalidate("app/cache-test")
        s = v.get("app/cache-test")
        self.assertEqual((s.reveal(), s.version), ("two", 2))

    def test_rotation_through_a_refresh_callback(self):
        api("POST", "/v1/secret/data/app/rot", {"data": {"value": "old-credential"}})
        v = VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN, ttl=60)
        rs = RotatingSecret(v, "app/rot", max_age_days=1e-9)                    # anything older than ~0 s is "too old"
        time.sleep(1.2)
        st = rs.status()
        self.assertTrue(st["needs_rotation"] and st["age_known"], st)
        self.assertEqual(st["version"], 1)

        def refresh(name):                                                      # your job: create the new credential in the system it belongs to
            api("POST", f"/v1/secret/data/{name}", {"data": {"value": "new-credential"}})
        fresh = RotatingSecret(v, "app/rot", max_age_days=1e-9, refresh=refresh).get(auto_rotate=True)
        self.assertEqual((fresh.reveal(), fresh.version), ("new-credential", 2))
        self.assertFalse(RotatingSecret(v, "app/rot", max_age_days=1).status()["needs_rotation"])

    def test_age_report_orders_oldest_first_and_reports_errors(self):
        v = VaultKV2Provider(STATE["addr"], token=ROOT_TOKEN)
        rows = age_report([RotatingSecret(v, "app/db", max_age_days=30), RotatingSecret(v, "app/missing", max_age_days=30)])
        self.assertEqual(len(rows), 2)
        self.assertTrue(any("error" in r for r in rows))
        self.assertTrue(all("v1-db-password" not in json.dumps(r) for r in rows))


if __name__ == "__main__":
    unittest.main()
