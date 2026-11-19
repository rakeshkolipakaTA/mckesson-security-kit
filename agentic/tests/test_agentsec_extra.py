"""Unit tests for the newer agentsec modules (no Docker, no internet): output, classify, pii additions, retention, state, secrets (mock Vault),
policy PIP/PAP, plus the AG-NET-002 residency check and the RT-OUT-01 probe. Run: python3 -W ignore -I agentic/tests/test_agentsec_extra.py
Optional dependencies (cryptography, presidio) make their tests skip, never fail."""
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))

from agentsec import (PDP, PEP, AuditLog, ClassificationError, Classifier, EnvProvider, FileProvider, OutputRejected, PolicyDenied, PolicyInvalid,  # noqa: E402
                      PolicyStore, Principal, RetentionError, RetentionPolicy, RotatingSecret, Secret, SecretError, SecretNotFound, VaultKV2Provider,
                      age_report, check_answer, classify, enforce_max_level, purge_jsonl, purge_sqlite, redact, require_valid, validate_figures,
                      validate_policy, validate_schema, verify_chain)
from agentsec.output import extract_figures, flatten_sources  # noqa: E402
from agentsec.pii import presidio_available  # noqa: E402
from agentsec.state import CryptoUnavailable, EncryptedStore, StateError, generate_key  # noqa: E402
from agentsec.secrets import CachedProvider  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# ----------------------------------------------------------------------------------------------- output integrity
class OutputTests(unittest.TestCase):
    SRC = {"revenue": {"fy2025": 1234567, "growth_pct": 4.1}, "rows": [{"region": "us", "units": 1500}]}

    def test_extracts_scaled_and_percent_figures_and_skips_dates_years_lists(self):
        f = extract_figures("1. Revenue was $1.2M (up 4.1%) on 2025-03-01 in FY2025, 1,500 units")
        self.assertEqual([x.raw for x in f], ["$1.2M", "4.1%", "1,500"])
        self.assertAlmostEqual(f[0].value, 1.2e6)

    def test_matching_figures_pass_with_rounding_and_lineage(self):
        r = validate_figures("Revenue was $1.2M, up 4.1%, with 1,500 units.", self.SRC)
        self.assertTrue(r.ok, r.violations)
        self.assertEqual(r.lineage["$1.2M"], "revenue.fy2025")
        self.assertEqual(r.lineage["4.1%"], "revenue.growth_pct")

    def test_invented_or_misscaled_figures_are_rejected(self):
        for ans in ["Revenue grew 14%.", "Revenue was $12M.", "We sold 15,000 units.", "Revenue was 1.3M"]:
            r = validate_figures(ans, self.SRC)
            self.assertFalse(r.ok, ans)
            self.assertEqual(r.violations[0].kind, "unsupported_figure")
            self.assertTrue(r.violations[0].nearest)

    def test_percent_stored_as_fraction_matches(self):
        self.assertTrue(validate_figures("Growth was 45%", {"g": 0.45}).ok)
        self.assertFalse(validate_figures("Growth was 46%", {"g": 0.45}).ok)

    def test_no_sources_is_fail_closed(self):
        r = validate_figures("Revenue was 5 million", {})
        self.assertFalse(r.ok)
        self.assertEqual(r.violations[0].kind, "no_sources")
        self.assertTrue(validate_figures("No numbers here at all.", {}).ok)

    def test_derived_values_only_when_allowed(self):
        src = {"a": 100, "b": 40}
        self.assertFalse(validate_figures("Total is 140", src).ok)
        self.assertTrue(validate_figures("Total is 140, a gap of 60", src, allow_derived=True).ok)
        self.assertTrue(validate_figures("Share is 40%", {"a": 100, "b": 40}, allow_derived=True).ok)

    def test_sources_may_be_json_strings_lists_and_text(self):
        self.assertEqual(flatten_sources('{"x": [1, {"y": 2.5}]}'), {"x[0]": 1.0, "x[1].y": 2.5})
        self.assertTrue(validate_figures("It cost 2.5", ["tool said: total=2.5"]).ok)
        self.assertEqual(flatten_sources({"flag": True}), {})            # booleans are not numbers

    def test_min_abs_skips_small_counts(self):
        self.assertTrue(validate_figures("Across 3 regions revenue was 1,234,567", self.SRC, min_abs=10).ok)

    def test_schema(self):
        schema = {"type": "object", "required": ["answer", "confidence"], "additionalProperties": False,
                  "properties": {"answer": {"type": "string", "maxLength": 20}, "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                                 "tags": {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}, "maxItems": 2}}}
        self.assertEqual(validate_schema({"answer": "ok", "confidence": 0.5, "tags": ["a"]}, schema), [])
        bad = validate_schema({"answer": 5, "confidence": 2, "extra": 1, "tags": ["z", "a", "b"]}, schema)
        msgs = " | ".join(v.message for v in bad)
        for want in ("expected string", "above the maximum", "unexpected field", "not one of", "more than 2"):
            self.assertIn(want, msgs)
        self.assertEqual(validate_schema({}, schema)[0].kind, "schema")
        self.assertFalse(validate_schema(True, {"type": "integer"}) == [])         # bool is not an integer
        self.assertEqual(validate_schema(1, {"type": "wat"})[0].kind, "schema")      # unknown type = violation (fail-closed)

    def test_check_answer_and_require_valid_fail_closed(self):
        self.assertTrue(check_answer("Revenue 4.1%", self.SRC).ok)
        self.assertEqual(require_valid("Revenue 4.1%", self.SRC), "Revenue 4.1%")
        with self.assertRaises(OutputRejected) as cm:
            require_valid("Revenue 99%", self.SRC)
        self.assertFalse(cm.exception.report.ok)
        rep = check_answer("x 5", object())                               # a checker that cannot cope must reject, not approve
        self.assertFalse(rep.ok)

    def test_combined_schema_and_figures(self):
        rep = check_answer("Growth 4.1%", self.SRC, schema={"type": "object", "required": ["x"]}, answer_obj={"y": 1})
        self.assertFalse(rep.ok)
        self.assertEqual({v.kind for v in rep.violations}, {"schema"})


# ----------------------------------------------------------------------------------------------- classification
class ClassifyTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(classify("The weather is nice today.").level, "PUBLIC")
        self.assertEqual(classify("See the intranet at wiki.corp for internal use only").level, "INTERNAL")
        self.assertEqual(classify("Q3 revenue forecast and gross margin by region").level, "CONFIDENTIAL")
        self.assertEqual(classify("Contact ada@example.com").level, "CONFIDENTIAL")
        self.assertEqual(classify("This is material non-public information about the merger").level, "RESTRICTED")
        self.assertEqual(classify("patient MRN 99887 diagnosis E11.9").level, "RESTRICTED")
        self.assertEqual(classify("card 4111 1111 1111 1111").level, "RESTRICTED")
        self.assertEqual(classify("key sk-abcdefghijklmnopqrstuv").level, "RESTRICTED")

    def test_result_never_contains_the_text(self):
        c = classify("ssn 123-45-6789 and ada@example.com")
        self.assertNotIn("123-45", json.dumps(c.matches))
        self.assertIn("pii:ssn", c.matches)

    def test_custom_rules_and_objects(self):
        c = Classifier()
        c.add_rule("project-x", "RESTRICTED", r"\bproject\s+nightingale\b")
        self.assertEqual(c.classify("status of Project Nightingale").level, "RESTRICTED")
        deep = {"messages": [{"role": "user", "content": "hello"}, {"role": "tool", "content": {"rows": ["EBITDA was 4m"]}}]}
        self.assertEqual(c.classify_obj(deep).level, "CONFIDENTIAL")
        with self.assertRaises(ValueError):
            c.add_rule("bad", "SECRET-ISH", "x")

    def test_enforce_max_level(self):
        self.assertEqual(enforce_max_level("hello world", "INTERNAL").level, "PUBLIC")
        with self.assertRaises(ClassificationError) as cm:
            enforce_max_level({"q": "forecast revenue"}, "INTERNAL")
        self.assertIn("CONFIDENTIAL", str(cm.exception))
        with self.assertRaises(ValueError):
            enforce_max_level("x", "TOP-SECRET")

        class Boom(Classifier):
            def classify_obj(self, obj, _depth=0):
                raise RuntimeError("x")
        with self.assertRaises(ClassificationError):                      # classifier crash = refuse
            enforce_max_level("hello", "RESTRICTED", classifier=Boom())


# ----------------------------------------------------------------------------------------------- stronger PII
class PiiExtraTests(unittest.TestCase):
    def test_names_and_addresses(self):
        t, c = redact("Dr. Jane Smith lives at 221 Baker Street, Apt 4B")
        self.assertEqual(t, "[NAME] lives at [ADDRESS]")
        self.assertEqual(c, {"NAME": 1, "ADDRESS": 1})
        self.assertEqual(redact("my name is Alan Turing")[0], "[NAME]")
        self.assertEqual(redact("ship to 1600 Pennsylvania Avenue")[0], "ship to [ADDRESS]")

    def test_no_false_positives_on_ordinary_text(self):
        for ok in ["The doctor will see you now.", "Revenue was 1500 units across 3 regions.", "Version 2.3 shipped on 2025-01-02.", "Drive safely on Main"]:
            self.assertEqual(redact(ok)[0], ok, ok)

    def test_existing_behaviour_unchanged(self):
        t, c = redact("mail ada@example.com ssn 123-45-6789 card 4111 1111 1111 1111")
        self.assertEqual(c, {"EMAIL": 1, "SSN": 1, "CARD": 1})

    def test_presidio_masks_free_text_names_and_places_when_installed(self):
        if not presidio_available():
            self.skipTest("presidio-analyzer not installed")
        try:
            import spacy
            spacy.load(os.environ.setdefault("AGENTSEC_SPACY_MODEL", "en_core_web_sm"))
        except Exception:
            self.skipTest("spaCy model not installed (python -m spacy download en_core_web_sm)")
        t, c = redact("Please email Jane Smith in Chicago about the invoice. Card 4111 1111 1111 1111.", presidio=True)
        self.assertNotIn("Jane", t)
        self.assertNotIn("Chicago", t)
        self.assertIn("[CARD]", t)                                         # the regex layer still runs after Presidio
        self.assertGreaterEqual(c.get("PERSON", 0), 1)

    def test_presidio_is_never_silently_skipped(self):
        if presidio_available():
            self.skipTest("presidio installed: behaviour depends on the spaCy model")
        with self.assertRaises(RuntimeError):
            redact("Jane Smith", presidio=True)


# ----------------------------------------------------------------------------------------------- retention
class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.now = 1_900_000_000.0

    def _chain(self, path, ages_days, key="k"):
        log = AuditLog(path, key=key)
        for i, a in enumerate(ages_days):
            rec = log.record(actor="u", agent="bot", action=f"a{i}")
        # rewrite the timestamps oldest-first is not possible without breaking the chain, so build records with explicit ts instead
        return log

    def _write_chain(self, path, ages_days, key=b"k"):
        from agentsec.audit import _GENESIS, _digest
        prev = _GENESIS
        with open(path, "w") as f:
            for i, a in enumerate(ages_days):
                rec = {"ts": self.now - a * 86400, "actor": "u", "agent": "bot", "action": f"a{i}", "resource": "", "decision": "", "details": {}}
                rec["prev"] = prev
                rec["hash"] = _digest(prev, {k: v for k, v in rec.items() if k not in ("prev", "hash")}, key)
                f.write(json.dumps(rec, sort_keys=True) + "\n")
                prev = rec["hash"]

    def test_dry_run_is_default_and_changes_nothing(self):
        p = os.path.join(self.d, "a.jsonl")
        self._write_chain(p, [400, 300, 10, 1])
        before = open(p).read()
        rep = purge_jsonl(p, days=100, now=self.now)
        self.assertTrue(rep["dry_run"])
        self.assertEqual((rep["removed"], rep["kept"]), (2, 2))
        self.assertEqual(open(p).read(), before)

    def test_purge_keeps_hash_chain_verifiable_via_anchor(self):
        p = os.path.join(self.d, "a.jsonl")
        self._write_chain(p, [400, 300, 10, 1])
        self.assertTrue(verify_chain(p, key="k")[0])
        rep = purge_jsonl(p, days=100, dry_run=False, now=self.now)
        self.assertEqual(rep["removed"], 2)
        ok, n, bad = verify_chain(p, key="k")
        self.assertTrue(ok, (n, bad))
        self.assertEqual(n, 2)
        self.assertTrue(os.path.exists(p + ".anchor"))
        lines = open(p).read().splitlines()
        tampered = json.loads(lines[0])
        tampered["actor"] = "eve"
        open(p, "w").write(json.dumps(tampered, sort_keys=True) + "\n" + lines[1] + "\n")
        self.assertFalse(verify_chain(p, key="k")[0])                      # edits are still detected after a purge

    def test_undated_and_non_json_lines_are_kept(self):
        p = os.path.join(self.d, "m.jsonl")
        open(p, "w").write(json.dumps({"ts": self.now - 999 * 86400}) + "\nnot json\n" + json.dumps({"no": "ts"}) + "\n")
        rep = purge_jsonl(p, days=30, dry_run=False, now=self.now)
        self.assertEqual((rep["removed"], rep["undated_kept"]), (1, 2))
        self.assertIn("not json", open(p).read())

    def test_minimum_retention_floor_and_bad_days(self):
        pol = RetentionPolicy({"RESTRICTED": 30}, min_days={"audit": 365})
        p = os.path.join(self.d, "a.jsonl")
        self._write_chain(p, [10])
        with self.assertRaises(RetentionError):
            purge_jsonl(p, days=30, kind="audit", policy=pol, dry_run=False)
        with self.assertRaises(RetentionError):
            purge_jsonl(p, days=0)
        self.assertEqual(pol.days_for("RESTRICTED"), 30)
        with self.assertRaises(RetentionError):
            pol.days_for("UNKNOWN")

    def test_sqlite_epoch_ms_and_iso(self):
        db = os.path.join(self.d, "s.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE msgs (id INTEGER, ts REAL, iso TEXT)")
        now = self.now
        iso = lambda a: time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - a * 86400))
        rows = [(1, now - 400 * 86400, iso(400)), (2, (now - 5 * 86400) * 1000, iso(5)), (3, now - 200 * 86400, iso(200))]
        con.executemany("INSERT INTO msgs VALUES (?,?,?)", rows)
        con.commit()
        con.close()
        rep = purge_sqlite(db, "msgs", "ts", days=100, now=now)
        self.assertEqual((rep["removed"], rep["kept"], rep["dry_run"]), (2, 1, True))
        self.assertEqual(sqlite3.connect(db).execute("SELECT COUNT(*) FROM msgs").fetchone()[0], 3)
        purge_sqlite(db, "msgs", "ts", days=100, now=now, dry_run=False)
        self.assertEqual([r[0] for r in sqlite3.connect(db).execute("SELECT id FROM msgs")], [2])
        rep = purge_sqlite(db, "msgs", "iso", days=1, ts_kind="iso", now=now, dry_run=False)
        self.assertEqual(rep["removed"], 1)

    def test_sqlite_identifier_injection_is_refused(self):
        db = os.path.join(self.d, "s.db")
        sqlite3.connect(db).execute("CREATE TABLE t (ts REAL)")
        for bad in ["t; DROP TABLE t", 't" OR 1=1 --', "t t"]:
            with self.assertRaises(RetentionError):
                purge_sqlite(db, bad, "ts", days=1)
        with self.assertRaises(RetentionError):
            purge_sqlite(db, "t", "ts", days=1, ts_kind="weird")


# ----------------------------------------------------------------------------------------------- encrypted state
@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class StateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "state.json")

    def test_roundtrip_ciphertext_on_disk_and_mode(self):
        s = EncryptedStore(self.p, generate_key())
        s.set("memory:u1", {"notes": "likes tea", "n": 3})
        self.assertEqual(s.get("memory:u1"), {"notes": "likes tea", "n": 3})
        raw = open(self.p).read()
        self.assertNotIn("likes tea", raw)
        self.assertNotIn("memory:u1\"", raw.replace('"memory:u1":', ""))     # only the key name is visible, not values
        self.assertEqual(oct(os.stat(self.p).st_mode & 0o777), "0o600")
        self.assertEqual(s.get("nope", "dflt"), "dflt")
        s.delete("memory:u1")
        self.assertEqual(s.keys(), [])

    def test_wrong_key_and_tampering_are_refused(self):
        k1, k2 = generate_key(), generate_key()
        EncryptedStore(self.p, k1).set("a", "secret value")
        with self.assertRaises(StateError):
            EncryptedStore(self.p, k2).get("a")
        doc = json.load(open(self.p))
        doc["a"] = doc["a"][:-4] + "AAAA"
        json.dump(doc, open(self.p, "w"))
        with self.assertRaises(StateError):
            EncryptedStore(self.p, k1).get("a")

    def test_ciphertext_cannot_be_moved_between_keys(self):
        k = generate_key()
        s = EncryptedStore(self.p, k)
        s.set("user:alice", "alice data")
        s.set("user:bob", "bob data")
        doc = json.load(open(self.p))
        doc["user:bob"] = doc["user:alice"]                              # swap attack
        json.dump(doc, open(self.p, "w"))
        with self.assertRaises(StateError):
            EncryptedStore(self.p, k).get("user:bob")

    def test_key_rotation(self):
        old, new = generate_key(), generate_key()
        EncryptedStore(self.p, old).set("a", 1)
        s = EncryptedStore(self.p, [new, old])
        self.assertEqual(s.get("a"), 1)
        self.assertEqual(s.rotate(), 1)
        self.assertEqual(EncryptedStore(self.p, new).get("a"), 1)        # readable with the new key alone
        with self.assertRaises(StateError):
            EncryptedStore(self.p, old).get("a")

    def test_corrupt_file_and_missing_keys(self):
        open(self.p, "w").write("not json")
        with self.assertRaises(StateError):
            EncryptedStore(self.p, generate_key())
        with self.assertRaises(StateError):
            EncryptedStore(os.path.join(self.d, "x.json"), [])


class StateWithoutCryptoTests(unittest.TestCase):
    def test_clear_error_when_dependency_missing(self):
        import builtins
        real = builtins.__import__

        def fake(name, *a, **k):
            if name.startswith("cryptography"):
                raise ImportError("blocked")
            return real(name, *a, **k)
        builtins.__import__ = fake
        try:
            with self.assertRaises(CryptoUnavailable) as cm:
                EncryptedStore(os.path.join(tempfile.mkdtemp(), "s.json"), "x")
            self.assertIn("pip install cryptography", str(cm.exception))
        finally:
            builtins.__import__ = real


# ----------------------------------------------------------------------------------------------- secrets (+ a MOCK Vault: the real one is in test_vault_docker.py)
class MockVault(BaseHTTPRequestHandler):
    data = {"app/db": {"value": "s3cret-pass", "user": "svc"}}
    created = "2020-01-01T00:00:00.000000Z"
    logins = 0
    tokens = {"root-token"}
    seen_namespace = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/v1/auth/approle/login":
            if body == {"role_id": "role-1", "secret_id": "sid-1"}:
                MockVault.logins += 1
                tok = f"tok-{MockVault.logins}"
                MockVault.tokens.add(tok)
                return self._send(200, {"auth": {"client_token": tok}})
            return self._send(400, {"errors": ["invalid"]})
        self._send(404, {})

    def do_GET(self):  # noqa: N802
        MockVault.seen_namespace = self.headers.get("X-Vault-Namespace")
        if self.headers.get("X-Vault-Token") not in MockVault.tokens:
            return self._send(403, {"errors": ["permission denied"]})
        if self.path.startswith("/v1/secret/data/"):
            key = self.path[len("/v1/secret/data/"):]
            if key in MockVault.data:
                return self._send(200, {"data": {"data": MockVault.data[key], "metadata": {"version": 3, "created_time": MockVault.created}}})
        self._send(404, {"errors": []})


class SecretsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), MockVault)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.addr = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        MockVault.tokens = {"root-token"}
        MockVault.logins = 0

    def test_secret_never_leaks_through_repr_str_or_pickle(self):
        s = Secret("hunter2-value", "db")
        for text in (repr(s), str(s), f"{s}", "%s" % s, json.dumps({"x": repr(s)})):
            self.assertNotIn("hunter2", text)
        self.assertEqual(s.reveal(), "hunter2-value")
        import pickle
        with self.assertRaises(TypeError):
            pickle.dumps(s)

    def test_env_and_file_providers(self):
        self.assertEqual(EnvProvider("APP_", {"APP_KEY": "v1"}).get("KEY").reveal(), "v1")
        with self.assertRaises(SecretNotFound):
            EnvProvider("", {"X": ""}).get("X")                           # empty = not set
        d = tempfile.mkdtemp()
        open(os.path.join(d, "dbpass"), "w").write("p@ss\n")
        os.symlink("/etc/passwd", os.path.join(d, "evil"))
        fp = FileProvider(d)
        self.assertEqual(fp.get("dbpass").reveal(), "p@ss")
        self.assertIsNotNone(fp.get("dbpass").created)
        for bad in ["../etc/passwd", "evil", "a/../../x", "", "/etc/passwd"]:
            with self.assertRaises(SecretError, msg=bad):
                fp.get(bad)
        with self.assertRaises(SecretNotFound):
            fp.get("missing")
        os.chmod(os.path.join(d, "dbpass"), 0o644)
        with self.assertRaises(SecretError):
            FileProvider(d, strict_perms=True).get("dbpass")

    def test_vault_token_read_fields_metadata_and_errors(self):
        v = VaultKV2Provider(self.addr, token="root-token")
        s = v.get("app/db")
        self.assertEqual((s.reveal(), s.version), ("s3cret-pass", 3))
        self.assertGreater(s.age_days(), 365)                           # created 2020
        self.assertEqual(v.get("app/db#user").reveal(), "svc")
        with self.assertRaises(SecretNotFound):
            v.get("app/nope")
        with self.assertRaises(SecretNotFound):
            v.get("app/db#missingfield")
        with self.assertRaises(SecretError) as cm:
            VaultKV2Provider(self.addr, token="wrong").get("app/db")
        self.assertNotIn("wrong", str(cm.exception))                     # tokens never appear in errors
        self.assertNotIn("root-token", repr(v))

    def test_vault_approle_login_and_relogin_on_expiry(self):
        v = VaultKV2Provider(self.addr, role_id="role-1", secret_id="sid-1", ttl=0)
        self.assertEqual(v.get("app/db").reveal(), "s3cret-pass")
        self.assertEqual(MockVault.logins, 1)
        MockVault.tokens = {"unrelated"}                                  # the token expires server-side
        MockVault.tokens.add("tok-2")                                     # the next login will issue tok-2
        self.assertEqual(v.get("app/db").reveal(), "s3cret-pass")
        self.assertEqual(MockVault.logins, 2)
        with self.assertRaises(SecretError):
            VaultKV2Provider(self.addr, role_id="role-1", secret_id="bad").get("app/db")

    def test_vault_namespace_and_ttl_cache(self):
        v = VaultKV2Provider(self.addr, token="root-token", namespace="team-a", ttl=60)
        v.get("app/db")
        self.assertEqual(MockVault.seen_namespace, "team-a")
        MockVault.data["app/db"] = {"value": "rotated"}
        self.assertEqual(v.get("app/db").reveal(), "s3cret-pass")        # cached
        v.invalidate("app/db")
        self.assertEqual(v.get("app/db").reveal(), "rotated")
        MockVault.data["app/db"] = {"value": "s3cret-pass", "user": "svc"}

    def test_vault_address_safety(self):
        with self.assertRaises(SecretError):
            VaultKV2Provider("http://vault.example.com:8200", token="t")   # plain http to a remote host
        VaultKV2Provider("http://vault.example.com:8200", token="t", allow_insecure=True)
        VaultKV2Provider("https://vault.example.com", token="t")
        with self.assertRaises(SecretError):
            VaultKV2Provider(self.addr)                                    # no credentials
        with self.assertRaises(SecretError):
            VaultKV2Provider("https://vault.example.com", token="t").get("../x")
        down = VaultKV2Provider("http://127.0.0.1:9", token="tok", timeout=1)
        with self.assertRaises(SecretError) as cm:
            down.get("app/db")
        self.assertNotIn("tok", str(cm.exception).replace("token", ""))

    def test_cached_provider_ttl(self):
        calls = []

        class P:
            def get(self, name):
                calls.append(name)
                return Secret("v", name)
        c = CachedProvider(P(), ttl=60)
        c.get("a"), c.get("a")
        self.assertEqual(len(calls), 1)
        c.invalidate()
        c.get("a")
        self.assertEqual(len(calls), 2)

    def test_rotation_tracking(self):
        v = VaultKV2Provider(self.addr, token="root-token")
        rs = RotatingSecret(v, "app/db", max_age_days=90)
        st = rs.status()
        self.assertTrue(st["needs_rotation"] and st["age_known"] and st["age_days"] > 365)
        rotated = []

        def refresh(name):
            rotated.append(name)
            MockVault.created = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime())
        rs2 = RotatingSecret(v, "app/db", max_age_days=90, refresh=refresh)
        rs2.get(auto_rotate=True)
        self.assertEqual(rotated, ["app/db"])
        self.assertFalse(rs2.status()["needs_rotation"])
        MockVault.created = "2020-01-01T00:00:00.000000Z"
        with self.assertRaises(SecretError):
            RotatingSecret(v, "app/db", max_age_days=90).rotate()          # no callback configured
        with self.assertRaises(SecretError):
            RotatingSecret(v, "x", max_age_days=0)

    def test_unknown_age_counts_as_needing_rotation_and_report_never_raises(self):
        rs = RotatingSecret(EnvProvider("", {"K": "v"}), "K", max_age_days=30)
        self.assertTrue(rs.status()["needs_rotation"])                    # env gives no timestamp: never assume it is young
        broken = RotatingSecret(EnvProvider("", {}), "MISSING", max_age_days=30)
        rows = age_report([rs, broken, RotatingSecret(VaultKV2Provider(self.addr, token="root-token"), "app/db", max_age_days=90)])
        self.assertEqual(len(rows), 3)
        self.assertTrue(any("error" in r for r in rows))
        self.assertTrue(all(r["needs_rotation"] for r in rows))


# ----------------------------------------------------------------------------------------------- policy PIP / PAP
POLICY = {"agents": {"bot": {"allow_roles": ["user"], "tools": {
    "search": {"scopes": ["docs:read"]},
    "refund": {"scopes": ["pay:refund"], "approval": True, "conditions": [{"attr": "risk_score", "max": 0.5}, {"attr": "device", "in": ["managed"]}]}}}}}
ALICE = Principal("alice", ("user",), "t1", ("docs:read", "pay:refund"))


class PipTests(unittest.TestCase):
    def test_conditions_use_provider_attributes(self):
        ctx = {"risk_score": 0.2, "device": "managed"}
        pdp = PDP(POLICY, context=[lambda p, a, t, args: ctx])
        self.assertEqual(pdp.decide(ALICE, "bot", "refund").effect, "permit")
        ctx["risk_score"] = 0.9
        d = pdp.decide(ALICE, "bot", "refund")
        self.assertEqual(d.effect, "deny")
        self.assertIn("risk_score", d.reason)
        ctx.update(risk_score=0.1, device="personal")
        self.assertEqual(pdp.decide(ALICE, "bot", "refund").effect, "deny")
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "permit")     # tools without conditions are unaffected

    def test_provider_errors_and_missing_attributes_deny(self):
        def boom(*a):
            raise TimeoutError("attribute service down")
        self.assertEqual(PDP(POLICY, context=[boom]).decide(ALICE, "bot", "refund").effect, "deny")
        self.assertEqual(PDP(POLICY, context=[lambda *a: {"risk_score": 0.1}]).decide(ALICE, "bot", "refund").effect, "deny")   # device missing
        self.assertEqual(PDP(POLICY).decide(ALICE, "bot", "refund").effect, "deny")                                              # no provider at all
        self.assertEqual(PDP(POLICY, context=[lambda *a: "not a dict"]).decide(ALICE, "bot", "refund").effect, "deny")

    def test_class_based_provider_and_pep_audit(self):
        from agentsec import ContextProvider

        class Risk(ContextProvider):
            def attributes(self, principal, agent_id, tool, args):
                return {"risk_score": 0.9 if args.get("amount", 0) > 100 else 0.1, "device": "managed"}
        d = tempfile.mkdtemp()
        pep = PEP(PDP(POLICY, context=[Risk()]), AuditLog(os.path.join(d, "a.jsonl")), approver=lambda *a: True)
        self.assertEqual(pep.call(ALICE, "bot", "refund", lambda amount: f"refunded {amount}", amount=50), "refunded 50")
        with self.assertRaises(PolicyDenied):
            pep.call(ALICE, "bot", "refund", lambda amount: "x", amount=500)
        self.assertTrue(verify_chain(os.path.join(d, "a.jsonl"))[0])


class PapTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "policy.json")
        self.audit = AuditLog(os.path.join(self.d, "audit.jsonl"))
        self.store = PolicyStore(self.p, audit=self.audit, create=True)

    def test_validation_catches_typos_and_bad_rules(self):
        self.assertEqual(validate_policy(POLICY), [])
        bad = json.loads(json.dumps(POLICY))
        bad["agents"]["bot"]["tools"]["search"]["scope"] = ["x"]                           # typo: 'scope'
        bad["agents"]["bot"]["tools"]["refund"]["args"] = {"to": {"regex": "(", "max_len": "ten", "wat": 1}}
        bad["agents"]["bot"]["tools"]["refund"]["conditions"] = [{"attr": "x", "approx": 1}, {"nope": 1}]
        bad["agents"]["bot"]["tools"]["empty"] = {"scopes": []}
        bad["agents"]["ghost"] = {"allow_roles": []}
        bad["extra"] = 1
        msg = " | ".join(validate_policy(bad))
        for want in ("unknown key 'scope'", "does not compile", "wrong type", "unknown rule 'wat'", "needs one or more", "each condition needs an 'attr'",
                     "scopes is empty", "allow_roles must be a non-empty", "unknown top-level key 'extra'"):
            self.assertIn(want, msg)
        self.assertTrue(validate_policy([]) and validate_policy({"agents": []}))

    def test_put_versions_audits_and_rejects_invalid(self):
        v1 = self.store.put(POLICY, actor="alice", reason="initial")
        self.assertEqual(self.store.version, v1)
        with self.assertRaises(PolicyInvalid):
            self.store.put({"agents": {"x": {}}}, actor="alice", reason="oops")
        self.assertEqual(self.store.version, v1)                                          # untouched
        with self.assertRaises(PolicyInvalid):
            self.store.put(POLICY, actor="", reason="r")                                  # who and why are mandatory
        recs = [json.loads(l) for l in open(os.path.join(self.d, "audit.jsonl"))]
        self.assertEqual(recs[-1]["action"], "policy:put")
        self.assertEqual(recs[-1]["actor"], "alice")
        self.assertTrue(verify_chain(os.path.join(self.d, "audit.jsonl"))[0])

    def test_pdp_follows_the_store_live_and_disable_is_a_kill_switch(self):
        self.store.put(POLICY, actor="alice", reason="init")
        pdp = PDP(self.store, context=[lambda *a: {"risk_score": 0.1, "device": "managed"}])
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "permit")
        self.store.disable("bot", "search", actor="oncall", reason="incident")
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "deny")
        self.assertEqual(pdp.decide(ALICE, "bot", "refund").effect, "permit")            # other tools unaffected
        self.store.disable("bot", actor="oncall", reason="full stop")
        self.assertEqual(pdp.decide(ALICE, "bot", "refund").effect, "deny")
        self.store.enable("bot", actor="oncall", reason="resolved")
        self.assertEqual(pdp.decide(ALICE, "bot", "refund").effect, "permit")            # agent back on, but the tool-level disable of 'search' remains
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "deny")
        self.store.enable("bot", "search", actor="oncall", reason="resolved")
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "permit")
        with self.assertRaises(PolicyInvalid):
            self.store.disable("nobody", actor="a", reason="r")
        with self.assertRaises(PolicyInvalid):
            self.store.disable("bot", "nothing", actor="a", reason="r")

    def test_corrupt_or_hand_edited_files_fail_closed(self):
        self.store.put(POLICY, actor="alice", reason="init")
        pdp = PDP(self.store, context=[lambda *a: {"risk_score": 0.1, "device": "managed"}])
        doc = json.load(open(self.p))
        doc["policy"]["agents"]["bot"]["allow_roles"].append("everyone")                  # edited without going through the store
        json.dump(doc, open(self.p, "w"))
        with self.assertRaises(PolicyInvalid):
            self.store.effective()
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "deny")              # PDP: indeterminate is deny
        open(self.p, "w").write("{not json")
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "deny")
        os.remove(self.p)
        self.assertEqual(pdp.decide(ALICE, "bot", "search").effect, "deny")

    def test_cli(self):
        good = os.path.join(self.d, "good.json")
        json.dump(POLICY, open(good, "w"))
        bad = os.path.join(self.d, "bad.json")
        json.dump({"agents": {"b": {"allow_roles": ["u"], "tools": {"t": {"scopes": ["s"], "oops": 1}}}}}, open(bad, "w"))
        run = lambda *a: subprocess.run([sys.executable, "-W", "ignore", "-m", "agentsec.policy_admin", *a], cwd=os.path.dirname(HERE), capture_output=True, text=True)
        r = run("validate", good)
        self.assertEqual((r.returncode, "valid" in r.stdout), (0, True), r.stdout + r.stderr)
        r = run("validate", bad)
        self.assertEqual(r.returncode, 1)
        self.assertIn("unknown key 'oops'", r.stdout)
        self.store.put(POLICY, actor="alice", reason="init")
        r = run("disable", self.p, "bot", "search", "--actor", "oncall", "--reason", "incident", "--audit", os.path.join(self.d, "cli-audit.jsonl"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("disabled=['search']", run("show", self.p).stdout)
        self.assertEqual(run("disable", self.p, "ghost", "--actor", "a", "--reason", "r").returncode, 1)
        self.assertEqual(run("validate", os.path.join(self.d, "missing.json")).returncode, 1)


# ----------------------------------------------------------------------------------------------- residency (agent_scan AG-NET-002) + RT-OUT-01
class ResidencyTests(unittest.TestCase):
    def _scan(self, files, registry):
        d = tempfile.mkdtemp()
        for name, src in files.items():
            open(os.path.join(d, name), "w").write(src)
        reg = os.path.join(d, "reg.json")
        json.dump(registry, open(reg, "w"))
        out = os.path.join(d, "out")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "agent_scan.py"), d, "--registry", reg, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.load(open(os.path.join(out, "agent-scan.json")))["findings"]

    def test_flags_unapproved_regions_only(self):
        src = ('import boto3\nc = boto3.client("bedrock-runtime", region_name="ap-south-1")\nok = boto3.client("bedrock-runtime", region_name="us-east-1")\n'
               'A = "https://bedrock-runtime.eu-west-3.amazonaws.com/x"\nB = "https://bedrock-runtime.us-east-2.amazonaws.com/x"\n')
        f = [x for x in self._scan({"app.py": src}, {"approved_models": [], "approved_endpoints": ["*"], "approved_regions": ["us-east-1", "us-east-2"]}) if x["rule"] == "AG-NET-002"]
        self.assertEqual(sorted(x["line"] for x in f), [2, 4])
        self.assertTrue(all(x["domain"] == "P7" and x["severity"] == "MEDIUM" for x in f))

    def test_check_is_off_without_approved_regions(self):
        src = 'A = "https://bedrock-runtime.ap-south-1.amazonaws.com/x"\n'
        self.assertEqual([x for x in self._scan({"app.py": src}, {"approved_models": [], "approved_endpoints": ["*"]}) if x["rule"] == "AG-NET-002"], [])

    def test_repo_registry_example_has_regions(self):
        reg = json.load(open(os.path.join(ROOT, "configs", "agentic", "approved-models.json")))
        self.assertIn("us-east-1", reg["approved_regions"])


class OutputProbeTests(unittest.TestCase):
    """RT-OUT-01 against a tiny fake agent: invented figure fails, faithful figure passes, unconfigured is skipped (never passed)."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("redteam_under_test", os.path.join(ROOT, "scripts", "redteam.py"))
        cls.rt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.rt)

        class Agent(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                msg = json.loads(self.rfile.read(n))["message"]
                ans = {"honest": "Revenue was $1.2M, up 4.1%.", "liar": "Revenue was $9.9M, up 41%.", "plain": "I could not find that."}[msg]
                b = json.dumps({"response": ans}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Agent)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _run(self, lineage):
        contract = self.rt.merge(self.rt.DEFAULTS, {"output_lineage": lineage} if lineage else {})
        client = self.rt.Client(self.url, contract, 5)
        client.token_a = None
        p = next(p for p in self.rt.PROBES if p["id"] == "RT-OUT-01")
        return p["fn"](client, {})

    def test_probe_outcomes(self):
        src = [1234567, 4.1]
        self.assertTrue(self._run({"message": "honest", "source_values": src})[0]["passed"])
        bad = self._run({"message": "liar", "source_values": src})[0]
        self.assertFalse(bad["passed"])
        self.assertIn("$9.9M", bad["evidence"])
        self.assertTrue(self._run({"message": "plain", "source_values": src})[0]["passed"])
        sk = self._run(None)[0]
        self.assertTrue(sk["skipped"])                                                  # unconfigured: skipped, not a pass

    def test_probe_registered_with_metadata(self):
        p = next(p for p in self.rt.PROBES if p["id"] == "RT-OUT-01")
        self.assertEqual((p["domain"], p["owasp"], p["severity"]), ("P3", "LLM09", "HIGH"))


if __name__ == "__main__":
    unittest.main()
