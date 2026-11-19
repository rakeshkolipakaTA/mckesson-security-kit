"""P5 Secrets lifecycle: fetch secrets from a managed store at run time (never from source), cache briefly, and track their age.

Providers (all return a `Secret`, whose repr/str never shows the value; call .reveal() at the point of use):
  EnvProvider(prefix)           environment variables (what a platform injects)
  FileProvider(directory)       one file per secret (Docker / Kubernetes secret mounts), path traversal safe
  VaultKV2Provider(addr, ...)   HashiCorp Vault KV v2 over HTTP: token or AppRole login, namespace, TTL cache, version/created_time metadata
  CachedProvider(provider, ttl) wrap any provider with a TTL cache
RotatingSecret(provider, name, max_age_days, refresh=callable) tracks age (Vault gives `created_time`), reports `needs_rotation`, and can
call your refresh callback (which should generate the new secret in the backing system) and re-read it. `age_report()` for dashboards/CI.

Honest limits: this reads and tracks secrets, it does not rotate the credentials of third-party systems for you (the refresh callback
does that), it does not renew Vault leases/dynamic secrets, and TLS verification is on by default (plain http is accepted only for
localhost unless allow_insecure=True). Standard library only.
"""
import datetime as dt
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")


class SecretError(RuntimeError):
    pass


class SecretNotFound(SecretError, KeyError):
    pass


class Secret:
    """A secret value that does not leak through logs, tracebacks, repr() or str()."""
    __slots__ = ("_v", "name", "version", "created")

    def __init__(self, value, name="", version=None, created=None):
        self._v, self.name, self.version, self.created = value, name, version, created   # created: epoch seconds or None

    def reveal(self):
        return self._v

    def age_days(self, now=None):
        return None if self.created is None else ((now or time.time()) - self.created) / 86400.0

    def __repr__(self):
        return f"Secret(name={self.name!r}, value=***, version={self.version})"

    __str__ = __repr__

    def __eq__(self, other):
        return isinstance(other, Secret) and self._v == other._v

    def __hash__(self):
        return hash(("secret", self.name))

    def __reduce__(self):                      # never pickle a secret by accident
        raise TypeError("Secret objects cannot be pickled")


class SecretProvider:
    def get(self, name):
        raise NotImplementedError


def _check_name(name):
    if not isinstance(name, str) or not _NAME.match(name) or ".." in name.split("/"):
        raise SecretError(f"invalid secret name {name!r}")
    return name


class EnvProvider(SecretProvider):
    def __init__(self, prefix="", environ=None):
        self.prefix, self.environ = prefix, os.environ if environ is None else environ

    def get(self, name):
        _check_name(name)
        v = self.environ.get(self.prefix + name)
        if v is None or v == "":
            raise SecretNotFound(name)
        return Secret(v, name)


class FileProvider(SecretProvider):
    def __init__(self, directory, *, strict_perms=False):
        self.dir, self.strict = os.path.realpath(directory), strict_perms

    def get(self, name):
        _check_name(name)
        p = os.path.realpath(os.path.join(self.dir, name))
        if os.path.commonpath([self.dir, p]) != self.dir:
            raise SecretError("secret path escapes the secrets directory")
        try:
            st = os.stat(p)
            if self.strict and st.st_mode & 0o007:
                raise SecretError(f"{name}: file is world-accessible (mode {oct(st.st_mode & 0o777)})")
            with open(p, "r", encoding="utf-8") as f:
                v = f.read().rstrip("\r\n")
        except FileNotFoundError:
            raise SecretNotFound(name) from None
        return Secret(v, name, created=st.st_mtime)


def _iso_epoch(s):
    try:
        base, _, frac = s.replace("Z", "").partition(".")
        return dt.datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp() + (float("0." + re.sub(r"\D", "", frac)) if frac else 0.0)
    except (ValueError, AttributeError):
        return None


class VaultKV2Provider(SecretProvider):
    """Read secrets from a Vault KV v2 mount. name = "path/to/secret" (returns field `field`, default "value") or "path/to/secret#field"."""

    def __init__(self, addr, *, mount="secret", token=None, role_id=None, secret_id=None, approle_mount="approle", namespace=None,
                 field="value", ttl=300, timeout=5, allow_insecure=False, opener=None):
        u = urllib.parse.urlparse(addr)
        local = u.hostname in ("localhost", "127.0.0.1", "::1")
        if u.scheme != "https" and not (u.scheme == "http" and (local or allow_insecure)):
            raise SecretError("Vault address must be https (plain http is allowed only for localhost, or with allow_insecure=True)")
        if not token and not (role_id and secret_id):
            raise SecretError("give a token, or role_id + secret_id for AppRole login")
        self.addr, self.mount, self.namespace, self.field, self.ttl, self.timeout = addr.rstrip("/"), mount.strip("/"), namespace, field, ttl, timeout
        self._token, self._role, self._secret_id, self._approle_mount = token, role_id, secret_id, approle_mount.strip("/")
        self._cache, self._lock = {}, threading.Lock()
        self._open = (opener or urllib.request.build_opener()).open

    def __repr__(self):
        return f"VaultKV2Provider(addr={self.addr!r}, mount={self.mount!r}, auth={'token' if self._token else 'approle'})"

    # -- http
    def _call(self, method, path, body=None, token=True):
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.namespace:
            h["X-Vault-Namespace"] = self.namespace
        if token:
            h["X-Vault-Token"] = self._token
        req = urllib.request.Request(self.addr + path, data=None if body is None else json.dumps(body).encode(), headers=h, method=method)
        try:
            with self._open(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            e.close()
            return e.code, {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SecretError(f"cannot reach Vault ({type(e).__name__})") from None   # no URL/token in the message

    def _login(self):
        st, js = self._call("POST", f"/v1/auth/{self._approle_mount}/login", {"role_id": self._role, "secret_id": self._secret_id}, token=False)
        tok = (js.get("auth") or {}).get("client_token")
        if st != 200 or not tok:
            raise SecretError(f"Vault AppRole login failed (HTTP {st})")
        self._token = tok

    def _read(self, path):
        if not self._token:
            self._login()
        st, js = self._call("GET", f"/v1/{self.mount}/data/{urllib.parse.quote(path, safe='/')}")
        if st == 403 and self._role:       # token expired: log in again once
            self._login()
            st, js = self._call("GET", f"/v1/{self.mount}/data/{urllib.parse.quote(path, safe='/')}")
        return st, js

    def get(self, name):
        _check_name(name.split("#", 1)[0])
        path, _, field = name.partition("#")
        field = field or self.field
        now = time.time()
        with self._lock:
            hit = self._cache.get(name)
            if hit and hit[0] > now:
                return hit[1]
        st, js = self._read(path)
        if st == 404:
            raise SecretNotFound(name)
        if st != 200:
            raise SecretError(f"Vault read failed (HTTP {st})")
        data = (js.get("data") or {})
        val = (data.get("data") or {}).get(field)
        if val is None:
            raise SecretNotFound(f"{name} (no field {field!r})")
        md = data.get("metadata") or {}
        sec = Secret(str(val), name, version=md.get("version"), created=_iso_epoch(md.get("created_time", "")))
        with self._lock:
            self._cache[name] = (now + self.ttl, sec)
        return sec

    def invalidate(self, name=None):
        with self._lock:
            self._cache.pop(name, None) if name else self._cache.clear()


class CachedProvider(SecretProvider):
    def __init__(self, inner, ttl=300):
        self.inner, self.ttl, self._c, self._lock = inner, ttl, {}, threading.Lock()

    def get(self, name):
        now = time.time()
        with self._lock:
            hit = self._c.get(name)
            if hit and hit[0] > now:
                return hit[1]
        s = self.inner.get(name)
        with self._lock:
            self._c[name] = (now + self.ttl, s)
        return s

    def invalidate(self, name=None):
        with self._lock:
            self._c.pop(name, None) if name else self._c.clear()


class RotatingSecret:
    """Track a secret's age against a maximum, and refresh it through your own callback.
    refresh(name) must create the new secret value in the backing store (e.g. call the provider's API and write a new Vault version)."""

    def __init__(self, provider, name, *, max_age_days, refresh=None, clock=time.time):
        if max_age_days <= 0:
            raise SecretError("max_age_days must be positive")
        self.provider, self.name, self.max_age_days, self.refresh_cb, self.clock = provider, name, max_age_days, refresh, clock

    def _fresh(self):
        inv = getattr(self.provider, "invalidate", None)
        if inv:
            inv(self.name)
        return self.provider.get(self.name)

    def status(self):
        s = self._fresh()
        age = s.age_days(self.clock())
        # an unknown age (provider has no timestamp) is treated as "needs rotation": never assume a secret is young
        return {"name": self.name, "version": s.version, "age_days": None if age is None else round(age, 2), "max_age_days": self.max_age_days,
                "needs_rotation": age is None or age > self.max_age_days, "age_known": age is not None}

    def get(self, *, auto_rotate=False):
        st = self.status()
        if st["needs_rotation"] and auto_rotate and self.refresh_cb:
            self.refresh_cb(self.name)
            return self._fresh()
        return self._fresh()

    def rotate(self):
        if not self.refresh_cb:
            raise SecretError("no refresh callback configured")
        self.refresh_cb(self.name)
        return self._fresh()


def age_report(secrets):
    """[RotatingSecret, ...] -> list of status dicts (errors become {"error": ...} entries, never exceptions), oldest first."""
    rows = []
    for rs in secrets:
        try:
            rows.append(rs.status())
        except SecretError as e:
            rows.append({"name": rs.name, "error": str(e), "needs_rotation": True})
    return sorted(rows, key=lambda r: -(r.get("age_days") or 1e9))
