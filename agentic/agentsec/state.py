"""P5/P7 Agent state and memory encrypted at rest.

EncryptedStore keeps agent memory / conversation state / embeddings-metadata in a file where every value is encrypted (Fernet:
AES-128-CBC + HMAC-SHA256, from the `cryptography` package) and bound to its key name, so ciphertexts cannot be swapped between entries.
Key rotation: give keys=[new, old]; reads accept any, writes use the first, rotate() re-encrypts everything under the first.
The file is written atomically with mode 0600. Keys come from you (a vault: see secrets.py); the store never writes a key to disk.

Limits: protects the file at rest, not memory contents while the agent runs, and not against someone who can read the key from the
same host. Key names and the number of entries are visible. `cryptography` is an optional dependency (clear error if absent).
"""
import json
import os
import tempfile
import time


class CryptoUnavailable(RuntimeError):
    pass


class StateError(RuntimeError):
    pass


def _fernet(keys):
    try:
        from cryptography.fernet import Fernet, MultiFernet
    except ImportError as e:
        raise CryptoUnavailable("EncryptedStore needs the optional dependency: pip install cryptography") from e
    fs = [Fernet(k if isinstance(k, bytes) else k.encode()) for k in keys]
    return MultiFernet(fs) if len(fs) > 1 else fs[0]


def generate_key():
    """A new random key (store it in your secret manager, not next to the data)."""
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:
        raise CryptoUnavailable("pip install cryptography") from e
    return Fernet.generate_key().decode()


class EncryptedStore:
    def __init__(self, path, keys):
        keys = [keys] if isinstance(keys, (str, bytes)) else list(keys)
        if not keys:
            raise StateError("at least one key is required")
        self.path, self._f = path, _fernet(keys)
        self._keys = keys
        self._data = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                try:
                    self._data = json.load(fh)
                except ValueError as e:
                    raise StateError("state file is not valid JSON") from e

    def _seal(self, name, value):
        env = json.dumps({"k": name, "v": value, "t": round(time.time(), 3)}, separators=(",", ":")).encode()
        return self._f.encrypt(env).decode()

    def _open(self, name, token):
        from cryptography.fernet import InvalidToken
        try:
            env = json.loads(self._f.decrypt(token.encode()))
        except (InvalidToken, ValueError) as e:
            raise StateError(f"cannot decrypt {name!r}: wrong key or tampered data") from e
        if env.get("k") != name:
            raise StateError(f"entry {name!r} was moved from another key: refused")
        return env["v"]

    def _flush(self):
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(self._data, out)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def set(self, name, value):
        self._data[name] = self._seal(name, value)
        self._flush()

    def get(self, name, default=None):
        if name not in self._data:
            return default
        return self._open(name, self._data[name])

    def delete(self, name):
        if self._data.pop(name, None) is not None:
            self._flush()

    def keys(self):
        return sorted(self._data)

    def rotate(self):
        """Re-encrypt every entry under the first (newest) key. Returns the number of entries rewritten."""
        for name in list(self._data):
            self._data[name] = self._seal(name, self._open(name, self._data[name]))
        self._flush()
        return len(self._data)
