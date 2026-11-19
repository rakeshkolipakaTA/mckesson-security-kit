"""P3 Trusted I/O boundary: never open a path the model or user supplied without normalising it against an allowed base."""
import os
from pathlib import Path


class PathViolation(ValueError):
    pass


def safe_path(base, user_path, *, allow_symlinks=False):
    """Resolve user_path under base. Rejects absolute paths, '..' escapes, NUL bytes and (by default) symlinks that leave base."""
    if not isinstance(user_path, (str, os.PathLike)):
        raise PathViolation("path must be a string")
    s = os.fspath(user_path)
    if "\x00" in s or s.strip() == "":
        raise PathViolation("empty path or NUL byte")
    if os.path.isabs(s) or s.startswith(("~", "\\")) or (len(s) > 1 and s[1] == ":"):
        raise PathViolation("absolute paths are not allowed")
    base_p = Path(base).resolve()
    cand = (base_p / s)
    resolved = cand.resolve() if allow_symlinks else Path(os.path.realpath(cand))
    try:
        resolved.relative_to(base_p)
    except ValueError:
        raise PathViolation("path escapes the allowed directory") from None
    return resolved
