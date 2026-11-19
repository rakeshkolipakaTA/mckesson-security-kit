"""`warden` entry point: locate the bundled kit and hand over to its bash CLI (scripts/warden)."""
import json
import os
import subprocess
import sys

from . import __version__

HERE = os.path.dirname(os.path.abspath(__file__))


def kit_root():
    bundled = os.path.join(HERE, "kit")
    if os.path.isfile(os.path.join(bundled, "scripts", "scan.sh")):
        return bundled
    checkout = os.path.abspath(os.path.join(HERE, "..", ".."))  # editable / development install
    if os.path.isfile(os.path.join(checkout, "scripts", "scan.sh")):
        return checkout
    sys.exit("warden: the scanning kit is missing from this installation; reinstall warden-kit")


def install_source():
    """How this package was installed (so `warden init` can pin the same source in the repo): git+URL@tag, a path, or the pinned version."""
    override = os.environ.get("WARDEN_SOURCE")
    if override:
        return override
    try:
        from importlib import metadata
        raw = metadata.distribution("warden-kit").read_text("direct_url.json")
        if raw:
            d = json.loads(raw)
            url, vcs = d.get("url", ""), d.get("vcs_info") or {}
            if vcs:
                rev = vcs.get("requested_revision") or vcs.get("commit_id") or ""
                return f"{vcs.get('vcs', 'git')}+{url}" + (f"@{rev}" if rev else "")
            if url.startswith("file://"):
                return url[len("file://"):]
    except Exception:
        pass
    return f"warden-kit=={__version__}"


def _make_executable(root):
    for d in ("scripts", os.path.join("modes", "per-project")):
        full = os.path.join(root, d)
        if os.path.isdir(full):
            for n in os.listdir(full):
                p = os.path.join(full, n)
                if n.endswith((".sh", ".py")) or n == "warden":
                    try:
                        os.chmod(p, os.stat(p).st_mode | 0o111)
                    except OSError:
                        pass  # read-only install: the bash scripts are invoked through `bash` where it matters


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = kit_root()
    _make_executable(root)
    env = dict(os.environ, WARDEN_VERSION=__version__, WARDEN_SOURCE=install_source(), WARDEN_PYTHON=sys.executable)
    try:
        return subprocess.call(["bash", os.path.join(root, "scripts", "warden")] + argv, env=env)
    except FileNotFoundError:
        print("warden needs bash (Linux/macOS, or Git Bash / WSL on Windows).", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
