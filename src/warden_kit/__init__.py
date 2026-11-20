"""Warden kit. The scanning engine is bundled under ``kit/``; ``warden`` (cli.py) runs it."""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _read_version():
    for p in (os.path.join(_HERE, "kit", "VERSION"), os.path.join(_HERE, "..", "..", "VERSION")):
        try:
            return open(p).read().strip()
        except OSError:
            pass
    return "0+unknown"


__version__ = _read_version()
