"""Build hook: bundle the scanning kit (scripts, configs, docker files, agentsec, CI templates) inside the package."""
import os
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ITEMS = ["VERSION", "versions.env", "scripts", "configs", "docker", "agentic/agentsec", "modes/per-project"]
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", "reports", "node_modules", "*.egg-info")


class build_py(_build_py):
    def run(self):
        super().run()
        here = os.path.dirname(os.path.abspath(__file__))
        dest = os.path.join(self.build_lib, "warden_kit", "kit")
        shutil.rmtree(dest, ignore_errors=True)
        for item in ITEMS:
            src, dst = os.path.join(here, item), os.path.join(dest, item)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=SKIP)
            else:
                shutil.copy2(src, dst)


setup(cmdclass={"build_py": build_py})
