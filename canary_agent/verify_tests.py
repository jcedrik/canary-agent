"""Behavior-preservation check.

A fix that clears the scanner by deleting the feature is not a fix. After a
patch is verified by re-scan, this runs the project's own test command and
reports whether it still passes, so a behavior-breaking "fix" is caught.
"""

from __future__ import annotations

import glob
import os
import subprocess
from typing import Dict, Any, Optional


def detect_cmd(project_dir: str) -> Optional[str]:
    """Best-effort detection of a project's test command."""
    j = os.path.join
    if any(os.path.exists(j(project_dir, f)) for f in ("pytest.ini", "tox.ini", "conftest.py")) \
            or glob.glob(j(project_dir, "tests", "**", "test_*.py"), recursive=True) \
            or glob.glob(j(project_dir, "test_*.py")):
        return "pytest -q"
    if os.path.exists(j(project_dir, "package.json")):
        return "npm test --silent"
    if os.path.exists(j(project_dir, "Makefile")):
        return "make test"
    return None


def run_tests(project_dir: str, cmd: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    cmd = cmd or detect_cmd(project_dir)
    if not cmd:
        return {"ran": False, "passed": None, "cmd": None,
                "note": "no test command detected"}
    try:
        p = subprocess.run(cmd, cwd=project_dir, shell=True, capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ran": True, "passed": False, "cmd": cmd, "note": "tests timed out"}
    tail = (p.stdout + p.stderr).strip().splitlines()[-8:]
    return {"ran": True, "passed": p.returncode == 0, "cmd": cmd,
            "note": "\n".join(tail)}
