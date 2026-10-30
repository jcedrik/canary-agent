"""Run canary as the deterministic verifier and return its findings.

This is the half of the agent that is NOT the model: a patch is only accepted
if canary, re-run on the patched code, confirms the finding is gone. Canary is
invoked as a subprocess so the agent works against whatever canary version is
installed, exactly as a user's CI would run it."""

from __future__ import annotations

import json
import subprocess
from typing import List, Set, Tuple

Key = Tuple[str, int]  # (rule_id, line)


def scan(path: str) -> List[dict]:
    """Return canary's raw findings for a path (empty list on a clean scan)."""
    proc = subprocess.run(
        ["canary", path, "--format", "json", "--include-tests"],
        capture_output=True,
        text=True,
    )
    # canary exits 1 when findings meet --fail-on; that is not an error here.
    out = proc.stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    return data.get("findings", []) if isinstance(data, dict) else data


def finding_keys(findings: List[dict]) -> Set[Key]:
    keys = set()
    for f in findings:
        keys.add((f.get("rule_id", ""), int(f.get("line", 0) or 0)))
    return keys


def rule_set(findings: List[dict]) -> Set[str]:
    return {f.get("rule_id", "") for f in findings}
