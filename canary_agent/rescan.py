"""Run canary as the deterministic verifier and return its findings.

This is the half of the agent that is NOT the model: a patch is only accepted
if canary, re-run on the patched code, confirms the finding is gone. Canary is
invoked as a subprocess so the agent works against whatever canary version is
installed, exactly as a user's CI would run it."""

from __future__ import annotations

import json
import os
import subprocess
from typing import List, Set, Tuple

Key = Tuple[str, int]  # (rule_id, line)


def scan(path: str) -> List[dict]:
    """Return canary's raw findings for a path (empty list on a clean scan)."""
    try:
        proc = subprocess.run(
            ["canary", path, "--format", "json", "--include-tests"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        # canary binary not installed: the in-repo detectors still run.
        return []
    # canary exits 1 when findings meet --fail-on; that is not an error here.
    out = proc.stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    return data.get("findings", []) if isinstance(data, dict) else data


def _snippet_for(filename: str, line: int) -> str:
    """Pull the source line so detector findings carry context into triage."""
    try:
        with open(filename, encoding="utf-8", errors="replace") as fh:
            rows = fh.readlines()
        if 1 <= line <= len(rows):
            return rows[line - 1].strip()
    except OSError:
        pass
    return ""


def detectors(path: str) -> List[dict]:
    """Findings from the in-repo AST detectors (agentic rules, taint, JS/TS).

    These complement canary: they catch agentic-specific patterns and follow
    intra-procedural taint that a pattern scanner misses. Each is normalised to
    canary's finding shape (file_path / line / rule_id / severity / snippet /
    explanation) so triage and the CI gate treat them uniformly."""
    from . import agentic_rules, taint, jsts_rules

    out: List[dict] = []
    for mod in (agentic_rules, taint, jsts_rules):
        try:
            found = mod.scan_path(path)
        except Exception:
            continue
        for f in found:
            fn = f.get("file", "")
            ln = int(f.get("line", 0) or 0)
            out.append({
                "rule_id": f.get("rule_id", ""),
                "severity": f.get("severity", "Medium"),
                "file_path": fn,
                "line": ln,
                "snippet": _snippet_for(fn, ln),
                "explanation": f.get("message", ""),
                "owasp": f.get("owasp_agentic", ""),
                "source": "canary-agent",
                "source_line": f.get("source_line"),
            })
    return out


def scan_all(path: str) -> List[dict]:
    """Canary findings plus the in-repo detectors, de-duplicated by (rule, file, line)."""
    merged = list(scan(path)) + detectors(path)
    seen: Set[Tuple[str, str, int]] = set()
    out = []
    for f in merged:
        key = (f.get("rule_id", ""),
               os.path.basename(f.get("file_path", f.get("file", ""))),
               int(f.get("line", 0) or 0))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def finding_keys(findings: List[dict]) -> Set[Key]:
    keys = set()
    for f in findings:
        keys.add((f.get("rule_id", ""), int(f.get("line", 0) or 0)))
    return keys


def rule_set(findings: List[dict]) -> Set[str]:
    return {f.get("rule_id", "") for f in findings}
