"""Lightweight agentic-threat detectors that supplement canary, added for the
OWASP Top 10 for Agentic Applications (2026). Kept to checks that are reliable
(low false-positive), AST-based for Python.

CANARY-ASI8-001 - an agent executor created with no iteration cap. An unbounded
agent loop is the cascading-failure / runaway-cost pattern (ASI-08): a
prompt-injected or confused agent can loop indefinitely. LangChain's
AgentExecutor and initialize_agent both accept max_iterations; omitting it
leaves the default or no cap.
"""

from __future__ import annotations

import ast
import os
from typing import Dict, Any, List

_EXECUTORS = {"AgentExecutor", "initialize_agent"}
_CODE_EXT = (".py",)
_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist"}


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def scan_source(src: str, filename: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in _EXECUTORS:
            kwargs = {kw.arg for kw in node.keywords if kw.arg}
            if "max_iterations" not in kwargs:
                out.append({
                    "rule_id": "CANARY-ASI8-001", "severity": "Medium",
                    "owasp_agentic": "ASI-08 Cascading Failures",
                    "file": filename, "line": node.lineno,
                    "message": "Agent executor created without max_iterations; an "
                               "unbounded loop can run away on cost or a confused/"
                               "injected agent. Set max_iterations.",
                })
    return out


def scan_path(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for dp, dn, fn in os.walk(path):
            dn[:] = [d for d in dn if d not in _SKIP]
            files += [os.path.join(dp, f) for f in fn if f.endswith(_CODE_EXT)]
    for fp in files:
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                out.extend(scan_source(fh.read(), fp))
        except OSError:
            continue
    return out
