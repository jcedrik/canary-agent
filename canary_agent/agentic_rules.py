"""Lightweight agentic-threat detectors that supplement canary, added for the
OWASP Top 10 for Agentic Applications (2026). Kept to checks that are reliable
(low false-positive), AST-based for Python.

  CANARY-ASI8-001 (ASI-08 Cascading Failures) - an agent executor created with
    no iteration cap. An unbounded agent loop is the runaway-cost / cascading
    pattern: a prompt-injected or confused agent can loop indefinitely.
    AgentExecutor and initialize_agent both accept max_iterations.
  CANARY-ASI5-001 (ASI-05 Code Execution) - eval / exec / compile called on a
    non-literal value. If that value can carry model or user input, it is
    arbitrary code execution.
  CANARY-ASI6-001 (ASI-06 Memory Poisoning) - content written to a vector or
    memory store (add_texts / add_documents / upsert / add_memory ...) from a
    non-literal value, with no visible sanitization: a poisoned document can
    inject instructions that resurface on later retrieval.
"""

from __future__ import annotations

import ast
import os
from typing import Dict, Any, List

_EXECUTORS = {"AgentExecutor", "initialize_agent"}
_EXEC_FUNCS = {"eval", "exec", "compile"}
_MEMORY_SINKS = {"add_texts", "aadd_texts", "add_documents", "aadd_documents",
                 "upsert", "add_embeddings", "add_memory", "aadd"}
_CODE_EXT = (".py",)
_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist"}


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _first_arg_is_dynamic(node: ast.Call) -> bool:
    """True when the call's first positional arg is not a literal constant."""
    if not node.args:
        return False
    a = node.args[0]
    if isinstance(a, ast.Constant):
        return False
    # a list/tuple of only literals is static content, not untrusted input.
    if isinstance(a, (ast.List, ast.Tuple)):
        return not all(isinstance(e, ast.Constant) for e in a.elts)
    # a joined-str (f-string) is dynamic only if it interpolates something.
    if isinstance(a, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in a.values)
    return True


def _f(rule, sev, asi, line, filename, msg):
    return {"rule_id": rule, "severity": sev, "owasp_agentic": asi,
            "file": filename, "line": line, "message": msg}


def scan_source(src: str, filename: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in _EXECUTORS:
            if "max_iterations" not in {kw.arg for kw in node.keywords if kw.arg}:
                out.append(_f("CANARY-ASI8-001", "Medium", "ASI-08 Cascading Failures",
                              node.lineno, filename,
                              "Agent executor created without max_iterations; an "
                              "unbounded loop can run away on cost or a confused/"
                              "injected agent. Set max_iterations."))
        elif name in _EXEC_FUNCS and _first_arg_is_dynamic(node):
            out.append(_f("CANARY-ASI5-001", "High", "ASI-05 Code Execution",
                          node.lineno, filename,
                          f"{name}() is called on a non-literal value. If that "
                          "value carries model or user input, it is arbitrary code "
                          "execution. Avoid eval/exec on dynamic input."))
        elif name in _MEMORY_SINKS and _first_arg_is_dynamic(node):
            out.append(_f("CANARY-ASI6-001", "Medium", "ASI-06 Memory Poisoning",
                          node.lineno, filename,
                          f"{name}() writes non-literal content to a vector/memory "
                          "store with no visible sanitization; poisoned content can "
                          "inject instructions that resurface on retrieval."))
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
