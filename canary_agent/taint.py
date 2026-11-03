"""Deterministic taint tracking (Python, intra-procedural).

Follows untrusted data from a source, through assignments and string building,
to a dangerous sink, and emits the source->sink path. This is the deterministic
half of the dataflow story; across functions and files it is complemented by the
agent's context lookups (`context_agent.py`). It is intra-procedural by design,
not a full inter-procedural SAST engine - scope stated honestly.

Sources: `input()`, `request.args/form/json/...`, `sys.argv`, and the parameters
of a function decorated as an agent tool (@tool / @mcp.tool).

Sinks:
  CANARY-TAINT-EXEC  (ASI-05 / CWE-95)  eval / exec / compile on tainted data
  CANARY-TAINT-SHELL (ASI-02 / CWE-78)  subprocess / os.system on tainted data
  CANARY-TAINT-SQL   (CWE-89)           cursor.execute on tainted data
  CANARY-TAINT-PROMPT(ASI-01 / LLM01)   tainted data into a prompt / LLM call
"""

from __future__ import annotations

import ast
import os
from typing import Dict, Any, List, Set

_REQ_ATTRS = {"args", "form", "json", "data", "values", "params", "query",
              "get_json", "cookies", "headers", "files", "GET", "POST"}
_REQ_BASES = {"request", "req"}
_TOOL_DECOS = {"tool", "mcp", "function_tool", "FunctionTool"}
_EXEC = {"eval", "exec", "compile"}
_SHELL_ATTRS = {"run", "call", "check_output", "check_call", "Popen", "system", "popen"}
_SHELL_BASES = {"subprocess", "os"}
_PROMPT_CALLS = {"create", "complete", "completions", "invoke", "ainvoke",
                 "generate_content", "generate", "predict", "chat"}
_PROMPT_VARS = ("prompt", "system_prompt", "system_instruction", "instruction",
                "template", "messages")
_STR_HELPERS = {"str", "format", "join", "f"}
_CODE_EXT = (".py",)
_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist"}


def _base_name(node) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.value if isinstance(node, (ast.Attribute, ast.Subscript)) else node.func
    return node.id if isinstance(node, ast.Name) else ""


def _is_source(node) -> bool:
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name) and f.id == "input":
            return True
    # request.args / req.form / request.get_json()
    cur = node
    attrs = []
    while isinstance(cur, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(cur, ast.Attribute):
            attrs.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        else:
            cur = cur.func
    if isinstance(cur, ast.Name):
        if cur.id in _REQ_BASES and any(a in _REQ_ATTRS for a in attrs):
            return True
        if cur.id == "sys" and "argv" in attrs:
            return True
    return False


def _tainted(node, tainted: Set[str]) -> bool:
    if node is None:
        return False
    if _is_source(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.JoinedStr):
        return any(_tainted(v.value, tainted) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp):
        return _tainted(node.left, tainted) or _tainted(node.right, tainted)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _tainted(node.value, tainted)
    if isinstance(node, ast.Call):
        fn = node.func
        nm = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
        if nm in _STR_HELPERS or isinstance(fn, ast.Attribute):
            if isinstance(fn, ast.Attribute) and _tainted(fn.value, tainted):
                return True
            if any(_tainted(a, tainted) for a in node.args):
                return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_tainted(v, tainted) for v in node.values)
    return False


def _tool_decorated(fn: ast.FunctionDef) -> bool:
    for d in fn.decorator_list:
        n = d
        if isinstance(n, ast.Call):
            n = n.func
        if isinstance(n, ast.Attribute) and n.attr in _TOOL_DECOS:
            return True
        if isinstance(n, ast.Name) and n.id in _TOOL_DECOS:
            return True
        if isinstance(n, ast.Attribute) and n.attr == "tool":
            return True
    return False


def _finding(rule, sev, asi, cwe, line, src_line, filename, msg):
    return {"rule_id": rule, "severity": sev, "owasp_agentic": asi, "cwe": cwe,
            "file": filename, "line": line, "source_line": src_line, "message": msg}


def _analyze_function(fn: ast.FunctionDef, filename: str) -> List[Dict[str, Any]]:
    tainted: Set[str] = set()
    src_line: Dict[str, int] = {}
    if _tool_decorated(fn):
        for a in fn.args.args + fn.args.kwonlyargs:
            tainted.add(a.arg)
            src_line[a.arg] = fn.lineno

    # fixpoint over assignments (order-insensitive, a few passes)
    for _ in range(4):
        changed = False
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                val = node.value
                if val is not None and _tainted(val, tainted):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            src_line[t.id] = getattr(node, "lineno", fn.lineno)
                            changed = True
        if not changed:
            break

    out: List[Dict[str, Any]] = []

    def src_of(node):
        # best-effort: the first tainted name referenced
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in src_line:
                return src_line[n.id]
        return fn.lineno

    # assignment-to-prompt sink
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and _tainted(node.value, tainted):
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else ""
                if nm and any(p in nm.lower() for p in _PROMPT_VARS):
                    out.append(_finding("CANARY-TAINT-PROMPT", "High",
                        "ASI-01 Agent Goal Hijack", "CWE-77", node.lineno,
                        src_of(node.value), filename,
                        f"Untrusted data reaches prompt variable `{nm}` "
                        f"(tainted from line {src_of(node.value)})."))

    # call sinks
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        fnc = node.func
        name = fnc.attr if isinstance(fnc, ast.Attribute) else (fnc.id if isinstance(fnc, ast.Name) else "")
        base = _base_name(fnc) if isinstance(fnc, ast.Attribute) else ""
        args_tainted = any(_tainted(a, tainted) for a in node.args) or \
            any(_tainted(k.value, tainted) for k in node.keywords)
        if name in _EXEC and node.args and _tainted(node.args[0], tainted):
            out.append(_finding("CANARY-TAINT-EXEC", "Critical", "ASI-05 Code Execution",
                "CWE-95", node.lineno, src_of(node), filename,
                f"{name}() executes tainted data (from line {src_of(node)})."))
        elif name in _SHELL_ATTRS and base in _SHELL_BASES and args_tainted:
            out.append(_finding("CANARY-TAINT-SHELL", "Critical", "ASI-02 Tool Misuse",
                "CWE-78", node.lineno, src_of(node), filename,
                f"Tainted data reaches a shell/subprocess call (from line {src_of(node)})."))
        elif name == "execute" and args_tainted:
            out.append(_finding("CANARY-TAINT-SQL", "High", "ASI-02 Tool Misuse",
                "CWE-89", node.lineno, src_of(node), filename,
                f"Tainted data reaches a SQL execute (from line {src_of(node)})."))
        elif name in _PROMPT_CALLS and args_tainted:
            out.append(_finding("CANARY-TAINT-PROMPT", "High", "ASI-01 Agent Goal Hijack",
                "CWE-77", node.lineno, src_of(node), filename,
                f"Tainted data reaches an LLM call (from line {src_of(node)})."))
    return out


def scan_source(src: str, filename: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out = []
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for f in _analyze_function(node, filename):
                key = (f["rule_id"], f["line"])
                if key not in seen:
                    seen.add(key)
                    out.append(f)
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
