"""Real AST detection for JS/TS prompt injection, using tree-sitter.

canary's JS/TS rule is pattern-based. This parses the file and flags a template
literal that interpolates an untrusted-looking value AND is used as a prompt
(assigned to a prompt-like variable, or passed to an LLM call). Parsing beats
regex: it knows an interpolation from plain text and reads the real variable
names.

Needs tree-sitter (`pip install -e .[jsts]`). Degrades to an empty result if the
parser is unavailable, so it never breaks a scan.

  CANARY-JSTS-001 (ASI-01 / LLM01) - untrusted value interpolated into a prompt.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Any, List

_UNTRUSTED = re.compile(
    r"\b(req|request|ctx|event|body|query|params|searchParams|formData|"
    r"userInput|userMessage|user_input|args|argv|payload|input)\b")
_PROMPT_VAR = re.compile(r"(prompt|system|instruction|template|messages?|content|query)", re.I)
_LLM_CALL = re.compile(r"(create|complete|completions|chat|invoke|ainvoke|generate(Text|Content)?|predict|run)", re.I)

_LANG = {".ts": "typescript", ".tsx": "tsx", ".js": "javascript",
         ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript"}


def _parser(lang: str):
    from tree_sitter_language_pack import get_parser
    return get_parser(lang)


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _ancestor_context(node, src: bytes) -> bool:
    """True if this template literal is used as a prompt: assigned to a
    prompt-like variable, or passed to an LLM-ish call."""
    cur = node.parent
    depth = 0
    while cur is not None and depth < 10:
        if cur.type == "variable_declarator":
            name = cur.child_by_field_name("name")
            if name and _PROMPT_VAR.search(_text(name, src)):
                return True
        if cur.type in ("call_expression", "new_expression"):
            fn = cur.child_by_field_name("function")
            if fn and _LLM_CALL.search(_text(fn, src)):
                return True
        cur = cur.parent
        depth += 1
    return False


def scan_source(src_text: str, filename: str) -> List[Dict[str, Any]]:
    lang = _LANG.get(os.path.splitext(filename)[1].lower())
    if not lang:
        return []
    try:
        parser = _parser(lang)
    except Exception:
        return []  # tree-sitter not installed: skip, never break the scan
    src = src_text.encode("utf-8")
    tree = parser.parse(src)
    out: List[Dict[str, Any]] = []

    def walk(node):
        if node.type == "template_string":
            subs = [c for c in node.children if c.type == "template_substitution"]
            if subs:
                interp = " ".join(_text(s, src) for s in subs)
                if _UNTRUSTED.search(interp) and _ancestor_context(node, src):
                    out.append({
                        "rule_id": "CANARY-JSTS-001", "severity": "High",
                        "owasp_agentic": "ASI-01 Agent Goal Hijack",
                        "file": filename, "line": node.start_point[0] + 1,
                        "message": "Untrusted value interpolated into a prompt template "
                                   "literal (JS/TS). Separate untrusted input from "
                                   "instructions; do not splice it into the prompt.",
                    })
        for c in node.children:
            walk(c)

    walk(tree.root_node)
    return out


def scan_path(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    exts = tuple(_LANG)
    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for dp, dn, fn in os.walk(path):
            dn[:] = [d for d in dn if d not in {".git", "node_modules", "dist", "build"}]
            files += [os.path.join(dp, f) for f in fn if f.endswith(exts)]
    for fp in files:
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                out.extend(scan_source(fh.read(), fp))
        except OSError:
            continue
    return out
