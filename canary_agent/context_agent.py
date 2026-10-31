"""Agentic triage: let the model fetch the context it needs.

A one-line snippet often can't tell the model whether an interpolated variable
is user-controlled or a trusted constant. Instead of abstaining, the triage
agent is given a fetch_context tool and can look across the repository for where
a symbol is defined or who calls a function, then judge with that in hand. The
model decides what to read; the resolver answers from the repo on disk.

In mock mode (no key) this falls back to the single-pass triage, since the mock
backend has nothing to reason with. Any error in the loop also falls back, so
the agent is never less reliable than plain triage.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Any, List

from .config import Config
from .model_client import ModelClient, SYSTEM_PROMPT, build_user_prompt
from .schema import Finding, Verdict
from .triage import triage_finding

_CODE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

FETCH_TOOL = {
    "type": "function",
    "function": {
        "name": "fetch_context",
        "description": (
            "Look across the repository for more context before judging the "
            "finding. Use it to learn whether a variable is user-controlled."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["definition", "callers", "file"],
                    "description": "definition: where a symbol is defined/assigned; "
                                   "callers: who calls a function; file: read a file.",
                },
                "symbol": {"type": "string", "description": "symbol name for definition/callers"},
                "path": {"type": "string", "description": "repo-relative path for kind=file"},
            },
            "required": ["kind"],
        },
    },
}


def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(_CODE_EXT):
                yield os.path.join(dirpath, fn)


def _search(root: str, pattern: str, max_hits: int = 6) -> str:
    rx = re.compile(pattern)
    hits: List[str] = []
    for path in _iter_files(root):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if rx.search(line):
                rel = os.path.relpath(path, root)
                lo, hi = max(0, i - 2), min(len(lines), i + 3)
                window = "".join(f"{j+1:>5}| {lines[j].rstrip()}\n" for j in range(lo, hi))
                hits.append(f"{rel}:{i+1}\n{window}")
                if len(hits) >= max_hits:
                    return "\n".join(hits)
    return "\n".join(hits) if hits else "(no matches found)"


def _resolve(root: str, args: Dict[str, Any]) -> str:
    kind = args.get("kind")
    sym = re.escape(str(args.get("symbol", "")).strip())
    if kind == "definition" and sym:
        return _search(root, rf"(def|class)\s+{sym}\b|{sym}\s*[:=]")
    if kind == "callers" and sym:
        return _search(root, rf"{sym}\s*\(")
    if kind == "file":
        rel = str(args.get("path", "")).lstrip("/\\")
        full = os.path.normpath(os.path.join(root, rel))
        if not full.startswith(os.path.abspath(root)) and not full.startswith(root):
            return "(path outside the repository)"
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                return "".join(f"{i+1:>5}| {ln.rstrip()}\n"
                                for i, ln in enumerate(fh.readlines()[:200]))
        except OSError:
            return "(file not found)"
    return "(invalid request)"


def triage_with_lookups(finding: Finding, client: ModelClient, repo_root: str,
                        code_context: str, max_steps: int = 3) -> Verdict:
    """Triage with the fetch_context tool. Falls back to single-pass triage in
    mock mode or on any error."""
    if client.config.mock:
        return triage_finding(finding, client, code_context)
    try:
        return _run(finding, client, repo_root, code_context, max_steps)
    except Exception:
        return triage_finding(finding, client, code_context)


def _run(finding: Finding, client: ModelClient, repo_root: str,
         code_context: str, max_steps: int) -> Verdict:
    oai = client._openai()
    sys_prompt = (SYSTEM_PROMPT + "\n\nIf the snippet alone is not enough to tell "
                  "whether data is untrusted, call fetch_context before deciding. "
                  "When you are ready, reply with the JSON verdict and no tool call.")
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": build_user_prompt(finding.__dict__, code_context)},
    ]
    lookups = 0
    for _ in range(max_steps + 1):
        resp = oai.chat.completions.create(
            model=client.config.model, messages=messages,
            tools=[FETCH_TOOL], temperature=0,
        )
        msg = resp.choices[0].message
        if not getattr(msg, "tool_calls", None):
            return _verdict_from(finding, msg.content or "{}", lookups)
        messages.append({
            "role": "assistant", "content": msg.content or "",
            "tool_calls": [tc.model_dump() for tc in msg.tool_calls],
        })
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            result = _resolve(repo_root, args)
            lookups += 1
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": result[:6000]})
    # out of steps: force a final answer without tools
    resp = oai.chat.completions.create(
        model=client.config.model, messages=messages, temperature=0)
    return _verdict_from(finding, resp.choices[0].message.content or "{}", lookups)


def _verdict_from(finding: Finding, content: str, lookups: int) -> Verdict:
    from .model_client import _parse_json_verdict
    from .triage import _coerce_confidence
    try:
        raw = _parse_json_verdict(content)
    except Exception:
        raw = {}
    decision = str(raw.get("decision", "uncertain")).strip().lower()
    if decision not in ("true_positive", "false_positive", "uncertain"):
        decision = "uncertain"
    expl = str(raw.get("exploitability", "unknown")).strip().lower()
    if expl not in Verdict.RISK_ORDER:
        expl = "unknown"
    reason = str(raw.get("reason", "")).strip()
    if lookups:
        reason = f"[after {lookups} lookup(s)] {reason}"
    return Verdict(
        rule_id=finding.rule_id, file=finding.file, line=finding.line,
        decision=decision, confidence=_coerce_confidence(raw.get("confidence")),
        reason=reason, suggested_fix=(raw.get("suggested_fix") or None),
        exploitability=expl, mode="muse-spark (deep)",
    )
