"""Thin wrapper around the Meta Model API, with an offline mock fallback.

Real mode uses the OpenAI SDK pointed at the Meta Model API endpoint
(drop-in OpenAI-compatible). Mock mode returns a transparent, rule-based
verdict so the whole pipeline runs with no key and no spend. The mock is NOT
a prediction of real model quality: it only exists so the plumbing can be
built and tested before credits arrive, and every mock verdict is tagged
mode="mock" so it can never be mistaken for a real result.
"""

from __future__ import annotations

import json
from typing import Dict, Any

from .config import Config

SYSTEM_PROMPT = (
    "You are a security triage analyst reviewing static-analysis findings for "
    "LLM and AI-agent code. Answer two INDEPENDENT questions.\n\n"
    "1. decision - is the vulnerable data flow real?\n"
    "   true_positive  = the pattern the rule describes genuinely holds here "
    "(e.g. attacker-controllable input really is interpolated into the prompt, "
    "or passed to the tool/sink). Judge this ONLY on whether the flow is real, "
    "NOT on how damaging it is. A real finding whose blast radius is small is "
    "STILL a true_positive.\n"
    "   false_positive = the flow is not real: the value is a trusted constant, "
    "the flagged line is a comment / docstring / type or field declaration, or "
    "the scanner mismatched the line.\n"
    "   Two kinds of rule, judged differently:\n"
    "   - PRESENCE rules (prompt injection, excessive agency, leaked key, PII in "
    "logs): true_positive when the bad flow is genuinely present.\n"
    "   - ABSENCE-of-control rules (e.g. an LLM call with no visible output "
    "guardrail): true_positive ONLY when the missing control plausibly matters "
    "here - untrusted or sensitive data is actually in play. A routine SDK call "
    "with trusted inputs and no dangerous downstream use is a false_positive, "
    "since 'no guardrail' is true of almost every model call and is not by "
    "itself a vulnerability.\n\n"
    "2. exploitability - the blast radius, rated separately (this NEVER turns a "
    "real finding into a false positive):\n"
    "   reaches_tool_or_shell   - untrusted data reaches a tool, shell, eval/exec or file write the model can drive\n"
    "   reaches_secret_or_exfil - secrets, credentials, or data exfiltration\n"
    "   self_output_only        - only affects the caller's own output; no tool, secret or cross-user boundary is crossed\n"
    "   not_applicable          - no untrusted data flow (e.g. a hardcoded key is exposure, not injection)\n\n"
    "Judge only from the evidence given. Respond with a single JSON object and "
    "nothing else, shaped exactly like:\n"
    '{"decision": "true_positive" | "false_positive" | "uncertain", '
    '"confidence": <float 0..1>, '
    '"exploitability": "reaches_tool_or_shell" | "reaches_secret_or_exfil" | "self_output_only" | "not_applicable", '
    '"reason": "<one or two sentences>", '
    '"suggested_fix": "<short fix, or null>"}'
)


def build_user_prompt(finding: Dict[str, Any], code_context: str) -> str:
    lines = [
        f"Rule: {finding.get('rule_id')} ({finding.get('title') or finding.get('severity')})",
        f"OWASP LLM: {finding.get('owasp', 'n/a')}",
        f"Severity: {finding.get('severity')}",
        f"File: {finding.get('file')}:{finding.get('line')}",
    ]
    if finding.get("explanation"):
        lines.append(f"Why the scanner flagged it: {finding['explanation']}")
    lines.append("")
    lines.append("Code context:")
    lines.append("```")
    lines.append(code_context.strip() or finding.get("snippet", ""))
    lines.append("```")
    return "\n".join(lines)


def _mock_verdict(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Transparent, documented heuristic. Not a quality claim.

    It mirrors what the benchmark already showed: GR-001 is a weak advisory
    rule (measured ~24% precision), so the mock leans false_positive on it and
    true_positive on the high-signal rules. This lets the eval exercise both
    branches offline without pretending to be the model.
    """
    rule = finding.get("rule_id", "")
    if rule == "CANARY-GR-001":
        return {
            "decision": "false_positive",
            "confidence": 0.55,
            "exploitability": "not_applicable",
            "reason": "MOCK: low-precision advisory rule; no concrete sink shown in the snippet.",
            "suggested_fix": None,
        }
    if rule == "CANARY-SEC-005":
        return {
            "decision": "false_positive",
            "confidence": 0.5,
            "exploitability": "not_applicable",
            "reason": "MOCK: generic api_key assignment; often a fixture or placeholder.",
            "suggested_fix": None,
        }
    _expl = {
        "CANARY-EA-001": "reaches_tool_or_shell",
        "CANARY-EA-002": "reaches_tool_or_shell",
        "CANARY-SEC-001": "reaches_secret_or_exfil",
        "CANARY-SEC-002": "reaches_secret_or_exfil",
        "CANARY-SEC-003": "reaches_secret_or_exfil",
        "CANARY-SEC-004": "reaches_secret_or_exfil",
        "CANARY-PII-001": "reaches_secret_or_exfil",
    }.get(rule, "self_output_only")
    return {
        "decision": "true_positive",
        "confidence": 0.7,
        "exploitability": _expl,
        "reason": "MOCK: high-signal rule; treated as a real issue pending model review.",
        "suggested_fix": "MOCK: review and apply the rule's documented remediation.",
    }


def _parse_json_verdict(text: str) -> Dict[str, Any]:
    """Pull the JSON object out of a model reply, tolerant of stray prose."""
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    return json.loads(text)


class ModelClient:
    def __init__(self, config: Config):
        self.config = config
        self._client = None

    def _openai(self):
        if self._client is None:
            from openai import OpenAI  # lazy: not needed in mock mode

            # timeout so one stuck call can't hang the whole run; a couple of
            # retries to ride out transient rate limits.
            self._client = OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                timeout=45.0,
                max_retries=2,
            )
        return self._client

    def triage(self, finding: Dict[str, Any], code_context: str) -> Dict[str, Any]:
        """Return a raw verdict dict plus the mode that produced it."""
        if self.config.mock:
            out = _mock_verdict(finding)
            out["mode"] = "mock"
            return out

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(finding, code_context)},
        ]
        try:
            resp = self._openai().chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
                response_format={"type": "json_object"},
            )
        except Exception:
            # Some endpoints reject response_format; the system prompt already
            # demands JSON only, and the parser tolerates stray prose.
            resp = self._openai().chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0,
            )
        out = _parse_json_verdict(resp.choices[0].message.content or "{}")
        out["mode"] = self.config.model
        return out
