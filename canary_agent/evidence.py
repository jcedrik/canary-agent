"""Deterministic evidence trail.

Every triage verdict ships with the deterministic facts it was judged against,
so a reviewer can check the finding without trusting the model: the rule, its
CWE and OWASP mappings (LLM Top 10 and, where it fits, Agentic Top 10), the
exact location, and the matched line. The model's verdict is a separate layer
on top of this evidence, never a replacement for it.
"""

from __future__ import annotations

from typing import Dict, Any

from .owasp import agentic_label


def evidence_record(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the deterministic facts out of a canary finding."""
    return {
        "rule_id": finding.get("rule_id", ""),
        "severity": finding.get("severity", ""),
        "cwe": finding.get("cwe", ""),
        "owasp_llm": finding.get("owasp", ""),
        "owasp_agentic": agentic_label(finding.get("rule_id", "")),
        "file": finding.get("file_path", finding.get("file", "")),
        "line": finding.get("line", 0),
        "matched": finding.get("snippet", ""),
        "scanner_explanation": finding.get("explanation", ""),
        "scanner_remediation": finding.get("remediation", ""),
    }


def with_verdict(finding: Dict[str, Any], verdict) -> Dict[str, Any]:
    """A full record: deterministic evidence + the model's judgment layer, kept
    clearly separate."""
    return {
        "evidence": evidence_record(finding),
        "verdict": {
            "decision": verdict.decision,
            "confidence": verdict.confidence,
            "exploitability": verdict.exploitability,
            "reason": verdict.reason,
            "suggested_fix": verdict.suggested_fix,
            "model": verdict.mode,
        },
    }
