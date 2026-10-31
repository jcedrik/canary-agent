"""Standards mapping.

canary already tags each finding with the OWASP LLM Top 10 (2025). This adds,
where it genuinely fits, the OWASP Top 10 for Agentic Applications (2026) - the
"ASI" list the agent-security field has moved to. Only rules with a clean
agentic mapping are listed; rules that are not agent-specific (PII in logs,
missing output guardrail) are left unmapped rather than forced.
"""

from __future__ import annotations

from typing import Optional, Tuple

# rule_id -> (ASI code, short title)
ASI_MAP = {
    "CANARY-PI-001": ("ASI-01", "Agent Goal Hijack"),
    "CANARY-PI-002": ("ASI-01", "Agent Goal Hijack"),
    "CANARY-EA-001": ("ASI-02", "Tool Misuse"),
    "CANARY-EA-002": ("ASI-02", "Tool Misuse"),
    "CANARY-SEC-001": ("ASI-03", "Identity & Privilege Abuse"),
    "CANARY-SEC-002": ("ASI-03", "Identity & Privilege Abuse"),
    "CANARY-SEC-003": ("ASI-03", "Identity & Privilege Abuse"),
    "CANARY-SEC-004": ("ASI-03", "Identity & Privilege Abuse"),
    "CANARY-SEC-005": ("ASI-03", "Identity & Privilege Abuse"),
}


def agentic(rule_id: str) -> Optional[Tuple[str, str]]:
    """Return (ASI code, title) for a rule, or None when it has no clean
    agentic-threat mapping."""
    return ASI_MAP.get(rule_id)


def agentic_label(rule_id: str) -> str:
    hit = ASI_MAP.get(rule_id)
    return f"{hit[0]} {hit[1]}" if hit else "-"
