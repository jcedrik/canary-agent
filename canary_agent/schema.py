"""Data shapes shared across the agent: a Finding (what the scanner reports)
and a Verdict (what the triage model decides about it)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any


@dataclass
class Finding:
    """One static-analysis finding, as produced by canary --format json."""

    rule_id: str
    severity: str
    file: str
    line: int
    snippet: str
    title: str = ""
    explanation: str = ""
    owasp: str = ""

    @classmethod
    def from_canary(cls, d: Dict[str, Any]) -> "Finding":
        """Build from a canary JSON finding object."""
        return cls(
            rule_id=d.get("rule_id", ""),
            severity=d.get("severity", ""),
            file=d.get("file_path", d.get("file", "")),
            line=int(d.get("line", 0) or 0),
            snippet=d.get("snippet", ""),
            title=d.get("title", ""),
            explanation=d.get("explanation", ""),
            owasp=d.get("owasp", ""),
        )


@dataclass
class Verdict:
    """The triage decision for a single finding."""

    rule_id: str
    file: str
    line: int
    decision: str  # "true_positive" | "false_positive" | "uncertain"
    confidence: float  # 0.0 - 1.0
    reason: str
    suggested_fix: Optional[str] = None
    mode: str = "mock"  # which backend produced it: "mock" or a model id

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def label(self) -> str:
        """Collapse the decision to the same TP/FP vocabulary as labels.csv."""
        return {"true_positive": "TP", "false_positive": "FP"}.get(self.decision, "?")
