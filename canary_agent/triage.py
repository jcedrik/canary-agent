"""Triage orchestration: turn a Finding into a Verdict by gathering a small
code window and asking the model (or the mock) for a structured judgment."""

from __future__ import annotations

from typing import Dict, Any

from .config import Config
from .context import code_window
from .model_client import ModelClient
from .schema import Finding, Verdict


def _coerce_confidence(value: Any) -> float:
    try:
        c = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, c))


def triage_finding(finding: Finding, client: ModelClient, code_context: str = None) -> Verdict:
    ctx = code_context if code_context is not None else code_window(finding.__dict__)
    raw = client.triage(finding.__dict__, ctx)
    decision = str(raw.get("decision", "uncertain")).strip().lower()
    if decision not in ("true_positive", "false_positive", "uncertain"):
        decision = "uncertain"
    return Verdict(
        rule_id=finding.rule_id,
        file=finding.file,
        line=finding.line,
        decision=decision,
        confidence=_coerce_confidence(raw.get("confidence")),
        reason=str(raw.get("reason", "")).strip(),
        suggested_fix=(raw.get("suggested_fix") or None),
        mode=str(raw.get("mode", "mock")),
    )


def make_client(config: Config = None) -> ModelClient:
    return ModelClient(config or Config.from_env())
