"""Noise refinement over canary's raw findings.

canary's generic-key rule (SEC-005, `api_key = "..."`) is deliberately broad and
fires mostly on test fixtures and placeholders. Rather than pay the model to
triage each one, canary-agent pre-filters the obvious fixtures deterministically
and reports them as suppressed. The provider-specific key rules (SEC-001..004)
and every other rule are left untouched.
"""

from __future__ import annotations

import re
from typing import Dict, Any, List, Tuple

_FIXTURE_PATH = re.compile(r"(^|[/\\])(tests?|fixtures?|examples?|samples?|mocks?|"
                           r"docs?|__mocks__|e2e|spec|conftest)([/\\]|\.|$)", re.I)

# placeholder values that are plainly not real secrets
_PLACEHOLDER = re.compile(
    r"(your[_-]?api|your[_-]?key|replace[_-]?me|changeme|change[_-]?this|placeholder|"
    r"example|dummy|sample|test[_-]?key|fake|xxx+|\.\.\.|<[^>]*>|\{\{?[^}]*\}?\}|"
    r"\$\{?[a-z_]+\}?|os\.environ|getenv|process\.env|sk-xxx|sk-\.\.\.)", re.I)


def _assigned_value(snippet: str):
    m = re.search(r"""=\s*['"]([^'"]*)['"]""", snippet)
    return m.group(1) if m else None


def is_low_value_sec005(finding: Dict[str, Any]) -> bool:
    if finding.get("rule_id") != "CANARY-SEC-005":
        return False
    path = finding.get("file_path", finding.get("file", "")) or ""
    if _FIXTURE_PATH.search(path):
        return True
    snippet = finding.get("snippet", "") or ""
    if _PLACEHOLDER.search(snippet):
        return True
    val = _assigned_value(snippet)
    if val is None:
        return False
    if _PLACEHOLDER.search(val):
        return True
    # a plausible real secret is long and high-entropy-ish; short values are noise
    if len(val) < 12 or " " in val or val.lower() in ("none", "null", "true", "false"):
        return True
    return False


def prefilter(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (kept, suppressed). Suppressed are obvious SEC-005 fixtures."""
    kept, suppressed = [], []
    for f in findings:
        (suppressed if is_low_value_sec005(f) else kept).append(f)
    return kept, suppressed
