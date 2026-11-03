"""Tests for SEC-005 refinement, the evidence trail, and MCP drift (offline)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.refine import prefilter, is_low_value_sec005
from canary_agent.evidence import evidence_record, with_verdict
from canary_agent.mcp_live import drift, _signature
from canary_agent.schema import Verdict


def test_fixture_path_sec005_suppressed():
    assert is_low_value_sec005({"rule_id": "CANARY-SEC-005",
                                "file": "tests/test_x.py", "snippet": 'api_key = "abc123"'})


def test_placeholder_sec005_suppressed():
    assert is_low_value_sec005({"rule_id": "CANARY-SEC-005", "file": "src/a.py",
                                "snippet": 'api_key = "your-api-key"'})


def test_plausible_real_key_kept():
    assert not is_low_value_sec005({"rule_id": "CANARY-SEC-005", "file": "src/a.py",
                                    "snippet": 'api_key = "Jk28slzMMvn39sKdjfLx92"'})


def test_other_rules_untouched():
    kept, sup = prefilter([{"rule_id": "CANARY-PI-001", "file": "a.py", "snippet": "x"}])
    assert len(kept) == 1 and sup == []


def test_evidence_record_carries_deterministic_facts():
    ev = evidence_record({"rule_id": "CANARY-EA-001", "cwe": "CWE-78",
                          "owasp": "LLM06", "file_path": "a.py", "line": 5,
                          "snippet": "subprocess.run(cmd, shell=True)"})
    assert ev["cwe"] == "CWE-78" and ev["owasp_agentic"].startswith("ASI-02")
    assert ev["matched"].startswith("subprocess")


def test_with_verdict_separates_layers():
    v = Verdict("CANARY-EA-001", "a.py", 5, "true_positive", 0.9, "r",
                exploitability="reaches_tool_or_shell")
    rec = with_verdict({"rule_id": "CANARY-EA-001", "file_path": "a.py", "line": 5}, v)
    assert "evidence" in rec and "verdict" in rec
    assert rec["verdict"]["exploitability"] == "reaches_tool_or_shell"


def test_drift_detects_rug_pull():
    base = _signature([{"name": "t", "description": "old", "input_schema": {}}])
    cur = _signature([{"name": "t", "description": "NEW poisoned", "input_schema": {}}])
    assert drift(base, cur)["changed"] == ["t"]
