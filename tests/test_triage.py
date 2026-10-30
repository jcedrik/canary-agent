"""Tests that run fully offline (mock mode), no key, no network."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.model_client import ModelClient, _parse_json_verdict, build_user_prompt
from canary_agent.schema import Finding, Verdict
from canary_agent.triage import triage_finding


def _mock_client():
    return ModelClient(Config(api_key="", model="muse-spark-1.3", base_url="x", mock=True))


def test_mock_returns_valid_verdict():
    f = Finding(rule_id="CANARY-PI-001", severity="High", file="a.py", line=10,
                snippet='prompt = f"{user_input}"')
    v = triage_finding(f, _mock_client())
    assert isinstance(v, Verdict)
    assert v.decision in ("true_positive", "false_positive", "uncertain")
    assert 0.0 <= v.confidence <= 1.0
    assert v.mode == "mock"


def test_mock_leans_fp_on_low_precision_rule():
    f = Finding(rule_id="CANARY-GR-001", severity="Low", file="a.py", line=5,
                snippet="response = client.messages.create(")
    assert triage_finding(f, _mock_client()).decision == "false_positive"


def test_label_mapping():
    assert Verdict("r", "f", 1, "true_positive", 0.9, "x").label == "TP"
    assert Verdict("r", "f", 1, "false_positive", 0.9, "x").label == "FP"
    assert Verdict("r", "f", 1, "uncertain", 0.5, "x").label == "?"


def test_json_parser_tolerates_prose():
    out = _parse_json_verdict('Sure!\n{"decision": "false_positive", "confidence": 0.3} done')
    assert out["decision"] == "false_positive"


def test_prompt_includes_rule_and_code():
    p = build_user_prompt({"rule_id": "CANARY-EA-001", "severity": "High",
                           "file": "t.py", "line": 3}, "subprocess.run(cmd)")
    assert "CANARY-EA-001" in p and "subprocess.run(cmd)" in p
