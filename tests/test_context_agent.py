"""Tests for the agentic context lookups (D). The resolver runs fully offline;
the agent loop falls back to single-pass triage in mock mode."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.context_agent import _resolve, triage_with_lookups
from canary_agent.model_client import ModelClient
from canary_agent.schema import Finding, Verdict

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "examples", "multifile_app")


def test_resolver_finds_callers_across_files():
    out = _resolve(EXAMPLE, {"kind": "callers", "symbol": "summarize"})
    assert "web.py" in out and "summarize(q)" in out


def test_resolver_finds_definition():
    out = _resolve(EXAMPLE, {"kind": "definition", "symbol": "summarize"})
    assert "def summarize" in out


def test_resolver_rejects_path_escape():
    out = _resolve(EXAMPLE, {"kind": "file", "path": "../../../etc/passwd"})
    assert "outside" in out or "not found" in out


def test_mock_falls_back_to_single_pass():
    cfg = Config(api_key="", model="muse-spark-1.3", base_url="x", mock=True)
    f = Finding(rule_id="CANARY-PI-001", severity="High", file="summarizer.py",
                line=7, snippet='prompt = f"...{document}"')
    v = triage_with_lookups(f, ModelClient(cfg), EXAMPLE, "prompt = f'...{document}'")
    assert isinstance(v, Verdict) and v.mode == "mock"
