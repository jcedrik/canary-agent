"""Tests for MCP configuration auditing (offline, no key)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.mcp_audit import audit_config, audit_file

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = os.path.join(HERE, "examples", "mcp_configs")


def _rules(findings):
    return {f["rule_id"] for f in findings}


def test_insecure_config_flags_all_rule_families():
    rules = _rules(audit_file(os.path.join(CONFIGS, "insecure.json")))
    for r in ("CANARY-MCP-001", "CANARY-MCP-002", "CANARY-MCP-003",
              "CANARY-MCP-004", "CANARY-MCP-005", "CANARY-MCP-006", "CANARY-MCP-007"):
        assert r in rules, f"{r} not flagged"


def test_safe_config_is_clean():
    assert audit_file(os.path.join(CONFIGS, "safe.json")) == []


def test_muse_style_key_is_supported():
    data = {"mcp_servers": {"x": {"url": "http://x/mcp"}}}
    assert any(f["rule_id"] == "CANARY-MCP-001" for f in audit_config(data))


def test_pinned_package_not_flagged():
    data = {"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg@1.2.3", "./scope"]}}}
    assert _rules(audit_config(data)) == set()


def test_every_finding_has_asi_mapping():
    for f in audit_file(os.path.join(CONFIGS, "insecure.json")):
        assert f["owasp_agentic"].startswith("ASI-")
