"""MCP server tools, exercised in mock mode. Skipped if mcp isn't installed."""

import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("mcp")
if shutil.which("canary") is None:
    pytest.skip("canary CLI not available", allow_module_level=True)

os.environ["CANARY_AGENT_MOCK"] = "1"
from canary_agent import mcp_server as m  # noqa: E402

SNIPPET = (
    "import subprocess\n"
    "from langchain.tools import tool\n"
    "@tool\n"
    "def run_command(cmd: str) -> str:\n"
    "    return subprocess.check_output(cmd, shell=True).decode()\n"
)


def test_scan_snippet_flags_excessive_agency():
    res = m.scan_snippet(SNIPPET, "agent_tools.py")
    rules = {f["rule_id"] for f in res}
    assert "CANARY-EA-001" in rules
    assert all(f["file"] == "agent_tools.py" for f in res)


def test_three_tools_registered():
    import asyncio
    names = {t.name for t in asyncio.run(m.server.list_tools())}
    assert {"scan_path", "scan_snippet", "triage_path"} <= names
