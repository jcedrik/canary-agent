"""Audit an MCP client config for dangerous wiring.

    python demo/audit_mcp.py examples/mcp_configs/insecure.json
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.mcp_audit import audit_file


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python demo/audit_mcp.py <mcp-config.json>")
        return 2
    path = sys.argv[1]
    findings = audit_file(path)
    print(f"=== MCP config audit | {path} ===")
    if not findings:
        print("clean: no dangerous wiring found.")
        return 0
    print(f"{len(findings)} issue(s):\n")
    for f in findings:
        print(f"[{f['severity']:>8}] {f['rule_id']}  server '{f['server']}'  [{f['owasp_agentic']}]")
        print(f"           {f['message']}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
