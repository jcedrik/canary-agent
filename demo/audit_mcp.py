"""Audit MCP wiring: a static config, or a live server.

    # static config audit:
    python demo/audit_mcp.py examples/mcp_configs/insecure.json

    # live server: list its tools read-only, and save/compare a baseline:
    python demo/audit_mcp.py --live http://127.0.0.1:8765/mcp
    python demo/audit_mcp.py --live http://127.0.0.1:8765/mcp --baseline base.json
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.mcp_audit import audit_file


def _static(path: str) -> int:
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


def _live(url: str, baseline: str) -> int:
    from canary_agent.mcp_live import inspect_server, save_baseline, load_baseline, drift
    insp = inspect_server(url)
    print(f"=== MCP live inspection | {url} ===")
    print(f"{insp['n_tools']} tool(s) exposed (listed read-only, none called):")
    for t in insp["tools"]:
        print(f"  - {t['name']}: {(t['description'] or '')[:70]}")
    if not baseline:
        return 0
    if not os.path.exists(baseline):
        save_baseline(baseline, insp)
        print(f"\nsaved baseline to {baseline}. Re-run with it to detect drift.")
        return 0
    d = drift(load_baseline(baseline)["signature"], insp["signature"])
    print("\nbaseline drift:")
    if not any(d.values()):
        print("  none: tools match the approved baseline.")
        return 0
    if d["changed"]:
        print(f"  CHANGED (rug-pull risk, ASI-04): {d['changed']}")
    if d["added"]:
        print(f"  added: {d['added']}")
    if d["removed"]:
        print(f"  removed: {d['removed']}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", nargs="?", help="MCP config JSON to audit")
    ap.add_argument("--live", help="URL of a running MCP server to inspect")
    ap.add_argument("--baseline", default="", help="baseline file to save/compare")
    args = ap.parse_args()
    if args.live:
        return _live(args.live, args.baseline)
    if args.config:
        return _static(args.config)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
