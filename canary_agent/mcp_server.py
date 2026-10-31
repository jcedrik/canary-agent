"""MCP server: exposes canary to coding agents (Muse Code, and any MCP client).

The point: a coding agent checks the code it is writing for LLM-security flaws
*as it writes*, instead of finding out in CI later. The agent calls scan_snippet
on a block it just produced, sees prompt injection / excessive agency / a leaked
key, and fixes it before the code is ever saved.

Run it directly:  canary-agent-mcp   (after pip install -e .[mcp])

Works with mcp>=2 (MCPServer) and mcp<2 (FastMCP); the API is the same here.
"""

from __future__ import annotations

import os
import tempfile
from typing import List, Dict, Any

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:  # mcp < 2
    from mcp.server.fastmcp import FastMCP as _Server

from .config import Config
from .model_client import ModelClient
from .rescan import scan
from .schema import Finding
from .triage import triage_finding

server = _Server("canary-agent")


def _slim(f: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": f.get("rule_id", ""),
        "severity": f.get("severity", ""),
        "owasp": f.get("owasp", ""),
        "file": f.get("file_path", f.get("file", "")),
        "line": f.get("line", 0),
        "why": f.get("explanation", ""),
        "fix": f.get("remediation", ""),
        "snippet": f.get("snippet", ""),
    }


@server.tool(description="Scan a file or directory for LLM/AI-agent security flaws with canary.")
def scan_path(path: str) -> List[Dict[str, Any]]:
    return [_slim(f) for f in scan(path)]


@server.tool(description="Scan a snippet of code you just wrote, before saving it. "
                         "Returns canary findings so you can fix them in place.")
def scan_snippet(code: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
    tmp = tempfile.mkdtemp(prefix="canary_mcp_")
    target = os.path.join(tmp, os.path.basename(filename) or "snippet.py")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(code)
    findings = [_slim(f) for f in scan(target)]
    for f in findings:  # report the caller's filename, not the temp path
        f["file"] = filename
    return findings


@server.tool(description="Scan a path and triage each finding with Muse Spark: "
                         "true/false positive, confidence, and reason.")
def triage_path(path: str) -> List[Dict[str, Any]]:
    client = ModelClient(Config.from_env())
    out = []
    for f in scan(path):
        finding = Finding.from_canary(f)
        v = triage_finding(finding, client)
        out.append({
            "rule_id": finding.rule_id,
            "file": finding.file,
            "line": finding.line,
            "decision": v.decision,
            "confidence": v.confidence,
            "reason": v.reason,
            "mode": v.mode,
        })
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="canary-agent MCP server")
    ap.add_argument("--http", action="store_true",
                    help="serve over HTTP (streamable-http) instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    if args.http:
        # For MCP clients that connect to a URL (e.g. Muse Code's mcp_servers
        # with transport "streamable_http", url http://127.0.0.1:8765/mcp).
        server.run(transport="streamable-http", host=args.host, port=args.port,
                   streamable_http_path="/mcp")
    else:
        server.run()  # stdio, for clients that launch the server as a command


if __name__ == "__main__":
    main()
