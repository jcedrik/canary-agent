"""Live MCP server inspection and baseline-drift detection.

The static audit (`mcp_audit.py`) reads a config. This connects to a declared
MCP server read-only, lists the tools it actually exposes WITHOUT calling any of
them, and records a signature. Re-checking later detects drift: a tool whose
description or schema changed after you approved it is the "rug-pull" supply
chain attack (ASI-04), where a server quietly repurposes a trusted tool.

Needs the MCP SDK (`pip install -e .[mcp]`). HTTP (streamable-http) servers only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Dict, Any, List


async def _alist(url: str) -> List[Dict[str, Any]]:
    from mcp.client.streamable_http import streamable_http_client
    from mcp.client.session import ClientSession
    async with streamable_http_client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.list_tools()
            return [{"name": t.name, "description": t.description or "",
                     "input_schema": getattr(t, "inputSchema", {}) or {}}
                    for t in res.tools]


def list_tools(url: str) -> List[Dict[str, Any]]:
    """List a running server's tools, read-only. Never calls a tool."""
    return asyncio.run(_alist(url))


def _signature(tools: List[Dict[str, Any]]) -> Dict[str, str]:
    sig = {}
    for t in tools:
        blob = (t.get("description", "") + "|" +
                json.dumps(t.get("input_schema", {}), sort_keys=True))
        sig[t["name"]] = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return sig


def inspect_server(url: str) -> Dict[str, Any]:
    tools = list_tools(url)
    return {"url": url, "n_tools": len(tools), "tools": tools,
            "signature": _signature(tools)}


def save_baseline(path: str, inspection: Dict[str, Any]) -> None:
    json.dump({"url": inspection["url"], "signature": inspection["signature"]},
              open(path, "w", encoding="utf-8"), indent=1)


def load_baseline(path: str) -> Dict[str, Any]:
    return json.load(open(path, encoding="utf-8"))


def drift(baseline_sig: Dict[str, str], current_sig: Dict[str, str]) -> Dict[str, List[str]]:
    """Compare two signatures. 'changed' tools are the rug-pull risk."""
    return {
        "added": [k for k in current_sig if k not in baseline_sig],
        "removed": [k for k in baseline_sig if k not in current_sig],
        "changed": [k for k in current_sig if k in baseline_sig
                    and current_sig[k] != baseline_sig[k]],
    }
