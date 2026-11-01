"""MCP configuration auditing.

An agent is only as safe as the MCP servers it is wired to. This reads an MCP
client config (Claude Desktop / Claude Code `mcpServers`, or Muse Code
`mcp_servers`) and flags dangerous wiring before an agent ever runs with it:
insecure transport, unpinned packages, over-broad filesystem scope, secrets in
the config, a raw shell as a server, or disabled approvals. Findings map to the
OWASP Top 10 for Agentic Applications (2026).

    python demo/audit_mcp.py path/to/config.json
    python demo/audit_mcp.py ~/.config/muse/settings.json
"""

from __future__ import annotations

import json
import re
from typing import Dict, Any, List

# rule_id -> (severity, ASI code + title, message)
_ROOTS = {"/", "~", "$HOME", "%USERPROFILE%"}
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")
_SECRET = re.compile(r"(sk-[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
                     r"|AIza[0-9A-Za-z_\-]{20,}|(api[_-]?key|token|secret)\s*[=:]\s*['\"][^'\"]{12,})")
_DANGER_FLAG = re.compile(r"^(--yolo|--dangerously[\w-]*|--disable-approval|"
                          r"--disable-sandbox|--allow-all|--auto-approve|--no-sandbox)$")


def _finding(server: str, rule: str, severity: str, asi: str, msg: str) -> Dict[str, Any]:
    return {"server": server, "rule_id": rule, "severity": severity,
            "owasp_agentic": asi, "message": msg}


def _audit_server(name: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(cfg, dict):
        return out
    command = str(cfg.get("command", "")).lower()
    args = [str(a) for a in cfg.get("args", []) if not isinstance(a, (dict, list))]
    url = str(cfg.get("url", ""))
    headers = cfg.get("headers") or {}
    env = cfg.get("env") or {}
    is_local = any(h in url for h in ("127.0.0.1", "localhost", "[::1]", "0.0.0.0"))

    # MCP-001 insecure transport (localhost http is fine, so skip it)
    if url.startswith("http://") and not is_local:
        out.append(_finding(name, "CANARY-MCP-001", "High", "ASI-04 Supply Chain",
                            "Remote MCP server over plain HTTP; traffic and tokens are exposed. Use https."))

    # MCP-002 unpinned package
    if command in ("npx", "uvx", "pnpm", "bunx") or (command == "npm" and "exec" in args):
        pkgs = [a for a in args if not a.startswith("-")]
        if pkgs and not any("@" in p[1:] or "==" in p for p in pkgs):
            out.append(_finding(name, "CANARY-MCP-002", "Medium", "ASI-04 Supply Chain",
                                f"Server runs {command} with an unpinned package ({pkgs[0]}); a later version can change behavior (rug-pull). Pin a version."))

    # MCP-003 over-broad filesystem scope
    for a in args:
        if a in _ROOTS or _DRIVE_ROOT.match(a):
            out.append(_finding(name, "CANARY-MCP-003", "High", "ASI-03 Identity & Privilege Abuse",
                                f"Filesystem scope is a root/home path ({a}); the server can read or write anywhere. Scope it to a project directory."))
            break

    # MCP-004 remote server without auth (localhost needs none)
    if url and not headers and not env and not is_local:
        out.append(_finding(name, "CANARY-MCP-004", "Medium", "ASI-03 Identity & Privilege Abuse",
                            "Remote MCP server with no auth headers or credentials; anyone reaching the URL can use it."))

    # MCP-005 secret hardcoded in config
    if _SECRET.search(json.dumps(cfg)):
        out.append(_finding(name, "CANARY-MCP-005", "Critical", "ASI-03 Identity & Privilege Abuse",
                            "A secret appears hardcoded in the MCP config; reference an environment variable instead."))

    # MCP-006 raw shell as server
    if command in ("bash", "sh", "zsh", "cmd", "powershell") and any(a in ("-c", "/c", "-command") for a in args):
        out.append(_finding(name, "CANARY-MCP-006", "High", "ASI-02 Tool Misuse",
                            "Server launches a raw shell (-c); the agent effectively gets arbitrary command execution."))

    # MCP-007 approvals/sandbox disabled
    for a in args:
        if _DANGER_FLAG.match(a):
            out.append(_finding(name, "CANARY-MCP-007", "High", "ASI-09 Trust Exploitation",
                                f"Server launched with {a}; approvals/sandbox are disabled, removing the human-in-the-loop guard."))
            break

    return out


def audit_config(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    out: List[Dict[str, Any]] = []
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            out.extend(_audit_server(str(name), cfg))
    return out


def audit_file(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return audit_config(json.load(fh))
