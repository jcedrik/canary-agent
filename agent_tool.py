"""Secure LangChain tool: run an allowlisted shell command.

Only read-only commands in ALLOWED_COMMANDS execute, with shell=False,
argument parsing via shlex, and a timeout. Anything else is blocked.
"""

from langchain.tools import tool
import shlex
import subprocess

ALLOWED_COMMANDS = frozenset({"ls", "pwd", "whoami", "date", "echo"})


@tool
def run_command(cmd: str) -> str:
    """Run an allowlisted read-only shell command and return its output."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return "blocked: could not parse command"
    if not parts or parts[0] not in ALLOWED_COMMANDS:
        return "blocked: command not in allowlist"
    try:
        proc = subprocess.run(
            parts, shell=False, capture_output=True, text=True, timeout=10
        )
    except subprocess.TimeoutExpired:
        return "blocked: command timed out"
    return proc.stdout
