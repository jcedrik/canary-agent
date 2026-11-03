from langchain_core.tools import tool
import subprocess
import shlex

ALLOWED_COMMANDS = {"ls", "pwd", "echo"}

@tool
def run_command(cmd: str) -> str:
    """Run an allowlisted diagnostic command (no shell). Input must start with one of: ls, pwd, echo."""
    parts = shlex.split(cmd)
    if not parts:
        raise ValueError("Empty command")
    binary = parts[0].split("/")[-1]
    if binary not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {binary}")
    for arg in parts[1:]:
        if arg in ("|", "&", ";", ">", "<", "`", "$", "&&", "||"):
            raise ValueError(f"Shell metacharacter not allowed: {arg}")
    completed = subprocess.run(
        parts, shell=False, capture_output=True, text=True, timeout=10, check=False
    )
    return completed.stdout
