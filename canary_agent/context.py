"""Build the code window a triage needs: a few lines around the finding, read
from the real file when it is on disk, otherwise just the snippet the scanner
captured. Keeping the window small is deliberate: it keeps token spend low
(only the finding plus a handful of lines travels to the model)."""

from __future__ import annotations

import os
from typing import Dict, Any


def code_window(finding: Dict[str, Any], radius: int = 8) -> str:
    """Return up to `radius` lines on each side of the finding's line.

    Falls back to the stored snippet when the file is not available (e.g. the
    offline eval, where the scanned repos are no longer on disk)."""
    path = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    if path and line and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            lo = max(0, line - 1 - radius)
            hi = min(len(lines), line + radius)
            out = []
            for i in range(lo, hi):
                marker = ">>" if (i + 1) == line else "  "
                out.append(f"{marker} {i + 1:>5} | {lines[i].rstrip()}")
            return "\n".join(out)
        except OSError:
            pass
    return finding.get("snippet", "")
