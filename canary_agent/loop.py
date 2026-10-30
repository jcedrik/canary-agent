"""Fix-and-verify loop.

For a finding judged a true positive: generate a patch, apply it to a scratch
copy of the file, re-run canary, and accept the patch only if that finding is
gone and no new rule fired. The model proposes; canary disposes.

    model/mock patch ──► scratch copy ──► canary re-scan ──► gone & no regression?
                                                               accept / discard
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Optional

from .config import Config
from .fixers import Fixer
from .rescan import scan, rule_set


@dataclass
class FixResult:
    rule_id: str
    file: str
    line: int
    patched: bool          # did the fixer produce a patch at all
    verified: bool         # did canary confirm the finding is gone
    regression: bool       # did a new rule appear after patching
    new_text: Optional[str]
    note: str


def _finding_present(findings, rule_id: str) -> bool:
    return any(f.get("rule_id") == rule_id for f in findings)


def fix_and_verify(file_path: str, rule_id: str, line: int,
                   fixer: Fixer, config: Config = None) -> FixResult:
    config = config or Config.from_env()
    with open(file_path, encoding="utf-8") as fh:
        original = fh.read()

    before = scan(file_path)
    before_rules = rule_set(before)

    new_text = fixer.fix(rule_id, original)
    if not new_text or new_text == original:
        return FixResult(rule_id, file_path, line, False, False, False, None,
                         "no patch produced for this rule")

    # apply to an isolated scratch copy and re-scan there
    scratch = tempfile.mkdtemp(prefix="canary_agent_")
    try:
        target = os.path.join(scratch, os.path.basename(file_path))
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        after = scan(target)
        after_rules = rule_set(after)

        verified = not _finding_present(after, rule_id)
        regression = bool(after_rules - before_rules)
        if verified and not regression:
            note = "patch verified by re-scan: finding cleared, no new findings"
        elif verified and regression:
            note = f"finding cleared but a new rule appeared: {sorted(after_rules - before_rules)}"
        else:
            note = "patch did not clear the finding on re-scan"
        return FixResult(rule_id, file_path, line, True, verified, regression,
                         new_text, note)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
