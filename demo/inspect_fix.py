"""Diagnostic: show the patch the model writes for one finding, and what
canary says about it afterwards. Lets us see whether a non-clearing fix is a
good patch canary over-flags, or a weak patch.

    python demo/inspect_fix.py examples/vulnerable_app/app.py CANARY-EA-001
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.fixers import Fixer
from canary_agent.rescan import scan, rule_set


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: python demo/inspect_fix.py <file> <RULE-ID>")
        return 2
    path, rule_id = sys.argv[1], sys.argv[2]
    config = Config.from_env()
    print(f"=== inspect fix | {'MOCK' if config.mock else config.model} | {rule_id} ===\n")

    with open(path, encoding="utf-8") as fh:
        original = fh.read()

    before = rule_set(scan(path))
    print(f"rules before: {sorted(before)}\n")

    patch = Fixer(config).fix(rule_id, original)
    if not patch:
        print("no patch produced for this rule.")
        return 0

    tmp = tempfile.mkdtemp(prefix="inspect_")
    target = os.path.join(tmp, os.path.basename(path))
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(patch)
    after = rule_set(scan(target))

    print(f"rules after patch: {sorted(after)}")
    print(f"{rule_id} cleared? {'YES' if rule_id not in after else 'NO'}")
    print(f"new rules introduced: {sorted(after - before) or 'none'}")
    print("\n--- patch muse-spark wrote (full file) ---\n")
    print(patch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
