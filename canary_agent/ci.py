"""CI entry point: scan a path, triage, and write a Markdown summary.

Designed for a CI/PR gate. It scans with canary, pre-filters obvious SEC-005
fixtures, triages the rest with Muse Spark when MODEL_API_KEY is set (otherwise
reports raw findings), and writes a summary suitable for a PR comment or
$GITHUB_STEP_SUMMARY. Exit code 1 when a confirmed finding reaches a tool/shell
or a secret, so the build can gate on real risk.

    python -m canary_agent.ci . --summary-out summary.md
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .model_client import ModelClient
from .owasp import agentic_label
from .refine import prefilter
from .rescan import scan_all
from .schema import Finding
from .triage import triage_finding

GATE = {"reaches_tool_or_shell", "reaches_secret_or_exfil"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--summary-out", default="")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    raw = scan_all(args.path)
    kept, suppressed = prefilter(raw)
    config = Config.from_env()
    client = ModelClient(config)

    lines = ["# canary-agent security report\n"]
    lines.append(f"Scanned `{args.path}`: **{len(raw)} findings** "
                 f"({len(suppressed)} obvious fixtures filtered).\n")

    gate_hit = 0
    if config.mock:
        lines.append("_No MODEL_API_KEY set: raw findings only, not triaged._\n")
        by_rule = Counter(f.get("rule_id", "") for f in kept)
        lines.append("| rule | count | OWASP Agentic |")
        lines.append("|---|---:|---|")
        for r, c in sorted(by_rule.items()):
            lines.append(f"| {r} | {c} | {agentic_label(r)} |")
    else:
        def work(f):
            fd = Finding.from_canary(f)
            return f, triage_finding(fd, client, f.get("snippet", ""))
        verdicts = []
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for fut in as_completed([pool.submit(work, f) for f in kept]):
                verdicts.append(fut.result())
        confirmed = [(f, v) for f, v in verdicts if v.decision == "true_positive"]
        expl = Counter(v.exploitability for _, v in confirmed)
        gate_hit = sum(1 for _, v in confirmed if v.exploitability in GATE)
        lines.append(f"Triaged with `{config.model}`: **{len(confirmed)} confirmed**, "
                     f"{gate_hit} reaching a tool/shell or a secret.\n")
        lines.append("| finding | rule | exploitability | OWASP Agentic |")
        lines.append("|---|---|---|---|")
        for f, v in sorted(confirmed, key=lambda x: x[1].exploitability not in GATE):
            loc = f"{os.path.basename(f.get('file_path', f.get('file','')))}:{f.get('line')}"
            lines.append(f"| `{loc}` | {f.get('rule_id')} | {v.exploitability} | "
                         f"{agentic_label(f.get('rule_id',''))} |")

    summary = "\n".join(lines) + "\n"
    if args.summary_out:
        with open(args.summary_out, "a", encoding="utf-8") as fh:
            fh.write(summary)
    print(summary)
    return 1 if gate_hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
