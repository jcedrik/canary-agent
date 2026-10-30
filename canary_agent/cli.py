"""Command line: triage a canary JSON report.

    canary ./my-app --format json -o findings.json
    canary-agent findings.json            # mock unless MODEL_API_KEY is set

Prints one line per finding with the agent's verdict. The fix-and-verify loop
(canary_agent.loop) plugs in here next."""

from __future__ import annotations

import argparse
import json
import sys

from .config import Config
from .model_client import ModelClient
from .schema import Finding
from .triage import triage_finding


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage a canary JSON report with Muse Spark.")
    ap.add_argument("report", help="path to a canary --format json report")
    ap.add_argument("--min-confidence", type=float, default=0.0)
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as fh:
        data = json.load(fh)
    raw = data.get("findings", data) if isinstance(data, dict) else data

    config = Config.from_env()
    client = ModelClient(config)
    mode = "MOCK" if config.mock else config.model
    print(f"canary-agent triage | {mode} | {len(raw)} findings\n")

    for item in raw:
        finding = Finding.from_canary(item)
        v = triage_finding(finding, client)
        if v.confidence < args.min_confidence:
            continue
        print(f"[{v.label:>2}] {v.confidence:.2f} {finding.rule_id:<16} "
              f"{finding.file}:{finding.line}")
        print(f"      {v.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
