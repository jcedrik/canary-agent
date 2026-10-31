"""End-to-end demo: scan -> triage -> fix -> verify, on one vulnerable file.

This is the backbone of the 3-minute hackathon video. It runs the whole agent
on a deliberately vulnerable app and prints, for each finding, the triage
verdict and whether an auto-generated patch was verified by a canary re-scan.

    # offline (mock), no key:
    CANARY_AGENT_MOCK=1 python demo/run_demo.py path/to/vulnerable_app

    # live, once credits land:
    MODEL_API_KEY=... python demo/run_demo.py path/to/vulnerable_app
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.context import code_window
from canary_agent.context_agent import triage_with_lookups
from canary_agent.fixers import Fixer
from canary_agent.loop import fix_and_verify
from canary_agent.model_client import ModelClient
from canary_agent.owasp import agentic_label
from canary_agent.rescan import scan
from canary_agent.schema import Finding
from canary_agent.triage import triage_finding


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--deep"]
    deep = "--deep" in sys.argv
    target = args[0] if args else "examples/vulnerable_app"
    repo_root = target if os.path.isdir(target) else os.path.dirname(target) or "."
    config = Config.from_env()
    mode = "MOCK (offline, not real model output)" if config.mock else f"LIVE {config.model}"
    if deep:
        mode += " + deep (agent fetches context)"
    client = ModelClient(config)
    fixer = Fixer(config)

    print(f"=== canary-agent demo | {mode} ===")
    print(f"target: {target}\n")

    findings = scan(target)
    print(f"canary found {len(findings)} findings. Running triage + fix:\n")

    confirmed = fixed = 0
    for f in findings:
        finding = Finding.from_canary(f)
        if deep:
            verdict = triage_with_lookups(finding, client, repo_root, code_window(f))
        else:
            verdict = triage_finding(finding, client)
        tag = verdict.label
        print(f"[{tag:>2}] {finding.rule_id:<16} {os.path.basename(finding.file)}:{finding.line}  "
              f"<{verdict.exploitability}>  [{agentic_label(finding.rule_id)}]")
        print(f"     triage: {verdict.reason}")

        if verdict.decision != "true_positive":
            print()
            continue
        confirmed += 1
        res = fix_and_verify(f.get("file_path", f.get("file", "")),
                             finding.rule_id, finding.line, fixer, config)
        mark = "VERIFIED" if res.verified and not res.regression else "not cleared"
        print(f"     fix:    {mark} - {res.note}")
        fixed += int(res.verified and not res.regression)
        print()

    print(f"summary: {len(findings)} findings, {confirmed} confirmed by triage, "
          f"{fixed} auto-fixed and verified by re-scan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
