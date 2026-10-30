"""Evaluate the triage agent against hand-reviewed ground truth.

labels.csv carries 77 findings that JC labelled TP/FP by hand while building
canary's benchmark. This harness runs the triage agent over those same
findings and measures how often the agent's verdict matches the expert label,
and how much the agent would improve precision if you kept only what it calls
a true positive.

    # offline, no key, no spend:
    CANARY_AGENT_MOCK=1 python eval/run_eval.py

    # live, once credits land:
    MODEL_API_KEY=... python eval/run_eval.py --rule CANARY-PI-001

Cost control: only the finding plus its snippet travels to the model, so a
full run over 77 findings is a few cents, and --rule / --limit shrink it
further while iterating.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.schema import Finding, Verdict
from canary_agent.triage import triage_finding
from canary_agent.model_client import ModelClient

LABELS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "labels.csv")


def load_labeled(path: str, rule: str = "", limit: int = 0):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            gold = (r.get("label") or "").strip()
            if gold not in ("TP", "FP"):
                continue
            if rule and r.get("rule_id") != rule:
                continue
            rows.append(r)
    if limit:
        rows = rows[:limit]
    return rows


def row_to_finding(r: dict) -> Finding:
    return Finding(
        rule_id=r.get("rule_id", ""),
        severity=r.get("severity", ""),
        file=r.get("file", ""),
        line=int(r.get("line", 0) or 0),
        snippet=r.get("snippet", ""),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage agent eval against expert labels.")
    ap.add_argument("--labels", default=LABELS)
    ap.add_argument("--rule", default="", help="restrict to one rule id")
    ap.add_argument("--limit", type=int, default=0, help="cap number of findings")
    ap.add_argument("--out", default="", help="write per-finding results to this JSON file")
    ap.add_argument("--workers", type=int, default=8, help="parallel triage calls")
    ap.add_argument("--dataset", default="", help="context-enriched JSON "
                    "(labeled_with_context.json); gives the model the real code "
                    "window instead of a one-line snippet")
    args = ap.parse_args()

    config = Config.from_env()
    client = ModelClient(config)
    if args.dataset:
        recs = json.load(open(args.dataset, encoding="utf-8"))
        rows = [{**r, "label": r.get("gold", r.get("label", ""))} for r in recs
                if (not args.rule or r.get("rule_id") == args.rule)]
        if args.limit:
            rows = rows[:args.limit]
    else:
        rows = load_labeled(args.labels, args.rule, args.limit)
    if not rows:
        print("No labelled findings matched.", file=sys.stderr)
        return 2

    banner = "MOCK MODE (no model called, numbers are not real)" if config.mock else f"LIVE: {config.model}"
    print(f"=== canary-agent triage eval | {banner} ===")
    print(f"findings: {len(rows)}\n")

    # confusion counts: agent decision vs gold
    agree = 0
    per_rule = defaultdict(lambda: {"n": 0, "agree": 0})
    kept_as_tp = 0          # agent said true_positive
    kept_and_really_tp = 0  # ...and gold agrees
    uncertain = 0
    gold_tp = sum(1 for r in rows if r["label"] == "TP")
    n = len(rows)

    def work(r):
        finding = row_to_finding(r)
        return r, finding, triage_finding(finding, client, r.get("code_context"))

    # Triage in parallel (one model call each) with live progress, so a long
    # run shows movement instead of silence. Mock mode runs serially.
    workers = 1 if config.mock else max(1, args.workers)
    pairs = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, r) for r in rows]
        for fut in as_completed(futures):
            r, finding, verdict = fut.result()
            pairs.append((r, finding, verdict))
            done += 1
            flag = "ok " if verdict.label == r["label"] else "DIFF"
            print(f"  [{done:>2}/{n}] {flag} {finding.rule_id:<16} "
                  f"gold={r['label']} agent={verdict.label}")

    results = []
    for r, finding, verdict in pairs:
        gold = r["label"]
        match = verdict.label == gold
        agree += int(match)
        per_rule[finding.rule_id]["n"] += 1
        per_rule[finding.rule_id]["agree"] += int(match)
        if verdict.decision == "true_positive":
            kept_as_tp += 1
            kept_and_really_tp += int(gold == "TP")
        elif verdict.decision == "uncertain":
            uncertain += 1
        results.append({
            "rule_id": finding.rule_id,
            "file": finding.file,
            "line": finding.line,
            "gold": gold,
            "agent": verdict.label,
            "decision": verdict.decision,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "mode": verdict.mode,
        })

    print()
    print(f"Agreement with expert labels: {agree}/{n} = {agree / n:.0%}")
    print(f"Raw precision of the labelled set (share that are real): {gold_tp}/{n} = {gold_tp / n:.0%}")
    if kept_as_tp:
        print(
            f"Precision if you keep only the agent's true_positives: "
            f"{kept_and_really_tp}/{kept_as_tp} = {kept_and_really_tp / kept_as_tp:.0%}"
        )
    if uncertain:
        print(f"Agent abstained (uncertain) on {uncertain} findings")
    print("\nPer rule:")
    for rule, s in sorted(per_rule.items()):
        print(f"  {rule:<16} {s['agree']}/{s['n']} = {s['agree'] / s['n']:.0%} agreement")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"mode": banner, "results": results}, fh, indent=2)
        print(f"\nWrote per-finding results to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
