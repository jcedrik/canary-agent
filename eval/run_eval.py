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
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.schema import Finding, Verdict
from canary_agent.triage import triage_finding
from canary_agent.model_client import ModelClient
from canary_agent.owasp import agentic_label

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


def _metrics(items):
    """items: list of (gold, pred) with pred in {TP, FP, ?}. Treats the agent's
    "true_positive" as the positive class: precision = of what it confirms,
    how much is really a TP; recall = of real TPs, how many it confirmed."""
    tp_conf = sum(1 for g, p in items if g == "TP" and p == "TP")
    fp_conf = sum(1 for g, p in items if g == "FP" and p == "TP")
    gold_tp = sum(1 for g, _ in items if g == "TP")
    pred_tp = tp_conf + fp_conf
    agree = sum(1 for g, p in items if g == p)
    prec = tp_conf / pred_tp if pred_tp else None
    rec = tp_conf / gold_tp if gold_tp else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else None
    return dict(n=len(items), agree=agree, tp_conf=tp_conf, fp_conf=fp_conf,
                pred_tp=pred_tp, gold_tp=gold_tp, precision=prec, recall=rec, f1=f1)


def _pct(x):
    return f"{x:.0%}" if x is not None else "n/a"


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
    all_items, hi_items, gr_items = [], [], []
    per_rule = defaultdict(list)
    uncertain = 0
    expl_counts = Counter()  # exploitability of findings the agent confirmed
    for r, finding, verdict in pairs:
        gold, pred = r["label"], verdict.label
        all_items.append((gold, pred))
        (gr_items if finding.rule_id == "CANARY-GR-001" else hi_items).append((gold, pred))
        per_rule[finding.rule_id].append((gold, pred))
        if verdict.decision == "true_positive":
            expl_counts[verdict.exploitability] += 1
        elif verdict.decision == "uncertain":
            uncertain += 1
        results.append({
            "rule_id": finding.rule_id, "file": finding.file, "line": finding.line,
            "gold": gold, "agent": pred, "decision": verdict.decision,
            "confidence": verdict.confidence, "exploitability": verdict.exploitability,
            "owasp_agentic": agentic_label(finding.rule_id),
            "reason": verdict.reason, "mode": verdict.mode,
        })

    m = _metrics(all_items)
    print()
    print(f"Overall ({n} findings)")
    print(f"  agreement : {m['agree']}/{n} = {_pct(m['agree'] / n)}")
    print(f"  precision : {m['tp_conf']}/{m['pred_tp']} = {_pct(m['precision'])}  (of what the agent confirms, how much is really a TP)")
    print(f"  recall    : {m['tp_conf']}/{m['gold_tp']} = {_pct(m['recall'])}  (of real TPs, how many it confirmed)")
    print(f"  F1        : {_pct(m['f1'])}")
    print(f"  false confirmations (gold FP called TP): {m['fp_conf']}")
    if uncertain:
        print(f"  abstained (uncertain): {uncertain}")

    if hi_items and gr_items:
        mh, mg = _metrics(hi_items), _metrics(gr_items)
        print(f"\nHigh-signal rules only (excludes GR-001 advisory):")
        print(f"  agreement {mh['agree']}/{mh['n']} = {_pct(mh['agree'] / mh['n'])}  |  "
              f"precision {_pct(mh['precision'])}  |  recall {_pct(mh['recall'])}")
        print(f"GR-001 advisory alone (canary rates this rule ~24% precision):")
        print(f"  agreement {mg['agree']}/{mg['n']} = {_pct(mg['agree'] / mg['n'])}")

    print("\nPer rule (agreement | precision | recall):")
    for rule, items in sorted(per_rule.items()):
        mr = _metrics(items)
        print(f"  {rule:<16} {mr['agree']}/{mr['n']}={_pct(mr['agree'] / mr['n']):>4} | "
              f"P {_pct(mr['precision']):>4} | R {_pct(mr['recall']):>4}")

    if expl_counts:
        print("\nConfirmed issues by exploitability (worst first):")
        for k in Verdict.RISK_ORDER:
            if expl_counts.get(k):
                print(f"  {k:<24} {expl_counts[k]}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"mode": banner, "metrics": m, "results": results}, fh, indent=2)
        print(f"\nWrote per-finding results to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
