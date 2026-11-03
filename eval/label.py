"""Expert labeling tool: turn candidate findings into a confirmed eval set.

The point of this tool is honesty about provenance. The agent (and a first
assistant pass) can *propose* labels, but an eval is only credible if a human
expert confirms them. This tool shows each candidate with its code context and
records YOUR verdict, writing a separate file whose every row is marked
`provenance=expert`. Nothing here fabricates a label; it only captures yours.

    # review candidates, write confirmed labels
    python eval/label.py --out eval/labels_expert.csv

    # pull from the wild candidate pool instead of labels.csv
    python eval/label.py --source eval/wild_findings.json --out eval/labels_expert.csv

Keys per finding:  t = true positive   f = false positive
                   u = uncertain/needs more   s = skip for now   q = save & quit

It is resumable: a candidate already in --out (same rule+file+line) is not shown
again. Run it over several sittings; the file grows and run_eval.py can target
it directly:

    python eval/run_eval.py --labels eval/labels_expert.csv
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import sys

FIELDS = ["repo", "rule_id", "severity", "file", "line", "snippet",
          "label", "note", "provenance", "labeled_by", "labeled_at"]
_CTX = ("code_context", "context", "window")


def _key(r):
    return (r.get("rule_id", ""), os.path.basename(r.get("file", "")), str(r.get("line", "")))


def _load_candidates(source: str):
    if source.endswith(".json"):
        recs = json.load(open(source, encoding="utf-8"))
        out = []
        for r in recs:
            out.append({
                "repo": r.get("repo", ""), "rule_id": r.get("rule_id", ""),
                "severity": r.get("severity", ""), "file": r.get("file", ""),
                "line": r.get("line", ""), "snippet": r.get("snippet", ""),
                "note": (r.get("note") or r.get("gold") or ""),
                "_context": next((r[k] for k in _CTX if r.get(k)), ""),
            })
        return out
    with open(source, newline="", encoding="utf-8") as fh:
        return [{**r, "_context": ""} for r in csv.DictReader(fh)]


def _load_done(out_path: str):
    done = {}
    if os.path.exists(out_path):
        with open(out_path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                done[_key(r)] = r
    return done


def _append(out_path: str, row: dict):
    new = not os.path.exists(out_path)
    with open(out_path, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in FIELDS})


_VERDICT = {"t": "TP", "f": "FP", "u": "uncertain"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Confirm candidate findings into an expert-labeled set.")
    ap.add_argument("--source", default=os.path.join(os.path.dirname(__file__), "labels.csv"),
                    help="candidate findings: a labels CSV or a *_findings.json pool")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "labels_expert.csv"))
    ap.add_argument("--labeled-by", default=os.environ.get("USER", "expert"))
    ap.add_argument("--rule", default="", help="only review this rule id")
    ap.add_argument("--context-lines", type=int, default=6)
    args = ap.parse_args()

    cands = _load_candidates(args.source)
    if args.rule:
        cands = [c for c in cands if c.get("rule_id") == args.rule]
    done = _load_done(args.out)
    todo = [c for c in cands if _key(c) not in done]

    print(f"candidates: {len(cands)} | already confirmed: {len(done)} | to review: {len(todo)}")
    if not todo:
        print("Nothing left to review. Expert set is at", args.out)
        return 0
    if not sys.stdin.isatty():
        print("Not a TTY - run this in an interactive terminal to label.", file=sys.stderr)
        return 2

    labeled = 0
    for i, c in enumerate(todo, 1):
        print("\n" + "=" * 72)
        print(f"[{i}/{len(todo)}]  {c.get('rule_id')}  ({c.get('severity')})   {c.get('repo','')}")
        print(f"  {c.get('file')}:{c.get('line')}")
        ctx = c.get("_context") or ""
        if ctx:
            for ln in ctx.splitlines()[: args.context_lines * 2]:
                print(f"    | {ln}")
        else:
            print(f"    > {c.get('snippet','').strip()}")
        if c.get("note"):
            print(f"  prior note (NOT a confirmed label): {c['note']}")
        print("  [t]rue  [f]alse  [u]ncertain  [s]kip  [q]uit")

        ans = ""
        while ans not in ("t", "f", "u", "s", "q"):
            ans = input("  verdict> ").strip().lower()
        if ans == "q":
            break
        if ans == "s":
            continue
        note = input("  note (optional)> ").strip()
        _append(args.out, {
            "repo": c.get("repo", ""), "rule_id": c.get("rule_id", ""),
            "severity": c.get("severity", ""), "file": c.get("file", ""),
            "line": c.get("line", ""), "snippet": c.get("snippet", ""),
            "label": _VERDICT[ans], "note": note, "provenance": "expert",
            "labeled_by": args.labeled_by,
            "labeled_at": datetime.date.today().isoformat(),
        })
        labeled += 1

    print(f"\nSaved {labeled} expert label(s) to {args.out}")
    print("Evaluate against them with:")
    print(f"  python eval/run_eval.py --labels {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
