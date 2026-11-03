"""Benchmark canary-agent across real-world projects (no ground-truth labels).

Takes a dataset of findings scanned from popular LLM/agent repos (each with its
code context baked in) and runs the full triage agent over them, then reports
aggregate results: how many findings the agent confirms, their exploitability
distribution, and the highest-risk confirmed findings per project.

These are candidate findings triaged by the agent, not confirmed, disclosed
vulnerabilities. It is a research benchmark of the triage, not a security
advisory about any project.

    MODEL_API_KEY=... python eval/run_wild.py --dataset eval/wild_findings.json \
        --out eval/wild_results.json --md eval/WILD.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.model_client import ModelClient
from canary_agent.owasp import agentic_label
from canary_agent.schema import Finding
from canary_agent.triage import triage_finding

HIGH = {"CANARY-PI-001", "CANARY-PI-002", "CANARY-EA-001", "CANARY-EA-002",
        "CANARY-SEC-001", "CANARY-SEC-002", "CANARY-SEC-003", "CANARY-SEC-004",
        "CANARY-SEC-005", "CANARY-PII-001"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="eval/wild_findings.json")
    ap.add_argument("--out", default="eval/wild_results.json")
    ap.add_argument("--md", default="eval/WILD.md")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=10)
    args = ap.parse_args()

    config = Config.from_env()
    client = ModelClient(config)
    recs = json.load(open(args.dataset, encoding="utf-8"))
    if args.limit:
        recs = recs[:args.limit]
    n = len(recs)
    mode = "MOCK (not real)" if config.mock else config.model
    print(f"=== canary-agent wild benchmark | {mode} | {n} findings ===\n")

    def work(r):
        f = Finding(rule_id=r["rule_id"], severity=r.get("severity", ""),
                    file=r.get("file", ""), line=int(r.get("line", 0) or 0),
                    snippet=r.get("snippet", ""), owasp=r.get("owasp", ""))
        return r, triage_finding(f, client, r.get("code_context"))

    results = []
    done = 0
    workers = 1 if config.mock else max(1, args.workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(work, r) for r in recs]
        for fut in as_completed(futs):
            r, v = fut.result()
            results.append({**{k: r[k] for k in ("repo", "rule_id", "file", "line")},
                            "decision": v.decision, "exploitability": v.exploitability,
                            "owasp_agentic": agentic_label(r["rule_id"]), "reason": v.reason})
            done += 1
            if done % 25 == 0 or done == n:
                print(f"  triaged {done}/{n}")

    confirmed = [x for x in results if x["decision"] == "true_positive"]
    fp = [x for x in results if x["decision"] == "false_positive"]
    unc = [x for x in results if x["decision"] == "uncertain"]
    repos = sorted({x["repo"] for x in results})
    expl = Counter(x["exploitability"] for x in confirmed)
    by_rule = defaultdict(lambda: [0, 0])  # rule -> [confirmed, total]
    for x in results:
        by_rule[x["rule_id"]][1] += 1
        if x["decision"] == "true_positive":
            by_rule[x["rule_id"]][0] += 1
    per_repo = Counter(x["repo"] for x in confirmed)

    # highest-risk: confirmed and reaching a tool/shell or secret
    risk_order = {"reaches_secret_or_exfil": 0, "reaches_tool_or_shell": 1}
    top = sorted([x for x in confirmed if x["exploitability"] in risk_order],
                 key=lambda x: risk_order[x["exploitability"]])[:20]

    print(f"\nrepos: {len(repos)} | findings: {n}")
    print(f"confirmed (true positive): {len(confirmed)} = {len(confirmed)/n:.0%}")
    print(f"false positive: {len(fp)} | uncertain: {len(unc)}")
    print("exploitability of confirmed:", dict(expl))

    json.dump({"model": mode, "n": n, "confirmed": len(confirmed),
               "results": results}, open(args.out, "w"), indent=1)
    print(f"\nwrote {args.out}")

    if args.md and not config.mock:
        _write_md(args.md, mode, n, repos, confirmed, fp, unc, expl, by_rule, per_repo, top)
        print(f"wrote {args.md}")
    return 0


def _write_md(path, mode, n, repos, confirmed, fp, unc, expl, by_rule, per_repo, top):
    L = []
    L.append("# Wild benchmark: canary-agent across real projects\n")
    L.append(f"The triage agent (`{mode}`) run over **{n} findings** scanned from "
             f"**{len(repos)} popular open-source LLM/agent projects**. These are "
             "candidate findings the agent triaged, not confirmed or disclosed "
             "vulnerabilities - a benchmark of the triage, not a security advisory.\n")
    L.append("## Results\n")
    L.append("| | count | share |")
    L.append("|---|---:|---:|")
    L.append(f"| Confirmed (true positive) | {len(confirmed)} | {len(confirmed)/n:.0%} |")
    L.append(f"| False positive | {len(fp)} | {len(fp)/n:.0%} |")
    L.append(f"| Uncertain | {len(unc)} | {len(unc)/n:.0%} |")
    L.append("\n## Exploitability of confirmed findings\n")
    L.append("| class | count |")
    L.append("|---|---:|")
    for k in ("reaches_secret_or_exfil", "reaches_tool_or_shell", "self_output_only",
              "not_applicable", "unknown"):
        if expl.get(k):
            L.append(f"| {k} | {expl[k]} |")
    L.append("\n## Confirmed by rule\n")
    L.append("| rule | confirmed / total |")
    L.append("|---|---:|")
    for rule in sorted(by_rule):
        c, t = by_rule[rule]
        L.append(f"| {rule} | {c} / {t} |")
    L.append("\n## Projects scanned\n")
    L.append(", ".join(repos) + "\n")
    L.append("## Highest-risk confirmed findings (reach a tool/shell or a secret)\n")
    L.append("| project | file:line | rule | exploitability |")
    L.append("|---|---|---|---|")
    for x in top:
        L.append(f"| {x['repo']} | `{x['file']}:{x['line']}` | {x['rule_id']} | {x['exploitability']} |")
    L.append("\n_Raw candidate findings triaged by the agent. Report responsibly; "
             "confirm before acting._\n")
    open(path, "w", encoding="utf-8").write("\n".join(L))


if __name__ == "__main__":
    raise SystemExit(main())
