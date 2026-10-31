# Triage evaluation: muse-spark vs expert labels

**What this measures.** canary-agent's triage step reads each canary finding
with its surrounding code and answers two independent questions: is the
vulnerable data flow real (true/false positive), and what is its blast radius
(exploitability). This evaluates both against 77 findings hand-reviewed TP/FP
while building canary's benchmark (`labels.csv`), across 10 public
LLM-application repos. The model sees the real code window around each finding
(71/77); 6 fell back to the stored one-line snippet because the file had moved.

Model: `muse-spark-1.3`, temperature 0, prompt in `canary_agent/model_client.py`.
Reproduce: `python eval/run_eval.py --dataset eval/labeled_with_context.json`.

## Headline (live, muse-spark-1.3, 77 findings)

| Metric | Value |
|---|---:|
| Agreement with expert labels | **69/77 = 90%** |
| Precision (of what it confirms, how much is real) | **39/41 = 95%** |
| Recall (of real TPs, how many it caught) | 39/44 = 89% |
| F1 | **92%** |
| False confirmations (gold FP called TP) | 2 |

**High-signal rules only** (prompt injection, PII in logs — the rules you gate a
build on, excluding the GR-001 advisory): **precision 97%, recall 91%**, 88%
agreement.

| Rule | Agreement | Precision | Recall |
|---|---:|---:|---:|
| CANARY-PI-001 (prompt injection) | 91% | 100% | 90% |
| CANARY-PI-002 (prompt injection, JS/TS) | 100% | 100% | 100% |
| CANARY-PII-001 (PII in logs) | 100% | 100% | 100% |
| CANARY-GR-001 (advisory, ~24% precision) | 92% | 88% | 78% |
| CANARY-SEC-005 (generic key, n=2, weak) | 0% | 0% | — |

## Two axes, judged independently

Early versions merged "is it real" with "how bad is it," which made the agent
call low-impact-but-real injections false positives and crashed recall to 37%.
Separating the two fixed it:

- **decision** (true/false positive): is the vulnerable data flow genuinely
  present? A real finding with a small blast radius is still a true positive.
- **exploitability** (blast radius), rated separately:

| Class | Confirmed findings |
|---|---:|
| reaches_tool_or_shell | 5 |
| reaches_secret_or_exfil | 1 |
| self_output_only | 34 |
| not_applicable | 1 |

This is what a security reviewer actually wants: not just "is it a finding," but
"patch these 6 first — untrusted data reaches a tool or a secret."

### Presence rules vs absence-of-control rules

A second distinction mattered. Rules that flag the **presence** of a bad flow
(injection, excessive agency, leaked key, PII) are true positives when that flow
is real. The **absence-of-control** rule GR-001 ("LLM call with no visible
guardrail") is true only when the missing control plausibly matters — untrusted
or sensitive data is actually in play — because "no guardrail" is true of almost
every model call. Teaching the agent that difference raised GR-001 agreement
from 49% to 92% without touching the high-signal rules.

## Agentic context lookups

When a one-line snippet is not enough to tell whether a variable is
user-controlled, the agent fetches more context itself (`canary_agent/context_agent.py`):
it calls a `fetch_context` tool to find where a symbol is defined or who calls a
function, across files, then decides. On the multi-file demo it took 5 lookups
to trace `request.args.get("q")` in `web.py` into `summarize(q)` and confirm the
prompt-injection flow it could not have judged from `summarizer.py` alone.

## Verified label errors

The agent caught false positives in the benchmark's own first-pass labels.
Three were confirmed against the source:

| Finding | Rule | What the line actually is |
|---|---|---|
| `_toolset.py:703` | GR-001 | inside a docstring |
| `_capability.py:168` | GR-001 | a parameter default (`mode: Literal[...] = 'auto'`) |
| `_summarizing_compaction.py:718` | PI-001 | a static dataclass field + docstring |

## Honest limitations

- Labels are a single reviewer's first pass, marked "to confirm"; this eval
  found at least 3 that were wrong.
- Recall is 89%: a precision-first gate, not a complete reviewer.
- SEC-005 (generic `api_key`) is a weak rule the agent over-confirms; with n=2
  here it is noise, and canary already rates it low-value.
- 6/77 findings were judged from a one-line snippet, not the full file.

## Takeaway

On the high-signal rules you gate a build on, muse-spark triage runs at 97%
precision and 91% recall, ranks confirmed issues by real exploitability, fetches
cross-file context when a snippet is ambiguous, and caught false positives in
the benchmark's own labels. It is conservative by design, so the fix-and-verify
loop only patches a confirmed issue.
