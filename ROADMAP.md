# Roadmap

canary-agent is a working, measured defensive agent. This is the honest path
from here to a production-grade tool, roughly in priority order. The hackathon
build is the foundation; these are the next milestones.

## 1. Cross-function / cross-file taint tracking

The single biggest step from prototype to real SAST. Today the triage agent
*fetches* the calling context when a snippet is ambiguous (see
`canary_agent/context_agent.py`), which is a lightweight, model-driven version.
A deterministic dataflow engine would track untrusted sources (`request.*`,
`input()`, tool parameters) through assignments and calls to sinks (prompts,
`subprocess`, raw SQL, file writes), and emit the full taint path as evidence.
This also lets findings be proven, not just judged.

## 2. Cover the full OWASP Top 10 for Agentic Applications (2026)

Today's rules map cleanly to ASI-01 (goal hijack), ASI-02 (tool misuse), ASI-03
(identity), ASI-04 (supply chain, via the MCP audit) and ASI-08 (cascading, the
unbounded-loop detector). The remaining categories are detectors still to write:

- ASI-05 Code Execution: `eval`/`exec` on model-derived input outside a sandbox
- ASI-06 Memory Poisoning: unsanitized input written to a vector store
- ASI-07 Inter-Agent Communication: agent-to-agent traffic without TLS/auth
- ASI-09 Trust Exploitation: missing human-in-the-loop on high-impact actions
- ASI-10 Rogue Agents: no kill switch or behavior monitoring

ASI-09 and ASI-10 are judgment-heavy and prone to false positives; they need
the triage agent to stay precise, not just more pattern rules.

## 3. Deeper MCP auditing

The config audit (`canary_agent/mcp_audit.py`) is static. Next: a read-only live
inspection of a declared MCP server (list tools without calling them), and
baseline-drift detection so a server that changes its tool descriptions after
approval (the "rug-pull") is caught.

## 4. A track record on real targets

Run the agent on real, in-scope bug-bounty and open-source targets, triage the
findings, manually confirm the true positives, and report them responsibly
through coordinated disclosure. Confirmed, credited findings are what separate a
benchmark from a trusted tool. This is a process, done carefully, not a sprint.

## 5. A larger, multi-reviewer evaluation

Grow the labelled set from 77 to several hundred findings across more repos,
with more than one reviewer, and establish recall ground truth. The harness
(`eval/run_eval.py`) already reports precision, recall, F1 and a confusion
matrix per rule; it needs more labelled data to tighten the estimates.

## Non-goals

canary-agent is defensive. It reads code, triages, fixes, and proves fixes by
re-scanning. It is not an offensive or exploitation tool and will not generate
working attacks.
