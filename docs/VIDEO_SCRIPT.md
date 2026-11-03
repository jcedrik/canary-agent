# 3-minute demo video script

Meta Global AI Developer Hackathon, Indie track. Keep it under 3 minutes. Show
only what was built during the hackathon (all of this was). Record each demo as
a clean take: run the command fresh, big terminal font (18-20pt), no scrolling.

**Before recording:** open two terminals in the repo, both with your key set
(`$env:MODEL_API_KEY="..."`). Terminal A for the agent demos, Terminal B for the
Muse Code server.

---

## 0:00 - 0:20 | Hook (Impact)

SAY: "AI agents now write a growing share of production code, and they introduce
exactly the failures classic tools miss: prompt injection, excessive agency,
leaked keys. I built LLM agents inside a large enterprise and did this hardening
by hand. canary-agent asks: who checks the code the AI writes? Another agent."

SHOW: your face or the title, then the Muse Image hero (`docs/threat_surface.png`).

## 0:20 - 0:35 | What it is + disclosure

SAY: "It runs on the Meta Model API. My open-source scanner canary, published
before the event, is the detection engine. The triage, the fix loop, the
Muse Code integration, the MCP audit - all built this week on muse-spark."

SHOW: the GitHub README top (hackathon line + hero image visible).

## 0:35 - 1:25 | Demo 1: the loop, live

SAY: "muse-spark reads each finding with its code, decides true or false
positive, rates its exploitability, writes a patch, and canary re-scans. The
patch is kept only if the scan is clean. The model proposes, the scanner
disposes."

SHOW (Terminal A): `python demo/run_demo.py examples/vulnerable_app`
Point out: the `<reaches_tool_or_shell>` / `<self_output_only>` exploitability
tags and the `[ASI-02 Tool Misuse]` OWASP Agentic mapping on each line, then
"5 findings, 5 confirmed, 5 auto-fixed and verified."

## 1:25 - 2:00 | Demo 2: scan-as-you-code with Muse Code

SAY: "Wired into Muse Code over MCP, Meta's own coding agent gets checked in
real time. It writes a tool that pipes model input to a shell, my server flags
it, and it rewrites before the file is ever saved."

SHOW (Terminal B running `python -m canary_agent.mcp_server --http`, then a
Muse Code session): paste the prompt that makes Muse Code write `run_command`,
call `scan_snippet`, get CANARY-EA-001, and fix it. (Use `muse --yolo` and "do
not run the file" for a clean, fast take.)

## 2:00 - 2:35 | It's measured (Technical depth)

SAY: "This isn't a vibe. Against 77 findings I reviewed by hand: 90% agreement,
95% precision. On the high-signal rules you gate a build on, 97% precision and
91% recall. It even caught false positives in my own benchmark, verified against
the source. And I ran it on real projects - autogen, crewAI, langflow - where it
surfaced real injection candidates."

SHOW: `eval/EVAL.md` (the headline table), and the real-targets table in the
README.

## 2:35 - 3:00 | Close

SAY: "muse-spark triage at 97% precision, fixes proven by re-scan, cross-file
context when a snippet is ambiguous, an MCP audit mapped to the OWASP Agentic
Top 10, and a Muse Image view of the attack surface. Built this week on Meta
Model API, muse-spark, and Muse Code. This is how you secure the code AI writes."

SHOW: the repo, the 5/5 summary.

---

## Optional 10-second beat (if you have room)

MCP config audit, offline and instant:
`python demo/audit_mcp.py examples/mcp_configs/insecure.json`
8 issues mapped to ASI categories. Good for the agentic-security angle.

## Honesty guardrails (keep these true)

- Say "97% precision on what it confirms," not "it finds everything" (recall 91%
  on high-signal; lower overall).
- The real-target numbers are raw candidate findings the agent triages, not
  confirmed vulnerabilities.
- The Muse Image picture is illustrative, generated with Muse Image, not a
  precise technical diagram.
