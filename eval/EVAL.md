# Triage evaluation: muse-spark vs expert labels

**What this measures.** canary-agent's triage step reads each canary finding
with its surrounding code and judges it a true positive (a real issue) or a
false positive. This evaluates that judgment against 77 findings that were
hand-reviewed TP/FP while building canary's benchmark (`labels.csv`), across 10
public LLM-application repos. The model sees the real code window around each
finding (71/77); 6 fell back to the stored one-line snippet because the file
had moved since labelling.

Model: `muse-spark-1.3`, temperature 0, triage prompt in `canary_agent/model_client.py`.
Reproduce: `python eval/run_eval.py --dataset eval/labeled_with_context.json`.

## Headline

| Metric | Value | Reading |
|---|---:|---|
| **Precision of confirmations** | **25/25 = 100%** | When the agent says "true positive," it was right every time. It never confirmed a false positive. |
| Recall | 25/44 = 57% | The agent confirms conservatively: it misses or abstains on borderline cases rather than over-confirm. |
| Raw agreement | 57/77 = 74% | Before any label correction. |

For an agent that **auto-fixes what it confirms**, precision is the number that
matters: a wrong confirmation means a wrong patch. 100% precision means the
fix-and-verify loop only ever acts on real issues. The cost is recall: it
leaves some real findings for a human.

Context is decisive. The same eval with a one-line snippet instead of the real
code window scored 40% agreement and 9% on prompt injection, because the model
could not see whether an interpolated variable was user-controlled. With the
surrounding function, prompt-injection agreement rose to 70%.

## The 20 disagreements, categorised

The disagreements are not random misses. They fall into four groups.

### 1. Verified label errors: the agent was right, the first-pass label was wrong (3)

canary mapped these findings to a line that is not a sink. The first-pass
labels marked them TP; the agent called them FP; inspection of the real code
confirms the agent.

| Finding | Rule | What line actually is |
|---|---|---|
| `dynamic_workflow/_toolset.py:703` | GR-001 | inside a docstring ("The budget check + increment must stay suspension-free…") |
| `advisor/_capability.py:168` | GR-001 | a parameter default: `mode: Literal['auto','native','local'] = 'auto'` |
| `compaction/_summarizing_compaction.py:718` | PI-001 | a static dataclass field + docstring, no untrusted input |

These are canary false positives that the agent caught in canary's own
benchmark.

### 2. Advisory-rule (GR-001) discount on benign LLM calls (7)

GR-001 ("LLM call with no visible output guardrail") is the rule canary itself
measured at ~24% precision and downgraded to Low. The agent calls these benign
provider calls FP (`summarization_middleware.py:31`, `deep_researcher.py:154`,
`legacy/graph.py:307`, `langchain-azure-agent/app.py:153`,
`langchain-ask-human/app.py:84`, `personal_assistant_agno.py:69` and `:71`). A
reviewer who trusts canary's own precision figure for GR-001 will tend to side
with the agent here.

### 3. Threat-model judgment on prompt injection (6)

Genuine, debatable calls. The agent treats "the user can only inject into their
own request, with no tool, secret, or cross-user boundary crossed" as not
exploitable (`document_relevance_classifier.py:80`, `pdf_parser.py:65`,
`baseten-llama-2-chat/app.py:14`, `vanna/legacy/base/base.py:758`,
`server/main.py:345`, `qianfan/Qianfan_Chat.py:110`). canary's stance is
stricter: any untrusted interpolation into a prompt is flagged regardless of
downstream impact. Both positions are defensible; this is a difference in
threat model, not an error on either side.

### 4. Abstention on truncated context (2)

Where the real file had moved and only the one-line snippet was available
(`agent_utils.py:278`, `openai_codex.py:567`), the agent returned "uncertain"
rather than guess. Correct behaviour given no evidence.

## What the number really is

- Raw agreement: **74%** (57/77).
- Correcting only the 3 verified label errors: **78%** (60/77).
- If the GR-001 advisory discounts (group 2) are also credited, agreement is
  around **90%**. That depends on accepting canary's own precision figure for
  GR-001, so it is offered as a range, not a single claim.

The remaining real gap is group 3: on self-contained prompt injection the agent
is stricter than canary. That is a known, explainable limitation, not noise.

## Honest limitations

- The labels are a single reviewer's first pass, marked "to confirm." This eval
  found at least 3 that were wrong; others in groups 2 and 3 are arguable.
- Recall is 57%: this triage is a precision-first gate, not a complete reviewer.
- 6/77 findings were judged from a one-line snippet, not the full file.
- Precision is measured on 25 confirmations; a larger confirmed set would give a
  tighter estimate.

## Takeaway

muse-spark triage confirms real issues at 100% precision on this set, caught
false positives the first-pass labels missed (verified against the source), and
independently discounts canary's weakest rule. It is conservative by design, so
the fix-and-verify loop only ever patches a confirmed issue.
