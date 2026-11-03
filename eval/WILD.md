# Wild benchmark: canary-agent across real projects

The triage agent (`muse-spark-1.3`) run over **119 findings** scanned from **10 popular open-source LLM/agent projects**. These are candidate findings the agent triaged, not confirmed or disclosed vulnerabilities - a benchmark of the triage, not a security advisory.

## Results

| | count | share |
|---|---:|---:|
| Confirmed (true positive) | 37 | 31% |
| False positive | 82 | 69% |
| Uncertain | 0 | 0% |

## Exploitability of confirmed findings

| class | count |
|---|---:|
| reaches_tool_or_shell | 14 |
| self_output_only | 19 |
| not_applicable | 4 |

## Confirmed by rule

| rule | confirmed / total |
|---|---:|
| CANARY-GR-001 | 7 / 52 |
| CANARY-PI-001 | 22 / 32 |
| CANARY-PI-002 | 1 / 9 |
| CANARY-PII-001 | 3 / 11 |
| CANARY-SEC-005 | 4 / 15 |

## Projects scanned

chainlit/chainlit, crewAIInc/crewAI, deepset-ai/haystack, geekan/MetaGPT, langchain-ai/langchainjs, microsoft/autogen, microsoft/semantic-kernel, openai/swarm, reworkd/AgentGPT, stanford-oval/storm

## Highest-risk confirmed findings (reach a tool/shell or a secret)

| project | file:line | rule | exploitability |
|---|---|---|---|
| microsoft/autogen | `python/packages/autogen-agentchat/src/autogen_agentchat/agents/_code_executor_agent.py:634` | CANARY-PI-001 | reaches_tool_or_shell |
| microsoft/autogen | `python/packages/agbench/benchmarks/GAIA/Templates/SelectorGroupChat/scenario.py:66` | CANARY-PI-001 | reaches_tool_or_shell |
| microsoft/autogen | `python/packages/agbench/benchmarks/GAIA/Templates/MagenticOne/scenario.py:81` | CANARY-PI-001 | reaches_tool_or_shell |
| crewAIInc/crewAI | `lib/crewai/src/crewai/a2a/wrapper.py:730` | CANARY-PI-001 | reaches_tool_or_shell |
| microsoft/autogen | `python/samples/gitty/src/gitty/_gitty.py:127` | CANARY-PI-001 | reaches_tool_or_shell |
| crewAIInc/crewAI | `lib/crewai-tools/src/crewai_tools/aws/bedrock/agents/invoke_agent_tool.py:111` | CANARY-PI-001 | reaches_tool_or_shell |
| geekan/MetaGPT | `metagpt/actions/write_code_review.py:160` | CANARY-PI-001 | reaches_tool_or_shell |
| geekan/MetaGPT | `examples/di/email_summary.py:21` | CANARY-PI-001 | reaches_tool_or_shell |
| langchain-ai/langchainjs | `libs/langchain-mcp-adapters/examples/filesystem_langgraph_example.ts:130` | CANARY-GR-001 | reaches_tool_or_shell |
| langchain-ai/langchainjs | `libs/langchain-mcp-adapters/examples/langgraph_example.ts:102` | CANARY-GR-001 | reaches_tool_or_shell |
| langchain-ai/langchainjs | `libs/langchain-mcp-adapters/examples/calculator_sse_shttp_example.ts:109` | CANARY-GR-001 | reaches_tool_or_shell |
| langchain-ai/langchainjs | `libs/langchain-classic/src/experimental/autogpt/prompt.ts:71` | CANARY-PI-002 | reaches_tool_or_shell |
| microsoft/semantic-kernel | `python/semantic_kernel/agents/open_ai/responses_agent_thread_actions.py:609` | CANARY-GR-001 | reaches_tool_or_shell |
| microsoft/semantic-kernel | `python/samples/concepts/processes/plan_and_execute.py:97` | CANARY-PI-001 | reaches_tool_or_shell |

_Raw candidate findings triaged by the agent. Report responsibly; confirm before acting._
