"""Tests for the ASI-08 agentic detector (offline, no key)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.agentic_rules import scan_source, scan_path

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_uncapped_executor_is_flagged():
    src = "from langchain.agents import AgentExecutor\nex = AgentExecutor(agent=a, tools=t)\n"
    f = scan_source(src, "x.py")
    assert len(f) == 1 and f[0]["rule_id"] == "CANARY-ASI8-001"
    assert f[0]["owasp_agentic"].startswith("ASI-08")


def test_capped_executor_is_clean():
    src = "ex = AgentExecutor(agent=a, tools=t, max_iterations=6)\n"
    assert scan_source(src, "x.py") == []


def test_initialize_agent_also_checked():
    src = "ex = initialize_agent(tools, llm)\n"
    assert any(f["rule_id"] == "CANARY-ASI8-001" for f in scan_source(src, "x.py"))


def test_scan_path_returns_list():
    # the example app has no agent executor, so this is clean
    assert scan_path(os.path.join(HERE, "examples", "multifile_app")) == []


def test_bad_syntax_does_not_crash():
    assert scan_source("def (:\n", "x.py") == []


def test_eval_on_dynamic_input_flagged_asi5():
    f = scan_source("eval(user_code)\n", "x.py")
    assert f and f[0]["rule_id"] == "CANARY-ASI5-001"


def test_eval_on_literal_not_flagged():
    assert scan_source("eval('1+1')\n", "x.py") == []


def test_vector_store_write_flagged_asi6():
    f = scan_source("store.add_texts(docs)\n", "x.py")
    assert f and f[0]["rule_id"] == "CANARY-ASI6-001"


def test_literal_list_to_store_not_flagged():
    assert scan_source('store.add_texts(["a", "b"])\n', "x.py") == []
