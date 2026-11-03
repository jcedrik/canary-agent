"""Tests for the deterministic intra-procedural taint engine."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.taint import scan_source


def _rules(src):
    return [f["rule_id"] for f in scan_source(src, "t.py")]


def test_exec_from_input():
    src = "def r():\n    cmd = input('x')\n    eval(cmd)\n"
    assert "CANARY-TAINT-EXEC" in _rules(src)


def test_shell_from_request_concat():
    src = ("import subprocess\n"
           "def h():\n"
           "    name = request.args.get('name')\n"
           "    full = 'echo ' + name\n"
           "    subprocess.run(full, shell=True)\n")
    assert "CANARY-TAINT-SHELL" in _rules(src)


def test_prompt_var_from_tool_param():
    src = ("@tool\n"
           "def search(query):\n"
           "    prompt = f'Search for: {query}'\n"
           "    return prompt\n")
    assert "CANARY-TAINT-PROMPT" in _rules(src)


def test_llm_call_from_request():
    src = ("def chat():\n"
           "    q = request.get_json()['q']\n"
           "    openai.chat.completions.create(messages=[{'content': q}])\n")
    assert "CANARY-TAINT-PROMPT" in _rules(src)


def test_sql_from_argv():
    src = ("import sys\n"
           "def q():\n"
           "    uid = sys.argv[1]\n"
           "    cursor.execute('SELECT * FROM u WHERE id=' + uid)\n")
    assert "CANARY-TAINT-SQL" in _rules(src)


def test_static_values_not_flagged():
    src = ("def ok():\n"
           "    prompt = 'static system prompt'\n"
           "    eval('1+1')\n"
           "    subprocess.run(['ls', '-l'])\n")
    assert _rules(src) == []


def test_indirect_multi_hop_chain():
    src = ("def r():\n"
           "    a = input()\n"
           "    b = a\n"
           "    c = b.strip()\n"
           "    exec(c)\n")
    assert "CANARY-TAINT-EXEC" in _rules(src)


def test_source_line_recorded():
    src = "def r():\n    cmd = input('x')\n    eval(cmd)\n"
    f = scan_source(src, "t.py")[0]
    assert f["source_line"] == 2 and f["line"] == 3


def test_syntax_error_returns_empty():
    assert scan_source("def (:\n", "t.py") == []
