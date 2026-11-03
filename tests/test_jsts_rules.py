"""Tests for the JS/TS AST detector. Skipped if tree-sitter is not installed."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("tree_sitter_language_pack")

from canary_agent.jsts_rules import scan_source


def test_untrusted_in_prompt_var_flagged():
    f = scan_source("const prompt = `Answer: ${req.query.q}`;\n", "a.ts")
    assert f and f[0]["rule_id"] == "CANARY-JSTS-001"


def test_untrusted_in_llm_call_flagged():
    src = 'openai.chat.completions.create({messages:[{content:`Q: ${body.q}`}]});\n'
    assert any(x["rule_id"] == "CANARY-JSTS-001" for x in scan_source(src, "a.ts"))


def test_static_template_not_flagged():
    assert scan_source("const sys = `plain static text`;\n", "a.ts") == []


def test_non_prompt_greeting_not_flagged():
    assert scan_source("const greeting = `Hi ${req.body.name}`;\n", "a.ts") == []


def test_non_js_file_skipped():
    assert scan_source("const prompt = `${req.q}`;\n", "a.py") == []
