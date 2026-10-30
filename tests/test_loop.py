"""Loop test: needs canary installed (pip install canary-sast). Skipped if the
canary CLI is not on PATH, so the offline triage tests still run anywhere."""

import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.fixers import Fixer
from canary_agent.loop import fix_and_verify

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "examples", "vulnerable_app", "app.py")

needs_canary = pytest.mark.skipif(
    shutil.which("canary") is None or not os.path.isfile(EXAMPLE),
    reason="canary CLI or example app not available",
)


def _mock_config():
    return Config(api_key="", model="muse-spark-1.3", base_url="x", mock=True)


@needs_canary
def test_secret_fix_is_verified_by_rescan():
    cfg = _mock_config()
    res = fix_and_verify(EXAMPLE, "CANARY-SEC-001", 15, Fixer(cfg), cfg)
    assert res.patched and res.verified and not res.regression


@needs_canary
def test_unfixable_rule_reports_no_patch():
    cfg = _mock_config()
    res = fix_and_verify(EXAMPLE, "CANARY-EA-001", 53, Fixer(cfg), cfg)
    assert not res.patched and not res.verified
