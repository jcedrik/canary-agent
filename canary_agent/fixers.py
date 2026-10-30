"""Patch generation.

Real mode asks Muse Spark for a corrected version of the file. Mock mode
applies small, documented, rule-specific transforms so the fix-and-verify loop
can be built and demonstrated offline. Whichever produces the patch, the loop
only keeps it if canary confirms the finding is gone, so a bad patch is caught
by the verifier, not trusted.

A fixer takes (rule_id, file_text) and returns new file_text (or None if it has
no fix to offer)."""

from __future__ import annotations

import re
from typing import Optional

from .config import Config


# --- mock transforms: minimal, correct, enough to clear the scan ---

def _fix_hardcoded_secret(text: str) -> Optional[str]:
    # openai.api_key = "sk-..."  ->  read from the environment
    new, n = re.subn(
        r'(\w[\w.]*\.api_key\s*=\s*)"[^"]+"',
        r'\1os.environ["OPENAI_API_KEY"]',
        text,
    )
    if n and "import os" not in new:
        new = "import os\n" + new
    return new if n else None


def _fix_prompt_injection(text: str) -> Optional[str]:
    # system prompt with user input interpolated -> constant system prompt.
    # (The user text belongs in a user-role message, not the system prompt.)
    new, n = re.subn(
        r'(system_prompt\s*=\s*)f"[^"]*\{[^"]*\}[^"]*"',
        r'\1"You are a helpful assistant."  # user text moved to a user-role message',
        text,
    )
    return new if n else None


def _fix_pii_logging(text: str) -> Optional[str]:
    # logger.info("... user_input ... response ...", user_input, answer) -> neutral log
    new, n = re.subn(
        r'logger\.(info|debug|warning|error)\([^\n]*\)',
        r'logger.\1("request handled")',
        text,
    )
    return new if n else None


_MOCK_FIXERS = {
    "CANARY-SEC-001": _fix_hardcoded_secret,
    "CANARY-SEC-005": _fix_hardcoded_secret,
    "CANARY-PI-001": _fix_prompt_injection,
    "CANARY-PII-001": _fix_pii_logging,
}


class Fixer:
    def __init__(self, config: Config):
        self.config = config
        self._client = None

    def fix(self, rule_id: str, file_text: str) -> Optional[str]:
        if self.config.mock:
            fn = _MOCK_FIXERS.get(rule_id)
            return fn(file_text) if fn else None
        return self._model_fix(rule_id, file_text)

    def _model_fix(self, rule_id: str, file_text: str) -> Optional[str]:
        from openai import OpenAI

        if self._client is None:
            self._client = OpenAI(api_key=self.config.api_key, base_url=self.config.base_url)
        prompt = (
            f"The static scanner canary flagged rule {rule_id} in this file. "
            "Return the COMPLETE corrected file that removes the vulnerability "
            "while preserving behaviour. Output only the file content, no fences.\n\n"
            + file_text
        )
        resp = self._client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        out = (resp.choices[0].message.content or "").strip()
        if out.startswith("```"):
            out = out.split("\n", 1)[1].rsplit("```", 1)[0]
        return out or None
