"""Runtime configuration, read from the environment so no secret ever lands
in the code or the repo.

    MODEL_API_KEY      your Meta Model API key (never hardcode it)
    CANARY_AGENT_MODEL model id, default muse-spark-1.3
    CANARY_AGENT_MOCK  set to 1 to force offline mock mode

If MODEL_API_KEY is absent, the agent runs in mock mode automatically, so you
can build and test the whole pipeline before your hackathon credits land.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

BASE_URL = "https://api.meta.ai/v1"


@dataclass
class Config:
    api_key: str
    model: str
    base_url: str
    mock: bool

    @classmethod
    def from_env(cls) -> "Config":
        key = os.environ.get("MODEL_API_KEY", "").strip()
        forced_mock = os.environ.get("CANARY_AGENT_MOCK", "").strip() in ("1", "true", "yes")
        return cls(
            api_key=key,
            model=os.environ.get("CANARY_AGENT_MODEL", "muse-spark-1.3").strip(),
            base_url=os.environ.get("CANARY_AGENT_BASE_URL", BASE_URL).strip(),
            mock=forced_mock or not key,
        )
