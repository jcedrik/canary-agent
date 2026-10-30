"""canary-agent: an AI triage-and-fix layer over the canary LLM security scanner.

Built for the Meta Global AI Developer Hackathon (Oct 27 - Nov 4, 2026).
The detection engine is canary (github.com/jcedrik/canary), published before
the event; everything in this package is the new hackathon work."""

__version__ = "0.1.0"

from .config import Config
from .schema import Finding, Verdict
from .triage import triage_finding, make_client

__all__ = ["Config", "Finding", "Verdict", "triage_finding", "make_client"]
