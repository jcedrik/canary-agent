"""C: generate a stylized 'attack surface' image with Muse Image.

Scans a target app, turns its findings into an image brief, and renders a
decorative attack-surface illustration with muse-image-1.0 (Meta Model API).
This is a creative/visual piece for the README or demo, not a precise diagram:
a text-to-image model cannot render accurate labels, so the picture is
illustrative only. The accurate diagram is Mermaid (see threat_model, C-a).

    MODEL_API_KEY=... python demo/threat_image.py examples/vulnerable_app
    MODEL_API_KEY=... python demo/threat_image.py examples/vulnerable_app --smart

--smart first asks muse-spark to write the image brief from the findings, so
the two Meta models cooperate: Spark reads the code, Muse Image draws it.
"""

from __future__ import annotations

import base64
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canary_agent.config import Config
from canary_agent.rescan import scan

BASE_BRIEF = (
    "A clean modern cybersecurity 'attack surface' illustration for an AI/LLM "
    "application. Show untrusted user input on the left flowing along glowing "
    "neon data-flow lines into a central AI model, then out to tools, a shell, "
    "and a secrets store on the right. Editorial tech-infographic style, dark "
    "background, teal and amber accents, clean geometric nodes, subtle grid. "
    "Abstract and iconographic, no paragraphs of text."
)


def _summary(findings) -> str:
    from collections import Counter
    c = Counter(f.get("rule_id", "") for f in findings)
    parts = {
        "CANARY-PI-001": "prompt injection", "CANARY-PI-002": "prompt injection",
        "CANARY-EA-001": "a tool wired to a shell", "CANARY-EA-002": "a tool with file/SQL access",
        "CANARY-SEC-001": "a leaked API key", "CANARY-PII-001": "PII written to logs",
        "CANARY-GR-001": "unvalidated model output",
    }
    seen = [parts[r] for r in c if r in parts]
    return ", ".join(dict.fromkeys(seen)) or "an AI application's data flow"


def _smart_brief(config: Config, findings) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=config.api_key, base_url=config.base_url)
    rules = sorted({f.get("rule_id", "") for f in findings})
    msg = (
        "Write a single vivid image-generation prompt (3-4 sentences, no text "
        "labels in the image) for a decorative 'attack surface' illustration of "
        f"an LLM app with these issue types: {', '.join(rules)}. Editorial "
        "tech-infographic style, dark background, neon data-flow lines."
    )
    resp = client.chat.completions.create(
        model=config.model, temperature=0.4,
        messages=[{"role": "user", "content": msg}],
    )
    return (resp.choices[0].message.content or BASE_BRIEF).strip()


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    smart = "--smart" in sys.argv
    target = args[0] if args else "examples/vulnerable_app"
    out = "threat_surface.png"

    config = Config.from_env()
    if config.mock:
        print("Image generation needs a live key (MODEL_API_KEY); there is no mock.")
        return 2

    findings = scan(target)
    brief = _smart_brief(config, findings) if smart else f"{BASE_BRIEF} It features {_summary(findings)}."
    print(f"brief: {brief}\n")

    from openai import OpenAI
    client = OpenAI(api_key=config.api_key, base_url=config.base_url)
    try:
        try:
            resp = client.images.generate(model="muse-image-1.0", prompt=brief,
                                           n=1, size="1024x1024", response_format="b64_json")
        except TypeError:
            resp = client.images.generate(model="muse-image-1.0", prompt=brief, n=1)
    except Exception as e:
        print("Muse Image call failed. If this is a 403/region error, Muse Image "
              "is likely not available for your account's country.")
        print(f"error: {type(e).__name__}: {e}")
        return 1

    d = resp.data[0]
    if getattr(d, "b64_json", None):
        with open(out, "wb") as fh:
            fh.write(base64.b64decode(d.b64_json))
    elif getattr(d, "url", None):
        urllib.request.urlretrieve(d.url, out)
    else:
        print("No image data returned.")
        return 1
    print(f"saved {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
