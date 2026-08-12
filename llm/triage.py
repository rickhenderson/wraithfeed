"""Triage: binary relevance call.

Runs on title + first 500 characters. Uses a local Ollama model to keep
API spend down (per HANDOVER.md operational constraints) — this is a cheap,
high-volume filter, not the extraction stage. Answers YES/NO only; never
emits or references indicator values.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import requests

DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "wraithfeed-triage"
DEFAULT_TIMEOUT_SECONDS = 30
SNIPPET_CHARS = 500

# Task framing lives in the model's Modelfile SYSTEM prompt (llm/Modelfile.triage) —
# `ollama create wraithfeed-triage -f llm/Modelfile.triage` builds it from qwen3.5.
# Keeping instructions there (not per-request) so temperature/num_ctx/thinking are
# baked in once and every triage call only needs to send the excerpt.
_PROMPT_TEMPLATE = """TITLE: {title}

TEXT: {snippet}"""


class TriageError(Exception):
    pass


def is_relevant(
    title: str,
    text: str,
    *,
    model: str = DEFAULT_MODEL,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """Ask the local model whether this article is worth full extraction.

    Any response other than a clean leading "yes" is treated as NO —
    fail closed, since a missed article is cheaper than a wasted
    extraction-stage API call on irrelevant content.
    """
    snippet = text[:SNIPPET_CHARS]
    prompt = _PROMPT_TEMPLATE.format(title=title, snippet=snippet)

    try:
        resp = requests.post(
            ollama_url,
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {"num_ctx": 4096, "temperature": 0},
            },
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise TriageError(f"triage call failed: {exc}") from exc

    answer = resp.json().get("response", "").strip().lower()
    return answer.startswith("yes")
