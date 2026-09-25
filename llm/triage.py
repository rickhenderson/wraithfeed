"""Triage: binary relevance call.

Runs on title + first 500 characters. Uses a cheap model to keep spend down
(per HANDOVER.md operational constraints) — this is a high-volume filter, not
the extraction stage. The backend is chosen by `llm.providers.get_provider`
(default: Anthropic Claude Haiku 4.5). Answers YES/NO only; never emits or
references indicator values.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

from llm.providers import LLMError, Provider, get_provider

SNIPPET_CHARS = 500
MAX_TOKENS = 5

# Originally lived only in llm/Modelfile.triage; moved here so every provider
# gets the same task framing. The "topic, not indicators" wording fixes false
# negatives on executive-summary-style snippets.
SYSTEM_PROMPT = """You are a triage filter for a threat intelligence pipeline. You are shown a short excerpt (title + opening text) from an article and must decide if the FULL article is likely a technical writeup of a specific malware family, intrusion, or campaign.

Answer YES if the excerpt describes a named malware/campaign/threat-actor, an intrusion, or attacker tooling/infrastructure/behavior — even if the excerpt itself is just an executive summary and doesn't list raw indicator values (hashes, IPs, domains). Full articles almost always contain indicators further down; you are judging the TOPIC, not verifying indicators are present in this excerpt.

Answer NO if the excerpt is about something else entirely: general security news, product announcements, opinion pieces, policy, culture, unrelated tech topics, or vulnerability disclosures with no malware/campaign/intrusion narrative.

Respond with exactly one word: YES or NO. No explanation, no punctuation, no other text."""

_PROMPT_TEMPLATE = """TITLE: {title}

TEXT: {snippet}"""


class TriageError(Exception):
    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


def is_relevant(title: str, text: str, *, provider: Provider | None = None) -> bool:
    """Ask the triage model whether this article is worth full extraction.

    Any response other than a clean leading "yes" is treated as NO —
    fail closed, since a missed article is cheaper than a wasted
    extraction-stage API call on irrelevant content.
    """
    snippet = text[:SNIPPET_CHARS]
    prompt = _PROMPT_TEMPLATE.format(title=title, snippet=snippet)

    try:
        provider = provider or get_provider("triage")
        answer = provider.complete(SYSTEM_PROMPT, prompt, max_tokens=MAX_TOKENS)
    except LLMError as exc:
        raise TriageError(f"triage call failed: {exc}", fatal=exc.fatal) from exc

    return answer.strip().lower().startswith("yes")
