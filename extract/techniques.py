"""MITRE ATT&CK technique ids the article states explicitly.

No LLM involved. Same idea as `extract.iocs`: code finds the values, the model
never writes them. Techniques an article only describes ("dumped LSASS memory")
are not inferred; a model can't map behavior to ids it can't see, and a wrong
valid id is worse than none (see HANDOVER.md). Whether a mentioned id is a
current ATT&CK technique is decided in stage 7 (`validate.techniques`).

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONTEXT_CHARS = 100
MAX_MENTIONS = 100

_ID_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
# attack.mitre.org links write sub-techniques as .../techniques/T1059/001/
_URL_RE = re.compile(r"/techniques/T(\d{4})(?:/(\d{3}))?\b")
_WS_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class TechniqueMention:
    technique_id: str
    context: str  # the article text around the first mention


def extract_techniques(text: str) -> list[TechniqueMention]:
    """Technique ids in order of first appearance, each with its surrounding text."""
    found: dict[str, tuple[int, TechniqueMention]] = {}  # id -> (position, mention)
    url_spans: list[tuple[int, int]] = []

    def record(m: re.Match) -> None:
        technique_id = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        if technique_id in found and found[technique_id][0] <= m.start():
            return
        context = text[max(0, m.start() - CONTEXT_CHARS) : m.end() + CONTEXT_CHARS]
        found[technique_id] = (m.start(), TechniqueMention(technique_id, _WS_RE.sub(" ", context).strip()))

    for m in _URL_RE.finditer(text):
        url_spans.append(m.span())
        record(m)
    for m in _ID_RE.finditer(text):
        # Inside a link the id is already taken from the URL form; matching it
        # again would report the parent of a sub-technique link as its own mention.
        if not any(start <= m.start() < end for start, end in url_spans):
            record(m)
    return [mention for _, mention in sorted(found.values(), key=lambda pm: pm[0])][:MAX_MENTIONS]
