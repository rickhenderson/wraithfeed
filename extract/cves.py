"""CVE ids the article states explicitly.

No LLM involved, like `extract.iocs` and `extract.techniques`: code finds the
ids, the model never writes them. A model left to report CVEs omitted them
entirely on an article that names eight. The trade-off is the same as for
techniques: every id the article mentions is taken, including ones it cites
only as background or from older campaigns, so a human reviews the list.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import re

MAX_CVES = 50

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    """Distinct CVE ids in order of first appearance, upper-cased."""
    found: dict[str, None] = {}
    for m in _CVE_RE.finditer(text):
        found.setdefault(f"CVE-{m.group(1)}-{m.group(2)}", None)
    return list(found)[:MAX_CVES]
