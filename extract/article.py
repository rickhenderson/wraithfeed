"""Full article text extraction.

No LLM involved. Fetches a URL and pulls clean article text (boilerplate,
nav, ads, comments stripped) via trafilatura. Output feeds both the regex
candidate extractor (extract/iocs.py) and the LLM structuring stage.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests
import trafilatura

from collectors.fetch import safe_get

DEFAULT_TIMEOUT_SECONDS = 20
HTML_TYPES = ("text/html", "application/xhtml+xml")


class ArticleFetchError(Exception):
    pass


@dataclass(frozen=True)
class Article:
    url: str
    title: str | None
    text: str


def fetch_article(url: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Article:
    """Fetch `url` and return its clean article text.

    Raises ArticleFetchError on network failure or if no extractable
    article body is found (e.g. paywall, JS-only rendering, non-article page).
    """
    try:
        result = safe_get(url, timeout=timeout, content_types=HTML_TYPES)
    except requests.RequestException as exc:
        raise ArticleFetchError(f"failed to fetch {url!r}: {exc}") from exc

    # Bytes, not decoded text: trafilatura detects the charset from the page itself.
    return extract_article(result.content, url)


def extract_article(html: str | bytes, url: str) -> Article:
    """Extract article text from already-fetched HTML."""
    text = trafilatura.extract(html, url=url, include_tables=True, include_comments=False)
    if not text:
        raise ArticleFetchError(f"no extractable article body at {url}")

    metadata = trafilatura.extract_metadata(html, default_url=url)
    title = metadata.title if metadata else None

    return Article(url=url, title=title, text=text)
