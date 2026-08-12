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

DEFAULT_TIMEOUT_SECONDS = 20
USER_AGENT = "wraithfeed/0.1 (+https://kevscan.cloud/)"


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
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ArticleFetchError(f"failed to fetch {url}: {exc}") from exc

    return extract_article(resp.text, url)


def extract_article(html: str, url: str) -> Article:
    """Extract article text from already-fetched HTML."""
    text = trafilatura.extract(html, url=url, include_tables=True, include_comments=False)
    if not text:
        raise ArticleFetchError(f"no extractable article body at {url}")

    metadata = trafilatura.extract_metadata(html, default_url=url)
    title = metadata.title if metadata else None

    return Article(url=url, title=title, text=text)
