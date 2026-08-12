"""RSS/Atom feed polling.

No LLM involved. Fetches a feed, normalizes entries into FeedItem, and
applies the `published >= now - 30d` filter here in code (per HANDOVER.md —
do not rely on the model to judge recency).

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

from calendar import timegm
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import feedparser
import requests

DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_TIMEOUT_SECONDS = 15
USER_AGENT = "wraithfeed/0.1 (+https://kevscan.cloud/)"


@dataclass(frozen=True)
class FeedItem:
    source: str
    title: str
    url: str
    published: datetime  # UTC, tz-aware


class FeedFetchError(Exception):
    pass


def _struct_time_to_utc(struct_time) -> datetime | None:
    if struct_time is None:
        return None
    return datetime.fromtimestamp(timegm(struct_time), tz=timezone.utc)


def _entry_published(entry) -> datetime | None:
    return _struct_time_to_utc(
        getattr(entry, "published_parsed", None)
        or getattr(entry, "updated_parsed", None)
    )


def parse_feed(raw: bytes, source: str, *, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> list[FeedItem]:
    """Parse feed bytes into FeedItems, dropping undated or stale entries."""
    parsed = feedparser.parse(raw)
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    items: list[FeedItem] = []
    for entry in parsed.entries:
        url = getattr(entry, "link", None)
        title = getattr(entry, "title", None)
        published = _entry_published(entry)
        if not url or not title or published is None:
            continue
        if published < cutoff:
            continue
        items.append(FeedItem(source=source, title=title, url=url, published=published))
    return items


def poll_feed(
    feed_url: str,
    source: str,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[FeedItem]:
    """Fetch a feed URL and return recent FeedItems for `source`."""
    try:
        resp = requests.get(
            feed_url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise FeedFetchError(f"{source}: failed to fetch {feed_url}: {exc}") from exc

    return parse_feed(resp.content, source, max_age_days=max_age_days)


# Narrative sources per HANDOVER.md. Feed URLs are intentionally left blank —
# confirm the actual RSS/Atom endpoint for each vendor before use.
SOURCES: dict[str, str] = {
    "The DFIR Report": "https://thedfirreport.com/feed/",
    "Unit 42": "https://unit42.paloaltonetworks.com/feed/",
    "Cisco Talos": "",
    "Securelist": "",
    "Elastic Security Labs": "",
    "Sekoia": "",
    "Microsoft MSTIC": "",
    "ESET Research": "",
    "Huntress": "",
    "Trend Micro": "",
    "Proofpoint": "",
    "Red Canary": "",
    # Not in HANDOVER.md's original source list — added for cloud-specific coverage.
    "Wiz Cloud Threat Landscape": "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
    "SANS ISC": "https://isc.sans.edu/rssfeed.xml",
}


def poll_all(
    sources: dict[str, str] = SOURCES,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> list[FeedItem]:
    """Poll every configured source. Per-source failures are logged and skipped."""
    items: list[FeedItem] = []
    for source, feed_url in sources.items():
        if not feed_url:
            continue
        try:
            items.extend(poll_feed(feed_url, source, max_age_days=max_age_days))
        except FeedFetchError as exc:
            print(f"[collectors.feeds] {exc}")
            continue
    return items
