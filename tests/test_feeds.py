from datetime import datetime, timedelta, timezone

from collectors.feeds import parse_feed

# Written by Claude Code

NOW = datetime.now(timezone.utc)


def _rss(*items: str) -> bytes:
    body = "\n".join(items)
    return f"""<?xml version="1.0"?>
<rss version="2.0"><channel>
<title>Test Feed</title>
{body}
</channel></rss>""".encode()


def _rss_item(title: str, url: str, pub_dt: datetime) -> str:
    pub = pub_dt.strftime("%a, %d %b %Y %H:%M:%S %z")
    return f"<item><title>{title}</title><link>{url}</link><pubDate>{pub}</pubDate></item>"


def test_parse_feed_keeps_recent_entries():
    raw = _rss(
        _rss_item("Recent Campaign", "https://example.com/a", NOW - timedelta(days=5)),
    )
    items = parse_feed(raw, source="Test Vendor")

    assert len(items) == 1
    assert items[0].source == "Test Vendor"
    assert items[0].title == "Recent Campaign"
    assert items[0].url == "https://example.com/a"


def test_parse_feed_drops_stale_entries():
    raw = _rss(
        _rss_item("Old Campaign", "https://example.com/old", NOW - timedelta(days=45)),
        _rss_item("Fresh Campaign", "https://example.com/fresh", NOW - timedelta(days=1)),
    )
    items = parse_feed(raw, source="Test Vendor")

    assert [i.title for i in items] == ["Fresh Campaign"]


def test_parse_feed_drops_entries_missing_link_or_title():
    raw = _rss(
        "<item><title>No Link</title><pubDate>%s</pubDate></item>"
        % NOW.strftime("%a, %d %b %Y %H:%M:%S %z"),
        "<item><link>https://example.com/no-title</link><pubDate>%s</pubDate></item>"
        % NOW.strftime("%a, %d %b %Y %H:%M:%S %z"),
    )
    items = parse_feed(raw, source="Test Vendor")

    assert items == []


def test_parse_feed_respects_custom_max_age():
    raw = _rss(
        _rss_item("Ten Days Old", "https://example.com/b", NOW - timedelta(days=10)),
    )
    assert parse_feed(raw, source="Test Vendor", max_age_days=30) != []
    assert parse_feed(raw, source="Test Vendor", max_age_days=5) == []
