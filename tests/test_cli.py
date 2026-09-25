import io
from datetime import datetime, timezone

import pytest

import cli
from collectors.feeds import FeedItem
from extract.article import ArticleFetchError
from llm.providers import LLMError
from store.seen import SeenStore

# Written by Claude Code


def _items(n):
    return [
        FeedItem(
            source="Test",
            title=f"t{i}",
            url=f"https://example.test/{i}",
            published=datetime.now(timezone.utc),
            summary="s",
        )
        for i in range(n)
    ]


class _Provider:
    name = "fake"
    model = "fake"

    def __init__(self, answer="YES", error=None):
        self.answer = answer
        self.error = error
        self.calls = 0

    def complete(self, system, prompt, *, max_tokens):
        self.calls += 1
        if self.error:
            raise self.error
        return self.answer


@pytest.fixture
def pipeline(monkeypatch):
    monkeypatch.setattr(cli, "SOURCES", {"Test": "https://example.test/feed"})
    monkeypatch.setattr(cli, "poll_feed", lambda url, name, max_age_days: _items(5))

    def use(provider, fetch=None):
        monkeypatch.setattr(cli, "get_provider", lambda stage: provider)
        if fetch:
            monkeypatch.setattr(cli, "fetch_article", fetch)

    return use


def _fetch_fails(url):
    raise ArticleFetchError("nope")


def test_limit_counts_failed_articles(pipeline, tmp_path):
    pipeline(_Provider("YES"), fetch=_fetch_fails)
    count = cli.run(db_path=str(tmp_path / "db"), limit=2, out=io.StringIO())
    assert count == 2


def test_transient_error_fails_article_and_continues(pipeline, tmp_path):
    provider = _Provider(error=LLMError("timeout", fatal=False))
    pipeline(provider)
    count = cli.run(db_path=str(tmp_path / "db"), out=io.StringIO())
    assert provider.calls == 5
    assert count == 5


def test_fatal_error_aborts_after_first_call(pipeline, tmp_path):
    provider = _Provider(error=LLMError("401 bad key", fatal=True))
    pipeline(provider)
    db = str(tmp_path / "db")
    with pytest.raises(cli.TriageError):
        cli.run(db_path=db, out=io.StringIO())
    assert provider.calls == 1
    # The article wasn't at fault, so it must be picked up again next run.
    with SeenStore(db) as store:
        assert not store.is_seen("https://example.test/0")


def test_main_returns_nonzero_on_fatal_error(pipeline, tmp_path, capsys):
    pipeline(_Provider(error=LLMError("401 bad key", fatal=True)))
    assert cli.main(["run", "--db", str(tmp_path / "db")]) == 1
    assert "aborting run" in capsys.readouterr().err
