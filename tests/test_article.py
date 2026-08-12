from pathlib import Path

import pytest

from extract.article import ArticleFetchError, extract_article

# Written by Claude Code

FIXTURES = Path(__file__).parent / "fixtures"


def test_unit42_article_golden():
    html = (FIXTURES / "sample_article_unit42.html").read_text()
    url = "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"

    article = extract_article(html, url)

    assert article.url == url
    assert article.title == "ChainDrop: Inside a Self-Propagating npm Worm"
    assert "Executive Summary" in article.text
    assert "ChainDrop" in article.text
    assert "keyv" in article.text
    assert len(article.text) > 5000


def test_extract_article_raises_on_no_body():
    html = "<html><head><title>Empty</title></head><body></body></html>"

    with pytest.raises(ArticleFetchError):
        extract_article(html, "https://example.com/empty")
