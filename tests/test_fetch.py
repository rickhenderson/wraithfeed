import socket

import pytest

from collectors import fetch
from collectors.fetch import FetchError, check_url, safe_get


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "http://127.0.0.1/",
        "http://localhost:11434/api/tags",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://100.78.76.1/",  # CGNAT / Tailscale range
        "http://[::1]/",
        "http:///nohost",
    ],
)
def test_check_url_rejects_unsafe(url):
    with pytest.raises(FetchError):
        check_url(url)


class _Resp:
    def __init__(self, status=200, headers=None, chunks=(b"ok",), redirect_to=None):
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks
        self.encoding = None
        if redirect_to:
            self.headers["Location"] = redirect_to
        self.is_redirect = redirect_to is not None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        yield from self._chunks


@pytest.fixture
def fake_net(monkeypatch):
    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]
    private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(
        fetch.socket, "getaddrinfo",
        lambda host, *a, **k: private if host == "internal.test" else public,
    )
    responses = {}
    requested = []

    def get(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        requested.append(url)
        return responses[url]

    monkeypatch.setattr(fetch.requests, "get", get)
    return responses, requested


def test_redirect_to_private_host_is_refused(fake_net):
    responses, requested = fake_net
    responses["https://public.test/a"] = _Resp(302, redirect_to="http://internal.test/secret")
    with pytest.raises(FetchError, match="non-public"):
        safe_get("https://public.test/a", timeout=1)
    assert requested == ["https://public.test/a"]


def test_relative_redirect_is_followed(fake_net):
    responses, _ = fake_net
    responses["https://public.test/a"] = _Resp(301, redirect_to="/b")
    responses["https://public.test/b"] = _Resp(chunks=(b"hello",))
    result = safe_get("https://public.test/a", timeout=1)
    assert result.url == "https://public.test/b"
    assert result.content == b"hello"


def test_redirect_loop_is_bounded(fake_net):
    responses, requested = fake_net
    responses["https://public.test/a"] = _Resp(302, redirect_to="https://public.test/a")
    with pytest.raises(FetchError, match="too many redirects"):
        safe_get("https://public.test/a", timeout=1)
    assert len(requested) == fetch.MAX_REDIRECTS + 1


def test_oversized_body_is_refused(fake_net):
    responses, _ = fake_net
    responses["https://public.test/big"] = _Resp(chunks=(b"x" * 600, b"x" * 600))
    with pytest.raises(FetchError, match="exceeds"):
        safe_get("https://public.test/big", timeout=1, max_bytes=1000)


def test_declared_oversize_is_refused_before_reading(fake_net):
    responses, _ = fake_net
    responses["https://public.test/big"] = _Resp(headers={"Content-Length": "5000"}, chunks=())
    with pytest.raises(FetchError, match="too large"):
        safe_get("https://public.test/big", timeout=1, max_bytes=1000)


def test_content_type_filter(fake_net):
    responses, _ = fake_net
    responses["https://public.test/f.zip"] = _Resp(headers={"Content-Type": "application/zip"})
    responses["https://public.test/p"] = _Resp(headers={"Content-Type": "text/html; charset=utf-8"})
    with pytest.raises(FetchError, match="content type"):
        safe_get("https://public.test/f.zip", timeout=1, content_types=("text/html",))
    assert safe_get("https://public.test/p", timeout=1, content_types=("text/html",)).content == b"ok"
