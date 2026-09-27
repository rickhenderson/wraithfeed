"""HTTP GET for untrusted URLs: public http(s) hosts only, every redirect re-checked, size-capped."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "wraithfeed/0.1 (+https://kevscan.cloud/)"
MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 5 * 1024 * 1024


class FetchError(requests.RequestException):
    """Raised for URLs we refuse to fetch or responses we refuse to read."""


@dataclass(frozen=True)
class FetchResult:
    url: str  # final URL after redirects
    content: bytes
    encoding: str | None


def check_url(url: str) -> None:
    # Checked before the request, so DNS rebinding between check and connect isn't covered.
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"refusing non-http(s) URL: {url!r}")
    if not parts.hostname:
        raise FetchError(f"URL has no host: {url!r}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise FetchError(f"cannot resolve {parts.hostname!r}: {exc}") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not addr.is_global:
            raise FetchError(f"refusing non-public address {addr} for {parts.hostname!r}")


def safe_get(
    url: str,
    *,
    timeout: float,
    max_bytes: int = DEFAULT_MAX_BYTES,
    content_types: tuple[str, ...] | None = None,
) -> FetchResult:
    """GET `url`, following redirects manually so each hop is re-validated.

    `content_types`, if given, is a tuple of allowed media-type prefixes.
    """
    for _ in range(MAX_REDIRECTS + 1):
        check_url(url)
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        with resp:
            if resp.is_redirect:
                location = resp.headers.get("Location")
                if not location:
                    raise FetchError(f"redirect without Location from {url}")
                url = urljoin(url, location)
                continue

            resp.raise_for_status()

            if content_types is not None:
                ctype = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if not ctype.startswith(content_types):
                    raise FetchError(f"unexpected content type {ctype or 'none'!r} at {url}")

            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"response too large ({declared} bytes) at {url}")

            body = bytearray()
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FetchError(f"response exceeds {max_bytes} bytes at {url}")

            return FetchResult(url=url, content=bytes(body), encoding=resp.encoding)

    raise FetchError(f"too many redirects starting from {url}")
