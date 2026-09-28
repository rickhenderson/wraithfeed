"""Stage 7b: resolve indicator indices to values and apply warninglists.

No LLM involved. Every value that leaves this module came from the regex
candidate list, never from model text. A warninglist hit forces to_ids=False
regardless of what the model said (HANDOVER.md MISP writing conventions).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import requests

from extract.iocs import Candidate
from validate.schema import Extraction, ExtractionRejected, Irrelevant, parse_extraction

# Model types each regex candidate type may be reported as. The regex can't
# tell a registered domain from a hostname, so either is accepted for "domain";
# types the regex never produces (filename, mutex, user-agent) can never match.
_COMPATIBLE_TYPES = {"domain": {"domain", "hostname"}}

# Hits on these are recorded but don't force to_ids off: they cover whole
# hosting ranges, which is exactly where most attacker C2 lives.
ADVISORY_LISTS = frozenset({
    "Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters",
    "Specialized list of IPv6 addresses belonging to common VPN providers and datacenters",
})


class WarninglistUnavailable(Exception):
    """Warninglists couldn't be consulted. Not the article's fault: retry later."""


class Warninglist(Protocol):
    def check(self, values: list[str]) -> dict[str, list[str]]:
        """Map each value that hits a warninglist to the names of the lists it hit."""
        ...


class StaticWarninglist:
    """In-memory exact-match list, for tests and the offline demo."""

    def __init__(self, entries: dict[str, str]):
        self._entries = {k.lower(): v for k, v in entries.items()}

    def check(self, values: list[str]) -> dict[str, list[str]]:
        return {v: [self._entries[v.lower()]] for v in values if v.lower() in self._entries}


class MispWarninglists:
    def __init__(self, base_url: str, api_key: str, *, verify: bool = True, timeout: float = 30):
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": api_key, "Accept": "application/json"}
        self._verify = verify
        self._timeout = timeout
        self._ready = False

    @classmethod
    def from_env(cls) -> "MispWarninglists":
        url, key = os.environ.get("MISP_URL"), os.environ.get("MISP_KEY")
        if not url or not key:
            raise WarninglistUnavailable("MISP_URL and MISP_KEY must be set")
        verify = os.environ.get("MISP_VERIFY_CERT", "true").strip().lower() not in ("false", "0", "no")
        return cls(url, key, verify=verify)

    def _request(self, method: str, path: str, **kwargs):
        try:
            resp = requests.request(
                method, self._base + path, headers=self._headers,
                verify=self._verify, timeout=self._timeout, **kwargs,
            )
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise WarninglistUnavailable(f"MISP warninglist call failed: {exc}") from exc

    def _ensure_enabled(self) -> None:
        # With every list disabled MISP reports no hits for anything, which
        # would silently clear every indicator for IDS. Refuse instead.
        if self._ready:
            return
        lists = self._request("GET", "/warninglists/index").get("Warninglists", [])
        if not any(w["Warninglist"].get("enabled") in (True, 1, "1") for w in lists):
            raise WarninglistUnavailable("no MISP warninglists are enabled")
        self._ready = True

    def check(self, values: list[str]) -> dict[str, list[str]]:
        if not values:
            return {}
        self._ensure_enabled()
        hits = self._request("POST", "/warninglists/checkValue", json=values)
        if not hits:  # MISP answers [] when nothing matched
            return {}
        return {value: [h["name"] for h in matches] for value, matches in hits.items()}


@dataclass(frozen=True)
class ResolvedIndicator:
    idx: int
    type: str
    value: str
    role: str
    comment: str
    to_ids: bool
    warninglist_hits: tuple[str, ...]


@dataclass(frozen=True)
class ValidatedExtraction:
    extraction: Extraction
    indicators: list[ResolvedIndicator]


def _lookup_keys(type_: str, value: str) -> list[str]:
    # Lists are mostly keyed on hosts, so a URL or email on a benign domain
    # should hit through its host part too.
    keys = [value]
    if type_ == "url":
        host = urlsplit(value).hostname
        if host:
            keys.append(host)
    elif type_ == "email-src":
        keys.append(value.rsplit("@", 1)[-1])
    return keys


def resolve_indicators(
    extraction: Extraction, candidates: list[Candidate], warninglist: Warninglist
) -> list[ResolvedIndicator]:
    by_idx = {c.idx: c for c in candidates}

    seen: set[int] = set()
    pairs: list[tuple] = []
    for ref in extraction.indicators:
        if ref.idx in seen:
            raise ExtractionRejected(f"indicator idx {ref.idx} referenced twice")
        seen.add(ref.idx)
        cand = by_idx.get(ref.idx)
        if cand is None:
            raise ExtractionRejected(f"unknown candidate idx {ref.idx} (have {len(candidates)})")
        if ref.type not in _COMPATIBLE_TYPES.get(cand.type, {cand.type}):
            raise ExtractionRejected(
                f"idx {ref.idx}: model says {ref.type!r} but candidate is {cand.type!r}"
            )
        pairs.append((ref, cand))

    keys_for = {cand.idx: _lookup_keys(cand.type, cand.value) for _, cand in pairs}
    hits = warninglist.check(sorted({k for keys in keys_for.values() for k in keys}))

    resolved = []
    for ref, cand in pairs:
        names = tuple(dict.fromkeys(n for k in keys_for[cand.idx] for n in hits.get(k, [])))
        resolved.append(
            ResolvedIndicator(
                idx=cand.idx,
                type=ref.type,
                value=cand.value,
                role=ref.role,
                comment=ref.comment,
                to_ids=ref.to_ids and all(n in ADVISORY_LISTS for n in names),
                warninglist_hits=names,
            )
        )
    return resolved


def validate_output(
    raw: str, candidates: list[Candidate], warninglist: Warninglist
) -> ValidatedExtraction | Irrelevant:
    """Full stage 7. Raises ExtractionRejected (discard) or WarninglistUnavailable (retry)."""
    parsed = parse_extraction(raw)
    if isinstance(parsed, Irrelevant):
        return parsed
    return ValidatedExtraction(parsed, resolve_indicators(parsed, candidates, warninglist))
