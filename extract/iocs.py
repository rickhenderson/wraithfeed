"""Regex-based IOC candidate extraction.

No LLM involved. Produces an ordered, de-duplicated, indexed list of
candidate indicator values from raw article text. The LLM stage may only
reference these candidates by index (see HANDOVER.md core design rule) —
it never emits an indicator value itself. False positives here are cheap
(the LLM just won't select them); false negatives are not, so extraction
favors recall over precision.
Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- defanging ---------------------------------------------------------
# Articles commonly defang indicators to avoid accidental execution/click.
# Refang before matching so candidates come out as live values.

_REFANG_SUBS = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[at\]|\(at\)|\[@\]", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    for pattern, replacement in _REFANG_SUBS:
        text = pattern.sub(replacement, text)
    return text


# --- candidate types -----------------------------------------------------

VALID_TYPES = {
    "sha256",
    "md5",
    "sha1",
    "ip-dst",
    "domain",
    "url",
    "email-src",
    "btc",
    "registry-key",
}


@dataclass(frozen=True)
class Candidate:
    idx: int
    type: str
    value: str


# --- component patterns, checked in priority order to avoid overlap ----
# (type, compiled pattern). Longer/more-specific matches (urls, emails,
# hashes, registry keys, btc) are claimed first so a later, looser pattern
# (domain) can't re-match a substring already spoken for.

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("url", re.compile(r"\bhttps?://[^\s'\"<>\)\]]+", re.IGNORECASE)),
    ("email-src", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    (
        "registry-key",
        re.compile(
            r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
            r"HKEY_USERS|HKLM|HKCU)\\[^\s\"']+",
            re.IGNORECASE,
        ),
    ),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("btc", re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,39})\b")),
    ("ip-dst", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        "domain",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,24}\b"
        ),
    ),
]

_COMMON_FILE_EXTS = {
    "exe", "dll", "sys", "bat", "ps1", "vbs", "zip", "rar", "pdf", "doc",
    "docx", "xls", "xlsx", "js", "jar", "bin", "tmp", "log", "txt", "png",
    "jpg", "gif", "html", "htm", "php", "asp", "py", "sh", "lnk", "scr",
}


def _valid_octets(ip: str) -> bool:
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def _looks_like_filename(domain: str) -> bool:
    """Reject obvious `payload.exe`-style false positives from the domain regex."""
    suffix = domain.rsplit(".", 1)[-1].lower()
    return suffix in _COMMON_FILE_EXTS


def extract_candidates(text: str) -> list[Candidate]:
    """Extract IOC candidates from article text.

    Returns an ordered, de-duplicated list of Candidate(idx, type, value).
    `idx` is stable for a given input and is what the LLM stage references —
    never re-sort or re-number an existing list once shown to a model call.
    """
    text = refang(text)

    claimed: list[tuple[int, int]] = []  # (start, end) spans already matched
    found: list[tuple[int, str, str]] = []  # (start, type, value)

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for type_, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span()
            value = m.group(0)

            if type_ in ("url", "registry-key"):
                stripped = value.rstrip(".,;:!?)")
                end -= len(value) - len(stripped)
                value = stripped

            if overlaps(start, end):
                continue

            if type_ == "ip-dst" and not _valid_octets(value):
                continue
            if type_ == "domain" and _looks_like_filename(value):
                continue

            claimed.append((start, end))
            found.append((start, type_, value))

    found.sort(key=lambda item: item[0])

    seen: set[tuple[str, str]] = set()
    candidates: list[Candidate] = []
    for _, type_, value in found:
        key = (type_, value.lower())
        if key in seen:
            continue
        seen.add(key)
        candidates.append(Candidate(idx=len(candidates), type=type_, value=value))

    return candidates
