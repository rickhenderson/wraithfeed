"""Stage 8: validated finding -> unpublished MISP event.

No LLM involved. Everything written here comes from a finding dict produced by
stage 7, so indicator values are the regex-extracted candidates, never model
text. Events are never published (HANDOVER.md: human review gate), and
`MispWriter` has no code path that calls publish.

`build_event` is pure (no network) so it can be tested and dry-run offline;
`MispWriter` is the only thing that talks to MISP, through an injected PyMISP-
style client.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.exceptions import PyMISPError

from validate import techniques

# Org-only: nothing leaves this instance until a human reviews and widens it.
DISTRIBUTION_ORG_ONLY = 0
THREAT_LEVEL_UNDEFINED = 4
ANALYSIS_INITIAL = 0

# Stable per article URL, so re-running the same article can never create a second event.
_EVENT_NAMESPACE = uuid.UUID("6f1c2a52-8d0b-4c53-9a3e-5b7f0c1d2e44")

_HASH_TYPES = ("sha256", "sha1", "md5")
# model/candidate type -> MISP attribute type, for indicators with no suitable object
_LOOSE_TYPES = {
    "email-src": "email-src",
    "btc": "btc",
    "registry-key": "regkey",
    "filename": "filename",
    "mutex": "mutex",
    "user-agent": "user-agent",
}
_TAG_VALUE_MAX = 80
_WS_RE = re.compile(r"\s+")


class MispWriteError(Exception):
    """`fatal`: MISP is unreachable or rejects us outright, so abort the run
    rather than fail every remaining article the same way."""

    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


@dataclass(frozen=True)
class WriteResult:
    outcome: str  # "created" | "exists"
    event_uuid: str
    event_id: str | None


def event_uuid_for(url: str) -> str:
    return str(uuid.uuid5(_EVENT_NAMESPACE, url))


def _tag_value(value: str) -> str:
    # Machine tags are predicate="value": quotes and backslashes would break the syntax.
    cleaned = _WS_RE.sub(" ", value.replace('"', "'").replace("\\", "/")).strip()
    return cleaned[:_TAG_VALUE_MAX]


def _source_domain(url: str) -> str:
    host = (urlsplit(url).hostname or "unknown").lower()
    return host[4:] if host.startswith("www.") else host


def _indicator_comment(ind: dict) -> str:
    parts = [ind["role"]]
    if ind.get("comment"):
        parts[0] += f": {ind['comment']}"
    if ind.get("warninglist_hits"):
        parts.append("warninglists: " + "; ".join(ind["warninglist_hits"]))
    return " | ".join(parts)


def _add_indicator(event: MISPEvent, ind: dict) -> None:
    kind, value, to_ids = ind["type"], ind["value"], ind["to_ids"]
    comment = _indicator_comment(ind)
    common = {"to_ids": to_ids, "comment": comment}

    if kind in _HASH_TYPES:
        obj = MISPObject("file")
        obj.add_attribute(kind, value=value, **common)
    elif kind == "url":
        obj = MISPObject("url")
        obj.add_attribute("url", value=value, **common)
    elif kind in ("domain", "hostname"):
        obj = MISPObject("domain-ip")
        obj.add_attribute("domain" if kind == "domain" else "hostname", value=value, **common)
    elif kind == "ip-dst":
        obj = MISPObject("domain-ip")
        obj.add_attribute("ip", value=value, type="ip-dst", **common)
    elif kind in _LOOSE_TYPES:
        event.add_attribute(_LOOSE_TYPES[kind], value=value, **common)
        return
    else:  # unreachable for validated findings; refuse rather than guess a type
        raise MispWriteError(f"no MISP mapping for indicator type {kind!r}")
    obj.comment = comment
    event.add_object(obj)


def build_event(finding: dict) -> MISPEvent:
    """Build the (unpublished) MISP event for a finding. Pure: no network."""
    data = finding["event"]
    url = finding["url"]

    event = MISPEvent()
    event.uuid = event_uuid_for(url)
    event.info = data["event_info"]
    event.date = datetime.fromisoformat(finding["published"]).date().isoformat()
    event.distribution = DISTRIBUTION_ORG_ONLY
    event.threat_level_id = THREAT_LEVEL_UNDEFINED
    event.analysis = ANALYSIS_INITIAL
    event.published = False

    event.add_tag("tlp:clear")
    event.add_tag(f"source:{_source_domain(url)}")
    event.add_tag('wraithfeed:review="pending"')
    if data.get("attribution_confidence"):
        # The confidence taxonomy (low/moderate/high) matches the schema's wording;
        # likelihood-probability would misstate "low confidence" as "unlikely".
        event.add_tag(f'estimative-language:confidence-in-analytic-judgement="{data["attribution_confidence"]}"')
    for pattern in data.get("attack_patterns", []):
        name = techniques.name(pattern["technique_id"])
        if name:
            event.add_tag(f'misp-galaxy:mitre-attack-pattern="{_tag_value(name)} - {pattern["technique_id"]}"')
    for predicate, key in (
        ("malware-family", "malware_families"),
        ("threat-actor", "threat_actors"),
        ("sector", "targeted_sectors"),
        ("region", "targeted_regions"),
    ):
        for item in data.get(key, []):
            if _tag_value(item):
                event.add_tag(f'wraithfeed:{predicate}="{_tag_value(item)}"')

    event.add_attribute("link", value=url, category="External analysis", to_ids=False, comment=finding.get("title") or "")
    summary = data["summary"] + (f" First seen: {data['first_seen']}." if data.get("first_seen") else "")
    event.add_attribute("comment", value=summary, category="Other", to_ids=False)

    for cve in data.get("cves", []):
        vuln = MISPObject("vulnerability")
        vuln.add_attribute("id", value=cve)
        event.add_object(vuln)
    for ind in data["indicators"]:
        _add_indicator(event, ind)
    return event


class MispWriter:
    def __init__(self, client):
        self._client = client

    @classmethod
    def from_env(cls) -> "MispWriter":
        url, key = os.environ.get("MISP_URL"), os.environ.get("MISP_KEY")
        if not url or not key:
            raise MispWriteError("MISP_URL and MISP_KEY must be set", fatal=True)
        verify = os.environ.get("MISP_VERIFY_CERT", "true").strip().lower() not in ("false", "0", "no")
        try:
            return cls(PyMISP(url, key, ssl=verify))
        except (PyMISPError, requests.RequestException) as exc:
            raise MispWriteError(f"cannot connect to MISP: {exc}", fatal=True) from exc

    def write(self, finding: dict) -> WriteResult:
        """Create the finding's event unless one already exists for its URL."""
        event = build_event(finding)
        try:
            found = self._client.search(controller="events", uuid=event.uuid, pythonify=False)
            if isinstance(found, dict) and found.get("errors"):
                raise MispWriteError(f"MISP search failed: {found['errors']}", fatal=True)
            if found:
                existing = found[0]["Event"] if isinstance(found, list) else None
                return WriteResult("exists", event.uuid, existing.get("id") if existing else None)

            created = self._client.add_event(event, pythonify=False)
        except (PyMISPError, requests.RequestException) as exc:
            raise MispWriteError(f"MISP call failed: {exc}", fatal=True) from exc

        if not isinstance(created, dict) or created.get("errors") or "Event" not in created:
            raise MispWriteError(f"MISP rejected the event: {created!r}"[:500])
        return WriteResult("created", event.uuid, str(created["Event"].get("id")))
