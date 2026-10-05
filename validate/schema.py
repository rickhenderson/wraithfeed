"""Stage 7a: parse and schema-check the structuring model's raw output.

No LLM involved. Output that fails here is discarded, never repaired
(HANDOVER.md core design rule). `extra="forbid"` everywhere is what stops the
model from smuggling an indicator value in as an unexpected field.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError, field_validator

INDICATOR_TYPES = Literal[
    "sha256", "md5", "sha1", "ip-dst", "domain", "hostname", "url", "email-src",
    "filename", "mutex", "btc", "registry-key", "user-agent",
]
ROLES = Literal[
    "c2", "payload_delivery", "dropper", "loader", "final_payload", "persistence", "exfil", "unknown",
]
MAX_SUMMARY_WORDS = 60

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class ExtractionRejected(Exception):
    """The model output is unusable; log the reason and drop the article."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AttackPattern(_Strict):
    # Whether the id exists is checked against the ATT&CK list in stage 7b
    # (validate.techniques); an unknown id drops this entry, not the article.
    technique_id: str = Field(min_length=1, max_length=40)
    evidence: str = Field(min_length=1, max_length=500)


class IndicatorRef(_Strict):
    idx: StrictInt = Field(ge=0)
    type: INDICATOR_TYPES
    role: ROLES
    comment: str = Field(default="", max_length=300)
    to_ids: StrictBool


class Irrelevant(_Strict):
    relevant: Literal[False]
    reason: str = Field(min_length=1, max_length=300)


class Extraction(_Strict):
    relevant: Literal[True]
    event_info: str = Field(min_length=1, max_length=256)
    summary: str = Field(min_length=1)
    indicators: list[IndicatorRef]
    malware_families: list[str] = []
    threat_actors: list[str] = []
    attribution_confidence: Literal["high", "moderate", "low"] | None = None
    targeted_sectors: list[str] = []
    targeted_regions: list[str] = []
    first_seen: date | None = None
    attack_patterns: list[AttackPattern] = []
    cves: list[str] = []

    @field_validator("summary")
    @classmethod
    def _summary_length(cls, v: str) -> str:
        if len(v.split()) > MAX_SUMMARY_WORDS:
            raise ValueError(f"summary longer than {MAX_SUMMARY_WORDS} words")
        return v

    @field_validator("first_seen", mode="before")
    @classmethod
    def _first_seen_is_iso_date(cls, v):
        if v is not None and (not isinstance(v, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v)):
            raise ValueError("first_seen must be YYYY-MM-DD or null")
        return v

    @field_validator("first_seen")
    @classmethod
    def _first_seen_not_future(cls, v: date | None) -> date | None:
        if v is not None and v > datetime.now(timezone.utc).date():
            raise ValueError("first_seen is in the future")
        return v

    @field_validator("cves")
    @classmethod
    def _cve_format(cls, v: list[str]) -> list[str]:
        bad = [c for c in v if not _CVE_RE.match(c)]
        if bad:
            raise ValueError(f"malformed CVE ids: {bad}")
        return v


def _reject_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        raise ExtractionRejected(f"duplicate JSON keys: {sorted(dupes)}")
    return dict(pairs)


def parse_extraction(raw: str) -> Extraction | Irrelevant:
    """Parse raw model text into a schema-checked result, or raise ExtractionRejected."""
    text = raw.strip()
    # Anything around the object (prose, markdown fences) means the model ignored the format.
    if not (text.startswith("{") and text.endswith("}")):
        raise ExtractionRejected("output is not a bare JSON object (prose or fences around it)")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ExtractionRejected(f"invalid JSON: {exc}") from exc

    relevant = data.get("relevant")
    if relevant is True:
        model = Extraction
    elif relevant is False:
        model = Irrelevant
    else:
        raise ExtractionRejected("'relevant' must be true or false")

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise ExtractionRejected(f"schema violation: {problems}") from exc
