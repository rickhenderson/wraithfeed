"""MITRE ATT&CK technique ids, checked in code, not by the model.

The list is validate/data/attack_techniques.json, generated from MISP's
mitre-attack-pattern galaxy by scripts/update_attack_techniques.py. Each id has
a status: "current", "revoked" (superseded in a later ATT&CK release) or
"deprecated". Only current ids may reach an event; anything else, including ids
the galaxy has never heard of, is dropped in stage 7.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "attack_techniques.json"


@lru_cache(maxsize=1)
def _techniques() -> dict[str, dict]:
    return json.loads(DATA_FILE.read_text())["techniques"]


def status(technique_id: str) -> str:
    """"current", "revoked", "deprecated", or "unknown" for an id not in the list."""
    entry = _techniques().get(technique_id)
    return entry["status"] if entry else "unknown"


def current_ids() -> list[str]:
    return sorted(t for t, e in _techniques().items() if e["status"] == "current")


def name(technique_id: str) -> str | None:
    entry = _techniques().get(technique_id)
    return entry["name"] if entry else None


def current_parents() -> list[tuple[str, str]]:
    """(id, name) of current top-level techniques, sorted by id."""
    return [(t, _techniques()[t]["name"]) for t in current_ids() if "." not in t]
