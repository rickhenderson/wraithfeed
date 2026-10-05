"""On-disk JSON artifacts for findings written to MISP.

Each finding that is pulled into MISP is also kept as a standalone JSON file,
independent of MISP and the seen-store: the validated event, the model's raw
output, and what MISP did with it. The file is written *before* the MISP call
(status "pending") and updated after, so a record exists even if MISP is down.
Layout: <dir>/<article date>/<sha256(url)[:16]>-<title slug>.json, stable per
URL so a re-run overwrites its own artifact instead of adding another.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DIR = "data/findings"
SCHEMA = "wraithfeed.finding/1"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def artifact_path(directory: str | Path, finding: dict) -> Path:
    digest = hashlib.sha256(finding["url"].encode()).hexdigest()[:16]
    slug = _SLUG_RE.sub("-", (finding.get("title") or "").lower()).strip("-")[:40].strip("-")
    day = finding["published"][:10]
    return Path(directory) / day / f"{digest}-{slug}.json" if slug else Path(directory) / day / f"{digest}.json"


def _write_atomic(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_finding(directory: str | Path, finding: dict) -> Path:
    """Write the artifact with MISP status "pending"; returns its path."""
    path = artifact_path(directory, finding)
    document = {"schema": SCHEMA, **finding, "misp": {"status": "pending"}}
    document["written_at"] = datetime.now(timezone.utc).isoformat()
    _write_atomic(path, document)
    return path


def record_misp_result(path: Path, **misp_fields) -> None:
    """Update the artifact's `misp` block, e.g. status="created", event_uuid=..."""
    document = json.loads(path.read_text(encoding="utf-8"))
    document["misp"] = {**misp_fields, "recorded_at": datetime.now(timezone.utc).isoformat()}
    _write_atomic(path, document)
