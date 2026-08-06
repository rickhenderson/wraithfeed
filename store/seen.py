"""SQLite dedupe store and run log.

No LLM involved. Tracks which article URLs have already been processed
(keyed by sha256(url), per HANDOVER.md) and records per-run stats. A single
sqlite3 connection per invocation is enough — this runs unattended on a
schedule, not as a long-lived server.

# Written by Claude Code for Rick Henderson 2026.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (
    url_hash TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    source TEXT NOT NULL,
    collected INTEGER NOT NULL,
    processed INTEGER NOT NULL,
    failed INTEGER NOT NULL
);
"""

STATUS_PENDING = "pending"
STATUS_PROCESSED = "processed"
STATUS_FAILED = "failed"


def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RunStats:
    source: str
    collected: int
    processed: int
    failed: int


class SeenStore:
    """Dedupe + run-log store backed by SQLite.

    Usage:
        with SeenStore(db_path) as store:
            if not store.is_seen(url):
                ...
                store.mark_processed(url)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = Path(db_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def __enter__(self) -> "SeenStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def is_seen(self, url: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM seen WHERE url_hash = ?", (_hash_url(url),)
        ).fetchone()
        return row is not None

    def mark_pending(self, url: str) -> None:
        """Record that a URL has been picked up for processing."""
        now = _now()
        self.conn.execute(
            """
            INSERT INTO seen (url_hash, url, status, retry_count, first_seen_at, updated_at)
            VALUES (?, ?, ?, 0, ?, ?)
            ON CONFLICT(url_hash) DO UPDATE SET updated_at = excluded.updated_at
            """,
            (_hash_url(url), url, STATUS_PENDING, now, now),
        )
        self.conn.commit()

    def mark_processed(self, url: str) -> None:
        self.conn.execute(
            "UPDATE seen SET status = ?, updated_at = ? WHERE url_hash = ?",
            (STATUS_PROCESSED, _now(), _hash_url(url)),
        )
        self.conn.commit()

    def mark_failed(self, url: str) -> None:
        """Mark a URL as failed and increment its retry counter.

        Per HANDOVER.md, a single article's failure must not abort the run —
        callers should catch per-article exceptions and call this instead.
        """
        self.conn.execute(
            """
            UPDATE seen
            SET status = ?, retry_count = retry_count + 1, updated_at = ?
            WHERE url_hash = ?
            """,
            (STATUS_FAILED, _now(), _hash_url(url)),
        )
        self.conn.commit()

    def retry_count(self, url: str) -> int:
        row = self.conn.execute(
            "SELECT retry_count FROM seen WHERE url_hash = ?", (_hash_url(url),)
        ).fetchone()
        return row[0] if row else 0

    def log_run(self, stats: RunStats) -> None:
        self.conn.execute(
            """
            INSERT INTO run_log (started_at, source, collected, processed, failed)
            VALUES (?, ?, ?, ?, ?)
            """,
            (_now(), stats.source, stats.collected, stats.processed, stats.failed),
        )
        self.conn.commit()
