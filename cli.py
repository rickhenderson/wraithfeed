"""Pipeline entry point.

Chains stages 1-2-4-5 (collect -> dedupe -> fetch -> candidates). Stages
3, 6, 7, 8 (triage/structure LLM calls, validation, MISP write) don't
exist yet, so `run` is dry-run-only for now: it prints one JSON object per
newly-seen article with its extracted IOC candidates and does not write
anywhere but the seen-store.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from collectors.feeds import SOURCES, FeedFetchError, poll_feed
from extract.article import ArticleFetchError, fetch_article
from extract.iocs import extract_candidates
from store.seen import RunStats, SeenStore

DEFAULT_DB_PATH = "data/wraithfeed.db"


def run(
    *,
    db_path: str = DEFAULT_DB_PATH,
    source: str | None = None,
    since_days: int = 30,
    limit: int | None = None,
    dry_run: bool = True,
    out=sys.stdout,
) -> int:
    """Run one pass of collect -> dedupe -> fetch -> candidates.

    Returns the number of articles processed (successfully or not).
    """
    sources = {source: SOURCES[source]} if source else SOURCES
    processed_count = 0

    with SeenStore(db_path) as store:
        for name, feed_url in sources.items():
            if not feed_url:
                continue

            try:
                items = poll_feed(feed_url, name, max_age_days=since_days)
            except FeedFetchError as exc:
                print(f"[cli] {exc}", file=sys.stderr)
                store.log_run(RunStats(source=name, collected=0, processed=0, failed=1))
                continue

            collected = len(items)
            processed = 0
            failed = 0

            for item in items:
                if limit is not None and processed_count >= limit:
                    break
                if store.is_seen(item.url):
                    continue

                store.mark_pending(item.url)
                try:
                    article = fetch_article(item.url)
                except ArticleFetchError as exc:
                    print(f"[cli] {exc}", file=sys.stderr)
                    store.mark_failed(item.url)
                    failed += 1
                    continue

                candidates = extract_candidates(article.text)

                result = {
                    "source": name,
                    "url": item.url,
                    "title": article.title or item.title,
                    "published": item.published.isoformat(),
                    "candidate_count": len(candidates),
                    "candidates": [asdict(c) for c in candidates],
                }
                print(json.dumps(result), file=out)

                store.mark_processed(item.url)
                processed += 1
                processed_count += 1

            store.log_run(RunStats(source=name, collected=collected, processed=processed, failed=failed))

            if limit is not None and processed_count >= limit:
                break

    return processed_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wraithfeed")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="collect, fetch, and extract candidates")
    run_parser.add_argument("--db", default=DEFAULT_DB_PATH, help="path to the seen-store SQLite DB")
    run_parser.add_argument("--source", choices=sorted(SOURCES), help="restrict to a single source")
    run_parser.add_argument("--since", type=int, default=30, help="max article age in days")
    run_parser.add_argument("--limit", type=int, default=None, help="max articles to process this run")
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="no-op for now; every run is a dry-run until the MISP write stage exists",
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        count = run(
            db_path=args.db,
            source=args.source,
            since_days=args.since,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        print(f"[cli] processed {count} new article(s)", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
