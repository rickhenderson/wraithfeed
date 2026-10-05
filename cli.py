"""Pipeline entry point.

Chains stages 1-8 (collect -> dedupe -> triage -> fetch -> candidates ->
structure -> validate -> write). By default `run` is a dry run: it prints one
JSON object per newly-seen, triage-relevant article with the proposed event
(indicators resolved from candidate indices to values by code) and writes
nothing but the seen-store. With `--write`, each finding is first saved as a
JSON artifact (store/artifacts.py), then created in MISP as an unpublished
event, and the artifact is updated with what MISP did.

An article whose model output fails validation is discarded and marked failed
(retry-counted); it is never repaired. A fatal model error, unavailable MISP
warninglists, or an unreachable MISP abort the run and release the article so
the next run retries it.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from dotenv import load_dotenv

from collectors.feeds import SOURCES, FeedFetchError, poll_feed
from extract.article import ArticleFetchError, fetch_article
from extract.iocs import extract_candidates
from extract.techniques import extract_techniques
from llm.providers import LLMError, get_provider
from llm.structure import StructureError, structure_article
from llm.triage import TriageError, is_relevant
from misp.writer import MispWriteError, MispWriter
from store import artifacts
from store.seen import RunStats, SeenStore
from validate.indicators import (
    MispWarninglists,
    ValidatedExtraction,
    Warninglist,
    WarninglistUnavailable,
    validate_output,
)
from validate.schema import ExtractionRejected

DEFAULT_DB_PATH = "data/wraithfeed.db"


def proposed_event(validated: ValidatedExtraction) -> dict:
    """The event stage 8 would write: model fields plus code-resolved indicator values."""
    event = validated.extraction.model_dump(mode="json", exclude={"indicators"})
    event["indicators"] = [
        {**asdict(i), "warninglist_hits": list(i.warninglist_hits)} for i in validated.indicators
    ]
    event["dropped_techniques"] = list(validated.dropped_techniques)
    return event


def run(
    *,
    db_path: str = DEFAULT_DB_PATH,
    source: str | None = None,
    since_days: int = 30,
    limit: int | None = None,
    dry_run: bool = True,
    warninglist: Warninglist | None = None,
    writer: MispWriter | None = None,
    artifact_dir: str = artifacts.DEFAULT_DIR,
    out=sys.stdout,
) -> int:
    """Run one pass of collect -> dedupe -> triage -> fetch -> structure -> validate [-> write].

    `warninglist` defaults to the MISP instance from the environment, created
    when the first relevant article needs it. With `dry_run=False`, `writer`
    defaults to the same instance and is created up front, so a missing or
    unreachable MISP fails the run before any model call is spent.

    Returns the number of articles processed (successfully or not).
    """
    sources = {source: SOURCES[source]} if source else SOURCES
    processed_count = 0
    if not dry_run and writer is None:
        writer = MispWriter.from_env()
    triage_provider = get_provider("triage")
    structure_provider = None

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
                if limit is not None and processed + failed >= limit:
                    break
                if not store.should_process(item.url):
                    continue

                store.mark_pending(item.url)

                try:
                    relevant = is_relevant(item.title, item.summary, provider=triage_provider)
                except TriageError as exc:
                    if exc.fatal:
                        store.release(item.url)
                        store.log_run(RunStats(source=name, collected=collected, processed=processed, failed=failed))
                        raise
                    print(f"[cli] {exc}", file=sys.stderr)
                    store.mark_failed(item.url)
                    failed += 1
                    processed_count += 1
                    continue

                if not relevant:
                    store.mark_processed(item.url)
                    processed += 1
                    processed_count += 1
                    continue

                try:
                    article = fetch_article(item.url)
                except ArticleFetchError as exc:
                    print(f"[cli] {exc}", file=sys.stderr)
                    store.mark_failed(item.url)
                    failed += 1
                    processed_count += 1
                    continue

                candidates = extract_candidates(article.text)

                try:
                    structure_provider = structure_provider or get_provider("structure")
                    warninglist = warninglist or MispWarninglists.from_env()
                    raw = structure_article(
                        item.title, item.url, article.text, candidates, provider=structure_provider
                    )
                    outcome = validate_output(raw, candidates, warninglist, extract_techniques(article.text))
                except (LLMError, StructureError, WarninglistUnavailable) as exc:
                    # Config or infrastructure problem, not this article's fault:
                    # every remaining article would fail the same way.
                    if isinstance(exc, WarninglistUnavailable) or exc.fatal:
                        store.release(item.url)
                        store.log_run(RunStats(source=name, collected=collected, processed=processed, failed=failed))
                        raise
                    print(f"[cli] {item.url}: {exc}", file=sys.stderr)
                    store.mark_failed(item.url)
                    failed += 1
                    processed_count += 1
                    continue
                except ExtractionRejected as exc:
                    print(f"[cli] discarded {item.url}: {exc}", file=sys.stderr)
                    store.mark_failed(item.url)
                    failed += 1
                    processed_count += 1
                    continue

                result = {
                    "source": name,
                    "url": item.url,
                    "title": article.title or item.title,
                    "published": item.published.isoformat(),
                    "candidate_count": len(candidates),
                }
                if isinstance(outcome, ValidatedExtraction):
                    if outcome.dropped_techniques:
                        print(f"[cli] {item.url}: dropped techniques {list(outcome.dropped_techniques)}", file=sys.stderr)
                    result["event"] = proposed_event(outcome)
                    if not dry_run:
                        finding = {
                            **result,
                            "pipeline": {
                                "triage": f"{triage_provider.name}/{triage_provider.model}",
                                "structure": f"{structure_provider.name}/{structure_provider.model}",
                            },
                            "model_output_raw": raw,
                        }
                        path = artifacts.write_finding(artifact_dir, finding)
                        try:
                            written = writer.write(finding)
                        except MispWriteError as exc:
                            artifacts.record_misp_result(path, status="failed", error=str(exc))
                            if exc.fatal:
                                store.release(item.url)
                                store.log_run(RunStats(source=name, collected=collected, processed=processed, failed=failed))
                                raise
                            print(f"[cli] {item.url}: {exc}", file=sys.stderr)
                            store.mark_failed(item.url)
                            failed += 1
                            processed_count += 1
                            continue
                        artifacts.record_misp_result(
                            path, status=written.outcome, event_uuid=written.event_uuid, event_id=written.event_id
                        )
                        result["misp"] = {"outcome": written.outcome, "event_uuid": written.event_uuid, "event_id": written.event_id}
                        result["artifact"] = str(path)
                else:
                    result["irrelevant"] = outcome.reason
                print(json.dumps(result), file=out)

                store.mark_processed(item.url)
                processed += 1
                processed_count += 1

            store.log_run(RunStats(source=name, collected=collected, processed=processed, failed=failed))

    return processed_count


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="wraithfeed")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="collect, triage, extract, validate, and optionally write MISP events")
    run_parser.add_argument("--db", default=DEFAULT_DB_PATH, help="path to the seen-store SQLite DB")
    run_parser.add_argument("--source", choices=sorted(SOURCES), help="restrict to a single source")
    run_parser.add_argument("--since", type=int, default=30, help="max article age in days")
    run_parser.add_argument("--limit", type=int, default=None, help="max articles to process per source this run")
    mode = run_parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print proposed events only (the default)")
    mode.add_argument(
        "--write",
        action="store_true",
        help="create unpublished MISP events and save each finding as a JSON artifact",
    )
    run_parser.add_argument(
        "--artifact-dir",
        default=os.environ.get("WRAITHFEED_ARTIFACT_DIR", artifacts.DEFAULT_DIR),
        help="where --write saves finding artifacts (env WRAITHFEED_ARTIFACT_DIR)",
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        try:
            count = run(
                db_path=args.db,
                source=args.source,
                since_days=args.since,
                limit=args.limit,
                dry_run=not args.write,
                artifact_dir=args.artifact_dir,
            )
        except (LLMError, TriageError, StructureError, WarninglistUnavailable, MispWriteError) as exc:
            print(f"[cli] aborting run: {exc}", file=sys.stderr)
            return 1
        print(f"[cli] processed {count} new article(s)", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
