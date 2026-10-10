"""Offline demo: one saved article through every stage, with no network.

`python cli.py demo` replays a saved article page, a recorded model response
and recorded warninglist hits (see scripts/record_demo.py for how they were
captured). Everything else is the real pipeline code: article extraction, regex
candidates, the stage 6 prompt, stage 7 validation and the MISP event builder.
Nothing is sent anywhere; the MISP event is written to a file for inspection.

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import json
from datetime import datetime
import sys
from pathlib import Path

from extract.article import Article, extract_article
from extract.iocs import extract_candidates
from extract.cves import extract_cves
from extract.techniques import extract_techniques
from llm.structure import fit_article, structure_article, visible_candidates
from misp.writer import build_event
from store import artifacts
from validate.indicators import ValidatedExtraction, proposed_event, validate_output
from validate.schema import ExtractionRejected

DEMO_DIR = Path(__file__).parent
ARTICLE_HTML = DEMO_DIR.parent / "tests/fixtures/sample_article_unit42.html"
SOURCE = {
    "source": "Unit 42",
    "url": "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/",
    "published": "2026-08-06T00:00:00+00:00",
}
DEFAULT_OUT = "demo_output"


def load_article() -> Article:
    return extract_article(ARTICLE_HTML.read_bytes(), SOURCE["url"])


class ReplayProvider:
    """Stands in for the stage 6 model: returns the recorded response."""

    name = "replay"

    def __init__(self, response: str, model: str):
        self.model = model
        self._response = response
        self.prompt = ""

    def complete(self, system: str, prompt: str, *, max_tokens: int, json_schema: dict | None = None) -> str:
        self.prompt = prompt
        return self._response


class ReplayWarninglist:
    """Stands in for MISP: answers from the hits recorded against the real warninglists."""

    def __init__(self, hits: dict[str, list[str]]):
        self._hits = hits

    def check(self, values: list[str]) -> dict[str, list[str]]:
        return {v: self._hits[v] for v in values if v in self._hits}


def _tampered_copies(raw: str) -> list[tuple[str, str]]:
    """Ways a model could break the index-only rule, each applied to the recorded response."""
    data = json.loads(raw)
    invented_idx = json.loads(raw)
    invented_idx["indicators"][0]["idx"] = 999
    smuggled = json.loads(raw)
    smuggled["indicators"][0]["value"] = "evil.example"
    return [
        ("cites an index that was never offered (idx 999)", json.dumps(invented_idx)),
        ('adds an indicator value of its own ("value": "evil.example")', json.dumps(smuggled)),
        ("wraps the JSON in prose", "Sure! Here is the analysis:\n" + json.dumps(data)),
    ]


def run_demo(out_dir: str = DEFAULT_OUT, out=None) -> int:
    stream = out or sys.stdout  # looked up per call so a redirected stdout is honoured

    def say(text: str = "") -> None:
        print(text, file=stream)

    source = json.loads((DEMO_DIR / "source.json").read_text())
    raw = (DEMO_DIR / "model_response.json").read_text()
    warninglist = ReplayWarninglist(json.loads((DEMO_DIR / "warninglist_hits.json").read_text()))

    say("wraithfeed demo: one saved article, replayed offline")
    say("(no network, no model server, no MISP; model response and warninglist hits are recorded)")
    say()

    article = load_article()
    say(f"Stage 4  article    {article.title}")
    say(f"                    {SOURCE['source']}, published {SOURCE['published'][:10]}, {len(article.text):,} characters extracted from saved HTML")

    candidates = extract_candidates(article.text)
    say()
    say(f"Stage 5  candidates {len(candidates)} indicator-shaped strings found by regex, numbered; the model may only cite these numbers:")
    for c in candidates:
        say(f"           [{c.idx:>2}] {c.type:<9} {c.value}")
    mentions = extract_techniques(article.text)
    cves = extract_cves(article.text)
    say(f"         CVE ids the article cites: {', '.join(cves) or 'none'}")
    say(f"         ATT&CK ids the article cites: {', '.join(m.technique_id for m in mentions) or 'none'}")

    provider = ReplayProvider(raw, source["structure_model"])
    returned = structure_article(article.title, SOURCE["url"], article.text, candidates, provider=provider)
    shown = visible_candidates(fit_article(article.text), candidates)
    say()
    say(f"Stage 6  structure  prompt = article text + {len(shown)} numbered candidates; recorded response from {source['structure_model']}")
    if len(shown) < len(candidates):
        say(f"                    ({len(candidates) - len(shown)} candidates sit in the part of the article cut to fit the model's context, so they were not offered;")
        say("                    numbers are never reassigned, so the ones shown keep their stage 5 numbers)")
    say("                    the model's indicator entries carry an index, never a value:")
    for ref in json.loads(returned)["indicators"]:
        say(f"           idx {ref['idx']:>2} -> {ref['type']}, {ref['role']}, to_ids={str(ref['to_ids']).lower()}")

    try:
        validated = validate_output(returned, candidates, warninglist, mentions, cves)
    except ExtractionRejected as exc:
        say()
        say(f"The recorded response no longer validates ({exc}).")
        say("The extractor changed; re-record with scripts/record_demo.py.")
        return 1
    if not isinstance(validated, ValidatedExtraction):
        say("The recorded response is an irrelevant verdict; re-record with scripts/record_demo.py.")
        return 1

    say()
    say("Stage 7  validate   code resolves each index to its value and applies the warninglists:")
    for ind in validated.indicators:
        note = f"   <- warninglist: {'; '.join(ind.warninglist_hits)}" if ind.warninglist_hits else ""
        say(f"           [{ind.idx:>2}] {ind.value[:62]:<62} to_ids={str(ind.to_ids).lower()}{note}")
    forced = [i for i in validated.indicators if i.warninglist_hits and not i.to_ids]
    if forced:
        say(f"         {len(forced)} indicator(s) the model marked to_ids=true were forced to false by a warninglist hit.")
    kept = ", ".join(p.technique_id for p in validated.extraction.attack_patterns) or "none"
    say(f"         techniques kept (cited by the article and current in ATT&CK): {kept}")

    say()
    say("         Malformed model output is discarded, never repaired. Same response, tampered:")
    for what, tampered in _tampered_copies(returned):
        try:
            validate_output(tampered, candidates, warninglist, mentions, cves)
        except ExtractionRejected as exc:
            say(f"           model {what}")
            say(f"             -> rejected: {str(exc)[:110]}")
        else:
            say(f"           model {what}\n             -> NOT rejected (this is a bug)")
            return 1

    event = proposed_event(
        validated, source_url=SOURCE["url"], published=datetime.fromisoformat(SOURCE["published"]).date()
    )
    finding = {
        **SOURCE,
        "title": article.title,
        "candidate_count": len(candidates),
        "event": event,
        "pipeline": {"structure": f"replay of {source['structure_model']} ({source['recorded_at']})"},
        "model_output_raw": returned,
    }
    misp_event = build_event(finding)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    event_file = out_path / "misp_event.json"
    # Wrapped in {"Event": ...} like a MISP export (not yet tried against MISP's import).
    event_file.write_text(json.dumps({"Event": json.loads(misp_event.to_json())}, indent=2) + "\n")
    artifact = artifacts.write_finding(out_path / "findings", finding)
    artifacts.record_misp_result(artifact, status="demo", note="built but not sent to MISP")

    d = misp_event.to_dict()
    say()
    say("Stage 8  write      built the MISP event but did not send it (demo mode never touches MISP):")
    say(f"           published={str(d['published']).lower()}, distribution=org-only, {len(d.get('Object', []))} objects, "
        f"{len(d.get('Attribute', []))} attributes, {len(d.get('Tag', []))} tags")
    say(f"           MISP event JSON   {event_file}")
    say(f"           finding artifact  {artifact}")
    say()
    say("To write real events: configure MISP_URL / MISP_KEY and a model, then `python cli.py run --write`.")
    return 0
