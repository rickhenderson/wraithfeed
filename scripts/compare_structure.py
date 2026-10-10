"""Compare stage 6 models on real articles (scripts/structure_corpus.json + the demo article).

The articles are fetched from their vendors on first use and cached under
data/structure_cache/ (gitignored: it is third-party text, not ours to commit).
Same prompt, same context, real stage 7 with the live MISP warninglists. One run per
article per model. Writes a markdown report (default data/structure_compare.md) with a
summary table and every accepted indicator, for hand review. Vendor pages change, so
a later fetch can differ from the one a report was made from.

    PYTHONPATH=. venv/bin/python scripts/compare_structure.py --models qwen3.5:latest llama3.2:3b
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from dotenv import load_dotenv

from demo.run import SOURCE, load_article
from extract.article import fetch_article
from extract.cves import extract_cves
from extract.iocs import extract_candidates
from extract.techniques import extract_techniques
from llm.providers import LLMError, OllamaProvider
from llm.structure import StructureError, structure_article
from validate.indicators import MispWarninglists, validate_output
from validate.schema import ExtractionRejected, Irrelevant

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "scripts/structure_corpus.json"
CACHE = ROOT / "data/structure_cache"


def load_corpus() -> list[dict]:
    demo = load_article()
    corpus = [{"name": "unit42_sample", "url": SOURCE["url"], "title": demo.title, "text": demo.text, "expected": "malware"}]
    CACHE.mkdir(parents=True, exist_ok=True)
    for entry in json.loads(CORPUS.read_text()):
        cached = CACHE / f"{entry['name']}.json"
        if not cached.exists():
            article = fetch_article(entry["url"])
            cached.write_text(json.dumps({"title": article.title, "text": article.text}, ensure_ascii=False))
        corpus.append({**entry, **json.loads(cached.read_text())})
    return corpus


def main() -> int:
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--base-url", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=12288)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", default="data/structure_compare.md")
    args = ap.parse_args()

    corpus = load_corpus()
    warninglists = MispWarninglists.from_env()
    rows, detail = [], []

    for model in args.models:
        provider = OllamaProvider(model, args.base_url, timeout=args.timeout, num_ctx=args.num_ctx)
        for art in corpus:
            candidates = extract_candidates(art["text"])
            t0 = time.perf_counter()
            status, note, n_ind, n_ids, n_wl = "", "", 0, 0, 0
            try:
                raw = structure_article(art["title"] or "", art["url"], art["text"], candidates, provider=provider)
                result = validate_output(
                    raw, candidates, warninglists, extract_techniques(art["text"]), extract_cves(art["text"])
                )
                if isinstance(result, Irrelevant):
                    status, note = "irrelevant", result.reason[:60]
                else:
                    status = "accepted"
                    n_ind = len(result.indicators)
                    n_ids = sum(i.to_ids for i in result.indicators)
                    n_wl = sum(bool(i.warninglist_hits) for i in result.indicators)
                    detail.append(f"\n### {model} / {art['name']}\n{result.extraction.event_info}\n")
                    for i in result.indicators:
                        wl = f" WL={list(i.warninglist_hits)}" if i.warninglist_hits else ""
                        detail.append(f"- [{i.idx}] {i.type} `{i.value}` {i.role} to_ids={i.to_ids}{wl} — {i.comment[:80]}")
            except ExtractionRejected as exc:
                status, note = "rejected", str(exc)[:80]
            except (StructureError, LLMError) as exc:
                status, note = "error", str(exc)[:80]
            secs = time.perf_counter() - t0
            rows.append((model, art["name"], art["expected"], len(candidates), status, n_ind, n_ids, n_wl, secs, note))
            print(f"{model:<36} {art['name']:<26} {status:<10} ind={n_ind:<3} ids={n_ids:<3} wl={n_wl:<2} {secs:5.1f}s {note}", flush=True)

    lines = ["# Stage 6 model comparison", "",
             f"num_ctx={args.num_ctx}, temperature 0, one run per article, real stage 7 + MISP warninglists.", "",
             "| model | article | expected | cands | result | ind | to_ids | wl hits | s | note |", "|---|---|---|---|---|---|---|---|---|---|"]
    lines += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | {r[6]} | {r[7]} | {r[8]:.1f} | {r[9]} |" for r in rows]
    lines += ["", "## Accepted indicators (for hand review)", *detail]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")
    print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
