"""Record the saved inputs that `cli.py demo` replays offline.

Runs the real stage 6 model call on the demo article and snapshots what the
MISP warninglists say about its candidates. Needs a running Ollama and a MISP
with warninglists enabled (MISP_URL / MISP_KEY). Re-run it only if the
extractor's candidate list changes (tests/test_demo.py will say so).

    venv/bin/python scripts/record_demo.py [--model qwen3.5:latest]

Writes demo/model_response.json (the model's raw output, untouched),
demo/warninglist_hits.json and demo/source.json.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from dotenv import load_dotenv

from demo.run import ARTICLE_HTML, DEMO_DIR, SOURCE, load_article
from extract.iocs import extract_candidates
from llm.providers import OllamaProvider
from llm.structure import structure_article
from validate.indicators import MispWarninglists, _lookup_keys, validate_output
from validate.schema import ExtractionRejected


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="qwen3.5:latest")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--num-ctx", type=int, default=12288)
    args = parser.parse_args()

    article = load_article()
    candidates = extract_candidates(article.text)
    warninglists = MispWarninglists.from_env()

    keys = sorted({k for c in candidates for k in _lookup_keys(c.type, c.value)})
    hits = warninglists.check(keys)
    (DEMO_DIR / "warninglist_hits.json").write_text(json.dumps(hits, indent=2, ensure_ascii=False) + "\n")

    provider = OllamaProvider(args.model, args.base_url, timeout=600, num_ctx=args.num_ctx)
    raw = structure_article(article.title, SOURCE["url"], article.text, candidates, provider=provider)
    try:
        validate_output(raw, candidates, warninglists)
    except ExtractionRejected as exc:
        print(f"model output rejected, nothing saved: {exc}")
        return 1
    (DEMO_DIR / "model_response.json").write_text(raw if raw.endswith("\n") else raw + "\n")

    (DEMO_DIR / "source.json").write_text(json.dumps(
        {
            **SOURCE,
            "article_file": str(ARTICLE_HTML.relative_to(DEMO_DIR.parent)),
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "structure_model": f"ollama/{args.model}",
            "num_ctx": args.num_ctx,
            "candidate_count": len(candidates),
        },
        indent=2,
    ) + "\n")
    print(f"recorded: {len(candidates)} candidates, {len(hits)} warninglist hits, model {args.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
