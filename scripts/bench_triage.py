"""Benchmark triage models on tests/fixtures/triage_labeled.json.

Compares the production triage path (llm.triage.is_relevant on Ollama
llama3.2:3b) against tev1:4b via Ollama's /v1/systemone decision endpoint.
Scores are reported over all items and with the borderline-labelled items
excluded. Latency is the median of warm calls (one warm-up call first).

Usage: venv/bin/python scripts/bench_triage.py
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

import requests

from llm.providers import OllamaProvider
from llm.triage import SNIPPET_CHARS, TriageError, is_relevant

FIXTURE = Path(__file__).resolve().parent.parent / "tests/fixtures/triage_labeled.json"
OLLAMA_URL = "http://localhost:11434"
REPEATS = 3
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

QUESTION = (
    "Is the full article likely a technical writeup of a specific malware family, "
    "intrusion, or campaign (named malware/threat actor, an intrusion, or attacker "
    "tooling/infrastructure/behavior)? Judge the topic, not whether indicator values "
    "appear in this excerpt. Answer false for general security news, product "
    "announcements, opinion, policy, defensive research, or vulnerability notices "
    "with no malware/campaign/intrusion narrative."
)


def tev1_prob(title: str, text: str, model: str) -> float:
    state = f"TITLE: {title}\n\nTEXT: {text[:SNIPPET_CHARS]}"
    body = {"model": model, "state": state,
            "questions": {"relevant": {"type": "noul", "instructions": QUESTION}}}
    resp = requests.post(f"{OLLAMA_URL}/v1/systemone", json=body, timeout=120)
    resp.raise_for_status()
    return resp.json()["answers"]["relevant"]["noul"]


def score(preds: list[bool], items: list[dict]) -> dict:
    tp = sum(p and i["label"] == "YES" for p, i in zip(preds, items))
    tn = sum((not p) and i["label"] == "NO" for p, i in zip(preds, items))
    fp = sum(p and i["label"] == "NO" for p, i in zip(preds, items))
    fn = sum((not p) and i["label"] == "YES" for p, i in zip(preds, items))
    return {"acc": f"{tp + tn}/{len(items)}", "fp": fp, "fn": fn}


def report(name: str, preds: list[bool], items: list[dict]) -> None:
    keep = [k for k, i in enumerate(items) if not i["borderline"]]
    full = score(preds, items)
    clean = score([preds[k] for k in keep], [items[k] for k in keep])
    print(f"{name:<22} all {full['acc']:>5} fp={full['fp']} fn={full['fn']}"
          f" | excl. borderline {clean['acc']:>5} fp={clean['fp']} fn={clean['fn']}")


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t0) * 1000


def main() -> None:
    items = json.loads(FIXTURE.read_text())
    print(f"{len(items)} items, {sum(i['label'] == 'YES' for i in items)} YES, "
          f"{sum(i['borderline'] for i in items)} borderline\n")

    llama = OllamaProvider("llama3.2:3b", OLLAMA_URL, timeout=60)
    is_relevant("warm", "warm", provider=llama)
    llama_preds, llama_ms = [], []
    for _ in range(REPEATS):
        run = []
        for i in items:
            try:
                pred, ms = timed(lambda i=i: is_relevant(i["title"], i["summary"], provider=llama))
            except TriageError as exc:
                raise SystemExit(f"llama call failed: {exc}")
            run.append(pred)
            llama_ms.append(ms)
        llama_preds = run

    tev_probs, tev_ms = [], []
    tev1_prob("warm", "warm", "tev1:4b")
    for _ in range(REPEATS):
        probs = []
        for i in items:
            p, ms = timed(tev1_prob, i["title"], i["summary"], "tev1:4b")
            probs.append(p)
            tev_ms.append(ms)
        tev_probs = probs

    report("llama3.2:3b", llama_preds, items)
    for t in THRESHOLDS:
        report(f"tev1:4b  thr>={t}", [p >= t for p in tev_probs], items)

    print(f"\nmedian warm latency: llama3.2:3b {statistics.median(llama_ms):.0f} ms, "
          f"tev1:4b {statistics.median(tev_ms):.0f} ms")

    print("\nmisses (llama | tev1@0.5 prob):")
    for k, i in enumerate(items):
        lp, tp = llama_preds[k], tev_probs[k] >= 0.5
        want = i["label"] == "YES"
        if lp != want or tp != want:
            print(f" #{i['id']:>2} {i['label']:<3}{'*' if i['borderline'] else ' '} "
                  f"llama={'Y' if lp else 'N'} tev1={tev_probs[k]:.2f}  {i['title'][:60]}")


if __name__ == "__main__":
    main()
