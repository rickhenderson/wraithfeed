# Malware Campaign Intel → MISP Ingestion Pipeline — Handover

## Purpose

Automated pipeline that collects recent (< 30 days) malware analysis publications,
extracts structured campaign intelligence and IOCs, and writes them into a local
MISP instance. Runs unattended on a schedule. A human reviews before publish.

This is a CTI tooling project, not a chatbot. The LLM is one stage in a
deterministic pipeline, not the orchestrator.

---

## Core design rule (do not violate)

**The LLM never emits an indicator value as text.**

Code extracts IOC candidates from article text via regex and presents them as a
numbered list. The LLM may only reference candidates *by index*, assign a type,
role, and comment. Code resolves indices back to values before anything touches
MISP.

Rationale: eliminates hallucinated, transposed, or truncated hashes — the single
highest-impact failure mode in LLM-assisted CTI.

Corollary rules:
- Any LLM output that fails JSON schema validation is discarded, not repaired by
  a second LLM call. Log and move on.
- Structured feeds (ThreatFox, MalwareBazaar, URLhaus, CISA KEV) bypass the LLM
  entirely. They are already structured; adding a model only adds risk.
- `published=False` on every event written. Human review gate is mandatory.

---

## Pipeline stages

```
1. collect      RSS/Atom poll + structured feed poll        (no LLM)
2. dedupe       SQLite seen-table on sha256(url)            (no LLM)
3. triage       "is this a technical malware analysis?"     (local/cheap LLM, YES/NO)
4. fetch        full article text extraction                (no LLM)
5. candidates   regex IOC extraction + defang normalization (no LLM)
6. structure    article + candidates → strict JSON          (API LLM)
7. validate     schema check, type/value match, warninglists(no LLM)
8. write        PyMISP event/object/attribute creation      (no LLM)
```

Each article is processed independently, one per LLM context window. No
cross-article state in the model.

---

## Source list

**Structured (direct to MISP, no LLM):**
- ThreatFox API
- MalwareBazaar
- URLhaus
- CISA KEV + CISA advisories

**Narrative (require stages 3–7):**
The DFIR Report, Unit 42, Cisco Talos, Securelist, Elastic Security Labs,
Sekoia, Microsoft MSTIC, ESET Research, Huntress, Trend Micro, Proofpoint,
Red Canary.

Feed URLs actually wired into `collectors/feeds.py`'s `SOURCES` so far:
Unit 42 (`unit42.paloaltonetworks.com/feed/` — note: separate from the
`live.paloaltonetworks.com` community-forum page, which 403s bots), The
DFIR Report (`thedfirreport.com/feed/`), and two sources not in the
original list above but added for extra coverage: Wiz Cloud Threat
Landscape and SANS ISC. The remaining vendors in the list still have empty
URLs in `SOURCES` — confirm/find their feeds before relying on them.

Date filter `published >= now - 30d` applied in code at stage 1. Do not rely on
the model to judge recency.

---

## Module layout (proposed — adjust to fit existing repo conventions)

| Module | Responsibility | Status |
|---|---|---|
| `collectors/feeds.py` | RSS/Atom poll, date filter, emit `FeedItem` | done |
| `collectors/structured.py` | ThreatFox / MalwareBazaar / URLhaus / KEV clients | not started |
| `store/seen.py` | SQLite dedupe on `sha256(url)`, plus run log | done |
| `extract/article.py` | trafilatura → clean text + tables | done |
| `extract/iocs.py` | regex candidates, defang normalization, indexing | done |
| `llm/triage.py` | binary relevance call | done |
| `llm/structure.py` | main extraction call, returns raw JSON | not started |
| `validate/schema.py` | pydantic model for the extraction schema | done |
| `validate/indicators.py` | index resolution, type/value match, warninglist check | done (not yet wired into `cli.py`; needs stage 6) |
| `misp/writer.py` | PyMISP event/object/attribute construction, dedupe-on-write | not started |
| `cli.py` | `run`, `--dry-run`, `--since`, `--source`, `--limit` (per source) | wired for stages 1-2-3-4-5 only; every run is currently dry-run since there's no write stage yet |

Stages 1 (`collect`), 2 (`dedupe`), 3 (`triage`), 4 (`fetch`), and 5
(`candidates`) are chained end-to-end via `cli.py run` and have been
smoke-tested against live feeds/articles. Stages 6, 7, 8 (structure/validate/
MISP write) remain to be built — `cli.py`'s shape will need to change once
they exist.

### LLM providers (update 2026-09-24)

All model calls go through `llm/providers.py`, selected per stage by env var
(`WRAITHFEED_<STAGE>_PROVIDER` / `_MODEL` / `_BASE_URL`, falling back to
`WRAITHFEED_LLM_*`). Supported: `anthropic` (SDK), `openai`, `openrouter`,
`local` (any OpenAI-compatible server), `ollama`. Triage defaults to
`anthropic` / `claude-haiku-4-5` in code; that default was chosen on an old
laptop (3.7 GB RAM, no GPU). The current dev machine has an RTX 3070 (8 GB VRAM)
and 24 GB RAM, so models up to ~6 GB (weights + KV cache) run fully on GPU.
Larger ones (e.g. an 8B Gemma 4 at 9.6 GB) spill to CPU and are very slow, and
ComfyUI holds ~17 GB RAM when running, so stop it before LLM work
(`systemctl --user stop comfyui`). Local `.env` runs triage on Ollama
`llama3.2:3b`: in a 2026-09-27 test on 28 hand-labeled feed items it scored
25/28 at ~170 ms/call with no false positives, vs 21/28 for
`qwen3.5-abliterated:4b` (7 false positives). Its 3 misses were SANS ISC items
whose feed summary is just `Introduction&#xd;`. The triage system prompt moved from the
Modelfile into `llm/triage.py`, so every provider gets it. The Ollama setup
below still works via `WRAITHFEED_TRIAGE_PROVIDER=ollama`.

### Triage (stage 3) — local model setup (original)

Triage uses a local Ollama model, not the commercial API model, per the
operational constraints below. It runs on the RSS `summary`/`description`
field plus title — *before* stage 4's fetch — so an irrelevant article
never costs a network fetch. This means `FeedItem` carries a `summary`
field (HTML-stripped) sourced straight from the feed entry, not from the
fetched article body.

The base `qwen3.5:latest` model, called directly with the literal prompt
text originally drafted for this stage ("...containing indicators?"),
produced false negatives: it required the snippet to literally list IOC
values (hashes/IPs) rather than judging topic relevance, and executive-
summary-style snippets almost never front-load raw indicators. Fixed by
building a custom Ollama model with a `SYSTEM` prompt that clarifies the
task is about topic, not indicator-presence-in-snippet, and pins
`temperature 0` + disables "thinking" mode (which otherwise burns ~1500
tokens and ~24s per YES/NO call on this model).

This custom model is a local Ollama artifact, not a pip dependency — it
won't exist on a fresh machine until rebuilt:

```
ollama create wraithfeed-triage -f llm/Modelfile.triage
```

`llm/triage.py` defaults to calling `wraithfeed-triage` at
`http://localhost:11434`. Requires Ollama running locally with that model
built (or `DEFAULT_MODEL`/`DEFAULT_OLLAMA_URL` overridden at the call site).

`extract/article.py` extraction quality is source-dependent: it works
cleanly on Unit 42 (WordPress) but produced nav boilerplate instead of
article text on a SANS ISC diary page — a known gap to account for when the
LLM stages are wired in, not yet fixed.

114/114 tests passing (`pytest`). New deps since project start: `feedparser`,
`trafilatura`, `pydantic` (pinned in `requirements.txt`).

---

## Extraction schema

```json
{
  "relevant": true,
  "event_info": "<Actor/Malware> - <campaign> - <source domain> - <YYYY-MM-DD>",
  "malware_families": ["..."],
  "threat_actors": ["..."],
  "attribution_confidence": "high|moderate|low",
  "targeted_sectors": ["..."],
  "targeted_regions": ["..."],
  "first_seen": "YYYY-MM-DD or null",
  "summary": "<= 60 words, factual",
  "attack_patterns": [{"technique_id": "Txxxx.xxx", "evidence": "paraphrase"}],
  "cves": ["CVE-YYYY-NNNNN"],
  "indicators": [
    {
      "idx": 12,
      "type": "sha256|md5|sha1|ip-dst|domain|hostname|url|email-src|filename|mutex|btc|registry-key|user-agent",
      "role": "c2|payload_delivery|dropper|loader|final_payload|persistence|exfil|unknown",
      "comment": "short context from article",
      "to_ids": true
    }
  ]
}
```

Irrelevant articles return `{"relevant": false, "reason": "..."}` and nothing else.

Enforce this with pydantic. Reject on: unknown `idx`, type mismatch against the
resolved candidate value, missing required fields, prose outside the JSON body.

As implemented in `validate/` (2026-09-27):
- Required: `relevant`, `event_info`, `summary`, `indicators`. Other lists
  default to empty; `attribution_confidence` and `first_seen` may be null.
- Also rejected: any unknown field (so a model can't add a `value`), non-integer
  `idx` (`"3"`, `3.0`, `true`), the same `idx` twice, duplicate JSON keys, bad
  CVE/technique ids, `first_seen` in the future.
- A regex `domain` candidate may be reported as `domain` or `hostname`; types
  the regex never produces (`filename`, `mutex`, `user-agent`) can't match.
- `validate_output()` raises `ExtractionRejected` (discard the article) or
  `WarninglistUnavailable` (MISP down or every list disabled: retry later).
  Warninglists are checked on the value and, for URLs/emails, the host too.
- The two "VPN providers and datacenters" lists are advisory
  (`ADVISORY_LISTS`): hits are recorded but don't force `to_ids=False`, since
  they cover whole hosting ranges where most attacker C2 lives.
- All 125 warninglists were enabled on the local MISP on 2026-09-27; they
  ship disabled. Enable them via `POST /warninglists/toggleEnable` with
  `{"id": [...], "enabled": 1}` (`enableWarninglist` errors on MISP 2.5.40).

---

## Extraction prompt (current version — treat as the reference implementation)

```
You are a CTI analyst assistant. You process ONE malware analysis article
and return STRICT JSON. No prose, no markdown fences.

You are given:
- ARTICLE_TEXT
- CANDIDATES: a numbered list of strings mechanically extracted from the
  article. Every indicator you report MUST be referenced by its index.
  You may NOT write an indicator value yourself. If a value is not in
  CANDIDATES, it does not exist.

Rules:
- Only report indicators the article attributes to ATTACKER infrastructure,
  tooling, or samples. Exclude vendor domains, sandbox URLs, reference links,
  legitimate services (unless the article explicitly states abuse), and
  indicators quoted from OTHER older campaigns.
- If the article is not a malware/intrusion analysis, return
  {"relevant": false, "reason": "<short>"} and nothing else.
- Confidence uses estimative language: high | moderate | low.
- Do not infer attribution not stated in the text. Empty is better than wrong.

Output schema:
<schema as above>

Set to_ids=false for anything shared/legitimate infrastructure, parked
domains, or values the article marks as non-actionable.
```

Triage prompt, run on title + first 500 characters:

```
Return only YES or NO — is this a technical analysis of a specific malware
family, intrusion, or campaign, containing indicators?
```

---

## MISP writing conventions

- Prefer MISP **objects** over loose attributes: `file`, `url`, `domain-ip`,
  `network-connection`. Better correlation and cleaner exports.
- Event tags: `tlp:clear`, `source:<domain>`,
  `estimative-language:likelihood-probability="..."`, plus
  `misp-galaxy:mitre-attack-pattern="..."` per extracted technique.
- Source article added as a `link` attribute with `to_ids=False`.
- Dedupe before add: `misp.search(controller='attributes', value=val)`. If an
  event already exists for that article URL hash, update rather than create.
- Run every candidate through the MISP warninglists before setting `to_ids=True`.
  A warninglist hit forces `to_ids=False` regardless of what the model said.
- `published=False`. Always.

---

## Operational constraints

- Runs on a consumer desktop under a scheduled trigger (cron/systemd timer), not
  interactively.
- Triage stage should use a small local model to keep API spend down. Extraction
  uses a commercial API model. Expected volume ~10–20 articles/day at roughly
  8k tokens each.
- Failure of any single article must not abort the run. Log, mark the URL as
  attempted-failed with a retry counter, continue.
- Network calls need backoff and a per-source rate limit. Several of these
  vendors will throttle.

---

## Testing expectations

- Golden-file tests: a handful of saved article HTML fixtures with expected
  candidate lists. Regex extraction must be tested without any LLM in the loop.
- Schema validation tests using deliberately malformed model output — invented
  indicator values, out-of-range indices, prose wrappers, markdown fences.
- MISP writer tested against a throwaway event, or mocked PyMISP, never against
  the live dataset.
- `--dry-run` must emit proposed MISP events as JSON to stdout/file without any
  write. This is the primary review mechanism for the first weeks of operation.

---

## Environment — confirm before assuming

The following are **not** documented here on purpose. Ask before writing code
that depends on them:

- MISP instance URL, auth key handling, and whether TLS verification is on
- Python version, virtualenv/uv/poetry, and existing repo layout
- Where secrets live (env file, keyring, other)
- Which API provider and model are actually in use for the extraction stage
- Which local model/runtime serves the triage stage, and on what endpoint
- Scheduler in use and how logs are collected
- Whether this lives in an existing repo or is a greenfield project

Do not infer running services, ports, paths, or hardware from anything in this
document.

---

## Definition of done (portfolio scope, set 2026-09-27)

Wraithfeed is a portfolio piece that only needs to run locally. It is done
when a reviewer can clone it, run one command, and watch an article become a
reviewed, unpublished MISP event, with the index-only indicator design visible.
Anything not on this list is out of scope; don't start it.

- [ ] Stage 6 `llm/structure.py`: one working prompt/model (local Ollama with
      JSON-schema `format`; API model optional for quality).
- [x] Stage 7 `validate/`: schema check, index resolution, warninglists, plus
      the malformed-output tests listed under Testing expectations.
- [ ] Stage 8 `misp/writer.py`: unpublished events only, behind an explicit
      `--write` flag; `--dry-run` emits the proposed event JSON.
- [ ] README: pipeline diagram, why index-only, triage benchmark, security
      hardening, sample dry-run output, screenshots of an event in MISP.
- [ ] Demo mode: a saved article fixture that runs end to end with no live
      feeds and no MISP instance.

Future work (list in the README, don't build): remaining vendor feeds,
structured feeds (ThreatFox, MalwareBazaar, URLhaus, CISA KEV), VPS/cloud
hosting, scheduling, and everything under Open items below.

---

## Open items

- MITRE technique extraction quality is unverified. May need a constrained
  vocabulary list injected into the prompt rather than free-form `Txxxx`.
- No decision yet on handling articles that cover multiple distinct campaigns.
  Current schema assumes one event per article.
- Retention/aging policy for events not reviewed within N days.
- Whether to auto-tag by sector/region galaxy or leave those as plain tags.
- Remaining narrative vendor feed URLs (Talos, Securelist, Elastic, Sekoia,
  MSTIC, ESET, Huntress, Trend Micro, Proofpoint) still need to be found and
  confirmed.