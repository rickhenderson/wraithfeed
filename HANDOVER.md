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

Date filter `published >= now - 30d` applied in code at stage 1. Do not rely on
the model to judge recency.

---

## Module layout (proposed — adjust to fit existing repo conventions)

| Module | Responsibility |
|---|---|
| `collectors/feeds.py` | RSS/Atom poll, date filter, emit `FeedItem` |
| `collectors/structured.py` | ThreatFox / MalwareBazaar / URLhaus / KEV clients |
| `store/seen.py` | SQLite dedupe on `sha256(url)`, plus run log |
| `extract/article.py` | trafilatura or readability → clean text + tables |
| `extract/iocs.py` | regex candidates, defang normalization, indexing |
| `llm/triage.py` | binary relevance call |
| `llm/structure.py` | main extraction call, returns raw JSON |
| `validate/schema.py` | pydantic model for the extraction schema |
| `validate/indicators.py` | index resolution, type/value match, warninglist check |
| `misp/writer.py` | PyMISP event/object/attribute construction, dedupe-on-write |
| `cli.py` | `run`, `--dry-run`, `--since`, `--source`, `--limit` |

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

## Open items

- MITRE technique extraction quality is unverified. May need a constrained
  vocabulary list injected into the prompt rather than free-form `Txxxx`.
- No decision yet on handling articles that cover multiple distinct campaigns.
  Current schema assumes one event per article.
- Retention/aging policy for events not reviewed within N days.
- Whether to auto-tag by sector/region galaxy or leave those as plain tags.