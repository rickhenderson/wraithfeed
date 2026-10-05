# Wraithfeed 

```ASCII
                                               .         s                                                   ..       
  x=~                                         @88>      :8      .uef^"       oec :                         dF         
 88x.   .e.   .e.     .u    .                 %8P      .88    :d88E         @88888                        '88bu.      
'8888X.x888:.x888   .d88B :@8c        u        .      :888ooo `888E         8"*88%       .u         .u    '*88888bu   
 `8888  888X '888k ="8888f8888r    us888u.   .@88u  -*8888888  888E .z8k    8b.       ud8888.    ud8888.    ^"*8888N  
  X888  888X  888X   4888>'88"  .@88 "8888" ''888E`   8888     888E~?888L  u888888> :888'8888. :888'8888.  beWE "888L 
  X888  888X  888X   4888> '    9888  9888    888E    8888     888E  888E   8888R   d888 '88%" d888 '88%"  888E  888E 
  X888  888X  888X   4888>      9888  9888    888E    8888     888E  888E   8888P   8888.+"    8888.+"     888E  888E 
 .X888  888X. 888~  .d888L .+   9888  9888    888E   .8888Lu=  888E  888E   *888>   8888L      8888L       888E  888F 
 `%88%``"*888Y"     ^"8888*"    9888  9888    888&   ^%888*    888E  888E   4888    '8888c. .+ '8888c. .+ .888N..888  
   `~     `"           "Y"      "888*""888"   R888"    'Y"    m888N= 888>   '888     "88888%    "88888%    `"888*""   
                                 ^Y"   ^Y'     ""              `Y"   888     88R       "YP'       "YP'        ""      
                                                                    J88"     88>                                      
                                                                    @%       48                                       
                                                                  :"         '8                                       
```

`Wraithfeed` is an autonomous threat intelligence pipeline that ingests CVE/KEV and malware feeds, scores and prioritizes findings, generates analyst-ready briefings, and pushes structured events to MISP. Built for lean security teams who need signal, not noise, from the threat landscape. 👻📡

Created: August 5, 2026

* Initially a portfolio piece
* You can also take a look at my SBOM scanning vulnerability tool called [KEVScan](https://kevscan.cloud/) which may have a minimal level of external functionality.

* 

## Features

* Extracts IOCs from a test article: 20260805
* Stage 6 and save to MISP tested successful: 20261004


## Try it in one command

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
python cli.py demo
```

The demo replays one saved article through every stage with **no network, no model server and no MISP**. It writes the MISP event it would create to `demo_output/`. The model response and warninglist hits it uses are recordings of real runs (`scripts/record_demo.py` regenerates them); everything else is the real pipeline code. It also shows what happens when a model misbehaves:

```text
Stage 5  candidates 27 indicator-shaped strings found by regex, numbered; the model may only cite these numbers:
           [10] domain    npm-cache.com
           [16] ip-dst    104.21.91.101
           ...
Stage 6  structure  ...the model's indicator entries carry an index, never a value:
           idx 10 -> domain, c2, to_ids=true
           idx 16 -> ip-dst, c2, to_ids=true
Stage 7  validate   code resolves each index to its value and applies the warninglists:
           [10] npm-cache.com                  to_ids=true
           [16] 104.21.91.101                  to_ids=false   <- warninglist: List of known Cloudflare IP ranges
         2 indicator(s) the model marked to_ids=true were forced to false by a warninglist hit.

         Malformed model output is discarded, never repaired. Same response, tampered:
           model cites an index that was never offered (idx 999)
             -> rejected: unknown candidate idx 999 (have 27)
           model adds an indicator value of its own ("value": "evil.example")
             -> rejected: schema violation: indicators.0.value: Extra inputs are not permitted
           model wraps the JSON in prose
             -> rejected: output is not a bare JSON object (prose or fences around it)
```

## What works today, and what doesn't

The one-paragraph description above is the goal. This is the state of the code:

| Built and tested | Not built yet |
|---|---|
| RSS/Atom collection for 4 sources (The DFIR Report, Unit 42, Wiz Cloud Threat Landscape, SANS ISC), 30-day filter in code | Feeds for the other vendors (Talos, Securelist, Elastic, Sekoia, MSTIC, ESET, Huntress, Trend Micro, Proofpoint, Red Canary) |
| SQLite dedupe, retry counter (3 attempts), run log | Structured feeds: ThreatFox, MalwareBazaar, URLhaus, CISA KEV. **CVE/KEV ingestion does not exist yet** |
| Triage, article fetch, regex IOC candidates, LLM structuring, validation, MISP write | Scoring/prioritisation and analyst briefings |
| `--dry-run` (default) and `--write`, one JSON artifact per finding | Scheduling (cron/systemd), per-source rate limiting and backoff |
| Offline demo mode | Handling articles that cover several campaigns (one event per article today) |

## How it works

```text
 feeds ──► 1 collect ──► 2 dedupe ──► 3 triage ──► 4 fetch ──► 5 candidates
           RSS/Atom      SQLite       small LLM    safe GET    regex IOCs,
           30-day cut    sha256(url)  YES/NO       + trafilatura  numbered
                                                                  │
                                                                  ▼
 MISP ◄── 8 write ◄── 7 validate ◄── 6 structure ◄───────────────┘
 unpublished  event     schema, idx→value,   LLM: article + numbered list
 + JSON       builder   warninglists,        → JSON that cites indices
 artifact               ATT&CK check

 LLM stages: 3 and 6 only. Everything else is deterministic code.
```

Each article is processed on its own, one model call per stage, with no state shared between articles. A failure on one article is logged, counted and skipped; it never aborts the run (except when the cause would hit every article, such as a bad API key or an unreachable MISP).

### Why indicators are referenced by index

LLM-assisted CTI has one failure mode that matters more than the rest: a hash that is one character wrong, a transposed IP, a truncated domain. A wrong indicator in a MISP event that feeds a blocklist is worse than a missing one.

So the model never writes an indicator. Code extracts candidates from the article with regex, numbers them, and shows the model the list. The model may only say "candidate 12 is a C2 domain, `to_ids` true". Code turns the index back into the value. If the model cites an index it wasn't given, adds a `value` field, or wraps its answer in prose, stage 7 discards the whole output. It is never repaired by a second model call. The demo above shows all three cases being rejected.

Related rules, all enforced in code:
- A warninglist hit forces `to_ids=false`, whatever the model said. If the warninglists can't be consulted, the run stops instead of silently clearing everything for IDS.
- Structured feeds bypass the LLM entirely (once built); there is nothing for a model to add to an already-structured record.
- Every event is written with `published=False`, org-only distribution. No code path publishes.

### ATT&CK techniques come from the article, not the model

Techniques are the one thing in an event a model can't be trusted with, because a wrong *valid* technique id looks right. In a test, constraining the model to real ATT&CK ids made it return valid ids that had nothing to do with its own supporting evidence (DGA and Fast Flux for a PHP web-shell chain). So the model isn't asked for them.

Instead `extract/techniques.py` finds ids the article cites (`T1059.001`, or `attack.mitre.org/techniques/T1059/001/`), and stage 7 keeps those that are *current* in `validate/data/attack_techniques.json`, with the article's own sentence as evidence. Cited ids that are revoked, deprecated or unknown are dropped and reported. The list is generated from MISP's `mitre-attack-pattern` galaxy (`scripts/update_attack_techniques.py`); 201 of its 1,222 entries are revoked, including all of `T1562`.

The trade-off is coverage. Techniques an article only *describes* are not tagged. A DFIR Report article cited 38 current ids; Unit 42 posts and older DFIR pages cite none. The planned upgrade is to have the model pick technique *names* from a list and let code resolve them to ids.

## Running it for real

Copy `.env.example` to `.env` and fill it in. The main settings:

| Variable | Purpose |
|---|---|
| `MISP_URL`, `MISP_KEY`, `MISP_VERIFY_CERT` | Your MISP. Needed for warninglists and for `--write` |
| `WRAITHFEED_TRIAGE_PROVIDER` / `_MODEL` / `_BASE_URL` | Triage backend: `anthropic`, `openai`, `openrouter`, `local` or `ollama` |
| `WRAITHFEED_STRUCTURE_PROVIDER` / `_MODEL` | Same, for stage 6. `_NUM_CTX` (Ollama) and `_TIMEOUT` are also per stage |
| `WRAITHFEED_ARTIFACT_DIR` | Where `--write` saves finding artifacts (default `data/findings`) |
| `DB_PATH` | The seen-store (default `data/wraithfeed.db`) |

```bash
# Dry run (the default): print the proposed events as JSON, write nothing but the seen-store
python cli.py run --source "The DFIR Report" --since 365 --limit 2

# Write unpublished events to MISP and save a JSON artifact for each
python cli.py run --source "The DFIR Report" --since 365 --limit 2 --write
```

`--limit` applies per source. Stage 7 needs MISP's warninglists enabled (they ship disabled; the pipeline refuses to run with all of them off).

### What a finding looks like

Each finding written to MISP is also saved as a standalone JSON file, before the MISP call and updated after it. It holds the validated event with values resolved by code, the model's raw output, the models used, and what MISP did with it (`pending` → `created` / `exists` / `failed`). A trimmed example:

```json
{
  "event_info": "ChainDrop - npm worm - Unit 42 - 2026-08-04",
  "malware_families": ["ChainDrop"],
  "attack_patterns": [
    {"technique_id": "T1059.007", "evidence": "...plant .claude and .vscode persistence, and exfiltrate..."},
    {"technique_id": "T1528", "evidence": "...authentication token, used for repository persistence..."}
  ],
  "indicators": [
    {"idx": 10, "type": "domain", "value": "npm-cache.com", "role": "c2", "to_ids": true, "warninglist_hits": []},
    {"idx": 16, "type": "ip-dst", "value": "104.21.91.101", "role": "c2", "to_ids": false,
     "warninglist_hits": ["List of known Cloudflare IP ranges"]}
  ]
}
```

### In MISP

A live run against a local MISP 2.5.40 (an article from The DFIR Report, 2026-06-29) created one event, read back and compared with its artifact. It was unpublished with org-only distribution. Its 11 indicators matched the artifact's values and `to_ids` flags exactly, as `domain-ip` objects. Its 38 ATT&CK galaxy tags resolved to 38 Attack Pattern clusters. One address inside GitHub's published ranges came back with `to_ids` false from the warninglists. Re-running the same article reported `exists` and created nothing.

Event tags: `tlp:clear`, `source:<domain>`, `wraithfeed:review="pending"`, `misp-galaxy:mitre-attack-pattern=...`, `estimative-language:confidence-in-analytic-judgement=...` and plain `wraithfeed:malware-family|threat-actor|sector|region` tags. The `tlp` and `estimative-language` taxonomies are disabled on that instance, so those two show as plain tags until enabled. Confidence uses the *confidence* predicate on purpose: high/moderate/low is confidence, and mapping it onto likelihood words would turn "low confidence" into "unlikely".

## Choosing the models

Triage is a cheap YES/NO filter on the feed title and summary, so a small local model is enough. I labelled 40 live feed items (`tests/fixtures/triage_labeled.json`, 23 YES, 6 flagged borderline) and compared the production prompt on `llama3.2:3b` with `tev1:4b`, a small "decision model" that scores a yes/no question as a probability (`scripts/bench_triage.py` reproduces this; it needs both models in Ollama 0.35+):

| Model | All 40 | False pos. | False neg. | Excl. borderline (34) | FP | FN |
|---|---|---|---|---|---|---|
| `llama3.2:3b` (production prompt) | 33/40 | 6 | 1 | 31/34 | 2 | 1 |
| `tev1:4b`, threshold 0.5 | 38/40 | 2 | 0 | 33/34 | 1 | 0 |

Median warm latency was 37 ms for llama and 170 ms for tev1. The labels are mine, from title and summary alone, on 40 items, and tev1's threshold was swept on the same set, so a gap of two to four items is not strong evidence. I kept `llama3.2:3b` because a false positive only costs one fetch and one stage 6 call (stage 7 still has to accept the output), while a decision model needs its own adapter. The sample skews toward campaigns because one source (Wiz) is all campaigns.

Stage 6 is harder. On a single test article, `llama3.2:3b` copied placeholder values from the prompt and was rejected by stage 7; `qwen3.5` (9.7B, Q4_K_M, roughly 45 to 70 seconds a call on an 8 GB GPU) produced valid output. That is a smoke test, not a benchmark. Choosing the stage 6 model is open, and its output is still reviewed by a human before anything is published.

## Security notes

The pipeline fetches URLs from feeds and feeds the text to a model, so both are treated as untrusted:

- **Fetching:** only public `http(s)` hosts (private, loopback and link-local addresses are refused), every redirect is re-validated, downloads are capped at 5 MB, and article pages must be HTML. *Known gap:* the address check happens before the request, so DNS rebinding between check and connect isn't covered.
- **Parsing:** the IOC regexes have bounded repetition so a hostile page can't make extraction quadratic.
- **Model output:** strict schema (`extra="forbid"`, strict integer indices, duplicate JSON keys rejected, bare JSON only), then index and type resolution against the regex candidates. Article text is delimited and the prompt says it is data, not instructions. This reduces prompt-injection impact; it can't remove it, which is why the model can't introduce a value and a human reviews every event.
- **Writing:** unpublished, org-only events; deterministic event UUID per article URL; tag values sanitised; artifacts written atomically; secrets only from the environment (`.env` is git-ignored); `MISP_VERIFY_CERT` defaults to on.
- **Not covered yet:** per-source rate limiting and request backoff.

## Testing

```bash
venv/bin/python -m pytest
```

194 tests, none needing a network, model or MISP. They include golden-input tests for candidate extraction, deliberately malformed model output (invented values, out-of-range indices, prose wrappers, fences), the MISP writer against a fake client, and a test that fails if demo mode opens a socket. The writer has been run once against a live MISP, as described above; that run is not part of the suite.

## Project layout

```text
cli.py              run / demo entry point
collectors/         feeds (stage 1) and the safe HTTP client
store/              seen-store (stage 2) and per-finding JSON artifacts
extract/            article text (4), IOC candidates (5), cited ATT&CK ids
llm/                providers, triage (3), structure (6)
validate/           schema, index resolution, warninglists, ATT&CK list (7)
misp/               event builder and writer (8)
demo/               recorded inputs for `cli.py demo`
scripts/            benchmark, demo and ATT&CK list generators
HANDOVER.md         design rules, decisions and status in detail
```

## Future work

Remaining vendor feeds, the structured feeds (ThreatFox, MalwareBazaar, URLhaus, CISA KEV and advisories), scheduling and hosting, rate limiting and backoff, multi-campaign articles, an aging policy for unreviewed events, and mapping described behaviour (not just cited ids) to ATT&CK techniques. See `HANDOVER.md` for the full list.

# References

* [MalwareBazzar Community API](https://bazaar.abuse.ch/api/) (this is currently a portfolio project)

# Experiential Notes

* I learned how to use `pytest`.
* I learned more about Pythonisms like using `_` as a throw-away variable and using `type_` as a variable name to avoid confusion with the `type` keyword, but argued with Claude that `indicator_type` would be a better variable name. I'm ol' school.
* On the Claude Pro Plan it really doesn't cost anything extra if you're only coding for a couple of hours a day. It's a nice change from my Hermes Agent project which runs solely on API credits from a number of model providers.


