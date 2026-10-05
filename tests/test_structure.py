import json

import pytest

from extract.iocs import Candidate, extract_candidates
from llm import structure
from llm.providers import LLMError
from llm.structure import StructureError, build_prompt, response_schema, structure_article
from validate.indicators import StaticWarninglist, ValidatedExtraction, validate_output

# Written by Claude Code


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, answer: str = "", error: Exception | None = None):
        self._answer = answer
        self._error = error
        self.calls = []

    def complete(self, system, prompt, *, max_tokens, json_schema=None):
        self.calls.append({"system": system, "prompt": prompt, "max_tokens": max_tokens, "schema": json_schema})
        if self._error:
            raise self._error
        return self._answer


SHA = "a" * 64
TEXT = f"The loader beacons to evil.example.com and drops {SHA}. See https://vendor.example.org/blog."


def test_prompt_lists_candidates_by_index_and_type():
    cands = extract_candidates(TEXT)
    prompt = build_prompt("T", "https://x/y", TEXT, cands)
    for c in cands:
        assert f"[{c.idx}] {c.type} {json.dumps(c.value)}" in prompt
    assert "<<<BEGIN ARTICLE_TEXT>>>" in prompt and "<<<END ARTICLE_TEXT>>>" in prompt


def test_prompt_with_no_candidates():
    assert build_prompt("T", "u", "plain text", []).endswith("(none)")


def test_candidates_from_truncated_part_are_not_shown_but_keep_their_idx():
    tail_ip = "203.0.113.9"
    text = "A" * 100 + f" first host 198.51.100.7 " + "B" * (structure.MAX_ARTICLE_CHARS) + f" tail {tail_ip}"
    cands = extract_candidates(text)
    fitted = structure.fit_article(text)
    shown = structure.visible_candidates(fitted, cands)
    assert [c.value for c in shown] == ["198.51.100.7"]
    assert tail_ip in {c.value for c in cands}


def test_candidate_cap(monkeypatch):
    monkeypatch.setattr(structure, "MAX_CANDIDATES", 2)
    cands = [Candidate(i, "ip-dst", f"10.0.0.{i}") for i in range(5)]
    text = " ".join(c.value for c in cands)
    assert [c.idx for c in structure.visible_candidates(text, cands)] == [0, 1]


def test_refanged_candidates_are_visible():
    text = "C2 at hxxp://bad[.]example[.]net/x"
    cands = extract_candidates(text)
    assert cands and structure.visible_candidates(text, cands) == cands


def test_structure_article_returns_raw_output_untouched():
    provider = _FakeProvider('{"relevant": false, "reason": "x"}\n')
    out = structure_article("T", "u", TEXT, extract_candidates(TEXT), provider=provider)
    assert out == '{"relevant": false, "reason": "x"}\n'
    call = provider.calls[0]
    assert call["max_tokens"] == structure.MAX_TOKENS
    assert call["schema"] == response_schema()


def test_article_text_is_truncated_in_prompt():
    provider = _FakeProvider("{}")
    structure_article("T", "u", "x" * (structure.MAX_ARTICLE_CHARS + 500), [], provider=provider)
    prompt = provider.calls[0]["prompt"]
    assert "x" * structure.MAX_ARTICLE_CHARS in prompt
    assert "x" * (structure.MAX_ARTICLE_CHARS + 1) not in prompt


def test_provider_failure_becomes_structure_error_and_keeps_fatal():
    with pytest.raises(StructureError) as exc:
        structure_article("T", "u", TEXT, [], provider=_FakeProvider(error=LLMError("bad key", fatal=True)))
    assert exc.value.fatal is True


def test_empty_response_is_an_error():
    with pytest.raises(StructureError):
        structure_article("T", "u", TEXT, [], provider=_FakeProvider("  \n"))


def test_system_prompt_forbids_writing_values_and_treats_article_as_data():
    assert "MUST be referenced by its index" in structure.SYSTEM_PROMPT
    assert "untrusted data" in structure.SYSTEM_PROMPT


def test_response_schema_covers_both_outcomes_and_forbids_extras():
    schema = response_schema()
    names = {r["$ref"].rsplit("/", 1)[-1] for r in schema["anyOf"]}
    assert names == {"Extraction", "Irrelevant"}
    assert schema["$defs"]["Extraction"]["additionalProperties"] is False
    assert "value" not in schema["$defs"]["IndicatorRef"]["properties"]


def test_stage6_to_stage7_round_trip_resolves_indices_to_values():
    cands = extract_candidates(TEXT)
    sha_idx = next(c.idx for c in cands if c.value == SHA)
    raw = json.dumps({
        "relevant": True,
        "event_info": "Loader - test - example.com - 2026-09-01",
        "summary": "A loader drops a payload.",
        "indicators": [{"idx": sha_idx, "type": "sha256", "role": "final_payload", "comment": "dropped", "to_ids": True}],
    })
    provider = _FakeProvider(raw)
    out = structure_article("T", "u", TEXT, cands, provider=provider)
    result = validate_output(out, cands, StaticWarninglist({}))
    assert isinstance(result, ValidatedExtraction)
    assert result.indicators[0].value == SHA


def test_model_is_not_asked_for_attack_patterns():
    assert "attack_patterns" not in structure.SYSTEM_PROMPT
    assert "attack_patterns" not in response_schema()["$defs"]["Extraction"]["properties"]
