import json

import pytest

from extract.iocs import extract_candidates
from validate import indicators as ind
from validate.indicators import (
    MispWarninglists,
    StaticWarninglist,
    WarninglistUnavailable,
    validate_output,
)
from validate.schema import ExtractionRejected, Irrelevant, parse_extraction

ARTICLE = (
    "The loader beacons to update-check[.]top and 185.220.101.47, then pulls "
    "hxxps://cdn.update-check[.]top/p.bin (sha256 "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855). "
    "It also resolves 8.8.8.8 and github.com to test connectivity."
)
CANDIDATES = extract_candidates(ARTICLE)
IDX = {c.value: c.idx for c in CANDIDATES}
NO_HITS = StaticWarninglist({})


def _ind(candidate, type_, **kw):
    return {"idx": IDX[candidate], "type": type_, "role": "c2", "comment": "", "to_ids": True, **kw}


def _doc(indicators=None, **overrides):
    doc = {
        "relevant": True,
        "event_info": "UpdateCheck loader - example.test - 2026-09-01",
        "summary": "A loader beacons to attacker infrastructure and fetches a payload.",
        "indicators": indicators if indicators is not None else [_ind("update-check.top", "domain")],
    }
    doc.update(overrides)
    return json.dumps(doc)


def test_candidates_fixture_is_what_the_tests_assume():
    assert {"update-check.top", "185.220.101.47", "8.8.8.8", "github.com"} <= IDX.keys()


def test_valid_output_resolves_values_from_candidates():
    raw = _doc([_ind("update-check.top", "domain"), _ind("185.220.101.47", "ip-dst")])
    result = validate_output(raw, CANDIDATES, NO_HITS)
    assert [(i.type, i.value, i.to_ids) for i in result.indicators] == [
        ("domain", "update-check.top", True),
        ("ip-dst", "185.220.101.47", True),
    ]


def test_irrelevant_output():
    result = validate_output('{"relevant": false, "reason": "product news"}', CANDIDATES, NO_HITS)
    assert isinstance(result, Irrelevant)


# --- malformed model output: discarded, never repaired -------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "Here is the JSON:\n" + _doc(),
        _doc() + "\nLet me know if you need anything else.",
        "```json\n" + _doc() + "\n```",
        "",
        "{not json}",
        '{"relevant": "yes"}',
        '{"summary": "no relevant flag"}',
    ],
    ids=["prose-before", "prose-after", "markdown-fence", "empty", "broken-json", "string-flag", "missing-flag"],
)
def test_malformed_wrappers_rejected(raw):
    with pytest.raises(ExtractionRejected):
        parse_extraction(raw)


def test_invented_indicator_value_field_rejected():
    raw = _doc([_ind("update-check.top", "domain", value="evil-made-up.com")])
    with pytest.raises(ExtractionRejected, match="value"):
        validate_output(raw, CANDIDATES, NO_HITS)


def test_indicator_without_idx_rejected():
    raw = _doc([{"type": "domain", "value": "evil.com", "role": "c2", "to_ids": True}])
    with pytest.raises(ExtractionRejected):
        validate_output(raw, CANDIDATES, NO_HITS)


@pytest.mark.parametrize("idx", [len(CANDIDATES), 999, -1])
def test_out_of_range_idx_rejected(idx):
    raw = _doc([{"idx": idx, "type": "domain", "role": "c2", "comment": "", "to_ids": True}])
    with pytest.raises(ExtractionRejected):
        validate_output(raw, CANDIDATES, NO_HITS)


@pytest.mark.parametrize("idx", ["3", 3.0, True])
def test_non_integer_idx_rejected(idx):
    raw = _doc([{"idx": idx, "type": "domain", "role": "c2", "comment": "", "to_ids": True}])
    with pytest.raises(ExtractionRejected):
        parse_extraction(raw)


def test_duplicate_idx_rejected():
    raw = _doc([_ind("update-check.top", "domain"), _ind("update-check.top", "hostname")])
    with pytest.raises(ExtractionRejected, match="twice"):
        validate_output(raw, CANDIDATES, NO_HITS)


def test_duplicate_json_keys_rejected():
    raw = _doc()[:-1] + ', "relevant": true}'
    with pytest.raises(ExtractionRejected, match="duplicate"):
        parse_extraction(raw)


@pytest.mark.parametrize(
    "value,claimed",
    [("185.220.101.47", "domain"), ("update-check.top", "ip-dst"), ("update-check.top", "filename")],
)
def test_type_mismatch_rejected(value, claimed):
    with pytest.raises(ExtractionRejected, match="candidate is"):
        validate_output(_doc([_ind(value, claimed)]), CANDIDATES, NO_HITS)


def test_domain_may_be_reported_as_hostname():
    result = validate_output(_doc([_ind("update-check.top", "hostname")]), CANDIDATES, NO_HITS)
    assert result.indicators[0].type == "hostname"


@pytest.mark.parametrize(
    "overrides",
    [
        {"summary": "word " * 61},
        {"attribution_confidence": "certain"},
        {"first_seen": "Sept 2026"},
        {"first_seen": "2999-01-01"},
        {"cves": ["CVE-26-1"]},
        {"attack_patterns": [{"technique_id": "", "evidence": "x"}]},
        {"event_info": ""},
        {"unexpected_field": 1},
    ],
    ids=["long-summary", "bad-confidence", "bad-date", "future-date", "bad-cve", "empty-technique-id", "empty-info", "extra-field"],
)
def test_field_violations_rejected(overrides):
    with pytest.raises(ExtractionRejected):
        parse_extraction(_doc(**overrides))


def test_irrelevant_with_extra_fields_rejected():
    with pytest.raises(ExtractionRejected):
        parse_extraction('{"relevant": false, "reason": "x", "indicators": []}')


# --- warninglists --------------------------------------------------------------


def test_warninglist_hit_forces_to_ids_false():
    wl = StaticWarninglist({"8.8.8.8": "List of known IPv4 public DNS resolvers"})
    raw = _doc([_ind("8.8.8.8", "ip-dst"), _ind("185.220.101.47", "ip-dst")])
    result = validate_output(raw, CANDIDATES, wl)
    assert [(i.value, i.to_ids, i.warninglist_hits) for i in result.indicators] == [
        ("8.8.8.8", False, ("List of known IPv4 public DNS resolvers",)),
        ("185.220.101.47", True, ()),
    ]


def test_advisory_list_hit_is_recorded_but_keeps_to_ids():
    vpn = next(iter(ind.ADVISORY_LISTS))
    wl = StaticWarninglist({"185.220.101.47": vpn})
    result = validate_output(_doc([_ind("185.220.101.47", "ip-dst")]), CANDIDATES, wl)
    assert (result.indicators[0].to_ids, result.indicators[0].warninglist_hits) == (True, (vpn,))


def test_advisory_plus_blocking_hit_still_forces_to_ids_false(monkeypatch):
    vpn = next(iter(ind.ADVISORY_LISTS))
    _fake_misp(monkeypatch, enabled=True, hits={"8.8.8.8": [{"name": vpn}, {"name": "public DNS"}]})
    result = validate_output(_doc([_ind("8.8.8.8", "ip-dst")]), CANDIDATES, MispWarninglists("https://misp", "k"))
    assert result.indicators[0].to_ids is False


def test_url_hits_warninglist_through_its_host():
    wl = StaticWarninglist({"cdn.update-check.top": "hypothetical CDN list"})
    raw = _doc([_ind("https://cdn.update-check.top/p.bin", "url")])
    assert validate_output(raw, CANDIDATES, wl).indicators[0].to_ids is False


def test_model_to_ids_false_is_respected_without_hit():
    raw = _doc([_ind("github.com", "domain", to_ids=False)])
    assert validate_output(raw, CANDIDATES, NO_HITS).indicators[0].to_ids is False


class _MispResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _fake_misp(monkeypatch, *, enabled, hits):
    calls = []

    def request(method, url, **kwargs):
        calls.append((method, url.rsplit("/", 2)[-2:], kwargs.get("json")))
        if url.endswith("/warninglists/index"):
            return _MispResp({"Warninglists": [{"Warninglist": {"id": "1", "enabled": enabled}}]})
        return _MispResp(hits)

    monkeypatch.setattr(ind.requests, "request", request)
    return calls


def test_misp_warninglists_parses_hits(monkeypatch):
    _fake_misp(monkeypatch, enabled=True, hits={"8.8.8.8": [{"id": "83", "name": "DNS", "matched": "8.8.8.8/32"}]})
    assert MispWarninglists("https://misp", "k").check(["8.8.8.8", "1.2.3.4"]) == {"8.8.8.8": ["DNS"]}


def test_misp_warninglists_empty_list_response_means_no_hits(monkeypatch):
    _fake_misp(monkeypatch, enabled=True, hits=[])
    assert MispWarninglists("https://misp", "k").check(["1.2.3.4"]) == {}


def test_misp_with_no_enabled_lists_refuses(monkeypatch):
    _fake_misp(monkeypatch, enabled=False, hits=[])
    with pytest.raises(WarninglistUnavailable, match="enabled"):
        MispWarninglists("https://misp", "k").check(["1.2.3.4"])


def test_misp_unreachable_is_retryable_not_a_rejection(monkeypatch):
    def boom(*a, **k):
        raise ind.requests.ConnectionError("refused")

    monkeypatch.setattr(ind.requests, "request", boom)
    with pytest.raises(WarninglistUnavailable):
        validate_output(_doc(), CANDIDATES, MispWarninglists("https://misp", "k"))


def test_from_env_reads_verify_flag(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://localhost")
    monkeypatch.setenv("MISP_KEY", "k")
    monkeypatch.setenv("MISP_VERIFY_CERT", "false")
    assert MispWarninglists.from_env()._verify is False
    monkeypatch.delenv("MISP_KEY")
    with pytest.raises(WarninglistUnavailable):
        MispWarninglists.from_env()


# --- ATT&CK techniques: only ids the article cites, checked against the list ----

from extract.techniques import TechniqueMention
from validate import techniques


def _mention(technique_id, context="the article cites it here"):
    return TechniqueMention(technique_id, context)


def test_cited_current_technique_is_attached_with_article_context():
    result = validate_output(_doc(), CANDIDATES, NO_HITS, [_mention("T1059.001", "ran PowerShell (T1059.001)")])
    assert [(p.technique_id, p.evidence) for p in result.extraction.attack_patterns] == [
        ("T1059.001", "ran PowerShell (T1059.001)")
    ]
    assert result.dropped_techniques == ()


def test_model_supplied_attack_patterns_are_discarded():
    raw = _doc(attack_patterns=[{"technique_id": "T1059.001", "evidence": "model says so"}])
    result = validate_output(raw, CANDIDATES, NO_HITS)
    assert result.extraction.attack_patterns == []


@pytest.mark.parametrize(
    "technique_id, reason",
    [
        ("T1133.004", "unknown"),  # an id a model invented in a live run
        ("T9999", "unknown"),
        ("T1562.001", "revoked"),  # real, but superseded in a later ATT&CK release
        ("T1002", "revoked"),
    ],
)
def test_cited_but_not_current_technique_is_dropped_and_reported(technique_id, reason):
    mentions = [_mention("T1059.001"), _mention(technique_id)]
    result = validate_output(_doc(), CANDIDATES, NO_HITS, mentions)
    assert [p.technique_id for p in result.extraction.attack_patterns] == ["T1059.001"]
    assert result.dropped_techniques == (f"{technique_id} ({reason})",)
    assert [i.value for i in result.indicators] == ["update-check.top"]


def test_technique_list_has_current_and_retired_entries():
    assert techniques.status("T1059.001") == "current"
    assert techniques.status("T1562.001") == "revoked"
    assert techniques.status("T0000") == "unknown"
    assert techniques.name("T1059.001") == "PowerShell"
    assert len(techniques.current_ids()) > 500
    assert all("." not in t for t, _ in techniques.current_parents())


@pytest.mark.parametrize("model_text", [
    "Loader - test campaign",
    "Loader - test campaign - example.test - 2024-02",
    "Loader - test campaign - example.test - 2024-02-03",
    "Loader - test campaign - Vendor Labs - 2024-02",
    "Loader - test campaign - example.test",
])
def test_compose_event_info_takes_source_and_date_from_code(model_text):
    from datetime import date
    from validate.indicators import compose_event_info
    assert compose_event_info(model_text, "https://www.vendor.example/blog/x", date(2026, 9, 1)) == \
        "Loader - test campaign - vendor.example - 2026-09-01"


def test_cves_come_from_the_article_not_the_model():
    raw = _doc(cves=["CVE-1999-0001"])
    result = validate_output(raw, CANDIDATES, NO_HITS, cves=["CVE-2026-88771"])
    assert result.extraction.cves == ["CVE-2026-88771"]
    assert validate_output(_doc(), CANDIDATES, NO_HITS).extraction.cves == []
