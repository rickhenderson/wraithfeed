import pytest
import requests
from pymisp.exceptions import PyMISPError

from misp.writer import MispWriteError, MispWriter, build_event, event_uuid_for

# Written by Claude Code

SHA = "a" * 64


def _ind(idx, type_, value, **kw):
    return {"idx": idx, "type": type_, "value": value, "role": "c2", "comment": "", "to_ids": True,
            "warninglist_hits": [], **kw}


def _finding(**event_overrides):
    event = {
        "event_info": "Loader - test - example.test - 2026-09-30",
        "summary": "A loader drops a payload.",
        "malware_families": [], "threat_actors": [], "attribution_confidence": None,
        "targeted_sectors": [], "targeted_regions": [], "first_seen": None,
        "attack_patterns": [], "cves": [], "dropped_techniques": [],
        "indicators": [],
    }
    event.update(event_overrides)
    return {"url": "https://www.example.test/post", "title": "Post", "published": "2026-09-30T10:00:00+00:00",
            "event": event}


def _dict(**event_overrides):
    return build_event(_finding(**event_overrides)).to_dict()


def _tags(d):
    return [t["name"] for t in d.get("Tag", [])]


def test_event_is_never_published_and_org_only():
    d = _dict()
    assert d["published"] is False
    assert int(d["distribution"]) == 0
    assert d["info"].startswith("Loader") and d["date"] == "2026-09-30"


def test_event_uuid_is_stable_per_url():
    assert event_uuid_for("https://a/x") == event_uuid_for("https://a/x") != event_uuid_for("https://a/y")
    assert _dict()["uuid"] == event_uuid_for("https://www.example.test/post")


def test_base_tags_and_source_domain_without_www():
    assert {"tlp:clear", "source:example.test", 'wraithfeed:review="pending"'} <= set(_tags(_dict()))


def test_source_link_and_summary_are_not_for_ids():
    attrs = {a["type"]: a for a in _dict(first_seen="2026-09-01")["Attribute"]}
    assert attrs["link"]["value"] == "https://www.example.test/post" and attrs["link"]["to_ids"] is False
    assert attrs["comment"]["to_ids"] is False and "First seen: 2026-09-01" in attrs["comment"]["value"]


def test_confidence_uses_the_confidence_taxonomy():
    assert 'estimative-language:confidence-in-analytic-judgement="high"' in _tags(_dict(attribution_confidence="high"))
    assert not [t for t in _tags(_dict()) if t.startswith("estimative-language")]


def test_attack_patterns_become_galaxy_tags_from_the_attack_list():
    tags = _tags(_dict(attack_patterns=[{"technique_id": "T1059.001", "evidence": "x"}]))
    assert 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"' in tags


def test_free_text_tag_values_cannot_break_machine_tag_syntax():
    tags = _tags(_dict(malware_families=['Foo "Bar"\\x'], threat_actors=["  "]))
    assert "wraithfeed:malware-family=\"Foo 'Bar'/x\"" in tags
    assert not [t for t in tags if "threat-actor" in t]


def test_indicators_become_objects_with_resolved_values_and_flags():
    d = _dict(indicators=[
        _ind(1, "sha256", SHA, role="final_payload", comment="dropped"),
        _ind(2, "domain", "evil.example", to_ids=False, warninglist_hits=["list x"]),
        _ind(3, "ip-dst", "203.0.113.5"),
        _ind(4, "url", "http://evil.example/p"),
    ])
    objs = {o["name"]: o for o in d["Object"]}
    sha = objs["file"]["Attribute"][0]
    assert (sha["object_relation"], sha["value"], sha["to_ids"]) == ("sha256", SHA, True)
    assert sha["comment"] == "final_payload: dropped"
    domain = next(o for o in d["Object"] if o["Attribute"][0]["value"] == "evil.example")
    assert domain["name"] == "domain-ip" and domain["Attribute"][0]["to_ids"] is False
    assert "warninglists: list x" in domain["Attribute"][0]["comment"]
    ip = next(o for o in d["Object"] if o["Attribute"][0]["value"] == "203.0.113.5")
    assert (ip["name"], ip["Attribute"][0]["object_relation"], ip["Attribute"][0]["type"]) == ("domain-ip", "ip", "ip-dst")
    assert objs["url"]["Attribute"][0]["value"] == "http://evil.example/p"


def test_types_without_a_suitable_object_are_loose_attributes():
    d = _dict(indicators=[_ind(1, "registry-key", "HKCU\\Software\\x"), _ind(2, "email-src", "a@evil.example"),
                          _ind(3, "btc", "1" + "a" * 30)])
    types = {a["type"] for a in d["Attribute"]}
    assert {"regkey", "email-src", "btc"} <= types


def test_cves_become_vulnerability_objects():
    d = _dict(cves=["CVE-2024-1234"])
    vuln = next(o for o in d["Object"] if o["name"] == "vulnerability")
    assert vuln["Attribute"][0]["value"] == "CVE-2024-1234"


def test_unmapped_indicator_type_is_refused_not_guessed():
    with pytest.raises(MispWriteError):
        build_event(_finding(indicators=[_ind(1, "carrier-pigeon", "x")]))


# --- MispWriter against a fake client -------------------------------------------


class _Client:
    def __init__(self, found=None, created=None, error=None):
        self.found = [] if found is None else found
        self.created = {"Event": {"id": "42"}} if created is None else created
        self.error = error
        self.calls = []

    def search(self, **kw):
        self.calls.append(("search", kw))
        if self.error:
            raise self.error
        return self.found

    def add_event(self, event, **kw):
        self.calls.append(("add_event", event))
        return self.created

    def __getattr__(self, name):  # anything else (publish, update...) is a test failure
        raise AssertionError(f"writer must not call client.{name}")


def test_creates_event_when_none_exists_for_the_url():
    client = _Client()
    result = MispWriter(client).write(_finding())
    assert (result.outcome, result.event_id, result.event_uuid) == ("created", "42", event_uuid_for("https://www.example.test/post"))
    assert [c[0] for c in client.calls] == ["search", "add_event"]
    assert client.calls[0][1]["uuid"] == result.event_uuid
    assert client.calls[1][1].published is False


def test_existing_event_is_left_alone():
    client = _Client(found=[{"Event": {"id": "7"}}])
    result = MispWriter(client).write(_finding())
    assert (result.outcome, result.event_id) == ("exists", "7")
    assert [c[0] for c in client.calls] == ["search"]


@pytest.mark.parametrize("error", [PyMISPError("boom"), requests.ConnectionError("down")])
def test_unreachable_misp_is_fatal(error):
    with pytest.raises(MispWriteError) as exc:
        MispWriter(_Client(error=error)).write(_finding())
    assert exc.value.fatal


def test_rejected_event_is_not_fatal():
    with pytest.raises(MispWriteError) as exc:
        MispWriter(_Client(created={"errors": ["bad"]})).write(_finding())
    assert not exc.value.fatal


def test_search_errors_are_fatal():
    with pytest.raises(MispWriteError) as exc:
        MispWriter(_Client(found={"errors": ["no perms"]})).write(_finding())
    assert exc.value.fatal


def test_from_env_requires_url_and_key(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)
    with pytest.raises(MispWriteError) as exc:
        MispWriter.from_env()
    assert exc.value.fatal
