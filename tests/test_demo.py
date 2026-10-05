import json
import socket

import pytest

import cli
from demo import run as demo

# Written by Claude Code


@pytest.fixture
def offline(monkeypatch):
    """Any attempt to open a network connection fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("demo mode touched the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for var in ("MISP_URL", "MISP_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)


def _run(tmp_path, capsys):
    code = cli.main(["demo", "--out", str(tmp_path / "out")])
    return code, capsys.readouterr().out


def test_demo_runs_with_no_network_credentials_or_services(offline, tmp_path, capsys):
    code, out = _run(tmp_path, capsys)
    assert code == 0
    for stage in ("Stage 4", "Stage 5", "Stage 6", "Stage 7", "Stage 8"):
        assert stage in out


def test_demo_shows_a_warninglist_overriding_the_model(offline, tmp_path, capsys):
    _, out = _run(tmp_path, capsys)
    assert "forced to false by a warninglist hit" in out
    assert "List of known Cloudflare IP ranges" in out


def test_demo_shows_tampered_output_being_rejected(offline, tmp_path, capsys):
    _, out = _run(tmp_path, capsys)
    assert "unknown candidate idx 999" in out
    assert "Extra inputs are not permitted" in out
    assert "not a bare JSON object" in out
    assert "NOT rejected" not in out


def test_demo_writes_unpublished_event_and_marked_artifact(offline, tmp_path, capsys):
    _run(tmp_path, capsys)
    event = json.loads((tmp_path / "out" / "misp_event.json").read_text())["Event"]
    assert event["published"] is False and int(event["distribution"]) == 0
    assert any(a["type"] == "link" and a["value"] == demo.SOURCE["url"] for a in event["Attribute"])
    (artifact,) = (tmp_path / "out" / "findings").rglob("*.json")
    doc = json.loads(artifact.read_text())
    assert doc["misp"]["status"] == "demo" and "not sent" in doc["misp"]["note"]
    assert doc["event"]["indicators"][0]["value"]  # values resolved by code


def test_recorded_response_still_matches_the_extractors_candidates():
    # If the regex extractor changes, indices shift and the recording is stale.
    from extract.iocs import extract_candidates
    from extract.techniques import extract_techniques
    from validate.indicators import ValidatedExtraction, validate_output

    article = demo.load_article()
    candidates = extract_candidates(article.text)
    source = json.loads((demo.DEMO_DIR / "source.json").read_text())
    assert source["candidate_count"] == len(candidates)
    hits = json.loads((demo.DEMO_DIR / "warninglist_hits.json").read_text())
    result = validate_output(
        (demo.DEMO_DIR / "model_response.json").read_text(),
        candidates,
        demo.ReplayWarninglist(hits),
        extract_techniques(article.text),
    )
    assert isinstance(result, ValidatedExtraction)


def test_demo_exits_nonzero_with_a_hint_when_the_recording_is_stale(offline, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(demo, "extract_candidates", lambda text: [])  # indices no longer line up
    code, out = _run(tmp_path, capsys)
    assert code == 1 and "re-record" in out


def test_replay_warninglist_only_answers_for_requested_values():
    wl = demo.ReplayWarninglist({"a": ["list"], "b": ["list"]})
    assert wl.check(["a", "z"]) == {"a": ["list"]}
