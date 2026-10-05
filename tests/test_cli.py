import io
from datetime import datetime, timezone

import pytest

import cli
from collectors.feeds import FeedItem
from extract.article import ArticleFetchError
from llm.providers import LLMError
from store.seen import SeenStore

# Written by Claude Code


def _items(n):
    return [
        FeedItem(
            source="Test",
            title=f"t{i}",
            url=f"https://example.test/{i}",
            published=datetime.now(timezone.utc),
            summary="s",
        )
        for i in range(n)
    ]


class _Provider:
    name = "fake"
    model = "fake"

    def __init__(self, answer="YES", error=None):
        self.answer = answer
        self.error = error
        self.calls = 0

    def complete(self, system, prompt, *, max_tokens):
        self.calls += 1
        if self.error:
            raise self.error
        return self.answer


@pytest.fixture
def pipeline(monkeypatch):
    monkeypatch.setattr(cli, "SOURCES", {"Test": "https://example.test/feed"})
    monkeypatch.setattr(cli, "poll_feed", lambda url, name, max_age_days: _items(5))

    def use(provider, fetch=None):
        monkeypatch.setattr(cli, "get_provider", lambda stage: provider)
        if fetch:
            monkeypatch.setattr(cli, "fetch_article", fetch)

    return use


def _fetch_fails(url):
    raise ArticleFetchError("nope")


def test_limit_counts_failed_articles(pipeline, tmp_path):
    pipeline(_Provider("YES"), fetch=_fetch_fails)
    count = cli.run(db_path=str(tmp_path / "db"), limit=2, out=io.StringIO())
    assert count == 2


def test_limit_applies_per_source(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "SOURCES", {"A": "https://a.test/feed", "B": "https://b.test/feed"})
    monkeypatch.setattr(
        cli,
        "poll_feed",
        lambda url, name, max_age_days: [
            FeedItem(source=name, title="t", url=f"https://{name}.test/{i}",
                     published=datetime.now(timezone.utc), summary="s")
            for i in range(5)
        ],
    )
    monkeypatch.setattr(cli, "get_provider", lambda stage: _Provider("NO"))
    db = str(tmp_path / "db")
    count = cli.run(db_path=db, limit=2, out=io.StringIO())
    assert count == 4
    with SeenStore(db) as store:
        assert store.is_seen("https://B.test/1")
        assert not store.is_seen("https://B.test/2")


def test_transient_error_fails_article_and_continues(pipeline, tmp_path):
    provider = _Provider(error=LLMError("timeout", fatal=False))
    pipeline(provider)
    count = cli.run(db_path=str(tmp_path / "db"), out=io.StringIO())
    assert provider.calls == 5
    assert count == 5


def test_fatal_error_aborts_after_first_call(pipeline, tmp_path):
    provider = _Provider(error=LLMError("401 bad key", fatal=True))
    pipeline(provider)
    db = str(tmp_path / "db")
    with pytest.raises(cli.TriageError):
        cli.run(db_path=db, out=io.StringIO())
    assert provider.calls == 1
    # The article wasn't at fault, so it must be picked up again next run.
    with SeenStore(db) as store:
        assert not store.is_seen("https://example.test/0")


def test_main_returns_nonzero_on_fatal_error(pipeline, tmp_path, capsys):
    pipeline(_Provider(error=LLMError("401 bad key", fatal=True)))
    assert cli.main(["run", "--db", str(tmp_path / "db")]) == 1
    assert "aborting run" in capsys.readouterr().err


# --- stages 6-7 -----------------------------------------------------------

import json

from extract.article import Article
from validate.indicators import StaticWarninglist, WarninglistUnavailable

SHA = "b" * 64
ARTICLE_TEXT = f"The loader talks to evil.example.com and drops {SHA}."


class _StructureProvider:
    name = "fake"
    model = "fake"

    def __init__(self, answer="", error=None):
        self.answer = answer
        self.error = error
        self.calls = 0

    def complete(self, system, prompt, *, max_tokens, json_schema=None):
        self.calls += 1
        if self.error:
            raise self.error
        return self.answer


def _extraction(idx_by_value, *, value=SHA, type_="sha256", **overrides):
    data = {
        "relevant": True,
        "event_info": "Loader - test - example.test - 2026-09-01",
        "summary": "A loader drops a payload.",
        "indicators": [
            {"idx": idx_by_value(value), "type": type_, "role": "final_payload", "comment": "dropped", "to_ids": True}
        ],
    }
    data.update(overrides)
    return data


@pytest.fixture
def full_pipeline(monkeypatch):
    monkeypatch.setattr(cli, "SOURCES", {"Test": "https://example.test/feed"})
    monkeypatch.setattr(cli, "poll_feed", lambda url, name, max_age_days: _items(2))
    monkeypatch.setattr(
        cli, "fetch_article", lambda url: Article(url=url, title="Article", text=ARTICLE_TEXT)
    )

    def use(structure_provider):
        providers = {"triage": _Provider("YES"), "structure": structure_provider}
        monkeypatch.setattr(cli, "get_provider", lambda stage: providers[stage])

    return use


def _idx(value):
    from extract.iocs import extract_candidates

    return next(c.idx for c in extract_candidates(ARTICLE_TEXT) if c.value == value)


def _run(tmp_path, out=None, **kwargs):
    return cli.run(
        db_path=str(tmp_path / "db"), out=out or io.StringIO(), warninglist=StaticWarninglist({}), **kwargs
    )


def test_relevant_article_emits_event_with_values_resolved_by_code(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    out = io.StringIO()
    assert _run(tmp_path, out) == 2
    first = json.loads(out.getvalue().splitlines()[0])
    indicator = first["event"]["indicators"][0]
    assert indicator["value"] == SHA and indicator["type"] == "sha256"
    assert indicator["to_ids"] is True and indicator["warninglist_hits"] == []
    assert first["event"]["event_info"].startswith("Loader")


def test_warninglist_hit_forces_to_ids_false_in_output(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    out = io.StringIO()
    cli.run(db_path=str(tmp_path / "db"), out=out, warninglist=StaticWarninglist({SHA: "known-benign"}))
    indicator = json.loads(out.getvalue().splitlines()[0])["event"]["indicators"][0]
    assert indicator["to_ids"] is False and indicator["warninglist_hits"] == ["known-benign"]


def test_irrelevant_result_is_reported_and_marked_processed(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider('{"relevant": false, "reason": "marketing"}'))
    out = io.StringIO()
    _run(tmp_path, out)
    assert json.loads(out.getvalue().splitlines()[0])["irrelevant"] == "marketing"
    with SeenStore(str(tmp_path / "db")) as store:
        assert not store.should_process("https://example.test/0")


def test_invented_index_is_discarded_and_run_continues(full_pipeline, tmp_path, capsys):
    provider = _StructureProvider(json.dumps(_extraction(lambda v: 999)))
    full_pipeline(provider)
    out = io.StringIO()
    assert _run(tmp_path, out) == 2
    assert provider.calls == 2 and out.getvalue() == ""
    assert "discarded" in capsys.readouterr().err
    with SeenStore(str(tmp_path / "db")) as store:
        assert store.retry_count("https://example.test/0") == 1


def test_prose_wrapped_output_is_discarded(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider("Here you go:\n" + json.dumps(_extraction(_idx))))
    out = io.StringIO()
    _run(tmp_path, out)
    assert out.getvalue() == ""


def test_transient_structure_error_fails_article_and_continues(full_pipeline, tmp_path):
    provider = _StructureProvider(error=LLMError("timeout"))
    full_pipeline(provider)
    assert _run(tmp_path) == 2
    assert provider.calls == 2


def test_fatal_structure_error_aborts_and_releases_article(full_pipeline, tmp_path):
    provider = _StructureProvider(error=LLMError("401", fatal=True))
    full_pipeline(provider)
    with pytest.raises(cli.StructureError):
        _run(tmp_path)
    assert provider.calls == 1
    with SeenStore(str(tmp_path / "db")) as store:
        assert not store.is_seen("https://example.test/0")


def test_unavailable_warninglists_abort_and_release_article(full_pipeline, tmp_path, monkeypatch):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))

    def unavailable():
        raise WarninglistUnavailable("MISP down")

    monkeypatch.setattr(cli.MispWarninglists, "from_env", staticmethod(unavailable))
    with pytest.raises(WarninglistUnavailable):
        cli.run(db_path=str(tmp_path / "db"), out=io.StringIO())
    with SeenStore(str(tmp_path / "db")) as store:
        assert not store.is_seen("https://example.test/0")


def test_main_returns_nonzero_when_warninglists_unavailable(full_pipeline, tmp_path, monkeypatch, capsys):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    assert cli.main(["run", "--db", str(tmp_path / "db")]) == 1
    assert "aborting run" in capsys.readouterr().err


def test_techniques_come_from_ids_the_article_cites(full_pipeline, tmp_path, monkeypatch, capsys):
    text = ARTICLE_TEXT + " It ran PowerShell (T1059.001), a made-up T1133.004, and the old T1562.001."
    monkeypatch.setattr(cli, "fetch_article", lambda url: Article(url=url, title="Article", text=text))
    from extract.iocs import extract_candidates

    idx = next(c.idx for c in extract_candidates(text) if c.value == SHA)
    # The model also volunteers a technique; it must be ignored.
    doc = _extraction(lambda v: idx, attack_patterns=[{"technique_id": "T1003.001", "evidence": "model guess"}])
    full_pipeline(_StructureProvider(json.dumps(doc)))
    out = io.StringIO()
    _run(tmp_path, out)
    event = json.loads(out.getvalue().splitlines()[0])["event"]
    assert [p["technique_id"] for p in event["attack_patterns"]] == ["T1059.001"]
    assert "PowerShell (T1059.001)" in event["attack_patterns"][0]["evidence"]
    assert event["dropped_techniques"] == ["T1133.004 (unknown)", "T1562.001 (revoked)"]
    assert "dropped techniques" in capsys.readouterr().err


# --- stage 8: --write ------------------------------------------------------------

from misp.writer import MispWriteError, WriteResult


class _Writer:
    def __init__(self, tmp_path, outcome="created", error=None):
        self.dir = tmp_path / "findings"
        self.outcome = outcome
        self.error = error
        self.seen_on_disk = []
        self.findings = []

    def write(self, finding):
        # What the artifact looked like at the moment MISP was called.
        self.seen_on_disk.append([json.loads(p.read_text())["misp"]["status"] for p in self.dir.rglob("*.json")])
        self.findings.append(finding)
        if self.error:
            raise self.error
        return WriteResult(self.outcome, "uuid-1", "42")


def _write_run(tmp_path, writer, out=None):
    return cli.run(db_path=str(tmp_path / "db"), out=out or io.StringIO(), warninglist=StaticWarninglist({}),
                   dry_run=False, writer=writer, artifact_dir=str(writer.dir))


def _artifacts(writer):
    return [json.loads(p.read_text()) for p in sorted(writer.dir.rglob("*.json"))]


def test_write_saves_artifact_before_misp_call_and_updates_it_after(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    writer = _Writer(tmp_path)
    out = io.StringIO()
    assert _write_run(tmp_path, writer, out) == 2
    assert writer.seen_on_disk[0] == ["pending"]
    doc = _artifacts(writer)[0]
    assert doc["misp"]["status"] == "created" and doc["misp"]["event_id"] == "42"
    assert doc["event"]["indicators"][0]["value"] == SHA
    assert doc["model_output_raw"].startswith("{")
    assert doc["pipeline"] == {"triage": "fake/fake", "structure": "fake/fake"}
    line = json.loads(out.getvalue().splitlines()[0])
    assert line["misp"]["outcome"] == "created" and line["artifact"].endswith(".json")
    assert "model_output_raw" not in line


def test_existing_event_is_recorded_as_exists(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    writer = _Writer(tmp_path, outcome="exists")
    _write_run(tmp_path, writer)
    assert _artifacts(writer)[0]["misp"]["status"] == "exists"


def test_dry_run_writes_no_artifacts_and_never_touches_misp(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    writer = _Writer(tmp_path)
    cli.run(db_path=str(tmp_path / "db"), out=io.StringIO(), warninglist=StaticWarninglist({}), writer=writer,
            artifact_dir=str(writer.dir))
    assert writer.findings == [] and not writer.dir.exists()


def test_irrelevant_article_writes_nothing(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider('{"relevant": false, "reason": "marketing"}'))
    writer = _Writer(tmp_path)
    _write_run(tmp_path, writer)
    assert writer.findings == [] and not writer.dir.exists()


def test_rejected_output_writes_nothing(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(lambda v: 999))))
    writer = _Writer(tmp_path)
    _write_run(tmp_path, writer)
    assert writer.findings == [] and not writer.dir.exists()


def test_rejected_event_marks_artifact_failed_and_run_continues(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    writer = _Writer(tmp_path, error=MispWriteError("rejected"))
    assert _write_run(tmp_path, writer) == 2
    assert len(writer.findings) == 2
    assert {d["misp"]["status"] for d in _artifacts(writer)} == {"failed"}
    with SeenStore(str(tmp_path / "db")) as store:
        assert store.retry_count("https://example.test/0") == 1


def test_unreachable_misp_aborts_releases_article_and_records_failure(full_pipeline, tmp_path):
    full_pipeline(_StructureProvider(json.dumps(_extraction(_idx))))
    writer = _Writer(tmp_path, error=MispWriteError("down", fatal=True))
    with pytest.raises(MispWriteError):
        _write_run(tmp_path, writer)
    assert len(writer.findings) == 1
    assert _artifacts(writer)[0]["misp"]["status"] == "failed"
    with SeenStore(str(tmp_path / "db")) as store:
        assert not store.is_seen("https://example.test/0")


def test_write_without_misp_config_fails_before_any_model_call(full_pipeline, tmp_path, monkeypatch, capsys):
    provider = _StructureProvider(json.dumps(_extraction(_idx)))
    full_pipeline(provider)
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    assert cli.main(["run", "--write", "--db", str(tmp_path / "db"), "--artifact-dir", str(tmp_path / "f")]) == 1
    assert "aborting run" in capsys.readouterr().err
    assert provider.calls == 0 and not (tmp_path / "f").exists()


def test_dry_run_and_write_flags_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit):
        cli.main(["run", "--dry-run", "--write"])
