import json

from store import artifacts

# Written by Claude Code

FINDING = {"url": "https://example.test/Post", "title": "ChainDrop: Inside a Worm!", "published": "2026-09-30T10:00:00+00:00",
           "event": {"event_info": "x"}, "model_output_raw": "{}"}


def test_path_is_stable_per_url_and_filesystem_safe(tmp_path):
    path = artifacts.artifact_path(tmp_path, FINDING)
    assert path.parent == tmp_path / "2026-09-30"
    assert path.name.endswith("-chaindrop-inside-a-worm.json")
    assert artifacts.artifact_path(tmp_path, FINDING) == path
    assert artifacts.artifact_path(tmp_path, dict(FINDING, url="https://example.test/other")) != path


def test_hostile_title_cannot_escape_the_directory(tmp_path):
    path = artifacts.artifact_path(tmp_path, dict(FINDING, title="../../etc/passwd\x00 ../x"))
    assert tmp_path in path.parents and ".." not in path.name


def test_title_with_no_usable_characters_still_gets_a_name(tmp_path):
    assert artifacts.artifact_path(tmp_path, dict(FINDING, title="!!!")).name.count("-") == 0


def test_write_then_record_result(tmp_path):
    path = artifacts.write_finding(tmp_path, FINDING)
    doc = json.loads(path.read_text())
    assert doc["schema"] == artifacts.SCHEMA and doc["misp"] == {"status": "pending"}
    assert doc["url"] == FINDING["url"] and doc["event"] == {"event_info": "x"}

    artifacts.record_misp_result(path, status="created", event_uuid="u", event_id="3")
    doc = json.loads(path.read_text())
    assert (doc["misp"]["status"], doc["misp"]["event_id"]) == ("created", "3")
    assert doc["event"] == {"event_info": "x"}  # rest of the record untouched


def test_rerun_overwrites_its_own_artifact(tmp_path):
    first = artifacts.write_finding(tmp_path, FINDING)
    second = artifacts.write_finding(tmp_path, FINDING)
    assert first == second and len(list(tmp_path.rglob("*.json"))) == 1


def test_no_temp_files_left_behind(tmp_path):
    artifacts.write_finding(tmp_path, FINDING)
    assert [p.name for p in tmp_path.rglob(".tmp-*")] == []
