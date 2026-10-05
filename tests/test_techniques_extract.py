from extract.techniques import CONTEXT_CHARS, MAX_MENTIONS, extract_techniques

# Written by Claude Code


def _ids(text):
    return [m.technique_id for m in extract_techniques(text)]


def test_finds_technique_and_subtechnique_ids_in_order_of_appearance():
    assert _ids("Later T1059.001 and earlier... T1003, then T1105.") == ["T1059.001", "T1003", "T1105"]


def test_each_id_once_with_context_from_first_mention():
    mentions = extract_techniques("First T1059 here. Second T1059 there.")
    assert [m.technique_id for m in mentions] == ["T1059"]
    assert mentions[0].context.startswith("First T1059")


def test_context_is_bounded_and_whitespace_collapsed():
    text = "a\n\n" * 200 + "T1059" + "\tb " * 200
    context = extract_techniques(text)[0].context
    assert "\n" not in context and "\t" not in context
    assert len(context) <= 2 * CONTEXT_CHARS + len("T1059")


def test_mitre_urls_are_recognised_including_subtechniques():
    text = "See https://attack.mitre.org/techniques/T1059/001/ and /techniques/T1003/ ."
    assert sorted(_ids(text)) == ["T1003", "T1059.001"]


def test_url_and_inline_forms_of_the_same_id_count_once():
    text = "PowerShell (T1059.001) https://attack.mitre.org/techniques/T1059/001/"
    assert _ids(text) == ["T1059.001"]


def test_ignores_lookalikes():
    assert _ids("Model XT1059, T10599, T105, ST1059.001 and t1059") == []


def test_describing_a_technique_without_citing_an_id_finds_nothing():
    assert _ids("The actor dumped LSASS memory to steal credentials.") == []


def test_mention_count_is_capped():
    text = " ".join(f"T{n:04d}" for n in range(1000, 1000 + MAX_MENTIONS + 50))
    assert len(extract_techniques(text)) == MAX_MENTIONS
