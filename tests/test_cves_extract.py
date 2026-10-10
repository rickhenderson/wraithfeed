from extract.cves import MAX_CVES, extract_cves


def test_distinct_ids_in_order_of_first_appearance():
    text = "Exploits CVE-2026-88772 then CVE-2026-88771, and again CVE-2026-88772."
    assert extract_cves(text) == ["CVE-2026-88772", "CVE-2026-88771"]


def test_lowercase_is_normalised_and_partial_ids_are_ignored():
    assert extract_cves("see cve-2024-3094; CVE-2024-123 and CVE-24-1234567 are not ids") == ["CVE-2024-3094"]


def test_no_ids():
    assert extract_cves("nothing here") == []


def test_capped():
    text = " ".join(f"CVE-2026-{n:05d}" for n in range(MAX_CVES + 20))
    assert len(extract_cves(text)) == MAX_CVES
