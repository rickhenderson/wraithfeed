from pathlib import Path

from extract.iocs import Candidate, extract_candidates, refang

# Written by Claude Code

FIXTURES = Path(__file__).parent / "fixtures"


def test_sample_article_01_golden():
    text = (FIXTURES / "sample_article_01.txt").read_text()

    assert extract_candidates(text) == [
        Candidate(0, "email-src", "finance-support@corp-billing.com"),
        Candidate(1, "url", "https://cdn-updates.net/invoice/setup.exe"),
        Candidate(
            2,
            "sha256",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        ),
        Candidate(3, "md5", "d41d8cd98f00b204e9800998ecf8427e"),
        Candidate(4, "ip-dst", "185.220.101.45"),
        Candidate(5, "domain", "c2.shadowlynx-panel.ru"),
        Candidate(
            6,
            "registry-key",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        ),
        Candidate(7, "btc", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
        Candidate(8, "url", "http://185.220.101.45:8080/gate.php"),
    ]


def test_refang_bracket_dot_and_at():
    assert refang("evil[.]com") == "evil.com"
    assert refang("user[@]evil.com") == "user@evil.com"
    assert refang("hxxps://evil[.]com") == "https://evil.com"


def test_no_candidates_in_clean_prose():
    text = "The threat actor deployed a loader and established persistence."
    assert extract_candidates(text) == []


def test_invalid_ip_octets_rejected():
    text = "Traffic was seen going to 999.999.999.999 which is not a real IP."
    candidates = extract_candidates(text)
    assert not any(c.type == "ip-dst" for c in candidates)


def test_filename_not_mistaken_for_domain():
    text = "The dropped payload was saved as invoice.exe on disk."
    candidates = extract_candidates(text)
    assert not any(c.type == "domain" for c in candidates)


def test_indices_are_stable_and_sequential():
    text = open(FIXTURES / "sample_article_01.txt").read()
    candidates = extract_candidates(text)
    assert [c.idx for c in candidates] == list(range(len(candidates)))
