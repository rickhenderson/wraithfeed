from unittest.mock import patch

from llm.triage import TriageError, is_relevant

# Written by Claude Code


def _mock_response(text: str):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": text}

    return _Resp()


def test_is_relevant_parses_yes():
    with patch("llm.triage.requests.post", return_value=_mock_response("YES")):
        assert is_relevant("title", "text") is True


def test_is_relevant_parses_no():
    with patch("llm.triage.requests.post", return_value=_mock_response("NO")):
        assert is_relevant("title", "text") is False


def test_is_relevant_fails_closed_on_garbage_output():
    with patch("llm.triage.requests.post", return_value=_mock_response("uh, maybe?")):
        assert is_relevant("title", "text") is False


def test_is_relevant_is_case_insensitive():
    with patch("llm.triage.requests.post", return_value=_mock_response("yes")):
        assert is_relevant("title", "text") is True


def test_is_relevant_raises_on_connection_failure():
    import requests

    with patch("llm.triage.requests.post", side_effect=requests.ConnectionError("down")):
        try:
            is_relevant("title", "text")
            assert False, "expected TriageError"
        except TriageError:
            pass
