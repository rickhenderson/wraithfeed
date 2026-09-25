from llm.providers import LLMError
from llm.triage import TriageError, is_relevant

# Written by Claude Code


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, answer: str = "", error: Exception | None = None):
        self._answer = answer
        self._error = error
        self.calls = []

    def complete(self, system: str, prompt: str, *, max_tokens: int) -> str:
        self.calls.append((system, prompt, max_tokens))
        if self._error:
            raise self._error
        return self._answer


def test_is_relevant_parses_yes():
    assert is_relevant("title", "text", provider=_FakeProvider("YES")) is True


def test_is_relevant_parses_no():
    assert is_relevant("title", "text", provider=_FakeProvider("NO")) is False


def test_is_relevant_fails_closed_on_garbage_output():
    assert is_relevant("title", "text", provider=_FakeProvider("uh, maybe?")) is False


def test_is_relevant_is_case_insensitive():
    assert is_relevant("title", "text", provider=_FakeProvider("yes")) is True


def test_is_relevant_truncates_snippet():
    provider = _FakeProvider("NO")
    is_relevant("title", "x" * 2000, provider=provider)
    _, prompt, _ = provider.calls[0]
    assert "x" * 500 in prompt
    assert "x" * 501 not in prompt


def test_is_relevant_raises_on_provider_failure():
    provider = _FakeProvider(error=LLMError("down"))
    try:
        is_relevant("title", "text", provider=provider)
        assert False, "expected TriageError"
    except TriageError:
        pass
