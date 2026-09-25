from unittest.mock import patch

import pytest
import requests

from llm.providers import (
    AnthropicProvider,
    LLMError,
    OllamaProvider,
    OpenAICompatibleProvider,
    get_provider,
)

# Written by Claude Code


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "WRAITHFEED_LLM_PROVIDER", "WRAITHFEED_LLM_MODEL", "WRAITHFEED_LLM_BASE_URL",
        "WRAITHFEED_TRIAGE_PROVIDER", "WRAITHFEED_TRIAGE_MODEL", "WRAITHFEED_TRIAGE_BASE_URL",
        "OPENAI_API_KEY", "OPENROUTER_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


def test_default_is_anthropic_haiku():
    provider = get_provider("triage")
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-haiku-4-5"


def test_stage_var_overrides_global(monkeypatch):
    monkeypatch.setenv("WRAITHFEED_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("WRAITHFEED_TRIAGE_PROVIDER", "ollama")
    monkeypatch.setenv("WRAITHFEED_TRIAGE_MODEL", "wraithfeed-triage")
    provider = get_provider("triage")
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "wraithfeed-triage"


def test_unknown_provider_rejected(monkeypatch):
    monkeypatch.setenv("WRAITHFEED_TRIAGE_PROVIDER", "nope")
    with pytest.raises(LLMError):
        get_provider("triage")


def test_missing_api_key_rejected(monkeypatch):
    monkeypatch.setenv("WRAITHFEED_TRIAGE_PROVIDER", "openrouter")
    with pytest.raises(LLMError, match="OPENROUTER_API_KEY"):
        get_provider("triage")


def test_local_needs_no_key(monkeypatch):
    monkeypatch.setenv("WRAITHFEED_TRIAGE_PROVIDER", "local")
    monkeypatch.setenv("WRAITHFEED_TRIAGE_BASE_URL", "http://box:1234/v1")
    provider = get_provider("triage")
    assert isinstance(provider, OpenAICompatibleProvider)
    with patch("llm.providers.requests.post",
               return_value=_Resp({"choices": [{"message": {"content": "YES"}}]})) as post:
        assert provider.complete("sys", "prompt", max_tokens=5) == "YES"
    assert post.call_args.args[0] == "http://box:1234/v1/chat/completions"
    assert post.call_args.kwargs["json"]["max_tokens"] == 5
    assert "Authorization" not in post.call_args.kwargs["headers"]


def test_openai_uses_max_completion_tokens(monkeypatch):
    monkeypatch.setenv("WRAITHFEED_TRIAGE_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = get_provider("triage")
    with patch("llm.providers.requests.post",
               return_value=_Resp({"choices": [{"message": {"content": "NO"}}]})) as post:
        provider.complete("sys", "prompt", max_tokens=5)
    body = post.call_args.kwargs["json"]
    assert body["max_completion_tokens"] == 5
    assert "max_tokens" not in body
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-test"


def test_ollama_parses_chat_response():
    provider = OllamaProvider("qwen3.5:latest", "http://localhost:11434")
    with patch("llm.providers.requests.post",
               return_value=_Resp({"message": {"content": "YES"}})) as post:
        assert provider.complete("sys", "prompt", max_tokens=5) == "YES"
    assert post.call_args.kwargs["json"]["think"] is False


def test_http_failure_becomes_llm_error():
    provider = OllamaProvider("m", "http://localhost:11434")
    with patch("llm.providers.requests.post", side_effect=requests.ConnectionError("down")):
        with pytest.raises(LLMError):
            provider.complete("sys", "prompt", max_tokens=5)


def test_anthropic_joins_text_blocks():
    provider = get_provider("triage")

    class _Block:
        type = "text"
        text = "YES"

    class _Msg:
        stop_reason = "end_turn"
        content = [_Block()]

    with patch.object(provider._client.messages, "create", return_value=_Msg()) as create:
        assert provider.complete("sys", "prompt", max_tokens=5) == "YES"
    assert create.call_args.kwargs["model"] == "claude-haiku-4-5"
    assert create.call_args.kwargs["system"] == "sys"


def _http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(f"{status}", response=resp)


@pytest.mark.parametrize("status,fatal", [(400, True), (401, True), (404, True), (429, False), (500, False)])
def test_http_status_sets_fatal(status, fatal):
    provider = OllamaProvider("m", "http://localhost:11434")
    with patch("llm.providers.requests.post", side_effect=_http_error(status)):
        with pytest.raises(LLMError) as excinfo:
            provider.complete("sys", "prompt", max_tokens=5)
    assert excinfo.value.fatal is fatal


def test_connection_error_is_not_fatal():
    provider = OllamaProvider("m", "http://localhost:11434")
    with patch("llm.providers.requests.post", side_effect=requests.ConnectionError("down")):
        with pytest.raises(LLMError) as excinfo:
            provider.complete("sys", "prompt", max_tokens=5)
    assert excinfo.value.fatal is False
