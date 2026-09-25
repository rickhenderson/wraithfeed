"""Swappable LLM backends.

Every pipeline stage that calls a model goes through `Provider.complete()`,
so the backend can change per stage without touching stage code. Selection
is by environment variable (see `get_provider`), e.g.:

    WRAITHFEED_TRIAGE_PROVIDER=anthropic
    WRAITHFEED_TRIAGE_MODEL=claude-haiku-4-5

Supported providers:
    anthropic   Anthropic Messages API via the official SDK (ANTHROPIC_API_KEY)
    openai      OpenAI Chat Completions (OPENAI_API_KEY)
    openrouter  OpenRouter, OpenAI-compatible (OPENROUTER_API_KEY)
    local       any OpenAI-compatible server: llama.cpp, LM Studio, vLLM (no key)
    ollama      Ollama native API

Written by Claude Code for Rick Henderson.
"""

from __future__ import annotations

import os
from typing import Protocol

import requests

DEFAULT_TIMEOUT_SECONDS = 30

# Per-provider defaults. A stage can override model/base URL via env vars.
_DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5",
    # Non-reasoning default: reasoning models spend max_tokens on hidden
    # reasoning and can return empty text on tiny YES/NO budgets.
    "openai": "gpt-4.1-mini",
    "openrouter": "anthropic/claude-haiku-4.5",
    "local": "local-model",
    "ollama": "qwen3.5:latest",
}

_DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "local": "http://localhost:8080/v1",
    "ollama": "http://localhost:11434",
}

_API_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}


class LLMError(Exception):
    """A model call failed.

    `fatal` means retrying other articles won't help — bad key, unknown model,
    malformed request — so the caller should abort the run rather than fail
    every remaining article the same way.
    """

    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


def _is_fatal_status(status: int) -> bool:
    # 4xx is a config/request problem; timeouts, conflicts and rate limits are transient.
    return 400 <= status < 500 and status not in (408, 409, 429)


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, prompt: str, *, max_tokens: int) -> str:
        """Return the model's text response. Raises LLMError on any failure."""
        ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        import anthropic  # imported lazily so other providers don't need the SDK

        self._anthropic = anthropic
        self.model = model
        # Credentials resolve from the environment (ANTHROPIC_API_KEY etc).
        self._client = anthropic.Anthropic(timeout=timeout)

    def complete(self, system: str, prompt: str, *, max_tokens: int) -> str:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except self._anthropic.APIStatusError as exc:
            raise LLMError(f"anthropic call failed: {exc}", fatal=_is_fatal_status(exc.status_code)) from exc
        except self._anthropic.APIConnectionError as exc:
            raise LLMError(f"anthropic call failed: {exc}") from exc
        except self._anthropic.AnthropicError as exc:
            # e.g. no credentials could be resolved — nothing will succeed this run.
            raise LLMError(f"anthropic call failed: {exc}", fatal=True) from exc

        if response.stop_reason == "refusal":
            raise LLMError("anthropic call refused")

        return "".join(b.text for b in response.content if b.type == "text")


class OpenAICompatibleProvider:
    """Chat Completions over HTTP: OpenAI, OpenRouter, and local servers."""

    def __init__(
        self,
        name: str,
        model: str,
        base_url: str,
        api_key: str | None,
        *,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.name = name
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._timeout = timeout

    def complete(self, system: str, prompt: str, *, max_tokens: int) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        # OpenAI renamed max_tokens; OpenRouter and local servers still expect the old name.
        body["max_completion_tokens" if self.name == "openai" else "max_tokens"] = max_tokens
        try:
            resp = requests.post(self._url, json=body, headers=self._headers, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"] or ""
        except requests.HTTPError as exc:
            raise LLMError(
                f"{self.name} call failed: {exc}", fatal=_is_fatal_status(exc.response.status_code)
            ) from exc
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"{self.name} call failed: {exc}") from exc


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.model = model
        self._url = base_url.rstrip("/") + "/api/chat"
        self._timeout = timeout

    def complete(self, system: str, prompt: str, *, max_tokens: int) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            # Thinking mode burns ~1500 tokens and ~24s per call on qwen3.5.
            "think": False,
            "options": {"num_ctx": 4096, "temperature": 0, "num_predict": max_tokens},
        }
        try:
            resp = requests.post(self._url, json=body, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        except requests.HTTPError as exc:
            # Ollama answers 404 for a model that hasn't been pulled/created.
            raise LLMError(
                f"ollama call failed: {exc}", fatal=_is_fatal_status(exc.response.status_code)
            ) from exc
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise LLMError(f"ollama call failed: {exc}") from exc


PROVIDERS = sorted(_DEFAULT_MODELS)


def _env(stage: str, key: str) -> str | None:
    """Stage-specific var first (WRAITHFEED_TRIAGE_MODEL), then global (WRAITHFEED_LLM_MODEL)."""
    return os.environ.get(f"WRAITHFEED_{stage.upper()}_{key}") or os.environ.get(f"WRAITHFEED_LLM_{key}")


def get_provider(stage: str, *, default: str = "anthropic") -> Provider:
    """Build the provider configured for a pipeline stage ("triage", "structure", ...)."""
    name = (_env(stage, "PROVIDER") or default).lower()
    if name not in _DEFAULT_MODELS:
        raise LLMError(f"unknown provider {name!r}; expected one of {', '.join(PROVIDERS)}")

    model = _env(stage, "MODEL") or _DEFAULT_MODELS[name]
    base_url = _env(stage, "BASE_URL") or _DEFAULT_BASE_URLS.get(name)

    if name == "anthropic":
        return AnthropicProvider(model)
    if name == "ollama":
        return OllamaProvider(model, base_url)

    key_var = _API_KEY_VARS.get(name)
    api_key = os.environ.get(key_var) if key_var else None
    if key_var and not api_key:
        raise LLMError(f"{name} provider needs {key_var} set")
    return OpenAICompatibleProvider(name, model, base_url, api_key)
