import os
import pytest
from unittest.mock import patch, MagicMock

from core.llm import (
    get_llm_client,
    BaseLLMClient,
    GroqClient,
    GeminiClient,
    OllamaClient,
    OpenAIClient,
    AnthropicClient,
    PROVIDER_DEFAULTS,
    LLMError,
)


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for key in ("LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)


class TestFactory:
    def test_groq_returns_groq_client(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "groq")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        client = get_llm_client()
        assert isinstance(client, GroqClient)

    def test_gemini_returns_gemini_client(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "gemini")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        assert isinstance(get_llm_client(), GeminiClient)

    def test_ollama_returns_ollama_client(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "ollama")
        assert isinstance(get_llm_client(), OllamaClient)

    def test_openai_returns_openai_client(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        assert isinstance(get_llm_client(), OpenAIClient)

    def test_anthropic_returns_anthropic_client(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        assert isinstance(get_llm_client(), AnthropicClient)

    def test_default_provider_is_groq(self, monkeypatch):
        # No LLM_PROVIDER set
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        assert isinstance(get_llm_client(), GroqClient)

    def test_unknown_provider_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "bogus_provider")
        with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
            get_llm_client()

    def test_uses_default_model_when_not_set(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "groq")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        client = get_llm_client()
        assert client.model == PROVIDER_DEFAULTS["groq"][0]

    def test_uses_override_model(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "groq")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        monkeypatch.setenv("LLM_MODEL", "custom-model-v9")
        client = get_llm_client()
        assert client.model == "custom-model-v9"

    def test_ollama_does_not_require_api_key(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "ollama")
        client = get_llm_client()
        assert client.api_key is None

    def test_case_insensitive_provider(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "GROQ")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        assert isinstance(get_llm_client(), GroqClient)


class TestAllProvidersHaveDefaults:
    def test_all_providers_in_defaults(self):
        expected = {"groq", "gemini", "ollama", "openai", "anthropic"}
        assert set(PROVIDER_DEFAULTS.keys()) == expected

    def test_each_default_is_non_empty_string(self):
        for provider, (model, _) in PROVIDER_DEFAULTS.items():
            assert isinstance(model, str) and model, f"Empty model for {provider}"

    def test_each_default_is_base_llm_subclass(self):
        for provider, (_, cls) in PROVIDER_DEFAULTS.items():
            assert issubclass(cls, BaseLLMClient), f"{cls} is not a BaseLLMClient subclass"


class TestOllamaClient:
    def test_instantiate_without_api_key(self):
        client = OllamaClient(api_key=None, model="llama3")
        assert client.model == "llama3"
        assert client.api_key is None

    def test_complete_posts_to_ollama_endpoint(self, mocker):
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "test response"}}
        mock_response.raise_for_status = MagicMock()

        mock_post = mocker.patch("httpx.post", return_value=mock_response)

        client = OllamaClient(api_key=None, model="llama3")
        result = client.complete(system="sys", user="usr")

        assert result == "test response"
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "api/chat" in call_kwargs[0][0]

    def test_complete_raises_llm_error_on_failure(self, mocker):
        mocker.patch("httpx.post", side_effect=Exception("Connection refused"))
        client = OllamaClient(api_key=None, model="llama3")
        with pytest.raises(LLMError, match="Ollama error"):
            client.complete(system="sys", user="usr")
