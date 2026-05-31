import os
from abc import ABC, abstractmethod
from typing import Iterator


class LLMError(Exception):
    pass


class BaseLLMClient(ABC):
    def __init__(self, api_key: str | None, model: str) -> None:
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return a single completion as a string."""

    @abstractmethod
    def stream(self, system: str, user: str) -> Iterator[str]:
        """Yield string chunks as they arrive."""


class GroqClient(BaseLLMClient):
    def complete(self, system: str, user: str) -> str:
        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise LLMError(f"Groq error: {exc}") from exc

    def stream(self, system: str, user: str) -> Iterator[str]:
        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)
            with client.chat.completions.stream(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            ) as stream:
                for chunk in stream:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        yield delta
        except Exception as exc:
            raise LLMError(f"Groq stream error: {exc}") from exc


class GeminiClient(BaseLLMClient):
    def complete(self, system: str, user: str) -> str:
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system,
            )
            response = model.generate_content(user)
            return response.text or ""
        except Exception as exc:
            raise LLMError(f"Gemini error: {exc}") from exc

    def stream(self, system: str, user: str) -> Iterator[str]:
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system,
            )
            for chunk in model.generate_content(user, stream=True):
                if chunk.text:
                    yield chunk.text
        except Exception as exc:
            raise LLMError(f"Gemini stream error: {exc}") from exc


class OllamaClient(BaseLLMClient):
    def __init__(self, api_key: str | None, model: str) -> None:
        super().__init__(api_key=None, model=model)
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    def complete(self, system: str, user: str) -> str:
        try:
            import httpx
            response = httpx.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "system", "content": system},
                                 {"role": "user", "content": user}],
                    "stream": False,
                },
                timeout=120.0,
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as exc:
            raise LLMError(f"Ollama error: {exc}") from exc

    def stream(self, system: str, user: str) -> Iterator[str]:
        try:
            import httpx
            with httpx.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "system", "content": system},
                                 {"role": "user", "content": user}],
                    "stream": True,
                },
                timeout=120.0,
            ) as response:
                response.raise_for_status()
                import json
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        content = data.get("message", {}).get("content", "")
                        if content:
                            yield content
        except Exception as exc:
            raise LLMError(f"Ollama stream error: {exc}") from exc


class OpenAIClient(BaseLLMClient):
    def complete(self, system: str, user: str) -> str:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise LLMError(f"OpenAI error: {exc}") from exc

    def stream(self, system: str, user: str) -> Iterator[str]:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            with client.chat.completions.stream(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            ) as stream:
                for chunk in stream:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        yield delta
        except Exception as exc:
            raise LLMError(f"OpenAI stream error: {exc}") from exc


class AnthropicClient(BaseLLMClient):
    def complete(self, system: str, user: str) -> str:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return message.content[0].text if message.content else ""
        except Exception as exc:
            raise LLMError(f"Anthropic error: {exc}") from exc

    def stream(self, system: str, user: str) -> Iterator[str]:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            with client.messages.stream(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user}],
            ) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as exc:
            raise LLMError(f"Anthropic stream error: {exc}") from exc


PROVIDER_DEFAULTS: dict[str, tuple[str, type[BaseLLMClient]]] = {
    "groq":      ("llama3-70b-8192",        GroqClient),
    "gemini":    ("gemini-1.5-flash",        GeminiClient),
    "ollama":    ("llama3",                  OllamaClient),
    "openai":    ("gpt-4o-mini",             OpenAIClient),
    "anthropic": ("claude-3-haiku-20240307", AnthropicClient),
}


def get_llm_client() -> BaseLLMClient:
    """Build the configured LLM client from environment variables."""
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    if provider not in PROVIDER_DEFAULTS:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{provider}'. "
            f"Choose from: {', '.join(PROVIDER_DEFAULTS)}"
        )
    api_key = os.getenv("LLM_API_KEY")
    default_model, cls = PROVIDER_DEFAULTS[provider]
    model = os.getenv("LLM_MODEL") or default_model
    return cls(api_key=api_key, model=model)
