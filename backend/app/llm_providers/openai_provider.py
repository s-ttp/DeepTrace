"""OpenAI-compatible adapter (covers OpenAI and Moonshot)."""
import time
from typing import Dict, List, Optional

import httpx
from openai import OpenAI

from .base import AdapterError, CompletionResult, LLMAdapter


class OpenAICompatibleAdapter(LLMAdapter):
    provider = "openai"

    def __init__(self, api_key: str, base_url: Optional[str] = None, provider_label: str = "openai"):
        super().__init__(api_key=api_key, base_url=base_url)
        self.provider = provider_label
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url or None,
            http_client=httpx.Client(),
        )

    @property
    def client(self) -> OpenAI:
        return self._client

    def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        max_tokens: int = 512,
        temperature: float = 1.0,
    ) -> CompletionResult:
        started = time.perf_counter()
        try:
            completion = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_completion_tokens=max_tokens,
            )
        except Exception as e:
            raise AdapterError(str(e)) from e
        latency_ms = int((time.perf_counter() - started) * 1000)
        content = completion.choices[0].message.content or ""
        return CompletionResult(
            content=content,
            model=model,
            provider=self.provider,
            latency_ms=latency_ms,
            raw=completion,
        )
