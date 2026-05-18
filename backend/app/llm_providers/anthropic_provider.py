"""Anthropic Claude adapter."""
import time
from typing import Dict, List, Optional

from .base import AdapterError, CompletionResult, LLMAdapter


class AnthropicAdapter(LLMAdapter):
    provider = "anthropic"

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key=api_key, base_url=base_url)
        import anthropic
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)

    def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        max_tokens: int = 512,
        temperature: float = 1.0,
    ) -> CompletionResult:
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        user_msgs = [
            {"role": m["role"], "content": m["content"]}
            for m in messages
            if m.get("role") in ("user", "assistant")
        ]
        if not user_msgs:
            user_msgs = [{"role": "user", "content": "\n".join(system_parts) or "ping"}]
            system_parts = []

        kwargs = {
            "model": model,
            "messages": user_msgs,
            "max_tokens": max_tokens,
            "temperature": min(temperature, 1.0),
        }
        if system_parts:
            kwargs["system"] = "\n\n".join(system_parts)

        started = time.perf_counter()
        try:
            response = self._client.messages.create(**kwargs)
        except Exception as e:
            raise AdapterError(str(e)) from e
        latency_ms = int((time.perf_counter() - started) * 1000)

        text_parts = []
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", None) == "text":
                text_parts.append(getattr(block, "text", ""))
        content = "".join(text_parts)

        return CompletionResult(
            content=content,
            model=model,
            provider=self.provider,
            latency_ms=latency_ms,
            raw=response,
        )
