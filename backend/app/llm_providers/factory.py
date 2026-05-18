"""Build the right adapter for a given provider."""
from typing import Optional

from .base import LLMAdapter


def build_adapter(provider: str, api_key: str, base_url: Optional[str] = None) -> LLMAdapter:
    provider = (provider or "").strip().lower()
    if provider in ("openai", "moonshot"):
        from .openai_provider import OpenAICompatibleAdapter
        return OpenAICompatibleAdapter(api_key=api_key, base_url=base_url, provider_label=provider)
    if provider == "anthropic":
        from .anthropic_provider import AnthropicAdapter
        return AnthropicAdapter(api_key=api_key, base_url=base_url)
    if provider == "google":
        from .google_provider import GoogleAdapter
        return GoogleAdapter(api_key=api_key, base_url=base_url)
    raise ValueError(f"Unknown LLM provider: {provider!r}")
