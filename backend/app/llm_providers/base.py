"""Common interface for all LLM provider adapters."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class AdapterError(RuntimeError):
    """Raised when an underlying SDK call fails."""


@dataclass
class CompletionResult:
    content: str
    model: str
    provider: str
    latency_ms: int
    raw: Any = None


class LLMAdapter:
    """Adapter interface. Subclasses must override `complete`."""

    provider: str = "base"

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url or None

    def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        max_tokens: int = 512,
        temperature: float = 1.0,
    ) -> CompletionResult:
        raise NotImplementedError
