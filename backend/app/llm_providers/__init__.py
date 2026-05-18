"""LLM provider adapters.

Each adapter exposes a uniform Completion interface so the rest of the
codebase can stay agnostic to which vendor SDK is in use.
"""
from .base import LLMAdapter, CompletionResult, AdapterError
from .factory import build_adapter

__all__ = ["LLMAdapter", "CompletionResult", "AdapterError", "build_adapter"]
