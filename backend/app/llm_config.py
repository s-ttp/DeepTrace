"""Persistent LLM provider/model configuration.

Source of truth: backend/config/llm_config.json (created on first save).
Falls back to environment variables if the JSON file does not exist, so
existing deployments keep working until an admin overwrites the config
via the /admin/llm page.
"""
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"
CONFIG_PATH = CONFIG_DIR / "llm_config.json"

VALID_PROVIDERS = {"openai", "anthropic", "google", "moonshot"}

DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "moonshot": "https://api.moonshot.ai/v1",
    "anthropic": "https://api.anthropic.com",
    "google": "",
}

_lock = threading.Lock()
_cached: Optional[Dict[str, Any]] = None
_last_test: Optional[Dict[str, Any]] = None


def _load_from_disk() -> Optional[Dict[str, Any]]:
    if not CONFIG_PATH.exists():
        return None
    try:
        with CONFIG_PATH.open("r") as f:
            data = json.load(f)
        if data.get("provider") not in VALID_PROVIDERS:
            logger.warning("Stored LLM config has unknown provider %r; ignoring file.", data.get("provider"))
            return None
        return data
    except Exception as e:
        logger.error("Failed to read %s: %s", CONFIG_PATH, e)
        return None


def _load_from_env() -> Dict[str, Any]:
    moonshot = os.getenv("MOONSHOT_API_KEY", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    if moonshot:
        return {
            "provider": "moonshot",
            "model": os.getenv("KIMI_MODEL", "kimi-k2.5"),
            "api_key": moonshot,
            "base_url": os.getenv("KIMI_API_BASE_URL", DEFAULT_BASE_URLS["moonshot"]),
            "updated_at": None,
            "source": "env",
        }
    if openai_key:
        return {
            "provider": "openai",
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "api_key": openai_key,
            "base_url": os.getenv("OPENAI_BASE_URL", DEFAULT_BASE_URLS["openai"]),
            "updated_at": None,
            "source": "env",
        }
    return {
        "provider": None,
        "model": None,
        "api_key": "",
        "base_url": "",
        "updated_at": None,
        "source": "unset",
    }


def get_active_config() -> Dict[str, Any]:
    """Return the active config (full, including api_key). Internal use only."""
    global _cached
    with _lock:
        if _cached is None:
            on_disk = _load_from_disk()
            if on_disk:
                on_disk.setdefault("source", "file")
                _cached = on_disk
            else:
                _cached = _load_from_env()
        return dict(_cached)


def get_active_model() -> Optional[str]:
    return get_active_config().get("model")


def get_active_provider() -> Optional[str]:
    return get_active_config().get("provider")


def _hint(api_key: str) -> str:
    if not api_key:
        return ""
    if len(api_key) <= 4:
        return "*" * len(api_key)
    return "…" + api_key[-4:]


def get_redacted_config() -> Dict[str, Any]:
    """Public view: provider, model, base_url, whether a key is set, last-4 hint, source."""
    cfg = get_active_config()
    api_key = cfg.get("api_key") or ""
    return {
        "provider": cfg.get("provider"),
        "model": cfg.get("model"),
        "base_url": cfg.get("base_url") or "",
        "key_set": bool(api_key),
        "key_hint": _hint(api_key),
        "updated_at": cfg.get("updated_at"),
        "source": cfg.get("source", "unset"),
        "last_test": _last_test,
    }


def set_active_config(provider: str, model: str, api_key: str, base_url: Optional[str] = None) -> Dict[str, Any]:
    """Persist a new config to disk and invalidate caches."""
    provider = (provider or "").strip().lower()
    if provider not in VALID_PROVIDERS:
        raise ValueError(f"Invalid provider {provider!r}. Must be one of: {sorted(VALID_PROVIDERS)}")
    model = (model or "").strip()
    if not model:
        raise ValueError("Model must not be empty.")
    api_key = (api_key or "").strip()
    if not api_key:
        raise ValueError("API key must not be empty.")
    base_url = (base_url or "").strip() or DEFAULT_BASE_URLS.get(provider, "")

    record = {
        "provider": provider,
        "model": model,
        "api_key": api_key,
        "base_url": base_url,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": "file",
    }

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(record, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)

    invalidate_cache()
    logger.info("LLM config updated: provider=%s model=%s base_url=%s", provider, model, base_url)
    return get_redacted_config()


def invalidate_cache() -> None:
    """Drop both this module's config cache and the llm_service client cache."""
    global _cached
    with _lock:
        _cached = None
    try:
        from . import llm_service
        llm_service.invalidate_client_cache()
    except Exception as e:
        logger.debug("llm_service client cache invalidation skipped: %s", e)


def record_test_result(ok: bool, provider: str, model: str, latency_ms: Optional[int],
                       sample: Optional[str], error: Optional[str]) -> None:
    global _last_test
    _last_test = {
        "ok": bool(ok),
        "provider": provider,
        "model": model,
        "latency_ms": latency_ms,
        "sample": (sample or "")[:200],
        "error": (error or "")[:300] if error else None,
        "at": datetime.now(timezone.utc).isoformat(),
    }
