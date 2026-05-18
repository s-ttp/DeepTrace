"""Admin API router for LLM provider/model management.

All routes are gated by HTTP Basic Auth. Credentials are read from env:
  ADMIN_USERNAME=<your username>
  ADMIN_PASSWORD_HASH=<bcrypt hash, e.g. $2b$12$...>

Generate the hash with:  python backend/scripts/hash_admin_password.py
"""
import logging
import os
import secrets
from typing import Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from .. import llm_config
from ..llm_providers import build_adapter, AdapterError

logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBasic()


def _admin_env() -> tuple[str, str]:
    username = os.getenv("ADMIN_USERNAME", "").strip()
    pw_hash = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
    return username, pw_hash


def require_admin(creds: HTTPBasicCredentials = Depends(security)) -> str:
    username, pw_hash = _admin_env()
    if not username or not pw_hash:
        # Refuse to authorize anything if admin auth is not configured.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin auth not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env.",
            headers={"WWW-Authenticate": "Basic"},
        )

    user_ok = secrets.compare_digest(creds.username.encode("utf-8"), username.encode("utf-8"))
    try:
        pw_ok = bcrypt.checkpw(creds.password.encode("utf-8"), pw_hash.encode("utf-8"))
    except (ValueError, TypeError):
        pw_ok = False

    if not (user_ok and pw_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


class ConfigUpdate(BaseModel):
    provider: str = Field(..., description="openai|anthropic|google|moonshot")
    model: str = Field(..., min_length=1)
    api_key: str = Field(..., min_length=1)
    base_url: Optional[str] = Field(default=None)


class TestRequest(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None


@router.get("/config")
def get_config(_: str = Depends(require_admin)):
    """Return the redacted current LLM config. Never includes the API key."""
    return llm_config.get_redacted_config()


@router.put("/config")
def put_config(payload: ConfigUpdate, _: str = Depends(require_admin)):
    """Persist a new LLM config and invalidate the cached client."""
    try:
        redacted = llm_config.set_active_config(
            provider=payload.provider,
            model=payload.model,
            api_key=payload.api_key,
            base_url=payload.base_url,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return redacted


@router.post("/test")
def test_config(payload: TestRequest, _: str = Depends(require_admin)):
    """Test an LLM config (without persisting). If body fields are omitted,
    tests the currently-active config instead."""
    if payload.provider or payload.model or payload.api_key:
        provider = payload.provider or ""
        model = payload.model or ""
        api_key = payload.api_key or ""
        base_url = payload.base_url
        if not (provider and model and api_key):
            raise HTTPException(
                status_code=400,
                detail="To test ad-hoc credentials, provide all of: provider, model, api_key.",
            )
    else:
        active = llm_config.get_active_config()
        provider = active.get("provider") or ""
        model = active.get("model") or ""
        api_key = active.get("api_key") or ""
        base_url = active.get("base_url") or None
        if not (provider and model and api_key):
            raise HTTPException(
                status_code=400,
                detail="No active LLM config to test. Save one first or supply credentials in the request.",
            )

    try:
        adapter = build_adapter(provider=provider, api_key=api_key, base_url=base_url)
    except Exception as e:
        msg = f"Failed to build {provider} client: {e}"
        llm_config.record_test_result(False, provider, model, None, None, msg)
        return {"ok": False, "provider": provider, "model": model, "error": msg}

    try:
        # Budget needs to be high enough for thinking models (Gemini 2.5/3,
        # Claude extended thinking, OpenAI o-series) to spend internal tokens
        # before emitting the visible reply.
        result = adapter.complete(
            messages=[
                {"role": "system", "content": "Reply with the single word: pong."},
                {"role": "user", "content": "ping"},
            ],
            model=model,
            max_tokens=1024,
            temperature=0.0,
        )
    except AdapterError as e:
        msg = str(e)[:500]
        llm_config.record_test_result(False, provider, model, None, None, msg)
        return {"ok": False, "provider": provider, "model": model, "error": msg}
    except Exception as e:
        msg = f"Unexpected error: {e}"
        llm_config.record_test_result(False, provider, model, None, None, msg)
        return {"ok": False, "provider": provider, "model": model, "error": msg}

    sample = (result.content or "").strip()[:200]
    llm_config.record_test_result(True, provider, model, result.latency_ms, sample, None)
    return {
        "ok": True,
        "provider": provider,
        "model": model,
        "latency_ms": result.latency_ms,
        "sample": sample,
    }
