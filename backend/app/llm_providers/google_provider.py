"""Google Gemini adapter."""
import time
from typing import Dict, List, Optional

from .base import AdapterError, CompletionResult, LLMAdapter


class GoogleAdapter(LLMAdapter):
    provider = "google"

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key=api_key, base_url=base_url)
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self._genai = genai

    def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        max_tokens: int = 512,
        temperature: float = 1.0,
    ) -> CompletionResult:
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        convo = []
        for m in messages:
            if m.get("role") == "system":
                continue
            role = "user" if m.get("role") == "user" else "model"
            convo.append({"role": role, "parts": [m.get("content", "")]})
        if not convo:
            convo = [{"role": "user", "parts": ["ping"]}]

        gen_kwargs = {
            "generation_config": {
                "max_output_tokens": max_tokens,
                "temperature": min(temperature, 1.0),
            }
        }
        if system_parts:
            gen_model = self._genai.GenerativeModel(
                model_name=model,
                system_instruction="\n\n".join(system_parts),
            )
        else:
            gen_model = self._genai.GenerativeModel(model_name=model)

        started = time.perf_counter()
        try:
            response = gen_model.generate_content(convo, **gen_kwargs)
        except Exception as e:
            raise AdapterError(str(e)) from e
        latency_ms = int((time.perf_counter() - started) * 1000)

        content = _extract_text(response)
        if not content:
            reason = _explain_empty(response)
            raise AdapterError(f"Gemini returned no text content ({reason}).")

        return CompletionResult(
            content=content,
            model=model,
            provider=self.provider,
            latency_ms=latency_ms,
            raw=response,
        )


def _extract_text(response) -> str:
    """Walk all candidates / parts and concatenate any text we find."""
    pieces = []
    for cand in getattr(response, "candidates", None) or []:
        content_obj = getattr(cand, "content", None)
        for part in getattr(content_obj, "parts", None) or []:
            text = getattr(part, "text", None)
            if text:
                pieces.append(text)
    if pieces:
        return "".join(pieces)
    # Last resort: response.text. Wrapped because it raises when the
    # response can't be cleanly stringified (safety block, MAX_TOKENS, etc.).
    try:
        return getattr(response, "text", "") or ""
    except Exception:
        return ""


_FINISH_REASON_NAMES = {
    0: "UNSPECIFIED",
    1: "STOP",
    2: "MAX_TOKENS",
    3: "SAFETY",
    4: "RECITATION",
    5: "OTHER",
    6: "BLOCKLIST",
    7: "PROHIBITED_CONTENT",
    8: "SPII",
    9: "MALFORMED_FUNCTION_CALL",
}


def _finish_reason_name(fr) -> str:
    if hasattr(fr, "name"):
        return str(fr.name)
    try:
        return _FINISH_REASON_NAMES.get(int(fr), f"reason={fr}")
    except Exception:
        return f"reason={fr}"


def _explain_empty(response) -> str:
    """Build a human-readable reason for an empty Gemini response."""
    pf = getattr(response, "prompt_feedback", None)
    if pf is not None:
        block_reason = getattr(pf, "block_reason", None)
        if block_reason:
            return f"prompt blocked: {block_reason}"
    cands = getattr(response, "candidates", None) or []
    if not cands:
        return "no candidates returned"
    reasons = []
    for cand in cands:
        fr = getattr(cand, "finish_reason", None)
        if fr is not None:
            name = _finish_reason_name(fr)
            if name == "MAX_TOKENS":
                reasons.append("MAX_TOKENS — thinking model consumed the budget before emitting text; increase max_tokens")
            else:
                reasons.append(f"finish_reason={name}")
        safety = getattr(cand, "safety_ratings", None) or []
        for sr in safety:
            if getattr(sr, "blocked", False):
                cat = getattr(sr, "category", "?")
                reasons.append(f"safety_blocked={cat}")
    return "; ".join(reasons) or "empty candidate content"
