"""5G HTTP/2 SBI (Service-Based Interface) error analysis.

When a 5G NF responds with HTTP/2 4xx/5xx, the body typically contains a
ProblemDetails JSON object (3GPP TS 29.500) with structured fields like
``cause`` (e.g. UE_ALREADY_REACHABLE) and ``title``. We parse that body to
turn opaque ``:status: 400`` lines into actionable error reasons.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)

# Known 5G SBI service names from the :path pseudo-header.
_SBI_SERVICE_PATTERNS = [
    ("namf-comm",   "AMF Communication"),
    ("namf-evts",   "AMF Event Exposure"),
    ("nsmf-pdusession", "SMF PDU Session"),
    ("nudm-sdm",    "UDM Subscriber Data Mgmt"),
    ("nudm-uecm",   "UDM UE Context Mgmt"),
    ("nudm-ueauth", "UDM UE Authentication"),
    ("nausf-auth",  "AUSF Authentication"),
    ("npcf-am-policy-control", "PCF Access & Mobility Policy"),
    ("npcf-sm-policy-control", "PCF Session Management Policy"),
    ("nnrf-disc",   "NRF NF Discovery"),
    ("nnrf-nfm",    "NRF NF Management"),
    ("nchf-spendinglimitcontrol", "CHF Spending Limit"),
]


def _proto(tx: Dict[str, Any]) -> str:
    return str(tx.get("protocol", "")).upper()


def _service_from_path(path: str) -> str:
    if not path:
        return "unknown"
    p = path.lower()
    for needle, label in _SBI_SERVICE_PATTERNS:
        if needle in p:
            return label
    return path.split("/")[1] if path.startswith("/") and "/" in path[1:] else "unknown"


def _problem_details(body: Any) -> Dict[str, Any]:
    """Try to parse a 5G SBI ProblemDetails JSON body. Tolerant to hex blobs."""
    if not body:
        return {}
    text = body
    if isinstance(body, (bytes, bytearray)):
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            return {}
    if isinstance(text, str):
        # tshark sometimes presents body bytes as hex (e.g. "7b22636175...")
        if re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(text) > 8:
            try:
                text = bytes.fromhex(re.sub(r"\s+", "", text)).decode("utf-8", "replace")
            except Exception:
                return {}
        idx = text.find("{")
        if idx >= 0:
            try:
                obj = json.loads(text[idx:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                return {}
    return {}


def analyze_sbi(transactions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    txs = [t for t in (transactions or []) if _proto(t) in ("HTTP2", "HTTP/2", "SBI")]
    if not txs:
        return {"sbi_present": False}

    status_counts: Dict[str, int] = defaultdict(int)
    by_service: Dict[str, Dict[str, int]] = defaultdict(lambda: {"requests": 0, "errors": 0})
    errors_detail = []
    error_causes: Dict[str, int] = defaultdict(int)

    for tx in txs:
        status_raw = tx.get("http2.status") or tx.get("status_code")
        try:
            status = int(status_raw) if status_raw is not None else None
        except (TypeError, ValueError):
            status = None
        path = tx.get("http2.headers.path") or tx.get(":path") or ""
        service = _service_from_path(path)
        slot = by_service[service]
        slot["requests"] += 1

        if status is not None:
            status_counts[str(status)] += 1
            if status >= 400:
                slot["errors"] += 1
                body = tx.get("http2.data.data") or tx.get("body")
                pd = _problem_details(body)
                cause = pd.get("cause") or pd.get("title") or ""
                if cause:
                    error_causes[str(cause)] += 1
                if len(errors_detail) < 10:
                    errors_detail.append({
                        "service": service,
                        "path": (path or "")[:80],
                        "status": status,
                        "cause": cause,
                        "title": pd.get("title", ""),
                        "detail": (pd.get("detail") or "")[:120],
                    })

    return {
        "sbi_present": True,
        "total_transactions": len(txs),
        "status_counts": dict(status_counts),
        "by_service": {k: v for k, v in by_service.items()},
        "top_error_causes": [{"cause": c, "count": n} for c, n in sorted(error_causes.items(), key=lambda kv: -kv[1])[:5]],
        "sample_errors": errors_detail,
    }


def format_sbi_context_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("sbi_present"):
        return "## 5G SBI ERROR ANALYSIS: No HTTP/2 SBI errors decoded."

    lines = ["## 5G SBI ERROR ANALYSIS",
             f"- Total HTTP/2 transactions: {summary['total_transactions']}"]
    if summary["status_counts"]:
        status_pairs = ", ".join(f"{k}×{v}" for k, v in sorted(summary["status_counts"].items()))
        lines.append(f"- Status codes: {status_pairs}")
    if summary["by_service"]:
        lines.append("- Per service:")
        for svc, info in list(summary["by_service"].items())[:6]:
            lines.append(f"  - {svc}: req={info['requests']} errors={info['errors']}")
    if summary["top_error_causes"]:
        cs = ", ".join(f"{c['cause']}×{c['count']}" for c in summary["top_error_causes"])
        lines.append(f"- Top SBI error causes: {cs}")
    if summary["sample_errors"]:
        lines.append("- Sample errors:")
        for e in summary["sample_errors"][:3]:
            tag = e.get("cause") or e.get("title") or "(no cause)"
            lines.append(f"  - {e['service']} {e['status']} on {e['path']}: {tag}")
    return "\n".join(lines)
