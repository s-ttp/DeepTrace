"""Diameter application-level interpretation.

The lower-level decoder already extracts AVPs (Result-Code, ApplicationId,
Session-Id, Origin-Host, CC-Request-Type, etc.). This module aggregates by
Diameter Application — S6a, Cx/Dx, Gx, Rx, Gy, Sh, SWx — and produces
per-application success/failure tallies with readable cause labels.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def _cause_label(code: Any) -> str:
    if code is None:
        return None
    try:
        c = int(code)
    except (TypeError, ValueError):
        return str(code)
    from decode.cause_maps import DIAMETER_RESULT_CODES, DIAMETER_3GPP_CODES
    return DIAMETER_RESULT_CODES.get(c) or DIAMETER_3GPP_CODES.get(c) or f"Diameter Code {c}"


def _app_label(app_id: Any) -> Dict[str, str]:
    try:
        a = int(app_id) if app_id is not None else None
    except (TypeError, ValueError):
        a = None
    from decode.cause_maps import DIAMETER_APP_IDS
    info = DIAMETER_APP_IDS.get(a) if a is not None else None
    if isinstance(info, dict):
        return {"id": str(a) if a is not None else "?", **info}
    if isinstance(info, str):
        return {"id": str(a), "name": info, "interface": "?", "description": ""}
    return {"id": str(a) if a is not None else "?", "name": f"AppID-{a}" if a is not None else "?", "interface": "?", "description": ""}


def _is_failure(code: Any) -> bool:
    try:
        c = int(code)
        return c >= 3000  # 3xxx/4xxx/5xxx ranges are protocol/transient/permanent failures
    except (TypeError, ValueError):
        return False


def analyze_diameter(transactions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate Diameter transactions by application and outcome."""
    diam_txs = [t for t in (transactions or []) if str(t.get("protocol", "")).lower().startswith("diameter")]
    if not diam_txs:
        return {"diameter_present": False}

    by_app: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "interface": "",
        "description": "",
        "messages": 0,
        "success": 0,
        "failure": 0,
        "cause_counts": defaultdict(int),
        "cmd_counts": defaultdict(int),
    })
    origin_hosts: set = set()
    realms: set = set()

    for tx in diam_txs:
        app_id = tx.get("diameter.applicationId") or tx.get("applicationId") or tx.get("app_id")
        info = _app_label(app_id)
        slot = by_app[info["name"]]
        slot["interface"] = info["interface"]
        slot["description"] = info["description"]
        slot["messages"] += 1

        cmd = tx.get("diameter.cmd.code") or tx.get("cmd_code")
        if cmd is not None:
            slot["cmd_counts"][str(cmd)] += 1

        # Pair Result-Code vs Experimental-Result-Code; the more specific one wins
        code = tx.get("diameter.Experimental-Result-Code") or tx.get("diameter.Result-Code") or tx.get("result_code")
        if code is not None:
            label = _cause_label(code)
            if _is_failure(code):
                slot["failure"] += 1
                slot["cause_counts"][label] += 1
            elif label:
                # Successful or informational; track but don't count as failure
                slot["success"] += 1
                slot["cause_counts"][label] += 1
        oh = tx.get("diameter.Origin-Host")
        if oh:
            origin_hosts.add(str(oh)[:80])
        rl = tx.get("diameter.Origin-Realm")
        if rl:
            realms.add(str(rl)[:80])

    apps_out = {}
    for name, slot in by_app.items():
        total = slot["messages"] or 1
        causes = sorted(slot["cause_counts"].items(), key=lambda kv: -kv[1])[:5]
        cmds = sorted(slot["cmd_counts"].items(), key=lambda kv: -kv[1])[:5]
        apps_out[name] = {
            "interface": slot["interface"],
            "description": slot["description"],
            "messages": slot["messages"],
            "success": slot["success"],
            "failure": slot["failure"],
            "failure_rate_pct": round(100.0 * slot["failure"] / total, 1),
            "top_causes": [{"cause": c, "count": n} for c, n in causes],
            "top_cmds": [{"cmd": c, "count": n} for c, n in cmds],
        }
    return {
        "diameter_present": True,
        "total_transactions": len(diam_txs),
        "by_application": apps_out,
        "origin_hosts_observed": len(origin_hosts),
        "realms_observed": len(realms),
    }


def format_diameter_context_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("diameter_present"):
        return "## DIAMETER APPLICATION-LEVEL OUTCOMES: No Diameter activity observable."

    lines = ["## DIAMETER APPLICATION-LEVEL OUTCOMES",
             f"- Total transactions: {summary['total_transactions']}",
             f"- Origin-Host(s): {summary['origin_hosts_observed']}  Realms: {summary['realms_observed']}"]
    for name, info in summary["by_application"].items():
        lines.append(f"### {name} ({info['interface']}) — {info['description']}")
        lines.append(f"  msgs={info['messages']} ok={info['success']} fail={info['failure']} ({info['failure_rate_pct']}%)")
        if info["top_causes"]:
            cs = ", ".join(f"{c['cause']}×{c['count']}" for c in info["top_causes"][:3])
            lines.append(f"  top causes: {cs}")
    return "\n".join(lines)
