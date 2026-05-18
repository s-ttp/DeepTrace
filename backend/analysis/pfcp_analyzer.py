"""PFCP / N4 analyser.

5G troubleshooting often pivots on the SMF↔UPF interface. Without per-SEID
session reasoning and readable cause codes, user-plane outages are invisible.

This module consumes the transaction list produced by `decode/transactions_builder.py`
(filtered to PFCP) and returns a per-SEID outcome summary plus a path/heartbeat
view.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# Lazy import to avoid circulars at module load.
def _cause_label(code: Any) -> str:
    try:
        from decode.cause_maps import PFCP_CAUSES
        return PFCP_CAUSES.get(int(code), f"Unknown PFCP Cause {code}")
    except Exception:
        return f"PFCP Cause {code}"


def _msg_label(code: Any) -> str:
    try:
        from decode.cause_maps import PFCP_MSG_TYPES
        return PFCP_MSG_TYPES.get(int(code), f"PFCP Msg {code}")
    except Exception:
        return f"PFCP Msg {code}"


_ESTABLISHMENT_REQ = 50
_ESTABLISHMENT_RSP = 51
_MODIFICATION_REQ = 52
_MODIFICATION_RSP = 53
_DELETION_REQ = 54
_DELETION_RSP = 55
_HEARTBEAT_REQ = 1
_HEARTBEAT_RSP = 2

_FAILURE_CAUSES = set(range(64, 80))  # 64-79 are failure codes in TS 29.244


def _msg_type(tx: Dict[str, Any]) -> Optional[int]:
    raw = tx.get("pfcp.msg_type") or tx.get("msg_type") or tx.get("message_type")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _cause(tx: Dict[str, Any]) -> Optional[int]:
    raw = tx.get("pfcp.cause") or tx.get("cause")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _seid(tx: Dict[str, Any]) -> str:
    return str(tx.get("pfcp.seid") or tx.get("seid") or "")


def _node(tx: Dict[str, Any]) -> str:
    return str(tx.get("pfcp.node_id_str") or tx.get("node_id") or "")


def analyze_pfcp(transactions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a per-SEID outcome table and path/heartbeat summary."""
    pfcp_txs = [t for t in (transactions or []) if str(t.get("protocol", "")).upper() == "PFCP"]
    if not pfcp_txs:
        return {"pfcp_present": False}

    per_seid: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "events": [],
        "established": False,
        "modified": 0,
        "deleted": False,
        "failures": [],
    })

    heartbeats = {"requests": 0, "responses": 0}
    associations = {"setup_success": 0, "setup_failure": 0, "release_success": 0, "release_failure": 0}
    message_counts: Dict[str, int] = defaultdict(int)
    failure_causes: Dict[str, int] = defaultdict(int)
    nodes_seen: set = set()

    for tx in pfcp_txs:
        msg = _msg_type(tx)
        cause = _cause(tx)
        seid = _seid(tx)
        node = _node(tx)
        if node:
            nodes_seen.add(node)
        message_counts[_msg_label(msg)] += 1

        if msg == _HEARTBEAT_REQ:
            heartbeats["requests"] += 1
            continue
        if msg == _HEARTBEAT_RSP:
            heartbeats["responses"] += 1
            continue

        if msg in (5, 7, 9):  # Association setup/update/release REQ — outcome is in RSP
            continue
        if msg == 6:  # Association Setup Response
            (associations["setup_failure"] if cause in _FAILURE_CAUSES else associations.update({"setup_success": associations["setup_success"] + 1}))
            if cause in _FAILURE_CAUSES:
                failure_causes[_cause_label(cause)] += 1
            continue
        if msg == 10:  # Association Release Response
            if cause in _FAILURE_CAUSES:
                associations["release_failure"] += 1
                failure_causes[_cause_label(cause)] += 1
            else:
                associations["release_success"] += 1
            continue

        if not seid:
            continue
        entry = per_seid[seid]
        entry["events"].append({"msg": _msg_label(msg), "cause": _cause_label(cause) if cause is not None else None})

        if msg == _ESTABLISHMENT_RSP:
            if cause in _FAILURE_CAUSES:
                entry["failures"].append({"phase": "establishment", "cause": _cause_label(cause)})
                failure_causes[_cause_label(cause)] += 1
            else:
                entry["established"] = True
        elif msg == _MODIFICATION_RSP:
            if cause in _FAILURE_CAUSES:
                entry["failures"].append({"phase": "modification", "cause": _cause_label(cause)})
                failure_causes[_cause_label(cause)] += 1
            else:
                entry["modified"] += 1
        elif msg == _DELETION_RSP:
            if cause in _FAILURE_CAUSES:
                entry["failures"].append({"phase": "deletion", "cause": _cause_label(cause)})
                failure_causes[_cause_label(cause)] += 1
            else:
                entry["deleted"] = True

    sessions_established = sum(1 for v in per_seid.values() if v["established"])
    sessions_failed = sum(1 for v in per_seid.values() if v["failures"])
    heartbeat_loss = heartbeats["requests"] - heartbeats["responses"]
    path_likely_down = heartbeats["requests"] > 0 and heartbeats["responses"] == 0

    top_failures = sorted(failure_causes.items(), key=lambda kv: -kv[1])[:5]

    return {
        "pfcp_present": True,
        "total_transactions": len(pfcp_txs),
        "unique_seids": len(per_seid),
        "sessions_established": sessions_established,
        "sessions_failed": sessions_failed,
        "association": associations,
        "heartbeats": heartbeats,
        "heartbeat_loss": max(heartbeat_loss, 0),
        "path_likely_down": path_likely_down,
        "message_counts": dict(message_counts),
        "top_failure_causes": [{"cause": c, "count": n} for c, n in top_failures],
        "nodes_observed": sorted(nodes_seen)[:10],
        "per_seid_failures": [
            {"seid": seid, "events": data["events"][:5], "failures": data["failures"]}
            for seid, data in per_seid.items() if data["failures"]
        ][:10],
    }


def format_pfcp_context_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    """Convert the PFCP summary into a compact LLM prompt section."""
    if not summary or not summary.get("pfcp_present"):
        return "## PFCP / N4 ANALYSIS: No PFCP traffic observed at this capture point."

    lines = ["## PFCP / N4 ANALYSIS"]
    lines.append(f"- Transactions: {summary['total_transactions']}, unique SEIDs: {summary['unique_seids']}")
    lines.append(f"- Sessions: {summary['sessions_established']} established, {summary['sessions_failed']} failed")
    a = summary["association"]
    lines.append(f"- Associations: setup ok={a['setup_success']} fail={a['setup_failure']} · release ok={a['release_success']} fail={a['release_failure']}")
    hb = summary["heartbeats"]
    lines.append(f"- Heartbeats: req={hb['requests']} rsp={hb['responses']} loss={summary['heartbeat_loss']}")
    if summary["path_likely_down"]:
        lines.append("- **Path likely DOWN**: heartbeats sent but no responses — SMF↔UPF connectivity issue")
    if summary["top_failure_causes"]:
        lines.append("- Top failure causes:")
        for f in summary["top_failure_causes"]:
            lines.append(f"  - {f['cause']} ×{f['count']}")
    if summary["per_seid_failures"]:
        lines.append("- Sample failing SEIDs:")
        for s in summary["per_seid_failures"][:3]:
            fails = ", ".join(f["{phase}/{cause}".format(**f)] if False else f"{f['phase']}: {f['cause']}" for f in s["failures"])
            lines.append(f"  - SEID {s['seid']}: {fails}")
    return "\n".join(lines)
