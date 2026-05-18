"""Trend / pattern detection over a session's transactions.

Sliding-window analysis to surface signal that single-event detectors miss:
  - **Recurring cause**: same cause code N+ times in any K-second window.
  - **Burstiness**: failure clusters tighter than baseline.
  - **Cell cohort**: many subscribers failing on the same cell → coverage issue.

Heuristics are deliberately conservative (high thresholds) to keep false-positive
rate low; tighter tuning can come from real-world feedback.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Heuristic thresholds — start conservative
_RECUR_MIN_HITS = 5
_RECUR_WINDOW_S = 120.0
_BURST_MIN_HITS = 10
_BURST_WINDOW_S = 60.0
_COHORT_MIN_SUBS = 3
_COHORT_MIN_FAILS = 5


def _ts(tx: Dict[str, Any]) -> Optional[float]:
    for k in ("time_epoch", "timestamp", "frame.time_epoch"):
        v = tx.get(k)
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
    return None


def _is_failure(tx: Dict[str, Any]) -> bool:
    if str(tx.get("status", "")).lower() == "failure":
        return True
    for k in ("cause", "pfcp.cause", "ngap.cause", "s1ap.cause", "diameter.Result-Code", "sip.Status-Code"):
        v = tx.get(k)
        if v is None:
            continue
        try:
            n = int(v)
            if k == "sip.Status-Code":
                return n >= 400
            if k == "diameter.Result-Code":
                return n >= 3000
            return n >= 64  # PFCP/NGAP/S1AP cause >=64 → failure family
        except (TypeError, ValueError):
            continue
    return False


def _cause_label(tx: Dict[str, Any]) -> str:
    return (tx.get("cause_label")
            or str(tx.get("cause") or tx.get("ngap.cause") or tx.get("s1ap.cause")
                   or tx.get("sip.Status-Code") or tx.get("diameter.Result-Code") or "")
            or "unknown")


def _max_window_density(times: List[float], window: float) -> Tuple[int, Optional[float]]:
    """Sliding-window max-count + the start of that window."""
    if not times:
        return 0, None
    times = sorted(times)
    j = 0
    best = (0, None)
    for i in range(len(times)):
        while j < len(times) and times[j] - times[i] <= window:
            j += 1
        count = j - i
        if count > best[0]:
            best = (count, times[i])
    return best


def detect_trends(transactions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    txs = [t for t in (transactions or []) if _ts(t) is not None]
    if not txs:
        return {"trends_present": False}

    # 1. Recurring failure cause within rolling window
    cause_times: Dict[str, List[float]] = defaultdict(list)
    for tx in txs:
        if _is_failure(tx):
            cause_times[_cause_label(tx)].append(_ts(tx))

    recurring = []
    for cause, times in cause_times.items():
        if len(times) < _RECUR_MIN_HITS:
            continue
        count, start = _max_window_density(times, _RECUR_WINDOW_S)
        if count >= _RECUR_MIN_HITS:
            recurring.append({
                "cause": cause,
                "occurrences_in_window": count,
                "window_seconds": _RECUR_WINDOW_S,
                "window_start_epoch": start,
                "total_in_trace": len(times),
            })

    # 2. Failure bursts (regardless of cause)
    all_fail_times = sorted(t for times in cause_times.values() for t in times)
    burst_count, burst_start = _max_window_density(all_fail_times, _BURST_WINDOW_S)
    burst = None
    if burst_count >= _BURST_MIN_HITS:
        burst = {
            "failures_in_window": burst_count,
            "window_seconds": _BURST_WINDOW_S,
            "window_start_epoch": burst_start,
        }

    # 3. Cell-level cohort: multiple SUBs (or just many txs) failing on the same cell
    cell_fail_subs: Dict[str, set] = defaultdict(set)
    cell_fail_count: Dict[str, int] = defaultdict(int)
    for tx in txs:
        if not _is_failure(tx):
            continue
        cell = tx.get("cell_id") or tx.get("e_utran_cgi") or tx.get("nr_cgi")
        if not cell:
            continue
        cell_fail_count[str(cell)] += 1
        sub = (tx.get("imsi") or tx.get("supi") or tx.get("sip.from.user")
               or tx.get("nas_eps.emm.imsi") or "")
        if sub:
            cell_fail_subs[str(cell)].add(str(sub))

    cohort = []
    for cell, count in cell_fail_count.items():
        subs = len(cell_fail_subs.get(cell, set()))
        if subs >= _COHORT_MIN_SUBS and count >= _COHORT_MIN_FAILS:
            cohort.append({"cell": cell, "subscribers_affected": subs, "failure_count": count})
    cohort.sort(key=lambda c: -c["failure_count"])

    # 4. Time-of-day buckets (UTC, just hour) — for very long traces this gives
    # cheap "spike at minute X" hints. Trace is usually one slice, so often empty.
    hour_counts = Counter()
    for tx in txs:
        ts = _ts(tx)
        if ts:
            from datetime import datetime, timezone
            try:
                hour_counts[datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:00")] += 1
            except Exception:
                pass

    if not (recurring or burst or cohort):
        return {"trends_present": False}

    return {
        "trends_present": True,
        "recurring_causes": sorted(recurring, key=lambda r: -r["occurrences_in_window"])[:5],
        "failure_burst": burst,
        "cell_cohort_failures": cohort[:5],
        "time_buckets_top": [{"bucket": k, "count": v} for k, v in hour_counts.most_common(3)],
    }


def format_trends_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("trends_present"):
        return "## TREND / PATTERN DETECTION: No recurring patterns detected."

    lines = ["## TREND / PATTERN DETECTION"]
    if summary["recurring_causes"]:
        lines.append("- Recurring failure causes (sliding window):")
        for r in summary["recurring_causes"]:
            lines.append(f"  - {r['cause']}: {r['occurrences_in_window']} in {r['window_seconds']}s (total {r['total_in_trace']})")
    if summary["failure_burst"]:
        b = summary["failure_burst"]
        lines.append(f"- Failure burst: {b['failures_in_window']} failures in {b['window_seconds']}s window")
    if summary["cell_cohort_failures"]:
        lines.append("- Cell-cohort failures (multiple subscribers, same cell):")
        for c in summary["cell_cohort_failures"]:
            lines.append(f"  - Cell {c['cell']}: {c['failure_count']} failures across {c['subscribers_affected']} subscriber(s)")
    if summary.get("time_buckets_top"):
        lines.append("- Top activity hours (UTC):")
        for b in summary["time_buckets_top"]:
            lines.append(f"  - {b['bucket']}: {b['count']} events")
    return "\n".join(lines)
