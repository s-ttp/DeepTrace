import statistics
from typing import List, Dict, Any, Tuple
from collections import Counter
import logging

logger = logging.getLogger(__name__)

def calculate_procedure_kpis(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate KPIs per procedure type:
    - Attempts
    - Success Rate
    - Avg Latency
    - Top Cause Codes
    """
    kpis = {}
    
    # Group by procedure/message type
    grouped = {}
    for tx in transactions:
        proc = tx.get("message_type") or tx.get("protocol") or "Unknown"
        if proc not in grouped:
            grouped[proc] = []
        grouped[proc].append(tx)
        
    for proc, txs in grouped.items():
        total = len(txs)
        successes = len([t for t in txs if t.get("status") == "success"])
        failures = total - successes
        
        # Latency
        latencies = [t["latency_ms"] for t in txs if t.get("latency_ms") is not None]
        avg_latency = statistics.mean(latencies) if latencies else 0
        
        # Cause Codes
        causes = [t.get("cause_label") or t.get("cause") for t in txs if t.get("cause")]
        top_causes = dict(Counter(causes).most_common(5))
        
        kpis[proc] = {
            "attempts": total,
            "success_rate": (successes / total) * 100 if total > 0 else 0,
            "avg_latency_ms": round(avg_latency, 2),
            "top_causes": top_causes
        }
        
    return kpis

def compare_time_windows(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enhanced baseline comparison:
    - Compare first 25% (baseline) vs rest (incident window)
    - Track success rate changes
    - Track latency percentile shifts
    - Detect new failure codes
    """
    if not transactions:
        return {}
        
    # Sort by timestamp
    sorted_tx = sorted(transactions, key=lambda x: x.get("timestamp", 0))
    
    cutoff = max(1, int(len(sorted_tx) * 0.25))
    baseline = sorted_tx[:cutoff]
    incident = sorted_tx[cutoff:]
    
    if not baseline or not incident:
        return {}
    
    base_kpis = calculate_procedure_kpis(baseline)
    inc_kpis = calculate_procedure_kpis(incident)
    
    # Calculate deltas
    deltas = {}
    all_procs = set(base_kpis.keys()) | set(inc_kpis.keys())
    
    for proc in all_procs:
        base_data = base_kpis.get(proc, {})
        inc_data = inc_kpis.get(proc, {})
        
        base_sr = base_data.get("success_rate", 0)
        inc_sr = inc_data.get("success_rate", 0)
        base_latency = base_data.get("avg_latency_ms", 0)
        inc_latency = inc_data.get("avg_latency_ms", 0)
        
        # Track significant changes
        changes = {}
        
        # Success rate change
        sr_delta = inc_sr - base_sr
        if abs(sr_delta) > 5.0:
            changes["success_rate"] = {
                "change_type": "degradation" if sr_delta < 0 else "improvement",
                "baseline": round(base_sr, 1),
                "incident": round(inc_sr, 1),
                "delta": round(sr_delta, 1)
            }
        
        # Latency change (>25% increase is significant)
        if base_latency > 0:
            latency_pct_change = ((inc_latency - base_latency) / base_latency) * 100
            if latency_pct_change > 25:
                changes["latency"] = {
                    "change_type": "degradation",
                    "baseline_ms": round(base_latency, 2),
                    "incident_ms": round(inc_latency, 2),
                    "pct_increase": round(latency_pct_change, 1)
                }
        
        # New failure codes
        base_causes = set(base_data.get("top_causes", {}).keys())
        inc_causes = set(inc_data.get("top_causes", {}).keys())
        new_causes = inc_causes - base_causes
        if new_causes:
            changes["new_failure_codes"] = list(new_causes)
        
        if changes:
            deltas[proc] = changes
            
    return {
        "baseline_window": f"First {cutoff} transactions",
        "incident_window": f"Remaining {len(incident)} transactions",
        "procedure_deltas": deltas,
        "summary": {
            "degraded_procedures": len([d for d in deltas.values() if d.get("success_rate", {}).get("change_type") == "degradation"]),
            "improved_procedures": len([d for d in deltas.values() if d.get("success_rate", {}).get("change_type") == "improvement"]),
            "new_failure_codes_detected": any("new_failure_codes" in d for d in deltas.values()),
        }
    }

