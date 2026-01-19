"""
Temporal Anomaly Detection Module

Analyzes timing patterns in telecom transactions to identify:
- Latency spikes beyond protocol-specific thresholds
- Retransmission storms
- Timeout patterns (missing responses)
- Inter-message gaps
- Traffic bursts

References:
- 3GPP TS 23.228 Section 4.2.7 (IMS timing requirements)
- 3GPP TS 29.274 Section 7 (GTP-C timer values)
- 3GPP TS 29.244 Section 6 (PFCP timer values)
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from statistics import mean, median, stdev

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    LATENCY_SPIKE = "latency_spike"
    TIMEOUT = "timeout"
    RETRANSMISSION = "retransmission"
    GAP = "inter_message_gap"
    BURST = "traffic_burst"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# Protocol-specific timing thresholds (in milliseconds)
TIMING_THRESHOLDS = {
    "GTPv2-C": {
        "response_timeout_ms": 3000,      # T3-RESPONSE (3GPP TS 29.274)
        "latency_warning_ms": 500,
        "latency_critical_ms": 1500,
        "retry_warning": 2,
        "retry_critical": 4,
    },
    "PFCP": {
        "response_timeout_ms": 5000,      # T1 timer (3GPP TS 29.244)
        "latency_warning_ms": 1000,
        "latency_critical_ms": 3000,
        "retry_warning": 2,
        "retry_critical": 3,
    },
    "SIP": {
        "100_trying_ms": 500,             # RFC 3261 - Timer A
        "180_ringing_ms": 10000,          # Alerting timeout
        "response_timeout_ms": 32000,     # Timer B
        "latency_warning_ms": 200,
        "latency_critical_ms": 1000,
    },
    "Diameter": {
        "response_timeout_ms": 4000,      # Typical Tw timer
        "latency_warning_ms": 1000,
        "latency_critical_ms": 3000,
    },
    "NGAP": {
        "response_timeout_ms": 5000,
        "latency_warning_ms": 500,
        "latency_critical_ms": 2000,
    },
    "S1AP": {
        "response_timeout_ms": 5000,
        "latency_warning_ms": 500,
        "latency_critical_ms": 2000,
    },
    "DEFAULT": {
        "response_timeout_ms": 5000,
        "latency_warning_ms": 1000,
        "latency_critical_ms": 3000,
    }
}


@dataclass
class TemporalAnomaly:
    """Represents a detected timing anomaly"""
    anomaly_type: AnomalyType
    severity: Severity
    protocol: str
    description: str
    evidence: Dict[str, Any]
    threshold: Optional[float] = None
    observed_value: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "protocol": self.protocol,
            "description": self.description,
            "evidence": self.evidence,
            "threshold_ms": self.threshold,
            "observed_ms": self.observed_value,
        }


@dataclass
class TemporalStats:
    """Aggregated timing statistics for a protocol"""
    protocol: str
    transaction_count: int = 0
    latency_min_ms: float = 0
    latency_max_ms: float = 0
    latency_mean_ms: float = 0
    latency_median_ms: float = 0
    latency_p95_ms: float = 0
    latency_p99_ms: float = 0
    timeout_count: int = 0
    retransmission_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "transaction_count": self.transaction_count,
            "latency_min_ms": round(self.latency_min_ms, 2),
            "latency_max_ms": round(self.latency_max_ms, 2),
            "latency_mean_ms": round(self.latency_mean_ms, 2),
            "latency_median_ms": round(self.latency_median_ms, 2),
            "latency_p95_ms": round(self.latency_p95_ms, 2),
            "latency_p99_ms": round(self.latency_p99_ms, 2),
            "timeout_count": self.timeout_count,
            "retransmission_count": self.retransmission_count,
        }


def get_thresholds(protocol: str) -> Dict[str, Any]:
    """Get timing thresholds for a protocol"""
    return TIMING_THRESHOLDS.get(protocol, TIMING_THRESHOLDS["DEFAULT"])


def percentile(data: List[float], p: float) -> float:
    """Calculate percentile (0-100) of a list"""
    if not data:
        return 0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = f + 1 if f + 1 < len(sorted_data) else f
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)


def analyze_temporal_patterns(
    transactions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Main entry point: Analyze transactions for temporal anomalies.
    
    Args:
        transactions: List of transaction dicts from transactions_builder
        
    Returns:
        Dictionary containing:
        - anomalies: List of detected anomalies
        - protocol_stats: Per-protocol timing statistics
        - summary: High-level summary
    """
    logger.info(f"Analyzing temporal patterns in {len(transactions)} transactions")
    
    anomalies: List[TemporalAnomaly] = []
    protocol_latencies: Dict[str, List[float]] = {}
    protocol_timeouts: Dict[str, int] = {}
    protocol_retransmits: Dict[str, int] = {}
    
    # Pass 1: Collect latencies and detect per-transaction anomalies
    for tx in transactions:
        protocol = tx.get("protocol", "Unknown")
        thresholds = get_thresholds(protocol)
        
        # Track latency
        latency = tx.get("latency_ms")
        if latency is not None:
            if protocol not in protocol_latencies:
                protocol_latencies[protocol] = []
            protocol_latencies[protocol].append(latency)
            
            # Check for latency spike
            if latency >= thresholds.get("latency_critical_ms", 3000):
                anomalies.append(TemporalAnomaly(
                    anomaly_type=AnomalyType.LATENCY_SPIKE,
                    severity=Severity.CRITICAL,
                    protocol=protocol,
                    description=f"{protocol} response latency {latency:.0f}ms exceeds critical threshold",
                    evidence={
                        "frame": tx.get("frame_number"),
                        "message_type": tx.get("message_type"),
                        "response_frame": tx.get("response_frame"),
                    },
                    threshold=thresholds.get("latency_critical_ms"),
                    observed_value=latency
                ))
            elif latency >= thresholds.get("latency_warning_ms", 1000):
                anomalies.append(TemporalAnomaly(
                    anomaly_type=AnomalyType.LATENCY_SPIKE,
                    severity=Severity.WARNING,
                    protocol=protocol,
                    description=f"{protocol} response latency {latency:.0f}ms exceeds warning threshold",
                    evidence={
                        "frame": tx.get("frame_number"),
                        "message_type": tx.get("message_type"),
                    },
                    threshold=thresholds.get("latency_warning_ms"),
                    observed_value=latency
                ))
        
        # Check for timeouts (requests without responses)
        if tx.get("type") == "request" and tx.get("status") == "no_response":
            if protocol not in protocol_timeouts:
                protocol_timeouts[protocol] = 0
            protocol_timeouts[protocol] += 1
            
            anomalies.append(TemporalAnomaly(
                anomaly_type=AnomalyType.TIMEOUT,
                severity=Severity.CRITICAL,
                protocol=protocol,
                description=f"{protocol} request timed out (no response captured)",
                evidence={
                    "frame": tx.get("frame_number"),
                    "message_type": tx.get("message_type"),
                    "timestamp": tx.get("timestamp"),
                },
                threshold=thresholds.get("response_timeout_ms"),
                observed_value=None
            ))
        
        # Check for retransmissions
        if tx.get("flags", {}).get("retransmission"):
            if protocol not in protocol_retransmits:
                protocol_retransmits[protocol] = 0
            protocol_retransmits[protocol] += 1
    
    # Pass 2: Generate per-protocol statistics
    protocol_stats: List[TemporalStats] = []
    
    for protocol, latencies in protocol_latencies.items():
        if not latencies:
            continue
            
        stats = TemporalStats(
            protocol=protocol,
            transaction_count=len(latencies),
            latency_min_ms=min(latencies),
            latency_max_ms=max(latencies),
            latency_mean_ms=mean(latencies),
            latency_median_ms=median(latencies),
            latency_p95_ms=percentile(latencies, 95),
            latency_p99_ms=percentile(latencies, 99),
            timeout_count=protocol_timeouts.get(protocol, 0),
            retransmission_count=protocol_retransmits.get(protocol, 0),
        )
        protocol_stats.append(stats)
        
        # Check if p95 exceeds warning threshold (aggregate anomaly)
        thresholds = get_thresholds(protocol)
        if stats.latency_p95_ms >= thresholds.get("latency_warning_ms", 1000):
            anomalies.append(TemporalAnomaly(
                anomaly_type=AnomalyType.LATENCY_SPIKE,
                severity=Severity.WARNING if stats.latency_p95_ms < thresholds.get("latency_critical_ms", 3000) else Severity.CRITICAL,
                protocol=protocol,
                description=f"{protocol} p95 latency ({stats.latency_p95_ms:.0f}ms) indicates systemic delay",
                evidence={
                    "sample_count": stats.transaction_count,
                    "p95_ms": stats.latency_p95_ms,
                    "p99_ms": stats.latency_p99_ms,
                },
                threshold=thresholds.get("latency_warning_ms"),
                observed_value=stats.latency_p95_ms
            ))
    
    # Check for high retransmission rates
    for protocol, count in protocol_retransmits.items():
        thresholds = get_thresholds(protocol)
        if count >= thresholds.get("retry_critical", 4):
            anomalies.append(TemporalAnomaly(
                anomaly_type=AnomalyType.RETRANSMISSION,
                severity=Severity.CRITICAL,
                protocol=protocol,
                description=f"{count} SCTP/TCP retransmissions detected for {protocol}",
                evidence={"retransmission_count": count},
                threshold=thresholds.get("retry_critical"),
                observed_value=count
            ))
        elif count >= thresholds.get("retry_warning", 2):
            anomalies.append(TemporalAnomaly(
                anomaly_type=AnomalyType.RETRANSMISSION,
                severity=Severity.WARNING,
                protocol=protocol,
                description=f"{count} retransmissions detected for {protocol}",
                evidence={"retransmission_count": count},
                threshold=thresholds.get("retry_warning"),
                observed_value=count
            ))
    
    # Generate summary
    critical_count = sum(1 for a in anomalies if a.severity == Severity.CRITICAL)
    warning_count = sum(1 for a in anomalies if a.severity == Severity.WARNING)
    total_timeouts = sum(protocol_timeouts.values())
    total_retransmits = sum(protocol_retransmits.values())
    
    summary = {
        "total_anomalies": len(anomalies),
        "critical_count": critical_count,
        "warning_count": warning_count,
        "timeout_count": total_timeouts,
        "retransmission_count": total_retransmits,
        "protocols_analyzed": list(protocol_latencies.keys()),
    }
    
    logger.info(f"Temporal analysis complete: {critical_count} critical, {warning_count} warning anomalies")
    
    return {
        "anomalies": [a.to_dict() for a in anomalies],
        "protocol_stats": [s.to_dict() for s in protocol_stats],
        "summary": summary,
    }


def format_for_llm(temporal_results: Dict[str, Any]) -> str:
    """
    Format temporal analysis results for inclusion in LLM prompt.
    """
    if not temporal_results or not temporal_results.get("anomalies"):
        return "No temporal anomalies detected."
    
    lines = ["## TEMPORAL ANOMALIES DETECTED"]
    
    # Group by severity
    critical = [a for a in temporal_results["anomalies"] if a["severity"] == "critical"]
    warning = [a for a in temporal_results["anomalies"] if a["severity"] == "warning"]
    
    if critical:
        lines.append("\n**CRITICAL:**")
        for a in critical[:5]:  # Limit to top 5
            lines.append(f"- [{a['protocol']}] {a['description']}")
    
    if warning:
        lines.append("\n**WARNING:**")
        for a in warning[:5]:
            lines.append(f"- [{a['protocol']}] {a['description']}")
    
    # Add protocol stats
    if temporal_results.get("protocol_stats"):
        lines.append("\n**LATENCY STATISTICS:**")
        for stat in temporal_results["protocol_stats"]:
            lines.append(
                f"- {stat['protocol']}: p50={stat['latency_median_ms']:.0f}ms, "
                f"p95={stat['latency_p95_ms']:.0f}ms, p99={stat['latency_p99_ms']:.0f}ms"
            )
    
    return "\n".join(lines)
