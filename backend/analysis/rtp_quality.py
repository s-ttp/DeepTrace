"""
RTP Quality Analyzer Module
Calculates voice quality metrics: jitter, packet loss, and MOS estimation.
"""
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import logging
import math

logger = logging.getLogger(__name__)


class RtpQualityAnalyzer:
    """
    Analyzes RTP/RTCP data for voice quality metrics.
    
    Metrics:
    - Jitter: Inter-arrival time variation (ITU-T P.861)
    - Packet Loss: Percentage of missing sequence numbers
    - MOS-LQE: Mean Opinion Score estimation based on E-model
    """
    
    # E-model constants (ITU-T G.107)
    R_FACTOR_BASE = 93.2  # Maximum R-factor
    
    def __init__(self):
        pass
    
    def analyze_rtp_stream(
        self, 
        rtp_packets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze a single RTP stream for quality metrics.
        
        Args:
            rtp_packets: List of RTP packet data with seq, timestamp, arrival_time
            
        Returns:
            {
                "ssrc": str,
                "packet_count": int,
                "jitter_ms": float,
                "packet_loss_pct": float,
                "out_of_order": int,
                "duplicates": int,
                "mos_lqe": float,
                "quality_rating": str
            }
        """
        if not rtp_packets:
            return self._empty_metrics()
        
        # Sort by sequence number
        sorted_pkts = sorted(rtp_packets, key=lambda p: int(p.get("rtp.seq", 0)))
        
        ssrc = sorted_pkts[0].get("rtp.ssrc", "unknown")
        packet_count = len(sorted_pkts)
        
        # Calculate metrics
        jitter_ms = self._calculate_jitter(sorted_pkts)
        loss_pct, out_of_order, duplicates = self._calculate_loss(sorted_pkts)
        mos = self._estimate_mos(jitter_ms, loss_pct)
        
        return {
            "ssrc": ssrc,
            "packet_count": packet_count,
            "jitter_ms": round(jitter_ms, 2),
            "packet_loss_pct": round(loss_pct, 2),
            "out_of_order": out_of_order,
            "duplicates": duplicates,
            "mos_lqe": round(mos, 2),
            "quality_rating": self._mos_to_rating(mos)
        }
    
    def _calculate_jitter(self, packets: List[Dict[str, Any]]) -> float:
        """
        Calculate mean jitter using RFC 3550 algorithm.
        
        Jitter = mean deviation of inter-arrival time from expected spacing.
        """
        if len(packets) < 2:
            return 0.0
        
        jitter_sum = 0.0
        prev_arrival = None
        prev_rtp_ts = None
        jitter_samples = 0
        
        # Assume 8kHz sample rate (AMR-NB) = 8 samples/ms
        # Adjust based on payload type if needed
        clock_rate = 8000
        
        for pkt in packets:
            arrival = float(pkt.get("frame.time_epoch", 0))
            rtp_ts = int(pkt.get("rtp.timestamp", 0))
            
            if prev_arrival is not None and prev_rtp_ts is not None:
                # Inter-arrival time in ms
                arrival_diff = (arrival - prev_arrival) * 1000
                
                # Expected inter-packet time based on RTP timestamp
                ts_diff = (rtp_ts - prev_rtp_ts) / clock_rate * 1000
                
                # Jitter is deviation from expected
                if ts_diff > 0:
                    deviation = abs(arrival_diff - ts_diff)
                    jitter_sum += deviation
                    jitter_samples += 1
            
            prev_arrival = arrival
            prev_rtp_ts = rtp_ts
        
        if jitter_samples == 0:
            return 0.0
        
        return jitter_sum / jitter_samples
    
    def _calculate_loss(
        self, 
        packets: List[Dict[str, Any]]
    ) -> Tuple[float, int, int]:
        """
        Calculate packet loss percentage, out-of-order count, and duplicates.
        
        Returns:
            (loss_percentage, out_of_order_count, duplicate_count)
        """
        if len(packets) < 2:
            return 0.0, 0, 0
        
        sequences = [int(p.get("rtp.seq", 0)) for p in packets]
        
        # Handle sequence number wraparound (16-bit)
        min_seq = min(sequences)
        max_seq = max(sequences)
        
        # Detect wraparound
        if max_seq - min_seq > 32768:
            # Adjust sequences that wrapped
            sequences = [s + 65536 if s < 32768 else s for s in sequences]
            min_seq = min(sequences)
            max_seq = max(sequences)
        
        expected_count = max_seq - min_seq + 1
        received_count = len(sequences)
        
        # Count duplicates
        unique_seqs = set()
        duplicates = 0
        out_of_order = 0
        prev_seq = None
        
        for seq in sequences:
            if seq in unique_seqs:
                duplicates += 1
            else:
                unique_seqs.add(seq)
            
            if prev_seq is not None and seq < prev_seq:
                out_of_order += 1
            prev_seq = seq
        
        unique_count = len(unique_seqs)
        lost_count = expected_count - unique_count
        
        loss_pct = (lost_count / expected_count * 100) if expected_count > 0 else 0.0
        
        return max(0, loss_pct), out_of_order, duplicates
    
    def _estimate_mos(self, jitter_ms: float, loss_pct: float) -> float:
        """
        Estimate MOS-LQE using simplified E-model (ITU-T G.107).
        
        This is a simplified estimation - production systems should use
        more sophisticated algorithms like PESQ or POLQA.
        """
        # E-model R-factor calculation (simplified)
        # R = R0 - Is - Id - Ie + A
        
        # Base R-factor
        r = self.R_FACTOR_BASE
        
        # Delay impairment (simplified - assume 100ms one-way delay + jitter)
        delay_ms = 100 + jitter_ms
        if delay_ms > 177:
            r -= 0.024 * (delay_ms - 177)
        
        # Equipment impairment (packet loss)
        # Ie = α + β * ln(1 + γ * loss)
        # For AMR-NB, typical values: α=0, β=30, γ=15
        if loss_pct > 0:
            ie = 30 * math.log(1 + 15 * loss_pct)
            r -= ie
        
        # Clamp R-factor
        r = max(0, min(100, r))
        
        # Convert R-factor to MOS (ITU-T G.107 formula)
        if r < 0:
            mos = 1.0
        elif r > 100:
            mos = 4.5
        else:
            mos = 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)
        
        return max(1.0, min(5.0, mos))
    
    def _mos_to_rating(self, mos: float) -> str:
        """Convert MOS score to quality rating."""
        if mos >= 4.3:
            return "Excellent"
        elif mos >= 4.0:
            return "Good"
        elif mos >= 3.6:
            return "Fair"
        elif mos >= 3.1:
            return "Poor"
        else:
            return "Bad"
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure."""
        return {
            "ssrc": "unknown",
            "packet_count": 0,
            "jitter_ms": 0.0,
            "packet_loss_pct": 0.0,
            "out_of_order": 0,
            "duplicates": 0,
            "mos_lqe": 0.0,
            "quality_rating": "Unknown"
        }
    
    def analyze_rtcp_reports(
        self, 
        rtcp_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Parse RTCP Receiver Reports for network-reported quality.
        
        Args:
            rtcp_data: RTCP packets with rtcp.jitter, rtcp.lost, rtcp.fraction
            
        Returns:
            {
                "reports_found": int,
                "avg_jitter_ms": float,
                "total_lost": int,
                "avg_fraction_lost": float
            }
        """
        if not rtcp_data:
            return {
                "reports_found": 0,
                "avg_jitter_ms": 0.0,
                "total_lost": 0,
                "avg_fraction_lost": 0.0
            }
        
        jitter_values = []
        lost_values = []
        fraction_values = []
        
        for pkt in rtcp_data:
            if pkt.get("rtcp.jitter"):
                try:
                    # RTCP jitter is in timestamp units, convert to ms
                    # Assume 8kHz clock rate
                    jitter = int(pkt["rtcp.jitter"]) / 8  # ms
                    jitter_values.append(jitter)
                except (ValueError, TypeError):
                    pass
            
            if pkt.get("rtcp.lost"):
                try:
                    lost_values.append(int(pkt["rtcp.lost"]))
                except (ValueError, TypeError):
                    pass
            
            if pkt.get("rtcp.fraction"):
                try:
                    # Fraction is 0-255, convert to percentage
                    fraction = int(pkt["rtcp.fraction"]) / 256 * 100
                    fraction_values.append(fraction)
                except (ValueError, TypeError):
                    pass
        
        return {
            "reports_found": len(rtcp_data),
            "avg_jitter_ms": round(sum(jitter_values) / len(jitter_values), 2) if jitter_values else 0.0,
            "total_lost": sum(lost_values) if lost_values else 0,
            "avg_fraction_lost": round(sum(fraction_values) / len(fraction_values), 2) if fraction_values else 0.0
        }
    
    def analyze_call_streams(
        self,
        call_id: str,
        rtp_packets: List[Dict[str, Any]],
        rtcp_packets: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze all streams for a single call.
        
        Returns:
            {
                "call_id": str,
                "streams": [{...metrics per SSRC...}],
                "rtcp_reports": {...},
                "aggregate": {
                    "avg_jitter_ms": float,
                    "avg_loss_pct": float,
                    "min_mos": float,
                    "overall_quality": str
                }
            }
        """
        # Group RTP by SSRC
        ssrc_groups = defaultdict(list)
        for pkt in rtp_packets:
            ssrc = pkt.get("rtp.ssrc", "unknown")
            ssrc_groups[ssrc].append(pkt)
        
        streams = []
        all_jitter = []
        all_loss = []
        all_mos = []
        
        for ssrc, pkts in ssrc_groups.items():
            if len(pkts) < 10:  # Skip very small streams
                continue
            
            metrics = self.analyze_rtp_stream(pkts)
            streams.append(metrics)
            
            if metrics["jitter_ms"] > 0:
                all_jitter.append(metrics["jitter_ms"])
            all_loss.append(metrics["packet_loss_pct"])
            if metrics["mos_lqe"] > 0:
                all_mos.append(metrics["mos_lqe"])
        
        # RTCP analysis
        rtcp_reports = self.analyze_rtcp_reports(rtcp_packets or [])
        
        # Aggregate
        aggregate = {
            "avg_jitter_ms": round(sum(all_jitter) / len(all_jitter), 2) if all_jitter else 0.0,
            "avg_loss_pct": round(sum(all_loss) / len(all_loss), 2) if all_loss else 0.0,
            "min_mos": round(min(all_mos), 2) if all_mos else 0.0,
            "overall_quality": self._mos_to_rating(min(all_mos)) if all_mos else "Unknown"
        }
        
        return {
            "call_id": call_id,
            "streams": streams,
            "rtcp_reports": rtcp_reports,
            "aggregate": aggregate
        }
    
    def detect_quality_issues(
        self,
        quality_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate findings based on quality thresholds.
        """
        findings = []
        call_id = quality_data.get("call_id", "unknown")
        aggregate = quality_data.get("aggregate", {})
        
        # High jitter (>50ms is problematic)
        if aggregate.get("avg_jitter_ms", 0) > 50:
            findings.append({
                "call_id": call_id,
                "type": "rtp_quality",
                "severity": "warning" if aggregate["avg_jitter_ms"] < 100 else "critical",
                "title": "High Jitter Detected",
                "description": f"Average jitter {aggregate['avg_jitter_ms']}ms exceeds acceptable threshold",
                "evidence": {
                    "jitter_ms": aggregate["avg_jitter_ms"],
                    "threshold": 50
                },
                "confidence": "high"
            })
        
        # High packet loss (>2% is problematic)
        if aggregate.get("avg_loss_pct", 0) > 2:
            findings.append({
                "call_id": call_id,
                "type": "rtp_quality",
                "severity": "warning" if aggregate["avg_loss_pct"] < 5 else "critical",
                "title": "High Packet Loss",
                "description": f"Packet loss {aggregate['avg_loss_pct']}% exceeds acceptable threshold",
                "evidence": {
                    "loss_pct": aggregate["avg_loss_pct"],
                    "threshold": 2
                },
                "confidence": "high"
            })
        
        # Low MOS (<3.5 is poor quality)
        if aggregate.get("min_mos", 5) < 3.5:
            findings.append({
                "call_id": call_id,
                "type": "rtp_quality",
                "severity": "warning" if aggregate["min_mos"] >= 3.0 else "critical",
                "title": "Poor Voice Quality",
                "description": f"Estimated MOS {aggregate['min_mos']} indicates {aggregate.get('overall_quality', 'Poor')} quality",
                "evidence": {
                    "mos": aggregate["min_mos"],
                    "rating": aggregate.get("overall_quality")
                },
                "confidence": "medium"  # MOS is estimated, not measured
            })
        
        return findings


def format_rtp_quality_for_llm(quality_results: List[Dict[str, Any]]) -> str:
    """Format RTP quality analysis for LLM prompt."""
    if not quality_results:
        return "## RTP QUALITY: No RTP quality data available (media plane may not be captured)."
    
    lines = ["## RTP QUALITY METRICS"]
    
    for result in quality_results[:5]:
        call_id = result.get("call_id", "unknown")[:8]
        agg = result.get("aggregate", {})
        
        lines.append(f"- **Call {call_id}**:")
        lines.append(f"  - Jitter: {agg.get('avg_jitter_ms', 'N/A')}ms")
        lines.append(f"  - Packet Loss: {agg.get('avg_loss_pct', 'N/A')}%")
        lines.append(f"  - Estimated MOS: {agg.get('min_mos', 'N/A')} ({agg.get('overall_quality', 'N/A')})")
    
    return "\n".join(lines)
