"""
Codec Analyzer Module
Detects codec mismatches between SDP offer and answer.
"""
from typing import List, Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Known codec compatibility groups
CODEC_FAMILIES = {
    "AMR": ["AMR", "AMR-NB"],
    "AMR-WB": ["AMR-WB"],
    "EVS": ["EVS"],
    "G711": ["PCMU", "PCMA", "G711"],
    "G729": ["G729", "G729A"],
}

# Codec priority for quality (higher = better)
CODEC_QUALITY_RANK = {
    "EVS": 100,
    "AMR-WB": 80,
    "AMR": 60,
    "AMR-NB": 60,
    "G729": 40,
    "PCMA": 30,
    "PCMU": 30,
}


class CodecAnalyzer:
    """
    Analyzes SDP codec negotiation for mismatches and compatibility issues.
    """
    
    def __init__(self):
        pass
    
    def analyze_call_codecs(self, call_media: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze codec negotiation for all calls.
        
        Args:
            call_media: Output from SdpParser.extract_from_transactions()
                        {call_id: {"offer": [...], "answer": [...], "expected_ports": [...]}}
        
        Returns:
            List of codec findings
        """
        findings = []
        
        for call_id, media_info in call_media.items():
            offer = media_info.get("offer", [])
            answer = media_info.get("answer", [])
            
            if not offer:
                continue
            
            # Analyze each media type (audio, video)
            for media_type in ["audio", "video"]:
                offer_media = [m for m in offer if m.get("type") == media_type]
                answer_media = [m for m in answer if m.get("type") == media_type]
                
                if not offer_media:
                    continue
                
                # Check 1: No answer for offered media
                if offer_media and not answer_media:
                    findings.append({
                        "call_id": call_id,
                        "type": "codec_rejection",
                        "severity": "warning",
                        "title": f"{media_type.title()} Media Rejected",
                        "description": f"Offered {media_type} was not accepted in answer",
                        "evidence": {
                            "offered_codecs": [m.get("codec") for m in offer_media],
                            "answer": "No answer SDP for this media type"
                        },
                        "confidence": "high"
                    })
                    continue
                
                # Check 2: Codec mismatch (offer vs answer)
                offer_codecs = set(m.get("codec", "").upper() for m in offer_media if m.get("codec"))
                answer_codecs = set(m.get("codec", "").upper() for m in answer_media if m.get("codec"))
                
                if answer_codecs and not (offer_codecs & answer_codecs):
                    # Answer codec not in offer - potential transcoding
                    findings.append({
                        "call_id": call_id,
                        "type": "codec_mismatch",
                        "severity": "warning",
                        "title": f"{media_type.title()} Codec Mismatch",
                        "description": f"Answer codec not in original offer - transcoding may occur",
                        "evidence": {
                            "offered": list(offer_codecs),
                            "answered": list(answer_codecs)
                        },
                        "confidence": "medium"
                    })
                
                # Check 3: Quality downgrade (e.g., AMR-WB offered, AMR-NB answered)
                downgrade = self._check_quality_downgrade(offer_media, answer_media)
                if downgrade:
                    findings.append({
                        "call_id": call_id,
                        "type": "codec_downgrade",
                        "severity": "info",
                        "title": f"{media_type.title()} Codec Downgrade",
                        "description": downgrade["description"],
                        "evidence": downgrade["evidence"],
                        "confidence": "high"
                    })
                
                # Check 4: Incompatible codec family
                incompatible = self._check_family_compatibility(offer_media, answer_media)
                if incompatible:
                    findings.append({
                        "call_id": call_id,
                        "type": "codec_incompatible",
                        "severity": "critical",
                        "title": f"{media_type.title()} Codec Incompatibility",
                        "description": incompatible["description"],
                        "evidence": incompatible["evidence"],
                        "confidence": "high"
                    })
        
        return findings
    
    def _check_quality_downgrade(
        self, 
        offer_media: List[Dict], 
        answer_media: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Check if answer codec is lower quality than best offered."""
        if not offer_media or not answer_media:
            return None
        
        # Get best offered codec quality
        best_offer_quality = 0
        best_offer_codec = None
        for m in offer_media:
            codec = (m.get("codec") or "").upper()
            quality = CODEC_QUALITY_RANK.get(codec, 0)
            if quality > best_offer_quality:
                best_offer_quality = quality
                best_offer_codec = codec
        
        # Get answer codec quality
        answer_codec = (answer_media[0].get("codec") or "").upper() if answer_media else None
        answer_quality = CODEC_QUALITY_RANK.get(answer_codec, 0) if answer_codec else 0
        
        # Significant downgrade (>20 points)
        if best_offer_quality - answer_quality >= 20:
            return {
                "description": f"Codec quality downgraded from {best_offer_codec} to {answer_codec}",
                "evidence": {
                    "best_offered": best_offer_codec,
                    "offered_quality": best_offer_quality,
                    "answered": answer_codec,
                    "answer_quality": answer_quality,
                    "quality_loss": best_offer_quality - answer_quality
                }
            }
        
        return None
    
    def _check_family_compatibility(
        self, 
        offer_media: List[Dict], 
        answer_media: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Check for incompatible codec families (may cause no audio)."""
        if not offer_media or not answer_media:
            return None
        
        offer_codecs = [m.get("codec", "").upper() for m in offer_media if m.get("codec")]
        answer_codec = (answer_media[0].get("codec") or "").upper() if answer_media else None
        
        if not answer_codec:
            return None
        
        # Find offer codec families
        offer_families = set()
        for codec in offer_codecs:
            for family, members in CODEC_FAMILIES.items():
                if codec in [m.upper() for m in members]:
                    offer_families.add(family)
        
        # Find answer codec family
        answer_family = None
        for family, members in CODEC_FAMILIES.items():
            if answer_codec in [m.upper() for m in members]:
                answer_family = family
                break
        
        # Check if answer family was offered
        if answer_family and offer_families and answer_family not in offer_families:
            return {
                "description": f"Answer codec family ({answer_family}) not in offered families",
                "evidence": {
                    "offered_families": list(offer_families),
                    "answer_family": answer_family,
                    "answer_codec": answer_codec
                }
            }
        
        return None
    
    def generate_codec_summary(
        self, 
        call_media: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate aggregate codec statistics for LLM context.
        """
        total_calls = len(call_media)
        codec_usage = {}
        
        for call_id, media_info in call_media.items():
            for phase in ["offer", "answer"]:
                for m in media_info.get(phase, []):
                    codec = m.get("codec")
                    if codec:
                        key = f"{phase}_{codec}"
                        codec_usage[key] = codec_usage.get(key, 0) + 1
        
        return {
            "total_calls_with_media": total_calls,
            "codec_usage": codec_usage
        }


def format_codec_context_for_llm(
    findings: List[Dict[str, Any]], 
    call_media: Dict[str, Dict[str, Any]]
) -> str:
    """Format codec analysis for LLM prompt."""
    if not call_media:
        return "## CODEC NEGOTIATION: No SDP media detected."
    
    lines = ["## CODEC NEGOTIATION"]
    
    # Summary table
    for call_id, media_info in list(call_media.items())[:5]:
        offer = media_info.get("offer", [])
        answer = media_info.get("answer", [])
        
        offer_codecs = [m.get("codec", "?") for m in offer]
        answer_codecs = [m.get("codec", "?") for m in answer]
        
        lines.append(f"- Call {call_id[:8]}: Offer=[{', '.join(offer_codecs)}] → Answer=[{', '.join(answer_codecs)}]")
    
    # Findings
    if findings:
        lines.append("\n### Codec Issues Detected:")
        for f in findings[:5]:
            lines.append(f"- **{f['title']}** ({f['severity']}): {f['description']}")
    
    return "\n".join(lines)
