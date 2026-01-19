"""
Wireshark-Backed Protocol Code Mapper

Provides authoritative code-to-label mappings using Wireshark's value_string tables.
Strategies:
1. Runtime enrichment via `tshark -G values` (cached)
2. Static baseline from 3GPP specs (fallback when TShark unavailable)
3. UNMAPPED label for unknown values (never invents meanings)

References:
- 3GPP TS 29.274 (GTPv2-C)
- 3GPP TS 29.244 (PFCP)
- 3GPP TS 38.413 (NGAP)
- 3GPP TS 36.413 (S1AP)
- RFC 6733 (Diameter)
"""

import subprocess
import shutil
import logging
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Cache file location
CACHE_DIR = Path(__file__).parent.parent / "artifacts" / ".cache"
VALUES_CACHE_FILE = CACHE_DIR / "wireshark_values.json"


class MappingSource(str, Enum):
    """Source of the code mapping"""
    WIRESHARK = "wireshark"      # From tshark -G values
    STATIC_3GPP = "static_3gpp"  # From hardcoded 3GPP specs
    UNMAPPED = "unmapped"        # No mapping found


@dataclass
class CodeMapping:
    """Result of a code mapping lookup"""
    code: int
    label: str
    source: MappingSource
    is_mapped: bool
    protocol: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "source": self.source.value,
            "is_mapped": self.is_mapped,
            "protocol": self.protocol
        }


# Protocol field names in Wireshark's value_string output
PROTOCOL_FIELD_MAP = {
    "GTPv2-C": ["gtpv2.cause", "gtpv2.cause_type"],
    "PFCP": ["pfcp.cause", "pfcp.cause_ie"],
    "Diameter": ["diameter.Result-Code", "diameter.Experimental-Result-Code"],
    "NGAP": ["ngap.Cause", "ngap.CauseRadioNetwork", "ngap.CauseTransport", "ngap.CauseNas", "ngap.CauseProtocol", "ngap.CauseMisc"],
    "S1AP": ["s1ap.Cause", "s1ap.CauseRadioNetwork", "s1ap.CauseTransport", "s1ap.CauseNAS", "s1ap.CauseProtocol", "s1ap.CauseMisc"],
    "NAS-EMM": ["nas_eps.emm.cause"],
    "NAS-ESM": ["nas_eps.esm.cause"],
    "SIP": ["sip.Status-Code"],
}


class WiresharkCodeMapper:
    """
    Authoritative code mapping using Wireshark's built-in definitions.
    Thread-safe singleton pattern for caching.
    """
    
    _instance: Optional['WiresharkCodeMapper'] = None
    _initialized: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if WiresharkCodeMapper._initialized:
            return
            
        self._wireshark_values: Dict[str, Dict[int, str]] = {}
        self._static_values: Dict[str, Dict[int, str]] = {}
        self._load_static_baseline()
        self._load_wireshark_values()
        WiresharkCodeMapper._initialized = True
    
    def _load_static_baseline(self):
        """Load static 3GPP baseline mappings from cause_maps.py"""
        try:
            from .cause_maps import (
                PFCP_CAUSES, GTPV2_CAUSES, NGAP_CAUSES,
                DIAMETER_RESULT_CODES, DIAMETER_3GPP_CODES,
                NAS_EMM_CAUSES, NAS_ESM_CAUSES, SIP_STATUS_CODES
            )
            
            self._static_values = {
                "GTPv2-C": GTPV2_CAUSES,
                "PFCP": PFCP_CAUSES,
                "NGAP": NGAP_CAUSES,
                "S1AP": NGAP_CAUSES,  # Similar cause structure
                "Diameter": {**DIAMETER_RESULT_CODES, **DIAMETER_3GPP_CODES},
                "NAS-EMM": NAS_EMM_CAUSES,
                "NAS-ESM": NAS_ESM_CAUSES,
                "SIP": SIP_STATUS_CODES,
            }
            logger.info("Loaded static 3GPP baseline mappings")
        except ImportError as e:
            logger.warning(f"Could not load static baseline: {e}")
            self._static_values = {}
    
    def _load_wireshark_values(self):
        """
        Load Wireshark value_string tables via `tshark -G values`.
        Uses disk cache to avoid repeated parsing.
        """
        # Try disk cache first
        if self._load_from_cache():
            return
        
        # Check if TShark is available
        if not shutil.which("tshark"):
            logger.warning("TShark not available, using static baseline only")
            return
        
        try:
            logger.info("Parsing Wireshark value_string tables (tshark -G values)...")
            cmd = ["tshark", "-G", "values"]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode != 0:
                logger.warning(f"tshark -G values failed: {result.stderr}")
                return
            
            self._parse_values_output(result.stdout)
            self._save_to_cache()
            logger.info(f"Loaded {sum(len(v) for v in self._wireshark_values.values())} Wireshark mappings")
            
        except subprocess.TimeoutExpired:
            logger.warning("tshark -G values timed out")
        except Exception as e:
            logger.error(f"Error loading Wireshark values: {e}")
    
    def _parse_values_output(self, output: str):
        """
        Parse `tshark -G values` output.
        Format: V  filter_name  value  label
        """
        target_fields = set()
        for fields in PROTOCOL_FIELD_MAP.values():
            target_fields.update(fields)
        
        for line in output.splitlines():
            if not line.startswith("V\t"):
                continue
            
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            
            _, field_name, value_str, label = parts[0], parts[1], parts[2], parts[3]
            
            # Only parse fields we care about
            if field_name not in target_fields:
                continue
            
            try:
                # Handle hex values (0x...)
                if value_str.startswith("0x"):
                    value = int(value_str, 16)
                else:
                    value = int(value_str)
                
                if field_name not in self._wireshark_values:
                    self._wireshark_values[field_name] = {}
                
                self._wireshark_values[field_name][value] = label
                
            except ValueError:
                continue  # Skip non-integer values
    
    def _load_from_cache(self) -> bool:
        """Load cached Wireshark values from disk"""
        try:
            if VALUES_CACHE_FILE.exists():
                with open(VALUES_CACHE_FILE, "r") as f:
                    cached = json.load(f)
                
                # Convert string keys back to integers
                self._wireshark_values = {
                    field: {int(k): v for k, v in values.items()}
                    for field, values in cached.items()
                }
                logger.info(f"Loaded Wireshark values from cache ({VALUES_CACHE_FILE})")
                return True
        except Exception as e:
            logger.debug(f"Cache load failed: {e}")
        return False
    
    def _save_to_cache(self):
        """Save Wireshark values to disk cache"""
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(VALUES_CACHE_FILE, "w") as f:
                json.dump(self._wireshark_values, f, indent=2)
            logger.debug(f"Saved Wireshark values to cache")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def map_code(
        self, 
        protocol: str, 
        code: Any, 
        field_hint: str = None
    ) -> CodeMapping:
        """
        Map a protocol code to its label.
        
        Args:
            protocol: Protocol name (GTPv2-C, PFCP, Diameter, NGAP, S1AP, etc.)
            code: The numeric code to map
            field_hint: Optional Wireshark field name for precise lookup
            
        Returns:
            CodeMapping with label and source information
        """
        # Normalize code to int
        try:
            code_int = int(code)
        except (ValueError, TypeError):
            return CodeMapping(
                code=0,
                label=f"INVALID({code})",
                source=MappingSource.UNMAPPED,
                is_mapped=False,
                protocol=protocol
            )
        
        # Strategy 1: Try Wireshark values first (most authoritative)
        label = self._lookup_wireshark(protocol, code_int, field_hint)
        if label:
            return CodeMapping(
                code=code_int,
                label=label,
                source=MappingSource.WIRESHARK,
                is_mapped=True,
                protocol=protocol
            )
        
        # Strategy 2: Fall back to static 3GPP baseline
        label = self._lookup_static(protocol, code_int)
        if label:
            return CodeMapping(
                code=code_int,
                label=label,
                source=MappingSource.STATIC_3GPP,
                is_mapped=True,
                protocol=protocol
            )
        
        # Strategy 3: Return UNMAPPED
        return CodeMapping(
            code=code_int,
            label=f"UNMAPPED({code_int})",
            source=MappingSource.UNMAPPED,
            is_mapped=False,
            protocol=protocol
        )
    
    def _lookup_wireshark(
        self, 
        protocol: str, 
        code: int, 
        field_hint: str = None
    ) -> Optional[str]:
        """Look up code in Wireshark values"""
        # If specific field hint provided, check it first
        if field_hint and field_hint in self._wireshark_values:
            return self._wireshark_values[field_hint].get(code)
        
        # Otherwise check all fields for this protocol
        fields = PROTOCOL_FIELD_MAP.get(protocol, [])
        for field in fields:
            if field in self._wireshark_values:
                label = self._wireshark_values[field].get(code)
                if label:
                    return label
        
        return None
    
    def _lookup_static(self, protocol: str, code: int) -> Optional[str]:
        """Look up code in static baseline"""
        protocol_map = self._static_values.get(protocol, {})
        return protocol_map.get(code)
    
    def enrich_transactions(
        self, 
        transactions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Batch-enrich transactions with mapped cause codes.
        
        Adds 'cause_mapped' field to each transaction that has a cause code.
        """
        enriched = []
        
        for tx in transactions:
            tx_copy = tx.copy()
            
            # Check for various cause code field names
            cause_fields = [
                ("cause_code", "cause_mapped"),
                ("result_code", "result_mapped"),
                ("pfcp_cause", "pfcp_cause_mapped"),
                ("gtpv2_cause", "gtpv2_cause_mapped"),
                ("ngap_cause", "ngap_cause_mapped"),
                ("diameter_result", "diameter_result_mapped"),
            ]
            
            protocol = tx.get("protocol", "Unknown")
            
            for code_field, mapped_field in cause_fields:
                if code_field in tx and tx[code_field] is not None:
                    mapping = self.map_code(protocol, tx[code_field])
                    tx_copy[mapped_field] = mapping.to_dict()
            
            enriched.append(tx_copy)
        
        return enriched
    
    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about loaded mappings"""
        return {
            "wireshark_fields": len(self._wireshark_values),
            "wireshark_total_values": sum(len(v) for v in self._wireshark_values.values()),
            "static_protocols": len(self._static_values),
            "static_total_values": sum(len(v) for v in self._static_values.values()),
            "tshark_available": shutil.which("tshark") is not None,
        }


# Module-level singleton accessor
_mapper_instance: Optional[WiresharkCodeMapper] = None

def get_mapper() -> WiresharkCodeMapper:
    """Get or create the singleton mapper instance"""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = WiresharkCodeMapper()
    return _mapper_instance


def map_protocol_code(protocol: str, code: Any, field_hint: str = None) -> Dict[str, Any]:
    """
    Convenience function for mapping a single code.
    
    Usage:
        result = map_protocol_code("GTPv2-C", 16)
        # {"code": 16, "label": "Request Accepted", "source": "wireshark", "is_mapped": true}
    """
    return get_mapper().map_code(protocol, code, field_hint).to_dict()


def enrich_transactions_with_codes(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function for batch enrichment.
    """
    return get_mapper().enrich_transactions(transactions)
