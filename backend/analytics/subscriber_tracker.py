"""
Subscriber Identity Correlation Module

Extracts and correlates subscriber identities across protocols:
- IMSI from NAS messages
- MSISDN from SIP headers
- IMEI from Identity Response
- User-Name from Diameter

Enables per-subscriber journey tracking across transactions.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


def extract_subscriber_ids(transactions: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """
    Extract subscriber identities from transactions.
    
    Returns:
        Dict mapping identity type to set of values found
        e.g. {"imsi": {"123456789012345"}, "msisdn": {"+1234567890"}}
    """
    identities = defaultdict(set)
    
    for tx in transactions:
        # IMSI from various fields
        for field in ["imsi", "nas_eps.emm.imsi", "supi", "user_name"]:
            if tx.get(field):
                imsi = _normalize_imsi(tx[field])
                if imsi:
                    identities["imsi"].add(imsi)
        
        # MSISDN from SIP
        if tx.get("protocol") == "SIP":
            # Extract from From/To headers
            for field in ["sip.from.user", "sip.to.user", "sip.p_asserted_identity"]:
                if tx.get(field):
                    msisdn = _extract_msisdn(tx[field])
                    if msisdn:
                        identities["msisdn"].add(msisdn)
        
        # IMEI from NAS
        if tx.get("imei") or tx.get("nas_eps.emm.imei"):
            imei = tx.get("imei") or tx.get("nas_eps.emm.imei")
            if imei:
                identities["imei"].add(str(imei)[:15])  # Truncate to 15 digits
        
        # Diameter User-Name (often IMSI@realm)
        if tx.get("diameter.User-Name"):
            user_name = tx["diameter.User-Name"]
            imsi = _normalize_imsi(user_name.split("@")[0])
            if imsi:
                identities["imsi"].add(imsi)
    
    return dict(identities)


def _normalize_imsi(value: str) -> Optional[str]:
    """Extract and normalize IMSI (15 digits)"""
    if not value:
        return None
    # Remove non-digits
    digits = re.sub(r"\D", "", str(value))
    # IMSI is typically 15 digits
    if 14 <= len(digits) <= 15:
        return digits
    return None


def _extract_msisdn(value: str) -> Optional[str]:
    """Extract MSISDN from SIP URI or tel: URI"""
    if not value:
        return None
    
    # Handle tel: URI
    if "tel:" in value:
        match = re.search(r"tel:([+\d]+)", value)
        if match:
            return match.group(1)
    
    # Handle sip: URI with phone number
    match = re.search(r"(\+?\d{10,15})", value)
    if match:
        return match.group(1)
    
    return None


def group_by_subscriber(
    transactions: List[Dict[str, Any]], 
    identities: Dict[str, Set[str]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group transactions by subscriber.
    
    Returns:
        Dict mapping subscriber ID to list of related transactions
    """
    # Create mapping of any identity value -> canonical subscriber ID
    identity_map = {}
    subscriber_id = 0
    
    for imsi in identities.get("imsi", set()):
        if imsi not in identity_map:
            identity_map[imsi] = f"SUB_{subscriber_id}"
            subscriber_id += 1
    
    for msisdn in identities.get("msisdn", set()):
        if msisdn not in identity_map:
            identity_map[msisdn] = f"SUB_{subscriber_id}"
            subscriber_id += 1
    
    # Group transactions
    grouped = defaultdict(list)
    unassigned = []
    
    for tx in transactions:
        assigned = False
        
        # Check all identity fields
        for field in ["imsi", "nas_eps.emm.imsi", "supi", "user_name", "sip.from.user", "sip.to.user"]:
            value = tx.get(field)
            if value:
                # Normalize and look up
                normalized = _normalize_imsi(value) or _extract_msisdn(value)
                if normalized and normalized in identity_map:
                    grouped[identity_map[normalized]].append(tx)
                    assigned = True
                    break
        
        if not assigned:
            unassigned.append(tx)
    
    # Add unassigned to special group
    if unassigned:
        grouped["UNIDENTIFIED"] = unassigned
    
    return dict(grouped)


def analyze_subscriber_journeys(
    transactions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Main entry point: Extract identities and group transactions.
    
    Returns:
        Dict with:
        - identities: Found subscriber IDs
        - subscribers: Grouped transactions per subscriber
        - summary: Statistics
    """
    logger.info(f"Analyzing subscriber journeys in {len(transactions)} transactions")
    
    identities = extract_subscriber_ids(transactions)
    grouped = group_by_subscriber(transactions, identities)
    
    # Build subscriber summaries
    subscriber_summaries = {}
    for sub_id, txs in grouped.items():
        if sub_id == "UNIDENTIFIED":
            continue
            
        protocols = set(tx.get("protocol", "Unknown") for tx in txs)
        causes = [tx.get("cause_label") or tx.get("cause") for tx in txs if tx.get("cause")]
        
        subscriber_summaries[sub_id] = {
            "transaction_count": len(txs),
            "protocols": list(protocols),
            "failures": len([tx for tx in txs if tx.get("status") == "failure"]),
            "top_causes": causes[:5] if causes else [],
        }
    
    logger.info(f"Found {len(identities.get('imsi', []))} IMSIs, {len(identities.get('msisdn', []))} MSISDNs")
    
    return {
        "identities": {k: list(v) for k, v in identities.items()},
        "subscriber_count": len([s for s in grouped if s != "UNIDENTIFIED"]),
        "unidentified_count": len(grouped.get("UNIDENTIFIED", [])),
        "subscribers": subscriber_summaries,
    }


def format_for_llm(subscriber_data: Dict[str, Any]) -> str:
    """Format subscriber analysis for LLM prompt"""
    if not subscriber_data or subscriber_data.get("subscriber_count", 0) == 0:
        return "## SUBSCRIBER CORRELATION: No subscriber identities detected."
    
    lines = ["## SUBSCRIBER CORRELATION"]
    lines.append(f"- Identified Subscribers: {subscriber_data['subscriber_count']}")
    lines.append(f"- Unidentified Transactions: {subscriber_data['unidentified_count']}")
    
    if subscriber_data.get("identities", {}).get("imsi"):
        lines.append(f"- IMSIs Found: {', '.join(subscriber_data['identities']['imsi'][:3])}")
    
    # Add per-subscriber summaries
    for sub_id, summary in list(subscriber_data.get("subscribers", {}).items())[:5]:
        failures = summary.get("failures", 0)
        if failures > 0:
            lines.append(f"- {sub_id}: {failures} failures in {summary['transaction_count']} transactions")
    
    return "\n".join(lines)
