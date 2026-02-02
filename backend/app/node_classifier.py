"""
Node Classifier Module

Implements hybrid node identification:
1. Deterministic rules based on protocol signaling patterns
2. LLM-assisted classification for unresolved nodes
"""
import logging
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

# =============================================================================
# Deterministic Rule Sets
# =============================================================================

# NGAP (5G N2 interface) - procedureCode based
NGAP_NODE_RULES = {
    # InitialUEMessage (15) - sent by gNB
    "15": ("src", "gNB"),
    # DownlinkNASTransport (4) - sent by AMF
    "4": ("src", "AMF"),
    # UplinkNASTransport (46) - sent by gNB
    "46": ("src", "gNB"),
    # InitialContextSetupRequest (14) - sent by AMF
    "14": ("src", "AMF"),
    # InitialContextSetupResponse - sent by gNB
    "InitialContextSetupResponse": ("src", "gNB"),
    # PDUSessionResourceSetupRequest (29) - sent by AMF
    "29": ("src", "AMF"),
    # PDUSessionResourceSetupResponse - sent by gNB
    "PDUSessionResourceSetupResponse": ("src", "gNB"),
    # UEContextReleaseCommand (41) - sent by AMF
    "41": ("src", "AMF"),
    # UEContextReleaseComplete - sent by gNB
    "UEContextReleaseComplete": ("src", "gNB"),
    # HandoverRequired (0) - sent by source gNB
    "0": ("src", "gNB"),
    # HandoverRequest (1) - sent by AMF to target gNB
    "1": ("src", "AMF"),
}

# S1AP (4G S1 interface) - procedureCode based
S1AP_NODE_RULES = {
    # InitialUEMessage (12) - sent by eNB
    "12": ("src", "eNB"),
    # DownlinkNASTransport (11) - sent by MME
    "11": ("src", "MME"),
    # UplinkNASTransport (13) - sent by eNB
    "13": ("src", "eNB"),
    # InitialContextSetupRequest (9) - sent by MME
    "9": ("src", "MME"),
    # InitialContextSetupResponse - sent by eNB
    "InitialContextSetupResponse": ("src", "eNB"),
    # UEContextReleaseCommand (23) - sent by MME
    "23": ("src", "MME"),
    # S1Setup - sent by eNB
    "17": ("src", "eNB"),
    # S1SetupResponse - sent by MME
    "S1SetupResponse": ("src", "MME"),
}

# Diameter (interface, command) -> (direction, node_type)
DIAMETER_NODE_RULES = {
    # S6a interface (MME <-> HSS)
    ("S6a", "ULR"): ("src", "MME"),      # Update-Location-Request
    ("S6a", "ULA"): ("src", "HSS"),      # Update-Location-Answer
    ("S6a", "AIR"): ("src", "MME"),      # Authentication-Info-Request
    ("S6a", "AIA"): ("src", "HSS"),      # Authentication-Info-Answer
    ("S6a", "CLR"): ("src", "HSS"),      # Cancel-Location-Request
    ("S6a", "PUR"): ("src", "MME"),      # Purge-UE-Request
    
    # Gx interface (PCEF <-> PCRF)
    ("Gx", "CCR"): ("src", "PCEF"),      # Credit-Control-Request
    ("Gx", "CCA"): ("src", "PCRF"),      # Credit-Control-Answer
    ("Gx", "RAR"): ("src", "PCRF"),      # Re-Auth-Request
    
    # Rx interface (AF <-> PCRF)
    ("Rx", "AAR"): ("src", "AF"),        # AA-Request
    ("Rx", "AAA"): ("src", "PCRF"),      # AA-Answer
    ("Rx", "STR"): ("src", "AF"),        # Session-Termination-Request
    
    # Gy interface (OCS <-> PCEF)
    ("Gy", "CCR"): ("src", "PCEF"),
    ("Gy", "CCA"): ("src", "OCS"),
    
    # Cx interface (I-CSCF/S-CSCF <-> HSS)
    ("Cx", "UAR"): ("src", "I-CSCF"),    # User-Authorization-Request
    ("Cx", "UAA"): ("src", "HSS"),
    ("Cx", "SAR"): ("src", "S-CSCF"),    # Server-Assignment-Request
    ("Cx", "SAA"): ("src", "HSS"),
    ("Cx", "MAR"): ("src", "I-CSCF"),    # Multimedia-Auth-Request
    ("Cx", "MAA"): ("src", "HSS"),
}

# PFCP (N4 interface) - message type based
PFCP_NODE_RULES = {
    # Session Establishment Request (50) - sent by SMF/SGW-C
    "50": ("src", "SMF"),
    # Session Establishment Response (51) - sent by UPF/SGW-U
    "51": ("src", "UPF"),
    # Session Modification Request (52) - sent by SMF
    "52": ("src", "SMF"),
    # Session Modification Response (53) - sent by UPF
    "53": ("src", "UPF"),
    # Session Deletion Request (54) - sent by SMF
    "54": ("src", "SMF"),
    # Session Deletion Response (55) - sent by UPF
    "55": ("src", "UPF"),
    # Heartbeat Request (1) - either direction
    # Association Setup Request (5) - declaring node
    "5": ("src", "PFCP_CP"),
    # Association Setup Response (6)
    "6": ("src", "PFCP_UP"),
}

# SIP node identification
SIP_NODE_RULES = {
    # Based on Via/Contact headers and message patterns
    "REGISTER_request": ("src", "UE"),
    "REGISTER_200": ("src", "S-CSCF"),
    "REGISTER_401": ("src", "S-CSCF"),
    "INVITE_request": ("src", "Caller"),
    "100_Trying": ("src", "P-CSCF"),
    "180_Ringing": ("src", "Callee"),
    "183_Progress": ("src", "Callee"),
    "200_INVITE": ("src", "Callee"),
    "BYE_request": ("src", "Terminator"),
}


class NodeEvidence:
    """Collects signaling evidence for an IP address."""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.protocols: Set[str] = set()
        self.messages_sent: List[str] = []
        self.messages_received: List[str] = []
        self.ports: Set[int] = set()
        self.peers: Set[str] = set()
        self.inferred_types: List[Tuple[str, str]] = []  # (type, reason)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "protocols": list(self.protocols),
            "messages_sent": self.messages_sent[:10],  # Limit for prompt
            "messages_received": self.messages_received[:10],
            "ports": list(self.ports),
            "peers": list(self.peers)[:5],
            "inferred_types": self.inferred_types,
        }


class NodeClassifier:
    """
    Hybrid node classifier using deterministic rules + LLM.
    """
    
    def __init__(self):
        self.evidence_map: Dict[str, NodeEvidence] = {}
        self.node_map: Dict[str, str] = {}  # Final IP -> NodeType
        self._cache: Dict[str, str] = {}  # Persistent cache
    
    def build_evidence(self, transactions: List[Dict[str, Any]]) -> Dict[str, NodeEvidence]:
        """
        Analyze transactions to build signaling evidence per IP.
        Uses normalized transaction fields from transactions_builder.py
        """
        self.evidence_map = {}
        
        for txn in transactions:
            # TShark transactions use _src and _dst for IP addresses
            src_ip = txn.get("_src")
            dst_ip = txn.get("_dst")
            
            if not src_ip or not dst_ip:
                continue
            
            # Initialize evidence objects
            if src_ip not in self.evidence_map:
                self.evidence_map[src_ip] = NodeEvidence(src_ip)
            if dst_ip not in self.evidence_map:
                self.evidence_map[dst_ip] = NodeEvidence(dst_ip)
            
            src_ev = self.evidence_map[src_ip]
            dst_ev = self.evidence_map[dst_ip]
            
            # Track peers
            src_ev.peers.add(dst_ip)
            dst_ev.peers.add(src_ip)
            
            # Protocol-specific evidence (using normalized fields)
            protocol = txn.get("protocol", "")
            message_type = txn.get("message_type", "")
            
            src_ev.protocols.add(protocol)
            dst_ev.protocols.add(protocol)
            src_ev.messages_sent.append(f"{protocol}_{message_type}")
            dst_ev.messages_received.append(f"{protocol}_{message_type}")
            
            # Extract procedure code from message_type like "Proc-15" -> "15"
            proc_code = None
            if message_type.startswith("Proc-"):
                proc_code = message_type.replace("Proc-", "")
            
            # NGAP evidence
            if protocol == "NGAP" and proc_code:
                if proc_code in NGAP_NODE_RULES:
                    direction, node_type = NGAP_NODE_RULES[proc_code]
                    target = src_ev if direction == "src" else dst_ev
                    target.inferred_types.append((node_type, f"NGAP proc {proc_code}"))
            
            # S1AP evidence  
            elif protocol == "S1AP" and proc_code:
                if proc_code in S1AP_NODE_RULES:
                    direction, node_type = S1AP_NODE_RULES[proc_code]
                    target = src_ev if direction == "src" else dst_ev
                    target.inferred_types.append((node_type, f"S1AP proc {proc_code}"))
            
            # PFCP evidence - extract msg type from "PFCP-Msg-50" -> "50"
            elif protocol == "PFCP":
                pfcp_type = message_type.replace("PFCP-Msg-", "") if message_type.startswith("PFCP-Msg-") else None
                if pfcp_type and pfcp_type in PFCP_NODE_RULES:
                    direction, node_type = PFCP_NODE_RULES[pfcp_type]
                    target = src_ev if direction == "src" else dst_ev
                    target.inferred_types.append((node_type, f"PFCP msg {pfcp_type}"))
            
            # Diameter evidence - extract cmd from "Cmd-316" -> "316"
            elif protocol == "Diameter":
                cmd_part = message_type.replace("Cmd-", "") if message_type.startswith("Cmd-") else None
                if cmd_part:
                    try:
                        cmd_code = int(cmd_part)
                        cmd_abbrev = self._diameter_cmd_abbrev(cmd_code)
                        # Try common interfaces
                        for interface in ["S6a", "Gx", "Rx", "Gy", "Cx"]:
                            key = (interface, cmd_abbrev)
                            if key in DIAMETER_NODE_RULES:
                                direction, node_type = DIAMETER_NODE_RULES[key]
                                target = src_ev if direction == "src" else dst_ev
                                target.inferred_types.append((node_type, f"Diameter {interface}/{cmd_abbrev}"))
                                break
                    except ValueError:
                        pass
            
            # GTPv2-C evidence - extract msg type from "GTP-Msg-32" -> "32"
            elif protocol == "GTPv2-C":
                gtp_type = message_type.replace("GTP-Msg-", "") if message_type.startswith("GTP-Msg-") else None
                if gtp_type:
                    # Create Session Request (32) -> src is MME/SGW
                    # Create Session Response (33) -> src is SGW/PGW
                    if gtp_type == "32":
                        src_ev.inferred_types.append(("MME", f"GTPv2 CSR sender"))
                    elif gtp_type == "33":
                        src_ev.inferred_types.append(("SGW", f"GTPv2 CSResp sender"))
            
            # SIP evidence
            elif protocol == "SIP":
                if "REGISTER" in message_type:
                    if "Response" not in message_type:
                        src_ev.inferred_types.append(("UE", "SIP REGISTER sender"))
                    else:
                        src_ev.inferred_types.append(("S-CSCF", "SIP REGISTER response"))
                elif "INVITE" == message_type:
                    src_ev.inferred_types.append(("Caller", "SIP INVITE sender"))
                elif "100" in message_type or "Trying" in message_type:
                    src_ev.inferred_types.append(("P-CSCF", "SIP 100 Trying"))
                elif "180" in message_type or "Ring" in message_type:
                    src_ev.inferred_types.append(("Callee", "SIP 180 Ringing"))
        
        logger.info(f"Built evidence for {len(self.evidence_map)} IPs")
        return self.evidence_map
    
    def classify_deterministic(self) -> Dict[str, str]:
        """
        First pass: Use deterministic rules to classify nodes.
        """
        results = {}
        
        for ip, evidence in self.evidence_map.items():
            if not evidence.inferred_types:
                continue
            
            # Count votes for each node type
            type_votes: Dict[str, int] = defaultdict(int)
            for node_type, reason in evidence.inferred_types:
                type_votes[node_type] += 1
            
            # Pick the most common type
            if type_votes:
                best_type = max(type_votes, key=type_votes.get)
                results[ip] = best_type
                logger.debug(f"Deterministic: {ip} -> {best_type} (votes: {type_votes})")
        
        return results
    
    async def classify_with_llm(self, unresolved_ips: List[str]) -> Dict[str, str]:
        """
        Second pass: Use LLM to classify unresolved IPs.
        """
        if not unresolved_ips:
            return {}
        
        # Check cache first
        results = {}
        ips_to_query = []
        for ip in unresolved_ips:
            if ip in self._cache:
                results[ip] = self._cache[ip]
            else:
                ips_to_query.append(ip)
        
        if not ips_to_query:
            return results
        
        # Build prompt with evidence
        evidence_text = []
        for ip in ips_to_query[:10]:  # Limit to 10 IPs per request
            ev = self.evidence_map.get(ip)
            if ev:
                evidence_text.append(
                    f"IP: {ip}\n"
                    f"  Protocols: {', '.join(ev.protocols)}\n"
                    f"  Messages sent: {', '.join(ev.messages_sent[:5])}\n"
                    f"  Messages received: {', '.join(ev.messages_received[:5])}\n"
                    f"  Ports: {ev.ports}\n"
                )
        
        if not evidence_text:
            return results
        
        prompt = f"""You are a telecom network analyst. Classify each IP address as a network function based on observed signaling.

Network functions to consider:
- 5G: gNB, AMF, SMF, UPF, AUSF, UDM, PCF, NSSF
- 4G: eNB, MME, SGW, PGW, HSS, PCRF
- IMS: P-CSCF, I-CSCF, S-CSCF, TAS, SBC
- Other: DNS_Server, RADIUS_Server, Probe

Evidence:
{chr(10).join(evidence_text)}

Respond ONLY with JSON array:
[{{"ip": "x.x.x.x", "node_type": "AMF", "confidence": "high"}}]
"""
        
        try:
            from .llm_service import get_llm_client
            import json
            
            client = get_llm_client()
            if not client:
                logger.warning("LLM client not available for node classification")
                return results
            
            response = client.chat.completions.create(
                model="kimi-k2-0711-preview",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=500,
            )
            
            content = response.choices[0].message.content.strip()
            # Extract JSON from response
            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            
            classifications = json.loads(content)
            for item in classifications:
                ip = item.get("ip")
                node_type = item.get("node_type")
                if ip and node_type:
                    results[ip] = node_type
                    self._cache[ip] = node_type  # Cache for reuse
                    logger.info(f"LLM classified: {ip} -> {node_type}")
        
        except Exception as e:
            logger.warning(f"LLM node classification failed: {e}")
        
        return results
    
    async def classify_nodes(self, transactions: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Main entry point: Hybrid classification.
        """
        # Build evidence
        self.build_evidence(transactions)
        
        # First pass: deterministic
        self.node_map = self.classify_deterministic()
        logger.info(f"Deterministic pass: {len(self.node_map)} nodes classified")
        
        # Find unresolved IPs
        all_ips = set(self.evidence_map.keys())
        resolved_ips = set(self.node_map.keys())
        unresolved_ips = list(all_ips - resolved_ips)
        
        if unresolved_ips:
            logger.info(f"LLM pass: {len(unresolved_ips)} nodes to classify")
            llm_results = await self.classify_with_llm(unresolved_ips)
            self.node_map.update(llm_results)
        
        logger.info(f"Total classified: {len(self.node_map)} nodes")
        return self.node_map
    
    def _diameter_app_to_interface(self, app_id: Any) -> str:
        """Map Diameter application ID to interface name."""
        app_map = {
            16777251: "S6a",
            16777238: "Gx",
            16777236: "Rx",
            4: "Gy",
            16777216: "Cx",
            16777272: "S6b",
        }
        try:
            return app_map.get(int(app_id), "Unknown")
        except (ValueError, TypeError):
            return "Unknown"
    
    def _diameter_cmd_abbrev(self, cmd_code: Any) -> str:
        """Map Diameter command code to abbreviation."""
        cmd_map = {
            316: "ULR", 317: "ULA",  # S6a Update-Location
            318: "AIR", 319: "AIA",  # S6a Authentication-Info
            317: "CLR",  # Cancel-Location
            272: "CCR", 273: "CCA",  # Credit-Control
            265: "AAR", 266: "AAA",  # AA (Rx)
            300: "UAR", 301: "UAA",  # Cx User-Auth
            301: "SAR", 302: "SAA",  # Cx Server-Assignment
            303: "MAR", 304: "MAA",  # Cx Multimedia-Auth
        }
        try:
            return cmd_map.get(int(cmd_code), str(cmd_code))
        except (ValueError, TypeError):
            return str(cmd_code)


# Convenience function
async def classify_network_nodes(transactions: List[Dict[str, Any]]) -> Dict[str, str]:
    """Classify network nodes from transaction data."""
    classifier = NodeClassifier()
    return await classifier.classify_nodes(transactions)
