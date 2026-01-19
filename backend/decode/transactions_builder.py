"""
Transaction Builder
Normalizes raw TShark field data into structured Transaction objects.
"""
from typing import List, Dict, Any, Optional
from .cause_maps import get_cause_label
from .wireshark_code_mapper import get_mapper, map_protocol_code

def get_first_value(row: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    """Helper to get the first non-empty value from a list of keys"""
    for key in keys:
        if row.get(key):
            return row[key]
    return None


def parse_reason_header(reason_raw: str) -> Dict[str, Any]:
    """
    Parse SIP Reason header into structured format.
    
    Supports:
    - RFC 3326 standard: "SIP;cause=503;text=..."
    - Q.850 ISUP causes: "Q.850;cause=16;text=..."
    - Nokia X.int vendor: "X.int;reasoncode=0x00000000;add-info=..."
    - Huawei proprietary text in standard format
    
    Returns dict with: protocol, cause, text, vendor_info
    """
    import re
    
    result = {
        "protocol": None,
        "cause": None,
        "text": None,
        "vendor_info": None,
        "is_vendor_specific": False
    }
    
    if not reason_raw:
        return result
    
    reason_str = str(reason_raw).strip()
    
    # Handle Nokia X.int format: "X.int;reasoncode=0x00000000;add-info=0132.0001.0B2E"
    if reason_str.startswith("X."):
        result["is_vendor_specific"] = True
        result["protocol"] = reason_str.split(";")[0]  # e.g., "X.int"
        
        # Extract reasoncode
        reasoncode_match = re.search(r"reasoncode=([0-9a-fA-Fx]+)", reason_str)
        if reasoncode_match:
            result["cause"] = reasoncode_match.group(1)
        
        # Extract add-info
        addinfo_match = re.search(r"add-info=([0-9a-fA-F.]+)", reason_str)
        if addinfo_match:
            result["vendor_info"] = {
                "add_info": addinfo_match.group(1),
                "vendor": "Nokia" if result["protocol"] == "X.int" else "Unknown"
            }
        
        return result
    
    # Handle standard RFC 3326 format: "SIP;cause=503;text=..."
    # Extract protocol (SIP, Q.850, etc.)
    proto_match = re.match(r"^([A-Za-z0-9._-]+)", reason_str)
    if proto_match:
        result["protocol"] = proto_match.group(1)
    
    # Extract cause code
    cause_match = re.search(r"cause=(\d+)", reason_str)
    if cause_match:
        result["cause"] = cause_match.group(1)
    
    # Extract text (may contain Huawei proprietary info)
    text_match = re.search(r'text="?([^"]*)"?', reason_str)
    if text_match:
        result["text"] = text_match.group(1).strip('"')
        
        # Check for Huawei proprietary patterns in text
        huawei_patterns = [
            "RELEASE FROM CC",
            "query adb failed",
            "No Prack received",
            "Invalid number format"
        ]
        for pattern in huawei_patterns:
            if pattern.lower() in result["text"].lower():
                result["is_vendor_specific"] = True
                result["vendor_info"] = {
                    "vendor": "Huawei",
                    "pattern_match": pattern
                }
                break
    
    return result


def build_transactions(field_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert raw TShark field output into normalized transactions.
    """
    transactions = []
    
    for row in field_data:
        # Skip rows without minimal info
        if not row.get("frame.number"):
            continue

        tx = {
            "tx_id": f"pkt_{row['frame.number']}",
            "timestamp": float(row.get("frame.time_epoch", 0)),
            "frame_number": int(row["frame.number"]),
            "protocol": "Unknown",
            "message_type": "Unknown",
            "cause": None,
            "session_ids": {},
            "info": {},
            "flags": {},
            # Raw identifiers for pairing
            "_seq": None,
            "_src": row.get("ip.src") or row.get("ipv6.src"),
            "_dst": row.get("ip.dst") or row.get("ipv6.dst"),
            "_teid": None,
            "_seid": None
        }
        
        # 1. Identify Protocol & Message Type
        
        # PFCP
        if row.get("pfcp.msg_type"):
            tx["protocol"] = "PFCP"
            tx["message_type"] = f"PFCP-Msg-{row['pfcp.msg_type']}" 
            tx["session_ids"]["seid"] = row.get("pfcp.seid")
            tx["_seid"] = row.get("pfcp.seid")
            tx["cause"] = row.get("pfcp.cause")
            if tx["cause"]:
                mapped = map_protocol_code("PFCP", tx["cause"], "pfcp.cause")
                tx["cause_label"] = mapped["label"]
                tx["cause_mapped"] = mapped
            
            # Use Sequence Number from updated field pack
            tx["_seq"] = row.get("pfcp.seqno")
            
        # GTPv2 (Control)
        elif row.get("gtp.message"):
            tx["protocol"] = "GTPv2-C"
            tx["message_type"] = f"GTP-Msg-{row['gtp.message']}"
            tx["session_ids"]["teid"] = row.get("gtp.teid")
            tx["_teid"] = row.get("gtp.teid")
            tx["cause"] = row.get("gtp.cause")
            if tx["cause"]:
                mapped = map_protocol_code("GTPv2-C", tx["cause"], "gtpv2.cause")
                tx["cause_label"] = mapped["label"]
                tx["cause_mapped"] = mapped
             
             # seq num for GTPv2 is often gtp.seq
            tx["_seq"] = row.get("gtp.seq")
            
        # GTP-U (Data)
        elif row.get("gtp.teid") and not row.get("gtp.message"):
             tx["protocol"] = "GTP-U"
             tx["session_ids"]["teid"] = row.get("gtp.teid")
             tx["info"]["qfi"] = row.get("gtp.ext_hdr.pdu_ses_con.qos_flow_id")
        
        # NGAP
        elif row.get("ngap.procedureCode"):
            tx["protocol"] = "NGAP"
            tx["message_type"] = f"Proc-{row['ngap.procedureCode']}"
            tx["session_ids"]["ran_ue_ngap_id"] = row.get("ngap.RAN_UE_NGAP_ID") # Updated field name
            tx["session_ids"]["amf_ue_ngap_id"] = row.get("ngap.AMF_UE_NGAP_ID")
            tx["cause"] = row.get("ngap.cause")
            if tx["cause"]:
                mapped = map_protocol_code("NGAP", tx["cause"], "ngap.Cause")
                tx["cause_label"] = mapped["label"]
                tx["cause_mapped"] = mapped
            
        # S1AP
        elif row.get("s1ap.procedureCode"):
            tx["protocol"] = "S1AP"
            tx["message_type"] = f"Proc-{row['s1ap.procedureCode']}"
            tx["cause"] = row.get("s1ap.cause")
            if tx["cause"]:
                mapped = map_protocol_code("S1AP", tx["cause"], "s1ap.Cause")
                tx["cause_label"] = mapped["label"]
                tx["cause_mapped"] = mapped

        # Diameter
        elif row.get("diameter.cmd.code"):
            tx["protocol"] = "Diameter"
            tx["message_type"] = f"Cmd-{row['diameter.cmd.code']}"
            tx["cause"] = row.get("diameter.Result-Code") or row.get("diameter.Experimental-Result-Code")
            tx["session_ids"]["session_id"] = row.get("diameter.Session-Id")
            if tx["cause"]:
                # Try Result-Code field first, then Experimental-Result-Code
                field_hint = "diameter.Result-Code" if row.get("diameter.Result-Code") else "diameter.Experimental-Result-Code"
                mapped = map_protocol_code("Diameter", tx["cause"], field_hint)
                tx["cause_label"] = mapped["label"]
                tx["cause_mapped"] = mapped

        # SIP
        elif row.get("sip.Method") or row.get("sip.Status-Code"):
            tx["protocol"] = "SIP"
            if row.get("sip.Method"):
                tx["message_type"] = row["sip.Method"]
            else:
                tx["message_type"] = f"{row.get('sip.Status-Code')} Response"
            
            tx["cause"] = row.get("sip.Reason")
            tx["session_ids"]["call_id"] = row.get("sip.Call-ID")
            
            # Parse structured Reason header (RFC 3326 + vendor extensions)
            reason_raw = row.get("sip.Reason")
            if reason_raw:
                tx["info"]["reason_raw"] = reason_raw
                tx["info"]["reason_parsed"] = parse_reason_header(reason_raw)

        # NAS (5GS) - Often embedded in NGAP, but might appear if dissected differently
        if row.get("nas_5gs.message_type"):
             # If we already detected headers like NGAP, append info
             if tx["protocol"] == "NGAP":
                 tx["info"]["nas_msg"] = row.get("nas_5gs.message_type")
                 if row.get("nas_5gs.emm.cause"):
                     tx["cause"] = f"EMM:{row['nas_5gs.emm.cause']}"
                 elif row.get("nas_5gs.sm.cause"):
                     tx["cause"] = f"SM:{row['nas_5gs.sm.cause']}"
             else:
                 tx["protocol"] = "NAS-5GS"
                 tx["message_type"] = f"Msg-{row['nas_5gs.message_type']}"

        # SCTP info (Transport)
        if row.get("sctp.assoc_id"):
            tx["transport"] = "SCTP"
            tx["info"]["sctp_assoc"] = row.get("sctp.assoc_id")
            if row.get("sctp.retransmission") == "1":
                 tx["flags"]["retransmission"] = True
                 tx["cause"] = "SCTP Retransmission" # Override or append cause?

        # Filter out boring packets (pure IP/TCP/UDP without identified telecom payload)
        # Unless they have specific issues or are requested
        if tx["protocol"] == "Unknown" and not tx.get("flags"):
            continue

        transactions.append(tx)
    
    # Feature 4: Pair Request/Response
    transactions = pair_transactions(transactions)
        
    return transactions

def pair_transactions(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Match Requests with Responses to calculate latency and status.
    Logic:
    - Maintain a map of pending requests key=(proto, seq, id, src, dst) -> index
    - When response seen, match key=(proto, seq, id, dst, src)
    """
    pending_reqs = {}
    
    for i, tx in enumerate(transactions):
        # We only really pair PFCP and GTPv2 reliably with Sequence Numbers
        if tx["protocol"] not in ["PFCP", "GTPv2-C"]:
            continue
            
        seq = tx.get("_seq")
        if not seq:
            continue
            
        is_response = "Resp" in tx["message_type"] or "Ack" in tx["message_type"] or tx.get("cause") is not None
        
        # Construct key
        # ID is usually SEID or TEID
        sess_id = tx.get("_seid") or tx.get("_teid") or "0"
        
        if not is_response:
            # IT IS A REQUEST
            key = (tx["protocol"], seq, sess_id, tx["_src"], tx["_dst"])
            pending_reqs[key] = i
            tx["type"] = "request"
            tx["status"] = "no_response" # Default until matched
        else:
            # IT IS A RESPONSE
            # Look for matching request: (proto, seq, id, REVERSED traffic direction)
            key = (tx["protocol"], seq, sess_id, tx["_dst"], tx["_src"])
            
            if key in pending_reqs:
                req_idx = pending_reqs[key]
                req_tx = transactions[req_idx]
                
                # Calculate latency
                latency = (tx["timestamp"] - req_tx["timestamp"]) * 1000.0 # ms
                if latency < 0: latency = 0
                
                # Update Request
                req_tx["latency_ms"] = round(latency, 2)
                req_tx["status"] = "success" if not tx.get("cause") else "failure" # Heuristic: cause usually implies failure or non-ok
                
                # If specific success causes exist (e.g. Cause=1), reliable success
                if tx["protocol"] == "PFCP" and tx.get("cause") == "1":
                    req_tx["status"] = "success"
                elif tx["protocol"] == "PFCP" and tx.get("cause") and tx.get("cause") != "1":
                     req_tx["status"] = "failure"
                     
                req_tx["response_frame"] = tx["frame_number"]
                req_tx["response_cause"] = tx.get("cause_label") or tx.get("cause")

                # Update Response
                tx["type"] = "response"
                tx["req_frame"] = req_tx["frame_number"]
                
                # Remove from pending
                del pending_reqs[key]
                
    return transactions
