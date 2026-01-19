"""
Call Builder Module
Reconstructs SIP Dialogs from normalized transaction data.
Enhanced with:
- SIP Timing KPIs (PDD, setup time, alerting time)
- Long-setup detection
- 8-category call-end classifier
- Session Timer tracking (RFC 4028)
- Call Transfer REFER/NOTIFY tracking (RFC 3515)
"""
from typing import List, Dict, Any
from datetime import datetime
import logging
import re

logger = logging.getLogger(__name__)

# Thresholds for timing anomalies
LONG_SETUP_THRESHOLD_MS = 10000  # 10 seconds
EARLY_DROP_THRESHOLD_S = 3.0     # BYE within 3s of 200 OK
SESSION_TIMER_GRACE_S = 32       # Grace period after session timer expiry

class CallBuilder:
    def __init__(self):
        self.calls = {} # Key: call_id

    def process_transactions(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze SIP transactions and separate Registrations from Calls.
        Returns:
        {
            "trace_type": "REGISTRATION_ONLY" | "CALLS_AND_REGISTRATIONS",
            "registrations": [...],
            "calls": [...],
            "sip_kpis": {...}
        }
        """
        registrations = {} # Key: call_id
        calls = {} # Key: call_id
        
        # Pass 1: Build Objects
        for tx in transactions:
            if tx.get("protocol") != "SIP":
                continue
            
            call_id = tx.get("session_ids", {}).get("call_id")
            if not call_id:
                continue
            
            msg_type = tx["message_type"]
            
            # Identify or Create Object
            target_dict = None
            is_new = False
            
            # If already exists, find where
            if call_id in registrations:
                target_dict = registrations
            elif call_id in calls:
                target_dict = calls
            else:
                # New session - Classify
                is_new = True
                if msg_type == "REGISTER":
                    target_dict = registrations
                elif msg_type == "INVITE":
                    target_dict = calls
                elif msg_type == "SUBSCRIBE" or msg_type == "OPTIONS":
                     target_dict = registrations
                else: 
                     target_dict = registrations

            session_store = target_dict
            if call_id not in session_store:
                session_store[call_id] = {
                    "call_id": call_id,
                    "start_time": tx["timestamp"],
                    "end_time": tx["timestamp"],
                    "duration_sec": 0.0,
                    "state": "SETUP", 
                    "method": "UNKNOWN",
                    "end_reason": "UNKNOWN",
                    "classification": "INCOMPLETE",  # NEW: Classification field
                    "messages": [],
                    "src_ip": tx.get("_src"),
                    "dst_ip": tx.get("_dst"),
                    "ua": tx.get("info", {}).get("user_agent"),
                    # NEW: Timing fields
                    "timing": {
                        "invite_time": None,
                        "first_provisional_time": None,
                        "ringing_time": None,  # 180
                        "session_progress_time": None,  # 183
                        "ok_time": None,  # 200 OK
                        "bye_time": None,
                        "cancel_time": None,
                        "last_refresh_time": None,  # Last re-INVITE/UPDATE
                        "refer_time": None,  # Call transfer initiated
                    },
                    "kpis": {},  # Will be populated in post-processing
                    # Session Timer (RFC 4028)
                    "session_timer": {
                        "session_expires": None,  # Negotiated value in seconds
                        "min_se": None,
                        "refresher": None,  # "uac" or "uas"
                        "is_expired": False
                    },
                    # Call Transfer (RFC 3515)
                    "transfer": {
                        "is_transfer": False,
                        "refer_to": None,
                        "referred_by": None,
                        "transfer_status": None,  # PENDING, COMPLETED, FAILED
                        "notify_responses": []
                    },
                    # Reason header from BYE (for SRVCC/CSFB detection)
                    "reason_header": None
                }
            
            session = session_store[call_id]
            session["end_time"] = tx["timestamp"]
            
            # Update Method if unknown
            if session["method"] == "UNKNOWN" and msg_type not in ["Response", "Ack"] and not str(tx.get("cause", "")).isdigit():
                session["method"] = msg_type

            session["messages"].append({
                "time": tx["timestamp"],
                "type": msg_type,
                "code": tx.get("cause"),
                "method": msg_type if "Response" not in msg_type else None,
                "sip_headers": {
                    "session_expires": tx.get("info", {}).get("sip.Session-Expires"),
                    "refer_to": tx.get("info", {}).get("sip.Refer-To"),
                    "event": tx.get("info", {}).get("sip.Event"),
                }
            })
            
            # Track Session Timer (RFC 4028)
            se_header = tx.get("info", {}).get("sip.Session-Expires")
            if se_header:
                # Parse "1800;refresher=uac" format
                match = re.match(r"(\d+)(?:;refresher=(\w+))?", str(se_header))
                if match:
                    session["session_timer"]["session_expires"] = int(match.group(1))
                    if match.group(2):
                        session["session_timer"]["refresher"] = match.group(2)
            
            min_se = tx.get("info", {}).get("sip.Min-SE")
            if min_se:
                try:
                    session["session_timer"]["min_se"] = int(min_se)
                except ValueError:
                    pass
            
            # Track REFER for call transfer
            if msg_type == "REFER":
                session["transfer"]["is_transfer"] = True
                session["transfer"]["refer_to"] = tx.get("info", {}).get("sip.Refer-To")
                session["transfer"]["referred_by"] = tx.get("info", {}).get("sip.Referred-By")
                session["transfer"]["transfer_status"] = "PENDING"
                session["timing"]["refer_time"] = tx["timestamp"]
            
            # Track NOTIFY for transfer status
            if msg_type == "NOTIFY":
                event = tx.get("info", {}).get("sip.Event", "")
                if "refer" in str(event).lower():
                    # Update transfer status based on NOTIFY body (simplified)
                    notify_code = tx.get("cause") or tx.get("info", {}).get("notify_status")
                    session["transfer"]["notify_responses"].append({
                        "time": tx["timestamp"],
                        "status": notify_code
                    })
                    # Check final status
                    if notify_code and str(notify_code).startswith("2"):
                        session["transfer"]["transfer_status"] = "COMPLETED"
                    elif notify_code and (str(notify_code).startswith("4") or str(notify_code).startswith("5")):
                        session["transfer"]["transfer_status"] = "FAILED"
            
            # Track re-INVITE/UPDATE for session refresh
            if msg_type == "UPDATE" or (msg_type == "INVITE" and session["state"] == "ESTABLISHED"):
                session["timing"]["last_refresh_time"] = tx["timestamp"]
            
            # Track timing milestones
            code = str(tx.get("cause", ""))
            timing = session["timing"]
            
            if msg_type == "INVITE" and timing["invite_time"] is None:
                timing["invite_time"] = tx["timestamp"]
            elif msg_type == "CANCEL":
                timing["cancel_time"] = tx["timestamp"]
            elif msg_type == "BYE":
                timing["bye_time"] = tx["timestamp"]
                # Extract Reason header for SRVCC/CSFB detection
                reason = tx.get("cause") or tx.get("info", {}).get("sip.Reason") or tx.get("info", {}).get("reason_raw")
                if reason and not session.get("reason_header"):
                    session["reason_header"] = reason
            elif code == "100" and timing["first_provisional_time"] is None:
                timing["first_provisional_time"] = tx["timestamp"]
            elif code == "180":
                timing["ringing_time"] = tx["timestamp"]
                if timing["first_provisional_time"] is None:
                    timing["first_provisional_time"] = tx["timestamp"]
            elif code == "183":
                timing["session_progress_time"] = tx["timestamp"]
                if timing["first_provisional_time"] is None:
                    timing["first_provisional_time"] = tx["timestamp"]
            elif code == "200" and timing["ok_time"] is None:
                timing["ok_time"] = tx["timestamp"]
            
            # State Machine
            # Registration / Other Logic
            if session_store is registrations:
                 if code == "200":
                     session["state"] = "SUCCESS"
                     session["end_reason"] = "COMPLETED"
                     session["classification"] = "ESTABLISHED"
                 elif code.startswith("4") or code.startswith("5") or code.startswith("6"):
                     session["state"] = "FAILED"
                     session["end_reason"] = f"SIP_ERROR_{code}"
                     session["classification"] = f"REJECTED_{code[0]}XX"

            # Call Logic (INVITE)
            elif session_store is calls:
                if session["state"] == "SETUP":
                    if code == "200":
                         session["state"] = "ESTABLISHED"
                    elif code.startswith("4"):
                         session["state"] = "FAILED"
                         session["end_reason"] = f"SIP_ERROR_{code}"
                         session["classification"] = "REJECTED_4XX"
                    elif code.startswith("5"):
                         session["state"] = "FAILED"
                         session["end_reason"] = f"SIP_ERROR_{code}"
                         session["classification"] = "REJECTED_5XX"
                    elif code.startswith("6"):
                         session["state"] = "FAILED"
                         session["end_reason"] = f"SIP_ERROR_{code}"
                         session["classification"] = "REJECTED_6XX"
                    elif msg_type == "CANCEL":
                         session["state"] = "FAILED"
                         session["end_reason"] = "CANCELLED"
                         session["classification"] = "CANCELLED_BY_CALLER"
                
                elif session["state"] == "ESTABLISHED":
                    if msg_type == "BYE":
                        session["state"] = "TERMINATED"
                        session["end_reason"] = "NORMAL_CLEARING"
                        session["classification"] = "ESTABLISHED"

        # Pass 2: Post-Processing & Cleanup
        final_registrations = []
        final_calls = []
        
        # --- Process Registrations ---
        for cid, reg in registrations.items():
            msgs = sorted(reg["messages"], key=lambda k: k["time"])
            if reg["end_time"] > reg["start_time"]:
                reg["duration_sec"] = round(reg["end_time"] - reg["start_time"], 3)
            
            if reg["state"] == "SETUP":
                 reg["state"] = "FAILED"
                 reg["end_reason"] = "REGISTER_TIMEOUT" if reg["method"] == "REGISTER" else "TRANSACTION_TIMEOUT"
                 reg["classification"] = "INVITE_TIMEOUT"
            
            reg["msg_count"] = len(msgs)
            final_registrations.append(reg)
            
        # --- Process Calls ---
        sip_kpis_aggregate = {
            "total_calls": 0,
            "avg_pdd_ms": 0,
            "avg_setup_time_ms": 0,
            "long_setup_count": 0,
            "classification_counts": {}
        }
        pdd_values = []
        setup_values = []
        
        for cid, call in calls.items():
            msgs = sorted(call["messages"], key=lambda k: k["time"])
            if call["end_time"] > call["start_time"]:
                call["duration_sec"] = round(call["end_time"] - call["start_time"], 3)
            
            timing = call["timing"]
            kpis = call["kpis"]
            
            # Calculate SIP Timing KPIs
            if timing["invite_time"]:
                # PDD: INVITE → 180 Ringing (or 183 if no 180)
                ring_time = timing["ringing_time"] or timing["session_progress_time"]
                if ring_time:
                    kpis["pdd_ms"] = round((ring_time - timing["invite_time"]) * 1000, 2)
                    pdd_values.append(kpis["pdd_ms"])
                
                # Setup Time: INVITE → 200 OK
                if timing["ok_time"]:
                    kpis["setup_time_ms"] = round((timing["ok_time"] - timing["invite_time"]) * 1000, 2)
                    setup_values.append(kpis["setup_time_ms"])
                    
                    # Long-setup detection
                    if kpis["setup_time_ms"] > LONG_SETUP_THRESHOLD_MS:
                        kpis["is_long_setup"] = True
                        sip_kpis_aggregate["long_setup_count"] += 1
                    else:
                        kpis["is_long_setup"] = False
                
                # Alerting Time: 180 → 200 OK
                if timing["ringing_time"] and timing["ok_time"]:
                    kpis["alerting_time_ms"] = round((timing["ok_time"] - timing["ringing_time"]) * 1000, 2)
            
            # Timeout Logic for INVITE
            if call["state"] == "SETUP":
                 call["state"] = "FAILED"
                 call["end_reason"] = "INVITE_SETUP_TIMEOUT"
                 call["classification"] = "INVITE_TIMEOUT"
            
            # Enhanced Drop Logic (8-category classification)
            elif call["state"] == "ESTABLISHED":
                if call["end_reason"] == "UNKNOWN":
                    call["end_reason"] = "DROP_NO_BYE"
                    call["classification"] = "EARLY_DROP"
                    call["confidence"] = "medium"
                
                # Early drop check: BYE within EARLY_DROP_THRESHOLD_S of 200 OK
                if timing["ok_time"] and timing["bye_time"]:
                    call_duration = timing["bye_time"] - timing["ok_time"]
                    if call_duration < EARLY_DROP_THRESHOLD_S:
                        call["end_reason"] = "DROP_IMMEDIATE_BYE"
                        call["classification"] = "EARLY_DROP"
                        call["confidence"] = "high"
                        kpis["call_duration_ms"] = round(call_duration * 1000, 2)
                    else:
                        call["classification"] = "ESTABLISHED"
                        kpis["call_duration_ms"] = round(call_duration * 1000, 2)
            
            # Session Timer Expiry Detection
            session_timer = call.get("session_timer", {})
            if session_timer.get("session_expires") and timing["ok_time"]:
                se_value = session_timer["session_expires"]
                last_refresh = timing.get("last_refresh_time") or timing["ok_time"]
                
                # Check if session expired without refresh
                time_since_refresh = call["end_time"] - last_refresh
                if time_since_refresh > (se_value + SESSION_TIMER_GRACE_S):
                    session_timer["is_expired"] = True
                    if call["end_reason"] in ["UNKNOWN", "DROP_NO_BYE"]:
                        call["end_reason"] = "DROP_SESSION_TIMEOUT"
                        call["classification"] = "SESSION_TIMER_EXPIRED"
                        call["confidence"] = "high"
                        kpis["session_timer_expired"] = True
            
            # Call Transfer Status
            transfer = call.get("transfer", {})
            if transfer.get("is_transfer"):
                if transfer["transfer_status"] == "COMPLETED":
                    call["classification"] = "TRANSFER_COMPLETED"
                    call["end_reason"] = "NORMAL_TRANSFER"
                elif transfer["transfer_status"] == "FAILED":
                    if call["end_reason"] == "UNKNOWN":
                        call["end_reason"] = "TRANSFER_FAILED"
                        call["classification"] = "TRANSFER_FAILED"
                elif transfer["transfer_status"] == "PENDING":
                    # Transfer never completed
                    call["classification"] = "TRANSFER_INCOMPLETE"
            
            call["msg_count"] = len(msgs)
            final_calls.append(call)
            
            # Aggregate counts
            sip_kpis_aggregate["total_calls"] += 1
            cls = call["classification"]
            sip_kpis_aggregate["classification_counts"][cls] = sip_kpis_aggregate["classification_counts"].get(cls, 0) + 1

        # Calculate averages
        if pdd_values:
            sip_kpis_aggregate["avg_pdd_ms"] = round(sum(pdd_values) / len(pdd_values), 2)
        if setup_values:
            sip_kpis_aggregate["avg_setup_time_ms"] = round(sum(setup_values) / len(setup_values), 2)

        # Trace Level Classification
        trace_type = "REGISTRATION_ONLY" if len(final_calls) == 0 and len(final_registrations) > 0 else "CALLS_AND_REGISTRATIONS"
        if len(final_calls) == 0 and len(final_registrations) == 0:
            trace_type = "EMPTY_OR_UNKNOWN"

        return {
            "trace_type": trace_type,
            "registrations": final_registrations,
            "calls": final_calls,
            "sip_kpis": sip_kpis_aggregate
        }

