
import asyncio
import json
import logging
import sys
from decode.tshark import get_tshark_stats, extract_telecom_fields
from decode.transactions_builder import build_transactions
from analytics.kpi_engine import calculate_procedure_kpis
from decode.cause_maps import get_cause_label

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_advanced_features")

def test_cause_maps():
    logger.info("Testing Cause Maps...")
    assert get_cause_label("PFCP", 1) == "Request Accepted"
    assert get_cause_label("GTPv2", 64) == "Context Not Found"
    assert get_cause_label("SIP", 404) == "Not Found"
    assert "Unknown" in get_cause_label("PFCP", 9999)
    logger.info("Cause Maps OK.")

def test_pairing_logic():
    # Simulate Request and Response
    raw_fields = [
        {
            "frame.number": "1",
            "frame.time_epoch": "1000.000",
            "pfcp.msg_type": "1", # Helper
            "pfcp.seqno": "100",
            "pfcp.seid": "12345",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2"
        },
        {
            "frame.number": "2",
            "frame.time_epoch": "1000.050", # 50ms later
            "pfcp.msg_type": "2", # Helper Ack
            "pfcp.seqno": "100",
            "pfcp.seid": "12345",
            "pfcp.cause": "1",
            "ip.src": "10.0.0.2", # Swapped
            "ip.dst": "10.0.0.1"
        }
    ]
    
    txs = build_transactions(raw_fields)
    logger.info(f"Built {len(txs)} transactions")
    
    # Check Request
    req = txs[0]
    assert req["type"] == "request"
    assert req["status"] == "success"
    assert req["latency_ms"] == 50.0
    assert req["response_frame"] == 2
    assert req["response_cause"] == "Request Accepted"
    
    # Check Response
    resp = txs[1]
    assert resp["type"] == "response"
    assert resp["req_frame"] == 1
    
    logger.info("Pairing Logic OK.")
    
    return txs

def test_kpis(transactions):
    kpis = calculate_procedure_kpis(transactions)
    logger.info(f"KPIs: {json.dumps(kpis, indent=2)}")
    
    pfcp_stats = kpis.get("PFCP-Msg-1") or kpis.get("PFCP-Msg-2")
    # Actually build_transactions uses PFCP-Msg-X for requests
    
    # Since we grouped by message type, and request is PFCP-Msg-1
    assert "PFCP-Msg-1" in kpis
    assert kpis["PFCP-Msg-1"]["attempts"] == 1
    assert kpis["PFCP-Msg-1"]["avg_latency_ms"] == 50.0
    
    logger.info("KPI Engine OK.")

if __name__ == "__main__":
    try:
        test_cause_maps()
        txs = test_pairing_logic()
        test_kpis(txs)
        print("ALL TESTS PASSED")
    except Exception as e:
        logger.error(f"TEST FAILED: {e}")
        sys.exit(1)
