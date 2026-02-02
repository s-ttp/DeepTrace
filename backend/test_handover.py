
import asyncio
import logging
from analysis.handover_analyzer import analyze_handover

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_handover")

def test_srvcc_detection():
    logger.info("Testing SRVCC Detection...")
    
    # Mock Call with SRVCC hint (SIP 503 + "Handover" key)
    calls = [{
        "call_id": "call_1",
        "reason_header": "SIP;cause=503;text=\"Handover triggered\"",
        "end_time": 1000.0,
        "is_established": True
    }]
    
    # Mock S1AP Handover Preparation (Proc 0) near call end
    s1ap_txns = [{
        "s1ap.procedureCode": "0", # HandoverPreparation
        "frame.time_epoch": "1000.1",
        "s1ap.MME_UE_S1AP_ID": "100",
        "s1ap.ENB_UE_S1AP_ID": "200"
    }]
    
    results = analyze_handover(calls, s1ap_txns, [], [])
    
    assert results["handover_detected"] == True
    assert results["has_ran_evidence"] == True
    finding = results["findings"][0]
    assert "PROVEN_PS_TO_CS_HANDOVER" in finding["classification"]
    assert "HIGH" in finding["confidence_level"]
    
    logger.info("SRVCC Detection OK: Found " + finding["classification"])

def test_csfb_detection():
    logger.info("Testing CSFB Detection...")
    
    # Mock Call Setup Failure with CSFB hint
    calls = [{
        "call_id": "call_2",
        "reason_header": "SIP;cause=380;text=\"CS Fallback required\"",
        "end_time": 2000.0,
        "is_established": False # Setup failed
    }]
    
    # Mock S1AP UE Context Modification (Proc 25) - commonly used in CSFB
    s1ap_txns = [{
        "s1ap.procedureCode": "25", 
        "frame.time_epoch": "2000.1",
        "s1ap.MME_UE_S1AP_ID": "300"
    }]
    
    results = analyze_handover(calls, s1ap_txns, [], [])
    
    assert results["handover_detected"] == True
    finding = results["findings"][0]
    assert "CSFB" in finding["classification"]
    
    logger.info("CSFB Detection OK: Found " + finding["classification"])

if __name__ == "__main__":
    try:
        test_srvcc_detection()
        test_csfb_detection()
        print("ALL HANDOVER TESTS PASSED")
    except Exception as e:
        logger.error(f"TEST FAILED: {e}")
        exit(1)
