
import asyncio
import logging
import json
from pathlib import Path
from decode.tshark import tshark_available, get_tshark_stats, extract_telecom_fields
from decode.transactions_builder import build_transactions

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TSharkTest")

async def test_tshark_logic():
    pcap_path = "test_traffic.pcap"
    
    if not Path(pcap_path).exists():
        logger.error(f"Test PCAP not found at {pcap_path}")
        return

    if not tshark_available():
        logger.warning("TShark not available on this system. Cannot test TShark logic.")
        return

    logger.info("=== Testing Mode A: Stats ===")
    stats = await asyncio.to_thread(get_tshark_stats, pcap_path)
    logger.info(f"Expert Info Count: {len(stats.get('expert_info', []))}")
    logger.info(f"IO Stats Count: {len(stats.get('io_stats', []))}")
    
    logger.info("\n=== Testing Mode B: Fields ===")
    field_data = await asyncio.to_thread(extract_telecom_fields, pcap_path)
    logger.info(f"Extracted Packets: {len(field_data)}")
    if field_data:
        logger.info(f"Sample Field Data (Row 0): {field_data[0]}")

    logger.info("\n=== Testing Transaction Builder ===")
    transactions = await asyncio.to_thread(build_transactions, field_data)
    logger.info(f"Built Transactions: {len(transactions)}")
    if transactions:
        logger.info(f"Sample Transaction (Row 0): {json.dumps(transactions[0], indent=2)}")

if __name__ == "__main__":
    asyncio.run(test_tshark_logic())
