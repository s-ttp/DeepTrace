import sys
sys.path.append('/home/sttp/pcap/backend/app')
import asyncio
from advanced_pcap_pipeline import run_advanced_pipeline

async def main():
    # Attempt simulated hook logic to see what dict gets returned
    adv_ctx = await run_advanced_pipeline("/home/sttp/pcap/backend/artifacts/75bee165-89f7-4a32-b055-1fcdc8592f01/pcap/Zaidan_case.pcap", [], [])
    
    print("KEYS returned from run_advanced_pipeline:")
    print(adv_ctx.keys())
    
    vc = adv_ctx.get("voice_context")
    if vc:
        print(f"voice_context calls len: {len(vc.get('calls', []))}")
    else:
        print("voice_context is None")

asyncio.run(main())
