from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
import os
from backend.core.detector import detector_instance

router = APIRouter()

@router.get("/pcap/{bssid}")
async def download_pcap(bssid: str):
    safe_bssid = bssid.replace(":", "")
    filename = f"capture_{safe_bssid}.pcap"
    filepath = os.path.join("data", filename)
    
    if not os.path.exists(filepath):
        # Dump memory buffer if not on disk
        detector_instance._capture_pcap(bssid)
            
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Failed to generate PCAP file.")
        
    return FileResponse(path=filepath, filename=filename, media_type="application/vnd.tcpdump.pcap")
