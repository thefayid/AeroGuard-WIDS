from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import time
import psutil
import csv
from io import StringIO
from typing import List
from pydantic import BaseModel

from backend.core.sniffer import sniffer_instance
from backend.core.interface import list_interfaces, enable_monitor_mode, disable_monitor_mode
from backend.core.profiler import profiler_instance
from backend.core.detector import detector_instance
from backend.core.countermeasures import countermeasures_instance
from backend.utils.models import InterfaceInfo, SettingsModel

router = APIRouter()

START_TIME = time.time()

@router.get("/health")
async def health_check():
    uptime = time.time() - START_TIME
    cpu_usage = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory()
    
    return {
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "sniffer_active": sniffer_instance.is_active(),
        "cpu_usage_percent": cpu_usage,
        "memory_usage_percent": memory.percent
    }

@router.get("/interfaces", response_model=List[InterfaceInfo])
async def get_interfaces():
    try:
        return list_interfaces()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/interfaces/{name}/monitor")
async def start_monitor(name: str):
    new_name = enable_monitor_mode(name)
    if not new_name:
        raise HTTPException(status_code=500, detail=f"Failed to enable monitor mode on {name}")
    sniffer_instance.interface = new_name
    sniffer_instance.start()
    return {"status": "success", "interface": new_name, "mode": "monitor"}

@router.post("/interfaces/{name}/select")
async def select_interface(name: str):
    sniffer_instance.interface = name
    if not sniffer_instance.is_active():
        sniffer_instance.start()
    return {"status": "success", "interface": name}

@router.post("/interfaces/{name}/managed")
async def start_managed(name: str):
    success = disable_monitor_mode(name)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to disable monitor mode on {name}")
    sniffer_instance.stop()
    base_name = name.replace('mon', '') if name.endswith('mon') else name
    return {"status": "success", "interface": base_name, "mode": "managed"}

class BaselineStartReq(BaseModel):
    duration: int = 180

@router.post("/baseline/start")
async def start_baseline(req: BaselineStartReq):
    success = await profiler_instance.start_profiling(req.duration)
    if not success:
        raise HTTPException(status_code=400, detail="Profiling already active")
    return {"status": "success", "message": f"Profiling started for {req.duration} seconds"}

@router.get("/baseline/status")
async def get_baseline_status():
    return profiler_instance.get_status()

@router.post("/baseline/save")
async def save_baseline():
    success = await profiler_instance.save_baseline()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save baseline")
    return {"status": "success", "message": "Baseline saved successfully"}

@router.get("/baseline")
async def get_baseline():
    return {ssid: profile.model_dump() for ssid, profile in profiler_instance.baseline.items()}

@router.get("/live")
async def get_live_networks():
    import time
    now_ts = time.time()
    stale_bssids = [b for b, data in detector_instance.live_aps.items() if now_ts - data['last_seen'] > 15]
    for b in stale_bssids:
        del detector_instance.live_aps[b]
    return detector_instance.live_aps

@router.get("/settings", response_model=SettingsModel)
async def get_settings():
    return SettingsModel(
        deauth_threshold=detector_instance.deauth_threshold,
        rssi_variance_tolerance=detector_instance.rssi_variance_tolerance,
        critical_cutoff=detector_instance.critical_cutoff
    )

@router.post("/settings", response_model=SettingsModel)
async def update_settings(settings: SettingsModel):
    detector_instance.deauth_threshold = settings.deauth_threshold
    detector_instance.rssi_variance_tolerance = settings.rssi_variance_tolerance
    detector_instance.critical_cutoff = settings.critical_cutoff
    return settings

class ReportReq(BaseModel):
    ssid: str
    bssid: str
    factors: List[str]
    score: float
    timestamp: float

@router.post("/reports/export")
async def export_report(req: ReportReq):
    f = StringIO()
    writer = csv.writer(f)
    writer.writerow(["Incident Timestamp", "Target SSID", "Attacker MAC", "Threat Score", "Triggering Factors", "Platform"])
    writer.writerow([
        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req.timestamp)),
        req.ssid,
        req.bssid,
        req.score,
        " | ".join(req.factors),
        "AeroGuard IDS"
    ])
    
    f.seek(0)
    response = StreamingResponse(iter([f.read()]), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=incident_report_{req.bssid.replace(':', '')}.csv"
    return response


# ---------------------------------------------------------------------------
# WIPS Active Countermeasures (Evil Twin deauth jamming)
# ---------------------------------------------------------------------------

class CountermeasuresConfigModel(BaseModel):
    threshold: int = 60
    reason: int = 7
    burst: int = 5
    attack_interval: float = 2.0
    holddown: float = 60.0
    deauth_broadcast: bool = False
    deauth_clients: bool = True
    max_deauths_per_sec: int = 30
    dry_run: bool = False


@router.get("/countermeasures")
async def get_countermeasures():
    """Status + config + active targets of the WIPS countermeasure engine."""
    return countermeasures_instance.status()


class CountermeasuresEnableReq(BaseModel):
    enabled: bool


@router.post("/countermeasures/toggle")
async def toggle_wips(enabled: bool):
    """Enable or disable Active Countermeasures (WIPS)."""
    if enabled:
        countermeasures_instance.start()
    else:
        countermeasures_instance.stop()
    return {"status": "success", "wips_enabled": countermeasures_instance.enabled}

@router.get("/clients")
async def get_clients():
    """Return live tracked clients."""
    now = time.time()
    clients = []
    
    # Prune stale clients (older than 60s)
    stale_macs = [mac for mac, data in detector_instance.live_clients.items() if now - data['last_seen'] > 60]
    for mac in stale_macs:
        del detector_instance.live_clients[mac]
        
    for mac, data in detector_instance.live_clients.items():
        clients.append({
            "mac": mac,
            "bssid": data["bssid"] or "Unassociated",
            "rssi": data["rssi"],
            "last_seen": data["last_seen"],
            "probed_ssids": list(data["probed_ssids"])
        })
    return {"clients": clients}


@router.post("/countermeasures/config")
async def update_countermeasures_config(cfg: CountermeasuresConfigModel):
    """Tune thresholds / deauth behaviour of the countermeasures."""
    countermeasures_instance.update_config(**cfg.model_dump())
    return countermeasures_instance.status()


class CountermeasuresTriggerReq(BaseModel):
    ssid: str
    bssid: str
    score: int = 100


@router.post("/countermeasures/trigger")
async def trigger_countermeasures(req: CountermeasuresTriggerReq):
    """Manually engage a rogue AP (testing / manual override)."""
    countermeasures_instance.trigger(
        ssid=req.ssid, bssid=req.bssid, score=req.score)
    return countermeasures_instance.status()

# ---------------------------------------------------------------------------
# Client Tracking
# ---------------------------------------------------------------------------

@router.get("/threats/{bssid}/clients")
async def get_compromised_clients(bssid: str):
    """Get list of MAC addresses of clients interacting with a rogue AP."""
    bssid_lower = bssid.lower()
    clients = detector_instance.compromised_clients.get(bssid_lower, set())
    return {"status": "success", "bssid": bssid_lower, "clients": list(clients)}
