from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import asyncio
import time
from backend.api.ws import router as ws_router
from backend.api.ws import manager as ws_manager  # noqa: F401
from backend.api import routes, reports
from backend.core.sniffer import sniffer_instance
from backend.core.profiler import profiler_instance
from backend.core.detector import detector_instance
from backend.core.countermeasures import countermeasures_instance
from backend.utils.logger import get_logger

logger = get_logger(__name__)

async def process_packets():
    logger.info("Starting async packet processing loop")
    while not sniffer_instance.stop_event.is_set():
        try:
            if not sniffer_instance.packet_queue.empty():
                packet = sniffer_instance.packet_queue.get_nowait()
                if profiler_instance.is_active:
                    await profiler_instance.process_packet(packet)
                    await detector_instance.process_packet(packet, skip_threats=True)
                else:
                    await detector_instance.process_packet(packet)
                # Also feed the WIPS countermeasure engine (client tracking).
                countermeasures_instance.ingest(packet)
            else:
                await asyncio.sleep(0.01)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            await asyncio.sleep(0.1)

async def telemetry_loop():
    logger.info("Starting WebSocket telemetry loop")
    while True:
        try:
            await asyncio.sleep(1)
            
            # Emit Instant Alerts
            new_alerts = []
            while detector_instance.active_alerts:
                new_alerts.append(detector_instance.active_alerts.pop(0))
                
            for alert in new_alerts:
                await ws_manager.broadcast_alert(alert)

            # Emit WIPS countermeasure events (engagement / deauth bursts)
            while countermeasures_instance.events:
                await ws_manager.broadcast_alert(
                    countermeasures_instance.events.popleft())
            
            # Telemetry logic
            active_clients = sum(1 for c in detector_instance.live_clients.values() if time.time() - c['last_seen'] <= 60)
            
            max_threat = 0
            for t in countermeasures_instance._targets.values():
                max_threat = max(max_threat, t.score)
            for score in detector_instance.rogue_bssids.values():
                max_threat = max(max_threat, score)
                
            rssis = [ap['rssi'] for ap in detector_instance.live_aps.values() if ap['rssi'] > -100]
            avg_rssi = sum(rssis) / len(rssis) if rssis else -100
            
            # Emit Telemetry (1 Hz)
            telemetry = {
                "total_packets": sniffer_instance.total_packets_scanned,
                "mgmt_packets": getattr(sniffer_instance, 'mgmt_count', 0),
                "ctrl_packets": getattr(sniffer_instance, 'ctrl_count', 0),
                "data_packets": getattr(sniffer_instance, 'data_count', 0),
                "deauth_packets": getattr(sniffer_instance, 'deauth_count', 0),
                "total_bytes": getattr(sniffer_instance, 'total_bytes', 0),
                "active_aps": len(profiler_instance.baseline),
                "live_aps": len(detector_instance.live_aps),
                "live_clients": active_clients,
                "countermeasures_enabled": countermeasures_instance.enabled,
                "max_threat_score": max_threat,
                "avg_rssi": avg_rssi,
                "channel_utilization": 0,  # Placeholder
                "noise_floor": -90         # Placeholder
            }
            await ws_manager.broadcast_telemetry(telemetry)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Telemetry loop error: {e}")

async def karma_loop():
    logger.info("Starting Karma attack detection loop")
    while True:
        try:
            await asyncio.sleep(30)
            if sniffer_instance.interface and sniffer_instance.is_active():
                # Inject a fake probe request natively if possible
                try:
                    from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
                    fake_ssid = detector_instance.karma_fake_ssid
                    probe = RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff") / Dot11ProbeReq() / Dot11Elt(ID="SSID", info=fake_ssid.encode())
                    sendp(probe, iface=sniffer_instance.interface, verbose=0)
                except Exception:
                    pass # May fail on Windows or if interface is managed
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"Karma injection loop error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AeroGuard IDS backend")
    packet_processor_task = asyncio.create_task(process_packets())
    telemetry_task = asyncio.create_task(telemetry_loop())
    karma_task = asyncio.create_task(karma_loop())
    
    yield
    
    logger.info("Shutting down AeroGuard IDS backend")
    sniffer_instance.stop()
    countermeasures_instance.stop()
    packet_processor_task.cancel()
    telemetry_task.cancel()
    karma_task.cancel()

app = FastAPI(title="AeroGuard IDS", lifespan=lifespan)

app.include_router(routes.router, prefix="/api")
app.include_router(reports.router, prefix="/api/reports")
app.include_router(ws_router, prefix="/ws")
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

@app.get("/")
async def serve_spa():
    return FileResponse("frontend/templates/index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # nosec B104
