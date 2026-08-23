import time
import json
import asyncio
import os
from typing import Dict, Any
from backend.utils.logger import get_logger
from backend.utils.models import SSIDProfile, BSSIDFingerprint, RSSIBaseline

try:
    from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt, RadioTap
except ImportError:
    Dot11Beacon = Dot11ProbeResp = Dot11 = Dot11Elt = RadioTap = None

logger = get_logger(__name__)

class ProfilerEngine:
    def __init__(self):
        self.is_active = False
        self.end_time = 0.0
        self.duration = 0
        self.baseline: Dict[str, SSIDProfile] = {}
        self.lock = asyncio.Lock()
        
    async def start_profiling(self, duration: int = 180):
        async with self.lock:
            if self.is_active:
                return False
            self.is_active = True
            self.duration = duration
            self.end_time = time.time() + duration
            self.baseline = {}
            logger.info(f"Started baseline profiling for {duration} seconds.")
            
            asyncio.create_task(self._auto_stop(duration))
            return True
            
    async def _auto_stop(self, duration: int):
        await asyncio.sleep(duration)
        async with self.lock:
            self.is_active = False
            logger.info("Baseline profiling automatically stopped.")

    def get_status(self) -> Dict[str, Any]:
        if not self.is_active:
            return {"active": False, "remaining_seconds": 0, "ap_count": len(self.baseline)}
        
        remaining = max(0.0, self.end_time - time.time())
        ap_count = sum(len(profile.bssids) for profile in self.baseline.values())
        return {
            "active": True,
            "remaining_seconds": round(remaining, 1),
            "ap_count": ap_count
        }
        
    async def process_packet(self, packet):
        if not self.is_active or not Dot11:
            return

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            try:
                bssid = packet[Dot11].addr3
                if not bssid:
                    return
                bssid = bssid.lower()
                
                ssid = ""
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode('utf-8', 'ignore')
                        except:
                            pass
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                
                if not ssid:
                    return

                rssi = -100
                if packet.haslayer(RadioTap):
                    try:
                        dbm = packet[RadioTap].dBm_AntSignal
                        if dbm is not None:
                            rssi = int(dbm)
                    except:
                        pass

                channel = 0
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3:
                        try:
                            channel = int(elt.info[0])
                        except:
                            pass
                        break
                    elt = elt.payload.getlayer(Dot11Elt)

                oui = bssid[:8].upper()
                
                async with self.lock:
                    if ssid not in self.baseline:
                        self.baseline[ssid] = SSIDProfile(ssid=ssid)
                    
                    profile = self.baseline[ssid]
                    if bssid not in profile.bssids:
                        profile.bssids[bssid] = BSSIDFingerprint(bssid=bssid, oui_vendor=oui)
                    
                    fingerprint = profile.bssids[bssid]
                    
                    if channel > 0 and channel not in fingerprint.channels:
                        fingerprint.channels.append(channel)
                        
                    stats = fingerprint.rssi_stats
                    stats.count += 1
                    fingerprint.historical_rssi.append(rssi)
                    
                    if stats.count == 1:
                        stats.min_rssi = rssi
                        stats.max_rssi = rssi
                        stats.avg_rssi = rssi
                    else:
                        stats.min_rssi = min(stats.min_rssi, rssi)
                        stats.max_rssi = max(stats.max_rssi, rssi)
                        stats.avg_rssi = ((stats.avg_rssi * (stats.count - 1)) + rssi) / stats.count

            except Exception as e:
                # logger.debug(f"Packet parse error: {e}")
                pass

    async def save_baseline(self, filepath: str = "data/baseline.json") -> bool:
        async with self.lock:
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                data = {ssid: profile.model_dump() for ssid, profile in self.baseline.items()}
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=4)
                    
                # Save to DB
                try:
                    from backend.db.database import SessionLocal, DBBaseline
                    db = SessionLocal()
                    for ssid, profile_data in data.items():
                        existing = db.query(DBBaseline).filter(DBBaseline.ssid == ssid).first()
                        if existing:
                            existing.json_data = json.dumps(profile_data)
                        else:
                            new_bl = DBBaseline(ssid=ssid, json_data=json.dumps(profile_data))
                            db.add(new_bl)
                    db.commit()
                    db.close()
                except ImportError:
                    pass
                    
                logger.info(f"Saved baseline with {len(self.baseline)} SSIDs to {filepath} and DB")
                return True
            except Exception as e:
                logger.error(f"Failed to save baseline: {e}")
                return False

    def load_baseline(self, filepath: str = "data/baseline.json"):
        data = None
        # Try DB first
        try:
            from backend.db.database import SessionLocal, DBBaseline
            db = SessionLocal()
            baselines = db.query(DBBaseline).all()
            if baselines:
                data = {bl.ssid: json.loads(bl.json_data) for bl in baselines}
            db.close()
        except ImportError:
            pass
            
        if not data:
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
            except FileNotFoundError:
                logger.info("No existing baseline found.")
                return
            except Exception as e:
                logger.error(f"Error loading baseline file: {e}")
                return
                
        if data:
            self.baseline = {ssid: SSIDProfile(**profile) for ssid, profile in data.items()}
            logger.info(f"Loaded baseline with {len(self.baseline)} SSIDs.")

profiler_instance = ProfilerEngine()
profiler_instance.load_baseline()
