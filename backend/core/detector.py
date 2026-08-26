from typing import Dict, Any
import time
from collections import deque
from backend.utils.logger import get_logger
from backend.core.profiler import profiler_instance
from backend.core.countermeasures import countermeasures_instance

try:
    from scapy.all import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11Deauth, Dot11Disas, wrpcap, EAPOL, Dot11ProbeResp
except ImportError:
    Dot11Beacon = Dot11 = Dot11Elt = RadioTap = Dot11Deauth = Dot11Disas = wrpcap = EAPOL = Dot11ProbeResp = None

logger = get_logger(__name__)

class DetectorEngine:
    def __init__(self):
        self.active_alerts = []
        self.last_alert_time = {}
        self.deauth_window = deque()
        self.consecutive_seconds = 3
        self.recent_deauth_floods = {} # {mac: timestamp}
        self.packet_buffer = deque(maxlen=20000) # Rolling 60s approx
        self.pcap_buffers = {} # {bssid: [packets]}
        self.eapol_tracking = {} # {bssid: deque of timestamps}
        
        # Threat Tracking
        self.rogue_bssids = {} # {bssid: score}
        self.compromised_clients = {} # {bssid: set(mac)}
        self.live_aps = {} # {bssid: {"ssid": str, "rssi": int, "channel": int, "vendor": str, "security": str, "last_seen": float, "is_rogue": bool}}
        self.live_clients = {} # {mac: {"bssid": str, "last_seen": float, "rssi": int, "probed_ssids": set()}}
        import random
        import string
        self.karma_fake_ssid = "AeroGuard_Probe_" + ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        
        # Dynamic Settings
        self.deauth_threshold = 10
        self.rssi_variance_tolerance = 25 # Increased to reduce false positives (natural fading)
        self.critical_cutoff = 70
        
        # Machine Learning Models
        self.ml_models = {} # {bssid: IsolationForest}
        self.ml_enabled = False
        import sys
        if sys.platform != "win32":
            import importlib.util
            if importlib.util.find_spec("sklearn"):
                self.ml_enabled = True
            else:
                logger.warning("scikit-learn not installed, ML anomaly detection disabled.")
        else:
            logger.warning("Windows host detected. ML anomaly detection disabled to prevent MemoryError.")

    async def process_packet(self, packet, skip_threats=False):
        if not Dot11:
            return
            
        self.packet_buffer.append((time.time(), packet))
        # Keep only last 60 seconds
        now = time.time()
        while self.packet_buffer and self.packet_buffer[0][0] < now - 60:
            self.packet_buffer.popleft()

        if skip_threats:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                await self._analyze_beacon(packet, skip_threats=True)
            return

        if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
            await self._handle_deauth(packet)
            return

        # Client Tracking Logic
        dot11 = packet.getlayer(Dot11)
        if dot11:
            addr1 = dot11.addr1
            addr2 = dot11.addr2
            addr3 = dot11.addr3
            
            # Identify client MAC (usually addr2 in probes/data from client)
            client_mac = None
            if dot11.type == 0 and dot11.subtype == 4: # Probe Request
                client_mac = addr2
            elif dot11.type == 2: # Data
                # From DS=0, To DS=1 -> client is addr2
                if dot11.FCfield & 0x1 and not (dot11.FCfield & 0x2):
                    client_mac = addr2
                # From DS=1, To DS=0 -> client is addr1
                elif not (dot11.FCfield & 0x1) and (dot11.FCfield & 0x2):
                    client_mac = addr1

            if client_mac and client_mac.lower() != "ff:ff:ff:ff:ff:ff":
                client_mac = client_mac.lower()
                rssi = -100
                if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                    rssi = int(packet[RadioTap].dBm_AntSignal)
                
                if client_mac not in self.live_clients:
                    self.live_clients[client_mac] = {"bssid": None, "last_seen": 0, "rssi": -100, "probed_ssids": set()}
                
                self.live_clients[client_mac]["last_seen"] = time.time()
                self.live_clients[client_mac]["rssi"] = rssi
                
                # Check for Probe Request SSIDs
                if dot11.type == 0 and dot11.subtype == 4 and packet.haslayer(Dot11Elt):
                    elt = packet.getlayer(Dot11Elt)
                    while isinstance(elt, Dot11Elt):
                        if elt.ID == 0 and elt.info: # SSID
                            try:
                                probed_ssid = elt.info.decode('utf-8', errors='ignore')
                                if probed_ssid:
                                    self.live_clients[client_mac]["probed_ssids"].add(probed_ssid)
                            except:
                                pass
                        elt = elt.payload.getlayer(Dot11Elt)

            # Compromised client tracking (rogue AP communication)
            if dot11.type in [0, 2]:
                for bssid in self.rogue_bssids:
                    # If the rogue is the receiver (addr1) or BSSID (addr3)
                    if (addr1 and addr1.lower() == bssid) or (addr3 and addr3.lower() == bssid):
                        if addr2 and addr2.lower() != bssid and addr2.lower() != "ff:ff:ff:ff:ff:ff":
                            if bssid not in self.compromised_clients:
                                self.compromised_clients[bssid] = set()
                            self.compromised_clients[bssid].add(addr2.lower())
                            if addr2.lower() in self.live_clients:
                                self.live_clients[addr2.lower()]["bssid"] = bssid

            # Handshake Capture (EAPOL)
            if packet.haslayer(EAPOL) and (addr1 or addr2):
                # We only want to capture handshakes related to rogue APs
                target_bssid = None
                if addr1 and addr1.lower() in self.rogue_bssids:
                    target_bssid = addr1.lower()
                elif addr2 and addr2.lower() in self.rogue_bssids:
                    target_bssid = addr2.lower()
                elif addr3 and addr3.lower() in self.rogue_bssids:
                    target_bssid = addr3.lower()
                
                if target_bssid and wrpcap:
                    import os
                    capture_dir = os.path.join("data", "captures")
                    os.makedirs(capture_dir, exist_ok=True)
                    pcap_file = os.path.join(capture_dir, f"{target_bssid.replace(':', '')}_handshake.pcap")
                    try:
                        wrpcap(pcap_file, packet, append=True)
                        logger.debug(f"Captured EAPOL frame for {target_bssid}")
                    except Exception as e:
                        logger.error(f"Failed to write handshake to pcap: {e}")

                # EAPOL tracking for brute-force/PMKID attack detection
                bssid = None
                if addr3: bssid = addr3.lower()
                elif addr1 and addr1.lower() != "ff:ff:ff:ff:ff:ff": bssid = addr1.lower()
                elif addr2: bssid = addr2.lower()
                
                if bssid:
                    now = time.time()
                    if bssid not in self.eapol_tracking:
                        self.eapol_tracking[bssid] = deque(maxlen=20)
                    self.eapol_tracking[bssid].append(now)
                    
                    # Check for >10 EAPOL frames in the last 15 seconds
                    recent_eapol = [t for t in self.eapol_tracking[bssid] if now - t <= 15]
                    if len(recent_eapol) >= 10:
                        ssid = self.live_aps.get(bssid, {}).get("ssid", "Unknown")
                        self._trigger_alert(
                            "WPA2/WPA3 Handshake Harvesting (PMKID Attack)",
                            f"Brute-force attack detected against {bssid}. {len(recent_eapol)} EAPOL frames intercepted in 15s.",
                            {
                                "ssid": ssid,
                                "bssid": bssid,
                                "score": 100,
                                "factors": ["W9: EAPOL Flood / PMKID Attack"],
                                "severity": "CRITICAL"
                            }
                        )
                        self.eapol_tracking[bssid].clear()

        if not packet.haslayer(Dot11Beacon):
            return

        await self._analyze_beacon(packet, skip_threats=False)

    async def _analyze_beacon(self, packet, skip_threats=False):
        try:
            bssid = packet[Dot11].addr3
            if not bssid:
                return
            bssid = bssid.lower()

            ssid = ""
            channel = 0
            encryption_capabilities = []
            vendor_ie_data = []

            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode('utf-8', 'ignore')
                    except:
                        pass
                elif elt.ID == 3:
                    try:
                        channel = int(elt.info[0])
                    except:
                        pass
                elif elt.ID == 48: 
                    encryption_capabilities.append("WPA2")
                    if b'\x00\x0f\xac\x08' in elt.info:
                        encryption_capabilities.append("WPA3")
                    if b'\x00\x0f\xac\x06' in elt.info:
                        encryption_capabilities.append("MFP")
                elif elt.ID == 221: 
                    vendor_ie_data.append(elt.info)
                    if elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                        encryption_capabilities.append("WPA")
                elt = elt.payload.getlayer(Dot11Elt)
                
            if not ssid:
                return

            rssi = -100
            if packet.haslayer(RadioTap):
                if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                    rssi = int(packet[RadioTap].dBm_AntSignal)

            if not encryption_capabilities:
                encryption_capabilities = ["Open"]

            oui = bssid[:8].upper()
            
            # Clean up old live APs (older than 15s)
            now_ts = time.time()
            stale_bssids = [b for b, data in self.live_aps.items() if now_ts - data['last_seen'] > 15]
            for b in stale_bssids:
                del self.live_aps[b]

            # Update live state
            self.live_aps[bssid] = {
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
                "vendor": oui,
                "security": encryption_capabilities[0],
                "last_seen": now_ts,
                "is_rogue": False # Will be updated if detected as rogue below
            }

            if skip_threats:
                return

            if ssid == self.karma_fake_ssid:
                score = 100
                factors = ["W7: Karma/Pineapple Attack (Fake Probe Response)"]
                countermeasures_instance.report_threat(
                    ssid=ssid,
                    bssid=bssid,
                    score=score,
                    factors=factors,
                    extra={"rssi": rssi, "channel": channel}
                )
                self.rogue_bssids[bssid] = score
                self.live_aps[bssid]['is_rogue'] = True
                self.live_aps[bssid]['score'] = score
                return

            score = 0
            factors = []

            if oui in ["00:13:37", "00:C0:CA"] or "pineapple" in ssid.lower() or "pineap" in ssid.lower():
                score += 50
                factors.append("W8: Hak5 Pineapple Hardware Signature Detected")

            baseline = profiler_instance.baseline
            if ssid in baseline:
                profile = baseline[ssid]
                
                # Check ML prediction
                if self.ml_enabled and bssid in self.ml_models:
                    model = self.ml_models[bssid]
                    import numpy as np
                    try:
                        prediction = model.predict(np.array([[rssi]]))
                        if prediction[0] == -1: # Anomaly detected
                            score += 25
                            factors.append("W6: ML Anomaly Detected (RSSI deviation)")
                    except Exception:
                        pass
                
                if bssid not in profile.bssids:
                    score += 35
                    factors.append("W1: Unknown BSSID")
                
                if bssid in profile.bssids:
                    bssid_info = profile.bssids[bssid]
                    
                    if bssid_info.oui_vendor != "UNKNOWN" and bssid_info.oui_vendor != oui:
                        score += 20
                        factors.append("W2: OUI Inconsistency")
                        
                    baseline_ciphers = bssid_info.cipher_suites
                    if baseline_ciphers:
                        if "WPA3" in baseline_ciphers and "WPA3" not in encryption_capabilities:
                            score += 35
                            factors.append("W5: WPA3 Downgrade Attack")
                        elif "WPA2" in baseline_ciphers and "WPA2" not in encryption_capabilities:
                            score += 25
                            factors.append("W5: Security Downgrade")
                            
                        if "MFP" in baseline_ciphers and "MFP" not in encryption_capabilities:
                            score += 15
                            factors.append("W5: MFP Disabled (Deauth vulnerability)")
                            
                    if bssid_info.rssi_stats.count > 0:
                        if rssi > (bssid_info.rssi_stats.avg_rssi + self.rssi_variance_tolerance):
                            score += 15
                            factors.append("W4: RSSI Delta Spike")
                            
                else:
                    overall_ciphers = set()
                    max_known_avg_rssi = -100
                    
                    for b_info in profile.bssids.values():
                        for c in b_info.cipher_suites:
                            overall_ciphers.add(c)
                        if b_info.rssi_stats.count > 0:
                            max_known_avg_rssi = max(max_known_avg_rssi, b_info.rssi_stats.avg_rssi)
                            
                    if "WPA3" in overall_ciphers and "WPA3" not in encryption_capabilities:
                        score += 35
                        factors.append("W5: WPA3 Downgrade Attack")
                    elif "WPA2" in overall_ciphers and "WPA2" not in encryption_capabilities:
                        score += 25
                        factors.append("W5: Security Downgrade")
                        
                    if "MFP" in overall_ciphers and "MFP" not in encryption_capabilities:
                        score += 15
                        factors.append("W5: MFP Disabled")
                    
                    if max_known_avg_rssi > -100 and rssi > (max_known_avg_rssi + self.rssi_variance_tolerance):
                        score += 15
                        factors.append("W4: RSSI Delta Spike")
                
                now = time.time()
                self.recent_deauth_floods = {m: t for m, t in self.recent_deauth_floods.items() if now - t <= 10}
                
                deauth_correlated = False
                if bssid in self.recent_deauth_floods:
                    deauth_correlated = True
                else:
                    for leg_bssid in profile.bssids:
                        if leg_bssid in self.recent_deauth_floods:
                            deauth_correlated = True
                            break
                            
                if deauth_correlated:
                    score += 30
                    factors.append("W3: Active Deauth Flood Correlated")
                
                score = min(score, 100)

                # Feed the active countermeasure engine (WIPS) so it can
                # engage the rogue AP with deauth injection when the score
                # crosses its configured threshold.
                countermeasures_instance.report_threat(
                    ssid=ssid,
                    bssid=bssid,
                    score=score,
                    factors=factors,
                    extra={"rssi": rssi, "channel": channel}
                )
                
                # If this AP was manually engaged (or engaged by WIPS), preserve its active threat score
                if bssid in countermeasures_instance._targets:
                    wips_target = countermeasures_instance._targets[bssid]
                    score = max(score, wips_target.score)
                    if wips_target.forced and "MANUAL TRIGGER" not in factors:
                        factors.append("MANUAL TRIGGER")
                
                # Keep track of known rogues
                if score >= 40:
                    self.rogue_bssids[bssid] = score
                    self.live_aps[bssid]['is_rogue'] = True
                    self.live_aps[bssid]['score'] = score
                elif bssid in self.rogue_bssids:
                    del self.rogue_bssids[bssid]

                if score < 40:
                    pass
                elif 40 <= score < self.critical_cutoff:
                    self._trigger_alert(
                        "Suspicious Rogue AP",
                        f"Threat Score: {score}/100. Anomalies: {', '.join(factors)}",
                        {
                            "ssid": ssid,
                            "bssid": bssid,
                            "score": score,
                            "factors": factors,
                            "severity": "WARNING"
                        }
                    )
                else:
                    self._trigger_alert(
                        "CRITICAL EVIL TWIN ATTACK IN PROGRESS",
                        f"Threat Score: {score}/100. Vectors: {', '.join(factors)}",
                        {
                            "ssid": ssid,
                            "bssid": bssid,
                            "score": score,
                            "factors": factors,
                            "severity": "CRITICAL",
                            "rssi": rssi,
                            "channel": channel
                        }
                    )
                    self._capture_pcap(bssid)

        except Exception:
            pass
            
    def _capture_pcap(self, bssid: str):
        import os
        if not wrpcap: return
        safe_bssid = bssid.replace(':', '')
        filename = f"capture_{safe_bssid}.pcap"
        filepath = os.path.join("data", filename)
        os.makedirs("data", exist_ok=True)
        
        # Dump buffer to disk
        packets = [p for ts, p in self.packet_buffer]
        try:
            wrpcap(filepath, packets)
            logger.info(f"PCAP captured to {filepath}")
        except Exception as e:
            logger.error(f"Failed to write PCAP: {e}")

    async def _handle_deauth(self, packet):
        try:
            dot11 = packet[Dot11]
            src_mac = dot11.addr2
            dst_mac = dot11.addr1
            if not src_mac or not dst_mac:
                return
                
            src_mac = src_mac.lower()
            dst_mac = dst_mac.lower()
            
            reason = 0
            is_deauth = packet.haslayer(Dot11Deauth)
            layer = packet[Dot11Deauth] if is_deauth else packet[Dot11Disas]
            if hasattr(layer, 'reason'):
                reason = layer.reason
                
            now = time.time()
            self.deauth_window.append({
                "ts": now,
                "src": src_mac,
                "dst": dst_mac,
                "reason": reason,
                "type": "Deauth" if is_deauth else "Disas"
            })
            
            while self.deauth_window and self.deauth_window[0]["ts"] < now - 4.0:
                self.deauth_window.popleft()
                
            self._evaluate_deauth_flood(now)
            
        except Exception:
            pass

    def _evaluate_deauth_flood(self, current_time: float):
        c1 = c2 = c3 = 0
        broadcast_count = 0
        total_count = 0
        attackers = set()
        targets = set()
        
        for event in self.deauth_window:
            ts = event["ts"]
            if current_time - 1.0 <= ts <= current_time:
                c1 += 1
            elif current_time - 2.0 <= ts < current_time - 1.0:
                c2 += 1
            elif current_time - 3.0 <= ts < current_time - 2.0:
                c3 += 1
                
            if current_time - 3.0 <= ts <= current_time:
                total_count += 1
                attackers.add(event["src"])
                targets.add(event["dst"])
                if event["dst"] == "ff:ff:ff:ff:ff:ff":
                    broadcast_count += 1
                    
        if c1 > self.deauth_threshold and c2 > self.deauth_threshold and c3 > self.deauth_threshold:
            broadcast_ratio = (broadcast_count / total_count * 100) if total_count > 0 else 0
            
            for mac in attackers.union(targets):
                if mac != "ff:ff:ff:ff:ff:ff":
                    self.recent_deauth_floods[mac] = current_time
            
            self._trigger_alert(
                "Deauth/Disassociation Flood Detected",
                f"Sustained attack: >{self.deauth_threshold} frames/sec for 3s. Broadcast ratio: {broadcast_ratio:.1f}%",
                {
                    "attackers": list(attackers),
                    "targets": list(targets),
                    "total_frames_3s": total_count,
                    "broadcast_ratio_percent": round(broadcast_ratio, 2),
                    "severity": "WARNING"
                }
            )
            self.deauth_window.clear()

    def _trigger_alert(self, title: str, description: str, metadata: Dict[str, Any]):
        cache_key = f"{title}_{metadata.get('bssid')}"
        
        # Debounce alerts for the same BSSID to prevent UI spam
        if cache_key in self.last_alert_time:
            if time.time() - self.last_alert_time[cache_key] < 30:
                return
        
        self.last_alert_time[cache_key] = time.time()
        
        alert = {
            "title": title,
            "description": description,
            "metadata": metadata,
            "timestamp": time.time()
        }

        logger.warning(f"THREAT DETECTED: {title} - {description}")
        self.active_alerts.append(alert)
        
        if metadata.get("severity") == "CRITICAL":
            # Dispatch Webhook
            from backend.utils.notifier import send_alert_webhook
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(send_alert_webhook(title, description, metadata))
            except RuntimeError:
                pass
                
            # Log to Database
            try:
                from backend.db.database import SessionLocal, DBIncidentLog
                db = SessionLocal()
                db_log = DBIncidentLog(
                    title=title,
                    description=description,
                    bssid=metadata.get("bssid", "Unknown"),
                    score=metadata.get("score", 0.0)
                )
                db.add(db_log)
                db.commit()
                db.close()
            except Exception as e:
                logger.error(f"Failed to log incident to DB: {e}")

    def train_ml_models(self):
        if not self.ml_enabled: return
        from sklearn.ensemble import IsolationForest
        import numpy as np
        
        baseline = profiler_instance.baseline
        trained_count = 0
        for ssid, profile in baseline.items():
            for bssid, fp in profile.bssids.items():
                if len(fp.historical_rssi) > 10:
                    model = IsolationForest(contamination=0.01, random_state=42)
                    X = np.array(fp.historical_rssi).reshape(-1, 1)
                    model.fit(X)
                    self.ml_models[bssid] = model
                    trained_count += 1
        logger.info(f"Trained {trained_count} ML anomaly detection models.")

detector_instance = DetectorEngine()
# Attempt to train models on startup if baseline already loaded
detector_instance.train_ml_models()
