#!/usr/bin/env python3
"""
AeroGuard WIDS - Active Countermeasures (WIPS) engine
=====================================================
Detects rogue / Evil Twin access points that impersonate a profiled SSID and
actively defends the network by injecting crafted 802.11 Deauthentication
frames at the offending BSSID.

Pipeline:  SENSE (passive 802.11 observation) -> SCORE (threat scoring)
           -> FIGHT (Deauth injection against the rogue BSSID + its clients)

Threat scoring (independent of the detector's score; final = max of both):
    +40 identity mismatch      same SSID, different BSSID than the baseline
    +20 no RSN IE              encryption downgrade / open network
    +10 PMF / 802.11w not req  vulnerable to deauth attacks
    +10 signal anomaly         rogue RSSI >= legit AP RSSI + margin
    + 5 vendor OUI mismatch    different vendor than the legitimate AP
    + 5 channel drift          rogue on a channel the legit AP never uses
    default threshold: 60

Platform behaviour
  * Linux  : real capture + real injection (requires monitor-mode NIC + root).
  * Windows: DEMO mode - threat tracking and scoring run normally, but no
             frames are injected. Crafted deauths are logged and dumped to
             data/wips_demo_deauths.pcap for Wireshark inspection.

Wiring (already present in the project):
  - detector.py : countermeasures_instance.report_threat(...)   score input
  - app.py      : countermeasures_instance.ingest(packet)       client/AP tracking
                  countermeasures_instance.stop()               shutdown
                  countermeasures_instance.enabled              telemetry
  - routes.py   : /api/countermeasures*                         control surface
"""

from __future__ import annotations

import os
import sys
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from backend.core.profiler import profiler_instance
from backend.core.sniffer import sniffer_instance
from backend.utils.logger import get_logger

try:
    from scapy.all import Dot11, Dot11Deauth, Dot11Elt, RadioTap, sendp, wrpcap
except ImportError:  # pragma: no cover
    Dot11 = Dot11Deauth = Dot11Elt = RadioTap = sendp = wrpcap = None

logger = get_logger(__name__)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

DEAUTH_REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving BSS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated because sending station is leaving BSS",
    9: "Station requesting (re)association is not authenticated",
    10: "Disassociated because the information in the Power Capability element is unacceptable",
    11: "Disassociated because the information in the Supported Channels element is unacceptable",
    12: "Disassociated due to BSS Transition Management",
    13: "Invalid element, i.e., an element whose content does not meet the specifications",
    14: "Message integrity check (MIC) failure",
    15: "Four-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "STA is requesting (re)association with an AP that does not support robust security",
    18: "Cipher suite rejected due to network security policy",
    19: "Association denied because the requesting STA does not support the BSS Basic Service Set (BSS) Transition Management capability",
    20: "Requested (re)association refused because the AP is disallowing the STA to associate based on the MAC address",
    32: "Unspecified QoS-related reason",
    33: "QoS policy cannot be satisfied",
    34: "Insufficient bandwidth",
    35: "Invalid, i.e., unrecognized or unsupported frame body",
    36: "Invalid, i.e., unrecognized or unsupported QoS policy control field",
    37: "Reserved (QoS-related)",
    38: "Reserved (QoS-related)",
    39: "Reserved (QoS-related)",
    40: "Reserved (QoS-related)",
    41: "Mesh STA is leaving the mesh BSS",
    42: "Mesh STA is no longer present in the mesh BSS",
    43: "Mesh STA is leaving the mesh BSS for unknown reasons",
    44: "Mesh STA is leaving the mesh BSS due to a Mesh Peering Cancel",
    45: "Mesh STA has been disassociated due to mesh control field error",
    46: "Mesh STA has been disassociated because the STA is not participating in mesh peering",
}


class _ThreatTarget:
    """An engaged rogue AP: scored, tracked, and under active countermeasures."""

    __slots__ = (
        "ssid", "bssid", "score", "factors", "rssi", "channel",
        "clients", "deauths_sent", "deauths_planned", "bursts",
        "last_frame_ts", "last_burst_ts", "engaged_ts", "forced",
    )

    def __init__(self, ssid: str, bssid: str, score: int,
                 factors: List[str], forced: bool = False) -> None:
        now = time.time()
        self.ssid = ssid
        self.bssid = bssid
        self.score = score
        self.factors = list(factors)
        self.rssi = -100
        self.channel = 0
        self.clients: Dict[str, float] = {}          # mac -> last_seen
        self.deauths_sent = 0
        self.deauths_planned = 0
        self.bursts = 0
        self.last_frame_ts = now
        self.last_burst_ts = 0.0
        self.engaged_ts = now
        self.forced = forced


class CountermeasuresEngine:
    """Active countermeasures / WIPS engine for AeroGuard WIDS."""

    def __init__(self) -> None:
        # -- configuration --------------------------------------------------
        self.threshold = 60          # min score to engage a rogue AP
        self.reason = 7              # 802.11 deauth reason code
        self.burst = 5               # max client deauths per burst
        self.attack_interval = 2.0   # seconds between bursts per target
        self.holddown = 60.0         # drop target after N s of silence
        self.deauth_broadcast = False # Default to targeted client containment
        self.deauth_clients = True
        self.max_deauths_per_sec = 30
        self.dry_run = False         # detect + plan, never inject
        self.signal_margin = 5.0     # dB above legit RSSI considered anomalous

        # -- runtime state ---------------------------------------------------
        self.enabled = True
        self.demo_mode = sys.platform.startswith("win")
        self._iface: Optional[str] = None
        self._lock = threading.RLock()
        self._targets: Dict[str, _ThreatTarget] = {}
        self._candidates: Dict[str, _ThreatTarget] = {}
        self._ap_obs: Dict[str, Dict[str, Any]] = {}   # bssid -> observation
        self._events: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._rate_window: Deque[float] = deque()
        self._demo_frames: List[Any] = []
        self.total_deauths_sent = 0
        self.total_deauths_planned = 0
        self.total_bursts = 0
        self.total_targets_engaged = 0

        if self.demo_mode:
            logger.warning(
                "Windows host detected - WIPS running in DEMO mode: threats "
                "are tracked and scored but no frames are injected. Real "
                "injection requires Linux + monitor-mode NIC + root.")

    # ------------------------------------------------------------------ utils
    @property
    def iface(self) -> str:
        if self._iface:
            return self._iface
        return getattr(sniffer_instance, "interface", None) or "wlan0mon"

    @staticmethod
    def _oui(addr: str) -> str:
        return (addr or "").replace(":", "")[:6].upper()

    def _emit(self, title: str, description: str, metadata: Dict[str, Any]) -> None:
        event = {
            "title": title,
            "description": description,
            "metadata": metadata,
            "timestamp": time.time(),
        }
        with self._lock:
            self._events.append(event)
        logger.warning("%s - %s", title, description)

    def _legit_bssids(self, ssid: str) -> Set[str]:
        """Baseline BSSIDs for an SSID are, by definition, legitimate."""
        profile = profiler_instance.baseline.get(ssid)
        if not profile:
            return set()
        return {b.lower() for b in profile.bssids}

    @staticmethod
    def _parse_beacon(packet) -> Dict[str, Any]:
        """Extract ssid/channel/RSN/PMF/WPA3 from a beacon or probe resp."""
        info: Dict[str, Any] = {"ssid": "", "channel": 0, "rsn": False,
                                "pmf": False, "wpa3": False}
        elt = packet.getlayer(Dot11Elt)
        while elt is not None:
            try:
                if elt.ID == 0:
                    info["ssid"] = elt.info.decode("utf-8", "ignore") or ""
                elif elt.ID == 3 and elt.info:
                    info["channel"] = int(elt.info[0])
                elif elt.ID == 48 and elt.info:
                    info["rsn"] = True
                    if b"\x00\x0f\xac\x06" in elt.info:      # BIP-CMAC-128
                        info["pmf"] = True
                    if b"\x00\x0f\xac\x08" in elt.info:      # SAE / WPA3
                        info["wpa3"] = True
            except Exception:
                pass
            elt = elt.payload.getlayer(Dot11Elt)
        return info

    @staticmethod
    def _rssi(packet) -> int:
        if packet.haslayer(RadioTap):
            try:
                dbm = packet[RadioTap].dBm_AntSignal
                if dbm is not None:
                    return int(dbm)
            except Exception:
                pass
        return -100

    # ------------------------------------------------------------------ ingest
    def ingest(self, packet) -> None:
        """Feed raw packets (called from app.py for every captured frame).

        Used for AP observation (scoring) and client tracking (targeted
        deauth). Never raises, never blocks.
        """
        if not Dot11 or not packet or not packet.haslayer(Dot11):
            return
        try:
            dot11 = packet[Dot11]
            ftype, fsub = dot11.type, dot11.subtype

            if ftype == 0 and fsub in (8, 5):            # Beacon / ProbeResp
                bssid = (dot11.addr3 or "").lower()
                if not bssid:
                    return
                info = self._parse_beacon(packet)
                obs = {
                    "ssid": info["ssid"],
                    "channel": info["channel"],
                    "rssi": self._rssi(packet),
                    "rsn": info["rsn"],
                    "pmf": info["pmf"],
                    "wpa3": info["wpa3"],
                    "ts": time.time(),
                }
                with self._lock:
                    self._ap_obs[bssid] = obs
                    target = self._targets.get(bssid)
                    if target is not None:
                        target.last_frame_ts = obs["ts"]
                        target.rssi = obs["rssi"]
                        if obs["channel"]:
                            target.channel = obs["channel"]
                return

            if ftype == 0 and fsub == 4:                 # ProbeReq
                client = (dot11.addr2 or "").lower()
                if client == BROADCAST_MAC or not client:
                    return
                info = self._parse_beacon(packet)
                with self._lock:
                    for target in self._targets.values():
                        if not info["ssid"] or info["ssid"] == target.ssid:
                            target.clients[client] = time.time()
                return

            if ftype == 0 and fsub in (0, 1):            # Assoc / Reassoc
                client = (dot11.addr2 or "").lower()
                bssid = (dot11.addr3 or "").lower()
                with self._lock:
                    target = self._targets.get(bssid)
                    if target is not None and client and client != BROADCAST_MAC:
                        target.clients[client] = time.time()
                return

            if ftype == 2:                               # Data frames
                bssid = (dot11.addr3 or "").lower()
                if not bssid:
                    return
                with self._lock:
                    target = self._targets.get(bssid)
                    if target is None:
                        return
                    target.last_frame_ts = time.time()
                    for cand in (dot11.addr2, dot11.addr1):
                        mac = (cand or "").lower()
                        if mac and mac != BROADCAST_MAC:
                            target.clients[mac] = time.time()
        except Exception:
            pass

    # --------------------------------------------------------------- scoring
    def _score_rogue(self, ssid: str, bssid: str, detector_score: int,
                     extra: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
        """Independent WIPS scoring; combined with the detector score later."""
        score = 40                                  # identity mismatch (guaranteed here)
        factors = ["WIPS: identity mismatch (same SSID, different BSSID)"]

        obs = self._ap_obs.get(bssid)
        if obs:
            if not obs["rsn"]:
                score += 20
                factors.append("WIPS: no RSN IE (encryption downgrade/open)")
            if not obs["pmf"]:
                score += 10
                factors.append("WIPS: PMF/802.11w not required")
            if obs["channel"]:
                legit_channels = self._legit_channels(ssid)
                if legit_channels and obs["channel"] not in legit_channels:
                    score += 5
                    factors.append("WIPS: channel drift")

        # signal anomaly vs legitimate AP average RSSI
        legit_avg = self._legit_avg_rssi(ssid)
        rssi = (extra or {}).get("rssi")
        if rssi is None:
            rssi = obs.get("rssi") if obs else None
        if rssi is not None and legit_avg is not None:
            if rssi >= legit_avg + self.signal_margin:
                score += 10
                factors.append("WIPS: signal anomaly (RSSI >= legit + margin)")

        # vendor OUI mismatch
        legit_ouis = self._legit_ouis(ssid)
        if legit_ouis and self._oui(bssid) not in legit_ouis:
            score += 5
            factors.append("WIPS: vendor OUI mismatch")

        score = max(detector_score, min(score, 100))
        return score, factors

    def _legit_channels(self, ssid: str) -> Set[int]:
        profile = profiler_instance.baseline.get(ssid)
        channels: Set[int] = set()
        if profile:
            for fp in profile.bssids.values():
                channels.update(fp.channels or [])
        return channels

    def _legit_avg_rssi(self, ssid: str) -> Optional[float]:
        profile = profiler_instance.baseline.get(ssid)
        best: Optional[float] = None
        if profile:
            for fp in profile.bssids.values():
                avg = fp.rssi_stats.avg_rssi if fp.rssi_stats else 0.0
                if fp.rssi_stats and fp.rssi_stats.count > 0:
                    best = avg if best is None else max(best, avg)
        return best

    def _legit_ouis(self, ssid: str) -> Set[str]:
        profile = profiler_instance.baseline.get(ssid)
        ouis: Set[str] = set()
        if profile:
            for fp in profile.bssids.values():
                vendor = (fp.oui_vendor or "").replace(":", "").upper()
                if vendor:
                    ouis.add(vendor)
        return ouis

    # --------------------------------------------------------------- threats
    def report_threat(self, ssid: str, bssid: str, score: int,
                      factors: List[str], extra: Optional[Dict[str, Any]] = None) -> None:
        """Called by the detector for every beacon of a profiled SSID."""
        try:
            bssid = (bssid or "").lower()
            ssid = str(ssid or "")
            if not bssid or not ssid:
                return

            legit = self._legit_bssids(ssid)
            if bssid in legit:
                # Legitimate AP - demote if we previously engaged it manually
                with self._lock:
                    target = self._targets.get(bssid)
                    if target is not None and not target.forced:
                        del self._targets[bssid]
                        self._emit("Rogue AP cleared (reclassified as legitimate)",
                                   f"{ssid} / {bssid}", {"ssid": ssid, "bssid": bssid})
                return

            # Candidate rogue: re-score with WIPS signals, take max
            wips_score, wips_factors = self._score_rogue(ssid, bssid, int(score), extra)
            combined_factors = list(dict.fromkeys(list(factors) + wips_factors))
            rssi = (extra or {}).get("rssi", -100)
            channel = (extra or {}).get("channel", 0)

            with self._lock:
                target = self._targets.get(bssid)
                if target is not None and not target.forced:
                    target.score = max(target.score, wips_score)
                    target.factors = combined_factors
                    target.last_frame_ts = time.time()
                    if rssi is not None and rssi > -100:
                        target.rssi = rssi
                    if channel:
                        target.channel = channel
                    return

                if wips_score >= self.threshold:
                    self._engage_locked(ssid, bssid, wips_score, combined_factors,
                                        rssi, channel, forced=False)
                else:
                    cand = self._candidates.get(bssid)
                    if cand is None:
                        cand = _ThreatTarget(ssid, bssid, wips_score, combined_factors)
                        self._candidates[bssid] = cand
                    cand.score = max(cand.score, wips_score)
                    cand.factors = combined_factors
                    cand.last_frame_ts = time.time()
        except Exception as exc:  # never crash the detector
            logger.debug("report_threat error: %s", exc)

    def trigger(self, ssid: str, bssid: str, score: int = 100) -> None:
        """Manual override / testing - force-engage a rogue AP."""
        try:
            bssid = (bssid or "").lower()
            with self._lock:
                self._engage_locked(str(ssid or "?"), bssid, int(score),
                                    ["MANUAL TRIGGER"], -100, 0, forced=True)
        except Exception as exc:
            logger.error("trigger error: %s", exc)

    def _engage_locked(self, ssid: str, bssid: str, score: int,
                       factors: List[str], rssi: int, channel: int,
                       forced: bool) -> None:
        target = self._targets.get(bssid)
        if target is None:
            target = _ThreatTarget(ssid, bssid, score, factors, forced=forced)
            self._targets[bssid] = target
            self.total_targets_engaged += 1
            self._candidates.pop(bssid, None)
            self._emit(
                "WIPS ENGAGED - deauth injection started",
                f"Rogue AP {ssid} ({bssid}) score={score}/100",
                {"ssid": ssid, "bssid": bssid, "score": score,
                 "factors": factors, "severity": "CRITICAL"})
        else:
            target.score = max(target.score, score)
            target.factors = factors
        target.rssi = rssi if rssi and rssi > -100 else target.rssi
        target.channel = channel or target.channel
        if not forced:
            target.forced = False

    # ---------------------------------------------------------------- attack
    def start(self) -> None:
        """Enable countermeasures (start the attack loop)."""
        with self._lock:
            self.enabled = True
            self._stop_event.clear()
        self._ensure_loop()

    def stop(self) -> None:
        """Disable countermeasures, join the loop, dump demo frames."""
        with self._lock:
            self.enabled = False
            self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        with self._lock:
            self._thread = None
        self._dump_demo_pcap()
        logger.info("WIPS stopped: %d deauths sent, %d planned, %d bursts, "
                    "%d targets", self.total_deauths_sent,
                    self.total_deauths_planned, self.total_bursts,
                    self.total_targets_engaged)

    def _ensure_loop(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._attack_loop,
                                            name="wips-attack-loop", daemon=True)
            self._thread.start()

    def _attack_loop(self) -> None:
        logger.info("WIPS attack loop started (iface=%s demo=%s dry_run=%s)",
                    self.iface, self.demo_mode, self.dry_run)
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                targets = list(self._targets.values())
            for target in targets:
                if not self.enabled:
                    break
                if now - target.last_frame_ts > self.holddown and not target.forced:
                    with self._lock:
                        self._targets.pop(target.bssid, None)
                    self._emit("Rogue AP cleared (no longer seen)",
                               f"{target.ssid} / {target.bssid}",
                               {"ssid": target.ssid, "bssid": target.bssid})
                    continue
                if now - target.last_burst_ts >= self.attack_interval:
                    self._burst(target)
            try:
                time.sleep(0.2)
            except KeyboardInterrupt:
                break
        logger.info("WIPS attack loop terminated")

    def _burst(self, target: _ThreatTarget) -> None:
        """Craft and send one burst: broadcast deauth, then client deauths."""
        frames: List[Any] = []
        bssid = target.bssid

        def make(addr1: str) -> Any:
            return RadioTap() / Dot11(type=0, subtype=12,
                                      addr1=addr1, addr2=bssid, addr3=bssid) \
                / Dot11Deauth(reason=self.reason)

        if self.deauth_broadcast:
            frames.append(make(BROADCAST_MAC))

        clients = []
        if self.deauth_clients:
            stale = time.time() - self.holddown
            clients = [mac for mac, ts in target.clients.items() if ts >= stale]
            clients = clients[:self.burst]
            for mac in clients:
                frames.append(make(mac))

        if not frames:
            target.last_burst_ts = time.time()
            return

        sent = planned = 0
        if self.demo_mode or self.dry_run or not sendp:
            planned = len(frames)
            with self._lock:
                self._demo_frames.extend(frames)
                if len(self._demo_frames) > 2000:
                    self._demo_frames = self._demo_frames[-2000:]
            for f in frames:
                logger.info("  [%s] would send Deauth(reason=%d) -> %s  (rogue %s)",
                            "DEMO" if self.demo_mode else "DRY-RUN",
                            self.reason, f.addr1, bssid)
        else:
            for f in frames:
                if not self._rate_ok():
                    time.sleep(0.05)
                    if not self._rate_ok():
                        break
                try:
                    sendp(f, iface=self.iface, verbose=False)
                    sent += 1
                except Exception as exc:
                    logger.error("deauth injection failed on %s: %s",
                                 self.iface, exc)
                    break

        with self._lock:
            target.deauths_sent += sent
            target.deauths_planned += planned
            target.bursts += 1
            target.last_burst_ts = time.time()
        self.total_deauths_sent += sent
        self.total_deauths_planned += planned
        self.total_bursts += 1

        self._emit(
            "WIPS deauth burst",
            f"{len(frames)} frame(s) {'sent' if sent else 'planned'} at {bssid} "
            f"(total {self.total_deauths_sent + self.total_deauths_planned})",
            {"bssid": bssid, "ssid": target.ssid, "frames": len(frames),
             "sent": sent, "planned": planned, "reason": self.reason,
             "clients": len(clients), "target_total": target.deauths_sent,
             "grand_total": self.total_deauths_sent,
             "mode": "inject" if sent else ("demo" if self.demo_mode else "dry-run")})

    def _rate_ok(self) -> bool:
        now = time.time()
        while self._rate_window and now - self._rate_window[0] >= 1.0:
            self._rate_window.popleft()
        if len(self._rate_window) < self.max_deauths_per_sec:
            self._rate_window.append(now)
            return True
        return False

    def _dump_demo_pcap(self) -> None:
        if not wrpcap or not self._demo_frames:
            return
        try:
            os.makedirs("data", exist_ok=True)
            path = os.path.join("data", "wips_demo_deauths.pcap")
            wrpcap(path, list(self._demo_frames))
            logger.info("wrote %d crafted deauth frames to %s",
                        len(self._demo_frames), path)
            self._demo_frames = []
        except Exception as exc:
            logger.debug("demo pcap dump failed: %s", exc)

    # ---------------------------------------------------------------- control
    def update_config(self, **kwargs) -> None:
        """Tune behaviour. Whitelisted keys only, values clamped."""
        with self._lock:
            if "threshold" in kwargs:
                self.threshold = max(0, min(100, int(kwargs["threshold"])))
            if "reason" in kwargs:
                self.reason = int(kwargs["reason"]) & 0xFFFF
            if "burst" in kwargs:
                self.burst = max(1, min(50, int(kwargs["burst"])))
            if "attack_interval" in kwargs:
                self.attack_interval = max(0.2, float(kwargs["attack_interval"]))
            if "holddown" in kwargs:
                self.holddown = max(5.0, float(kwargs["holddown"]))
            if "deauth_broadcast" in kwargs:
                self.deauth_broadcast = bool(kwargs["deauth_broadcast"])
            if "deauth_clients" in kwargs:
                self.deauth_clients = bool(kwargs["deauth_clients"])
            if "max_deauths_per_sec" in kwargs:
                self.max_deauths_per_sec = max(1, min(500, int(kwargs["max_deauths_per_sec"])))
            if "dry_run" in kwargs:
                self.dry_run = bool(kwargs["dry_run"])
            if "signal_margin" in kwargs:
                self.signal_margin = max(0.0, float(kwargs["signal_margin"]))

    def status(self) -> Dict[str, Any]:
        with self._lock:
            legit_aps: Dict[str, List[str]] = {}
            for ssid, profile in profiler_instance.baseline.items():
                legit_aps[ssid] = sorted(profile.bssids)

            targets = {}
            for bssid, t in self._targets.items():
                now = time.time()
                live_clients = [mac for mac, ts in t.clients.items()
                                if now - ts <= self.holddown]
                targets[bssid] = {
                    "ssid": t.ssid,
                    "score": t.score,
                    "factors": t.factors,
                    "engaged": True,
                    "forced": t.forced,
                    "rssi": t.rssi,
                    "channel": t.channel,
                    "deauths_sent": t.deauths_sent,
                    "deauths_planned": t.deauths_planned,
                    "bursts": t.bursts,
                    "clients": live_clients,
                    "client_count": len(live_clients),
                    "engaged_for": round(now - t.engaged_ts, 1),
                    "last_seen": round(now - t.last_frame_ts, 1),
                }

            candidates = {}
            for bssid, c in self._candidates.items():
                candidates[bssid] = {
                    "ssid": c.ssid,
                    "score": c.score,
                    "factors": c.factors,
                    "engaged": False,
                    "last_seen": round(time.time() - c.last_frame_ts, 1),
                }

            return {
                "enabled": self.enabled,
                "platform": "windows" if self.demo_mode else "linux",
                "demo_mode": self.demo_mode,
                "dry_run": self.dry_run,
                "iface": self.iface,
                "config": {
                    "threshold": self.threshold,
                    "reason": self.reason,
                    "burst": self.burst,
                    "attack_interval": self.attack_interval,
                    "holddown": self.holddown,
                    "deauth_broadcast": self.deauth_broadcast,
                    "deauth_clients": self.deauth_clients,
                    "max_deauths_per_sec": self.max_deauths_per_sec,
                    "signal_margin": self.signal_margin,
                },
                "totals": {
                    "deauths_sent": self.total_deauths_sent,
                    "deauths_planned": self.total_deauths_planned,
                    "bursts": self.total_bursts,
                    "targets_engaged": self.total_targets_engaged,
                },
                "targets": targets,
                "candidates": candidates,
                "legit_aps": legit_aps,
                "events": list(self._events)[-20:],
            }

    @property
    def events(self) -> Deque[Dict[str, Any]]:
        return self._events


countermeasures_instance = CountermeasuresEngine()
