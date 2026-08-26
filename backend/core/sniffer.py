import threading
import queue
import time
import subprocess
from typing import Optional
from backend.utils.logger import get_logger

try:
    from scapy.all import sniff, Dot11
except ImportError:
    Dot11 = None
    sniff = None

logger = get_logger(__name__)

class PacketSniffer:
    def __init__(self, interface: str = "wlan0mon"):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.sniff_thread: Optional[threading.Thread] = None
        self.hopper_thread: Optional[threading.Thread] = None
        self.total_packets_scanned = 0
        self.channels = [1, 6, 11] + list(range(2, 11)) # 2.4GHz channels
        self.current_channel_index = 0
        self.hop_interval = 0.5 # seconds
        self.mgmt_count = 0
        self.ctrl_count = 0
        self.data_count = 0
        self.deauth_count = 0
        self.total_bytes = 0

    def _hop_channels(self):
        logger.info(f"Starting channel hopper on {self.interface}")
        while not self.stop_event.is_set():
            try:
                ch = self.channels[self.current_channel_index]
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(ch)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self.current_channel_index = (self.current_channel_index + 1) % len(self.channels)
            except Exception as e:
                logger.debug(f"Hopper error: {e}")
            time.sleep(self.hop_interval)

    def _sniff_loop(self):
        if not sniff:
            logger.error("Scapy is not installed. Sniffer cannot start.")
            return

        logger.info(f"Starting Scapy sniffer on interface {self.interface}")
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=False
            )
        except Exception as e:
            logger.error(f"Sniffer error on {self.interface}: {e}")
        logger.info("Sniffer loop terminated.")

    def _packet_handler(self, packet):
        self.total_packets_scanned += 1
        self.total_bytes += len(packet)
        if packet.haslayer(Dot11):
            if packet.type == 0:
                self.mgmt_count += 1
                if packet.subtype in (10, 12):
                    self.deauth_count += 1
            elif packet.type == 1:
                self.ctrl_count += 1
            elif packet.type == 2:
                self.data_count += 1
            
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                logger.warning("Packet queue is full, dropping packet")

    def start(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            logger.warning("Sniffer is already running")
            return
        
        self.stop_event.clear()
        self.total_packets_scanned = 0
        self.mgmt_count = 0
        self.ctrl_count = 0
        self.data_count = 0
        self.deauth_count = 0
        self.total_bytes = 0
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        
        self.hopper_thread = threading.Thread(target=self._hop_channels, daemon=True)
        self.hopper_thread.start()

    def stop(self):
        logger.info("Stopping sniffer...")
        self.stop_event.set()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2.0)
        if self.hopper_thread:
            self.hopper_thread.join(timeout=1.0)

    def is_active(self) -> bool:
        return self.sniff_thread is not None and self.sniff_thread.is_alive()

sniffer_instance = PacketSniffer()
