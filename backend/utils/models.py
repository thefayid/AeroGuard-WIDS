from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class AccessPoint(BaseModel):
    bssid: str
    ssid: str
    channel: int
    rssi: int
    encryption: str
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class BeaconMetadata(BaseModel):
    bssid: str
    oui_vendor: Optional[str]
    is_hidden: bool
    capabilities: str

class DeauthAlert(BaseModel):
    target_mac: str
    source_mac: str
    reason_code: int
    count: int
    sensor_id: str = "local"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ThreatScoreEvent(BaseModel):
    bssid: str
    score: float
    factors: List[str]
    sensor_id: str = "local"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class InterfaceStatus(BaseModel):
    interface: str
    mode: str
    channel: int
    is_active: bool

class InterfaceInfo(BaseModel):
    name: str
    phy: Optional[str] = None
    mode: Optional[str] = None
    mac: Optional[str] = None

class RSSIBaseline(BaseModel):
    min_rssi: int = 0
    max_rssi: int = -100
    avg_rssi: float = 0.0
    count: int = 0

class BSSIDFingerprint(BaseModel):
    bssid: str
    oui_vendor: str = "Unknown"
    channels: List[int] = Field(default_factory=list)
    cipher_suites: List[str] = Field(default_factory=list)
    rssi_stats: RSSIBaseline = Field(default_factory=RSSIBaseline)
    historical_rssi: List[int] = Field(default_factory=list) # For ML training
    beacon_interval: int = 100
    jitter_tolerance: float = 0.0

class SSIDProfile(BaseModel):
    ssid: str
    bssids: Dict[str, BSSIDFingerprint] = Field(default_factory=dict)

class SettingsModel(BaseModel):
    deauth_threshold: int = 10
    rssi_variance_tolerance: int = 15
    critical_cutoff: int = 70
