# AeroGuard WIDS 🛡️ (Flagship Edition)

AeroGuard is a state-of-the-art, enterprise-grade Wireless Intrusion Detection System (WIDS) and Wireless Intrusion Prevention System (WIPS). It is designed to passively monitor 802.11 wireless networks, detect advanced threats (like Evil Twins and Deauthentication Storms) using a combination of heuristic and machine-learning anomaly detection, and actively defend the network through targeted countermeasures.

Featuring a beautiful, modern, macOS-inspired UI, AeroGuard brings professional-grade wireless security out of the terminal and into a stunning dashboard.

> [!WARNING]
> **Linux & Hardware Requirement**
> AeroGuard is designed to be run on **Linux** (e.g., Kali Linux, Ubuntu, Debian). 
> You **MUST** have a WiFi adapter that supports **Monitor Mode** and **Packet Injection** (e.g., Alfa AWUS036ACM, TP-Link TL-WN722N v1).
> *Note: If run on Windows, AeroGuard operates in a restricted "Demo Mode". It will detect threats but cannot actively inject countermeasures.*

---

## 🔥 Flagship Features

*   **Advanced Threat Detection Engine:** Catches Evil Twins via BSSID spoofing, encryption downgrades (WPA3 -> WPA2/Open), PMF/802.11w stripping, and vendor OUI mismatches.
*   **Machine Learning (ML) Anomaly Detection:** Uses Scikit-Learn `IsolationForest` to profile legitimate Access Point signal strengths (RSSI) over time. Automatically flags sudden spatial shifts indicative of a spoofed AP.
*   **Deauthentication Storm Tracking:** Detects mass-deauth attacks (e.g., from a WiFi Pineapple or `aireplay-ng`), quantifies the frames, and isolates the attacker's MAC address.
*   **Targeted Client Containment (Active WIPS):** Instead of indiscriminately broadcasting deauth frames (which can cause collateral damage), AeroGuard tracks which specific clients are falling victim to the Evil Twin and surgically deauths *only those clients* to force them back to the legitimate network.
*   **Automated PCAP Capture:** Automatically dumps 60-second rolling packet captures of attack traffic to disk for forensic Wireshark analysis when a critical threat is triggered.
*   **Apple HIG Inspired UI:** A breathtaking, responsive frontend featuring a real-time radar, network telemetry charts, live threat scoring, and a seamless Dark/Light mode toggle.

---

## 🛠️ Automated Installation (Linux)

We have created an automated installation script to make deploying AeroGuard incredibly simple.

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/aeroguard-wids.git
cd aeroguard-wids
```

### 2. Run the Installer
The installer will automatically install system dependencies (`iw`, `tcpdump`), create a Python virtual environment, and install all required Python packages.

```bash
chmod +x install.sh
sudo ./install.sh
```

### 3. Enable Monitor Mode (Required)
Before starting AeroGuard, ensure your wireless interface is in monitor mode. 
Replace `wlan0` with your actual wireless interface name.

```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```
*(Alternatively, use `sudo airmon-ng start wlan0`)*

---

## 🚀 Usage

Because AeroGuard uses Scapy to sniff and inject raw 802.11 frames, the backend **must be run as root**. We have provided a `run.sh` script to simplify this.

```bash
chmod +x run.sh
sudo ./run.sh
```

Once the server is running, open your web browser and navigate to:
**http://localhost:8000**

### First-Time Workflow:
1. **Select Sensor:** Pick your monitor-mode interface from the dropdown in the sidebar.
2. **Baseline Scan:** Click "Start Baseline Scan". AeroGuard will spend 3 minutes listening to the environment, profiling your legitimate Access Points, their encryption suites, and average signal strengths.
3. **Monitor:** Once the baseline is saved, AeroGuard begins actively defending your airspace.

---

## 📸 Interface Guide

*   **Radar:** Provides a visual representation of nearby BSSIDs. Red dots indicate critical threats, amber indicates suspicious activity, and blue indicates legitimate networks.
*   **Target Inspection:** Click any row in the "Active Threats" table to open the inspection modal. Here you can view forensic details, see the list of **Compromised Clients**, and manually engage the WIPS engine.
*   **Attack Mode:** Before engaging, you can choose between **Targeted Containment** (deauth only victims) or **Full BSSID Takedown** (broadcast deauth).

---

## ⚖️ Legal Disclaimer
*AeroGuard is designed exclusively for educational purposes and authorized auditing of networks you own or have explicit permission to test. Unauthorized interception or disruption of wireless networks is illegal in most jurisdictions. The developers assume no liability for misuse.*
