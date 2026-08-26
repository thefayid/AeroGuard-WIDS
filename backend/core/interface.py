import subprocess
import re
from typing import List, Dict, Any, Optional
from backend.utils.logger import get_logger

logger = get_logger(__name__)

def run_command(cmd: List[str], timeout: int = 5) -> tuple[int, str, str]:
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", "timeout"
        return process.returncode, stdout, stderr
    except Exception as e:
        logger.error(f"Failed to execute command {' '.join(cmd)}: {e}")
        return -1, "", str(e)



def list_interfaces() -> List[Dict[str, Any]]:
    code, stdout, stderr = run_command(["iw", "dev"])
    interfaces = []
    if code != 0:
        logger.warning(f"iw dev command failed (expected if not on Linux or iw is missing): {stderr}")
        # In a real environment, this might be a mock or empty if not supported
        return interfaces
        
    current_phy = None
    current_iface = None
    
    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith("phy#"):
            current_phy = line.replace("phy#", "")
        elif line.startswith("Interface"):
            if current_iface:
                interfaces.append(current_iface)
            current_iface = {"phy": current_phy, "name": line.split()[1]}
        elif line.startswith("type"):
            if current_iface is not None:
                current_iface["mode"] = line.split()[1]
        elif line.startswith("addr"):
            if current_iface is not None:
                current_iface["mac"] = line.split()[1]
                
    if current_iface:
        interfaces.append(current_iface)
        
    return interfaces

def enable_monitor_mode(interface: str) -> Optional[str]:
    logger.info("Killing interfering processes (NetworkManager, wpa_supplicant)...")
    run_command(["airmon-ng", "check", "kill"])
    
    logger.info(f"Enabling monitor mode on {interface}...")
    code, stdout, stderr = run_command(["airmon-ng", "start", interface])
    if code != 0:
        logger.error(f"Failed to enable monitor mode via airmon-ng: {stderr}")
        # Fallback to iw approach
        run_command(["ip", "link", "set", interface, "down"])
        code_iw, stdout_iw, stderr_iw = run_command(["iw", "dev", interface, "set", "type", "monitor"])
        run_command(["ip", "link", "set", interface, "up"])
        
        if code_iw != 0:
            logger.error(f"Failed to enable monitor mode via iw: {stderr_iw}")
            return None
        return interface

    # Attempt to parse the new interface name created by airmon-ng (e.g., wlan0mon)
    match = re.search(r'monitor mode vif enabled for \[phy\d+\]\S+ on \[phy\d+\](\S+)', stdout)
    if match:
         return match.group(1)
         
    # Fallback to check if a 'mon' suffixed interface was created
    ifaces = list_interfaces()
    for iface in ifaces:
        if iface.get("name") == f"{interface}mon":
            return f"{interface}mon"
            
    return interface

def disable_monitor_mode(interface: str) -> bool:
    logger.info(f"Disabling monitor mode on {interface}...")
    code, stdout, stderr = run_command(["airmon-ng", "stop", interface])
    if code != 0:
        logger.warning(f"airmon-ng stop failed, trying iw manual fallback: {stderr}")
        run_command(["ip", "link", "set", interface, "down"])
        run_command(["iw", "dev", interface, "set", "type", "managed"])
        run_command(["ip", "link", "set", interface, "up"])
    
    logger.info("Restarting network services to restore connectivity...")
    run_command(["systemctl", "start", "NetworkManager"])
    run_command(["systemctl", "start", "wpa_supplicant"])
    
    return True
