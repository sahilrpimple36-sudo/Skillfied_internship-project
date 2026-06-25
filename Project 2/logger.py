import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "capture_log.txt")

def log_message(message: str, level: str = "INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass

def log_arp_alert(ip, original_mac, fake_mac):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = (
        f"\n[{timestamp}] *** ARP SPOOFING DETECTED ***\n"
        f"  IP Address   : {ip}\n"
        f"  Original MAC : {original_mac}\n"
        f"  Fake MAC     : {fake_mac}\n"
        f"{'='*50}\n"
    )
    try:
        with open(LOG_FILE, "a") as f:
            f.write(alert)
    except Exception:
        pass

def get_log_contents():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                return f.read()
    except Exception:
        pass
    return ""

def get_log_path():
    return LOG_FILE
