"""
packet_sniffer.py  –  NetGuard
All captured data is stored in memory and served to the web GUI.
Nothing is printed to the terminal.

FIX: Rolling window — never drops below MAX_DISPLAY packets visible to UI,
     keeps full session in captured_packets for pcap export, no hard stop.
"""

import threading
import os
import sys
from datetime import datetime

captured_packets = []
packet_log       = []          # list of dicts for the web UI  (rolling, unbounded for session)
sniffer_running  = False
sniffer_thread   = None

MAX_DISPLAY = 5000             # UI keeps last 5000 rows — was 2000 with a pop(0) bug

CAPTURE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "captures", "session.pcap"
)


def _process_packet(pkt):
    global captured_packets, packet_log
    try:
        from scapy.all import IP, TCP, UDP, ARP
        from utils import get_protocol_name

        proto = get_protocol_name(pkt)
        size  = len(pkt)

        src  = "N/A"
        dst  = "N/A"
        info = ""

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst

        if pkt.haslayer(ARP):
            src  = pkt[ARP].psrc
            dst  = pkt[ARP].pdst
            op   = pkt[ARP].op
            info = f"ARP {'Request' if op == 1 else 'Reply'} | {pkt[ARP].hwsrc}"
        elif pkt.haslayer(TCP):
            info = f"Port {pkt[TCP].sport} → {pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            info = f"Port {pkt[UDP].sport} → {pkt[UDP].dport}"

        entry = {
            "time"    : datetime.now().strftime("%H:%M:%S"),
            "src"     : src,
            "dst"     : dst,
            "protocol": proto,
            "size"    : size,
            "info"    : info,
        }

        captured_packets.append(pkt)
        packet_log.append(entry)

        # Rolling window: trim only when significantly over limit
        # (bulk-trim to avoid per-packet overhead)
        if len(packet_log) > MAX_DISPLAY + 500:
            del packet_log[:500]

    except Exception:
        pass


def start_sniffing(interface, filter_str=""):
    global sniffer_running, sniffer_thread, captured_packets, packet_log
    if sniffer_running:
        return {"status": "already_running"}

    captured_packets = []
    packet_log       = []
    sniffer_running  = True

    def _run():
        old_stderr = sys.stderr
        try:
            sys.stderr = open(os.devnull, "w")
        except Exception:
            pass

        from scapy.all import sniff
        try:
            sniff(
                iface=interface,
                prn=_process_packet,
                store=False,
                stop_filter=lambda x: not sniffer_running,
                filter=filter_str if filter_str else None,
            )
        except Exception:
            pass
        finally:
            try:
                sys.stderr.close()
                sys.stderr = old_stderr
            except Exception:
                pass

    sniffer_thread = threading.Thread(target=_run, daemon=True)
    sniffer_thread.start()
    return {"status": "started"}


def stop_sniffing():
    global sniffer_running
    sniffer_running = False
    if captured_packets:
        try:
            from scapy.all import wrpcap
            os.makedirs(os.path.dirname(CAPTURE_FILE), exist_ok=True)
            wrpcap(CAPTURE_FILE, captured_packets)
        except Exception:
            pass
    return {"status": "stopped", "packets": len(packet_log)}


def get_packets(since=0):
    return packet_log[since:]

def is_running():
    return sniffer_running

def get_packet_count():
    return len(packet_log)

def get_capture_path():
    return CAPTURE_FILE
