"""
arp_detector.py  –  NetGuard
Monitors ARP replies and detects IP-to-MAC conflicts (ARP spoofing).
All output is served to the web GUI – nothing is printed to the terminal.
"""

import threading
import sys
import os
from datetime import datetime

arp_table   = {}
alerts      = []
arp_running = False
arp_thread  = None


def _check_arp(pkt):
    global arp_table, alerts
    try:
        from scapy.all import ARP
        from logger import log_arp_alert, log_message

        if not pkt.haslayer(ARP):
            return
        if pkt[ARP].op != 2:          # only ARP replies (op=2)
            return

        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip in arp_table:
            known_mac = arp_table[src_ip]
            if known_mac.lower() != src_mac.lower():
                alert = {
                    "time"        : datetime.now().strftime("%H:%M:%S"),
                    "ip"          : src_ip,
                    "original_mac": known_mac,
                    "fake_mac"    : src_mac,
                    "count"       : len(alerts) + 1,
                    # extra detail for the GUI
                    "detail"      : (
                        f"Device at {src_ip} suddenly changed its MAC address. "
                        f"This may indicate a man-in-the-middle attack."
                    ),
                }
                alerts.append(alert)
                log_arp_alert(src_ip, known_mac, src_mac)
        else:
            arp_table[src_ip] = src_mac
            log_message(f"Learned ARP: {src_ip} → {src_mac}", "ARP")

    except Exception:
        pass   # never print to terminal


def start_arp_detection(interface):
    global arp_running, arp_thread, arp_table, alerts
    if arp_running:
        return {"status": "already_running"}

    arp_table   = {}
    alerts      = []
    arp_running = True

    def _run():
        # Suppress Scapy terminal noise
        old_stderr = sys.stderr
        try:
            sys.stderr = open(os.devnull, "w")
        except Exception:
            pass

        from scapy.all import sniff
        from logger import log_message
        log_message(f"ARP detector started on {interface}", "INFO")
        try:
            sniff(
                iface=interface,
                prn=_check_arp,
                store=False,
                filter="arp",
                stop_filter=lambda x: not arp_running,
            )
        except Exception:
            pass   # do not print to terminal
        finally:
            try:
                sys.stderr.close()
                sys.stderr = old_stderr
            except Exception:
                pass

    arp_thread = threading.Thread(target=_run, daemon=True)
    arp_thread.start()
    return {"status": "started"}


def stop_arp_detection():
    global arp_running
    arp_running = False
    return {"status": "stopped"}

def get_arp_table():
    return dict(arp_table)

def get_alerts(since=0):
    return alerts[since:]

def get_alert_count():
    return len(alerts)

def is_running():
    return arp_running
