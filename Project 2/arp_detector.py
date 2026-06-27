"""
arp_detector.py  –  NetGuard
Real-time ARP spoofing detection.

FIXES vs original:
1. Detects BOTH op=1 (requests) AND op=2 (replies)
   — Kali tools (arpspoof, ettercap, bettercap) send gratuitous requests too.
2. ARP table is pre-seeded from the OS ARP cache at startup so the
   very first spoofed packet is caught, not learned as "real".
3. Conflict threshold: flags even the first conflicting packet (no grace count).
4. Tracks total ARP packet count and spoof attempt count separately.
5. Alert deduplication with 3-second cooldown per IP so one spoof storm
   doesn't flood the alert list with identical entries.
"""

import threading
import subprocess
import sys
import os
import re
import time
from datetime import datetime

_lock       = threading.Lock()
arp_table   = {}      # { ip: mac }  — learned from OS + live traffic
alerts      = []      # list of alert dicts shown in the UI
arp_running = False
arp_thread  = None

arp_packet_count = 0
_last_alert_time = {}   # { ip: timestamp }  — cooldown per IP


# ── Seed ARP table from the OS ────────────────────────────────────────────────
def _seed_from_os():
    """
    Read the OS ARP cache before sniffing starts.
    This means the very first spoofed packet triggers an alert instead of being
    silently learned as the legitimate MAC.
    """
    try:
        result = subprocess.check_output(
            ["arp", "-a"], stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        # Windows:  hostname (192.168.1.1)  at  aa-bb-cc-dd-ee-ff
        # Linux:    hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether]
        for line in result.splitlines():
            # Extract first IP and MAC on the line
            ip_match  = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            mac_match = re.search(r'([0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}'
                                   r'[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2})',
                                   line, re.IGNORECASE)
            if ip_match and mac_match:
                ip  = ip_match.group(1)
                mac = mac_match.group(1).lower().replace("-", ":")
                arp_table[ip] = mac
    except Exception:
        pass   # silently continue — seeding is best-effort


# ── Per-packet handler ─────────────────────────────────────────────────────────
def _check_arp(pkt):
    global arp_packet_count

    try:
        from scapy.all import ARP
        from logger import log_arp_alert, log_message

        if not pkt.haslayer(ARP):
            return

        arp_layer = pkt[ARP]
        op        = arp_layer.op          # 1 = request, 2 = reply
        src_ip    = arp_layer.psrc
        src_mac   = arp_layer.hwsrc.lower()

        # Ignore broadcast/zero MACs — not real hosts
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return
        # Ignore 0.0.0.0 source (DHCP probes)
        if src_ip == "0.0.0.0":
            return

        with _lock:
            arp_packet_count += 1

            if src_ip in arp_table:
                known_mac = arp_table[src_ip]

                if known_mac != src_mac:
                    # ── CONFLICT DETECTED ──────────────────────────────────
                    now = time.time()
                    last = _last_alert_time.get(src_ip, 0)

                    if now - last >= 3:          # 3-second cooldown per IP
                        _last_alert_time[src_ip] = now

                        op_name = "Request" if op == 1 else "Reply"
                        alert = {
                            "time"        : datetime.now().strftime("%H:%M:%S"),
                            "ip"          : src_ip,
                            "original_mac": known_mac,
                            "fake_mac"    : src_mac,
                            "count"       : len(alerts) + 1,
                            "op"          : op_name,
                            "detail"      : (
                                f"ARP {op_name}: {src_ip} claims MAC {src_mac} "
                                f"but was previously seen as {known_mac}. "
                                f"Possible MITM / ARP Poisoning attack from Kali or another host."
                            ),
                        }
                        alerts.append(alert)
                        log_arp_alert(src_ip, known_mac, src_mac)

                    # Don't update the table — keep the original (first-seen) MAC
                    # so every subsequent spoof packet still triggers an alert

            else:
                # New IP — learn it
                arp_table[src_ip] = src_mac
                log_message(f"Learned ARP: {src_ip} → {src_mac} (op={op})", "ARP")

    except Exception:
        pass


# ── Start / Stop ──────────────────────────────────────────────────────────────
def start_arp_detection(interface):
    global arp_running, arp_thread, arp_table, alerts, arp_packet_count, _last_alert_time

    if arp_running:
        return {"status": "already_running"}

    # Reset state
    arp_table        = {}
    alerts           = []
    arp_packet_count = 0
    _last_alert_time = {}
    arp_running      = True

    # Seed from OS cache BEFORE sniffing starts
    _seed_from_os()

    def _run():
        old_stderr = sys.stderr
        try:
            sys.stderr = open(os.devnull, "w")
        except Exception:
            pass

        from scapy.all import sniff
        from logger import log_message
        log_message(f"ARP detector started on {interface} "
                    f"(seeded {len(arp_table)} entries from OS cache)", "INFO")
        try:
            sniff(
                iface=interface,
                prn=_check_arp,
                store=False,
                filter="arp",                          # BPF filter — only ARP frames
                stop_filter=lambda x: not arp_running,
            )
        except Exception:
            pass
        finally:
            try:
                sys.stderr.close()
                sys.stderr = old_stderr
            except Exception:
                pass

    arp_thread = threading.Thread(target=_run, daemon=True)
    arp_thread.start()
    return {"status": "started", "seeded": len(arp_table)}


def stop_arp_detection():
    global arp_running
    arp_running = False
    return {"status": "stopped"}


# ── Getters ───────────────────────────────────────────────────────────────────
def get_arp_table():
    with _lock:
        return dict(arp_table)

def get_alerts(since=0):
    with _lock:
        return alerts[since:]

def get_alert_count():
    with _lock:
        return len(alerts)

def get_arp_packet_count():
    with _lock:
        return arp_packet_count

def is_running():
    return arp_running
