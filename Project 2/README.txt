╔══════════════════════════════════════════════════════════════╗
║         NetGuard — Packet Sniffer + ARP Spoofing Detector   ║
║                         v2.0                                 ║
╚══════════════════════════════════════════════════════════════╝

FILES IN THIS FOLDER
─────────────────────────────────────────────────────────────────
  server.py             → Main Flask web server (run this first)
  arp_detector.py       → ARP spoofing detection engine
  packet_sniffer.py     → Live packet capture engine
  utils.py              → Interface helpers + protocol names
  logger.py             → File logging
  arp_spoof_tester.py   → Windows ARP spoof test tool (see below)
  static/index.html     → Web GUI (auto-served by server.py)
  logs/                 → Log files saved here
  captures/             → .pcap files saved here


REQUIREMENTS
─────────────────────────────────────────────────────────────────
  pip install flask scapy


HOW TO RUN NETGUARD
─────────────────────────────────────────────────────────────────
  1. Open CMD as Administrator
  2. cd into this folder
  3. Run:  python server.py
  4. Browser opens at http://localhost:5000 automatically
  5. Choose your network interface → click Start


HOW TO TEST ARP SPOOFING (Windows → Windows)
─────────────────────────────────────────────────────────────────
  1. Start NetGuard first (python server.py)
  2. Open a SECOND CMD as Administrator
  3. Run:  python arp_spoof_tester.py
  4. Follow the on-screen menu
  5. Watch ARP Alerts tab in the NetGuard GUI fire!

  Test Modes available:
    [1] Quick Test       - Safest, uses fake IPs. No real devices touched.
    [2] Scan & Spoof     - Scans LAN, spoofs a real device once
    [3] Continuous Spoof - Keeps sending every 2 seconds
    [4] Custom Values    - Enter your own IP/MAC values


ETHICAL NOTICE
─────────────────────────────────────────────────────────────────
  Run only on networks you own or have explicit permission to test.
  The ARP spoof tester is for educational/lab use only.
  Always obtain permission before scanning or sniffing networks.
