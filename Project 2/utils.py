import socket
import re

def _friendly_name(raw_name, ip):
    n = raw_name.lower()
    if n in ('lo', 'loopback', 'loop'):
        return f'Loopback – testing only ({ip})'
    if any((x in n for x in ('wlan', 'wifi', 'wi-fi', 'wireless', 'wlp', 'wl'))):
        return f'Wi-Fi / Wireless  [{raw_name}]  ({ip})'
    if any((x in n for x in ('eth', 'ethernet', 'en0', 'en1', 'enp', 'local area'))):
        return f'Wired Network (Ethernet)  [{raw_name}]  ({ip})'
    if any((x in n for x in ('vmnet', 'vbox', 'veth', 'virbr'))):
        return f'Virtual Machine Network  [{raw_name}]  ({ip})'
    if 'docker' in n:
        return f'Docker / Container Network  [{raw_name}]  ({ip})'
    if any((x in n for x in ('tun', 'tap', 'vpn', 'ppp'))):
        return f'VPN / Tunnel Adapter  [{raw_name}]  ({ip})'
    if any((x in n for x in ('br', 'bridge'))):
        return f'Network Bridge  [{raw_name}]  ({ip})'
    if any((x in n for x in ('bond', 'team', 'lagg'))):
        return f'Bonded / Aggregated Link  [{raw_name}]  ({ip})'
    if 'local area connection' in n:
        return f'Wired Network (Ethernet)  [{raw_name}]  ({ip})'
    if 'wireless' in n or 'wi-fi' in n:
        return f'Wi-Fi / Wireless  [{raw_name}]  ({ip})'
    return f'Network Adapter  [{raw_name}]  ({ip})'

def get_interfaces():
    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
            except Exception:
                ip = 'N/A'
            interfaces.append({'name': iface, 'ip': ip, 'label': _friendly_name(iface, ip)})
        return interfaces
    except Exception as e:
        return [{'name': 'Error', 'ip': str(e), 'label': 'Error loading interfaces'}]

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_protocol_name(packet):
    try:
        from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
        if packet.haslayer(ARP):
            return 'ARP'
        if packet.haslayer(ICMP):
            return 'ICMP'
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if 80 in (sport, dport):
                return 'HTTP'
            if 443 in (sport, dport):
                return 'HTTPS'
            if 22 in (sport, dport):
                return 'SSH'
            if 21 in (sport, dport):
                return 'FTP'
            if 53 in (sport, dport):
                return 'DNS'
            return 'TCP'
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if 53 in (sport, dport):
                return 'DNS'
            return 'UDP'
        if packet.haslayer(IP):
            return 'IP'
        return 'OTHER'
    except Exception:
        return 'UNKNOWN'