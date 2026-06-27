import os
import sys
import logging
import webbrowser
import threading
os.environ['SCAPY_IFACE_CONF'] = '0'
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy.loading').setLevel(logging.ERROR)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
log.disabled = True
import flask.cli
flask.cli.show_server_banner = lambda *args, **kwargs: None
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, jsonify, request, send_from_directory
import packet_sniffer as sniffer
import arp_detector as arp
from utils import get_interfaces, get_local_ip
from logger import get_log_contents, get_log_path
app = Flask(__name__, static_folder='static')
app.logger.disabled = True

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(get_interfaces())

@app.route('/api/localip')
def api_localip():
    return jsonify({'ip': get_local_ip()})

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json() or {}
    interface = data.get('interface', '')
    flt = data.get('filter', '')
    if not interface:
        return (jsonify({'error': 'No interface provided'}), 400)
    r1 = sniffer.start_sniffing(interface, filter_str=flt)
    r2 = arp.start_arp_detection(interface)
    return jsonify({'sniffer': r1, 'arp': r2})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    r1 = sniffer.stop_sniffing()
    r2 = arp.stop_arp_detection()
    return jsonify({'sniffer': r1, 'arp': r2})

@app.route('/api/status')
def api_status():
    return jsonify({'running': sniffer.is_running(), 'packet_count': sniffer.get_packet_count(), 'alert_count': arp.get_alert_count(), 'arp_packet_count': arp.get_arp_packet_count()})

@app.route('/api/packets')
def api_packets():
    since = int(request.args.get('since', 0))
    return jsonify(sniffer.get_packets(since))

@app.route('/api/alerts')
def api_alerts():
    since = int(request.args.get('since', 0))
    return jsonify(arp.get_alerts(since))

@app.route('/api/arptable')
def api_arptable():
    return jsonify(arp.get_arp_table())

@app.route('/api/log')
def api_log():
    return jsonify({'log': get_log_contents()})

@app.route('/api/openpcap', methods=['POST'])
def api_openpcap():
    path = sniffer.get_capture_path()
    if os.path.exists(path):
        try:
            os.startfile(path)
        except AttributeError:
            import subprocess
            subprocess.Popen(['xdg-open', path])
        return jsonify({'status': 'opened'})
    return (jsonify({'error': 'No capture file yet'}), 404)

@app.route('/api/openlog', methods=['POST'])
def api_openlog():
    path = get_log_path()
    if os.path.exists(path):
        try:
            os.startfile(path)
        except AttributeError:
            import subprocess
            subprocess.Popen(['xdg-open', path])
        return jsonify({'status': 'opened'})
    return (jsonify({'error': 'No log file yet'}), 404)

def open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open('http://localhost:5000')
if __name__ == '__main__':
    print('\n' + '=' * 55)
    print('  NetGuard — Packet Sniffer + ARP Spoofing Detector')
    print('=' * 55)
    print('  Open in browser: http://localhost:5000')
    print('  Press Ctrl+C to stop.')
    print('=' * 55 + '\n')
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)