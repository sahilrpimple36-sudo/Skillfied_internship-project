import os
import sys
import logging
import webbrowser
import threading

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
log.disabled = True

import flask.cli
flask.cli.show_server_banner = lambda *a, **kw: None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, send_from_directory
import scanner

app = Flask(__name__, static_folder="static")
app.logger.disabled = True

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data = request.get_json() or {}
    target = data.get("path", "").strip()
    if not target:
        return jsonify({"error": "No path provided"}), 400
    if not os.path.exists(target):
        return jsonify({"error": f"Path does not exist: {target}"}), 400
    result = scanner.start_scan(target)
    return jsonify(result)

@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    return jsonify(scanner.stop_scan())

@app.route("/api/scan/progress")
def api_scan_progress():
    return jsonify(scanner.get_progress())

@app.route("/api/scan/results")
def api_scan_results():
    since = int(request.args.get("since", 0))
    return jsonify(scanner.get_results(since))

@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({
        "running"      : scanner.is_running(),
        "threat_count" : scanner.get_threat_count(),
    })

@app.route("/api/scan/file", methods=["POST"])
def api_scan_file():
    data = request.get_json() or {}
    target = data.get("path", "").strip()
    if not target or not os.path.isfile(target):
        return jsonify({"error": "Invalid file path"}), 400
    
    from scanner import _scan_single_file
    return jsonify(_scan_single_file(target))

@app.route("/api/quarantine/list")
def api_quarantine_list():
    return jsonify(scanner.get_quarantine_list())

@app.route("/api/quarantine/move", methods=["POST"])
def api_quarantine_move():
    data = request.get_json() or {}
    path = data.get("path", "").strip()
    if not path:
        return jsonify({"error": "No path provided"}), 400
    return jsonify(scanner.quarantine_file(path))

@app.route("/api/quarantine/delete", methods=["POST"])
def api_quarantine_delete():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    return jsonify(scanner.delete_quarantined(name))

@app.route("/api/quarantine/restore", methods=["POST"])
def api_quarantine_restore():
    data      = request.get_json() or {}
    name      = data.get("name", "").strip()
    dest_path = data.get("restore_path", "").strip()
    return jsonify(scanner.restore_file(name, dest_path))

@app.route("/api/signatures/list")
def api_signatures_list():
    from signatures import get_all_signatures, get_all_patterns
    return jsonify({
        "signatures": [{"hash": k, "label": v} for k, v in get_all_signatures().items()],
        "patterns"  : [{"pattern": p["pattern"].decode("utf-8", errors="replace"),
                        "label": p["label"]} for p in get_all_patterns()],
    })

@app.route("/api/signatures/add", methods=["POST"])
def api_signatures_add():
    data  = request.get_json() or {}
    sha   = data.get("hash", "").strip().lower()
    label = data.get("label", "Custom Signature").strip()
    return jsonify(scanner.add_custom_signature(sha, label))

@app.route("/api/log")
def api_log():
    return jsonify({"log": scanner.get_log_contents()})

@app.route("/api/log/open", methods=["POST"])
def api_log_open():
    path = scanner.get_log_path()
    if os.path.exists(path):
        try:
            os.startfile(path)
        except AttributeError:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        return jsonify({"status": "opened"})
    return jsonify({"error": "No log file yet"}), 404

@app.route("/api/demo/create", methods=["POST"])
def api_demo_create():
    import hashlib
    targets_dir = os.path.join(os.path.dirname(__file__), "scan_targets")
    os.makedirs(targets_dir, exist_ok=True)

    created = []

    
    eicar_path = os.path.join(targets_dir, "eicar_test.txt")
    with open(eicar_path, "wb") as f:
        f.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    created.append(eicar_path)

    
    clean_path = os.path.join(targets_dir, "readme_clean.txt")
    with open(clean_path, "w") as f:
        f.write("This is a clean file. No threats here.\nHello World!\n")
    created.append(clean_path)

    
    sus_path = os.path.join(targets_dir, "suspicious_script.bat")
    with open(sus_path, "wb") as f:
        f.write(b"@echo off\ncmd.exe /c net user /add hacker Password123\n")
    created.append(sus_path)

    
    known_hash_path = os.path.join(targets_dir, "fake_malware.bin")
    
    
    content = b"SIMULATED_MALWARE_PAYLOAD_DEADBEEF" * 100
    h = hashlib.sha256(content).hexdigest()
    
    from signatures import MALWARE_SIGNATURES
    MALWARE_SIGNATURES[h] = "Trojan.SimPayload.Demo"
    with open(known_hash_path, "wb") as f:
        f.write(content)
    created.append(known_hash_path)

    return jsonify({
        "created": created,
        "scan_path": targets_dir,
        "message": f"Created {len(created)} demo files in scan_targets/"
    })

def _open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open("http://localhost:5000")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  BasicAV — Basic Antivirus Simulation (Signature Scanner)")
    print("="*60)
    print("  Open in browser : http://localhost:5000")
    print("  Press Ctrl+C    : to stop the server")
    print("="*60 + "\n")

    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )
