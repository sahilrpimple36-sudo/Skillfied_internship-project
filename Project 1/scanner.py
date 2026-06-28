import os
import hashlib
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from signatures import get_all_signatures, get_all_patterns, add_signature

BASE_DIR       = Path(__file__).parent
QUARANTINE_DIR = BASE_DIR / "quarantine"
LOGS_DIR       = BASE_DIR / "logs"
SCAN_LOG       = LOGS_DIR / "scan_history.txt"

QUARANTINE_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

_lock         = threading.Lock()
_scan_results : list[dict] = []          
_scan_running : bool       = False
_scan_progress: dict       = {
    "current_file": "",
    "scanned": 0,
    "total": 0,
    "threats": 0,
    "start_time": None,
    "end_time": None,
    "status": "idle",                    
}

def _hash_file(path: str) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None

def _scan_single_file(filepath: str) -> dict:
    path    = Path(filepath)
    result  = {
        "path"      : str(path),
        "name"      : path.name,
        "size"      : 0,
        "hash"      : None,
        "status"    : "clean",           
        "threats"   : [],
        "scan_type" : [],
        "timestamp" : datetime.now().isoformat(timespec="seconds"),
    }

    if not path.exists():
        result["status"] = "error"
        result["threats"].append("File not found")
        return result

    if not path.is_file():
        result["status"] = "skipped"
        return result

    try:
        result["size"] = path.stat().st_size
    except OSError:
        pass

    
    file_hash = _hash_file(str(path))
    result["hash"] = file_hash

    if file_hash is None:
        result["status"] = "error"
        result["threats"].append("Cannot read file (permission denied or locked)")
        return result

    sigs = get_all_signatures()
    if file_hash in sigs:
        result["status"]  = "infected"
        result["threats"].append(f"[SIGNATURE] {sigs[file_hash]}")
        result["scan_type"].append("signature")

    
    try:
        with open(str(path), "rb") as f:
            raw = f.read(1_048_576)          
        for pat in get_all_patterns():
            if pat["pattern"] in raw:
                if result["status"] == "clean":
                    result["status"] = "suspicious"
                result["threats"].append(f"[HEURISTIC] {pat['label']}")
                if "heuristic" not in result["scan_type"]:
                    result["scan_type"].append("heuristic")
    except (PermissionError, OSError):
        pass

    return result

def _collect_files(path: str) -> list[str]:
    p = Path(path)
    if p.is_file():
        return [str(p)]
    files = []
    for root, _, filenames in os.walk(str(p)):
        for fn in filenames:
            files.append(os.path.join(root, fn))
    return files

def start_scan(target_path: str) -> dict:
    global _scan_running, _scan_results, _scan_progress

    with _lock:
        if _scan_running:
            return {"error": "Scan already in progress"}

        _scan_running  = True
        _scan_results  = []
        _scan_progress = {
            "current_file": "",
            "scanned": 0,
            "total": 0,
            "threats": 0,
            "start_time": datetime.now().isoformat(timespec="seconds"),
            "end_time": None,
            "status": "running",
            "target": target_path,
        }

    threading.Thread(target=_run_scan, args=(target_path,), daemon=True).start()
    return {"started": True, "target": target_path}

def _run_scan(target_path: str):
    global _scan_running, _scan_results, _scan_progress

    try:
        files = _collect_files(target_path)
        with _lock:
            _scan_progress["total"] = len(files)

        results = []
        for fp in files:
            with _lock:
                _scan_progress["current_file"] = fp

            res = _scan_single_file(fp)
            results.append(res)

            with _lock:
                _scan_progress["scanned"] += 1
                if res["status"] in ("infected", "suspicious"):
                    _scan_progress["threats"] += 1

            time.sleep(0.05)       

        with _lock:
            _scan_results              = results
            _scan_progress["status"]   = "done"
            _scan_progress["end_time"] = datetime.now().isoformat(timespec="seconds")
            _scan_running              = False

        _write_log(target_path, results)

    except Exception as exc:
        with _lock:
            _scan_progress["status"]   = "error"
            _scan_progress["end_time"] = datetime.now().isoformat(timespec="seconds")
            _scan_running              = False
        _write_log(target_path, [], error=str(exc))

def stop_scan() -> dict:
    global _scan_running
    with _lock:
        if not _scan_running:
            return {"error": "No scan running"}
        _scan_running              = False
        _scan_progress["status"]   = "stopped"
        _scan_progress["end_time"] = datetime.now().isoformat(timespec="seconds")
    return {"stopped": True}

def get_progress() -> dict:
    with _lock:
        return dict(_scan_progress)

def get_results(since: int = 0) -> list[dict]:
    with _lock:
        return _scan_results[since:]

def is_running() -> bool:
    with _lock:
        return _scan_running

def get_threat_count() -> int:
    with _lock:
        return _scan_progress.get("threats", 0)

def quarantine_file(filepath: str) -> dict:
    src = Path(filepath)
    if not src.exists():
        return {"error": f"File not found: {filepath}"}
    try:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = QUARANTINE_DIR / f"{ts}_{src.name}"
        shutil.move(str(src), str(dest))
        _log_quarantine(str(src), str(dest))
        return {"quarantined": True, "original": str(src), "quarantine_path": str(dest)}
    except Exception as e:
        return {"error": str(e)}

def get_quarantine_list() -> list[dict]:
    items = []
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file():
            items.append({
                "name"     : f.name,
                "path"     : str(f),
                "size"     : f.stat().st_size,
                "modified" : datetime.fromtimestamp(f.stat().st_mtime).isoformat(timespec="seconds"),
            })
    return sorted(items, key=lambda x: x["modified"], reverse=True)

def restore_file(quarantine_name: str, restore_path: str) -> dict:
    src = QUARANTINE_DIR / quarantine_name
    if not src.exists():
        return {"error": "Quarantined file not found"}
    try:
        dest = Path(restore_path) / quarantine_name
        shutil.move(str(src), str(dest))
        return {"restored": True, "path": str(dest)}
    except Exception as e:
        return {"error": str(e)}

def delete_quarantined(quarantine_name: str) -> dict:
    f = QUARANTINE_DIR / quarantine_name
    if not f.exists():
        return {"error": "File not found"}
    f.unlink()
    return {"deleted": True}

def add_custom_signature(sha256: str, label: str) -> dict:
    ok = add_signature(sha256, label)
    if ok:
        return {"added": True, "hash": sha256, "label": label}
    return {"error": "Invalid SHA-256 hash (must be 64 hex chars)"}

def _write_log(target: str, results: list[dict], error: str = ""):
    try:
        with open(SCAN_LOG, "a", encoding="utf-8") as f:
            f.write("\n" + "="*70 + "\n")
            f.write(f"Scan Target : {target}\n")
            f.write(f"Date/Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Files Scanned: {len(results)}\n")
            threats = [r for r in results if r['status'] in ('infected','suspicious')]
            f.write(f"Threats Found: {len(threats)}\n")
            if error:
                f.write(f"ERROR: {error}\n")
            f.write("-"*70 + "\n")
            for r in results:
                if r['status'] in ('infected','suspicious'):
                    f.write(f"  [{r['status'].upper()}] {r['path']}\n")
                    for t in r['threats']:
                        f.write(f"      {t}\n")
            f.write("="*70 + "\n")
    except Exception:
        pass

def _log_quarantine(original: str, dest: str):
    try:
        with open(SCAN_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n[QUARANTINE] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Original  : {original}\n")
            f.write(f"  Moved to  : {dest}\n")
    except Exception:
        pass

def get_log_contents() -> str:
    if SCAN_LOG.exists():
        return SCAN_LOG.read_text(encoding="utf-8", errors="replace")
    return "No scan log yet."

def get_log_path() -> str:
    return str(SCAN_LOG)
