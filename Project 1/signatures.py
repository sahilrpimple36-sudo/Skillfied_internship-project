"""
signatures.py — Known Malware Signature Database
Stores SHA-256 hashes that represent 'known malware' for simulation purposes.
In a real AV engine these would be regularly updated from threat-intel feeds.
"""

# Format: { "sha256_hash": "Malware Name / Threat Label" }
MALWARE_SIGNATURES: dict[str, str] = {
    # ── Simulated / demo signatures (pre-seeded so the scanner has something to find) ──
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File (AV Test Signature)",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-MD5 (legacy)",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EmptyFile.Suspicious (zero-byte executable)",
    "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344": "Trojan.FakeUpdate.Gen",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": "Worm.DeadBeef.Sim",
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe00": "Ransomware.CafeBabe.Sim",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": "Spyware.KeyLogger.Sim",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00": "Rootkit.AllFF.Sim",
}

# String patterns that may indicate malicious intent (heuristic scan)
SUSPICIOUS_PATTERNS: list[dict] = [
    {"pattern": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "label": "EICAR Test String"},
    {"pattern": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "label": "EICAR Signature Bytes"},
    {"pattern": b"CreateRemoteThread",                  "label": "Heuristic.RemoteThread (code injection)"},
    {"pattern": b"VirtualAllocEx",                      "label": "Heuristic.VirtualAlloc (shellcode loader)"},
    {"pattern": b"WScript.Shell",                       "label": "Heuristic.WScriptShell (script dropper)"},
    {"pattern": b"cmd.exe /c",                          "label": "Heuristic.CmdExec (command execution)"},
    {"pattern": b"powershell -enc",                     "label": "Heuristic.PowerShellEncoded (obfuscated PS)"},
    {"pattern": b"net user /add",                       "label": "Heuristic.AddUser (privilege escalation)"},
    {"pattern": b"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                                        "label": "Heuristic.Persistence (registry run key)"},
    {"pattern": b"socket.connect",                      "label": "Heuristic.NetworkConnect (C2 callback)"},
]


def get_all_signatures() -> dict[str, str]:
    return MALWARE_SIGNATURES.copy()


def get_all_patterns() -> list[dict]:
    return SUSPICIOUS_PATTERNS.copy()


def add_signature(sha256: str, label: str) -> bool:
    """Add a custom signature at runtime."""
    sha256 = sha256.strip().lower()
    if len(sha256) != 64:
        return False
    MALWARE_SIGNATURES[sha256] = label
    return True
