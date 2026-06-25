================================================================
  BasicAV — Basic Antivirus Simulation (Signature Scanner)
  By: Tanishka Ganesh Mahadik | Skillfied Mentor Internship
================================================================

PROJECT OVERVIEW
----------------
BasicAV is a Python-based antivirus simulation that demonstrates
how real antivirus engines detect malware using:

  1. SIGNATURE SCANNING   — SHA-256 file hashes compared against
                            a known malware database
  2. HEURISTIC SCANNING   — Byte-pattern search inside files for
                            suspicious strings (cmd.exe /c, PowerShell
                            encoding, WScript.Shell, registry persistence, etc.)
  3. QUARANTINE           — Detected files can be isolated into a
                            sandboxed quarantine folder
  4. CUSTOM SIGNATURES    — Add your own SHA-256 hash + label via the UI

⚠️  NOTE: This tool is for EDUCATIONAL and ETHICAL use only.
    It will NOT detect real-world malware unless real signatures
    are added. It demonstrates the concepts used by real AV systems.

----------------------------------------------------------------
FILES & FOLDERS
----------------------------------------------------------------
  server.py          Flask web server (main entry point)
  scanner.py         Core scan engine (hashing, heuristics, quarantine)
  signatures.py      Malware signature database (SHA-256 + patterns)
  static/index.html  Single-page web GUI
  run.bat            One-click Windows launcher
  quarantine/        Quarantined files are stored here
  logs/              Scan history log
  scan_targets/      Auto-generated demo test files (created via UI)

----------------------------------------------------------------
HOW TO RUN
----------------------------------------------------------------

METHOD 1 — Double-click (Windows, Easiest)
  1. Double-click run.bat
  2. A console window opens; it installs Flask if needed
  3. Your browser opens automatically at http://localhost:5000
  4. Press Ctrl+C in the console to stop

METHOD 2 — Command Prompt / Terminal (All OS)
  Step 1: Make sure Python 3.8+ is installed
          → python --version

  Step 2: Install Flask
          → pip install flask

  Step 3: Run the server
          → python server.py

  Step 4: Open your browser at http://localhost:5000

METHOD 3 — Virtual Environment (Recommended for clean setup)
  → python -m venv venv
  → venv\Scripts\activate          (Windows)
     source venv/bin/activate      (Mac/Linux)
  → pip install flask
  → python server.py

----------------------------------------------------------------
USING THE GUI
----------------------------------------------------------------
  DASHBOARD    — Overview stats, quick-start, how-it-works guide
  SCAN FILES   — Enter a folder/file path and click "Start Scan"
  SCAN RESULTS — Browse all results with filter by status
  QUARANTINE   — View and manage quarantined files
  SIGNATURES   — Browse the signature DB, add custom hashes
  SCAN LOG     — Full text log of every scan session

  QUICK DEMO:
    1. Open the app (http://localhost:5000)
    2. Click "Create Demo Test Files" on the Dashboard
    3. Go to "Scan Files"
    4. The path is pre-filled — click "Start Scan"
    5. Watch it detect the EICAR test file and suspicious scripts!

----------------------------------------------------------------
REQUIREMENTS
----------------------------------------------------------------
  Python  : 3.8 or higher
  Package : flask  (auto-installed by run.bat)
  OS      : Windows / macOS / Linux

----------------------------------------------------------------
PRACTICAL USES (as per project brief)
----------------------------------------------------------------
  - Understand how signature-based antivirus engines work
  - Learn cybersecurity fundamentals: hashing, file scanning,
    quarantine logic
  - Detect unauthorized or modified files in restricted environments
  - Build a real-world security automation tool

================================================================
