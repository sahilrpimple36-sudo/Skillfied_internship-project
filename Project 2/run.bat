@echo off
:: Change to the folder where this bat file lives — fixes the System32 issue
cd /d "%~dp0"

title NetGuard — Web GUI Launcher
echo.
echo  ============================================================
echo    NetGuard — Packet Sniffer + ARP Spoofing Detector
echo  ============================================================
echo.
echo  [1] Starting NetGuard server...
echo  [2] Browser will open automatically at http://localhost:5000
echo  [3] Press Ctrl+C here to stop the server
echo.
echo  TIP: To test ARP spoofing, open a SECOND cmd as Admin
echo       and run:  python arp_spoof_tester.py
echo.
echo  ============================================================
echo.
python server.py
pause
