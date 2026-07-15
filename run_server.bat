@echo off
cd /d "C:\Users\ANANT TRIPATHI\.gemini\antigravity\scratch\Firewall-Simulator"
echo Starting Sentry Firewall Simulator as Administrator...
"C:\Users\ANANT TRIPATHI\AppData\Local\Python\pythoncore-3.14-64\python.exe" app.py
if %errorlevel% neq 0 (
    echo.
    echo Server stopped with error code %errorlevel%.
    pause
)
