Set objShell = CreateObject("Shell.Application")
' Execute the batch file as Administrator, keeping the working directory correct.
objShell.ShellExecute "C:\Users\ANANT TRIPATHI\.gemini\antigravity\scratch\Firewall-Simulator\run_server.bat", "", "C:\Users\ANANT TRIPATHI\.gemini\antigravity\scratch\Firewall-Simulator", "runas", 1
