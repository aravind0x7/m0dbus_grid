#!/usr/bin/env python3
"""
Launch script for the Modbus OT Pentest Lab.
Works when all files are in the same directory (flat layout).
"""
import subprocess
import sys
import os
import time
import threading

# All files are in the same directory as this script
BASE = os.path.dirname(os.path.abspath(__file__))

PLC_SCRIPT  = os.path.join(BASE, 'plc_simulator.py')
HMI_SCRIPT  = os.path.join(BASE, 'hmi_server.py')

# ANSI Color Codes
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BOLD = "\033[1m"
RESET = "\033[0m"

def run_plc():
    print(f"{CYAN}[LAUNCHER]{RESET} Starting PLC Simulator on port 5020...")
    subprocess.run([sys.executable, PLC_SCRIPT, '5020'])

def run_hmi():
    time.sleep(2)
    print(f"{CYAN}[LAUNCHER]{RESET} Starting HMI Web Server on http://localhost:8080...")
    env = os.environ.copy()
    env['PLC_HOST'] = '127.0.0.1'
    env['PLC_PORT'] = '5020'
    subprocess.run([sys.executable, HMI_SCRIPT], env=env)

if __name__ == '__main__':
    # Cool ASCII Banner inspired by the vuln-mqtt style
    BANNER = f"""{CYAN}
  __  __  ____  _____  ____  _   _  ____        ___  _____ 
 |  \/  |/ __ \|  __ \|  _ \| | | |/ ___|      / _ \|_   _|
 | \  / | |  | | |  | | |_) | | | | \___ \ ___| | | | | |  
 | |\/| | |  | | |  | |  _ <| |_| |  ___) |___| |_| | | |  
 |_|  |_|\____/|_____/|_____|\____/|_____/     \___/  |_|  
                                                           
 {BOLD}Industrial Control Systems Security Lab{RESET}
 {MAGENTA}Developed by aravind0x7{RESET}
    """
    print(BANNER)
    
    print(f"{GREEN}[+]{RESET} {BOLD}PLC Simulator{RESET}  : 0.0.0.0:5020 (Modbus TCP)")
    print(f"{GREEN}[+]{RESET} {BOLD}HMI Interface{RESET}  : http://localhost:8080")
    print(f"{GREEN}[+]{RESET} {BOLD}Pentest Tools{RESET}  : python3 modbus_pentest.py -p 5020 dump")
    print(f"{YELLOW}[!] FOR AUTHORIZED EDUCATIONAL USE ONLY{RESET}")
    print("-" * 60)

    # Verify files exist
    missing = []
    for f in [PLC_SCRIPT, HMI_SCRIPT]:
        if not os.path.exists(f):
            missing.append(f)

    if missing:
        print(f"{RED}[ERROR] Missing files:{RESET}")
        for f in missing:
            print(f"  - {f}")
        print(f"{YELLOW}Make sure all .py files are in: {BASE}{RESET}")
        sys.exit(1)

    t1 = threading.Thread(target=run_plc, daemon=True)
    t2 = threading.Thread(target=run_hmi, daemon=True)
    t1.start()
    t2.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[LAUNCHER] Shutting down lab...{RESET}")
        sys.exit(0)
