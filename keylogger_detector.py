import os
import sys
import platform
import subprocess
from datetime import datetime

# Cross-platform known keylogger indicators
KNOWN_PROCESSES = {
    'linux': ['logkeys', 'keylogger', 'lkl', 'uberkey'],
    'windows': ['keylogger.exe', 'hooker.exe', 'rat.exe', 'ahk.exe']
}

KNOWN_PORTS = [1337, 31337, 6667, 12345]  # Common malware ports
COMMON_KEYLOG_PATHS = {
    'linux': ['/usr/bin/', '/var/log/', '/tmp/'],
    'windows': ['C:\\Windows\\Temp\\', 'AppData\\Local\\Temp\\']
}

def check_processes():
    suspicious = []
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            processes = subprocess.check_output(['ps', 'aux']).decode().split('\n')
        elif system == 'windows':
            processes = subprocess.check_output(['tasklist']).decode().split('\n')
        
        for proc in KNOWN_PROCESSES.get(system, []):
            if any(proc in p for p in processes):
                suspicious.append(proc)
                
    except Exception as e:
        print(f"Process check error: {str(e)}")
    
    return suspicious

def check_network():
    suspicious_ports = []
    try:
        netstat = subprocess.check_output(['netstat', '-ano'] if platform.system() == 'Windows' 
                                         else ['netstat', '-tulpn']).decode()
        for port in KNOWN_PORTS:
            if str(port) in netstat:
                suspicious_ports.append(port)
    except Exception as e:
        print(f"Network check error: {str(e)}")
    
    return suspicious_ports

def check_filesystem():
    suspicious_files = []
    system = platform.system().lower()
    
    for path in COMMON_KEYLOG_PATHS.get(system, []):
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if any(kw in file.lower() for kw in ['keylog', 'logger', 'hook']):
                        suspicious_files.append(os.path.join(root, file))
    
    return suspicious_files

def generate_report(findings):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"Keylogger Detection Report - {timestamp}\n")
        f.write("\nSuspicious Processes:\n")
        f.write('\n'.join(findings['processes']) or "None found")
        f.write("\n\nSuspicious Ports:\n")
        f.write('\n'.join(map(str, findings['ports'])) or "None found")
        f.write("\n\nSuspicious Files:\n")
        f.write('\n'.join(findings['files']) or "None found")
    
    return filename

def main():
    print("Starting keylogger detection scan...")
    
    findings = {
        'processes': check_processes(),
        'ports': check_network(),
        'files': check_filesystem()
    }
    
    report_file = generate_report(findings)
    
    print(f"\nScan complete! Report saved to {report_file}")
    print("Summary of findings:")
    print(f"- Suspicious processes: {len(findings['processes'])}")
    print(f"- Suspicious ports: {len(findings['ports'])}")
    print(f"- Suspicious files: {len(findings['files'])}")

if __name__ == "__main__":
    if os.geteuid() == 0 or platform.system() == 'Windows' and os.environ.get('OS') == 'Windows_NT':
        main()
    else:
        print("Error: This script requires administrator privileges.")
        sys.exit(1)
