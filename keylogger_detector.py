import argparse
import json
import os
import platform
import sys
from datetime import datetime
from typing import Dict, List, Tuple

import psutil

# Cross-platform known keylogger indicators
KNOWN_PROCESSES = {
    "linux": ["logkeys", "keylogger", "lkl", "uberkey"],
    "windows": ["keylogger.exe", "hooker.exe", "rat.exe", "ahk.exe"],
}

KNOWN_PORTS = [1337, 31337, 6667, 12345]  # Common malware ports
COMMON_KEYLOG_PATHS = {
    "linux": ["/usr/bin/", "/var/log/", "/tmp/"],
    "windows": ["C:\\Windows\\Temp\\", "AppData\\Local\\Temp\\"],
}
FILE_KEYWORDS = ["keylog", "logger", "hook"]


def normalize_name(value: str) -> str:
    return (value or "").strip().lower()


def check_processes() -> List[Dict[str, str]]:
    suspicious = []
    system = platform.system().lower()
    known = {normalize_name(p) for p in KNOWN_PROCESSES.get(system, [])}

    for proc in psutil.process_iter(["name", "exe", "cmdline", "pid"]):
        try:
            name = normalize_name(proc.info.get("name") or "")
            exe = normalize_name(proc.info.get("exe") or "")
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()

            matched_indicator = None
            for indicator in known:
                if name == indicator or indicator in exe or indicator in cmdline:
                    matched_indicator = indicator
                    break

            if matched_indicator:
                suspicious.append(
                    {
                        "pid": str(proc.info.get("pid", "")),
                        "name": proc.info.get("name") or "unknown",
                        "exe": proc.info.get("exe") or "unknown",
                        "indicator": matched_indicator,
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return suspicious


def check_network() -> List[Dict[str, str]]:
    suspicious_ports = []
    known_ports = set(KNOWN_PORTS)

    for conn in psutil.net_connections(kind="inet"):
        try:
            if not conn.laddr:
                continue
            local_port = conn.laddr.port
            if local_port in known_ports:
                suspicious_ports.append(
                    {
                        "port": str(local_port),
                        "status": conn.status,
                        "pid": str(conn.pid) if conn.pid else "unknown",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    }
                )
        except Exception:
            continue

    return suspicious_ports


def check_filesystem(paths: List[str], max_files: int = 5000) -> Tuple[List[str], int]:
    suspicious_files = []
    scanned_files = 0

    for path in paths:
        if not os.path.exists(path):
            continue
        for root, _, files in os.walk(path):
            for file in files:
                scanned_files += 1
                if scanned_files > max_files:
                    return suspicious_files, scanned_files
                filename = file.lower()
                if any(kw in filename for kw in FILE_KEYWORDS):
                    suspicious_files.append(os.path.join(root, file))

    return suspicious_files, scanned_files


def calculate_risk(findings: Dict[str, list]) -> Dict[str, str]:
    score = 0
    score += min(len(findings["processes"]) * 30, 60)
    score += min(len(findings["ports"]) * 20, 40)
    score += min(len(findings["files"]) * 2, 20)

    if score >= 70:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {"score": str(score), "level": level}


def generate_text_report(findings: Dict[str, list], risk: Dict[str, str], scanned_files: int) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Keylogger Detection Report - {timestamp}\n")
        f.write(f"Host: {platform.node()} ({platform.system()})\n")
        f.write(f"Risk score: {risk['score']} ({risk['level']})\n")
        f.write(f"Files scanned: {scanned_files}\n")

        f.write("\nSuspicious Processes:\n")
        if findings["processes"]:
            for proc in findings["processes"]:
                f.write(
                    f"- PID {proc['pid']} | {proc['name']} | indicator={proc['indicator']} | exe={proc['exe']}\n"
                )
        else:
            f.write("None found\n")

        f.write("\nSuspicious Ports:\n")
        if findings["ports"]:
            for port in findings["ports"]:
                f.write(
                    f"- Port {port['port']} | status={port['status']} | pid={port['pid']} | remote={port['remote']}\n"
                )
        else:
            f.write("None found\n")

        f.write("\nSuspicious Files:\n")
        if findings["files"]:
            f.write("\n".join(findings["files"]))
            f.write("\n")
        else:
            f.write("None found\n")

    return filename


def generate_json_report(findings: Dict[str, list], risk: Dict[str, str], scanned_files: int) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"
    payload = {
        "timestamp": timestamp,
        "host": platform.node(),
        "platform": platform.system(),
        "risk": risk,
        "scanned_files": scanned_files,
        "findings": findings,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return filename


def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    return os.geteuid() == 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect potential keylogger indicators")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=5000,
        help="Maximum files to scan before stopping",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        help="Optional paths to scan instead of OS defaults",
    )
    parser.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="Run without requiring administrator privileges",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.skip_admin_check and not is_admin():
        print("Error: This script requires administrator privileges (or use --skip-admin-check).")
        return 1

    print("Starting keylogger detection scan...")
    system = platform.system().lower()
    scan_paths = args.paths if args.paths else COMMON_KEYLOG_PATHS.get(system, [])

    suspicious_files, scanned_files = check_filesystem(scan_paths, max_files=args.max_files)
    findings = {
        "processes": check_processes(),
        "ports": check_network(),
        "files": suspicious_files,
    }
    risk = calculate_risk(findings)

    if args.format == "json":
        report_file = generate_json_report(findings, risk, scanned_files)
    else:
        report_file = generate_text_report(findings, risk, scanned_files)

    print(f"\nScan complete! Report saved to {report_file}")
    print("Summary of findings:")
    print(f"- Suspicious processes: {len(findings['processes'])}")
    print(f"- Suspicious ports: {len(findings['ports'])}")
    print(f"- Suspicious files: {len(findings['files'])}")
    print(f"- Risk score: {risk['score']} ({risk['level']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
