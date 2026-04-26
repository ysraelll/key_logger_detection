import json
import platform
from datetime import datetime
from typing import Dict

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
