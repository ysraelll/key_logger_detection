import os
import platform
from typing import Dict, List, Tuple
import psutil
from ..config import KNOWN_PROCESSES, KNOWN_PORTS
from ..utils import normalize_name
from .logger import logger
from .yara_scanner import YaraScanner
from .hash_engine import HashEngine

def check_processes() -> List[Dict[str, str]]:
    suspicious = []
    system = platform.system().lower()
    known = {normalize_name(p) for p in KNOWN_PROCESSES.get(system, [])}

    logger.debug(f"Scanning processes for {system}...")
    yara_scanner = YaraScanner()
    hash_engine = HashEngine()
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

            # Add YARA check if no name match
            if not matched_indicator:
                yara_matches = yara_scanner.scan_memory(proc.info.get("pid"))
                if yara_matches:
                    matched_indicator = f"yara:{yara_matches[0]}"

            # Add Hash check if no other match
            if not matched_indicator:
                exe_path = proc.exe()
                if exe_path:
                    is_bad, fhash = hash_engine.is_malicious(exe_path)
                    if is_bad:
                        matched_indicator = f"hash:{fhash[:8]}"

            if matched_indicator:
                logger.debug(f"Found suspicious process: {name} (PID: {proc.info.get('pid')})")
                suspicious.append(
                    {
                        "pid": str(proc.info.get("pid", "")),
                        "name": proc.info.get("name") or "unknown",
                        "exe": proc.info.get("exe") or "unknown",
                        "indicator": matched_indicator,
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.debug(f"Skipping process {proc.info.get('pid')}: {e}")
            continue

    return suspicious

def check_behavioral_indicators() -> List[Dict[str, str]]:
    """
    Detects behavioral indicators of keyloggers.
    """
    suspicious = []
    system = platform.system().lower()

    if system == "linux":
        # Linux: Check for processes accessing /dev/input/
        logger.debug("Checking Linux behavioral indicators (/dev/input access)...")
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                # Iterate through open files of the process
                for file in proc.open_files():
                    if "/dev/input/" in file.path:
                        logger.info(f"Behavioral match: Process {proc.info['name']} (PID: {proc.info['pid']}) is accessing input devices!")
                        suspicious.append({
                            "pid": str(proc.info['pid']),
                            "name": proc.info['name'],
                            "indicator": "input_device_access",
                            "exe": "unknown"
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

    elif system == "windows":
        # Windows: Scan process memory strings for keylogging APIs
        logger.debug("Checking Windows behavioral indicators (API string scan)...")
        keylog_apis = ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "RegisterHotKey"]
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                exe_path = proc.exe()
                if exe_path:
                    with open(exe_path, "rb") as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        for api in keylog_apis:
                            if api in content:
                                logger.info(f"Behavioral match: Process {proc.info['name']} contains API string {api}!")
                                suspicious.append({
                                    "pid": str(proc.info['pid']),
                                    "name": proc.info['name'],
                                    "indicator": f"api_string_{api}",
                                    "exe": exe_path
                                })
                                break
            except (psutil.AccessDenied, psutil.NoSuchProcess, IOError):
                continue

    return suspicious

def check_network() -> List[Dict[str, str]]:
    suspicious_ports = []
    known_ports = set(KNOWN_PORTS)

    logger.debug("Scanning network connections...")
    for conn in psutil.net_connections(kind="inet"):
        try:
            if not conn.laddr:
                continue
            local_port = conn.laddr.port
            if local_port in known_ports:
                logger.debug(f"Found suspicious port: {local_port}")
                suspicious_ports.append(
                    {
                        "port": str(local_port),
                        "status": conn.status,
                        "pid": str(conn.pid) if conn.pid else "unknown",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    }
                )
        except Exception as e:
            logger.debug(f"Error checking connection: {e}")
            continue

    return suspicious_ports

def check_filesystem(paths: List[str], max_files: int = 5000) -> Tuple[List[str], int]:
    suspicious_files = []
    scanned_files = 0
    from ..config import FILE_KEYWORDS

    logger.debug(f"Scanning filesystem paths: {paths}")
    for path in paths:
        if not os.path.exists(path):
            logger.debug(f"Path does not exist: {path}")
            continue
        for root, _, files in os.walk(path):
            for file in files:
                scanned_files += 1
                if scanned_files > max_files:
                    logger.info(f"Max files reached ({max_files}). Stopping scan.")
                    return suspicious_files, scanned_files
                filename = file.lower()
                if any(kw in filename for kw in FILE_KEYWORDS):
                    logger.debug(f"Found suspicious file: {file}")
                    suspicious_files.append(os.path.join(root, file))

    return suspicious_files, scanned_files
