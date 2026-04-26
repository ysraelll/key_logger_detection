import yaml
import os
from .core.logger import logger

CONFIG_FILE = "config.yaml"

def load_config():
    """
    Loads configuration from config.yaml.
    """
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config.yaml: {e}. Using internal defaults.")
        return {
            "known_processes": {
                "linux": ["logkeys", "keylogger", "lkl", "uberkey"],
                "windows": ["keylogger.exe", "hooker.exe", "rat.exe", "ahk.exe"],
            },
            "known_ports": [1337, 31337, 6667, 12345],
            "common_paths": {
                "linux": ["/usr/bin/", "/var/log/", "/tmp/"],
                "windows": ["C:\\Windows\\Temp\\", "AppData\\Local\\Temp\\"],
            },
            "file_keywords": ["keylog", "logger", "hook"],
        }

# Initialize config
_CONFIG = load_config()

KNOWN_PROCESSES = _CONFIG.get("known_processes", {})
KNOWN_PORTS = _CONFIG.get("known_ports", [])
COMMON_KEYLOG_PATHS = _CONFIG.get("common_paths", {})
FILE_KEYWORDS = _CONFIG.get("file_keywords", [])
