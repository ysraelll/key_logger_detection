import yara
import os
from ..core.logger import logger

class YaraScanner:
    def __init__(self, rules_path: str = "rules/keylogger.yar"):
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self):
        try:
            return yara.compile(filepath=self.rules_path)
        except Exception as e:
            logger.error(f"Failed to load YARA rules from {self.rules_path}: {e}")
            return None

    def scan_file(self, file_path: str):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            logger.debug(f"YARA scan error on {file_path}: {e}")
            return []

    def scan_memory(self, pid: int):
        # Real memory scanning requires root and complex mapping.
        # For this tool, we scan the binary associated with the PID.
        try:
            import psutil
            proc = psutil.Process(pid)
            exe = proc.exe()
            if exe:
                return self.scan_file(exe)
        except Exception as e:
            logger.debug(f"YARA memory scan error on PID {pid}: {e}")
        return []
