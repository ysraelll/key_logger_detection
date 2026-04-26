import hashlib
import os
from typing import List, Optional
from ..core.logger import logger

class HashEngine:
    def __init__(self, signatures_file: str = "signatures.txt"):
        self.signatures_file = signatures_file
        self.bad_hashes = self._load_signatures()

    def _load_signatures(self) -> set:
        """
        Loads hashes into a set for O(1) lookup performance.
        """
        hashes = set()
        try:
            if os.path.exists(self.signatures_file):
                with open(self.signatures_file, "r") as f:
                    for line in f:
                        h = line.strip().lower()
                        if h:
                            hashes.add(h)
            logger.debug(f"Loaded {len(hashes)} signatures from {self.signatures_file}")
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")
        return hashes

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """
        Calculates SHA-256 hash of a file.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.debug(f"Error hashing file {file_path}: {e}")
            return None

    def is_malicious(self, file_path: str) -> Tuple[bool, Optional[str]]:
        file_hash = self.calculate_hash(file_path)
        if file_hash and file_hash in self.bad_hashes:
            return True, file_hash
        return False, None
