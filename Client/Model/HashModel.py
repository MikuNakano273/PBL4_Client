import json
import logging
import os
import shutil
import tempfile
import threading
from typing import List, Optional, Union

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )


class HashModel:
    DEFAULT_PATH = r"C:\ProgramData\PBL4_AV_DATA\new_hash.json"

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or self.DEFAULT_PATH
        self._lock = threading.Lock()
        self._ensure_parent_exists()
        self._ensure_file_initialized()

    def _ensure_parent_exists(self) -> None:
        parent_dir = os.path.dirname(self.path)
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
                logger.debug("Created parent directory for hash file: %s", parent_dir)
            except Exception as e:
                logger.exception(
                    "Failed creating parent directory %s: %s", parent_dir, e
                )
                raise

    def _ensure_file_initialized(self) -> None:
        with self._lock:
            if not os.path.exists(self.path):
                try:
                    with open(self.path, "w", encoding="utf-8") as f:
                        json.dump([], f, ensure_ascii=False, indent=2)
                    logger.info("Initialized new hash file at %s", self.path)
                except Exception as e:
                    logger.exception(
                        "Unable to initialize hash file %s: %s", self.path, e
                    )
                    raise
            else:
                try:
                    with open(self.path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if not isinstance(data, list):
                        raise ValueError("Hash file JSON is not a list")
                except Exception:
                    try:
                        backup_path = self.path + ".bak"
                        shutil.copy2(self.path, backup_path)
                        logger.warning("Backed up invalid hash file to %s", backup_path)
                    except Exception as e:
                        logger.exception("Failed to back up invalid hash file: %s", e)
                    try:
                        with open(self.path, "w", encoding="utf-8") as f:
                            json.dump([], f, ensure_ascii=False, indent=2)
                        logger.info("Reinitialized hash file at %s", self.path)
                    except Exception as e:
                        logger.exception("Failed to reinitialize hash file: %s", e)
                        raise

    def _safe_load(self) -> List[dict]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            logger.warning("Hash file contained non-list JSON; treating as empty list")
            return []
        except Exception as e:
            logger.warning(
                "Failed to read/parse hash file; treating as empty list: %s", e
            )
            return []

    def _atomic_write(self, data: List[dict]) -> None:
        dir_name = os.path.dirname(self.path) or "."
        fd, temp_path = tempfile.mkstemp(
            prefix="new_hash_", suffix=".json", dir=dir_name
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmpf:
                json.dump(data, tmpf, ensure_ascii=False, indent=2)
                tmpf.flush()
                os.fsync(tmpf.fileno())
            os.replace(temp_path, self.path)
            logger.debug("Atomically wrote %d entries to %s", len(data), self.path)
        except Exception as e:
            logger.exception("Atomic write failed: %s", e)
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            raise

    def add_hash(
        self,
        hash_value: str,
        type: str = "sha256",
        malware_name: str = "",
        rule_match: Union[str, List[str]] = "",
    ) -> bool:
        if not hash_value:
            logger.error("add_hash called without hash_value")
            return False

        if isinstance(rule_match, list):
            rule_match_str = ", ".join(
                str(r).strip() for r in rule_match if r is not None and str(r).strip()
            )
        else:
            rule_match_str = str(rule_match).strip()

        record = {
            "hash": str(hash_value),
            "type": str(type),
            "malware_name": str(malware_name),
            "rule_match": rule_match_str,
        }

        with self._lock:
            try:
                entries = self._safe_load()
                entries.append(record)
                self._atomic_write(entries)
                logger.info("Appended hash record: %s", record.get("hash"))
                return True
            except Exception as e:
                logger.exception("Failed to append hash record: %s", e)
                return False

    def get_all(self) -> List[dict]:
        with self._lock:
            return self._safe_load()

    def is_empty(self) -> bool:
        with self._lock:
            data = self._safe_load()
            return len(data) == 0

    def clear(self) -> bool:
        with self._lock:
            try:
                self._atomic_write([])
                logger.info("Cleared all hash records in %s", self.path)
                return True
            except Exception as e:
                logger.exception("Failed to clear hash file: %s", e)
                return False

    def pop_all(self) -> List[dict]:
        with self._lock:
            entries = self._safe_load()
            try:
                self._atomic_write([])
                logger.debug("Popped %d records from %s", len(entries), self.path)
            except Exception:
                logger.exception(
                    "Failed to clear file after pop; returning entries but file may not be cleared"
                )
            return entries
