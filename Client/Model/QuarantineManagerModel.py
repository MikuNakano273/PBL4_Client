from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("pbl4.QuarantineManagerModel")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

try:
    import quarantinemanager
except Exception as e:
    quarantinemanager = None
    logger.debug("quarantinemanager extension not available: %s", e)


DEFAULT_QUARANTINE_FOLDER = Path("C:/ProgramData/PBL4_AV_DATA/Quarantine")
DEFAULT_DB_PATH = str(DEFAULT_QUARANTINE_FOLDER / "quarantine.db")


def _parse_native_response(resp: str) -> Dict:
    """
    Normalize the textual response returned by the native QuarantineManager APIs.

    The native API returns human readable strings. This helper maps them into a
    dict with at least a `status` key and other structured fields where reasonable.

    Example mappings:
      - "ERROR: message" -> {"status": "error", "message": "message"}
      - "QUARANTINED: stored_as=..." -> {"status": "quarantined", "stored_path": "...", "message": resp}
      - "PRUNED_AND_QUARANTINED: freed=NN; stored_as=..." -> {"status":"quarantined_pruned", ...}
      - "WHITELISTED: sha256=<hex>" -> {"status":"whitelisted","hash":"<hex>"}
      - "RESTORED: <path> [sha256=...]" -> {"status":"restored","restored_to": "<path>", "hash": maybe}
      - "EMERGENCY_DELETED: ..." -> {"status":"emergency_deleted", "message": resp}
    """
    if not isinstance(resp, str):
        return {
            "status": "error",
            "message": "Invalid response type from native extension",
        }

    r = resp.strip()
    if r.startswith("ERROR:"):
        return {"status": "error", "message": r[len("ERROR:") :].strip(), "raw": r}

    if r.startswith("QUARANTINED:"):
        out = {"status": "quarantined", "message": r, "raw": r}
        idx = r.find("stored_as=")
        if idx != -1:
            stored = r[idx + len("stored_as=") :].strip()
            out["stored_path"] = stored
            out["stored_name"] = Path(stored).name
        return out

    if r.startswith("PRUNED_AND_QUARANTINED:"):
        out = {"status": "quarantined_pruned", "message": r, "raw": r}
        try:
            parts = [p.strip() for p in r.split(";")]
            for p in parts:
                if p.startswith("freed="):
                    freed_part = p[len("freed=") :]
                    freed_num = "".join(ch for ch in freed_part if ch.isdigit())
                    if freed_num:
                        out["freed_bytes"] = int(freed_num)
                if "stored_as=" in p:
                    idx = p.find("stored_as=")
                    stored = p[idx + len("stored_as=") :].strip()
                    out["stored_path"] = stored
                    out["stored_name"] = Path(stored).name
        except Exception:
            logger.debug(
                "Failed to robustly parse PRUNED_AND_QUARANTINED response: %s", r
            )
        return out

    if r.startswith("WHITELISTED:"):
        out = {"status": "whitelisted", "message": r, "raw": r}
        idx = r.find("sha256=")
        if idx != -1:
            out["hash"] = r[idx + len("sha256=") :].strip()
        return out

    if r.startswith("RESTORED:"):
        out = {"status": "restored", "message": r, "raw": r}
        body = r[len("RESTORED:") :].strip()
        sha_idx = body.find("sha256=")
        if sha_idx != -1:
            path_part = body[:sha_idx].strip()
            hash_part = body[sha_idx + len("sha256=") :].strip()
            out["restored_to"] = path_part
            out["hash"] = hash_part
        else:
            out["restored_to"] = body
        return out

    if r.startswith("EMERGENCY_DELETED:"):
        return {"status": "emergency_deleted", "message": r, "raw": r}

    return {"status": "ok", "message": r, "raw": r}


class QuarantineManagerModel:
    def __init__(self, db_path: Optional[str] = None):
        if quarantinemanager is None:
            raise RuntimeError(
                "Native `quarantinemanager` extension is not available. Ensure the "
                "pybind11 extension is built and on PYTHONPATH."
            )
        self.db_path = db_path or DEFAULT_DB_PATH
        try:
            if hasattr(quarantinemanager, "create_quarantine_manager"):
                self._native = quarantinemanager.create_quarantine_manager(self.db_path)
            else:
                self._native = quarantinemanager.QuarantineManager(self.db_path)
        except Exception as e:
            raise RuntimeError(f"Failed to create native QuarantineManager: {e}") from e

        self._closed = False
        logger.info("QuarantineManagerModel initialized (db=%s)", self.db_path)

    def __enter__(self) -> "QuarantineManagerModel":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

    def __del__(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def quarantine_file(self, src: str) -> Dict:
        self._ensure_open()
        try:
            resp = self._native.quarantine(str(src))
            parsed = _parse_native_response(resp)
            # If we have a stored_path, expose stored_name separately
            if parsed.get("stored_path") and "stored_name" not in parsed:
                parsed["stored_name"] = Path(parsed["stored_path"]).name
            return parsed
        except Exception as e:
            logger.exception("quarantine_file failed for %s", src)
            return {"status": "error", "message": str(e)}

    def whitelist_file(self, path: str) -> Dict:
        self._ensure_open()
        try:
            resp = self._native.whitelist(str(path))
            return _parse_native_response(resp)
        except Exception as e:
            logger.exception("whitelist_file failed for %s", path)
            return {"status": "error", "message": str(e)}

    def restore_file(
        self, stored_name_or_path: str, dest_path: Optional[str] = None
    ) -> Dict:
        self._ensure_open()
        try:
            resp = self._native.restore(str(stored_name_or_path))
            return _parse_native_response(resp)
        except Exception as e:
            logger.exception("restore_file failed for %s", stored_name_or_path)
            return {"status": "error", "message": str(e)}

    def shutdown(self) -> None:
        if self._closed:
            return
        try:
            if hasattr(self, "_native") and self._native is not None:
                try:
                    if hasattr(self._native, "shutdown"):
                        self._native.shutdown()
                except Exception:
                    logger.debug(
                        "Exception while calling native.shutdown()", exc_info=True
                    )
                self._native = None
        finally:
            self._closed = True
            logger.info("QuarantineManagerModel shutdown complete")

    # Utilities
    def _ensure_open(self):
        if quarantinemanager is None:
            raise RuntimeError("Native `quarantinemanager` extension is not available.")
        if getattr(self, "_closed", False):
            raise RuntimeError(
                "QuarantineManagerModel has been shutdown and cannot be used."
            )

    def get_db_path(self) -> str:
        return self.db_path

    def is_closed(self) -> bool:
        return bool(self._closed)


_global_manager: Optional[QuarantineManagerModel] = None


def init_global_quarantine_manager(
    db_path: Optional[str] = None,
) -> QuarantineManagerModel:
    global _global_manager
    if _global_manager is not None and not _global_manager.is_closed():
        return _global_manager
    _global_manager = QuarantineManagerModel(db_path=db_path or DEFAULT_DB_PATH)
    return _global_manager


def get_global_quarantine_manager() -> QuarantineManagerModel:
    if _global_manager is None or _global_manager.is_closed():
        raise RuntimeError(
            "Global QuarantineManagerModel is not initialized. Call init_global_quarantine_manager(...) first."
        )
    return _global_manager
