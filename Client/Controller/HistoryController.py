import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from Client.Model.HistoryModel import HistoryModel

logger = logging.getLogger("pbl4.HistoryController")

try:
    from Client.Controller.QuarantineManagerController import (
        global_quarantine_manager_controller,
    )
except Exception:
    global_quarantine_manager_controller = None


class HistoryController:
    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.RLock()
        final_path = Path(db_path) if db_path else self._locate_db()
        self.model = HistoryModel(final_path)
        logger.debug("HistoryController initialized with Model at %s", final_path)

    def _locate_db(self) -> Optional[Path]:
        try:
            if global_quarantine_manager_controller:
                m = getattr(global_quarantine_manager_controller, "model", None)
                if m and hasattr(m, "get_db_path"):
                    p = Path(m.get_db_path())
                    if p.exists():
                        return p
        except Exception:
            pass

        cwd_db = Path.cwd() / "full_hash.db"
        if cwd_db.exists():
            return cwd_db

        try:
            candidate = Path(__file__).resolve().parents[2] / "full_hash.db"
            if candidate.exists():
                return candidate
        except Exception:
            pass
        return None

    # --- Functions for UI ---
    def list_quarantined(self, include_deleted: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            return self.model.get_all_quarantine(include_deleted)

    def get_record(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.model.get_record_by_id(int(record_id))

    def restore(
        self, record_id: int, dest_override: Optional[str] = None
    ) -> Dict[str, Any]:
        with self._lock:
            rec = self.get_record(record_id)
            if not rec:
                return {"status": "error", "message": f"Record {record_id} not found"}
            if rec.get("restored"):
                return {"status": "ok", "message": "Already restored", "record": rec}

            native_res = self._try_native_restore(rec, dest_override)
            if native_res:
                return native_res

            return self._fallback_restore(rec, dest_override)

    def delete(self, record_id: int) -> Dict[str, Any]:
        with self._lock:
            rec = self.get_record(record_id)
            if not rec:
                return {"status": "error", "message": "Record not found"}

            if self._try_native_delete(record_id):
                return {"status": "ok", "message": "Requested native deletion"}

            try:
                stored_full = os.path.join(
                    rec.get("stored_path") or "", rec.get("stored_filename") or ""
                )
                if stored_full and os.path.exists(stored_full):
                    self.model.remove_physical_file(stored_full)

                self.model.delete_record(int(record_id))
                return {"status": "ok", "message": "Deleted (fallback)"}
            except Exception as e:
                return {"status": "error", "message": str(e)}

    def whitelist(
        self, record_id: int, hash_type_override: Optional[str] = None
    ) -> Dict[str, Any]:
        with self._lock:
            rec = self.get_record(record_id)
            if not rec:
                return {"status": "error", "message": "Record not found"}

            if self._try_native_whitelist(rec, hash_type_override):
                return {"status": "ok", "message": "Whitelist requested via native"}

            orig_hash = rec.get("original_hash")
            if not orig_hash:
                return {"status": "error", "message": "No hash found"}

            h_type = hash_type_override or rec.get("hash_type") or "sha256"
            self.model.add_to_whitelist(
                orig_hash, h_type, "Whitelisted from Protection History UI"
            )
            return {"status": "ok", "message": "Hash inserted into whitelist"}

    # --- Private Helpers ---
    def _try_native_restore(self, rec, dest_override):
        if not (
            global_quarantine_manager_controller
            and global_quarantine_manager_controller.is_initialized()
        ):
            return None
        try:
            stored_full = os.path.join(
                rec.get("stored_path") or "", rec.get("stored_filename") or ""
            )
            res = global_quarantine_manager_controller.restore_file(
                stored_full, dest_path=dest_override or rec.get("original_path")
            )
            if isinstance(res, dict) and not res.get("status", "").lower().startswith(
                "error"
            ):
                newrec = self.get_record(rec["id"])
                r_path = (
                    res.get("restored_path")
                    or res.get("requested_dest_override")
                    or rec.get("original_path")
                )
                self._whitelist_after_restore(r_path, newrec or rec)
                return {
                    "status": "ok",
                    "message": "Restore via native",
                    "record": newrec or rec,
                }
        except Exception:
            logger.debug("Native restore failed, falling back", exc_info=True)
        return None

    def _fallback_restore(self, rec, dest_override):
        stored_full = os.path.join(
            rec.get("stored_path") or "", rec.get("stored_filename") or ""
        )
        dest_path = dest_override or rec.get("original_path")

        if not os.path.exists(stored_full):
            return {"status": "error", "message": "Stored file not found"}

        try:
            self.model.move_file(stored_full, dest_path)
            self.model.update_restored_status(rec["id"], dest_path)
            self._whitelist_after_restore(dest_path, rec)
            return {"status": "ok", "message": f"Restored to {dest_path}"}
        except Exception as e:
            return {"status": "error", "message": f"Restore failed: {e}"}

    def _whitelist_after_restore(self, restored_path, record):
        h_type = record.get("hash_type") or "sha256"
        if (
            restored_path
            and global_quarantine_manager_controller
            and global_quarantine_manager_controller.is_initialized()
        ):
            try:
                global_quarantine_manager_controller.whitelist_file(
                    restored_path, hash_type=h_type
                )
                return
            except Exception:
                pass

        orig_hash = record.get("original_hash")
        if orig_hash:
            self.model.add_to_whitelist(
                orig_hash, h_type, "Auto-whitelisted after restore"
            )

    def _try_native_delete(self, record_id):
        try:
            if (
                global_quarantine_manager_controller
                and global_quarantine_manager_controller.is_initialized()
            ):
                model = global_quarantine_manager_controller.model
                fn = getattr(model, "remove_quarantine_record_by_id", None)
                if fn:
                    try:
                        fn(int(record_id), "")
                    except:
                        fn(int(record_id))
                    return True
        except Exception:
            pass
        return False

    def _try_native_whitelist(self, rec, h_override):
        if not (
            global_quarantine_manager_controller
            and global_quarantine_manager_controller.is_initialized()
        ):
            return False
        try:
            path = rec.get("restored_path") or rec.get("original_path")
            h_type = h_override or rec.get("hash_type") or "sha256"
            res = global_quarantine_manager_controller.whitelist_file(
                path, hash_type=h_type
            )
            return not (
                isinstance(res, dict)
                and res.get("status", "").lower().startswith("error")
            )
        except Exception:
            return False
