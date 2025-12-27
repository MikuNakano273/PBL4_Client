from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("pbl4.QuarantineManagerController")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

StatusCallback = Callable[[str], None]

_QuarantineManagerModel = None
_init_global_quarantine_manager = None
_get_global_quarantine_manager = None
_DEFAULT_DB_PATH = None
_DEFAULT_QUARANTINE_FOLDER = None


def _lazy_import_model_helpers():
    """Attempt to import QuarantineManagerModel and helper functions."""
    global \
        _QuarantineManagerModel, \
        _init_global_quarantine_manager, \
        _get_global_quarantine_manager, \
        _DEFAULT_DB_PATH, \
        _DEFAULT_QUARANTINE_FOLDER
    if _QuarantineManagerModel is not None:
        return
    try:
        from Client.Model.QuarantineManagerModel import (  # type: ignore
            DEFAULT_DB_PATH,
            DEFAULT_QUARANTINE_FOLDER,
            QuarantineManagerModel,
            get_global_quarantine_manager,
            init_global_quarantine_manager,
        )

        _QuarantineManagerModel = QuarantineManagerModel
        _init_global_quarantine_manager = init_global_quarantine_manager
        _get_global_quarantine_manager = get_global_quarantine_manager
        _DEFAULT_DB_PATH = DEFAULT_DB_PATH
        _DEFAULT_QUARANTINE_FOLDER = DEFAULT_QUARANTINE_FOLDER
        logger.debug("Imported QuarantineManagerModel helpers")
    except Exception:
        logger.debug(
            "QuarantineManagerModel import failed (native extension may be unavailable)",
            exc_info=True,
        )


class QuarantineManagerController:
    def __init__(self, model: Optional[Any] = None):
        self._lock = threading.RLock()
        self._model: Optional[Any] = None
        self._initialized = False

        if model is not None:
            self._model = model
            self._initialized = True
            logger.info("QuarantineManagerController: using injected model instance")
            return

        try:
            _lazy_import_model_helpers()
            if callable(_get_global_quarantine_manager):
                try:
                    gm = _get_global_quarantine_manager()
                except Exception:
                    gm = None
                if gm is not None:
                    self._model = gm
                    self._initialized = True
                    logger.info(
                        "QuarantineManagerController: bound to existing global model"
                    )
                    return
        except Exception:
            logger.debug(
                "Error while attempting to bind to global QuarantineManagerModel",
                exc_info=True,
            )

        logger.info(
            "QuarantineManagerController created uninitialized (no model bound)"
        )

    # ----------------------
    # Initialization helpers
    # ----------------------
    def init(
        self, db_path: Optional[str] = None, status_cb: Optional[StatusCallback] = None
    ) -> bool:
        with self._lock:
            _lazy_import_model_helpers()
            db = db_path if db_path is not None else _DEFAULT_DB_PATH

            # 1) If a global helper exists, try to initialize/bind the global manager
            if callable(_init_global_quarantine_manager):
                try:
                    _init_global_quarantine_manager(db_path=db)
                    if callable(_get_global_quarantine_manager):
                        try:
                            gm = _get_global_quarantine_manager()
                        except Exception:
                            gm = None
                        if gm is not None:
                            self._model = gm
                            self._initialized = True
                            if status_cb:
                                status_cb("Bound to global quarantine manager")
                            logger.info(
                                "QuarantineManagerController: bound to global manager"
                            )
                            return True
                except Exception as e:
                    logger.debug(
                        "init_global_quarantine_manager failed: %s", e, exc_info=True
                    )
                    if status_cb:
                        status_cb(f"init_global_quarantine_manager failed: {e}")

            # 2) Fallback: construct a local model instance if binding did not succeed
            if _QuarantineManagerModel is not None:
                try:
                    self._model = _QuarantineManagerModel(db_path=db)
                    self._initialized = True
                    if status_cb:
                        status_cb("Constructed local QuarantineManagerModel instance")
                    logger.info("QuarantineManagerController: constructed local model")
                    return True
                except Exception as e:
                    logger.debug(
                        "Construct local QuarantineManagerModel failed: %s",
                        e,
                        exc_info=True,
                    )
                    if status_cb:
                        status_cb(f"Construct local model failed: {e}")

            # final failure
            if status_cb:
                status_cb("Quarantine manager not available")
            logger.warning("QuarantineManagerController: initialization failed")
            return False

    def init_with_retries(
        self,
        max_seconds: int = 60,
        interval: float = 0.5,
        db_path: Optional[str] = None,
        status_cb: Optional[StatusCallback] = None,
    ) -> bool:
        deadline = time.time() + float(max_seconds)
        attempt = 0
        while True:
            attempt += 1
            try:
                if status_cb:
                    status_cb(f"Initializing quarantine manager (attempt {attempt})...")
                ok = self.init(db_path=db_path, status_cb=status_cb)
                if ok:
                    return True
            except Exception as e:
                logger.debug(
                    "Exception during quarantine init attempt: %s", e, exc_info=True
                )
                if status_cb:
                    status_cb(f"Quarantine init exception: {e}")

            if time.time() >= deadline:
                if status_cb:
                    status_cb("Quarantine manager init timed out")
                logger.warning(
                    "QuarantineManagerController: init_with_retries timed out"
                )
                return False

            # small sleep before next attempt
            try:
                time.sleep(interval)
            except Exception:
                pass

    def ensure_initialized(self) -> bool:
        """
        Ensure the controller has a usable model bound. Returns True if so.
        Else try to bind to a global model if available.
        """
        with self._lock:
            if self._initialized and self._model is not None:
                return True
            _lazy_import_model_helpers()
            try:
                if callable(_get_global_quarantine_manager):
                    try:
                        gm = _get_global_quarantine_manager()
                    except Exception:
                        gm = None
                    if gm is not None:
                        self._model = gm
                        self._initialized = True
                        return True
            except Exception:
                pass
            return False

    def is_initialized(self) -> bool:
        return self.ensure_initialized()

    @property
    def model(self) -> Optional[Any]:
        with self._lock:
            return self._model

    # ----------------------
    # High-level operations
    # ----------------------
    def quarantine_file(self, src: str, note: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if not self.ensure_initialized():
                return {
                    "status": "error",
                    "message": "Quarantine manager not initialized",
                }

            model = self._model
            if model is None:
                return {
                    "status": "error",
                    "message": "Quarantine manager not available",
                }

            quarantine_fn = getattr(model, "quarantine_file", None)
            if not callable(quarantine_fn):
                return {
                    "status": "error",
                    "message": "quarantine_file not supported by model",
                }

            # Attempt to determine the DB path backing the model for diagnostics
            model_db = None
            try:
                if hasattr(model, "get_db_path"):
                    try:
                        model_db = model.get_db_path()
                    except Exception:
                        model_db = None
                elif hasattr(model, "db_path"):
                    model_db = getattr(model, "db_path", None)
            except Exception:
                model_db = None

            logger.debug(
                "quarantine_file called: src=%s model_db=%s controller_initialized=%s",
                src,
                model_db,
                bool(self._initialized),
            )

            try:
                try:
                    import logging

                    logging.getLogger("pbl4.ScanController").debug(
                        "Attempting quarantine for filepath=%r", str(src)
                    )
                except Exception:
                    pass

                try:
                    print(
                        f"[QUARANTINE] Called: src={src} model_db={model_db} controller_initialized={bool(self._initialized)}"
                    )
                except Exception:
                    pass

                try:
                    if isinstance(src, dict):
                        src_arg = (
                            src.get("full_path")
                            or src.get("stored_path")
                            or src.get("path")
                            or src.get("fullpath")
                            or src.get("filename")
                        )
                        if not src_arg:
                            rec = src.get("record")
                            try:
                                src_arg = getattr(rec, "file", None) or getattr(
                                    rec, "filename", None
                                )
                            except Exception:
                                src_arg = None
                        if src_arg:
                            src_arg = str(src_arg)
                        else:
                            src_arg = str(src)
                    else:
                        src_arg = str(src)
                except Exception:
                    src_arg = str(src)

                raw = quarantine_fn(src_arg)
                logger.debug("quarantine_file raw response for %s: %r", src_arg, raw)
                try:
                    try:
                        src_disp = src_arg
                    except Exception:
                        src_disp = src
                    print(f"[QUARANTINE] Raw native response for {src_disp!r}: {raw!r}")
                except Exception:
                    pass

                if isinstance(raw, dict):
                    res = raw.copy()
                else:
                    res = {"status": "ok", "message": str(raw), "raw": raw}

                try:
                    sp = res.get("stored_path")
                    if sp is not None:
                        res["stored_path"] = str(Path(sp))
                        try:
                            res.setdefault("stored_name", Path(res["stored_path"]).name)
                        except Exception:
                            pass
                except Exception:
                    pass

                if note and isinstance(res, dict):
                    res.setdefault("note", note)

                logger.debug("quarantine_file normalized result for %s: %r", src, res)
                try:
                    print(f"[QUARANTINE] Normalized result for {src!r}: {res!r}")
                except Exception:
                    pass

                try:
                    status_lower = (res.get("status") or "").lower()
                    if status_lower.startswith("quarantined") and not res.get(
                        "stored_path"
                    ):
                        logger.warning(
                            "quarantine_file: status indicates quarantined but no stored_path for %s; result=%r db=%s",
                            src,
                            res,
                            model_db,
                        )
                        try:
                            print(
                                f"[QUARANTINE][WARN] status indicates quarantined but no stored_path for {src}; result={res!r} db={model_db}"
                            )
                        except Exception:
                            pass
                except Exception:
                    pass

                return res
            except Exception as e:
                logger.exception(
                    "quarantine_file failed for %s (model_db=%s)", src, model_db
                )
                try:
                    print(
                        f"[QUARANTINE][ERROR] quarantine_file failed for {src} model_db={model_db} exc={e}"
                    )
                except Exception:
                    pass
                return {"status": "error", "message": str(e)}

    def whitelist_file(self, path: str, hash_type: str = "sha256") -> Dict[str, Any]:
        with self._lock:
            if not self.ensure_initialized():
                return {
                    "status": "error",
                    "message": "Quarantine manager not initialized",
                }
            model = self._model
            if model is None:
                return {
                    "status": "error",
                    "message": "Quarantine manager not available",
                }

            method = getattr(model, "whitelist_file", None)
            if not callable(method):
                return {
                    "status": "error",
                    "message": "whitelist_file not available on model",
                }
            try:
                raw = method(path)
                if isinstance(raw, dict):
                    res = raw.copy()
                    res.setdefault("hash_type", hash_type.upper())
                else:
                    res = {
                        "status": "ok",
                        "message": str(raw),
                        "hash_type": hash_type.upper(),
                    }
                return res
            except Exception as e:
                logger.exception("whitelist_file failed for %s", path)
                return {"status": "error", "message": str(e)}

    def restore_file(
        self, stored_name_or_path: str, dest_path: Optional[str] = None
    ) -> Dict[str, Any]:
        with self._lock:
            if not self.ensure_initialized():
                return {
                    "status": "error",
                    "message": "Quarantine manager not initialized",
                }

            model = self._model
            if model is None:
                return {
                    "status": "error",
                    "message": "Quarantine manager not available",
                }

            restore_fn = getattr(model, "restore_file", None)
            if not callable(restore_fn):
                return {
                    "status": "error",
                    "message": "restore_file not supported by model",
                }

            try:
                param_for_native = None
                try:
                    if isinstance(stored_name_or_path, dict):
                        param_for_native = (
                            stored_name_or_path.get("stored_path")
                            or stored_name_or_path.get("stored_name")
                            or stored_name_or_path.get("stored_filename")
                            or stored_name_or_path.get("full_path")
                            or stored_name_or_path.get("path")
                            or stored_name_or_path.get("fullpath")
                        )
                        if not param_for_native:
                            rec = stored_name_or_path.get("record")
                            try:
                                param_for_native = getattr(
                                    rec, "file", None
                                ) or getattr(rec, "filename", None)
                            except Exception:
                                param_for_native = None
                        if param_for_native:
                            param_for_native = str(param_for_native)
                    else:
                        param_for_native = str(stored_name_or_path)
                except Exception:
                    param_for_native = str(stored_name_or_path)

                raw = restore_fn(param_for_native)
                if isinstance(raw, dict):
                    res = raw.copy()
                    if dest_path is not None:
                        res.setdefault("requested_dest_override", dest_path)
                else:
                    res = {
                        "status": "ok",
                        "message": str(raw),
                        "requested_dest_override": dest_path,
                    }
                return res
            except Exception as e:
                logger.exception("restore_file failed for %s", stored_name_or_path)
                return {"status": "error", "message": str(e)}

    # ----------------------
    # Utility
    # ----------------------
    def get_quarantine_folder(self) -> Optional[Path]:
        _lazy_import_model_helpers()
        try:
            if _DEFAULT_QUARANTINE_FOLDER is not None:
                return Path(_DEFAULT_QUARANTINE_FOLDER)
        except Exception:
            pass
        with self._lock:
            if self._model is not None and hasattr(self._model, "get_db_path"):
                try:
                    return Path(self._model.get_db_path()).parent
                except Exception:
                    pass
        return None

    def shutdown(self) -> None:
        with self._lock:
            try:
                if self._model is not None and hasattr(self._model, "shutdown"):
                    try:
                        self._model.shutdown()
                    except Exception:
                        logger.debug(
                            "Exception while calling model.shutdown()", exc_info=True
                        )
            finally:
                self._model = None
                self._initialized = False


# Module-level global quarantine manager controller
try:
    try:
        _lazy_import_model_helpers()
    except Exception:
        pass

    _bound_qm = None
    if callable(_get_global_quarantine_manager):
        try:
            _bound_qm = _get_global_quarantine_manager()
        except Exception:
            _bound_qm = None

    if _bound_qm is not None:
        global_quarantine_manager_controller = QuarantineManagerController(
            model=_bound_qm
        )
    else:
        global_quarantine_manager_controller = QuarantineManagerController()
except Exception:
    global_quarantine_manager_controller = None
    logger.debug(
        "Failed to create module-level global_quarantine_manager_controller",
        exc_info=True,
    )

__all__ = ["QuarantineManagerController", "global_quarantine_manager_controller"]
