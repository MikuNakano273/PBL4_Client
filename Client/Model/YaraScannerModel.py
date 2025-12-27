from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional, Tuple

DEFAULT_COMPILED_RULES = Path.cwd() / "all_rules.yarc"
DEFAULT_RULES_DB = Path.cwd() / "full_hash.db"

try:
    import yarascanner
except Exception:
    yarascanner = None

StatusCallback = Callable[[object], None]
ResultCallback = Callable[[object], None]


# old rules folder resolution logic
def _rules_folder() -> Path:
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass) / "Rules"
    return Path(__file__).parent.parent.parent / "Rules"


class YaraScannerModel:
    def __init__(self) -> None:
        if yarascanner is None:
            raise ImportError("yarascanner native extension is not available")
        self._scanner = yarascanner.YaraScanner()
        self._initialized = False
        self._rules_path: Optional[str] = None
        self._db_path: Optional[str] = None
        self._status_cb: Optional[StatusCallback] = None

    def init(
        self,
        rules_path: Optional[str] = None,
        db_path: Optional[str] = None,
        status_cb: Optional[StatusCallback] = None,
    ) -> bool:
        rules = rules_path or DEFAULT_COMPILED_RULES
        db = db_path or DEFAULT_RULES_DB

        self._rules_path = str(rules)
        self._db_path = str(db)
        self._status_cb = status_cb

        try:
            ok = self._scanner.init(self._rules_path, self._db_path, self._status_cb)
            self._initialized = bool(ok)
            return self._initialized
        except Exception as e:
            # print minimal info; controllers / callers can handle/log as appropriate
            print(f"[YaraScannerModel] init() exception: {e}")
            self._initialized = False
            return False

    def ensure_initialized(self, status_cb: Optional[StatusCallback] = None) -> bool:
        if self._initialized:
            return True
        return self.init(
            self._rules_path or DEFAULT_COMPILED_RULES,
            self._db_path or DEFAULT_RULES_DB,
            status_cb,
        )

    # ----------------------
    # Scanning operations
    # ----------------------
    def scan_file(
        self,
        path: str,
        on_result: Optional[ResultCallback] = None,
        full_scan: bool = False,
    ) -> None:
        if not self.ensure_initialized():
            raise RuntimeError("Scanner not initialized")
        if not path:
            raise ValueError("path is required")
        cb = on_result or (lambda _res: None)

        override_set = False
        try:
            if full_scan and hasattr(self, "_scanner"):
                try:
                    setattr(self._scanner, "full_scan_override", True)
                    override_set = True
                except Exception:
                    try:
                        if hasattr(self._scanner, "set_full_scan"):
                            try:
                                self._scanner.set_full_scan(True)
                                override_set = True
                            except Exception:
                                override_set = False
                    except Exception:
                        override_set = False
        except Exception:
            override_set = False

        try:
            try:
                self._scanner.scan_file(path, cb, full_scan=full_scan)  # type: ignore
            except TypeError:
                try:
                    try:
                        if hasattr(self._scanner, "reset_progress"):
                            try:
                                self._scanner.reset_progress()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    self._scanner.scan_file(path, cb)
                except Exception as e:
                    print(f"[YaraScannerModel] scan_file raised: {e}")
            except Exception as e:
                print(f"[YaraScannerModel] scan_file raised: {e}")
        finally:
            try:
                if override_set and hasattr(self, "_scanner"):
                    try:
                        setattr(self._scanner, "full_scan_override", False)
                    except Exception:
                        try:
                            if hasattr(self._scanner, "set_full_scan"):
                                try:
                                    self._scanner.set_full_scan(False)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass

    def scan_folder(
        self,
        path: str,
        on_result: Optional[ResultCallback] = None,
        full_scan: bool = False,
    ) -> None:
        if not self.ensure_initialized():
            raise RuntimeError("Scanner not initialized")
        if not path:
            raise ValueError("path is required")
        cb = on_result or (lambda _res: None)

        override_set = False
        try:
            if full_scan and hasattr(self, "_scanner"):
                try:
                    setattr(self._scanner, "full_scan_override", True)
                    override_set = True
                except Exception:
                    try:
                        if hasattr(self._scanner, "set_full_scan"):
                            try:
                                self._scanner.set_full_scan(True)
                                override_set = True
                            except Exception:
                                override_set = False
                    except Exception:
                        override_set = False
        except Exception:
            override_set = False

        try:
            try:
                if hasattr(self._scanner, "reset_progress"):
                    try:
                        self._scanner.reset_progress()
                    except Exception:
                        pass
                elif hasattr(self._scanner, "clear_progress"):
                    try:
                        self._scanner.clear_progress()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                try:
                    self._scanner.scan_folder(path, cb, full_scan=full_scan)  # type: ignore
                except TypeError:
                    self._scanner.scan_folder(path, cb)
            except Exception as e:
                print(f"[YaraScannerModel] scan_folder raised: {e}")
                raise
        finally:
            try:
                if hasattr(self._scanner, "set_throttle_duty"):
                    try:
                        self._scanner.set_throttle_duty(0.0)
                    except Exception:
                        pass
                if hasattr(self._scanner, "set_throttle_max_sleep_ms"):
                    try:
                        self._scanner.set_throttle_max_sleep_ms(0)
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if override_set and hasattr(self, "_scanner"):
                    try:
                        setattr(self._scanner, "full_scan_override", False)
                    except Exception:
                        try:
                            if hasattr(self._scanner, "set_full_scan"):
                                try:
                                    self._scanner.set_full_scan(False)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass

    # ----------------------
    # Progress accessor
    # ----------------------
    def get_progress(self) -> int:
        if not hasattr(self, "_scanner") or self._scanner is None:
            return 0
        try:
            # Delegate directly to native accessor. Binding exposes a safe get_progress().
            if hasattr(self._scanner, "get_progress"):
                p = self._scanner.get_progress()
                try:
                    return int(max(0, min(100, int(p))))
                except Exception:
                    return 0
            # Fallback: if an older binding exposes get_progress_percent, allow it
            if hasattr(self._scanner, "get_progress_percent"):
                p = self._scanner.get_progress_percent()
                try:
                    return int(max(0, min(100, int(p))))
                except Exception:
                    return 0
        except Exception:
            pass
        return 0

    def get_progress_counts(self) -> Tuple[Optional[int], Optional[int]]:
        completed = None
        total = None
        try:
            if hasattr(self._scanner, "get_completed_count"):
                try:
                    completed = int(self._scanner.get_completed_count())
                except Exception:
                    completed = None
            if hasattr(self._scanner, "get_total_count"):
                try:
                    total = int(self._scanner.get_total_count())
                except Exception:
                    total = None
        except Exception:
            pass
        return (completed, total)

    def reset_progress(self) -> None:
        try:
            if hasattr(self._scanner, "reset_progress"):
                try:
                    self._scanner.reset_progress()
                    return
                except Exception:
                    pass
            if hasattr(self._scanner, "clear_progress"):
                try:
                    self._scanner.clear_progress()
                    return
                except Exception:
                    pass
        except Exception:
            pass

    # ----------------------
    # Convenience rule-oriented flows
    # ----------------------
    def _compiled_or_source_for(self, base_name: str) -> str:
        rules_dir = _rules_folder()
        compiled = rules_dir / f"{base_name}.yarc"
        src = rules_dir / f"{base_name}.yar"
        if compiled.exists():
            return str(compiled)
        if src.exists():
            return str(src)
        return DEFAULT_COMPILED_RULES

    # ----------------------
    # Realtime support
    # ----------------------
    def start_realtime(
        self, watch_path: str, on_result: Optional[ResultCallback] = None
    ) -> bool:
        if not self.ensure_initialized():
            raise RuntimeError("Scanner not initialized")
        cb = on_result or (lambda _res: None)
        try:
            return bool(self._scanner.start_realtime(watch_path, cb))
        except Exception as e:
            print(f"[YaraScannerModel] start_realtime raised: {e}")
            return False

    def stop_realtime(self) -> None:
        try:
            if hasattr(self._scanner, "stop_realtime"):
                self._scanner.stop_realtime()
        except Exception:
            pass

    def shutdown(self) -> None:
        try:
            try:
                self.stop_realtime()
            except Exception:
                pass
            if hasattr(self._scanner, "shutdown"):
                try:
                    self._scanner.shutdown()
                except Exception:
                    pass
        except Exception as e:
            print(f"[YaraScannerModel] shutdown raised: {e}")
        finally:
            self._initialized = False


# ---------------------------------------------------------------------
# Global scanner helper (singleton) for application lifetime
# ---------------------------------------------------------------------
# The application can call `get_global_scanner()` at startup to create and
# initialize a single shared YaraScannerModel instance. Controllers can
# then call `get_global_scanner()` to obtain the same instance and avoid
# repeated init/shutdown cycles.
_GLOBAL_SCANNER: Optional["YaraScannerModel"] = None


def get_global_scanner(
    init_if_missing: bool = True,
    rules: Optional[str] = None,
    db: Optional[str] = None,
    status_cb: Optional[Callable[[object], None]] = None,
) -> Optional["YaraScannerModel"]:
    global _GLOBAL_SCANNER
    if _GLOBAL_SCANNER is not None:
        return _GLOBAL_SCANNER

    if not init_if_missing:
        return None

    scanner = YaraScannerModel()
    try:
        scanner.init(rules or DEFAULT_COMPILED_RULES, db or DEFAULT_RULES_DB, status_cb)
    except Exception as e:
        print(f"[YaraScannerModel] global init failed: {e}")
    _GLOBAL_SCANNER = scanner
    return _GLOBAL_SCANNER


def set_global_scanner(scanner: Optional["YaraScannerModel"]) -> None:
    global _GLOBAL_SCANNER
    _GLOBAL_SCANNER = scanner
