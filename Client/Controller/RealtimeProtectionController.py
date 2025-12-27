from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

try:
    from Client.Controller.YaraScannerController import YaraScannerController
except Exception:
    YaraScannerController = None

# Try to import win10toast variants.
_WIN10_CLICK = False
try:
    from win10toast_click import ToastNotifier

    _WIN10_CLICK = True
except Exception:
    try:
        from win10toast import ToastNotifier

        _WIN10_CLICK = False
    except Exception:
        ToastNotifier = None
        _WIN10_CLICK = False

try:
    from Client.Controller.QuarantineManagerController import (
        global_quarantine_manager_controller,
    )
except Exception:
    global_quarantine_manager_controller = None  # type: ignore

# Type aliases
ResultCallback = Callable[[object], None]
NotificationClickCallback = Callable[[str], None]


class RealtimeProtectionController:
    SETTINGS_FILENAME = "realtime_protection_settings.json"
    DEFAULT_WATCH = r"%USERPROFILE%\Downloads;%USERPROFILE%\Desktop;%USERPROFILE%\AppData\Local\Temp;%USERPROFILE%\AppData\Roaming"

    def __init__(
        self, on_notification_click: Optional[NotificationClickCallback] = None
    ):
        self._lock = threading.RLock()
        self._op_lock = threading.RLock()
        self._op_in_progress = False
        self._op_thread = None

        self._yara_ctrl = None
        self._realtime_running = False

        # callback provided by UI layer; may be None
        self._on_notification_click = on_notification_click

        # settings
        self._settings_path = self._ensure_settings_dir() / self.SETTINGS_FILENAME
        self._settings = self._load_settings()

        self._notifier = self._init_notifier()

    # -----------------------
    # Settings persistence
    # -----------------------
    def _ensure_settings_dir(self) -> Path:
        base = Path(r"C:\ProgramData\PBL4_AV_DATA")
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            try:
                fallback = Path(os.getcwd()) / "PBL4_AV_DATA"
                fallback.mkdir(parents=True, exist_ok=True)
                return fallback
            except Exception:
                return Path(".")

    def _load_settings(self) -> dict:
        defaults = {"enabled": False, "watch": ""}
        try:
            if self._settings_path.exists():
                with open(self._settings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {**defaults, **data}
        except Exception:
            pass
        defaults["watch"] = self.DEFAULT_WATCH.replace(";", "\n")
        return defaults

    def _save_settings(self) -> None:
        try:
            with open(self._settings_path, "w", encoding="utf-8") as f:
                json.dump(self._settings, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    # -----------------------
    # Notifier: init + show
    # -----------------------
    def _init_notifier(self):
        if ToastNotifier is None:
            return None
        try:
            inst = ToastNotifier()
            return (
                ("win10_click", inst)
                if globals().get("_WIN10_CLICK", False)
                else ("win10", inst)
            )
        except Exception:
            return None

    def _show_notification(
        self, title: str, msg: str, filepath: Optional[str] = None
    ) -> None:
        def _invoke_cb(fp: Optional[str]):
            if not fp or self._on_notification_click is None:
                return
            try:
                # Chạy callback trong thread riêng để không block UI/System
                threading.Thread(
                    target=lambda: self._on_notification_click(fp), daemon=True
                ).start()
            except Exception:
                pass

        notifier = self._notifier
        if notifier is None:
            print(f"[THÔNG BÁO] {title} - {msg} ({filepath})")
            _invoke_cb(filepath)
            return

        backend, inst = notifier if isinstance(notifier, tuple) else (None, notifier)

        try:
            if backend == "win10_click":

                def _cb_wrapper(*args):
                    try:
                        _invoke_cb(filepath)
                    except Exception:
                        pass
                    return 0  # trả về 0 (int) cho Windows LRESULT

                inst.show_toast(
                    title,
                    msg,
                    duration=6,
                    threaded=True,
                    callback_on_click=_cb_wrapper,  # Không dùng lambda ở đây
                )
            else:
                # Đối với bản win10toast thường, không truyền callback_on_click
                inst.show_toast(title, msg, duration=6, threaded=True)
        except Exception as e:
            # Nếu vẫn lỗi, fallback về print để không làm crash chương trình
            print(f"[NOTIFICATION ERROR] {e} | {title}: {msg}")
            _invoke_cb(filepath)

    # -----------------------
    # Watch folder helpers
    # -----------------------
    def set_watch_folders(self, watch_arg: str) -> None:
        with self._lock:
            if not watch_arg:
                self._settings["watch"] = ""
                self._save_settings()
                return
            normalized = watch_arg.replace("|", "\n").replace(";", "\n")
            parts = [ln.strip() for ln in normalized.splitlines() if ln.strip()]
            valid = []
            for ln in parts:
                try:
                    expanded = os.path.expandvars(ln)
                    expanded = os.path.expanduser(expanded)
                    expanded = os.path.normpath(expanded)
                    if expanded:
                        valid.append(expanded)
                except Exception:
                    continue
            self._settings["watch"] = "\n".join(valid)
            self._save_settings()

    def get_watch_folders(self) -> str:
        with self._lock:
            raw = self._settings.get("watch", "")
            if not raw:
                return self.DEFAULT_WATCH.replace(";", "\n")
            return raw.replace(";", "\n")

    def _watchlist_to_native(self) -> str:
        raw = self.get_watch_folders()
        lines = [ln.strip() for ln in raw.replace("|", "\n").splitlines() if ln.strip()]
        return ";".join(lines) if lines else self.DEFAULT_WATCH

    # -----------------------
    # Protection control
    # -----------------------
    def is_protecting(self) -> bool:
        with self._lock:
            return bool(self._realtime_running)

    def start_protection(self) -> bool:
        with self._op_lock:
            if self._op_in_progress:
                return False
            self._op_in_progress = True

        def _worker_start():
            try:
                if self._yara_ctrl is None:
                    try:
                        if YaraScannerController is not None:
                            self._yara_ctrl = YaraScannerController()
                    except Exception:
                        self._yara_ctrl = None

                if self._yara_ctrl is None:
                    return

                watch_arg = self._watchlist_to_native()

                def _on_result(res_obj):
                    try:
                        is_mal = getattr(res_obj, "isMalware", False)
                    except Exception:
                        is_mal = False

                    filename = getattr(res_obj, "filename", "") or os.path.basename(
                        getattr(res_obj, "filepath", "") or ""
                    )
                    filepath = getattr(res_obj, "filepath", "") or ""
                    malware_name = getattr(res_obj, "malware_name", "") or ""
                    desc = getattr(res_obj, "desc", "") or ""

                    if is_mal:
                        title = f"Threat detected - {filename}"
                        parts = []
                        if malware_name:
                            parts.append(malware_name)
                        if desc:
                            parts.append(desc)
                        msg = " - ".join(parts) if parts else f"Detected in {filename}"

                        # Auto-quarantine if global controller exists (best-effort)
                        if global_quarantine_manager_controller:
                            try:
                                global_quarantine_manager_controller.quarantine_file(
                                    filepath, "Detected by realtime protection"
                                )
                            except Exception:
                                pass

                        try:
                            self._show_notification(title, msg, filepath)
                        except Exception:
                            pass

                try:
                    started = self._yara_ctrl.start_realtime(
                        watch_arg, callback=_on_result
                    )
                except Exception:
                    started = False

                if started:
                    with self._lock:
                        self._realtime_running = True
                        self._settings["enabled"] = True
                        self._save_settings()
            finally:
                with self._op_lock:
                    self._op_in_progress = False

        t = threading.Thread(
            target=_worker_start, daemon=True, name="RealtimeStartWorker"
        )
        self._op_thread = t
        t.start()
        return True

    def stop_protection(self) -> bool:
        with self._op_lock:
            if self._op_in_progress:
                return False
            self._op_in_progress = True

        def _worker_stop():
            try:
                with self._lock:
                    running = self._realtime_running

                if not running and self._yara_ctrl is None:
                    with self._lock:
                        self._settings["enabled"] = False
                        self._save_settings()
                    return

                try:
                    if self._yara_ctrl is not None:
                        try:
                            self._yara_ctrl.stop_realtime()
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    if self._yara_ctrl is not None:
                        self._yara_ctrl.shutdown()
                except Exception:
                    pass

                with self._lock:
                    self._realtime_running = False
                    self._settings["enabled"] = False
                    self._save_settings()
            finally:
                with self._op_lock:
                    self._op_in_progress = False

        t = threading.Thread(
            target=_worker_stop, daemon=True, name="RealtimeStopWorker"
        )
        self._op_thread = t
        t.start()
        return True

    def toggle_protection(self) -> bool:
        if self.is_protecting():
            return self.stop_protection()
        return self.start_protection()

    # -----------------------
    # Test helper
    # -----------------------
    def trigger_test_file_creation(self) -> Optional[str]:
        raw = self.get_watch_folders()
        normalized = raw.replace("|", "\n").replace(";", "\n")
        parts = [ln.strip() for ln in normalized.splitlines() if ln.strip()]
        created_any = None
        for p in parts:
            try:
                expanded = os.path.expandvars(p)
                expanded = os.path.expanduser(expanded)
                expanded = os.path.normpath(expanded)
            except Exception:
                continue
            try:
                os.makedirs(expanded, exist_ok=True)
            except Exception:
                continue
            name = f"yaratest_{uuid.uuid4().hex[:8]}.txt"
            full = os.path.join(expanded, name)
            try:
                with open(full, "wb") as f:
                    f.write(b"This is a realtime test file for yarascanner.\n")
                created_any = full
            except Exception:
                continue
        return created_any

    # -----------------------
    # Lifecycle / utilities
    # -----------------------
    def shutdown(self, wait: bool = False, timeout: Optional[float] = None) -> None:
        try:
            self.stop_protection()
        except Exception:
            pass
        if wait:
            self.wait_for_operation(timeout=timeout)
        try:
            self._yara_ctrl = None
        except Exception:
            pass

    def is_operation_in_progress(self) -> bool:
        with self._op_lock:
            return bool(self._op_in_progress)

    def wait_for_operation(self, timeout: Optional[float] = None) -> bool:
        if self._op_thread is None:
            return True
        self._op_thread.join(timeout=timeout)
        return not self._op_thread.is_alive()
