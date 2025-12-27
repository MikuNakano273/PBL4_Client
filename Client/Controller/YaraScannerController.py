from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Optional

from Client.Model.YaraScannerModel import (
    DEFAULT_COMPILED_RULES,
    DEFAULT_RULES_DB,
    YaraScannerModel,
    get_global_scanner,
)

ResultCallback = Callable[[object], None]
StatusCallback = Callable[[object], None]


def _default_result_cb(res: object) -> None:
    # used to swallow results if no callback is provided
    return


class YaraScannerController:
    def __init__(self):
        self._lock = threading.RLock()
        try:
            global_model = get_global_scanner(init_if_missing=False)
        except Exception:
            global_model = None

        if global_model is not None:
            self.model = global_model
            self._owns_model = False
        else:
            self.model = YaraScannerModel()
            self._owns_model = True

        self._scan_thread: Optional[threading.Thread] = None
        self._scan_cancel_event = threading.Event()
        self._realtime_running = False
        self._stopping = False
        self._realtime_lock = threading.RLock()

    # ----------------------
    # Scan (core + extended) - asynchronous with cancellation
    # ----------------------
    def _run_scan_worker(
        self,
        path: str,
        callback: Optional[ResultCallback],
        is_file: bool,
        full_scan: bool = False,
    ) -> None:
        cb = callback or _default_result_cb
        try:
            print("[Controller] Worker: starting scan")
            if self._scan_cancel_event.is_set():
                print("[Controller] Worker: cancelled before scan")
                return

            try:
                if not getattr(self.model, "_initialized", False):
                    self.model.init(DEFAULT_COMPILED_RULES, DEFAULT_RULES_DB)
            except Exception as e:
                print(f"[Controller] Worker: init failed (continuing): {e}")

            try:
                if full_scan and hasattr(self.model, "_scanner"):
                    try:
                        setattr(self.model._scanner, "full_scan_override", True)
                    except Exception:
                        try:
                            if hasattr(self.model._scanner, "set_full_scan"):
                                try:
                                    self.model._scanner.set_full_scan(True)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass

            # Perform the scan (file or folder)
            try:
                if is_file or Path(path).is_file():
                    self.model.scan_file(path, cb)
                else:
                    self.model.scan_folder(path, cb)
            except Exception as e:
                print(f"[Controller] scan error: {e}")

            print("[Controller] Worker: scan complete")
        finally:
            try:
                if hasattr(self.model, "_scanner"):
                    try:
                        if getattr(self.model._scanner, "full_scan_override", False):
                            try:
                                setattr(
                                    self.model._scanner, "full_scan_override", False
                                )
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

            with self._lock:
                self._scan_thread = None
                self._scan_cancel_event.clear()

    def run_full_scan(
        self,
        path: str,
        callback: Optional[ResultCallback] = None,
        is_file: bool = False,
        full_scan: bool = False,
    ) -> bool:
        with self._lock:
            if self.is_scanning():
                print("[Controller] run_full_scan: scan already in progress")
                return False

            self._scan_cancel_event.clear()
            worker = threading.Thread(
                target=self._run_scan_worker,
                args=(path, callback, is_file, full_scan),
                daemon=True,
                name="YaraScanWorker",
            )
            self._scan_thread = worker
            worker.start()
            print(f"[Controller] run_full_scan: started thread {worker.name}")
            return True

    def is_scanning(self) -> bool:
        with self._lock:
            return self._scan_thread is not None and self._scan_thread.is_alive()

    def cancel_scan(self, timeout: Optional[float] = 5.0) -> bool:
        with self._lock:
            if not self.is_scanning():
                print("[Controller] cancel_scan: no active scan to cancel")
                return False
            print("[Controller] cancel_scan: requesting cancellation")
            self._scan_cancel_event.set()

            try:
                self.model.shutdown()
            except Exception as e:
                print(f"[Controller] cancel_scan: model.shutdown raised: {e}")

            thread = self._scan_thread

        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                print("[Controller] cancel_scan: worker did not exit within timeout")
                return False
            else:
                print("[Controller] cancel_scan: worker stopped")
                return True
        return False

    def wait_for_scan(self, timeout: Optional[float] = None) -> bool:
        thread = None
        with self._lock:
            thread = self._scan_thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()

    # ----------------------
    # Realtime start / stop
    # ----------------------
    def start_realtime(
        self,
        watch_arg: str,
        callback: Optional[ResultCallback] = None,
        status_cb: Optional[StatusCallback] = None,
    ) -> bool:
        with self._realtime_lock:
            if self._realtime_running:
                print("[Controller] start_realtime: realtime already running")
                return False
            if getattr(self, "_stopping", False):
                print("[Controller] start_realtime: stop in progress, cannot start yet")
                return False

            try:
                ok = self.model.init(
                    DEFAULT_COMPILED_RULES, DEFAULT_RULES_DB, status_cb
                )
                if not ok:
                    print("[Controller] start_realtime: model.init failed")
                    return False
            except Exception as e:
                print(f"[Controller] start_realtime: init raised: {e}")
                return False

            cb = callback or _default_result_cb
            try:
                ok = self.model.start_realtime(watch_arg, cb)
            except Exception as e:
                print(f"[Controller] start_realtime: model.start_realtime raised: {e}")
                try:
                    self.model.shutdown()
                except Exception:
                    pass
                return False

            if not ok:
                print(
                    "[Controller] start_realtime: model.start_realtime returned False - not starting"
                )
                try:
                    if getattr(self, "_owns_model", False):
                        self.model.shutdown()
                except Exception:
                    pass
                return False

            self._realtime_running = True
            print("[Controller] start_realtime: realtime monitoring started")
            return True

    def stop_realtime(self) -> bool:
        with self._realtime_lock:
            if not self._realtime_running and not getattr(self, "_stopping", False):
                print("[Controller] stop_realtime: realtime not running")
                return False
            if getattr(self, "_stopping", False):
                print("[Controller] stop_realtime: stop already in progress")
                return False

            print("[Controller] stop_realtime: scheduling realtime stop")
            self._stopping = True
            self._realtime_running = False
            model_ref = self.model

        def _stop_worker(m, owns):
            try:
                try:
                    m.stop_realtime()
                except Exception as e:
                    print(
                        f"[Controller] stop_realtime: model.stop_realtime raised: {e}"
                    )
                if owns:
                    try:
                        m.shutdown()
                    except Exception as e:
                        print(f"[Controller] stop_realtime: model.shutdown raised: {e}")
            finally:
                with self._realtime_lock:
                    try:
                        self._stopping = False
                    except Exception:
                        pass

        t = threading.Thread(
            target=_stop_worker,
            args=(model_ref, getattr(self, "_owns_model", False)),
            daemon=True,
            name="YaraStopRealtime",
        )
        t.start()
        print("[Controller] stop_realtime: stop scheduled (background)")
        return True

    def is_realtime_running(self) -> bool:
        with self._realtime_lock:
            return self._realtime_running

    # ----------------------
    # Cleanup
    # ----------------------
    def shutdown(self) -> None:
        print("[Controller] shutdown: begin")
        try:
            self.cancel_scan(timeout=2.0)
        except Exception as e:
            print(f"[Controller] shutdown: cancel_scan error: {e}")

        try:
            self.stop_realtime()
        except Exception as e:
            print(f"[Controller] shutdown: stop_realtime error: {e}")

        try:
            waited = 0.0
            wait_step = 0.1
            max_wait = 5.0
            while getattr(self, "_stopping", False) and waited < max_wait:
                time.sleep(wait_step)
                waited += wait_step
            if getattr(self, "_owns_model", False):
                try:
                    self.model.shutdown()
                except Exception as e:
                    print(f"[Controller] shutdown: model.shutdown error: {e}")
            else:
                print(
                    "[Controller] shutdown: shared/global model detected - skipping shutdown"
                )
        except Exception as e:
            print(f"[Controller] shutdown: error during shutdown sequence: {e}")

        print("[Controller] shutdown: complete")
