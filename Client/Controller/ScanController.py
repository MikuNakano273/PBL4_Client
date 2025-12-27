import datetime
import json
import threading
from pathlib import Path
from typing import Dict, List, Optional

from Client.Controller.HashController import get_hash_controller
from Client.Controller.YaraScannerController import YaraScannerController
from Client.Model.ScanResultList import ScanResultList
from Client.UI.scanning import ScanningDialog


class ScanController:
    def __init__(self, main_window=None):
        self.model = ScanResultList()
        self.yara_ctrl = YaraScannerController()
        self.main_window = main_window
        self.dialog: Optional[ScanningDialog] = None
        self._qm_ctrl = None
        try:
            self._hashctrl = get_hash_controller()
        except Exception:
            self._hashctrl = None
        self._hashctrl_prev_enabled = None

        self._scan_lock = threading.RLock()
        self._result_count = 0
        self._total_files = 0
        self._new_hashes: List[Dict] = []

    # ---------------------------
    # UI callback builder
    # ---------------------------
    def make_ui_callback(
        self,
        dialog: ScanningDialog,
        total_files: int,
        immediate_quarantine: bool = False,
    ):
        count = {"n": 0}  # use mutable holder for closure
        new_hashes: List[Dict] = []

        def extract_hash_info(res):
            # Basic metadata
            filename = (
                getattr(res, "filename", "") or getattr(res, "filepath", "") or ""
            )
            malware_name = getattr(res, "malware_name", "") or ""
            desc = getattr(res, "desc", "") or ""

            # Build rule_match string from matched_rules (list or str)
            matched = getattr(res, "matched_rules", None)
            if matched is None:
                rule_match = ""
            elif isinstance(matched, (list, tuple)):
                try:
                    rule_match = ", ".join(str(x) for x in matched if x is not None)
                except Exception:
                    rule_match = ""
            else:
                rule_match = str(matched)

            # Prefer explicit digest fields if present; result must be strings or empty
            md5 = getattr(res, "md5", "") or ""
            sha1 = getattr(res, "sha1", "") or ""
            sha256 = getattr(res, "sha256", "") or ""

            # Fallback: if none of explicit fields present, try heuristic single-hash detection
            if not (md5 or sha1 or sha256):
                candidates = [
                    ("hash", None),
                    ("hash_value", None),
                    ("sha256", "sha256"),
                    ("sha1", "sha1"),
                    ("md5", "md5"),
                    ("file_hash", None),
                ]
                for attr, forced_type in candidates:
                    v = getattr(res, attr, None)
                    if v:
                        v = str(v)
                        # If attribute name indicates a type, place into that slot
                        if forced_type == "md5":
                            md5 = v
                        elif forced_type == "sha1":
                            sha1 = v
                        elif forced_type == "sha256":
                            sha256 = v
                        else:
                            # unknown attribute name -> assume sha256 for compatibility
                            sha256 = v
                        break

            detected_at = datetime.datetime.now().isoformat()
            return (
                md5,
                sha1,
                sha256,
                filename,
                malware_name,
                desc,
                rule_match,
                detected_at,
            )

        def callback(res):
            # The callback may be invoked from the yarascanner worker thread.
            if res is None:
                return

            # Add to internal model for later queries
            try:
                self.model.add_result(res)
            except Exception:
                # don't let model errors break the callback
                pass

            # Compose UI row
            full_path = (
                getattr(res, "filepath", None) or getattr(res, "filename", None) or ""
            )
            try:
                display_name = (
                    Path(full_path).name
                    if full_path
                    else (getattr(res, "filename", "") or "unknown")
                )
            except Exception:
                display_name = (
                    getattr(res, "filename", "") or str(full_path) or "unknown"
                )

            is_mal = getattr(res, "isMalware", False)
            severity = (
                "MALWARE" if is_mal else (getattr(res, "severity", "INFO") or "INFO")
            )
            desc = getattr(res, "desc", "") or ""

            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            # UI-facing row may include metadata as fifth element: time, filename, severity, desc, meta
            meta = {"full_path": full_path, "record": res}
            row = [now, display_name, severity, desc, meta]

            # Emit status and log to dialog
            try:
                if is_mal:
                    try:
                        print(f"[SCAN][MALWARE] detected path: {full_path!r}")
                    except Exception:
                        pass
                try:
                    dialog.log_signal.emit(row)
                except Exception as e:
                    try:
                        import traceback

                        print(
                            f"[EMIT][ERROR] log_signal.emit failed for row={row!r}: {e}"
                        )
                        traceback.print_exc()
                    except Exception:
                        pass

            except Exception as e:
                try:
                    import traceback

                    print(f"[EMIT][ERROR] unexpected error in emit block: {e}")
                    traceback.print_exc()
                except Exception:
                    pass

            # Update progress(don't use now, changed to UI poller querying native model)
            count["n"] += 1

            # If malware, store more structured info
            try:
                if is_mal and getattr(res, "detection_source", "") == "YARA":
                    hinfo = extract_hash_info(res)
                    if hinfo:
                        (
                            md5_val,
                            sha1_val,
                            sha256_val,
                            fn,
                            mname,
                            dsc,
                            rule_match,
                            detected_at,
                        ) = hinfo

                        # Append one record per digest (preserve previous upload shape for post-scan upload)
                        for htype, hval in (
                            ("md5", md5_val),
                            ("sha1", sha1_val),
                            ("sha256", sha256_val),
                        ):
                            if not hval:
                                continue
                            try:
                                new_hashes.append(
                                    {
                                        "filename": fn,
                                        "hash_type": htype,
                                        "hash_value": hval,
                                        "malware_name": mname,
                                        "desc": dsc,
                                        "rule_match": rule_match,
                                        "detected_at": detected_at,
                                    }
                                )
                            except Exception:
                                pass

                            try:
                                if get_hash_controller is not None:
                                    get_hash_controller().add_hash_record(
                                        hval,
                                        htype,
                                        fn,
                                        rule_match or "",
                                    )
                            except Exception:
                                pass

            except Exception:
                pass

            with self._scan_lock:
                self._result_count = count["n"]
                self._new_hashes = list(new_hashes)

        return callback

    # ---------------------------
    # Delegate upload to model
    # ---------------------------
    def upload_new_hashes(self, hashes: List[Dict]) -> bool:
        if not hashes:
            return False

        try:
            if hasattr(self.model, "upload_new_hashes"):
                try:
                    return bool(self.model.upload_new_hashes(hashes))
                except Exception:
                    pass
        except Exception:
            pass

        try:
            payload = json.dumps({"new_hashes": hashes}, indent=2, ensure_ascii=False)
        except Exception:
            payload = str(hashes)

        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        try:
            # Debugging: write payload to disk
            debug_path = "C:/ProgramData/PBL4_AV_DATA/uploaded_hashes_debug.json"
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(payload)
            if self.dialog:
                try:
                    self.dialog.log_signal.emit(
                        [
                            now,
                            "---",
                            "NOTICE",
                            f"Saved upload payload to {str(debug_path)}",
                        ]
                    )
                except Exception:
                    pass
            return True
        except Exception as e:
            if self.dialog:
                try:
                    self.dialog.log_signal.emit(
                        [now, "---", "ERROR", f"Failed to prepare upload: {e}"]
                    )
                except Exception:
                    pass
            return False

    # Memory scan (removed, but keep for possible future use)
    def _run_memory_scan(self, dialog: ScanningDialog):
        return

    # ---------------------------
    # Orchestration: start / watch / finish
    # ---------------------------
    def handle_next_clicked(self, page_scan=None):
        if page_scan is None and hasattr(self.main_window, "page_scan"):
            page_scan = self.main_window.page_scan
        if not page_scan:
            return

        scan_path = page_scan.get_selected_path()
        if not scan_path:
            print("[WARN] No file or folder selected.")
            return

        scan_path = str(Path(scan_path))
        is_file = Path(scan_path).is_file()

        # Create dialog and attach to main window
        self.dialog = ScanningDialog(main_window=self.main_window)
        if hasattr(self.main_window, "content_area"):
            try:
                self.main_window.content_area.addWidget(self.dialog)
                self.main_window.content_area.setCurrentWidget(self.dialog)
            except Exception:
                pass

        # Lock UI
        try:
            self.dialog.lock_signal.emit()
        except Exception:
            pass

        total_files = 1 if is_file else 0
        try:
            if not is_file and Path(scan_path).is_dir():
                # count files with simple pattern (may be slow on large trees)
                total_files = sum(1 for _ in Path(scan_path).rglob("*.*"))
                if total_files == 0:
                    total_files = 1
        except Exception:
            total_files = 1

        immediate = False
        full_scan = False
        try:
            if page_scan is None and hasattr(self.main_window, "page_scan"):
                page_scan = self.main_window.page_scan
            if page_scan:
                if hasattr(page_scan, "get_immediate_quarantine"):
                    try:
                        immediate = bool(page_scan.get_immediate_quarantine())
                    except Exception:
                        immediate = False
                if hasattr(page_scan, "get_full_scan"):
                    try:
                        full_scan = bool(page_scan.get_full_scan())
                    except Exception:
                        full_scan = False
        except Exception:
            immediate = False
            full_scan = False

        callback = self.make_ui_callback(self.dialog, total_files, immediate)

        # Reset internal counters
        with self._scan_lock:
            self._result_count = 0
            self._total_files = total_files
            self._new_hashes = []

        started = False
        try:
            is_folder_scan = not is_file
            limit_cpu = False
            try:
                if is_folder_scan and page_scan and hasattr(page_scan, "get_limit_cpu"):
                    try:
                        limit_cpu = bool(page_scan.get_limit_cpu())
                    except Exception:
                        limit_cpu = False

                if limit_cpu:
                    try:
                        model = getattr(self.yara_ctrl, "model", None)
                        if model is not None and hasattr(model, "_scanner"):
                            scanner = getattr(model, "_scanner")
                            if hasattr(scanner, "set_throttle_duty"):
                                try:
                                    scanner.set_throttle_duty(0.5)
                                except Exception:
                                    pass
                            if hasattr(scanner, "set_throttle_max_sleep_ms"):
                                try:
                                    scanner.set_throttle_max_sleep_ms(500)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if getattr(self, "_hashctrl", None) is None:
                    try:
                        self._hashctrl = get_hash_controller()
                    except Exception:
                        self._hashctrl = None
                if self._hashctrl is not None:
                    try:
                        self._hashctrl_prev_enabled = self._hashctrl.is_enabled()
                        self._hashctrl.set_enabled(False)
                    except Exception:
                        self._hashctrl_prev_enabled = None
            except Exception:
                pass

            started = self.yara_ctrl.run_full_scan(
                scan_path, callback=callback, is_file=is_file, full_scan=full_scan
            )
        except Exception as e:
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            if self.dialog:
                try:
                    self.dialog.log_signal.emit(
                        [now, "---", "ERROR", f"Failed to start scan: {e}"]
                    )
                except Exception:
                    pass

        if not started:
            try:
                self.dialog.progress_signal.emit(100)
                self.dialog.unlock_signal.emit()
                self.dialog.scan_finished.emit()
            except Exception:
                pass
            return

        def _progress_poller():
            try:
                status_state = -1
                while True:
                    try:
                        scanning = False
                        if hasattr(self, "yara_ctrl") and self.yara_ctrl is not None:
                            try:
                                scanning = self.yara_ctrl.is_scanning()
                            except Exception:
                                scanning = False
                        if not scanning:
                            break
                    except Exception:
                        break

                    try:
                        percent = 0
                        model = getattr(self.yara_ctrl, "model", None)
                        if model is not None and hasattr(model, "get_progress"):
                            p = model.get_progress()
                            try:
                                percent = int(max(0, min(100, int(p))))
                            except Exception:
                                percent = 0
                    except Exception:
                        percent = 0

                    try:
                        if self.dialog:
                            self.dialog.progress_signal.emit(percent)

                            try:
                                status_state = (status_state + 1) % 3
                            except Exception:
                                status_state = 0
                            dots = "." * (status_state + 1)
                            try:
                                self.dialog.status_signal.emit(f"Scanning{dots}")
                            except Exception:
                                pass
                    except Exception:
                        pass

                    try:
                        threading.Event().wait(0.2)
                    except Exception:
                        break

                try:
                    if self.dialog:
                        self.dialog.progress_signal.emit(100)
                except Exception:
                    pass
            except Exception:
                pass

        try:
            poller = threading.Thread(
                target=_progress_poller,
                daemon=True,
                name="ScanProgressPoller",
            )
            poller.start()
        except Exception:
            pass

        def watcher():
            try:
                wait_ok = False
                try:
                    wait_ok = self.yara_ctrl.wait_for_scan(timeout=None)
                except Exception:
                    wait_ok = False

                if not wait_ok:
                    while True:
                        try:
                            if not self.yara_ctrl.is_scanning():
                                break
                        except Exception:
                            break
                        threading.Event().wait(0.5)
            except Exception:
                try:
                    for _ in range(10):
                        try:
                            if not self.yara_ctrl.is_scanning():
                                break
                        except Exception:
                            break
                        threading.Event().wait(0.5)
                except Exception:
                    pass

            try:
                if self.dialog:
                    self.dialog.progress_signal.emit(100)
                    self.dialog.status_signal.emit("Scan complete.")
            except Exception:
                pass

            with self._scan_lock:
                collected_hashes = list(self._new_hashes)

            if collected_hashes:
                uploaded = False
                try:
                    if hasattr(self.model, "upload_new_hashes"):
                        uploaded = bool(self.model.upload_new_hashes(collected_hashes))
                    else:
                        uploaded = self.upload_new_hashes(collected_hashes)
                except Exception:
                    uploaded = False

                now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                if not uploaded:
                    try:
                        if self.dialog:
                            self.dialog.log_signal.emit(
                                [
                                    now,
                                    "---",
                                    "WARN",
                                    "Failed to upload new hashes (placeholder).",
                                ]
                            )
                    except Exception:
                        pass
            else:
                try:
                    if self.dialog:
                        self.dialog.log_signal.emit(
                            [
                                datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                                "---",
                                "NOTICE",
                                "No new hashes collected.",
                            ]
                        )
                except Exception:
                    pass
            try:
                try:
                    if (
                        getattr(self, "_hashctrl", None) is not None
                        and self._hashctrl_prev_enabled is not None
                    ):
                        try:
                            self._hashctrl.set_enabled(
                                bool(self._hashctrl_prev_enabled)
                            )
                        except Exception:
                            # ignore restore failures
                            pass
                        # clear saved state after restore
                        self._hashctrl_prev_enabled = None
                except Exception:
                    pass

                if self.dialog:
                    self.dialog.unlock_signal.emit()
                    self.dialog.scan_finished.emit()
            except Exception:
                pass

        t = threading.Thread(target=watcher, daemon=True, name="ScanWatcher")
        t.start()

    # ---------------------------
    # Cancellation / cleanup
    # ---------------------------
    def cancel_current_scan(self):
        try:
            cancelled = False
            try:
                cancelled = self.yara_ctrl.cancel_scan(timeout=2.0)
            except Exception:
                cancelled = False

            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            if self.dialog:
                try:
                    if cancelled:
                        self.dialog.log_signal.emit(
                            [now, "---", "NOTICE", "Scan cancelled by user."]
                        )
                    else:
                        self.dialog.log_signal.emit(
                            [
                                now,
                                "---",
                                "WARN",
                                "Cancellation requested; scan may still be running.",
                            ]
                        )
                except Exception:
                    pass
        except Exception as e:
            if self.dialog:
                try:
                    self.dialog.log_signal.emit(
                        [
                            datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                            "---",
                            "ERROR",
                            f"Cancel failed: {e}",
                        ]
                    )
                except Exception:
                    pass
