import csv
import os
from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from Client.Controller.QuarantineManagerController import (
    global_quarantine_manager_controller,
)
from Client.UI.scan_options import ScanOptionsPage


class ScanningDialog(QWidget):
    log_signal = Signal(object)  # Nhận data từ YaraController
    progress_signal = Signal(int)  # Nhận % tiến độ
    status_signal = Signal(str)  # Nhận thông tin status scanning (file/current step)
    scan_finished = Signal()
    stop_signal = Signal()
    unlock_signal = Signal()
    lock_signal = Signal()

    def __init__(self, main_window=None):
        super().__init__()
        self.main_window = main_window
        self.dialog_layout = None
        self.table = None
        self.init_ui()

        # Connect signals
        self.log_signal.connect(self.add_row_to_table)
        self.progress_signal.connect(self.update_progress)
        self.status_signal.connect(self.update_status)
        self.unlock_signal.connect(self.unlock_ui)
        self.lock_signal.connect(self.lock_ui)

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.dialog_layout = layout

        layout.addWidget(QLabel("<h3>Scan Output</h3>"))

        # --- Progress Bar ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress_bar)

        # --- Status Label ---
        self.status_label = QLabel("Ready.")
        self.status_label.setStyleSheet("color: #0077cc; font-weight: bold;")
        layout.addWidget(self.status_label)

        # --- QTableWidget ---
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Time", "File", "Severity", "Rule/Description", "Action"]
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(False)
        layout.addWidget(self.table)

        # --- Buttons Save / Back ---
        btn_layout = QHBoxLayout()
        self.btn_save = QPushButton("Save")
        self.btn_process = QPushButton("Quarantine selected file(s)")
        self.btn_back = QPushButton("Back")
        btn_layout.addWidget(self.btn_save)
        btn_layout.addWidget(self.btn_process)
        btn_layout.addWidget(self.btn_back)
        layout.addLayout(btn_layout)

        self.btn_save.clicked.connect(self.export_csv)
        self.btn_process.clicked.connect(self.process_selected)
        self.btn_back.clicked.connect(self.go_back)
        # Allow double-click on a table item to show full record details
        try:
            self.table.itemDoubleClicked.connect(self._on_item_double_clicked)
        except Exception:
            # Best-effort: do not fail UI init if connection can't be made
            pass

    # ------------------------------------------------------
    #             TABLE UPDATE
    # ------------------------------------------------------
    def add_row_to_table(self, data: list):
        # Accept 4 or 5 element payloads (5th element is optional full_path)
        if not (len(data) == 4 or len(data) == 5):
            print(f"[ERROR] Invalid scan data: {data}")
            return

        row_pos = self.table.rowCount()
        self.table.insertRow(row_pos)

        # If metadata provided, separate it out. 'meta' may be a dict {'full_path':..., 'record':...}
        # or it may be a plain full_path string. Normalize into both `meta` and `full_path`.
        meta = None
        full_path = None
        if len(data) == 5:
            time_val, filename_val, severity_val, desc_val, meta = data
            if isinstance(meta, dict):
                full_path = meta.get("full_path") or None
            else:
                full_path = meta
            items = [time_val, filename_val, severity_val, desc_val]
        else:
            items = data

        for i, item in enumerate(items):
            twi = QTableWidgetItem(item)
            if i == 1:
                try:
                    if isinstance(meta, dict):
                        twi.setData(Qt.UserRole, meta)
                    elif full_path:
                        twi.setData(Qt.UserRole, full_path)
                except Exception:
                    pass
            self.table.setItem(row_pos, i, twi)

        severity = items[2].lower()
        if "malware" in severity or "high" in severity or "infected" in severity:
            chk = QCheckBox()
            chk.setToolTip("Select this row for quarantine/restore action")
            try:
                chk.setStyleSheet(
                    "QCheckBox::indicator { width: 16px; height: 16px; }"
                    "QCheckBox::indicator:unchecked { background-color: transparent; border: 1px solid #4a4a4a; border-radius: 3px; }"
                    "QCheckBox::indicator:checked { background-color: #09eb49; border: 1px solid #09eb49; border-radius: 3px; }"
                )
            except Exception:
                pass
            self.table.setCellWidget(row_pos, 4, chk)
        else:
            self.table.setItem(row_pos, 4, QTableWidgetItem(""))

        self.table.scrollToBottom()

    def store_metadata_for_last_row(self, meta: dict):
        try:
            if not isinstance(meta, dict):
                return
            row = self.table.rowCount() - 1
            if row < 0:
                return
            file_item = self.table.item(row, 1)
            if file_item is None:
                file_item = QTableWidgetItem("")
                self.table.setItem(row, 1, file_item)
            try:
                try:
                    print(f"[UI][STORE_META] storing meta for row={row}: {meta!r}")
                except Exception:
                    pass
                file_item.setData(Qt.UserRole, meta)
            except Exception:
                pass
        except Exception:
            pass

    def delete_file_from_button(self, button):
        index = self.table.indexAt(button.pos())
        row = index.row()
        self.delete_file(row)

    def delete_file(self, row: int):
        file_item = self.table.item(row, 1)
        if not file_item:
            QMessageBox.warning(self, "Error", "Không tìm thấy tên file.")
            return
        filename = file_item.text()

        # Lấy root path từ UI scan options
        root_path = ""
        if self.main_window and hasattr(self.main_window, "page_scan"):
            root_path = self.main_window.page_scan.get_selected_path()

        if os.path.isdir(root_path):
            full_path = os.path.join(root_path, filename)
        else:
            full_path = root_path

        if not os.path.exists(full_path):
            QMessageBox.warning(self, "Warning", f"File không tồn tại:\n{full_path}")
            return

        reply = QMessageBox.question(
            self,
            "Delete File",
            f"Bạn có chắc muốn xoá file này không?\n\n{full_path}",
            QMessageBox.Yes | QMessageBox.Cancel,
        )

        if reply == QMessageBox.Yes:
            try:
                os.remove(full_path)
                QMessageBox.information(self, "Deleted", f"Đã xoá file:\n{full_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Lỗi khi xoá file:\n{e}")

    def process_selected(self):
        immediate = False
        if self.main_window and hasattr(self.main_window, "page_scan"):
            try:
                immediate = bool(self.main_window.page_scan.get_immediate_quarantine())
            except Exception:
                immediate = False

        action = "restore" if immediate else "quarantine"

        # Collect selected rows
        selected_rows = []
        for r in range(self.table.rowCount()):
            widget = self.table.cellWidget(r, 4)
            if isinstance(widget, QCheckBox) and widget.isChecked():
                selected_rows.append(r)

        if not selected_rows:
            QMessageBox.information(self, "No selection", "No rows selected.")
            return

        reply = QMessageBox.question(
            self,
            f"Confirm {action.title()}",
            f"Are you sure you want to {action} selected file(s)?",
            QMessageBox.Yes | QMessageBox.Cancel,
        )

        if reply != QMessageBox.Yes:
            return

        self.lock_ui()

        try:
            for r in sorted(selected_rows, reverse=True):
                file_item = self.table.item(r, 1)
                filename = file_item.text() if file_item else ""
                try:
                    userrole_preview = (
                        file_item.data(Qt.UserRole) if file_item is not None else None
                    )
                    print(
                        f"[UI][PROCESS_SELECTED][DEBUG] row={r} filename={filename!r} userrole_preview={userrole_preview!r}"
                    )
                except Exception:
                    pass
                stored_full = None
                try:
                    if file_item is not None:
                        stored_full = file_item.data(Qt.UserRole)
                except Exception:
                    stored_full = None

                root_path = ""
                if self.main_window and hasattr(self.main_window, "page_scan"):
                    root_path = self.main_window.page_scan.get_selected_path()

                full_path = ""
                try:
                    if isinstance(stored_full, dict):
                        fp = (
                            stored_full.get("full_path")
                            or stored_full.get("stored_path")
                            or stored_full.get("path")
                            or stored_full.get("fullpath")
                        )
                        if not fp:
                            rec = stored_full.get("record")
                            try:
                                fp = getattr(rec, "file", None) or getattr(
                                    rec, "filename", None
                                )
                            except Exception:
                                fp = None
                        if fp:
                            full_path = str(fp)
                    elif isinstance(stored_full, str):
                        full_path = stored_full
                    else:
                        full_path = ""
                except Exception:
                    full_path = ""

                if not full_path:
                    if os.path.isdir(root_path):
                        full_path = os.path.join(root_path, filename)
                    else:
                        full_path = root_path

                try:
                    if action == "quarantine":
                        try:
                            print(
                                f"[PROCESS_SELECTED][QUARANTINE] requesting quarantine for: {full_path}"
                            )
                        except Exception:
                            pass
                        if global_quarantine_manager_controller:
                            try:
                                res = global_quarantine_manager_controller.quarantine_file(
                                    full_path
                                )
                            except Exception as e:
                                res = {"status": "error", "message": str(e)}
                        else:
                            res = {
                                "status": "error",
                                "message": "Quarantine manager not available",
                            }

                        status = res.get("status", "").lower()
                        if status.startswith("quarantined") or status == "quarantined":
                            # remove row from table after successful quarantine
                            self.table.removeRow(r)
                        else:
                            # show result in description column
                            self.table.setItem(
                                r,
                                3,
                                QTableWidgetItem(
                                    f"Quarantine result: {res.get('message', '')}"
                                ),
                            )

                    else:  # restore (option removed, might be re-added later)
                        stored = None
                        try:
                            stored = file_item.data(Qt.UserRole)
                        except Exception:
                            stored = None
                        if not stored:
                            stored = filename

                        if global_quarantine_manager_controller:
                            try:
                                res = global_quarantine_manager_controller.restore_file(
                                    stored
                                )
                            except Exception as e:
                                res = {"status": "error", "message": str(e)}
                        else:
                            res = {
                                "status": "error",
                                "message": "Quarantine manager not available",
                            }

                        if res.get("status") == "restored":
                            restored_to = (
                                res.get("restored_to") or res.get("message") or ""
                            )
                            try:
                                if global_quarantine_manager_controller:
                                    global_quarantine_manager_controller.whitelist_file(
                                        restored_to
                                    )
                            except Exception:
                                pass
                            self.table.removeRow(r)
                        else:
                            self.table.setItem(
                                r,
                                3,
                                QTableWidgetItem(
                                    f"Restore result: {res.get('message', '')}"
                                ),
                            )

                except Exception as e:
                    self.table.setItem(r, 3, QTableWidgetItem(f"Error: {e}"))
        finally:
            self.unlock_ui()

    # ------------------------------------------------------
    #             Record details (double-click)
    # ------------------------------------------------------
    def _on_item_double_clicked(self, item):
        try:
            row = item.row()
            self.show_record_details(row)
        except Exception:
            pass

    def show_record_details(self, row: int):
        try:

            def _cell(cidx):
                try:
                    itm = self.table.item(row, cidx)
                    return itm.text() if itm is not None else ""
                except Exception:
                    return ""

            time_txt = _cell(0)
            file_txt = _cell(1)
            severity_txt = _cell(2)
            desc_txt = _cell(3)

            stored_meta = None
            try:
                file_item = self.table.item(row, 1)
                if file_item is not None:
                    try:
                        stored_meta = file_item.data(Qt.UserRole)
                    except Exception:
                        stored_meta = file_item.text() or None
            except Exception:
                stored_meta = None

            meta_dict = {}
            path_val = ""
            sha256 = sha1 = md5 = ""
            try:
                if isinstance(stored_meta, dict):
                    meta_dict = stored_meta.copy()
                    path_val = meta_dict.get("full_path") or ""
                    rec = meta_dict.get("record")
                    if isinstance(rec, dict):
                        path_val = (
                            path_val
                            or rec.get("filepath")
                            or rec.get("full_path")
                            or ""
                        )
                    sha256 = meta_dict.get("sha256") or ""
                    sha1 = meta_dict.get("sha1") or ""
                    md5 = meta_dict.get("md5") or ""
                    if not sha256 and isinstance(rec, dict):
                        sha256 = rec.get("sha256") or ""
                        sha1 = sha1 or rec.get("sha1") or ""
                        md5 = md5 or rec.get("md5") or ""
                else:
                    rec = stored_meta
                    try:
                        if hasattr(rec, "to_dict") and callable(
                            getattr(rec, "to_dict")
                        ):
                            meta_dict = rec.to_dict() or {}
                        else:
                            meta_dict = {}
                            for attr in (
                                "filepath",
                                "full_path",
                                "filename",
                                "sha256",
                                "sha1",
                                "md5",
                                "desc",
                            ):
                                try:
                                    val = getattr(rec, attr, None)
                                    if val:
                                        meta_dict[attr] = val
                                except Exception:
                                    pass
                    except Exception:
                        meta_dict = {}
                    if isinstance(stored_meta, str) and stored_meta:
                        path_val = stored_meta
                    else:
                        path_val = (
                            meta_dict.get("filepath")
                            or meta_dict.get("full_path")
                            or ""
                        )
                        sha256 = meta_dict.get("sha256") or ""
                        sha1 = meta_dict.get("sha1") or ""
                        md5 = meta_dict.get("md5") or ""
            except Exception:
                try:
                    if isinstance(stored_meta, str):
                        path_val = stored_meta
                    else:
                        path_val = ""
                except Exception:
                    path_val = ""

            hashes = ", ".join(
                x
                for x in (
                    ("sha256:" + sha256) if sha256 else None,
                    ("sha1:" + sha1) if sha1 else None,
                    ("md5:" + md5) if md5 else None,
                )
                if x
            )
            if not hashes:
                hashes = "N/A"

            dlg = QDialog(self)
            dlg.setWindowTitle("Record Details")
            dlg.resize(700, 320)
            main_layout = QVBoxLayout(dlg)

            try:
                lbl_time = QLabel(f"<b>Time:</b> {time_txt}")
                lbl_file = QLabel(f"<b>File:</b> {file_txt}")
                lbl_sev = QLabel(f"<b>Severity:</b> {severity_txt}")
                lbl_desc = QLabel(f"<b>Rule/Description:</b> {desc_txt}")
                lbl_path = QLabel(f"<b>Path:</b> {path_val or '(unknown)'}")

                for w in (lbl_time, lbl_file, lbl_sev, lbl_desc, lbl_path):
                    w.setWordWrap(True)
                    main_layout.addWidget(w)
            except Exception:
                pass

            raw_box = QTextEdit()
            raw_box.setReadOnly(True)
            raw_box.setVisible(False)
            try:
                import json

                pretty = ""
                if isinstance(meta_dict, dict) and meta_dict:
                    try:
                        pretty = json.dumps(meta_dict, indent=2, ensure_ascii=False)
                    except Exception:
                        pretty = str(meta_dict)
                else:
                    try:
                        pretty = str(stored_meta)
                    except Exception:
                        pretty = ""
                raw_box.setPlainText(pretty)
            except Exception:
                try:
                    raw_box.setPlainText(str(stored_meta or ""))
                except Exception:
                    raw_box.setPlainText("")

            main_layout.addWidget(raw_box, 1)

            btn_row = QHBoxLayout()
            btn_toggle = QPushButton("Show raw metadata")
            btn_toggle.setCheckable(True)

            def _toggle_raw(checked):
                try:
                    raw_box.setVisible(bool(checked))
                    btn_toggle.setText(
                        "Hide raw metadata" if checked else "Show raw metadata"
                    )
                except Exception:
                    pass

            btn_toggle.toggled.connect(_toggle_raw)

            btn_close = QPushButton("Close")
            btn_close.clicked.connect(dlg.accept)
            btn_row.addWidget(btn_toggle)
            btn_row.addStretch()
            btn_row.addWidget(btn_close)
            main_layout.addLayout(btn_row)

            dlg.exec()
        except Exception as e:
            try:
                QMessageBox.warning(self, "Error", f"Failed to show details: {e}")
            except Exception:
                pass

    # ------------------------------------------------------
    #             PROGRESS + STATUS UPDATE
    # ------------------------------------------------------
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)

    def update_status(self, text: str):
        self.status_label.setText(text)

    # ------------------------------------------------------
    #             UI CONTROL
    # ------------------------------------------------------
    def go_back(self):
        if self.main_window is None:
            QMessageBox.critical(self, "Error", "Main window reference is missing!")
            return
        mw = self.main_window
        if (
            hasattr(mw, "content_area")
            and hasattr(mw, "page_scan")
            and hasattr(mw, "menu")
        ):
            mw.content_area.setCurrentWidget(mw.page_scan)
            mw.menu.setCurrentRow(1)
        else:
            QMessageBox.critical(self, "Error", "Content area or page_scan not found!")

    def lock_ui(self):
        if self.main_window and hasattr(self.main_window, "menu"):
            self.main_window.menu.setDisabled(True)
        self.btn_save.setEnabled(False)
        self.btn_back.setEnabled(False)

    def unlock_ui(self):
        if self.main_window and hasattr(self.main_window, "menu"):
            self.main_window.menu.setDisabled(False)
        self.btn_save.setEnabled(True)
        self.btn_back.setEnabled(True)

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Log", "", "CSV files (*.csv);;All files (*.*)"
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["YARA Scan Report"])
                writer.writerow(
                    ["Exported at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
                )
                writer.writerow([])
                writer.writerow(
                    ["#", "File Path", "Severity", "Rule/Description", "Date/Time"]
                )

                for r in range(self.table.rowCount()):
                    row_data = []
                    for c in range(
                        self.table.columnCount() - 1
                    ):  # không xuất nút Delete
                        item = self.table.item(r, c)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)

            QMessageBox.information(
                self, "Saved", f"Log file đã được lưu thành công:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Không thể lưu file log:\n{e}")
