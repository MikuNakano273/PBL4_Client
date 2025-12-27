from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Controller import (may be missing in some environments)
try:
    from Client.Controller.HistoryController import HistoryController
except Exception as e:
    print("HistoryController import failed:", e)
    HistoryController = None


class ProtectionHistoryDialog(QDialog):
    RIGHT_COLUMN_WIDTH = 140
    INNER_PADDING = 6
    CONTENT_RADIUS = 4
    CARD_HORIZONTAL_PADDING = 24

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Protection / Quarantine History")
        self.resize(920, 640)

        # controller
        if HistoryController is None:
            QMessageBox.critical(
                self,
                "Missing controller",
                "HistoryController not available. The protection history UI requires it.",
            )
            self.controller = None
        else:
            self.controller = HistoryController()

        # state
        self._row_widgets: Dict[int, Dict[str, Any]] = {}
        self._loading_in_progress = False

        # auto-refresh timer (5s)
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(5000)
        self._auto_timer.timeout.connect(self._on_auto_refresh)

        # restored dialog (created on demand)
        self._restored_dialog: Optional["RestoredHistoryDialog"] = None

        # build UI and initial load
        self._build_ui()
        # initial load
        try:
            self.load_data()
        except Exception:
            # swallow to avoid breaking startup
            pass

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)

        header = QLabel("<h2>Protection / Quarantine History</h2>")
        main_layout.addWidget(header)

        # Selected count
        self.selected_count_label = QLabel("Selected: 0")
        self.selected_count_label.setStyleSheet("color: #ffd43b; font-weight: bold;")
        main_layout.addWidget(self.selected_count_label)

        # Actions row: Refresh | Show Restored | (spacer) | Restore selected | Delete selected
        actions = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_show_restored = QPushButton("Show Restored")
        self.btn_clear_selection = QPushButton("Clear selected")
        self.btn_restore = QPushButton("Restore selected")
        self.btn_delete = QPushButton("Delete selected")

        actions.addWidget(self.btn_refresh)
        actions.addWidget(self.btn_show_restored)
        actions.addWidget(self.btn_clear_selection)
        actions.addStretch()
        actions.addWidget(self.btn_restore)
        actions.addWidget(self.btn_delete)

        main_layout.addLayout(actions)

        # Scroll area for cards
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_contents = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_contents)
        self.scroll_layout.setSpacing(8)
        self.scroll_layout.setContentsMargins(6, 6, 6, 6)
        self.scroll.setWidget(self.scroll_contents)
        main_layout.addWidget(self.scroll)

        # Connect signals
        self.btn_refresh.clicked.connect(self.trigger_refresh)
        self.btn_show_restored.clicked.connect(self.open_restored_view)
        self.btn_clear_selection.clicked.connect(self.clear_selection)
        self.btn_restore.clicked.connect(self.restore_selected)
        self.btn_delete.clicked.connect(self.delete_selected)

        # Restored overlay (hidden by default) - a simple in-dialog overlay that sits on top
        # of the history view. This provides a read-only "restored" view with a back button.
        try:
            self._restored_overlay = QFrame(self)
            self._restored_overlay.setFrameShape(QFrame.NoFrame)
            # semi-opaque dark background so it visually sits on top
            self._restored_overlay.setStyleSheet(
                "background: rgba(0,0,0,0.95); color: #f0f0f0; border: none;"
            )
            self._restored_overlay.setVisible(False)
            overlay_layout = QVBoxLayout(self._restored_overlay)
            overlay_layout.setContentsMargins(12, 12, 12, 12)

            overlay_header = QHBoxLayout()
            overlay_label = QLabel("<h2>Restored Protection History</h2>")
            btn_back = QPushButton("Back to History")
            btn_back.setFixedWidth(140)
            btn_back.clicked.connect(lambda: self._hide_restored_overlay())
            overlay_header.addWidget(overlay_label)
            overlay_header.addStretch()
            overlay_header.addWidget(btn_back)
            overlay_layout.addLayout(overlay_header)

            # Minimal informational area (read-only)
            info = QLabel(
                "This view shows restored quarantine records (read-only). Use the back button to return to the main history."
            )
            info.setStyleSheet("color: #bdbdbd; padding: 8px;")
            info.setWordWrap(True)
            overlay_layout.addWidget(info)

            # Scroll area for restored items (read-only list)
            self._restored_scroll = QScrollArea(self._restored_overlay)
            self._restored_scroll.setWidgetResizable(True)
            self._restored_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self._restored_contents = QWidget()
            self._restored_layout = QVBoxLayout(self._restored_contents)
            self._restored_layout.setSpacing(8)
            self._restored_layout.setContentsMargins(6, 6, 6, 6)
            self._restored_scroll.setWidget(self._restored_contents)
            overlay_layout.addWidget(self._restored_scroll)

            # Ensure overlay covers the dialog area when shown
            try:
                self._restored_overlay.setGeometry(self.rect())
            except Exception:
                pass
            self._restored_overlay.setSizePolicy(
                QSizePolicy.Expanding, QSizePolicy.Expanding
            )
            self._restored_overlay.raise_()
        except Exception:
            # Best-effort: if overlay creation fails, fall back to original behavior when possible
            try:
                self._restored_overlay = None
            except Exception:
                self._restored_overlay = None

    # -----------------
    # Data operations
    # -----------------
    def _clear_list(self) -> None:
        # Remove existing widgets from layout
        for i in reversed(range(self.scroll_layout.count())):
            item = self.scroll_layout.takeAt(i)
            w = item.widget()
            if w:
                try:
                    w.setParent(None)
                except Exception:
                    pass
        self._row_widgets.clear()

    def load_data(self) -> None:
        # 1. Lưu lại các ID đang được chọn trước khi xóa list
        prev_selected_ids = {
            rid for rid, p in self._row_widgets.items() if p.get("selected")
        }

        self._clear_list()

        if self.controller is None:
            QMessageBox.critical(self, "Error", "No HistoryController available.")
            return

        try:
            rows = self.controller.list_quarantined()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Could not load quarantine records:\n{e}"
            )
            return

        # Filter to non-restored only
        try:
            rows = [r for r in rows if not bool(r.get("restored"))]
        except Exception:
            pass

        if not rows:
            empty = QLabel("No quarantine records found.")
            empty.setStyleSheet("color: gray; padding: 12px;")
            self.scroll_layout.addWidget(empty)
            # Cập nhật lại label đếm số lượng về 0 nếu danh sách trống
            self._update_selected_count()
            return

        for rec in rows:
            rec_id = int(rec.get("id"))
            wrapper = self._create_row_wrapper(rec)
            self.scroll_layout.addWidget(wrapper)

            # 2. Nếu ID này nằm trong danh sách đã chọn trước đó, hãy tick lại nó
            if rec_id in prev_selected_ids:
                self._on_row_toggled(rec_id, True)

        # spacer to push items to top
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.scroll_layout.addWidget(spacer)

        self._elide_all_titles()

        # 3. Cập nhật lại con số hiển thị trên label "Selected: X"
        self._update_selected_count()

    # -----------------
    # Card UI creation
    # -----------------
    def _create_row_wrapper(self, rec: Dict[str, Any]) -> QWidget:
        rec_id = int(rec.get("id"))

        wrapper = QFrame()
        wrapper.setFrameShape(QFrame.NoFrame)
        wrapper_layout = QHBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)
        wrapper.setAttribute(Qt.WA_StyledBackground, True)
        wrapper.setStyleSheet("background: transparent; border: none;")

        pad_frame = QFrame()
        pad_frame.setFrameShape(QFrame.NoFrame)
        pad_layout = QHBoxLayout(pad_frame)
        pad_layout.setContentsMargins(
            self.INNER_PADDING,
            self.INNER_PADDING,
            self.INNER_PADDING,
            self.INNER_PADDING,
        )
        pad_layout.setSpacing(0)
        pad_frame.setStyleSheet("background: transparent;")
        pad_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        content_frame = QFrame()
        content_frame.setFrameShape(QFrame.NoFrame)
        content_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        content_frame.setStyleSheet(
            f"""
            background: #111217;
            color: #f0f0f0;
            border-radius: {self.CONTENT_RADIUS}px;
            padding: 8px;
            """
        )

        content_layout = QHBoxLayout(content_frame)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)

        # Title + subtitle
        main_v = QVBoxLayout()
        main_v.setSpacing(2)

        original_path = rec.get("original_path") or ""
        stored_name = rec.get("stored_filename") or ""
        display_name = (
            os.path.basename(original_path)
            if original_path
            else (stored_name or "(unknown)")
        )

        title_label = QLabel(display_name)
        title_label.setObjectName("title")
        title_label.setStyleSheet("font-weight: bold; font-size: 14.5pt;")
        title_label.setWordWrap(False)
        title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        qtime = rec.get("quarantined_at") or ""
        note = rec.get("note") or ""
        subtitle_text = f"{qtime}"
        if note:
            subtitle_text += " — " + str(note)
        sub_label = QLabel(subtitle_text)
        sub_label.setObjectName("sub")
        sub_label.setWordWrap(True)
        sub_label.setStyleSheet("margin-top:4px; color: #bdbdbd; font-size: 9pt;")

        main_v.addWidget(title_label)
        main_v.addWidget(sub_label)
        content_layout.addLayout(main_v, 1)

        # Right column (See detail + meta)
        right_col = QVBoxLayout()
        right_col.setSpacing(6)
        right_col.setContentsMargins(0, 0, 0, 0)

        btn_detail = QPushButton("See detail")
        btn_detail.setFocusPolicy(Qt.NoFocus)
        btn_detail.setFixedWidth(96)

        meta_label = QLabel(
            f"Size: {rec.get('stored_size') or 0} B\nRestored: {'Yes' if rec.get('restored') else 'No'}"
        )
        meta_label.setStyleSheet("color: #bdbdbd; font-size: 9pt;")
        meta_label.setAlignment(Qt.AlignRight)

        btn_detail.clicked.connect(lambda _checked, r=rec: self._show_detail_dialog(r))

        right_col.addWidget(btn_detail, alignment=Qt.AlignRight)
        right_col.addWidget(meta_label, alignment=Qt.AlignRight)

        right_widget = QWidget()
        right_widget.setLayout(right_col)
        right_widget.setFixedWidth(self.RIGHT_COLUMN_WIDTH)
        right_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)

        content_layout.addWidget(right_widget)

        pad_layout.addWidget(content_frame)
        wrapper_layout.addWidget(pad_frame, 1)

        # Click handling: toggle selection (ignore detail button)
        def _row_mouse_release(event, rid=rec_id, detail_btn=btn_detail):
            try:
                if detail_btn and detail_btn.underMouse():
                    return
            except Exception:
                pass
            parts = self._row_widgets.get(rid)
            if parts:
                checked = not bool(parts.get("selected"))
                self._on_row_toggled(rid, checked)

        wrapper.mouseReleaseEvent = _row_mouse_release
        wrapper.setCursor(Qt.PointingHandCursor)

        # store refs
        self._row_widgets[rec_id] = {
            "wrapper": wrapper,
            "pad_frame": pad_frame,
            "content_frame": content_frame,
            "title_label": title_label,
            "sub_label": sub_label,
            "detail_button": btn_detail,
            "record": rec,
            "full_title": display_name,
            "selected": False,
        }

        return wrapper

    def _on_row_toggled(self, rec_id: int, checked: bool) -> None:
        parts = self._row_widgets.get(rec_id)
        if not parts:
            return
        pad_frame: QFrame = parts.get("pad_frame")
        accent_color = "#ffd43b"
        parts["selected"] = bool(checked)
        if checked:
            pad_frame.setStyleSheet(
                f"background: {accent_color}; border-radius: {self.CONTENT_RADIUS + self.INNER_PADDING}px;"
            )
        else:
            pad_frame.setStyleSheet("background: transparent;")

        wrapper = parts.get("wrapper")
        if wrapper:
            wrapper.update()
        try:
            self._update_selected_count()
        except Exception:
            pass

    def _update_selected_count(self) -> None:
        try:
            cnt = sum(1 for p in self._row_widgets.values() if p.get("selected"))
            if hasattr(self, "selected_count_label") and self.selected_count_label:
                self.selected_count_label.setText(f"Selected: {cnt}")
        except Exception:
            pass

    # -----------------------
    # Scrolling + blink helpers
    # -----------------------
    def scroll_to_record(
        self, rec_id: int, blink_times: int = 4, blink_interval: int = 250
    ) -> bool:
        parts = self._row_widgets.get(rec_id)
        if not parts:
            return False
        wrapper = parts.get("wrapper")
        pad_frame = parts.get("pad_frame")
        if wrapper is None or pad_frame is None:
            return False

        try:
            try:
                self.scroll.ensureWidgetVisible(wrapper)
            except Exception:
                vbar = self.scroll.verticalScrollBar()
                try:
                    y = wrapper.y()
                except Exception:
                    y = 0
                try:
                    vbar.setValue(max(0, y - 20))
                except Exception:
                    pass
        except Exception:
            pass

        try:
            self._start_blink(rec_id, blink_times, blink_interval)
        except Exception:
            pass

        return True

    def _start_blink(self, rec_id: int, times: int, interval_ms: int) -> None:
        parts = self._row_widgets.get(rec_id)
        if not parts:
            return
        pad_frame: QFrame = parts.get("pad_frame")
        if pad_frame is None:
            return

        accent = "#ffd43b"
        state = {"count": 0, "on": False}

        def _tick():
            try:
                state["on"] = not state["on"]
                if state["on"]:
                    pad_frame.setStyleSheet(
                        f"background: {accent}; border-radius: {self.CONTENT_RADIUS + self.INNER_PADDING}px;"
                    )
                else:
                    pad_frame.setStyleSheet("background: transparent;")
                state["count"] += 1
                if state["count"] >= times * 2:
                    if parts.get("selected"):
                        pad_frame.setStyleSheet(
                            f"background: {accent}; border-radius: {self.CONTENT_RADIUS + self.INNER_PADDING}px;"
                        )
                    else:
                        pad_frame.setStyleSheet("background: transparent;")
                    try:
                        timer.stop()
                        timer.deleteLater()
                    except Exception:
                        pass
            except Exception:
                try:
                    timer.stop()
                except Exception:
                    pass

        timer = QTimer(self)
        timer.timeout.connect(_tick)
        timer.start(interval_ms)

    def scroll_to_and_blink(
        self, filepath: str, blink_count: int = 4, interval: int = 300
    ) -> bool:
        if not filepath:
            return False
        try:
            needle = filepath.strip().lower()
        except Exception:
            needle = filepath

        for rec_id, parts in self._row_widgets.items():
            rec = parts.get("record") or {}
            orig = (rec.get("original_path") or "").lower()
            stored = (rec.get("stored_filename") or "").lower()
            if not needle:
                continue
            match = False
            if needle == orig or needle == stored:
                match = True
            else:
                basename = os.path.basename(needle)
                if basename and (
                    basename == os.path.basename(orig)
                    or basename == os.path.basename(stored)
                ):
                    match = True
            if match:
                try:
                    return self.scroll_to_record(rec_id, blink_count, interval)
                except Exception:
                    try:
                        return self.scroll_to_record(rec_id, blink_count, interval)
                    except Exception:
                        return False
        return False

    def _elide_all_titles(self) -> None:
        viewport_width = max(200, self.scroll.viewport().width())
        for rec_id, p in self._row_widgets.items():
            title_label: QLabel = p.get("title_label")
            if not title_label:
                continue
            full_text = p.get("full_title") or title_label.text()
            available = viewport_width - (
                self.RIGHT_COLUMN_WIDTH + self.CARD_HORIZONTAL_PADDING
            )
            if available < 40:
                available = 40
            font = title_label.font()
            fm = QFontMetrics(font)
            elided = fm.elidedText(full_text, Qt.ElideRight, int(available))
            title_label.setText(elided)
            title_label.setToolTip(full_text)

    # -----------------------
    # Selection helpers
    # -----------------------
    def clear_selection(self) -> None:
        """Hủy chọn tất cả các item đang được tick."""
        for rec_id, parts in self._row_widgets.items():
            if parts.get("selected"):
                # Gọi hàm toggle với giá trị False để cập nhật UI và biến state
                self._on_row_toggled(rec_id, False)

    # -----------------------
    # Actions: restore / delete
    # -----------------------
    def _selected_ids(self) -> List[int]:
        return [
            rid for rid, parts in self._row_widgets.items() if parts.get("selected")
        ]

    def restore_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(
                self, "No selection", "Please select one or more items to restore."
            )
            return
        ok = QMessageBox.question(
            self,
            "Confirm restore",
            f"Restore {len(ids)} selected quarantined file(s)?\n\nEach file will be whitelisted automatically prior to restore.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if ok != QMessageBox.Yes:
            return

        successes = []
        failures = []
        for rid in ids:
            try:
                if self.controller:
                    rres = self.controller.restore(int(rid))
                else:
                    rres = {"status": "error", "message": "No controller available"}
                if rres.get("status") == "ok":
                    successes.append((rid, rres.get("message")))
                else:
                    failures.append((rid, rres.get("message")))
            except Exception as e:
                failures.append((rid, str(e)))

        msg = ""
        if successes:
            msg += f"Restored: {len(successes)}\n"
        if failures:
            msg += f"Failed: {len(failures)}\n"
            for fid, reason in failures[:8]:
                msg += f"- id {fid}: {reason}\n"
        QMessageBox.information(self, "Restore results", msg or "No actions performed.")
        # refresh main and restored views
        try:
            self.trigger_refresh()
        except Exception:
            pass
        try:
            if self._restored_dialog is not None:
                self._restored_dialog.trigger_refresh()
        except Exception:
            pass

    def delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(
                self, "No selection", "Please select one or more items to delete."
            )
            return
        ok = QMessageBox.warning(
            self,
            "Confirm delete",
            f"Delete {len(ids)} selected quarantined file(s)? This will remove stored files and DB records and cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if ok != QMessageBox.Yes:
            return

        successes = []
        failures = []
        for rid in ids:
            try:
                if self.controller:
                    dres = self.controller.delete(int(rid))
                else:
                    dres = {"status": "error", "message": "No controller available"}
                if dres.get("status") == "ok":
                    successes.append((rid, dres.get("message")))
                else:
                    failures.append((rid, dres.get("message")))
            except Exception as e:
                failures.append((rid, str(e)))

        msg = ""
        if successes:
            msg += f"Deleted: {len(successes)}\n"
        if failures:
            msg += f"Failed: {len(failures)}\n"
            for fid, reason in failures[:8]:
                msg += f"- id {fid}: {reason}\n"
        QMessageBox.information(self, "Delete results", msg or "No actions performed.")
        # refresh main and restored views
        try:
            self.trigger_refresh()
        except Exception:
            pass
        try:
            if self._restored_dialog is not None:
                self._restored_dialog.trigger_refresh()
        except Exception:
            pass

    def _show_detail_dialog(self, rec: Dict[str, Any]) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Details")
        dlg.resize(560, 320)
        layout = QVBoxLayout(dlg)

        orig = rec.get("original_path") or ""
        name_display = (
            os.path.basename(orig) if orig else rec.get("stored_filename") or ""
        )
        name_label = QLabel(f"<b>Name:</b> {name_display}")
        name_label.setWordWrap(True)
        layout.addWidget(name_label)

        full_path_label = QLabel(f"<b>Original path:</b> {orig or ''}")
        full_path_label.setWordWrap(True)
        layout.addWidget(full_path_label)

        qa = QLabel(f"<b>Quarantined at:</b> {rec.get('quarantined_at') or ''}")
        layout.addWidget(qa)

        size_hash = QLabel(
            f"<b>Size:</b> {rec.get('stored_size') or 0} bytes    <b>Hash:</b> {rec.get('original_hash') or ''}"
        )
        layout.addWidget(size_hash)

        note_text = rec.get("note") or ""
        layout.addWidget(QLabel("<b>Details / Note:</b>"))
        details = QTextEdit()
        details.setReadOnly(True)
        details.setPlainText(str(note_text))
        details.setFixedHeight(120)
        layout.addWidget(details)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        footer = QHBoxLayout()
        footer.addStretch()
        footer.addWidget(btn_close)
        layout.addLayout(footer)

        dlg.exec()

    # -----------------------
    # Refresh helpers & visibility
    # -----------------------
    def trigger_refresh(self) -> None:
        try:
            if getattr(self, "_loading_in_progress", False):
                return
            self._loading_in_progress = True
            try:
                self.load_data()
            finally:
                self._loading_in_progress = False
        except Exception:
            try:
                self._loading_in_progress = False
            except Exception:
                pass

    def _on_auto_refresh(self) -> None:
        try:
            if not self.isVisible():
                return
            self.trigger_refresh()
        except Exception:
            pass

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # immediate refresh and start timer
        try:
            self.trigger_refresh()
        except Exception:
            pass
        try:
            if not self._auto_timer.isActive():
                self._auto_timer.start()
        except Exception:
            pass

    def hideEvent(self, event) -> None:
        try:
            if self._auto_timer.isActive():
                self._auto_timer.stop()
        except Exception:
            pass
        super().hideEvent(event)

    # -----------------------
    # Restored dialog management
    # -----------------------
    def _populate_restored_overlay(self) -> None:
        try:
            if not hasattr(self, "_restored_layout"):
                return
            # Clear existing content
            for i in reversed(range(self._restored_layout.count())):
                item = self._restored_layout.takeAt(i)
                w = item.widget()
                if w:
                    try:
                        w.setParent(None)
                    except Exception:
                        pass

            if self.controller is None:
                lbl = QLabel("No HistoryController available.")
                lbl.setStyleSheet("color: gray; padding: 8px;")
                self._restored_layout.addWidget(lbl)
                return

            try:
                rows = self.controller.list_quarantined()
            except Exception as e:
                lbl = QLabel(f"Could not load restored records: {e}")
                lbl.setStyleSheet("color: gray; padding: 8px;")
                self._restored_layout.addWidget(lbl)
                return

            try:
                rows = [r for r in rows if bool(r.get("restored"))]
            except Exception:
                rows = []

            if not rows:
                empty = QLabel("No restored quarantine records found.")
                empty.setStyleSheet("color: gray; padding: 12px;")
                self._restored_layout.addWidget(empty)
                return

            for rec in rows:
                title = os.path.basename(
                    rec.get("original_path")
                    or rec.get("stored_filename")
                    or "(unknown)"
                )
                ts = rec.get("quarantined_at") or ""
                # Two-line read-only row:
                # * filename -- fullpath
                #   time (indented)
                row_w = QWidget()
                row_layout = QVBoxLayout(row_w)
                row_layout.setContentsMargins(4, 4, 4, 4)
                row_layout.setSpacing(2)
                top = QLabel(
                    f"* {title} -- {rec.get('original_path') or rec.get('stored_filename') or ''}"
                )
                top.setStyleSheet(
                    "background: transparent; color: #e0e0e0; padding: 6px; border-radius: 4px;"
                )
                top.setWordWrap(True)
                bottom = QLabel(f"  {ts}")
                bottom.setStyleSheet("color: #bdbdbd; padding-left: 10px;")
                bottom.setWordWrap(True)
                row_layout.addWidget(top)
                row_layout.addWidget(bottom)
                self._restored_layout.addWidget(row_w)

            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self._restored_layout.addWidget(spacer)
        except Exception:
            pass

    def open_restored_view(self) -> None:
        try:
            # If overlay was not created during UI build, nothing to show
            if not hasattr(self, "_restored_overlay") or self._restored_overlay is None:
                return

            # Populate restored list right before showing
            try:
                self._populate_restored_overlay()
            except Exception:
                pass

            try:
                # make sure overlay covers the dialog (best-effort)
                self._restored_overlay.setGeometry(self.rect())
            except Exception:
                pass

            # stop auto-refresh of main list while overlay visible
            try:
                if self._auto_timer.isActive():
                    self._auto_timer.stop()
            except Exception:
                pass

            self._restored_overlay.setVisible(True)
            self._restored_overlay.raise_()
        except Exception:
            pass

    def _hide_restored_overlay(self) -> None:
        try:
            if hasattr(self, "_restored_overlay") and self._restored_overlay:
                try:
                    self._restored_overlay.setVisible(False)
                except Exception:
                    pass
            # Refresh main view when returning
            try:
                self.trigger_refresh()
            except Exception:
                pass
        except Exception:
            pass


class RestoredHistoryDialog(ProtectionHistoryDialog):
    def __init__(self, parent: Optional[QWidget] = None):
        # Notice: call parent init to build UI, but we will adjust buttons & behavior
        super().__init__(parent)
        try:
            self.setWindowTitle("Restored Protection History")
        except Exception:
            pass
        # Hide restore button and clear selection button
        try:
            if hasattr(self, "btn_restore") and self.btn_restore:
                self.btn_restore.hide()
            if hasattr(self, "btn_clear_selection") and self.btn_clear_selection:
                self.btn_clear_selection.hide()
        except Exception:
            pass

    def load_data(self) -> None:
        self._clear_list()

        if self.controller is None:
            QMessageBox.critical(self, "Error", "No HistoryController available.")
            return

        try:
            rows = self.controller.list_quarantined()
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Could not load quarantine records:\n{e}"
            )
            return

        # Keep only restored
        try:
            rows = [r for r in rows if bool(r.get("restored"))]
        except Exception:
            pass

        if not rows:
            empty = QLabel("No restored quarantine records found.")
            empty.setStyleSheet("color: gray; padding: 12px;")
            self.scroll_layout.addWidget(empty)
            return

        for rec in rows:
            wrapper = self._create_row_wrapper(rec)
            self.scroll_layout.addWidget(wrapper)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.scroll_layout.addWidget(spacer)

        self._elide_all_titles()


# set compat alias
HistoryDialog = ProtectionHistoryDialog
