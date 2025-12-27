from __future__ import annotations

import sys
import threading
from typing import Optional

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Import the controller we created earlier; if import fails we handle gracefully.
try:
    from Client.Controller.RealtimeProtectionController import (
        RealtimeProtectionController,
    )
except Exception as e:
    RealtimeProtectionController = None  # type: ignore
    _IMPORT_ERROR = e
else:
    _IMPORT_ERROR = None


class RoundToggleButton(QPushButton):
    def __init__(self, diameter: int = 160, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._diameter = diameter
        self.setCheckable(True)
        self.setFixedSize(self._diameter, self._diameter)
        self.setCursor(Qt.PointingHandCursor)
        self._update_style()

        # Large font for an icon/text inside the circle
        f = QFont()
        f.setPointSize(int(self._diameter / 6))
        f.setBold(True)
        self.setFont(f)

        # Toggle style update on click
        self.toggled.connect(lambda _: self._update_style())

    def _update_style(self) -> None:
        checked = self.isChecked()
        bg = "#28a745" if checked else "#c82333"  # green / red
        label = "ON" if checked else "OFF"
        # subtle inner shadow and border
        self.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {bg};
                color: white;
                border: 3px solid rgba(0,0,0,0.15);
                border-radius: {int(self._diameter / 2)}px;
            }}
            QPushButton:pressed {{
                background-color: rgba(0,0,0,0.08);
            }}
            """
        )
        self.setText(label)


class RealtimeProtectionDialog(QDialog):
    notification_clicked = Signal(str)

    def _handle_notification_click(self, filepath: str) -> None:
        try:
            mw = None
            try:
                mw = self.window()
            except Exception:
                mw = None

            if (
                mw is not None
                and hasattr(mw, "content_area")
                and hasattr(mw, "page_history")
            ):
                try:
                    # Switch stacked widget to history page (prefer direct set, fallback to display_page)
                    try:
                        mw.content_area.setCurrentWidget(mw.page_history)
                    except Exception:
                        try:
                            mw.display_page(2)
                        except Exception:
                            pass

                    # Update menu selection if available
                    try:
                        if hasattr(mw, "menu"):
                            mw.menu.setCurrentRow(2)
                    except Exception:
                        pass

                    try:
                        ph = getattr(mw, "page_history", None)
                        if ph is not None:
                            if hasattr(ph, "trigger_refresh") and callable(
                                getattr(ph, "trigger_refresh")
                            ):
                                try:
                                    ph.trigger_refresh()
                                except Exception:
                                    try:
                                        if hasattr(ph, "load_data") and callable(
                                            getattr(ph, "load_data")
                                        ):
                                            ph.load_data()
                                    except Exception:
                                        pass
                            else:
                                try:
                                    if hasattr(ph, "load_data") and callable(
                                        getattr(ph, "load_data")
                                    ):
                                        ph.load_data()
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    try:
                        mw.raise_()
                        mw.activateWindow()
                    except Exception:
                        pass

                    return
                except Exception:
                    pass

            try:
                self.raise_()
                self.activateWindow()
            except Exception:
                pass
        except Exception:
            pass

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Realtime Protection")
        self.resize(480, 640)
        self.setModal(False)

        self.controller: Optional[RealtimeProtectionController] = None
        self._init_controller()

        self._build_ui()
        self._apply_initial_state()

        self._state_timer = QTimer(self)
        self._state_timer.setInterval(1000)
        self._state_timer.timeout.connect(self._refresh_ui_state)
        self._state_timer.start()

    def _init_controller(self) -> None:
        if RealtimeProtectionController is None:
            self.controller = None
            return

        try:
            self.notification_clicked.connect(self._handle_notification_click)
        except Exception:
            pass

        def _on_notification_click(filepath: str) -> None:
            try:
                # Emit the Qt signal (queued to GUI thread if called from worker threads)
                self.notification_clicked.emit(filepath)
            except Exception:
                # Swallow exceptions silently — keep notification handler lightweight.
                pass

        try:
            self.controller = RealtimeProtectionController(
                on_notification_click=_on_notification_click
            )
        except Exception:
            self.controller = None

    def _build_ui(self) -> None:
        root = QVBoxLayout()
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)
        self.setLayout(root)

        root.addSpacerItem(
            QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )

        center_widget = QWidget()
        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        center_layout.setSpacing(8)
        center_widget.setLayout(center_layout)

        self.toggle_btn = RoundToggleButton(diameter=160)
        self.toggle_btn.clicked.connect(self._on_toggle_clicked)
        center_layout.addWidget(self.toggle_btn, alignment=Qt.AlignHCenter)

        self.status_label = QLabel()
        small_font = QFont()
        small_font.setPointSize(10)
        self.status_label.setFont(small_font)
        self.status_label.setAlignment(Qt.AlignCenter)
        center_layout.addWidget(self.status_label)

        root.addWidget(center_widget)

        root.addSpacerItem(
            QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )

        show_opt_layout = QHBoxLayout()
        show_opt_layout.setAlignment(Qt.AlignCenter)
        self.show_options_btn = QPushButton("Show option")
        self.show_options_btn.setCursor(Qt.PointingHandCursor)
        self.show_options_btn.clicked.connect(self._toggle_options_panel)
        show_opt_layout.addWidget(self.show_options_btn)
        root.addLayout(show_opt_layout)

        self.options_frame = QFrame()
        self.options_frame.setFrameShape(QFrame.StyledPanel)
        self.options_frame.setMaximumHeight(0)
        self.options_frame.setMinimumHeight(0)
        self.options_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        options_layout = QVBoxLayout()
        options_layout.setContentsMargins(12, 12, 12, 12)
        options_layout.setSpacing(8)
        self.options_frame.setLayout(options_layout)

        lbl = QLabel("Folders to watch (one path per line):")
        options_layout.addWidget(lbl)
        self.watch_text = QTextEdit()
        self.watch_text.setPlaceholderText(
            r"%USERPROFILE%\\Downloads\n%USERPROFILE%\\Desktop\n..."
        )
        self.watch_text.setFixedHeight(80)
        options_layout.addWidget(self.watch_text)

        btn_row = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self._on_save_clicked)
        self.create_test_btn = QPushButton("Create test files")
        self.create_test_btn.clicked.connect(self._on_create_test_clicked)
        self.close_options_btn = QPushButton("Close")
        self.close_options_btn.clicked.connect(self._toggle_options_panel)
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(self.create_test_btn)
        btn_row.addWidget(self.close_options_btn)
        options_layout.addLayout(btn_row)

        root.addWidget(self.options_frame)

        self._options_anim = QPropertyAnimation(
            self.options_frame, b"maximumHeight", self
        )
        self._options_anim.setDuration(250)
        self._options_anim.setEasingCurve(QEasingCurve.OutCubic)

    def _apply_initial_state(self) -> None:
        if self.controller is not None:
            try:
                self.watch_text.setPlainText(self.controller.get_watch_folders())
                protecting = self.controller.is_protecting()
            except Exception:
                protecting = False
        else:
            protecting = False
            if _IMPORT_ERROR is not None:
                QMessageBox.warning(
                    self,
                    "Controller unavailable",
                    f"RealtimeProtectionController could not be imported:\n{_IMPORT_ERROR}\n"
                    "Realtime functions will be disabled.",
                )

        self._set_protection_ui(protecting)

    def _set_protection_ui(self, protecting: bool) -> None:
        self.toggle_btn.blockSignals(True)
        self.toggle_btn.setChecked(protecting)
        self.toggle_btn.blockSignals(False)
        if protecting:
            self.status_label.setText("Thiết bị của bạn đang được bảo vệ")  # green
            self.status_label.setStyleSheet("color: #28a745;")
            self.toggle_btn.setText("ON")
        else:
            self.status_label.setText("Thiết bị của bạn đang không được bảo vệ")  # red
            self.status_label.setStyleSheet("color: #c82333;")
            self.toggle_btn.setText("OFF")

        # If controller absent, disable controls that require it
        enabled = self.controller is not None
        self.toggle_btn.setEnabled(enabled)
        self.save_btn.setEnabled(enabled)
        self.create_test_btn.setEnabled(enabled)

    @Slot()
    def _on_toggle_clicked(self) -> None:
        if self.controller is None:
            QMessageBox.warning(
                self, "Unavailable", "Realtime controller is not available."
            )
            return

        want_on = self.toggle_btn.isChecked()
        if want_on:
            ok = self.controller.start_protection()
            if not ok:
                QMessageBox.warning(
                    self, "Start failed", "Failed to start realtime protection."
                )
            self._set_protection_ui(self.controller.is_protecting())
        else:
            ok = self.controller.stop_protection()
            if not ok:
                QMessageBox.warning(
                    self, "Stop failed", "Failed to stop realtime protection."
                )
            self._set_protection_ui(self.controller.is_protecting())

    @Slot()
    def _toggle_options_panel(self) -> None:
        expanded = self.options_frame.maximumHeight() > 0
        if expanded:
            start_h = self.options_frame.maximumHeight()
            end_h = 0
            self._options_anim.stop()
            self._options_anim.setStartValue(start_h)
            self._options_anim.setEndValue(end_h)
            self._options_anim.start()
            self.show_options_btn.setText("Show option")
        else:
            desired = 180
            self._options_anim.stop()
            self._options_anim.setStartValue(0)
            self._options_anim.setEndValue(desired)
            self._options_anim.start()
            self.show_options_btn.setText("Hide option")

    @Slot()
    def _on_save_clicked(self) -> None:
        if self.controller is None:
            QMessageBox.warning(
                self, "Unavailable", "Realtime controller is not available."
            )
            return
        txt = self.watch_text.toPlainText().strip()
        if not txt:
            QMessageBox.warning(
                self, "Validation", "Please enter at least one folder to watch."
            )
            return
        try:
            self.controller.set_watch_folders(txt)
            QMessageBox.information(self, "Saved", "Watch folders saved.")
        except Exception as e:
            QMessageBox.warning(
                self, "Save failed", f"Failed to save watch folders:\n{e}"
            )

    @Slot()
    def _on_create_test_clicked(self) -> None:
        if self.controller is None:
            QMessageBox.warning(
                self, "Unavailable", "Realtime controller is not available."
            )
            return
        created = None
        try:
            created = self.controller.trigger_test_file_creation()
        except Exception as e:
            QMessageBox.warning(self, "Failed", f"Failed to create test file(s):\n{e}")
            return
        if created:
            QMessageBox.information(
                self, "Test files created", f"Created test file: {created}"
            )
        else:
            QMessageBox.information(self, "Test files", "No test files were created.")

    @Slot()
    def _refresh_ui_state(self) -> None:
        if self.controller is None:
            return
        try:
            # Detect background operation in controller (safe fallback to False)
            in_progress = False
            try:
                in_progress = getattr(
                    self.controller, "is_operation_in_progress", lambda: False
                )()
            except Exception:
                in_progress = False

            # Get actual runtime protecting state
            protecting = False
            try:
                protecting = self.controller.is_protecting()
            except Exception:
                protecting = False

            # Keep UI in sync if it drifted
            if protecting != self.toggle_btn.isChecked():
                self._set_protection_ui(protecting)

            # While an operation is in-progress, disable toggle/save/create to avoid repeated requests.
            # Once operation finishes the periodic timer will re-enable controls.
            can_use = (not in_progress) and (self.controller is not None)
            self.toggle_btn.setEnabled(can_use)
            self.save_btn.setEnabled(can_use)
            self.create_test_btn.setEnabled(can_use)

        except Exception:
            pass

    def closeEvent(self, event) -> None:
        super().closeEvent(event)


# For quick manual testing
if __name__ == "__main__" and "pytest" not in sys.modules:
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dlg = RealtimeProtectionDialog()
    dlg.show()
    sys.exit(app.exec())
