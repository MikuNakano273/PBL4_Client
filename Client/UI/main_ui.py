# main_window.py
from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from Client.Controller.ScanController import ScanController
from Client.UI.history import ProtectionHistoryDialog
from Client.UI.realtime_protection import RealtimeProtectionDialog
from Client.UI.scan_options import ScanOptionsPage

try:
    from Client.Controller.HashController import get_hash_controller
except Exception:
    get_hash_controller = None

try:
    from Client.Controller.AutostartController import (
        disable_autostart,
        enable_autostart,
        is_autostart_enabled,
        load_settings,
        save_settings,
    )
except Exception:
    load_settings = None
    save_settings = None
    enable_autostart = None
    disable_autostart = None
    is_autostart_enabled = None


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.page_scan_dialog = None
        self.scan_controller = None
        self._hashctrl_prev_enabled = None
        self._hashctrl = (
            get_hash_controller() if get_hash_controller is not None else None
        )
        self._last_shown_response = None

        self.setWindowTitle("Virus scan app")
        self.resize(1000, 600)
        self.init_ui()

    def init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setLayout(root_layout)

        # Main horizontal area (left menu + content)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(5)
        root_layout.addLayout(main_layout)

        # --- MENU BÊN TRÁI ---
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        # Limit left menu maximum width so the navigation area does not exceed a reasonable size
        # (kept smaller than previously requested 700 for typical app layout; adjust if desired)
        left_widget.setMaximumWidth(250)

        menu_label = QLabel("Menu")
        menu_label.setAlignment(Qt.AlignCenter)
        menu_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 18px;
                font-weight: bold;
                background-color: #23272a;
                padding: 10px;
                border-bottom: 2px solid #7289da;
            }
        """)
        left_layout.addWidget(menu_label)

        self.menu = QListWidget()
        self.menu.setStyleSheet("""
            QListWidget {
                background-color: #2c2f33;
                color: white;
                border: none;
                font-size: 16px;
                outline: none;
            }
            QListWidget::item {
                padding: 14px;
            }
            QListWidget::item:selected {
                background-color: #7289da;
                border: none;
                outline: none;
            }
            QListWidget::item:hover {
                background-color: #99aab5;
            }
        """)
        # Ensure the menu widget itself also respects the maximum width
        self.menu.setMaximumWidth(250)

        # Reordered menu: move Real-time scanner to top, remove Home, rename View statistics -> Protection history
        menu_items = ["Real-time scanner", "Local scan", "Protection history"]
        for item_text in menu_items:
            item = QListWidgetItem(item_text)
            item.setTextAlignment(Qt.AlignCenter)
            item.setSizeHint(QSize(150, 50))
            self.menu.addItem(item)

        left_layout.addWidget(self.menu)
        main_layout.addWidget(left_widget, 2)

        # --- KHU VỰC NỘI DUNG (BÊN PHẢI) ---
        self.content_area = QStackedWidget()
        main_layout.addWidget(self.content_area, 8)

        self.page_realtime = RealtimeProtectionDialog()
        self.page_scan = ScanOptionsPage()
        self.page_history = ProtectionHistoryDialog()

        self.content_area.addWidget(self.page_realtime)
        self.content_area.addWidget(self.page_scan)
        self.content_area.addWidget(self.page_history)

        self.menu.currentRowChanged.connect(self.display_page)

        self.menu.setCurrentRow(0)
        self.display_page(0)

        self.scan_controller = ScanController(main_window=self)
        if hasattr(self.page_scan, "next_clicked"):
            self.page_scan.next_clicked.connect(
                lambda: self.scan_controller.handle_next_clicked(self.page_scan)
            )

        # --- Bottom status panel ---
        # It shows a left-side status text (reflecting HashController/send state) and a right-side settings button.
        bottom_panel = QFrame()
        bottom_panel.setFrameShape(QFrame.NoFrame)
        bottom_panel.setObjectName("bottom_panel")
        bottom_panel.setStyleSheet(
            "#bottom_panel { background-color: #2b2f33; color: white; padding: 6px 10px; }"
        )
        bp_layout = QHBoxLayout(bottom_panel)
        bp_layout.setContentsMargins(8, 6, 8, 6)
        bp_layout.setSpacing(8)

        # Left-side status label (dynamic)
        self.status_label = QLabel("Đang tạm dừng")
        self.status_label.setStyleSheet("color: #ffffff;")
        bp_layout.addWidget(self.status_label, 1)

        # spacer between left and right
        bp_layout.addSpacerItem(
            QSpacerItem(20, 10, QSizePolicy.Expanding, QSizePolicy.Minimum)
        )

        # Settings button (square)
        self.settings_btn = QPushButton("⚙")
        self.settings_btn.setFixedSize(40, 36)
        self.settings_btn.setCursor(Qt.PointingHandCursor)
        self.settings_btn.setToolTip("Open settings")
        self.settings_btn.clicked.connect(self._open_settings_overlay)
        bp_layout.addWidget(self.settings_btn, 0, Qt.AlignRight)

        # Add bottom panel to the root layout so it spans full window width
        self.layout().addWidget(bottom_panel)

        # Build settings overlay (hidden by default)
        self._build_settings_overlay()

        # Update overlay: shown when performing manual hash update. Hidden by default.
        self.update_overlay = QWidget(self)
        self.update_overlay.setObjectName("update_overlay")
        self.update_overlay.setStyleSheet(
            "#update_overlay { background-color: rgba(0,0,0,0.6); color: white; }"
        )
        self.update_overlay.setVisible(False)
        self.update_overlay.setGeometry(0, 0, self.width(), self.height())
        u_layout = QVBoxLayout(self.update_overlay)
        u_layout.setContentsMargins(30, 30, 30, 30)
        u_layout.setAlignment(Qt.AlignCenter)
        lbl_up = QLabel("Updating...")
        lbl_up.setAlignment(Qt.AlignCenter)
        lbl_up.setStyleSheet("font-size:18px; color: white;")
        u_layout.addWidget(lbl_up)
        self.update_progress = QProgressBar()
        self.update_progress.setRange(0, 0)  # indeterminate/busy
        self.update_progress.setFixedWidth(220)
        u_layout.addWidget(self.update_progress)
        self.update_overlay.installEventFilter(self)

        # Timer to refresh status_label based on HashController state (and simple retry counter)
        self._status_counter = 0
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._refresh_hash_status)
        self._status_timer.start()

    def display_page(self, index):
        # Mapping menu index → content page
        if index == 0:
            # Real-time scanner
            self.content_area.setCurrentWidget(self.page_realtime)
        elif index == 1:
            self.content_area.setCurrentWidget(self.page_scan)
        elif index == 2:
            # Protection history
            self.content_area.setCurrentWidget(self.page_history)

    def go_to_scan_options(self):
        self.content_area.setCurrentWidget(self.page_scan)
        # Menu index for scan page is 1 in the new ordering
        self.menu.setCurrentRow(1)

    def _build_settings_overlay(self) -> None:
        """Construct an overlay widget that covers the main window with settings placeholders."""
        try:
            self.settings_overlay = QWidget(self)
            self.settings_overlay.setObjectName("settings_overlay")
            self.settings_overlay.setStyleSheet(
                "#settings_overlay { background-color: rgba(30,30,30,0.98); color: white; }"
            )
            self.settings_overlay.setVisible(False)
            self.settings_overlay.setGeometry(0, 0, self.width(), self.height())

            overlay_layout = QVBoxLayout(self.settings_overlay)
            overlay_layout.setContentsMargins(20, 20, 20, 20)
            overlay_layout.setSpacing(12)

            # Top row with back arrow and title
            top_row = QHBoxLayout()
            self.back_btn = QPushButton("←")
            self.back_btn.setFixedSize(36, 36)
            self.back_btn.setCursor(Qt.PointingHandCursor)
            self.back_btn.clicked.connect(self._close_settings_overlay)
            top_row.addWidget(self.back_btn, 0, Qt.AlignLeft)

            title = QLabel("Settings")
            title.setStyleSheet("font-weight: bold; font-size: 18px;")
            top_row.addWidget(title, 1, Qt.AlignLeft)

            overlay_layout.addLayout(top_row)

            # Content placeholder: startup checkbox and update button
            content = QWidget()
            content_layout = QVBoxLayout()
            content_layout.setContentsMargins(6, 6, 6, 6)
            content_layout.setSpacing(10)
            content.setLayout(content_layout)

            self.startup_chk = QCheckBox("Start up with Windows")
            # Improve visibility: use a brighter, high-contrast green for the checked indicator
            try:
                self.startup_chk.setStyleSheet(
                    "QCheckBox::indicator { width: 16px; height: 16px; }"
                    "QCheckBox::indicator:unchecked { background-color: transparent; border: 1px solid #4a4a4a; border-radius: 3px; }"
                    "QCheckBox::indicator:checked { background-color: #09eb49; border: 1px solid #09eb49; border-radius: 3px; }"
                )
            except Exception:
                pass
            # initialize checkbox from saved settings (ProgramData settings.json) or existing shortcut presence
            try:
                checked = False
                if load_settings is not None:
                    try:
                        s = load_settings()
                        checked = bool(s.get("start_with_windows", False))
                    except Exception:
                        checked = False
                # if shortcut exists, treat as enabled
                try:
                    if is_autostart_enabled is not None and is_autostart_enabled():
                        checked = True
                except Exception:
                    pass
                try:
                    self.startup_chk.setChecked(checked)
                except Exception:
                    pass
            except Exception:
                pass
            # connect toggle handler
            try:
                self.startup_chk.toggled.connect(self._on_startup_toggled)
            except Exception:
                pass
            content_layout.addWidget(self.startup_chk)

            # Auto-update checkbox for hash updates on launch (default: checked)
            self.auto_update_chk = QCheckBox("Auto update hash when launch")
            try:
                self.auto_update_chk.setStyleSheet(
                    "QCheckBox::indicator { width: 16px; height: 16px; }"
                    "QCheckBox::indicator:unchecked { background-color: transparent; border: 1px solid #4a4a4a; border-radius: 3px; }"
                    "QCheckBox::indicator:checked { background-color: #09eb49; border: 1px solid #09eb49; border-radius: 3px; }"
                )
            except Exception:
                pass
            # initialize from saved settings (ProgramData settings.json)
            try:
                checked = True
                if load_settings is not None:
                    try:
                        s = load_settings()
                        checked = bool(s.get("auto_update_hash", True))
                    except Exception:
                        checked = True
                try:
                    self.auto_update_chk.setChecked(checked)
                except Exception:
                    pass
            except Exception:
                pass
            # persist toggle to the same settings file used by AutostartController
            try:

                def _on_auto_toggled(checked):
                    try:
                        if load_settings is None or save_settings is None:
                            return
                        s = load_settings()
                        s["auto_update_hash"] = bool(checked)
                        save_settings(s)
                    except Exception:
                        pass

                self.auto_update_chk.toggled.connect(_on_auto_toggled)
            except Exception:
                pass
            content_layout.addWidget(self.auto_update_chk)

            self.check_update_btn = QPushButton("Check for new hash update")
            # bind update action: run UpdateModel.check_and_update in background and print progress
            try:

                def _on_check_update_clicked():
                    try:
                        from Client.Model.UpdateModel import UpdateModel
                    except Exception as e:
                        print("UpdateModel import failed:", e, flush=True)
                        return
                    import threading

                    # Show update overlay (non-blocking)
                    try:
                        self.update_overlay.setGeometry(
                            0, 0, self.width(), self.height()
                        )
                        self.update_overlay.setVisible(True)
                        self.update_overlay.raise_()
                    except Exception:
                        pass

                    def _worker():
                        try:
                            print("Starting hash update...", flush=True)
                            um = UpdateModel()
                            res = um.check_and_update(dry_run=False)
                            ok = bool(getattr(res, "success", False))
                            msg = getattr(res, "message", "")
                            print(
                                f"Hash update finished: success={ok}, message={msg}",
                                flush=True,
                            )
                        except Exception as ex:
                            print("Hash update error:", ex, flush=True)

                    t = threading.Thread(target=_worker, daemon=True)
                    t.start()

                    # Poll the thread and hide overlay when finished (safe from main thread)
                    try:

                        def _poll():
                            if not t.is_alive():
                                try:
                                    self._update_check_timer.stop()
                                except Exception:
                                    pass
                                try:
                                    self.update_overlay.setVisible(False)
                                except Exception:
                                    pass

                        self._update_check_timer = QTimer(self)
                        self._update_check_timer.timeout.connect(_poll)
                        self._update_check_timer.start(200)
                    except Exception:
                        # If timer creation fails, attempt simple hide after a delay fallback
                        try:
                            QTimer.singleShot(
                                5000, lambda: self.update_overlay.setVisible(False)
                            )
                        except Exception:
                            pass

                try:
                    self.check_update_btn.clicked.connect(_on_check_update_clicked)
                except Exception:
                    pass
            except Exception:
                pass
            content_layout.addWidget(self.check_update_btn)

            # Filler spacer
            content_layout.addSpacerItem(
                QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
            )

            overlay_layout.addWidget(content, 1)

            # Keep overlay on resize
            self.settings_overlay.installEventFilter(self)
        except Exception:
            # Best-effort only; overlay is optional
            self.settings_overlay = None

    def _on_startup_toggled(self, checked: bool) -> None:
        try:
            if checked:
                # Attempt to enable autostart. If the controller is unavailable or creation fails,
                # revert checkbox to False to reflect the actual state.
                try:
                    if enable_autostart is not None:
                        ok = enable_autostart()
                        if not ok:
                            try:
                                self.startup_chk.setChecked(False)
                            except Exception:
                                pass
                    else:
                        # controller missing: revert visual state
                        try:
                            self.startup_chk.setChecked(False)
                        except Exception:
                            pass
                except Exception:
                    try:
                        self.startup_chk.setChecked(False)
                    except Exception:
                        pass
            else:
                # disable autostart (best-effort)
                try:
                    if disable_autostart is not None:
                        disable_autostart()
                except Exception:
                    pass
        except Exception:
            pass

    def _open_settings_overlay(self) -> None:
        # Show overlay and pause HashController while settings are visible
        try:
            if hasattr(self, "settings_overlay") and self.settings_overlay is not None:
                self.settings_overlay.setGeometry(0, 0, self.width(), self.height())
                self.settings_overlay.setVisible(True)
                self.settings_overlay.raise_()
        except Exception:
            pass

        try:
            # store previous state and then disable background sender
            if self._hashctrl is not None:
                try:
                    self._hashctrl_prev_enabled = self._hashctrl.is_enabled()
                    self._hashctrl.set_enabled(False)
                except Exception:
                    self._hashctrl_prev_enabled = None
        except Exception:
            pass

    def _close_settings_overlay(self) -> None:
        # Hide overlay and restore HashController state
        try:
            if hasattr(self, "settings_overlay") and self.settings_overlay is not None:
                self.settings_overlay.setVisible(False)
        except Exception:
            pass

        try:
            if self._hashctrl is not None and self._hashctrl_prev_enabled is not None:
                try:
                    self._hashctrl.set_enabled(bool(self._hashctrl_prev_enabled))
                except Exception:
                    pass
                self._hashctrl_prev_enabled = None
        except Exception:
            pass

    def _refresh_hash_status(self) -> None:
        try:
            self._status_counter = (self._status_counter + 1) % 60
            # Default message
            msg = "Đang tạm dừng"
            append_retry_suffix = True  # whether to add ". Thử lại sau" at the end

            # If we have a controller, inspect its state and update message accordingly.
            ctrl = getattr(self, "_hashctrl", None)
            if ctrl is not None:
                try:
                    if not ctrl.is_enabled():
                        msg = "Đang tạm dừng"
                    else:
                        # read model entries (best-effort)
                        try:
                            mdl = getattr(ctrl, "model", None)
                            entries = []
                            if mdl is not None and hasattr(mdl, "get_all"):
                                entries = mdl.get_all() or []
                        except Exception:
                            entries = []

                        # Prefer explicit status exposed by controller if present
                        # Read the controller's status fields under the controller's internal lock
                        status = None
                        attempt = 0
                        last_resp = None
                        try:
                            status_lock = getattr(ctrl, "_status_lock", None)
                            if status_lock is not None:
                                with status_lock:
                                    status = getattr(ctrl, "status", None)
                                    attempt = int(
                                        getattr(ctrl, "current_attempt", 0) or 0
                                    )
                                    last_resp = getattr(ctrl, "last_response", None)
                            else:
                                # No lock present (older controllers) — best-effort read
                                status = getattr(ctrl, "status", None)
                                attempt = int(getattr(ctrl, "current_attempt", 0) or 0)
                                last_resp = getattr(ctrl, "last_response", None)
                        except Exception:
                            # If anything goes wrong while acquiring/using the lock,
                            # fall back to an unlocked read to avoid breaking the UI.
                            status = getattr(ctrl, "status", None)
                            attempt = int(getattr(ctrl, "current_attempt", 0) or 0)
                            last_resp = getattr(ctrl, "last_response", None)

                        if not entries:
                            msg = "Không có dữ liệu để gửi tới server"
                        else:
                            # If controller indicates sending or attempt > 0, show sending message (no retry suffix)
                            if status == "sending" or attempt > 0:
                                # use provided attempt number if present; fallback to simple animation
                                if attempt > 0:
                                    msg = f"Đang gửi lần {attempt}"
                                else:
                                    # fallback animated attempt using internal counter
                                    anim_attempt = (self._status_counter // 20) + 1
                                    anim_attempt = min(3, max(1, anim_attempt))
                                    msg = f"Đang gửi lần {anim_attempt}"
                                    # try:
                                    #     print(
                                    #         f"[UI] Animated sending message: {msg}",
                                    #         flush=True,
                                    #     )
                                    # except Exception:
                                    #     pass
                                append_retry_suffix = False
                            elif status in ("success",):
                                msg = "Gửi thành công"
                            elif status in ("no_connection",):
                                msg = "Không kết nối được tới server"
                            elif status in ("busy",):
                                msg = "Server đang bận"
                            elif status in ("failure",):
                                msg = "Gửi thất bại"
                            else:
                                # If thread is running and controller has no clear status, show sending animation
                                running = False
                                try:
                                    running = ctrl.is_running()
                                except Exception:
                                    running = False

                                if running:
                                    # Thay vì hiện "Đang gửi lần...", hãy hiện trạng thái chờ
                                    msg = "Đang chạy ngầm (Chờ dữ liệu/mạng)"
                                    append_retry_suffix = False
                                else:
                                    msg = "Chưa kích hoạt gửi ngầm"

                        # Print server last_response once when it changes (debug visibility)
                        try:
                            if last_resp is not None and last_resp != getattr(
                                self, "_last_shown_response", None
                            ):
                                # print to console (visible to the user), and set tooltip
                                try:
                                    print("[SERVER RESPONSE]", last_resp, flush=True)
                                except Exception:
                                    pass
                                try:
                                    # store shown response and set a short tooltip on the status label
                                    self._last_shown_response = last_resp
                                    # set tooltip to pretty string (best-effort)
                                    tr = str(last_resp)
                                    self.status_label.setToolTip(
                                        tr if len(tr) < 2000 else tr[:2000] + "..."
                                    )
                                except Exception:
                                    pass
                        except Exception:
                            # ignore last_response printing errors
                            pass

                except Exception:
                    msg = "Gửi thất bại"
                    append_retry_suffix = True

            # Build final displayed text. Do not append "Thử lại sau" when sending (append_retry_suffix == False)
            if append_retry_suffix:
                self.status_label.setText(f"{msg}. Thử lại sau")
            else:
                self.status_label.setText(msg)
        except Exception:
            pass

    def showEvent(self, event):
        try:
            from Client.Controller.HashController import get_hash_controller

            ctrl = get_hash_controller()
            ctrl.start()
            # Use print for visibility in the terminal per user's preference.
            print("HashController background sender started.", flush=True)
        except Exception as e:
            print("Failed to start HashController:", e, flush=True)

        # Call the base implementation to ensure normal show behavior.
        super().showEvent(event)
