from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class ScanOptionsPage(QWidget):
    next_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Scan Target</h2>"))

        group = QGroupBox("Select scan target")
        g_layout = QVBoxLayout()

        # --- File row ---
        file_row = QHBoxLayout()
        file_label = QLabel("File:")
        file_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)

        self.path_file = QLabel("")
        self.path_file.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        btn_file = QPushButton("Browse")
        btn_file.setMinimumWidth(120)
        btn_file.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        btn_file.clicked.connect(self._browse_file)

        file_row.addWidget(file_label)
        file_row.addWidget(self.path_file, 1)
        file_row.addWidget(btn_file)

        # --- Folder row ---
        dir_row = QHBoxLayout()
        dir_label = QLabel("Folder:")
        dir_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)

        self.path_dir = QLabel("")
        self.path_dir.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        btn_dir = QPushButton("Browse")
        btn_dir.setMinimumWidth(120)
        btn_dir.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        btn_dir.clicked.connect(self._browse_dir)

        dir_row.addWidget(dir_label)
        dir_row.addWidget(self.path_dir, 1)
        dir_row.addWidget(btn_dir)

        g_layout.addLayout(file_row)
        g_layout.addLayout(dir_row)
        group.setLayout(g_layout)
        layout.addWidget(group)

        # Optional
        layout.addWidget(QLabel("<b>Optional</b>"))

        # Limit CPU usage option (only applicable when scanning a folder).
        self.chk_limit_cpu = QCheckBox("Limit CPU usage (approx. ~50%)")
        self.chk_limit_cpu.setToolTip(
            "If enabled and a folder is selected, the scanner will insert short sleeps between files to reduce average CPU usage."
        )
        # Use a brighter, high-contrast green for the checked indicator to improve visibility
        try:
            self.chk_limit_cpu.setStyleSheet(
                "QCheckBox::indicator { width: 16px; height: 16px; }"
                "QCheckBox::indicator:unchecked { background-color: transparent; border: 1px solid #4a4a4a; border-radius: 3px; }"
                "QCheckBox::indicator:checked { background-color: #09eb49; border: 1px solid #09eb49; border-radius: 3px; }"
            )
        except Exception:
            pass
        # Initially disabled until a folder is selected
        self.chk_limit_cpu.setEnabled(False)
        layout.addWidget(self.chk_limit_cpu)

        # Full scan option: when enabled, scanner will skip Authenticode signature
        # and size-based skipping in native scanner and perform only hash + YARA checks.
        self.chk_full_scan = QCheckBox(
            "Full scan (scan full files without any restrictions)"
        )
        self.chk_full_scan.setToolTip(
            "If enabled, the native scanner will skip publisher signature checks and size-based skips. Use with caution."
        )
        try:
            self.chk_full_scan.setStyleSheet(
                "QCheckBox::indicator { width: 16px; height: 16px; }"
                "QCheckBox::indicator:unchecked { background-color: transparent; border: 1px solid #4a4a4a; border-radius: 3px; }"
                "QCheckBox::indicator:checked { background-color: #09eb49; border: 1px solid #09eb49; border-radius: 3px; }"
            )
        except Exception:
            pass
        # Default off
        try:
            self.chk_full_scan.setChecked(False)
        except Exception:
            pass
        layout.addWidget(self.chk_full_scan)

        btn_layout = QHBoxLayout()
        self.btn_next = QPushButton("Next")
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_next)
        layout.addLayout(btn_layout)

        self.btn_next.clicked.connect(self.on_next)

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.path_file.setText(path)
            self.path_dir.setText("")
            try:
                self.chk_limit_cpu.setEnabled(False)
                self.chk_limit_cpu.setChecked(False)
            except Exception:
                pass

    def _browse_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            self.path_dir.setText(path)
            self.path_file.setText("")
            try:
                self.chk_limit_cpu.setEnabled(True)
            except Exception:
                pass

    def on_next(self):
        if not self.path_file.text() and not self.path_dir.text():
            QMessageBox.warning(
                self, "Validation", "Please select a file or folder to scan."
            )
            return
        self.next_clicked.emit()

    def get_selected_path(self):
        if self.path_file.text():
            return self.path_file.text()
        elif self.path_dir.text():
            return self.path_dir.text()
        return ""

    def get_immediate_quarantine(self) -> bool:
        return False

    def get_limit_cpu(self) -> bool:
        try:
            return bool(self.chk_limit_cpu.isChecked())
        except Exception:
            return False

    def get_full_scan(self) -> bool:
        try:
            return bool(self.chk_full_scan.isChecked())
        except Exception:
            return False
