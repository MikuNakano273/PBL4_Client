from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QRadioButton, QGroupBox,
    QCheckBox, QPushButton, QHBoxLayout, QMessageBox
)
from PySide6.QtCore import Qt, Signal


class ScanOptionsPage(QWidget):
    # Signal khi người dùng bấm Next
    next_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<h2>Scan Target</h2>"))

        group = QGroupBox("Required (choose one)")
        g_layout = QVBoxLayout()
        self.rb_all_drives = QRadioButton("Scan all local drives")
        self.rb_specific_drives = QRadioButton("Scan specific drive(s)")
        self.rb_specific_dirs = QRadioButton("Scan specific/suspicious directories")
        g_layout.addWidget(self.rb_all_drives)
        g_layout.addWidget(self.rb_specific_drives)
        g_layout.addWidget(self.rb_specific_dirs)
        group.setLayout(g_layout)
        layout.addWidget(group)

        # Optional
        layout.addWidget(QLabel("<b>Optional</b>"))
        self.chk_pe_sieve = QCheckBox("Enable memory scan (PE-sieve)")
        self.chk_limit_cpu = QCheckBox("Limit CPU usage (use process-governor)")
        layout.addWidget(self.chk_pe_sieve)
        layout.addWidget(self.chk_limit_cpu)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_next = QPushButton("Next")
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_next)
        layout.addLayout(btn_layout)

        # Signal
        self.btn_next.clicked.connect(self.on_next)

    def on_next(self):
        if not (self.rb_all_drives.isChecked() or self.rb_specific_drives.isChecked() or self.rb_specific_dirs.isChecked()):
            QMessageBox.warning(self, "Validation", "Please choose one required option.")
            return
        # Gửi tín hiệu để MainWindow biết chuyển sang trang Scanning
        self.next_clicked.emit()
