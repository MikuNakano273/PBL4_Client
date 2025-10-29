from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QFileDialog, QMessageBox)
from PySide6.QtCore import Qt

class RealtimeScanning(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Real-time Scanning")
        self.resize(600, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        header = QLabel("<h2>Real-time Scanning Options</h2>")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        subtitle = QLabel("Configure your real-time scanning preferences below:")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        btn_layout = QHBoxLayout()

        self.btn_enable_scanning = QPushButton("Enable Scanning")
        self.btn_disable_scanning = QPushButton("Disable Scanning")

        btn_layout.addWidget(self.btn_enable_scanning)
        btn_layout.addWidget(self.btn_disable_scanning)

        layout.addLayout(btn_layout)

        # connections
        self.btn_enable_scanning.clicked.connect(self.enable_scanning)
        self.btn_disable_scanning.clicked.connect(self.disable_scanning)

        footer = QLabel("<i>Configure real-time scanning settings as needed.</i>")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)

        self.setLayout(layout)

    def enable_scanning(self):
        QMessageBox.information(self, "Real-time Scanning", "Real-time scanning has been enabled.")

    def disable_scanning(self):
        QMessageBox.information(self, "Real-time Scanning", "Real-time scanning has been disabled.")