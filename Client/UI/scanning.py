from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout, QMessageBox

class ScanningDialog(QWidget):
    def __init__(self, main_window=None):
        super().__init__()
        self.main_window = main_window  # ✅ giữ tham chiếu đến MainWindow
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<h3>Scan Output</h3>"))

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Scan output will be shown here (stdout/stderr).")
        layout.addWidget(self.output)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_stop = QPushButton("Stop")
        self.btn_back = QPushButton("Back")
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_back)
        layout.addLayout(btn_layout)

        self.btn_stop.clicked.connect(self.stop_scanning)
        self.btn_back.clicked.connect(self.go_back)

    def append_output(self, text: str):
        self.output.append(text)

    def stop_scanning(self):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Stop scanning")
        msg_box.setText("Do you want to stop scanning?")
        msg_box.setIcon(QMessageBox.Warning)

        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)

        msg_box.setDefaultButton(QMessageBox.No)

        result = msg_box.exec()

        if result == QMessageBox.Yes:
            print("ok")
        elif result == QMessageBox.No:
            msg_box.close()
            self.append_output("Scan stopped by user.")

    def go_back(self):
        if self.main_window is None:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Error")
            msg_box.setText("Error!")
            return

        mw = self.main_window
        if hasattr(mw, "content_area") and hasattr(mw, "page_scan"):
            mw.content_area.setCurrentWidget(mw.page_scan)
            mw.menu.setCurrentRow(1)
        else:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Error")
            msg_box.setText("Error!")

