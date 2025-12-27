# Client/UI/loading_ui.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from Client.Controller.SetupController import SetupController

class DownloadWorker(QThread):
    progress = Signal(int)
    status = Signal(str)
    finished = Signal(bool)

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

    def run(self):
        self.controller.progress.connect(self.progress.emit)
        self.controller.status.connect(self.status.emit)
        self.controller.finished.connect(self.finished.emit)
        self.controller.start()  # ← Critical!

class LoadingUI(QWidget):
    ready = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Loading...")
        self.setFixedSize(460, 220)
        self._init_ui()
        self._start_setup()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        title = QLabel("<h2>Virus Scan App</h2>")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        self.lbl_status = QLabel("Checking files…")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.lbl_status)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

    def _start_setup(self):
        controller = SetupController()
        self.worker = DownloadWorker(controller)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.lbl_status.setText)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, success):
        self.lbl_status.setText("Ready!")
        self.progress.setValue(100)
        def emit():
            if self.worker.isRunning():
                self.worker.quit()
                self.worker.wait(1000)
            self.ready.emit()
        QTimer.singleShot(600, emit)