import sys
from PySide6.QtWidgets import QApplication, QWidget, QFileDialog, QMessageBox, QInputDialog
from PySide6.QtCore import QThread, Signal, QFileInfo
from Client.Model.file_sender import FileSender
from Client.UI.main_ui import Ui_Widget
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

CHUNK_SIZE = 64 * 1024  # 64KB

class SendThread(QThread):
    progress = Signal(int)
    done = Signal()
    error = Signal(str)

    def __init__(self, path, server_ip="192.168.0.10", server_port=5000):
        super().__init__()
        self.path = path
        self.server_ip = server_ip
        self.server_port = server_port


    def run(self):
        try:
            sender = FileSender(self.server_ip, self.server_port)
            sender.send(self.path, progress_callback=self.progress.emit)
            self.done.emit()
        except Exception as e:
            self.error.emit(str(e))


class MainController(QWidget, Ui_Widget):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.file_path = None
        self.thread = None

        self.btnBrowseFile.clicked.connect(self.select_file)
        self.btnBrowseFolder.clicked.connect(self.select_folder)
        self.btnSend.clicked.connect(self.start_send)

    def encrypt_file(self, file_path, key):
        """Mã hóa file bằng AES-256 CBC"""
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv

        encrypted_path = file_path + ".enc"
        with open(file_path, "rb") as f_in, open(encrypted_path, "wb") as f_out:
            f_out.write(iv)  # ghi IV vào đầu file
            while chunk := f_in.read(CHUNK_SIZE):
                padded_chunk = pad(chunk, AES.block_size)
                encrypted_chunk = cipher.encrypt(padded_chunk)
                f_out.write(encrypted_chunk)

        return encrypted_path

    def select_file(self):
        """Chọn file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Chọn file cần gửi",
            self.file_path or "",  # mở lại thư mục cuối
            "All Files (*)"
        )
        if file_path:
            self.file_path = file_path
            self.txtFilePath.setText(file_path)

    def select_folder(self):
        """Chọn thư mục"""
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Chọn thư mục cần gửi",
            self.file_path or ""
        )
        if folder_path:
            self.file_path = folder_path
            self.txtFilePath.setText(folder_path)

    def thread_finished(self):
        self.btnSend.setEnabled(True)
        self.btnBrowseFolder.setEnabled(True)
        self.btnBrowseFile.setEnabled(True)
        self.thread = None

    def start_send(self):
        """Khởi chạy thread gửi file"""
        if not self.file_path:
            QMessageBox.warning(self, "Lỗi", "Chưa chọn file hoặc thư mục!")
            return

        if self.thread and self.thread.isRunning():
            QMessageBox.warning(self, "Đang gửi", "Vui lòng chờ quá trình hiện tại hoàn tất!")
            return

        self.progressBar.setValue(0)
        self.thread = SendThread(self.file_path)

        self.thread.progress.connect(self.progressBar.setValue)
        self.thread.done.connect(lambda: QMessageBox.information(self, "Thành công", "Đã gửi file xong!"))
        self.thread.error.connect(lambda msg: QMessageBox.critical(self, "Lỗi", msg))
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.error.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.thread_finished)
        self.btnSend.setEnabled(False)
        self.btnBrowseFolder.setEnabled(False)
        self.btnBrowseFile.setEnabled(False)
        self.thread.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainController()
    window.show()
    sys.exit(app.exec())
