import os
import socket
import zipfile
import tempfile
from Crypto.Cipher import


class FileSender:
    def __init__(self, server_ip='192.168.0.10', server_port=5000):
        self.server_ip = server_ip
        self.server_port = server_port
        self.chunk_size = 4096
        self.max_size = 1024 * 1024 * 1024  # 1Gb

    def _zip_folder(self, folder_path):
        """Nén toàn bộ folder (kể cả folder con) thành file zip tạm."""
        tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(tmp_zip.name, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, folder_path)
                    zipf.write(abs_path, rel_path)
        return tmp_zip.name

    def send(self, path, progress_callback=None):
        if not os.path.exists(path):
            raise FileNotFoundError("Đường dẫn không tồn tại!")

        if os.path.isdir(path):
            zip_path = self._zip_folder(path)
            filename = os.path.basename(path.rstrip("/\\")) + ".zip"
        else:
            zip_path = path
            filename = os.path.basename(path)

        file_size = os.path.getsize(zip_path)
        if file_size > self.max_size:
            raise ValueError("File vượt quá kích thước 500MB!")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_ip, self.server_port))

            # Gửi header filename|filesize
            header = f"{filename}|{file_size}".encode()
            s.sendall(header + b"\n")
            s.recv(2)  # nhận OK

            # Gửi dữ liệu nhị phân
            sent = 0
            with open(zip_path, "rb") as f:
                while chunk := f.read(self.chunk_size):
                    s.sendall(chunk)
                    sent += len(chunk)
                    if progress_callback:
                        progress_callback(int(sent / file_size * 100))

        if os.path.isdir(path):
            os.remove(zip_path)

        print(f"[✓] Đã gửi thành công: {filename}")
