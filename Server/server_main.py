import socket
import os
import threading
import base64
import zipfile
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5000
BASE_DIR = "received_files"

if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

def size_calculate(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def write_log(ip: str, port: int, filename: str, size: int):
    #Ghi log riêng cho từng IP.
    #Mỗi IP có 1 folder riêng trong 'logs', chứa file log.txt.

    ip_folder = os.path.join(BASE_DIR, ip.replace(".", "_"))
    os.makedirs(ip_folder, exist_ok=True)

    log_file = os.path.join(ip_folder, "log.txt")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{ts}] {ip}:{port} -> {filename} ({size_calculate(size)})\n"

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line)


def handle_client(conn, addr):
    ip, port = addr
    print(f"[+] Kết nối từ {ip}:{port}")

    try:
        header_line = conn.recv(4096).decode().strip()
        filename, filesize = header_line.split("|")
        filesize = int(filesize)
        conn.sendall(b"OK")

        ip_folder = os.path.join(BASE_DIR, ip.replace(".", "_"))
        os.makedirs(ip_folder, exist_ok=True)
        save_path = os.path.join(ip_folder, filename)

        received = 0
        with open(save_path, "wb") as f:
            while received < filesize:
                data = conn.recv(8192)
                if not data:
                    break
                f.write(data)
                received += len(data)

        # Giải nén nếu là file zip
        if filename.endswith(".zip"):
            extract_dir = save_path[:-4]
            os.makedirs(extract_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(save_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
                os.remove(save_path)
                print(f"[✓] Đã giải nén vào: {extract_dir}")
            except zipfile.BadZipFile:
                print("[!] File zip bị lỗi, không thể giải nén")

        write_log(ip, port, filename, filesize)
        print(f"[✓] Nhận thành công từ {ip}: {filename}")

    except Exception as e:
        print(f"[!] Lỗi với {ip}: {e}")

    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        print(f"🌍 Server đang chạy tại {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_server()
