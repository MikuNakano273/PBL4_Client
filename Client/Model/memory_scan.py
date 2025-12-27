import os
import requests
import zipfile
import io
import psutil
import subprocess


def ensure_pe_sieve():
    """Tự động tải PE-sieve nếu chưa có"""
    tools_dir = os.path.join(os.path.dirname(__file__), "Tools")
    os.makedirs(tools_dir, exist_ok=True)
    exe_path = os.path.join(tools_dir, "pe-sieve.exe")

    if os.path.exists(exe_path):
        return exe_path

    print("[INFO] Downloading PE-sieve...")
    url = "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve64.zip"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(tools_dir)
    except Exception as e:
        print(f"[ERROR] Could not download PE-sieve: {e}")
        return None

    return exe_path if os.path.exists(exe_path) else None


def run_memory_scan_with_callback(callback):
    """Quét toàn bộ process bằng PE-sieve, gọi callback(pid, name, status)"""
    exe_path = ensure_pe_sieve()
    if not exe_path:
        callback(0, "PE-sieve", "Download failed")
        return

    for proc in psutil.process_iter(['pid', 'name']):
        pid, name = proc.info['pid'], proc.info['name']
        try:
            subprocess.run(
                [exe_path, "/pid", str(pid), "/quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10
            )
            callback(pid, name, "Scanned successfully")
        except subprocess.TimeoutExpired:
            callback(pid, name, "Timeout")
        except Exception as e:
            callback(pid, name, f"Error: {e}")
