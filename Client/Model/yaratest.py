# Client/Model/yaratest.py
import sys
from pathlib import Path
from yarascanner import YaraScanner

# ------------------------------------------------------------------
# PATH: Use Rules/full.yar (not dist/Rules/)
# ------------------------------------------------------------------
def get_rules_path():
    if getattr(sys, 'frozen', False):
        # Inside .exe → _MEIPASS/Rules/full.yar
        base = Path(sys._MEIPASS)
    else:
        # Development → PBL4_Client/Rules/full.yar
        base = Path(__file__).parent.parent.parent

    rules_path = base / "Rules" / "extended.yar"
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")
    return str(rules_path)

# ------------------------------------------------------------------
# CALLBACK
# ------------------------------------------------------------------
def on_event(res):
    if res.isMalware:
        print(f"[MALWARE] {res.filename} : {res.filepath} : {res.desc}")
    else:
        print(f"[LOG] {res.severity} | {res.desc}")

# ------------------------------------------------------------------
# SCAN
# ------------------------------------------------------------------
def scan_file(filepath):
    rules_path = get_rules_path()
    print(f"[INFO] Loading rules: {rules_path}")

    s.init(rules_path.encode('utf-8'))
    print(f"[INFO] Scanning: {filepath}")
    s.scan(filepath.encode('utf-8'), on_event)

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
if __name__ == "__main__":
    s = YaraScanner()
    try:
        scan_file(r"C:/Users/Nam/Downloads")
    finally:
        s.shutdown()
        print("[SUCCESS] YARA scanner shut down.")