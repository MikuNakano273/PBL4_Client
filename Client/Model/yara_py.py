import yara
import os
import sys

# ================================
# CONFIGURATION
# ================================

RULE_FILE = "C:/Users/Nam/PycharmProjects/PBL4_Client/Rules/extended.yar"                    # Your YARA rule file
SCAN_PATH = "C:/Users/Nam/Downloads"                  # CHANGE THIS TO YOUR TARGET DIRECTORY

# ================================

def scan_directory(rule_file, scan_path):
    # Validate paths
    if not os.path.isfile(rule_file):
        print(f"[!] Rule file not found: {rule_file}")
        return
    if not os.path.isdir(scan_path):
        print(f"[!] Scan path not found or not a directory: {scan_path}")
        return

    # Compile rules
    try:
        rules = yara.compile(filepath=rule_file)
    except Exception as e:
        print(f"[!] Failed to compile rules: {e}")
        return

    # Scan
    print(f"[+] Scanning: {scan_path}")
    print(f"[+] Using rules: {rule_file}\n")

    for root, _, files in os.walk(scan_path):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                matches = rules.match(filepath)
                if matches:
                    for match in matches:
                        print(f"MATCH: {match.rule} -> {filepath}")
            except:
                pass  # Skip unreadable or unsupported files

    print("\n[+] Scan complete.")

if __name__ == "__main__":
    # Optional: override scan path via command line
    if len(sys.argv) > 1:
        SCAN_PATH = sys.argv[1]

    scan_directory(RULE_FILE, SCAN_PATH)