import importlib.util
import os
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

# === PYINSTALLER BUNDLE FIX ===
if getattr(sys, "frozen", False):
    bundle_dir = sys._MEIPASS
    print(f"[DEBUG] Running in .exe, bundle_dir = {bundle_dir}")
else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"[DEBUG] Running in dev, bundle_dir = {bundle_dir}")

# Add Client/ to path
client_path = os.path.join(bundle_dir, "Client")
if client_path not in sys.path:
    sys.path.insert(0, client_path)
print(f"[DEBUG] sys.path[0] = {sys.path[0]}")

# === LIST BUNDLED FILES ===
print("[DEBUG] Listing bundled Client/UI folder:")
ui_dir = os.path.join(bundle_dir, "Client", "UI")
if os.path.exists(ui_dir):
    for f in os.listdir(ui_dir):
        print(f"  → {f}")
else:
    print(f"[ERROR] Client/UI folder NOT FOUND at {ui_dir}")

try:
    from Client.UI.loading_ui import LoadingUI

    print("[SUCCESS] LoadingUI imported")
except Exception as e:
    print(f"[FATAL] Cannot import LoadingUI: {e}")
    sys.exit(1)


def load_main_window():
    ui_path = os.path.join(bundle_dir, "Client", "UI", "main_ui.py")
    print(f"[DEBUG] Trying to load: {ui_path}")

    if not os.path.exists(ui_path):
        print(f"[ERROR] main_ui.py NOT FOUND at {ui_path}")
        return None

    try:
        spec = importlib.util.spec_from_file_location("main_ui", ui_path)
        if spec is None:
            print("[ERROR] spec is None")
            return None
        main_ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_ui)
        if hasattr(main_ui, "MainWindow"):
            print("[SUCCESS] MainWindow class loaded")
            return main_ui.MainWindow
        else:
            print("[ERROR] main_ui.py exists but has no MainWindow class")
            return None
    except Exception as e:
        print(f"[FATAL] Exception loading main_ui.py: {e}")
        import traceback

        traceback.print_exc()
        return None


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # === STORE main_window HERE ===
    app.main_window = None
    loading = LoadingUI()
    loading.show()
    print("[DEBUG] Loading screen shown")

    MainWindowClass = load_main_window()
    if not MainWindowClass:
        QMessageBox.critical(None, "Error", "Cannot load main UI.")
        return

    def open_main():
        try:
            # Initialize a single global YARA scanner instance now that the loading/setup
            # has completed. This moves the scanner init after SetupController runs so
            # the DB download/setup can occur before any global scanner attempts to open the DB.
            try:
                from Client.Model.YaraScannerModel import get_global_scanner

                print("[DEBUG] Initializing global yara scanner...")
                # Request creation and initialization of the global scanner using defaults.
                # Any initialization errors will be logged but won't stop the UI from loading.
                try:
                    get_global_scanner(init_if_missing=True)
                    print("[DEBUG] Global yara scanner initialized")
                except Exception as ie:
                    print(f"[WARN] Global yara scanner init failed: {ie}")
            except Exception as e:
                print(f"[WARN] get_global_scanner not available: {e}")

            print("[DEBUG] Creating MainWindow...")
            app.main_window = MainWindowClass()
            app.main_window.resize(1000, 600)
            app.main_window.show()
            app.main_window.raise_()
            app.main_window.activateWindow()

            QTimer.singleShot(200, loading.close)
        except Exception as e:
            print(f"[ERROR] {e}")
            QMessageBox.critical(None, "Crash", str(e))

    loading.ready.connect(open_main)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
