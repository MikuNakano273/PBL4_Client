# app.py
import sys
from PySide6.QtWidgets import QApplication
import Client.UI.main_ui as main_ui
import Client.Controller as Controller

def main():
    app = QApplication(sys.argv)
    window = main_ui.MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
