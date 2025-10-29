# main_window.py
from tkinter.constants import CENTER

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QSize
from scipy.ndimage import center_of_mass

from Client.UI.scan_options import ScanOptionsPage
from Client.UI.statistics import StatisticsDialog
from Client.UI.scanning import ScanningDialog
from Client.UI.generate_script import GenerateScriptDialog
from Client.UI.real_time_scanning import RealtimeScanning


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Virus scan app")
        self.resize(1000, 600)
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        self.setLayout(main_layout)

        # --- MENU BÊN TRÁI ---
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)

        # Thêm nhãn MENU
        menu_label = QLabel("Menu")
        menu_label.setAlignment(Qt.AlignCenter)
        menu_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 18px;
                font-weight: bold;
                background-color: #23272a;
                padding: 10px;
                border-bottom: 2px solid #7289da;
            }
        """)
        left_layout.addWidget(menu_label)

        # Thêm danh sách menu
        self.menu = QListWidget()
        self.menu.setStyleSheet("""
            QListWidget {
                background-color: #2c2f33;
                color: white;
                border: none;
                font-size: 16px;
                outline: none;
            }
            QListWidget::item {
                padding: 14px;
            }
            QListWidget::item:selected {
                background-color: #7289da;
                border: none;
                outline: none;
            }
            QListWidget::item:hover {
                background-color: #99aab5;
            }
        """)

        menu_items = ["Home", "Local scan", "View statistics", "Real-time scanner"]
        for item_text in menu_items:
            item = QListWidgetItem(item_text)
            item.setTextAlignment(Qt.AlignCenter)
            item.setSizeHint(QSize(150, 50))
            self.menu.addItem(item)

        left_layout.addWidget(self.menu)
        main_layout.addWidget(left_widget, 2)

        # --- KHU VỰC NỘI DUNG (BÊN PHẢI) ---
        self.content_area = QStackedWidget()
        main_layout.addWidget(self.content_area, 8)

        # --- MỖI TRANG ---
        self.page_welcome = self.create_welcome_page()
        self.page_scan = ScanOptionsPage()
        self.page_stats = StatisticsDialog()
        self.page_realtime = RealtimeScanning()

        # Thêm vào stack
        self.content_area.addWidget(self.page_welcome)
        self.content_area.addWidget(self.page_scan)
        self.content_area.addWidget(self.page_stats)
        self.content_area.addWidget(self.page_realtime)

        self.page_scan.next_clicked.connect(self.show_scan_dialog)

        # Khi chọn menu
        self.menu.currentRowChanged.connect(self.display_page)

        # Chọn trang mặc định
        self.menu.setCurrentRow(0)
        self.display_page(0)

    def create_welcome_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel("<h1>Welcome!</h1>")
        header.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("Select a feature from the left menu.")
        subtitle.setAlignment(Qt.AlignCenter)
        footer = QLabel("<i>Ported GUI — logic not included. Connect backend as needed.</i>")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        layout.addWidget(subtitle)
        layout.addStretch()
        layout.addWidget(footer)
        return page

    def display_page(self, index):
        # Mapping menu index → content page
        if index == 0:
            self.content_area.setCurrentWidget(self.page_welcome)
        elif index == 1:
            self.content_area.setCurrentWidget(self.page_scan)
        elif index == 2:
            self.content_area.setCurrentWidget(self.page_stats)
        elif index == 3:
            self.content_area.setCurrentWidget(self.page_realtime)

    def show_scan_dialog(self):
        if not hasattr(self, "page_scan_dialog"):
            self.page_scan_dialog = ScanningDialog(main_window=self)  # ✅ truyền thẳng
            self.content_area.addWidget(self.page_scan_dialog)

        self.content_area.setCurrentWidget(self.page_scan_dialog)

    def go_to_scan_options(self):
        self.content_area.setCurrentWidget(self.page_scan)
        self.menu.setCurrentRow(1)
