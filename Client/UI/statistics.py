from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QFileDialog, QMessageBox
import csv
from PySide6.QtCore import Qt

class StatisticsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Statistics")
        self.resize(900, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("<h3>Scan Statistics</h3>"))

        self.table = QTableWidget(0, 5)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setHorizontalHeaderLabels(["Time", "Scanner", "File/Target", "Severity", "Notes"])
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.btn_load = QPushButton("Load files...")
        self.btn_export = QPushButton("Export CSV")
        btn_layout.addWidget(self.btn_load)
        btn_layout.addWidget(self.btn_export)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.btn_load.clicked.connect(self.csv_load)
        self.btn_export.clicked.connect(self.export_csv)

    def csv_load(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Chọn file CSV",
            "",
            "CSV Files (*.csv)"
        )

        if not file_name:
            return

        try:
            with open(file_name, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                first_row = next(reader, None)

                expected_header = ["virus-app"]
                if first_row != expected_header:
                    QMessageBox.warning(
                        self,
                        "Sai file",
                        "File này không phải được tạo bởi ứng dụng của bạn!\nVui lòng chọn lại file đúng."
                    )
                    return

                header_row = next(reader, None)

                self.table.setRowCount(0)

                for row in reader:
                    if not row:
                        continue
                    row_position = self.table.rowCount()
                    self.table.insertRow(row_position)
                    for col, value in enumerate(row):
                        item = QTableWidgetItem(value)
                        item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Không cho sửa
                        self.table.setItem(row_position, col, item)

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Không thể đọc file:\n{e}")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save CSV",
            filter="CSV files (*.csv);;All files (*.*)"
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8", newline='') as f:
                f.write("virus-app\n")

                for r in range(self.table.rowCount()):
                    rowvals = []
                    for c in range(self.table.columnCount()):
                        item = self.table.item(r, c)
                        rowvals.append(item.text() if item else "")
                    f.write(",".join(rowvals) + "\n")

            QMessageBox.information(self, "Saved", f"File log đã được lưu: {path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Không thể lưu file:\n{e}")
