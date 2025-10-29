# statistics.py
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QFileDialog, QMessageBox

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
        self.table.setHorizontalHeaderLabels(["Time", "Scanner", "File/Target", "Severity", "Notes"])
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.btn_load = QPushButton("Load files...")
        self.btn_export = QPushButton("Export CSV")
        btn_layout.addWidget(self.btn_load)
        btn_layout.addWidget(self.btn_export)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.btn_load.clicked.connect(self.mock_load)
        self.btn_export.clicked.connect(self.export_csv)

    def mock_load(self):
        # demo: add some rows
        self.table.setRowCount(3)
        rows = [
            ("2025-10-17 15:00", "YARA", "C:\\Windows\\System32", "High", "Match found"),
            ("2025-10-17 16:10", "LOKI", "C:\\Users", "Medium", "suspicious"),
            ("2025-10-17 17:20", "YARA", "D:\\Temp", "Low", "benign")
        ]
        for r,row in enumerate(rows):
            for c,val in enumerate(row):
                self.table.setItem(r, c, QTableWidgetItem(val))

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", filter="CSV files (*.csv);;All files (*.*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                # header
                headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]
                f.write(",".join(headers) + "\n")
                for r in range(self.table.rowCount()):
                    rowvals = []
                    for c in range(self.table.columnCount()):
                        item = self.table.item(r, c)
                        rowvals.append(item.text() if item else "")
                    f.write(",".join(rowvals) + "\n")
            QMessageBox.information(self, "Saved", f"Exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
