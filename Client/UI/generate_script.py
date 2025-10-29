# generate_script.py
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextEdit, QPushButton, QFileDialog, QHBoxLayout, QMessageBox

class GenerateScriptDialog(QDialog):
    def __init__(self, parent=None, generated_text="::example command::"):
        super().__init__(parent)
        self.setWindowTitle("Generate Batch Script")
        self.resize(800, 500)
        self.generated_text = generated_text
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("<h3>Generated Commands / Batch Script</h3>"))
        self.editor = QTextEdit()
        self.editor.setPlainText(self.generated_text)
        layout.addWidget(self.editor)

        btn_layout = QHBoxLayout()
        self.btn_save = QPushButton("Save as .bat")
        self.btn_close = QPushButton("Close")
        btn_layout.addWidget(self.btn_save)
        btn_layout.addWidget(self.btn_close)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.btn_save.clicked.connect(self.save_file)
        self.btn_close.clicked.connect(self.accept)

    def save_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save batch", filter="Batch files (*.bat);;All files (*.*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())
            QMessageBox.information(self, "Saved", f"Saved to {path}")
