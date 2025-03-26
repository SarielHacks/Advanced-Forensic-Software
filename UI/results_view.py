from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from UI.ui_components import UIComponents

class ResultsView(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.addWidget(UIComponents.create_label("📊 Analysis Results", 18))
        layout.addWidget(UIComponents.create_label("✔️ Files Analyzed: 45,231"))
        layout.addWidget(UIComponents.create_label("❌ Deleted Files: 1,205"))
        layout.addWidget(UIComponents.create_label("⚠️ Suspicious Files: 23"))
        self.setLayout(layout)
