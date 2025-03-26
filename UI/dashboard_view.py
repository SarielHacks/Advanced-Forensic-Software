from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from ui_components import UIComponents

class DashboardView(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.addWidget(UIComponents.create_label("📊 Dashboard Overview", 18))
        layout.addWidget(UIComponents.create_label("🔍 Recent Activities: File Analysis, Disk Imaging"))
        layout.addWidget(UIComponents.create_label("⚡ System Status: Running Smoothly"))
        self.setLayout(layout)
