from PyQt6.QtWidgets import QMainWindow, QPushButton, QLabel, QWidget, QVBoxLayout
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

class DashboardWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard")
        self.setGeometry(100, 100, 500, 400)
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        self.label = QLabel("Welcome to Cyber Forensic Tool!", self)
        self.label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

        self.logout_button = QPushButton("Logout", self)
        self.logout_button.clicked.connect(self.logout)
        layout.addWidget(self.logout_button)

        self.central_widget.setLayout(layout)

    def logout(self):
        from main_window import MainWindow  # Lazy import here to avoid circular dependency
        self.login_window = MainWindow()
        self.login_window.show()
        self.close()
