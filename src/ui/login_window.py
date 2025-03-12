import sys
import json
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QMessageBox, QStackedWidget
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt
from register_window import RegisterWindow  # ✅ Fix missing import

# Store user credentials
USERS_FILE = "users.json"

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("User Login")
        self.setGeometry(100, 100, 900, 500)
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        # ✅ Fix: Ensure background image exists before using it
        background_label = QLabel(self.central_widget)
        image_path = r"/home/sariel/Desktop/Automated Forensics Software/Anaswara/assets/bg.jpg"
        if os.path.exists(image_path):  # ✅ Check if image exists
            pixmap = QPixmap(image_path)
            background_label.setPixmap(pixmap)
            background_label.setScaledContents(True)
            background_label.setGeometry(0, 0, 900, 500)
        else:
            print(f"Warning: Background image not found at {image_path}")

        # Stack widgets to place login form on top of the background
        self.stacked_widget = QStackedWidget(self.central_widget)
        self.stacked_widget.setGeometry(250, 100, 400, 300)

        login_widget = QWidget()
        layout = QVBoxLayout(login_widget)

        # Title
        self.title_label = QLabel("Cyber Forensic Tool - Login", self)
        self.title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("color: white;")
        layout.addWidget(self.title_label)

        # Username Input
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.setStyleSheet(self.input_style())
        layout.addWidget(self.username_input)

        # Password Input
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(self.input_style())
        layout.addWidget(self.password_input)

        # Login Button
        self.login_button = QPushButton("Login", self)
        self.login_button.setFont(QFont("Arial", 12))
        self.login_button.setStyleSheet(self.button_style("#0275d8"))
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        # Register Button
        self.register_button = QPushButton("New User? Register", self)
        self.register_button.setFont(QFont("Arial", 10))
        self.register_button.setStyleSheet(self.link_style())
        self.register_button.clicked.connect(self.show_register)  # ✅ Fix: Register button correctly opens RegisterWindow
        layout.addWidget(self.register_button)

        self.stacked_widget.addWidget(login_widget)
        self.stacked_widget.setCurrentWidget(login_widget)

    def login(self):
        """ Validate login credentials """
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Both fields are required!")
            return

        users = self.load_users()

        if username in users and users[username] == password:  # ✅ Check against stored users
            QMessageBox.information(self, "Login Successful", "Welcome!")
            self.open_main_window()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def show_register(self):
        """ Open Registration Window """
        self.register_window = RegisterWindow()  # ✅ No more NameError!
        self.register_window.show()
        self.close()

    def open_main_window(self):
        """ Open the Main Window after successful login """
        from main_window import MainWindow  # ✅ Lazy import to avoid circular dependency
        self.main_window = MainWindow()
        self.main_window.show()
        self.close()

    @staticmethod
    def load_users():
        """ Load user credentials from JSON file """
        try:
            if not os.path.exists(USERS_FILE):  # ✅ Ensure the file exists
                return {}

            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def input_style():
        """ Style for input fields """
        return """
            QLineEdit {
                border: 2px solid white;
                border-radius: 10px;
                padding: 8px;
                background: rgba(255, 255, 255, 0.2);
                color: white;
                font-size: 14px;
            }
            QLineEdit::placeholder {
                color: white;
                opacity: 0.7;
            }
        """

    @staticmethod
    def button_style(color):
        """ Style for buttons """
        return f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border-radius: 10px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #0056b3;
            }}
        """

    @staticmethod
    def link_style():
        """ Style for link-like buttons """
        return """
            QPushButton {
                color: white;
                background: none;
                border: none;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #ccc;
            }
        """


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
