import sys
import json
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QMessageBox, QStackedWidget, QGridLayout
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt
from UI.register_window import RegisterWindow

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

        # Create Grid Layout for responsive design
        self.layout = QGridLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)

        # ✅ Background Label for Image
        self.background_label = QLabel(self.central_widget)
        image_path = os.path.join(os.path.dirname(__file__), "assets", "login_bg.jpeg")
        if os.path.exists(image_path):
            pixmap = QPixmap(image_path)
            self.background_label.setPixmap(pixmap)
            self.background_label.setScaledContents(True)
        else:
            self.background_label.setText("Background image not found")
            self.background_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.layout.addWidget(self.background_label, 0, 0, 1, 1)

        # Create a Widget for the Login Form
        self.form_widget = QWidget(self.central_widget)
        self.form_layout = QVBoxLayout(self.form_widget)
        self.form_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # ✅ Title Label
        self.title_label = QLabel("Cyber Forensic Tool - Login", self.form_widget)
        self.title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("color: white;")
        self.form_layout.addWidget(self.title_label)

        # ✅ Username Input
        self.username_input = QLineEdit(self.form_widget)
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.setStyleSheet(self.input_style())
        self.form_layout.addWidget(self.username_input)

        # ✅ Password Input
        self.password_input = QLineEdit(self.form_widget)
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(self.input_style())
        self.form_layout.addWidget(self.password_input)

        # ✅ Login Button
        self.login_button = QPushButton("Login", self.form_widget)
        self.login_button.setFont(QFont("Arial", 12))
        self.login_button.setStyleSheet(self.button_style("#0275d8"))
        self.login_button.clicked.connect(self.login)
        self.form_layout.addWidget(self.login_button)

        # ✅ Register Button
        self.register_button = QPushButton("New User? Register", self.form_widget)
        self.register_button.setFont(QFont("Arial", 10))
        self.register_button.setStyleSheet(self.link_style())
        self.register_button.clicked.connect(self.show_register)
        self.form_layout.addWidget(self.register_button)

        # Add the form widget to the grid layout
        self.layout.addWidget(self.form_widget, 0, 0, 1, 1, alignment=Qt.AlignmentFlag.AlignCenter)

    def login(self):
        """Validate login credentials"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Both fields are required!")
            return

        users = self.load_users()

        if username in users and users[username] == password:
            QMessageBox.information(self, "Login Successful", "Welcome!")
            self.open_main_window(username)  # This correctly passes the username
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def show_register(self):
        """Open Registration Window"""
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.close()

    def open_main_window(self, username):
        """Open Main Window after successful login"""
        from UI.main_window import MainWindow
        self.main_window = MainWindow(username)
        self.main_window.show()
        self.close()

    @staticmethod
    def load_users():
        """Load user credentials from JSON file"""
        try:
            if not os.path.exists(USERS_FILE):
                return {}

            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def input_style():
        """Style for input fields"""
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
        """Style for buttons"""
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
        """Style for link-like buttons"""
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
    window.showMaximized()  # ✅ Show window in full-screen mode by default
    sys.exit(app.exec())
