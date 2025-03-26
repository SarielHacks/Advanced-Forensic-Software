import os
import json
from PyQt6.QtWidgets import QMainWindow, QPushButton, QLabel, QWidget, QVBoxLayout, QLineEdit, QMessageBox
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

# Path for storing user credentials
USERS_FILE = "users.json"

class RegisterWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Register")
        self.setGeometry(100, 100, 900, 500)
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        # Title
        self.label = QLabel("Register", self)
        self.label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

        # Username Input
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setStyleSheet(self.input_style())
        layout.addWidget(self.username_input)

        # Password Input
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(self.input_style())
        layout.addWidget(self.password_input)

        # Confirm Password Input
        self.confirm_password_input = QLineEdit(self)
        self.confirm_password_input.setPlaceholderText("Confirm password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setStyleSheet(self.input_style())
        layout.addWidget(self.confirm_password_input)

        # Register Button
        self.register_button = QPushButton("Register", self)
        self.register_button.setStyleSheet(self.button_style("#0275d8"))
        self.register_button.clicked.connect(self.register_user)
        layout.addWidget(self.register_button)

        # Back to Login Button
        self.login_button = QPushButton("Back to Login", self)
        self.login_button.setStyleSheet(self.button_style("#5A5A5A"))
        self.login_button.clicked.connect(self.go_to_login)
        layout.addWidget(self.login_button)

        self.central_widget.setLayout(layout)

    def register_user(self):
        """ Register a new user and save to users.json """
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        confirm_password = self.confirm_password_input.text().strip()

        # Input validation
        if not username or not password or not confirm_password:
            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        if not username.isalnum():
            QMessageBox.warning(self, "Error", "Username must be alphanumeric!")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return

        if len(password) < 6:
            QMessageBox.warning(self, "Error", "Password must be at least 6 characters!")
            return

        # Save user credentials
        if self.save_user(username, password):
            QMessageBox.information(self, "Success", "User registered successfully!")
            self.go_to_login()
        else:
            QMessageBox.warning(self, "Error", "Username already exists!")

    def save_user(self, username, password):
        """ Save user to the JSON file """
        users = self.load_users()

        if username in users:
            return False  # User already exists

        users[username] = password  # Save new user

        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)
            return True
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save user: {e}")
            return False

    def load_users(self):
        """ Load existing users from JSON file """
        if not os.path.exists(USERS_FILE):
            return {}

        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def go_to_login(self):
        """ Redirect to Login Window """
        from login_window import LoginWindow  # ✅ Correctly import LoginWindow
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

    @staticmethod
    def input_style():
        """ Style for input fields """
        return """
            QLineEdit {
                border: 2px solid #ccc;
                border-radius: 10px;
                padding: 8px;
                font-size: 14px;
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
