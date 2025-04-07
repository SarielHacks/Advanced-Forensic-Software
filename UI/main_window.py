import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt
from UI.login_window import LoginWindow  # Import LoginWindow for transitioning


class MainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("WELCOME!")
        self.setGeometry(100, 100, 900, 500)
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout(self.central_widget)

        # Background Image
        background_label = QLabel(self)
        pixmap = QPixmap(os.path.join(os.path.dirname(__file__), "assets", "main_background.jpg"))
        if not pixmap.isNull():
            background_label.setPixmap(pixmap)
            background_label.setScaledContents(True)
            background_label.setGeometry(0, 0, 900, 500)
        else:
            background_label.setText("Image not found")
            background_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(background_label)

        # Title
        self.title_label = QLabel("Cyber Forensic Tool", self)
        self.title_label.setFont(QFont("Arial", 30, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: black; background-color: rgba(255, 255, 255, 150);")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)

        # Caption
        self.caption_label = QLabel(
            "A comprehensive cyber forensic tool for analyzing digital evidence, providing forensic reports, and ensuring data integrity.",
            self
        )
        self.caption_label.setFont(QFont("Arial", 12))
        self.caption_label.setStyleSheet("color: black; background-color: rgba(255, 255, 255, 200);")
        self.caption_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.caption_label.setWordWrap(True)
        layout.addWidget(self.caption_label)

        # Upload Evidence Button
        self.upload_button = QPushButton("📁 Upload Evidence", self)
        self.upload_button.setFont(QFont("Arial", 14))
        self.upload_button.setStyleSheet("background-color: #0275d8; color: white; padding: 10px; border-radius: 5px;")
        self.upload_button.clicked.connect(self.open_evidence_upload)
        layout.addWidget(self.upload_button, alignment=Qt.AlignmentFlag.AlignCenter)

    def open_evidence_upload(self):
        """ Open the Evidence Upload Window """
        try:
            from UI.evidence_upload_window import EvidenceUploadWindow
            self.evidence_window = EvidenceUploadWindow(self.username)
            self.evidence_window.show()
            self.close()
        except Exception as e:
            print(f"Error opening Evidence Upload Window: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
