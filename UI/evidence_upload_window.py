import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
    QWidget, QFileDialog, QListWidget, QMessageBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

class EvidenceUploadWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Forensic Tool - Evidence Upload")
        self.setGeometry(100, 100, 900, 600)
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()
        
        # Sidebar layout
        sidebar = QVBoxLayout()
        
        self.back_button = QPushButton("← Back")
        self.back_button.setFont(QFont("Arial", 12))
        self.back_button.setStyleSheet("background-color: #ccc; padding: 8px;")
        self.back_button.clicked.connect(self.go_back)
        sidebar.addWidget(self.back_button)
        
        self.disk_selection_button = QPushButton("💾 Disk Selection")
        self.disk_selection_button.setFont(QFont("Arial", 12))
        self.disk_selection_button.clicked.connect(self.open_file_dialog)
        sidebar.addWidget(self.disk_selection_button)
        
        self.analysis_button = QPushButton("🔍 Analysis")
        self.analysis_button.setFont(QFont("Arial", 12))
        self.analysis_button.clicked.connect(self.start_analysis)
        sidebar.addWidget(self.analysis_button)
        
        self.report_button = QPushButton("📄 Report")
        self.report_button.setFont(QFont("Arial", 12))
        self.report_button.clicked.connect(self.show_report)
        sidebar.addWidget(self.report_button)
        
        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setFixedWidth(200)
        main_layout.addWidget(sidebar_widget)
        
        # Main content area
        self.content_layout = QVBoxLayout()
        self.title_label = QLabel("Disk Analysis Dashboard")
        self.title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_layout.addWidget(self.title_label)
        
        self.evidence_list = QListWidget()
        self.content_layout.addWidget(self.evidence_list)
        
        content_widget = QWidget()
        content_widget.setLayout(self.content_layout)
        main_layout.addWidget(content_widget)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def open_file_dialog(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Evidence File", "", "All Files (*.*)")
        if file_path:
            self.evidence_list.addItem(file_path)
    
    def start_analysis(self):
        QMessageBox.information(self, "Analysis", "Analysis started on selected evidence.")
    
    def show_report(self):
        QMessageBox.information(self, "Report", "Analysis report generated. Download available.")
    
    def go_back(self):
        self.close()
        # You can integrate navigation to home if needed.

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EvidenceUploadWindow()
    window.show()
    sys.exit(app.exec())
