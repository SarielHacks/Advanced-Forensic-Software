import sys
import os
from PyQt6.QtWidgets import QApplication

def main():
    # Initialize Qt application FIRST
    app = QApplication(sys.argv)
    
    # Set application stylesheet if needed
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f0f0f0;
        }
    """)
    
    # Now import and create the main window
    from UI.main_window import MainWindow
    window = MainWindow()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
