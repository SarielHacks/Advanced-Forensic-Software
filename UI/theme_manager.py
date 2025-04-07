from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtWidgets import QApplication

class ThemeManager:
    @staticmethod
    def apply_dark_theme(app: QApplication):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(40, 40, 40))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(50, 50, 50))
        app.setPalette(dark_palette)
