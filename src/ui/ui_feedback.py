from PyQt6.QtWidgets import QMessageBox

class UIFeedback:
    @staticmethod
    def show_error(message):
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Icon.Critical)
        error_box.setWindowTitle("Error")
        error_box.setText(message)
        error_box.exec()

    @staticmethod
    def show_info(message):
        info_box = QMessageBox()
        info_box.setIcon(QMessageBox.Icon.Information)
        info_box.setWindowTitle("Information")
        info_box.setText(message)
        info_box.exec()
