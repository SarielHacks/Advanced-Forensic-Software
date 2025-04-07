from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton
from UI.ui_components import UIComponents, UIFeedback

class PluginInterface(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.addWidget(UIComponents.create_label("🔌 Plugin Manager", 18))

        install_button = UIComponents.create_button("Install Plugin", self.install_plugin)
        layout.addWidget(install_button)

        self.setLayout(layout)

    def install_plugin(self):
        UIFeedback.show_info("Plugin installed successfully!")
