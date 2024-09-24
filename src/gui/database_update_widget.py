# gui/database_update_widget.py

import os
import time
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout, QTextEdit, QMessageBox, QApplication
)
from PySide6.QtCore import Slot
from config.config_manager import ConfigManager
from modules.database_updater import DatabaseUpdateThread

class DatabaseUpdateWidget(QWidget):
    def __init__(self, config_manager):
        super().__init__()
        self.config_manager = ConfigManager()
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.freshclam_thread = None
        self.init_ui()
        self.update_database_info()

    def init_ui(self):
        # Database info label
        self.database_info_label = QLabel('Virus Database Last Updated: Unknown')

        # Update button
        self.update_database_button = QPushButton('Update Virus Database')
        self.update_database_button.clicked.connect(self.update_database)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.database_info_label)
        main_layout.addWidget(self.update_database_button)
        main_layout.addWidget(self.results_display)

        self.setLayout(main_layout)

    def update_database_info(self):
        if self.database_path and os.path.exists(self.database_path):
            try:
                db_files = ['main.cvd', 'daily.cvd', 'main.cld', 'daily.cld']
                latest_time = None
                for db_file in db_files:
                    file_path = os.path.join(self.database_path, db_file)
                    if os.path.exists(file_path):
                        file_time = os.path.getmtime(file_path)
                        if latest_time is None or file_time > latest_time:
                            latest_time = file_time
                if latest_time:
                    last_updated = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_time))
                    self.database_info_label.setText(f'Virus Database Last Updated: {last_updated}')
                else:
                    self.database_info_label.setText('Virus Database Last Updated: Unknown')
            except Exception as e:
                self.database_info_label.setText('Virus Database Last Updated: Error')
        else:
            self.database_info_label.setText('Virus Database Last Updated: Unknown')

    def update_database(self):
        if not self.freshclam_path or not os.path.exists(self.freshclam_path):
            QMessageBox.critical(
                self,
                "Freshclam Path Not Found",
                "Freshclam path is not configured correctly."
            )
            self.config_manager.prompt_for_freshclam_path(self)
            self.freshclam_path = self.config_manager.get_freshclam_path()
            if not self.freshclam_path:
                return

        self.update_database_button.setEnabled(False)
        self.results_display.append('Updating virus database...\n')

        # Create a FreshclamThread instance
        self.update_button.setEnabled(False)
        self.database_thread = DatabaseUpdateThread(self.freshclam_path)
        self.database_thread.update_progress.connect(self.display_update_progress)
        self.database_thread.update_finished.connect(self.update_database_finished)
        self.database_thread.start()

    @Slot()
    def database_update_finished(self):
        self.results_display.append('\nDatabase update completed.')
        self.update_database_button.setEnabled(True)
        self.update_database_info()

    @Slot(str)
    def update_progress(self, progress):
        self.results_display.append(progress)
        QApplication.processEvents()  # Keep GUI responsive

    @Slot(str)
    def handle_error(self, error_message):
        self.results_display.append(f"\nError: {error_message}")
        QMessageBox.critical(self, "Error", error_message)
        self.update_database_button.setEnabled(True)
