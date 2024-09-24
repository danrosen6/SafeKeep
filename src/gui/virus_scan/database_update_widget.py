"""
GUI module for updating the virus definition database.

This module defines the DatabaseUpdateWidget class, which provides a user interface
for updating the virus definition database using ClamAV's freshclam utility.
It displays the last update time, allows users to initiate a database update,
and shows progress and results of the update process.
"""

import os
import time
import logging
from PySide6.QtWidgets import (
    QWidget, QLabel, QPushButton, QVBoxLayout, QTextEdit, QMessageBox, QApplication
)
from PySide6.QtCore import Slot
from config.config_manager import ConfigManager
from modules.virus_scan.database_updater import DatabaseUpdateThread


class DatabaseUpdateWidget(QWidget):
    """
    The DatabaseUpdateWidget class provides the interface for updating the virus
    definition database. It displays the last update time, allows users to initiate
    updates, and shows real-time progress and results of the update process.
    """

    def __init__(self, config_manager):
        """
        Initialize the DatabaseUpdateWidget.

        Args:
            config_manager (ConfigManager): An instance of the configuration manager to access settings.
        """
        super().__init__()
        self.config_manager = config_manager
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.freshclam_thread = None
        self.init_ui()
        self.update_database_info()

    def init_ui(self):
        """
        Set up the user interface components of the widget.
        """
        # Label to display the last database update time
        self.database_info_label = QLabel('Virus Database Last Updated: Unknown')

        # Button to initiate the database update process
        self.update_database_button = QPushButton('Update Virus Database')
        self.update_database_button.clicked.connect(self.update_database)

        # Text edit widget to display update results and progress messages
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Arrange widgets in a vertical layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.database_info_label)
        main_layout.addWidget(self.update_database_button)
        main_layout.addWidget(self.results_display)

        self.setLayout(main_layout)

    def update_database_info(self):
        """
        Update the label to show the last time the virus database was updated.

        Checks the modification times of the database files and displays the most recent
        update time. If no valid database files are found, displays 'Unknown'.
        """
        if self.database_path and os.path.exists(self.database_path):
            try:
                # List of common ClamAV database files
                db_files = ['main.cvd', 'daily.cvd', 'main.cld', 'daily.cld']
                latest_time = None
                for db_file in db_files:
                    file_path = os.path.join(self.database_path, db_file)
                    if os.path.exists(file_path):
                        file_time = os.path.getmtime(file_path)
                        if latest_time is None or file_time > latest_time:
                            latest_time = file_time
                if latest_time:
                    # Format the timestamp into a readable string
                    last_updated = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_time))
                    self.database_info_label.setText(f'Virus Database Last Updated: {last_updated}')
                else:
                    self.database_info_label.setText('Virus Database Last Updated: Unknown')
            except Exception as e:
                logging.error(f"Error retrieving database update info: {e}")
                self.database_info_label.setText('Virus Database Last Updated: Error')
        else:
            self.database_info_label.setText('Virus Database Last Updated: Unknown')

    def update_database(self):
        """
        Initiate the virus database update process.

        Validates the freshclam path and starts the DatabaseUpdateThread to perform the update.
        Disables the update button during the update process and connects thread signals to slots
        for handling progress and completion.
        """
        # Validate the freshclam executable path
        if not self.freshclam_path or not os.path.exists(self.freshclam_path):
            QMessageBox.critical(
                self,
                "Freshclam Path Not Found",
                "Freshclam path is not configured correctly."
            )
            self.config_manager.prompt_for_freshclam_path(self)
            self.freshclam_path = self.config_manager.get_freshclam_path()
            if not self.freshclam_path:
                return  # Abort if freshclam path is still not set

        # Disable the update button to prevent multiple updates
        self.update_database_button.setEnabled(False)
        self.results_display.append('Updating virus database...\n')

        # Create and start the DatabaseUpdateThread
        self.database_thread = DatabaseUpdateThread(self.freshclam_path)
        self.database_thread.update_progress.connect(self.display_update_progress)
        self.database_thread.update_finished.connect(self.update_database_finished)
        self.database_thread.start()

    @Slot(bool)
    def update_database_finished(self, success):
        """
        Handle the completion of the database update process.

        Args:
            success (bool): True if the update was successful, False otherwise.
        """
        if success:
            self.results_display.append('\nDatabase update completed successfully.')
            QMessageBox.information(self, "Update Successful", "Virus database updated successfully.")
        else:
            self.results_display.append('\nDatabase update failed.')
            QMessageBox.warning(self, "Update Failed", "Failed to update virus database.")
        # Re-enable the update button and refresh the update info label
        self.update_database_button.setEnabled(True)
        self.update_database_info()

    @Slot(str)
    def display_update_progress(self, progress):
        """
        Display progress messages from the database update process.

        Args:
            progress (str): The progress message to display.
        """
        self.results_display.append(progress)
        # Process events to keep the GUI responsive
        QApplication.processEvents()

    @Slot(str)
    def handle_error(self, error_message):
        """
        Handle errors that occur during the database update process.

        Args:
            error_message (str): The error message to display.
        """
        self.results_display.append(f"\nError: {error_message}")
        QMessageBox.critical(self, "Error", error_message)
        # Re-enable the update button after an error
        self.update_database_button.setEnabled(True)
