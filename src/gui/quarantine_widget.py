"""
GUI module for managing quarantined files.

This module defines the QuarantineWidget class, which provides a user interface
for viewing, restoring, and deleting files that have been quarantined by the
antivirus application. It interacts with the QuarantineManager to perform file
operations and updates the UI accordingly.
"""

import os
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QHBoxLayout, QPushButton, QMessageBox, QFileDialog
)
from PySide6.QtCore import Slot
from modules.quarantine_manager import QuarantineManager


class QuarantineWidget(QWidget):
    """
    The QuarantineWidget class provides an interface for users to manage quarantined files.

    Users can view the list of quarantined files, restore selected files to a chosen
    directory, or permanently delete them from the quarantine.
    """

    def __init__(self, config_manager):
        """
        Initialize the QuarantineWidget.

        Args:
            config_manager (ConfigManager): An instance of the configuration manager to access settings.
        """
        super().__init__()
        self.config_manager = config_manager
        self.quarantine_path = self.config_manager.get_quarantine_path()
        self.quarantine_manager = QuarantineManager(self.quarantine_path)
        self.init_ui()
        self.load_quarantined_files()
        self.setWindowTitle("Quarantine")
        self.setGeometry(150, 150, 600, 400)

    def init_ui(self):
        """
        Set up the user interface components of the widget.
        """
        layout = QVBoxLayout()

        # List widget to display quarantined files
        self.quarantined_files_list = QListWidget()
        layout.addWidget(self.quarantined_files_list)

        # Buttons for restoring and deleting files
        button_layout = QHBoxLayout()
        self.restore_button = QPushButton("Restore")
        self.delete_button = QPushButton("Delete")
        button_layout.addWidget(self.restore_button)
        button_layout.addWidget(self.delete_button)

        # Connect buttons to their respective slots
        self.restore_button.clicked.connect(self.restore_file)
        self.delete_button.clicked.connect(self.delete_file)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def load_quarantined_files(self):
        """
        Load and display the list of quarantined files in the QListWidget.

        Clears the existing list and populates it with the current files in the quarantine directory.
        Logs an error if the quarantine directory does not exist.
        """
        self.quarantined_files_list.clear()
        if os.path.exists(self.quarantine_path):
            try:
                files = os.listdir(self.quarantine_path)
                for file in files:
                    self.quarantined_files_list.addItem(file)
            except Exception as e:
                logging.error(f"Failed to load quarantined files: {e}")
                QMessageBox.critical(self, "Error", f"Failed to load quarantined files: {e}")
        else:
            logging.error("Quarantine directory does not exist.")
            QMessageBox.critical(self, "Error", "Quarantine directory does not exist.")

    @Slot()
    def restore_file(self):
        """
        Restore selected quarantined files to a user-specified directory.

        Prompts the user to select a destination directory and attempts to restore each selected file.
        Displays informational or warning messages based on the outcome of each restore operation.
        Updates the quarantined files list upon successful restoration.
        """
        selected_items = self.quarantined_files_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
            return

        # Prompt the user to select a destination directory for restoration
        restore_directory = QFileDialog.getExistingDirectory(
            self,
            "Select Restore Directory",
            "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )

        if not restore_directory:
            QMessageBox.information(self, "Restore Cancelled", "No directory selected for restoration.")
            return

        for item in selected_items:
            file_name = item.text()
            restored = self.quarantine_manager.restore_file(file_name, restore_directory)
            if restored:
                logging.debug(f"File {file_name} restored to {restore_directory}.")
                QMessageBox.information(self, "File Restored", f"{file_name} has been restored to {restore_directory}.")
                # Remove the restored file from the list widget
                self.quarantined_files_list.takeItem(self.quarantined_files_list.row(item))
            else:
                QMessageBox.warning(self, "Restore Failed", f"Failed to restore {file_name}.")

        # Reload the quarantined files list to reflect changes
        self.load_quarantined_files()

    @Slot()
    def delete_file(self):
        """
        Permanently delete selected quarantined files from the quarantine directory.

        Prompts the user for confirmation before deletion. Attempts to delete each selected file
        and displays warning messages if any deletions fail. Updates the quarantined files list
        upon successful deletion.
        """
        selected_items = self.quarantined_files_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
            return

        # Confirm deletion with the user
        confirm = QMessageBox.question(
            self,
            "Confirm Deletion",
            "Are you sure you want to permanently delete the selected file(s)?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            for item in selected_items:
                file_name = item.text()
                deleted = self.quarantine_manager.delete_file(file_name)
                if deleted:
                    logging.debug(f"File {file_name} deleted.")
                    # Remove the deleted file from the list widget
                    self.quarantined_files_list.takeItem(self.quarantined_files_list.row(item))
                else:
                    QMessageBox.warning(self, "Delete Failed", f"Failed to delete {file_name}.")

            # Reload the quarantined files list to reflect changes
            self.load_quarantined_files()
