# src/features/quarantine/quarantine_widget.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QListWidget, QLabel, QMessageBox, QFileDialog
from logs.logger import SafeKeepLogger
from .quarantine import QuarantineManager
import os

class QuarantineWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Quarantine Manager")
        self.setLayout(QVBoxLayout())

        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing QuarantineWidget.")

        # Initialize the QuarantineManager instance
        self.quarantine_manager = QuarantineManager()

        # Create UI components
        self.quarantine_list = QListWidget()
        self.file_info_label = QLabel("Select a file to view details.")
        self.refresh_button = QPushButton("Refresh List")
        self.restore_button = QPushButton("Restore File")
        self.delete_button = QPushButton("Delete File")

        # Add components to layout
        self.layout().addWidget(self.quarantine_list)
        self.layout().addWidget(self.file_info_label)
        self.layout().addWidget(self.refresh_button)
        self.layout().addWidget(self.restore_button)
        self.layout().addWidget(self.delete_button)

        # Connect button signals to methods
        self.refresh_button.clicked.connect(self.refresh_quarantine_list)
        self.restore_button.clicked.connect(self.restore_file)
        self.delete_button.clicked.connect(self.delete_file)

        # Connect list item selection to method
        self.quarantine_list.itemClicked.connect(self.display_file_info)

        # Refresh the quarantine list on initialization
        self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        """
        Refreshes the list of quarantined files displayed in the UI.
        """
        try:
            self.quarantine_list.clear()
            files = self.quarantine_manager.list_quarantined_files()
            self.quarantine_list.addItems(files)
            self.logger.info("Quarantine list refreshed successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to refresh quarantine list: {e}")
            self.logger.error(f"Failed to refresh quarantine list: {e}")

    def display_file_info(self, item):
        """
        Displays additional information about the selected quarantined file.
        """
        file_name = item.text()
        file_path = f"{self.quarantine_manager.quarantine_path}/{file_name}"
        file_size = os.path.getsize(file_path)
        file_info = f"File Name: {file_name}\nFile Size: {file_size} bytes\nLocation: {file_path}"
        self.file_info_label.setText(file_info)
        self.logger.info(f"Displaying information for file: {file_name}")

    def restore_file(self):
        """
        Restores the selected file from the quarantine directory.
        """
        selected_item = self.quarantine_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No File Selected", "Please select a file to restore.")
            self.logger.warning("No file selected for restoration.")
            return

        restore_path = QFileDialog.getExistingDirectory(self, "Select Directory to Restore File To")
        if not restore_path:
            QMessageBox.warning(self, "No Directory Selected", "Please select a directory to restore the file to.")
            self.logger.warning("No directory selected for file restoration.")
            return

        try:
            restored_file_path = self.quarantine_manager.restore_file(selected_item.text(), restore_path)
            QMessageBox.information(self, "File Restored", f"File restored successfully to: {restored_file_path}")
            self.logger.info(f"File restored successfully to: {restored_file_path}")
            self.refresh_quarantine_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore file: {e}")
            self.logger.error(f"Failed to restore file '{selected_item.text()}': {e}")

    def delete_file(self):
        """
        Deletes the selected file from the quarantine directory.
        """
        selected_item = self.quarantine_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No File Selected", "Please select a file to delete.")
            self.logger.warning("No file selected for deletion.")
            return

        confirm = QMessageBox.question(self, "Confirm Delete", f"Are you sure you want to delete '{selected_item.text()}'?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm == QMessageBox.No:
            self.logger.info(f"Deletion of file '{selected_item.text()}' canceled by user.")
            return

        try:
            self.quarantine_manager.delete_file(selected_item.text())
            QMessageBox.information(self, "File Deleted", f"File '{selected_item.text()}' deleted successfully.")
            self.logger.info(f"File '{selected_item.text()}' deleted successfully.")
            self.refresh_quarantine_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete file: {e}")
            self.logger.error(f"Failed to delete file '{selected_item.text()}': {e}")
