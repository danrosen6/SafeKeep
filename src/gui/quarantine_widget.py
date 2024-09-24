# gui/quarantine_widget.py

import os
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QHBoxLayout, QPushButton, QMessageBox, QFileDialog
)
from PySide6.QtCore import Slot
from modules.quarantine_manager import QuarantineManager

class QuarantineWidget(QWidget):
    def __init__(self, config_manager):
        super().__init__()
        self.config_manager = config_manager
        self.quarantine_path = self.config_manager.get_quarantine_path()
        self.quarantine_manager = QuarantineManager(self.quarantine_path)
        self.init_ui()
        self.load_quarantined_files()
        self.setWindowTitle("Quarantine")
        self.setGeometry(150, 150, 600, 400)

    def init_ui(self):
        layout = QVBoxLayout()
        self.quarantined_files_list = QListWidget()
        layout.addWidget(self.quarantined_files_list)

        button_layout = QHBoxLayout()
        self.restore_button = QPushButton("Restore")
        self.delete_button = QPushButton("Delete")
        button_layout.addWidget(self.restore_button)
        button_layout.addWidget(self.delete_button)

        self.restore_button.clicked.connect(self.restore_file)
        self.delete_button.clicked.connect(self.delete_file)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def load_quarantined_files(self):
        self.quarantined_files_list.clear()
        if os.path.exists(self.quarantine_path):
            files = os.listdir(self.quarantine_path)
            for file in files:
                self.quarantined_files_list.addItem(file)
        else:
            logging.error("Quarantine directory does not exist.")

    @Slot()
    def restore_file(self):
        selected_items = self.quarantined_files_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
            return

        # Prompt the user to select a directory
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
                # Remove the item from the list
                self.quarantined_files_list.takeItem(self.quarantined_files_list.row(item))
            else:
                QMessageBox.warning(self, "Restore Failed", f"Failed to restore {file_name}.")

        # Reload the quarantined files list
        self.load_quarantined_files()

    @Slot()
    def delete_file(self):
        selected_items = self.quarantined_files_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
            return

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
                    # Remove the item from the list
                    self.quarantined_files_list.takeItem(self.quarantined_files_list.row(item))
                else:
                    QMessageBox.warning(self, "Delete Failed", f"Failed to delete {file_name}.")

            # Reload the quarantined files list
            self.load_quarantined_files()
