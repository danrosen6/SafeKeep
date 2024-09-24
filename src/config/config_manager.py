# config/config_manager.py

import os
import configparser
import logging
from PySide6.QtWidgets import (
    QFileDialog, QMessageBox,
)


CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')

class ConfigManager:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = CONFIG_FILE
        self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file)
                logging.debug(f"Configuration loaded from {self.config_file}")
            else:
                logging.debug("No existing configuration file found.")
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")

    def save_config(self):
        try:
            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)
            logging.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")

    # ClamAV Path
    def get_clamav_path(self):
        return self.config.get('ClamAV', 'clamscan_path', fallback=None)

    def set_clamav_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['clamscan_path'] = path
        self.save_config()

    # Freshclam Path
    def get_freshclam_path(self):
        return self.config.get('ClamAV', 'freshclam_path', fallback=None)

    def set_freshclam_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['freshclam_path'] = path
        self.save_config()

    # Database Path
    def get_database_path(self):
        return self.config.get('ClamAV', 'database_path', fallback=None)

    def set_database_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['database_path'] = path
        self.save_config()

    # Quarantine Path
    def get_quarantine_path(self):
        return self.config.get('Quarantine', 'quarantine_path', fallback=None)

    def set_quarantine_path(self, path):
        if 'Quarantine' not in self.config:
            self.config['Quarantine'] = {}
        self.config['Quarantine']['quarantine_path'] = path
        self.save_config()

    # Prompt methods
    def prompt_for_clamav_path(self, parent):
        while True:
            QMessageBox.information(
                parent,
                "ClamAV Path Required",
                "Please locate your ClamAV 'clamscan.exe' executable."
            )
            file_path, _ = QFileDialog.getOpenFileName(
                parent,
                "Select clamscan.exe",
                "",
                "Executable Files (clamscan.exe);;All Files (*)"
            )
            if not file_path:
                QMessageBox.critical(
                    parent,
                    "Operation Cancelled",
                    "ClamAV path configuration is required to proceed."
                )
                continue  # Prompt again
            elif os.path.basename(file_path).lower() == 'clamscan.exe':
                self.set_clamav_path(file_path)
                break  # Valid path selected, exit the loop
            else:
                QMessageBox.critical(
                    parent,
                    "Invalid Selection",
                    "Please select the 'clamscan.exe' executable."
                )

    def prompt_for_freshclam_path(self, parent):
        while True:
            QMessageBox.information(
                parent,
                "Freshclam Path Required",
                "Please locate your ClamAV 'freshclam.exe' executable."
            )
            file_path, _ = QFileDialog.getOpenFileName(
                parent,
                "Select freshclam.exe",
                "",
                "Executable Files (freshclam.exe);;All Files (*)"
            )
            if not file_path:
                QMessageBox.critical(
                    parent,
                    "Operation Cancelled",
                    "Freshclam path configuration is required to proceed."
                )
                continue  # Prompt again
            elif os.path.basename(file_path).lower() == 'freshclam.exe':
                self.set_freshclam_path(file_path)
                break  # Valid path selected, exit the loop
            else:
                QMessageBox.critical(
                    parent,
                    "Invalid Selection",
                    "Please select the 'freshclam.exe' executable."
                )

    def prompt_for_database_path(self, parent):
        while True:
            QMessageBox.information(
                parent,
                "Database Path Required",
                "Please locate your ClamAV database directory."
            )
            directory = QFileDialog.getExistingDirectory(
                parent,
                "Select ClamAV Database Directory",
                ""
            )
            if not directory:
                QMessageBox.critical(
                    parent,
                    "Operation Cancelled",
                    "Database path configuration is required to proceed."
                )
                continue  # Prompt again
            else:
                if os.path.exists(directory):
                    self.set_database_path(directory)
                    break  # Valid path selected, exit the loop
                else:
                    QMessageBox.critical(
                        parent,
                        "Invalid Selection",
                        "Please select a valid directory."
                    )

    def prompt_for_quarantine_path(self, parent):
        while True:
            QMessageBox.information(
                parent,
                "Quarantine Directory Required",
                "Please select or create a directory to be used as the quarantine location."
            )
            directory = QFileDialog.getExistingDirectory(
                parent,
                "Select Quarantine Directory",
                ""
            )
            if directory:
                if os.path.exists(directory):
                    self.set_quarantine_path(directory)
                    # Set directory permissions to restrict access
                    os.chmod(directory, 0o700)
                    break  # Valid directory selected
                else:
                    QMessageBox.critical(
                        parent,
                        "Invalid Selection",
                        "Please select a valid directory."
                    )
            else:
                # User did not select a directory, offer to create a default one
                create_new = QMessageBox.question(
                    parent,
                    "Create Quarantine Directory",
                    "No directory selected. Would you like to create a default quarantine directory?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if create_new == QMessageBox.Yes:
                    self.setup_quarantine_directory(parent)
                    break
                else:
                    QMessageBox.warning(
                        parent,
                        "Quarantine Directory Required",
                        "A quarantine directory is required to proceed."
                    )
                    # Loop again to prompt for directory

    def setup_quarantine_directory(self, parent):
        default_quarantine_path = os.path.join(os.path.expanduser('~'), 'SafeKeep_Quarantine')
        try:
            if not os.path.exists(default_quarantine_path):
                os.makedirs(default_quarantine_path)
            # Set directory permissions to restrict access
            os.chmod(default_quarantine_path, 0o700)
            self.set_quarantine_path(default_quarantine_path)
            QMessageBox.information(
                parent,
                "Quarantine Directory Created",
                f"A default quarantine directory has been created at:\n{default_quarantine_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                parent,
                "Error Creating Quarantine Directory",
                f"An error occurred while creating the quarantine directory:\n{str(e)}"
            )
            # Prompt the user again
            self.prompt_for_quarantine_path(parent)
