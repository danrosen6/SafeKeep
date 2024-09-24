"""
Configuration Manager Module for SafeKeep Antivirus.

This module defines the ConfigManager class, which handles reading, writing, and
managing configuration settings for the SafeKeep Antivirus application. It provides
methods to get and set paths for ClamAV executables, the virus database, and the
quarantine directory. Additionally, it includes user interface prompts to allow
users to configure these paths through dialog windows.
"""

import os
import configparser
import logging
from PySide6.QtWidgets import (
    QFileDialog, QMessageBox,
)


# Define the path to the configuration file
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')


class ConfigManager:
    """
    Manages configuration settings for the SafeKeep Antivirus application.

    The ConfigManager handles loading and saving configuration settings from a
    configuration file. It provides methods to get and set paths related to ClamAV,
    the virus database, and the quarantine directory. It also facilitates user prompts
    to configure these paths through graphical dialogs.
    """

    def __init__(self):
        """
        Initialize the ConfigManager.

        Loads the existing configuration from the configuration file if it exists.
        If the configuration file does not exist, it initializes an empty configuration.
        """
        self.config = configparser.ConfigParser()
        self.config_file = CONFIG_FILE
        self.load_config()

    def load_config(self):
        """
        Load configuration settings from the configuration file.

        If the configuration file exists, it reads the settings. Otherwise, it logs
        that no existing configuration file was found.
        """
        try:
            if os.path.exists(self.config_file):
                self.config.read(self.config_file)
                logging.debug(f"Configuration loaded from {self.config_file}")
            else:
                logging.debug("No existing configuration file found.")
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")

    def save_config(self):
        """
        Save the current configuration settings to the configuration file.

        Writes the configuration data to the file specified by self.config_file.
        Logs an error if the save operation fails.
        """
        try:
            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)
            logging.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")

    # ============================
    # ClamAV Path Configuration
    # ============================

    def get_clamav_path(self):
        """
        Retrieve the path to the ClamAV 'clamscan' executable.

        Returns:
            str or None: The path to 'clamscan.exe' if configured, otherwise None.
        """
        return self.config.get('ClamAV', 'clamscan_path', fallback=None)

    def set_clamav_path(self, path):
        """
        Set the path to the ClamAV 'clamscan' executable.

        Args:
            path (str): The full path to 'clamscan.exe'.
        """
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['clamscan_path'] = path
        self.save_config()

    # ==============================
    # Freshclam Path Configuration
    # ==============================

    def get_freshclam_path(self):
        """
        Retrieve the path to the ClamAV 'freshclam' executable.

        Returns:
            str or None: The path to 'freshclam.exe' if configured, otherwise None.
        """
        return self.config.get('ClamAV', 'freshclam_path', fallback=None)

    def set_freshclam_path(self, path):
        """
        Set the path to the ClamAV 'freshclam' executable.

        Args:
            path (str): The full path to 'freshclam.exe'.
        """
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['freshclam_path'] = path
        self.save_config()

    # ===============================
    # Virus Database Path Configuration
    # ===============================

    def get_database_path(self):
        """
        Retrieve the path to the ClamAV virus definition database.

        Returns:
            str or None: The path to the database directory if configured, otherwise None.
        """
        return self.config.get('ClamAV', 'database_path', fallback=None)

    def set_database_path(self, path):
        """
        Set the path to the ClamAV virus definition database.

        Args:
            path (str): The full path to the database directory.
        """
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['database_path'] = path
        self.save_config()

    # ===============================
    # Quarantine Directory Configuration
    # ===============================

    def get_quarantine_path(self):
        """
        Retrieve the path to the quarantine directory.

        Returns:
            str or None: The path to the quarantine directory if configured, otherwise None.
        """
        return self.config.get('Quarantine', 'quarantine_path', fallback=None)

    def set_quarantine_path(self, path):
        """
        Set the path to the quarantine directory.

        Args:
            path (str): The full path to the quarantine directory.
        """
        if 'Quarantine' not in self.config:
            self.config['Quarantine'] = {}
        self.config['Quarantine']['quarantine_path'] = path
        self.save_config()

    # ====================
    # User Prompt Methods
    # ====================

    def prompt_for_clamav_path(self, parent):
        """
        Prompt the user to select the ClamAV 'clamscan.exe' executable.

        Opens a file dialog to allow the user to locate 'clamscan.exe'. Continues to prompt
        until a valid executable is selected or the user cancels the operation.

        Args:
            parent (QWidget): The parent widget for the dialog.
        """
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
        """
        Prompt the user to select the ClamAV 'freshclam.exe' executable.

        Opens a file dialog to allow the user to locate 'freshclam.exe'. Continues to prompt
        until a valid executable is selected or the user cancels the operation.

        Args:
            parent (QWidget): The parent widget for the dialog.
        """
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
        """
        Prompt the user to select the ClamAV virus definition database directory.

        Opens a directory selection dialog to allow the user to locate the database
        directory. Continues to prompt until a valid directory is selected or the user
        cancels the operation.

        Args:
            parent (QWidget): The parent widget for the dialog.
        """
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
        """
        Prompt the user to select or create a quarantine directory.

        Opens a directory selection dialog to allow the user to choose a quarantine
        directory. If the user does not select a directory, offers to create a default
        quarantine directory.

        Args:
            parent (QWidget): The parent widget for the dialog.
        """
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
                    try:
                        os.chmod(directory, 0o700)
                    except Exception as e:
                        logging.error(f"Failed to set permissions on quarantine directory: {e}")
                        QMessageBox.warning(
                            parent,
                            "Permission Error",
                            f"Failed to set permissions on quarantine directory:\n{e}"
                        )
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
        """
        Create a default quarantine directory in the user's home directory.

        Attempts to create a directory named 'SafeKeep_Quarantine' in the user's home
        directory. Sets appropriate permissions and updates the configuration. If creation
        fails, displays an error message and re-prompts the user.

        Args:
            parent (QWidget): The parent widget for the dialog.
        """
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
