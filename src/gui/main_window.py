"""
GUI module for the main application window.

This module defines the MainWindow class, which serves as the primary interface
for the SafeKeep Antivirus application. It integrates various widgets, manages
configuration settings, and handles user interactions through the menu bar.
"""

import os
from PySide6.QtWidgets import QMainWindow, QTabWidget, QMenuBar
from PySide6.QtGui import QAction
import logging
from config.config_manager import ConfigManager
from gui.virus_scan.virus_scanner_widget import VirusScannerWidget
from gui.virus_scan.database_update_widget import DatabaseUpdateWidget
from gui.virus_scan.quarantine_widget import QuarantineWidget


class MainWindow(QMainWindow):
    """
    The MainWindow class represents the main window of the SafeKeep Antivirus application.

    It initializes the primary widgets, loads configuration settings, and sets up the
    application menu for accessing various functionalities such as changing configuration
    paths.
    """

    def __init__(self):
        """
        Initialize the MainWindow.

        Sets up the window title, geometry, configuration manager, and the central widget.
        Initiates the initial setup checks to ensure all necessary paths are configured.
        """
        super().__init__()
        self.setWindowTitle('SafeKeep')
        self.setGeometry(100, 100, 800, 600)
        self.config_manager = ConfigManager()

        # Set VirusScannerWidget as the central widget of the main window
        self.virus_scanner_widget = VirusScannerWidget(self.config_manager)
        self.setCentralWidget(self.virus_scanner_widget)

        # Load configuration paths from the configuration manager
        self.clamscan_path = self.config_manager.get_clamav_path()
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.quarantine_path = self.config_manager.get_quarantine_path()

        # Perform initial setup checks to ensure all required paths are configured
        self.check_initial_setup()

    def check_initial_setup(self):
        """
        Verify that all necessary configuration paths are set and valid.

        Checks the existence of the ClamAV executable, freshclam utility, database path,
        and quarantine directory. Prompts the user to provide paths if any are missing
        or invalid.
        """
        # Check if ClamAV path is configured and exists
        if not self.clamscan_path or not os.path.exists(self.clamscan_path):
            self.prompt_for_clamav_path()

        # Check if Freshclam path is configured and exists
        if not self.freshclam_path or not os.path.exists(self.freshclam_path):
            self.prompt_for_freshclam_path()

        # Check if database path is configured and exists
        if not self.database_path or not os.path.exists(self.database_path):
            self.prompt_for_database_path()

        # Check if quarantine path is configured and exists
        if not self.quarantine_path or not os.path.exists(self.quarantine_path):
            self.prompt_for_quarantine_path()

    def init_menu_bar(self):
        """
        Initialize the menu bar with Settings and other relevant menus.

        Adds actions to the Settings menu for changing configuration paths such as
        ClamAV, Freshclam, database, and quarantine directory paths.
        """
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)

        # Settings Menu
        settings_menu = menu_bar.addMenu('Settings')

        # Action to change ClamAV executable path
        change_clamav_path_action = QAction('Change ClamAV Path', self)
        change_clamav_path_action.triggered.connect(self.prompt_for_clamav_path)
        settings_menu.addAction(change_clamav_path_action)

        # Action to change Freshclam executable path
        change_freshclam_path_action = QAction('Change Freshclam Path', self)
        change_freshclam_path_action.triggered.connect(self.prompt_for_freshclam_path)
        settings_menu.addAction(change_freshclam_path_action)

        # Action to change the virus database path
        change_database_path_action = QAction('Change Database Path', self)
        change_database_path_action.triggered.connect(self.prompt_for_database_path)
        settings_menu.addAction(change_database_path_action)

        # Action to change the quarantine directory path
        change_quarantine_path_action = QAction('Change Quarantine Directory', self)
        change_quarantine_path_action.triggered.connect(self.prompt_for_quarantine_path)
        settings_menu.addAction(change_quarantine_path_action)

    # Configuration prompt methods

    def prompt_for_clamav_path(self):
        """
        Prompt the user to specify the path to the ClamAV executable.

        Invokes the configuration manager to handle the path selection and updates
        the internal ClamAV path accordingly.
        """
        self.config_manager.prompt_for_clamav_path(self)
        self.clamscan_path = self.config_manager.get_clamav_path()

    def prompt_for_freshclam_path(self):
        """
        Prompt the user to specify the path to the Freshclam utility.

        Invokes the configuration manager to handle the path selection and updates
        the internal Freshclam path accordingly.
        """
        self.config_manager.prompt_for_freshclam_path(self)
        self.freshclam_path = self.config_manager.get_freshclam_path()

    def prompt_for_database_path(self):
        """
        Prompt the user to specify the path to the virus definition database.

        Invokes the configuration manager to handle the path selection and updates
        the internal database path accordingly.
        """
        self.config_manager.prompt_for_database_path(self)
        self.database_path = self.config_manager.get_database_path()

    def prompt_for_quarantine_path(self):
        """
        Prompt the user to specify the quarantine directory path.

        Invokes the configuration manager to handle the path selection and updates
        the internal quarantine path accordingly.
        """
        self.config_manager.prompt_for_quarantine_path(self)
        self.quarantine_path = self.config_manager.get_quarantine_path()
