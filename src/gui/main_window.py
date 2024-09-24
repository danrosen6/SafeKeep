# gui/main_window.py

import os
from PySide6.QtWidgets import QMainWindow, QTabWidget, QMenuBar
from PySide6.QtGui import QAction
import logging
from config.config_manager import ConfigManager
from gui.virus_scanner_widget import VirusScannerWidget
from gui.database_update_widget import DatabaseUpdateWidget
from gui.quarantine_widget import QuarantineWidget


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SafeKeep')
        self.setGeometry(100, 100, 800, 600)
        self.config_manager = ConfigManager()

        # Set VirusScannerWidget as the central widget
        self.virus_scanner_widget = VirusScannerWidget(self.config_manager)
        self.setCentralWidget(self.virus_scanner_widget)

        # Load configurations
        self.clamscan_path = self.config_manager.get_clamav_path()
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.quarantine_path = self.config_manager.get_quarantine_path()

        # Remove the call to check_initial_setup
        self.check_initial_setup()  # This will be called after the event loop starts

    def check_initial_setup(self):
        # Check if ClamAV path is configured
        if not self.clamscan_path or not os.path.exists(self.clamscan_path):
            self.prompt_for_clamav_path()

        # Check if Freshclam path is configured
        if not self.freshclam_path or not os.path.exists(self.freshclam_path):
            self.prompt_for_freshclam_path()

        # Check if database path is configured
        if not self.database_path or not os.path.exists(self.database_path):
            self.prompt_for_database_path()

        # Check if quarantine path is configured
        if not self.quarantine_path or not os.path.exists(self.quarantine_path):
            self.prompt_for_quarantine_path()

    def init_menu_bar(self):
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        settings_menu = menu_bar.addMenu('Settings')

        change_clamav_path_action = QAction('Change ClamAV Path', self)
        change_clamav_path_action.triggered.connect(self.prompt_for_clamav_path)
        settings_menu.addAction(change_clamav_path_action)

        change_freshclam_path_action = QAction('Change Freshclam Path', self)
        change_freshclam_path_action.triggered.connect(self.prompt_for_freshclam_path)
        settings_menu.addAction(change_freshclam_path_action)

        change_database_path_action = QAction('Change Database Path', self)
        change_database_path_action.triggered.connect(self.prompt_for_database_path)
        settings_menu.addAction(change_database_path_action)

        change_quarantine_path_action = QAction('Change Quarantine Directory', self)
        change_quarantine_path_action.triggered.connect(self.prompt_for_quarantine_path)
        settings_menu.addAction(change_quarantine_path_action)

    # Configuration prompts
    def prompt_for_clamav_path(self):
        self.config_manager.prompt_for_clamav_path(self)
        self.clamscan_path = self.config_manager.get_clamav_path()

    def prompt_for_freshclam_path(self):
        self.config_manager.prompt_for_freshclam_path(self)
        self.freshclam_path = self.config_manager.get_freshclam_path()

    def prompt_for_database_path(self):
        self.config_manager.prompt_for_database_path(self)
        self.database_path = self.config_manager.get_database_path()

    def prompt_for_quarantine_path(self):
        self.config_manager.prompt_for_quarantine_path(self)
        self.quarantine_path = self.config_manager.get_quarantine_path()
