# gui/virus_scanner_widget.py

import os
import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit,
    QFileDialog, QMessageBox, QProgressBar, QMenuBar, QApplication
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt, Slot
from modules.virus_scanner import ScannerThread
from modules.database_updater import DatabaseUpdateThread
from gui.quarantine_widget import QuarantineWidget
from config.config_manager import ConfigManager

class VirusScannerWidget(QWidget):
    def __init__(self, config_manager):
        super().__init__()
        self.config_manager = config_manager
        self.clamscan_path = self.config_manager.get_clamav_path()
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.quarantine_path = self.config_manager.get_quarantine_path()
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Menubar
        self.menu_bar = QMenuBar()
        self.init_menu_bar()
        main_layout.setMenuBar(self.menu_bar)

        # Scan Path Input
        scan_path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_path)
        scan_path_layout.addWidget(QLabel("Select Path to Scan:"))
        scan_path_layout.addWidget(self.path_input)
        scan_path_layout.addWidget(self.browse_button)
        main_layout.addLayout(scan_path_layout)

        # Scan and Control Buttons
        button_layout = QHBoxLayout()

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)

        self.cancel_button = QPushButton("Cancel Scan")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)

        self.update_db_button = QPushButton("Update Database")
        self.update_db_button.clicked.connect(self.update_database)

        self.quarantine_button = QPushButton("Quarantine")
        self.quarantine_button.clicked.connect(self.open_quarantine)

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.update_db_button)
        button_layout.addWidget(self.quarantine_button)

        main_layout.addLayout(button_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        main_layout.addWidget(self.results_display)

        # Last Database Update Label
        self.last_update_label = QLabel()
        self.update_last_update_label()
        main_layout.addWidget(self.last_update_label)

        self.setLayout(main_layout)

    def init_menu_bar(self):
        # File Menu
        file_menu = self.menu_bar.addMenu('File')

        # Exit Action
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close_application)
        file_menu.addAction(exit_action)

        # Help Menu
        help_menu = self.menu_bar.addMenu('Help')

        # About Action
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)


    def close_application(self):
        QApplication.quit()

    def show_about_dialog(self):
        QMessageBox.information(self, "About SafeKeep", "SafeKeep Antivirus\nVersion 1.0")

    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            self.path_input.setText(path)

    def start_scan(self):
        scan_path = self.path_input.text()
        if not scan_path:
            QMessageBox.warning(self, "No Path Selected", "Please select a path to scan.")
            return

        self.results_display.clear()
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)

        # Start the scanner thread
        self.scanner_thread = ScannerThread(
            self.clamscan_path, scan_path, self.quarantine_path
        )
        self.scanner_thread.scan_progress.connect(self.update_results)
        self.scanner_thread.scan_finished.connect(self.scan_finished)
        self.scanner_thread.scan_error.connect(self.scan_error)
        self.scanner_thread.progress_update.connect(self.update_progress)
        self.scanner_thread.start()

    def cancel_scan(self):
        if hasattr(self, 'scanner_thread'):
            self.scanner_thread.stop()
            self.scan_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.results_display.append("Scan cancelled.")

    def update_last_update_label(self):
        last_update_time = self.get_last_update_time()
        self.last_update_label.setText(f"Last Database Update: {last_update_time}")

    def get_last_update_time(self):
        # Assuming the database files are stored in self.database_path
        if os.path.exists(self.database_path):
            # Get the modification time of the database directory or files
            db_files = ['main.cvd', 'daily.cvd', 'main.cld', 'daily.cld']
            latest_time = None
            for db_file in db_files:
                file_path = os.path.join(self.database_path, db_file)
                if os.path.exists(file_path):
                    file_time = os.path.getmtime(file_path)
                    if latest_time is None or file_time > latest_time:
                        latest_time = file_time
            if latest_time:
                return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_time))
            else:
                return "Unknown"
        else:
            return "Unknown"

    @Slot(str)
    def update_results(self, message):
        self.results_display.append(message)

    @Slot(int)
    def update_progress(self, value):
        self.progress_bar.setValue(value)

    @Slot(str)
    def scan_finished(self, message):
        self.results_display.append("\nScan completed.")
        if message:
            self.results_display.append(message)
            QMessageBox.warning(
                self, "Threats Detected", "Threats were detected and quarantined."
            )
        else:
            QMessageBox.information(self, "No Threats", "No threats were detected.")
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(100)

    @Slot(str)
    def scan_error(self, error_message):
        QMessageBox.critical(self, "Scan Error", error_message)
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(0)

    def update_database(self):
        # Disable the update database button during the update
        self.update_db_button.setEnabled(False)
        # Start the database update in a separate thread
        self.database_thread = DatabaseUpdateThread(self.freshclam_path)
        self.database_thread.update_progress.connect(self.display_update_progress)
        self.database_thread.update_finished.connect(self.update_database_finished)
        self.database_thread.start()


    @Slot(str)
    def display_update_progress(self, message):
        self.results_display.append(message)

    @Slot(bool)
    def update_database_finished(self, success):
        self.update_db_button.setEnabled(True)
        if success:
            QMessageBox.information(self, "Update Successful", "Virus database updated successfully.")
        else:
            QMessageBox.warning(self, "Update Failed", "Failed to update virus database.")
        self.update_last_update_label()


    def open_quarantine(self):
        # Open the Quarantine interface
        self.quarantine_widget = QuarantineWidget(self.config_manager)
        self.quarantine_widget.show()
