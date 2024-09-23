import os
import time
from PySide6.QtWidgets import (
    QWidget, QPushButton, QLabel, QLineEdit,
    QFileDialog, QVBoxLayout, QHBoxLayout, QTextEdit,
    QMessageBox, QMenuBar, QProgressBar, QApplication
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Slot
from virusScan.clamav_integration import ScannerThread
from virusScan.freshclam_integration import FreshclamThread
import config.config_manager

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SafeKeep - Virus Scanner')
        self.setGeometry(100, 100, 600, 400)
        self.scanner_thread = None
        self.freshclam_thread = None
        self.config_manager = config.config_manager.ConfigManager()
        self.clamscan_path = self.config_manager.get_clamav_path()
        self.freshclam_path = self.config_manager.get_freshclam_path()
        self.database_path = self.config_manager.get_database_path()
        self.init_ui()

        # Check if ClamAV path is configured
        if not self.clamscan_path or not os.path.exists(self.clamscan_path):
            self.prompt_for_clamav_path()

        # Check if freshclam path is configured
        if not self.freshclam_path or not os.path.exists(self.freshclam_path):
            self.prompt_for_freshclam_path()

        # Check if database path is configured
        if not self.database_path or not os.path.exists(self.database_path):
            self.prompt_for_database_path()

        # Update the virus database info
        self.update_database_info()

    def init_ui(self):
        # Menu Bar
        menu_bar = QMenuBar(self)
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

        # Path input
        self.path_label = QLabel('Select File or Directory:')
        self.path_input = QLineEdit()
        self.browse_file_button = QPushButton('Browse File')
        self.browse_file_button.clicked.connect(self.browse_file)
        self.browse_dir_button = QPushButton('Browse Directory')
        self.browse_dir_button.clicked.connect(self.browse_directory)

        # Scan button
        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setEnabled(False)

        # Cancel button
        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)

        # Progress bar for scan
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Database info and update button
        self.database_info_label = QLabel('Virus Database Last Updated: Unknown')
        self.update_database_button = QPushButton('Update Virus Database')
        self.update_database_button.clicked.connect(self.update_database)

        # Layouts
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.browse_file_button)
        path_layout.addWidget(self.browse_dir_button)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.cancel_button)

        database_layout = QHBoxLayout()
        database_layout.addWidget(self.database_info_label)
        database_layout.addWidget(self.update_database_button)

        main_layout = QVBoxLayout()
        main_layout.setMenuBar(menu_bar)
        main_layout.addWidget(self.path_label)
        main_layout.addLayout(path_layout)
        main_layout.addWidget(self.progress_bar)
        main_layout.addLayout(button_layout)
        main_layout.addLayout(database_layout)
        main_layout.addWidget(self.results_display)

        self.setLayout(main_layout)

        # Connect signals
        self.path_input.textChanged.connect(self.check_input)

    def prompt_for_clamav_path(self):
        while True:
            QMessageBox.information(
                self,
                "ClamAV Path Required",
                "Please locate your ClamAV 'clamscan.exe' executable."
            )
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select clamscan.exe",
                "",
                "Executable Files (clamscan.exe);;All Files (*)"
            )
            if not file_path:
                QMessageBox.critical(
                    self,
                    "Operation Cancelled",
                    "ClamAV path configuration is required to proceed."
                )
                break  # Exit the loop if the user cancels the dialog
            elif os.path.basename(file_path).lower() == 'clamscan.exe':
                self.clamscan_path = file_path
                self.config_manager.set_clamav_path(file_path)
                break  # Valid path selected, exit the loop
            else:
                QMessageBox.critical(
                    self,
                    "Invalid Selection",
                    "Please select the 'clamscan.exe' executable."
                )

    def prompt_for_freshclam_path(self):
        while True:
            QMessageBox.information(
                self,
                "Freshclam Path Required",
                "Please locate your ClamAV 'freshclam.exe' executable."
            )
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select freshclam.exe",
                "",
                "Executable Files (freshclam.exe);;All Files (*)"
            )
            if not file_path:
                QMessageBox.critical(
                    self,
                    "Operation Cancelled",
                    "Freshclam path configuration is required to proceed."
                )
                break  # Exit the loop if the user cancels the dialog
            elif os.path.basename(file_path).lower() == 'freshclam.exe':
                self.freshclam_path = file_path
                self.config_manager.set_freshclam_path(file_path)
                break  # Valid path selected, exit the loop
            else:
                QMessageBox.critical(
                    self,
                    "Invalid Selection",
                    "Please select the 'freshclam.exe' executable."
                )

    def prompt_for_database_path(self):
        while True:
            QMessageBox.information(
                self,
                "Database Path Required",
                "Please locate your ClamAV database directory."
            )
            directory = QFileDialog.getExistingDirectory(
                self,
                "Select ClamAV Database Directory",
                ""
            )
            if not directory:
                QMessageBox.critical(
                    self,
                    "Operation Cancelled",
                    "Database path configuration is required to proceed."
                )
                break  # Exit the loop if the user cancels the dialog
            else:
                if os.path.exists(directory):
                    self.database_path = directory
                    self.config_manager.set_database_path(directory)
                    break  # Valid path selected, exit the loop
                else:
                    QMessageBox.critical(
                        self,
                        "Invalid Selection",
                        "Please select a valid directory."
                    )

    def check_input(self):
        if self.path_input.text():
            self.scan_button.setEnabled(True)
        else:
            self.scan_button.setEnabled(False)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*)"
        )
        if file_path:
            self.path_input.setText(file_path)

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            ""
        )
        if directory:
            self.path_input.setText(directory)

    def start_scan(self):
        if not self.clamscan_path or not os.path.exists(self.clamscan_path):
            QMessageBox.critical(
                self,
                "ClamAV Path Not Found",
                "ClamAV path is not configured correctly. Please locate 'clamscan.exe' again."
            )
            self.prompt_for_clamav_path()
            return

        path = self.path_input.text()
        normalized_path = os.path.normpath(path)
        if not os.path.exists(normalized_path):
            QMessageBox.warning(self, "Invalid Path", "The selected path does not exist.")
            return

        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.results_display.clear()
        self.results_display.append('Scanning started...\n')
        self.progress_bar.setValue(0)

        # Create a ScannerThread instance
        self.scanner_thread = ScannerThread(self.clamscan_path, path)
        self.scanner_thread.scan_progress.connect(self.update_progress)
        self.scanner_thread.progress_update.connect(self.update_progress_bar)
        self.scanner_thread.scan_finished.connect(self.display_results)
        self.scanner_thread.scan_error.connect(self.handle_error)
        self.scanner_thread.start()

    @Slot(int)
    def update_progress_bar(self, progress):
        self.progress_bar.setValue(progress)
        QApplication.processEvents()  # Keep the GUI responsive

    def cancel_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.results_display.append('\nScan cancellation requested...')
            self.cancel_button.setEnabled(False)

    @Slot(str)
    def update_progress(self, progress):
        self.results_display.append(progress)

    @Slot(str)
    def display_results(self, results):
        self.results_display.append('\nScan completed.')

        if results.strip() == '':
            # No infected files found
            path = self.path_input.text()
            self.results_display.append(f"No threats detected in {path}")
        else:
            # Infected files found
            self.results_display.append("Threats detected in the following files:")
            self.results_display.append(results)

        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(100)

    @Slot(str)
    def handle_error(self, error_message):
        self.results_display.append(f"\nError: {error_message}")
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.update_database_button.setEnabled(True)
        self.progress_bar.setValue(0)

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
                "Freshclam path is not configured correctly. Please locate 'freshclam.exe' again."
            )
            self.prompt_for_freshclam_path()
            return

        self.update_database_button.setEnabled(False)
        self.results_display.append('Updating virus database...\n')

        # Create a FreshclamThread instance
        self.freshclam_thread = FreshclamThread(self.freshclam_path)
        self.freshclam_thread.update_progress.connect(self.update_progress)
        self.freshclam_thread.update_finished.connect(self.database_update_finished)
        self.freshclam_thread.update_error.connect(self.handle_error)
        self.freshclam_thread.start()

    @Slot()
    def database_update_finished(self):
        self.results_display.append('\nDatabase update completed.')
        self.update_database_button.setEnabled(True)
        self.update_database_info()
