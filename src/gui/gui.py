import os
from PySide6.QtWidgets import (
    QWidget, QPushButton, QLabel, QLineEdit,
    QFileDialog, QVBoxLayout, QHBoxLayout, QTextEdit,
    QMessageBox, QMenuBar
)

from PySide6.QtGui import QAction
from PySide6.QtCore import Slot
from virusScan.clamav_integration import ScannerThread
import config.config_manager

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SafeKeep - Virus Scanner')
        self.setGeometry(100, 100, 600, 400)
        self.scanner_thread = None
        self.config_manager = config.config_manager.ConfigManager()
        self.clamscan_path = self.config_manager.get_clamav_path()
        self.init_ui()

        # Check if ClamAV path is configured
        if not self.clamscan_path or not os.path.exists(self.clamscan_path):
            self.prompt_for_clamav_path()

    def init_ui(self):
        # Menu Bar
        menu_bar = QMenuBar(self)
        settings_menu = menu_bar.addMenu('Settings')

        change_clamav_path_action = QAction('Change ClamAV Path', self)
        change_clamav_path_action.triggered.connect(self.prompt_for_clamav_path)
        settings_menu.addAction(change_clamav_path_action)

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

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Layouts
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.browse_file_button)
        path_layout.addWidget(self.browse_dir_button)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.cancel_button)

        main_layout = QVBoxLayout()
        main_layout.setMenuBar(menu_bar)
        main_layout.addWidget(self.path_label)
        main_layout.addLayout(path_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.results_display)

        self.setLayout(main_layout)

        # Connect signals
        self.path_input.textChanged.connect(self.check_input)

    def prompt_for_clamav_path(self):
        QMessageBox.information(
            self,
            "ClamAV Path Required",
            "Please locate your ClamAV 'clamscan.exe' executable."
        )
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select clamscan.exe",
            "",
            "Executable Files (clamscan.exe);;All Files (*)",
            options=options
        )
        if file_path and os.path.basename(file_path).lower() == 'clamscan.exe':
            self.clamscan_path = file_path
            self.config_manager.set_clamav_path(file_path)
        else:
            QMessageBox.critical(
                self,
                "Invalid Selection",
                "Please select the 'clamscan.exe' executable."
            )
            self.prompt_for_clamav_path()

    def check_input(self):
        if self.path_input.text():
            self.scan_button.setEnabled(True)
        else:
            self.scan_button.setEnabled(False)

    def browse_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*)",
            options=options
        )
        if file_path:
            self.path_input.setText(file_path)

    def browse_directory(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            "",
            options=options
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

        # Create a ScannerThread instance
        self.scanner_thread = ScannerThread(self.clamscan_path, path)
        self.scanner_thread.scan_progress.connect(self.update_progress)
        self.scanner_thread.scan_finished.connect(self.display_results)
        self.scanner_thread.scan_error.connect(self.handle_error)
        self.scanner_thread.start()

    def cancel_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.results_display.append('\nScan cancellation requested...')

    @Slot(str)
    def update_progress(self, progress):
        self.results_display.append(progress)

    @Slot(str)
    def display_results(self, results):
        self.results_display.append('\nScan completed.')
        self.results_display.append(results)
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    @Slot(str)
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Error", error_message)
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
