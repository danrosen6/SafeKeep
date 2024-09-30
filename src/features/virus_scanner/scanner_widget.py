# src/features/virus_scanner/scanner_widget.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QTextEdit, QMessageBox, QLabel
from PySide6.QtCore import Qt, Signal, Slot
from features.thread_manager import ThreadManager  # Import the ThreadManager
from logs.logger import SafeKeepLogger
from .scanner import VirusScanner

class VirusScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Virus Scanner")
        self.setLayout(QVBoxLayout())

        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing VirusScannerWidget.")

        # Create UI components
        self.scan_file_button = QPushButton("Scan File")
        self.scan_directory_button = QPushButton("Scan Directory")
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        self.status_label = QLabel("Status: Ready")

        # Add components to layout
        self.layout().addWidget(self.scan_file_button)
        self.layout().addWidget(self.scan_directory_button)
        self.layout().addWidget(self.scan_results)
        self.layout().addWidget(self.status_label)

        # Connect button signals to methods
        self.scan_file_button.clicked.connect(self.scan_file)
        self.scan_directory_button.clicked.connect(self.scan_directory)

        # Initialize the VirusScanner instance
        self.scanner = VirusScanner()

        # Initialize the ThreadManager
        self.thread_manager = ThreadManager()
        self.thread_manager.scan_completed_signal.connect(self.display_scan_results)
        self.thread_manager.scan_failed_signal.connect(self.handle_scan_failed)

    def set_status(self, message):
        """
        Updates the status label with the given message.
        """
        self.status_label.setText(f"Status: {message}")
        self.logger.info(f"Status set to: {message}")

    def scan_file(self):
        """
        Prompts the user to select a file and initiates a virus scan on it using ThreadManager.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*)")
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to scan.")
            self.logger.warning("No file selected for scanning.")
            return

        self.logger.info(f"Selected file for scanning: {file_path}")
        self.set_status("Scanning file...")
        self.scan_file_button.setEnabled(False)
        self.scan_directory_button.setEnabled(False)

        # Submit the file scan task to the ThreadManager
        self.thread_manager.submit_task(self.scanner.scan_file, file_path)

    def scan_directory(self):
        """
        Prompts the user to select a directory and initiates a virus scan on it using ThreadManager.
        """
        directory_path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not directory_path:
            QMessageBox.warning(self, "No Directory Selected", "Please select a directory to scan.")
            self.logger.warning("No directory selected for scanning.")
            return

        self.logger.info(f"Selected directory for scanning: {directory_path}")
        self.set_status("Scanning directory...")
        self.scan_file_button.setEnabled(False)
        self.scan_directory_button.setEnabled(False)

        # Submit the directory scan task to the ThreadManager
        self.thread_manager.submit_task(self.scanner.scan_directory, directory_path)

    @Slot(str, dict)
    def display_scan_results(self, path, result):
        """
        Slot function to display the scan results in the scan_results text box.
        This function is connected to the custom signal and will always run in the main thread.
        """
        output_text = f"Scan Results for {path}:\n{result.get('output', '')}\n"
        output_text += result.get('summary', '')

        self.scan_results.append(output_text)
        self.logger.info(f"Displayed scan results for {path}.")

        # If infected files are found, display a message
        if result['infected_files']:
            infected_text = "\n".join([f"{file['file']} - {file['virus']}" for file in result['infected_files']])
            self.scan_results.append(f"\nInfected files detected:\n{infected_text}\n")
            QMessageBox.warning(self, "Infected Files Found", f"Infected files were detected during the scan:\n{infected_text}")

        self.set_status("Scan completed")
        self.scan_file_button.setEnabled(True)
        self.scan_directory_button.setEnabled(True)

    @Slot(str, str)
    def handle_scan_failed(self, path, error_message):
        """
        Slot function to handle failed scans.
        :param path: The path that was scanned.
        :param error_message: The error message describing the failure.
        """
        self.set_status(f"Scan failed for {path}")
        QMessageBox.critical(self, "Scan Failed", f"Scan failed for {path}.\nError: {error_message}")
        self.logger.error(f"Scan failed for {path}. Error: {error_message}")
        self.scan_file_button.setEnabled(True)
        self.scan_directory_button.setEnabled(True)
