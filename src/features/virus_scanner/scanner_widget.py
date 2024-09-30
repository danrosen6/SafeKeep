# src/features/virus_scanner/scanner_widget.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QTextEdit, QMessageBox, QLabel
from PySide6.QtCore import Qt
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

    def set_status(self, message):
        """
        Updates the status label with the given message.
        :param message: The status message to display.
        """
        self.status_label.setText(f"Status: {message}")
        self.logger.info(message)

    def scan_file(self):
        """
        Prompts the user to select a file and initiates a virus scan on it.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*)")
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to scan.")
            self.logger.warning("No file selected for scanning.")
            return

        self.logger.info(f"Selected file for scanning: {file_path}")
        self.set_status("Scanning file...")

        try:
            # Disable the buttons to prevent starting another scan
            self.scan_file_button.setEnabled(False)
            self.scan_directory_button.setEnabled(False)

            # Perform the scan
            result = self.scanner.scan_file(file_path)

            # Display the scan results and summary
            self.display_scan_results(file_path, result)

            self.set_status("Scan completed")
            self.logger.info(f"File scan completed for: {file_path}")
            QMessageBox.information(self, "Scan Complete", f"Scan completed for file: {file_path}")
        except Exception as e:
            self.set_status("Scan failed")
            QMessageBox.critical(self, "Scan Failed", f"Failed to scan file: {e}")
            self.logger.error(f"Scan failed for file {file_path}: {e}")
        finally:
            # Re-enable the buttons
            self.scan_file_button.setEnabled(True)
            self.scan_directory_button.setEnabled(True)

    def scan_directory(self):
        """
        Prompts the user to select a directory and initiates a virus scan on it.
        """
        directory_path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not directory_path:
            QMessageBox.warning(self, "No Directory Selected", "Please select a directory to scan.")
            self.logger.warning("No directory selected for scanning.")
            return

        self.logger.info(f"Selected directory for scanning: {directory_path}")
        self.set_status("Scanning directory...")

        try:
            # Disable the buttons to prevent starting another scan
            self.scan_file_button.setEnabled(False)
            self.scan_directory_button.setEnabled(False)

            # Perform the scan
            result = self.scanner.scan_directory(directory_path)

            # Display the scan results and summary
            self.display_scan_results(directory_path, result)

            self.set_status("Scan completed")
            self.logger.info(f"Directory scan completed for: {directory_path}")
            QMessageBox.information(self, "Scan Complete", f"Scan completed for directory: {directory_path}")
        except Exception as e:
            self.set_status("Scan failed")
            QMessageBox.critical(self, "Scan Failed", f"Failed to scan directory: {e}")
            self.logger.error(f"Scan failed for directory {directory_path}: {e}")
        finally:
            # Re-enable the buttons
            self.scan_file_button.setEnabled(True)
            self.scan_directory_button.setEnabled(True)

    def display_scan_results(self, path, result):
        """
        Displays the scan results in the scan_results text box.
        :param path: The path that was scanned (file or directory).
        :param result: The scan result returned by the VirusScanner.
        """
        output_text = f"Scan Results for {path}:\n"
        output_text += f"{result['output']}\n"

        # Include the summary if available
        if 'summary' in result and result['summary']:
            output_text += f"{result['summary']}\n"

        # Display in the text box
        self.scan_results.append(output_text)
        self.logger.info(f"Displayed scan results for {path}.")

        # If infected files are found, display a message
        if result['infected_files']:
            infected_text = "\n".join([f"{file['file']} - {file['virus']}" for file in result['infected_files']])
            self.scan_results.append(f"\nInfected files detected:\n{infected_text}\n")
            QMessageBox.warning(self, "Infected Files Found", f"Infected files were detected during the scan:\n{infected_text}")
