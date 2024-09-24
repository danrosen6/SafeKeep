"""
Module for virus scanning functionality using ClamAV.

This module defines the ScannerThread class, which performs virus scanning
operations in a separate thread using ClamAV's clamscan utility.
"""

import os
import subprocess
import re
import logging
from PySide6.QtCore import QThread, Signal

class ScannerThread(QThread):
    """
    A QThread subclass that handles virus scanning using ClamAV's clamscan utility.

    Signals:
        scan_progress (str): Emitted to update scan progress messages.
        scan_finished (str): Emitted when scanning is completed.
        progress_update (int): Emitted to update the progress bar percentage.
        scan_error (str): Emitted when an error occurs during scanning.
        file_quarantined (str): Emitted when a file is successfully quarantined.
    """

    # Define Qt signals
    scan_progress = Signal(str)
    scan_finished = Signal(str)
    progress_update = Signal(int)
    scan_error = Signal(str)
    file_quarantined = Signal(str)

    def __init__(self, clamscan_path, scan_path, quarantine_path):
        """
        Initialize the ScannerThread.

        Args:
            clamscan_path (str): Path to the clamscan executable.
            scan_path (str): Path to the directory or file to be scanned.
            quarantine_path (str): Path to the quarantine directory.
        """
        super().__init__()
        self.clamscan_path = clamscan_path
        self.scan_path = scan_path
        self.quarantine_path = quarantine_path
        self._is_running = True
        self.process = None
        self.total_files = 0
        self.scanned_files = 0
        self.infected_files = []

    def run(self):
        """
        Execute the scanning process in a separate thread.
        """
        # Normalize paths to ensure consistency
        normalized_scan_path = os.path.normpath(self.scan_path)
        normalized_quarantine_path = os.path.normpath(self.quarantine_path)

        # Ensure the quarantine path exists
        if not os.path.isdir(normalized_quarantine_path):
            try:
                os.makedirs(normalized_quarantine_path)
                os.chmod(normalized_quarantine_path, 0o700)  # Set directory permissions
            except Exception as e:
                error_message = f"Failed to create quarantine directory: {e}"
                logging.error(error_message)
                self.scan_error.emit(error_message)
                return

        # Count the total number of files to be scanned
        self.total_files = self.count_files(normalized_scan_path)
        if self.total_files == 0:
            self.scan_error.emit("No files to scan in the selected path.")
            return

        # Construct the clamscan command without --move or --copy options
        command = [
            self.clamscan_path,
            '-r',
            normalized_scan_path
        ]

        try:
            # Start the clamscan process
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            self.infected_files = []

            # Read and process clamscan output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    # If the scanning has been stopped by the user
                    self.process.terminate()
                    self.process.wait()
                    self.scan_finished.emit("Scan cancelled by user.")
                    return

                line = line.strip()
                if line:
                    # Check if the line indicates a file scan result
                    if line.endswith("OK") or "FOUND" in line:
                        self.scanned_files += 1
                        self.update_progress_bar()

                        # Check if the file is infected
                        if "FOUND" in line:
                            # Extract the infected file path using regex
                            match = re.match(r'^(.*?): (.*) FOUND$', line)
                            if match:
                                infected_file = match.group(1)
                                self.infected_files.append(infected_file)
                                self.quarantine_file(infected_file)
                            else:
                                logging.error(f"Failed to parse infected file from line: {line}")
                                self.scan_error.emit(f"Failed to parse infected file from line: {line}")

                        # Emit the scan progress signal
                        self.scan_progress.emit(line)
                    else:
                        # Emit other output lines as scan progress
                        self.scan_progress.emit(line)

            # Wait for the clamscan process to finish
            self.process.wait()

            # Capture any errors from stderr
            stdout, stderr = self.process.communicate()
            if stderr:
                stderr = stderr.strip()
                if stderr:
                    self.scan_error.emit(stderr)
                    return

            # Prepare the results message
            if self.infected_files:
                results_message = '\n'.join([f"{file} was quarantined." for file in self.infected_files])
            else:
                results_message = ''

            # Emit the scan finished signal with the results
            self.scan_finished.emit(results_message)

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            logging.error(error_message)
            self.scan_error.emit(error_message)

    def quarantine_file(self, file_path):
        """
        Move the infected file to the quarantine directory and set appropriate permissions.

        Args:
            file_path (str): Path to the infected file.
        """
        logging.debug(f"Attempting to quarantine file: {file_path}")
        try:
            if os.path.exists(file_path):
                # Move the infected file to the quarantine directory
                file_name = os.path.basename(file_path)
                quarantine_file_path = os.path.join(self.quarantine_path, file_name)
                os.rename(file_path, quarantine_file_path)

                # Set file permissions to read-only
                os.chmod(quarantine_file_path, 0o400)
                logging.debug("File quarantined successfully.")

                # Emit the signal indicating the file has been quarantined
                self.file_quarantined.emit(file_name)
            else:
                logging.error(f"File not found: {file_path}")
                self.scan_error.emit(f"File not found: {file_path}")
        except Exception as e:
            logging.exception(f"Failed to quarantine {file_path}")
            self.scan_error.emit(f"Failed to quarantine {file_path}: {repr(e)}")

    def count_files(self, path):
        """
        Count the total number of files in the given path.

        Args:
            path (str): Directory or file path.

        Returns:
            int: Total number of files.
        """
        if os.path.isfile(path):
            return 1

        file_count = 0
        for root, dirs, files in os.walk(path):
            file_count += len(files)
        return file_count

    def update_progress_bar(self):
        """
        Update the progress bar based on the number of scanned files.
        """
        if self.total_files > 0:
            progress = int((self.scanned_files / self.total_files) * 100)
            self.progress_update.emit(progress)

    def stop(self):
        """
        Stop the scanning process gracefully.
        """
        self._is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
