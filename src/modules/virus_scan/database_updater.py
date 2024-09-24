"""
Module for updating the virus definition database using ClamAV's freshclam utility.

This module defines the DatabaseUpdateThread class, which runs the freshclam utility
in a separate thread to update the virus definition database, emitting signals to
provide progress updates to the user interface.
"""

from PySide6.QtCore import QThread, Signal
import subprocess
import logging

class DatabaseUpdateThread(QThread):
    """
    A QThread subclass that handles updating the virus definition database using
    ClamAV's freshclam utility.

    Signals:
        update_progress (str): Emitted to provide progress updates during the update process.
        update_finished (bool): Emitted when the update process finishes, indicating success or failure.
    """

    # Define Qt signals for inter-thread communication
    update_progress = Signal(str)
    update_finished = Signal(bool)

    def __init__(self, freshclam_path):
        """
        Initialize the DatabaseUpdateThread.

        Args:
            freshclam_path (str): Path to the freshclam executable.
        """
        super().__init__()
        self.freshclam_path = freshclam_path

    def run(self):
        """
        Execute the database update process in a separate thread.
        """
        try:
            # Start the freshclam process to update the virus definitions
            process = subprocess.Popen(
                [self.freshclam_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Read and emit output from freshclam line by line
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if line:
                    # Emit each line to update the UI with progress information
                    self.update_progress.emit(line)

            # Wait for the process to complete
            process.wait()
            if process.returncode == 0:
                # Emit signal indicating the update finished successfully
                self.update_finished.emit(True)
            else:
                # Emit signal indicating the update failed
                self.update_finished.emit(False)
        except Exception as e:
            # Log any exceptions that occur during the update process
            logging.error(f"Database update failed: {e}")
            self.update_finished.emit(False)
