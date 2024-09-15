import subprocess
import os
from PySide6.QtCore import QThread, Signal

class ScannerThread(QThread):
    """
    A QThread subclass that runs ClamAV's clamscan command in a separate thread.

    Signals:
        scan_progress (str): Emitted when there is progress output from clamscan.
        scan_finished (str): Emitted when the scan is completed successfully.
        scan_error (str): Emitted when an error occurs during scanning.
    """

    scan_progress = Signal(str)
    scan_finished = Signal(str)
    scan_error = Signal(str)

    def __init__(self, clamscan_path, scan_path):
        """
        Initializes the ScannerThread.

        Args:
            clamscan_path (str): The full path to the clamscan executable.
            scan_path (str): The file or directory path to be scanned.
        """
        super().__init__()
        self.clamscan_path = clamscan_path
        self.scan_path = scan_path
        self._is_running = True
        self.process = None

    def run(self):
        """
        Executes the clamscan command and processes its output.
        """
        # Normalize the scan path to ensure correct formatting
        normalized_scan_path = os.path.normpath(self.scan_path)

        # Construct the clamscan command
        command = [
            self.clamscan_path,
            '-r',  # Enable recursive scanning
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

            # Read and emit clamscan output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    # Terminate the process if scanning has been stopped
                    self.process.terminate()
                    break
                line = line.strip()
                if line:
                    self.scan_progress.emit(line)
            self.process.wait()

            # Capture the final output and emit the appropriate signal
            stdout, stderr = self.process.communicate()
            if stderr:
                self.scan_error.emit(stderr)
            else:
                self.scan_finished.emit(stdout)

        except Exception as e:
            # Emit any exceptions that occur during scanning
            self.scan_error.emit(f"An error occurred: {e}")

    def stop(self):
        """
        Stops the scanning process if it is running.
        """
        self._is_running = False
        if self.process:
            self.process.terminate()
