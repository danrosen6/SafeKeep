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
    progress_update = Signal(int)
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
        self.total_files = 0
        self.scanned_files = 0
        self.infected_files = []

    def run(self):
        """
        Executes the clamscan command and processes its output.
        """
        # Normalize the scan path to ensure correct formatting
        normalized_scan_path = os.path.normpath(self.scan_path)

        # Count total files for progress calculation
        self.total_files = self.count_files(normalized_scan_path)
        if self.total_files == 0:
            self.scan_error.emit("No files to scan in the selected path.")
            return

        # Construct the clamscan command
        command = [
            self.clamscan_path,
            '-r',             # Enable recursive scanning
            '--bell',         # Beep when a virus is found
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

            # Read and emit clamscan output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    # Terminate the process if scanning has been stopped
                    self.process.terminate()
                    self.process.wait()
                    self.scan_finished.emit("Scan cancelled by user.")
                    return
                line = line.strip()
                if line:
                    # Check if line indicates a file scan result
                    if line.endswith("OK") or "FOUND" in line:
                        self.scanned_files += 1
                        self.update_progress_bar()
                        # Check if the line indicates an infected file
                        if "FOUND" in line:
                            self.infected_files.append(line)
                    self.scan_progress.emit(line)

            self.process.wait()

            # Capture the final output and emit the appropriate signal
            stdout, stderr = self.process.communicate()
            if stderr:
                self.scan_error.emit(stderr)
            else:
                # Send the infected files list to the main window
                self.scan_finished.emit('\n'.join(self.infected_files))

        except Exception as e:
            # Emit any exceptions that occur during scanning
            error_message = f"An error occurred: {str(e)}"
            self.scan_error.emit(error_message)

    def count_files(self, path):
        """
        Counts the total number of files to be scanned.

        Args:
            path (str): The path to the file or directory.

        Returns:
            int: The total number of files.
        """
        if os.path.isfile(path):
            return 1
        file_count = 0
        for root, dirs, files in os.walk(path):
            file_count += len(files)
        return file_count

    def update_progress_bar(self):
        """
        Calculates and emits the current progress percentage.
        """
        if self.total_files > 0:
            progress = int((self.scanned_files / self.total_files) * 100)
            self.progress_update.emit(progress)

    def stop(self):
        """
        Stops the scanning process if it is running.
        """
        self._is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
