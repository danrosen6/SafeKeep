import subprocess
import os
from PySide6.QtCore import QThread, Signal

class ScannerThread(QThread):
    scan_progress = Signal(str)
    scan_finished = Signal(str)
    scan_error = Signal(str)

    def __init__(self, path):
        super().__init__()
        self.path = path
        self._is_running = True
        self.process = None

    def run(self):
        # Normalize the path to use backslashes
        normalized_path = os.path.normpath(self.path)
        print(f"Normalized path: {normalized_path}")

        clamscan_path = r'C:\Program Files\ClamAV\clamscan.exe'

        command = [
            clamscan_path,
            '-r',  # Recursive scan
            normalized_path
        ]
        print(f"Executing command: {command}")

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Read output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    self.process.terminate()
                    break
                line = line.strip()
                if line:
                    self.scan_progress.emit(line)
            self.process.wait()

            stdout, stderr = self.process.communicate()
            if stderr:
                self.scan_error.emit(stderr)
            else:
                self.scan_finished.emit(stdout)

        except Exception as e:
            self.scan_error.emit(f"An error occurred: {e}")

    def stop(self):
        self._is_running = False
        if self.process:
            self.process.terminate()
