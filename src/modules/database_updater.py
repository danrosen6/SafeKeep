# modules/database_updater.py

from PySide6.QtCore import QThread, Signal
import subprocess
import logging

class DatabaseUpdateThread(QThread):
    update_progress = Signal(str)
    update_finished = Signal(bool)

    def __init__(self, freshclam_path):
        super().__init__()
        self.freshclam_path = freshclam_path

    def run(self):
        try:
            process = subprocess.Popen(
                [self.freshclam_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if line:
                    self.update_progress.emit(line)

            process.wait()
            if process.returncode == 0:
                self.update_finished.emit(True)
            else:
                self.update_finished.emit(False)
        except Exception as e:
            logging.error(f"Database update failed: {e}")
            self.update_finished.emit(False)
