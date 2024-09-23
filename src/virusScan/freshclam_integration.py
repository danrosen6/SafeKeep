import subprocess
from PySide6.QtCore import QThread, Signal

class FreshclamThread(QThread):
    """
    A QThread subclass that runs ClamAV's freshclam command in a separate thread.

    Signals:
        update_progress (str): Emitted when there is output from freshclam.
        update_finished (): Emitted when the update is completed successfully.
        update_error (str): Emitted when an error occurs during updating.
    """

    update_progress = Signal(str)
    update_finished = Signal()
    update_error = Signal(str)

    def __init__(self, freshclam_path):
        """
        Initializes the FreshclamThread.

        Args:
            freshclam_path (str): The full path to the freshclam executable.
        """
        super().__init__()
        self.freshclam_path = freshclam_path
        self._is_running = True
        self.process = None

    def run(self):
        """
        Executes the freshclam command and processes its output.
        """
        # Construct the freshclam command
        command = [
            self.freshclam_path,
            '--verbose'
        ]

        try:
            # Start the freshclam process
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Read and emit freshclam output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    # Terminate the process if updating has been stopped
                    self.process.terminate()
                    self.process.wait()
                    break
                line = line.strip()
                if line:
                    self.update_progress.emit(line)

            self.process.wait()

            # Capture the final output and emit the appropriate signal
            stdout, stderr = self.process.communicate()
            if stderr:
                self.update_error.emit(stderr)
            else:
                self.update_finished.emit()

        except Exception as e:
            # Emit any exceptions that occur during updating
            error_message = f"An error occurred during database update: {str(e)}"
            self.update_error.emit(error_message)

    def stop(self):
        """
        Stops the updating process if it is running.
        """
        self._is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
