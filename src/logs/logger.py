import os
import logging
from datetime import datetime

class SafeKeepLogger:
    def __init__(self, log_dir='logs', log_filename='safekeep.log'):
        """
        Initializes the logger, creates the log file and directory if not present.
        :param log_dir: Directory where logs will be stored.
        :param log_filename: Name of the log file.
        """
        self.log_dir = os.path.join(os.path.dirname(__file__), '..', log_dir)
        self.log_file = os.path.join(self.log_dir, log_filename)

        # Ensure the log directory exists
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # Configure logging
        self.logger = logging.getLogger('SafeKeepLogger')
        self.logger.setLevel(logging.DEBUG)

        # Check if the logger already has handlers (avoid duplicate logs)
        if not self.logger.handlers:
            # Create a file handler with timestamped log entries
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)

            # Create a logging format
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)

            # Add the file handler to the logger
            self.logger.addHandler(file_handler)

    def get_logger(self):
        """
        Returns the configured logger instance.
        """
        return self.logger

# Example usage within this module (this would not run when imported):
if __name__ == "__main__":
    log = SafeKeepLogger().get_logger()
    log.info("Logger setup complete.")

"""
main.py implementation

from core.logger import SafeKeepLogger

# Initialize the logger
logger = SafeKeepLogger().get_logger()

# Example usage
logger.info("Application has started.")
logger.error("An error occurred during execution.")


"""