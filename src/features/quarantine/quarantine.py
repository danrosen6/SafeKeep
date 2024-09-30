# src/features/quarantine/quarantine.py
import os
import shutil
from config.config_manager import ConfigManager
from logs.logger import SafeKeepLogger

class QuarantineManager:
    def __init__(self):
        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing QuarantineManager.")

        # Retrieve the quarantine path from the configuration file
        config_manager = ConfigManager()
        try:
            self.quarantine_path = config_manager.get_config_value('Paths', 'quarantine_path')
            if not os.path.exists(self.quarantine_path):
                os.makedirs(self.quarantine_path)  # Create the quarantine directory if it doesn't exist
                self.logger.info(f"Created quarantine directory: {self.quarantine_path}")
            self.logger.info(f"Quarantine path set to: {self.quarantine_path}")
        except KeyError:
            self.logger.error("Failed to retrieve the quarantine path from configuration.")
            raise

    def quarantine_file(self, file_path):
        """
        Moves a file to the quarantine directory.
        :param file_path: The path to the file to be moved to quarantine.
        :return: The path of the quarantined file in the quarantine directory.
        """
        self.logger.info(f"Quarantining file: {file_path}")
        if not os.path.isfile(file_path):
            self.logger.error(f"The file '{file_path}' does not exist.")
            raise FileNotFoundError(f"The file '{file_path}' does not exist.")

        try:
            # Move the file to the quarantine directory
            quarantined_file_path = os.path.join(self.quarantine_path, os.path.basename(file_path))
            shutil.move(file_path, quarantined_file_path)
            self.logger.info(f"File quarantined successfully: {quarantined_file_path}")
            return quarantined_file_path
        except Exception as e:
            self.logger.error(f"Failed to quarantine file '{file_path}': {e}")
            raise RuntimeError(f"Failed to quarantine file '{file_path}': {e}")

    def restore_file(self, file_name, restore_path):
        """
        Restores a quarantined file to its original or specified location.
        :param file_name: The name of the file in the quarantine directory.
        :param restore_path: The path to restore the file to.
        :return: The path of the restored file.
        """
        self.logger.info(f"Restoring file: {file_name} to {restore_path}")
        quarantined_file_path = os.path.join(self.quarantine_path, file_name)

        if not os.path.isfile(quarantined_file_path):
            self.logger.error(f"The quarantined file '{file_name}' does not exist.")
            raise FileNotFoundError(f"The quarantined file '{file_name}' does not exist.")

        try:
            # Move the file back to the specified restore path
            restored_file_path = os.path.join(restore_path, file_name)
            shutil.move(quarantined_file_path, restored_file_path)
            self.logger.info(f"File restored successfully to: {restored_file_path}")
            return restored_file_path
        except Exception as e:
            self.logger.error(f"Failed to restore file '{file_name}': {e}")
            raise RuntimeError(f"Failed to restore file '{file_name}': {e}")

    def delete_file(self, file_name):
        """
        Deletes a quarantined file from the quarantine directory.
        :param file_name: The name of the file in the quarantine directory.
        """
        self.logger.info(f"Deleting quarantined file: {file_name}")
        quarantined_file_path = os.path.join(self.quarantine_path, file_name)

        if not os.path.isfile(quarantined_file_path):
            self.logger.error(f"The quarantined file '{file_name}' does not exist.")
            raise FileNotFoundError(f"The quarantined file '{file_name}' does not exist.")

        try:
            os.remove(quarantined_file_path)
            self.logger.info(f"Quarantined file '{file_name}' deleted successfully.")
        except Exception as e:
            self.logger.error(f"Failed to delete quarantined file '{file_name}': {e}")
            raise RuntimeError(f"Failed to delete quarantined file '{file_name}': {e}")

    def list_quarantined_files(self):
        """
        Lists all files currently in the quarantine directory.
        :return: A list of filenames in the quarantine directory.
        """
        try:
            files = os.listdir(self.quarantine_path)
            self.logger.info(f"Quarantined files: {files}")
            return files
        except Exception as e:
            self.logger.error(f"Failed to list quarantined files: {e}")
            raise RuntimeError(f"Failed to list quarantined files: {e}")
