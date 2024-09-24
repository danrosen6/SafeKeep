"""
Module for managing quarantined files.

This module defines the QuarantineManager class, which provides functionality
to restore and delete files from a quarantine directory.
"""

import os
import shutil
import logging

class QuarantineManager:
    """
    Manages files within the quarantine directory.

    Attributes:
        quarantine_path (str): The path to the quarantine directory.
    """

    def __init__(self, quarantine_path):
        """
        Initialize the QuarantineManager with the specified quarantine path.

        Args:
            quarantine_path (str): Path to the quarantine directory.
        """
        self.quarantine_path = quarantine_path

    def restore_file(self, file_name, destination_directory):
        """
        Restore a quarantined file to a specified destination directory.

        Args:
            file_name (str): Name of the file to restore.
            destination_directory (str): Path to the directory where the file will be restored.

        Returns:
            bool: True if the file was restored successfully, False otherwise.
        """
        try:
            quarantine_file_path = os.path.join(self.quarantine_path, file_name)
            if os.path.exists(quarantine_file_path):
                # Ensure the destination directory exists
                if not os.path.exists(destination_directory):
                    os.makedirs(destination_directory, exist_ok=True)

                # Change permissions to allow moving the file
                os.chmod(quarantine_file_path, 0o600)

                restored_file_path = os.path.join(destination_directory, file_name)
                # Move the file from quarantine to the destination directory
                shutil.move(quarantine_file_path, restored_file_path)

                # Optionally reset permissions on the restored file
                os.chmod(restored_file_path, 0o644)

                logging.debug(f"File {file_name} restored to {restored_file_path}.")
                return True
            else:
                logging.error(f"File {file_name} not found in quarantine.")
                return False
        except Exception as e:
            logging.error(f"Error restoring file: {e}")
            return False

    def delete_file(self, file_name):
        """
        Delete a file from the quarantine directory.

        Args:
            file_name (str): Name of the file to delete.

        Returns:
            bool: True if the file was deleted successfully, False otherwise.
        """
        try:
            file_path = os.path.join(self.quarantine_path, file_name)
            if os.path.exists(file_path):
                # Change permissions to allow deletion
                os.chmod(file_path, 0o600)
                # Remove the file from the filesystem
                os.remove(file_path)

                logging.debug(f"File {file_name} deleted successfully.")
                return True
            else:
                logging.error(f"File {file_name} not found in quarantine.")
                return False
        except Exception as e:
            logging.error(f"Error deleting file: {e}")
            return False
