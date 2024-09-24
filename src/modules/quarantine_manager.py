# modules/quarantine_manager.py

import os
import shutil
import logging

class QuarantineManager:
    def __init__(self, quarantine_path):
        self.quarantine_path = quarantine_path

    def restore_file(self, file_name, destination_directory):
        try:
            quarantine_file_path = os.path.join(self.quarantine_path, file_name)
            if os.path.exists(quarantine_file_path):
                # Ensure destination directory exists
                if not os.path.exists(destination_directory):
                    os.makedirs(destination_directory, exist_ok=True)

                # Change permissions to allow moving
                os.chmod(quarantine_file_path, 0o600)
                restored_file_path = os.path.join(destination_directory, file_name)
                shutil.move(quarantine_file_path, restored_file_path)
                # Optionally, reset permissions on the restored file
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
        try:
            file_path = os.path.join(self.quarantine_path, file_name)
            if os.path.exists(file_path):
                # Change permissions to allow deletion
                os.chmod(file_path, 0o600)
                os.remove(file_path)
                logging.debug(f"File {file_name} deleted successfully.")
                return True
            else:
                logging.error(f"File {file_name} not found in quarantine.")
                return False
        except Exception as e:
            logging.error(f"Error deleting file: {e}")
            return False
