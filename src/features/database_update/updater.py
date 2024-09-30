# src/features/database_update/updater.py
import subprocess
import os
from datetime import datetime
from config.config_manager import ConfigManager
from logs.logger import SafeKeepLogger

class DatabaseUpdater:
    def __init__(self):
        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing DatabaseUpdater.")

        # Retrieve the path to freshclam and the ClamAV database from the configuration file
        config_manager = ConfigManager()
        try:
            self.freshclam_path = config_manager.get_config_value('Paths', 'freshclam_path')
            self.clamav_database_path = config_manager.get_config_value('Paths', 'clamav_database_path')
            self.logger.info(f"Freshclam path set to: {self.freshclam_path}")
            self.logger.info(f"ClamAV database path set to: {self.clamav_database_path}")
        except KeyError:
            self.logger.error("Failed to retrieve paths from configuration.")
            raise

    def update_database(self):
        """
        Updates the ClamAV database using the freshclam utility.
        Verifies if the update was successful by comparing database timestamps.
        :return: A dictionary containing the update result and a boolean indicating if the update occurred.
        """
        self.logger.info("Starting ClamAV database update.")
        if not os.path.isfile(self.freshclam_path):
            self.logger.error(f"The freshclam executable '{self.freshclam_path}' does not exist.")
            raise FileNotFoundError(f"The freshclam executable '{self.freshclam_path}' does not exist.")

        # Get the timestamp or version before the update
        previous_version = self.get_database_version()
        self.logger.info(f"Previous database version: {previous_version}")

        # Execute freshclam command to update the database
        try:
            result = subprocess.run([self.freshclam_path], capture_output=True, text=True)
            self.logger.info(f"Database update completed. Return code: {result.returncode}")

            # Get the timestamp or version after the update
            new_version = self.get_database_version()
            self.logger.info(f"New database version: {new_version}")

            # Check if the database was actually updated
            update_occurred = new_version != previous_version

            if update_occurred:
                self.logger.info("Database was updated successfully.")
            else:
                self.logger.info("No changes detected in the database.")

            return {"output": result.stdout, "return_code": result.returncode, "update_occurred": update_occurred}
        except Exception as e:
            self.logger.error(f"Failed to update ClamAV database: {e}")
            raise RuntimeError(f"Failed to update ClamAV database: {e}")

    def get_database_version(self):
        """
        Retrieves the current version or timestamp of the ClamAV database.
        This method uses the 'freshclam --version' command to get the database information.
        :return: A string representing the current version or timestamp, or None if unavailable.
        """
        try:
            # Execute the 'freshclam --version' command to get the database information
            result = subprocess.run([self.freshclam_path, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout.strip()
                self.logger.info(f"Fetched ClamAV version and database info: {output}")

                # The output is expected to be in the format:
                # ClamAV 1.4.1/27413/Mon Sep 30 04:48:24 2024
                # We want to extract the date part after the second slash
                parts = output.split('/')
                if len(parts) >= 3:
                    # The third part should contain the last update date
                    last_update_time = parts[2].strip()
                    self.logger.info(f"Extracted last database update time: {last_update_time}")
                    return last_update_time
                else:
                    self.logger.warning("Unable to parse the database version from freshclam output.")
                    return None
            else:
                self.logger.error(f"Failed to get ClamAV database version. Return code: {result.returncode}. Output: {result.stdout}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to get ClamAV database version: {e}")
            return None