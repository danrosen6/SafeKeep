import os
import configparser
from PySide6.QtWidgets import QFileDialog, QApplication, QMessageBox
from logs.logger import SafeKeepLogger

class ConfigManager:
    def __init__(self, config_filename='config.ini'):
        """
        Initializes the ConfigManager with the specified config filename.
        If the config file does not exist, it will be created.
        """

        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing ConfigManager.")

        self.config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')
        self.config_file = os.path.join(self.config_dir, config_filename)

        # Ensure the config directory exists
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
            self.logger.info(f"Created config directory: {self.config_dir}")

        # Initialize a config parser
        self.config = configparser.ConfigParser()

        # Create the config file if it does not exist
        if not os.path.isfile(self.config_file):
            self.logger.info("Config file not found. Creating a new one...")
            self.create_config()
        else:
            self.logger.info(f"Config file found: {self.config_file}")

    def create_config(self):
        """
        Creates a new configuration file and prompts the user to set the required paths.
        """
        self.logger.info("Creating a new configuration file.")
        try:
            # Prompt the user for the required paths
            clamscan_path = self.prompt_for_path("Select the path to clamscan.exe", file_selection=True)
            freshclam_path = self.prompt_for_path("Select the path to freshclam.exe", file_selection=True)
            clamav_database_path = self.prompt_for_path("Select the ClamAV database directory", file_selection=False)
            quarantine_path = self.prompt_for_path("Select the quarantine directory", file_selection=False)
            tshark_path = self.prompt_for_path("Select the path to tshark.exe", file_selection=True)

            # Save the configuration to the file
            self.config['Paths'] = {
                'clamscan_path': clamscan_path,
                'freshclam_path': freshclam_path,
                'clamav_database_path': clamav_database_path,
                'quarantine_path': quarantine_path,
                'tshark_path': tshark_path
            }

            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)
            self.logger.info(f"Configuration file created successfully at {self.config_file}")

        except Exception as e:
            self.logger.error(f"Failed to create configuration file: {e}")

    def prompt_for_path(self, message, file_selection=False):
        """
        Prompts the user to select a file or directory path using a dialog box.
        :param message: Message displayed on the file dialog prompt.
        :param file_selection: If True, a file selection dialog is displayed. Otherwise, a directory selection dialog is shown.
        :return: The selected path as a string.
        """
        app = QApplication.instance()
        if not app:
            app = QApplication([])

        path = ""
        if file_selection:
            path, _ = QFileDialog.getOpenFileName(None, message, "", "Executables (*.exe);;All Files (*)")
        else:
            path = QFileDialog.getExistingDirectory(None, message)

        if not path:
            QMessageBox.warning(None, "Path Selection", "No path was selected. Exiting...")
            self.logger.warning(f"No path was selected for: {message}")
            raise SystemExit(f"No path selected for {message}. Exiting application.")
        self.logger.info(f"Path selected for '{message}': {path}")
        return path

    def get_config_value(self, section, key):
        """
        Retrieves a value from the configuration file.
        :param section: The section of the configuration file.
        :param key: The key to retrieve the value for.
        :return: The value corresponding to the specified section and key.
        """
        try:
            self.config.read(self.config_file)
            value = self.config[section][key]
            self.logger.info(f"Retrieved value for [{section}] {key}: {value}")
            return value
        except KeyError as e:
            self.logger.error(f"Key '{key}' not found in section '{section}' of the config file: {e}")
            raise

    def set_config_value(self, section, key, value):
        """
        Sets a value in the configuration file.
        :param section: The section of the configuration file.
        :param key: The key to set the value for.
        :param value: The value to be set.
        """
        self.config.read(self.config_file)
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

        # Write changes back to the file
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        self.logger.info(f"Set value for [{section}] {key} to {value} in config file.")

# Example usage within this module (this would not run when imported):
if __name__ == "__main__":
    config_manager = ConfigManager()
    tshark_path = config_manager.get_config_value('Paths', 'tshark_path')
    print(f"TShark Path: {tshark_path}")
