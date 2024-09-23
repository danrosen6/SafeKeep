import os
import configparser

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')

class ConfigManager:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = CONFIG_FILE
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            # Initialize default sections
            self.config['ClamAV'] = {}
            self.config['Quarantine'] = {}
            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)

    # Existing methods to get and set paths
    def get_clamav_path(self):
        return self.config.get('ClamAV', 'clamscan_path', fallback=None)

    def set_clamav_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['clamscan_path'] = path
        self.save_config()

    def get_freshclam_path(self):
        return self.config.get('ClamAV', 'freshclam_path', fallback=None)

    def set_freshclam_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['freshclam_path'] = path
        self.save_config()

    def get_database_path(self):
        return self.config.get('ClamAV', 'database_path', fallback=None)

    def set_database_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['database_path'] = path
        self.save_config()

    def get_quarantine_path(self):
        return self.config.get('Quarantine', 'quarantine_path', fallback=None)

    def set_quarantine_path(self, path):
        if 'Quarantine' not in self.config:
            self.config['Quarantine'] = {}
        self.config['Quarantine']['quarantine_path'] = path
        self.save_config()

    def save_config(self):
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
