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

    def get_clamav_path(self):
        return self.config.get('ClamAV', 'clamscan_path', fallback=None)

    def set_clamav_path(self, path):
        if 'ClamAV' not in self.config:
            self.config['ClamAV'] = {}
        self.config['ClamAV']['clamscan_path'] = path
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
