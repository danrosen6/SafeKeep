# src/features/virus_scanner/scanner.py
import subprocess
import os
import re
from config.config_manager import ConfigManager
from logs.logger import SafeKeepLogger
from features.quarantine.quarantine import QuarantineManager

class VirusScanner:
    def __init__(self):
        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing VirusScanner.")

        # Retrieve paths from the configuration file
        config_manager = ConfigManager()
        try:
            self.clamscan_path = config_manager.get_config_value('Paths', 'clamscan_path')
            self.clamav_database_path = config_manager.get_config_value('Paths', 'clamav_database_path')
            self.logger.info(f"ClamAV scan executable path set to: {self.clamscan_path}")
            self.logger.info(f"ClamAV database path set to: {self.clamav_database_path}")
        except KeyError:
            self.logger.error("Failed to retrieve ClamAV paths from configuration.")
            raise

        # Initialize the QuarantineManager
        self.quarantine_manager = QuarantineManager()

    def scan_file(self, file_path):
        """
        Scans a single file using ClamAV and captures real-time output.
        :param file_path: The path to the file to be scanned.
        :return: A dictionary containing the scan results, including the scan summary.
        """
        self.logger.info(f"Starting file scan for: {file_path}")

        # Verify that the file exists and is accessible
        if not os.path.isfile(file_path):
            self.logger.error(f"The file '{file_path}' does not exist or cannot be accessed.")
            raise FileNotFoundError(f"The file '{file_path}' does not exist or cannot be accessed.")

        # Normalize the file path
        normalized_path = os.path.normpath(file_path)
        self.logger.info(f"Normalized file path: {normalized_path}")

        # Construct the clamscan command
        command = [self.clamscan_path, normalized_path]

        # Infected files list to keep track of detected threats and summary to hold scan details
        infected_files = []
        scan_summary = ""

        try:
            # Start the clamscan process using Popen to read real-time output
            self.logger.info(f"Running clamscan with command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            # Read the clamscan output line by line
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                self.logger.info(f"ClamAV Output: {line}")

                # Check if the line indicates an infected file
                if "FOUND" in line:
                    match = re.match(r'^(.*?): (.*) FOUND$', line)
                    if match:
                        infected_file = match.group(1)
                        virus_name = match.group(2)
                        infected_files.append({"file": infected_file, "virus": virus_name})
                        self.logger.warning(f"Infected file detected: {infected_file} ({virus_name})")

                        # Quarantine the infected file
                        try:
                            quarantined_file_path = self.quarantine_manager.quarantine_file(infected_file)
                            self.logger.info(f"Quarantined file: {quarantined_file_path}")
                        except Exception as e:
                            self.logger.error(f"Failed to quarantine file '{infected_file}': {e}")

                # Capture the summary details
                if line.startswith("----------- SCAN SUMMARY -----------") or any(key in line for key in ["Known viruses:", "Scanned directories:", "Scanned files:", "Infected files:", "Data scanned:", "Time:"]):
                    scan_summary += f"{line}\n"

            # Wait for the clamscan process to finish and capture any errors
            stdout, stderr = process.communicate()
            if stderr:
                self.logger.error(f"ClamAV error: {stderr}")
                raise RuntimeError(f"ClamAV error: {stderr}")

            self.logger.info(f"File scan completed for {file_path}. Infected files: {len(infected_files)}")

            # Return the scan results along with the summary
            return {"file_path": file_path, "infected_files": infected_files, "output": stdout, "summary": scan_summary}

        except Exception as e:
            self.logger.error(f"Failed to scan file '{file_path}': {e}")
            raise RuntimeError(f"Failed to scan file '{file_path}': {e}")

    def scan_directory(self, directory_path):
        """
        Scans an entire directory using ClamAV and captures real-time output.
        :param directory_path: The path to the directory to be scanned.
        :return: A dictionary containing the scan results, including the scan summary.
        """
        normalized_path = os.path.normpath(directory_path)
        self.logger.info(f"Starting directory scan for: {normalized_path}")

        # Check if the directory exists and is accessible
        if not os.path.isdir(normalized_path):
            self.logger.error(f"The directory '{normalized_path}' does not exist or cannot be accessed.")
            raise FileNotFoundError(f"The directory '{normalized_path}' does not exist or cannot be accessed.")
        
        try:
            # Attempt to access the directory to check permissions
            os.listdir(normalized_path)
            self.logger.info(f"Directory is accessible: {normalized_path}")
        except PermissionError as e:
            self.logger.error(f"Directory is not accessible: {normalized_path}. Error: {e}")
            raise PermissionError(f"The directory '{normalized_path}' cannot be accessed: {e}")

        # Construct the clamscan command for directory scanning
        command = [
            self.clamscan_path,
            '-r',  # Recursively scan the directory
            normalized_path
        ]

        # Infected files list to keep track of detected threats and summary to hold scan details
        infected_files = []
        scan_summary = ""

        try:
            # Start the clamscan process using Popen to read real-time output
            self.logger.info(f"Running clamscan with command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            # Read the clamscan output line by line
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                self.logger.info(f"ClamAV Output: {line}")

                # Check if the line indicates an infected file
                if "FOUND" in line:
                    match = re.match(r'^(.*?): (.*) FOUND$', line)
                    if match:
                        infected_file = match.group(1)
                        virus_name = match.group(2)
                        infected_files.append({"file": infected_file, "virus": virus_name})
                        self.logger.warning(f"Infected file detected: {infected_file} ({virus_name})")

                        # Quarantine the infected file
                        try:
                            quarantined_file_path = self.quarantine_manager.quarantine_file(infected_file)
                            self.logger.info(f"Quarantined file: {quarantined_file_path}")
                        except Exception as e:
                            self.logger.error(f"Failed to quarantine file '{infected_file}': {e}")

                # Capture the summary details
                if line.startswith("----------- SCAN SUMMARY -----------") or any(key in line for key in ["Known viruses:", "Scanned directories:", "Scanned files:", "Infected files:", "Data scanned:", "Time:"]):
                    scan_summary += f"{line}\n"

            # Wait for the clamscan process to finish and capture any errors
            stdout, stderr = process.communicate()
            if stderr:
                self.logger.error(f"ClamAV error: {stderr}")
                raise RuntimeError(f"ClamAV error: {stderr}")

            self.logger.info(f"Directory scan completed for {directory_path}. Infected files: {len(infected_files)}")

            # Return the scan results along with the summary
            return {"directory_path": directory_path, "infected_files": infected_files, "output": stdout, "summary": scan_summary}

        except Exception as e:
            self.logger.error(f"Failed to scan directory '{directory_path}': {e}")
            raise RuntimeError(f"Failed to scan directory '{directory_path}': {e}")
