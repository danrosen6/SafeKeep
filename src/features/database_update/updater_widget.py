# src/features/database_update/updater_widget.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMessageBox
from logs.logger import SafeKeepLogger
from .updater import DatabaseUpdater

class DatabaseUpdateWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Database Updater")
        self.setLayout(QVBoxLayout())

        # Initialize the logger
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing DatabaseUpdateWidget.")

        # Initialize the DatabaseUpdater instance
        self.database_updater = DatabaseUpdater()

        # Create UI components
        self.update_button = QPushButton("Update Database")
        self.last_update_label = QLabel("Last Database Update: Fetching...")
        self.update_output = QTextEdit()
        self.update_output.setReadOnly(True)

        # Add components to layout
        self.layout().addWidget(self.update_button)
        self.layout().addWidget(self.last_update_label)
        self.layout().addWidget(self.update_output)

        # Connect button signals to methods
        self.update_button.clicked.connect(self.update_database)

        # Fetch and display the last update time
        self.display_last_update_time()

    def display_last_update_time(self):
        """
        Fetches and displays the last time the ClamAV database was updated.
        """
        self.logger.info("Fetching last database update time.")
        last_update_time = self.database_updater.get_database_version()
        if last_update_time:
            self.last_update_label.setText(f"Last Database Update: {last_update_time}")
            self.logger.info(f"Displayed last database update time: {last_update_time}")
        else:
            self.last_update_label.setText("Last Database Update: Unknown")
            self.logger.warning("Unable to fetch last database update time. Displaying 'Unknown'.")

    def update_database(self):
        """
        Initiates the ClamAV database update process and displays the output in the UI.
        """
        try:
            # Perform the database update
            self.update_output.append("Starting ClamAV database update...")
            result = self.database_updater.update_database()
            self.update_output.append(f"Update Results:\n{result['output']}")

            # Check if the update actually occurred
            if result.get("update_occurred"):
                QMessageBox.information(self, "Update Complete", "ClamAV database was updated successfully.")
                self.logger.info("ClamAV database was updated successfully.")
            else:
                QMessageBox.information(self, "No Updates", "No changes detected. The database is already up-to-date.")
                self.logger.info("No changes detected in the database. Already up-to-date.")

            # Update the last update time after successful update
            self.display_last_update_time()
        except Exception as e:
            QMessageBox.critical(self, "Update Failed", f"Failed to update ClamAV database: {e}")
            self.logger.error(f"Failed to update ClamAV database: {e}")
