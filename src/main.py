import os
import sys
import ctypes
from PySide6.QtWidgets import QApplication, QMainWindow, QMenuBar, QStackedWidget, QMessageBox
from PySide6.QtGui import QAction
from features.virus_scanner.scanner_widget import VirusScannerWidget
from features.quarantine.quarantine_widget import QuarantineWidget
from features.database_update.updater_widget import DatabaseUpdateWidget
from features.url_checker.url_analysis_widget import URLCheckerWindow
from features.traffic_analysis.traffic_analysis_widget import TrafficAnalyzer
from features.traffic_analysis.anomaly_management_widget import AnomalyManagementWidget
from logs.logger import SafeKeepLogger
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

def is_admin():
    """
    Check if the current user has administrative privileges.

    Returns:
        bool: True if the user is an administrator, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # If checking admin status fails, assume not an admin
        return False

def elevate_privileges():
    """
    Re-run the application with administrative privileges.
    """
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])

    # Use ShellExecuteW to re-run the script with elevated privileges
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    sys.exit()

# Ensure the application is running with administrative privileges
if not is_admin():
    elevate_privileges()
else:
    # If running as admin, proceed to main
    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("SafeKeep Application")
            self.setGeometry(100, 100, 1000, 700)

            # Initialize the logger
            self.logger = SafeKeepLogger().get_logger()
            self.logger.info("Initializing main window.")

            # Create the menu bar
            menu_bar = QMenuBar(self)
            self.setMenuBar(menu_bar)

            # Create menus and actions
            features_menu = menu_bar.addMenu("Features")
            help_menu = menu_bar.addMenu("Help")

            # Add actions to the Features menu
            virus_scanner_action = QAction("Virus Scanner", self)
            quarantine_manager_action = QAction("Quarantine Manager", self)
            database_update_action = QAction("Database Updater", self)
            url_checker_action = QAction("URL Analysis", self)
            traffic_analysis_action = QAction("Traffic Analysis", self)
            anomaly_management_action = QAction("Anomaly Management", self)
            
            features_menu.addAction(virus_scanner_action)
            features_menu.addAction(quarantine_manager_action)
            features_menu.addAction(database_update_action)
            features_menu.addAction(url_checker_action)
            features_menu.addAction(traffic_analysis_action)
            features_menu.addAction(anomaly_management_action)

            # Add Help menu actions
            about_action = QAction("About", self)
            help_menu.addAction(about_action)

            # Create a QStackedWidget to hold different feature widgets
            self.stacked_widget = QStackedWidget()
            self.setCentralWidget(self.stacked_widget)

            # Create and add feature widgets to the stacked widget
            self.virus_scanner_widget = VirusScannerWidget()
            self.quarantine_widget = QuarantineWidget()
            self.database_update_widget = DatabaseUpdateWidget()
            self.url_checker_widget = URLCheckerWindow()
            self.traffic_analyzer_widget = TrafficAnalyzer()
            self.anomaly_management_widget = AnomalyManagementWidget()

            self.stacked_widget.addWidget(self.virus_scanner_widget)
            self.stacked_widget.addWidget(self.quarantine_widget)
            self.stacked_widget.addWidget(self.database_update_widget)
            self.stacked_widget.addWidget(self.url_checker_widget)
            self.stacked_widget.addWidget(self.traffic_analyzer_widget)
            self.stacked_widget.addWidget(self.anomaly_management_widget)

            # Connect menu actions to methods for switching widgets
            virus_scanner_action.triggered.connect(lambda: self.show_feature(self.virus_scanner_widget, "Virus Scanner"))
            quarantine_manager_action.triggered.connect(lambda: self.show_feature(self.quarantine_widget, "Quarantine Manager"))
            database_update_action.triggered.connect(lambda: self.show_feature(self.database_update_widget, "Database Updater"))
            url_checker_action.triggered.connect(lambda: self.show_feature(self.url_checker_widget, "URL Analysis"))
            traffic_analysis_action.triggered.connect(lambda: self.show_feature(self.traffic_analyzer_widget, "Traffic Analysis"))
            anomaly_management_action.triggered.connect(lambda: self.show_feature(self.anomaly_management_widget, "Anomaly Management"))
            about_action.triggered.connect(self.show_about_dialog)

            # Show the initial widget
            self.stacked_widget.setCurrentWidget(self.virus_scanner_widget)
            self.logger.info("Main window initialized successfully.")

        def show_feature(self, widget, feature_name):
            """
            Switch to the given feature widget in the stacked widget.
            Args:
                widget (QWidget): The widget to display.
                feature_name (str): The name of the feature to log.
            """
            self.stacked_widget.setCurrentWidget(widget)
            self.logger.info(f"Switched to {feature_name} feature.")

        def show_about_dialog(self):
            """Display an About dialog."""
            self.logger.info("Showing About dialog.")
            QMessageBox.about(self, "About SafeKeep", "SafeKeep\nPersonal Security Application\nDeveloped by Daniel Rosen.")

    # Initialize the QApplication
    app = QApplication([])

    # Create and show the main window
    main_window = MainWindow()
    main_window.show()

    # Run the application event loop
    app.exec()
