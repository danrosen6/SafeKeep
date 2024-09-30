# src/main.py
import os
import sys
import ctypes
from PySide6.QtWidgets import QApplication, QMessageBox
from features.virus_scanner.scanner_widget import VirusScannerWidget
from features.quarantine.quarantine_widget import QuarantineWidget
from features.database_update.updater_widget import DatabaseUpdateWidget
from logs.logger import SafeKeepLogger
from PySide6.QtWidgets import QMainWindow, QMenuBar, QStackedWidget
from PySide6.QtGui import QAction

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
            self.setGeometry(100, 100, 800, 600)

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
            features_menu.addAction(virus_scanner_action)
            features_menu.addAction(quarantine_manager_action)
            features_menu.addAction(database_update_action)

            # Add Help menu actions (optional)
            about_action = QAction("About", self)
            help_menu.addAction(about_action)

            # Create a container to hold different feature widgets
            self.stacked_widget = QStackedWidget()
            self.setCentralWidget(self.stacked_widget)

            # Create and add feature widgets to the stacked widget
            self.virus_scanner_widget = VirusScannerWidget()
            self.quarantine_widget = QuarantineWidget()
            self.database_update_widget = DatabaseUpdateWidget()

            self.stacked_widget.addWidget(self.virus_scanner_widget)
            self.stacked_widget.addWidget(self.quarantine_widget)
            self.stacked_widget.addWidget(self.database_update_widget)

            # Connect menu actions to methods
            virus_scanner_action.triggered.connect(self.show_virus_scanner)
            quarantine_manager_action.triggered.connect(self.show_quarantine_manager)
            database_update_action.triggered.connect(self.show_database_updater)
            about_action.triggered.connect(self.show_about_dialog)

            # Show the initial widget
            self.stacked_widget.setCurrentWidget(self.virus_scanner_widget)

        def show_virus_scanner(self):
            """Switch to the Virus Scanner widget."""
            self.logger.info("Switching to Virus Scanner widget.")
            self.stacked_widget.setCurrentWidget(self.virus_scanner_widget)

        def show_quarantine_manager(self):
            """Switch to the Quarantine Manager widget."""
            self.logger.info("Switching to Quarantine Manager widget.")
            self.stacked_widget.setCurrentWidget(self.quarantine_widget)

        def show_database_updater(self):
            """Switch to the Database Updater widget."""
            self.logger.info("Switching to Database Updater widget.")
            self.stacked_widget.setCurrentWidget(self.database_update_widget)

        def show_about_dialog(self):
            """Display an About dialog."""
            self.logger.info("Showing About dialog.")
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.about(self, "About SafeKeep", "SafeKeep Application\nPersonal Security Application\nDeveloped by Daniel Rosen.")

    # Initialize the QApplication
    app = QApplication([])

    # Create and show the main window
    main_window = MainWindow()
    main_window.show()

    # Run the application event loop
    app.exec()
