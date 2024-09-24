"""
Main entry point for the application. Handles administrative privilege escalation
and initializes the GUI application.
"""

import sys
import os
import ctypes
import logging
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow

# Configure logging to display messages of level DEBUG or higher
logging.basicConfig(level=logging.DEBUG)

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

def main():
    """
    Main function to initialize the application and start the event loop.
    """
    try:
        # Create an instance of the application
        app = QApplication(sys.argv)
        
        # Instantiate and display the main window
        window = MainWindow()
        window.show()
        
        # Execute the application event loop
        sys.exit(app.exec())
    except Exception as e:
        # Log any exceptions that occur during execution
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}", exc_info=True)

if __name__ == '__main__':
    # Entry point of the script
    if not is_admin():
        # If not running with admin rights, re-run the program with elevated privileges
        script = os.path.abspath(sys.argv[0])
        
        # Build the command line parameters string
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        
        # Re-run the script with administrative rights
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit()
    else:
        # If running as admin, proceed to main
        main()
