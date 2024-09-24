# main.py

import sys
import os
import ctypes
import logging
from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"An error occurred: {e}", exc_info=True)

if __name__ == '__main__':
    if not is_admin():
        # Re-run the program with admin rights
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit()
    else:
        main()
