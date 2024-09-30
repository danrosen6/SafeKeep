# Adjusted url_analysis_widget.py

import sys
import threading
import time
from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QTextOption
from features.url_checker.url_decomposition import analyze_url
from features.url_checker.virus_total_analysis import initiate_virus_total_analysis
from logs.logger import SafeKeepLogger


class URLCheckerWindow(QWidget):
    virus_total_complete_signal = Signal(str)  # Signal to emit results of VirusTotal analysis
    url_analysis_complete_signal = Signal(str)  # Signal to emit results of URL analysis

    def __init__(self):
        super().__init__()
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing URLCheckerWindow.")

        self.setWindowTitle("URL Analysis")
        self.setGeometry(300, 300, 600, 600)

        # Create layout and UI components
        layout = QVBoxLayout(self)
        self.url_input = QLineEdit(self)
        self.check_button = QPushButton("Decompose URL", self)
        self.results_text = QTextEdit(self)
        self.results_text.setReadOnly(True)
        self.results_text.setWordWrapMode(QTextOption.WordWrap)

        self.virus_total_button = QPushButton("Analyze with VirusTotal", self)
        self.virus_total_results = QTextEdit(self)
        self.virus_total_results.setReadOnly(True)
        self.virus_total_results.setWordWrapMode(QTextOption.WordWrap)
        self.virus_total_timer = QTimer(self)
        self.virus_total_timer.setInterval(1000)
        self.virus_total_time_left = 15

        # Add widgets to the layout
        layout.addWidget(QLabel("Enter the URL:"))
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)
        layout.addWidget(self.virus_total_button)
        layout.addWidget(self.virus_total_results)

        # Connect signals and slots
        self.check_button.clicked.connect(self.start_url_analysis)
        self.virus_total_button.clicked.connect(self.start_virus_total_analysis)
        self.virus_total_timer.timeout.connect(self.update_countdown)

        self.virus_total_complete_signal.connect(self.update_virus_total_results)
        self.url_analysis_complete_signal.connect(self.update_url_analysis_results)

        self.logger.info("URLCheckerWindow initialized successfully.")

    def start_url_analysis(self):
        url = self.url_input.text()
        threading.Thread(target=self.check_url, args=(url,), daemon=True).start()
        self.logger.info(f"Started URL analysis for: {url}")

    def check_url(self, url):
        result = analyze_url(url)
        self.url_analysis_complete_signal.emit(result)

    def update_url_analysis_results(self, result):
        self.results_text.setText(result)
        self.logger.info("URL analysis results updated in UI.")

    def start_virus_total_analysis(self):
        url = self.url_input.text()
        self.reset_timer()
        # Submit the URL to VirusTotal and fetch the results after 15 seconds
        threading.Thread(target=self.analyze_with_virustotal, args=(url,), daemon=True).start()
        self.logger.info(f"Started VirusTotal analysis for: {url}")

    def analyze_with_virustotal(self, url):
        result = initiate_virus_total_analysis(url, self.emit_results)
        self.logger.info("VirusTotal analysis initiated.")

    def emit_results(self, report):
        # Emit the report through the signal
        self.virus_total_complete_signal.emit(report)

    def reset_timer(self):
        self.virus_total_time_left = 15
        self.virus_total_button.setEnabled(False)
        self.virus_total_timer.start()
        self.update_countdown()

    def update_countdown(self):
        self.virus_total_time_left -= 1
        if self.virus_total_time_left <= 0:
            self.virus_total_timer.stop()
            self.virus_total_button.setEnabled(True)
            self.virus_total_button.setText("Analyze with VirusTotal")
        else:
            self.virus_total_button.setText(f"Analyzing... ({self.virus_total_time_left}s)")

    def update_virus_total_results(self, report):
        self.virus_total_results.setText(report)
        self.virus_total_button.setEnabled(True)
        self.logger.info("VirusTotal results updated in UI.")
