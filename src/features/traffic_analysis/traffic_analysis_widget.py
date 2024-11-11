import pyshark
import asyncio
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, QComboBox, QLineEdit
from PySide6.QtCore import Signal, Slot
from logs.logger import SafeKeepLogger
from threading import Thread
import os
from config.config_manager import ConfigManager

class TrafficAnalyzer(QWidget):
    traffic_capture_complete_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.logger = SafeKeepLogger().get_logger()
        self.logger.info("Initializing TrafficAnalyzer.")

        self.setWindowTitle("Traffic Analysis")
        self.setGeometry(300, 300, 800, 600)

        layout = QVBoxLayout(self)
        self.interface_combo = QComboBox(self)
        self.capture_filter_input = QLineEdit(self)
        self.capture_filter_input.setPlaceholderText("Optional: Enter capture filter (e.g., tcp port 80)")
        self.start_capture_button = QPushButton("Start Capture", self)
        self.stop_capture_button = QPushButton("Stop Capture", self)
        self.capture_output = QTextEdit(self)
        self.capture_output.setReadOnly(True)
        
        self.stop_capture_button.setEnabled(False)

        layout.addWidget(QLabel("Traffic Analysis Tool"))
        layout.addWidget(QLabel("Select Network Interface:"))
        layout.addWidget(self.interface_combo)
        layout.addWidget(self.capture_filter_input)
        layout.addWidget(self.start_capture_button)
        layout.addWidget(self.stop_capture_button)
        layout.addWidget(self.capture_output)

        self.start_capture_button.clicked.connect(self.start_capture)
        self.stop_capture_button.clicked.connect(self.stop_capture)
        self.traffic_capture_complete_signal.connect(self.update_capture_output)

        self.capture_thread = None
        self.stop_capture_flag = False
        self.config_manager = ConfigManager()
        self.tshark_path = self.get_tshark_path_from_config()
        self.logger.debug("TrafficAnalyzer initialized with default values.")

        # Populate available interfaces
        self.populate_interfaces()

    def get_tshark_path_from_config(self):
        try:
            tshark_path = self.config_manager.get_config_value('Paths', 'tshark_path')
            self.logger.info(f"Retrieved TShark path from config: {tshark_path}")
            return tshark_path
        except KeyError:
            self.logger.warning("TShark path not found in config. Please set it manually.")
            return None

    def populate_interfaces(self):
        try:
            interfaces = pyshark.LiveCapture().interfaces
            self.logger.info(f"Available interfaces: {interfaces}")
            self.interface_combo.addItems(interfaces)
        except Exception as e:
            self.logger.error(f"Failed to retrieve network interfaces: {e}")

    def start_capture(self):
        self.logger.info("Starting traffic capture.")
        self.capture_output.append("Starting packet capture...")
        self.stop_capture_flag = False
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)
        
        self.capture_thread = Thread(target=self.capture_traffic, daemon=True)
        self.logger.debug("Capture thread initialized and started.")
        self.capture_thread.start()

    def stop_capture(self):
        self.logger.info("Stopping traffic capture.")
        self.stop_capture_flag = True
        self.logger.debug("Stop capture flag set to True.")
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)
        self.logger.debug("Start and Stop buttons updated accordingly.")
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()
            self.logger.debug("Capture thread joined successfully.")

    def capture_traffic(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.logger.debug("Attempting to start packet capture using PyShark.")
            if self.tshark_path:
                os.environ["PATH"] += os.pathsep + os.path.dirname(self.tshark_path)

            interface = self.interface_combo.currentText()
            capture_filter = self.capture_filter_input.text()
            self.logger.info(f"Using interface: {interface}")
            if capture_filter:
                self.logger.info(f"Using capture filter: {capture_filter}")
            else:
                self.logger.info("No filter set. Capturing all protocols, including UDP.")

            capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter if capture_filter else None, tshark_path=self.tshark_path)
            self.logger.debug(f"Initialized LiveCapture with filter: {capture_filter} and interface: {interface}")
            for packet in capture.sniff_continuously():
                if self.stop_capture_flag:
                    self.logger.debug("Stop capture flag detected. Exiting packet capture loop.")
                    break
                packet_info = self.format_packet(packet)
                self.logger.info(f"Captured packet: {packet_info}")
                self.traffic_capture_complete_signal.emit(packet_info)

            self.logger.info("Packet capture completed.")
            self.traffic_capture_complete_signal.emit("Packet capture completed.")
        except Exception as e:
            error_message = f"Failed to capture traffic: {e}"
            self.logger.error(error_message)
            self.traffic_capture_complete_signal.emit(error_message)
        finally:
            loop.stop()
            loop.close()

    def format_packet(self, packet):
        try:
            summary = f"[{packet.sniff_time}] {packet.highest_layer} - {packet.ip.src} -> {packet.ip.dst}"
            self.logger.debug(f"Formatted packet: {summary}")
            return summary
        except AttributeError as e:
            self.logger.warning(f"Failed to format packet due to missing attributes: {e}")
            return "[Unknown Packet Type]"

    @Slot(str)
    def update_capture_output(self, packet_info):
        self.logger.debug(f"Updating capture output with packet info: {packet_info}")
        self.capture_output.append(packet_info)
        self.logger.info("Updated capture output with new packet information.")
