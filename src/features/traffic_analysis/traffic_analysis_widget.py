import os
import pyshark
import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QLineEdit
)
from PySide6.QtCore import Signal, Slot
from threading import Thread
from collections import defaultdict
from features.traffic_analysis.anomaly_management_widget import AnomalyManagementWidget
from config.config_manager import ConfigManager
from logs.logger import SafeKeepLogger

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
        self.capture_filter_input.setPlaceholderText(
            "Optional: Enter capture filter (e.g., tcp port 80)"
        )
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

        self.open_anomaly_management_button = QPushButton("Anomaly Management Settings", self)
        layout.addWidget(self.open_anomaly_management_button)
        self.open_anomaly_management_button.clicked.connect(self.open_anomaly_management)

        self.start_capture_button.clicked.connect(self.start_capture)
        self.stop_capture_button.clicked.connect(self.stop_capture)
        self.traffic_capture_complete_signal.connect(self.update_capture_output)

        self.capture_thread = None
        self.stop_capture_flag = False
        self.config_manager = ConfigManager()
        self.tshark_path = self.get_tshark_path_from_config()
        self.logger.debug("TrafficAnalyzer initialized with interface selection and default values.")

        self.populate_interfaces()
        self.protocol_counts = defaultdict(int)
        self.load_thresholds()
        self.anomalies = []

    def open_anomaly_management(self):
        self.anomaly_management_widget = AnomalyManagementWidget()
        self.anomaly_management_widget.thresholds_updated.connect(self.reload_thresholds)
        self.anomaly_management_widget.show()

    def reload_thresholds(self):
        self.logger.info("Thresholds updated. Reloading thresholds in TrafficAnalyzer.")
        self.load_thresholds()

    def get_tshark_path_from_config(self):
        try:
            tshark_path = self.config_manager.get_config_value('Paths', 'tshark_path')
            self.logger.debug(f"Retrieved TShark path from config: {tshark_path}")
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

    def load_thresholds(self):
        try:
            self.udp_flood_threshold = int(self.config_manager.get_config_value('Anomalies', 'udp_threshold'))
            self.icmp_flood_threshold = int(self.config_manager.get_config_value('Anomalies', 'icmp_threshold'))
            self.logger.info("Reloaded thresholds from configuration.")
        except KeyError:
            self.udp_flood_threshold = 200
            self.icmp_flood_threshold = 150
            self.logger.warning("Thresholds not found in configuration. Using default values.")

    def start_capture(self):
        interface = self.interface_combo.currentText()
        self.interface_name = interface
        capture_filter = self.capture_filter_input.text()
        self.logger.info(f"Starting traffic capture on interface: {interface} with filter: {capture_filter if capture_filter else 'None'}.")
        self.capture_output.append("Starting packet capture...")
        self.stop_capture_flag = False
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)

        self.capture_thread = Thread(target=self.capture_traffic, daemon=True)
        self.capture_thread.start()
        self.logger.debug(f"Capture thread started for interface: {interface} with filter: {capture_filter}.")

    def stop_capture(self):
        self.logger.info("Stopping traffic capture.")
        self.stop_capture_flag = True
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                self.logger.warning("Capture thread did not terminate in a timely manner.")

        self.capture_output.append("\nAnomalies Detected:")
        for anomaly in self.anomalies:
            self.capture_output.append(
                f"Protocol: {anomaly['protocol']}, Source IP: {anomaly['source_ip']}, "
                f"Destination IP: {anomaly['destination_ip']}, Packet Count: {anomaly['packet_count']}, "
                f"Interface: {anomaly['interface']}"
            )

    def capture_traffic(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.logger.debug("Attempting to start packet capture using PyShark.")
            if self.tshark_path:
                os.environ["PATH"] += os.pathsep + os.path.dirname(self.tshark_path)

            interface = self.interface_combo.currentText()
            capture_filter = self.capture_filter_input.text()
            capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter if capture_filter else None, tshark_path=self.tshark_path)

            for packet in capture.sniff_continuously():
                if self.stop_capture_flag:
                    self.logger.debug("Stop capture flag detected. Exiting packet capture loop.")
                    break
                packet_info = self.format_packet(packet)
                self.traffic_capture_complete_signal.emit(packet_info)
                self.analyze_packet(packet)

            self.logger.info("Packet capture completed.")
            self.traffic_capture_complete_signal.emit("Packet capture completed.")
        except Exception as e:
            error_message = f"Failed to capture traffic: {e}"
            self.logger.error(error_message)
            self.traffic_capture_complete_signal.emit(error_message)
        finally:
            self.logger.debug("Event loop closing after packet capture.")
            if loop.is_running():
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.stop()
            loop.close()

    def format_packet(self, packet):
        try:
            time = packet.sniff_time
            protocol = packet.highest_layer
            length = packet.length

            if hasattr(packet, 'ip'):
                source = packet.ip.src
                destination = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                source = packet.ipv6.src
                destination = packet.ipv6.dst
            elif hasattr(packet, 'eth'):
                source = packet.eth.src
                destination = packet.eth.dst
            else:
                source = 'N/A'
                destination = 'N/A'

            additional_info = ' | '.join(
                f"{key}: {value}" for key, value in [
                    ("Frame Number", getattr(packet, 'frame_info', {}).get('number', 'N/A')),
                    ("TCP Port", getattr(packet.tcp, 'port', 'N/A') if hasattr(packet, 'tcp') else 'N/A'),
                    ("UDP Port", getattr(packet.udp, 'port', 'N/A') if hasattr(packet, 'udp') else 'N/A'),
                    ("ICMP Type", getattr(packet.icmp, 'type', 'N/A') if hasattr(packet, 'icmp') else 'N/A'),
                    ("TTL", getattr(packet.ip, 'ttl', 'N/A') if hasattr(packet, 'ip') else 'N/A'),
                    ("Hop Limit", getattr(packet.ipv6, 'hlim', 'N/A') if hasattr(packet, 'ipv6') else 'N/A')
                ] if value != 'N/A'
            )

            summary = f"[{time}] {protocol} - {source} -> {destination} | Length: {length} | Info: {additional_info}"
            self.logger.debug(f"Formatted packet: {summary}")
            return summary
        except AttributeError as e:
            self.logger.warning(f"Failed to format packet due to missing attributes: {e}")
            return f"[Unknown Packet Type] - Packet Length: {packet.length}"

    def analyze_packet(self, packet):
        try:
            protocol = packet.highest_layer
            self.protocol_counts[protocol] += 1

            if protocol == 'UDP' and self.protocol_counts[protocol] > self.udp_flood_threshold:
                anomaly_message = f"Anomaly detected: Potential UDP flood attack ({self.protocol_counts[protocol]} UDP packets)"
                self.logger.warning(anomaly_message)
                self.capture_output.append(anomaly_message)
                self.log_anomaly(protocol, packet)
            if protocol in ['ICMP', 'ICMPV6'] and self.protocol_counts[protocol] > self.icmp_flood_threshold:
                anomaly_message = f"Anomaly detected: Potential ICMP flood attack ({self.protocol_counts[protocol]} {protocol} packets)"
                self.logger.warning(anomaly_message)
                self.capture_output.append(anomaly_message)
                self.log_anomaly(protocol, packet)

        except AttributeError as e:
            self.logger.warning(f"Failed to analyze packet due to missing attributes: {e}")

    def log_anomaly(self, protocol, packet):
        try:
            if hasattr(packet, 'ip'):
                source_ip = packet.ip.src
                destination_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                source_ip = packet.ipv6.src
                destination_ip = packet.ipv6.dst
            else:
                source_ip = destination_ip = "N/A"

            anomaly_details = {
                'protocol': protocol,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'packet_count': self.protocol_counts.get(protocol, 0),
                'interface': getattr(self, 'interface_name', 'Unknown')
            }
            self.anomalies.append(anomaly_details)

            AnomalyManagementWidget.log_anomaly(
                protocol,
                source_ip,
                destination_ip,
                self.protocol_counts.get(protocol, 0),
                getattr(self, 'interface_name', 'Unknown')
            )
        except AttributeError as e:
            self.logger.error(f"Error in logging anomaly for packet: {e}. Packet details: {packet}")

    @Slot(str)
    def update_capture_output(self, packet_info):
        self.capture_output.append(packet_info)
        self.logger.debug(f"Capture output updated with packet info: {packet_info}")
