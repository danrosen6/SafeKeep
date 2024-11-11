# File: features/traffic_analysis/traffic_analysis_widget.py

import pyshark
import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QLineEdit
)
from PySide6.QtCore import Signal, Slot
from logs.logger import SafeKeepLogger
from threading import Thread
import os
from config.config_manager import ConfigManager
from collections import defaultdict
from features.traffic_analysis.anomaly_management_widget import AnomalyManagementWidget

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

        # Add the new button for anomaly management settings
        self.open_anomaly_management_button = QPushButton(
            "Anomaly Management Settings", self
        )
        layout.addWidget(self.open_anomaly_management_button)
        self.open_anomaly_management_button.clicked.connect(
            self.open_anomaly_management
        )

        self.start_capture_button.clicked.connect(self.start_capture)
        self.stop_capture_button.clicked.connect(self.stop_capture)
        self.traffic_capture_complete_signal.connect(self.update_capture_output)

        self.capture_thread = None
        self.stop_capture_flag = False
        self.config_manager = ConfigManager()
        self.tshark_path = self.get_tshark_path_from_config()
        self.logger.debug(
            "TrafficAnalyzer initialized with interface selection and default values."
        )

        # Populate available interfaces
        self.populate_interfaces()

        # Initialize anomaly detection data
        self.protocol_counts = defaultdict(int)
        self.load_thresholds()

        # Add dictionary to store anomaly details
        self.anomalies = []

    def open_anomaly_management(self):
        self.anomaly_management_widget = AnomalyManagementWidget()
        self.anomaly_management_widget.thresholds_updated.connect(
            self.reload_thresholds
        )
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
            self.udp_flood_threshold = int(
                self.config_manager.get_config_value('Anomalies', 'udp_threshold')
            )
            self.icmp_flood_threshold = int(
                self.config_manager.get_config_value('Anomalies', 'icmp_threshold')
            )
            self.logger.info("Reloaded thresholds from configuration.")
        except KeyError:
            # Use default values if thresholds are not found in config
            self.udp_flood_threshold = 200
            self.icmp_flood_threshold = 150
            self.logger.warning(
                "Thresholds not found in configuration. Using default values."
            )

    def start_capture(self):
        interface = self.interface_combo.currentText()
        self.interface_name = interface  # Store the selected interface name
        capture_filter = self.capture_filter_input.text()
        self.logger.info(
            f"Starting traffic capture on interface: {interface} with filter: "
            f"{capture_filter if capture_filter else 'None'}."
        )
        self.capture_output.append("Starting packet capture...")
        self.stop_capture_flag = False
        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)

        self.capture_thread = Thread(target=self.capture_traffic, daemon=True)
        self.capture_thread.start()
        self.logger.debug(
            f"Capture thread started for interface: {interface} with filter: {capture_filter}."
        )

    def stop_capture(self):
        self.logger.info("Stopping traffic capture.")
        self.stop_capture_flag = True
        self.logger.debug("Stop capture requested, setting stop flag.")
        self.start_capture_button.setEnabled(True)
        self.stop_capture_button.setEnabled(False)
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()
            self.logger.debug("Capture thread joined successfully.")

        # Display the logged anomalies for review
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
            self.logger.info(f"Using interface: {interface}")
            if capture_filter:
                self.logger.info(f"Using capture filter: {capture_filter}")
            else:
                self.logger.info("No filter set. Capturing all protocols, including UDP.")

            capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=capture_filter if capture_filter else None,
                tshark_path=self.tshark_path
            )
            self.logger.debug(
                f"Initialized LiveCapture with filter: {capture_filter} and interface: {interface}"
            )
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
            loop.stop()
            loop.close()

    def format_packet(self, packet):
        try:
            time = packet.sniff_time
            protocol = packet.highest_layer
            length = packet.length

            # Attempt to extract IP addresses, falling back to other layers if needed
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

            # Extract additional details similar to Wireshark's Info column
            info = []
            if hasattr(packet, 'frame_info'):
                info.append(f"Frame Number: {packet.frame_info.number}")
            if hasattr(packet, 'tcp'):
                info.append(f"TCP Port: {packet.tcp.port}")
                if hasattr(packet.tcp, 'flags'):  # Adding TCP flags for more insight
                    info.append(f"TCP Flags: {packet.tcp.flags.show}")
            if hasattr(packet, 'udp'):
                info.append(f"UDP Port: {packet.udp.port}")
            if hasattr(packet, 'icmp'):
                info.append(f"ICMP Type: {packet.icmp.type}")
            if hasattr(packet, 'ip'):
                info.append(f"TTL: {packet.ip.ttl}")
            elif hasattr(packet, 'ipv6'):
                info.append(f"Hop Limit: {packet.ipv6.hlim}")
            additional_info = ' | '.join(info) if info else 'No additional info'

            summary = f"[{time}] {protocol} - {source} -> {destination} | Length: {length} | Info: {additional_info}"
            self.logger.debug(f"Formatted packet: {summary}")
            return summary
        except AttributeError as e:
            self.logger.warning(f"Failed to format packet due to missing attributes: {e}")
            detailed_info = f"Packet Length: {packet.length} | Layers: {[layer.layer_name for layer in packet.layers]} | Protocols: {packet.frame_info.protocols}"
            self.logger.debug(f"Unknown packet details: {detailed_info}")
            return f"[Unknown Packet Type] - {detailed_info}"

    def analyze_packet(self, packet):
        try:
            protocol = packet.highest_layer
            self.protocol_counts[protocol] += 1

            # Detect UDP flood
            if protocol == 'UDP' and self.protocol_counts[protocol] > self.udp_flood_threshold:
                anomaly_message = f"Anomaly detected: Potential UDP flood attack ({self.protocol_counts[protocol]} UDP packets)"
                self.logger.warning(anomaly_message)
                self.capture_output.append(anomaly_message)
                self.log_anomaly(protocol, packet)
            
            # Detect ICMP flood
            if protocol in ['ICMP', 'ICMPV6'] and self.protocol_counts[protocol] > self.icmp_flood_threshold:
                anomaly_message = f"Anomaly detected: Potential ICMP flood attack ({self.protocol_counts[protocol]} {protocol} packets)"
                self.logger.warning(anomaly_message)
                self.capture_output.append(anomaly_message)
                self.log_anomaly(protocol, packet)

        except AttributeError as e:
            self.logger.warning(f"Failed to analyze packet due to missing attributes: {e}")

    def log_anomaly(self, protocol, packet):
        try:
            # Print available packet layers to debug IPv6 issues
            self.logger.debug(f"Packet layers: {[layer.layer_name for layer in packet.layers]}")

            # Initialize source and destination IPs as N/A
            source_ip = "N/A"
            destination_ip = "N/A"

            # Try extracting IP addresses based on available layers
            if hasattr(packet, 'ip'):
                # IPv4
                source_ip = packet.ip.src
                destination_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                # IPv6
                source_ip = packet.ipv6.src
                destination_ip = packet.ipv6.dst
            else:
                self.logger.warning(f"Unknown packet type for anomaly detection: {packet}")

            # Log detailed information if source or destination IP is missing
            if source_ip == "N/A" or destination_ip == "N/A":
                self.logger.warning(f"Failed to extract IPs for {protocol} packet. Packet details: {packet}")

            # Handle case where interface_name might not be set
            interface_name = getattr(self, 'interface_name', 'Unknown')

            # Add anomaly details to the list
            anomaly_details = {
                'protocol': protocol,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'packet_count': self.protocol_counts.get(protocol, 0),
                'interface': interface_name  # Include interface name
            }
            self.anomalies.append(anomaly_details)

            # Log anomaly to a JSON file
            AnomalyManagementWidget.log_anomaly(
                protocol,
                source_ip,
                destination_ip,
                self.protocol_counts.get(protocol, 0),
                interface_name  # Pass the interface name
            )

        except AttributeError as e:
            self.logger.error(f"Error in logging anomaly for packet: {e}. Packet details: {packet}")

    @Slot(str)
    def update_capture_output(self, packet_info):
        self.capture_output.append(packet_info)
        self.logger.debug(f"Capture output updated with packet info: {packet_info}")
