# File: features/traffic_analysis/anomaly_management_widget.py

import json
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QSpinBox, QPushButton, QTextEdit
)
from PySide6.QtCore import Signal
from logs.logger import SafeKeepLogger
from config.config_manager import ConfigManager

class AnomalyManagementWidget(QWidget):
    thresholds_updated = Signal()

    def __init__(self):
        super().__init__()
        self.logger = SafeKeepLogger().get_logger()
        self.setWindowTitle("Anomaly Management Settings")
        self.setGeometry(300, 300, 600, 400)

        layout = QVBoxLayout(self)

        # Add threshold options for different protocols
        layout.addWidget(QLabel("Set UDP Flood Threshold:"))
        self.udp_threshold_spinbox = QSpinBox()
        self.udp_threshold_spinbox.setRange(1, 10000)
        self.udp_threshold_spinbox.setValue(200)  # Default value
        layout.addWidget(self.udp_threshold_spinbox)

        layout.addWidget(QLabel("Set ICMP Flood Threshold:"))
        self.icmp_threshold_spinbox = QSpinBox()
        self.icmp_threshold_spinbox.setRange(1, 10000)
        self.icmp_threshold_spinbox.setValue(150)  # Default value
        layout.addWidget(self.icmp_threshold_spinbox)

        # Save button
        self.save_button = QPushButton("Save Thresholds")
        layout.addWidget(self.save_button)

        # Load and review anomalies
        layout.addWidget(QLabel("Anomalies Detected:"))
        self.anomalies_output = QTextEdit()
        self.anomalies_output.setReadOnly(True)
        layout.addWidget(self.anomalies_output)

        self.load_anomalies_button = QPushButton("Load Anomalies")
        layout.addWidget(self.load_anomalies_button)

        # Connect the buttons to actions
        self.save_button.clicked.connect(self.save_thresholds)
        self.load_anomalies_button.clicked.connect(self.load_anomalies)

        # Load thresholds from config if available
        self.config_manager = ConfigManager()
        self.load_thresholds()

    def save_thresholds(self):
        udp_threshold = self.udp_threshold_spinbox.value()
        icmp_threshold = self.icmp_threshold_spinbox.value()

        # Save thresholds using ConfigManager
        self.config_manager.set_config_value(
            'Anomalies', 'udp_threshold', str(udp_threshold)
        )
        self.config_manager.set_config_value(
            'Anomalies', 'icmp_threshold', str(icmp_threshold)
        )

        self.logger.info(f"Saved thresholds - UDP: {udp_threshold}, ICMP: {icmp_threshold}")

        # Emit the thresholds_updated signal
        self.thresholds_updated.emit()

    def load_thresholds(self):
        try:
            udp_threshold = int(
                self.config_manager.get_config_value('Anomalies', 'udp_threshold')
            )
            icmp_threshold = int(
                self.config_manager.get_config_value('Anomalies', 'icmp_threshold')
            )

            self.udp_threshold_spinbox.setValue(udp_threshold)
            self.icmp_threshold_spinbox.setValue(icmp_threshold)

            self.logger.info("Loaded thresholds from configuration.")
        except KeyError:
            self.logger.warning("Thresholds not found in configuration. Using default values.")

    def load_anomalies(self):
        anomalies_file = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'anomalies.json')
        if os.path.exists(anomalies_file):
            with open(anomalies_file, 'r') as f:
                anomalies = json.load(f)
                self.anomalies_output.clear()
                for anomaly in anomalies:
                    anomaly_text = (
                        f"Protocol: {anomaly['protocol']}, Source IP: {anomaly['source_ip']}, "
                        f"Destination IP: {anomaly['destination_ip']}, Packet Count: {anomaly['packet_count']}, "
                        f"Interface: {anomaly['interface']}"
                    )
                    self.anomalies_output.append(anomaly_text)
        else:
            self.logger.warning("No anomalies file found.")
            self.anomalies_output.setText("No anomalies detected.")

    @staticmethod
    def log_anomaly(protocol, source_ip, destination_ip, packet_count, interface):
        anomalies_file = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'anomalies.json')
        anomalies = []
        if os.path.exists(anomalies_file):
            with open(anomalies_file, 'r') as f:
                anomalies = json.load(f)

        anomalies.append({
            'protocol': protocol,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'packet_count': packet_count,
            'interface': interface  # Include interface in the anomaly log
        })

        with open(anomalies_file, 'w') as f:
            json.dump(anomalies, f, indent=4)

        SafeKeepLogger().get_logger().info(
            f"Logged anomaly - Protocol: {protocol}, Source IP: {source_ip}, "
            f"Destination IP: {destination_ip}, Packet Count: {packet_count}, Interface: {interface}"
        )
