import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
from datetime import datetime
import time
import threading
import asyncio
import logging
import sqlite3
from fastapi import FastAPI, WebSocket
import sys
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import uvicorn
import websockets
from collections import defaultdict
import requests
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cyberguardian.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberGuardian")

app = FastAPI()
live_data_lock = threading.Lock()
network_anomalies_lock = threading.Lock()

WHITELIST = set(os.environ.get("WHITELIST", "192.168.1.100,192.168.1.101").split(","))
BLACKLIST = set(os.environ.get("BLACKLIST", "192.168.1.200,192.168.1.201").split(","))
TARGET_IP = None
SIEM_DB = "siem_logs.db"
clients = []
request_counts = defaultdict(int)
REQUEST_THRESHOLD = 1
PACKET_SIZE_THRESHOLD = 300
live_data = []
network_anomalies = []
model_user = IsolationForest(contamination=0.01, random_state=42)
attack_active = True  # Flag to track if attack is active

def init_siem_db():
    conn = sqlite3.connect(SIEM_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (timestamp TEXT, ip TEXT, event_type TEXT, request_count INTEGER, action TEXT)''')
    conn.commit()
    conn.close()

def log_siem_event(ip, event_type, request_count, action):
    conn = sqlite3.connect(SIEM_DB)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO events (timestamp, ip, event_type, request_count, action) VALUES (?, ?, ?, ?, ?)",
              (timestamp, ip, event_type, request_count, action))
    conn.commit()
    conn.close()

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

async def quarantine_device(ip):
    global TARGET_IP
    if ip == TARGET_IP:
        logger.info(f"Skipping quarantine for {ip} as it is the target device")
        return
    BLACKLIST.add(ip)
    logger.info(f"Quarantining {ip}")
    log_siem_event(ip, "DDoS Detected", request_counts[ip], "Quarantined")
    os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
    await asyncio.sleep(2)

@app.get("/analyze_request/{ip}")
async def analyze_request(ip: str, packet_size: int = 500):
    global TARGET_IP, attack_active
    if TARGET_IP and ip != TARGET_IP:
        log_siem_event(ip, "Ignored Request", 1, "Ignored")
        return {"status": "Ignored", "message": f"Monitoring only {TARGET_IP}"}
    request_counts[ip] += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_log = pd.DataFrame([[0, packet_size]], columns=["session_duration", "network_packet_size"])
    # Fully random risk score between 0 and 100
    risk_score = random.uniform(0, 100)

    session_duration = random.randint(0, 10)

    if risk_score > 5:
        alert = (timestamp, ip, session_duration, packet_size, risk_score, 1 if risk_score > 10 else 0)
        with live_data_lock:
            live_data.append(alert)
        logger.info(f"Alert generated - IP: {ip}, Duration: {session_duration}, Packet Size: {packet_size}, Risk Score: {risk_score}")

    if packet_size > PACKET_SIZE_THRESHOLD:
        with network_anomalies_lock:
            network_anomalies.append((timestamp, ip, "Large Packet", packet_size))
        logger.info(f"Network Anomaly - Large Packet: {packet_size} from {ip}")

    if request_counts[ip] > REQUEST_THRESHOLD:
        log_siem_event(ip, "DDoS Detected", request_counts[ip], "Detected")
        return {"status": "Detected", "message": f"DDoS detected from {ip}"}
    if ip in BLACKLIST:
        attack_active = False  # Stop attack if IP is blacklisted
        return {"status": "Blocked", "message": f"{ip} is blacklisted"}
    if ip in WHITELIST:
        return {"status": "Allowed", "message": f"{ip} is whitelisted"}
    return {"status": "Processed", "message": f"Request from {ip} processed"}

@app.get("/stop_attack_signal")
async def stop_attack_signal():
    global attack_active
    attack_active = False
    logger.info("Received stop attack signal from attacker.")
    return {"status": "Attack stopped"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except Exception:
        clients.remove(websocket)

async def send_logs():
    while True:
        log_msg = f"Monitoring {TARGET_IP} - Requests: {sum(request_counts.values())}"
        for client in clients:
            await client.send_text(log_msg)
        await asyncio.sleep(1)

dummy_data = pd.DataFrame([[0, 500], [0, 1000]], columns=["session_duration", "network_packet_size"])
model_user.fit(dummy_data)

class ThreatReviewWindow(QtWidgets.QWidget):
    def __init__(self, yellow_alerts, parent):
        super().__init__()
        self.parent = parent  # Reference to CyberGuardianApp to update live_data
        self.setWindowTitle("Threat Review - Yellow Alerts")
        self.setGeometry(300, 300, 800, 600)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

        self.layout = QtWidgets.QVBoxLayout(self)

        title = QtWidgets.QLabel("Review Yellow Alerts (Risk Score 50-80)")
        title.setFont(QtGui.QFont("Arial", 16, QtGui.QFont.Bold))
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("color: #d3d3d3;")
        self.layout.addWidget(title)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Time", "IP", "Duration", "Packet Size", "Risk Score", "Threat", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #000000;
                border: 1px solid #555555;
                padding: 4px;
            }
        """)
        self.layout.addWidget(self.table)

        # Populate table with yellow alerts
        self.yellow_alerts = yellow_alerts
        self.table.setRowCount(0)
        for alert in yellow_alerts:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, data in enumerate(alert[:5]):  # First 5 columns: Time, IP, Duration, Packet Size, Risk Score
                self.table.setItem(row, col, QtWidgets.QTableWidgetItem(str(data)))
            # Add checkbox for Threat column
            checkbox = QtWidgets.QCheckBox()
            checkbox.setStyleSheet("QCheckBox { background-color: #333333; color: #ffffff; }")
            self.table.setCellWidget(row, 5, checkbox)
            # Add Quarantine button for Action column
            quarantine_btn = QtWidgets.QPushButton("Quarantine")
            quarantine_btn.setStyleSheet("background-color: #FF9800; color: white;")
            quarantine_btn.clicked.connect(lambda _, ip=alert[1], row=row: self.quarantine_ip(ip, row))
            self.table.setCellWidget(row, 6, quarantine_btn)

        # Add a "Confirm" button to process ticked/unticked alerts
        self.confirm_button = QtWidgets.QPushButton("Confirm Selections")
        self.confirm_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.confirm_button.clicked.connect(self.confirm_selections)
        self.layout.addWidget(self.confirm_button)

    def quarantine_ip(self, ip, row):
        asyncio.run(quarantine_device(ip))
        QtWidgets.QMessageBox.information(self, "Quarantine Success", f"IP {ip} has been quarantined.")
        # Remove the alert from live_data
        with live_data_lock:
            self.parent.live_data[:] = [alert for alert in self.parent.live_data if alert[1] != ip]
        self.table.removeRow(row)

    def confirm_selections(self):
        global live_data
        rows_to_remove = []
        for row in range(self.table.rowCount()):
            checkbox = self.table.cellWidget(row, 5)
            ip = self.table.item(row, 1).text()
            if checkbox.isChecked():
                # Quarantine if ticked
                asyncio.run(quarantine_device(ip))
                logger.info(f"IP {ip} quarantined based on user selection.")
                rows_to_remove.append(row)
            else:
                # Clear if unticked
                rows_to_remove.append(row)
        # Remove processed alerts from live_data and table
        with live_data_lock:
            for row in sorted(rows_to_remove, reverse=True):
                ip = self.table.item(row, 1).text()
                self.parent.live_data[:] = [alert for alert in self.parent.live_data if alert[1] != ip]
                self.table.removeRow(row)
        QtWidgets.QMessageBox.information(self, "Processing Complete", "Selections have been processed.")

class CyberGuardianApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        global TARGET_IP
        self.setWindowTitle("CyberGuardian: DDoS Defender")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

        init_siem_db()
        ip, ok = QtWidgets.QInputDialog.getText(self, "Target Device", "Enter IP to monitor (e.g., 172.16.46.16):")
        if ok and ip:
            TARGET_IP = ip
        else:
            sys.exit("IP required.")

        self.central_widget = QtWidgets.QTabWidget()
        self.central_widget.setStyleSheet("QTabWidget::pane { border: 1px solid #555555; } QTabBar::tab { background: #333333; color: #000000; padding: 5px; } QTabBar::tab:selected { background: #4CAF50; color: white; }")
        self.setCentralWidget(self.central_widget)

        self.main_widget = QtWidgets.QWidget()
        self.main_layout = QtWidgets.QVBoxLayout(self.main_widget)
        self.central_widget.addTab(self.main_widget, "Main Dashboard")

        title = QtWidgets.QLabel(f"CyberGuardian: DDoS Defender - Monitoring {TARGET_IP}")
        title.setFont(QtGui.QFont("Arial", 18, QtGui.QFont.Bold))
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("color: #d3d3d3;")
        self.main_layout.addWidget(title)

        self.status_label = QtWidgets.QLabel("Status: Server Running")
        self.status_label.setFont(QtGui.QFont("Arial", 12))
        self.status_label.setStyleSheet("color: #4CAF50;")
        self.main_layout.addWidget(self.status_label)

        self.stats_layout = QtWidgets.QHBoxLayout()
        self.total_alerts_label = QtWidgets.QLabel("Total Alerts: 0")
        self.avg_risk_label = QtWidgets.QLabel("Avg Risk Score: 0.0")
        self.attack_rate_label = QtWidgets.QLabel("Attack Rate: 0%")
        self.total_alerts_label.setFont(QtGui.QFont("Arial", 12))
        self.avg_risk_label.setFont(QtGui.QFont("Arial", 12))
        self.attack_rate_label.setFont(QtGui.QFont("Arial", 12))
        self.total_alerts_label.setStyleSheet("color: #d3d3d3;")
        self.avg_risk_label.setStyleSheet("color: #d3d3d3;")
        self.attack_rate_label.setStyleSheet("color: #d3d3d3;")
        self.stats_layout.addWidget(self.total_alerts_label)
        self.stats_layout.addWidget(self.avg_risk_label)
        self.stats_layout.addWidget(self.attack_rate_label)
        self.main_layout.addLayout(self.stats_layout)

        self.plot_widget = FigureCanvas(Figure(figsize=(5, 3)))
        self.ax = self.plot_widget.figure.add_subplot(111)
        self.ax.set_facecolor("#333333")
        self.plot_widget.figure.set_facecolor("#2b2b2b")
        self.main_layout.addWidget(self.plot_widget)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "IP", "Duration", "Packet Size", "Risk Score", "Attack"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #000000;
                border: 1px solid #555555;
                padding: 4px;
            }
        """)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.main_layout.addWidget(self.table)

        button_layout = QtWidgets.QHBoxLayout()
        self.filter_button = QtWidgets.QPushButton("Show Attacks Only")
        self.filter_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.filter_button.clicked.connect(self.filter_attacks)
        self.export_button = QtWidgets.QPushButton("Export Alerts")
        self.export_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.export_button.clicked.connect(self.export_alerts)
        self.network_button = QtWidgets.QPushButton("Network Anomaly Monitor")
        self.network_button.setStyleSheet("background-color: #FFC107; color: black;")
        self.network_button.clicked.connect(self.open_network_monitor)
        self.clear_button = QtWidgets.QPushButton("Clear Alerts")
        self.clear_button.setStyleSheet("background-color: #f44336; color: white;")
        self.clear_button.clicked.connect(self.clear_alerts)
        button_layout.addWidget(self.filter_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.network_button)
        button_layout.addWidget(self.clear_button)
        self.main_layout.addLayout(button_layout)

        self.alert_feed = QtWidgets.QTextEdit()
        self.alert_feed.setReadOnly(True)
        self.alert_feed.setMaximumHeight(150)
        self.alert_feed.setStyleSheet("background-color: #333333; color: #ffffff; border: 1px solid #555555;")
        self.main_layout.addWidget(self.alert_feed)

        self.siem_widget = QtWidgets.QWidget()
        self.siem_layout = QtWidgets.QVBoxLayout(self.siem_widget)
        self.central_widget.addTab(self.siem_widget, "SIEM Dashboard")

        siem_title = QtWidgets.QLabel("SIEM Dashboard")
        siem_title.setFont(QtGui.QFont("Arial", 16, QtGui.QFont.Bold))
        siem_title.setAlignment(QtCore.Qt.AlignCenter)
        siem_title.setStyleSheet("color: #d3d3d3;")
        self.siem_layout.addWidget(siem_title)

        self.siem_stats_layout = QtWidgets.QHBoxLayout()
        self.total_events_label = QtWidgets.QLabel("Total Events: 0")
        self.detected_label = QtWidgets.QLabel("Detected: 0")
        self.quarantined_label = QtWidgets.QLabel("Quarantined: 0")
        self.frequent_ip_label = QtWidgets.QLabel("Most Frequent IP: None")
        self.total_events_label.setFont(QtGui.QFont("Arial", 12))
        self.detected_label.setFont(QtGui.QFont("Arial", 12))
        self.quarantined_label.setFont(QtGui.QFont("Arial", 12))
        self.frequent_ip_label.setFont(QtGui.QFont("Arial", 12))
        self.total_events_label.setStyleSheet("color: #d3d3d3;")
        self.detected_label.setStyleSheet("color: #d3d3d3;")
        self.quarantined_label.setStyleSheet("color: #d3d3d3;")
        self.frequent_ip_label.setStyleSheet("color: #d3d3d3;")
        self.siem_stats_layout.addWidget(self.total_events_label)
        self.siem_stats_layout.addWidget(self.detected_label)
        self.siem_stats_layout.addWidget(self.quarantined_label)
        self.siem_stats_layout.addWidget(self.frequent_ip_label)
        self.siem_layout.addLayout(self.siem_stats_layout)

        self.siem_table = QtWidgets.QTableWidget()
        self.siem_table.setColumnCount(5)
        self.siem_table.setHorizontalHeaderLabels(["Timestamp", "IP", "Event Type", "Request Count", "Action"])
        self.siem_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.siem_table.setStyleSheet("""
            QTableWidget {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #000000;
                border: 1px solid #555555;
                padding: 4px;
            }
        """)
        self.siem_layout.addWidget(self.siem_table)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_ui)
        self.timer.start(1000)

        self.websocket_thread = threading.Thread(target=self.start_websocket_listener, daemon=True)
        self.websocket_thread.start()

        self.last_summary_time = time.time()
        self.minute_alerts = 0
        self.minute_anomalies = 0
        self.show_attacks_only = False
        self.live_data = live_data  # Reference to live_data for ThreatReviewWindow

        self.show()

    def update_ui(self):
        global live_data, network_anomalies, attack_active
        with live_data_lock:
            total_alerts = len(live_data)
            avg_risk = round(np.mean([row[4] for row in live_data]) if live_data else 0, 2)
            attack_count = sum(1 for row in live_data if row[5] == 1)
            attack_rate = round((attack_count / total_alerts * 100) if total_alerts > 0 else 0, 2)
            # Sort live_data by risk score (low to high)
            sorted_data = sorted(live_data, key=lambda x: x[4])
            display_data = [row for row in sorted_data if not self.show_attacks_only or row[5] == 1]

        if attack_active and attack_count > 0:
            self.status_label.setText("Status: Attack Detected")
            self.status_label.setStyleSheet("color: #f44336;")
        elif not attack_active:
            self.status_label.setText("Status: Attack Stopped")
            self.status_label.setStyleSheet("color: #4CAF50;")
            # Process alerts after attack stops
            green_alerts = [alert for alert in live_data if alert[4] <= 50]
            yellow_alerts = [alert for alert in live_data if 50 < alert[4] <= 80]
            red_alerts = [alert for alert in live_data if alert[4] > 80]

            # Clear green alerts
            with live_data_lock:
                live_data[:] = [alert for alert in live_data if alert[4] > 50]

            # Quarantine red alerts
            for alert in red_alerts:
                ip = alert[1]
                asyncio.run(quarantine_device(ip))
                logger.info(f"Automatically quarantined IP {ip} with risk score {alert[4]}")
                with live_data_lock:
                    live_data[:] = [a for a in live_data if a[1] != ip]

            # Open Threat Review window for yellow alerts
            if yellow_alerts and not hasattr(self, 'threat_review_window'):
                self.threat_review_window = ThreatReviewWindow(yellow_alerts, self)
                self.threat_review_window.show()
        else:
            self.status_label.setText("Status: Monitoring")
            self.status_label.setStyleSheet("color: #4CAF50;")

        self.total_alerts_label.setText(f"Total Alerts: {total_alerts}")
        self.avg_risk_label.setText(f"Avg Risk Score: {avg_risk}")
        self.attack_rate_label.setText(f"Attack Rate: {attack_rate}%")

        # Update graph with recent risk scores
        risk_scores = [row[4] for row in display_data[-20:]]  # Show last 20 data points for better trend
        self.ax.clear()
        self.ax.plot(range(len(risk_scores)), risk_scores, color="#FF5733", marker='o', linestyle='-', linewidth=2, markersize=5)
        # Dynamically set y-axis limits based on min and max risk scores
        if risk_scores:
            min_risk = min(risk_scores)
            max_risk = max(risk_scores)
            # Add some padding to the y-axis for better visualization
            padding = (max_risk - min_risk) * 0.1 if max_risk != min_risk else 5
            self.ax.set_ylim(max(0, min_risk - padding), min(100, max_risk + padding))
        else:
            self.ax.set_ylim(0, 100)  # Default range if no data
        self.ax.set_xlim(0, len(risk_scores) - 1 if risk_scores else 1)
        self.ax.set_title("Recent Risk Scores", color="white", fontsize=12)
        self.ax.set_xlabel("Time (Recent Alerts)", color="white", fontsize=10)
        self.ax.set_ylabel("Risk Score", color="white", fontsize=10)
        self.ax.tick_params(colors="white")
        self.ax.grid(True, linestyle='--', alpha=0.7, color="gray")  # Add grid for better readability
        self.plot_widget.draw()

        self.table.setRowCount(0)
        for row_data in display_data:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, data in enumerate(row_data):
                item = QtWidgets.QTableWidgetItem(str(data))
                if col == 4:
                    risk = float(data)
                    if risk > 80:
                        item.setForeground(QtGui.QBrush(QtGui.QColor("red")))
                    elif risk > 50:
                        item.setForeground(QtGui.QBrush(QtGui.QColor("orange")))
                self.table.setItem(row, col, item)

        conn = sqlite3.connect(SIEM_DB)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM events")
        total_events = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM events WHERE event_type = 'DDoS Detected' AND action = 'Detected'")
        detected_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM events WHERE event_type = 'DDoS Detected' AND action = 'Quarantined'")
        quarantined_count = c.fetchone()[0]
        c.execute("SELECT ip, COUNT(*) as count FROM events GROUP BY ip ORDER BY count DESC LIMIT 1")
        frequent_ip_result = c.fetchone()
        frequent_ip = frequent_ip_result[0] if frequent_ip_result else "None"
        c.execute("SELECT timestamp, ip, event_type, request_count, action FROM events ORDER BY timestamp DESC LIMIT 10")
        siem_data = c.fetchall()
        conn.close()

        self.total_events_label.setText(f"Total Events: {total_events}")
        self.detected_label.setText(f"Detected: {detected_count}")
        self.quarantined_label.setText(f"Quarantined: {quarantined_count}")
        self.frequent_ip_label.setText(f"Most Frequent IP: {frequent_ip}")

        self.siem_table.setRowCount(0)
        for row_data in siem_data:
            row = self.siem_table.rowCount()
            self.siem_table.insertRow(row)
            for col, data in enumerate(row_data):
                self.siem_table.setItem(row, col, QtWidgets.QTableWidgetItem(str(data)))

        current_time = time.time()
        if current_time - self.last_summary_time >= 60:
            summary = f"Minute Summary: {self.minute_alerts} alerts, {self.minute_anomalies} anomalies detected"
            logger.info(summary)
            QtCore.QMetaObject.invokeMethod(self.alert_feed, "append", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, summary))
            self.minute_alerts = 0
            self.minute_anomalies = 0
            self.last_summary_time = current_time

    def filter_attacks(self):
        self.show_attacks_only = not self.show_attacks_only
        self.filter_button.setText("Show All" if self.show_attacks_only else "Show Attacks Only")
        self.update_ui()

    def export_alerts(self):
        global live_data
        if not live_data:
            QtWidgets.QMessageBox.warning(self, "Export Failed", "No alerts to export!")
            return
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Alerts", "alerts.csv", "CSV Files (*.csv)")
        if file_name:
            with live_data_lock:
                pd.DataFrame(live_data, columns=["Time", "IP", "Duration", "Packet Size", "Risk Score", "Attack"]).to_csv(file_name, index=False)
            QtWidgets.QMessageBox.information(self, "Export Success", f"Alerts exported to {file_name}")

    def open_network_monitor(self):
        self.network_window = NetworkAnomalyWindow()
        self.network_window.show()

    def clear_alerts(self):
        global live_data
        with live_data_lock:
            live_data.clear()
        logger.info("Alerts cleared")

    def start_websocket_listener(self):
        async def listen():
            uri = "ws://localhost:8000/ws"
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    async with websockets.connect(uri) as websocket:
                        logger.info("WebSocket connected")
                        while True:
                            message = await websocket.recv()
                            QtCore.QMetaObject.invokeMethod(self.alert_feed, "append", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, message))
                except Exception as e:
                    logger.error(f"WebSocket failed: {e}. Retrying in {2 ** attempt} seconds...")
                    time.sleep(2 ** attempt)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(listen())

class NetworkAnomalyWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Anomaly Monitor")
        self.setGeometry(200, 200, 800, 600)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

        self.layout = QtWidgets.QVBoxLayout(self)

        title = QtWidgets.QLabel("Network Anomaly Monitor")
        title.setFont(QtGui.QFont("Arial", 16, QtGui.QFont.Bold))
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("color: #d3d3d3;")
        self.layout.addWidget(title)

        self.stats_label = QtWidgets.QLabel("Total Network Anomalies: 0")
        self.stats_label.setFont(QtGui.QFont("Arial", 12))
        self.stats_label.setStyleSheet("color: #d3d3d3;")
        self.layout.addWidget(self.stats_label)

        self.plot_widget = FigureCanvas(Figure(figsize=(5, 3)))
        self.ax = self.plot_widget.figure.add_subplot(111)
        self.ax.set_facecolor("#333333")
        self.plot_widget.figure.set_facecolor("#2b2b2b")
        self.layout.addWidget(self.plot_widget)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Time", "IP", "Anomaly Type", "Value"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #000000;
                border: 1px solid #555555;
                padding: 4px;
            }
        """)
        self.layout.addWidget(self.table)

        button_layout = QtWidgets.QHBoxLayout()
        self.export_button = QtWidgets.QPushButton("Export Anomalies")
        self.export_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.export_button.clicked.connect(self.export_anomalies)
        self.clear_button = QtWidgets.QPushButton("Clear Anomalies")
        self.clear_button.setStyleSheet("background-color: #f44336; color: white;")
        self.clear_button.clicked.connect(self.clear_anomalies)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.clear_button)
        self.layout.addLayout(button_layout)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_ui)
        self.timer.start(1000)

    def update_ui(self):
        global network_anomalies
        with network_anomalies_lock:
            total_anomalies = len(network_anomalies)
            display_data = network_anomalies[-10:]
        self.stats_label.setText(f"Total Network Anomalies: {total_anomalies}")

        values = [row[3] for row in display_data]
        self.ax.clear()
        self.ax.plot(range(len(values)), values, color="#FF5733", marker='o')
        self.ax.set_title("Recent Network Anomaly Values", color="white")
        self.ax.tick_params(colors="white")
        self.plot_widget.draw()

        self.table.setRowCount(0)
        for row_data in display_data:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, data in enumerate(row_data):
                self.table.setItem(row, col, QtWidgets.QTableWidgetItem(str(data)))

    def export_anomalies(self):
        global network_anomalies
        if not network_anomalies:
            QtWidgets.QMessageBox.warning(self, "Export Failed", "No anomalies to export!")
            return
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Anomalies", "network_anomalies.csv", "CSV Files (*.csv)")
        if file_name:
            with network_anomalies_lock:
                pd.DataFrame(network_anomalies, columns=["Time", "IP", "Anomaly Type", "Value"]).to_csv(file_name, index=False)
            QtWidgets.QMessageBox.information(self, "Export Success", f"Anomalies exported to {file_name}")

    def clear_anomalies(self):
        global network_anomalies
        with network_anomalies_lock:
            network_anomalies.clear()
        logger.info("Network anomalies cleared")

def run_fastapi():
    logger.info("Starting CyberGuardian server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

if __name__ == "__main__":
    fastapi_thread = threading.Thread(target=run_fastapi, daemon=True)
    fastapi_thread.start()
    time.sleep(2)

    qt_app = QtWidgets.QApplication(sys.argv)
    window = CyberGuardianApp()
    sys.exit(qt_app.exec_())
