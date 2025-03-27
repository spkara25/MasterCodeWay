import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
from datetime import datetime
import time
import threading
from PyQt5 import QtWidgets, QtCore, QtGui, QtMultimedia
import sys
import os
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from collections import defaultdict

# Resource path for PyInstaller
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Network anomaly parsing and detection
def parse_csv_file(csv_path):
    net_act = defaultdict(lambda: {"ips": set(), "loginf": 0, "devices": set(), "last_login": None, "failed_attempts": 0})
    try:
        df = pd.read_csv(csv_path, skipinitialspace=True)
        df.columns = df.columns.str.strip()
        required_columns = ["timestamp", "device", "type", "user", "ip", "status"]
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            raise ValueError(f"Missing columns: {', '.join(missing)}")
        for index, row in df.iterrows():
            try:
                timestamp = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                user = str(row["user"]).strip()
                status = str(row["status"]).strip().capitalize()
                net_act[user]["ips"].add(row["ip"])
                net_act[user]["devices"].add(row["device"])
                net_act[user]["last_login"] = timestamp
                if status == "Failed":
                    net_act[user]["failed_attempts"] += 1
            except Exception as e:
                print(f"Error in row {index + 2}: {e}")
    except Exception as e:
        print(f"Fatal error in parsing network CSV: {e}")
    return net_act

def det_anomalies(activity):
    alerts = []
    for user, data in activity.items():
        if data["failed_attempts"] >= 3:
            alerts.append(f"Suspicious logins: User {user} has {data['failed_attempts']} failed attempts")
        if len(data["ips"]) > 2:
            alerts.append(f"Multiple IPs: User {user} logged in from {len(data['ips'])} IPs")
        if len(data["devices"]) > 3:
            alerts.append(f"Excessive devices: User {user} accessed {len(data['devices'])} devices")
    return alerts

# Intrusion detection initialization
print("Initializing script...")
csv_path = resource_path("cybersecurity_intrusion_data.csv")
df_initial = pd.read_csv(csv_path)
print("Dataset loaded from cybersecurity_intrusion_data.csv...")

X_initial = df_initial[["session_duration", "network_packet_size"]]
model_user = IsolationForest(contamination=0.01, random_state=42)
model_user.fit(X_initial)
print("Isolation Forest trained...")

df_initial["anomaly"] = model_user.predict(X_initial)
decision_scores = model_user.decision_function(X_initial)
df_initial["risk_score"] = (decision_scores - decision_scores.min()) / (decision_scores.max() - decision_scores.min()) * 100
df_initial["risk_score"] += np.where(df_initial["network_packet_size"] > 1000, df_initial["network_packet_size"] // 100, 0)
df_initial["risk_score"] = df_initial["risk_score"].clip(0, 100)
print("Initial risk scores calculated...")
print(f"Max risk score: {df_initial['risk_score'].max()}")

live_data = [(str(datetime.now()), row["session_id"], row["session_duration"], row["network_packet_size"], row["risk_score"], row["attack_detected"]) 
             for i, row in df_initial[df_initial["risk_score"] > 15].iterrows()]
print("Live data initialized with initial anomalies...")
print(f"Initial live_data length: {len(live_data)}")

class CyberGuardianApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberGuardian: Intrusion & Network Monitor")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")

        # Main widget and layout
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QtWidgets.QVBoxLayout(self.central_widget)

        # Title
        title = QtWidgets.QLabel("CyberGuardian: Intrusion & Network Monitor")
        title.setFont(QtGui.QFont("Arial", 18, QtGui.QFont.Bold))
        title.setAlignment(QtCore.Qt.AlignCenter)
        self.layout.addWidget(title)

        # Stats Section
        self.stats_layout = QtWidgets.QHBoxLayout()
        self.total_alerts_label = QtWidgets.QLabel("Total Alerts: 0")
        self.avg_risk_label = QtWidgets.QLabel("Avg Risk Score: 0.0")
        self.attack_rate_label = QtWidgets.QLabel("Attack Rate: 0%")
        self.total_alerts_label.setFont(QtGui.QFont("Arial", 12))
        self.avg_risk_label.setFont(QtGui.QFont("Arial", 12))
        self.attack_rate_label.setFont(QtGui.QFont("Arial", 12))
        self.stats_layout.addWidget(self.total_alerts_label)
        self.stats_layout.addWidget(self.avg_risk_label)
        self.stats_layout.addWidget(self.attack_rate_label)
        self.layout.addLayout(self.stats_layout)

        # Plot
        self.plot_widget = FigureCanvas(Figure(figsize=(5, 3)))
        self.ax = self.plot_widget.figure.add_subplot(111)
        self.ax.set_facecolor("#333333")
        self.plot_widget.figure.set_facecolor("#2b2b2b")
        self.layout.addWidget(self.plot_widget)

        # Intrusion Table
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Session ID", "Duration", "Packet Size", "Risk Score", "Attack"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setStyleSheet("background-color: #333333; color: #ffffff; border: 1px solid #555555;")
        self.layout.addWidget(self.table)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.filter_button = QtWidgets.QPushButton("Show Attacks Only")
        self.filter_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.filter_button.clicked.connect(self.filter_attacks)
        self.export_button = QtWidgets.QPushButton("Export Alerts")
        self.export_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.export_button.clicked.connect(self.export_alerts)
        self.network_button = QtWidgets.QPushButton("Analyze Network Activity")
        self.network_button.setStyleSheet("background-color: #FFC107; color: black;")
        self.network_button.clicked.connect(self.analyze_network)
        self.clear_button = QtWidgets.QPushButton("Clear Alerts")
        self.clear_button.setStyleSheet("background-color: #f44336; color: white;")
        self.clear_button.clicked.connect(self.clear_alerts)
        button_layout.addWidget(self.filter_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.network_button)
        button_layout.addWidget(self.clear_button)
        self.layout.addLayout(button_layout)

        # Alert Feed
        self.alert_feed = QtWidgets.QTextEdit()
        self.alert_feed.setReadOnly(True)
        self.alert_feed.setMaximumHeight(150)
        self.alert_feed.setStyleSheet("background-color: #333333; color: #ffffff; border: 1px solid #555555;")
        self.layout.addWidget(self.alert_feed)

        # Network Analysis Output
        self.network_output = QtWidgets.QTextEdit()
        self.network_output.setReadOnly(True)
        self.network_output.setMaximumHeight(150)
        self.network_output.setStyleSheet("background-color: #333333; color: #ffffff; border: 1px solid #555555;")
        self.layout.addWidget(self.network_output)

        # Sound
        alert_path = resource_path("alert.wav")
        print("Alert sound path:", alert_path)
        self.alert_sound = QtMultimedia.QSoundEffect()
        self.alert_sound.setSource(QtCore.QUrl.fromLocalFile(alert_path))
        print("Sound initialized:", self.alert_sound.isLoaded())

        # Timer
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_ui)
        self.timer.start(1000)

        # Data thread
        self.data_thread = threading.Thread(target=self.generate_data)
        self.data_thread.daemon = True
        self.data_thread.start()
        print("Data thread started...")

        self.show_attacks_only = False

    def generate_data(self):
        global live_data, model_user, df_initial
        print("Starting data simulation from dataset...")
        index = 0
        while True:
            if index >= len(df_initial):
                index = 0
            row = df_initial.iloc[index]
            time_val = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session_id = row["session_id"]
            duration = row["session_duration"]
            packet_size = row["network_packet_size"]
            attack = row["attack_detected"]

            new_log = pd.DataFrame([[duration, packet_size]], columns=["session_duration", "network_packet_size"])
            base_score = model_user.decision_function(new_log)[0]
            risk_score = (base_score - decision_scores.min()) / (decision_scores.max() - decision_scores.min()) * 100
            risk_score += packet_size // 100 if packet_size > 1000 else 0
            risk_score = min(risk_score, 100)

            if risk_score > 15:
                alert = (time_val, session_id, duration, packet_size, risk_score, attack)
                live_data.append(alert)
                print(f"ALERT! Time: {time_val}, ID: {session_id}, Packet Size: {packet_size}, Risk Score: {risk_score}, Attack: {attack}")
                if risk_score > 80:
                    print("Attempting to play sound...")
                    self.alert_sound.play()
                    print("Sound played:", self.alert_sound.isPlaying())

            index += 1
            time.sleep(0.5)

    def update_ui(self):
        global live_data
        total_alerts = len(live_data)
        avg_risk = round(np.mean([row[4] for row in live_data]) if live_data else 0, 2)
        attack_count = sum(1 for row in live_data if row[5] == 1)
        attack_rate = round((attack_count / total_alerts * 100) if total_alerts > 0 else 0, 2)
        self.total_alerts_label.setText(f"Total Alerts: {total_alerts}")
        self.avg_risk_label.setText(f"Avg Risk Score: {avg_risk}")
        self.attack_rate_label.setText(f"Attack Rate: {attack_rate}%")

        risk_scores = [row[4] for row in live_data[-10:]]
        self.ax.clear()
        self.ax.bar(range(len(risk_scores)), risk_scores, color="#FF5733")
        self.ax.set_ylim(0, 100)
        self.ax.set_title("Recent Risk Scores", color="white")
        self.ax.tick_params(colors="white")
        self.plot_widget.draw()

        display_data = [row for row in live_data if not self.show_attacks_only or row[5] == 1][-10:]
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
                    else:
                        item.setForeground(QtGui.QBrush(QtGui.QColor("white")))
                self.table.setItem(row, col, item)

        self.alert_feed.clear()
        for alert in display_data[-5:]:
            self.alert_feed.append(f"{alert[0]} - {alert[1]}: Packet Size {alert[3]}, Risk Score {alert[4]}, Attack: {alert[5]}")

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
            pd.DataFrame(live_data, columns=["Time", "Session ID", "Duration", "Packet Size", "Risk Score", "Attack"]).to_csv(file_name, index=False)
            QtWidgets.QMessageBox.information(self, "Export Success", f"Alerts exported to {file_name}")

    def analyze_network(self):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Network CSV", "", "CSV Files (*.csv)")
        if file_name:
            print(f"Analyzing network activity from {file_name}...")
            net_act = parse_csv_file(file_name)
            anomalies = det_anomalies(net_act)
            self.network_output.clear()
            if anomalies:
                self.network_output.append("Potential network credential compromises detected:")
                for alert in anomalies:
                    self.network_output.append(f"- {alert}")
            else:
                self.network_output.append("No network anomalies detected.")

    def clear_alerts(self):
        global live_data
        live_data.clear()
        print("Alerts cleared...")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CyberGuardianApp()
    window.show()
    sys.exit(app.exec_())
