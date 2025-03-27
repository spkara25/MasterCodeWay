# MasterCodeWay
#Introduction:
CyberGuardian is an advanced cybersecurity tool designed to protect networks from Distributed Denial of Service (DDoS) attacks and other network anomalies. This README provides an overview of the application, its features, and instructions for setup and usage.

#Features
Real-time network traffic monitoring

DDoS attack detection and prevention

Network anomaly detection

Interactive GUI dashboard

SIEM (Security Information and Event Management) integration

Packet sniffing and analysis

Customizable IP whitelisting and blacklisting

Export capabilities for alerts and anomalies


#Requirements
1.)Python 3.7+

2.)PyQt5

3.)FastAPI

4.)Scapy

5.)pandas

6.)scikit-learn

7.)matplotlib

8.)websockets

9.)uvicorn


#Installation
1.)Clone the repository:


2.)Install the required packages:
pip install -r requirements.txt


#Usage
1.)Run the main application:
python cyberguardian.py

2.)Enter the IP address of the target device to monitor when prompted.

3.)The main dashboard will display real-time statistics, alerts, and a graph of risk scores.

4.)Use the buttons at the bottom of the main window to:

Filter attacks

Export alerts

Open the Network Anomaly Monitor

Clear alerts

5.)The SIEM Dashboard tab provides an overview of security events and actions taken.

6.)The Network Anomaly Monitor window shows detailed information about detected network anomalies.


#Configuration
Adjust the WHITELIST and BLACKLIST variables in the code to customize allowed and blocked IP addresses.
Modify the REQUEST_THRESHOLD and PACKET_SIZE_THRESHOLD variables to fine-tune attack detection sensitivity.


#Security Considerations
Ensure that you have the necessary permissions to monitor network traffic on your system.

Use this tool responsibly and in compliance with all applicable laws and regulations.

Regularly update the application and its dependencies to maintain security.


#Contributing
Contributions to CyberGuardian are welcome. Please submit pull requests or open issues on the GitHub repository.

#Disclaimer
This tool is for educational and defensive purposes only. The authors are not responsible for any misuse or damage caused by this program.

#Youtube Link: 
https://youtu.be/-GlinijU4Dw
