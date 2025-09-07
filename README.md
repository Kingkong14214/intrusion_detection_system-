# Real-Time Defender IDS

## 📌 Overview
This project is a lightweight real-time intrusion detection system built using Python.  
It monitors live network traffic, detects suspicious activities (e.g., port scans, brute-force attempts, unusual protocols, anauthorised logins),  
and provides alerts through a simple dashboard.

The goal of this IDS is to help learners and security enthusiasts understand how network monitoring  
and anomaly detection work in practice.

---

## 🚀 Features
- 📡 Live Packet Capture – using Scapy for sniffing traffic in real time  
- 🔍 Detection Engine – identifies suspicious patterns (e.g., Nmap scans, SSH logins, hping3 floods, Telnet logins)  
- 📊 Interactive Dashboard – built with Dash/Plotly for real-time visualization  
- 📑 Reporting– export traffic and alerts to CSV, PDF, and other formats  
- 🔔 Notifications– alerts displayed on the dashboard (can be extended to SMS/email)  

---

## 🛠️ Installation
Clone the repo:

git clone https://github.com/Kingkong14214/intrusion_detection_system-

cd intrusion_detection_system-



## Install depedencies
pip install -r requirements.txt

## Run IDS
python defender_ids.py

## Access the Dashboard
http://localhost:8050/

## 📸 Screenshots
Login page

<img width="1298" height="759" alt="githubogin" src="https://github.com/user-attachments/assets/925c7fcd-1ac1-4d5d-bae3-b5a913284157" />

Dynamic graphs and portion of alert box

<img width="1320" height="768" alt="githubfront" src="https://github.com/user-attachments/assets/c91a471e-72f4-4928-a004-4b2ba929fcad" />

## Usage
1.Start the IDS (python defender_ids.py).

2.Open the dashboard in your browser.

3.Authenticate login page using the following credentials(admin/admin123)

3.Monitor real-time traffic and alerts.

4.Export reports for further analysis.

# Future improvements
🤖 AI/ML Capabilities – integrate machine learning models for smarter anomaly detection.

📱 SMS/Email Notifications – send real-time alerts directly to administrators.

☁️ Cloud Support – enable distributed monitoring across multiple servers.

🛡️ Signature + Anomaly Hybrid Detection – combine known attack signatures with anomaly-based detection.

## License
This product is licensed under MIT license






