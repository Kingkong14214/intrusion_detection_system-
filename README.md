# Real-Time Intrusion Detection System (IDS)

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

git clone https://github.com/your-username/realtime-ids.git
cd realtime-ids


## Install depedencies
pip install -r requirements.txt

## Run IDS
python

## Access the Dashboard
http://127.0.0.1:8050/

## 📸 Screenshots
<img width="1366" height="768" alt="loginpage" src="https://github.com/user-attachments/assets/703171b2-84b0-48a0-892d-bdc4af4cc8dd" />

<img width="1366" height="768" alt="Screenshot 2025-06-10 074324" src="https://github.com/user-attachments/assets/d6cc63e0-2e59-493d-9a30-96ad2302c898" />


## Usage
1.Start the IDS (python app.py).
2.Open the dashboard in your browser.
3.Monitor real-time traffic and alerts.
4.Export reports for further analysis.

# Future improvements
🤖 AI/ML Capabilities – integrate machine learning models for smarter anomaly detection.

📱 SMS/Email Notifications – send real-time alerts directly to administrators.

☁️ Cloud Support – enable distributed monitoring across multiple servers.

🛡️ Signature + Anomaly Hybrid Detection – combine known attack signatures with anomaly-based detection.

## License
This product is licensed under MIT license






