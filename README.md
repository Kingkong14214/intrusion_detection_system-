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
```bash
git clone https://github.com/your-username/realtime-ids.git
cd realtime-ids
