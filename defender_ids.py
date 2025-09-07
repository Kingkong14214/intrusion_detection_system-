import dash
from dash import html, dcc, Input, Output, State, no_update
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate
import threading
import pandas as pd
import scapy.all as scapy
import plotly.express as px
from datetime import datetime
import subprocess
import json
import os
import bcrypt
from collections import defaultdict
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import io

USER_FILE = "users.json"

# === Load user credentials ===
def load_users():
	if os.path.exists(USER_FILE):
		with open(USER_FILE, "r") as f:
			return json.load(f)
	return {}

# === Global data stores ===
packet_data = []
alert_log = []
lock = threading.Lock()
ssh_attempts = defaultdict(list)
syn_tracker = defaultdict(list)
portscan_tracker = defaultdict(list)
telnet_tracker = defaultdict(list)  # track Telnet attempts

# === Detection engine ===
def detect_threat(packet):
	if packet.haslayer(scapy.IP):
		src = packet[scapy.IP].src
		dst = packet[scapy.IP].dst
		now = datetime.now().strftime('%H:%M:%S')

		if packet.haslayer(scapy.TCP):
			tcp_flags = packet[scapy.TCP].flags
			dport = packet[scapy.TCP].dport
			sport = packet[scapy.TCP].sport

			# Detecting nmap Null scans
			if tcp_flags == 0:
				alert_log.append(f"[{now}] [HIGH] Possible Nmap NULL scan from {src} to {dst}")
			# Detecting nmap XMAS scans
			elif tcp_flags == 0x29:
				alert_log.append(f"[{now}] [HIGH] Possible Nmap XMAS scan from {src} to {dst}")

			# SSH brute-force detection
			if dport == 22:
				alert_log.append(html.Div(f"[{now}] [MEDIUM] SSH connection attempt from {src} to {dst}", style={'color': 'orange'}))
				ssh_attempts[src].append(datetime.now())
				recent = [t for t in ssh_attempts[src] if (datetime.now() - t).seconds < 60]
				if len(recent) > 5:
					alert_log.append(f"[{now}] [HIGH] Possible SSH brute-force from {src} to {dst}")
					ssh_attempts[src] = []

			# SYN Flood detection
			if tcp_flags == 2:
				syn_tracker[src].append(datetime.now())
				recent_syns = [t for t in syn_tracker[src] if (datetime.now() - t).seconds < 10]
				if len(recent_syns) > 20:
					alert_log.append(html.Div(f"[{now}] [HIGH] SYN flood detected from {src} to {dst}", style={'color': 'red'}))
					syn_tracker[src] = []

			# Port scan detection
			portscan_tracker[(src, dst)].append(dport)
			if len(set(portscan_tracker[(src, dst)])) > 10:
				alert_log.append(html.Div(f"[{now}] [MEDIUM] Port scan from {src} to {dst} on multiple ports", style={'color': 'orange'}))
				portscan_tracker[(src, dst)] = []

			# ---- ADDED: Telnet connection attempts / brute-force (TCP/23) ----
			if dport == 23 or sport == 23:
				telnet_tracker[src].append(datetime.now())
				recent_telnet = [t for t in telnet_tracker[src] if (datetime.now() - t).seconds < 10]
				if len(recent_telnet) > 5:
					alert_log.append(html.Div(f"[{now}] [HIGH] Possible Telnet brute-force from {src} to {dst}", style={'color': 'red'}))
					telnet_tracker[src] = []
				else:
					alert_log.append(html.Div(f"[{now}] [MEDIUM] Telnet connection attempt from {src} to {dst}", style={'color': 'orange'}))

		# hping3-style ICMP (large payloads)
		if packet.haslayer(scapy.ICMP):
			if packet[scapy.ICMP].type in [8, 0] and len(packet) > 100:
				alert_log.append(f"[{now}] [HIGH] Large ICMP packet (possible hping3) from {src} to {dst}")

		# Detecting suspicious DNS queries
		if packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport == 53 and len(packet) < 100:
			if not src.startswith("192.168.") and not src.startswith("10.") and not src.startswith("172."):
				alert_log.append(f"[{now}] [MEDIUM] Suspicious DNS query from external IP {src} to {dst}")

		# Detection of suspicious tools + basic SQLi in HTTP payloads (ADDED signatures)
		if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in [80, 443]:
			try:
				payload = packet[scapy.Raw].load.decode(errors='ignore')
				pl = payload.lower()

				# Existing tool detection
				if "curl" in pl or "sqlmap" in pl:
					alert_log.append(f"[{now}] [MEDIUM] Suspicious HTTP tool detected in payload from {src} to {dst}")

				#Basic SQL injection signatures ----
				sql_signatures = [
					" or 1=1", "' or '1'='1", "\" or \"1\"=\"1",
					"union select", "sleep(", "benchmark(",
					"drop table", "information_schema", "load_file(",
					"';--", "\";--", "-- ", "/*", "*/"
				]
				if any(sig in pl for sig in sql_signatures):
					alert_log.append(html.Div(f"[{now}] [HIGH] Possible SQL injection attempt in HTTP payload from {src} to {dst}", style={'color': 'red'}))
			except:
				pass

# === Packet sniffer thread ===
def packet_sniffer():
	def process_packet(packet):
		with lock:
			packet_info = {
				'Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
				'Source IP': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'N/A',
				'Source Port': packet.sport if hasattr(packet, 'sport') else 'N/A',
				'Destination IP': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'N/A',
				'Destination Port': packet.dport if hasattr(packet, 'dport') else 'N/A',
				'Protocol': packet.lastlayer().name,
				'Length': len(packet)
			}
			packet_data.append(packet_info)
			detect_threat(packet)

	scapy.sniff(prn=process_packet, store=False)

threading.Thread(target=packet_sniffer, daemon=True).start()

# === Dash app setup ===
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG], suppress_callback_exceptions=True)
server = app.server

# === Layouts ===
def login_layout():
	return dbc.Container([
		dbc.Row([dbc.Col(html.H2("Login to Defender_IDS Dashboard"))]),
		dbc.Row([dbc.Col([
			dbc.Input(id='login-username', placeholder='Username', type='text', className="mb-2"),
			dbc.Input(id='login-password', placeholder='Password', type='password', className="mb-2"),
			dbc.Button("Login", id='login-button', color='primary'),
			html.Div(id='login-alert', className='mt-2')
		], width=4)])
	], className="mt-4")

def dashboard_layout():
	return dbc.Container([
		dcc.Interval(id="interval-component", interval=5 * 1000, n_intervals=0),
		dbc.Row([
			dbc.Col(html.H2("Defender REAL-TIME IDS"), width=10),
			dbc.Col(dbc.Button("Logout", id="logout-button", color="warning"), width=2)
		]),
		dbc.Row([
			dbc.Col(html.Div(id="alert-box", style={"whiteSpace": "pre-wrap", "color": "orange"}), width=12)
		]),
		dbc.Row([
			dbc.Col(dbc.Button("Export Packet Logs", id="export-button", color="primary"), width="auto"),
			dbc.Col(dcc.Download(id="download-csv"), width="auto"),
			dbc.Col(dbc.Button("Export Alerts", id="export-alerts", color="info"), width="auto"),
			dbc.Col(dcc.Download(id="download-alerts"), width="auto"),
			dbc.Col(dbc.Button("Run Nmap Scan", id="scan-button", color="danger"), width="auto"),
			dbc.Col(dcc.Input(id="target-ip", type="text", placeholder="Target IP"), width="auto"),
			dbc.Col(html.Div(id="nmap-output", style={"whiteSpace": "pre-wrap"}), width=12),
			dbc.Col(dbc.Button("Download Nmap Report", id="download-nmap-btn", color="success"), width="auto"),
			dbc.Col(dcc.Download(id="download-nmap"), width="auto")
		]),
		dbc.Row([
			dbc.Col(dcc.Graph(id="protocol-chart"), width=6),
			dbc.Col(dcc.Graph(id="packet-size-chart"), width=6)
		]),
		dbc.Row([
			dbc.Col(dcc.Graph(id="severity-count-chart"), width=12)
		]),
		dbc.Row([dbc.Col(html.Div(id="live-table"))])
	])

app.layout = html.Div([
	dcc.Location(id='url'),
	dcc.Store(id='nmap-store', data=None),
	dcc.Store(id='session-auth', data=False, storage_type="session"),
	html.Div(id='page-content')
])

@app.callback(Output('page-content', 'children'), Input('session-auth', 'data'))
def route_page(auth):
	return dashboard_layout() if auth else login_layout()

@app.callback(
	Output('session-auth', 'data'),
	Output('login-alert', 'children'),
	Input('login-button', 'n_clicks'),
	State('login-username', 'value'),
	State('login-password', 'value'),
	prevent_initial_call=True
)
def process_login(n_clicks, username, password):
	if not username or not password:
		raise PreventUpdate
	users = load_users()
	if username in users:
		stored_hash = users[username].encode()
		if bcrypt.checkpw(password.encode(), stored_hash):
			return True, ''
	return False, dbc.Alert("Invalid username or password", color="danger")

@app.callback(
	Output('session-auth', 'clear_data'),
	Input('logout-button', 'n_clicks'),
	prevent_initial_call=True
)
def logout(n_clicks):
	if not n_clicks or n_clicks < 1:
		raise PreventUpdate
	return True

@app.callback(
	Output("protocol-chart", "figure"),
	Output("packet-size-chart", "figure"),
	Output("live-table", "children"),
	Input("interval-component", "n_intervals"),
	State("session-auth", "data")
)
def update_dashboard(n, auth):
	if not auth:
		raise PreventUpdate
	with lock:
		df = pd.DataFrame(packet_data[-100:])
	if df.empty:
		raise PreventUpdate
	fig1 = px.histogram(df, x="Protocol", title="Protocol Distribution")
	fig2 = px.line(df, y="Length", title="Packet Size Over Time")
	table = dbc.Table.from_dataframe(df.tail(10), striped=True, bordered=True, hover=True, class_name="table-dark")
	return fig1, fig2, table

@app.callback(
	Output("severity-count-chart", "figure"),
	Input("interval-component", "n_intervals")
)
def update_severity_chart(n):
	if not alert_log:
		raise PreventUpdate

	levels = ["LOW", "MEDIUM", "HIGH"]
	counts = {lvl: 0 for lvl in levels}

	def extract_text(alert):
		if isinstance(alert, str):
			return alert
		elif hasattr(alert, "children"):
			if isinstance(alert.children, list):
				return "".join(str(c) for c in alert.children)
			return str(alert.children)
		return str(alert)

	for alert in alert_log[-100:]:
		text = extract_text(alert)
		for lvl in levels:
			if f"[{lvl}]" in text:
				counts[lvl] += 1

	df = pd.DataFrame({
		"Severity": list(counts.keys()),
		"Count": list(counts.values())
	})

	return px.bar(
		df,
		x="Severity",
		y="Count",
		title="Alert Severity Counts",
		color="Severity"
	)

@app.callback(
	Output("alert-box", "children"),
	Input("interval-component", "n_intervals")
)
def update_alerts(n):
	if not alert_log:
		return "No alerts."
	return alert_log

@app.callback(
	Output("download-csv", "data"),
	Input("export-button", "n_clicks"),
	State("session-auth", "data"),
	prevent_initial_call=True
)
def export_csv(n_clicks, auth):
	if not auth:
		raise PreventUpdate
	with lock:
		df = pd.DataFrame(packet_data)
	return dcc.send_data_frame(df.to_csv, filename="packet_logs.csv")

@app.callback(
	Output("download-alerts", "data"),
	Input("export-alerts", "n_clicks"),
	State("session-auth", "data"),
	prevent_initial_call=True
)
def export_alerts(n_clicks, auth):
	if not auth:
		raise PreventUpdate
	with lock:
		if not alert_log:
			raise PreventUpdate

		# Convert alerts to plain text for export
		def extract_text(alert):
			if isinstance(alert, str):
				return alert
			elif hasattr(alert, "children"):
				if isinstance(alert.children, list):
					return "".join(str(c) for c in alert.children)
				return str(alert.children)
			return str(alert)

		cleaned_alerts = [extract_text(a) for a in alert_log]
		df = pd.DataFrame(cleaned_alerts, columns=["Alert"])

	return dcc.send_data_frame(df.to_csv, filename="alert_logs.csv")

@app.callback(
	Output("nmap-output", "children"),
	Output("nmap-store", "data"),
	Input("scan-button", "n_clicks"),
	State("target-ip", "value"),
	State("session-auth", "data"),
	prevent_initial_call=True
)
def run_nmap(n, ip, auth):
	if not auth or not ip:
		raise PreventUpdate
	try:
		result = subprocess.check_output(["nmap", "-F", ip], stderr=subprocess.STDOUT).decode()
		return result, result
	except subprocess.CalledProcessError as e:
		return f"Scan failed: {e.output.decode()}", None

@app.callback(
	Output("download-nmap", "data"),
	Input("download-nmap-btn", "n_clicks"),
	State("nmap-store", "data"),
	prevent_initial_call=True
)
def download_nmap_report(n_clicks, scan_result):
	if not scan_result or scan_result is None:
		raise PreventUpdate

	def generate_pdf(f):
		buffer = io.BytesIO()
		doc = SimpleDocTemplate(buffer)
		styles = getSampleStyleSheet()
		story = [Paragraph("Nmap Scan Report", styles['Heading1'])]
		for line in scan_result.splitlines():
			story.append(Paragraph(line, styles['Normal']))
		doc.build(story)
		buffer.seek(0)
		f.write(buffer.read())  # write into Dash's file object

	return dcc.send_bytes(generate_pdf, "nmap_report.pdf")

if __name__ == '__main__':
	app.run(debug=True)
