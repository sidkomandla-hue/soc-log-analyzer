# 🔐 SOC Log Analyzer Pro

Enterprise-style Security Operations Center (SOC) log analysis and threat detection dashboard built with Python, Flask, and real-time WebSocket streaming.

---

## 🚀 Features

- Real-time live alert dashboard
- Log upload and analysis engine
- Brute-force and suspicious activity detection
- Severity-based alert classification
- Interactive Chart.js analytics
- Search and filter active alerts
- JSON, JSONL, and XML log parsing support
- Dark-mode SOC-style UI

---

## 🧠 Detection Capabilities

- Brute-force attack detection
- Suspicious authentication behavior
- Failed login correlation
- Alert prioritization by severity
- Threat scoring for analyzed datasets

---

## 🏗️ Architecture

Log Upload → Parsing Engine → Detection Engine → Alert Correlation → Dashboard Visualization

---

## ⚙️ Tech Stack

- Python 3.11+
- Flask
- Flask-SocketIO
- Bootstrap 5
- Chart.js
- HTML/CSS/JavaScript
- SQLite (alert persistence)

---

## 📂 Project Structure

```
soc-log-analyzer/
├── app.py
├── templates/
│   └── dashboard.html
├── static/
│   └── socket.io.min.js
├── screenshots/
├── sample_attack_logs.json
└── requirements.txt
```

---

## ▶️ Installation

```powershell
git clone <your-repository-url>
cd soc-log-analyzer
python -m venv .venv
.venv\Scripts\Activate.ps1    # Windows PowerShell
pip install -r requirements.txt
python app.py
```

> If you are using Command Prompt, run `.venv\Scripts\activate.bat` instead.

---

## 🌐 Access the Dashboard

Open the following URL in your browser:

```text
http://127.0.0.1:5000
```

---

## 🛠️ Notes

- The app uses a local Socket.IO client file from `static/socket.io.min.js`.
- Uploaded logs are parsed from JSON, JSON Lines, or XML.
- Alerts are stored in `alerts.db` by default.

---

## 📌 Future Improvements

- MITRE ATT&CK mapping
- Real-time log ingestion
- Elasticsearch / SIEM integration
- Machine learning anomaly detection
- User authentication and role-based access

---

## 👨‍💻 Author

Siddartha Reddy Komandla
Cybersecurity & SOC Enthusiast
