# SOC Log Analyzer Pro

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Desktop App](https://img.shields.io/badge/Platform-Desktop-brightgreen)](#)
[![Security](https://img.shields.io/badge/Domain-Cybersecurity-orange)](#)

## Professional SOC Log Analytics for Authentication Events

SOC Log Analyzer Pro is a polished desktop tool built for security operations teams and cybersecurity analysts. It delivers rapid visibility into authentication traffic, suspicious login behavior, and threat scoring using JSON and XML-based log data.

---

## 🚀 Project Overview

SOC Log Analyzer Pro combines intuitive visualization, export-ready reporting, and IP risk detection to help security practitioners accelerate incident triage and monitoring. The tool is engineered to make log review more efficient, generate professional artifacts, and expose suspicious authentication patterns in a single workflow.

---

## 📸 Screenshots

> Add screenshot images here once available.

- `screenshots/dashboard.png` — Main analysis dashboard
- `screenshots/report-panel.png` — Detailed report view
- `screenshots/export-options.png` — Export and monitoring controls

---

## ✅ Key Features

- File-based log analysis for JSON and XML authentication events
- Failed login aggregation with top attacker source identification
- Success/failure split, unique source counting, and threat severity scoring
- Intelligent suspicious IP detection with a ranked high-risk list
- Timeline plotting for failed login activity and attack trends
- Analyst notes panel for investigation context and triage remarks
- Searchable report view for quick IP lookups
- Multiple export options: TXT, CSV, HTML, and PDF

---

## 🧰 Technologies Used

- Python 3
- Tkinter for desktop UI
- Matplotlib for visualizations
- JSON and XML parsing with built-in Python libraries
- ReportLab for PDF report generation

---

## 🛠 Installation

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd "soc-log-analyzer working"
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

> Note: `reportlab` is required for PDF export. If missing, the app will still run for TXT, CSV, and HTML exports.

---

## ▶️ How to Run

From the project directory, launch the application:

```bash
python log_analyzer_pro.py
```

Then:

1. Click **Browse** to select a JSON or XML log file.
2. Click **Analyze** to generate the dashboard summary.
3. Review the report, charts, and suspicious IP table.
4. Use export buttons to save analyst-ready output.

---

## 📤 Export Features

SOC Log Analyzer Pro supports professional report export options for security workflows:

- **Export TXT** — clean text summary with counts, severity, and notes
- **Export CSV** — structured dataset for analysis and SIEM ingestion
- **Export HTML** — polished browser-ready report with styled tables
- **Export PDF** — formatted executive summary and audit-ready documentation

---

## 📈 Monitoring Features

The application includes built-in monitoring-oriented controls and alerts:

- Threat severity classification based on failed login volume
- High-risk attacker identification for top suspicious IP addresses
- Live timeline visualization for failed login activity
- Summary KPI cards for rapid SOC awareness
- Searchable report text for one-click IP lookup

---

## 🧪 Sample Log Usage

### JSON sample

```json
[
  {"ip": "192.168.1.42", "status": "failed", "timestamp": "2026-05-17T10:15:23"},
  {"ip": "192.168.1.42", "status": "failed", "timestamp": "2026-05-17T10:16:05"},
  {"ip": "192.168.1.100", "status": "success", "timestamp": "2026-05-17T10:18:42"}
]
```

### XML sample

```xml
<Events>
  <Event>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-05-17T10:15:23" />
    <Data Name="IpAddress">192.168.1.42</Data>
  </Event>
  <Event>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-05-17T10:18:42" />
    <Data Name="IpAddress">192.168.1.100</Data>
  </Event>
</Events>
```

---

## 🔮 Future Improvements

Potential roadmap enhancements for SOC Log Analyzer Pro:

- Add support for additional log formats (CSV, syslog, CEF, JSONL)
- Add real-time socket or file-watch ingestion
- Add richer analytics with anomaly detection and rate-based alerting
- Add user-configurable severity thresholds and custom risk policies
- Add export templates for SOC playbooks and incident reports

---

## 💼 Resume / Project Value

SOC Log Analyzer Pro is a strong portfolio project for cybersecurity and SOC roles. It demonstrates:

- practical log parsing and threat detection skills
- security-focused UI/UX design for analyst workflows
- report generation and export automation
- proficiency with Python, data visualization, and incident triage tooling

Use this project to highlight your ability to build analyst-ready security utilities that bridge log data and investigative outcomes.

---

## 🛡 Cybersecurity Relevance

This tool is relevant for threat detection, incident response, and SOC monitoring because it:

- identifies suspicious authentication behavior from raw logs
- surfaces attacker IPs and failed login trends
- supports rapid escalation with formatted evidence exports
- improves situational awareness for security operations teams

---

## 📌 License

Add your preferred open-source license here.
