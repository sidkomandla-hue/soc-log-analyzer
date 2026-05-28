from flask import Flask, render_template, request
import json
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

app = Flask(__name__)


# LOAD LOGS

def load_logs(filepath):

    with open(filepath, "r") as file:
        return json.load(file)
    
def find_child_by_name(parent, name):
    for child in parent:
        if child.tag.split("}")[-1] == name:
            return child
    return None


def findall_by_name(root, name):
    return [element for element in root.iter() if element.tag.split("}")[-1] == name]


def parse_event_element(event_el):
    event = {}

    for child in event_el.iter():
        tag = child.tag.split("}")[-1]

        if tag == "EventID" and child.text:
            event["event_id"] = child.text.strip()
        elif tag == "TimeCreated":
            event["timestamp"] = child.attrib.get("SystemTime") or child.text
        elif tag == "Data":
            name = (child.attrib.get("Name") or "").lower()
            value = child.text

            if name in ("ipaddress", "ip", "sourceip", "clientip"):
                event["ip"] = value
            elif name in ("user", "username", "targetusername", "subjectusername", "account"):
                event["user"] = value
            elif name in ("status", "result", "outcome", "event", "event_type", "action"):
                event["status"] = value
            elif name in ("eventid", "event_id"):
                event["event_id"] = value

    return event


def parse_xml_logs(root):
    events = []

    if root.tag.split("}")[-1] == "Event":
        events.append(parse_event_element(root))
    else:
        for event_el in findall_by_name(root, "Event"):
            events.append(parse_event_element(event_el))

    return events


def parse_uploaded_logs(uploaded_file):
    uploaded_file.seek(0)
    raw = uploaded_file.read()
    text = raw.decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)

    if not text.strip():
        return []

    try:
        logs = json.loads(text)
    except json.JSONDecodeError:
        logs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if logs:
            return logs

        try:
            root = ET.fromstring(text)
            return parse_xml_logs(root)
        except ET.ParseError:
            return []

    if isinstance(logs, dict):
        for key in ("events", "Events", "records", "Records", "logs", "Logs"):
            if key in logs and isinstance(logs[key], list):
                return logs[key]
        return [logs]

    return logs


ALERT_DB_PATH = "alerts.db"
POWERSHELL_KEYWORDS = [
    "powershell", "invoke-expression", "iex", "downloadstring", "bypass",
    "-nop", "-w hidden", "encodedcommand", "cmd.exe", "bitsadmin",
    "certutil", "Invoke-Command", "Start-Process", "New-Object System.Net.WebClient"
]
BRUTE_FORCE_HIGH = 5
BRUTE_FORCE_MEDIUM = 3
EXCESSIVE_AUTH_HIGH = 10
EXCESSIVE_AUTH_MEDIUM = 6
PORT_SCAN_HIGH = 10
PORT_SCAN_MEDIUM = 6


def parse_timestamp(value):
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def format_timestamp(value):
    parsed = parse_timestamp(value)
    if parsed:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Alert:
    title: str
    severity: str
    ip: str
    timestamp: str
    rule: str
    type: str
    user: str = "unknown"
    attempts: int = 0
    raw_message: str = ""

    def to_row(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "ip": self.ip,
            "timestamp": self.timestamp,
            "rule": self.rule,
            "type": self.type,
            "user": self.user,
            "attempts": self.attempts,
            "raw_message": self.raw_message,
        }


class AlertStore:
    def __init__(self, db_path=ALERT_DB_PATH):
        self.db_path = db_path
        self._initialize()

    def _initialize(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    timestamp TEXT,
                    rule TEXT,
                    alert_type TEXT,
                    user TEXT,
                    attempts INTEGER,
                    message TEXT,
                    created_at TEXT
                )
                """
            )
            conn.commit()

    def save_alerts(self, alerts):
        if not alerts:
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO alerts (title, severity, source_ip, timestamp, rule, alert_type, user, attempts, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        alert.title,
                        alert.severity,
                        alert.ip,
                        alert.timestamp,
                        alert.rule,
                        alert.type,
                        alert.user,
                        alert.attempts,
                        alert.raw_message,
                        datetime.now(timezone.utc).isoformat(),
                    )
                    for alert in alerts
                ],
            )
            conn.commit()

    def fetch_recent(self, limit=50):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT title, severity, source_ip AS ip, timestamp, rule, alert_type AS type, user, attempts, message FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


class DetectionRule:
    def __init__(self, name):
        self.name = name

    def apply(self, logs):
        return []


class BruteForceRule(DetectionRule):
    def __init__(self):
        super().__init__("Brute Force Detection")

    def apply(self, logs):
        failed_by_key = defaultdict(int)
        latest_timestamp = {}

        for log in logs:
            if log.get("status") != "failed":
                continue

            ip = log.get("ip", "unknown")
            user = log.get("user", "unknown")
            key = (ip, user)
            failed_by_key[key] += 1
            ts = parse_timestamp(log.get("timestamp"))
            if ts and (key not in latest_timestamp or ts > latest_timestamp[key]):
                latest_timestamp[key] = ts

        alerts = []
        for (ip, user), count in failed_by_key.items():
            severity = "HIGH" if count >= BRUTE_FORCE_HIGH else "MEDIUM" if count >= BRUTE_FORCE_MEDIUM else None
            if not severity:
                continue

            title = "Brute Force Attack" if count >= BRUTE_FORCE_HIGH else "Suspicious Login Activity"
            alerts.append(
                Alert(
                    title=title,
                    severity=severity,
                    ip=ip,
                    timestamp=format_timestamp(latest_timestamp.get((ip, user))),
                    rule=self.name,
                    type="Brute Force",
                    user=user,
                    attempts=count,
                    raw_message=f"Detected {count} failed login attempts from {ip}.",
                ).to_row()
            )

        return alerts


class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__("Port Scan Detection")

    def _extract_port(self, log):
        for key in ("destination_port", "dst_port", "dport", "port", "target_port", "remote_port"):
            value = log.get(key)
            if value:
                try:
                    return int(value)
                except (ValueError, TypeError):
                    continue
        return None

    def apply(self, logs):
        ports_by_ip = defaultdict(set)
        latest_timestamp = {}

        for log in logs:
            ip = log.get("ip", "unknown")
            port = self._extract_port(log)
            if port is None:
                continue

            ports_by_ip[ip].add(port)
            ts = parse_timestamp(log.get("timestamp"))
            if ts and (ip not in latest_timestamp or ts > latest_timestamp[ip]):
                latest_timestamp[ip] = ts

        alerts = []
        for ip, ports in ports_by_ip.items():
            count = len(ports)
            if count >= PORT_SCAN_HIGH:
                severity = "HIGH"
            elif count >= PORT_SCAN_MEDIUM:
                severity = "MEDIUM"
            else:
                continue

            alerts.append(
                Alert(
                    title="Port Scan Detected",
                    severity=severity,
                    ip=ip,
                    timestamp=format_timestamp(latest_timestamp.get(ip)),
                    rule=self.name,
                    type="Port Scan",
                    user="unknown",
                    attempts=count,
                    raw_message=f"Source scanned {count} unique ports.",
                ).to_row()
            )

        return alerts


class SuspiciousPowerShellRule(DetectionRule):
    def __init__(self):
        super().__init__("PowerShell Command Detection")

    def apply(self, logs):
        suspects = defaultdict(lambda: {"matches": [], "timestamps": []})

        for log in logs:
            ip = log.get("ip", "unknown")
            user = log.get("user", "unknown")
            text = " ".join(
                str(log.get(k, "")) for k in ("command", "message", "details", "script", "event_description", "raw_entry")
            ).lower()
            if not text:
                continue

            found = [kw for kw in POWERSHELL_KEYWORDS if kw in text]
            if not found:
                continue

            key = (ip, user)
            suspects[key]["matches"].extend(found)
            ts = parse_timestamp(log.get("timestamp"))
            if ts:
                suspects[key]["timestamps"].append(ts)

        alerts = []
        for (ip, user), details in suspects.items():
            count = len(details["matches"])
            severity = "CRITICAL" if any(k in ["invoke-expression", "encodedcommand", "downloadstring", "bypass"] for k in details["matches"]) else "HIGH"
            alerts.append(
                Alert(
                    title="Suspicious PowerShell Activity",
                    severity=severity,
                    ip=ip,
                    timestamp=format_timestamp(max(details["timestamps"]) if details["timestamps"] else None),
                    rule=self.name,
                    type="PowerShell Execution",
                    user=user,
                    attempts=count,
                    raw_message=f"Detected PowerShell keywords: {', '.join(sorted(set(details['matches'])))}.",
                ).to_row()
            )

        return alerts


class ExcessiveFailedAuthRule(DetectionRule):
    def __init__(self):
        super().__init__("Failed Authentication Detection")

    def apply(self, logs):
        failed_by_ip = defaultdict(int)
        latest_timestamp = {}

        for log in logs:
            if log.get("status") != "failed":
                continue

            ip = log.get("ip", "unknown")
            failed_by_ip[ip] += 1
            ts = parse_timestamp(log.get("timestamp"))
            if ts and (ip not in latest_timestamp or ts > latest_timestamp[ip]):
                latest_timestamp[ip] = ts

        alerts = []
        for ip, count in failed_by_ip.items():
            if count >= EXCESSIVE_AUTH_HIGH:
                severity = "CRITICAL"
                title = "Excessive Failed Authentication"
            elif count >= EXCESSIVE_AUTH_MEDIUM:
                severity = "HIGH"
                title = "Repeated Failed Logins"
            else:
                continue

            alerts.append(
                Alert(
                    title=title,
                    severity=severity,
                    ip=ip,
                    timestamp=format_timestamp(latest_timestamp.get(ip)),
                    rule=self.name,
                    type="Failed Authentication",
                    user="unknown",
                    attempts=count,
                    raw_message=f"Detected {count} failed authentication attempts from {ip}.",
                ).to_row()
            )

        return alerts


class DetectionEngine:
    def __init__(self, rules):
        self.rules = rules

    def run(self, logs):
        normalized_logs = [normalize_log_entry(entry) for entry in logs if isinstance(entry, dict)]
        alerts = []
        for rule in self.rules:
            alerts.extend(rule.apply(normalized_logs))
        return sorted(alerts, key=lambda item: (item["severity"], item["timestamp"]), reverse=True)


alert_store = AlertStore()
engine = DetectionEngine([
    BruteForceRule(),
    PortScanRule(),
    SuspiciousPowerShellRule(),
    ExcessiveFailedAuthRule(),
])


def normalize_log_entry(entry):
    if not isinstance(entry, dict):
        return {"ip": "unknown", "user": "unknown", "status": "", "event_id": None}

    normalized = {}

    for name in (
        "ip", "ip_address", "source_ip", "src_ip", "client_ip",
        "IpAddress", "ClientIP"
    ):
        if entry.get(name):
            normalized["ip"] = entry.get(name)
            break

    for name in (
        "user", "username", "account",
        "TargetUserName", "SubjectUserName"
    ):
        if entry.get(name):
            normalized["user"] = entry.get(name)
            break

    status = None
    for name in (
        "status", "result", "outcome",
        "event", "event_type", "action"
    ):
        value = entry.get(name)
        if value:
            status = str(value).strip().lower()
            break

    if not status:
        for name in ("message", "msg", "description", "event_description"):
            value = entry.get(name)
            if not value:
                continue
            lower = str(value).lower()
            if "failed" in lower or "denied" in lower or "unauthorized" in lower:
                status = "failed"
                break
            if "success" in lower or "successful" in lower:
                status = "success"
                break

    event_id = entry.get("event_id") or entry.get("EventID") or entry.get("eventid")
    if event_id is not None and not status:
        event_id = str(event_id).strip()
        if event_id == "4625":
            status = "failed"
        elif event_id == "4624":
            status = "success"

    normalized["timestamp"] = (
        entry.get("timestamp")
        or entry.get("time")
        or entry.get("TimeCreated")
        or entry.get("SystemTime")
        or entry.get("event_time")
        or entry.get("date")
    )
    normalized["command_text"] = (
        entry.get("command")
        or entry.get("message")
        or entry.get("details")
        or entry.get("script")
        or entry.get("event_description")
        or ""
    )
    normalized["raw_entry"] = entry

    normalized["ip"] = normalized.get("ip", "unknown")
    normalized["user"] = normalized.get("user", "unknown")
    normalized["status"] = status or ""
    if event_id is not None:
        normalized["event_id"] = event_id

    return normalized


# DASHBOARD ROUTE

@app.route("/", methods=["GET", "POST"])

def dashboard():

    alerts = []

    upload_error = None

    if request.method == "POST":

        uploaded_file = request.files.get("logfile")

        if uploaded_file and uploaded_file.filename:
            uploaded_file.seek(0)
            logs = parse_uploaded_logs(uploaded_file)

            if not logs:
                upload_error = (
                    "Unable to parse the uploaded log file. "
                    "Supported file formats are JSON array, JSON Lines, or XML event data."
                )
                analysis_done = False
            else:
                alerts = engine.run(logs)
                alert_store.save_alerts([Alert(**alert) for alert in alerts])
                analysis_done = True

        else:
            alerts = []
            analysis_done = False

    else:
        alerts = []
        analysis_done = False


    # STATISTICS

    high_count = sum(
        1 for a in alerts if a["severity"] == "HIGH"
    )

    medium_count = sum(
        1 for a in alerts if a["severity"] == "MEDIUM"
    )

    low_count = sum(
        1 for a in alerts if a["severity"] == "LOW"
    )

    ip_counts = Counter(a.get("ip", "unknown") for a in alerts)
    user_counts = Counter(a.get("user", "unknown") for a in alerts)
    attack_counts = Counter(a.get("type", "unknown") for a in alerts)

    top_ip, top_ip_count = ip_counts.most_common(1)[0] if ip_counts else ("n/a", 0)
    top_user, top_user_alerts = user_counts.most_common(1)[0] if user_counts else ("n/a", 0)
    top_attack = attack_counts.most_common(1)[0][0] if attack_counts else "n/a"

    return render_template(

        "dashboard.html",

        alerts=alerts,

        total_alerts=len(alerts),

        high_alerts=high_count,

        medium_alerts=medium_count,

        low_alerts=low_count,

        suspicious_ips=len(
            set(a["ip"] for a in alerts)
        ),

        top_ip=top_ip,
        top_ip_count=top_ip_count,
        top_user=top_user,
        top_user_alerts=top_user_alerts,
        top_attack=top_attack,
        upload_error=upload_error,
        analysis_done=analysis_done

    )


if __name__ == "__main__":

    app.run(debug=True)