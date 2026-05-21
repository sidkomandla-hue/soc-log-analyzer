from flask import Flask, render_template, request
import json
import os
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter

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

    normalized["ip"] = normalized.get("ip", "unknown")
    normalized["user"] = normalized.get("user", "unknown")
    normalized["status"] = status or ""
    if event_id is not None:
        normalized["event_id"] = event_id

    return normalized


# DETECTION ENGINE

def detect_bruteforce(logs):

    failed_attempts = defaultdict(int)

    alerts = []

    for raw_log in logs:

        if not isinstance(raw_log, dict):
            continue

        log = normalize_log_entry(raw_log)
        status = log.get("status", "")

        if status == "failed":

            ip = log.get("ip", "unknown")
            user = log.get("user", "unknown")

            key = (ip, user)

            failed_attempts[key] += 1


    for (ip, user), count in failed_attempts.items():

        if count >= 5:

            alerts.append({

                "severity": "HIGH",
                "type": "Brute Force Attack",
                "ip": ip,
                "user": user,
                "attempts": count

            })

        elif count >= 3:

            alerts.append({

                "severity": "MEDIUM",
                "type": "Suspicious Login Activity",
                "ip": ip,
                "user": user,
                "attempts": count

            })


    return alerts


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

            alerts = detect_bruteforce(logs)
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