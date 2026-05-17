import html
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont
import csv
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

print("APP STARTING...")
APP_VERSION = "v1.2"
APP_LOGO = "🛡️"
THREAT_SEVERITY = [
    (2, "LOW", "#7fffd4"),
    (5, "MEDIUM", "#25d1ff"),
    (9, "HIGH", "#ffba00"),
    (float('inf'), "CRITICAL", "#ff5a6d"),
]

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    reportlab_available = True
except ImportError:
    reportlab_available = False

THRESHOLD = 5

# UI Theme
BG_COLOR = "#07101a"
PANEL_BG = "#101b26"
CARD_BG = "#152033"
INPUT_BG = "#142337"
TEXT_COLOR = "#e9f1ff"
SUBTEXT_COLOR = "#8aa4cf"
ACCENT = "#4bc3ff"
WARN_COLOR = "#ff7b82"
DANGER_COLOR = "#ffb86c"
BORDER_COLOR = "#223050"

PRIMARY_FONT = "Segoe UI"
PRIMARY_SEMIBOLD_FONT = "Segoe UI Semibold"
MONO_FONT = ("Cascadia Code", 11)

TITLE_FONT = (PRIMARY_SEMIBOLD_FONT, 22)
SUBTITLE_FONT = (PRIMARY_FONT, 12)
BODY_FONT = (PRIMARY_FONT, 11)
CARD_TITLE_FONT = (PRIMARY_FONT, 10)
CARD_VALUE_FONT = (PRIMARY_SEMIBOLD_FONT, 26)
BUTTON_FONT = (PRIMARY_SEMIBOLD_FONT, 10)
SMALL_FONT = (PRIMARY_FONT, 10)

root = tk.Tk()
root.title("SOC Log Analyzer")
root.geometry("1200x700")
root.configure(bg=BG_COLOR)
root.minsize(1080, 620)

root.update_idletasks()
screen_dpi = root.winfo_fpixels("1i")
scaling = min(max(screen_dpi / 72, 1.0), 2.5)
root.tk.call("tk", "scaling", scaling)
root.option_add("*Font", BODY_FONT)
root.option_add("*Text*font", BODY_FONT)
root.option_add("*Treeview*Font", BODY_FONT)
root.option_add("*Treeview.Heading.Font", CARD_TITLE_FONT)
root.option_add("*Button*font", BUTTON_FONT)

failed_data = {}
success_data = {}
timeline_data = []
suspicious_ips = []
log_status = "Ready"

# =========================
# PARSERS
# =========================
def parse_json(path):
    failed = defaultdict(int)
    success = defaultdict(int)

    with open(path, "r") as f:
        logs = json.load(f)

    for entry in logs:
        ip = entry.get("ip")
        status = entry.get("status")

        if not ip:
            continue

        if status == "failed":
            failed[ip] += 1
        elif status == "success":
            success[ip] += 1

    return failed, success


def parse_xml(path):
    failed = defaultdict(int)
    success = defaultdict(int)

    tree = ET.parse(path)
    root_xml = tree.getroot()

    for event in root_xml.findall(".//Event"):
        event_id = None
        ip = None

        eid = event.find(".//EventID")
        if eid is not None:
            event_id = eid.text

        for data in event.findall(".//Data"):
            if data.attrib.get("Name") == "IpAddress":
                ip = data.text

        if not ip:
            continue

        if event_id == "4625":
            failed[ip] += 1
        elif event_id == "4624":
            success[ip] += 1

    return failed, success


# =========================
# ANALYSIS
# =========================
def analyze_file():
    global failed_data, success_data

    path = entry.get().strip()

    if not path:
        messagebox.showerror("Error", "Select a file")
        return

    try:
        normalized_path = path.lower()
        if normalized_path.endswith(".json"):
            failed, success = parse_json(path)
        elif normalized_path.endswith(".xml"):
            failed, success = parse_xml(path)
        else:
            messagebox.showerror("Error", "Unsupported file")
            return

        failed_data = failed
        success_data = success
        build_timeline_and_suspicious(path)

        generate_report()
        draw_graph()

    except Exception as e:
        messagebox.showerror("Error", str(e))


def get_severity(count):
    for threshold, severity, _ in THREAT_SEVERITY:
        if count <= threshold:
            return severity
    return "UNKNOWN"


def get_severity_color(severity):
    for _, label, color in THREAT_SEVERITY:
        if label == severity:
            return color
    return TEXT_COLOR


def build_timeline_and_suspicious(path):
    global timeline_data, suspicious_ips, log_status
    suspicious_ips = []
    timeline_data = []
    log_status = f"Analyzed: {os.path.basename(path)}"
    try:
        status_label.config(text=log_status)
    except NameError:
        pass

    normalized_path = path.lower()
    if normalized_path.endswith('.json'):
        with open(path, 'r', encoding='utf-8') as f:
            logs = json.load(f)

        events = []
        for entry in logs:
            ip = entry.get('ip')
            status = entry.get('status')
            timestamp = entry.get('timestamp') or entry.get('time')
            if ip and status:
                if timestamp:
                    try:
                        events.append((datetime.fromisoformat(timestamp), status.lower(), ip))
                    except ValueError:
                        pass
                else:
                    events.append((None, status.lower(), ip))

    elif normalized_path.endswith('.xml'):
        tree = ET.parse(path)
        root_xml = tree.getroot()
        events = []

        for event in root_xml.findall('.//Event'):
            ip = None
            status = None
            timestamp = None

            eid = event.find('.//EventID')
            if eid is not None:
                status = 'failed' if eid.text == '4625' else 'success' if eid.text == '4624' else None

            time_node = event.find('.//TimeCreated')
            if time_node is not None:
                timestamp = time_node.attrib.get('SystemTime') or time_node.text

            for data in event.findall('.//Data'):
                if data.attrib.get('Name') == 'IpAddress':
                    ip = data.text

            if ip and status:
                if timestamp:
                    try:
                        events.append((datetime.fromisoformat(timestamp), status, ip))
                    except ValueError:
                        pass
                else:
                    events.append((None, status, ip))
    else:
        events = []

    failed_counts = defaultdict(int)
    last_seen = {}
    time_buckets = defaultdict(int)

    for timestamp, status, ip in events:
        if status == 'failed':
            failed_counts[ip] += 1
            if timestamp:
                bucket = timestamp.replace(minute=0, second=0, microsecond=0)
                time_buckets[bucket] += 1
        if timestamp:
            last_seen[ip] = timestamp.strftime('%Y-%m-%d %H:%M:%S')

    suspicious_ips = []
    for ip, count in sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        severity = get_severity(count)
        suspicious_ips.append({
            'ip': ip,
            'count': count,
            'severity': severity,
            'last_seen': last_seen.get(ip, 'n/a'),
        })

    if time_buckets:
        timeline_data = sorted(time_buckets.items())
    elif failed_counts:
        timeline_data = [(i + 1, count) for i, count in enumerate(sorted(failed_counts.values()))]
    else:
        timeline_data = []


# =========================
# REPORT
# =========================
def generate_report():
    report.delete("1.0", tk.END)

    report.insert(tk.END, "SOC LOG ANALYSIS REPORT\n", "header")
    report.insert(tk.END, "=" * 60 + "\n\n", "section")

    total_failed = sum(failed_data.values())
    total_success = sum(success_data.values())
    highest_severity = get_severity(max(failed_data.values()) if failed_data else 0)
    highest_color = get_severity_color(highest_severity)

    report.insert(tk.END, f"Total Failed Attempts: {total_failed}\n", "normal")
    report.insert(tk.END, f"Total Successful Logins: {total_success}\n", "normal")
    report.insert(tk.END, f"Current Threat Severity: {highest_severity}\n\n", "severity")

    report.insert(tk.END, "FAILED LOGIN ATTEMPTS\n", "section")
    report.insert(tk.END, "-" * 60 + "\n", "section")

    for ip, count in sorted(failed_data.items(), key=lambda x: x[1], reverse=True):
        severity = get_severity(count)
        report.insert(tk.END, f"{ip:<20} {count:<10}", "normal")
        report.insert(tk.END, f" [{severity}]\n", severity.lower())

    report.insert(tk.END, "\nSUCCESSFUL LOGINS\n", "section")
    report.insert(tk.END, "-" * 60 + "\n", "section")

    for ip, count in sorted(success_data.items(), key=lambda x: x[1], reverse=True):
        report.insert(tk.END, f"{ip:<20} {count} logins\n", "normal")

    update_summary_cards()


# =========================
# EXPORT
# =========================
def export_csv():
    if not failed_data and not success_data:
        messagebox.showerror("Export Error", "Analyze a log file before exporting.")
        return

    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Export report to CSV",
    )
    if not path:
        return

    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Category", "IP Address", "Count", "Severity", "Last Seen"])
        writer.writerow(["Totals", "", sum(failed_data.values()), "Failed Attempts", ""])
        writer.writerow(["Totals", "", sum(success_data.values()), "Successful Logins", ""])
        writer.writerow([])
        writer.writerow(["Failed Login Attempts", "", "", "", ""])
        for ip, count in sorted(failed_data.items(), key=lambda x: x[1], reverse=True):
            severity = get_severity(count)
            last_seen = next((item["last_seen"] for item in suspicious_ips if item["ip"] == ip), "n/a")
            writer.writerow(["Failed", ip, count, severity, last_seen])
        writer.writerow([])
        writer.writerow(["Successful Logins", "", "", "", ""])
        for ip, count in sorted(success_data.items(), key=lambda x: x[1], reverse=True):
            writer.writerow(["Success", ip, count, "Logins", ""])

    messagebox.showinfo("Export CSV", f"Report exported successfully to {path}")


def get_analyst_notes():
    return notes_text.get("1.0", tk.END).strip()


def export_txt():
    if not failed_data and not success_data:
        messagebox.showerror("Export Error", "Analyze a log file before exporting.")
        return

    path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt")],
        title="Export report to TXT",
    )
    if not path:
        return

    notes = get_analyst_notes()
    with open(path, "w", encoding="utf-8") as txtfile:
        txtfile.write("SOC LOG ANALYSIS REPORT\n")
        txtfile.write("" + "=" * 60 + "\n\n")
        txtfile.write(f"Total Failed Attempts: {sum(failed_data.values())}\n")
        txtfile.write(f"Total Successful Logins: {sum(success_data.values())}\n")
        txtfile.write(f"Unique IP Addresses: {len({*failed_data.keys(), *success_data.keys()})}\n")
        txtfile.write(f"High-Risk Attackers: {sum(1 for count in failed_data.values() if count >= THRESHOLD)}\n\n")
        txtfile.write("FAILED LOGIN ATTEMPTS\n")
        txtfile.write("" + "-" * 60 + "\n")
        for ip, count in sorted(failed_data.items(), key=lambda x: x[1], reverse=True):
            severity = get_severity(count)
            last_seen = next((item["last_seen"] for item in suspicious_ips if item["ip"] == ip), "n/a")
            txtfile.write(f"{ip:<20} {count:<10} {severity:<10} {last_seen}\n")
        txtfile.write("\nSUCCESSFUL LOGINS\n")
        txtfile.write("" + "-" * 60 + "\n")
        for ip, count in sorted(success_data.items(), key=lambda x: x[1], reverse=True):
            txtfile.write(f"{ip:<20} {count} logins\n")
        txtfile.write("\nANALYST NOTES\n")
        txtfile.write("" + "-" * 60 + "\n")
        txtfile.write(notes + "\n")

    messagebox.showinfo("Export TXT", f"Report exported successfully to {path}")


def export_html():
    if not failed_data and not success_data:
        messagebox.showerror("Export Error", "Analyze a log file before exporting.")
        return

    path = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML files", "*.html")],
        title="Export report to HTML",
    )
    if not path:
        return

    notes = html.escape(get_analyst_notes()).replace("\n", "<br/>")
    high_risk_count = sum(1 for count in failed_data.values() if count >= THRESHOLD)

    html_lines = [
        "<html><head><meta charset='utf-8'><title>SOC Log Analyzer Report</title>",
        "<style>body{background:#0d121b;color:#e7eef7;font-family:Segoe UI,Arial,sans-serif;}",
        ".container{margin:24px;padding:24px;background:#111a26;border:1px solid #293248;border-radius:12px;}",
        "h1{color:#25d1ff;}h2{color:#8fa6c4;margin-top:28px;}table{width:100%;border-collapse:collapse;margin-top:18px;}",
        "th,td{padding:12px 10px;text-align:left;border-bottom:1px solid #293248;}",
        "th{color:#8fa6c4;} tr:nth-child(even){background:#111a26;} .highrisk{color:#ff5a6d;font-weight:700;} pre{white-space:pre-wrap;}",
        "</style></head><body><div class='container'>",
        "<h1>SOC Log Analysis Report</h1>",
        f"<p><strong>Total Failed Attempts:</strong> {sum(failed_data.values())}</p>",
        f"<p><strong>Total Successful Logins:</strong> {sum(success_data.values())}</p>",
        f"<p><strong>Unique IP Addresses:</strong> {len({*failed_data.keys(), *success_data.keys()})}</p>",
        f"<p><strong>High-Risk Attackers:</strong> {high_risk_count}</p>",
        "<h2>Analyst Notes</h2>",
        f"<pre>{notes}</pre>",
        "<h2>Failed Login Attempts</h2>",
        "<table><tr><th>IP Address</th><th>Count</th><th>Risk</th></tr>",
    ]

    for ip, count in sorted(failed_data.items(), key=lambda x: x[1], reverse=True):
        risk = "HIGH RISK" if count >= THRESHOLD else "MEDIUM"
        risk_class = "highrisk" if count >= THRESHOLD else ""
        html_lines.append(f"<tr><td>{ip}</td><td>{count}</td><td class='{risk_class}'>{risk}</td></tr>")

    html_lines.extend([
        "</table>",
        "<h2>Successful Logins</h2>",
        "<table><tr><th>IP Address</th><th>Count</th></tr>",
    ])

    for ip, count in sorted(success_data.items(), key=lambda x: x[1], reverse=True):
        html_lines.append(f"<tr><td>{ip}</td><td>{count}</td></tr>")

    html_lines.extend(["</table>", "</div></body></html>"])

    with open(path, "w", encoding="utf-8") as htmlfile:
        htmlfile.write("\n".join(html_lines))

    messagebox.showinfo("Export HTML", f"Report exported successfully to {path}")


def export_pdf():
    if not reportlab_available:
        messagebox.showerror(
            "Export Error",
            "The reportlab library is not installed. Install reportlab to enable PDF export.",
        )
        return

    if not failed_data and not success_data:
        messagebox.showerror("Export Error", "Analyze a log file before exporting.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suggested_name = f"SOC_Log_Report_{timestamp}.pdf"
    path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Export report to PDF",
        initialfile=suggested_name,
    )
    if not path:
        return

    if not path.lower().endswith(".pdf"):
        path += ".pdf"

    notes_text = get_analyst_notes()
    notes = html.escape(notes_text).replace("\n", "<br/>") if notes_text else "No analyst notes provided."
    report_time = datetime.now().strftime("%B %d, %Y %H:%M:%S")
    high_risk_count = sum(1 for count in failed_data.values() if count >= THRESHOLD)
    threat_level = get_severity(max(failed_data.values()) if failed_data else 0)

    doc = SimpleDocTemplate(
        path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=48,
        bottomMargin=48,
    )
    doc.title = "SOC Log Analyzer Report"
    doc.author = "SOC Log Analyzer"
    doc.subject = "Authentication event log analysis"
    doc.creator = "SOC Log Analyzer"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name="CustomReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=rl_colors.HexColor(ACCENT),
        spaceAfter=10,
    )
    section_style = ParagraphStyle(
        name="CustomSectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=14,
        textColor=rl_colors.white,
        spaceBefore=16,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        name="CustomBodyText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=rl_colors.white,
    )
    small_style = ParagraphStyle(
        name="CustomSmallText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=rl_colors.HexColor("#8aa4cf"),
    )

    summary_data = [
        [Paragraph("<strong>Metric</strong>", body_style), Paragraph("<strong>Value</strong>", body_style)],
        [Paragraph("Total Failed Attempts", body_style), Paragraph(str(sum(failed_data.values())), body_style)],
        [Paragraph("Successful Logins", body_style), Paragraph(str(sum(success_data.values())), body_style)],
        [Paragraph("Unique IP Addresses", body_style), Paragraph(str(len({*failed_data.keys(), *success_data.keys()})), body_style)],
        [Paragraph("Threat Level", body_style), Paragraph(threat_level, body_style)],
        [Paragraph("High-Risk Attackers", body_style), Paragraph(str(high_risk_count), body_style)],
    ]

    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#111a26")),
        ("TEXTCOLOR", (0, 0), (-1, -1), rl_colors.white),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#293248")),
        ("BOX", (0, 0), (-1, -1), 1, rl_colors.HexColor("#293248")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ])

    elements = [
        Paragraph(f"{APP_LOGO} SOC Log Analyzer Report", title_style),
        Paragraph(report_time, small_style),
        Spacer(1, 10),
        Paragraph("Executive Summary", section_style),
        Table(summary_data, colWidths=[240, 200], style=table_style),
        Spacer(1, 16),
        Paragraph("Analyst Notes", section_style),
        Paragraph(notes, body_style),
        Spacer(1, 16),
        Paragraph("Failed Login Attempts", section_style),
    ]

    failed_rows = [
        [
            Paragraph("<strong>IP Address</strong>", body_style),
            Paragraph("<strong>Count</strong>", body_style),
            Paragraph("<strong>Severity</strong>", body_style),
            Paragraph("<strong>Last Seen</strong>", body_style),
        ]
    ]

    for ip, count in sorted(failed_data.items(), key=lambda x: x[1], reverse=True):
        severity = get_severity(count)
        risk_color = get_severity_color(severity)
        failed_rows.append(
            [
                Paragraph(ip, body_style),
                Paragraph(str(count), body_style),
                Paragraph(f"<font color='{risk_color}'>{severity}</font>", body_style),
                Paragraph(next((item["last_seen"] for item in suspicious_ips if item["ip"] == ip), "n/a"), body_style),
            ]
        )

    if len(failed_rows) == 1:
        failed_rows.append([
            Paragraph("No failed login attempts found.", body_style),
            Paragraph("", body_style),
            Paragraph("", body_style),
            Paragraph("", body_style),
        ])

    failed_table = Table(failed_rows, colWidths=[180, 70, 100, 120], style=table_style)
    elements.append(failed_table)
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Successful Logins", section_style))

    success_rows = [
        [
            Paragraph("<strong>IP Address</strong>", body_style),
            Paragraph("<strong>Count</strong>", body_style),
        ]
    ]
    for ip, count in sorted(success_data.items(), key=lambda x: x[1], reverse=True):
        success_rows.append([Paragraph(ip, body_style), Paragraph(str(count), body_style)])
    if len(success_rows) == 1:
        success_rows.append([Paragraph("No successful logins found.", body_style), Paragraph("", body_style)])

    success_table = Table(success_rows, colWidths=[280, 170], style=table_style)
    elements.append(success_table)
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Suspicious IP Detection", section_style))

    if suspicious_ips:
        suspicious_rows = [
            [
                Paragraph("<strong>IP Address</strong>", body_style),
                Paragraph("<strong>Attempts</strong>", body_style),
                Paragraph("<strong>Severity</strong>", body_style),
                Paragraph("<strong>Last Seen</strong>", body_style),
            ]
        ]
        for item in suspicious_ips:
            severity_color = get_severity_color(item["severity"])
            suspicious_rows.append(
                [
                    Paragraph(item["ip"], body_style),
                    Paragraph(str(item["count"]), body_style),
                    Paragraph(f"<font color='{severity_color}'>{item['severity']}</font>", body_style),
                    Paragraph(item["last_seen"], body_style),
                ]
            )
        suspicious_table = Table(suspicious_rows, colWidths=[150, 70, 100, 120], style=table_style)
        elements.append(suspicious_table)
    else:
        elements.append(Paragraph("No suspicious IPs detected.", body_style))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Recommendations", section_style))
    recommendations = [
        "Review high-risk IPs and isolate suspicious sources.",
        "Increase MFA coverage for all authentication endpoints.",
        "Monitor repeated failed login patterns for unusual behavior.",
        "Validate log integrity and ensure time synchronization across systems.",
    ]
    for rec in recommendations:
        elements.append(Paragraph(f"• {html.escape(rec)}", body_style))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"Generated by SOC Log Analyzer {APP_VERSION}", small_style))

    def draw_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(rl_colors.HexColor(BG_COLOR))
        canvas.rect(0, 0, letter[0], letter[1], stroke=False, fill=True)
        canvas.setFillColor(rl_colors.HexColor("#8aa4cf"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 30, f"{APP_LOGO} {APP_VERSION} - SOC Log Analyzer")
        canvas.drawRightString(letter[0] - 40, 30, f"Page {doc.page}")
        canvas.restoreState()

    try:
        doc.build(elements, onFirstPage=draw_background, onLaterPages=draw_background)
        messagebox.showinfo("Export PDF", f"Report exported successfully to {path}")
    except Exception as e:
        messagebox.showerror("Export PDF Error", f"PDF export failed: {e}")


def search_ip():
    search_term = search_entry.get().strip()
    report.tag_remove("highlight", "1.0", tk.END)

    if not search_term:
        messagebox.showinfo("Search", "Enter an IP address to search.")
        return

    match_found = False
    position = "1.0"

    first_match = None
    while True:
        idx = report.search(search_term, position, nocase=False, stopindex=tk.END)
        if not idx:
            break
        end = f"{idx}+{len(search_term)}c"
        report.tag_add("highlight", idx, end)
        if first_match is None:
            first_match = idx
        match_found = True
        position = end

    if match_found:
        report.see(first_match)
        messagebox.showinfo("Search", f"Found matches for {search_term}.")
    else:
        messagebox.showinfo("Search", f"No entries found for {search_term}.")


# =========================
# GRAPH
# =========================
def draw_graph():
    fig.clear()
    fig.patch.set_facecolor(PANEL_BG)

    ax1, ax2 = fig.subplots(2, 1, gridspec_kw={"height_ratios": [1, 1], "hspace": 0.32})
    ax1.set_facecolor(CARD_BG)
    ax2.set_facecolor(CARD_BG)

    ips = list(failed_data.keys())[:10]
    counts = list(failed_data.values())[:10]

    if ips:
        ax1.barh(ips, counts, color=ACCENT, edgecolor="#0f263c", height=0.65)
        ax1.set_title(
            "Top Failed Login Sources",
            color=TEXT_COLOR,
            pad=14,
            fontdict={"family": PRIMARY_FONT, "size": 12, "weight": "bold"},
        )
        ax1.invert_yaxis()
        ax1.xaxis.grid(True, color=BORDER_COLOR, linestyle="--", linewidth=0.7)
        ax1.yaxis.grid(False)
        ax1.tick_params(colors=TEXT_COLOR, labelsize=10)
        ax1.spines["top"].set_visible(False)
        ax1.spines["right"].set_visible(False)
        ax1.spines["left"].set_color(BORDER_COLOR)
        ax1.spines["bottom"].set_color(BORDER_COLOR)
        ax1.set_xlabel(
            "Attempts",
            color=SUBTEXT_COLOR,
            fontdict={"family": PRIMARY_FONT, "size": 10},
        )
        ax1.set_ylabel(
            "Source IP",
            color=SUBTEXT_COLOR,
            fontdict={"family": PRIMARY_FONT, "size": 10},
        )

    if timeline_data:
        x_values, y_values = zip(*timeline_data)
        ax2.plot(x_values, y_values, color=ACCENT, marker="o", linewidth=2.2, markersize=6)
        ax2.fill_between(x_values, y_values, color=ACCENT, alpha=0.15)
        ax2.set_title(
            "Failed Login Activity Timeline",
            color=TEXT_COLOR,
            pad=14,
            fontdict={"family": PRIMARY_FONT, "size": 12, "weight": "bold"},
        )
        if isinstance(x_values[0], datetime):
            ax2.set_xlabel(
                "Time",
                color=SUBTEXT_COLOR,
                fontdict={"family": PRIMARY_FONT, "size": 10},
            )
            fig.autofmt_xdate(rotation=30)
        else:
            ax2.set_xlabel(
                "Event Index",
                color=SUBTEXT_COLOR,
                fontdict={"family": PRIMARY_FONT, "size": 10},
            )

        ax2.xaxis.grid(True, color=BORDER_COLOR, linestyle="--", linewidth=0.7)
        ax2.yaxis.grid(True, color=BORDER_COLOR, linestyle="--", linewidth=0.7)
        ax2.tick_params(colors=TEXT_COLOR, labelsize=10)
        ax2.spines["top"].set_visible(False)
        ax2.spines["right"].set_visible(False)
        ax2.spines["left"].set_color(BORDER_COLOR)
        ax2.spines["bottom"].set_color(BORDER_COLOR)
    else:
        ax2.text(
            0.5,
            0.5,
            "No timeline data available",
            color=SUBTEXT_COLOR,
            ha="center",
            va="center",
            fontsize=10,
            fontfamily=PRIMARY_FONT,
        )
        ax2.set_axis_off()

    canvas.draw()


# =========================
# FILE BROWSER
# =========================
def browse_file():
    path = filedialog.askopenfilename(
        title="Select log file",
        filetypes=[
            ("JSON files", "*.json *.JSON"),
            ("XML files", "*.xml *.XML"),
            ("All files", "*.*"),
        ],
    )

    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


# =========================
# UI
# =========================

def button_hover(event):
    widget = event.widget
    widget.configure(bg="#1c4d85", fg=TEXT_COLOR)


def button_leave(event):
    widget = event.widget
    widget.configure(bg="#172b44", fg=TEXT_COLOR)


def style_button(button):
    button.configure(
        bg="#172b44",
        fg=TEXT_COLOR,
        activebackground="#1b557f",
        activeforeground=TEXT_COLOR,
        bd=0,
        relief=tk.FLAT,
        padx=18,
        pady=10,
        cursor="hand2",
        font=BUTTON_FONT,
        highlightthickness=0,
    )
    button.bind("<Enter>", button_hover)
    button.bind("<Leave>", button_leave)


def on_widget_scroll(widget, event):
    delta = 0
    if hasattr(event, 'delta') and event.delta:
        delta = -1 if event.delta > 0 else 1
    elif event.num == 4:
        delta = -1
    elif event.num == 5:
        delta = 1
    widget.yview_scroll(delta, 'units')
    return 'break'


def create_stat_card(parent, title, value):
    frame = tk.Frame(parent, bg=CARD_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
    frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=6)

    tk.Label(frame, text=title, fg=SUBTEXT_COLOR, bg=CARD_BG, font=CARD_TITLE_FONT).pack(anchor="w", padx=18, pady=(14, 4))
    value_label = tk.Label(frame, text=value, fg=TEXT_COLOR, bg=CARD_BG, font=CARD_VALUE_FONT)
    value_label.pack(anchor="w", padx=18, pady=(0, 16))

    return value_label


def update_summary_cards():
    total_failed = sum(failed_data.values())
    total_success = sum(success_data.values())
    total_sources = len({*failed_data.keys(), *success_data.keys()})
    high_risk_attackers = sum(1 for count in failed_data.values() if count >= THRESHOLD)

    failed_total_label.config(text=str(total_failed))
    success_total_label.config(text=str(total_success))
    unique_sources_label.config(text=str(total_sources))
    high_risk_label.config(text=str(high_risk_attackers))

    if not failed_data and not success_data:
        threat_level_label.config(text="No Data", fg=SUBTEXT_COLOR)
    else:
        threat_level = get_severity(max(failed_data.values()) if failed_data else 0)
        threat_color = get_severity_color(threat_level)
        threat_level_label.config(text=threat_level, fg=threat_color)

    update_suspicious_table()


def update_suspicious_table():
    suspicious_table.delete(*suspicious_table.get_children())
    for item in suspicious_ips:
        tag = item['severity'].lower()
        suspicious_table.insert(
            '',
            tk.END,
            values=(item['ip'], item['count'], item['severity'], item['last_seen']),
            tags=(tag,),
        )
    suspicious_table.tag_configure('CRITICAL'.lower(), background='#2b1016')
    suspicious_table.tag_configure('HIGH'.lower(), background='#2a2213')
    suspicious_table.tag_configure('MEDIUM'.lower(), background='#101d2f')
    suspicious_table.tag_configure('LOW'.lower(), background='#11221b')


# Header
header_frame = tk.Frame(root, bg=BG_COLOR)
header_frame.pack(fill=tk.X, padx=16, pady=(16, 4))

brand_frame = tk.Frame(header_frame, bg=BG_COLOR)
brand_frame.pack(side=tk.LEFT, anchor="w")

brand_label = tk.Label(
    brand_frame,
    text=APP_LOGO,
    fg=ACCENT,
    bg=BG_COLOR,
    font=("Segoe UI Semibold", 30),
)
brand_label.pack(side=tk.LEFT)

label_title = tk.Label(
    brand_frame,
    text="SOC Log Analyzer",
    fg=TEXT_COLOR,
    bg=BG_COLOR,
    font=TITLE_FONT,
)
label_title.pack(side=tk.LEFT, padx=(14, 0), anchor="w")

version_label = tk.Label(
    header_frame,
    text=f"Version {APP_VERSION}",
    fg=SUBTEXT_COLOR,
    bg=BG_COLOR,
    font=("Segoe UI", 9),
)
version_label.pack(side=tk.RIGHT, anchor="e", pady=8)

label_subtitle = tk.Label(
    header_frame,
    text="Premium SOC dashboard for authentication events, suspicious IP detection, and threat scoring.",
    fg=SUBTEXT_COLOR,
    bg=BG_COLOR,
    font=SUBTITLE_FONT,
    wraplength=760,
    justify=tk.LEFT,
)
label_subtitle.pack(side=tk.LEFT, padx=16, pady=8)

# Controls
control_frame = tk.Frame(root, bg=BG_COLOR)
control_frame.pack(fill=tk.X, padx=16, pady=(0, 14))

entry = tk.Entry(
    control_frame,
    font=("Segoe UI", 11),
    bg=INPUT_BG,
    fg=TEXT_COLOR,
    insertbackground=TEXT_COLOR,
    relief=tk.FLAT,
    bd=0,
    width=56,
    highlightthickness=1,
    highlightbackground=BORDER_COLOR,
    highlightcolor=ACCENT,
)
entry.pack(side=tk.LEFT, padx=(0, 8), pady=4, ipady=8)

browse_btn = tk.Button(control_frame, text="Browse", command=browse_file)
style_button(browse_btn)
browse_btn.pack(side=tk.LEFT, padx=(0, 8))

analyze_btn = tk.Button(control_frame, text="Analyze", command=analyze_file)
style_button(analyze_btn)
analyze_btn.pack(side=tk.LEFT, padx=(0, 8))

export_csv_btn = tk.Button(control_frame, text="Export CSV", command=export_csv)
style_button(export_csv_btn)
export_csv_btn.pack(side=tk.LEFT, padx=(0, 8))

export_html_btn = tk.Button(control_frame, text="Export HTML 🌐", command=export_html)
style_button(export_html_btn)
export_html_btn.pack(side=tk.LEFT, padx=(0, 8))

export_txt_btn = tk.Button(control_frame, text="Export TXT 📝", command=export_txt)
style_button(export_txt_btn)
export_txt_btn.pack(side=tk.LEFT, padx=(0, 8))

export_pdf_btn = tk.Button(control_frame, text="Export PDF 📄", command=export_pdf)
style_button(export_pdf_btn)
export_pdf_btn.pack(side=tk.LEFT, padx=(0, 12))

search_entry = tk.Entry(
    control_frame,
    font=("Segoe UI", 11),
    bg=INPUT_BG,
    fg=TEXT_COLOR,
    insertbackground=TEXT_COLOR,
    relief=tk.FLAT,
    bd=0,
    width=22,
    highlightthickness=1,
    highlightbackground=BORDER_COLOR,
    highlightcolor=ACCENT,
)
search_entry.pack(side=tk.LEFT, padx=(0, 8), pady=4, ipady=8)

search_btn = tk.Button(control_frame, text="Search IP 🔎", command=search_ip)
style_button(search_btn)
search_btn.pack(side=tk.LEFT)

# Dashboard cards
cards_frame = tk.Frame(root, bg=BG_COLOR)
cards_frame.pack(fill=tk.X, padx=16, pady=(0, 12))

failed_total_label = create_stat_card(cards_frame, "🛡️ Failed Attempts", "0")
unique_sources_label = create_stat_card(cards_frame, "🔐 Unique Sources", "0")
threat_level_label = create_stat_card(cards_frame, "⚠️ Threat Level", "No Data")
high_risk_label = create_stat_card(cards_frame, "🔥 High-Risk Attackers", "0")
success_total_label = create_stat_card(cards_frame, "✅ Successful Logins", "0")

# Main content
content_frame = tk.Frame(root, bg=BG_COLOR)
content_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

left_panel = tk.Frame(content_frame, bg=BG_COLOR)
left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

# Report panel
report_frame = tk.Frame(left_panel, bg=PANEL_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
report_frame.pack(fill=tk.BOTH, expand=True)

report_header = tk.Label(
    report_frame,
    text="Analysis Report",
    fg=TEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI Semibold", 12),
)
report_header.pack(anchor="w", padx=16, pady=(16, 10))

report = tk.Text(
    report_frame,
    bg=PANEL_BG,
    fg=TEXT_COLOR,
    insertbackground=TEXT_COLOR,
    relief=tk.FLAT,
    bd=0,
    font=MONO_FONT,
    wrap=tk.WORD,
    undo=False,
    maxundo=0,
    spacing1=4,
    spacing3=4,
)
report.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

report_scroll = tk.Scrollbar(report_frame, command=report.yview, bg=PANEL_BG, troughcolor=BG_COLOR, activebackground=ACCENT)
report_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 16), padx=(0, 10))
report.config(yscrollcommand=report_scroll.set)
report.bind("<Enter>", lambda e: report.focus_set())
report.bind("<MouseWheel>", lambda e: on_widget_scroll(report, e))
report.bind("<Button-4>", lambda e: on_widget_scroll(report, e))
report.bind("<Button-5>", lambda e: on_widget_scroll(report, e))

report.insert(tk.END, "WELCOME TO SOC LOG ANALYZER\n", "header")
report.insert(tk.END, """\nSecure your environment with rapid authentication analysis, risk scoring, and suspicious IP detection.\n\n""", "section")
report.insert(tk.END, "• Select a JSON or XML log file\n", "bullet")
report.insert(tk.END, "• Review failed and successful authentication events\n", "bullet")
report.insert(tk.END, "• Monitor threat severity and high-risk attackers\n", "bullet")
report.insert(tk.END, "• Export reports to TXT, HTML, CSV, or PDF\n", "bullet")
report.insert(tk.END, "\nReady to investigate.\n", "normal")

report.tag_configure("header", foreground=ACCENT, font=("Segoe UI Semibold", 13))
report.tag_configure("section", foreground=SUBTEXT_COLOR, font=("Segoe UI", 10))
report.tag_configure("bullet", foreground=TEXT_COLOR, font=("Segoe UI", 10), lmargin1=18, lmargin2=18)
report.tag_configure("warning", foreground=WARN_COLOR)
report.tag_configure("normal", foreground=TEXT_COLOR)
report.tag_configure("highlight", background="#133a5b", foreground=ACCENT)
report.tag_configure("low", foreground="#7fffd4")
report.tag_configure("medium", foreground=ACCENT)
report.tag_configure("high", foreground=DANGER_COLOR)
report.tag_configure("critical", foreground=WARN_COLOR)
report.tag_configure("success", foreground="#6bed8c")
report.tag_configure("severity", foreground=ACCENT, font=("Segoe UI Semibold", 10))

# Analyst notes panel
notes_frame = tk.Frame(left_panel, bg=PANEL_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
notes_frame.pack(fill=tk.BOTH, expand=False, pady=(12, 0))

notes_header = tk.Label(
    notes_frame,
    text="Analyst Notes",
    fg=TEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI Semibold", 12),
)
notes_header.pack(anchor="w", padx=16, pady=(16, 10))

notes_text = tk.Text(
    notes_frame,
    bg=PANEL_BG,
    fg=TEXT_COLOR,
    insertbackground=TEXT_COLOR,
    relief=tk.FLAT,
    bd=0,
    font=("Segoe UI", 10),
    wrap=tk.WORD,
    height=10,
    undo=False,
    maxundo=0,
)
notes_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 8))
notes_text.bind("<Enter>", lambda e: notes_text.focus_set())
notes_text.bind("<MouseWheel>", lambda e: on_widget_scroll(notes_text, e))
notes_text.bind("<Button-4>", lambda e: on_widget_scroll(notes_text, e))
notes_text.bind("<Button-5>", lambda e: on_widget_scroll(notes_text, e))

notes_hint = tk.Label(
    notes_frame,
    text="Tip: save notes with Export TXT, HTML, or PDF.",
    fg=SUBTEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI", 9),
)
notes_hint.pack(anchor="w", padx=14, pady=(0, 10))

notes_scroll = tk.Scrollbar(notes_frame, command=notes_text.yview, bg=PANEL_BG, troughcolor=BG_COLOR, activebackground=ACCENT)
notes_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 14))
notes_text.config(yscrollcommand=notes_scroll.set)

# Right-side analytics panel
right_panel = tk.Frame(content_frame, bg=BG_COLOR)
right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Graph panel
graph_frame = tk.Frame(right_panel, bg=PANEL_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
graph_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

graph_header = tk.Label(
    graph_frame,
    text="Visualizations",
    fg=TEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI Semibold", 12),
)
graph_header.pack(anchor="w", padx=16, pady=(16, 10))

fig = Figure(figsize=(6, 6), dpi=110, facecolor=PANEL_BG)
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 14))

# Suspicious IP Detection panel
suspicious_frame = tk.Frame(right_panel, bg=PANEL_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
suspicious_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

suspicious_header = tk.Label(
    suspicious_frame,
    text="Suspicious IP Detection",
    fg=TEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI Semibold", 12),
)
suspicious_header.pack(anchor="w", padx=16, pady=(16, 10))

suspicious_columns = ("ip", "attempts", "severity", "last_seen")
suspicious_table = ttk.Treeview(
    suspicious_frame,
    columns=suspicious_columns,
    show="headings",
    style="Dark.Treeview",
    height=6,
)
for col, title in zip(suspicious_columns, ("IP Address", "Attempts", "Severity", "Last Seen")):
    suspicious_table.heading(col, text=title)
    suspicious_table.column(col, anchor=tk.W, width=100)
suspicious_table.column("severity", width=90, anchor=tk.CENTER)
suspicious_table.column("last_seen", width=140)
suspicious_table.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 14))

suspicious_scroll = tk.Scrollbar(suspicious_frame, command=suspicious_table.yview, bg=PANEL_BG, troughcolor=BG_COLOR, activebackground=ACCENT)
suspicious_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 14))
suspicious_table.configure(yscrollcommand=suspicious_scroll.set)
suspicious_table.bind("<MouseWheel>", lambda e: on_widget_scroll(suspicious_table, e))
suspicious_table.bind("<Button-4>", lambda e: on_widget_scroll(suspicious_table, e))
suspicious_table.bind("<Button-5>", lambda e: on_widget_scroll(suspicious_table, e))

style = ttk.Style()
style.theme_use('default')
style.configure("Dark.Treeview", background=PANEL_BG, fieldbackground=PANEL_BG, foreground=TEXT_COLOR, rowheight=24, bordercolor=BORDER_COLOR, lightcolor=BORDER_COLOR, darkcolor=BORDER_COLOR)
style.map("Dark.Treeview", background=[('selected', '#134661')], foreground=[('selected', TEXT_COLOR)])

footer_frame = tk.Frame(root, bg=PANEL_BG, bd=1, relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER_COLOR)
footer_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=16, pady=(0, 12))

status_label = tk.Label(
    footer_frame,
    text="Status: Ready — Load a log file to analyze.",
    fg=SUBTEXT_COLOR,
    bg=PANEL_BG,
    font=SMALL_FONT,
)
status_label.pack(side=tk.LEFT, padx=14, pady=8)

copyright_label = tk.Label(
    footer_frame,
    text="© 2026 SOC Log Analyzer",
    fg=SUBTEXT_COLOR,
    bg=PANEL_BG,
    font=("Segoe UI", 9),
)
copyright_label.pack(side=tk.RIGHT, padx=14, pady=8)

root.mainloop()
