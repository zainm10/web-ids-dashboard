import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import pandas as pd

from ids_engine import detect_intrusions_from_lines

APP_NAME = "Web-Based IDS Dashboard"
UPLOAD_FOLDER = "uploads"
DB_FILE = "database.db"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB
app.secret_key = "coursework-prototype-secret"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            log_filename TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            src_ip TEXT,
            details TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_alerts(alerts, log_filename: str):
    if not alerts:
        return
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    for a in alerts:
        cur.execute("""
            INSERT INTO alerts (created_at, log_filename, alert_type, severity, src_ip, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            a["timestamp"], log_filename, a["type"], a["severity"], a.get("ip"), a["details"]
        ))
    conn.commit()
    conn.close()

def fetch_alerts():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, created_at, log_filename, alert_type, severity, src_ip, details
        FROM alerts
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("logfile")
        if not file or file.filename.strip() == "":
            flash("Please choose a log file to upload.", "warning")
            return redirect(url_for("index"))

        fname = file.filename
        if not fname.lower().endswith((".txt", ".csv", ".log")):
            flash("Only .txt, .csv or .log files are supported for this prototype.", "danger")
            return redirect(url_for("index"))

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        file.save(filepath)

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        alerts, stats = detect_intrusions_from_lines(lines)
        save_alerts(alerts, fname)

        return render_template("dashboard.html", app_name=APP_NAME, filename=fname, alerts=alerts, stats=stats)

    return render_template("index.html", app_name=APP_NAME)

@app.route("/history")
def history():
    rows = fetch_alerts()
    return render_template("history.html", app_name=APP_NAME, rows=rows)

@app.route("/download")
def download():
    rows = fetch_alerts()
    df = pd.DataFrame(rows, columns=["id","created_at","log_filename","alert_type","severity","src_ip","details"])
    out_path = "alerts_report.csv"
    df.to_csv(out_path, index=False)
    return send_file(out_path, as_attachment=True)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
