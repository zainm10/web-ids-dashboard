import re
from datetime import datetime

PRIVATE_IP_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31."
)

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_intrusions_from_lines(lines):
    """
    Simplified, rule-based IDS engine (prototype).
    Rules:
      1) Brute force: 5+ failed logins from same IP -> High
      2) Unknown IP: successful login from non-private IP -> Medium
      3) Restricted access keywords -> Medium
    Returns: (alerts, stats)
    """
    alerts = []
    stats = {
        "total_lines": len(lines),
        "failed_login_events": 0,
        "successful_login_events": 0,
        "restricted_events": 0,
        "alerts_generated": 0,
    }

    failed_counts = {}
    FAILED_THRESHOLD = 5

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        m = re.search(r"Failed\s+login\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})", line, re.IGNORECASE)
        if m:
            ip = m.group(1)
            stats["failed_login_events"] += 1
            failed_counts[ip] = failed_counts.get(ip, 0) + 1
            if failed_counts[ip] == FAILED_THRESHOLD:
                alerts.append({
                    "timestamp": _now(),
                    "type": "Brute Force Attempt",
                    "severity": "High",
                    "ip": ip,
                    "details": f"{FAILED_THRESHOLD}+ failed login attempts detected from {ip}."
                })
            continue

        m2 = re.search(r"Login\s+success\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})", line, re.IGNORECASE)
        if m2:
            ip = m2.group(1)
            stats["successful_login_events"] += 1
            if not ip.startswith(PRIVATE_IP_PREFIXES):
                alerts.append({
                    "timestamp": _now(),
                    "type": "Unknown IP Access",
                    "severity": "Medium",
                    "ip": ip,
                    "details": f"Successful login from unusual/public IP address: {ip}."
                })
            continue

        if "restricted" in line.lower() or "admin panel" in line.lower():
            stats["restricted_events"] += 1
            alerts.append({
                "timestamp": _now(),
                "type": "Restricted Area Access",
                "severity": "Medium",
                "ip": None,
                "details": line
            })

    stats["alerts_generated"] = len(alerts)
    return alerts, stats
