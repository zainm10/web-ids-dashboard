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

def classify_severity(score):
    if score >= 8:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"

def calculate_risk_score(failed_count=0, unknown_ip=False, restricted=False):
    score = 0
    score += failed_count * 2
    if unknown_ip:
        score += 5
    if restricted:
        score += 3
    return score

def detect_intrusions_from_lines(lines):
    alerts = []
    stats = {
        "total_lines": len(lines),
        "failed_login_events": 0,
        "successful_login_events": 0,
        "restricted_events": 0,
        "alerts_generated": 0,
        "risk_score": 0
    }

    failed_counts = {}
    failed_threshold = 5
    unknown_ip_found = False
    restricted_found = False

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        # Rule 1: Failed login detection
        m = re.search(r"Failed\s+login\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})", line, re.IGNORECASE)
        if m:
            ip = m.group(1)
            stats["failed_login_events"] += 1
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

            if failed_counts[ip] == failed_threshold:
                score = calculate_risk_score(failed_count=failed_counts[ip])
                alerts.append({
                    "timestamp": _now(),
                    "type": "Brute Force Attempt",
                    "severity": classify_severity(score),
                    "ip": ip,
                    "details": f"{failed_threshold}+ failed login attempts detected from {ip}.",
                    "score": score
                })
            continue

        # Rule 2: Successful login from unusual/public IP
        m2 = re.search(r"Login\s+success\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})", line, re.IGNORECASE)
        if m2:
            ip = m2.group(1)
            stats["successful_login_events"] += 1
            if not ip.startswith(PRIVATE_IP_PREFIXES):
                unknown_ip_found = True
                score = calculate_risk_score(unknown_ip=True)
                alerts.append({
                    "timestamp": _now(),
                    "type": "Unknown IP Access",
                    "severity": classify_severity(score),
                    "ip": ip,
                    "details": f"Successful login from unusual/public IP address: {ip}.",
                    "score": score
                })
            continue

        # Rule 3: Restricted area access
        if "restricted" in line.lower() or "admin panel" in line.lower():
            restricted_found = True
            stats["restricted_events"] += 1
            score = calculate_risk_score(restricted=True)
            alerts.append({
                "timestamp": _now(),
                "type": "Restricted Area Access",
                "severity": classify_severity(score),
                "ip": None,
                "details": line,
                "score": score
            })

    total_score = 0
    for ip, count in failed_counts.items():
        if count >= failed_threshold:
            total_score += calculate_risk_score(failed_count=count)
    if unknown_ip_found:
        total_score += 5
    if restricted_found:
        total_score += 3

    stats["risk_score"] = total_score
    stats["alerts_generated"] = len(alerts)
    return alerts, stats
