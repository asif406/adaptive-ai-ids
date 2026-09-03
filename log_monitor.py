import re
import time
import requests
from collections import defaultdict

from models import insert_incident, add_blocked_ip
from alerting import notify_high_severity
from firewall_blocker import block_ip
from config import LOG_FILE_PATH, ENABLE_AUTO_BLOCK

# =========================
# Threat scoring config
# =========================
THREAT_WEIGHTS = {
    "SQL Injection Attempt": 40,
    "Brute Force Login": 35,
    "Failed Login": 10,
    "DoS-like behavior": 50,
    "Scanning Activity": 25,
    "Honeypot Access": 60,
    "Anomaly Detected": 20,
}

COUNTRY_RISK = {
    "Russia": 25, "China": 25, "Nigeria": 20, "Brazil": 15,
    "Iran": 22, "USA": 10, "Germany": 8, "India": 5, "Unknown": 8,
}

HONEYPOT_PATHS = [
    "/admin_panel", "/secret", "/backup.zip", "/database_dump",
    "/private", "/db_dump", "/root", "/wp-admin.php"
]

SENSITIVE_PATHS = [
    "/admin", "/wp-login.php", "/config.php",
    "/phpmyadmin", "/server-status"
]

SQLI_PATTERN = re.compile(
    r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b\s+1=1|\bOR\b\s+'1'='1')",
    re.IGNORECASE,
)

# =========================
# Runtime trackers
# =========================
request_count = defaultdict(list)
failed_logins = defaultdict(list)
scanner_hits = defaultdict(list)

REQ_MEAN = 0
REQ_COUNT = 0

# =========================
# GEO lookup
# =========================
def get_geo_for_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        return {
            "country": data.get("country", "Unknown"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    except Exception:
        return {"country": "Unknown", "lat": None, "lon": None}

# =========================
# Anomaly detection
# =========================
def anomaly_score(request):
    global REQ_MEAN, REQ_COUNT
    length = len(request)
    if REQ_COUNT > 5 and abs(length - REQ_MEAN) > 45:
        return 20
    REQ_MEAN = (REQ_MEAN * REQ_COUNT + length) / (REQ_COUNT + 1)
    REQ_COUNT += 1
    return 0

# =========================
# Rule engine
# =========================
def apply_rules(entry):
    ip = entry["ip"]
    now = time.time()
    geo = get_geo_for_ip(ip)

    country = geo["country"]
    lat = geo["lat"]
    lon = geo["lon"]

    incidents = []
    total_score = COUNTRY_RISK.get(country, 10)

    # Honeypot
    for hp in HONEYPOT_PATHS:
        if hp in entry["request"]:
            incidents.append((
                "Honeypot Access", "HIGH",
                f"Trap endpoint accessed: {entry['request']} [{country}]"
            ))
            total_score += THREAT_WEIGHTS["Honeypot Access"]

    # SQL Injection
    if SQLI_PATTERN.search(entry["request"]):
        incidents.append((
            "SQL Injection Attempt", "HIGH",
            f"Possible SQLi: {entry['request']} [{country}]"
        ))
        total_score += THREAT_WEIGHTS["SQL Injection Attempt"]

    # Failed login / brute force
    if entry["status"] == "401" and "/login" in entry["request"]:
        failed_logins[ip].append(now)
        failed_logins[ip] = [t for t in failed_logins[ip] if now - t <= 60]

        if len(failed_logins[ip]) >= 5:
            incidents.append((
                "Brute Force Login", "HIGH",
                f"{len(failed_logins[ip])} failed logins [{country}]"
            ))
            total_score += THREAT_WEIGHTS["Brute Force Login"]
        else:
            incidents.append((
                "Failed Login", "MEDIUM",
                f"Failed login attempt [{country}]"
            ))
            total_score += THREAT_WEIGHTS["Failed Login"]

    # DoS detection
    request_count[ip].append(now)
    request_count[ip] = [t for t in request_count[ip] if now - t <= 60]
    if len(request_count[ip]) > 20:
        incidents.append((
            "DoS-like behavior", "HIGH",
            f"{len(request_count[ip])} requests in 60s [{country}]"
        ))
        total_score += THREAT_WEIGHTS["DoS-like behavior"]

    # Scanning
    for path in SENSITIVE_PATHS:
        if path in entry["request"]:
            scanner_hits[ip].append(now)
            scanner_hits[ip] = [t for t in scanner_hits[ip] if now - t <= 120]
            if len(scanner_hits[ip]) >= 3:
                incidents.append((
                    "Scanning Activity", "MEDIUM",
                    f"Sensitive path scanning [{country}]"
                ))
                total_score += THREAT_WEIGHTS["Scanning Activity"]
            break

    # Anomaly
    a = anomaly_score(entry["request"])
    if a:
        incidents.append((
            "Anomaly Detected", "MEDIUM",
            f"Abnormal request length [{country}]"
        ))
        total_score += THREAT_WEIGHTS["Anomaly Detected"]

    # =========================
    # AUTO BLOCK LOGIC (FIXED)
    # =========================
    if total_score >= 65:
        if ENABLE_AUTO_BLOCK:
            block_ip(ip)
            add_blocked_ip(ip, f"Score {total_score}")
        notify_high_severity(ip, "Adaptive Threat", f"Score: {total_score}")

    return incidents, country, total_score, lat, lon

# =========================
# Log parsing
# =========================
def parse_log_line(line):
    parts = line.split()
    if len(parts) < 9:
        return None
    return {
        "ip": parts[0],
        "timestamp": line.split("[", 1)[1].split("]")[0],
        "request": " ".join(line.split('"')[1:2]),
        "status": parts[-2],
    }

# =========================
# Main loop
# =========================
def monitor_logs():
    print("🔥 Adaptive AI IDS is now monitoring logs...")
    with open(LOG_FILE_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            entry = parse_log_line(line)
            if not entry:
                continue

            incidents, country, score, lat, lon = apply_rules(entry)

            for rule, sev, msg in incidents:
                insert_incident(
                    entry["ip"],
                    entry["timestamp"],
                    rule,
                    sev,
                    msg,
                    country,
                    score,
                    lat,
                    lon,
                )

if __name__ == "__main__":
    monitor_logs()
