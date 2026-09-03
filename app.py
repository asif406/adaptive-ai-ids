import io
import csv
import zipfile
from flask import Flask, render_template, jsonify, Response, send_file, abort

from models import (
    init_db,
    get_all_incidents,
    get_stats_by_ip,
    get_severity_stats,
    get_rule_stats,
    get_incidents_geo,
    get_incident_by_id,
    get_blocked_ips          # ✅ NEW
)

app = Flask(__name__)

# Initialize DB (incidents + blocked_ips tables)
init_db()

# =========================
# DASHBOARD
# =========================
@app.route("/")
def dashboard():
    incidents = get_all_incidents()
    total = len(incidents)

    severity_stats = get_severity_stats()
    high_count = severity_stats.get("HIGH", 0)

    rule_stats = get_rule_stats()
    sqli_count = rule_stats.get("SQL Injection Attempt", 0)
    dos_count = rule_stats.get("DoS-like behavior", 0)

    blocked_ips = get_blocked_ips()     # ✅ FETCH BLOCKED IPs
    latest_incidents = incidents[:10]

    return render_template(
        "dashboard.html",
        incidents=latest_incidents,
        total=total,
        high_count=high_count,
        sqli_count=sqli_count,
        dos_count=dos_count,
        rule_stats=rule_stats,
        blocked_ips=blocked_ips          # ✅ PASS TO TEMPLATE
    )


@app.route("/incidents")
def incidents_page():
    incidents = get_all_incidents()
    total = len(incidents)

    severity_stats = get_severity_stats()
    high_count = severity_stats.get("HIGH", 0)

    rule_stats = get_rule_stats()
    sqli_count = rule_stats.get("SQL Injection Attempt", 0)
    dos_count = rule_stats.get("DoS-like behavior", 0)

    blocked_ips = get_blocked_ips()     # ✅ FETCH BLOCKED IPs

    return render_template(
        "dashboard.html",
        incidents=incidents,
        total=total,
        high_count=high_count,
        sqli_count=sqli_count,
        dos_count=dos_count,
        rule_stats=rule_stats,
        blocked_ips=blocked_ips          # ✅ PASS TO TEMPLATE
    )

# =========================
# GRAPHS PAGE
# =========================
@app.route("/graphs")
def graphs_page():
    return render_template("graphs.html")

# =========================
# API: STATS
# =========================
@app.route("/api/stats/ip")
def api_stats_ip():
    data = get_stats_by_ip()
    labels = [row[0] for row in data]
    counts = [row[1] for row in data]
    return jsonify({"labels": labels, "counts": counts})


@app.route("/api/stats/severity")
def api_stats_severity():
    data = get_severity_stats()
    return jsonify({
        "labels": list(data.keys()),
        "counts": list(data.values())
    })


@app.route("/api/stats/rules")
def api_stats_rules():
    data = get_rule_stats()
    return jsonify({
        "labels": list(data.keys()),
        "counts": list(data.values())
    })

# =========================
# API: MAP DATA
# =========================
@app.route("/api/incidents_geo")
def api_incidents_geo():
    return jsonify(get_incidents_geo())

# =========================
# API: SINGLE INCIDENT
# =========================
@app.route("/api/incident/<int:incident_id>")
def api_incident(incident_id):
    row = get_incident_by_id(incident_id)
    if not row:
        abort(404)

    return jsonify({
        "id": row[0],
        "ip": row[1],
        "timestamp": row[2],
        "rule": row[3],
        "severity": row[4],
        "message": row[5],
        "country": row[6],
        "score": row[7],
        "lat": row[8],
        "lon": row[9]
    })

# =========================
# EXPORT REPORT (ZIP)
# =========================
@app.route("/export/report")
def export_report():
    incidents = get_all_incidents()

    # CSV
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(["id","ip","timestamp","rule","severity","message","country","score","lat","lon"])
    for r in incidents:
        writer.writerow(r)
    csv_bytes = csv_buf.getvalue().encode("utf-8")

    # HTML summary
    severity_stats = get_severity_stats()
    rule_stats = get_rule_stats()

    html = "<html><body><h1>IDS Report</h1>"
    html += f"<p>Total Incidents: {len(incidents)}</p>"
    html += "<h3>Severity Summary</h3><ul>"
    for k,v in severity_stats.items():
        html += f"<li>{k}: {v}</li>"
    html += "</ul><h3>Rule Summary</h3><ul>"
    for k,v in rule_stats.items():
        html += f"<li>{k}: {v}</li>"
    html += "</ul></body></html>"

    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w") as z:
        z.writestr("incidents.csv", csv_bytes)
        z.writestr("report.html", html.encode("utf-8"))
    mem.seek(0)

    return send_file(
        mem,
        mimetype="application/zip",
        as_attachment=True,
        download_name="ids_report.zip"
    )

# =========================
# EXPORT CSV
# =========================
@app.route("/export/csv")
def export_csv():
    incidents = get_all_incidents()

    def generate():
        yield "id,ip,timestamp,rule,severity,message,country,score,lat,lon\n"
        for r in incidents:
            msg = str(r[5]).replace(",", " ")
            country = str(r[6]).replace(",", " ")
            lat = r[8] if r[8] is not None else ""
            lon = r[9] if r[9] is not None else ""
            yield f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]},{msg},{country},{r[7]},{lat},{lon}\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"}
    )

# =========================
if __name__ == "__main__":
    app.run(debug=True)
